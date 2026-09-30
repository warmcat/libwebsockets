/*
 * Sai builder - ./src/builder/b-pool.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * Pools, builder side: see READMEs/README-pool.md
 *
 * A task whose .sai.json configuration names a pool gets a local copy of it
 * under $HOME/pools/, which we keep synced with sai-server: before its first
 * build step starts, every minute while it runs, and once more after it ends.
 * Doing it here rather than in the task means a task that's killed loses
 * nothing it had written, and several tasks on the builder using the same
 * pool share one copy.
 *
 *   corpus/	both ways, content addressed <sub>/<sha1> files
 *   known/	a copy of what the server has, eg, known reproducers
 *   findings/	anything the task leaves in <sub>/ here is sent to the
 *		server, then deleted
 *
 * Each sync is its own connection to the server, a stream of records after
 * the hello (see private.h):
 *
 *  - PULL both content addressed namespaces from where we got to last time
 *  - OFFER the server corpus files that appeared locally since the last sync,
 *    and PUT the ones it wants
 *  - PUT everything in findings/
 *  - REPLACE any corpus sub a task asked for, see README-pool.md
 */

#include <libwebsockets.h>

#include "b-private.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#if !defined(WIN32)
#include <unistd.h>
#endif

/* how often we sync a pool while tasks are using it */
#define SAIB_POOL_SYNC_INTERVAL_US	(60 * LWS_US_PER_SEC)
/* a task's first build step waits for a pull unless there was one this recently */
#define SAIB_POOL_PULL_FRESH_US		(60 * LWS_US_PER_SEC)
/* the longest a step waits for its pool to sync before starting anyway */
#define SAIB_POOL_WAIT_MAX_US		(180 * LWS_US_PER_SEC)
/* the longest one sync can take before we give up on it */
#define SAIB_POOL_SESSION_MAX_US	(15 * 60 * LWS_US_PER_SEC)
/* how often we offer the server every corpus file, not just new ones */
#define SAIB_POOL_FULL_OFFER_SECS	(24 * 3600)
/* files this much older than the last sync are offered again anyway */
#define SAIB_POOL_OFFER_SLACK_SECS	60
/* how many times the sync after the last task ends is tried */
#define SAIB_POOL_FINAL_TRIES		3

typedef struct saib_pool {
	lws_dll2_t		list;		/* builder.pool_owner */
	lws_dll2_owner_t	waiters;	/* nspawns waiting for a pull */

	lws_sorted_usec_list_t	sul_sync;	/* next sync */
	lws_sorted_usec_list_t	sul_wait;	/* waiters stop waiting */
	lws_sorted_usec_list_t	sul_session;	/* sync taking too long */

	struct sai_plat_server	*spm;
	struct lws_ss_handle	*ss;		/* the sync going on, if any */

	char			name[33];
	char			key[160];	/* server-repo-pool, purified */
	char			dir[300];

	/* the task we sync on behalf of: the latest one to use the pool */
	char			task_uuid[65];
	char			nonce[33];

	uint64_t		cursor[2];	/* corpus, known */
	uint64_t		offer_since;	/* wall clock, see offer scan */
	uint64_t		full_offer;	/* wall clock of last full offer */
	lws_usec_t		last_pull;

	int			users;		/* nspawns using it */
	int			final_tries;
	char			resync;		/* sync again when this one ends */
} saib_pool_t;

/* one record queued to go, or waiting to be acknowledged */

typedef struct saib_pool_rec {
	lws_dll2_t		list;
	char			path[384];	/* unlink on ACK, if any */
	char			name[SAI_POOL_REC_NAME_MAX + 1];
	uint64_t		replace_base;
	size_t			len;
	size_t			ofs;
	char			is_replace;
	/* len bytes of record follow */
} saib_pool_rec_t;

/* a corpus file the server said it wants */

typedef struct saib_pool_put {
	lws_dll2_t		list;
	char			name[SAI_POOL_REC_NAME_MAX + 1];
} saib_pool_put_t;

typedef struct saib_pool_ss {
	struct lws_ss_handle	*ss;
	void			*opaque_data;

	saib_pool_t		*pool;

	lws_dll2_owner_t	txq;		/* saib_pool_rec_t to send */
	lws_dll2_owner_t	acks;		/* saib_pool_rec_t awaiting ACK */
	lws_dll2_owner_t	puts;		/* saib_pool_put_t to load */
	struct lwsac		*ac_puts;

	uint8_t			*rxb;
	size_t			rxb_len;
	size_t			rxb_alloc;

	uint64_t		scan_start;	/* wall clock at the offer scan */

	int			pulls_left;
	int			offers_left;

	char			sent_auth;
	char			sent_hello;
	char			pulled;
	char			full_offer;
	char			done;
} saib_pool_ss_t;

static void
saib_pool_sync_start(saib_pool_t *pool);

static const char * const ns_dir[] = { "corpus", "known", "findings" };

/*
 * Local state
 */

static const char * const state_paths[] = {
	"corpus", "known", "offer_since", "full_offer",
};

static signed char
saib_pool_state_cb(struct lejp_ctx *ctx, char reason)
{
	saib_pool_t *pool = (saib_pool_t *)ctx->user;
	uint64_t v;

	if (reason != LEJPCB_VAL_NUM_INT || !ctx->path_match)
		return 0;

	v = (uint64_t)strtoull(ctx->buf, NULL, 10);

	switch (ctx->path_match - 1) {
	case 0:
		pool->cursor[SAI_POOL_NS_CORPUS] = v;
		break;
	case 1:
		pool->cursor[SAI_POOL_NS_KNOWN] = v;
		break;
	case 2:
		pool->offer_since = v;
		break;
	case 3:
		pool->full_offer = v;
		break;
	}

	return 0;
}

static void
saib_pool_state_load(saib_pool_t *pool)
{
	struct lejp_ctx ctx;
	char path[384];
	uint8_t buf[256];
	int fd, n, m = 0;

	lws_snprintf(path, sizeof(path), "%s/.sai-pool-state", pool->dir);
	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return;

	lejp_construct(&ctx, saib_pool_state_cb, pool, state_paths,
		       LWS_ARRAY_SIZE(state_paths));
	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);
	lejp_destruct(&ctx);
	close(fd);

	if (m < 0 && m != LEJP_CONTINUE) {
		lwsl_warn("%s: %s unreadable, starting over\n", __func__, path);
		pool->cursor[0] = pool->cursor[1] = 0;
		pool->offer_since = pool->full_offer = 0;
	}
}

/*
 * Write a file so it's never seen half-written: via tmp, which must be in a
 * place nothing looks at, eg, not a corpus dir a fuzzer is reading
 */

static int
saib_pool_write_file(const char *tmp, const char *path, const void *buf,
		     size_t len)
{
	int fd;

	fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY
#if defined(WIN32)
			| _O_BINARY
#endif
			, 0644);
	if (fd < 0)
		return -1;
	if (len && (size_t)write(fd, buf,
#if defined(WIN32)
				 (unsigned int)
#endif
				 len) != len) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);

#if defined(WIN32)
	unlink(path);
#endif
	if (rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}

	return 0;
}

static void
saib_pool_state_save(saib_pool_t *pool)
{
	char path[384], tmp[384], buf[256];
	int n;

	n = lws_snprintf(buf, sizeof(buf), "{\"corpus\":%llu,\"known\":%llu,"
			 "\"offer_since\":%llu,\"full_offer\":%llu}",
			 (unsigned long long)pool->cursor[SAI_POOL_NS_CORPUS],
			 (unsigned long long)pool->cursor[SAI_POOL_NS_KNOWN],
			 (unsigned long long)pool->offer_since,
			 (unsigned long long)pool->full_offer);
	lws_snprintf(path, sizeof(path), "%s/.sai-pool-state", pool->dir);
	lws_snprintf(tmp, sizeof(tmp), "%s/.sai-tmp", pool->dir);
	if (saib_pool_write_file(tmp, path, buf, (size_t)n))
		lwsl_err("%s: unable to write %s\n", __func__, path);

	/*
	 * Tasks replacing a corpus sub need to know where we pulled up to,
	 * see README-pool.md
	 */
	n = lws_snprintf(buf, sizeof(buf), "%llu\n",
			 (unsigned long long)pool->cursor[SAI_POOL_NS_CORPUS]);
	lws_snprintf(path, sizeof(path), "%s/corpus/.sai-pool-seq", pool->dir);
	saib_pool_write_file(tmp, path, buf, (size_t)n);
}

/*
 * Nspawns waiting to start until their pool is pulled
 */

static void
saib_pool_release_waiters(saib_pool_t *pool, const char *why)
{
	lws_sul_cancel(&pool->sul_wait);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   pool->waiters.head) {
		struct sai_nspawn *ns = lws_container_of(d, struct sai_nspawn,
							 pool_wait_list);

		lws_dll2_remove(&ns->pool_wait_list);

		if (why)
			saib_task_logf(ns->spm, ns, NULL, "Pool %s: %s, "
				       "starting anyway", pool->name, why);

		if (saib_spawn_script(ns)) {
			saib_task_logf(ns->spm, ns, NULL, "Builder %s could "
				       "not start step %d, failing the task",
				       ns->sp->name, ns->task->build_step + 1);
			saib_set_ns_state(ns, NSSTATE_FAILED);
		}

	} lws_end_foreach_dll_safe(d, d1);
}

static void
saib_pool_wait_timeout_cb(lws_sorted_usec_list_t *sul)
{
	saib_pool_t *pool = lws_container_of(sul, saib_pool_t, sul_wait);

	saib_pool_release_waiters(pool, "syncing is taking too long");
}

static void
saib_pool_sync_cb(lws_sorted_usec_list_t *sul)
{
	saib_pool_t *pool = lws_container_of(sul, saib_pool_t, sul_sync);

	saib_pool_sync_start(pool);
}

static void
saib_pool_session_timeout_cb(lws_sorted_usec_list_t *sul)
{
	saib_pool_t *pool = lws_container_of(sul, saib_pool_t, sul_session);

	lwsl_warn("%s: pool %s sync took too long\n", __func__, pool->name);
	if (pool->ss)
		lws_ss_destroy(&pool->ss);
}

/*
 * Tx side of a sync
 */

static saib_pool_rec_t *
saib_pool_rec_new(int type, int ns, const char *name, size_t name_len,
		  size_t data_len)
{
	saib_pool_rec_t *r;

	r = malloc(sizeof(*r) + SAI_POOL_REC_HDR_LEN + name_len + data_len);
	if (!r)
		return NULL;
	memset(r, 0, sizeof(*r));

	r->len = SAI_POOL_REC_HDR_LEN + name_len + data_len;
	sai_pool_rec_hdr_write((uint8_t *)&r[1], type, ns, name_len, data_len);
	if (name_len) {
		memcpy((uint8_t *)&r[1] + SAI_POOL_REC_HDR_LEN, name, name_len);
		lws_strnncpy(r->name, name, name_len, sizeof(r->name));
	}

	return r;
}

static uint8_t *
saib_pool_rec_data(saib_pool_rec_t *r)
{
	sai_pool_rec_hdr_t h;

	sai_pool_rec_hdr_read((uint8_t *)&r[1], &h);

	return (uint8_t *)&r[1] + SAI_POOL_REC_HDR_LEN + h.name_len;
}

static void
saib_pool_queue(saib_pool_ss_t *ps, saib_pool_rec_t *r)
{
	lws_dll2_add_tail(&r->list, &ps->txq);
	if (lws_ss_request_tx(ps->ss))
		lwsl_warn("%s: request tx failed\n", __func__);
}

static void
saib_pool_free_list(lws_dll2_owner_t *o)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, o->head) {
		lws_dll2_remove(d);
		free(lws_container_of(d, saib_pool_rec_t, list));
	} lws_end_foreach_dll_safe(d, d1);
}

/* read a whole local file into a PUT record, if it's still there */

static saib_pool_rec_t *
saib_pool_put_rec(int ns, const char *name, const char *path, size_t max)
{
	saib_pool_rec_t *r;
	struct stat s;
	int fd;

	fd = lws_open(path, O_RDONLY
#if defined(WIN32)
			| _O_BINARY
#endif
			);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &s) || (uint64_t)s.st_size > max) {
		if (!fstat(fd, &s))
			lwsl_warn("%s: %s is too big to send (%llu)\n", __func__,
				  path, (unsigned long long)s.st_size);
		close(fd);
		return NULL;
	}

	r = saib_pool_rec_new(SAI_POOL_REC_PUT, ns, name, strlen(name),
			      (size_t)s.st_size);
	if (r && s.st_size &&
	    read(fd, saib_pool_rec_data(r),
#if defined(WIN32)
		 (unsigned int)
#endif
		 (size_t)s.st_size) != (ssize_t)s.st_size) {
		free(r);
		r = NULL;
	}
	close(fd);

	if (r)
		lws_strncpy(r->path, path, sizeof(r->path));

	return r;
}

/* the sync is over when nothing is left to send or to hear back about */

static int
saib_pool_session_idle(saib_pool_ss_t *ps)
{
	return ps->pulled && !ps->pulls_left && !ps->offers_left &&
	       !ps->txq.count && !ps->acks.count && !ps->puts.count;
}

static lws_ss_state_return_t
saib_pool_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
	     size_t *len, int *flags)
{
	saib_pool_ss_t *ps = (saib_pool_ss_t *)userobj;
	saib_pool_t *pool = ps->pool;
	lws_struct_serialize_t *js;
	sai_pool_hello_t hello;
	saib_pool_rec_t *r;
	size_t w, n = 0;

	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	if (!ps->sent_auth) {
		/* it lands on sai-server's /builder, so the link auth first */
		*len = (size_t)lws_snprintf((char *)buf, *len,
			 "{\"schema\":\"" SAI_LINKAUTH_SCHEMA
			 "\",\"secret\":\"%s\"}",
			 builder.link_key ? builder.link_key : "");
		ps->sent_auth = 1;

		return lws_ss_request_tx(ps->ss);
	}

	if (!ps->sent_hello) {
		memset(&hello, 0, sizeof(hello));
		lws_strncpy(hello.task_uuid, pool->task_uuid,
			    sizeof(hello.task_uuid));
		lws_strncpy(hello.nonce, pool->nonce, sizeof(hello.nonce));

		js = lws_struct_json_serialize_create(lsm_schema_pool_hello,
				LWS_ARRAY_SIZE(lsm_schema_pool_hello), 0,
				&hello);
		if (!js)
			return LWSSSSRET_DESTROY_ME;
		lws_struct_json_serialize(js, buf, *len, &w);
		lws_struct_json_serialize_destroy(&js);
		*len = w;
		ps->sent_hello = 1;

		return lws_ss_request_tx(ps->ss);
	}

	/* coalesce queued records into one message, up to what fits */

	while (ps->txq.head && n < *len) {
		size_t l;

		r = lws_container_of(ps->txq.head, saib_pool_rec_t, list);
		l = r->len - r->ofs;
		if (l > *len - n)
			l = *len - n;
		memcpy(buf + n, (uint8_t *)&r[1] + r->ofs, l);
		r->ofs += l;
		n += l;

		if (r->ofs == r->len) {
			lws_dll2_remove(&r->list);
			if (r->name[0])
				/* PUT and REPLACE hear back */
				lws_dll2_add_tail(&r->list, &ps->acks);
			else
				free(r);
		}
	}

	/* the next corpus file the server wants, now there's room */

	while (!ps->txq.count && ps->puts.head) {
		saib_pool_put_t *pp = lws_container_of(ps->puts.head,
						saib_pool_put_t, list);
		char path[384];

		lws_dll2_remove(&pp->list);
		lws_snprintf(path, sizeof(path), "%s/corpus/%s", pool->dir,
			     pp->name);
		r = saib_pool_put_rec(SAI_POOL_NS_CORPUS, pp->name, path,
				      SAI_POOL_ENTRY_MAX);
		if (!r)
			/* it's gone since we offered it, or too big */
			continue;
		r->path[0] = '\0'; /* we keep corpus files, of course */
		lws_dll2_add_tail(&r->list, &ps->txq);
	}

	if (!n) {
		if (ps->done)
			return LWSSSSRET_DESTROY_ME;
		return LWSSSSRET_TX_DONT_SEND;
	}

	*len = n;

	if (ps->txq.count)
		return lws_ss_request_tx(ps->ss);

	return LWSSSSRET_OK;
}

/*
 * The offer, findings and replace scans, once the pull is done
 */

typedef struct {
	saib_pool_ss_t		*ps;
	const char		*sub;		/* as we scan inside one */
	uint8_t			*list;		/* names being collected */
	size_t			list_len;
	size_t			list_max;
	uint64_t		since;
	int			ns;
	char			overflow;
} saib_pool_scan_t;

static int
saib_pool_offer_flush(saib_pool_scan_t *sc)
{
	saib_pool_rec_t *r;

	if (!sc->list_len)
		return 0;

	r = saib_pool_rec_new(SAI_POOL_REC_OFFER, SAI_POOL_NS_CORPUS, NULL, 0,
			      sc->list_len);
	if (!r)
		return -1;
	memcpy(saib_pool_rec_data(r), sc->list, sc->list_len);
	saib_pool_queue(sc->ps, r);
	sc->ps->offers_left++;
	sc->list_len = 0;

	return 0;
}

/* each file in corpus/<sub>/ or findings/<sub>/ */

static int
saib_pool_scan_file_cb(const char *dirpath, void *user,
		       struct lws_dir_entry *lde)
{
	saib_pool_scan_t *sc = (saib_pool_scan_t *)user;
	char name[SAI_POOL_REC_NAME_MAX + 1], path[384];
	size_t fl = strlen(lde->name);
	saib_pool_rec_t *r;
	int nl;

	if (lde->type != LDOT_FILE)
		return 0;

	nl = lws_snprintf(name, sizeof(name), "%s/%s", sc->sub, lde->name);
	if (!sai_pool_entry_name_ok(sc->ns, name, (size_t)nl))
		/* not something we sync, eg, a temp file */
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (sc->ns == SAI_POOL_NS_FINDINGS) {
		r = saib_pool_put_rec(SAI_POOL_NS_FINDINGS, name, path,
				      SAI_POOL_FINDING_MAX);
		if (r)
			/* the path stays set, we delete it once it's stored */
			saib_pool_queue(sc->ps, r);

		return 0;
	}

	/* otherwise we're collecting the names in a sub for a replace */

	if (sc->list_len + fl + 1 > sc->list_max) {
		sc->overflow = 1;
		return 1;
	}
	memcpy(sc->list + sc->list_len, lde->name, fl);
	sc->list_len += fl;
	sc->list[sc->list_len++] = '\n';

	return 0;
}

static int
saib_pool_offer_file_cb(const char *dirpath, void *user,
			struct lws_dir_entry *lde)
{
	saib_pool_scan_t *sc = (saib_pool_scan_t *)user;
	char name[SAI_POOL_REC_NAME_MAX + 1], path[384];
	struct stat s;
	int nl;

	if (lde->type != LDOT_FILE)
		return 0;

	nl = lws_snprintf(name, sizeof(name), "%s/%s", sc->sub, lde->name);
	if (!sai_pool_entry_name_ok(SAI_POOL_NS_CORPUS, name, (size_t)nl))
		return 0;

	if (sc->since) {
		lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
		if (stat(path, &s) || (uint64_t)s.st_mtime < sc->since)
			/* nothing new */
			return 0;
	}

	if (sc->list_len + (size_t)nl + 1 > SAI_POOL_OFFER_MAX &&
	    saib_pool_offer_flush(sc))
		return 1;

	memcpy(sc->list + sc->list_len, name, (size_t)nl);
	sc->list_len += (size_t)nl;
	sc->list[sc->list_len++] = '\n';

	return 0;
}

/* each sub in corpus/ or findings/ */

static int
saib_pool_scan_sub_cb(const char *dirpath, void *user,
		      struct lws_dir_entry *lde)
{
	saib_pool_scan_t *sc = (saib_pool_scan_t *)user;
	char path[384];

	if (lde->type != LDOT_DIR ||
	    !sai_pool_sub_ok(lde->name, strlen(lde->name)))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	sc->sub = lde->name;

	return lws_dir(path, sc, sc->ns == SAI_POOL_NS_CORPUS ?
				 saib_pool_offer_file_cb :
				 saib_pool_scan_file_cb);
}

/*
 * A task that replaced the contents of corpus/<sub> leaves
 * corpus/.sai-replace-<sub> holding the cursor it began from, see
 * README-pool.md
 */

static int
saib_pool_replace_marker_cb(const char *dirpath, void *user,
			    struct lws_dir_entry *lde)
{
	saib_pool_scan_t *sc = (saib_pool_scan_t *)user;
	char path[384], sub[33], num[32];
	saib_pool_scan_t rsc;
	saib_pool_rec_t *r;
	uint64_t base = 0;
	size_t sl;
	int fd, n, i;

	if (lde->type != LDOT_FILE || strncmp(lde->name, ".sai-replace-", 13))
		return 0;

	sl = strlen(lde->name + 13);
	if (!sai_pool_sub_ok(lde->name + 13, sl))
		return 0;
	lws_strncpy(sub, lde->name + 13, sizeof(sub));

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	n = (int)read(fd, num, sizeof(num) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	for (i = 0; i < n && num[i] >= '0' && num[i] <= '9'; i++)
		base = (base * 10) + (uint64_t)(num[i] - '0');
	if (!i) {
		lwsl_warn("%s: ignoring %s, no cursor in it\n", __func__, path);
		return 0;
	}

	memset(&rsc, 0, sizeof(rsc));
	rsc.ps = sc->ps;
	rsc.ns = SAI_POOL_NS_CORPUS;
	rsc.sub = sub;
	rsc.list_max = SAI_POOL_LIST_MAX - 8;
	rsc.list = malloc(rsc.list_max);
	if (!rsc.list)
		return 1;

	{
		char subdir[384];

		lws_snprintf(subdir, sizeof(subdir), "%s/%s", dirpath, sub);
		lws_dir(subdir, &rsc, saib_pool_scan_file_cb);
	}

	if (rsc.overflow) {
		lwsl_warn("%s: %s has too many files to replace\n", __func__,
			  sub);
		free(rsc.list);
		return 0;
	}

	r = saib_pool_rec_new(SAI_POOL_REC_REPLACE, SAI_POOL_NS_CORPUS, sub,
			      strlen(sub), 8 + rsc.list_len);
	if (r) {
		sai_pool_u64_write(saib_pool_rec_data(r), base);
		memcpy(saib_pool_rec_data(r) + 8, rsc.list, rsc.list_len);
		lws_strncpy(r->path, path, sizeof(r->path));
		r->is_replace = 1;
		r->replace_base = base;
		saib_pool_queue(sc->ps, r);
	}
	free(rsc.list);

	return 0;
}

static void
saib_pool_after_pull(saib_pool_ss_t *ps)
{
	saib_pool_t *pool = ps->pool;
	saib_pool_scan_t sc;
	char path[384];

	ps->pulled = 1;
	pool->last_pull = lws_now_usecs();
	saib_pool_state_save(pool);
	saib_pool_release_waiters(pool, NULL);

	/* offer the server what appeared in corpus/ since the last sync */

	ps->scan_start = (uint64_t)lws_now_secs();
	ps->full_offer = !pool->full_offer ||
			 ps->scan_start - pool->full_offer >
						SAIB_POOL_FULL_OFFER_SECS;

	memset(&sc, 0, sizeof(sc));
	sc.ps = ps;
	sc.ns = SAI_POOL_NS_CORPUS;
	if (!ps->full_offer && pool->offer_since > SAIB_POOL_OFFER_SLACK_SECS)
		sc.since = pool->offer_since - SAIB_POOL_OFFER_SLACK_SECS;
	sc.list = malloc(SAI_POOL_OFFER_MAX);
	if (sc.list) {
		lws_snprintf(path, sizeof(path), "%s/corpus", pool->dir);
		lws_dir(path, &sc, saib_pool_scan_sub_cb);
		saib_pool_offer_flush(&sc);
		free(sc.list);
	}

	/* send everything in findings/, deleting each once it's stored */

	memset(&sc, 0, sizeof(sc));
	sc.ps = ps;
	sc.ns = SAI_POOL_NS_FINDINGS;
	lws_snprintf(path, sizeof(path), "%s/findings", pool->dir);
	lws_dir(path, &sc, saib_pool_scan_sub_cb);

	/* any replacing tasks asked for */

	memset(&sc, 0, sizeof(sc));
	sc.ps = ps;
	lws_snprintf(path, sizeof(path), "%s/corpus", pool->dir);
	lws_dir(path, &sc, saib_pool_replace_marker_cb);
}

/*
 * Rx side of a sync
 */

static int
saib_pool_entry(saib_pool_t *pool, const sai_pool_rec_hdr_t *h,
		const char *name, const uint8_t *data)
{
	char path[384], dir[384], tmp[384];
	const char *sl = memchr(name, '/', h->name_len);

	if ((h->ns != SAI_POOL_NS_CORPUS && h->ns != SAI_POOL_NS_KNOWN) ||
	    !sai_pool_entry_name_ok(h->ns, name, h->name_len))
		return -1;

	lws_snprintf(dir, sizeof(dir), "%s/%s/%.*s", pool->dir, ns_dir[h->ns],
		     (int)lws_ptr_diff(sl, name), name);
	lws_snprintf(path, sizeof(path), "%s/%s/%.*s", pool->dir,
		     ns_dir[h->ns], (int)h->name_len, name);

	if (h->type == SAI_POOL_REC_DEAD) {
		unlink(path);
		return 0;
	}

	/* the server checked, but it's going in a file with that name */
	if (!sai_pool_content_matches(data, h->len, sl + 1)) {
		lwsl_err("%s: content isn't %s\n", __func__, path);
		return -1;
	}

	if (mkdir(dir, 0755) && errno != EEXIST)
		return -1;

	lws_snprintf(tmp, sizeof(tmp), "%s/.sai-tmp", pool->dir);

	return saib_pool_write_file(tmp, path, data, h->len);
}

static int
saib_pool_ack(saib_pool_ss_t *ps, const char *name, size_t name_len)
{
	saib_pool_t *pool = ps->pool;
	saib_pool_rec_t *r;

	if (!ps->acks.head)
		return -1;

	/* the server answers in order */

	r = lws_container_of(ps->acks.head, saib_pool_rec_t, list);
	if (strlen(r->name) != name_len || memcmp(r->name, name, name_len)) {
		lwsl_err("%s: ACK for %.*s, expected %s\n", __func__,
			 (int)name_len, name, r->name);
		return -1;
	}
	lws_dll2_remove(&r->list);

	if (r->path[0])
		/* a finding it has now, or a replace marker it's dealt with */
		unlink(r->path);

	if (r->is_replace) {
		/*
		 * Go back to where the replacing task started from, so we
		 * hear about what the server removed and what anyone added
		 * meanwhile, which the replace may have lost locally
		 */
		if (pool->cursor[SAI_POOL_NS_CORPUS] > r->replace_base)
			pool->cursor[SAI_POOL_NS_CORPUS] = r->replace_base;
		saib_pool_state_save(pool);
	}

	free(r);

	return 0;
}

static int
saib_pool_record(saib_pool_ss_t *ps, const sai_pool_rec_hdr_t *h,
		 const char *name, const uint8_t *data)
{
	saib_pool_t *pool = ps->pool;
	const char *p, *end;

	switch (h->type) {
	case SAI_POOL_REC_ENTRY:
	case SAI_POOL_REC_DEAD:
		return saib_pool_entry(pool, h, name, data);

	case SAI_POOL_REC_PULL_END:
		if (h->ns > SAI_POOL_NS_KNOWN || h->len != 8 || !ps->pulls_left)
			return -1;
		pool->cursor[h->ns] = sai_pool_u64_read(data);
		if (!--ps->pulls_left)
			saib_pool_after_pull(ps);
		return 0;

	case SAI_POOL_REC_WANT:
		if (h->ns != SAI_POOL_NS_CORPUS || !ps->offers_left)
			return -1;
		ps->offers_left--;

		p = (const char *)data;
		end = p + h->len;
		while (p < end) {
			const char *nl = memchr(p, '\n',
						lws_ptr_diff_size_t(end, p)),
				   *e = nl ? nl : end;
			size_t l = lws_ptr_diff_size_t(e, p);
			saib_pool_put_t *pp;

			if (l && sai_pool_entry_name_ok(SAI_POOL_NS_CORPUS, p, l)) {
				pp = lwsac_use_zero(&ps->ac_puts, sizeof(*pp),
						    8192);
				if (!pp)
					return -1;
				lws_strnncpy(pp->name, p, l, sizeof(pp->name));
				lws_dll2_add_tail(&pp->list, &ps->puts);
			}
			p = e + 1;
		}
		if (ps->puts.count && lws_ss_request_tx(ps->ss))
			return -1;
		return 0;

	case SAI_POOL_REC_ACK:
		return saib_pool_ack(ps, name, h->name_len);
	}

	lwsl_err("%s: unexpected record type 0x%x\n", __func__, h->type);

	return -1;
}

static lws_ss_state_return_t
saib_pool_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	saib_pool_ss_t *ps = (saib_pool_ss_t *)userobj;
	sai_pool_rec_hdr_t h;
	size_t ofs = 0, need;

	if (ps->rxb_len + len > ps->rxb_alloc) {
		size_t na = ps->rxb_len + len + 4096;
		uint8_t *nb;

		if (na > SAI_POOL_ENTRY_MAX + SAI_POOL_OFFER_MAX + 65536)
			return LWSSSSRET_DESTROY_ME;
		nb = realloc(ps->rxb, na);
		if (!nb)
			return LWSSSSRET_DESTROY_ME;
		ps->rxb = nb;
		ps->rxb_alloc = na;
	}

	memcpy(ps->rxb + ps->rxb_len, buf, len);
	ps->rxb_len += len;

	while (ps->rxb_len - ofs >= SAI_POOL_REC_HDR_LEN) {
		sai_pool_rec_hdr_read(ps->rxb + ofs, &h);

		if (h.ns >= SAI_POOL_NS_COUNT ||
		    h.name_len > SAI_POOL_REC_NAME_MAX ||
		    h.len > sai_pool_rec_max(h.ns, h.type)) {
			lwsl_err("%s: bad record from server\n", __func__);
			return LWSSSSRET_DESTROY_ME;
		}

		need = SAI_POOL_REC_HDR_LEN + h.name_len + h.len;
		if (ps->rxb_len - ofs < need)
			break;

		if (saib_pool_record(ps, &h, (const char *)ps->rxb + ofs +
					SAI_POOL_REC_HDR_LEN,
				     ps->rxb + ofs + SAI_POOL_REC_HDR_LEN +
					h.name_len))
			return LWSSSSRET_DESTROY_ME;

		ofs += need;
	}

	if (ofs) {
		memmove(ps->rxb, ps->rxb + ofs, ps->rxb_len - ofs);
		ps->rxb_len -= ofs;
	}

	if (saib_pool_session_idle(ps)) {
		/* everything done, a successful sync */
		ps->pool->offer_since = ps->scan_start;
		if (ps->full_offer)
			ps->pool->full_offer = ps->scan_start;
		saib_pool_state_save(ps->pool);
		ps->done = 1;

		return lws_ss_request_tx(ps->ss);
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_pool_state(void *userobj, void *sh, lws_ss_constate_t state,
		lws_ss_tx_ordinal_t ack)
{
	saib_pool_ss_t *ps = (saib_pool_ss_t *)userobj;
	saib_pool_t *pool;
	saib_pool_rec_t *r;
	uint8_t since[8];
	int ns;

	switch (state) {
	case LWSSSCS_CREATING:
		ps->pool = (saib_pool_t *)ps->opaque_data;
		break;

	case LWSSSCS_CONNECTED:
		/* pull what happened since last time, in both namespaces */
		for (ns = SAI_POOL_NS_CORPUS; ns <= SAI_POOL_NS_KNOWN; ns++) {
			sai_pool_u64_write(since, ps->pool->cursor[ns]);
			r = saib_pool_rec_new(SAI_POOL_REC_PULL, ns, NULL, 0, 8);
			if (!r)
				return LWSSSSRET_DESTROY_ME;
			memcpy(saib_pool_rec_data(r), since, 8);
			lws_dll2_add_tail(&r->list, &ps->txq);
			ps->pulls_left++;
		}
		return lws_ss_request_tx(ps->ss);

	case LWSSSCS_DISCONNECTED:
	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_TIMEOUT:
		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_DESTROYING:
		pool = ps->pool;

		saib_pool_free_list(&ps->txq);
		saib_pool_free_list(&ps->acks);
		lws_dll2_owner_clear(&ps->puts);
		lwsac_free(&ps->ac_puts);
		free(ps->rxb);

		if (!pool)
			break;

		pool->ss = NULL;
		lws_sul_cancel(&pool->sul_session);

		if (!ps->done)
			lwsl_warn("%s: pool %s sync didn't complete\n",
				  __func__, pool->name);

		if (pool->waiters.count)
			/* nothing more is coming for them this time */
			saib_pool_release_waiters(pool,
					"couldn't sync with the server");

		/* decide when we sync next, if at all */

		if (pool->resync) {
			pool->resync = 0;
			lws_sul_schedule(builder.context, 0, &pool->sul_sync,
					 saib_pool_sync_cb, 1);
		} else
			if (pool->users)
				lws_sul_schedule(builder.context, 0,
						 &pool->sul_sync,
						 saib_pool_sync_cb,
						 SAIB_POOL_SYNC_INTERVAL_US);
			else
				if (!ps->done &&
				    ++pool->final_tries < SAIB_POOL_FINAL_TRIES)
					/* the last one after the task failed */
					lws_sul_schedule(builder.context, 0,
						&pool->sul_sync,
						saib_pool_sync_cb,
						SAIB_POOL_SYNC_INTERVAL_US);

		saib_reassess_idle_situation();
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

const lws_ss_info_t ssi_sai_pool = {
	.handle_offset			= offsetof(saib_pool_ss_t, ss),
	.opaque_user_data_offset	= offsetof(saib_pool_ss_t, opaque_data),
	.rx				= saib_pool_rx,
	.tx				= saib_pool_tx,
	.state				= saib_pool_state,
	.user_alloc			= sizeof(saib_pool_ss_t),
	.streamtype			= "sai_pool"
};

static void
saib_pool_sync_start(saib_pool_t *pool)
{
	lws_sul_cancel(&pool->sul_sync);

	if (pool->ss) {
		/* one at a time, but have another go after this one */
		pool->resync = 1;
		return;
	}

	if (!pool->spm || !pool->spm->url || !pool->task_uuid[0])
		return;

	if (lws_ss_create(builder.context, 0, &ssi_sai_pool, pool, &pool->ss,
			  NULL, NULL)) {
		lwsl_err("%s: unable to create pool sync stream\n", __func__);
		pool->ss = NULL;
		if (pool->users)
			lws_sul_schedule(builder.context, 0, &pool->sul_sync,
					 saib_pool_sync_cb,
					 SAIB_POOL_SYNC_INTERVAL_US);
		saib_pool_release_waiters(pool, "couldn't start syncing");
		return;
	}

	if (lws_ss_set_metadata(pool->ss, "url", pool->spm->url,
				strlen(pool->spm->url)))
		lwsl_warn("%s: unable to set metadata\n", __func__);

	lws_sul_schedule(builder.context, 0, &pool->sul_session,
			 saib_pool_session_timeout_cb, SAIB_POOL_SESSION_MAX_US);

	if (lws_ss_client_connect(pool->ss))
		lwsl_warn("%s: connect failed\n", __func__);
}

/*
 * The task running in this nspawn names a pool: find or create our copy of
 * it, and account for the nspawn using it
 */

int
saib_pool_attach(struct sai_nspawn *ns)
{
	char path[300], pur[160], *p;
	saib_pool_t *pool = NULL;
	int n;

	if (!ns->task->pool[0] || ns->task->build_step < 2)
		/* nothing to sync, or it's just git steps */
		return 0;

	if (!sai_pool_name_ok(ns->task->pool)) {
		saib_task_logf(ns->spm, ns, NULL, "Ignoring bad pool name");
		return 0;
	}

	/* one copy per server, repo and pool */

	lws_snprintf(pur, sizeof(pur), "%s-%s-%s", ns->spm->name,
		     ns->task->repo_name, ns->task->pool);
	lws_filename_purify_inplace(pur);
	p = pur;
	while ((p = strchr(p, '/')))
		*p++ = '_';

	lws_start_foreach_dll(struct lws_dll2 *, d, builder.pool_owner.head) {
		saib_pool_t *xp = lws_container_of(d, saib_pool_t, list);

		if (!strcmp(xp->key, pur)) {
			pool = xp;
			break;
		}

	} lws_end_foreach_dll(d);

	if (!pool) {
		pool = malloc(sizeof(*pool));
		if (!pool)
			return -1;
		memset(pool, 0, sizeof(*pool));

		lws_strncpy(pool->name, ns->task->pool, sizeof(pool->name));
		lws_strncpy(pool->key, pur, sizeof(pool->key));
		lws_snprintf(pool->dir, sizeof(pool->dir), "%s/pools/%s",
			     builder.home, pur);

		lws_snprintf(path, sizeof(path), "%s/pools", builder.home);
		if (mkdir(path, 0755) && errno != EEXIST)
			goto bail;
		if (mkdir(pool->dir, 0755) && errno != EEXIST)
			goto bail;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(ns_dir); n++) {
			lws_snprintf(path, sizeof(path), "%s/%s", pool->dir,
				     ns_dir[n]);
			if (mkdir(path, 0755) && errno != EEXIST)
				goto bail;
		}

		saib_pool_state_load(pool);
		lws_dll2_add_tail(&pool->list, &builder.pool_owner);
	}

	/* the latest task to use it is who we sync on behalf of */

	pool->spm = ns->spm;
	lws_strncpy(pool->task_uuid, ns->task->uuid, sizeof(pool->task_uuid));
	lws_strncpy(pool->nonce, ns->task->art_up_nonce, sizeof(pool->nonce));
	pool->final_tries = 0;

	ns->pool = pool;
	if (!pool->users++ && !pool->ss && !pool->sul_sync.list.owner)
		lws_sul_schedule(builder.context, 0, &pool->sul_sync,
				 saib_pool_sync_cb, SAIB_POOL_SYNC_INTERVAL_US);

	return 0;

bail:
	saib_task_logf(ns->spm, ns, NULL, "Unable to create pool dir %s: "
		       "errno %d", pool->dir, errno);
	free(pool);

	return -1;
}

/*
 * The step would like to start: if its pool hasn't been pulled lately, it
 * waits for that.  Returns 1 if the step was deferred, and will be spawned
 * when the pull is done or given up on.
 */

int
saib_pool_defer_spawn(struct sai_nspawn *ns)
{
	saib_pool_t *pool = ns->pool;

	if (!pool || (pool->last_pull &&
		      lws_now_usecs() - pool->last_pull < SAIB_POOL_PULL_FRESH_US))
		return 0;

	saib_task_logf(ns->spm, ns, NULL, "Syncing pool %s before starting",
		       pool->name);

	lws_dll2_add_tail(&ns->pool_wait_list, &pool->waiters);
	if (!pool->sul_wait.list.owner)
		lws_sul_schedule(builder.context, 0, &pool->sul_wait,
				 saib_pool_wait_timeout_cb,
				 SAIB_POOL_WAIT_MAX_US);

	/*
	 * If a sync is already going, it hasn't pulled yet (or the pull would
	 * be fresh), so its pull releases us too
	 */
	if (!pool->ss)
		saib_pool_sync_start(pool);

	return 1;
}

/*
 * The nspawn is being stopped while it waits for its pool: it never started,
 * so it has to be failed here.  Returns 1 if it was waiting.
 */

int
saib_pool_waiter_abort(struct sai_nspawn *ns)
{
	if (lws_dll2_is_detached(&ns->pool_wait_list))
		return 0;

	lws_dll2_remove(&ns->pool_wait_list);
	saib_set_ns_state(ns, NSSTATE_FAILED);
	if (!ns->idle_yield)
		ns->retcode = SAISPRF_TERMINATED;

	return 1;
}

/* the nspawn is done with the pool, sync what it left there */

void
saib_pool_detach(struct sai_nspawn *ns)
{
	saib_pool_t *pool = ns->pool;

	if (!pool)
		return;

	lws_dll2_remove(&ns->pool_wait_list);
	ns->pool = NULL;

	if (--pool->users)
		return;

	lws_sul_cancel(&pool->sul_sync);
	saib_pool_sync_start(pool);
}

/* what the task is told about its pool */

void
saib_pool_env(struct sai_nspawn *ns, char *buf, size_t len)
{
	saib_pool_t *pool = ns->pool;

	buf[0] = '\0';
	if (!pool)
		return;

	lws_snprintf(buf, len,
#if defined(WIN32)
		     "set SAI_POOL_DIR=%s\\corpus\n"
		     "set SAI_POOL_KNOWN=%s\\known\n"
		     "set SAI_POOL_FINDINGS=%s\\findings\n",
#else
		     "export SAI_POOL_DIR=%s/corpus\n"
		     "export SAI_POOL_KNOWN=%s/known\n"
		     "export SAI_POOL_FINDINGS=%s/findings\n",
#endif
		     pool->dir, pool->dir, pool->dir);
}

/* are we still syncing, or about to, so we shouldn't power off yet? */

int
saib_pool_busy(void)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, builder.pool_owner.head) {
		saib_pool_t *pool = lws_container_of(d, saib_pool_t, list);

		if (pool->ss || (!pool->users && pool->sul_sync.list.owner))
			return 1;

	} lws_end_foreach_dll(d);

	return 0;
}

void
saib_pool_destroy_all(void)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   builder.pool_owner.head) {
		saib_pool_t *pool = lws_container_of(d, saib_pool_t, list);

		lws_sul_cancel(&pool->sul_sync);
		lws_sul_cancel(&pool->sul_wait);
		lws_sul_cancel(&pool->sul_session);
		if (pool->ss) {
			/* its DESTROYING mustn't touch the pool after this */
			saib_pool_ss_t *ps = lws_ss_to_user_object(pool->ss);

			ps->pool = NULL;
			lws_ss_destroy(&pool->ss);
		}
		lws_dll2_remove(&pool->list);
		free(pool);

	} lws_end_foreach_dll_safe(d, d1);
}
