/*
 * Sai server - ./src/server/s-pool.c
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
 * Pools, server side: see READMEs/README-pool.md
 *
 * Each repo's pool lives in its own sqlite db, as entries in an append-only
 * log: every entry added, or removed, gets the next sequence number, so a
 * builder only has to ask for what happened after the last sequence number it
 * saw.  Removed entries leave a "dead" row behind to tell builders about it.
 * Findings builders send go in their own table.
 *
 * A pool sync connection arrives on /builder like any other, proves the link
 * key, then sends a JSON hello naming a task and its artifact upload nonce.
 * The task decides the repo and pool, so a builder can only sync the pool of
 * a task it was given.  After that it's binary records both ways.
 */

#include <libwebsockets.h>
#include <string.h>

#include "s-private.h"

/* past this many live entries, a pool takes no more */
#define SAIS_POOL_ENTRIES_MAX		(2 * 1000 * 1000)
/* we queue pulled entries for sending until there's this much waiting */
#define SAIS_POOL_TX_HIGHWATER		(256 * 1024)
/* the most we send in one ws message */
#define SAIS_POOL_TX_CHUNK		(64 * 1024)

typedef struct sais_pool_db {
	lws_dll2_t		list;		/* vhd->pool_dbs */
	sqlite3			*pdb;
	int			refcount;
	unsigned int		live;		/* live entries */
	char			key[128];	/* "<repo>/<pool>" */
} sais_pool_db_t;

struct sais_pool_session {
	sais_pool_db_t		*db;

	struct lws_buflist	*tx;		/* records waiting to go */
	uint8_t			*txb;		/* LWS_PRE + chunk */

	uint8_t			*rxb;		/* partial incoming record(s) */
	size_t			rxb_len;
	size_t			rxb_alloc;

	/* pulls going on, per content addressed ns: from pos up to end */
	uint64_t		pull_pos[2];
	uint64_t		pull_end[2];
	char			pulling[2];

	char			task_uuid[65];
};

static const char * const pool_schema[] = {
	"CREATE TABLE IF NOT EXISTS entries ("
		"seq INTEGER PRIMARY KEY AUTOINCREMENT, "
		"ns INTEGER NOT NULL, "
		"sub VARCHAR(32) NOT NULL, "
		"name VARCHAR(64) NOT NULL, "
		"len INTEGER, "
		"dead INTEGER NOT NULL DEFAULT 0, "
		"added INTEGER, "
		"blob BLOB, "
		"UNIQUE(ns, sub, name));",
	"CREATE INDEX IF NOT EXISTS idx_entries_ns_seq ON entries(ns, seq);",
	"CREATE TABLE IF NOT EXISTS findings ("
		"uid INTEGER PRIMARY KEY AUTOINCREMENT, "
		"sub VARCHAR(32) NOT NULL, "
		"name VARCHAR(64) NOT NULL, "
		"len INTEGER, "
		"received INTEGER, "
		"task_uuid VARCHAR(65), "
		"peer VARCHAR(48), "
		"blob BLOB, "
		"UNIQUE(sub, name));",
	"PRAGMA journal_mode=WAL;",
};

static sais_pool_db_t *
sais_pool_db_get(struct vhd *vhd, const char *repo, const char *pool)
{
	char key[128], fn[256], saf[128], *p;
	sais_pool_db_t *db;
	sqlite3_stmt *sm;
	size_t n;

	lws_snprintf(key, sizeof(key), "%s/%s", repo, pool);

	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->pool_dbs.head) {
		db = lws_container_of(d, sais_pool_db_t, list);

		if (!strcmp(db->key, key)) {
			db->refcount++;
			return db;
		}

	} lws_end_foreach_dll(d);

	/* the repo name was checked at hook intake, but it's going in a path */

	lws_snprintf(saf, sizeof(saf), "%s-%s", repo, pool);
	lws_filename_purify_inplace(saf);
	p = saf;
	while ((p = strchr(p, '/')))
		*p++ = '_';

	lws_snprintf(fn, sizeof(fn), "%s-pool-%s.sqlite3",
		     vhd->sqlite3_path_lhs, saf);

	db = malloc(sizeof(*db));
	if (!db)
		return NULL;
	memset(db, 0, sizeof(*db));
	lws_strncpy(db->key, key, sizeof(db->key));

	if (sqlite3_open_v2(fn, &db->pdb, SQLITE_OPEN_READWRITE |
					  SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
		lwsl_err("%s: unable to open %s\n", __func__, fn);
		sqlite3_close(db->pdb);
		free(db);
		return NULL;
	}

	sqlite3_busy_timeout(db->pdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);

	for (n = 0; n < LWS_ARRAY_SIZE(pool_schema); n++)
		if (sai_sqlite3_statement(db->pdb, pool_schema[n],
					  "pool schema")) {
			sqlite3_close(db->pdb);
			free(db);
			return NULL;
		}

	if (sqlite3_prepare_v2(db->pdb, "SELECT count(*) FROM entries WHERE "
			       "dead = 0", -1, &sm, NULL) == SQLITE_OK) {
		if (sqlite3_step(sm) == SQLITE_ROW)
			db->live = (unsigned int)sqlite3_column_int(sm, 0);
		sqlite3_finalize(sm);
	}

	db->refcount = 1;
	lws_dll2_add_tail(&db->list, &vhd->pool_dbs);

	lwsl_notice("%s: opened pool %s, %u entries\n", __func__, key, db->live);

	return db;
}

static void
sais_pool_db_put(sais_pool_db_t *db)
{
	if (--db->refcount)
		return;

	lws_dll2_remove(&db->list);
	sqlite3_close(db->pdb);
	free(db);
}

/* the newest sequence number, ie, what a pull started now goes up to */

static uint64_t
sais_pool_seq_now(sais_pool_db_t *db)
{
	sqlite3_stmt *sm;
	uint64_t v = 0;

	if (sqlite3_prepare_v2(db->pdb, "SELECT max(seq) FROM entries", -1,
			       &sm, NULL) != SQLITE_OK)
		return 0;
	if (sqlite3_step(sm) == SQLITE_ROW)
		v = (uint64_t)sqlite3_column_int64(sm, 0);
	sqlite3_finalize(sm);

	return v;
}

/* 1 = live, 0 = never seen or dead, -1 = error */

static int
sais_pool_live(sais_pool_db_t *db, int ns, const char *sub, size_t sub_len,
	       const char *name, size_t name_len)
{
	sqlite3_stmt *sm;
	int r = 0;

	if (sqlite3_prepare_v2(db->pdb, "SELECT 1 FROM entries WHERE ns = ? "
			       "AND sub = ? AND name = ? AND dead = 0", -1,
			       &sm, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_int(sm, 1, ns);
	sqlite3_bind_text(sm, 2, sub, (int)sub_len, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 3, name, (int)name_len, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW)
		r = 1;
	sqlite3_finalize(sm);

	return r;
}

/*
 * (Re)write the entry as the newest thing in the log: any older row for it,
 * dead or alive, goes, so the entry appears again with a new sequence number
 * and builders hear about it on their next pull.  blob NULL means make it a
 * dead entry.
 */

static int
sais_pool_log_entry(sais_pool_db_t *db, int ns, const char *sub,
		    size_t sub_len, const char *name, size_t name_len,
		    const uint8_t *blob, size_t len)
{
	sqlite3_stmt *sm;
	int r;

	if (sqlite3_prepare_v2(db->pdb, "DELETE FROM entries WHERE ns = ? AND "
			       "sub = ? AND name = ?", -1, &sm, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int(sm, 1, ns);
	sqlite3_bind_text(sm, 2, sub, (int)sub_len, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 3, name, (int)name_len, SQLITE_TRANSIENT);
	r = sqlite3_step(sm);
	sqlite3_finalize(sm);
	if (r != SQLITE_DONE)
		return -1;

	if (sqlite3_prepare_v2(db->pdb, "INSERT INTO entries (ns, sub, name, "
			       "len, dead, added, blob) VALUES (?,?,?,?,?,?,?)",
			       -1, &sm, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int(sm, 1, ns);
	sqlite3_bind_text(sm, 2, sub, (int)sub_len, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 3, name, (int)name_len, SQLITE_TRANSIENT);
	sqlite3_bind_int64(sm, 4, (sqlite3_int64)len);
	sqlite3_bind_int(sm, 5, !blob);
	sqlite3_bind_int64(sm, 6, (sqlite3_int64)lws_now_secs());
	if (blob)
		sqlite3_bind_blob(sm, 7, blob, (int)len, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(sm, 7);
	r = sqlite3_step(sm);
	sqlite3_finalize(sm);

	return r == SQLITE_DONE ? 0 : -1;
}

/* queue a record to go to the builder */

static int
sais_pool_queue(struct pss *pss, int type, int ns, const char *name,
		size_t name_len, const uint8_t *data, size_t len)
{
	sais_pool_session_t *ps = pss->pool;
	uint8_t hdr[SAI_POOL_REC_HDR_LEN];

	sai_pool_rec_hdr_write(hdr, type, ns, name_len, len);

	if (lws_buflist_append_segment(&ps->tx, hdr, sizeof(hdr)) < 0 ||
	    (name_len && lws_buflist_append_segment(&ps->tx,
				(const uint8_t *)name, name_len) < 0) ||
	    (len && lws_buflist_append_segment(&ps->tx, data, len) < 0)) {
		lwsl_err("%s: tx OOM\n", __func__);
		return -1;
	}

	lws_callback_on_writable(pss->wsi);

	return 0;
}

/*
 * The builder offered us names it has in a content addressed ns... tell it
 * which ones we want it to send
 */

static int
sais_pool_offer(struct pss *pss, int ns, const uint8_t *data, size_t len)
{
	sais_pool_db_t *db = pss->pool->db;
	const char *p = (const char *)data, *end = p + len;
	uint8_t *want;
	size_t wl = 0;
	int r;

	want = malloc(len + 1);
	if (!want)
		return -1;

	while (p < end) {
		const char *nl = memchr(p, '\n', lws_ptr_diff_size_t(end, p)),
			   *e = nl ? nl : end, *sl;
		size_t l = lws_ptr_diff_size_t(e, p);

		if (l && sai_pool_entry_name_ok(ns, p, l)) {
			sl = memchr(p, '/', l);
			if (sais_pool_live(db, ns, p, lws_ptr_diff_size_t(sl, p),
					   sl + 1,
					   l - lws_ptr_diff_size_t(sl, p) - 1) == 0) {
				memcpy(want + wl, p, l);
				wl += l;
				want[wl++] = '\n';
			}
		}

		p = e + 1;
	}

	r = sais_pool_queue(pss, SAI_POOL_REC_WANT, ns, NULL, 0, want, wl);
	free(want);

	return r;
}

static int
sais_pool_put(struct pss *pss, int ns, const char *name, size_t name_len,
	      const uint8_t *data, size_t len)
{
	sais_pool_session_t *ps = pss->pool;
	const char *sl = memchr(name, '/', name_len);
	size_t sub_len = lws_ptr_diff_size_t(sl, name);
	sqlite3_stmt *sm;
	int r;

	if (ns == SAI_POOL_NS_FINDINGS) {
		if (sqlite3_prepare_v2(ps->db->pdb, "INSERT OR IGNORE INTO "
				"findings (sub, name, len, received, "
				"task_uuid, peer, blob) VALUES (?,?,?,?,?,?,?)",
				-1, &sm, NULL) != SQLITE_OK)
			return -1;
		sqlite3_bind_text(sm, 1, name, (int)sub_len, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 2, sl + 1, (int)(name_len - sub_len - 1),
				  SQLITE_TRANSIENT);
		sqlite3_bind_int64(sm, 3, (sqlite3_int64)len);
		sqlite3_bind_int64(sm, 4, (sqlite3_int64)lws_now_secs());
		sqlite3_bind_text(sm, 5, ps->task_uuid, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 6, pss->peer_ip, -1, SQLITE_TRANSIENT);
		sqlite3_bind_blob(sm, 7, data, (int)len, SQLITE_TRANSIENT);
		r = sqlite3_step(sm);
		sqlite3_finalize(sm);
		if (r != SQLITE_DONE)
			return -1;

		lwsl_notice("%s: %s: finding %.*s from %s\n", __func__,
			    ps->db->key, (int)name_len, name, pss->peer_ip);

		goto ack;
	}

	/* the corpus is content addressed, so we can check it's really that */

	if (!sai_pool_content_matches(data, len, sl + 1)) {
		lwsl_notice("%s: %s: content isn't %.*s\n", __func__,
			    ps->db->key, (int)name_len, name);
		return -1;
	}

	r = sais_pool_live(ps->db, ns, name, sub_len, sl + 1,
			   name_len - sub_len - 1);
	if (r < 0)
		return -1;
	if (!r) {
		if (ps->db->live >= SAIS_POOL_ENTRIES_MAX) {
			lwsl_warn("%s: %s: full, dropping %.*s\n", __func__,
				  ps->db->key, (int)name_len, name);
			goto ack;
		}

		if (sais_pool_log_entry(ps->db, ns, name, sub_len, sl + 1,
					name_len - sub_len - 1, data, len))
			return -1;
		ps->db->live++;
	}

ack:
	return sais_pool_queue(pss, SAI_POOL_REC_ACK, ns, name, name_len,
			       NULL, 0);
}

/*
 * The builder replaced the set of entries in a sub, eg, after minimizing a
 * corpus: it tells us the sequence number it had pulled up to when it began,
 * and the names it's keeping.  Entries up to then that aren't on the list are
 * removed.  Anything added since then, by anyone, stays: they didn't know
 * about it.
 */

static int
sais_pool_replace(struct pss *pss, int ns, const char *sub, size_t sub_len,
		  const uint8_t *data, size_t len)
{
	sais_pool_db_t *db = pss->pool->db;
	const char *p = (const char *)data + 8, *end = (const char *)data + len;
	uint64_t base = sai_pool_u64_read(data);
	struct lwsac *ac = NULL;
	lws_dll2_owner_t owner;
	unsigned int dropped = 0;
	sqlite3_stmt *sm;
	int r = -1;

	typedef struct {
		lws_dll2_t	list;
		char		name[41];
	} gone_t;

	lws_dll2_owner_clear(&owner);

	if (sai_sqlite3_statement(db->pdb, "CREATE TEMP TABLE IF NOT EXISTS "
				  "keep (name VARCHAR(64) PRIMARY KEY)",
				  "pool keep") ||
	    sai_sqlite3_statement(db->pdb, "DELETE FROM keep", "pool keep"))
		return -1;

	if (sqlite3_prepare_v2(db->pdb, "INSERT OR IGNORE INTO keep VALUES "
			       "(?)", -1, &sm, NULL) != SQLITE_OK)
		return -1;

	sai_sqlite3_statement(db->pdb, "BEGIN", "pool replace");

	while (p < end) {
		const char *nl = memchr(p, '\n', lws_ptr_diff_size_t(end, p)),
			   *e = nl ? nl : end;
		size_t l = lws_ptr_diff_size_t(e, p);

		if (l == 40) {
			sqlite3_bind_text(sm, 1, p, 40, SQLITE_TRANSIENT);
			/*
			 * A name that didn't make it onto the keep list would
			 * get removed below
			 */
			if (sqlite3_step(sm) != SQLITE_DONE) {
				lwsl_err("%s: %s: unable to keep %.40s: %s\n",
					 __func__, db->key, p,
					 sqlite3_errmsg(db->pdb));
				sqlite3_finalize(sm);
				goto bail;
			}
			sqlite3_reset(sm);
		}
		p = e + 1;
	}
	sqlite3_finalize(sm);

	/* collect first, we're going to be rewriting the rows */

	if (sqlite3_prepare_v2(db->pdb, "SELECT name FROM entries WHERE ns = ? "
			       "AND sub = ? AND dead = 0 AND seq <= ? AND "
			       "name NOT IN (SELECT name FROM keep)", -1, &sm,
			       NULL) != SQLITE_OK)
		goto bail;
	sqlite3_bind_int(sm, 1, ns);
	sqlite3_bind_text(sm, 2, sub, (int)sub_len, SQLITE_TRANSIENT);
	sqlite3_bind_int64(sm, 3, (sqlite3_int64)base);
	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *n = (const char *)sqlite3_column_text(sm, 0);
		gone_t *g;

		if (!n)
			continue;
		g = lwsac_use_zero(&ac, sizeof(*g), 16384);
		if (!g)
			break;
		lws_strncpy(g->name, n, sizeof(g->name));
		lws_dll2_add_tail(&g->list, &owner);
	}
	sqlite3_finalize(sm);

	lws_start_foreach_dll(struct lws_dll2 *, d, owner.head) {
		gone_t *g = lws_container_of(d, gone_t, list);

		if (sais_pool_log_entry(db, ns, sub, sub_len, g->name,
					strlen(g->name), NULL, 0))
			goto bail;
		dropped++;

	} lws_end_foreach_dll(d);

	db->live = db->live > dropped ? db->live - dropped : 0;
	r = 0;

bail:
	sai_sqlite3_statement(db->pdb, r ? "ROLLBACK" : "COMMIT",
			      "pool replace");
	lwsac_free(&ac);

	if (r)
		return r;

	lwsl_notice("%s: %s: replaced %.*s up to %llu, %u removed\n", __func__,
		    db->key, (int)sub_len, sub, (unsigned long long)base,
		    dropped);

	return sais_pool_queue(pss, SAI_POOL_REC_ACK, ns, sub, sub_len,
			       NULL, 0);
}

/* one whole record from the builder: 0 if OK, -1 to drop the connection */

static int
sais_pool_record(struct pss *pss, const sai_pool_rec_hdr_t *h,
		 const char *name, const uint8_t *data)
{
	sais_pool_session_t *ps = pss->pool;

	switch (h->type) {
	case SAI_POOL_REC_PULL:
		if (h->ns > SAI_POOL_NS_KNOWN || h->len != 8 || h->name_len)
			return -1;
		ps->pull_pos[h->ns] = sai_pool_u64_read(data);
		ps->pull_end[h->ns] = sais_pool_seq_now(ps->db);
		ps->pulling[h->ns] = 1;
		lws_callback_on_writable(pss->wsi);
		return 0;

	case SAI_POOL_REC_OFFER:
		if (h->ns != SAI_POOL_NS_CORPUS || h->name_len)
			return -1;
		return sais_pool_offer(pss, h->ns, data, h->len);

	case SAI_POOL_REC_PUT:
		if ((h->ns != SAI_POOL_NS_CORPUS &&
		     h->ns != SAI_POOL_NS_FINDINGS) ||
		    !sai_pool_entry_name_ok(h->ns, name, h->name_len))
			return -1;
		return sais_pool_put(pss, h->ns, name, h->name_len, data,
				     h->len);

	case SAI_POOL_REC_REPLACE:
		if (h->ns != SAI_POOL_NS_CORPUS || h->len < 8 ||
		    !sai_pool_sub_ok(name, h->name_len))
			return -1;
		return sais_pool_replace(pss, h->ns, name, h->name_len, data,
					 h->len);
	}

	lwsl_notice("%s: unexpected record type 0x%x\n", __func__, h->type);

	return -1;
}

/*
 * Bytes arrived on an established pool sync connection
 */

int
sais_pool_rx(struct vhd *vhd, struct pss *pss, const uint8_t *buf, size_t len)
{
	sais_pool_session_t *ps = pss->pool;
	sai_pool_rec_hdr_t h;
	size_t ofs = 0, need;

	if (!len)
		return 0;

	if (ps->rxb_len + len > ps->rxb_alloc) {
		size_t na = ps->rxb_len + len + 4096;
		uint8_t *nb;

		if (na > SAI_POOL_LIST_MAX + SAI_POOL_REC_HDR_LEN +
			 SAI_POOL_REC_NAME_MAX + 65536) {
			lwsl_notice("%s: rx too large\n", __func__);
			return -1;
		}
		nb = realloc(ps->rxb, na);
		if (!nb)
			return -1;
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
			lwsl_notice("%s: bad record hdr type 0x%x, ns %u, "
				    "name %u, len %u\n", __func__, h.type,
				    h.ns, h.name_len, h.len);
			return -1;
		}

		need = SAI_POOL_REC_HDR_LEN + h.name_len + h.len;
		if (ps->rxb_len - ofs < need)
			break; /* the rest of it isn't here yet */

		if (sais_pool_record(pss, &h, (const char *)ps->rxb + ofs +
					SAI_POOL_REC_HDR_LEN,
				     ps->rxb + ofs + SAI_POOL_REC_HDR_LEN +
					h.name_len))
			return -1;

		ofs += need;
	}

	if (ofs) {
		memmove(ps->rxb, ps->rxb + ofs, ps->rxb_len - ofs);
		ps->rxb_len -= ofs;
	}

	return 0;
}

/*
 * Queue up the next part of whatever the builder is pulling, as long as there
 * isn't much waiting to go already
 */

static int
sais_pool_pull_more(struct pss *pss)
{
	sais_pool_session_t *ps = pss->pool;
	sqlite3_stmt *sm;
	uint8_t cur[8];
	int ns, n;

	for (ns = 0; ns < 2; ns++) {
		if (!ps->pulling[ns])
			continue;

		if (sqlite3_prepare_v2(ps->db->pdb, "SELECT seq, sub, name, "
				"dead, blob FROM entries WHERE ns = ? AND "
				"seq > ? AND seq <= ? ORDER BY seq LIMIT 64",
				-1, &sm, NULL) != SQLITE_OK)
			return -1;
		sqlite3_bind_int(sm, 1, ns);
		sqlite3_bind_int64(sm, 2, (sqlite3_int64)ps->pull_pos[ns]);
		sqlite3_bind_int64(sm, 3, (sqlite3_int64)ps->pull_end[ns]);

		n = 0;
		while (sqlite3_step(sm) == SQLITE_ROW) {
			const char *sub = (const char *)sqlite3_column_text(sm, 1),
				   *name = (const char *)sqlite3_column_text(sm, 2);
			char nm[SAI_POOL_REC_NAME_MAX];
			int nl;

			n++;
			ps->pull_pos[ns] = (uint64_t)sqlite3_column_int64(sm, 0);
			if (!sub || !name)
				continue;

			nl = lws_snprintf(nm, sizeof(nm), "%s/%s", sub, name);

			if (sqlite3_column_int(sm, 3)) {
				if (sais_pool_queue(pss, SAI_POOL_REC_DEAD, ns,
						    nm, (size_t)nl, NULL, 0))
					goto fail;
			} else
				if (sais_pool_queue(pss, SAI_POOL_REC_ENTRY, ns,
					nm, (size_t)nl,
					sqlite3_column_blob(sm, 4),
					(size_t)sqlite3_column_bytes(sm, 4)))
					goto fail;

			if (lws_buflist_total_len(&ps->tx) >
						SAIS_POOL_TX_HIGHWATER)
				break;
		}
		sqlite3_finalize(sm);

		if (!n) {
			/* nothing left up to where it started */
			sai_pool_u64_write(cur, ps->pull_end[ns]);
			ps->pulling[ns] = 0;
			if (sais_pool_queue(pss, SAI_POOL_REC_PULL_END, ns,
					    NULL, 0, cur, sizeof(cur)))
				return -1;
		}

		/* one ns at a time */
		return 0;
	}

	return 0;

fail:
	sqlite3_finalize(sm);

	return -1;
}

int
sais_pool_tx(struct vhd *vhd, struct pss *pss)
{
	sais_pool_session_t *ps = pss->pool;
	uint8_t *p;
	size_t n;

	if (lws_buflist_total_len(&ps->tx) < SAIS_POOL_TX_HIGHWATER &&
	    sais_pool_pull_more(pss))
		return -1;

	n = lws_buflist_next_segment_len(&ps->tx, &p);
	if (!n)
		return 0;

	/* coalesce what's waiting into one message, up to a chunk */

	n = 0;
	while (n < SAIS_POOL_TX_CHUNK) {
		size_t l = lws_buflist_next_segment_len(&ps->tx, &p);

		if (!l)
			break;
		if (l > SAIS_POOL_TX_CHUNK - n)
			l = SAIS_POOL_TX_CHUNK - n;
		memcpy(ps->txb + LWS_PRE + n, p, l);
		lws_buflist_use_segment(&ps->tx, l);
		n += l;
	}

	if (lws_write(pss->wsi, ps->txb + LWS_PRE, n, LWS_WRITE_BINARY) < (int)n)
		return -1;

	if (lws_buflist_total_len(&ps->tx) || ps->pulling[0] || ps->pulling[1])
		lws_callback_on_writable(pss->wsi);

	return 0;
}

/*
 * A builder connection sent the pool hello: check it's for a real task with
 * a pool that it has the nonce for, and turn the connection into a sync
 * session for the task's repo and pool.  -1 to drop the connection.
 */

int
sais_pool_hello(struct vhd *vhd, struct pss *pss, const sai_pool_hello_t *hello)
{
	char event_uuid[33], esc[96], filt[128], repo[65], pool[33];
	struct lwsac *ac = NULL;
	sais_pool_session_t *ps;
	sqlite3 *pdb = NULL;
	lws_dll2_owner_t o;
	sai_event_t *e;
	sai_task_t *t;
	int n;

	if (pss->pool || sais_validate_id(hello->task_uuid, SAI_TASKID_LEN)) {
		lwsl_notice("%s: bad pool hello\n", __func__);
		return -1;
	}

	sai_task_uuid_to_event_uuid(event_uuid, hello->task_uuid);

	lws_sql_purify(esc, event_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(vhd->server.pdb, filt, NULL,
				       lsm_schema_sq3_map_event, &o, &ac, 0, 1);
	if (n < 0 || !o.head)
		goto bail;
	e = lws_container_of(o.head, sai_event_t, list);
	lws_strncpy(repo, e->repo_name, sizeof(repo));

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		goto bail;

	lws_sql_purify(esc, hello->task_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pdb, filt, "run desc",
				       lsm_schema_sq3_map_task, &o, &ac, 0, 1);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	if (n < 0 || !o.head)
		goto bail;
	t = lws_container_of(o.head, sai_task_t, list);

	/* both fixed 32-char hex in 33-byte arrays */
	if (lws_timingsafe_bcmp(t->art_up_nonce, hello->nonce, 32)) {
		lwsl_notice("%s: pool hello nonce mismatch\n", __func__);
		goto bail;
	}

	if (!sai_pool_name_ok(t->pool) || sai_str_has_shell_metachars(repo)) {
		lwsl_notice("%s: task %s has no usable pool\n", __func__,
			    hello->task_uuid);
		goto bail;
	}
	lws_strncpy(pool, t->pool, sizeof(pool));
	lwsac_free(&ac);

	ps = malloc(sizeof(*ps));
	if (!ps)
		return -1;
	memset(ps, 0, sizeof(*ps));

	ps->txb = malloc(LWS_PRE + SAIS_POOL_TX_CHUNK);
	ps->db = sais_pool_db_get(vhd, repo, pool);
	if (!ps->txb || !ps->db) {
		if (ps->db)
			sais_pool_db_put(ps->db);
		free(ps->txb);
		free(ps);
		return -1;
	}
	lws_strncpy(ps->task_uuid, hello->task_uuid, sizeof(ps->task_uuid));

	pss->pool = ps;

	/*
	 * It's not a builder platform connection: take it off that list, so
	 * nothing meant for builders gets queued on it, and drop anything that
	 * already was
	 */

	lws_dll2_remove(&pss->same);
	lws_dll2_add_tail(&pss->same, &vhd->pool_conns);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   pss->viewer_state_owner.head) {
		lws_dll2_remove(d);
		free(lws_container_of(d, sai_viewer_state_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   pss->task_cancel_owner.head) {
		lws_dll2_remove(d);
		free(lws_container_of(d, sai_cancel_t, list));
	} lws_end_foreach_dll_safe(d, d1);

	lwsl_notice("%s: %s: sync from %s for %s\n", __func__, ps->db->key,
		    pss->peer_ip, ps->task_uuid);

	return 0;

bail:
	lwsac_free(&ac);
	lwsl_notice("%s: refusing pool sync for %s\n", __func__,
		    hello->task_uuid);

	return -1;
}

void
sais_pool_session_destroy(struct pss *pss)
{
	sais_pool_session_t *ps = pss->pool;

	if (!ps)
		return;

	lws_buflist_destroy_all_segments(&ps->tx);
	sais_pool_db_put(ps->db);
	free(ps->txb);
	free(ps->rxb);
	free(ps);
	pss->pool = NULL;
}
