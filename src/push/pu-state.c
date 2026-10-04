/*
 * Sai push - src/push/pu-state.c
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
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
 * For each target branch, the last event promoted to it on the primary
 * remote is remembered in <repo-cache>/sai-push-state.json, so that across
 * restarts too, an event whose notification arrived before that one's is
 * never promoted over it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "pu-private.h"

typedef struct saip_state_entry {
	lws_dll2_t		list;
	char			fetchurl[96];
	char			branch[65];
	char			hash[65];
	char			uuid[65];
	uint64_t		received;
} saip_state_entry_t;

typedef struct saip_state {
	lws_dll2_owner_t	entries; /* saip_state_entry_t */
} saip_state_t;

static const lws_struct_map_t lsm_saip_state_entry[] = {
	LSM_CARRAY	(saip_state_entry_t, fetchurl,		"fetchurl"),
	LSM_CARRAY	(saip_state_entry_t, branch,		"branch"),
	LSM_CARRAY	(saip_state_entry_t, hash,		"hash"),
	LSM_CARRAY	(saip_state_entry_t, uuid,		"uuid"),
	LSM_UNSIGNED	(saip_state_entry_t, received,		"received"),
};

static const lws_struct_map_t lsm_saip_state[] = {
	LSM_LIST	(saip_state_t, entries, saip_state_entry_t, list,
			 NULL, lsm_saip_state_entry,		"promoted"),
};

static const lws_struct_map_t lsm_saip_state_schema[] = {
	LSM_SCHEMA	(saip_state_t, NULL, lsm_saip_state,	"sai-push-state"),
};

static void
saip_state_path(char *buf, size_t len, const char *suffix)
{
	lws_snprintf(buf, len, "%s/sai-push-state.json%s",
		     saip.conf->repo_cache, suffix);
}

int
saip_state_load(void)
{
	unsigned char buf[512];
	lws_struct_args_t a;
	struct lejp_ctx ctx;
	int n, m = LEJP_CONTINUE, fd;
	saip_state_t *st;
	char path[512];

	saip_state_path(path, sizeof(path), "");

	fd = lws_open(path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			lwsl_err("%s: can't open %s: %s\n", __func__, path,
				 strerror(errno));
			return 1;
		}

		/* first run */
		return 0;
	}

	memset(&a, 0, sizeof(a));
	a.map_st[0]		= lsm_saip_state_schema;
	a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_saip_state_schema);
	a.ac_block_size		= 1024;

	lws_struct_json_init_parse(&ctx, NULL, &a);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);
	lejp_destruct(&ctx);

	if (m < 0 || !a.dest) {
		/*
		 * Don't carry on without it: it's what stops us promoting an
		 * older event over a newer one
		 */
		lwsl_err("%s: %s is damaged ('%s'), remove it to start over\n",
			 __func__, path, lejp_error_to_string(m));
		lwsac_free(&a.ac);

		return 1;
	}

	st = (saip_state_t *)a.dest;

	lws_start_foreach_dll(struct lws_dll2 *, p, st->entries.head) {
		saip_state_entry_t *e = lws_container_of(p, saip_state_entry_t,
							 list);
		saip_target_t *t = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, q,
				      saip.conf->watches.head) {
			saip_watch_t *w = lws_container_of(q, saip_watch_t,
							   list);

			if (!strcmp(w->fetchurl, e->fetchurl))
				t = saip_target_get(w, e->branch);
		} lws_end_foreach_dll(q);

		if (!t)
			/* not a watch we have any more, it'll be dropped */
			continue;

		t->promoted_received = e->received;
		lws_strncpy(t->promoted_hash, e->hash,
			    sizeof(t->promoted_hash));
		lws_strncpy(t->promoted_uuid, e->uuid,
			    sizeof(t->promoted_uuid));

		lwsl_notice("%s: %s %s: last promoted %.12s, event %s\n",
			    __func__, e->fetchurl, e->branch, e->hash,
			    e->uuid);
	} lws_end_foreach_dll(p);

	lwsac_free(&a.ac);

	return 0;
}

/*
 * Written to a temp file and renamed over the old one, so there's always a
 * whole state file, the old one or the new one
 */
void
saip_state_save(void)
{
	char path[512], tmp[520];
	lws_struct_serialize_t *js;
	struct lwsac *ac = NULL;
	saip_state_entry_t *e;
	uint8_t buf[1024];
	lws_struct_json_serialize_result_t r;
	saip_state_t st;
	int fd, bad = 0;
	size_t w;

	memset(&st, 0, sizeof(st));

	lws_start_foreach_dll(struct lws_dll2 *, q, saip.conf->watches.head) {
		saip_watch_t *wa = lws_container_of(q, saip_watch_t, list);

		lws_start_foreach_dll(struct lws_dll2 *, p, wa->targets.head) {
			saip_target_t *t = lws_container_of(p, saip_target_t,
							    list);

			if (!t->promoted_received)
				continue;

			e = lwsac_use_zero(&ac, sizeof(*e), 1024);
			if (!e)
				goto bail;

			lws_strncpy(e->fetchurl, wa->fetchurl,
				    sizeof(e->fetchurl));
			lws_strncpy(e->branch, t->branch, sizeof(e->branch));
			lws_strncpy(e->hash, t->promoted_hash,
				    sizeof(e->hash));
			lws_strncpy(e->uuid, t->promoted_uuid,
				    sizeof(e->uuid));
			e->received = t->promoted_received;
			lws_dll2_add_tail(&e->list, &st.entries);
		} lws_end_foreach_dll(p);
	} lws_end_foreach_dll(q);

	saip_state_path(path, sizeof(path), "");
	saip_state_path(tmp, sizeof(tmp), ".tmp");

	fd = lws_open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("%s: can't create %s: %s\n", __func__, tmp,
			 strerror(errno));
		goto bail;
	}

	js = lws_struct_json_serialize_create(lsm_saip_state_schema,
			LWS_ARRAY_SIZE(lsm_saip_state_schema), 0, &st);
	if (!js) {
		close(fd);
		goto bail_unlink;
	}

	do {
		w = 0;
		r = lws_struct_json_serialize(js, buf, sizeof(buf), &w);
		if (r == LSJS_RESULT_ERROR ||
		    (w && write(fd, buf, w) != (ssize_t)w))
			bad = 1;
	} while (r == LSJS_RESULT_CONTINUE && !bad);

	lws_struct_json_serialize_destroy(&js);

	if (fsync(fd))
		bad = 1;
	if (close(fd))
		bad = 1;

	if (bad || rename(tmp, path)) {
		lwsl_err("%s: failed writing %s\n", __func__, path);
		goto bail_unlink;
	}

	lwsac_free(&ac);

	return;

bail_unlink:
	unlink(tmp);
bail:
	lwsac_free(&ac);
}
