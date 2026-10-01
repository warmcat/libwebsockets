/*
 * Sai web - ./src/web/w-findings.c
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
 * Findings, for admins only: see READMEs/README-findings.md
 *
 * Like cloneinfo, we answer these from the databases sai-server keeps, which we
 * read directly: the events db lists the repos' pools, and each pool's db has
 * its findings grouped into bugs.  Changes to a group go to sai-server.
 *
 * Findings can be unfixed security bugs, so the caller must only call these
 * for admins.
 */

#include <libwebsockets.h>
#include <string.h>

#include "w-private.h"

/* how many groups of each pool we list */
#define SAIW_FINDINGS_GROUPS_MAX	200
/* how big the list reply can get */
#define SAIW_FINDINGS_LIST_MAX		(256 * 1024)
/* the most of a report we send */
#define SAIW_FINDINGS_REPORT_MAX	(64 * 1024)
/* the biggest reproducer we send to the browser */
#define SAIW_FINDINGS_REPRO_MAX		(512 * 1024)

static int
saiw_findings_open(struct vhd *vhd, const char *repo, const char *pool,
		   sqlite3 **ppdb)
{
	char fn[256];

	if (!sai_pool_name_ok(pool) || sai_str_has_shell_metachars(repo))
		return 1;

	sai_pool_db_path(fn, sizeof(fn), vhd->sqlite3_path_lhs, repo, pool);

	/* sai-server makes it; if it isn't there, there's nothing to show */
	if (sqlite3_open_v2(fn, ppdb, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
		sqlite3_close(*ppdb);
		*ppdb = NULL;
		return 1;
	}
	sqlite3_busy_timeout(*ppdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);

	return 0;
}

static const char *
saiw_col(sqlite3_stmt *sm, int col, char *esc, size_t len)
{
	const char *c = (const char *)sqlite3_column_text(sm, col);

	return lws_json_purify(esc, c ? c : "", (int)len - 1, NULL);
}

/*
 * com.warmcat.sai.findings: every pool's groups, unacknowledged and open
 * ones first
 */

int
saiw_browser_send_findings(struct vhd *vhd, struct pss *pss)
{
	char *buf, *start, *p, *end, e1[256], e2[256], q[384];
	sqlite3_stmt *sm = NULL, *gsm;
	int first_pool = 1, ret = 1;

	buf = malloc(LWS_PRE + SAIW_FINDINGS_LIST_MAX);
	if (!buf)
		return 1;
	start = p = buf + LWS_PRE;
	end = start + SAIW_FINDINGS_LIST_MAX - 1024;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"com.warmcat.sai.findings\","
			  "\"pools\":[");

	/* sai-server creates the table; without it, there are no pools yet */

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT repo, pool FROM pools ORDER "
			       "BY repo, pool", -1, &sm, NULL) != SQLITE_OK)
		goto done;

	lws_snprintf(q, sizeof(q), "SELECT id, sub, kind, frames, status, "
		     "acked, regressed, hits, first_seen, last_seen, "
		     "first_hash, last_hash, last_ok_hash, last_ok_time, "
		     "platforms, repro_len FROM groups ORDER BY acked, status, "
		     "last_seen DESC LIMIT %d", SAIW_FINDINGS_GROUPS_MAX);

	while (sqlite3_step(sm) == SQLITE_ROW && p < end) {
		const char *repo = (const char *)sqlite3_column_text(sm, 0),
			   *pool = (const char *)sqlite3_column_text(sm, 1);
		int first = 1;
		sqlite3 *pdb;

		if (!repo || !pool || saiw_findings_open(vhd, repo, pool, &pdb))
			continue;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s{\"repo\":\"%s\",\"pool\":\"%s\","
				  "\"groups\":[", first_pool ? "" : ",",
				  lws_json_purify(e1, repo, sizeof(e1) - 1, NULL),
				  lws_json_purify(e2, pool, sizeof(e2) - 1, NULL));
		first_pool = 0;

		if (sqlite3_prepare_v2(pdb, q, -1, &gsm, NULL) == SQLITE_OK) {
			while (sqlite3_step(gsm) == SQLITE_ROW &&
			       lws_ptr_diff_size_t(end, p) > 2048) {
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"%s{\"id\":\"%s\",", first ? "" : ",",
					saiw_col(gsm, 0, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"sub\":\"%s\",",
					saiw_col(gsm, 1, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"kind\":\"%s\",",
					saiw_col(gsm, 2, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"frames\":\"%s\",",
					saiw_col(gsm, 3, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"status\":%d,\"acked\":%d,"
					"\"regressed\":%d,\"hits\":%d,"
					"\"first_seen\":%lld,\"last_seen\":%lld,",
					sqlite3_column_int(gsm, 4),
					sqlite3_column_int(gsm, 5),
					sqlite3_column_int(gsm, 6),
					sqlite3_column_int(gsm, 7),
					(long long)sqlite3_column_int64(gsm, 8),
					(long long)sqlite3_column_int64(gsm, 9));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"first_hash\":\"%s\",",
					saiw_col(gsm, 10, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"last_hash\":\"%s\",",
					saiw_col(gsm, 11, e1, sizeof(e1)));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"last_ok_hash\":\"%s\","
					"\"last_ok_time\":%lld,",
					saiw_col(gsm, 12, e1, sizeof(e1)),
					(long long)sqlite3_column_int64(gsm, 13));
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"\"platforms\":\"%s\",\"repro_len\":%lld}",
					saiw_col(gsm, 14, e1, sizeof(e1)),
					(long long)sqlite3_column_int64(gsm, 15));
				first = 0;
			}
			sqlite3_finalize(gsm);
		}

		sqlite3_close(pdb);
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");
	}
	sqlite3_finalize(sm);

done:
	p += lws_snprintf(p, lws_ptr_diff_size_t(end + 1024, p), "]}");

	ret = saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
				lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);
	free(buf);

	return ret;
}

/*
 * com.warmcat.sai.findingget: one group's report and reproducer
 */

int
saiw_browser_send_finding(struct vhd *vhd, struct pss *pss,
			  const sai_findingset_t *fs)
{
	char *buf = NULL, *start, *p, *end, e1[256], sub[33] = "",
	     rname[65] = "", *esc = NULL;
	sqlite3_stmt *sm;
	sqlite3 *pdb;
	size_t blen;
	int ret = 1;

	if (saiw_findings_open(vhd, fs->repo, fs->pool, &pdb))
		return 1;

	if (sqlite3_prepare_v2(pdb, "SELECT sub, repro_name FROM groups WHERE "
			       "id = ?", -1, &sm, NULL) != SQLITE_OK)
		goto bail;
	sqlite3_bind_text(sm, 1, fs->group, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *c;

		if ((c = (const char *)sqlite3_column_text(sm, 0)))
			lws_strncpy(sub, c, sizeof(sub));
		if ((c = (const char *)sqlite3_column_text(sm, 1)))
			lws_strncpy(rname, c, sizeof(rname));
	}
	sqlite3_finalize(sm);
	if (!sub[0] || !rname[0])
		goto bail;

	/* the report can JSON-escape to 6x, the reproducer b64s to 4/3 */

	blen = LWS_PRE + 1024 + (SAIW_FINDINGS_REPORT_MAX * 6) +
	       ((SAIW_FINDINGS_REPRO_MAX * 4) / 3) + 16;
	buf = malloc(blen);
	esc = malloc((SAIW_FINDINGS_REPORT_MAX * 6) + 8);
	if (!buf || !esc)
		goto bail;
	start = p = buf + LWS_PRE;
	end = buf + blen - 8;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"com.warmcat.sai.finding\","
			  "\"repo\":\"%s\",",
			  lws_json_purify(e1, fs->repo, sizeof(e1) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"pool\":\"%s\",",
			  lws_json_purify(e1, fs->pool, sizeof(e1) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"group\":\"%s\",",
			  lws_json_purify(e1, fs->group, sizeof(e1) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"name\":\"%s\",",
			  lws_json_purify(e1, rname, sizeof(e1) - 1, NULL));

	/* the report on the group's reproducer */

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"report\":\"");
	if (sqlite3_prepare_v2(pdb, "SELECT blob FROM findings WHERE sub = ? "
			       "AND name = ? || '.log'", -1, &sm,
			       NULL) == SQLITE_OK) {
		sqlite3_bind_text(sm, 1, sub, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 2, rname, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(sm) == SQLITE_ROW) {
			int l = sqlite3_column_bytes(sm, 0);
			char *rep;

			if (l > SAIW_FINDINGS_REPORT_MAX)
				l = SAIW_FINDINGS_REPORT_MAX;
			rep = malloc((size_t)l + 1);
			if (rep) {
				if (l)
					memcpy(rep, sqlite3_column_blob(sm, 0),
					       (size_t)l);
				rep[l] = '\0';
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"%s", lws_json_purify(esc, rep,
					(SAIW_FINDINGS_REPORT_MAX * 6) + 7,
					NULL));
				free(rep);
			}
		}
		sqlite3_finalize(sm);
	}

	/* the reproducer itself, if it's not too big for this */

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\",\"repro\":\"");
	if (sqlite3_prepare_v2(pdb, "SELECT blob FROM findings WHERE sub = ? "
			       "AND name = ?", -1, &sm, NULL) == SQLITE_OK) {
		sqlite3_bind_text(sm, 1, sub, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 2, rname, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(sm) == SQLITE_ROW) {
			int l = sqlite3_column_bytes(sm, 0);

			if (l <= SAIW_FINDINGS_REPRO_MAX && l > 0) {
				int n = lws_b64_encode_string(
					(const char *)sqlite3_column_blob(sm, 0),
					l, p, (int)lws_ptr_diff_size_t(end, p));
				if (n > 0)
					p += n;
			}
		}
		sqlite3_finalize(sm);
	}
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"}");

	ret = saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
				lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);

bail:
	free(esc);
	free(buf);
	sqlite3_close(pdb);

	return ret;
}
