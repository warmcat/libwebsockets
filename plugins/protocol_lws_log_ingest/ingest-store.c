/*
 * lws-log-ingest - keeps the log lines of many log shippers in one place
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The store: one sqlite db, in WAL mode so something else may read it while we
 * write.  Lines are kept once, whichever sessions they were sent for; a session
 * is a window of time and the sources it asked for, so sessions may overlap
 * at no cost.
 */

#include "private.h"

/* sources we keep state on, past this the least recent is forgotten */
#define LI_SRCS_MAX		1024
/* how often we expire old lines */
#define LI_EXPIRE_US		(3600ll * LWS_US_PER_SEC)
/* how many old lines we delete at a time */
#define LI_EXPIRE_CHUNK		20000
#define LI_BUSY_TIMEOUT_MS	5000

static const char * const li_schema[] = {
	"PRAGMA journal_mode=WAL",
	"CREATE TABLE IF NOT EXISTS sources ("
		"src_id INTEGER PRIMARY KEY, "
		"kind TEXT NOT NULL, "
		"host TEXT NOT NULL, "
		"inst TEXT NOT NULL UNIQUE, "
		"first_us INTEGER, "
		"last_us INTEGER, "
		"lag_us INTEGER)",
	/* seq is NULL for lines we add ourselves, eg, to say some were lost */
	"CREATE TABLE IF NOT EXISTS lines ("
		"id INTEGER PRIMARY KEY, "
		"src_id INTEGER NOT NULL, "
		"seq INTEGER, "
		"t_us INTEGER NOT NULL, "
		"rx_us INTEGER NOT NULL, "
		"lvl INTEGER NOT NULL, "
		"line TEXT NOT NULL, "
		"tag TEXT)",
	"CREATE UNIQUE INDEX IF NOT EXISTS lines_src_seq ON lines (src_id, seq)",
	"CREATE INDEX IF NOT EXISTS lines_t ON lines (t_us)",
	"CREATE INDEX IF NOT EXISTS lines_src_t ON lines (src_id, t_us)",
	/* when each tag was seen first and last, the window to look in */
	"CREATE TABLE IF NOT EXISTS tags ("
		"tag TEXT PRIMARY KEY, "
		"first_us INTEGER NOT NULL, "
		"last_us INTEGER NOT NULL)",
	"CREATE TABLE IF NOT EXISTS sessions ("
		"id TEXT PRIMARY KEY, "
		"created_us INTEGER NOT NULL, "
		"from_us INTEGER NOT NULL, "
		"until_us INTEGER NOT NULL, "
		"stopped_us INTEGER, "
		"lvl INTEGER NOT NULL, "
		"src TEXT NOT NULL, "
		"who TEXT NOT NULL, "
		"note TEXT NOT NULL)",
	"CREATE INDEX IF NOT EXISTS sessions_created ON sessions (created_us)",
};

static int
li_exec(struct vhd *vhd, const char *sql)
{
	char *err = NULL;

	if (sqlite3_exec(vhd->pdb, sql, NULL, NULL, &err) == SQLITE_OK)
		return 0;

	lwsl_vhost_err(vhd->vh, "%s: %s", sql, err ? err : "?");
	sqlite3_free(err);

	return 1;
}

static int
li_has_column(struct vhd *vhd, const char *table, const char *col)
{
	char sql[64];
	sqlite3_stmt *sm;
	int r = 0;

	lws_snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
	if (sqlite3_prepare_v2(vhd->pdb, sql, -1, &sm, NULL) != SQLITE_OK)
		return 0;
	while (!r && sqlite3_step(sm) == SQLITE_ROW) {
		const char *c = (const char *)sqlite3_column_text(sm, 1);

		r = c && !strcmp(c, col);
	}
	sqlite3_finalize(sm);

	return r;
}

/* 1 to 32 of [A-Za-z0-9._/-] */

int
li_valid_tag(const char *s)
{
	size_t n;

	for (n = 0; s[n]; n++)
		if (n == LI_TAG_MAX ||
		    !((s[n] >= 'a' && s[n] <= 'z') || (s[n] >= 'A' && s[n] <= 'Z') ||
		      (s[n] >= '0' && s[n] <= '9') || s[n] == '.' ||
		      s[n] == '_' || s[n] == '-' || s[n] == '/'))
			return 0;

	return n > 0;
}

int
li_store_open(struct vhd *vhd, const char *path)
{
	size_t n;

	if (lws_struct_sq3_open(vhd->cx, path, 1, &vhd->pdb)) {
		lwsl_vhost_err(vhd->vh, "unable to open %s", path);
		return 1;
	}

	sqlite3_busy_timeout(vhd->pdb, LI_BUSY_TIMEOUT_MS);

	for (n = 0; n < LWS_ARRAY_SIZE(li_schema); n++)
		if (li_exec(vhd, li_schema[n]))
			goto bail;

	/* a db from before lines had tags */
	if (!li_has_column(vhd, "lines", "tag") &&
	    li_exec(vhd, "ALTER TABLE lines ADD COLUMN tag TEXT"))
		goto bail;
	if (li_exec(vhd, "CREATE INDEX IF NOT EXISTS lines_tag ON lines "
			 "(tag, t_us) WHERE tag IS NOT NULL"))
		goto bail;

	return 0;

bail:
	lws_struct_sq3_close(&vhd->pdb);

	return 1;
}

void
li_store_close(struct vhd *vhd)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->srcs.head) {
		li_src_t *s = lws_container_of(d, li_src_t, list);

		lws_dll2_remove(&s->list);
		free(s);
	} lws_end_foreach_dll_safe(d, d1);

	if (vhd->pdb)
		lws_struct_sq3_close(&vhd->pdb);
}

/*
 * A source goes by a new name, eg, a process that learned its name after it
 * started.  It's the same instance, so its lines so far are the new name's too.
 */

static int
li_store_rename(struct vhd *vhd, int64_t src_id, const char *was,
		const char *now_host)
{
	sqlite3_stmt *sm;
	int r;

	if (sqlite3_prepare_v2(vhd->pdb, "UPDATE sources SET host = ? WHERE "
			"src_id = ?", -1, &sm, NULL) != SQLITE_OK)
		return 1;
	sqlite3_bind_text(sm, 1, now_host, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(sm, 2, (sqlite3_int64)src_id);
	r = sqlite3_step(sm) != SQLITE_DONE;
	sqlite3_finalize(sm);

	if (!r)
		lwsl_vhost_notice(vhd->vh, "source %s is now %s", was,
				  now_host);

	return r;
}

/*
 * The source a shipper is, by its instance: found, or added.  An instance
 * that comes back claiming to be another kind is refused; one going by
 * another host name is renamed.
 */

li_src_t *
li_store_src(struct vhd *vhd, const char *kind, const char *host,
	     const char *inst, uint64_t now)
{
	char oldhost[LI_HOST_MAX + 1];
	int64_t src_id = -1;
	sqlite3_stmt *sm;
	int renamed = 0;
	li_src_t *src;

	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->srcs.head) {
		src = lws_container_of(d, li_src_t, list);

		if (!strcmp(src->inst, inst)) {
			if (strcmp(src->kind, kind))
				return NULL;
			if (strcmp(src->host, host) &&
			    li_store_rename(vhd, src->src_id, src->host, host))
				return NULL;
			lws_strncpy(src->host, host, sizeof(src->host));

			/* most recently used goes to the head */
			lws_dll2_remove(&src->list);
			lws_dll2_add_head(&src->list, &vhd->srcs);

			return src;
		}
	} lws_end_foreach_dll(d);

	if (sqlite3_prepare_v2(vhd->pdb, "INSERT OR IGNORE INTO sources "
			"(kind, host, inst, first_us, last_us) VALUES "
			"(?, ?, ?, ?, ?)", -1, &sm, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(sm, 1, kind, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 2, host, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 3, inst, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(sm, 4, (sqlite3_int64)now);
	sqlite3_bind_int64(sm, 5, (sqlite3_int64)now);
	sqlite3_step(sm);
	sqlite3_finalize(sm);

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT src_id, kind, host FROM "
			"sources WHERE inst = ?", -1, &sm, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(sm, 1, inst, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *k = (const char *)sqlite3_column_text(sm, 1),
			   *h = (const char *)sqlite3_column_text(sm, 2);

		if (k && h && !strcmp(k, kind)) {
			src_id = sqlite3_column_int64(sm, 0);
			if (strcmp(h, host)) {
				lws_strncpy(oldhost, h, sizeof(oldhost));
				renamed = 1;
			}
		}
	}
	sqlite3_finalize(sm);

	if (src_id < 0 ||
	    (renamed && li_store_rename(vhd, src_id, oldhost, host)))
		return NULL;

	if (vhd->srcs.count >= LI_SRCS_MAX) {
		/* forget the one we heard from least recently */
		src = lws_container_of(vhd->srcs.tail, li_src_t, list);
		lws_dll2_remove(&src->list);
		free(src);
	}

	src = malloc(sizeof(*src));
	if (!src)
		return NULL;

	memset(src, 0, sizeof(*src));
	src->src_id = src_id;
	src->rate_start_us = now;
	lws_strncpy(src->inst, inst, sizeof(src->inst));
	lws_strncpy(src->kind, kind, sizeof(src->kind));
	lws_strncpy(src->host, host, sizeof(src->host));
	lws_dll2_add_head(&src->list, &vhd->srcs);

	return src;
}

/* a line of our own, about the source, eg, that some of its were lost */

void
li_store_say(struct vhd *vhd, li_src_t *src, uint64_t now, const char *line)
{
	sqlite3_stmt *sm;

	if (sqlite3_prepare_v2(vhd->pdb, "INSERT INTO lines (src_id, t_us, "
			"rx_us, lvl, line) VALUES (?, ?, ?, ?, ?)", -1, &sm,
			NULL) != SQLITE_OK)
		return;

	sqlite3_bind_int64(sm, 1, src->src_id);
	sqlite3_bind_int64(sm, 2, (sqlite3_int64)now);
	sqlite3_bind_int64(sm, 3, (sqlite3_int64)now);
	sqlite3_bind_int(sm, 4, LLL_WARN);
	sqlite3_bind_text(sm, 5, line, -1, SQLITE_TRANSIENT);
	sqlite3_step(sm);
	sqlite3_finalize(sm);
}

/*
 * Lines are stored a transaction per piece of a message we parse: pieces of
 * different shippers' messages come interleaved, so a transaction can't span
 * a message
 */

int
li_store_begin(struct vhd *vhd)
{
	if (li_exec(vhd, "BEGIN"))
		return 1;

	if (sqlite3_prepare_v2(vhd->pdb, "INSERT OR IGNORE INTO lines (src_id, "
			"seq, t_us, rx_us, lvl, line, tag) VALUES "
			"(?, ?, ?, ?, ?, ?, ?)", -1, &vhd->sm_line, NULL) !=
								SQLITE_OK ||
	    sqlite3_prepare_v2(vhd->pdb, "INSERT INTO tags (tag, first_us, "
			"last_us) VALUES (?1, ?2, ?2) ON CONFLICT(tag) DO UPDATE "
			"SET first_us = min(first_us, excluded.first_us), "
			"last_us = max(last_us, excluded.last_us)", -1,
			&vhd->sm_tag, NULL) != SQLITE_OK) {
		lwsl_vhost_err(vhd->vh, "prepare: %s", sqlite3_errmsg(vhd->pdb));
		sqlite3_finalize(vhd->sm_line);
		vhd->sm_line = NULL;
		li_exec(vhd, "ROLLBACK");
		return 1;
	}

	return 0;
}

/*
 * Store one line, inside the transaction.  Returns 0 if it was stored or we
 * had it already, 1 if it was refused, 2 if it was over the source's rate.
 * Lines are checked as if they came from anywhere: the secret only says the
 * shipper is one of ours, not that what it says is sane.
 */

int
li_store_line(struct vhd *vhd, li_src_t *src, uint64_t seq, uint64_t t,
	      uint64_t now, int lvl, const char *x, size_t xlen,
	      const char *tag)
{
	sqlite3_stmt *sm = vhd->sm_line;
	size_t n;
	int r;

	if (!seq || lvl <= 0 || lvl >= (1 << LLL_COUNT) || (lvl & (lvl - 1)) ||
	    !xlen || xlen > LWS_LOG_SHIP_LINE_MAX ||
	    (t > now && t - now > (uint64_t)LI_SKEW_MAX_US) ||
	    (t <= now && now - t > (uint64_t)LI_SKEW_MAX_US) ||
	    (tag && !li_valid_tag(tag)))
		return 1;

	for (n = 0; n < xlen; n++)
		if ((unsigned char)x[n] < 0x20 || (unsigned char)x[n] > 0x7e)
			return 1;

	if (now - src->rate_start_us > 60ull * LWS_US_PER_SEC) {
		if (src->over_rate) {
			char say[128];

			lws_snprintf(say, sizeof(say), "log-ingest: dropped %u "
				     "lines over the limit of %u a minute",
				     src->over_rate, vhd->rate_lines);
			li_store_say(vhd, src, now, say);
		}
		src->rate_start_us = now;
		src->rate_lines = 0;
		src->over_rate = 0;
	}

	if (src->rate_lines >= vhd->rate_lines) {
		src->over_rate++;
		return 2;
	}
	src->rate_lines++;

	if (!sm)
		return 1;

	sqlite3_bind_int64(sm, 1, src->src_id);
	sqlite3_bind_int64(sm, 2, (sqlite3_int64)seq);
	sqlite3_bind_int64(sm, 3, (sqlite3_int64)t);
	sqlite3_bind_int64(sm, 4, (sqlite3_int64)now);
	sqlite3_bind_int(sm, 5, lvl);
	sqlite3_bind_text(sm, 6, x, (int)xlen, SQLITE_TRANSIENT);
	if (tag)
		sqlite3_bind_text(sm, 7, tag, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(sm, 7);
	r = sqlite3_step(sm) != SQLITE_DONE;
	sqlite3_reset(sm);
	sqlite3_clear_bindings(sm);

	if (!r && tag) {
		sqlite3_bind_text(vhd->sm_tag, 1, tag, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(vhd->sm_tag, 2, (sqlite3_int64)t);
		sqlite3_step(vhd->sm_tag);
		sqlite3_reset(vhd->sm_tag);
	}

	return r;
}

void
li_store_commit(struct vhd *vhd, li_src_t *src, uint64_t now, int64_t lag)
{
	sqlite3_stmt *sm;

	if (vhd->sm_line) {
		sqlite3_finalize(vhd->sm_line);
		sqlite3_finalize(vhd->sm_tag);
		vhd->sm_line = NULL;
		vhd->sm_tag = NULL;
	}

	if (src && sqlite3_prepare_v2(vhd->pdb, "UPDATE sources SET last_us = ?, "
			"lag_us = coalesce(?, lag_us) WHERE src_id = ?", -1,
			&sm, NULL) == SQLITE_OK) {
		sqlite3_bind_int64(sm, 1, (sqlite3_int64)now);
		if (lag != INT64_MAX)
			sqlite3_bind_int64(sm, 2, lag);
		else
			sqlite3_bind_null(sm, 2);
		sqlite3_bind_int64(sm, 3, src->src_id);
		sqlite3_step(sm);
		sqlite3_finalize(sm);
	}

	if (li_exec(vhd, "COMMIT"))
		li_exec(vhd, "ROLLBACK");
}

void
li_store_expire_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_expire);
	uint64_t before = lws_log_ship_utc_us() - vhd->retention_us;
	lws_usec_t next = LI_EXPIRE_US;
	sqlite3_stmt *sm;

	if (sqlite3_prepare_v2(vhd->pdb, "DELETE FROM lines WHERE id IN "
			"(SELECT id FROM lines WHERE t_us < ? LIMIT ?)", -1,
			&sm, NULL) == SQLITE_OK) {
		sqlite3_bind_int64(sm, 1, (sqlite3_int64)before);
		sqlite3_bind_int(sm, 2, LI_EXPIRE_CHUNK);
		if (sqlite3_step(sm) == SQLITE_DONE &&
		    sqlite3_changes(vhd->pdb) == LI_EXPIRE_CHUNK)
			/* there's more, but let other things happen first */
			next = LWS_US_PER_SEC;
		sqlite3_finalize(sm);
	}

	if (next == LI_EXPIRE_US) {
		if (sqlite3_prepare_v2(vhd->pdb, "DELETE FROM tags WHERE "
				"last_us < ?", -1, &sm, NULL) == SQLITE_OK) {
			sqlite3_bind_int64(sm, 1, (sqlite3_int64)before);
			sqlite3_step(sm);
			sqlite3_finalize(sm);
		}
		if (sqlite3_prepare_v2(vhd->pdb, "DELETE FROM sessions WHERE "
				"until_us < ?", -1, &sm, NULL) == SQLITE_OK) {
			sqlite3_bind_int64(sm, 1, (sqlite3_int64)before);
			sqlite3_step(sm);
			sqlite3_finalize(sm);
		}
		if (sqlite3_prepare_v2(vhd->pdb, "DELETE FROM sources WHERE "
				"last_us < ? AND NOT EXISTS (SELECT 1 FROM lines "
				"l WHERE l.src_id = sources.src_id)", -1, &sm,
				NULL) == SQLITE_OK) {
			sqlite3_bind_int64(sm, 1, (sqlite3_int64)before);
			sqlite3_step(sm);
			sqlite3_finalize(sm);
		}
	}

	lws_sul_schedule(vhd->cx, 0, &vhd->sul_expire, li_store_expire_cb,
			 next);
}

/* the sessions still open, eg, after we restarted */

int
li_store_sessions_load(struct vhd *vhd)
{
	uint64_t now = lws_log_ship_utc_us();
	sqlite3_stmt *sm;

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT id, from_us, until_us, lvl, "
			"src FROM sessions WHERE stopped_us IS NULL AND "
			"until_us > ?", -1, &sm, NULL) != SQLITE_OK)
		return 1;

	sqlite3_bind_int64(sm, 1, (sqlite3_int64)now);
	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *id = (const char *)sqlite3_column_text(sm, 0),
			   *src = (const char *)sqlite3_column_text(sm, 4);
		li_session_t *s;

		if (!id || !src || strlen(id) != LI_SESSION_LEN ||
		    strlen(src) > LI_SRC_MAX)
			continue;

		s = malloc(sizeof(*s));
		if (!s)
			break;
		memset(s, 0, sizeof(*s));
		lws_strncpy(s->id, id, sizeof(s->id));
		lws_strncpy(s->src, src, sizeof(s->src));
		s->from_us = (uint64_t)sqlite3_column_int64(sm, 1);
		s->until_us = (uint64_t)sqlite3_column_int64(sm, 2);
		s->lvl = sqlite3_column_int(sm, 3);
		lws_dll2_add_tail(&s->list, &vhd->sessions);
	}
	sqlite3_finalize(sm);

	return 0;
}

int
li_store_session_add(struct vhd *vhd, const li_session_t *s,
		     const char *who, const char *note, uint64_t now)
{
	sqlite3_stmt *sm;
	int r;

	if (sqlite3_prepare_v2(vhd->pdb, "INSERT INTO sessions (id, created_us, "
			"from_us, until_us, lvl, src, who, note) VALUES "
			"(?, ?, ?, ?, ?, ?, ?, ?)", -1, &sm, NULL) != SQLITE_OK)
		return 1;

	sqlite3_bind_text(sm, 1, s->id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(sm, 2, (sqlite3_int64)now);
	sqlite3_bind_int64(sm, 3, (sqlite3_int64)s->from_us);
	sqlite3_bind_int64(sm, 4, (sqlite3_int64)s->until_us);
	sqlite3_bind_int(sm, 5, s->lvl);
	sqlite3_bind_text(sm, 6, s->src, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 7, who, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 8, note, -1, SQLITE_TRANSIENT);
	r = sqlite3_step(sm) != SQLITE_DONE;
	sqlite3_finalize(sm);

	return r;
}

/* a session is stopped early: it ends now, and its window says so */

int
li_store_session_stop(struct vhd *vhd, const char *id, uint64_t now)
{
	sqlite3_stmt *sm;
	int r;

	if (sqlite3_prepare_v2(vhd->pdb, "UPDATE sessions SET stopped_us = ?1, "
			"until_us = min(until_us, ?1) WHERE id = ?2 AND "
			"stopped_us IS NULL", -1, &sm, NULL) != SQLITE_OK)
		return 1;

	sqlite3_bind_int64(sm, 1, (sqlite3_int64)now);
	sqlite3_bind_text(sm, 2, id, -1, SQLITE_TRANSIENT);
	r = sqlite3_step(sm) != SQLITE_DONE || !sqlite3_changes(vhd->pdb);
	sqlite3_finalize(sm);

	return r;
}
