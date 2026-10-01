/*
 * Sai server - ./src/server/s-findings.c
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
 * Findings: see READMEs/README-findings.md
 *
 * Tasks leave findings in their pool's findings dir, which the builder sends
 * us (s-pool.c).  A finding is a pair of files in a sub (eg, the fuzz target):
 * the input, eg, "crash-<sha1>", and the sanitizer's report about it,
 * "crash-<sha1>.log".  When we have both, we work out which bug it is from the
 * report, and group it with the other findings of the same bug.
 *
 * The first finding of a bug, or one of a bug that was marked fixed, is news:
 * it's flagged until an admin acknowledges it in sai-web, and mailed to
 * "findings-notify" if that's set.  Later ones of an open bug just count.
 *
 * Each bug's smallest input is published in the pool's "known" namespace, so
 * the builders have it to replay, eg, at the start of every CI fuzzing run,
 * which then fails while it still crashes.  A task that replays one that
 * doesn't crash any more leaves "ok-<sha1>" in its findings, and we note at
 * which commit that was.
 */

#include <libwebsockets.h>
#include <string.h>

#include "s-private.h"

/* frames that decide which bug a finding is */
#define SAIS_FINDINGS_FRAMES		3
/* how often groups whose mail didn't go yet are tried again */
#define SAIS_FINDINGS_RETRY_US		(5 * 60 * LWS_US_PER_SEC)

enum {
	SAIS_FINDINGS_OPEN,
	SAIS_FINDINGS_FIXED,
	SAIS_FINDINGS_WONTFIX,
};

enum {
	SAIS_FINDINGS_NOTIFY_NONE,
	SAIS_FINDINGS_NOTIFY_PENDING,
	SAIS_FINDINGS_NOTIFY_QUEUED,
	SAIS_FINDINGS_NOTIFY_DELIVERED,
	SAIS_FINDINGS_NOTIFY_FAILED,
};

/* keep only what's safe to show and store */

static void
sais_findings_clean(char *s)
{
	for (; *s; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		      (*s >= '0' && *s <= '9') || *s == '_' || *s == '-' ||
		      *s == ':' || *s == '.' || *s == ' '))
			*s = '_';
}

/* frames that aren't the code being tested: the runtime, allocators */

static int
sais_findings_frame_skip(const char *f)
{
	static const char * const skip[] = {
		"malloc", "calloc", "realloc", "free", "strdup", "strndup",
		"memcpy", "memmove", "memset", "memcmp", "strlen", "strcmp",
		"strncmp", "strcpy", "strncpy", "abort", "raise",
	};
	size_t n;

	if ((f[0] == '_' && f[1] == '_') ||
	    /* eg, libFuzzer's own alarm handler, at the top of a timeout */
	    !strncmp(f, "fuzzer::", 8))
		return 1;

	for (n = 0; n < LWS_ARRAY_SIZE(skip); n++)
		if (!strcmp(f, skip[n]))
			return 1;

	return 0;
}

/* frames from here on are the fuzzer driving the test, not the test */

static int
sais_findings_frame_stop(const char *f)
{
	return !strcmp(f, "LLVMFuzzerTestOneInput") || !strcmp(f, "main");
}

/*
 * Work out what kind of bug a sanitizer report is about, and where: the
 * SUMMARY line's kind, and the first few frames of the first stack that are in
 * the code being tested.  Function names only, not lines, so the same bug
 * stays the same bug as unrelated code around it changes.
 *
 * The report came from a task, so it's treated as hostile: we only ever look
 * at bounded tokens out of it.
 */

static void
sais_findings_signature(const char *rep, size_t len, char *kind, size_t kind_len,
			char frames[SAIS_FINDINGS_FRAMES][96])
{
	const char *p = rep, *end = rep + len;
	int nframes = 0, in_stack = 0, stack_done = 0, n;

	lws_strncpy(kind, "unknown", kind_len);
	for (n = 0; n < SAIS_FINDINGS_FRAMES; n++)
		frames[n][0] = '\0';

	while (p < end) {
		const char *nl = memchr(p, '\n', lws_ptr_diff_size_t(end, p)),
			   *e = nl ? nl : end, *q = p, *s;
		char tool[48], type[48], fn[96];
		size_t l;

		while (q < e && (*q == ' ' || *q == '\t'))
			q++;

		/*
		 * "#3 0x4f2a1c in lws_foo /src/lib/x.c:12:3"... but not
		 * libFuzzer's "#1024	pulse  cov: ..." status lines
		 */

		if (!stack_done && e - q > 4 && *q == '#' &&
		    q[1] >= '0' && q[1] <= '9' &&
		    (s = memchr(q, ' ', lws_ptr_diff_size_t(e, q))) &&
		    e - s > 4 && s[1] == '0' && s[2] == 'x') {
			const char *in = NULL, *x;

			in_stack = 1;
			for (x = s; x + 4 <= e; x++)
				if (!memcmp(x, " in ", 4)) {
					in = x + 4;
					break;
				}

			if (in && nframes < SAIS_FINDINGS_FRAMES) {
				l = 0;
				while (in + l < e && in[l] != ' ' &&
				       in[l] != '(' && in[l] != '.' &&
				       l < sizeof(fn) - 1)
					l++;
				memcpy(fn, in, l);
				fn[l] = '\0';

				if (sais_findings_frame_stop(fn))
					stack_done = 1;
				else
					if (l && !sais_findings_frame_skip(fn)) {
						sais_findings_clean(fn);
						lws_strncpy(frames[nframes++], fn,
							    sizeof(frames[0]));
					}
			}
		} else
			if (in_stack)
				/* only the first stack decides it */
				stack_done = 1;

		/* "SUMMARY: AddressSanitizer: heap-buffer-overflow ..." */

		s = memchr(q, 'S', lws_ptr_diff_size_t(e, q));
		if (s && e - s > 9 && !memcmp(s, "SUMMARY: ", 9)) {
			const char *t = s + 9;

			l = 0;
			while (t + l < e && t[l] != ' ' && l < sizeof(tool) - 1)
				l++;
			memcpy(tool, t, l);
			tool[l] = '\0';
			t += l;
			while (t < e && *t == ' ')
				t++;
			l = 0;
			while (t + l < e && t[l] != ' ' && t[l] != '(' &&
			       l < sizeof(type) - 1)
				l++;
			memcpy(type, t, l);
			type[l] = '\0';

			/* "32 byte(s) leaked in 1 allocation(s)." */
			if (type[0] >= '0' && type[0] <= '9')
				lws_strncpy(type, "leak", sizeof(type));

			lws_snprintf(kind, kind_len, "%s %s", tool, type);
			sais_findings_clean(kind);
		}

		p = e + 1;
	}
}

static void
sais_findings_sha1_hex(const uint8_t *data, size_t len, char *hex41)
{
	uint8_t md[20];
	int n;

	lws_SHA1(data, len, md);
	for (n = 0; n < 20; n++)
		lws_snprintf(hex41 + (n * 2), 3, "%02x", md[n]);
}

/*
 * Mail
 */

#if defined(LWS_WITH_EMAIL)

typedef struct {
	char		dbpath[256];
	char		id[17];
} sais_findings_mail_t;

static void
sais_findings_mail_done(void *opaque, const lws_smtp_email_t *email,
			const lws_smtpc_result_t *res)
{
	sais_findings_mail_t *m = (sais_findings_mail_t *)opaque;
	sqlite3_stmt *sm;
	sqlite3 *pdb;
	int st;

	switch (res->outcome) {
	case LWS_SMTPC_DELIVERED:
		st = SAIS_FINDINGS_NOTIFY_DELIVERED;
		break;
	case LWS_SMTPC_ABANDONED:
		/*
		 * We're going away: it stays queued in the db, and the next
		 * sai-server tries it again
		 */
		free(m);
		return;
	default:
		lwsl_err("%s: mail about finding %s failed: %d %s\n", __func__,
			 m->id, res->code, res->text);
		st = SAIS_FINDINGS_NOTIFY_FAILED;
		break;
	}

	/*
	 * This can come after anything else we have open is gone, so it only
	 * uses what it was given
	 */

	if (sqlite3_open_v2(m->dbpath, &pdb, SQLITE_OPEN_READWRITE,
			    NULL) == SQLITE_OK) {
		sqlite3_busy_timeout(pdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);
		if (sqlite3_prepare_v2(pdb, "UPDATE groups SET notify = ? "
				       "WHERE id = ?", -1, &sm,
				       NULL) == SQLITE_OK) {
			sqlite3_bind_int(sm, 1, st);
			sqlite3_bind_text(sm, 2, m->id, -1, SQLITE_TRANSIENT);
			sai_sqlite3_step_done(pdb, sm, "set group notify");
		}
	}
	sqlite3_close(pdb);
	free(m);
}

#endif

/*
 * Mail about the group, if we're set up to.  It only says what and where, the
 * details are behind the admin login.
 */

static void
sais_findings_notify(struct vhd *vhd, sais_pool_db_t *db, const char *id)
{
#if defined(LWS_WITH_EMAIL)
	char subject[256], body[1024], kind[96] = "", sub[33] = "",
	     hash[65] = "", platforms[128] = "";
	sais_findings_mail_t *m;
	lws_smtp_email_t email;
	struct lws_smtpc *smtpc;
	int regressed = 0;
	sqlite3_stmt *sm;

	if (!vhd->findings_notify)
		return;

	if (sqlite3_prepare_v2(db->pdb, "SELECT kind, sub, last_hash, "
			       "platforms, regressed FROM groups WHERE id = ?",
			       -1, &sm, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *c;

		if ((c = (const char *)sqlite3_column_text(sm, 0)))
			lws_strncpy(kind, c, sizeof(kind));
		if ((c = (const char *)sqlite3_column_text(sm, 1)))
			lws_strncpy(sub, c, sizeof(sub));
		if ((c = (const char *)sqlite3_column_text(sm, 2)))
			lws_strncpy(hash, c, sizeof(hash));
		if ((c = (const char *)sqlite3_column_text(sm, 3)))
			lws_strncpy(platforms, c, sizeof(platforms));
		regressed = sqlite3_column_int(sm, 4);
	}
	sqlite3_finalize(sm);

	lws_snprintf(subject, sizeof(subject), "[sai] %s: %s finding %s in %s",
		     db->repo, regressed ? "regressed" : "new", id, sub);
	lws_snprintf(body, sizeof(body),
		     "%s %s finding in %s, pool %s:\n\n"
		     "  group:     %s\n"
		     "  target:    %s\n"
		     "  kind:      %s\n"
		     "  commit:    %s\n"
		     "  platforms: %s\n\n"
		     "%s%s%s",
		     regressed ? "A bug marked fixed has come back, a" : "A new",
		     regressed ? "regressed" : "fuzzing", db->repo, db->pool,
		     id, sub, kind, hash, platforms,
		     vhd->findings_url ? "The details are for admins, at\n  " : "",
		     vhd->findings_url ? vhd->findings_url : "",
		     vhd->findings_url ? "\n" : "");

	memset(&email, 0, sizeof(email));
	email.from	= vhd->findings_from ? vhd->findings_from :
					       vhd->findings_notify;
	email.to	= vhd->findings_notify;
	email.subject	= subject;
	email.body	= body;

	smtpc = lws_smtpc_vhost(vhd->vhost);
	m = malloc(sizeof(*m));
	if (!smtpc || !m) {
		free(m);
		return;
	}
	sai_pool_db_path(m->dbpath, sizeof(m->dbpath), vhd->sqlite3_path_lhs,
			 db->repo, db->pool);
	lws_strncpy(m->id, id, sizeof(m->id));

	if (lws_smtpc_queue(smtpc, &email, sais_findings_mail_done, m)) {
		lwsl_warn("%s: unable to queue mail about %s\n", __func__, id);
		free(m);
		return;
	}

	if (sqlite3_prepare_v2(db->pdb, "UPDATE groups SET notify = ? WHERE "
			       "id = ?", -1, &sm, NULL) == SQLITE_OK) {
		sqlite3_bind_int(sm, 1, SAIS_FINDINGS_NOTIFY_QUEUED);
		sqlite3_bind_text(sm, 2, id, -1, SQLITE_TRANSIENT);
		sai_sqlite3_step_done(db->pdb, sm, "set group notify");
	}
#else
	(void)vhd;
	(void)db;
	(void)id;
#endif
}

/*
 * Every so often, mail about groups that weren't mailed yet, eg, the relay was
 * down, or the mail was queued when sai-server went away
 */

void
sais_findings_notify_retry(struct vhd *vhd)
{
	lws_usec_t now = lws_now_usecs();
	sqlite3_stmt *sm, *gsm;

	if (!vhd->findings_notify ||
	    now - vhd->findings_last_retry < SAIS_FINDINGS_RETRY_US)
		return;
	vhd->findings_last_retry = now;

	if (sqlite3_prepare_v2(vhd->server.pdb, "SELECT repo, pool FROM pools",
			       -1, &sm, NULL) != SQLITE_OK)
		return;

	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *repo = (const char *)sqlite3_column_text(sm, 0),
			   *pool = (const char *)sqlite3_column_text(sm, 1);
		sais_pool_db_t *db;

		if (!repo || !pool || !sai_pool_name_ok(pool))
			continue;

		db = sais_pool_db_get(vhd, repo, pool);
		if (!db)
			continue;

		if (!vhd->findings_reset_done)
			/* nothing is really queued in a new sai-server */
			sai_sqlite3_statement(db->pdb, "UPDATE groups SET "
					      "notify = 1 WHERE notify = 2",
					      "findings requeue");

		if (sqlite3_prepare_v2(db->pdb, "SELECT id FROM groups WHERE "
				       "notify = 1", -1, &gsm,
				       NULL) == SQLITE_OK) {
			while (sqlite3_step(gsm) == SQLITE_ROW) {
				char id[17];
				const char *c = (const char *)
						sqlite3_column_text(gsm, 0);

				if (!c)
					continue;
				lws_strncpy(id, c, sizeof(id));
				sais_findings_notify(vhd, db, id);
			}
			sqlite3_finalize(gsm);
		}

		sais_pool_db_put(db);
	}
	sqlite3_finalize(sm);

	vhd->findings_reset_done = 1;
}

/*
 * Make this input the bug's reproducer that builders replay, replacing the
 * one we published before, if any
 */

static void
sais_findings_publish(sais_pool_db_t *db, const char *sub, const char *old_sha1,
		      const char *sha1, const uint8_t *data, size_t len)
{
	size_t sl = strlen(sub);

	if (old_sha1 && old_sha1[0] && (!sha1 || strcmp(old_sha1, sha1)))
		sais_pool_log_entry(db, SAI_POOL_NS_KNOWN, sub, sl, old_sha1,
				    40, NULL, 0);

	if (!sha1)
		return;

	if (len > SAI_POOL_ENTRY_MAX) {
		lwsl_notice("%s: %s/%s too big to publish\n", __func__, sub,
			    sha1);
		return;
	}

	if (sais_pool_log_entry(db, SAI_POOL_NS_KNOWN, sub, sl, sha1, 40,
				data, len))
		lwsl_err("%s: unable to publish %s/%s\n", __func__, sub, sha1);
}

/*
 * We have both the input and the report of a finding: which bug is it?
 */

static void
sais_findings_group(struct vhd *vhd, sais_pool_db_t *db, const char *sub,
		    const char *input_name, const uint8_t *input,
		    size_t input_len, const char *rep, size_t rep_len,
		    const char *hash, const char *platform)
{
	char frames[SAIS_FINDINGS_FRAMES][96], kind[96], sig[512], fr[320],
	     id[17], sha1[41], hex[41], old_sha1[41] = "", platforms[512] = "";
	int exists = 0, status = SAIS_FINDINGS_OPEN, notify = 0, n;
	uint64_t now = (uint64_t)lws_now_secs();
	size_t repro_len = 0;
	sqlite3_stmt *sm;

	sais_findings_signature(rep, rep_len, kind, sizeof(kind), frames);

	n = lws_snprintf(sig, sizeof(sig), "%s\n%s", sub, kind);
	fr[0] = '\0';
	for (int f = 0; f < SAIS_FINDINGS_FRAMES; f++) {
		n += lws_snprintf(sig + n, sizeof(sig) - (size_t)n, "\n%s",
				  frames[f]);
		if (frames[f][0])
			lws_snprintf(fr + strlen(fr), sizeof(fr) - strlen(fr),
				     "%s%s", fr[0] ? " < " : "", frames[f]);
	}
	sais_findings_sha1_hex((const uint8_t *)sig, (size_t)n, hex);
	lws_strnncpy(id, hex, 16, sizeof(id));
	sais_findings_sha1_hex(input, input_len, sha1);

	if (sqlite3_prepare_v2(db->pdb, "SELECT status, repro_sha1, repro_len, "
			       "platforms FROM groups WHERE id = ?", -1, &sm,
			       NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *c;

		exists = 1;
		status = sqlite3_column_int(sm, 0);
		if ((c = (const char *)sqlite3_column_text(sm, 1)))
			lws_strncpy(old_sha1, c, sizeof(old_sha1));
		repro_len = (size_t)sqlite3_column_int64(sm, 2);
		if ((c = (const char *)sqlite3_column_text(sm, 3)))
			lws_strncpy(platforms, c, sizeof(platforms));
	}
	sqlite3_finalize(sm);

	/* the platforms it's been seen on, as a comma-separated set */

	if (platform && platform[0]) {
		const char *p = platforms;
		size_t pl = strlen(platform);
		int found = 0;

		while (*p) {
			const char *c = strchr(p, ',');
			size_t l = c ? (size_t)(c - p) : strlen(p);

			if (l == pl && !memcmp(p, platform, pl))
				found = 1;
			p += l + (c ? 1 : 0);
		}
		if (!found && strlen(platforms) + pl + 2 < sizeof(platforms))
			lws_snprintf(platforms + strlen(platforms),
				     sizeof(platforms) - strlen(platforms),
				     "%s%s", platforms[0] ? "," : "", platform);
	}

	if (!exists) {
		lwsl_notice("%s: %s: new group %s: %s %s\n", __func__, db->key,
			    id, kind, fr);

		if (sqlite3_prepare_v2(db->pdb, "INSERT INTO groups (id, sub, "
				"kind, frames, notify, hits, first_seen, "
				"last_seen, first_hash, last_hash, platforms, "
				"repro_name, repro_sha1, repro_len) VALUES "
				"(?,?,?,?,1,1,?,?,?,?,?,?,?,?)", -1, &sm,
				NULL) != SQLITE_OK)
			return;
		sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 2, sub, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 3, kind, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 4, fr, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(sm, 5, (sqlite3_int64)now);
		sqlite3_bind_int64(sm, 6, (sqlite3_int64)now);
		sqlite3_bind_text(sm, 7, hash, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 8, hash, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 9, platforms, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 10, input_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 11, sha1, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(sm, 12, (sqlite3_int64)input_len);
		if (sai_sqlite3_step_done(db->pdb, sm, "add group"))
			return;

		sais_findings_publish(db, sub, NULL, sha1, input, input_len);
		notify = 1;
	} else {
		/*
		 * Another finding of a bug we know.  If it was marked fixed,
		 * it's back: that's news again
		 */
		int regressed = status == SAIS_FINDINGS_FIXED;

		if (regressed)
			lwsl_notice("%s: %s: group %s regressed\n", __func__,
				    db->key, id);

		if (sqlite3_prepare_v2(db->pdb, "UPDATE groups SET hits = "
				"hits + 1, last_seen = ?, last_hash = ?, "
				"platforms = ?, status = CASE WHEN status = 1 "
				"THEN 0 ELSE status END, regressed = CASE "
				"WHEN status = 1 THEN 1 ELSE regressed END, "
				"acked = CASE WHEN status = 1 THEN 0 ELSE "
				"acked END, notify = CASE WHEN status = 1 "
				"THEN 1 ELSE notify END WHERE id = ?", -1, &sm,
				NULL) != SQLITE_OK)
			return;
		sqlite3_bind_int64(sm, 1, (sqlite3_int64)now);
		sqlite3_bind_text(sm, 2, hash, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 3, platforms, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 4, id, -1, SQLITE_TRANSIENT);
		if (sai_sqlite3_step_done(db->pdb, sm, "update group"))
			return;

		/* a smaller input is a better reproducer */

		if (status != SAIS_FINDINGS_WONTFIX && input_len < repro_len) {
			/*
			 * Only swap the published reproducer if the group
			 * now points at the new one
			 */
			if (sqlite3_prepare_v2(db->pdb, "UPDATE groups SET "
					"repro_name = ?, repro_sha1 = ?, "
					"repro_len = ? WHERE id = ?", -1, &sm,
					NULL) == SQLITE_OK) {
				sqlite3_bind_text(sm, 1, input_name, -1,
						  SQLITE_TRANSIENT);
				sqlite3_bind_text(sm, 2, sha1, -1,
						  SQLITE_TRANSIENT);
				sqlite3_bind_int64(sm, 3,
						   (sqlite3_int64)input_len);
				sqlite3_bind_text(sm, 4, id, -1,
						  SQLITE_TRANSIENT);
				if (!sai_sqlite3_step_done(db->pdb, sm,
							   "update reproducer"))
					sais_findings_publish(db, sub, old_sha1,
							      sha1, input,
							      input_len);
			}
		}

		notify = regressed;
	}

	/* the finding's files know their group */

	if (sqlite3_prepare_v2(db->pdb, "UPDATE findings SET group_id = ? WHERE "
			       "sub = ? AND (name = ? OR name = ? || '.log')",
			       -1, &sm, NULL) == SQLITE_OK) {
		sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 2, sub, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 3, input_name, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(sm, 4, input_name, -1, SQLITE_TRANSIENT);
		sai_sqlite3_step_done(db->pdb, sm, "set finding group");
	}

	if (notify)
		sais_findings_notify(vhd, db, id);
}

/* the blob of a finding file we have, or NULL; free() it after */

static uint8_t *
sais_findings_blob(sais_pool_db_t *db, const char *sub, const char *name,
		   size_t *len)
{
	uint8_t *b = NULL;
	sqlite3_stmt *sm;

	if (sqlite3_prepare_v2(db->pdb, "SELECT blob FROM findings WHERE "
			       "sub = ? AND name = ?", -1, &sm, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_text(sm, 1, sub, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 2, name, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		*len = (size_t)sqlite3_column_bytes(sm, 0);
		b = malloc(*len + 1);
		if (b) {
			if (*len)
				memcpy(b, sqlite3_column_blob(sm, 0), *len);
			b[*len] = '\0';
		}
	}
	sqlite3_finalize(sm);

	return b;
}

/*
 * The builder sent us a finding file (s-pool.c has stored it already)
 */

void
sais_findings_received(struct vhd *vhd, sais_pool_db_t *db, const char *sub_in,
		       size_t sub_len, const char *name_in, size_t name_len,
		       const uint8_t *data, size_t len, const char *hash,
		       const char *platform)
{
	char sub[33], name[65], other[70];
	uint8_t *b;
	size_t bl;

	lws_strnncpy(sub, sub_in, sub_len, sizeof(sub));
	lws_strnncpy(name, name_in, name_len, sizeof(name));

	if (name_len == 43 && !strncmp(name, "ok-", 3)) {
		sqlite3_stmt *sm;

		/* a known reproducer that doesn't crash at this commit */

		if (sqlite3_prepare_v2(db->pdb, "UPDATE groups SET "
				"last_ok_hash = ?, last_ok_time = ? WHERE "
				"sub = ? AND repro_sha1 = ?", -1, &sm,
				NULL) == SQLITE_OK) {
			sqlite3_bind_text(sm, 1, hash, -1, SQLITE_TRANSIENT);
			sqlite3_bind_int64(sm, 2, (sqlite3_int64)lws_now_secs());
			sqlite3_bind_text(sm, 3, sub, -1, SQLITE_TRANSIENT);
			sqlite3_bind_text(sm, 4, name + 3, -1, SQLITE_TRANSIENT);
			sai_sqlite3_step_done(db->pdb, sm, "set group last ok");
		}
		return;
	}

	if (name_len > 4 && !strcmp(name + name_len - 4, ".log")) {
		/* the report... do we have its input yet? */
		lws_strnncpy(other, name, name_len - 4, sizeof(other));
		b = sais_findings_blob(db, sub, other, &bl);
		if (!b)
			return;
		sais_findings_group(vhd, db, sub, other, b, bl,
				    (const char *)data, len, hash, platform);
		free(b);
		return;
	}

	/* the input... do we have its report yet? */

	lws_snprintf(other, sizeof(other), "%s.log", name);
	b = sais_findings_blob(db, sub, other, &bl);
	if (!b)
		return;
	sais_findings_group(vhd, db, sub, name, data, len, (const char *)b, bl,
			    hash, platform);
	free(b);
}

/*
 * An admin changed a group in sai-web
 */

void
sais_findings_set(struct vhd *vhd, const char *repo, const char *pool,
		  const char *group, const char *op)
{
	char sub[33] = "", sha1[41] = "", rname[65] = "";
	sais_pool_db_t *db;
	sqlite3_stmt *sm;
	const char *q;
	size_t n;

	if (!sai_pool_name_ok(pool) || sai_str_has_shell_metachars(repo) ||
	    strlen(group) != 16)
		return;
	for (n = 0; n < 16; n++)
		if (!((group[n] >= '0' && group[n] <= '9') ||
		      (group[n] >= 'a' && group[n] <= 'f')))
			return;

	if (!strcmp(op, "ack"))
		q = "UPDATE groups SET acked = 1 WHERE id = ?";
	else if (!strcmp(op, "fixed"))
		q = "UPDATE groups SET status = 1, acked = 1, regressed = 0 "
		    "WHERE id = ?";
	else if (!strcmp(op, "wontfix"))
		q = "UPDATE groups SET status = 2, acked = 1 WHERE id = ?";
	else if (!strcmp(op, "reopen"))
		q = "UPDATE groups SET status = 0 WHERE id = ?";
	else {
		lwsl_notice("%s: unknown op %s\n", __func__, op);
		return;
	}

	db = sais_pool_db_get(vhd, repo, pool);
	if (!db)
		return;

	if (sqlite3_prepare_v2(db->pdb, q, -1, &sm, NULL) == SQLITE_OK) {
		sqlite3_bind_text(sm, 1, group, -1, SQLITE_TRANSIENT);
		sai_sqlite3_step_done(db->pdb, sm, "change group");
	}

	lwsl_notice("%s: %s: %s %s\n", __func__, db->key, op, group);

	/*
	 * A bug nobody's going to fix isn't replayed; one that's reopened is
	 * again.  Fixed ones still are, to catch them coming back.
	 */

	if ((!strcmp(op, "wontfix") || !strcmp(op, "reopen")) &&
	    sqlite3_prepare_v2(db->pdb, "SELECT sub, repro_sha1, repro_name "
			       "FROM groups WHERE id = ?", -1, &sm,
			       NULL) == SQLITE_OK) {
		sqlite3_bind_text(sm, 1, group, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(sm) == SQLITE_ROW) {
			const char *c;

			if ((c = (const char *)sqlite3_column_text(sm, 0)))
				lws_strncpy(sub, c, sizeof(sub));
			if ((c = (const char *)sqlite3_column_text(sm, 1)))
				lws_strncpy(sha1, c, sizeof(sha1));
			if ((c = (const char *)sqlite3_column_text(sm, 2)))
				lws_strncpy(rname, c, sizeof(rname));
		}
		sqlite3_finalize(sm);

		if (sub[0] && strlen(sha1) == 40) {
			if (!strcmp(op, "wontfix"))
				sais_findings_publish(db, sub, sha1, NULL,
						      NULL, 0);
			else {
				uint8_t *b;
				size_t bl;

				b = sais_findings_blob(db, sub, rname, &bl);
				if (b)
					sais_findings_publish(db, sub, NULL,
							      sha1, b, bl);
				free(b);
			}
		}
	}

	sais_pool_db_put(db);
}
