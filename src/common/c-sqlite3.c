/*
 * Sai common utils
 *
 * Copyright (C) 2025 Andy Green <andy@warmcat.com>
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
 */

#include <libwebsockets.h>
#include <sqlite3.h>

#include <assert.h>
#include <errno.h>

#include "include/private.h"

/*
 * Event dbs made before tasks could have several runs have idx_task_uuid on
 * tasks(uuid) alone, and need it rebuilt on tasks(uuid, run).  Only do that
 * when the index needs it: rebuilding it takes the db write lock, and both
 * sai-server and sai-web open event dbs while sai-server is writing a live
 * event's logs into them.
 */
static int
sai_task_index_needs_run(sqlite3 *pdb)
{
	sqlite3_stmt *sm;
	const char *sql;
	int r = 0;

	if (sqlite3_prepare_v2(pdb, "SELECT sql FROM sqlite_master WHERE "
			       "type='index' AND name='idx_task_uuid'", -1,
			       &sm, NULL) != SQLITE_OK)
		return 0;

	if (sqlite3_step(sm) == SQLITE_ROW) {
		sql = (const char *)sqlite3_column_text(sm, 0);
		r = !sql || !strstr(sql, "run");
	} else
		/* missing entirely */
		r = 1;

	sqlite3_finalize(sm);

	return r;
}

int
sai_event_db_ensure_open(struct lws_context *cx, lws_dll2_owner_t *sqlite3_cache,
			 const char *sqlite3_path_lhs, const char *event_uuid,
			 char create_if_needed, sqlite3 **ppdb)
{
	char filepath[256], saf[33];
	sais_sqlite_cache_t *sc;

	// lwsl_notice("%s: (sai-server) entry\n", __func__);

	if (*ppdb)
		return 0;

	/* do we have this guy cached? */

	lws_start_foreach_dll(struct lws_dll2 *, p, sqlite3_cache->head) {
		sc = lws_container_of(p, sais_sqlite_cache_t, list);

		if (!strcmp(event_uuid, sc->uuid)) {
			sc->refcount++;
			*ppdb = sc->pdb;
			return 0;
		}

	} lws_end_foreach_dll(p);

	/* ... nope, well, let's open and cache him then... */

	lws_strncpy(saf, event_uuid, sizeof(saf));
	lws_filename_purify_inplace(saf);

	lws_snprintf(filepath, sizeof(filepath), "%s-event-%s.sqlite3",
		     sqlite3_path_lhs, saf);

	if (lws_struct_sq3_open(cx, filepath, create_if_needed, ppdb)) {
		lwsl_err("%s: Unable to open db %s: %s\n", __func__,
			 filepath, sqlite3_errmsg(*ppdb));

		return 2;
	}

	sqlite3_busy_timeout(*ppdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);

	/*
	 * create / add to the schema for the tables we will have in here.
	 *
	 * On an existing db, none of this writes: "if not exists" finds the
	 * table or index already there, an ALTER TABLE adding a column that
	 * exists fails when it is prepared, and journal_mode=WAL is already
	 * set.  That matters since the other daemon may be writing to it.
	 */

	if (lws_struct_sq3_create_table(*ppdb, lsm_schema_sq3_map_task)) {
		lwsl_err("%s: unable to create task table in %s\n", __func__, filepath);
		return 3;
	}

	{
		char *err = NULL;
		sqlite3_exec(*ppdb, "ALTER TABLE tasks ADD COLUMN task_log_limit integer;", NULL, NULL, &err);
		if (err) sqlite3_free(err);
		err = NULL;
		sqlite3_exec(*ppdb, "ALTER TABLE tasks ADD COLUMN parallel integer;", NULL, NULL, &err);
		if (err) sqlite3_free(err);
		err = NULL;
		sqlite3_exec(*ppdb, "ALTER TABLE tasks ADD COLUMN rebuildable integer;", NULL, NULL, &err);
		if (err) sqlite3_free(err);
		err = NULL;
		sqlite3_exec(*ppdb, "ALTER TABLE tasks ADD COLUMN run integer;", NULL, NULL, &err);
		if (err) sqlite3_free(err);
	}

	sai_sqlite3_statement(*ppdb, "CREATE UNIQUE INDEX IF NOT EXISTS idx_task_uuid ON tasks(uuid, run);", "create task index");

	sai_sqlite3_statement(*ppdb, "PRAGMA journal_mode=WAL;", "set WAL");

	if (lws_struct_sq3_create_table(*ppdb, lsm_schema_sq3_map_log)) {
		lwsl_err("%s: unable to create log table in %s\n", __func__, filepath);

		return 4;
	}

	sai_sqlite3_statement(*ppdb, "CREATE INDEX IF NOT EXISTS idx_log_task_time ON logs(task_uuid, timestamp);", "create log index");

	if (lws_struct_sq3_create_table(*ppdb, lsm_schema_sq3_map_artifact)) {
		lwsl_err("%s: unable to create artifact table in %s\n", __func__, filepath);

		return 5;
	}

	sai_sqlite3_statement(*ppdb, "CREATE INDEX IF NOT EXISTS idx_art_task ON artifacts(task_uuid);", "create artifact index");

	if (sai_task_index_needs_run(*ppdb)) {
		lwsl_notice("%s: migrating idx_task_uuid in %s\n", __func__,
			    filepath);
		sqlite3_exec(*ppdb, "DROP INDEX IF EXISTS idx_task_uuid;",
			     NULL, NULL, NULL);
		sai_sqlite3_statement(*ppdb, "CREATE UNIQUE INDEX idx_task_uuid "
				      "ON tasks(uuid, run);", "migrate task index");
	}

	sc = malloc(sizeof(*sc));
	if (!sc) {
		lwsl_err("%s: unable to alloc sc for %s\n", __func__, filepath);

		lws_struct_sq3_close(ppdb);
		*ppdb = NULL;
		return 6;
	}

	memset(sc, 0, sizeof(*sc));

	lws_strncpy(sc->uuid, event_uuid, sizeof(sc->uuid));
	sc->refcount = 1;
	sc->pdb = *ppdb;
	lws_dll2_add_tail(&sc->list, sqlite3_cache);

	return 0;
}


void
sai_event_db_close(lws_dll2_owner_t *sqlite3_cache, sqlite3 **ppdb)
{
	sais_sqlite_cache_t *sc;

	if (!*ppdb)
		return;

	/* look for him in the cache */

	lws_start_foreach_dll(struct lws_dll2 *, p, sqlite3_cache->head) {
		sc = lws_container_of(p, sais_sqlite_cache_t, list);

		if (sc->pdb == *ppdb) {
			*ppdb = NULL;
			if (!--sc->refcount) {
				lwsl_info("%s: zero refcount to idle\n",
						__func__);
				/*
				 * He's not currently in use then... don't
				 * close him immediately, s-central.c has a
				 * timer that closes and removes sqlite3
				 * cache entries idle for longer than 60s
				 */
				sc->idle_since = lws_now_usecs();
			}

			return;
		}

	} lws_end_foreach_dll(p);

	lws_struct_sq3_close(ppdb);
	*ppdb = NULL;
}

int
sai_event_db_close_all_now(lws_dll2_owner_t *sqlite3_cache)
{
	sais_sqlite_cache_t *sc;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   sqlite3_cache->head) {
		sc = lws_container_of(p, sais_sqlite_cache_t, list);

		lws_struct_sq3_close(&sc->pdb);
		lws_dll2_remove(&sc->list);
		free(sc);

	} lws_end_foreach_dll_safe(p, p1);

	return 0;
}

int
sai_event_db_delete_database(const char *sqlite3_path_lhs, const char *event_uuid)
{
	char filepath[256], saf[33], r = 0, ra = 0;

	lws_strncpy(saf, event_uuid, sizeof(saf));
	lws_filename_purify_inplace(saf);

	lws_snprintf(filepath, sizeof(filepath), "%s-event-%s.sqlite3",
		     sqlite3_path_lhs, saf);

	r = (char)!!unlink(filepath);
	if (r) {
		lwsl_err("%s: unable to delete %s (%d)\n", __func__, filepath, errno);
		ra = 1;
	}

	lws_snprintf(filepath, sizeof(filepath), "%s-event-%s.sqlite3-wal",
		     sqlite3_path_lhs, saf);

	r = (char)!!unlink(filepath);
	if (r) {
		lwsl_err("%s: unable to delete %s (%d)\n", __func__, filepath, errno);
		ra = 1;
	}

	lws_snprintf(filepath, sizeof(filepath), "%s-event-%s.sqlite3-shm",
		     sqlite3_path_lhs, saf);

	r = (char)!!unlink(filepath);
	if (r) {
		lwsl_err("%s: unable to delete %s (%d)\n", __func__, filepath, errno);
		ra = 1;
	}

	if (!ra)
		lwsl_notice("%s: deleted %s OK\n", __func__, filepath);

	return ra;
}

/* len is typically 16 (event uuid is 32 chars + NUL)
 * But eg, task uuid is concatenated 32-char eventid and 32-char taskid
 */

int
sai_sqlite3_statement(sqlite3 *pdb, const char *cmd, const char *desc)
{
	sqlite3_stmt *sm;
	int n;

	if (sqlite3_prepare_v2(pdb, cmd, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: Unable to %s: %s\n",
			 __func__, desc, sqlite3_errmsg(pdb));

		return 1;
	}

	n = sqlite3_step(sm);
	sqlite3_reset(sm);
	sqlite3_finalize(sm);
	if (n != SQLITE_DONE) {
		n = sqlite3_extended_errcode(pdb);
		if (!n) {
			lwsl_info("%s: failed '%s'\n", __func__, cmd);
			return 0;
		}

		lwsl_err("%s: %d: Unable to perform \"%s\": %s\n", __func__,
			 n, desc, sqlite3_errmsg(pdb));
		puts(cmd);

		return 1;
	}

	return 0;
}
