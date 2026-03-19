/*
 * Sai server
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 *
 * Central dispatcher for jobs from events that made it into the database.  This
 * is done in an event-driven way in m-task.c, but management of it also has to
 * be done in the background for when there are no events coming,
 */

#include <libwebsockets.h>


#include "s-private.h"

extern struct lws_context *context;

static void
sais_central_clean_abandoned(struct vhd *vhd)
{
	sais_sqlite_cache_t *sc;
	struct lwsac *ac = NULL;
	lws_usec_t now = lws_now_usecs();
	lws_dll2_owner_t o;
	char s[160];
	int n, nzr;

	/*
	 * Sqlite cache cleaning
	 */

	nzr = 0;
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->sqlite3_cache.head) {
		sc = lws_container_of(p, sais_sqlite_cache_t, list);

		if (!sc->refcount &&
		    (now - sc->idle_since) > (60 * LWS_USEC_PER_SEC)) {
			lwsl_info("%s: delayed db pool clean %s\n", __func__,
					sc->uuid);
			lws_struct_sq3_close(&sc->pdb);
			lws_dll2_remove(&sc->list);
			free(sc);
		} else
			if (sc->refcount)
				nzr++;

	} lws_end_foreach_dll_safe(p, p1);

	if (vhd->sqlite3_cache.count)
		lwsl_notice("%s: db pool items: in-use: %d, total: %d\n",
			    __func__, nzr, vhd->sqlite3_cache.count);

	/*
	 * Collect the most recent <=10 events that still feel they're
	 * incomplete and may be running something
	 */

	n = lws_struct_sq3_deserialize(vhd->server.pdb,
				       " and (state != 3 and state != 4 and state != 5)",
				       NULL, lsm_schema_sq3_map_event, &o,
				       &ac, 0, 10);
	if (n < 0 || !o.head)
		return;

	/*
	 * For each of those events, look for tasks that have been running
	 * "too long", eg, builder restarted or lost connection etc
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, o.head) {
		sai_event_t *e = lws_container_of(p, sai_event_t, list);
		sqlite3 *pdb = NULL;

		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {
			char *err = NULL;

			/*
			 * Check for tasks that have waited long enough since
			 * the notification to allow to be built
			 */

			lws_snprintf(s, sizeof(s),
				     "update tasks set state=0 where "
				     "(state=%u) and last_updated < %llu",
				     SAIES_NOT_READY_FOR_BUILD, (unsigned long long)
					     (lws_now_secs() - 5));

			if (sqlite3_exec(pdb, s, NULL, NULL, &err) !=
					 SQLITE_OK) {
				lwsl_err("%s: %s: %s: fail\n", __func__, s,
					 sqlite3_errmsg(pdb));
				if (err)
					sqlite3_free(err);
			}

			/*
			 * Check for tasks that have been running too long
			 */
			sqlite3_stmt *sm;

			lws_snprintf(s, sizeof(s),
				     "SELECT uuid FROM tasks WHERE "
				     "(state = %d OR state = %d) AND "
				     "started != 0 AND started < %llu",
				     SAIES_PASSED_TO_BUILDER,
				     SAIES_BEING_BUILT, (unsigned long long)
					(lws_now_secs() -
					 (vhd->task_abandoned_timeout_mins * 60)));

			if (sqlite3_prepare_v2(pdb, s, -1, &sm, NULL) == SQLITE_OK) {
				while (sqlite3_step(sm) == SQLITE_ROW) {
					const unsigned char *task_uuid = sqlite3_column_text(sm, 0);
					if (task_uuid) {
						lwsl_notice("%s: resetting abandoned task %s\n",
								__func__, (const char *)task_uuid);
						sais_task_clear_build_and_logs(vhd, (const char *)task_uuid, 0);
					}
				}
				sqlite3_finalize(sm);
			}

			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}

	} lws_end_foreach_dll(p);

	lwsac_free(&ac);
}

/* Check if we need to create new tables or add columns */
static void
sais_ensure_tables(struct vhd *vhd)
{
	char *err = NULL;

	/* We already added power_controllers and pcon_builders,
	 * but we need to make sure 'builders' table has 'pcon' column.
	 */

	/* Try adding the column, ignore error if it exists */
	sqlite3_exec(vhd->server.pdb, "ALTER TABLE builders ADD COLUMN pcon varchar(64);", NULL, NULL, &err);
	if (err) {
		/* lwsl_notice("%s: (stateless) %s\n", __func__, err); */
		sqlite3_free(err);
	}

	sai_sqlite3_statement(vhd->server.pdb,
		"CREATE TABLE IF NOT EXISTS power_controllers ("
		" name varchar(64) primary key,"
		" type varchar(32),"
		" url varchar(128),"
		" depends_on varchar(64),"
		" state integer"
		");", "create pcon table");

	sai_sqlite3_statement(vhd->server.pdb,
		"CREATE TABLE IF NOT EXISTS pcon_builders ("
		" pcon_name varchar(64),"
		" builder_name varchar(64)"
		");", "create pcon_builders table");

}

void
sais_central_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_central);

	/*
	 * Need to globally check for abandoned tasks periodically
	 */

	if (!vhd->last_check_abandoned_tasks ||
	    lws_now_usecs() > (vhd->last_check_abandoned_tasks +
			       (3 * 60 * LWS_USEC_PER_SEC))) {

		sais_central_clean_abandoned(vhd);

		/* Also ensure tables exist periodically/on startup */
		if (!vhd->last_check_abandoned_tasks)
			sais_ensure_tables(vhd);

		vhd->last_check_abandoned_tasks = lws_now_usecs();
	}

	/*
	 * Wake up builders if there are new tasks that just became mature enough
	 * (older than 10s)
	 */
	sais_prune_inflight_list(vhd);
	sais_platforms_with_tasks_pending(vhd);

	/* check again in 1s */

	lws_sul_schedule(context, 0, &vhd->sul_central, sais_central_cb,
			 1 * LWS_US_PER_SEC);
}
