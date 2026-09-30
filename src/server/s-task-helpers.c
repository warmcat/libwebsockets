/*
 * Sai server
 *
 * Copyright (C) 2019 - 2025 Andy Green <andy@warmcat.com>
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
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "s-private.h"

/*
 * Count the build steps the builder will split "build" into: one per line,
 * plus the git mirror and checkout steps that precede them.
 */
int
sais_task_build_step_count(const char *build)
{
	const char *p = build;
	int c = 2; /* git mirror and checkout */

	if (!build || !build[0])
		return c;

	c++;
	while (*p)
		if (*p++ == '\n')
			c++;
	if (build[strlen(build) - 1] == '\n')
		c--;

	return c;
}

/*
 * Finish and insert a task as a new row in an event's database.
 *
 * The caller has already set the per-configuration strings (platform,
 * taskname, build, packages, artifacts...); this fills in everything that is
 * derived from the event or must be freshly minted per task: uuids, artifact
 * nonces, uid, the repo / ref / hash pointers used in the offer, and the step
 * count.  Shared by the hook notification path (one task per platform per
 * configuration) and the ad-hoc clone path (one task).
 */
int
sais_task_insert(struct lws_context *cx, sqlite3 *pdb, sai_event_t *e,
		 sai_task_t *t, int uid)
{
	lws_dll2_owner_t owner;

	/*
	 * task uuid is the event uuid and another random 32 chars, so you
	 * can always recover the related event uuid from the task uuid
	 */
	memcpy(t->uuid, e->uuid, 32);
	sai_uuid16_create(cx, t->uuid + 32);
	lws_strncpy(t->event_uuid, e->uuid, sizeof(t->event_uuid));
	t->uid = uid;

	/*
	 * This is basically a secret that anything trying to upload an
	 * artifact for the task must provide to authenticate.
	 */
	sai_uuid16_create(cx, t->art_up_nonce);
	/*
	 * An unrelated secret that anything trying to download an artifact
	 * for the task must provide to identify it.
	 */
	sai_uuid16_create(cx, t->art_down_nonce);

	t->git_repo_url		= e->repo_fetchurl;
	t->repo_name		= e->repo_name;
	t->git_ref		= e->ref;
	t->git_hash		= e->hash;
	t->build_step_count	= sais_task_build_step_count(t->build);
	t->parallel		= 2;

	e->last_updated = (unsigned long long)lws_now_secs();
	e->state = SAIES_WAITING;

	lws_dll2_clear(&t->list);
	lws_dll2_owner_clear(&owner);
	lws_dll2_add_head(&t->list, &owner);

	return lws_struct_sq3_serialize(pdb, lsm_schema_sq3_map_task, &owner,
					(uint32_t)uid);
}

void
sais_get_task_metrics_estimates(struct vhd *vhd, sai_task_t *task)
{
	char query[256], hex[65];
	sqlite3_stmt *stmt;

	task->est_peak_mem_kib	= 0;
	task->est_disk_kib	= 0;
	task->est_wallclock_ms	= 0; /* actually total us compute */
	task->est_compute_ms	= 0;

	if (!vhd->pdb_metrics || !task->repo_name || !task->builder[0] ||
	    !task->taskname[0])
		return;

	if (sai_metrics_hash((uint8_t *)hex, sizeof(hex), task->repo_name,
			     task->builder, task->taskname, task->git_ref))
		return;

	lws_snprintf(query, sizeof(query),
		     "SELECT peak_mem_rss, stg_bytes, wallclock_us, us_cpu_user, us_cpu_sys "
		     "FROM build_metrics "
		     "ORDER BY unixtime DESC "
		     "WHERE key = '%s' and step = %d "
		     "LIMIT 1", hex, task->build_step + 1);

	if (sqlite3_prepare_v2(vhd->pdb_metrics, query, -1, &stmt, NULL) != SQLITE_OK)
		return;

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		if (sqlite3_column_type(stmt, 0) != SQLITE_NULL)
			task->est_peak_mem_kib = (unsigned int)sqlite3_column_int(stmt, 0);
		if (sqlite3_column_type(stmt, 1) != SQLITE_NULL)
			task->est_disk_kib = (unsigned int)sqlite3_column_int(stmt, 1);
		if (sqlite3_column_type(stmt, 2) != SQLITE_NULL)
			task->est_wallclock_ms = (unsigned int)(sqlite3_column_int(stmt, 2) / 1000);
		if (sqlite3_column_type(stmt, 3) != SQLITE_NULL &&
		    sqlite3_column_type(stmt, 4) != SQLITE_NULL)
			task->est_compute_ms = (unsigned int)((sqlite3_column_int(stmt, 3) +
							       sqlite3_column_int(stmt, 4)) / 1000);
	}

	sqlite3_finalize(stmt);
}

int
sais_bind_task_to_builder(struct vhd *vhd, const char *builder_name,
			  const char *builder_uuid, const char *task_uuid)
{
	char update[512], esc[96], esc1[96], esc2[96], event_uuid[33];
	struct lwsac *ac = NULL;
	sai_event_t *e = NULL;
	lws_dll2_owner_t o;
	int n, r = 1;

	/*
	 * Extract the event uuid from the task uuid
	 */

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	/*
	 * Look up the task's event in the event database...
	 */

	lws_dll2_owner_clear(&o);
	lws_sql_purify(esc1, event_uuid, sizeof(esc1));
	lws_snprintf(esc2, sizeof(esc2), " and uuid='%s'", esc1);
	n = lws_struct_sq3_deserialize(vhd->server.pdb, esc2, NULL,
				       lsm_schema_sq3_map_event, &o, &ac, 0, 1);
	if (n < 0 || !o.head) {
		lwsl_err("%s: failed to get task_uuid %s\n", __func__, esc1);
		goto bail;
	}

	e = lws_container_of(o.head, sai_event_t, list);

	/*
	 * Open the event-specific database on the temporary event object
	 */

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, (sqlite3 **)&e->pdb)) {
		lwsl_err("%s: unable to open event-specific database\n",
				__func__);

		return -1;
	}

	if (builder_name)
		lws_sql_purify(esc, builder_name, sizeof(esc));
	else
		esc[0] = '\0';

	if (builder_uuid)
		lws_sql_purify(esc1, builder_uuid, sizeof(esc1));
	else
		esc1[0] = '\0';
	lws_sql_purify(esc2, task_uuid, sizeof(esc2));

	/*
	 * Update the task by uuid, in the event-specific database
	 */

	lws_snprintf(update, sizeof(update),
		"update tasks set builder='%s',builder_name='%s' where uuid='%s' and run=(select max(run) from tasks where uuid='%s')",
		 esc1, esc, esc2, esc2);

	if (sqlite3_exec((sqlite3 *)e->pdb, update, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s: fail\n", __func__, update,
			 sqlite3_errmsg(vhd->server.pdb));
		goto bail;
	}

	r = 0;

bail:
	if (e)
		sai_event_db_close(&vhd->sqlite3_cache, (sqlite3 **)&e->pdb);
	lwsac_free(&ac);

	return r;
}

int
sais_set_task_state(struct vhd *vhd, const char *task_uuid,
		    sai_event_state_t state, uint64_t started, uint64_t duration)
{
	char update[512], esc1[96], esc2[96], esc3[32], esc4[32], event_uuid[33];
	sai_event_state_t oes, sta, task_ostate;
	unsigned int count = 0, count_good = 0, count_bad = 0;
	int idle = 0;
	uint64_t started_orig = started;
	struct lwsac *ac = NULL;
	sai_event_t *e = NULL;
	lws_dll2_owner_t o;
	int n;

	/*
	 * Extract the event uuid from the task uuid
	 */

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	/*
	 * Look up the task's event in the event database...
	 */

	lws_dll2_owner_clear(&o);
	lws_sql_purify(esc1, event_uuid, sizeof(esc1));
	lws_snprintf(esc2, sizeof(esc2), " and uuid='%s'", esc1);
	n = lws_struct_sq3_deserialize(vhd->server.pdb, esc2, NULL,
				       lsm_schema_sq3_map_event, &o, &ac, 0, 1);
	if (n < 0 || !o.head) {
		lwsl_err("%s: failed to get task_uuid %s\n", __func__, esc1);
		goto bail;
	}

	e = lws_container_of(o.head, sai_event_t, list);
	oes = e->state;

	/*
	 * Open the event-specific database on the temporary event object
	 */

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, (sqlite3 **)&e->pdb)) {
		lwsl_err("%s: unable to open event-specific database\n",
				__func__);

		return -1;
	}

	lws_sql_purify(esc2, task_uuid, sizeof(esc2));

	esc3[0] = esc4[0] = '\0';

	/*
	 * grab the current state of it for seeing if it changed
	 */
	lws_snprintf(update, sizeof(update),
		     "select state from tasks where uuid='%s' order by run desc limit 1", esc2);
	if (sqlite3_exec((sqlite3 *)e->pdb, update,
			 sql3_get_integer_cb, &task_ostate, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s: fail\n", __func__, update,
			 sqlite3_errmsg(vhd->server.pdb));
		goto bail;
	}

	lws_snprintf(update, sizeof(update),
		     "select idle from tasks where uuid='%s' order by run desc limit 1", esc2);
	if (sqlite3_exec((sqlite3 *)e->pdb, update,
			 sql3_get_integer_cb, &idle, NULL) != SQLITE_OK)
		idle = 0;

	if (task_ostate == SAIES_PAUSED &&
	    (state == SAIES_BEING_BUILT || state == SAIES_PASSED_TO_BUILDER ||
	     state == SAIES_STEP_SUCCESS || state == SAIES_FAIL ||
	     state == SAIES_CANCELLED || state == SAIES_SUCCESS))
		state = SAIES_PAUSED;

	if (started) {
		if (started == 1)
			lws_snprintf(esc3, sizeof(esc3), ",started=0");
		else
			lws_snprintf(esc3, sizeof(esc3), ",started=%llu",
			     (unsigned long long)started);
	}
	if (duration) {
		if (duration == 1)
			duration = 0;
		lws_snprintf(esc4, sizeof(esc4), ",duration=%llu",
			     (unsigned long long)duration);
	}

	/*
	 * Update the task by uuid, in the event-specific database
	 */

	lws_snprintf(update, sizeof(update),
		"update tasks set state=%d%s%s%s where uuid='%s' and run=(select max(run) from tasks where uuid='%s')", state,
		esc3, esc4, state == SAIES_WAITING && started_orig == 1 ?
						",build_step=0" : "", esc2, esc2);

	if (sqlite3_exec((sqlite3 *)e->pdb, update, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s: fail\n", __func__, update,
			 sqlite3_errmsg(vhd->server.pdb));
		goto bail;
	}

	/*
	 * We tell interested parties about logs separately.  So there's only
	 * something to tell about change to task state if he literally changed
	 * the state
	 */

	if (state != task_ostate) {

		if ((state == SAIES_PASSED_TO_BUILDER ||
		     state == SAIES_BEING_BUILT) &&
		    !vhd->sul_activity.list.owner)
			lws_sul_schedule(vhd->context, 0, &vhd->sul_activity,
					 sais_activity_cb, 1 * LWS_US_PER_SEC);

		lwsl_notice("%s: seen task [%s st %d -> %d\n", __func__,
				task_uuid, task_ostate, state);

		sais_taskchange(vhd->h_ss_websrv, task_uuid, state);

		if (state == SAIES_SUCCESS || state == SAIES_FAIL ||
		    state == SAIES_CANCELLED || state == SAIES_YIELDED)
			lws_sul_schedule(vhd->context, 0, &vhd->sul_central,
					 sais_central_cb, 1);

		if (state != SAIES_STEP_SUCCESS)
			sais_platforms_with_tasks_pending(vhd);

		if (idle) {
			/*
			 * Idle tasks have no say in their event's state, it
			 * was decided by the real tasks.  But the end of a
			 * slice is when its builder starts to owe rest.
			 */
			if (state == SAIES_SUCCESS || state == SAIES_FAIL ||
			    state == SAIES_CANCELLED || state == SAIES_YIELDED)
				sais_idle_slice_ended(vhd, (sqlite3 *)e->pdb,
						      task_uuid);
			goto done;
		}

		/*
		 * So, how many tasks for this event?
		 */

		if (sqlite3_exec((sqlite3 *)e->pdb, "select count(*) from (select max(run) from tasks where idle=0 group by uuid)",
				 sql3_get_integer_cb, &count, NULL) != SQLITE_OK) {
			lwsl_err("%s: %s: %s: fail\n", __func__, update,
				 sqlite3_errmsg(vhd->server.pdb));
			goto bail;
		}

		/*
		 * ... how many completed well?
		 */

		if (sqlite3_exec((sqlite3 *)e->pdb, "select count(*) from (select max(run) as mx, state from tasks where idle=0 group by uuid) where state == 3",
				 sql3_get_integer_cb, &count_good, NULL) != SQLITE_OK) {
			lwsl_err("%s: %s: %s: fail\n", __func__, update,
				 sqlite3_errmsg(vhd->server.pdb));
			goto bail;
		}

		/*
		 * ... how many failed?
		 */

		if (sqlite3_exec((sqlite3 *)e->pdb, "select count(*) from (select max(run) as mx, state from tasks where idle=0 group by uuid) where state == 4",
				 sql3_get_integer_cb, &count_bad, NULL) != SQLITE_OK) {
			lwsl_err("%s: %s: %s: fail\n", __func__, update,
				 sqlite3_errmsg(vhd->server.pdb));
			goto bail;
		}

		/*
		 * Decide how to set the event state based on that
		 */

		lwsl_notice("%s: ev %s, task %s, state %d -> %d, count %u, good %u, bad %u, oes %d\n",
			    __func__, event_uuid, task_uuid, task_ostate, state,
			    count, count_good, count_bad, (int)oes);

		sta = SAIES_BEING_BUILT;

		if (count) {
			if (count == count_good)
				sta = SAIES_SUCCESS;
			else
				if (count == count_bad)
					sta = SAIES_FAIL;
				else
					if (count_bad)
						sta = SAIES_BEING_BUILT_HAS_FAILURES;
		}

		if (oes == SAIES_DELETED)
			sta = SAIES_DELETED;

		if (sta != oes) {
			lwsl_notice("%s: event state changed\n", __func__);

			/*
			 * Update the event
			 */

			lws_sql_purify(esc1, event_uuid, sizeof(esc1));
			lws_snprintf(update, sizeof(update),
				"update events set state=%d where uuid='%s'", sta, esc1);

			if (sqlite3_exec(vhd->server.pdb, update, NULL, NULL, NULL) != SQLITE_OK) {
				lwsl_err("%s: %s: %s: fail\n", __func__, update,
					 sqlite3_errmsg(vhd->server.pdb));
				goto bail;
			}

			sais_eventchange(vhd->h_ss_websrv, event_uuid, (int)sta);
		}
	}

done:
	sai_event_db_close(&vhd->sqlite3_cache, (sqlite3 **)&e->pdb);
	lwsac_free(&ac);



	return 0;

bail:
	if (e)
		sai_event_db_close(&vhd->sqlite3_cache, (sqlite3 **)&e->pdb);
	lwsac_free(&ac);

	return 1;
}

int
sais_task_pause(struct vhd *vhd, const char *task_uuid)
{
	char event_uuid[33], esc_uuid[129], q[384];
	int build_step = -1, state = -1;
	sqlite3 *pdb = NULL;

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);
	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		lwsl_err("%s: unable to open db for event %s\n", __func__, event_uuid);
		return -1;
	}

	lws_sql_purify(esc_uuid, task_uuid, sizeof(esc_uuid));
	lws_snprintf(q, sizeof(q),
		     "select build_step,state from tasks where uuid='%s' order by run desc limit 1",
		     esc_uuid);

	if (sqlite3_exec(pdb, q, sql3_get_integer_cb, &build_step,
			 NULL) != SQLITE_OK)
		build_step = -1;
	/* sql3_get_integer_cb will put the last column in there */
	if (sqlite3_exec(pdb, q, sql3_get_integer_cb, &state,
			 NULL) != SQLITE_OK)
		state = -1;

	if (state == SAIES_PASSED_TO_BUILDER || state == SAIES_BEING_BUILT) {
		/*
		 * If it's already building, we need to cancel it on the
		 * builder and decrement the step so it restarts this step
		 * on resume
		 */
		if (build_step > 0) {
			build_step--;
			lws_snprintf(q, sizeof(q),
				     "update tasks set build_step=%d where uuid='%s' and run=(select max(run) from tasks where uuid='%s')",
				     build_step, esc_uuid, esc_uuid);
			sqlite3_exec(pdb, q, NULL, NULL, NULL);
		}
		sais_task_stop_on_builders(vhd, task_uuid, 0);
	}

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	return sais_set_task_state(vhd, task_uuid, SAIES_PAUSED, 0, 0);
}

int
sais_task_cancel(struct vhd *vhd, const char *task_uuid, int erase, int killed)
{
	sai_cancel_t *can;

	/*
	 * For every pss that we have from builders...
	 */
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->builders.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);


		/*
		 * ... queue the task cancel message
		 */
		can = malloc(sizeof *can);
		if (!can)
			return -1;
		memset(can, 0, sizeof(*can));

		lws_strncpy(can->task_uuid, task_uuid, sizeof(can->task_uuid));
		can->erase = (unsigned int)erase;
		can->killed = (unsigned int)killed;

		lws_dll2_add_tail(&can->list, &pss->task_cancel_owner);

		lws_callback_on_writable(pss->wsi);

	} lws_end_foreach_dll(p);

	sais_taskchange(vhd->h_ss_websrv, task_uuid, SAIES_CANCELLED);

	/*
	 * Recompute startable task platforms and broadcast to all sai-power,
	 * after there has been a change in tasks
	 */
	sais_platforms_with_tasks_pending(vhd);

	return 0;
}

int
sais_task_stop_on_builders(struct vhd *vhd, const char *task_uuid, int killed)
{
	char event_uuid[33], builder_name[128], esc_uuid[129], q[128];
	struct pss *pss_match = NULL;
	sqlite3 *pdb = NULL;
	sai_cancel_t *can;
	sai_plat_t *sp;

	lwsl_notice("%s: builders count %d\n", __func__, vhd->builders.count);

	/*
	 * We will send the task cancel message only to the builder that was
	 * assigned the task, if any.
	 */

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		lwsl_err("%s: unable to open event-specific database\n", __func__);
		return -1;
	}

	builder_name[0] = '\0';
	lws_sql_purify(esc_uuid, task_uuid, sizeof(esc_uuid));
	lws_snprintf(q, sizeof(q), "select builder_name from tasks where uuid='%s' order by run desc limit 1",
		     esc_uuid);
	if (sqlite3_exec(pdb, q, sql3_get_string_cb, builder_name, NULL) !=
							SQLITE_OK ||
	    !builder_name[0]) {
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		/*
		 * This is not an error... the task may not have had a builder
		 * assigned yet.  There's nothing to do.
		 */
		return 0;
	}
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	/*
	 * This frees the sqlite task from being bound to any builder
	 */

	sais_bind_task_to_builder(vhd, NULL, NULL, task_uuid);

	sp = sais_builder_from_uuid(vhd, builder_name);
	if (!sp)
		/* Builder not connected, nothing to do */
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->builders.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);
		if (pss->wsi == sp->wsi) {
			pss_match = pss;
			break;
		}
	} lws_end_foreach_dll(p);

	if (!pss_match)
		/* Builder is live but has no pss? */
		return 0;

	can = malloc(sizeof *can);
	if (!can)
		return -1;

	memset(can, 0, sizeof(*can));

	lws_strncpy(can->task_uuid, task_uuid, sizeof(can->task_uuid));
	can->erase = 0;
	can->killed = (unsigned int)killed;

	lws_dll2_add_tail(&can->list, &pss_match->task_cancel_owner);
	lws_callback_on_writable(pss_match->wsi);

	return 0;
}

/*
 * Keep the task record itself, but remove all logs and artifacts related to
 * it and reset the task state back to WAITING.
 */

sai_db_result_t
sais_task_clear_build_and_logs(struct vhd *vhd, const char *task_uuid, int from_rejection)
{
	char esc[96], cmd[256], event_uuid[33];
	sqlite3 *pdb = NULL;
	int ret;

	lwsl_notice("%s: ================== task reset %s\n", __func__, task_uuid);

	if (!task_uuid[0])
		return SAI_DB_RESULT_OK;

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		lwsl_err("%s: unable to open event-specific database\n",
				__func__);

		return SAI_DB_RESULT_ERROR;
	}

	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_snprintf(cmd, sizeof(cmd), " and uuid='%s'", esc);
	
	ret = lws_struct_sq3_deserialize(pdb, cmd, "run desc", lsm_schema_sq3_map_task, &o, &ac, 0, 1);
	if (ret >= 0 && o.head) {
		sai_task_t *t = lws_container_of(o.head, sai_task_t, list);
		
		if (!from_rejection)
			t->run++;
			
		t->started = 0;
		t->duration = 0;
		t->build_step = 0;
		
		if (!from_rejection) {
			/* Reset builder bindings for the new run so it can be picked up by any suitable builder */
			t->builder[0] = '\0';
			t->builder_name[0] = '\0';
			t->server_name = "";
			t->state = -1;
			/* serialize as a new row */
			lws_struct_sq3_serialize(pdb, lsm_schema_sq3_map_task, &o, 0);
		} else {
			/* update the existing row if it's a rejection */
			lws_snprintf(cmd, sizeof(cmd), 
				"update tasks set state=%d,started=0,duration=0,build_step=0 where uuid='%s' and run=%d",
				-1, esc, t->run);
			sqlite3_exec(pdb, cmd, NULL, NULL, NULL);
		}
	}
	
	lwsac_free(&ac);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	sais_set_task_state(vhd, task_uuid, SAIES_WAITING, 0, 0);

	sais_task_stop_on_builders(vhd, task_uuid, 0);

	/*
	 * Reassess now if there's a builder we can match to a pending task,
	 * but not if we are being reset due to a rejection... that would
	 * just cause us to spam the builder with the same task again
	 */

	if (!from_rejection) {
		lwsl_err("%s: scheduling sul_central to find a new task\n", __func__);
		lws_sul_schedule(vhd->context, 0, &vhd->sul_central, sais_central_cb, 1);
	}

	/*
	 * Recompute startable task platforms and broadcast to all sai-power,
	 * after there has been a change in tasks
	 */
	sais_platforms_with_tasks_pending(vhd);

	lwsl_notice("%s: exiting OK\n", __func__);

	return SAI_DB_RESULT_OK;
}

sai_db_result_t
sais_task_remove_all_tries(struct vhd *vhd, const char *task_uuid)
{
	char esc[96], cmd[384], event_uuid[33];
	sqlite3 *pdb = NULL;

	lwsl_notice("%s: ================== task remove all tries %s\n", __func__, task_uuid);

	if (!task_uuid[0])
		return SAI_DB_RESULT_OK;

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		lwsl_err("%s: unable to open event-specific database\n",
				__func__);
		return SAI_DB_RESULT_ERROR;
	}

	lws_sql_purify(esc, task_uuid, sizeof(esc));

	sais_task_stop_on_builders(vhd, task_uuid, 0);

	lws_snprintf(cmd, sizeof(cmd), "DELETE FROM logs WHERE task_uuid='%s'", esc);
	sqlite3_exec(pdb, cmd, NULL, NULL, NULL);

	lws_snprintf(cmd, sizeof(cmd), "DELETE FROM artifacts WHERE task_uuid='%s'", esc);
	sqlite3_exec(pdb, cmd, NULL, NULL, NULL);

	lws_snprintf(cmd, sizeof(cmd), "DELETE FROM tasks WHERE uuid='%s' AND run > 0", esc);
	sqlite3_exec(pdb, cmd, NULL, NULL, NULL);

	lws_snprintf(cmd, sizeof(cmd), 
		"update tasks set state=%d,started=0,duration=0,build_step=0,builder_name='',builder='',server_name='' where uuid='%s' and run=0",
		-1, esc);
	sqlite3_exec(pdb, cmd, NULL, NULL, NULL);

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	sais_set_task_state(vhd, task_uuid, SAIES_WAITING, 0, 0);

	lwsl_notice("%s: scheduling sul_central to find a new task\n", __func__);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_central, sais_central_cb, 1);

	sais_platforms_with_tasks_pending(vhd);

	return SAI_DB_RESULT_OK;
}

sai_db_result_t
sais_task_rebuild_last_step(struct vhd *vhd, const char *task_uuid)
{
	char esc[96], cmd[384], event_uuid[33];
	struct lwsac *ac = NULL;
	sqlite3 *pdb = NULL;
	lws_dll2_owner_t o;
	sai_task_t *task;
	int ret;

	if (!task_uuid[0])
		return SAI_DB_RESULT_OK;

	lwsl_notice("%s: received request to rebuild last step of task %s\n",
		    __func__, task_uuid);

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		lwsl_err("%s: unable to open event-specific database\n",
				__func__);

		return SAI_DB_RESULT_ERROR;
	}

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_snprintf(cmd, sizeof(cmd), " and uuid='%s'", esc);
	ret = lws_struct_sq3_deserialize(pdb, cmd, NULL,
					 lsm_schema_sq3_map_task, &o, &ac, 0, 1);
	if (ret < 0 || !o.head) {
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		lwsac_free(&ac);
		return SAI_DB_RESULT_ERROR;
	}

	task = lws_container_of(o.head, sai_task_t, list);

	int new_step = task->build_step > 0 ? task->build_step - 1 : 0;

	lws_snprintf(cmd, sizeof(cmd),
		     "update tasks set build_step=%d%s where uuid='%s' and run=(select max(run) from tasks where uuid='%s')",
		     new_step, new_step == 0 ? ",builder_name='',builder=''" : "", esc, esc);

	ret = sqlite3_exec(pdb, cmd, NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		lwsac_free(&ac);
		if (ret == SQLITE_BUSY)
			return SAI_DB_RESULT_BUSY;

		lwsl_err("%s: %s: %s: fail\n", __func__, cmd,
			 sqlite3_errmsg(pdb));
		return SAI_DB_RESULT_ERROR;
	}

	lwsac_free(&ac);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	sais_set_task_state(vhd, task_uuid, SAIES_WAITING, 0, 0);

	sais_task_stop_on_builders(vhd, task_uuid, 0);

	lwsl_err("%s: scheduling sul_central to find a new task\n", __func__);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_central, sais_central_cb, 1);

	sais_platforms_with_tasks_pending(vhd);

	lwsl_notice("%s: exiting OK\n", __func__);

	return SAI_DB_RESULT_OK;
}

int
sais_metrics_db_prune(struct vhd *vhd, const char *key)
{
	sqlite3_stmt *stmt;
	char sql[256];
	int rc, count = 0;

	if (!vhd->pdb_metrics)
		return 0;

	lws_snprintf(sql, sizeof(sql),
		     "SELECT COUNT(*) FROM build_metrics WHERE key = ?;");

	rc = sqlite3_prepare_v2(vhd->pdb_metrics, sql, -1, &stmt, 0);
	if (rc != SQLITE_OK) {
		lwsl_err("%s: failed to prepare statement: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb_metrics));
		return 1;
	}

	sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW)
		count = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);

	if (count <= 10)
		return 0;

	lws_snprintf(sql, sizeof(sql),
		     "DELETE FROM build_metrics WHERE key = ? AND rowid IN "
		     "(SELECT rowid FROM build_metrics WHERE key = ? "
		     "ORDER BY unixtime ASC LIMIT %d);", count - 10);

	rc = sqlite3_prepare_v2(vhd->pdb_metrics, sql, -1, &stmt, 0);
	if (rc != SQLITE_OK) {
		lwsl_err("%s: failed to prepare statement: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb_metrics));
		return 1;
	}

	sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		lwsl_err("%s: failed to delete old metrics: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb_metrics));
		sqlite3_finalize(stmt);
		return 1;
	}

	sqlite3_finalize(stmt);

	return 0;
}

int
sais_metrics_db_init(struct vhd *vhd)
{
	char db_path[PATH_MAX];
	int rc;

	if (vhd->pdb_metrics)
		return 0;

	if (!vhd->sqlite3_path_lhs)
		return 0;

	lws_snprintf(db_path, sizeof(db_path), "%s-build-metrics.sqlite3",
		     vhd->sqlite3_path_lhs);

	rc = sqlite3_open(db_path, &vhd->pdb_metrics);
	if (rc != SQLITE_OK) {
		lwsl_err("%s: cannot open database %s: %s\n", __func__,
			 db_path, sqlite3_errmsg(vhd->pdb_metrics));
		sqlite3_close(vhd->pdb_metrics);
		vhd->pdb_metrics = NULL;
		return 1;
	}

	if (lws_struct_sq3_create_table(vhd->pdb_metrics,
					lsm_schema_sq3_map_build_metric)) {
		lwsl_err("%s: failed to create build_metrics table\n", __func__);
		sqlite3_close(vhd->pdb_metrics);
		vhd->pdb_metrics = NULL;
		return 1;
	}

	return 0;
}


