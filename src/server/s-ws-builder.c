/*
 * Sai server - ./src/server/s-ws-builder.c
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
 *
 * These are ws rx and tx handlers related to builder ws connections, at the
 * sai-server
 *
 *   b1 --\   sai-        sai-   /-- browser
 *   b2 ----- server ---- web ------ browser
 *   b3 --/   *                  \-- browser
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <assert.h>
#include <time.h>

#include "s-private.h"

/*
 * Sanity cap on the per-builder loadreport reassembly.  Loadreports are
 * small; the reassembly exists so fragmented ones can be forwarded to the
 * web side as an atomic message.
 */
#define SAIS_LOADREPORT_REASSEMBLY_MAX (64 * 1024)

const lws_struct_map_t lsm_schema_map_ta[] = {
	LSM_SCHEMA (sai_task_t,	    NULL, lsm_task,    "com-warmcat-sai-ta"),
};

enum sai_overview_state {
	SOS_EVENT,
	SOS_TASKS,
};

typedef struct sais_logcache_pertask {
	lws_dll2_t		list; /* vhd->tasklog_cache is the owner */
	char			uuid[65];
	lws_dll2_owner_t	cache; /* sai_log_t */
} sais_logcache_pertask_t;

/*
 * The Schema that may be sent to us by a builder
 *
 * Artifacts are sent on secondary SS connections so they don't block ongoing
 * log delivery etc.  The JSON is immediately followed by binary data to the
 * length told in the JSON.
 */

static const lws_struct_map_t lsm_schema_map_ba[] = {
	LSM_SCHEMA_DLL2	(sai_plat_owner_t, plat_owner, NULL, lsm_plat_list,
						"com-warmcat-sai-ba"),
	LSM_SCHEMA      (sai_log_t,	  NULL, lsm_log,
						"com-warmcat-sai-logs"),
	LSM_SCHEMA      (sai_event_t,	  NULL, lsm_task_rej,
						"com.warmcat.sai.taskrej"),
	LSM_SCHEMA      (sai_artifact_t,  NULL, lsm_artifact,
						"com-warmcat-sai-artifact"),
	LSM_SCHEMA	(sai_load_report_t, NULL, lsm_load_report_members, /* from builder */
						"com.warmcat.sai.loadreport"),
	LSM_SCHEMA      (sai_resource_t,  NULL, lsm_resource,
						"com-warmcat-sai-resource"),
	LSM_SCHEMA	(sai_build_metric_t, NULL, lsm_build_metric,
						"com.warmcat.sai.build-metric"),
	LSM_SCHEMA	(sai_ptydata_t, NULL, lsm_ptydata,
						"com.warmcat.sai.ptydata"),
	LSM_SCHEMA	(sai_active_shells_t, NULL, lsm_schema_active_shells,
						"com.warmcat.sai.active_shells"),
	LSM_SCHEMA	(sai_pool_hello_t, NULL, lsm_pool_hello,
						SAI_POOL_SCHEMA),
};

enum {
	SAIM_WSSCH_BUILDER_PLATS,
	SAIM_WSSCH_BUILDER_LOGS,
	SAIM_WSSCH_BUILDER_TASKREJ,
	SAIM_WSSCH_BUILDER_ARTIFACT,
	SAIM_WSSCH_BUILDER_LOADREPORT,
	SAIM_WSSCH_BUILDER_RESOURCE_REQ,
	SAIM_WSSCH_BUILDER_METRIC,
	SAIM_WSSCH_BUILDER_PTYDATA,
	SAIM_WSSCH_BUILDER_ACTIVE_SHELLS,
	SAIM_WSSCH_BUILDER_POOL_HELLO,
};

static void
sais_dump_logs_to_db(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_logcache);
	char event_uuid[33], sw[192 + LWS_PRE];
	sais_logcache_pertask_t *lcpt;
	lws_wsmsg_info_t info;
	sqlite3 *pdb = NULL;
	sai_log_t *hlog;
	char *err;
	int n;

	/*
	 * for each task that acquired logs in the interval
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->tasklog_cache.head) {
		lcpt = lws_container_of(p, sais_logcache_pertask_t, list);

		sai_task_uuid_to_event_uuid(event_uuid, lcpt->uuid);

		pdb = NULL;
		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {

			/*
			 * Empty the task-specific log cache into the event-
			 * specific db for the task in one go, this is much
			 * more efficient
			 */

			char q[192], esc[132];
			int run = -1;

			/*
			 * Logs that don't say which run they are for go with
			 * the task's latest run.  sais_logcache_flush() makes
			 * sure that's still the run that was latest when they
			 * arrived.
			 */

			lws_start_foreach_dll(struct lws_dll2 *, pq, lcpt->cache.head) {
				sai_log_t *hl = lws_container_of(pq, sai_log_t, list);

				if (hl->run_given)
					continue;

				if (run < 0) {
					run = 0;
					lws_sql_purify(esc, lcpt->uuid, sizeof(esc));
					lws_snprintf(q, sizeof(q), "select max(run) "
						     "from tasks where uuid='%s'", esc);
					sqlite3_exec(pdb, q, sql3_get_integer_cb,
						     &run, NULL);
				}

				hl->run = run;
			} lws_end_foreach_dll(pq);

			sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &err);
			if (err)
				sqlite3_free(err);

			lws_struct_sq3_serialize(pdb, lsm_schema_sq3_map_log,
					 &lcpt->cache, 0);

			sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
			if (err)
				sqlite3_free(err);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		} else
			lwsl_err("%s: unable to open event-specific database\n",
					__func__);

		/*
		 * Destroy the logs in the task cache and the task cache
		 */

		lws_start_foreach_dll_safe(struct lws_dll2 *, pq, pq1,
					   lcpt->cache.head) {
			hlog = lws_container_of(pq, sai_log_t, list);
			lws_dll2_remove(&hlog->list);
			free(hlog);
		} lws_end_foreach_dll_safe(pq, pq1);

		/*
		 * Inform anybody who's looking at this task's logs that
		 * something changed (event_hash is actually the task hash)
		 */

		n = lws_snprintf(sw + LWS_PRE, sizeof(sw) - LWS_PRE,
				"{\"schema\":\"sai-tasklogs\","
				 "\"event_hash\":\"%s\"}", lcpt->uuid);

		memset(&info, 0, sizeof(info));

		info.private_source_idx		= SAI_WEBSRV_PB__LOGS;
		info.buf			= (uint8_t *)sw + LWS_PRE;
		info.len			= (unsigned int)n;
		info.ss_flags			= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

		if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
			lwsl_warn("%s: unable to broadcast to web\n", __func__);

		/*
		 * Destroy the whole task-specific cache, it will regenerate
		 * if more logs come for it
		 */

		lws_dll2_remove(&lcpt->list);
		free(lcpt);

	} lws_end_foreach_dll_safe(p, p1);

}

/*
 * Write out the logs we're holding now, instead of when the timer says.
 *
 * This must be done before a new run of a task is created: until then, the
 * logs we hold that don't say which run they're for belong to the run that's
 * about to stop being the latest.  Otherwise the end of a run's log, eg, an
 * idle slice's last output and our "task succeeded" for it, ends up at the
 * start of the next run's.
 */

void
sais_logcache_flush(struct vhd *vhd)
{
	if (!vhd->tasklog_cache.count)
		return;

	lws_sul_cancel(&vhd->sul_logcache);
	sais_dump_logs_to_db(&vhd->sul_logcache);
}

/*
 * We're going to stash these logs on a per-task list, and deal with them
 * inside a single trasaction per task efficiently on a timer.
 */

static void
sais_log_to_db(struct vhd *vhd, sai_log_t *log)
{
	sais_logcache_pertask_t *lcpt = NULL;
	sai_log_t *hlog;

	if (!log || !log->log)
		return;

	/*
	 * find the pertask if one exists
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->tasklog_cache.head) {
		lcpt = lws_container_of(p, sais_logcache_pertask_t, list);

		if (!strcmp(lcpt->uuid, log->task_uuid))
			break;
		lcpt = NULL;

	} lws_end_foreach_dll(p);

	if (!lcpt) {
		/*
		 * Create a pertask and add it to the vhd list of them
		 */
		lcpt = malloc(sizeof(*lcpt));
		if (!lcpt)
			return;
		memset(lcpt, 0, sizeof(*lcpt));
		lws_strncpy(lcpt->uuid, log->task_uuid, sizeof(lcpt->uuid));
		lws_dll2_add_tail(&lcpt->list, &vhd->tasklog_cache);
	}

	hlog = malloc(sizeof(*hlog) + log->len + strlen(log->log) + 1);
	if (!hlog)
		return;

	*hlog = *log;
	memset(&hlog->list, 0, sizeof(hlog->list));
	memcpy(&hlog[1], log->log, strlen(log->log) + 1);
	hlog->log = (char *)&hlog[1];

	/*
	 * add our log copy to the task-specific cache
	 */

	lws_dll2_add_tail(&hlog->list, &lcpt->cache);

	if (!vhd->sul_logcache.list.owner)
		/* if not already scheduled, schedule it for 250ms */
		lws_sul_schedule(vhd->context, 0, &vhd->sul_logcache,
				 sais_dump_logs_to_db, 250 * LWS_US_PER_MS);

	if (log->channel != 3 /* control channel */)
		return;

	/*
	 * Repo-controlled control-channel line asking us to watch a public
	 * status url for this task.  The url is attacker-influenced, so which
	 * service (if any) it belongs to is decided by
	 * sais_watcher_url_matches(): the configured match host must be the
	 * url's host (or parent of it), not a substring found anywhere in it.
	 */

	if (log->len >= 14 && !memcmp(log->log, "SAI_WATCH_URL:", 14)) {
		const char *url = log->log + 14;
		sai_watcher_t w;

		while (*url == ' ')
			url++;

		memset(&w, 0, sizeof(w));
		lws_strncpy(w.url, url, sizeof(w.url));
		lws_strncpy(w.task_hash, log->task_uuid, sizeof(w.task_hash));
		sai_task_uuid_to_event_uuid(w.event_hash, log->task_uuid);
		w.created = (uint64_t)lws_now_usecs();
		w.state = SAIWS_QUEUED;

		/* Identify service immediately to store service_name */
		lws_start_foreach_dll(struct lws_dll2 *, p, vhd->watcher_services.head) {
			sai_watcher_service_t *s = lws_container_of(p, sai_watcher_service_t, list);
			if (sais_watcher_url_matches(s, w.url)) {
				lws_strncpy(w.service_name, s->name, sizeof(w.service_name));
				break;
			}
		} lws_end_foreach_dll(p);

		if (w.service_name[0]) {
			lwsl_notice("%s: triggering watcher for %s (%s)\n", __func__, w.service_name, w.url);
			/* For now, just use sqlite3_exec */
			char q[512], esc_url[256], esc_svc[64], esc_event[65], esc_task[65];
			lws_sql_purify(esc_url, w.url, sizeof(esc_url));
			lws_sql_purify(esc_svc, w.service_name, sizeof(esc_svc));
			lws_sql_purify(esc_event, w.event_hash, sizeof(esc_event));
			lws_sql_purify(esc_task, w.task_hash, sizeof(esc_task));

			lws_snprintf(q, sizeof(q),
				"REPLACE INTO watchers (service_name, event_hash, task_hash, url, state, created, last_polled, metrics_json) "
				"VALUES ('%s', '%s', '%s', '%s', %d, %llu, 0, '{}')",
				esc_svc, esc_event, esc_task, esc_url, w.state, (unsigned long long)w.created);

			if (sai_sqlite3_statement(vhd->server.pdb, q, "insert watcher"))
				lwsl_err("%s: failed to insert watcher\n", __func__);
		}
	}

	/*
	 * There used to be a second, log-driven writer of tasks.build_step
	 * here, matching a chunk starting " Step " and taking the step number
	 * out of it.  The builder's line is ">saib> Step N: [...]", so it never
	 * matched and has been dead for a long time; sais_process_rej()'s
	 * SAI_TASK_REASON_ACCEPTED handler is the only thing that advances
	 * build_step, and it does so from the DB rather than from log text.
	 *
	 * It isn't worth reviving: logs reach the db from a 250ms timer, so a
	 * step's line can land after the next step was already accepted, and
	 * rewinding build_step there re-runs a step -- or makes
	 * build_step == build_step_count - 1 come true early, which has the
	 * builder delete the job dir out from under the rest of the build.
	 */
}

/*
 * Say something in a task's own log, as the server.
 *
 * A builder cannot always explain itself: it may be a VM that just went away,
 * and anything it had queued for us went with it.  When we are the one deciding
 * a task's fate, the reason has to go somewhere the user will find it, and the
 * only place that survives is the task's log.
 *
 * The log column holds base64 the browser decodes, and the timestamps are the
 * builder's monotonic clock, so borrow the newest one we have for this task
 * rather than inventing a value from our own unrelated clock.
 */

int
sais_task_logf(struct vhd *vhd, const char *task_uuid, const char *fmt, ...)
{
	char text[512], esc[132], q[224], event_uuid[33];
	uint64_t ts = 0;
	sqlite3 *pdb = NULL;
	sai_log_t log;
	va_list ap;
	int n;

	if (!task_uuid || !task_uuid[0])
		return -1;

	n = lws_snprintf(text, sizeof(text), ">sais> ");

	va_start(ap, fmt);
	n += vsnprintf(text + n, sizeof(text) - (unsigned int)n - 2, fmt, ap);
	va_end(ap);

	if (n > (int)sizeof(text) - 2)
		n = (int)sizeof(text) - 2;
	text[n++] = '\n';
	text[n] = '\0';

	lwsl_notice("%s: %s: %s", __func__, task_uuid, text);

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);
	lws_sql_purify(esc, task_uuid, sizeof(esc));

	if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0,
				      &pdb)) {
		lws_snprintf(q, sizeof(q),
			     "select coalesce(max(timestamp), 0) from logs "
			     "where task_uuid='%s'", esc);
		sqlite3_exec(pdb, q, sai_sql3_get_uint64_cb, &ts, NULL);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	}

	memset(&log, 0, sizeof(log));
	lws_strncpy(log.task_uuid, task_uuid, sizeof(log.task_uuid));
	log.timestamp	= ts + 1;
	log.channel	= 3;
	log.len		= (size_t)n;

	{
		char b64[(sizeof(text) * 4) / 3 + 8];

		if (lws_b64_encode_string(text, n, b64, (int)sizeof(b64)) < 0)
			return -1;

		log.log = b64;

		sais_log_to_db(vhd, &log);
	}

	return 0;
}

sai_plat_t *
sais_builder_from_uuid(struct vhd *vhd, const char *hostname)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      vhd->server.builder_owner.head) {
		sai_plat_t *sp = lws_container_of(p, sai_plat_t,
				sai_plat_list);

		if (!strcmp(hostname, sp->name)) {
			sp->online = 1;

			return sp;
		}

	} lws_end_foreach_dll(p);

	return NULL;
}

sai_plat_t *
sais_builder_from_host(struct vhd *vhd, const char *host)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      vhd->server.builder_owner.head) {
		sai_plat_t *sp = lws_container_of(p, sai_plat_t,
				sai_plat_list);
		size_t host_len = strlen(host);

		if (!strncmp(sp->name, host, host_len) &&
		    sp->name[host_len] == '.')
			return sp;

	} lws_end_foreach_dll(p);

	return NULL;
}

void
sais_set_builder_power_state(struct vhd *vhd, const char *name, int up, int down)
{
	sai_power_state_t *ps = NULL;
	sai_plat_t *live_builder = sais_builder_from_host(vhd, name);

	if (live_builder && up) {
		lwsl_notice("%s: live builder so killing up\n", __func__);
		up = 0;
	}

	if (!live_builder && down) {
		lwsl_notice("%s: no live builder so killing down\n", __func__);
		down = 0;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
			      vhd->server.power_state_owner.head) {
		ps = lws_container_of(p, sai_power_state_t, list);

		if (!strcmp(ps->host, name)) {
			if (live_builder && ps->powering_up) {
				lwsl_notice("%s: live builder so removing powering_up\n", __func__);
				ps->powering_up = 0;
			}

			if (!live_builder && ps->powering_down) {
				lwsl_notice("%s: no live builder so killing powering_down\n", __func__);
				ps->powering_down = 0;
			}

			if (!ps->powering_up && !ps->powering_down) {
				lwsl_notice("%s: nothing left to do for power state change, removing\n", __func__);
				lws_dll2_remove(&ps->list);
				free(ps);
			}
		}
	} lws_end_foreach_dll_safe(p, p1);

	ps = NULL;

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.power_state_owner.head) {
		ps = lws_container_of(p, sai_power_state_t, list);

		if (!strcmp(ps->host, name))
			break;
		ps = NULL;
	} lws_end_foreach_dll(p);

	if (!ps && (up || down)) {
		ps = malloc(sizeof(*ps));
		if (!ps)
			return;
		memset(ps, 0, sizeof(*ps));
		lws_strncpy(ps->host, name, sizeof(ps->host));
		lws_dll2_add_tail(&ps->list, &vhd->server.power_state_owner);
	}

	if (ps) {
		ps->powering_up = (char)up;
		ps->powering_down = (char)down;
		if (!ps->powering_up && !ps->powering_down) {
			lws_dll2_remove(&ps->list);
			free(ps);
		} else
			lwsl_notice("%s: added ps with %d %d\n", __func__, up, down);
	}

	sais_list_builders(vhd);
}

/*
 * Called from the builder protocol LWS_CALLBACK_CLOSED handler
 */
void
sais_builder_disconnected(struct vhd *vhd, struct lws *wsi)
{
	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;
	sai_plat_t *sp;
	int n;

	/*
	 * A builder's websocket has closed. Find all platforms associated
	 * with it, mark them as offline in the database, and remove them
	 * from the live in-memory list.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->server.builder_owner.head) {
		sp = lws_container_of(p, sai_plat_t, sai_plat_list);

		if (sp->wsi == wsi) {
			char q[256];

			lwsl_notice("%s: Builder '%s' disconnected\n", __func__,
				    sp->name);

			/*
			 * Check all active events for tasks that were running
			 * on this builder, and reset them
			 */

			n = lws_struct_sq3_deserialize(vhd->server.pdb,
				" and (state != 3 and state != 4 and state != 5 and state != 7)",
				NULL, lsm_schema_sq3_map_event, &o, &ac, 0, 100);
			if (n >= 0 && o.head) {
				lws_start_foreach_dll(struct lws_dll2 *, pe, o.head) {
					sai_event_t *e = lws_container_of(pe, sai_event_t, list);
					sqlite3 *pdb = NULL;

					if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
							      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {
						sqlite3_stmt *sm;

						lws_snprintf(q, sizeof(q),
							"SELECT uuid, build_step FROM tasks WHERE "
							"builder_name=? AND (state = 0 OR state = %d OR state = %d) "
							"AND run=(SELECT max(run) FROM tasks t2 WHERE t2.uuid = tasks.uuid)",
							SAIES_PASSED_TO_BUILDER,
							SAIES_BEING_BUILT);

						if (sqlite3_prepare_v2(pdb, q, -1, &sm, NULL) == SQLITE_OK) {
							sqlite3_bind_text(sm, 1, sp->name, -1, SQLITE_TRANSIENT);
							while (sqlite3_step(sm) == SQLITE_ROW) {
								const unsigned char *task_uuid = sqlite3_column_text(sm, 0);
								int bs = sqlite3_column_int(sm, 1);

								if (task_uuid) {
									lwsl_notice("%s: resetting task %s from disconnected builder %s\n",
											__func__, (const char *)task_uuid, sp->name);
									sais_task_clear_build_and_logs(vhd, (const char *)task_uuid, 0);

									/*
									 * The builder went away mid-task, so whatever it
									 * was about to tell us went with it and its log just
									 * stops.  Say so at the top of the retry's log: the
									 * reset above has already moved us to a new run, so
									 * this lands there.
									 */
									sais_task_logf(vhd, (const char *)task_uuid,
										"builder %s disconnected while this task was "
										"at step %d, so its log stops there; retrying "
										"the task from the beginning",
										sp->name, bs);
								}
							}
							sqlite3_finalize(sm);
						}
						sai_event_db_close(&vhd->sqlite3_cache, &pdb);
					}
				} lws_end_foreach_dll(pe);

				lwsac_free(&ac);
			}

			/* ... and any idle tasks it had */
			sais_idle_builder_gone(vhd, sp);

			/* drop any inflight task information for this builder */

			lws_start_foreach_dll_safe(struct lws_dll2 *, pif, pif1,
					      	   sp->inflight_owner.head) {
				sai_uuid_list_t *ul = lws_container_of(pif, sai_uuid_list_t, list);

				sais_inflight_entry_destroy(ul);

			} lws_end_foreach_dll_safe(pif, pif1);


			const char *dot = strchr(sp->name, '.');
			if (dot) {
				char host[128];
				lws_strnncpy(host, sp->name, dot - sp->name, sizeof(host));
				lws_start_foreach_dll_safe(struct lws_dll2 *, p2, p3, vhd->server.power_state_owner.head) {
					sai_power_state_t *ps = lws_container_of(p2, sai_power_state_t, list);
					if (!strcmp(ps->host, host)) {
						lws_dll2_remove(&ps->list);
						free(ps);
						break;
					}
				} lws_end_foreach_dll_safe(p2, p3);
			}

			lws_dll2_remove(&sp->sai_plat_list);
			lws_sul_cancel(&sp->sul_find_jobs);
			free(sp);

			// assert(0);
		}
	} lws_end_foreach_dll_safe(p, p1);
}

int
sai_sql3_get_uint64_cb(void *user, int cols, char **values, char **name)
{
	uint64_t *pui = (uint64_t *)user;

	*pui = (uint64_t)atoll(values[0]);

	return 0;
}

/*
 * Builders say which step (1-based) an ACCEPTED or DESTROYED is about.  It's
 * only news if it's about the step the task is at: for ACCEPTED, the one after
 * the last one accepted; for DESTROYED, the last one accepted... and either way
 * only while the task's latest run is still going.
 *
 * Anything else is about a step the task has moved past, eg, a second offer of
 * a step that completed in the meantime.  Acting on it overruns or rewinds
 * build_step, and can fail a task that already succeeded.  Builders that don't
 * say (step 0) are believed, as before.
 *
 * *build_step is set to the task's build_step, or -1 if we couldn't read it.
 */

static int
sais_rej_is_stale(sqlite3 *pdb, const sai_rejection_t *rej, int *build_step)
{
	sqlite3_stmt *sm;
	int state = -1;

	*build_step = -1;

	if (sqlite3_prepare_v2(pdb, "select build_step,state from tasks where "
				    "uuid=? order by run desc limit 1",
			       -1, &sm, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(sm, 1, rej->task_uuid, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		*build_step	= sqlite3_column_int(sm, 0);
		state		= sqlite3_column_int(sm, 1);
	}
	sqlite3_finalize(sm);

	if (!rej->step || *build_step < 0)
		return 0;

	if (state == SAIES_SUCCESS || state == SAIES_FAIL ||
	    state == SAIES_CANCELLED || state == SAIES_DELETED)
		return 1;

	return (int)rej->step != *build_step +
				(rej->reason == SAI_TASK_REASON_ACCEPTED);
}

/*
 * "reject" packet from the builder is actually a disposition about the
 * offered task, it can also indicate ACCEPTED.
 */

static int
sais_process_rej(struct vhd *vhd, struct pss *pss,
		 sai_plat_t *sp, sai_rejection_t *rej)
{
	char event_uuid[33], do_remove_uuid = 0, q[384], esc_uuid[129];
	int n, build_step = -1, stale = 0;
	sqlite3 *pdb = NULL;
	sai_uuid_list_t *ul;

	switch (rej->reason) {
	case SAI_TASK_REASON_ACCEPTED:
		lwsl_info("%s: SAI_TASK_REASON_ACCEPTED: %s\n",
			    __func__, rej->task_uuid);

		/* start build duration only from first step accepted */

		sai_task_uuid_to_event_uuid(event_uuid, rej->task_uuid);
		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
			lwsl_err("%s: unable to open db for event %s\n", __func__, event_uuid);
			break;
		}

		if (sais_rej_is_stale(pdb, rej, &build_step)) {
			/*
			 * Leave build_step, the state and the inflight entry
			 * alone, they belong to the step the task is really
			 * at.  Whatever this step does, we'll ignore when it
			 * ends.
			 */
			lwsl_warn("%s: %s: stale accept of step %u, at %d\n",
				  __func__, rej->task_uuid, rej->step,
				  build_step);
			sais_task_logf(vhd, rej->task_uuid,
				       "builder %s started step %u, which the "
				       "task is no longer at; ignoring that run",
				       sp->name, rej->step);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			break;
		}

		lws_sql_purify(esc_uuid, rej->task_uuid, sizeof(esc_uuid));

		/*
		 * Bump the build step on the accepted task
		 */

		build_step++;
		lws_snprintf(q, sizeof(q),
			     "update tasks set build_step=%d "
			     "where uuid='%s' and run=(select max(run) from tasks where uuid='%s')",
			     build_step, esc_uuid, esc_uuid);
		if (sai_sqlite3_statement(pdb, q, "update build_step accepted"))
			lwsl_err("%s: failed to update build_step\n", __func__);

		lwsl_info("%s: %s: build_step set to %d\n", __func__,
			  rej->task_uuid, build_step);

		if (build_step == 1) {
			pss->first_log_timestamp = (uint64_t)lws_now_secs();
			lws_snprintf(q, sizeof(q),
			     "update tasks set started=%llu where uuid='%s' and run=(select max(run) from tasks where uuid='%s')",
			     (unsigned long long)pss->first_log_timestamp, esc_uuid, esc_uuid);

			lwsl_info("%s: setting task %s started to %llu\n",
				  __func__, esc_uuid, (unsigned long long)pss->first_log_timestamp);

			if (sai_sqlite3_statement(pdb, q, "update started"))
				lwsl_notice("%s: unable to set started\n", __func__);
		}

		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		if (sais_set_task_state(vhd,
					rej->task_uuid,
					SAIES_BEING_BUILT,
					build_step == 1 ? pss->first_log_timestamp : 0, 0))
			break;

		/* leave the uuid listed as inflight until step completed */
		if (sais_is_task_inflight(vhd, NULL, rej->task_uuid, &ul)) {
			ul->started = 1;
		}
		break;

	case SAI_TASK_REASON_DUPE:
		lwsl_notice("%s: SAI_TASK_REASON_DUPE: %s\n",
				__func__, rej->task_uuid);
		break;

	case SAI_TASK_REASON_BUSY:
		lwsl_notice("%s: SAI_TASK_REASON_BUSY: Set busy: %s\n",
				__func__, rej->task_uuid);
		do_remove_uuid = 1;

		sai_task_uuid_to_event_uuid(event_uuid, rej->task_uuid);
		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
			sais_rej_is_stale(pdb, rej, &build_step);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}

		if (build_step > 0) {
			/*
			 * It refused a later step of a task it already
			 * started.  The earlier steps' work is in its job
			 * dir, so the task can only go on there: leave it
			 * bound, waiting for its next step.  Making it WAITING
			 * for anyone let another builder of the platform run
			 * the next step in a job dir with no src/ tree.
			 */
			sais_set_task_state(vhd, rej->task_uuid,
					    SAIES_STEP_SUCCESS, 0, 0);
		} else {
			sais_bind_task_to_builder(vhd, NULL, NULL,
						  rej->task_uuid);
			sais_set_task_state(vhd, rej->task_uuid,
					    SAIES_WAITING, 0, 0);
		}
		sais_plat_busy(sp, 1);
		break;

	case SAI_TASK_REASON_IDLE_DECLINED:
		lwsl_notice("%s: SAI_TASK_REASON_IDLE_DECLINED: %s\n",
				__func__, rej->task_uuid);
		do_remove_uuid = 1;
		sais_idle_declined(vhd, sp, rej->task_uuid);
		break;

	case SAI_TASK_REASON_DESTROYED:
		lwsl_info("%s: SAI_TASK_REASON_DESTROYED: Clear busy: %s\n",
				__func__, rej->task_uuid);

		sai_task_uuid_to_event_uuid(event_uuid, rej->task_uuid);
		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
			stale = sais_rej_is_stale(pdb, rej, &build_step);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}

		if (stale) {
			/*
			 * It's about a step the task isn't at.  Either we
			 * already ignored it starting, or we rewound the task
			 * under it (pause, rebuild last step) and stopped it.
			 *
			 * The task state is not this step's to change, and
			 * an inflight entry still waiting for an accept is
			 * the offer of the step the task is really at.  One
			 * whose step had started is this one, though, and
			 * it's over.
			 */
			lwsl_warn("%s: %s: stale end of step %u, at %d\n",
				  __func__, rej->task_uuid, rej->step,
				  build_step);
			if (sais_is_task_inflight(vhd, NULL, rej->task_uuid,
						  &ul) && ul->started)
				sais_inflight_entry_destroy(ul);
			sais_plat_busy(sp, 0);
			break;
		}

		do_remove_uuid = 1;

		if (rej->ecode & SAISPRF_YIELDED) {
			/*
			 * The builder stopped an idle task's slice, to make
			 * way for real work or because its time was up
			 */
			n = SAIES_YIELDED;
			lwsl_notice("%s: |||| SAIES_YIELDED: %s\n",
					__func__, rej->task_uuid);
			if (rej->ecode & SAISPRF_OVERRAN)
				sais_idle_slice_overran(vhd, rej->task_uuid);
		} else
		if (rej->ecode & SAISPRF_EXIT) {
			if ((rej->ecode & 0xff) == 0) {
				n = SAIES_STEP_SUCCESS;
				lwsl_info("%s: SAIES_STEP_SUCCESS: %s\n",
						__func__, rej->task_uuid);
			} else {
				n = SAIES_FAIL;
				lwsl_notice("%s: |||| SAIES_FAIL: %s\n",
						__func__, rej->task_uuid);
				sais_task_logf(vhd, rej->task_uuid,
					       "builder %s reported the step exited %d, "
					       "failing the task", sp->name,
					       rej->ecode & 0xff);
			}
		} else
			if (rej->ecode & SAISPRF_TERMINATED) {
				n = SAIES_CANCELLED;
				lwsl_notice("%s: |||| SAIES_CANCELLED: %s\n",
						__func__, rej->task_uuid);

			} else {
				n = SAIES_FAIL;
				lwsl_notice("%s: |||| SAIES_STEP_FAIL: %s\n",
						__func__, rej->task_uuid);

				/*
				 * We are about to make this red, and unlike a
				 * nonzero exit the builder has no log line that
				 * matches: an ecode of 0 in particular means it
				 * never worked out how the step ended
				 */
				if (rej->ecode & SAISPRF_TIMEDOUT)
					sais_task_logf(vhd, rej->task_uuid,
						"builder %s timed the step out, "
						"failing the task", sp->name);
				else
					if (rej->ecode & SAISPRF_SIGNALLED)
						sais_task_logf(vhd, rej->task_uuid,
							"builder %s reported the step "
							"was killed by signal %d, "
							"failing the task", sp->name,
							rej->ecode & 0xff);
					else
						sais_task_logf(vhd, rej->task_uuid,
							"builder %s finished this step "
							"without saying how it ended "
							"(ecode 0x%x), failing the task",
							sp->name, rej->ecode);
			}

		if (sais_set_task_state(vhd, rej->task_uuid, n, 0,
					lws_now_secs() - pss->first_log_timestamp))
			lwsl_notice("%s: task state update failed, possibly event deleted\n", __func__);

		if (n == SAIES_STEP_SUCCESS)
			do_remove_uuid = 0;
		else
			sais_plat_busy(sp, 0);
		break;
	}

	if (do_remove_uuid &&
	    sais_is_task_inflight(vhd, NULL, rej->task_uuid, &ul)) {
		lwsl_notice("%s: ### Removing %s from inflight\n",
				__func__, rej->task_uuid);
		sais_inflight_entry_destroy(ul);
		// sais_task_clear_build_and_logs(vhd, rej->task_uuid, 1);
	}

	if (rej->reason == SAI_TASK_REASON_DESTROYED && !stale)
		/* uuid will not be found listed as inflight for this */
		sais_create_and_offer_task_step(vhd, rej->task_uuid);

	sais_list_builders(vhd);

	return 0;
}

/*
 * Server received a communication from a builder
 *
 * buf is lws callback `in` which has LWS_PRE already set aside
 *
 * This could contain multiple pieces, including partials concatenated.
 */

int
sais_ws_json_rx_builder(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl, unsigned int ss_flags)
{
	char event_uuid[33], s[128], esc[96];
	sai_resource_requisition_t *rr;
	sai_resource_wellknown_t *wk;
	sai_plat_owner_t *bp_owner;
	lws_struct_serialize_t *js;
	sai_build_metric_t *metric;
	struct lwsac *ac = NULL;
	sai_plat_t *build, *sp;
	lws_wsmsg_info_t info;
	sai_rejection_t *rej;
	sai_resource_t *res;
	lws_dll2_owner_t o;
	sai_artifact_t *ap;
	uint8_t xbuf[2048];
	sai_task_t *task;
	size_t used = 0;
	sai_log_t *log;
	uint64_t rid;
	int n, m;

	sais_metrics_db_init(vhd);

	if (pss->pool)
		/* after its hello, a pool sync connection is binary records */
		return sais_pool_rx(vhd, pss, buf, bl);

	if (pss->bulk_binary_data) {
		lwsl_info("%s: bulk %d\n", __func__, (int)bl);
		m = (int)bl;
		goto handle;
	}

	while (bl) {

		/*
		 * use the schema name on the incoming JSON to decide what kind of
		 * structure to instantiate
		 *
		 * We may have:
		 *
		 *  - just received a fragment of the whole JSON
		 *
		 *  - received whole JSON + partial of next
		 *
		 *  - received whole JSONs
		 *
		 *  - received the JSON and be handling appeneded blob data
		 */

		if (!pss->frag) {
			memset(&pss->a, 0, sizeof(pss->a));
			pss->a.map_st[0] = lsm_schema_map_ba;
			pss->a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_schema_map_ba);
			pss->a.map_st[1] = lsm_schema_map_ba;
			pss->a.map_entries_st[1] = LWS_ARRAY_SIZE(lsm_schema_map_ba);
			pss->a.ac_block_size = 4096;

			lws_struct_json_init_parse(&pss->ctx, NULL, &pss->a);
		} else
			pss->frag = 0;

		m = lejp_parse(&pss->ctx, (uint8_t *)buf, (int)bl);

		/*
		 * returns negative, or unused amount... for us, we either had a
		 * (negative) error, had LEJP_CONTINUE, or if 0/positive, finished
		 */
		if (m < 0 && m != LEJP_CONTINUE) {
			/* an explicit error */
			lwsl_hexdump_err(buf, bl);
			lwsl_err("%s: rx JSON decode failed '%s', %d, %s, %s, %d\n",
				    __func__, lejp_error_to_string(m), m,
				    pss->ctx.path, pss->ctx.buf, pss->ctx.npos);
			lwsac_free(&pss->a.ac);
			return 1;
		}

		// lwsl_hexdump_notice(buf, bl);

		if (m == LEJP_CONTINUE) { /* ie, we used all of bl and need more */
			if (pss->a.top_schema_index == SAIM_WSSCH_BUILDER_LOADREPORT) {

				/*
				 * We can't directly proxy these pieces, because
				 * with several builders connected and spamming
				 * fragmented load reports, when we forward them
				 * the adjacent fragments will be randomly
				 * ordered (* shows where this code is)
				 *
				 *   b1 --\   sai-        sai-   /-- browser
				 *   b2 ----- server ---- web ------ browser
				 *   b3 --/   *                  \-- browser
				 *
				 * Even though each builder is sending
				 * them correctly ordered, when all combined
				 * together on the srv -> web link, the fragments
				 * will be disorderd.  Eg, b1 first frag, b2
				 * first frag, b1 last frag, b2 last frag is
				 * legal for each builder, but illegal when
				 * proxied and forwarded in the order they were
				 * received on a single connection.
				 *
				 * Instead we have to collect the pieces per-
				 * builder and forward them when we have an
				 * atomic message.
				 */

				*((unsigned int *)(buf - sizeof(int))) = ss_flags;
				if (sais_buflist_append_bounded(
						&pss->onward_reassembly,
						buf - sizeof(int),
						bl + sizeof(int),
						SAIS_LOADREPORT_REASSEMBLY_MAX)) {
					lwsl_err("%s: loadreport reassembly over cap / OOM\n",
						 __func__);
					return -1;
				}
			}

			pss->frag = 1;
			return 0;
		}

		if (!pss->a.dest) {
			lwsac_free(&pss->a.ac);
			lwsl_err("%s: json decode didn't make an object\n", __func__);
			return 1;
		}

	handle:

		// lwsl_notice("%s: bl: %d, m %d, schema: %d\n", __func__, (int)bl, m, pss->a.top_schema_index);

		switch (pss->a.top_schema_index) {
		case SAIM_WSSCH_BUILDER_PLATS:

			/*
			 * builder is sending us an array of platforms it provides us
			 */

			bp_owner = (sai_plat_owner_t *)pss->a.dest;

			lws_start_foreach_dll(struct lws_dll2 *, pb,
					      bp_owner->plat_owner.head) {
				build = lws_container_of(pb, sai_plat_t, sai_plat_list);
				sai_plat_t *live_sp;

				/*
				 * Step 1: Update this platform in the persistent database.
				 *
				 * Security: build->name/platform/pcon/sai_hash/lws_hash
				 * and peer_ip all originate from the (possibly untrusted
				 * or malicious) builder websocket JSON and are
				 * interpolated into SQL here.  Reject any value
				 * containing shell/SQL metacharacters outright, and
				 * additionally pass each through lws_sql_purify as
				 * defense-in-depth before interpolation.
				 */
				char q[1024];
				char esc_name[192], esc_platform[192],
				     esc_pcon[192], esc_sai_hash[192],
				     esc_lws_hash[192], esc_peer_ip[96];

				/*
				 * A platform the builder couldn't name (eg,
				 * from a conf it misread) is no use to us,
				 * and everything below needs the names
				 */
				if (!build->name || !build->platform) {
					lwsl_notice("%s: ignoring builder plat "
						    "with no name\n", __func__);
					continue;
				}

				if (sai_str_has_shell_metachars(build->name)	||
				    sai_str_has_shell_metachars(build->platform) ||
				    (build->pcon &&
				     sai_str_has_shell_metachars(build->pcon)) ||
				    sai_str_has_shell_metachars(build->sai_hash) ||
				    sai_str_has_shell_metachars(build->lws_hash) ||
				    sai_str_has_shell_metachars(pss->peer_ip)) {
					lwsl_notice("%s: rejecting builder plats "
						    "with unsafe chars\n",
						    __func__);
					continue;
				}

				lws_sql_purify(esc_name, build->name,
					       sizeof(esc_name));
				lws_sql_purify(esc_platform, build->platform,
					       sizeof(esc_platform));
				lws_sql_purify(esc_pcon, build->pcon ? build->pcon : "",
					       sizeof(esc_pcon));
				lws_sql_purify(esc_sai_hash, build->sai_hash,
					       sizeof(esc_sai_hash));
				lws_sql_purify(esc_lws_hash, build->lws_hash,
					       sizeof(esc_lws_hash));
				lws_sql_purify(esc_peer_ip, pss->peer_ip,
					       sizeof(esc_peer_ip));

				lws_snprintf(q, sizeof(q),
					     "INSERT INTO builders (name, platform, pcon, last_seen, peer_ip, sai_hash, lws_hash, windows) "
					     "VALUES ('%s', '%s', %s%s%s, %llu, '%s', '%s', '%s', %d) "
					     "ON CONFLICT(name) DO UPDATE SET pcon=COALESCE(NULLIF(excluded.pcon, ''), pcon), last_seen=excluded.last_seen, "
					     "peer_ip=excluded.peer_ip, sai_hash=excluded.sai_hash, lws_hash=excluded.lws_hash",
					     esc_name, esc_platform,
					     build->pcon ? "'" : "NULL",
					     build->pcon ? esc_pcon : "",
					     build->pcon ? "'" : "",
					     (unsigned long long)lws_now_secs(),
					     esc_peer_ip, esc_sai_hash,
					     esc_lws_hash, build->windows);

				if (sai_sqlite3_statement(vhd->server.pdb, q, "upsert builder"))
					lwsl_err("%s: Failed to upsert builder %s\n",
						 __func__, build->name);

				/*
				 * Step 1.5: Synchronize PCON binding from pcon_builders table if available.
				 * This handles the case where sai-power registered the PCON relationship
				 * before the builder connected.
				 */
				{
					char host[128], esc_host[192];
					const char *dot = strchr(build->name, '.');

					if (dot)
						lws_strnncpy(host, build->name, dot - build->name, sizeof(host));
					else
						lws_strncpy(host, build->name, sizeof(host));

					lws_sql_purify(esc_host, host, sizeof(esc_host));

					lws_snprintf(q, sizeof(q),
						     "UPDATE builders SET pcon = COALESCE((SELECT pcon_name FROM pcon_builders WHERE builder_name = '%s'), pcon) "
						     "WHERE name = '%s' OR name LIKE '%s.%%'",
						     esc_host, esc_name, esc_name);
					// lwsl_notice("%s: Syncing pcon for host '%s' (plat '%s'): %s\n", __func__, host, build->name, q);
					sai_sqlite3_statement(vhd->server.pdb, q, "sync builder pcon");
				}

				/*
				 * Step 2: Update the long-lived, malloc'd in-memory list.
				 */

				live_sp = sais_builder_from_uuid(vhd, build->name);
				if (live_sp) {
					/* Already exists (reconnect), just update dynamic info */
					// lwsl_info("%s: found live builder for %s\n", __func__, build->name);
					live_sp->wsi				= pss->wsi;
					live_sp->cx				= lws_get_context(pss->wsi);
					live_sp->vhd				= vhd;
					lws_strncpy(live_sp->peer_ip, pss->peer_ip, sizeof(live_sp->peer_ip));
					lws_strncpy(live_sp->sai_hash, build->sai_hash,
						    sizeof(live_sp->sai_hash));
					lws_strncpy(live_sp->lws_hash, build->lws_hash,
						    sizeof(live_sp->lws_hash));
					live_sp->windows			= build->windows;
					live_sp->online				= 1;
					live_sp->avail_mem_kib			= (unsigned int)-1;
					live_sp->avail_sto_kib			= (unsigned int)-1;
					sais_plat_busy(live_sp, 0);
				} else {
					/* New builder, create a deep-copied, malloc'd object */
					size_t nlen = strlen(build->name) + 1;
					size_t plen = strlen(build->platform) + 1;

					lwsl_err("%s: no live for %s\n", __func__, build->name);

					live_sp = malloc(sizeof(*live_sp) + nlen + plen);
					if (!live_sp)
						continue;

					char *p_str = (char *)(live_sp + 1);

					memset(live_sp, 0, sizeof(*live_sp));
					live_sp->name				= p_str;
					memcpy(p_str, build->name, nlen);
					live_sp->platform			= p_str + nlen;
					memcpy(p_str + nlen, build->platform, plen);
					lws_strncpy(live_sp->sai_hash, build->sai_hash,
						    sizeof(live_sp->sai_hash));
					lws_strncpy(live_sp->lws_hash, build->lws_hash,
						    sizeof(live_sp->lws_hash));
					live_sp->windows			= build->windows;
					live_sp->avail_mem_kib			= (unsigned int)-1;
					live_sp->avail_sto_kib			= (unsigned int)-1;
					live_sp->wsi				= pss->wsi;
					live_sp->cx				= lws_get_context(pss->wsi);
					live_sp->vhd				= vhd;
					live_sp->online				= 1;
					lws_strncpy(live_sp->peer_ip, pss->peer_ip, sizeof(live_sp->peer_ip));

					lws_dll2_add_tail(&live_sp->sai_plat_list, &vhd->server.builder_owner);
				}

				/* and what it wants to do with its idle time */
				sais_idle_plat_update(vhd, build);

				lws_sul_schedule(live_sp->cx, 0, &live_sp->sul_find_jobs,
						 sais_plat_find_jobs_cb, 500 * LWS_US_PER_MS);

				const char *dot = strchr(build->name, '.');
				if (dot) {
					char host[128];
					lws_strnncpy(host, build->name, dot - build->name, sizeof(host));
					sais_set_builder_power_state(vhd, host, 0, 0);
				}
			} lws_end_foreach_dll(pb);

			/* The lwsac from the parsed message is now completely disposable */
			lwsac_free(&pss->a.ac);

			/*
			 * Now, iterate through the in-memory list of online builders and
			 * try to allocate a task for each platform that belongs to the
			 * builder that just connected.
			 */
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.builder_owner.head) {
				sp = lws_container_of(p, sai_plat_t, sai_plat_list);
				if (sp->wsi == pss->wsi) {
					/* This platform belongs to the connection that sent the message */
					if (sais_allocate_task(vhd, pss, sp, sp->platform) < 0)
						goto bail;
				}
			} lws_end_foreach_dll(p);
			/*
			 * Also, if there are any pending in-memory shell sessions for this builder,
			 * send them down now!
			 */
			lws_start_foreach_dll(struct lws_dll2 *, p_sh, vhd->shell_sessions.head) {
				sai_shell_session_t *sh = lws_container_of(p_sh, sai_shell_session_t, list);
				lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.builder_owner.head) {
					sai_plat_t *sp = lws_container_of(p, sai_plat_t, sai_plat_list);
					const char *sh_plat = strchr(sh->builder_name, '.');
					if (sh_plat) sh_plat++; else sh_plat = sh->builder_name;

					const char *sp_plat = strchr(sp->name, '.');
					if (sp_plat) sp_plat++; else sp_plat = sp->name;

					if (sp->wsi == pss->wsi &&
					    (!strcmp(sh->builder_name, sp->name) || !strcmp(sh_plat, sp_plat))) {
						sai_openshell_t *s = malloc(sizeof(*s));
						if (s) {
							memset(s, 0, sizeof(*s));
							lws_strncpy(s->task_uuid, sh->task_uuid, sizeof(s->task_uuid));
							lws_strncpy(s->builder_name, sp->name, sizeof(s->builder_name));
							lws_dll2_add_tail(&s->list, &pss->openshell_owner);

							lws_start_foreach_dll_safe(struct lws_dll2 *, pd, pd1, sh->ptydata_owner.head) {
								sai_ptydata_t *pdy = lws_container_of(pd, sai_ptydata_t, list);
								lws_dll2_remove(pd);
								lws_strncpy(pdy->builder_name, sp->name, sizeof(pdy->builder_name));
								lws_dll2_add_tail(&pdy->list, &pss->ptydata_owner);
							} lws_end_foreach_dll_safe(pd, pd1);

							lws_callback_on_writable(pss->wsi);
						}
						break;
					}
				} lws_end_foreach_dll(p);
			} lws_end_foreach_dll(p_sh);

			/*
			 * If we did allocate a task in pss->a.ac, responsibility of
			 * callback_on_writable handler to empty it
			 */

			sais_list_builders(vhd);

			break;

	bail:
			lwsac_free(&pss->a.ac);
			return -1;

		case SAIM_WSSCH_BUILDER_LOGS:
			/*
			 * builder is sending us info about task logs
			 */

			log = (sai_log_t *)pss->a.dest;
			sais_log_to_db(vhd, log);

			lwsac_free(&pss->a.ac);

			break;

		case SAIM_WSSCH_BUILDER_TASKREJ:

			/*
			 * builder is updating us about a task status
			 */

			rej = (sai_rejection_t *)pss->a.dest;

			if (!rej->task_uuid[0])
				break;

			rej->host_platform[sizeof(rej->host_platform) - 1] = '\0';
			sp = sais_builder_from_uuid(vhd, rej->host_platform);
			if (!sp) {
				lwsl_info("%s: unknown builder %s rejecting\n",
					 __func__, rej->host_platform);
				lwsac_free(&pss->a.ac);
				break;
			}

			lwsl_info("%s: builder %s reports task status update, "
				  "reason: %d, %s, slots %d, mem %d, sto %d\n",
				  __func__, sp->name, rej->reason, rej->task_uuid,
				  sp->avail_slots, sp->avail_mem_kib, sp->avail_sto_kib);

			if (sais_process_rej(vhd, pss, sp, rej))
				goto bail;

			lwsac_free(&pss->a.ac);
			break;

		case SAIM_WSSCH_BUILDER_POOL_HELLO:
			/*
			 * This connection is for syncing a pool: from here on
			 * it carries binary records, including any that came
			 * after the hello in this buffer
			 */
			n = sais_pool_hello(vhd, pss,
					    (sai_pool_hello_t *)pss->a.dest);
			lwsac_free(&pss->a.ac);
			if (n)
				return -1;

			return sais_pool_rx(vhd, pss, buf + bl - (unsigned int)m,
					    (size_t)m);

		case SAIM_WSSCH_BUILDER_ACTIVE_SHELLS:
		{
			sai_active_shells_t *ash = (sai_active_shells_t *)pss->a.dest;
			lws_start_foreach_dll(struct lws_dll2 *, d, ash->shells.head) {
				sai_active_shell_t *s = lws_container_of(d, sai_active_shell_t, list);
				int found = 0;
				lws_start_foreach_dll(struct lws_dll2 *, d2, vhd->shell_sessions.head) {
					sai_shell_session_t *sh = lws_container_of(d2, sai_shell_session_t, list);
					if (!strcmp(sh->task_uuid, s->task_uuid)) {
						found = 1;
						break;
					}
				} lws_end_foreach_dll(d2);

				if (!found) {
					sai_shell_session_t *nsh = malloc(sizeof(*nsh));
					if (nsh) {
						memset(nsh, 0, sizeof(*nsh));
						lws_strncpy(nsh->task_uuid, s->task_uuid, sizeof(nsh->task_uuid));
						if (vhd->server.builder_owner.head) {
							lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.builder_owner.head) {
								sai_plat_t *sp = lws_container_of(p, sai_plat_t, sai_plat_list);
								if (sp->wsi == pss->wsi) {
									lws_strncpy(nsh->builder_name, sp->name, sizeof(nsh->builder_name));
									break;
								}
							} lws_end_foreach_dll(p);
						}
						lws_dll2_add_tail(&nsh->list, &vhd->shell_sessions);
						lwsl_notice("%s: Rediscovered shell %s for builder %s\n", __func__, nsh->task_uuid, nsh->builder_name);
					}
				}
			} lws_end_foreach_dll(d);

			sais_platforms_with_tasks_pending(vhd);

			lwsac_free(&pss->a.ac);
			break;
		}

		case SAIM_WSSCH_BUILDER_LOADREPORT:

			/*
			 * If we got here, we have any intermediate parts
			 * already, let's add this final part there first
			 */

			*((unsigned int *)(buf - sizeof(int))) = ss_flags;
			if (sais_buflist_append_bounded(
					&pss->onward_reassembly,
					buf - sizeof(int),
					bl + sizeof(int),
					SAIS_LOADREPORT_REASSEMBLY_MAX)) {
				lwsl_err("%s: loadreport reassembly over cap / OOM\n",
					 __func__);
				return -1;
			}

			/*
			 * Then let's forward the whole reassembly buflist on
			 * to the proxying buflist atomically.
			 */

			sais_websrv_broadcast_buflist(vhd->h_ss_websrv,
						      &pss->onward_reassembly);

			break;

		case SAIM_WSSCH_BUILDER_ARTIFACT:
			/*
			 * Builder wants to send us an artifact.
			 *
			 * We get sent a JSON object immediately followed by binary
			 * data for the artifact.
			 *
			 * We place the binary data as a blob in the sql record in the
			 * artifact table.
			 */

			lwsl_info("%s: SAIM_WSSCH_BUILDER_ARTIFACT: m = %d, bl = %d\n", __func__, m, (int)bl);

			if (!pss->bulk_binary_data) {

				lwsl_info("%s: BUILDER_ARTIFACT: blob start, m = %d\n", __func__, m);

				ap = (sai_artifact_t *)pss->a.dest;

				/*
				 * The task_uuid from the builder decides which
				 * event db we open and reaches queries and
				 * broadcasts below, so it has to be a real
				 * server-minted task id, not something the
				 * builder cooked up.
				 */
				if (sais_validate_id(ap->task_uuid,
						     SAI_TASKID_LEN)) {
					lwsl_wsi_err(pss->wsi,
						"artifact upload with invalid "
						"task_uuid");
					lwsac_free(&pss->a.ac);

					return -1;
				}

				sai_task_uuid_to_event_uuid(event_uuid, ap->task_uuid);

				/*
				 * Open the event-specific database object... the
				 * handle is closed when the stream closes, for whatever
				 * reason.
				 */

				if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
						      vhd->sqlite3_path_lhs, event_uuid, 0,
							      &pss->pdb_artifact)) {
					lwsl_err("%s: unable to open event-specific "
						 "database\n", __func__);

					lwsac_free(&pss->a.ac);
					return -1;
				}

				/*
				 * Retreive the task object
				 */

				lws_sql_purify(esc, ap->task_uuid, sizeof(esc));
				lws_snprintf(s, sizeof(s)," and uuid == '%s'", esc);
				n = lws_struct_sq3_deserialize(pss->pdb_artifact, s,
							       "run desc", lsm_schema_sq3_map_task,
							       &o, &ac, 0, 1);
				if (n < 0 || !o.head) {
					sai_event_db_close(&vhd->sqlite3_cache, &pss->pdb_artifact);
					lwsl_notice("%s: no task of that id\n", __func__);
					lwsac_free(&pss->a.ac);
					return -1;
				}

				task = (sai_task_t *)o.head;

				/*
				 * Both are fixed 32-char hex in 33-byte
				 * arrays, so a fixed-length compare stays
				 * in-bounds whatever the sender sent
				 */

				n = lws_timingsafe_bcmp(task->art_up_nonce,
							ap->artifact_up_nonce,
							32);

				if (n) {
					lwsl_err("%s: artifact nonce mismatch\n",
						 __func__);
					goto afail;
				}

				/*
				 * The task the sender is sending us an artifact for
				 * exists.  The sender knows the random upload nonce
				 * for that task's artifacts.
				 *
				 * Create a random download nonce unrelated to the
				 * random upload nonce (so knowing the download one
				 * won't let you upload anything).
				 *
				 * Create the artifact's entry in the event-specific
				 * database
				 */

				sai_uuid16_create(pss->vhd->context,
						  ap->artifact_down_nonce);

				ap->run = task->run;

				lws_dll2_owner_clear(&o);
				lws_dll2_add_head(&ap->list, &o);

				/*
				 * Create the task in event-specific database
				 */

				if (lws_struct_sq3_serialize(pss->pdb_artifact,
							 lsm_schema_sq3_map_artifact,
							 &o, (unsigned int)ap->uid)) {
					lwsl_err("%s: failed artifact struct insert\n",
							__func__);

					goto afail;
				}

				/*
				 * recover the rowid
				 */

				lws_snprintf(s, sizeof(s),
					     "select rowid from artifacts "
						"where timestamp=%llu",
					     (unsigned long long)ap->timestamp);

				if (sqlite3_exec((sqlite3 *)pss->pdb_artifact, s,
						sai_sql3_get_uint64_cb, &rid, NULL) !=
									 SQLITE_OK) {
					lwsl_err("%s: %s: %s: fail\n", __func__, s,
						 sqlite3_errmsg(pss->pdb_artifact));
					goto afail;
				}

				/*
				 * Set the blob size on associated row
				 */

				lws_snprintf(s, sizeof(s),
					     "update artifacts set blob=zeroblob(%llu) "
						"where rowid=%llu",
					     (unsigned long long)ap->len,
					     (unsigned long long)rid);

				if (sqlite3_exec((sqlite3 *)pss->pdb_artifact, s,
						 NULL, NULL, NULL) != SQLITE_OK) {
					lwsl_err("%s: %s: %s: fail\n", __func__, s,
						 sqlite3_errmsg(pss->pdb_artifact));
					goto afail;
				}

				/*
				 * Open a blob on the associated row... the blob handle
				 * is closed when this stream closes for whatever
				 * reason.
				 */

				if (sqlite3_blob_open(pss->pdb_artifact, "main",
						  "artifacts", "blob", (sqlite3_int64)rid, 1,
						  &pss->blob_artifact) != SQLITE_OK) {
					lwsl_err("%s: unable to open blob\n", __func__);
					goto afail;
				}

				/*
				 * First time around, m == number of bytes let in buf
				 * after JSON, (bl - m) offset
				 */
				pss->bulk_binary_data = 1;
				pss->artifact_length = ap->len;
			} else {
				m = (int)bl;
				lwsl_info("%s: BUILDER_ARTIFACT: blob bulk\n", __func__);
			}

			if (m) {
				lwsl_info("%s: blob write +%d, ofs %llu / %llu, len %d (0x%02x)\n",
					    __func__, (int)(bl - (unsigned int)m),
					    (unsigned long long)pss->artifact_offset,
					    (unsigned long long)pss->artifact_length, m, buf[0]);
				if (sqlite3_blob_write(pss->blob_artifact,
						   (uint8_t *)buf + (bl - (unsigned int)m), (int)m,
						   (int)pss->artifact_offset)) {
					lwsl_err("%s: writing blob failed\n", __func__);
					goto afail;
				}

				lws_set_timeout(pss->wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
				pss->artifact_offset = pss->artifact_offset + (uint64_t)m;
			} else
				lwsl_info("%s: no m\n", __func__);

			lwsl_info("%s: ofs %d, len %d\n", __func__, (int)pss->artifact_offset, (int)pss->artifact_length);

			if (pss->artifact_offset == pss->artifact_length) {
				int state;

				lwsl_notice("%s: blob upload finished\n", __func__);
				pss->bulk_binary_data = 0;

				ap = (sai_artifact_t *)pss->a.dest;

				lws_sql_purify(esc, ap->task_uuid, sizeof(esc));
				lws_snprintf(s, sizeof(s)," select state from tasks where uuid == '%s' order by run desc limit 1", esc);
				if (sqlite3_exec((sqlite3 *)pss->pdb_artifact, s,
						 sql3_get_integer_cb, &state, NULL) != SQLITE_OK) {
					lwsl_err("%s: %s: %s: fail\n", __func__, s,
						 sqlite3_errmsg(pss->pdb_artifact));
					goto bail;
				}

				sais_taskchange(pss->vhd->h_ss_websrv, ap->task_uuid, state);

				goto afail;
			}

			m = 0;

			break;

		case SAIM_WSSCH_BUILDER_RESOURCE_REQ:
			res = (sai_resource_t *)pss->a.dest;

			/*
			 * We get resource requests here, and also the handing back of
			 * assigned leases.  The requests have the resname member and
			 * the lease yield messages don't.
			 */

			if (!res->resname) {
				sai_resource_requisition_t *rr;

				/*
				 * An assigned resource lease is being yielded
				 */

				rr = sais_resource_lookup_lease_by_cookie(&vhd->server,
									  res->cookie);
				if (!rr) {
					/*
					 * He never got allocated... if he's on the
					 * queue delete him from there... if he doesn't
					 * exist on our side it's OK, just finish
					 */
					sais_resource_destroy_queued_by_cookie(
							&vhd->server, res->cookie);

					return 0;
				}

				/*
				 * Destroy the requisition, freeing any leased resources
				 * allocated to him
				 */

				sais_resource_rr_destroy(rr);

				return 0;
			}

			/*
			 * This is a new request for resources, find out the well-known
			 * resource to attach it to
			 */


			wk = sais_resource_wellknown_by_name(&pss->vhd->server,
							     res->resname);
			if (!wk) {
				sai_resource_msg_t *mq;

				/*
				 * Requested well-known resource doesn't exist
				 */

				lwsl_info("%s: resource %s not well-known\n", __func__,
						res->resname);

				mq = malloc(sizeof(*mq) + LWS_PRE + 256);
				if (!mq)
					return 0;

				memset(mq, 0, sizeof(*mq));

				/* return with cookie but no amount == fail */

				mq->len = (size_t)lws_snprintf((char *)&mq[1] + LWS_PRE, 256,
						"{\"schema\":\"com-warmcat-sai-resource\","
						"\"cookie\":\"%s\"}", res->cookie);
				mq->msg = (char *)&mq[1] + LWS_PRE;

				lws_dll2_add_tail(&mq->list, &pss->res_pending_reply_owner);
				lws_callback_on_writable(pss->wsi);

				return 0;
			}

			/*
			 * Create and queue the request on the right well-known
			 * resource manager, check if we can accept it
			 */

			rr = malloc(sizeof(*rr) + strlen(res->cookie) + 1);
			if (!rr)
				return 0;
			memset(rr, 0, sizeof(*rr));
			memcpy((char *)&rr[1], res->cookie, strlen(res->cookie) + 1);

			rr->cookie = (char *)&rr[1];
			rr->lease_secs = res->lease;
			rr->amount = res->amount;

			lws_dll2_add_tail(&rr->list_pss, &pss->res_owner);
			lws_dll2_add_tail(&rr->list_resource_wellknown, &wk->owner);
			lws_dll2_add_tail(&rr->list_resource_queued_leased, &wk->owner_queued);

			sais_resource_check_if_can_accept_queued(wk);
			break;

		case SAIM_WSSCH_BUILDER_METRIC:
			metric = (sai_build_metric_t *)pss->a.dest;

			/*
			 * We have serialized the incoming JSON representation
			 * into a sai_build_metric_t *metric.
			 *
			 * Let's send it back into JSON so we can broadcast it.
			 */

			js = lws_struct_json_serialize_create(
					lsm_schema_map_build_metric,
					LWS_ARRAY_SIZE(lsm_schema_map_build_metric),
					0, (void *)metric);

			if (!js)
				break;

			switch (lws_struct_json_serialize(js, xbuf + LWS_PRE,
							  sizeof(xbuf) - LWS_PRE, &used)) {
			case LSJS_RESULT_CONTINUE:
				/* we don't expect it not to fit in one fragment */
				lwsl_err("%s: metric for %s too large: %.*s\n",
					 __func__, metric->task_uuid, (int)used,
					 (const char *)xbuf + LWS_PRE);
				assert(0);
				break;
			case LSJS_RESULT_ERROR:
				/* we don't expect not to be able to represent it */
				lwsl_err("%s: unable to serialize metric for %s\n",
					 __func__, metric->task_uuid);
				assert(0);
				break;
			case LSJS_RESULT_FINISH:
				memset(&info, 0, sizeof(info));

				info.private_source_idx	= SAI_WEBSRV_PB__PROXIED_FROM_BUILDER;
				info.buf		= xbuf + LWS_PRE;
				info.len		= used;
				info.ss_flags		= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

				lws_dll2_owner_clear(&o);
				lws_dll2_add_head(&metric->list, &o);

				if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
					lwsl_warn("%s: unable to broadcast to web\n", __func__);

				/*
				 * Let's send the struct also into Sqlite3 so we
				 * can store the metrics
				 */

				if (lws_struct_sq3_serialize(pss->vhd->pdb_metrics,
						lsm_schema_sq3_map_build_metric,
							     &o, 0) < 0)
					lwsl_err("%s: !!!!!!!!!!!!!!!!!! failed to set metrics in db\n", __func__);

				break;
			}
			lws_struct_json_serialize_destroy(&js);


			lwsac_free(&pss->a.ac);
			break;

		case SAIM_WSSCH_BUILDER_PTYDATA:
		{
			sai_ptydata_t *pd = (sai_ptydata_t *)pss->a.dest;

			js = lws_struct_json_serialize_create(lsm_schema_ptydata,
					LWS_ARRAY_SIZE(lsm_schema_ptydata), 0, pd);
			if (!js) {
				lwsac_free(&pss->a.ac);
				break;
			}

			switch (lws_struct_json_serialize(js, xbuf + LWS_PRE,
							  sizeof(xbuf) - LWS_PRE, &used)) {
			case LSJS_RESULT_CONTINUE:
			case LSJS_RESULT_ERROR:
				break;
			case LSJS_RESULT_FINISH:
				memset(&info, 0, sizeof(info));

				info.private_source_idx	= SAI_WEBSRV_PB__PROXIED_FROM_BUILDER;
				info.buf		= xbuf + LWS_PRE;
				info.len		= used;
				info.ss_flags		= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

				// lwsl_notice("%s: PTYDATA received from builder shell %s, relaying %d bytes to web\n", __func__, pd->task_uuid, (int)used);

				if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
					lwsl_warn("%s: unable to broadcast to web\n", __func__);
				break;
			}
			lws_struct_json_serialize_destroy(&js);
			lwsac_free(&pss->a.ac);
			break;
		}
		}

		buf += ((int)bl - m);
		bl = (size_t)m;

	} /* while (bl) */

	return 0;

afail:
	lwsac_free(&ac);
	lwsac_free(&pss->a.ac);
	sai_event_db_close(&vhd->sqlite3_cache, &pss->pdb_artifact);

	return -1;
}

/*
 * We're sending something on a builder ws connection
 */

int
sais_ws_json_tx_builder(struct vhd *vhd, struct pss *pss, uint8_t *buf,
			size_t bl)
{
	uint8_t *start = buf + LWS_PRE, *p = start, *end = buf + bl - 1;
	int n, flags = LWS_WRITE_TEXT, first = 1;
	lws_struct_serialize_t *js;
	sai_task_t *task;
	size_t w;

	if (pss->pool)
		return sais_pool_tx(vhd, pss);

	if (pss->viewer_state_owner.head) {
		/*
		 * Pending viewer state message to send to a builder
		 */
		sai_viewer_state_t *vs = lws_container_of(
				pss->viewer_state_owner.head,
				sai_viewer_state_t, list);

		const lws_struct_map_t lsm_viewerstate_members[] = {
			LSM_UNSIGNED(sai_viewer_state_t, viewers, "viewers"),
		};
		const lws_struct_map_t lsm_schema_viewerstate[] = {
			LSM_SCHEMA(sai_viewer_state_t, NULL, lsm_viewerstate_members,
				   "com.warmcat.sai.viewerstate")
		};

		lwsl_wsi_info(pss->wsi, "++++ Sending viewerstate (count: %u) to builder\n",
			    vs->viewers);

		js = lws_struct_json_serialize_create(lsm_schema_viewerstate,
				LWS_ARRAY_SIZE(lsm_schema_viewerstate), 0, vs);
		if (!js) {
			lwsl_err("%s: lws_struct_json_serialize_create failed for viewerstate\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		/* Dequeue the message we just sent */
		lws_dll2_remove(&vs->list);
		/* And free the memory */
		free(vs);

		/*
		 * If there are more viewer state messages, or other messages,
		 * * request another writeable callback.
		 */
		if (pss->viewer_state_owner.head)
			lws_callback_on_writable(pss->wsi);

		goto send_json;
	}

	if (pss->rebuild_owner.head) {
		/*
		 * Pending rebuild message to send
		 */
		sai_rebuild_t *r = lws_container_of(pss->rebuild_owner.head,
						   sai_rebuild_t, list);

		js = lws_struct_json_serialize_create(lsm_schema_rebuild,
				LWS_ARRAY_SIZE(lsm_schema_rebuild), 0, r);
		if (!js) {
			lwsl_err("%s: lws_struct_json_serialize_create failed for rebuild\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		lws_dll2_remove(&r->list);
		free(r);

		goto send_json;
	}

	if (pss->task_cancel_owner.head) {
		/*
		 * Pending cancel message to send
		 */
		sai_cancel_t *c = lws_container_of(pss->task_cancel_owner.head,
						   sai_cancel_t, list);

		js = lws_struct_json_serialize_create(lsm_schema_json_map_can,
				LWS_ARRAY_SIZE(lsm_schema_json_map_can), 0, c);
		if (!js) {
			lwsl_err("%s: lws_struct_json_serialize_create failed for task_cancel\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		lws_dll2_remove(&c->list);
		free(c);

		goto send_json;
	}

	if (pss->openshell_owner.head) {
		sai_openshell_t *os = lws_container_of(pss->openshell_owner.head,
						       sai_openshell_t, list);

		js = lws_struct_json_serialize_create(lsm_schema_openshell,
				LWS_ARRAY_SIZE(lsm_schema_openshell), 0, os);
		if (!js) {
			lwsl_err("%s: lws_struct_json_serialize_create failed for openshell\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		lws_dll2_remove(&os->list);
		free(os);

		goto send_json;
	}

	if (pss->ptydata_owner.head) {
		sai_ptydata_t *pd = lws_container_of(pss->ptydata_owner.head,
						     sai_ptydata_t, list);

		js = lws_struct_json_serialize_create(lsm_schema_ptydata,
				LWS_ARRAY_SIZE(lsm_schema_ptydata), 0, pd);
		if (!js) {
			lwsl_err("%s: lws_struct_json_serialize_create failed for ptydata\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		lws_dll2_remove(&pd->list);
		if (pd->data)
			free(pd->data);
		free(pd);

		goto send_json;
	}

	/*
	 * resource response?
	 */

	if (pss->res_pending_reply_owner.count) {
		sai_resource_msg_t *rm = lws_container_of(pss->res_pending_reply_owner.head,
				sai_resource_msg_t, list);

		n = (int)rm->len;
		if (n > lws_ptr_diff(end, p))
			n = lws_ptr_diff(end, p);

		memcpy(p, rm->msg, (unsigned int)n);
		w = (size_t)n;

		lwsl_info("%s: issuing pending resouce reply %.*s\n", __func__, (int)n, (const char *)start);

		lws_dll2_remove(&rm->list);
		free(rm);

		goto send_json;
	}

       if (!pss->issue_task_owner.head)
		return 0; /* nothing to send */

	/*
	 * We're sending a builder specific task info that has been bound to the
	 * builder.
	 *
	 * We already got the task struct out of the db in .one_event
	 * (all in .ac)
	 */

	task = lws_container_of(pss->issue_task_owner.head, sai_task_t, pending_assign_list);
	lws_dll2_remove(&task->pending_assign_list);

	js = lws_struct_json_serialize_create(lsm_schema_map_ta,
					      LWS_ARRAY_SIZE(lsm_schema_map_ta),
					      0, task);
	if (!js)
		goto bail;

	n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
	lws_struct_json_serialize_destroy(&js);
	pss->one_event = NULL;
	lwsac_free(&task->ac_task_container);
	free(task);

	// sai_dump_stderr(start, w);
	// lwsl_info("%s: ########## ATTACH TASK --^\n", __func__);

	first = 1;

send_json:
	p += w;
	if (n == LSJS_RESULT_ERROR) {
		lwsl_notice("%s: taskinfo: error generating json\n",
			    __func__);
		return 1;
	}
	if (!lws_ptr_diff(p, start)) {
		lwsl_notice("%s: taskinfo: empty json\n", __func__);
		return 0;
	}

	flags = lws_write_ws_flags(LWS_WRITE_TEXT, first, 1);

	// lwsl_hexdump_notice(start, p - start);

	if (lws_write(pss->wsi, start, lws_ptr_diff_size_t(p, start),
			(enum lws_write_protocol)flags) < 0) {
		lwsl_err("%s: lws_write failed for task allocation\n", __func__);
		return -1;
	}

	if (pss->viewer_state_owner.head || pss->task_cancel_owner.head ||
	    pss->res_pending_reply_owner.count ||
	    pss->issue_task_owner.count || pss->openshell_owner.head ||
	    pss->ptydata_owner.head)
		lws_callback_on_writable(pss->wsi);

	return 0;

bail:
	lwsl_err("%s: bailing, returning 1\n", __func__);
	lwsac_free(&task->ac_task_container);
	free(task);

	return 1;

}
