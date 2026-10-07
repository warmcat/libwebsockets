/*
 * Sai server - ./src/server/m-ws-browser.c
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
 *   b1 --\   sai-        sai-   /-- browser
 *   b2 ----- server ---- web ------ browser
 *   b3 --/                  *   \-- browser
 *
 * These are ws rx and tx handlers related to browser ws connections, on
 * /broswe URLs.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "w-private.h"

/*
 * For decoding specific event data request from browser
 */

/*
 * (Structs and maps removed - now in common/include/private.h and common/struct-metadata.c)
 */

static lws_struct_map_t lsm_browser_evinfo[] = {
	LSM_CARRAY	(sai_browse_rx_evinfo_t, event_hash,	"event_hash"),
};

static lws_struct_map_t lsm_browser_branchlist[] = {
	LSM_CARRAY	(sai_browse_rx_branchlist_t, project,	"project"),
};

static lws_struct_map_t lsm_browser_taskreset[] = {
	LSM_CARRAY	(sai_browse_rx_evinfo_t, event_hash,	"uuid"),
};

static lws_struct_map_t lsm_browser_platreset[] = {
	LSM_CARRAY	(sai_browse_rx_platreset_t, event_uuid, "event_uuid"),
	LSM_CARRAY	(sai_browse_rx_platreset_t, platform,   "platform"),
};

static lws_struct_map_t lsm_browser_builderdelete[] = {
	LSM_CARRAY	(sai_browse_rx_builderdelete_t, builder_name, "builder_name"),
};

typedef struct sai_browse_rx_builder_visibility {
	uint8_t visible;
} sai_browse_rx_builder_visibility_t;

static lws_struct_map_t lsm_browser_builder_visibility[] = {
	LSM_UNSIGNED	(sai_browse_rx_builder_visibility_t, visible, "visible"),
};

static void
saiw_browser_logs_reset(struct pss *pss);
static int
saiw_browser_logs_cursor_stale(struct vhd *vhd, struct pss *pss);

static lws_struct_map_t lsm_browser_taskinfo[] = {
	LSM_CARRAY	(sai_browse_rx_taskinfo_t, task_hash,		"task_hash"),
	LSM_UNSIGNED	(sai_browse_rx_taskinfo_t, logs,		"logs"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, js_api_version,	"js_api_version"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, offset,		"offset"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, last_log_ts,		"last_log_ts"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, last_log_uid,	"last_log_uid"),
	LSM_SIGNED      (sai_browse_rx_taskinfo_t, run,			"run"),
	/* Sidebar selection scoping the overview to project + branch */
	LSM_CARRAY	(sai_browse_rx_taskinfo_t, project,		"project"),
	LSM_CARRAY	(sai_browse_rx_taskinfo_t, ref,		"ref"),
};

/*
 * Schema list so lws_struct can pick the right object to create based on the
 * incoming schema name
 */

static const lws_struct_map_t lsm_schema_json_map_bwsrx[] = {
	LSM_SCHEMA	(sai_browse_rx_taskinfo_t, NULL, lsm_browser_taskinfo,
					      "com.warmcat.sai.taskinfo"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_evinfo,
					      "com.warmcat.sai.eventinfo"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskreset"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskremovealltries"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskrebuildlaststep"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.eventreset"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.eventdelete"),
	LSM_SCHEMA	(sai_cancel_t,		 NULL, lsm_task_cancel,
					      "com.warmcat.sai.taskcan"),
	LSM_SCHEMA	(sai_load_report_t,	 NULL, lsm_load_report_members,
					      "com.warmcat.sai.loadreport"),
	LSM_SCHEMA	(sai_rebuild_t,		 NULL, lsm_rebuild,
					      "com.warmcat.sai.rebuild"),
	LSM_SCHEMA	(sai_browse_rx_platreset_t, NULL, lsm_browser_platreset,
					      "com.warmcat.sai.platreset"),
	LSM_SCHEMA	(sai_stay_t,		 NULL, lsm_stay,
					      "com.warmcat.sai.stay"),
	LSM_SCHEMA	(sai_pcon_control_t,	 NULL, lsm_pcon_control,
			/* shares struct */   "com.warmcat.sai.pcon_control"),
	LSM_SCHEMA_DLL2	(sai_watcher_service_t, list, NULL, lsm_watcher_service,
					      "com.warmcat.sai.watcher_services"),
	LSM_SCHEMA	(sai_browse_rx_builderdelete_t, NULL, lsm_browser_builderdelete,
					      "com.warmcat.sai.builderdelete"),
	LSM_SCHEMA	(sai_openshell_t, NULL, lsm_openshell,
					      "com.warmcat.sai.openshell"),
	LSM_SCHEMA	(sai_closeshell_t, NULL, lsm_closeshell,
					      "com.warmcat.sai.closeshell"),
	LSM_SCHEMA	(sai_ptydata_t, NULL, lsm_ptydata,
					      "com.warmcat.sai.ptydata"),
	LSM_SCHEMA	(sai_browse_rx_builder_visibility_t, NULL, lsm_browser_builder_visibility,
					      "com.warmcat.sai.builder_visibility"),
	/* sidebar project / branch list requests (read-only, no auth) */
	LSM_SCHEMA	(sai_browse_rx_branchlist_t, NULL, lsm_browser_branchlist,
					      "com.warmcat.sai.projlist"),
	LSM_SCHEMA	(sai_browse_rx_branchlist_t, NULL, lsm_browser_branchlist,
					      "com.warmcat.sai.branchlist"),
	/*
	 * Ad-hoc builds (admin only): cloneinfo is answered locally with what
	 * the dialog needs to prefill, taskclone is forwarded to sai-server
	 */
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.cloneinfo"),
	LSM_SCHEMA	(sai_browse_rx_taskclone_t, NULL, lsm_taskclone,
					      "com.warmcat.sai.taskclone"),
	/*
	 * Findings (admin only): the list and one finding's details are
	 * answered locally, changes are forwarded to sai-server
	 */
	LSM_SCHEMA	(sai_findingset_t, NULL, lsm_findingset,
			/* shares struct */   "com.warmcat.sai.findings"),
	LSM_SCHEMA	(sai_findingset_t, NULL, lsm_findingset,
			/* shares struct */   "com.warmcat.sai.findingget"),
	LSM_SCHEMA	(sai_findingset_t, NULL, lsm_findingset,
					      "com.warmcat.sai.findingset"),
};

enum {
	SAIM_WS_BROWSER_RX_TASKINFO,
	SAIM_WS_BROWSER_RX_EVENTINFO,
	SAIM_WS_BROWSER_RX_TASKRESET,
	SAIM_WS_BROWSER_RX_TASKREMOVEALLTRIES,
	SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP,
	SAIM_WS_BROWSER_RX_EVENTRESET,
	SAIM_WS_BROWSER_RX_EVENTDELETE,
	SAIM_WS_BROWSER_RX_TASKCANCEL,
	SAIM_WS_BROWSER_RX_LOADREPORT,
	SAIM_WS_BROWSER_RX_REBUILD,
	SAIM_WS_BROWSER_RX_PLATRESET,
	SAIM_WS_BROWSER_RX_STAY,
	SAIM_WS_BROWSER_RX_PCON_CONTROL,
	SAIM_WS_BROWSER_RX_WATCHER_SERVICES,
	SAIM_WS_BROWSER_RX_BUILDERDELETE,
	SAIM_WS_BROWSER_RX_OPENSHELL,
	SAIM_WS_BROWSER_RX_CLOSESHELL,
	SAIM_WS_BROWSER_RX_PTYDATA,
	SAIM_WS_BROWSER_RX_BUILDER_VISIBILITY,
	SAIM_WS_BROWSER_RX_PROJLIST,
	SAIM_WS_BROWSER_RX_BRANCHLIST,
	SAIM_WS_BROWSER_RX_CLONEINFO,
	SAIM_WS_BROWSER_RX_TASKCLONE,
	SAIM_WS_BROWSER_RX_FINDINGS,
	SAIM_WS_BROWSER_RX_FINDINGGET,
	SAIM_WS_BROWSER_RX_FINDINGSET,
};

/* nonzero if s is exactly len hex chars, as task / event uuids are */
static int
saiw_id_ok(const char *s, size_t len)
{
	return strlen(s) == len && sai_is_git_hash(s);
}

/*
 * Answer com.warmcat.sai.cloneinfo: everything the ad-hoc build dialog needs
 * to prefill from the seed task, plus the project's scratch ("_"-prefixed)
 * branches as most recently pushed, newest first, so the dialog can default
 * to the latest one.
 *
 * Everything here comes from the databases sai-server maintains, which we
 * read directly, so no round trip to the server is needed.
 */
static int
saiw_browser_send_cloneinfo(struct vhd *vhd, struct pss *pss,
			    const char *seed_uuid)
{
	struct lwsac *ac_t = NULL, *ac_e = NULL;
	char event_uuid[33], esc[96], filt[160], *ebuf = NULL, *p, *end;
	lws_dll2_owner_t o_t, o_e;
	sqlite3_stmt *stmt = NULL;
	uint8_t *rbuf = NULL;
	sqlite3 *pdb = NULL;
	int ret = 1, first = 1, n;
	sai_event_t *e;
	sai_task_t *t;

	sai_task_uuid_to_event_uuid(event_uuid, seed_uuid);

	/* the seed task's event, for the repo name and its current ref */

	lws_sql_purify(esc, event_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(vhd->pdb, filt, NULL,
				       lsm_schema_sq3_map_event, &o_e, &ac_e,
				       0, 1);
	if (n < 0 || !o_e.head) {
		lwsl_notice("%s: no event %s\n", __func__, event_uuid);
		goto bail;
	}
	e = lws_container_of(o_e.head, sai_event_t, list);

	/* the seed task itself, latest run */

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, event_uuid, 0,
				     &pdb)) {
		lwsl_notice("%s: no event db %s\n", __func__, event_uuid);
		goto bail;
	}

	lws_sql_purify(esc, seed_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pdb, filt, "run desc",
				       lsm_schema_sq3_map_task, &o_t, &ac_t,
				       0, 1);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	if (n < 0 || !o_t.head) {
		lwsl_notice("%s: no task %s\n", __func__, seed_uuid);
		goto bail;
	}
	t = lws_container_of(o_t.head, sai_task_t, list);

	/*
	 * The build script is up to 4KiB and JSON escaping can grow each
	 * byte to 6, so both the escape buffer and the reply are heap
	 */
	ebuf = malloc((sizeof(t->build) * 6) + 8);
	rbuf = malloc(LWS_PRE + 32768);
	if (!ebuf || !rbuf)
		goto bail;
	p = (char *)rbuf + LWS_PRE;
	end = p + 32768;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"com.warmcat.sai.cloneinfo\","
			  "\"seed_uuid\":\"%s\",",
			  lws_json_purify(esc, seed_uuid, sizeof(esc) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"repo_name\":\"%s\",",
			  lws_json_purify(esc, e->repo_name, sizeof(esc) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"ref\":\"%s\",",
			  lws_json_purify(esc, e->ref, sizeof(esc) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"taskname\":\"%s\",",
			  lws_json_purify(esc, t->taskname, sizeof(esc) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"platform\":\"%s\",",
			  lws_json_purify(esc, t->platform, sizeof(esc) - 1, NULL));
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"build\":\"%s\",",
			  lws_json_purify(ebuf, t->build,
					  (int)(sizeof(t->build) * 6) + 7, NULL));

	/*
	 * Scratch branches pushed for this project, newest first.  The
	 * pushes table is created by sai-server; if it isn't there yet the
	 * prepare fails and the list is simply empty.
	 */
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"refs\":[");

	if (sqlite3_prepare_v2(vhd->pdb,
			"SELECT ref, hash FROM pushes WHERE repo_name = ? "
			"AND ref LIKE 'refs/heads/\\_%' ESCAPE '\\' "
			"ORDER BY created DESC LIMIT 20",
			-1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, e->repo_name, -1, SQLITE_STATIC);

		while (sqlite3_step(stmt) == SQLITE_ROW &&
		       lws_ptr_diff_size_t(end, p) > 256) {
			const char *rn = (const char *)sqlite3_column_text(stmt, 0),
				   *h = (const char *)sqlite3_column_text(stmt, 1);

			if (!rn || !h)
				continue;

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s{\"ref\":\"%s\",", first ? "" : ",",
					  lws_json_purify(esc, rn, sizeof(esc) - 1, NULL));
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "\"hash\":\"%s\"}",
					  lws_json_purify(esc, h, sizeof(esc) - 1, NULL));
			first = 0;
		}
		sqlite3_finalize(stmt);
	} else
		lwsl_info("%s: no pushes table\n", __func__);

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, rbuf + LWS_PRE,
			lws_ptr_diff_size_t(p, (char *)rbuf + LWS_PRE),
			LWS_WRITE_TEXT);
	ret = 0;

bail:
	free(rbuf);
	free(ebuf);
	lwsac_free(&ac_t);
	lwsac_free(&ac_e);

	return ret;
}


/*
 * For issuing combined task and event data back to browser
 */

typedef struct sai_browse_taskreply {
	const sai_event_t	*event;
	const sai_task_t	*task;
	lws_dll2_owner_t	runs;
} sai_browse_taskreply_t;

static lws_struct_map_t lsm_taskreply[] = {
	LSM_CHILD_PTR	(sai_browse_taskreply_t, event,	sai_event_t, NULL,
			 lsm_event, "e"),
	LSM_CHILD_PTR	(sai_browse_taskreply_t, task,	sai_task_t, NULL,
			 lsm_task, "t"),
	LSM_LIST	(sai_browse_taskreply_t, runs,	sai_task_t, list, NULL,
			 lsm_task, "runs"),
};

const lws_struct_map_t lsm_schema_json_map_taskreply[] = {
	LSM_SCHEMA	(sai_browse_taskreply_t, NULL, lsm_taskreply,
			 "com.warmcat.sai.taskinfo"),
};

enum sai_overview_state {
	SOS_EVENT,
	SOS_TASKS,
};

/*
 * Tx backpressure thresholds for browser connections.
 *
 * DEFER: producers that can retry (overview / log batches) hold off while
 *        the connection is this backed-up, and retry from a sul once it has
 *        drained below; matches the threshold the log path already used.
 *
 * HWM:   if the backlog is still above this, the peer is simply not
 *        consuming (zero TCP window).  It is set above the largest legit
 *        single composed message (an unscoped overview on a populated db
 *        can be a few MB), so reaching it means repeated messages have
 *        piled up undrained; we shed the connection instead of letting it
 *        pin memory.  The raw_tx sanity limit (32MiB) remains the hard
 *        ceiling behind this.
 */
#define SAIW_BROWSER_TX_DEFER	(100 * 1024)
#define SAIW_BROWSER_TX_HWM	(8 * 1024 * 1024)

int
saiw_ws_browser_queue_REQUIRES_LWS_PRE(struct pss *pss, const void *buf,
				       size_t len, enum lws_write_protocol flags)
{
	int *pi = (int *)((const char *)buf - sizeof(int)), r = 0;

	if (lws_buflist2_total_len(&pss->raw_tx) > SAIW_BROWSER_TX_HWM) {
		/*
		 * The browser stopped reading and everything queued for it is
		 * still sitting here.  Stop appending and have the connection
		 * closed rather than keep allocating for it.
		 */
		if (!pss->tx_shed) {
			pss->tx_shed = 1;
			lwsl_wsi_notice(pss->wsi,
					"tx backlog over HWM, shedding conn");
			lws_wsi_close(pss->wsi, LWS_TO_KILL_ASYNC);
		}

		return 1;
	}

	*pi = (int)flags;

	if (lws_buflist2_append_segment(&pss->raw_tx, buf - sizeof(int), len + sizeof(int)) < 0) {
		lwsl_wsi_err(pss->wsi, "unable to buflist_append"); /* still ask to drain */
		r = 1;
	}

	lws_callback_on_writable(pss->wsi);

	return r;
}

/*
 * This allows other parts of sai-web to queue a raw buffer to be sent to
 * all connected browsers, eg, for load reports.
 *
 * The flags are lws_write() flags.
 */
void
saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(struct vhd *vhd, const void *buf,
					    size_t len, enum lws_write_protocol flags)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, buf, len, flags);

	} lws_end_foreach_dll(p);
}



int
sai_sql3_get_uint64_cb(void *user, int cols, char **values, char **name)
{
	uint64_t *pui = (uint64_t *)user;

	*pui = (uint64_t)atoll(values[0]);

	return 0;
}



/*
 * Ask for writeable cb on all browser connections subscribed to a particular
 * task (so we can send them some more logs)
 */

int
saiw_subs_request_writeable(struct vhd *vhd, const char *task_uuid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      vhd->subs_owner.head) {
		struct pss *pss = lws_container_of(p, struct pss, subs_list);

		if (!strcmp(pss->sub_task_uuid, task_uuid))
			lws_callback_on_writable(pss->wsi);

	} lws_end_foreach_dll(p);

	return 0;
}

static int
saiw_pss_schedule_eventinfo(struct pss *pss, const char *event_uuid)
{
	/*
	 * This pss may be locked to a specific event
	 */

	if (pss->specific_task[0] && memcmp(pss->specific_task, event_uuid, 32))
		goto bail;

	/*
	 * The browser selected a specific event (com.warmcat.sai.eventinfo) and
	 * wants that one event's full task list in the tasks pane.  Stash the
	 * event uuid as a one-shot hint so saiw_browser_queue_overview() scopes
	 * to just that event AND emits full task data for it (bypassing the
	 * summary-only mode used for the multi-event sidebar list).  The hint
	 * is cleared by saiw_browser_queue_overview() after it is consumed.
	 */
	lws_strncpy(pss->event_tasks_uuid, event_uuid,
		    sizeof(pss->event_tasks_uuid));

	saiw_browser_queue_overview(pss->vhd, pss);
	saiw_browser_broadcast_queue_builders(pss->vhd, pss);

	return 0;

bail:
	saiw_browser_queue_overview(pss->vhd, pss);
	saiw_browser_broadcast_queue_builders(pss->vhd, pss);

	return 1;
}

/* we leave an allocation in sch->query_ac ... */

static int
saiw_pss_schedule_taskinfo(struct pss *pss, const char *task_uuid, int logsub, int run_idx)
{
	char qu[192], event_uuid[33], esc2[96], buf[4096 + LWS_PRE],
	     *start = buf + LWS_PRE, *p = start, *end = buf + sizeof(buf);
	const sai_event_t *one_event = NULL;
	sai_browse_taskreply_t task_reply;
	struct lwsac *query_ac = NULL, *runs_ac = NULL, *art_ac = NULL;
	sai_task_t *one_task = NULL;
	lws_struct_serialize_t *js;
	char esc[256], filt[192];
	lws_dll2_owner_t owner;
	sqlite3 *pdb = NULL;
	lws_dll2_owner_t o;
	sai_task_t *pt;
	char fi = 1;
	int m, n;
	size_t w;

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	/*
	 * This pss may be locked to a specific event and not want to hear
	 * anything unrelated to that event... lock to task is same deal but
	 * we will also send it non-log info about other tasks, so it can
	 * keep its event summary alive
	 */

	if (pss->specific_task[0] &&
	    memcmp(pss->specific_task, event_uuid, 32)) {
		lwsl_info("%s: specific_task '%s' vs event_uuid '%s\n",
			    __func__, pss->specific_task, event_uuid);
		goto bail;
	}

	/*
	 * Open the event-specific database object... a task in a project this
	 * vhost doesn't show is treated the same as one whose event is gone
	 */

	if (!saiw_event_visible(pss->vhd, event_uuid) ||
	    sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
			      pss->vhd->sqlite3_path_lhs, event_uuid, 0, &pdb)) {
		uint8_t buf[LWS_PRE + 128];
		int n1 = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE,
				     "{\"schema\":\"com.warmcat.sai.event_deleted\"}");
		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, buf + LWS_PRE, (size_t)n1,
						       LWS_WRITE_TEXT);
		return 0;
	}

	/*
	 * get the related task object into its own ac... there might
	 * be a lot of related data, so we hold the ac in the sch for
	 * as long as needed to send it out
	 */

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	if (run_idx >= 0)
		lws_snprintf(qu, sizeof(qu), " and uuid='%s' and run=%d", esc, run_idx);
	else
		lws_snprintf(qu, sizeof(qu), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pdb, qu, run_idx >= 0 ? NULL : "run desc", lsm_schema_sq3_map_task,
				       &o, &query_ac, 0, 1);
				       
	memset(&task_reply, 0, sizeof(task_reply));
	lws_dll2_owner_clear(&task_reply.runs);
	lws_snprintf(qu, sizeof(qu), " and uuid='%s'", esc);
	if (lws_struct_sq3_deserialize(pdb, qu, "run desc", lsm_schema_sq3_map_task,
				       &task_reply.runs, &runs_ac, 0, 100) < 0)
		lwsl_err("%s: runs deserialize failed\n", __func__);
				       
	sai_event_db_close(&pss->vhd->sqlite3_cache, &pdb);
	if (n < 0 || !o.head)
		goto bail;

	pt = lws_container_of(o.head, sai_task_t, list);
	one_task = pt;

	/* let the pss take over the task info ac and schedule sending */

	lws_dll2_remove((struct lws_dll2 *)&one_task->list);

	/*
	 * let's also get the event object the task relates to into
	 * its own event struct, additionally qualify this task against any
	 * pss reponame-specific constraint and bail if doesn't match
	 */

	lws_sql_purify(esc, event_uuid, sizeof(esc));
	m = lws_snprintf(qu, sizeof(qu), " and uuid='%s'", esc);
	if (pss->specific_project[0]) {
		lws_sql_purify(esc2, pss->specific_project, sizeof(esc2));
		m += lws_snprintf(qu + m, sizeof(qu) - (unsigned int)m, " and repo_name='%s'", esc2);
	}

	if (pss->specific_ref[0] && pss->specificity != SAIM_SPECIFIC_TASK) {
		lws_sql_purify(esc2, pss->specific_ref, sizeof(esc2));
		if (pss->specific_ref[0] == 'r') {
			/* check event ref against, eg, ref/heads/xxx */
			if (!strcmp(pss->specific_ref, "refs/heads/master"))
				m += lws_snprintf(qu + m, sizeof(qu) - (unsigned int)m,
					" and (ref='refs/heads/master' or ref='refs/heads/main')");
			else
				m += lws_snprintf(qu + m, sizeof(qu) - (unsigned int)m, " and ref='%s'", esc2);
		} else
			/* check event hash against, eg, 12341234abcd... */
			m += lws_snprintf(qu + m, sizeof(qu) - (unsigned int)m, " and hash='%s'", esc2);
	}

	n = lws_struct_sq3_deserialize(pss->vhd->pdb, qu, NULL,
				       lsm_schema_sq3_map_event, &o,
				       &query_ac, 0, 1);
	if (n < 0 || !o.head)
		/*
		 * It's OK if the parent event is not visible in the current
		 * filtered view, we can still update the task state where it
		 * appears inside other visible events
		 */
		one_event = NULL;
	else
		one_event = lws_container_of(o.head, sai_event_t, list);

	/*
	 * We're sending a browser the specific task info that he
	 * asked for.
	 *
	 * We already got the task struct out of the db in .one_task
	 * (all in .query_ac)... we're responsible for destroying it
	 * when we go out of scope...
	 */

	/*
	 * As in the overview, the browser mustn't get the task's nonces: the
	 * up nonce is the key builders use to upload artifacts and sync pools
	 * for the task, and the down nonce is the key to download its
	 * artifacts, which browsers only get in the artifact links
	 */

	one_task->art_up_nonce[0] = '\0';
	one_task->art_down_nonce[0] = '\0';
	lws_start_foreach_dll(struct lws_dll2 *, d, task_reply.runs.head) {
		sai_task_t *rt = lws_container_of(d, sai_task_t, list);

		rt->art_up_nonce[0] = '\0';
		rt->art_down_nonce[0] = '\0';
	} lws_end_foreach_dll(d);

	task_reply.event		= one_event;
	task_reply.task			= one_task;
	one_task->rebuildable		= (one_task->state == SAIES_FAIL ||
					   one_task->state == SAIES_CANCELLED) &&
					  (lws_now_secs() - (one_task->started +
					   (one_task->duration / 1000000)) < 24 * 3600);

	js = lws_struct_json_serialize_create(lsm_schema_json_map_taskreply,
					      LWS_ARRAY_SIZE(lsm_schema_json_map_taskreply),
					      0, &task_reply);
	if (!js) {
		lwsl_warn("%s: couldn't create\n", __func__);
		goto bail;
	}

	do {
		n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
		if (n == LSJS_RESULT_ERROR) {
			lws_struct_json_serialize_destroy(&js);
			lwsl_notice("%s: taskinfo: error generating json\n", __func__);
			goto bail;
		}
		p += w;

		if (lws_ptr_diff_size_t(end, (uint8_t *)p) < 512) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
								    lws_ptr_diff_size_t(p, start),
								    lws_write_ws_flags(LWS_WRITE_TEXT, fi, 0));
			p = start;
			fi = 0;
		}

	} while (n == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);

	/*
	 * Let's also try to fetch any artifacts into pss->aft_owner...
	 * no db or no artifacts can also be a normal situation...
	 */

	sai_task_uuid_to_event_uuid(event_uuid, one_task->uuid);

	lws_dll2_owner_clear(&owner);
	if (!sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
				      pss->vhd->sqlite3_path_lhs, event_uuid,
				      0, &pdb)) {

		/* uuid is db-derived, purify keeps the literal safe anyway */
		lws_sql_purify(esc, one_task->uuid, sizeof(esc));

		if (run_idx >= 0)
			lws_snprintf(filt, sizeof(filt), " and (task_uuid == '%s') and run=%d",
			     esc, run_idx);
		else
			lws_snprintf(filt, sizeof(filt), " and (task_uuid == '%s') and run=%d",
			     esc, one_task->run);

		if (lws_struct_sq3_deserialize(pdb, filt, NULL,
					       lsm_schema_sq3_map_artifact,
					       &owner,
					       &art_ac, 0, 10))
			lwsl_err("%s: get afcts failed\n", __func__);

		sai_event_db_close(&pss->vhd->sqlite3_cache, &pdb);
	}



	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, fi, 1));

	/* does he want to subscribe to logs? */
	if (logsub) {
		int new_run = run_idx >= 0 ? run_idx : one_task->run;
		/* was this pss watching anything before now? */
		int had_sub = !!pss->sub_task_uuid[0];
		int is_new_task = strcmp(pss->sub_task_uuid, one_task->uuid);
		int is_new_run = pss->sub_run != new_run;

		strcpy(pss->sub_task_uuid, one_task->uuid);
		pss->sub_run = new_run;

		if (!pss->subs_list.owner) {
			lws_dll2_add_head(&pss->subs_list, &pss->vhd->subs_owner);
		}

		/*
		 * The browser tells us the highest row it already has, so it can
		 * resume across a reconnect instead of us shipping the whole log
		 * again.  It sends 0 when it wants the log from the start, which
		 * is what it does whenever it selects a task.
		 *
		 * We have to wipe what it is showing if we are about to send
		 * from the start, or if the rows it has belong to a run it is no
		 * longer looking at... otherwise the new lines just pile up
		 * underneath lines that are not part of this build any more.
		 */

		if (!pss->initial_log_uid ||
		    (had_sub && (is_new_task || is_new_run))) {
			saiw_browser_logs_reset(pss);
			saiw_broadcast_logs_batch(pss->vhd, pss);
		} else {
			pss->sub_uid = pss->initial_log_uid;
			pss->sub_timestamp = pss->initial_log_timestamp;

			if (saiw_browser_logs_cursor_stale(pss->vhd, pss)) {
				/* the rows it is resuming from are gone */
				saiw_browser_logs_reset(pss);
				saiw_broadcast_logs_batch(pss->vhd, pss);
			}
		}
	} else if (!strcmp(pss->sub_task_uuid, one_task->uuid)) {
		/* If already subscribed to this task, track new runs automatically */
		int new_run = run_idx >= 0 ? run_idx : one_task->run;

		if (pss->sub_run != new_run) {
			pss->sub_run = new_run;
			saiw_browser_logs_reset(pss);
			saiw_broadcast_logs_batch(pss->vhd, pss);
		} else
			/*
			 * Same task, same run, but the rows may have been
			 * removed under us: "remove all tries" deletes a task's
			 * logs and puts it back to run 0, so the run alone does
			 * not always change
			 */
			if (saiw_browser_logs_cursor_stale(pss->vhd, pss)) {
				saiw_browser_logs_reset(pss);
				saiw_broadcast_logs_batch(pss->vhd, pss);
			}
	}

	saiw_browser_broadcast_queue_builders(pss->vhd, pss);

	if (owner.head) {
		sai_artifact_t *aft = (sai_artifact_t *)owner.head;

		p = start;
		fi = 1;

		lwsl_info("%s: WSS_SEND_ARTIFACT_INFO: consuming artifact\n", __func__);

		lws_dll2_remove(&aft->list);

		/* we don't want to disclose this to browsers */
		aft->artifact_up_nonce[0] = '\0';

		js = lws_struct_json_serialize_create(lsm_schema_json_map_artifact,
				LWS_ARRAY_SIZE(lsm_schema_json_map_artifact),
				0, aft);
		if (!js) {
			lwsl_err("%s ----------------- failed to render artifact json\n", __func__);
			goto bail;
		}

		do {
			n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
			if (n == LSJS_RESULT_ERROR) {
				lws_struct_json_serialize_destroy(&js);
				lwsl_notice("%s: taskinfo: ---------- error generating json\n", __func__);
				goto bail;
			}
			p += w;
			if (lws_ptr_diff_size_t(end, p) < 512) {
				saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(pss->vhd, start,
									    lws_ptr_diff_size_t(p, start),
									    lws_write_ws_flags(LWS_WRITE_TEXT, fi, 0));
				p = start;
				fi = 0;
			}

		} while (n == LSJS_RESULT_CONTINUE);

		lws_struct_json_serialize_destroy(&js);
	}

	lwsac_free(&query_ac);
	lwsac_free(&runs_ac);
	lwsac_free(&art_ac);

	return 0;

bail:
	lwsac_free(&query_ac);
	lwsac_free(&runs_ac);
	lwsac_free(&art_ac);

	return 1;
}

/*
 * We need to schedule re-sending out task and event state to anyone subscribed
 * to the task that changed or its associated event
 */

int
saiw_subs_task_state_change(struct vhd *vhd, const char *task_uuid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      vhd->subs_owner.head) {
		struct pss *pss = lws_container_of(p, struct pss, subs_list);

		if (!strcmp(pss->sub_task_uuid, task_uuid))
			saiw_pss_schedule_taskinfo(pss, task_uuid, 0, pss->sub_run);

	} lws_end_foreach_dll(p);

	return 0;
}


int
saiw_browsers_task_state_change(struct vhd *vhd, const char *task_uuid)
{
	char event_uuid[33];

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		if (!pss->is_gitohashi &&
		    (!pss->selected_event_uuid[0] ||
		     !strcmp(pss->selected_event_uuid, event_uuid)))
			saiw_pss_schedule_taskinfo(pss, task_uuid, 0, -1);
	} lws_end_foreach_dll(p);

	return 0;
}


int
saiw_event_state_change(struct vhd *vhd, const char *event_uuid)
{
	/* long poll feed requests may be waiting on this */
	saiw_rss_event_change(vhd);

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		if (!pss->is_gitohashi)
			saiw_pss_schedule_eventinfo(pss, event_uuid);
	} lws_end_foreach_dll(p);

	return 0;
}

/*
 * Nonzero if the browser message, which has decoded into dest, is about
 * something in a project this vhost shows, or about nothing project-specific
 * at all (eg, builders).  Taskinfo and eventinfo don't need checking here,
 * the replies to them are already limited to the visible projects.
 */

static int
saiw_rx_visible(struct vhd *vhd, int schema_idx, void *dest)
{
	switch (schema_idx) {
	case SAIM_WS_BROWSER_RX_TASKRESET:
	case SAIM_WS_BROWSER_RX_TASKREMOVEALLTRIES:
	case SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP:
	case SAIM_WS_BROWSER_RX_EVENTRESET:
	case SAIM_WS_BROWSER_RX_EVENTDELETE:
	case SAIM_WS_BROWSER_RX_CLONEINFO:
		return saiw_event_visible(vhd,
				((sai_browse_rx_evinfo_t *)dest)->event_hash);
	case SAIM_WS_BROWSER_RX_TASKCANCEL:
		return saiw_event_visible(vhd, ((sai_cancel_t *)dest)->task_uuid);
	case SAIM_WS_BROWSER_RX_PLATRESET:
		return saiw_event_visible(vhd,
				((sai_browse_rx_platreset_t *)dest)->event_uuid);
	case SAIM_WS_BROWSER_RX_OPENSHELL:
		return saiw_event_visible(vhd,
				((sai_openshell_t *)dest)->task_uuid);
	case SAIM_WS_BROWSER_RX_CLOSESHELL:
		return saiw_event_visible(vhd,
				((sai_closeshell_t *)dest)->task_uuid);
	case SAIM_WS_BROWSER_RX_PTYDATA:
		return saiw_event_visible(vhd,
				((sai_ptydata_t *)dest)->task_uuid);
	case SAIM_WS_BROWSER_RX_TASKCLONE:
		return saiw_event_visible(vhd,
				((sai_browse_rx_taskclone_t *)dest)->seed_uuid);
	case SAIM_WS_BROWSER_RX_FINDINGGET:
	case SAIM_WS_BROWSER_RX_FINDINGSET:
		return saiw_project_visible(vhd,
				((sai_findingset_t *)dest)->repo);
	}

	return 1;
}

/*
 * sai-web has sent us a request for either overview, or data on a specific
 * task
 */

int
saiw_ws_json_rx_browser(struct vhd *vhd, struct pss *pss, uint8_t *buf,
			size_t bl, unsigned int ss_flags)
{
	sai_browse_rx_taskinfo_t *ti;
	sai_browse_rx_evinfo_t *ei;
	lws_struct_args_t a;
	sai_cancel_t *can;
	int m, ret = -1;

	lwsl_info("%s: len %d, flags: %d\n", __func__, (int)bl, ss_flags);
	/* lwsl_hexdump_info(buf, bl); */

	memset(&a, 0, sizeof(a));
	/*
	 * pss->js_api_version defaults to 1 (from ESTABLISHED callback).
	 * A new client will update it by sending a js-hello message.
	 */
	a.map_st[0] = lsm_schema_json_map_bwsrx;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_schema_json_map_bwsrx);
	a.map_entries_st[1] = LWS_ARRAY_SIZE(lsm_schema_json_map_bwsrx);
	a.ac_block_size = 128;

	lws_struct_json_init_parse(&pss->ctx, NULL, &a);
	m = lejp_parse(&pss->ctx, (uint8_t *)buf, (int)bl);
	if (m < 0 || !a.dest) {
		lwsl_hexdump_notice(buf, bl);
		lwsl_notice("%s: browser->web JSON decode failed '%s'\n",
				__func__, lejp_error_to_string(m));
		ret = m;
		goto bail;
	}

	/*
	 * Which object we ended up with depends on the schema that came in...
	 * a.top_schema_index is the index in lsm_schema_json_map_bwsrx it
	 * matched on
	 */

	if (pss->auth_state != SAI_AUTH_STATE_LOGGED_IN_GRANT_ADMIN && (
	    a.top_schema_index == SAIM_WS_BROWSER_RX_TASKRESET ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_TASKREMOVEALLTRIES ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_EVENTRESET ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_EVENTDELETE ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_TASKCANCEL ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_REBUILD ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_PLATRESET ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_STAY ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_PCON_CONTROL ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_BUILDERDELETE ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_OPENSHELL ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_CLOSESHELL ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_PTYDATA ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_CLONEINFO ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_TASKCLONE ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_FINDINGS ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_FINDINGGET ||
	    a.top_schema_index == SAIM_WS_BROWSER_RX_FINDINGSET)) {
		uint8_t unauth_buf[LWS_PRE + 128];
		int n1 = lws_snprintf((char *)unauth_buf + LWS_PRE, sizeof(unauth_buf) - LWS_PRE,
				     "{\"schema\":\"com.warmcat.sai.unauthorized\"}");
		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, unauth_buf + LWS_PRE, (size_t)n1, LWS_WRITE_TEXT);
		lwsl_notice("%s: Unauthorized attempt to execute administrative action (schema %d, auth_state %d)\n", __func__, a.top_schema_index, (int)pss->auth_state);
		goto soft_error;
	}

	/*
	 * Nobody, admin or not, can act on projects this vhost doesn't show:
	 * for it, they don't exist.  Drop it, the UI never sends these.
	 */
	if (!saiw_rx_visible(vhd, a.top_schema_index, a.dest)) {
		lwsl_notice("%s: dropping schema %d for a project not shown "
			    "on this vhost\n", __func__, a.top_schema_index);
		goto ok;
	}

	switch (a.top_schema_index) {

	case SAIM_WS_BROWSER_RX_BUILDER_VISIBILITY:
		{
			sai_browse_rx_builder_visibility_t *v = (sai_browse_rx_builder_visibility_t *)a.dest;
			pss->wants_builder_info = v->visible;
			if (v->visible) {
				saiw_browser_broadcast_queue_builders(pss->vhd, pss);
				saiw_browser_broadcast_queue_pcons(pss->vhd, pss);
				saiw_browser_broadcast_queue_power_history(pss->vhd, pss);
			}
		}
		goto ok;

	case SAIM_WS_BROWSER_RX_TASKINFO:
		ti = (sai_browse_rx_taskinfo_t *)a.dest;

		lwsl_info("%s: schema index %d, task hash %s\n", __func__,
				a.top_schema_index, ti->task_hash);

		if (!ti->task_hash[0]) {
			/*
			 * he's asking for the overview schema
			 */
			// lwsl_warn("%s: SAIM_WS_BROWSER_RX_TASKINFO: doing WSS_PREPARE_BUILDER_SUMMARY\n", __func__);

			if (ti->js_api_version)
				pss->js_api_version = ti->js_api_version;
			pss->overview_offset = ti->offset;

			/*
			 * Update the runtime sidebar selection so subsequent
			 * overview / live pushes are scoped to this project +
			 * branch.  An empty value means "no constraint".
			 */
			lws_strncpy(pss->selected_project, ti->project,
				    sizeof(pss->selected_project));
			lws_strncpy(pss->selected_ref, ti->ref,
				    sizeof(pss->selected_ref));

			saiw_browser_broadcast_queue_builders(pss->vhd, pss);
 
			{
				uint8_t buf[LWS_PRE + 4096], *start = buf + LWS_PRE, *p = start, *end = buf + sizeof(buf);
				
				p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), 
					"{\"schema\":\"com.warmcat.sai.watcher_services\",\"watchers\":[]}");
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);
			}

			{
				uint8_t buf[LWS_PRE + 256], *start = buf + LWS_PRE, *p = start, *end = buf + sizeof(buf);
				
				p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), 
					"{\"schema\":\"com.warmcat.sai.auth_state\",\"auth_state\":%d}", (int)pss->auth_state);
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);
			}
 
			saiw_browser_queue_overview(pss->vhd, pss);
			break;
		}

		/*
		 * get the related task object into its own ac... there might
		 * be a lot of related data, so we hold the ac in the pss for
		 * as long as needed to send it out
		 */

		if (ti->logs) {
			pss->initial_log_timestamp = ti->last_log_ts;
			pss->initial_log_uid = ti->last_log_uid;
		} else {
			pss->initial_log_timestamp = 0;
			pss->initial_log_uid = 0;
		}

		if (saiw_pss_schedule_taskinfo(pss, ti->task_hash, !!ti->logs, ti->run))
			goto soft_error;

		goto ok;

	case SAIM_WS_BROWSER_RX_EVENTINFO:

		ei = (sai_browse_rx_evinfo_t *)a.dest;

		lws_strncpy(pss->selected_event_uuid, ei->event_hash, sizeof(pss->selected_event_uuid));

		if (saiw_pss_schedule_eventinfo(pss, ei->event_hash))
			goto soft_error;

		goto ok;

	case SAIM_WS_BROWSER_RX_PROJLIST:
	{
		/*
		 * Return the set of unique project (repo_name) values seen
		 * in the events db, ordered by name.  Read-only.
		 */
		sqlite3_stmt *stmt = NULL;
		uint8_t buf[LWS_PRE + 4096], *start = buf + LWS_PRE,
			*p = start, *end = buf + sizeof(buf);
		char esc[96], q[256];
		/* first_elem = first array entry (omit leading comma);
		 * sent_any   = have we already tx'd a ws fragment of this msg */
		int first_elem = 1, sent_any = 0, rc;

		lws_snprintf(q, sizeof(q),
				"SELECT repo_name, MAX(created) AS mc FROM events "
				"WHERE state != ?%s GROUP BY repo_name "
				"ORDER BY mc DESC", saiw_visible_sql(vhd));

		if (sqlite3_prepare_v2(vhd->pdb, q, -1, &stmt, NULL) !=
								SQLITE_OK) {
			lwsl_notice("%s: projlist prepare failed\n", __func__);
			goto soft_error;
		}
		sqlite3_bind_int(stmt, 1, SAIES_DELETED);

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "{\"schema\":\"com.warmcat.sai.projlist\","
				  "\"projects\":[");
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			const char *pn = (const char *)
					sqlite3_column_text(stmt, 0);
			if (!pn)
				continue;
			if (lws_ptr_diff_size_t(end, p) < 96) {
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss,
					start, lws_ptr_diff_size_t(p, start),
					lws_write_ws_flags(LWS_WRITE_TEXT,
							   !sent_any, 0));
				sent_any = 1;
				p = start;
			}
			p += lws_snprintf((char *)p,
				lws_ptr_diff_size_t(end, p), "%s\"%s\"",
				first_elem ? "" : ",",
				lws_json_purify(esc, pn, sizeof(esc) - 1, NULL));
			first_elem = 0;
		}
		sqlite3_finalize(stmt);

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "]}");
		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
				lws_ptr_diff_size_t(p, start),
				LWS_WRITE_TEXT);
		goto ok;
	}

	case SAIM_WS_BROWSER_RX_BRANCHLIST:
	{
		/*
		 * Return the set of unique refs for the given project, in
		 * most-recent-first order (the ref whose latest event is the
		 * newest comes first).  A parallel "branch_states" object maps
		 * each ref to the state of its latest non-deleted event, so the
		 * browser can colour the branch list rows by build result.
		 * Read-only.  project and the state filters are bound, not
		 * interpolated.
		 *
		 * We run the grouped query once into an lwsac snapshot, then
		 * emit both the "branches" array and the "branch_states" object
		 * from that single consistent result.  The correlated subquery
		 * resolves the state of the newest non-deleted event for the
		 * group's ref within the same project.  Bind order follows
		 * parameter appearance: project, SAIES_DELETED (subquery),
		 * then SAIES_DELETED, project (outer).
		 */
		sai_browse_rx_branchlist_t *bl =
				(sai_browse_rx_branchlist_t *)a.dest;
		struct bl_row {
			struct lws_dll2	list;
			char		*ref;
			int		state;
		};
		struct lwsac *ac = NULL;
		lws_dll2_owner_t owner;
		sqlite3_stmt *stmt = NULL;
		uint8_t buf[LWS_PRE + 4096], *start = buf + LWS_PRE,
			*p = start, *end = buf + sizeof(buf);
		char esc[96], pesc[96], q[512];
		int first_elem = 1, sent_any = 0, rc;

		lws_dll2_owner_clear(&owner);

		/*
		 * Belt-and-braces: also purify (the bound param already
		 * prevents injection, but this keeps the echoed project
		 * field safe to emit too).
		 */
		lws_sql_purify(pesc, bl->project, sizeof(pesc) - 1);

		/*
		 * A project this vhost doesn't show has no branches; the
		 * subquery only looks at the project the outer one found.
		 */
		lws_snprintf(q, sizeof(q),
				"SELECT ref, "
				"(SELECT e2.state FROM events e2 "
				" WHERE e2.ref = events.ref "
				" AND e2.repo_name = ? AND e2.state != ? "
				" ORDER BY e2.created DESC LIMIT 1) AS ls "
				"FROM events "
				"WHERE state != ? AND repo_name = ?%s "
				"GROUP BY ref ORDER BY MAX(created) DESC",
				saiw_visible_sql(vhd));

		if (sqlite3_prepare_v2(vhd->pdb, q, -1, &stmt, NULL) !=
								SQLITE_OK) {
			lwsl_notice("%s: branchlist prepare failed\n",
					__func__);
			goto soft_error;
		}
		sqlite3_bind_text(stmt, 1, pesc, -1, SQLITE_STATIC);
		sqlite3_bind_int(stmt, 2, SAIES_DELETED);
		sqlite3_bind_int(stmt, 3, SAIES_DELETED);
		sqlite3_bind_text(stmt, 4, pesc, -1, SQLITE_STATIC);

		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			struct bl_row *row;
			const char *rn = (const char *)
					sqlite3_column_text(stmt, 0);
			size_t rn_len;
			if (!rn)
				continue;
			rn_len = strlen(rn);
			row = lwsac_use_zero(&ac, sizeof(*row), 0);
			if (!row) {
				sqlite3_finalize(stmt);
				lwsac_free(&ac);
				goto soft_error;
			}
			row->ref = lwsac_use(&ac, rn_len + 1, 0);
			if (!row->ref) {
				sqlite3_finalize(stmt);
				lwsac_free(&ac);
				goto soft_error;
			}
			memcpy(row->ref, rn, rn_len + 1);
			row->state = sqlite3_column_int(stmt, 1);
			lws_dll2_add_tail(&row->list, &owner);
		}
		sqlite3_finalize(stmt);

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "{\"schema\":\"com.warmcat.sai.branchlist\","
				  "\"project\":\"%s\",\"branches\":[",
				  lws_json_purify(esc, pesc,
						  sizeof(esc) - 1, NULL));
		first_elem = 1;
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   owner.head) {
			struct bl_row *row = lws_container_of(d,
						struct bl_row, list);
			if (lws_ptr_diff_size_t(end, p) < 96) {
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss,
					start, lws_ptr_diff_size_t(p, start),
					lws_write_ws_flags(LWS_WRITE_TEXT,
							   !sent_any, 0));
				sent_any = 1;
				p = start;
			}
			p += lws_snprintf((char *)p,
				lws_ptr_diff_size_t(end, p), "%s\"%s\"",
				first_elem ? "" : ",",
				lws_json_purify(esc, row->ref,
						sizeof(esc) - 1, NULL));
			first_elem = 0;
		} lws_end_foreach_dll_safe(d, d1);

		/*
		 * Parallel ref -> latest-state map.  Kept as a separate object
		 * so the existing "branches" string array stays unchanged for
		 * older clients that ignore the extra field.
		 */
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "],\"branch_states\":{");
		first_elem = 1;
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   owner.head) {
			struct bl_row *row = lws_container_of(d,
						struct bl_row, list);
			if (lws_ptr_diff_size_t(end, p) < 96) {
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss,
					start, lws_ptr_diff_size_t(p, start),
					lws_write_ws_flags(LWS_WRITE_TEXT,
							   !sent_any, 0));
				sent_any = 1;
				p = start;
			}
			p += lws_snprintf((char *)p,
				lws_ptr_diff_size_t(end, p), "%s\"%s\":%d",
				first_elem ? "" : ",",
				lws_json_purify(esc, row->ref,
						sizeof(esc) - 1, NULL),
				row->state);
			first_elem = 0;
		} lws_end_foreach_dll_safe(d, d1);

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "}}");
		lwsac_free(&ac);

		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
				lws_ptr_diff_size_t(p, start),
				LWS_WRITE_TEXT);
		goto ok;
	}

	case SAIM_WS_BROWSER_RX_CLONEINFO:
		/*
		 * Admin wants to seed an ad-hoc build from this task; answer
		 * locally with what the dialog needs, nothing goes to the
		 * server until he submits the taskclone
		 */
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (!saiw_id_ok(ei->event_hash, 64)) {
			lwsl_notice("%s: bad cloneinfo uuid\n", __func__);
			goto soft_error;
		}
		saiw_browser_send_cloneinfo(vhd, pss, ei->event_hash);
		goto ok;

	case SAIM_WS_BROWSER_RX_FINDINGS:
		saiw_browser_send_findings(vhd, pss);
		goto ok;

	case SAIM_WS_BROWSER_RX_FINDINGGET:
		saiw_browser_send_finding(vhd, pss,
					  (sai_findingset_t *)a.dest);
		goto ok;

	case SAIM_WS_BROWSER_RX_FINDINGSET:
	{
		sai_findingset_t *fs = (sai_findingset_t *)a.dest;

		/* sai-server checks these again */
		if (!sai_pool_name_ok(fs->pool) || strlen(fs->group) != 16 ||
		    !sai_is_git_hash(fs->group) ||
		    sai_str_has_shell_metachars(fs->repo)) {
			lwsl_notice("%s: dropping malformed findingset\n",
				    __func__);
			goto soft_error;
		}
		break; /* forward it to sai-server with the rest */
	}

	case SAIM_WS_BROWSER_RX_TASKCLONE:
	{
		sai_browse_rx_taskclone_t *tc =
				(sai_browse_rx_taskclone_t *)a.dest;

		/*
		 * Sanity-check before forwarding; sai-server validates again
		 * and resolves the ref to a hash itself.  A string that fills
		 * its array exactly was truncated by lws_struct on the way in
		 * and can't be what the user meant.
		 */
		if (!saiw_id_ok(tc->seed_uuid, 64) ||
		    strncmp(tc->ref, "refs/", 5) || !sai_is_safe_ref(tc->ref) ||
		    strlen(tc->ref) >= sizeof(tc->ref) - 1 ||
		    !tc->build[0] ||
		    strlen(tc->build) >= sizeof(tc->build) - 1) {
			lwsl_notice("%s: dropping malformed taskclone\n",
				    __func__);
			goto soft_error;
		}

		lwsl_notice("%s: forwarding taskclone: seed %s, ref %s\n",
			    __func__, tc->seed_uuid, tc->ref);
		break; /* forward it to sai-server with the rest */
	}

	case SAIM_WS_BROWSER_RX_TASKREMOVEALLTRIES:
	case SAIM_WS_BROWSER_RX_TASKRESET:

		/*
		 * User is asking us to reset / rebuild this task
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;
		break;

	case SAIM_WS_BROWSER_RX_STAY:
		lwsl_notice("%s: web: received stay req\n", __func__);

		/*
		 * User is asking us to set or release a stay on a builder
		 */
		break;

	case SAIM_WS_BROWSER_RX_PCON_CONTROL:
		lwsl_warn("%s: web: received pcon control req (len %d)\n", __func__, (int)bl);

		/* Forward to sai-server via websrv link */
		if (sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(vhd->h_ss_websrv,
			&((saiw_websrv_t *)lws_ss_to_user_object(vhd->h_ss_websrv))->wbltx,
			buf, bl, ss_flags))
			lwsl_err("%s: failed to queue pcon control to server\n", __func__);
		else
			lwsl_warn("%s: queued pcon control to server OK\n", __func__);

		goto ok;

	case SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP:

		/*
		 * User is asking us to rebuild the last step of this task
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;
		break;

	case SAIM_WS_BROWSER_RX_EVENTRESET:

		/*
		 * User is asking us to reset / rebuild every task in the event
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;

		lwsl_notice("%s: received request to reset event %s\n",
			    __func__, ei->event_hash);
		break;

	case SAIM_WS_BROWSER_RX_EVENTDELETE:
		/*
		 * User is asking us to delete the whole event
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;

		lwsl_notice("%s: received request to delete event %s\n",
			    __func__, ei->event_hash);

		break;

	case SAIM_WS_BROWSER_RX_TASKCANCEL:

		/*
		 * Browser is informing us of task's STOP button clicked, we
		 * need to inform any builder that might be building it
		 */
		can = (sai_cancel_t *)a.dest;

		lwsl_notice("%s: received request to cancel task %s\n",
			    __func__, can->task_uuid);
		break; /* forward it to sai-server with the rest */

	case SAIM_WS_BROWSER_RX_REBUILD:
		/*
		 * User is asking us to rebuild a builder
		 */
		break;

	case SAIM_WS_BROWSER_RX_PLATRESET:
		/*
		 * User is asking us to reset / rebuild a whole platform
		 */
		break;

	case SAIM_WS_BROWSER_RX_BUILDERDELETE:
		/*
		 * User is asking us to delete a builder
		 */
		break;

	case SAIM_WS_BROWSER_RX_OPENSHELL:
		/*
		 * This browser opened a shell; only it will be sent the
		 * shell's ptydata.  The forward to sai-server happens with
		 * the rest below.
		 */
		saiw_pss_shell_open(pss,
			    ((sai_openshell_t *)a.dest)->task_uuid);
		break;

	case SAIM_WS_BROWSER_RX_CLOSESHELL:
		saiw_pss_shell_close(pss,
			    ((sai_closeshell_t *)a.dest)->task_uuid);
		break;

	case SAIM_WS_BROWSER_RX_PTYDATA:
		break;

	/*
	 * Load reports flow builder -> server -> us -> browsers; a browser
	 * sending one is meaningless.  Drop it locally rather than forward
	 * it, sai-server does not accept this schema on the web link and
	 * would tear the link down trying to decode it.
	 */
	case SAIM_WS_BROWSER_RX_LOADREPORT:
		lwsl_notice("%s: dropping loadreport from browser\n", __func__);
		goto ok;

	/*
	 * Watcher services are a server config-file concern; the schema only
	 * ever flows from us towards browsers.  A browser sending one is
	 * meaningless: drop it locally rather than forward it, sai-server
	 * does not accept this schema on the web link.
	 */
	case SAIM_WS_BROWSER_RX_WATCHER_SERVICES:
		lwsl_notice("%s: dropping watcher_services from browser\n",
				__func__);
		goto ok;

	default:
		/*
		 * No schema in the map today reaches here.  If one is added
		 * to the map without a case above, log and drop it rather
		 * than assert (remote-crashable) or forward an unknown
		 * schema on the server link.
		 */
		lwsl_notice("%s: unhandled schema index %d from browser, dropping\n",
				__func__, a.top_schema_index);
		goto ok;
	}

	sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(vhd->h_ss_websrv,
		&((saiw_websrv_t *)lws_ss_to_user_object(vhd->h_ss_websrv))->wbltx,
		buf, bl, ss_flags);

ok:
	ret = 0;

soft_error:
bail:
	lwsac_free(&a.ac);

	return ret;
}

static void
saiw_retry_logs(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul_logcache);

	saiw_broadcast_logs_batch(pss->vhd, pss);
}

/*
 * Tell a browser to throw away the log lines it is showing for the task it is
 * subscribed to, and start again from the first row.
 *
 * The task's logs can go away underneath a browser that is looking at them:
 * "remove all tries" deletes them outright, and a builder disconnecting or a
 * rebuild starts a new run.  Without this the pane keeps showing lines that no
 * longer exist, and for a fresh run appends the new ones underneath the old.
 */

static void
saiw_browser_logs_reset(struct pss *pss)
{
	uint8_t buf[LWS_PRE + 192], *start = buf + LWS_PRE;
	char esc[132];
	int n;

	pss->sub_uid		= 0;
	pss->sub_timestamp	= 0;

	n = lws_snprintf((char *)start, sizeof(buf) - LWS_PRE,
			 "{\"schema\":\"com.warmcat.sai.logs_reset\","
			  "\"task_hash\":\"%s\",\"run\":%d}",
			 lws_json_purify(esc, pss->sub_task_uuid,
					 sizeof(esc) - 1, NULL), pss->sub_run);

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start, (size_t)n,
					       LWS_WRITE_TEXT);
}

/*
 * The cursor can never legitimately be ahead of the newest row that exists, so
 * if it is, the rows it was counting have been deleted (or we have moved to a
 * run that has not produced any yet) and the browser has to start over.
 */

static int
saiw_browser_logs_cursor_stale(struct vhd *vhd, struct pss *pss)
{
	char event_uuid[33], q[256], pesc[132];
	uint64_t max_uid = 0;
	sqlite3 *pdb = NULL;

	if (!pss->sub_uid || !pss->sub_task_uuid[0])
		return 0;

	sai_task_uuid_to_event_uuid(event_uuid, pss->sub_task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		/* the event is gone, which the log query itself will report */
		return 0;

	lws_sql_purify(pesc, pss->sub_task_uuid, sizeof(pesc));
	lws_snprintf(q, sizeof(q),
		     "select coalesce(max(uid), 0) from logs where "
		     "task_uuid='%s' and run=%d", pesc, pss->sub_run);

	if (sqlite3_exec(pdb, q, sai_sql3_get_uint64_cb, &max_uid, NULL) !=
								SQLITE_OK)
		max_uid = pss->sub_uid; /* don't guess on a query failure */

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	return max_uid < pss->sub_uid;
}

static void
saiw_retry_overview(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul_overview);

	saiw_browser_queue_overview(pss->vhd, pss);
}

int
saiw_broadcast_logs_batch(struct vhd *vhd, struct pss *pss)
{
	char event_uuid[33];

	if (!pss->subs_list.owner)
		return 0;

	if (lws_buflist2_total_len(&pss->raw_tx) > SAIW_BROWSER_TX_DEFER) {
		lws_sul_schedule(vhd->context, 0, &pss->sul_logcache,
				 saiw_retry_logs, 250 * LWS_US_PER_MS);
		return 0;
	}

	/*
	 * For efficiency, let's try to grab the next 100 at
	 * once from sqlite and work our way through sending
	 * them
	 */

	//if (pss->log_cache_index == pss->log_cache_size)
	{
		sqlite3 *pdb = NULL;
		char esc[256], pesc[132];
		int sr;

		sai_task_uuid_to_event_uuid(event_uuid, pss->sub_task_uuid);

		lwsac_free(&pss->logs_ac);

		/* uuid is db-derived, purify keeps the literal safe anyway */
		lws_sql_purify(pesc, pss->sub_task_uuid, sizeof(pesc));

		/*
		 * Page on uid, the logs table's autoincrement primary key, not
		 * on timestamp: the timestamps are the builder's
		 * CLOCK_MONOTONIC, so they restart from near zero whenever a
		 * builder VM reboots, and rows issued below the cursor are
		 * never delivered.  uid only ever increases, and the rows come
		 * back in uid order anyway.
		 */

		lws_snprintf(esc, sizeof(esc),
		     "and task_uuid='%s' and run=%d and uid > %llu",
		     pesc, pss->sub_run,
		     (unsigned long long)pss->sub_uid);

		// lwsl_notice("%s: collecting logs %s\n", __func__, esc);

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					     vhd->sqlite3_path_lhs, event_uuid,
					     0, &pdb)) {
			uint8_t buf[LWS_PRE + 128];
			int n1;
			lwsl_notice("%s: unable to open event-specific database\n",
					__func__);

			n1 = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE,
				     "{\"schema\":\"com.warmcat.sai.event_deleted\"}");
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, buf + LWS_PRE, (size_t)n1,
						       LWS_WRITE_TEXT);

			return 0;
		}

		sr = lws_struct_sq3_deserialize(pdb, esc,
						"uid ",
						lsm_schema_sq3_map_log,
						&pss->logs_owner,
						&pss->logs_ac, 0, 50);

		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		if (sr) {

			lwsl_err("%s: subs failed\n", __func__);

			return 0;
		}

		pss->log_cache_index = 0;
		pss->log_cache_size = (int)pss->logs_owner.count;
	}

	while (pss->log_cache_index++ < pss->log_cache_size) {
		sai_log_t *log = lws_container_of(pss->logs_owner.head,
						  sai_log_t, list);
		lws_struct_serialize_t *js;
		char buf[1200 + LWS_PRE];
		char fi = 1;
		int n;

		lws_dll2_remove(&log->list);

		/*
		 * Turn it back into JSON so we can give it to
		 * the browser
		 */

		js = lws_struct_json_serialize_create(lsm_schema_json_map_log,
						      1, 0, log);
		if (!js) {
			lwsl_notice("%s: json ser fail\n", __func__);
			return 0;
		}

		do {
			size_t w;
			n = lws_struct_json_serialize(js, (uint8_t *)buf + LWS_PRE,
						      sizeof(buf) - LWS_PRE, &w);

			if (n != LSJS_RESULT_CONTINUE)
				lws_struct_json_serialize_destroy(&js);
			if (n == LSJS_RESULT_ERROR)
				return 1;

			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, buf + LWS_PRE, w,
					lws_write_ws_flags(LWS_WRITE_TEXT,
						fi, n == LSJS_RESULT_FINISH));

			fi = 0;
			pss->sub_timestamp = log->timestamp;
			pss->sub_uid = (uint64_t)log->uid;
		} while (n != LSJS_RESULT_FINISH);
	}

	lwsac_free(&pss->logs_ac);

	lws_sul_schedule(vhd->context, 0, &pss->sul_logcache,
			 saiw_retry_logs,
			 pss->log_cache_size == 50 ? 500 : 250 * LWS_US_PER_MS);

	return 0;
}

/*
 * For sidebar-scoped overviews we don't ship the full per-event task array
 * (it can be hundreds of tasks per event and blow the 2MiB buflist sanity
 * limit when many events match).  Instead we compute a short summary string
 * server-side, matching the format the browser's summarize_build_situation()
 * produces ("All N passed", "OK: g, Bad: b, Building: o, Wait: p", ...).
 *
 * The task state values are the SAIES_* enum, bucketed the same way as the
 * browser: 0 -> pending, {1,2,6} -> ongoing, 3 -> good, {4,5} -> bad.
 *
 * The rss feed reports the same counts, see w-rss.c.
 */
void
saiw_event_summary_string(sqlite3 *pdb_event, const char *event_uuid,
			  char *out, size_t out_len,
			  unsigned int *p_good, unsigned int *p_bad,
			  unsigned int *p_ongoing, unsigned int *p_pending,
			  unsigned int *p_total)
{
	sqlite3_stmt *stmt = NULL;
	unsigned int good = 0, bad = 0, ongoing = 0, pending = 0, total = 0;
	char q[160];
	int rc;

	if (p_good)    *p_good = 0;
	if (p_bad)     *p_bad = 0;
	if (p_ongoing) *p_ongoing = 0;
	if (p_pending) *p_pending = 0;
	if (p_total)   *p_total = 0;

	if (!pdb_event || !event_uuid || !out || out_len < 16)
		goto empty;

	/*
	 * tasks holds one row per (task, run); the browser summarises on the
	 * latest (max) run per task uuid.  Pick exactly that row per uuid using
	 * a correlated max-run subquery, so we count each task once.
	 *
	 * Idle tasks don't count, they're not part of the event's result.
	 */
	lws_snprintf(q, sizeof(q),
			"SELECT state FROM tasks t WHERE idle=0 AND rowid = ("
			"SELECT rowid FROM tasks t2 WHERE t2.uuid = t.uuid "
			"ORDER BY t2.run DESC LIMIT 1)");

	if (sqlite3_prepare_v2(pdb_event, q, -1, &stmt, NULL) != SQLITE_OK)
		goto empty;

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		int s = sqlite3_column_int(stmt, 0);
		total++;
		switch (s) {
		case 0:  pending++;  break;
		case 1:
		case 2:
		case 6:  ongoing++; break;
		case 3:  good++;    break;
		case 4:
		case 5:  bad++;     break;
		default: break;
		}
	}
	sqlite3_finalize(stmt);

	if (p_good)    *p_good = good;
	if (p_bad)     *p_bad = bad;
	if (p_ongoing) *p_ongoing = ongoing;
	if (p_pending) *p_pending = pending;
	if (p_total)   *p_total = total;

	if (!total)
		goto empty;

	if (good == total)
		lws_snprintf(out, out_len, "All %u passed", good);
	else if (bad == total)
		lws_snprintf(out, out_len, "All %u failed", bad);
	else if (pending == total)
		lws_snprintf(out, out_len, "%u pending", total);
	else {
		char *o = out;
		size_t l = out_len, n;
		int first = 1;
#define EMIT(fmt, ...) do { \
		n = (size_t)lws_snprintf(o, l, "%s" fmt, first ? "" : ", ", ##__VA_ARGS__); \
		if (n >= l) { o = out + out_len - 1; break; } o += n; l -= n; first = 0; \
	} while (0)
		if (good)    EMIT("OK: %u", good);
		if (bad)     EMIT("Bad: %u", bad);
		if (ongoing) EMIT("Building: %u", ongoing);
		if (pending) EMIT("Wait: %u", pending);
#undef EMIT
	}
	return;

empty:
	if (out && out_len)
		out[0] = '\0';
}

int
saiw_browser_queue_overview(struct vhd *vhd, struct pss *pss)
{
	char buf[4096 + LWS_PRE], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf);
	char esc[256], filt[448], subsequent;
	struct lwsac *task_ac = NULL, *ac = NULL;
	lws_dll2_owner_t task_owner, owner;
	unsigned int task_index = 0;
	lws_struct_serialize_t *js;
	sqlite3 *pdb = NULL;
	lws_dll2_t *walk;
	sai_task_t *t;
	int n;
	size_t w;

	if (lws_buflist2_total_len(&pss->raw_tx) > SAIW_BROWSER_TX_DEFER) {
		/*
		 * Our own tx towards this browser is backed-up (he is not
		 * draining, or a previous overview is still in flight).  The
		 * overview can be megabytes on a populated db, so composing
		 * another one now would just pile it onto the backlog; come
		 * back from a timer when it has drained.
		 */
		lws_sul_schedule(vhd->context, 0, &pss->sul_overview,
				 saiw_retry_overview, 250 * LWS_US_PER_MS);

		return 0;
	}

	filt[0] = '\0';
	esc[0] = '\0';
	n = -6;

	if (pss->specific_task[0] && !pss->resolved_task_offset) {
		char event_uuid[33];
		char q[256];
		sqlite3_stmt *stmt = NULL;
		uint64_t ev_created = 0;

		sai_task_uuid_to_event_uuid(event_uuid, pss->specific_task);
		lws_snprintf(q, sizeof(q), "SELECT created FROM events WHERE uuid='%s'", event_uuid);
		if (sqlite3_prepare_v2(vhd->pdb, q, -1, &stmt, NULL) == SQLITE_OK) {
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				ev_created = (uint64_t)sqlite3_column_int64(stmt, 0);
			}
			sqlite3_finalize(stmt);
		}
		if (ev_created > 0) {
			unsigned int events_newer = 0;
			lws_snprintf(q, sizeof(q), "SELECT COUNT(*) FROM events WHERE state != %d AND created > %llu%s", SAIES_DELETED, (unsigned long long)ev_created, saiw_visible_sql(vhd));
			if (sqlite3_prepare_v2(vhd->pdb, q, -1, &stmt, NULL) == SQLITE_OK) {
				if (sqlite3_step(stmt) == SQLITE_ROW) {
					events_newer = (unsigned int)sqlite3_column_int(stmt, 0);
				}
				sqlite3_finalize(stmt);
			}
			pss->overview_offset = (events_newer / 6) * 6;
		}
		pss->resolved_task_offset = 1;
	}

	/*
	 * The vhost may only show some projects: that clause goes right after
	 * the first one, so if anything is going to be truncated off the end
	 * of filt, it isn't that.
	 */

	if (pss->specific_project[0]) {
		/*
		 * gitohashi /git/<project> URL-locked mode: lock to that one
		 * project, no row cap.
		 */
		lws_sql_purify(esc, pss->specific_project, sizeof(esc) - 1);
		lws_snprintf(filt, sizeof(filt),
			 " and state != %d%s and repo_name='%s'",
			 SAIES_DELETED, saiw_visible_sql(vhd), esc);
		n = -1;
	} else {
		size_t fl;

		/*
		 * Base filter: hide deleted events.  We keep appending extra
		 * " and ..." clauses here; the COUNT query below skips the
		 * leading " and " with filt + 5 and uses the rest verbatim.
		 */
		lws_snprintf(filt, sizeof(filt), " and state != %d%s",
			 SAIES_DELETED, saiw_visible_sql(vhd));

		/*
		 * A specific event selection (com.warmcat.sai.eventinfo from
		 * the browser clicking an event) takes precedence: scope to
		 * just that one event uuid.  Full task data is emitted for it
		 * (the summary-only path below is skipped in this case).
		 */
		if (pss->event_tasks_uuid[0]) {
			fl = strlen(filt);
			lws_sql_purify(esc, pss->event_tasks_uuid,
				       sizeof(esc) - 1);
			lws_snprintf(filt + fl, sizeof(filt) - fl,
				     " and uuid='%s'", esc);
			n = -1;
		}

		/*
		 * Sidebar runtime selection: scope to the browser's currently
		 * selected project and (if set) branch, capping at the newest
		 * 100 matching events.
		 */
		if (!pss->event_tasks_uuid[0] && pss->selected_project[0]) {
			fl = strlen(filt);
			lws_sql_purify(esc, pss->selected_project,
				       sizeof(esc) - 1);
			lws_snprintf(filt + fl, sizeof(filt) - fl,
					     " and repo_name='%s'", esc);
			n = -100;
		}

		if (!pss->event_tasks_uuid[0] && pss->selected_ref[0]) {
			fl = strlen(filt);
			lws_sql_purify(esc, pss->selected_ref,
				       sizeof(esc) - 1);
			lws_snprintf(filt + fl, sizeof(filt) - fl,
					     " and ref='%s'", esc);
			if (n == -6)
				n = -100;
		}
	}

	unsigned int total_events = 0;
	{
		char q[64 + sizeof(filt)];
		sqlite3_stmt *stmt;
		lws_snprintf(q, sizeof(q), "SELECT COUNT(*) FROM events WHERE %s", filt + 5);
		if (sqlite3_prepare_v2(vhd->pdb, q, -1, &stmt, NULL) == SQLITE_OK) {
			if (sqlite3_step(stmt) == SQLITE_ROW)
				total_events = (unsigned int)sqlite3_column_int(stmt, 0);
			sqlite3_finalize(stmt);
		}
	}

	pss->wants_event_updates = 1;
	if (lws_struct_sq3_deserialize(vhd->pdb, filt[0] ? filt : NULL,
				       "created ", lsm_schema_sq3_map_event,
				       &owner, &ac, (int)pss->overview_offset, n)) {
		lwsl_notice("%s: OVERVIEW 2 failed\n", __func__);

		return 0;
	}

	/*
	 * we get zero or more sai_event_t laid out in pss->query_ac,
	 * and listed in pss->query_owner
	 */

	p += (size_t)lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
		"{\"schema\":\"sai.warmcat.com.overview\","
		" \"api_version\":%u,"
		" \"alang\":\"%s\","
		" \"total_events\":%u,"
		" \"offset\":%u,"
		"\"overview\":[", SAIW_API_VERSION,
		lws_json_purify(esc, pss->alang, sizeof(esc) - 1, NULL),
		total_events, pss->overview_offset
	);

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, 1, 0));
	p = start;


	/*
	 * Walk through events
	 */

	if (pss->specificity && pss->specificity != SAIM_SPECIFIC_TASK)
		walk = lws_dll2_get_head(&owner);
	else
		walk = lws_dll2_get_tail(&owner);

	subsequent = 0;

	if (!owner.count) /* nothing to do */
		goto so_finish;

	while (walk) {
		sai_event_t *e = lws_container_of(walk, sai_event_t, list);

		if (pss->specificity && pss->specificity != SAIM_SPECIFIC_TASK) {
			if (!strcmp(pss->specific_ref, "refs/heads/master") &&
			    !strcmp(e->ref, "refs/heads/main"))
				; // any = 1;
			else {
				if (strcmp(e->hash, pss->specific_ref) &&
				    strcmp(e->ref, pss->specific_ref)) {
					walk = walk->next;
					continue;
				}
				// any = 1;
			}
		}

		{
			char wfilt[128], wesc[70];
			struct lwsac *ac_watchers = NULL;
			lws_dll2_owner_clear(&e->watcher_owner);
			/* uuid is db-derived, purify keeps the literal safe anyway */
			lws_sql_purify(wesc, e->uuid, sizeof(wesc));
			lws_snprintf(wfilt, sizeof(wfilt), " and event_hash='%s'", wesc);
			if (lws_struct_sq3_deserialize(vhd->pdb, wfilt, "created",
						   lsm_schema_sq3_map_watcher, &e->watcher_owner, &ac_watchers, 0, 0) < 0)
				lwsl_err("%s: watchers deserialize failed\n", __func__);

		js = lws_struct_json_serialize_create(
			lsm_schema_json_map_event,
			LWS_ARRAY_SIZE(lsm_schema_json_map_event), 0, e);
		if (!js) {
			lwsl_err("%s: json ser fail\n", __func__);
			return 1;
		}
		if (lws_ptr_diff_size_t(end, p) < 128) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
							       lws_ptr_diff_size_t(p, start),
							       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
			p = start;
		}

		if (subsequent)
			*p++ = ',';
		subsequent = 1;

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "{\"e\":");


		do {
			n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
			switch (n) {
			case LSJS_RESULT_ERROR:
				lwsl_err("%s: json ser error\n", __func__);
				lws_struct_json_serialize_destroy(&js);
				return 1;

			case LSJS_RESULT_FINISH:
				lws_struct_json_serialize_destroy(&js);
				p += w;
				break;

			case LSJS_RESULT_CONTINUE:
				p += w;
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
								       lws_ptr_diff_size_t(p, start),
								       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
				p = start;
				break;
			}
		} while (n == LSJS_RESULT_CONTINUE);

		if (ac_watchers)
			lwsac_free(&ac_watchers);
		}

		if (lws_ptr_diff_size_t(end, p) < 128) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
							       lws_ptr_diff_size_t(p, start),
							       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
			p = start;
		}

		task_index = 0;

		/*
		 * For sidebar-scoped overviews (project / branch selected in
		 * the LHS pane), we don't ship the full per-event task array:
		 * it can be hundreds of tasks per event and overflow the 2MiB
		 * buflist when many events match.  The sidebar only needs the
		 * event metadata + a short summary string, so emit an empty
		 * "t":[] plus a server-computed "summary" the browser shows
		 * verbatim.  The full task list is fetched on demand when the
		 * user selects a specific event.
		 */
		if ((pss->selected_project[0] || pss->selected_ref[0]) &&
		    !pss->event_tasks_uuid[0]) {
			/*
			 * Sidebar-scoped path: emit a tiny per-event payload
			 * (empty task array + server-computed summary) instead
			 * of the full task list, so many events fit the buflist.
			 * We close the {"e":...} wrapper object here with '}'
			 * and skip the shared "]" below (which closes the task
			 * array opened by the unscoped path).
			 */
				char sum[96], esc_sum[128];
				unsigned int sg = 0, sb = 0, so = 0, sp = 0, st = 0;

				e = lws_container_of(walk, sai_event_t, list);
				sum[0] = '\0';
				if (!sai_event_db_ensure_open(vhd->context,
						&vhd->sqlite3_cache,
						vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {
					saiw_event_summary_string(pdb, e->uuid, sum,
								  sizeof(sum),
								  &sg, &sb, &so, &sp, &st);
					sai_event_db_close(&vhd->sqlite3_cache, &pdb);
				}

				if (lws_ptr_diff_size_t(end, p) < 160) {
					saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss,
						start, lws_ptr_diff_size_t(p, start),
						lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
					p = start;
				}
				p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
					", \"t\":[], \"summary\":\"%s\","
					"\"sum_counts\":{\"good\":%u,\"bad\":%u,"
					"\"ongoing\":%u,\"pending\":%u,\"total\":%u}}",
					lws_json_purify(esc_sum, sum, sizeof(esc_sum) - 1,
							NULL),
					sg, sb, so, sp, st);

			/* advance to the next event like the unscoped path */
			if (pss->specificity && pss->specificity != SAIM_SPECIFIC_TASK)
				walk = walk->next;
			else
				walk = walk->prev;

			if (walk && (!pss->specificity ||
				     pss->specificity == SAIM_SPECIFIC_TASK))
				continue;
			goto so_finish;
		} else {
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), ", \"t\":[");


		/*
		 * Enumerate the tasks associated with this event...
		 */

		e = lws_container_of(walk, sai_event_t, list);
		lws_dll2_owner_clear(&task_owner);

		task_index = 0;

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {
			lwsl_err("%s: unable to open event-specific database\n",
					__func__);
		} else {
			task_ac = NULL;
			lws_dll2_owner_clear(&task_owner);
			if (lws_struct_sq3_deserialize(pdb, NULL, "taskname, platform",
					lsm_schema_sq3_map_task, &task_owner,
					&task_ac, 0, 999)) {
				lwsl_err("%s: OVERVIEW 1 failed\n", __func__);
			} else {
				lws_start_foreach_dll(struct lws_dll2 *, pt, task_owner.head) {
					t = lws_container_of(pt, sai_task_t, list);

					if (lws_ptr_diff_size_t(end, p) < 128) {
						saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
										       lws_ptr_diff_size_t(p, start),
										       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
						p = start;
					}

					if (task_index)
						*p++ = ',';

					/*
					 * We don't want to send everyone the artifact nonces...
					 * the up nonce is a key for uploading artifacts on to
					 * this task, it should only be stored in the server db
					 * and sent to the builder to use.
					 *
					 * The down nonce is used in generated links, but still
					 * you should have to acquire such a link via whatever
					 * auth rather than be able to cook them up yourself
					 * from knowing the task uuid.
					 */

					t->art_up_nonce[0] = '\0';
					t->art_down_nonce[0] = '\0';

					t->rebuildable = (t->state == SAIES_FAIL || t->state == SAIES_CANCELLED) &&
						(lws_now_secs() - (t->started + t->duration / 1000000) < 24 * 3600);

					js = lws_struct_json_serialize_create(
						lsm_schema_json_map_task,
						LWS_ARRAY_SIZE(lsm_schema_json_map_task), 0, t);

					t->build[0] = '\0';

					do {
						n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
						switch (n) {
						case LSJS_RESULT_ERROR:
							lwsl_err("%s: json ser error for task\n", __func__);
							lws_struct_json_serialize_destroy(&js);
							return 1;

						case LSJS_RESULT_FINISH:
							lws_struct_json_serialize_destroy(&js);
							p += w;
							break;

						case LSJS_RESULT_CONTINUE:
							p += w;
							saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
											       lws_ptr_diff_size_t(p, start),
											       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
							p = start;
							break;
						}
					} while (n == LSJS_RESULT_CONTINUE);

					task_index++;
				} lws_end_foreach_dll(pt);
			}

			lwsac_free(&task_ac);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}
		} /* end of full-task (unscoped) path */

		/* none left to do, go back up a level */

		if (lws_ptr_diff_size_t(end, p) < 128) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
							       lws_ptr_diff_size_t(p, start),
							       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
			p = start;
		}

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");

		if (pss->specificity && pss->specificity != SAIM_SPECIFIC_TASK)
			walk = walk->next;
		else
			walk = walk->prev;

		if (walk && (!pss->specificity || pss->specificity == SAIM_SPECIFIC_TASK))
			continue;
	}

so_finish:
	if (lws_ptr_diff_size_t(end, p) < 16) {
		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
						       lws_ptr_diff_size_t(p, start),
						       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
		p = start;
	}

	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 1));

	/*
	 * Consume the one-shot single-event hint (set by eventinfo) so later
	 * overview pushes for the multi-event sidebar list aren't locked to it.
	 */
	pss->event_tasks_uuid[0] = '\0';

	return 0;
}

struct sai_dyn_buf {
	char *buf;
	size_t len;
	size_t alloc;
};

static int
sai_dyn_buf_ensure(struct sai_dyn_buf *d, size_t needed)
{
	if (d->len + needed <= d->alloc)
		return 0;
	size_t na = d->alloc ? d->alloc * 2 : 4096;
	while (d->len + needed > na)
		na *= 2;
	char *nb = realloc(d->buf, na);
	if (!nb)
		return 1;
	d->buf = nb;
	d->alloc = na;
	return 0;
}

static inline int
sai_dyn_buf_append(struct sai_dyn_buf *d, const void *p, size_t len)
{
	if (sai_dyn_buf_ensure(d, len))
		return 1;
	memcpy(d->buf + d->len, p, len);
	d->len += len;
	return 0;
}

static int
saiw_dedup_and_queue(struct pss *pss, int idx, struct sai_dyn_buf *d)
{
	int changed = 1;

	/* check if we changed versus last payload */
	if (pss->last_bps[idx] && pss->last_bps_len[idx] == d->len - LWS_PRE &&
	    !memcmp(pss->last_bps[idx], d->buf + LWS_PRE, d->len - LWS_PRE)) {
		changed = 0;
	} else {
		free(pss->last_bps[idx]);
		pss->last_bps[idx] = NULL;
		pss->last_bps_len[idx] = 0;
		pss->last_bps[idx] = malloc(d->len - LWS_PRE);
		if (pss->last_bps[idx]) {
			memcpy(pss->last_bps[idx], d->buf + LWS_PRE, d->len - LWS_PRE);
			pss->last_bps_len[idx] = d->len - LWS_PRE;
		}
	}

	if (changed)
		saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, d->buf + LWS_PRE,
						       d->len - LWS_PRE,
						       lws_write_ws_flags(LWS_WRITE_TEXT, 1, 1));

	free(d->buf);
	d->buf = NULL;
	return 0;
}

int
saiw_browser_broadcast_queue_pcon_energy(struct vhd *vhd, struct pss *pss, sai_pcon_energy_report_t *energy)
{
	struct sai_dyn_buf d;
	char buf[1024];
	lws_struct_serialize_t *js;
	lws_struct_json_serialize_result_t r;
	size_t w;

	if (pss && !pss->wants_builder_info)
		return 0;

	if (!vhd || !energy || !pss)
		return 0;

	memset(&d, 0, sizeof(d));

	/* Reserve LWS_PRE header space */
	memset(buf, 0, LWS_PRE);
	if (sai_dyn_buf_append(&d, buf, LWS_PRE))
		return 1;

	js = lws_struct_json_serialize_create(
		lsm_schema_pcon_energy,
		LWS_ARRAY_SIZE(lsm_schema_pcon_energy),
		0, energy);
	if (!js) {
		free(d.buf);
		return 1;
	}

	do {
		r = lws_struct_json_serialize(js, (uint8_t *)buf, sizeof(buf), &w);

		if (w && sai_dyn_buf_append(&d, buf, w)) {
			lws_struct_json_serialize_destroy(&js);
			free(d.buf);
			return 1;
		}

		if (r == LSJS_RESULT_ERROR) {
			lws_struct_json_serialize_destroy(&js);
			free(d.buf);
			return 1;
		}
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);

	return saiw_dedup_and_queue(pss, 2, &d);
}

int
saiw_browser_broadcast_queue_pcons(struct vhd *vhd, struct pss *pss)
{
	struct sai_dyn_buf d;
	char buf[1024]; /* temp buffer for serialization before append */
	lws_struct_serialize_t *js;
	sai_power_managed_builders_t pmb;
	lws_struct_json_serialize_result_t r;
	size_t w;

	if (pss && !pss->wants_builder_info)
		return 0;

	if (!vhd || !vhd->pcons || !pss)
		return 0;

	memset(&d, 0, sizeof(d));

	/* Reserve LWS_PRE header space */
	memset(buf, 0, LWS_PRE);
	if (sai_dyn_buf_append(&d, buf, LWS_PRE))
		return 1;

	memset(&pmb, 0, sizeof(pmb));
	pmb.power_controllers = vhd->pcons_owner;

	js = lws_struct_json_serialize_create(
		lsm_schema_power_managed_builders,
		LWS_ARRAY_SIZE(lsm_schema_power_managed_builders),
		0, &pmb);
	if (!js) {
		free(d.buf);
		return 1;
	}

	do {
		r = lws_struct_json_serialize(js, (uint8_t *)buf, sizeof(buf), &w);

		if (sai_dyn_buf_append(&d, buf, w)) {
			lws_struct_json_serialize_destroy(&js);
			free(d.buf);
			return 1;
		}

		if (r == LSJS_RESULT_ERROR) {
			lws_struct_json_serialize_destroy(&js);
			free(d.buf);
			return 1;
		}
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);

	return saiw_dedup_and_queue(pss, 1, &d);
}

int
saiw_browser_broadcast_queue_builders(struct vhd *vhd, struct pss *pss)
{
	struct sai_dyn_buf d;
	char buf[1024]; /* temp buffer for serialization before append */
	lws_struct_serialize_t *js;
	char esc[256];
	lws_dll2_t *walk = NULL;
	char subsequent;
	size_t w;
	int n;

	if (pss && !pss->wants_builder_info)
		return 0;

	if (!vhd || !vhd->builders || !pss)
		return 0;

	saiw_browser_broadcast_queue_pcons(vhd, pss);

	memset(&d, 0, sizeof(d));

	/* Reserve LWS_PRE header space */
	memset(buf, 0, LWS_PRE);
	if (sai_dyn_buf_append(&d, buf, LWS_PRE))
		return 1;

	n = lws_snprintf(buf, sizeof(buf),
			  "{\"schema\":\"com.warmcat.sai.builders\","
			  " \"alang\":\"%s\","
			  " \"builders\":[",
			  lws_json_purify(esc, pss->alang, sizeof(esc) - 1,
					  NULL));
	if (sai_dyn_buf_append(&d, buf, (size_t)n)) {
		free(d.buf);
		return 1;
	}

	if (vhd && vhd->builders)
		walk = lws_dll2_get_head(&vhd->builders_owner);

	subsequent = 0;

	while (walk) {
		sai_plat_t *b = lws_container_of(walk, sai_plat_t, sai_plat_list);
		lws_struct_json_serialize_result_t r;
		char start_of_this_builder = 1;

		lwsl_info("%s: processing builder '%s' (online %d)\n", __func__, b->name, b->online);

		js = lws_struct_json_serialize_create(
			lsm_schema_map_plat_simple,
			LWS_ARRAY_SIZE(lsm_schema_map_plat_simple),
			0, b);
		if (!js) {
			free(d.buf);
			return 1;
		}

		do {
			if (subsequent && start_of_this_builder) {
				if (sai_dyn_buf_append(&d, ",", 1)) {
					lws_struct_json_serialize_destroy(&js);
					free(d.buf);
					return 1;
				}
				start_of_this_builder = 0;
			}

			r = lws_struct_json_serialize(js, (uint8_t *)buf, sizeof(buf), &w);

			if (w && sai_dyn_buf_append(&d, buf, w)) {
				lws_struct_json_serialize_destroy(&js);
				free(d.buf);
				return 1;
			}

			switch (r) {
			case LSJS_RESULT_ERROR:
				lws_struct_json_serialize_destroy(&js);
				free(d.buf);
				return 1;
			case LSJS_RESULT_CONTINUE:
			case LSJS_RESULT_FINISH:
				break;
			}
		} while (r == LSJS_RESULT_CONTINUE);

		lws_struct_json_serialize_destroy(&js);

		subsequent = 1;
		walk = walk->next;
	}

	n = lws_snprintf(buf, sizeof(buf), " \n]}");
	if (sai_dyn_buf_append(&d, buf, (size_t)n)) {
		free(d.buf);
		return 1;
	}

	
	saiw_browser_broadcast_queue_power_history(vhd, pss);

	return saiw_dedup_and_queue(pss, 0, &d);
}

/*
 * This should be called from the browser-facing websocket protocol handler
 * on LWS_CALLBACK_ESTABLISHED and LWS_CALLBACK_CLOSED events to keep an
 * accurate real-time list of connected browsers.
 */
void
saiw_browser_state_changed(struct pss *pss, int established)
{
	if (established)
		lws_dll2_add_tail(&pss->same, &pss->vhd->browsers);
	else
		lws_dll2_remove(&pss->same);

	/*
	 * After any change, recalculate the total and inform the server
	 */
	saiw_update_viewer_count(pss->vhd);
}

/*
 * Track which builder shells this browser opened itself (the rx side only
 * lets admins send openshell/closeshell).  Shell ptydata coming back from
 * the server is delivered only to connections on this list.
 */
void
saiw_pss_shell_open(struct pss *pss, const char *task_uuid)
{
	unsigned int n;

	if (!task_uuid[0])
		return;

	for (n = 0; n < pss->shell_count; n++)
		if (!strcmp(pss->shell_task_uuid[n], task_uuid))
			return;

	if (pss->shell_count >= SAIW_MAX_SHELLS) {
		lwsl_wsi_notice(pss->wsi,
				"shell tracking full, ptydata for %s will "
				"not be delivered here", task_uuid);
		return;
	}

	lws_strncpy(pss->shell_task_uuid[pss->shell_count], task_uuid,
		    sizeof(pss->shell_task_uuid[0]));
	pss->shell_count++;
}

void
saiw_pss_shell_close(struct pss *pss, const char *task_uuid)
{
	unsigned int n;

	for (n = 0; n < pss->shell_count; n++) {
		if (!strcmp(pss->shell_task_uuid[n], task_uuid)) {
			memmove(&pss->shell_task_uuid[n],
				&pss->shell_task_uuid[n + 1],
				(pss->shell_count - n - 1) *
					sizeof(pss->shell_task_uuid[0]));
			pss->shell_count--;

			return;
		}
	}
}

int
saiw_pss_owns_shell(struct pss *pss, const char *task_uuid)
{
	unsigned int n;

	for (n = 0; n < pss->shell_count; n++)
		if (!strcmp(pss->shell_task_uuid[n], task_uuid))
			return 1;

	return 0;
}




typedef struct pcon_watts {
	lws_dll2_t list;
	char name[64];
	unsigned int active_power_w;
} pcon_watts_t;

void
saiw_update_global_power_history(struct vhd *vhd, sai_pcon_energy_report_t *energy)
{
	unsigned int total_w;
	char buf[1024];

	if (!vhd || !energy)
		return;

	/* Record or update individual PCON wattages */
	lws_start_foreach_dll(struct lws_dll2 *, p, energy->items.head) {
		sai_pcon_energy_report_item_t *item = lws_container_of(p, sai_pcon_energy_report_item_t, list);
		pcon_watts_t *pw = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, pt, vhd->pcon_watts_owner.head) {
			pcon_watts_t *pw_iter = lws_container_of(pt, pcon_watts_t, list);
			if (!strcmp(pw_iter->name, item->name)) {
				pw = pw_iter;
				break;
			}
		} lws_end_foreach_dll(pt);

		if (!pw) {
			pw = malloc(sizeof(*pw));
			if (pw) {
				memset(pw, 0, sizeof(*pw));
				lws_strncpy(pw->name, item->name, sizeof(pw->name));
				lws_dll2_add_tail(&pw->list, &vhd->pcon_watts_owner);
			}
		}
		if (pw)
			pw->active_power_w = item->data.active_power_w;

	} lws_end_foreach_dll(p);

	/* Calculate global watts across all tracked PCONs */
	total_w = 0;
	lws_start_foreach_dll(struct lws_dll2 *, pt, vhd->pcon_watts_owner.head) {
		pcon_watts_t *pw = lws_container_of(pt, pcon_watts_t, list);
		total_w += pw->active_power_w;
	} lws_end_foreach_dll(pt);

	/* Record this sample */
	if (vhd->power_history_count == 150) {
		memmove(vhd->power_history, vhd->power_history + 1, sizeof(unsigned int) * 149);
		vhd->power_history[149] = total_w;
	} else {
		vhd->power_history[vhd->power_history_count++] = total_w;
	}

	if (total_w > vhd->max_total_power_w) {
		vhd->max_total_power_w = total_w;
		if (vhd->pdb) {
			lws_snprintf(buf, sizeof(buf), "INSERT OR REPLACE INTO saiweb_state (key, val) VALUES ('max_power', %u)", total_w);
			sai_sqlite3_statement(vhd->pdb, buf, "update max_power");
		}
	}
}

int
saiw_browser_broadcast_queue_power_history(struct vhd *vhd, struct pss *pss)
{
	struct sai_dyn_buf d;
	char buf[2048];
	int n, i;

	if (pss && !pss->wants_builder_info)
		return 0;

	if (!vhd || !pss)
		return 0;

	memset(&d, 0, sizeof(d));

	/* Reserve LWS_PRE header space */
	memset(buf, 0, LWS_PRE);
	if (sai_dyn_buf_append(&d, buf, LWS_PRE))
		return 1;

	n = lws_snprintf(buf, sizeof(buf),
		"{\"schema\":\"com.warmcat.sai.power_history\","
		" \"max_w\":%u,"
		" \"samples\":[", vhd->max_total_power_w);

	if (sai_dyn_buf_append(&d, buf, (size_t)n)) {
		free(d.buf);
		return 1;
	}

	for (i = 0; i < vhd->power_history_count; i++) {
		n = lws_snprintf(buf, sizeof(buf), "%s%u",
				 i ? "," : "",
				 vhd->power_history[i]);
		if (sai_dyn_buf_append(&d, buf, (size_t)n)) {
			free(d.buf);
			return 1;
		}
	}

	n = lws_snprintf(buf, sizeof(buf), "]}");
	if (sai_dyn_buf_append(&d, buf, (size_t)n)) {
		free(d.buf);
		return 1;
	}

	return saiw_dedup_and_queue(pss, 3, &d);
}
