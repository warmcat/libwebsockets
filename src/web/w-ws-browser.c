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
#include <assert.h>
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

static lws_struct_map_t lsm_browser_taskreset[] = {
	LSM_CARRAY	(sai_browse_rx_evinfo_t, event_hash,	"uuid"),
};

static lws_struct_map_t lsm_browser_platreset[] = {
	LSM_CARRAY	(sai_browse_rx_platreset_t, event_uuid, "event_uuid"),
	LSM_CARRAY	(sai_browse_rx_platreset_t, platform,   "platform"),
};

static lws_struct_map_t lsm_browser_taskinfo[] = {
	LSM_CARRAY	(sai_browse_rx_taskinfo_t, task_hash,		"task_hash"),
	LSM_UNSIGNED	(sai_browse_rx_taskinfo_t, logs,		"logs"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, js_api_version,	"js_api_version"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, last_log_ts,		"last_log_ts"),
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
};

enum {
	SAIM_WS_BROWSER_RX_TASKINFO,
	SAIM_WS_BROWSER_RX_EVENTINFO,
	SAIM_WS_BROWSER_RX_TASKRESET,
	SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP,
	SAIM_WS_BROWSER_RX_EVENTRESET,
	SAIM_WS_BROWSER_RX_EVENTDELETE,
	SAIM_WS_BROWSER_RX_TASKCANCEL,
	SAIM_WS_BROWSER_RX_LOADREPORT,
	SAIM_WS_BROWSER_RX_REBUILD,
	SAIM_WS_BROWSER_RX_PLATRESET,
	SAIM_WS_BROWSER_RX_STAY,
	SAIM_WS_BROWSER_RX_PCON_CONTROL,
};


/*
 * For issuing combined task and event data back to browser
 */

typedef struct sai_browse_taskreply {
	const sai_event_t	*event;
	const sai_task_t	*task;
	char			auth_user[33];
	int			authorized;
	int			auth_secs;
} sai_browse_taskreply_t;

static lws_struct_map_t lsm_taskreply[] = {
	LSM_CHILD_PTR	(sai_browse_taskreply_t, event,	sai_event_t, NULL,
			 lsm_event, "e"),
	LSM_CHILD_PTR	(sai_browse_taskreply_t, task,	sai_task_t, NULL,
			 lsm_task, "t"),
	LSM_CARRAY	(sai_browse_taskreply_t, auth_user,	"auth_user"),
	LSM_UNSIGNED	(sai_browse_taskreply_t, authorized,	"authorized"),
	LSM_UNSIGNED	(sai_browse_taskreply_t, auth_secs,	"auth_secs"),
};

const lws_struct_map_t lsm_schema_json_map_taskreply[] = {
	LSM_SCHEMA	(sai_browse_taskreply_t, NULL, lsm_taskreply,
			 "com.warmcat.sai.taskinfo"),
};

enum sai_overview_state {
	SOS_EVENT,
	SOS_TASKS,
};

int
saiw_ws_browser_queue_REQUIRES_LWS_PRE(struct pss *pss, const void *buf,
				       size_t len, enum lws_write_protocol flags)
{
	int *pi = (int *)((const char *)buf - sizeof(int)), r = 0;

	*pi = (int)flags;

	if (lws_buflist_append_segment(&pss->raw_tx, buf - sizeof(int), len + sizeof(int)) < 0) {
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

/* 1 == authorized */

static int
sais_conn_auth(struct pss *pss)
{
	if (!pss->authorized)
		return 0;
	if (pss->expiry_unix_time < (unsigned long)lws_now_secs())
		return 0;

	return 1;
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
//	char qu[180], esc[66], esc2[96];
//	int n;

	/*
	 * This pss may be locked to a specific event
	 */

	if (pss->specific_task[0] && memcmp(pss->specific_task, event_uuid, 32))
		goto bail;

	/*
	 * This pss may be locked to a specific project, qualify the db lookup
	 * vs any project name specificity.
	 *
	 * Just collect the event struct into pss->query_owner to dump
	 */
#if 0
	lws_sql_purify(esc, event_uuid, sizeof(esc));

	if (pss->specific_project[0]) {
		lws_sql_purify(esc2, pss->specific_project, sizeof(esc2));
		lws_snprintf(qu, sizeof(qu), " and uuid='%s' and repo_name='%s'", esc, esc2);
	} else
		lws_snprintf(qu, sizeof(qu), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pss->vhd->pdb, qu, NULL,
				       lsm_schema_sq3_map_event,
				       &sch->owner, &sch->ac, 0, 1);
	if (n < 0 || !sch->owner.head)
		goto bail;
#endif
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
saiw_pss_schedule_taskinfo(struct pss *pss, const char *task_uuid, int logsub)
{
	char qu[192], event_uuid[33], esc2[96], buf[4096 + LWS_PRE],
	     *start = buf + LWS_PRE, *p = start, *end = buf + sizeof(buf);
	const sai_event_t *one_event = NULL;
	sai_browse_taskreply_t task_reply;
	struct lwsac *query_ac = NULL;
	sai_task_t *one_task = NULL;
	lws_struct_serialize_t *js;
	char esc[256], filt[128];
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

	/* open the event-specific database object */

	if (sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
			      pss->vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		return 0;

	/*
	 * get the related task object into its own ac... there might
	 * be a lot of related data, so we hold the ac in the sch for
	 * as long as needed to send it out
	 */

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_snprintf(qu, sizeof(qu), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pdb, qu, NULL, lsm_schema_sq3_map_task,
				       &o, &query_ac, 0, 1);
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
	if (!pss->authorized)
		m += lws_snprintf(qu + m, sizeof(qu) - (unsigned int)m, " and sec=0");

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

	memset(&task_reply, 0, sizeof(task_reply));

	/*
	 * We're sending a browser the specific task info that he
	 * asked for.
	 *
	 * We already got the task struct out of the db in .one_task
	 * (all in .query_ac)... we're responsible for destroying it
	 * when we go out of scope...
	 */

	task_reply.event		= one_event;
	task_reply.task			= one_task;
	one_task->rebuildable		= (one_task->state == SAIES_FAIL ||
					   one_task->state == SAIES_CANCELLED) &&
					  (lws_now_secs() - (one_task->started +
					   (one_task->duration / 1000000)) < 24 * 3600);
	task_reply.auth_secs		= (int)(pss->authorized ? pss->expiry_unix_time - lws_now_secs() : 0);
	task_reply.authorized		= pss->authorized;
	lws_strncpy(task_reply.auth_user, pss->auth_user, sizeof(task_reply.auth_user));

	js = lws_struct_json_serialize_create(lsm_schema_json_map_taskreply,
					      LWS_ARRAY_SIZE(lsm_schema_json_map_taskreply),
					      0, &task_reply);
	if (!js) {
		lwsl_warn("%s: couldn't create\n", __func__);
		goto bail;
	}

	do {
		n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);

		if (lws_ptr_diff_size_t(end, (uint8_t *)p) < 512) {
			saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(pss->vhd, start,
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

	if (one_task) {

		sai_task_uuid_to_event_uuid(event_uuid, one_task->uuid);

		lws_dll2_owner_clear(&owner);
		if (!sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
					      pss->vhd->sqlite3_path_lhs, event_uuid,
					      0, &pdb)) {

			lws_snprintf(filt, sizeof(filt), " and (task_uuid == '%s')",
				     one_task->uuid);

			if (lws_struct_sq3_deserialize(pdb, filt, NULL,
						       lsm_schema_sq3_map_artifact,
						       &owner,
						       &query_ac, 0, 10))
				lwsl_err("%s: get afcts failed\n", __func__);

			sai_event_db_close(&pss->vhd->sqlite3_cache, &pdb);
		}
	}

	if (n == LSJS_RESULT_ERROR) {
		lwsl_notice("%s: taskinfo: error generating json\n", __func__);
		goto bail;
	}
	p += w;

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, fi, 1));

	/* does he want to subscribe to logs? */
	if (logsub && one_task && !pss->subs_list.owner) {
		strcpy(pss->sub_task_uuid, one_task->uuid);
		lws_dll2_add_head(&pss->subs_list, &pss->vhd->subs_owner);
		pss->sub_timestamp = pss->initial_log_timestamp; /* where we got up to */
		saiw_broadcast_logs_batch(pss->vhd, pss);
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

	return 0;

bail:
	lwsac_free(&query_ac);

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
			saiw_pss_schedule_taskinfo(pss, task_uuid, 0);

	} lws_end_foreach_dll(p);

	return 0;
}


int
saiw_browsers_task_state_change(struct vhd *vhd, const char *task_uuid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		saiw_pss_schedule_taskinfo(pss, task_uuid, 0);
	} lws_end_foreach_dll(p);

	return 0;
}


int
saiw_event_state_change(struct vhd *vhd, const char *event_uuid)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		saiw_pss_schedule_eventinfo(pss, event_uuid);
	} lws_end_foreach_dll(p);

	return 0;
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

	lwsl_notice("%s: len %d, flags: %d\n", __func__, (int)bl, ss_flags);
	/* lwsl_hexdump_notice(buf, bl); */

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

	switch (a.top_schema_index) {

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

			saiw_browser_broadcast_queue_builders(pss->vhd, pss);
			saiw_browser_queue_overview(pss->vhd, pss);
			break;
		}

		/*
		 * get the related task object into its own ac... there might
		 * be a lot of related data, so we hold the ac in the pss for
		 * as long as needed to send it out
		 */

		if (ti->logs)
			pss->initial_log_timestamp = ti->last_log_ts;
		else
			pss->initial_log_timestamp = 0;

		if (saiw_pss_schedule_taskinfo(pss, ti->task_hash, !!ti->logs))
			goto soft_error;

		goto ok;

	case SAIM_WS_BROWSER_RX_EVENTINFO:

		ei = (sai_browse_rx_evinfo_t *)a.dest;

		if (saiw_pss_schedule_eventinfo(pss, ei->event_hash))
			goto soft_error;

		goto ok;

	case SAIM_WS_BROWSER_RX_TASKRESET:

		if (!sais_conn_auth(pss))
			goto auth_error;

		/*
		 * User is asking us to reset / rebuild this task
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;
		break;

	case SAIM_WS_BROWSER_RX_STAY:
		if (!sais_conn_auth(pss)) {
			lwsl_err("%s: stay didn't like auth\n", __func__);
			goto auth_error;
		}

		lwsl_notice("%s: web: received stay req\n", __func__);

		/*
		 * User is asking us to set or release a stay on a builder
		 */
		break;

	case SAIM_WS_BROWSER_RX_PCON_CONTROL:
		if (!sais_conn_auth(pss)) {
			lwsl_err("%s: pcon control didn't like auth\n", __func__);
			goto auth_error;
		}
		lwsl_notice("%s: web: received pcon control req\n", __func__);

		/* Forward to sai-server via websrv link */
		sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(vhd->h_ss_websrv,
			&((saiw_websrv_t *)lws_ss_to_user_object(vhd->h_ss_websrv))->wbltx,
			buf, bl, ss_flags);
		goto ok;

	case SAIM_WS_BROWSER_RX_TASKREBUILDLASTSTEP:
		if (!sais_conn_auth(pss))
			goto auth_error;

		/*
		 * User is asking us to rebuild the last step of this task
		 */

		ei = (sai_browse_rx_evinfo_t *)a.dest;
		break;

	case SAIM_WS_BROWSER_RX_EVENTRESET:

		if (!sais_conn_auth(pss))
			goto auth_error;

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

		if (!sais_conn_auth(pss))
			goto auth_error;

		ei = (sai_browse_rx_evinfo_t *)a.dest;

		lwsl_notice("%s: received request to delete event %s\n",
			    __func__, ei->event_hash);

		break;

	case SAIM_WS_BROWSER_RX_TASKCANCEL:

		if (!sais_conn_auth(pss))
			goto auth_error;

		/*
		 * Browser is informing us of task's STOP button clicked, we
		 * need to inform any builder that might be building it
		 */
		can = (sai_cancel_t *)a.dest;

		lwsl_notice("%s: received request to cancel task %s\n",
			    __func__, can->task_uuid);

		saiw_task_cancel(vhd, can->task_uuid);
		goto ok;

	case SAIM_WS_BROWSER_RX_REBUILD:
		if (!sais_conn_auth(pss))
			goto auth_error;

		/*
		 * User is asking us to rebuild a builder
		 */
		break;

	case SAIM_WS_BROWSER_RX_PLATRESET:
		if (!sais_conn_auth(pss))
			goto auth_error;

		/*
		 * User is asking us to reset / rebuild a whole platform
		 */
		break;

	default:
		assert(0);
		break;
	}

	sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(vhd->h_ss_websrv,
		&((saiw_websrv_t *)lws_ss_to_user_object(vhd->h_ss_websrv))->wbltx,
		buf, bl, ss_flags);

ok:
	ret = 0;

bail:
	lwsac_free(&a.ac);

	return ret;

auth_error:
	{
		uint8_t buf[LWS_PRE + 128];
		int n;

		n = lws_snprintf((char *)buf + LWS_PRE, sizeof(buf) - LWS_PRE,
			"{\"schema\":\"com.warmcat.sai.unauthorized\"}");
		lws_write(pss->wsi, buf + LWS_PRE, (size_t)n, LWS_WRITE_TEXT);
	}

soft_error:
	lwsac_free(&a.ac);

	return 0;
}

static void
saiw_retry_logs(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul_logcache);

	saiw_broadcast_logs_batch(pss->vhd, pss);
}

int
saiw_broadcast_logs_batch(struct vhd *vhd, struct pss *pss)
{
	char event_uuid[33];

	if (!pss->subs_list.owner)
		return 0;

	/*
	 * For efficiency, let's try to grab the next 100 at
	 * once from sqlite and work our way through sending
	 * them
	 */

	//if (pss->log_cache_index == pss->log_cache_size)
	{
		sqlite3 *pdb = NULL;
		char esc[256];
		int sr;

		sai_task_uuid_to_event_uuid(event_uuid, pss->sub_task_uuid);

		lwsac_free(&pss->logs_ac);

		lws_snprintf(esc, sizeof(esc),
		     "and task_uuid='%s' and timestamp > %llu",
		     pss->sub_task_uuid,
		     (unsigned long long)pss->sub_timestamp);

		// lwsl_notice("%s: collecting logs %s\n", __func__, esc);

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					     vhd->sqlite3_path_lhs, event_uuid,
					     0, &pdb)) {
			lwsl_notice("%s: unable to open event-specific database\n",
					__func__);

			return 0;
		}

		sr = lws_struct_sq3_deserialize(pdb, esc,
						"uid,timestamp ",
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
		} while (n != LSJS_RESULT_FINISH);
	}

	lwsac_free(&pss->logs_ac);

	lws_sul_schedule(vhd->context, 0, &pss->sul_logcache,
			 saiw_retry_logs,
			 pss->log_cache_size == 50 ? 500 : 250 * LWS_US_PER_MS);

	return 0;
}

int
saiw_browser_queue_overview(struct vhd *vhd, struct pss *pss)
{
	char buf[4096 + LWS_PRE], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf);
	char esc[256], esc1[33], filt[128], subsequent;
	struct lwsac *task_ac = NULL, *ac = NULL;
	lws_dll2_owner_t task_owner, owner;
	unsigned int task_index = 0;
	lws_struct_serialize_t *js;
	sqlite3 *pdb = NULL;
	lws_dll2_t *walk;
	sai_task_t *t;
	int n, iu;
	size_t w;

	filt[0] = '\0';
	esc[0] = '\0';
	n = -8;

	if (pss->specific_project[0]) {
		lws_sql_purify(esc, pss->specific_project, sizeof(esc) - 1);
		lws_snprintf(filt, sizeof(filt), " and repo_name=\"%s\"", esc);
		n = -1;
	}
	if (!pss->authorized)
		lws_snprintf(filt + strlen(filt), sizeof(filt) - strlen(filt), " and sec=0");

	pss->wants_event_updates = 1;
	if (lws_struct_sq3_deserialize(vhd->pdb, filt[0] ? filt : NULL,
				       "created ", lsm_schema_sq3_map_event,
				       &owner, &ac, 0, n)) {
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
		" \"authorized\": %d,"
		" \"auth_secs\": %ld,"
		" \"auth_user\": \"%s\","
		"\"overview\":[", SAIW_API_VERSION,
		lws_json_purify(esc, pss->alang, sizeof(esc) - 1, &iu),
		pss->authorized, pss->authorized ? pss->expiry_unix_time - lws_now_secs() : 0,
		lws_json_purify(esc1, pss->auth_user, sizeof(esc1) - 1, &iu)
	);

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, 1, 0));
	p = start;


	/*
	 * "authorized" here is used to decide whether to render the
	 * additional controls clientside.  The events the controls
	 * cause if used are separately checked for coming from an
	 * authorized pss when they are received.
	 *
	 * If you're not authorized, you're only going to see events
	 * that have sec=0.  Otherwise you can see all events.
	 */

	if (pss->specificity)
		walk = lws_dll2_get_head(&owner);
	else
		walk = lws_dll2_get_tail(&owner);

	subsequent = 0;

	if (!owner.count) /* nothing to do */
		goto so_finish;

	while (walk) {
		sai_event_t *e = lws_container_of(walk, sai_event_t, list);

		if (pss->specificity) {
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

		js = lws_struct_json_serialize_create(
			lsm_schema_json_map_event,
			LWS_ARRAY_SIZE(lsm_schema_json_map_event), 0, e);
		if (!js) {
			lwsl_err("%s: json ser fail\n", __func__);
			return 1;
		}
		if (subsequent)
			*p++ = ',';
		subsequent = 1;

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "{\"e\":");

		if (lws_ptr_diff_size_t(end, p) < 256) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
							       lws_ptr_diff_size_t(p, start),
							       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
			p = start;
		}

		n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);
		switch (n) {
		case LSJS_RESULT_ERROR:
			lwsl_err("%s: json ser error\n", __func__);
			return 1;

		case LSJS_RESULT_FINISH:
		case LSJS_RESULT_CONTINUE:
			p += w;
			task_index = 0;
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), ", \"t\":[");
			break;
		}

		if (lws_ptr_diff_size_t(end, p) < 2560) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
							       lws_ptr_diff_size_t(p, start),
							       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
			p = start;
		}

		/*
		 * Enumerate the tasks associated with this event...
		 */

		e = lws_container_of(walk, sai_event_t, list);
		lws_dll2_owner_clear(&task_owner);

		do {
			task_ac = NULL;

			if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {
				lwsl_err("%s: unable to open event-specific database\n",
						__func__);

				break;
			}

			lws_dll2_owner_clear(&task_owner);
			if (lws_struct_sq3_deserialize(pdb, NULL, NULL,
					lsm_schema_sq3_map_task, &task_owner,
					&task_ac, (int)task_index, 1)) {
				lwsl_err("%s: OVERVIEW 1 failed\n", __func__);
				sai_event_db_close(&vhd->sqlite3_cache, &pdb);

				break;
			}
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);

			if (!task_owner.count)
				break;

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

			t = (sai_task_t *)task_owner.head;
			t->art_up_nonce[0] = '\0';
			t->art_down_nonce[0] = '\0';

			t->rebuildable = (t->state == SAIES_FAIL || t->state == SAIES_CANCELLED) &&
				(lws_now_secs() - (t->started + t->duration / 1000000) < 24 * 3600);

			/* only one in it at a time */
			t = lws_container_of(task_owner.head, sai_task_t, list);

			js = lws_struct_json_serialize_create(
				lsm_schema_json_map_task,
				LWS_ARRAY_SIZE(lsm_schema_json_map_task), 0, t);

			t->build[0] = '\0';
			n = (int)lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w);
			lws_struct_json_serialize_destroy(&js);
			lwsac_free(&task_ac);
			p += w;

			if (lws_ptr_diff_size_t(end, p) < 2560) {
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
								       lws_ptr_diff_size_t(p, start),
								       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 0));
				p = start;
			}

			task_index++;
		} while (1);

		/* none left to do, go back up a level */

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");

		if (pss->specificity)
			walk = walk->next;
		else
			walk = walk->prev;

		if (walk && !pss->specificity)
			continue;
	}

so_finish:
	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
					       lws_ptr_diff_size_t(p, start),
					       lws_write_ws_flags(LWS_WRITE_TEXT, 0, 1));

	return 0;
}

int
saiw_browser_broadcast_queue_builders(struct vhd *vhd, struct pss *pss)
{
	char buf[4096 + LWS_PRE], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf);
	lws_struct_serialize_t *js;
	char esc[256], esc1[33];
	lws_dll2_t *walk = NULL;
	char fi = 1, subsequent;
	size_t w;
	int iu;

	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"com.warmcat.sai.builders\","
			  " \"alang\":\"%s\","
			  " \"authorized\":%d,"
			  " \"auth_secs\":%ld,"
			  " \"auth_user\": \"%s\","
			  " \"builders\":[",
			  lws_sql_purify(esc, pss->alang, sizeof(esc) - 1),
			  pss->authorized, pss->authorized ? pss->expiry_unix_time - lws_now_secs() : 0,
			  lws_json_purify(esc1, pss->auth_user, sizeof(esc1) - 1, &iu));

	if (vhd && vhd->builders)
		walk = lws_dll2_get_head(&vhd->builders_owner);

	subsequent = 0;

	while (walk) {
		sai_plat_t *b = lws_container_of(walk, sai_plat_t, sai_plat_list);

		js = lws_struct_json_serialize_create(
			lsm_schema_map_plat_simple,
			LWS_ARRAY_SIZE(lsm_schema_map_plat_simple),
			0, b);
		if (!js) {
			lwsac_unreference(&vhd->builders);
			return 1;
		}
		if (subsequent)
			*p++ = ',';
		subsequent = 1;

		switch (lws_struct_json_serialize(js, (uint8_t *)p, lws_ptr_diff_size_t(end, p), &w)) {
		case LSJS_RESULT_ERROR:
			lws_struct_json_serialize_destroy(&js);
			return 1;

		case LSJS_RESULT_FINISH:
			lws_struct_json_serialize_destroy(&js);
			/* fallthru */
		case LSJS_RESULT_CONTINUE:
			p += w;
			walk = walk->next;
			break;
		}

		if (lws_ptr_diff_size_t(end, p) < 256) {
			saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
								    lws_ptr_diff_size_t(p, start),
								    lws_write_ws_flags(LWS_WRITE_TEXT, fi, 0));
			fi = 0;
			p = start;
		}
	}

	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");

	saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, start,
						    lws_ptr_diff_size_t(p, start),
						    lws_write_ws_flags(LWS_WRITE_TEXT, fi, 1));
	return 0;
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


