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
 *
 *   b1 --\   sai-        sai-   /-- browser
 *   b2 ----- server ---- web ------ browser
 *   b3 --/        *             \-- browser
 *
 * This is a ws server over a unix domain socket made available by sai-server
 * and connected to by sai-web instances running on the same box.
 *
 * The server notifies the sai-web instances of event and task changes (just
 * that a particular event or task changed) and builder list updates (the
 * whole current builder list JSON each time).
 *
 * Sai-web instances can send requests to restart or delete tasks and whole
 * events made by authenticated clients.
 *
 * Since this is on a local UDS protected by user:group, there's no tls or auth
 * on this link itself.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "s-private.h"

typedef struct sai_sul_retry_ctx {
	lws_sorted_usec_list_t	sul;
	struct vhd		*vhd;
	char			uuid[SAI_TASKID_LEN + 1];
	char			platform[96];
	int			retries;
	uint8_t			op; /* SAIS_WS_WEBSRV_RX_... */
} sai_sul_retry_ctx_t;


static lws_struct_map_t lsm_browser_taskreset[] = {
	LSM_CARRAY	(sai_browse_rx_evinfo_t, event_hash,	"uuid"),
};

/*
 * (Structs and maps removed - now in common/include/private.h and common/struct-metadata.c)
 */

static lws_struct_map_t lsm_browser_platreset[] = {
	LSM_CARRAY	(sai_browse_rx_platreset_t, event_uuid, "event_uuid"),
	LSM_CARRAY	(sai_browse_rx_platreset_t, platform,   "platform"),
};

static lws_struct_map_t lsm_browser_builderdelete[] = {
	LSM_CARRAY	(sai_browse_rx_builderdelete_t, builder_name, "builder_name"),
};

static const lws_struct_map_t lsm_viewercount_members[] = {
	LSM_UNSIGNED(sai_viewer_state_t, viewers,		"count"),
};

static lws_struct_map_t lsm_browser_taskinfo[] = {
	LSM_CARRAY	(sai_browse_rx_taskinfo_t, task_hash,		"task_hash"),
	LSM_UNSIGNED	(sai_browse_rx_taskinfo_t, logs,		"logs"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, js_api_version,	"js_api_version"),
	LSM_UNSIGNED    (sai_browse_rx_taskinfo_t, last_log_ts,		"last_log_ts"),
	LSM_SIGNED      (sai_browse_rx_taskinfo_t, run,			"run"),
};

static const lws_struct_map_t lsm_schema_json_map[] = {
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
	LSM_SCHEMA	(sai_viewer_state_t,	 NULL, lsm_viewercount_members,
					      "com.warmcat.sai.viewercount"),
	LSM_SCHEMA	(sai_rebuild_t,		 NULL, lsm_rebuild,
					      "com.warmcat.sai.rebuild"),
	LSM_SCHEMA	(sai_browse_rx_platreset_t, NULL, lsm_browser_platreset,
					      "com.warmcat.sai.platreset"),
	LSM_SCHEMA	(sai_stay_t,		 NULL, lsm_stay,
					      "com.warmcat.sai.stay"),
	LSM_SCHEMA	(sai_pcon_control_t,	 NULL, lsm_pcon_control,
			/* shares struct */   "com.warmcat.sai.pcon_control"),
	LSM_SCHEMA	(sai_browse_rx_taskinfo_t, NULL, lsm_browser_taskinfo,
						"com.warmcat.sai.taskinfo"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskpause"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskresume"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_browser_taskreset,
			/* shares struct */   "com.warmcat.sai.taskkill"),
	LSM_SCHEMA	(sai_browse_rx_builderdelete_t, NULL, lsm_browser_builderdelete,
					      "com.warmcat.sai.builderdelete"),
	LSM_SCHEMA	(sai_openshell_t, NULL, lsm_openshell,
					      "com.warmcat.sai.openshell"),
	LSM_SCHEMA	(sai_closeshell_t, NULL, lsm_closeshell,
					      "com.warmcat.sai.closeshell"),
	LSM_SCHEMA	(sai_ptydata_t, NULL, lsm_ptydata,
					      "com.warmcat.sai.ptydata"),
	LSM_SCHEMA	(sai_browse_rx_taskclone_t, NULL, lsm_taskclone,
					      "com.warmcat.sai.taskclone"),
	LSM_SCHEMA	(sai_findingset_t, NULL, lsm_findingset,
					      "com.warmcat.sai.findingset"),
};

enum {
	SAIS_WS_WEBSRV_RX_TASKRESET,
	SAIS_WS_WEBSRV_RX_TASKREMOVEALLTRIES,
	SAIS_WS_WEBSRV_RX_TASKREBUILDLASTSTEP,
	SAIS_WS_WEBSRV_RX_EVENTRESET,
	SAIS_WS_WEBSRV_RX_EVENTDELETE,
	SAIS_WS_WEBSRV_RX_TASKCANCEL,
	SAIS_WS_WEBSRV_RX_VIEWERCOUNT,
	SAIS_WS_WEBSRV_RX_REBUILD,
	SAIS_WS_WEBSRV_RX_PLATRESET,
	SAIS_WS_WEBSRV_RX_STAY,
	SAIS_WS_WEBSRV_RX_PCON_CONTROL,
	SAIS_WS_WEBSRV_RX_TASKINFO,
	SAIS_WS_WEBSRV_RX_TASKPAUSE,
	SAIS_WS_WEBSRV_RX_TASKRESUME,
	SAIS_WS_WEBSRV_RX_TASKKILL,
	SAIS_WS_WEBSRV_RX_BUILDERDELETE,
	SAIS_WS_WEBSRV_RX_OPENSHELL,
	SAIS_WS_WEBSRV_RX_CLOSESHELL,
	SAIS_WS_WEBSRV_RX_PTYDATA,
	SAIS_WS_WEBSRV_RX_TASKCLONE,
	SAIS_WS_WEBSRV_RX_FINDINGSET,
};

/*
 * Cap on a reassembled web -> server message.  The largest legitimate one is
 * a taskclone: a 4KiB build script JSON-escaped, plus the small fixed fields.
 */
#define SAIS_WEBSRV_RX_REASM_MAX	32768

static int
sais_validate_builder_name(const char *id)
{
	const char *idin = id;

	while (*id) {
		if (!((*id >= '0' && *id <= '9') ||
		      (*id >= 'a' && *id <= 'z') ||
		      (*id >= 'A' && *id <= 'Z') ||
		      *id == '.' || *id == '/' || *id == '-' || *id == '_'))
			goto reject;
		id++;
	}

	return 0;
reject:

	lwsl_notice("%s: Invalid builder name '%s'\n", __func__, idin);

	return 1;
}

int
sais_list_pcons(struct vhd *vhd)
{
	char json_pcons[LWS_PRE + 8192], *start = json_pcons + LWS_PRE,
	     *p = start, *end = p + sizeof(json_pcons) - LWS_PRE;
	unsigned int ss_flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;
	lws_struct_serialize_t *js;
	struct lwsac *ac = NULL;
	lws_wsmsg_info_t info;
	size_t w;
	lws_struct_json_serialize_result_t r;
	char pcon_query[128];
	sqlite3_stmt *pcon_stmt;

	sai_power_managed_builders_t pmb;
	sai_power_controller_t *pc;

	memset(&pmb, 0, sizeof(pmb));

	/*
	 * We use raw sqlite queries for PCON deserialization to bypass
	 * complex inner/outer lws_struct_sq3 memory management edge cases that truncates rows.
	 */
	lws_snprintf(pcon_query, sizeof(pcon_query),
		     "SELECT name, type, depends_on, state, manual_on FROM power_controllers ORDER BY name LIMIT 100");

	if (sqlite3_prepare_v2(vhd->server.pdb, pcon_query, -1, &pcon_stmt, NULL) == SQLITE_OK) {
		while (sqlite3_step(pcon_stmt) == SQLITE_ROW) {
			const char *name = (const char *)sqlite3_column_text(pcon_stmt, 0);
			if (name) {
				pc = lwsac_use_zero(&ac, sizeof(*pc), 2048);
				if (pc) {
					lws_strncpy(pc->name, name, sizeof(pc->name));
					
					const char *type = (const char *)sqlite3_column_text(pcon_stmt, 1);
					if (type) lws_strncpy(pc->type, type, sizeof(pc->type));
					
					const char *depends_on = (const char *)sqlite3_column_text(pcon_stmt, 2);
					if (depends_on) lws_strncpy(pc->depends_on, depends_on, sizeof(pc->depends_on));
					
					pc->on = (unsigned int)sqlite3_column_int(pcon_stmt, 3);
					pc->manual_on = (unsigned int)sqlite3_column_int(pcon_stmt, 4);
					
					lws_dll2_add_tail(&pc->list, &pmb.power_controllers);
				}
			}
		}
		sqlite3_finalize(pcon_stmt);
	}



	/* Serialize */
	js = lws_struct_json_serialize_create(lsm_schema_power_managed_builders,
					      LWS_ARRAY_SIZE(lsm_schema_power_managed_builders),
					      0, &pmb);
	if (!js)
		goto bail;

	do {
		r = lws_struct_json_serialize(js, (uint8_t *)p,
				lws_ptr_diff_size_t(end, p) - 2, &w);
		p += w;

		switch (r) {
		case LSJS_RESULT_FINISH:
			/* fallthru */
		case LSJS_RESULT_CONTINUE:
			memset(&info, 0, sizeof(info));

			info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
			info.buf			= (uint8_t *)start;
			info.len			= lws_ptr_diff_size_t(p, start);
			info.ss_flags			= ss_flags;

			if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
				lwsl_warn("%s: unable to broadcast pcons to web\n", __func__);

			p = start;
			ss_flags &= ~((unsigned int)LWSSS_FLAG_SOM);
			break;

		case LSJS_RESULT_ERROR:
			lws_struct_json_serialize_destroy(&js);
			goto bail;
		}

	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);
	lwsac_free(&ac);
	return 0;

bail:
	lwsac_free(&ac);
	return 1;
}

int
sais_list_builders(struct vhd *vhd)
{
	char json_builders[LWS_PRE + 8192], *start = json_builders + LWS_PRE,
	     *p = start, *end = p + sizeof(json_builders) - LWS_PRE,
	     subsequent = 0;
	unsigned int ss_flags = LWSSS_FLAG_SOM;
	lws_dll2_owner_t db_builders_owner;
	lws_struct_serialize_t *js;
	struct lwsac *ac = NULL;
	lws_wsmsg_info_t info;
	sai_plat_t *sp;
	size_t w;

	/* Send PCONs first */
	sais_list_pcons(vhd);

	memset(&db_builders_owner, 0, sizeof(db_builders_owner));

	/* Query builders table, which now includes 'pcon' column */
	if (lws_struct_sq3_deserialize(vhd->server.pdb, NULL, "name ",
				       lsm_schema_sq3_map_plat,
				       &db_builders_owner, &ac, 0, 100)) {
		lwsl_err("%s: Failed to query builders from DB\n", __func__);
		return 1;
	}

	// lwsl_warn("%s: count deserialized %d\n", __func__, (int)db_builders_owner.count);

	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
			"{\"schema\":\"com.warmcat.sai.builders\",\"builders\":[");

	lws_start_foreach_dll(struct lws_dll2 *, walk, db_builders_owner.head) {
		lws_struct_json_serialize_result_t r;
		sai_plat_t *live_builder;

		sp = lws_container_of(walk, sai_plat_t, sai_plat_list);
		lwsl_info("%s: listing builder '%s', pcon='%s'\n", __func__, sp->name, sp->pcon ? sp->pcon : "(null)");

		live_builder = sais_builder_from_uuid(vhd, sp->name);

		if (live_builder) {
			sp->online		= 1;
			lws_strncpy(sp->peer_ip, live_builder->peer_ip,
				    sizeof(sp->peer_ip));
			sp->stay_on	= live_builder->stay_on;
		} else
			sp->online		= 0;

		sp->powering_up			= 0;
		sp->powering_down		= 0;

		lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.power_state_owner.head) {
			sai_power_state_t *ps = lws_container_of(p, sai_power_state_t, list);
			size_t host_len = strlen(ps->host), pl = strlen(sp->name);

			if ((!strncmp(sp->name, ps->host, host_len) &&
			    sp->name[host_len] == '.') || (pl > host_len &&
					    !strncmp(sp->name + (pl - host_len), ps->host, host_len)) ||
			    (sp->pcon && !strcmp(sp->pcon, ps->host)))
			{
				lwsl_notice("%s: %s vs %s, sp->online %d, pup %d, pdwn %d\n", __func__, sp->name, ps->host, sp->online, ps->powering_up, ps->powering_down);
				/*
				 * powering_up/down comes to us as a one-shot
				 * notification, we have to clear our copy of it
				 */
				if (sp->online)
					ps->powering_up		= 0;
				else
					ps->powering_down	= 0;

				lwsl_notice("%s: adjusting powering_ %d %d\n", __func__, ps->powering_up, ps->powering_down);
				sp->powering_up		= ps->powering_up;
				sp->powering_down	= ps->powering_down;
				break;
			}
		} lws_end_foreach_dll(p);

		/* Use schema including pcon if available */
		js = lws_struct_json_serialize_create(lsm_schema_map_plat_simple,
						      LWS_ARRAY_SIZE(lsm_schema_map_plat_simple),
						      0, sp);
		if (!js)
			goto bail;

		if (subsequent)
			*p++ = ',';
		subsequent = 1;

		do {
			r = lws_struct_json_serialize(js, (uint8_t *)p,
					lws_ptr_diff_size_t(end, p) - 2, &w);
			p += w;

			switch (r) {
			case LSJS_RESULT_FINISH:
				/* fallthru */
			case LSJS_RESULT_CONTINUE:
				memset(&info, 0, sizeof(info));

				info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
				info.buf			= (uint8_t *)start;
				info.len			= lws_ptr_diff_size_t(p, start);
				info.ss_flags			= ss_flags;

				if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
					lwsl_warn("%s: unable to broadcast to web\n", __func__);

				p = start;
				ss_flags &= ~((unsigned int)LWSSS_FLAG_SOM);
				break;

			case LSJS_RESULT_ERROR:
				lws_struct_json_serialize_destroy(&js);
				goto bail;
			}

		} while (r == LSJS_RESULT_CONTINUE);

		lws_struct_json_serialize_destroy(&js);

	} lws_end_foreach_dll(walk);

	ss_flags |= LWSSS_FLAG_EOM;
	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]}");
	memset(&info, 0, sizeof(info));

	info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
	info.buf			= (uint8_t *)start;
	info.len			= lws_ptr_diff_size_t(p, start);
	info.ss_flags			= ss_flags;

	if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
		lwsl_warn("%s: unable to broadcast to web\n", __func__);

	// lwsl_notice("%s: Broadcasting builder list: %s\n", __func__, start);
	lwsac_free(&ac);
	return 0;

bail:
	lwsac_free(&ac);
	return 1;
}



static void
sum_viewers_cb(struct lws_ss_handle *h, void *arg)
{
	websrvss_srv_t *m_client = (websrvss_srv_t *)lws_ss_to_user_object(h);
	*(unsigned int *)arg += m_client->viewers;
}




static lws_ss_state_return_t
websrvss_ws_rx_msg(websrvss_srv_t *m, const uint8_t *buf, size_t len,
		   int flags)
{
	sai_browse_rx_evinfo_t *ei;
	sai_cancel_t *can;
	lws_struct_args_t a;
	sai_db_result_t r;
	int n;

	lwsl_info("%s: len %d, flags: %d\n", __func__, (int)len, flags);
	lwsl_hexdump_info(buf, len);

	memset(&a, 0, sizeof(a));
	a.map_st[0]		= lsm_schema_json_map;
	a.map_st[1]		= lsm_schema_json_map;
	a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
	a.map_entries_st[1]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
	a.ac_block_size		= 128;

	lws_struct_json_init_parse(&m->ctx, NULL, &a);
	n = lejp_parse(&m->ctx, (uint8_t *)buf, (int)len);
	if (n < 0 || !a.dest) {
		/*
		 * This link carries forwarded browser requests whose content
		 * we do not control, so an undecodable message is skipped,
		 * not fatal: tearing down the ss link here would take the
		 * nailed-up control channel away from every connected
		 * sai-web instance for the retry period.
		 */
		lwsl_hexdump_notice(buf, len);
		lwsl_notice("%s: notification JSON decode failed '%s'\n",
				__func__, lejp_error_to_string(n));
		lwsac_free(&a.ac);

		return 0;
	}

	// lwsl_notice("%s: schema idx %d\n", __func__, a.top_schema_index);

	switch (a.top_schema_index) {

	case SAIS_WS_WEBSRV_RX_TASKRESET:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKRESET: %s: received", ei->event_hash);
		if (sais_task_clear_build_and_logs(m->vhd, ei->event_hash, 0))
			lwsl_ss_err(m->ss, "taskreset failed");
		break;

	case SAIS_WS_WEBSRV_RX_TASKREMOVEALLTRIES:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKREMOVEALLTRIES: %s: received", ei->event_hash);
		if (sais_task_remove_all_tries(m->vhd, ei->event_hash))
			lwsl_ss_err(m->ss, "taskremovealltries failed");
		break;


	case SAIS_WS_WEBSRV_RX_TASKPAUSE:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKPAUSE: %s: received", ei->event_hash);
		if (sais_task_pause(m->vhd, ei->event_hash))
			lwsl_ss_err(m->ss, "taskpause failed");
		break;

	case SAIS_WS_WEBSRV_RX_TASKRESUME:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKRESUME: %s: received", ei->event_hash);
		if (sais_set_task_state(m->vhd, ei->event_hash, SAIES_WAITING, 0, 0))
			lwsl_ss_err(m->ss, "taskresume failed");
		else
			sais_platforms_with_tasks_pending(m->vhd);
		break;

	case SAIS_WS_WEBSRV_RX_TASKKILL:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKKILL: %s: received", ei->event_hash);
		if (sais_task_stop_on_builders(m->vhd, ei->event_hash, 1))
			lwsl_ss_err(m->ss, "taskkill failed");
		break;

	case SAIS_WS_WEBSRV_RX_TASKREBUILDLASTSTEP:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_TASKID_LEN))
			goto soft_error;

		lwsl_ss_warn(m->ss, "SAIS_WS_WEBSRV_RX_TASKREBUILDLASTSTEP: %s: received", ei->event_hash);
		if (sais_task_rebuild_last_step(m->vhd, ei->event_hash))
			lwsl_ss_err(m->ss, "taskrebuildlaststep failed");
		break;

	case SAIS_WS_WEBSRV_RX_EVENTRESET:
		ei = (sai_browse_rx_evinfo_t *)a.dest;

		if (sais_validate_id(ei->event_hash, SAI_EVENTID_LEN))
			goto soft_error;

		r = sais_event_reset(m->vhd, ei->event_hash);
		if (r)
			lwsl_ss_err(m->ss, "eventreset failed");

		break;

	case SAIS_WS_WEBSRV_RX_PLATRESET: {
		sai_browse_rx_platreset_t *pr = (sai_browse_rx_platreset_t *)a.dest;

		if (sais_validate_id(pr->event_uuid, SAI_EVENTID_LEN))
			goto soft_error;

		r = sais_plat_reset(m->vhd, pr->event_uuid, pr->platform);
		if (r)
			lwsl_ss_err(m->ss, "platreset failed");
		break;
	}
	case SAIS_WS_WEBSRV_RX_PCON_CONTROL:
	{
		sai_pcon_control_t *ctl = (sai_pcon_control_t *)a.dest;
		int count = 0;

		lwsl_warn("%s: pcon control received from web: '%s' -> %d\n",
			    __func__, ctl->pcon_name, ctl->on);

		lws_start_foreach_dll(struct lws_dll2 *, p,
				      m->vhd->sai_powers.head) {
			struct pss *pss_power = lws_container_of(p, struct pss, same);
			sai_pcon_control_t *s;

			s = malloc(sizeof(*s));
			if (s) {
				*s = *ctl;
				lws_dll2_add_tail(&s->list, &pss_power->pcon_control_owner);
				lws_callback_on_writable(pss_power->wsi);
				lwsl_wsi_warn(pss_power->wsi, "queued pcon control on power conn");
				count++;
			} else
				lwsl_err("%s: OOM queuing control\n", __func__);
		} lws_end_foreach_dll(p);

		if (!count)
			lwsl_warn("%s: No sai-power connections found to forward control to!\n", __func__);

		break;
	}

	case SAIS_WS_WEBSRV_RX_EVENTDELETE:
		ei = (sai_browse_rx_evinfo_t *)a.dest;
		if (sais_validate_id(ei->event_hash, SAI_EVENTID_LEN))
			goto soft_error;

		lwsl_notice("%s: eventdelete %s\n", __func__, ei->event_hash);

		r = sais_event_delete(m->vhd, ei->event_hash);
		if (r)
			lwsl_ss_err(m->ss, "event delete failed");
		break;

	case SAIS_WS_WEBSRV_RX_TASKCANCEL:
		can = (sai_cancel_t *)a.dest;
		if (sais_validate_id(can->task_uuid, SAI_TASKID_LEN))
			goto soft_error;

		sais_task_cancel(m->vhd, can->task_uuid, 0, 0);

		break;

	case SAIS_WS_WEBSRV_RX_VIEWERCOUNT:
		{
			sai_viewer_state_t *vs = (sai_viewer_state_t *)a.dest;
			unsigned int total_viewers = 0;
			char old_viewers_present = !!m->vhd->viewers_are_present;

			/* Store viewer count for this specific sai-web client */
			m->viewers = vs->viewers;

			/* Recalculate total from all connected sai-web clients */
			lws_ss_server_foreach_client(m->vhd->h_ss_websrv,
						     sum_viewers_cb, &total_viewers);

			m->vhd->browser_viewer_count = total_viewers;

			m->vhd->viewers_are_present = !!total_viewers;

			/*
			 * Only broadcast to builders if the state has changed
			 * from 0 viewers to >0, or from >0 viewers to 0.
			 */
			if (old_viewers_present == m->vhd->viewers_are_present)
				break;

			lws_start_foreach_dll(struct lws_dll2 *, p, m->vhd->builders.head) {
				struct pss *pss_builder = lws_container_of(p, struct pss, same);
				sai_viewer_state_t *vsend = calloc(1, sizeof(*vsend));

				if (vsend) {
					vsend->viewers = m->vhd->viewers_are_present;
					lws_dll2_add_tail(&vsend->list, &pss_builder->viewer_state_owner);
					lws_callback_on_writable(pss_builder->wsi);
				}
			} lws_end_foreach_dll(p);
			break;
		}
	case SAIS_WS_WEBSRV_RX_REBUILD:
		{
			sai_rebuild_t *reb = (sai_rebuild_t *)a.dest;
			sai_plat_t *sp;

			if (sais_validate_builder_name(reb->builder_name))
				goto soft_error;

			sp = sais_builder_from_uuid(m->vhd, reb->builder_name);
			if (!sp) {
				lwsl_info("%s: unknown builder %s for rebuild\n",
					    __func__, reb->builder_name);
				break;
			}

			/* sp->wsi is the builder connection to server */
			lws_start_foreach_dll(struct lws_dll2 *, p,
					      m->vhd->builders.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				if (pss->wsi == sp->wsi) {
					sai_rebuild_t *r = malloc(sizeof(*r));

					if (!r)
						break;
					*r = *reb;
					lws_dll2_add_tail(&r->list,
							  &pss->rebuild_owner);
					lws_callback_on_writable(pss->wsi);
					break;
				}
			} lws_end_foreach_dll(p);
		}
		break;

	case SAIS_WS_WEBSRV_RX_STAY:
	{
		sai_stay_t *stay = (sai_stay_t *)a.dest;

		lwsl_notice("%s: stay received from web\n", __func__);

		lws_start_foreach_dll(struct lws_dll2 *, p,
				      m->vhd->sai_powers.head) {
			struct pss *pss_power = lws_container_of(p, struct pss, same);
			sai_stay_t *s;

			s = malloc(sizeof(*s));
			if (s) {
				*s = *stay;
				lws_dll2_add_tail(&s->list, &pss_power->stay_owner);
				lws_callback_on_writable(pss_power->wsi);
				lwsl_wsi_notice(pss_power->wsi, "queued stay on power conn");
			}
		} lws_end_foreach_dll(p);

		break;
	}
	case SAIS_WS_WEBSRV_RX_FINDINGSET:
	{
		sai_findingset_t *fs = (sai_findingset_t *)a.dest;

		/* sai-web only forwards this from admins; checked in there */
		sais_findings_set(m->vhd, fs->repo, fs->pool, fs->group,
				  fs->op);
		break;
	}

	case SAIS_WS_WEBSRV_RX_TASKCLONE:
	{
		sai_browse_rx_taskclone_t *tc =
				(sai_browse_rx_taskclone_t *)a.dest;

		/*
		 * sai-web only forwards this from admin-authenticated
		 * browsers; validation of the fields is done in the helper
		 */
		lwsl_ss_notice(m->ss, "SAIS_WS_WEBSRV_RX_TASKCLONE: seed %s, "
				      "ref %s", tc->seed_uuid, tc->ref);
		if (sais_event_clone_task(m->vhd, tc) != SAI_DB_RESULT_OK)
			lwsl_ss_err(m->ss, "taskclone failed");
		break;
	}

	case SAIS_WS_WEBSRV_RX_OPENSHELL:
	{
		sai_openshell_t *os = (sai_openshell_t *)a.dest;
		sai_plat_t *sp;

		/*
		 * Defense-in-depth: even though this arrives on the trusted
		 * internal websrv link, validate the builder name so a
		 * malformed/leaked message cannot target an arbitrary name
		 * that is later interpolated into shell/SQL contexts on the
		 * builder.
		 */
		if (sais_validate_builder_name(os->builder_name)) {
			lwsl_notice("%s: OPENSHELL bad builder name '%s'\n",
				    __func__, os->builder_name);
			break;
		}

		lwsl_notice("%s: OPENSHELL received from web for %s, passing to builder\n", __func__, os->builder_name);

		/*
		 * The shell id must be a shell-shaped id if given, so the
		 * session we create can always be addressed (and closed) by
		 * the ptydata/closeshell validation below.
		 */
		if (os->task_uuid[0]) {
			if (sais_validate_id(os->task_uuid, SAI_SHELLID_LEN)) {
				lwsl_notice("%s: OPENSHELL bad shell id\n",
					    __func__);
				break;
			}
		} else
			sai_uuid16_create(m->vhd->context, os->task_uuid);

		/* Add it to in-memory shell sessions list */
		sai_shell_session_t *sh = malloc(sizeof(*sh));
		if (sh) {
			memset(sh, 0, sizeof(*sh));
			lws_strncpy(sh->task_uuid, os->task_uuid, sizeof(sh->task_uuid));
			lws_strncpy(sh->builder_name, os->builder_name, sizeof(sh->builder_name));
			lws_dll2_add_tail(&sh->list, &m->vhd->shell_sessions);
		}

		sp = sais_builder_from_uuid(m->vhd, os->builder_name);
		if (sp) {
			lws_start_foreach_dll(struct lws_dll2 *, p, m->vhd->builders.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				if (pss->wsi == sp->wsi) {
					sai_openshell_t *s = malloc(sizeof(*s));
					if (s) {
						*s = *os;
						lws_dll2_add_tail(&s->list, &pss->openshell_owner);
						lws_callback_on_writable(pss->wsi);
					}
					break;
				}
			} lws_end_foreach_dll(p);
		}

		sais_platforms_with_tasks_pending(m->vhd);

		break;
	}

	case SAIS_WS_WEBSRV_RX_CLOSESHELL:
	{
		sai_closeshell_t *cs = (sai_closeshell_t *)a.dest;

		if (sais_validate_id(cs->task_uuid, SAI_SHELLID_LEN)) {
			lwsl_notice("%s: CLOSESHELL bad shell id\n", __func__);
			break;
		}

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, m->vhd->shell_sessions.head) {
			sai_shell_session_t *sh = lws_container_of(d, sai_shell_session_t, list);
			if (!strcmp(sh->task_uuid, cs->task_uuid)) {
				lws_start_foreach_dll_safe(struct lws_dll2 *, pd, pd1, sh->ptydata_owner.head) {
					sai_ptydata_t *pdy = lws_container_of(pd, sai_ptydata_t, list);
					lws_dll2_remove(&pdy->list);
					if (pdy->data) free(pdy->data);
					free(pdy);
				} lws_end_foreach_dll_safe(pd, pd1);

				lws_dll2_remove(&sh->list);
				free(sh);
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		sais_task_cancel(m->vhd, cs->task_uuid, 0, 0);
		sais_platforms_with_tasks_pending(m->vhd);

		break;
	}

	case SAIS_WS_WEBSRV_RX_PTYDATA:
	{
		sai_ptydata_t *pd = (sai_ptydata_t *)a.dest;
		sai_plat_t *sp;

		/*
		 * Validate ids (not pd->data, which is opaque pty payload that
		 * must pass through to the builder's shell).
		 */
		if (sais_validate_id(pd->task_uuid, SAI_SHELLID_LEN) ||
		    sais_validate_builder_name(pd->builder_name)) {
			lwsl_notice("%s: PTYDATA bad shell id/builder\n",
				    __func__);
			break;
		}

		sp = sais_builder_from_uuid(m->vhd, pd->builder_name);
		if (!sp) {
			/* Builder offline, buffer it! */
			lws_start_foreach_dll(struct lws_dll2 *, d, m->vhd->shell_sessions.head) {
				sai_shell_session_t *sh = lws_container_of(d, sai_shell_session_t, list);
				if (!strcmp(sh->task_uuid, pd->task_uuid)) {
					sai_ptydata_t *s = malloc(sizeof(*s));
					if (s) {
						size_t slen = pd->data ? strlen(pd->data) : 0;
						*s = *pd;
						s->data = pd->data ? malloc(slen + 1) : NULL;
						if (s->data || !pd->data) {
							if (pd->data)
								memcpy((char *)s->data, pd->data, slen + 1);
							lws_dll2_add_tail(&s->list, &sh->ptydata_owner);
						} else
							free(s);
					}
					break;
				}
			} lws_end_foreach_dll(d);

			break;
		}

		// lwsl_notice("%s: PTYDATA received from web (len %d), passing to builder %s\n", __func__, (int)pd->len, pd->builder_name);

		lws_start_foreach_dll(struct lws_dll2 *, p, m->vhd->builders.head) {
			struct pss *pss = lws_container_of(p, struct pss, same);

			if (pss->wsi == sp->wsi) {
				sai_ptydata_t *s = malloc(sizeof(*s));
				if (s) {
					size_t slen = pd->data ? strlen(pd->data) : 0;
					*s = *pd;
					s->data = pd->data ? malloc(slen + 1) : NULL;
					if (s->data || !pd->data) {
						if (pd->data)
							memcpy((char *)s->data, pd->data, slen + 1);
						lws_dll2_add_tail(&s->list, &pss->ptydata_owner);
						lws_callback_on_writable(pss->wsi);
					} else
						free(s);
				}
				break;
			}
		} lws_end_foreach_dll(p);

		break;
	}

	case SAIS_WS_WEBSRV_RX_BUILDERDELETE:
	{
		sai_browse_rx_builderdelete_t *bd = (sai_browse_rx_builderdelete_t *)a.dest;
		char q[256], esc[96];

		if (sais_validate_builder_name(bd->builder_name))
			goto soft_error;

		lwsl_notice("%s: builder delete received for %s\n", __func__, bd->builder_name);

		lws_sql_purify(esc, bd->builder_name, sizeof(esc));

		lws_snprintf(q, sizeof(q), "DELETE FROM builders WHERE name = '%s'", esc);
		if (sai_sqlite3_statement(m->vhd->server.pdb, q, "delete builder"))
			lwsl_err("%s: failed to delete builder %s\n", __func__, esc);

		lws_snprintf(q, sizeof(q), "DELETE FROM pcon_builders WHERE builder_name = '%s'", esc);
		if (sai_sqlite3_statement(m->vhd->server.pdb, q, "delete pcon builder"))
			lwsl_err("%s: failed to delete pcon_builders %s\n", __func__, esc);

		/* Force broadcast of updated builders list */
		sais_list_builders(m->vhd);

		break;
	}
	}

	lwsac_free(&a.ac);

	return 0;

soft_error:
	lwsl_warn("%s: soft error\n", __func__);

	lwsac_free(&a.ac);

	return 0;
}

/*
 * Messages from sai-web are normally small enough to arrive whole, but a
 * taskclone carries an edited build script and can span several fragments.
 * websrvss_ws_rx_msg() parses one-shot, so reassemble anything that isn't
 * a complete message before handing it over.
 */
static lws_ss_state_return_t
websrvss_ws_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	websrvss_srv_t *m = (websrvss_srv_t *)userobj;
	lws_ss_state_return_t r;
	uint8_t *reasm;
	size_t rl;

	if ((flags & LWSSS_FLAG_SOM) && (flags & LWSSS_FLAG_EOM) &&
	    !m->rx_reasm)
		return websrvss_ws_rx_msg(m, buf, len, flags);

	if (flags & LWSSS_FLAG_SOM)
		/* a new message while holding fragments: discard the old */
		lws_buflist_destroy_all_segments(&m->rx_reasm);

	if (lws_buflist_total_len(&m->rx_reasm) + len >
	    SAIS_WEBSRV_RX_REASM_MAX) {
		lwsl_ss_warn(m->ss, "rx reassembly over size, dropping");
		lws_buflist_destroy_all_segments(&m->rx_reasm);

		return LWSSSSRET_OK;
	}

	if (len && lws_buflist_append_segment(&m->rx_reasm, buf, len) < 0) {
		lwsl_ss_warn(m->ss, "rx reassembly oom, dropping");
		lws_buflist_destroy_all_segments(&m->rx_reasm);

		return LWSSSSRET_OK;
	}

	if (!(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;

	rl = lws_buflist_total_len(&m->rx_reasm);
	reasm = malloc(rl);
	if (!reasm) {
		lws_buflist_destroy_all_segments(&m->rx_reasm);

		return LWSSSSRET_OK;
	}

	lws_buflist_linear_use(&m->rx_reasm, reasm, rl);
	lws_buflist_destroy_all_segments(&m->rx_reasm);

	r = websrvss_ws_rx_msg(m, reasm, rl,
			       LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
	free(reasm);

	return r;
}

static lws_ss_state_return_t
websrvss_ws_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
	       size_t *len, int *flags)
{
	websrvss_srv_t *m = (websrvss_srv_t *)userobj;

	return sai_ss_tx_from_buflist_helper(m->ss, &m->bl_srv_to_web,
					     buf, len, flags);
}


static lws_ss_state_return_t
websrvss_srv_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	websrvss_srv_t *m = (websrvss_srv_t *)userobj;

	// lwsl_user("%s: %p %s, ord 0x%x\n", __func__, m->ss,
	//	  lws_ss_state_name((int)state), (unsigned int)ack);

	switch (state) {
	case LWSSSCS_DISCONNECTED: {
		unsigned int total_viewers = 0;

		lws_buflist_destroy_all_segments(&m->bl_srv_to_web);
		lws_buflist_destroy_all_segments(&m->rx_reasm);
		lws_wsmsg_destroy(m->private_heads, LWS_ARRAY_SIZE(m->private_heads));

		m->viewers = 0;

		/* This sai-web client disconnected, recalculate total viewers */
		lws_ss_server_foreach_client(m->vhd->h_ss_websrv,
					     sum_viewers_cb, &total_viewers);

		m->vhd->browser_viewer_count = total_viewers;
		char new_viewers_present = !!total_viewers;

		if (m->vhd->viewers_are_present != new_viewers_present) {
			m->vhd->viewers_are_present = !!new_viewers_present;
			lwsl_notice("%s: A sai-web client disconnected, viewer presence changed to %d. Broadcasting.\n",
				    __func__, new_viewers_present);

			/* Broadcast new presence state to builders */
			lws_start_foreach_dll(struct lws_dll2 *, p, m->vhd->builders.head) {
				struct pss *pss_builder = lws_container_of(p, struct pss, same);
				sai_viewer_state_t *vsend = calloc(1, sizeof(*vsend));

				if (vsend) {
					vsend->viewers = (unsigned int)new_viewers_present;
					lws_dll2_add_tail(&vsend->list, &pss_builder->viewer_state_owner);
					lws_callback_on_writable(pss_builder->wsi);
				}
			} lws_end_foreach_dll(p);
		}

		break;
	}
	case LWSSSCS_CREATING:
		m->viewers = 0;
		return lws_ss_request_tx(m->ss);

	case LWSSSCS_CONNECTED:
		sais_list_builders(m->vhd);
		break;
	case LWSSSCS_ALL_RETRIES_FAILED:
		break;

	case LWSSSCS_SERVER_TXN:
		break;

	case LWSSSCS_SERVER_UPGRADE:
		break;

	default:
		break;
	}

	return 0;
}

const lws_ss_info_t ssi_server = {
	.handle_offset			= offsetof(websrvss_srv_t, ss),
	.opaque_user_data_offset	= offsetof(websrvss_srv_t, vhd),
	.streamtype			= "websrv",
	.rx				= websrvss_ws_rx,
	.tx				= websrvss_ws_tx,
	.state				= websrvss_srv_state,
	.user_alloc			= sizeof(websrvss_srv_t),
};
