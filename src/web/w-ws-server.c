/*
 * Sai web websrv - saiw SS client private link to sais SS server
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
 *   b3 --/               *      \-- browser
 *
 * We copy JSON to heap and forward it in order to sais side.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "w-private.h"

static lws_struct_map_t lsm_websrv_evinfo[] = {
	LSM_CARRAY	(sai_browse_rx_evinfo_t, event_hash,	"event_hash"),
};

/*
 * sai-server's periodic list of the tasks that are building, and how
 * recently each one produced logs.  We only need to decode it to remove the
 * tasks a vhost doesn't show, see saiw_reissue_activity()
 */

typedef struct saiw_activity {
	lws_dll2_t		list;
	char			uuid[65];
	int			cat;
} saiw_activity_t;

typedef struct saiw_activities {
	lws_dll2_owner_t	activity;
} saiw_activities_t;

static const lws_struct_map_t lsm_websrv_activity[] = {
	LSM_CARRAY	(saiw_activity_t, uuid,			"uuid"),
	LSM_SIGNED	(saiw_activity_t, cat,			"cat"),
};

static const lws_struct_map_t lsm_websrv_activities[] = {
	LSM_LIST	(saiw_activities_t, activity, saiw_activity_t, list,
			 NULL, lsm_websrv_activity,		"activity"),
};

/*
 * (Structs and maps removed - now in common/include/private.h and common/struct-metadata.c)
 */

const lws_struct_map_t lsm_schema_json_map[] = {
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_websrv_evinfo,
			/* shares struct */   "sai-taskchange"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_websrv_evinfo,
			/* shares struct */   "sai-eventchange"),
	LSM_SCHEMA	(sai_plat_owner_t, NULL, lsm_plat_list, "com.warmcat.sai.builders"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_websrv_evinfo,
			/* shares struct */   "sai-overview"),
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_websrv_evinfo,
			/* shares struct */   "sai-tasklogs"),
	LSM_SCHEMA	(sai_load_report_t, NULL, lsm_load_report_members,
			 "com.warmcat.sai.loadreport"),
	LSM_SCHEMA	(saiw_activities_t, NULL, lsm_websrv_activities,
			 "com.warmcat.sai.taskactivity"),
	LSM_SCHEMA	(sai_build_metric_t, NULL, lsm_build_metric,
			 "com.warmcat.sai.build-metric"),
	LSM_SCHEMA(sai_power_managed_builders_t, NULL,
			lsm_power_managed_builders_list,
			"com.warmcat.sai.power_managed_builders"),
	LSM_SCHEMA	(sai_pcon_energy_report_t, NULL, lsm_pcon_energy_report,
			 /* shares struct */ "com.warmcat.sai.pcon_energy"),
	LSM_SCHEMA	(sai_ptydata_t, NULL, lsm_ptydata,
			 "com.warmcat.sai.ptydata"),
};

enum {
	SAIS_WS_WEBSRV_RX_TASKCHANGE,
	SAIS_WS_WEBSRV_RX_EVENTCHANGE,
	SAIS_WS_WEBSRV_RX_SAI_BUILDERS,
	SAIS_WS_WEBSRV_RX_OVERVIEW,	/* deleted or added event */
	SAIS_WS_WEBSRV_RX_TASKLOGS,	/* new logs for task (ratelimited) */
	SAIS_WS_WEBSRV_RX_LOADREPORT,	/* builder's cpu load report */
	SAIS_WS_WEBSRV_RX_TASKACTIVITY,
	SAIS_WS_WEBSRV_RX_BUILD_METRIC,
	SAIS_WS_WEBSRV_RX_POWER_MANAGED_BUILDERS,
	SAIS_WS_WEBSRV_RX_PCON_ENERGY,
	SAIS_WS_WEBSRV_RX_PTYDATA,
};

/*
 * sai-web is receiving from sai-server
 *
 * This may come in chunks and is statefully parsed
 * so it's not directly sensitive to size or fragmentation
 */

/*
 * Reassemble ptydata rx until the message completes: the members saying
 * which browser owns the shell are only trusted once the whole message has
 * parsed, and the shell output must not be queued to anyone else in the
 * meantime.  sai-server sends these in one piece (its own serialization
 * buffer is 2KiB), so this is normally a single append.  The cap just
 * bounds what a broken or hostile peer can make us hold.
 */
#define SAIW_PTY_ACCUM_MAX (64 * 1024)

static void
saiw_pty_accum_reset(saiw_websrv_t *m)
{
	free(m->pty_accum);
	m->pty_accum	= NULL;
	m->pty_accum_len = 0;
	m->pty_dropped	 = 0;
}

static void
saiw_pty_accum_drop(saiw_websrv_t *m)
{
	free(m->pty_accum);
	m->pty_accum	= NULL;
	m->pty_accum_len = 0;
	m->pty_dropped	 = 1;
}

static int
saiw_pty_accum(saiw_websrv_t *m, const uint8_t *frag, size_t len)
{
	uint8_t *na;

	if (m->pty_dropped)
		return 0;

	if (m->pty_accum_len + len > SAIW_PTY_ACCUM_MAX) {
		lwsl_notice("%s: ptydata reassembly over size, dropping msg\n",
			    __func__);
		saiw_pty_accum_drop(m);

		return 0;
	}

	na = realloc(m->pty_accum, LWS_PRE + m->pty_accum_len + len);
	if (!na) {
		lwsl_notice("%s: ptydata reassembly oom, dropping msg\n",
			    __func__);
		saiw_pty_accum_drop(m);

		return 0;
	}

	m->pty_accum = na;
	memcpy(m->pty_accum + LWS_PRE + m->pty_accum_len, frag, len);
	m->pty_accum_len += len;

	return 0;
}

/*
 * A vhost that only shows some projects can't pass on messages that mention
 * tasks in the others as they came.  Instead it serializes the decoded
 * object, with those tasks removed, from the same schema and queues it to its
 * browsers (only ones showing builders, if builder_info).
 */

static void
saiw_reissue_to_browsers(struct vhd *vhd, int schema_idx, void *obj,
			 int builder_info)
{
	uint8_t buf[LWS_PRE + 2048], *start = buf + LWS_PRE;
	lws_struct_serialize_t *js;
	int r, fi = 1;
	size_t w;

	js = lws_struct_json_serialize_create(&lsm_schema_json_map[schema_idx],
					      1, 0, obj);
	if (!js)
		return;

	do {
		r = (int)lws_struct_json_serialize(js, start,
						   sizeof(buf) - LWS_PRE, &w);
		if (r == LSJS_RESULT_ERROR) {
			lwsl_err("%s: unable to serialize schema %d\n",
				 __func__, schema_idx);
			break;
		}

		lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
			struct pss *pss = lws_container_of(p, struct pss, same);

			if (!builder_info ||
			    (!pss->is_gitohashi && pss->wants_builder_info))
				saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss,
					start, w, lws_write_ws_flags(
						LWS_WRITE_TEXT, fi,
						r == LSJS_RESULT_FINISH));
		} lws_end_foreach_dll(p);

		fi = 0;
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);
}

static void
saiw_reissue_activity(struct vhd *vhd, saiw_activities_t *acts)
{
	char last[33] = "";
	int last_vis = 0;

	/* the list comes grouped by event, so check each event once */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   acts->activity.head) {
		saiw_activity_t *act = lws_container_of(p, saiw_activity_t,
							list);

		if (strncmp(act->uuid, last, 32)) {
			last_vis = saiw_event_visible(vhd, act->uuid);
			lws_strnncpy(last, act->uuid, 32, sizeof(last));
		}

		if (!last_vis)
			lws_dll2_remove(&act->list);
	} lws_end_foreach_dll_safe(p, p1);

	saiw_reissue_to_browsers(vhd, SAIS_WS_WEBSRV_RX_TASKACTIVITY, acts, 0);
}

static void
saiw_reissue_loadreport(struct vhd *vhd, sai_load_report_t *lr)
{
	/*
	 * The builders and their load are shared by every project, only the
	 * tasks they're building belong to one
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   lr->active_tasks.head) {
		sai_active_task_info_t *ati = lws_container_of(p,
					sai_active_task_info_t, list);

		if (!saiw_project_visible(vhd, ati->repo_name))
			lws_dll2_remove(&ati->list);
	} lws_end_foreach_dll_safe(p, p1);

	saiw_reissue_to_browsers(vhd, SAIS_WS_WEBSRV_RX_LOADREPORT, lr, 1);
}

static int
saiw_lp_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	saiw_websrv_t *m = (saiw_websrv_t *)userobj;
	struct vhd *vhd = (struct vhd *)m->opaque_data;
	int n, is_start = (flags & LWSSS_FLAG_SOM);
	const uint8_t *p = buf;
	size_t rem = len;

	// lwsl_ss_warn(m->ss, "%s: len %d, flags %d\n", __func__, (int)len, flags);
	// lwsl_hexdump_notice(buf, len);

	if (is_start) {
		/* First frag of a new message. Clear old parse results and init */
		lwsac_free(&m->a.ac);
		saiw_pty_accum_reset(m);
		memset(&m->a, 0, sizeof(m->a));
		m->a.map_st[0]		= lsm_schema_json_map;
		m->a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
		m->a.map_st[1]		= lsm_schema_json_map;
		m->a.map_entries_st[1]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
		m->a.ac_block_size	= 4096;

		lws_struct_json_init_parse(&m->ctx, NULL, &m->a);
	}

	while (rem > 0) {
		n = lejp_parse(&m->ctx, (uint8_t *)p, (int)rem);

		/* Check for fatal error OR completion without an object */
		if (n < 0 && n != LEJP_CONTINUE) {
			lwsl_notice("%s: srv->web JSON decode failed '%s' (ssflags %d)\n",
					__func__, lejp_error_to_string(n), flags);
			lwsl_hexdump_notice(p, rem);
			goto cleanup_and_disconnect;
		}

		if (n == LEJP_CONTINUE) {
			/*
			 * Also forward this fragment to browsers if the message is for them.
			 * We can check the schema index which is available after the
			 * "schema" member is parsed, even on the first fragment.
			 */
			switch (m->a.top_schema_index) {
			case SAIS_WS_WEBSRV_RX_TASKACTIVITY:
			{
				uint8_t *tmp;

				if (saiw_restricted(vhd))
					/* reissued filtered when complete */
					break;

				tmp = malloc(LWS_PRE + rem);
				if (tmp) {
					memcpy(tmp + LWS_PRE, p, rem);
					saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(vhd, tmp + LWS_PRE, rem,
						lws_write_ws_flags(LWS_WRITE_TEXT,
								   is_start,
								   0)); /* Not EOM */
					free(tmp);
				}
				break;
			}
			case SAIS_WS_WEBSRV_RX_PTYDATA:
				/*
				 * Hold the fragment until the message
				 * completes; it goes out only to the
				 * shell's owner once we know who that is
				 */
				saiw_pty_accum(m, p, rem);
				break;
			case SAIS_WS_WEBSRV_RX_LOADREPORT:
			{
				uint8_t *tmp;

				if (saiw_restricted(vhd))
					/* reissued filtered when complete */
					break;

				tmp = malloc(LWS_PRE + rem);
				if (tmp) {
					memcpy(tmp + LWS_PRE, p, rem);
					lws_start_foreach_dll(struct lws_dll2 *, pt, vhd->browsers.head) {
						struct pss *pss = lws_container_of(pt, struct pss, same);
						if (!pss->is_gitohashi && pss->wants_builder_info)
							saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, tmp + LWS_PRE, rem,
								lws_write_ws_flags(LWS_WRITE_TEXT, is_start, 0));
					} lws_end_foreach_dll(pt);
					free(tmp);
				}
				break;
			}
			default:
				// lwsl_err("%s: SWALLOWING %.*s\n", __func__, (int)len, buf);
				break;
			}

			return 0;
		}

		/* We have a completed message */
		size_t consumed = rem - (size_t)n;

		sai_browse_rx_evinfo_t *ei;

		/*
		 * This vhost's browsers hear nothing about events in projects
		 * it doesn't show
		 */
		if ((m->a.top_schema_index == SAIS_WS_WEBSRV_RX_TASKCHANGE ||
		     m->a.top_schema_index == SAIS_WS_WEBSRV_RX_EVENTCHANGE) &&
		    m->a.dest && !saiw_event_visible(vhd,
				((sai_browse_rx_evinfo_t *)m->a.dest)->event_hash))
			goto cleanup_parse_allocs;

		switch (m->a.top_schema_index) {
		case SAIS_WS_WEBSRV_RX_TASKACTIVITY:
			if (saiw_restricted(vhd)) {
				if (m->a.dest)
					saiw_reissue_activity(vhd, m->a.dest);
				break;
			}
			/* fallthru */
		case SAIS_WS_WEBSRV_RX_TASKCHANGE:
		case SAIS_WS_WEBSRV_RX_EVENTCHANGE:
		{
			uint8_t *tmp = malloc(LWS_PRE + consumed);
			if (tmp) {
				memcpy(tmp + LWS_PRE, p, consumed);
				saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(vhd, tmp + LWS_PRE, consumed,
					lws_write_ws_flags(LWS_WRITE_TEXT,
							   is_start,
							   1)); /* Force EOM */
				free(tmp);
			}
			break;
		}
		case SAIS_WS_WEBSRV_RX_PTYDATA:
		{
			/*
			 * Shell output is private to the admin session that
			 * opened the shell: queue it only to browsers that
			 * sent openshell for this task_uuid.  Reassemble the
			 * whole message first so we know the parsed members
			 * are complete and honest.
			 */
			sai_ptydata_t *pd = (sai_ptydata_t *)m->a.dest;

			saiw_pty_accum(m, p, consumed);

			if (m->pty_accum && pd && pd->task_uuid[0]) {
				lws_start_foreach_dll(struct lws_dll2 *, pt,
						      vhd->browsers.head) {
					struct pss *pss = lws_container_of(
							pt, struct pss, same);

					if (saiw_pss_owns_shell(pss,
							        pd->task_uuid))
						saiw_ws_browser_queue_REQUIRES_LWS_PRE(
							pss,
							m->pty_accum + LWS_PRE,
							m->pty_accum_len,
							lws_write_ws_flags(
								LWS_WRITE_TEXT,
								1, 1));
				} lws_end_foreach_dll(pt);
			} else
				lwsl_notice("%s: ptydata for unowned shell,"
					    " not forwarded\n", __func__);

			saiw_pty_accum_reset(m);
			break;
		}
		case SAIS_WS_WEBSRV_RX_LOADREPORT:
		{
			uint8_t *tmp;

			if (saiw_restricted(vhd)) {
				if (m->a.dest)
					saiw_reissue_loadreport(vhd, m->a.dest);
				break;
			}

			tmp = malloc(LWS_PRE + consumed);
			if (tmp) {
				memcpy(tmp + LWS_PRE, p, consumed);
				lws_start_foreach_dll(struct lws_dll2 *, pt, vhd->browsers.head) {
					struct pss *pss = lws_container_of(pt, struct pss, same);
					if (!pss->is_gitohashi && pss->wants_builder_info)
						saiw_ws_browser_queue_REQUIRES_LWS_PRE(pss, tmp + LWS_PRE, consumed,
							lws_write_ws_flags(LWS_WRITE_TEXT, is_start, 1));
				} lws_end_foreach_dll(pt);
				free(tmp);
			}
			break;
		}
		}

		/*
		 * If we get here, the message is fully parsed (n >= 0).
		 * Now we can safely process m->a.dest.
		 */
		if (!m->a.dest) {
			lwsl_warn("%s: JSON parsed but produced no object\n", __func__);
			goto cleanup_parse_allocs;
		}

		switch (m->a.top_schema_index) {

		case SAIS_WS_WEBSRV_RX_TASKCHANGE:
			ei = (sai_browse_rx_evinfo_t *)m->a.dest;
			lwsl_notice("%s: TASKCHANGE %s\n", __func__, ei->event_hash);
			saiw_browsers_task_state_change(vhd, ei->event_hash);
			break;

		case SAIS_WS_WEBSRV_RX_EVENTCHANGE:
			ei = (sai_browse_rx_evinfo_t *)m->a.dest;
			lwsl_notice("%s: EVENTCHANGE %s\n", __func__, ei->event_hash);
			saiw_event_state_change(vhd, ei->event_hash);
			break;

		case SAIS_WS_WEBSRV_RX_SAI_BUILDERS:
			lwsac_free(&vhd->builders);
			lws_dll2_owner_clear(&vhd->builders_owner);
			vhd->builders = m->a.ac;
			m->a.ac = NULL; /* The vhd now owns this memory */

			/* Move the parsed objects to the vhd's list */
			lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
						   ((sai_plat_owner_t *)m->a.dest)->plat_owner.head) {
				sai_plat_t *sp = lws_container_of(p, sai_plat_t, sai_plat_list);

				lws_dll2_remove(&sp->sai_plat_list);
				lws_dll2_add_tail(&sp->sai_plat_list, &vhd->builders_owner);
			} lws_end_foreach_dll_safe(p, p1);

			/* schedule emitting the builder summary to each browser */
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				if (!pss->is_gitohashi)
					saiw_browser_broadcast_queue_builders(pss->vhd, pss);
			} lws_end_foreach_dll(p);
			break;

		case SAIS_WS_WEBSRV_RX_POWER_MANAGED_BUILDERS:
			lwsac_free(&vhd->pcons);
			lws_dll2_owner_clear(&vhd->pcons_owner);
			vhd->pcons = m->a.ac;
			m->a.ac = NULL; /* The vhd now owns this memory */

			/* Move the parsed objects to the vhd's list */
			lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
						   ((sai_power_managed_builders_t *)m->a.dest)->power_controllers.head) {
				sai_power_controller_t *pc = lws_container_of(p, sai_power_controller_t, list);

				lws_dll2_remove(&pc->list);
				lws_dll2_add_tail(&pc->list, &vhd->pcons_owner);
			} lws_end_foreach_dll_safe(p, p1);

			/* schedule emitting the builder summary to each browser */
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				if (!pss->is_gitohashi)
					saiw_browser_broadcast_queue_pcons(pss->vhd, pss);
			} lws_end_foreach_dll(p);
			break;

		case SAIS_WS_WEBSRV_RX_PCON_ENERGY:
			saiw_update_global_power_history(vhd, (sai_pcon_energy_report_t *)m->a.dest);
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				if (!pss->is_gitohashi) {
					saiw_browser_broadcast_queue_power_history(pss->vhd, pss);
					saiw_browser_broadcast_queue_pcon_energy(pss->vhd, pss, (sai_pcon_energy_report_t *)m->a.dest);
				}
			} lws_end_foreach_dll(p);
			break;

		case SAIS_WS_WEBSRV_RX_OVERVIEW:
			lwsl_notice("%s: force overview\n", __func__);
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->browsers.head) {
				struct pss *pss = lws_container_of(p, struct pss, same);

				saiw_browser_queue_overview(pss->vhd, pss);
			} lws_end_foreach_dll(p);
			break;

		case SAIS_WS_WEBSRV_RX_TASKLOGS:
			ei = (sai_browse_rx_evinfo_t *)m->a.dest;
			lws_start_foreach_dll(struct lws_dll2 *, p, vhd->subs_owner.head) {
				struct pss *pss = lws_container_of(p, struct pss, subs_list);
				if (!strcmp(pss->sub_task_uuid, ei->event_hash))
					saiw_broadcast_logs_batch(vhd, pss);
			} lws_end_foreach_dll(p);
			break;
		}

cleanup_parse_allocs:
		/*
		 * Free the memory used for THIS parse.
		 * In the BUILDERS case, m->a.ac was transferred to vhd->builders,
		 * so it will be NULL here and lwsac_free is a no-op.
		 */
		lwsac_free(&m->a.ac);

		/* Advance to next part of buffer */
		p += consumed;
		rem = (size_t)n; // unused bytes

		if (rem > 0) {
			/* Prepare for next message */
			memset(&m->a, 0, sizeof(m->a));
			m->a.map_st[0]		= lsm_schema_json_map;
			m->a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
			m->a.map_st[1]		= lsm_schema_json_map;
			m->a.map_entries_st[1]	= LWS_ARRAY_SIZE(lsm_schema_json_map);
			m->a.ac_block_size	= 4096;

			lws_struct_json_init_parse(&m->ctx, NULL, &m->a);
			
			/* Subsequent messages in same packet are always new Starts */
			is_start = 1;
		}
	}

	return 0;

cleanup_and_disconnect:
	lwsac_free(&m->a.ac);
	return LWSSSSRET_DISCONNECT_ME;
}


static int
saiw_lp_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	     int *flags)
{
	saiw_websrv_t *m = (saiw_websrv_t *)userobj;

	return sai_ss_tx_from_buflist_helper(m->ss, &m->wbltx, buf, len, flags);
}

static int
saiw_lp_state(void *userobj, void *sh, lws_ss_constate_t state,
	        lws_ss_tx_ordinal_t ack)
{
	saiw_websrv_t *m = (saiw_websrv_t *)userobj;
	struct vhd *vhd = (struct vhd *)m->opaque_data;

	lwsl_info("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name((int)state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_DESTROYING:
		saiw_pty_accum_reset(m);
		break;

	case LWSSSCS_CONNECTED:
		lwsl_info("%s: connected to websrv uds\n", __func__);
		return lws_ss_request_tx(m->ss);

	case LWSSSCS_DISCONNECTED:
		lws_buflist_destroy_all_segments(&m->wbltx);
		lwsac_detach(&vhd->builders);
		break;

	case LWSSSCS_ALL_RETRIES_FAILED:
		return lws_ss_client_connect(m->ss);

	case LWSSSCS_QOS_ACK_REMOTE:
		break;

	default:
		break;
	}

	return 0;
}

const lws_ss_info_t ssi_saiw_websrv = {
	.handle_offset		 = offsetof(saiw_websrv_t, ss),
	.opaque_user_data_offset = offsetof(saiw_websrv_t, opaque_data),
	.rx			 = saiw_lp_rx,
	.tx			 = saiw_lp_tx,
	.state			 = saiw_lp_state,
	.user_alloc		 = sizeof(saiw_websrv_t),
	.streamtype		 = "websrv"
};

/*
 * This function calculates the current number of connected browsers and
 * sends an update to the sai-server.
 */
void
saiw_update_viewer_count(struct vhd *vhd)
{
	sai_viewer_state_t vs;
	char buf[LWS_PRE + 256];
	size_t len;

	if (!vhd || !vhd->h_ss_websrv)
		return;

	/* The count is simply the number of items in the browsers list */
	vs.viewers = (unsigned int)vhd->browsers.count;

	const lws_struct_map_t lsm_viewercount_members[] = {
		LSM_UNSIGNED(sai_viewer_state_t, viewers,	"count"),
	};

	const lws_struct_map_t lsm_schema_json_map[] = {
		LSM_SCHEMA	(sai_viewer_state_t,	 NULL, lsm_viewercount_members,
						      "com.warmcat.sai.viewercount"),
	};

	lws_struct_serialize_t *js = lws_struct_json_serialize_create(
			lsm_schema_json_map, LWS_ARRAY_SIZE(lsm_schema_json_map),
			0, &vs);
	if (!js)
		return;

	len = 0;
	lws_struct_json_serialize(js, (unsigned char *)buf + LWS_PRE,
				      sizeof(buf) - LWS_PRE, &len);
	lws_struct_json_serialize_destroy(&js);

	if (len > 0)
		sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(vhd->h_ss_websrv,
			&((saiw_websrv_t *)lws_ss_to_user_object(vhd->h_ss_websrv))->wbltx,
			buf + LWS_PRE, len, LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
}
