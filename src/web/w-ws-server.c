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
	LSM_SCHEMA	(sai_browse_rx_evinfo_t, NULL, lsm_websrv_evinfo,
			 "com.warmcat.sai.taskactivity"),
	LSM_SCHEMA	(sai_build_metric_t, NULL, lsm_build_metric,
			 "com.warmcat.sai.build-metric"),
	LSM_SCHEMA(sai_power_managed_builders_t, NULL,
			lsm_power_managed_builders_list,
			"com.warmcat.sai.power_managed_builders"),
	LSM_SCHEMA	(sai_pcon_energy_report_t, NULL, lsm_pcon_energy_report,
			 /* shares struct */ "com.warmcat.sai.pcon_energy"),
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
};

/*
 * sai-web is receiving from sai-server
 *
 * This may come in chunks and is statefully parsed
 * so it's not directly sensitive to size or fragmentation
 */
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
			case SAIS_WS_WEBSRV_RX_LOADREPORT:
			case SAIS_WS_WEBSRV_RX_TASKACTIVITY:
			case SAIS_WS_WEBSRV_RX_SAI_BUILDERS:
			case SAIS_WS_WEBSRV_RX_POWER_MANAGED_BUILDERS:
			case SAIS_WS_WEBSRV_RX_PCON_ENERGY:
				saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(vhd, p, rem,
					lws_write_ws_flags(LWS_WRITE_TEXT,
							   is_start,
							   0)); /* Not EOM */
				break;
			default:
				// lwsl_err("%s: SWALLOWING %.*s\n", __func__, (int)len, buf);
				break;
			}

			return 0;
		}

		/* We have a completed message */
		size_t consumed = rem - (size_t)n;

		sai_browse_rx_evinfo_t *ei;

		switch (m->a.top_schema_index) {
		case SAIS_WS_WEBSRV_RX_TASKCHANGE:
		case SAIS_WS_WEBSRV_RX_EVENTCHANGE:
		case SAIS_WS_WEBSRV_RX_SAI_BUILDERS:
		case SAIS_WS_WEBSRV_RX_POWER_MANAGED_BUILDERS:
		case SAIS_WS_WEBSRV_RX_PCON_ENERGY:
		case SAIS_WS_WEBSRV_RX_LOADREPORT:
		case SAIS_WS_WEBSRV_RX_TASKACTIVITY:
			saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(vhd, p, consumed,
				lws_write_ws_flags(LWS_WRITE_TEXT,
						   is_start,
						   1)); /* Force EOM */
			break;
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

				saiw_browser_broadcast_queue_builders(pss->vhd, pss);
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
