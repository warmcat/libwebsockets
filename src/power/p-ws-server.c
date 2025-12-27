/*
 * sai-power com-warmcat-sai client protocol implementation
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
 * This is the part of sai-power that handles communication with sai-server
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#include "p-private.h"

extern void saip_switch(saip_pcon_t *pc, int on);

/* Map for the "powering up" message we send to the server */
static const lws_struct_map_t lsm_schema_power_state[] = {
	LSM_SCHEMA(sai_power_state_t, NULL, lsm_power_state,
		   "com.warmcat.sai.powerstate"),
};

/*
 * (Structs and maps removed - now in common/include/private.h and common/struct-metadata.c)
 */

int
saip_queue_energy_report(saip_server_t *sps)
{
	sai_pcon_energy_report_t report;
	struct lwsac *ac = NULL;
	saip_server_link_t *m;
	int r = 0;
	int count = 0;

	if (!sps->ss)
		return 0;

	m = (saip_server_link_t *)lws_ss_to_user_object(sps->ss);

	memset(&report, 0, sizeof(report));

	lws_start_foreach_dll(struct lws_dll2 *, p, power.sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);

		/* Only include if we have valid data (checked within last 60s?) */
		if (pc->last_monitor_time &&
		    lws_now_usecs() - pc->last_monitor_time < 60 * LWS_US_PER_SEC) {
			sai_pcon_energy_report_item_t *item =
				lwsac_use_zero(&ac, sizeof(*item), 1024);

			if (item) {
				lws_strncpy(item->name, pc->name, sizeof(item->name));
				item->data = pc->latest_data;
				lws_dll2_add_tail(&item->list, &report.items);
				count++;
			}
		} else {
			if (pc->last_monitor_time)
				lwsl_notice("%s: Stale monitor data for %s (age %llus)\n", __func__, pc->name, (unsigned long long)(lws_now_usecs() - pc->last_monitor_time) / LWS_US_PER_SEC);
			else
				lwsl_notice("%s: No monitor data for %s\n", __func__, pc->name);
		}
	} lws_end_foreach_dll(p);

	if (count) {
		lwsl_notice("%s: Queuing energy report with %d items\n", __func__, count);
		r = sai_ss_serialize_queue_helper(sps->ss, &m->bl_pwr_to_srv,
						  lsm_schema_pcon_energy,
						  LWS_ARRAY_SIZE(lsm_schema_pcon_energy),
						  &report);
	}

	lwsac_free(&ac);
	return r;
}

void
saip_notify_server_power_state(const char *pcon_name, int up, int down)
{
	saip_server_link_t *m;
	sai_power_state_t ps;
	saip_server_t *sps;

	/* Find the first (usually only) configured sai-server connection */
	if (!power.sai_server_owner.head) {
		lwsl_warn("%s: No sai-server configured to notify\n", __func__);
		return;
	}
	sps = lws_container_of(power.sai_server_owner.head, saip_server_t, list);
	if (!sps->ss) {
		lwsl_warn("%s: Not connected to sai-server to notify\n", __func__);
		return;
	}

	m = (saip_server_link_t *)lws_ss_to_user_object(sps->ss);

	memset(&ps, 0, sizeof(ps));

	lws_strncpy(ps.host, pcon_name, sizeof(ps.host));
	ps.powering_up		= (char)up;
	ps.powering_down	= (char)down;

	sai_ss_serialize_queue_helper(sps->ss, &m->bl_pwr_to_srv,
				      lsm_schema_power_state,
				      LWS_ARRAY_SIZE(lsm_schema_power_state),
				      &ps);
}

int
saip_queue_stay_info(saip_server_t *sps)
{
	sai_power_managed_builders_t pmb;
	struct lwsac *ac = NULL;
	saip_server_link_t *m;
	int r;

	/* lwsl_ss_notice(sps->ss, "@@@@@@@@@@@@@@ sai-power CONNECTED to server"); */

	m = (saip_server_link_t *)lws_ss_to_user_object(sps->ss);

	memset(&pmb, 0, sizeof(pmb));

	/* Send the PCON configuration and connected builders */

	lws_start_foreach_dll(struct lws_dll2 *, p, power.sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);
		sai_power_controller_t *pc1 = lwsac_use_zero(&ac, sizeof(*pc1), 2048);

		if (pc1 && pc->name) {
			lws_strncpy(pc1->name, pc->name, sizeof(pc1->name));
			pc1->on		= pc->on;
			if (pc->depends_on)
				lws_strncpy(pc1->depends_on, pc->depends_on, sizeof(pc1->depends_on));
			if (pc->type)
				lws_strncpy(pc1->type, pc->type, sizeof(pc1->type));

			lws_dll2_add_tail(&pc1->list, &pmb.power_controllers);

			/* Attach registered builders */
			lws_start_foreach_dll(struct lws_dll2 *, p1,
					      pc->registered_builders_owner.head) {
				saip_builder_t *sb = lws_container_of(p1,
						saip_builder_t, list);
				sai_controlled_builder_t *c = lwsac_use_zero(&ac,
							      sizeof(*c), 2048);

				if (c) {
					lws_strncpy(c->name, sb->name, sizeof(c->name));

					lws_dll2_add_tail(&c->list,
						&pc1->controlled_builders_owner);
				}
			} lws_end_foreach_dll(p1);
		}
	} lws_end_foreach_dll(p);

	/* The 'builders' list in pmb was for "power managed builders" (legacy).
	 * We now put builders *inside* power controllers.
	 * So we leave pmb.builders empty.
	 */

	r = sai_ss_serialize_queue_helper(sps->ss, &m->bl_pwr_to_srv,
				          lsm_schema_power_managed_builders,
				          LWS_ARRAY_SIZE(lsm_schema_power_managed_builders),
				          &pmb);
	lwsac_free(&ac);

	return r;
}

static lws_ss_state_return_t
saip_m_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	saip_server_link_t *pss = (saip_server_link_t *)userobj;
	saip_server_t *sps = (saip_server_t *)lws_ss_opaque_from_user(pss);
	lws_struct_args_t a;
	struct lejp_ctx ctx;

	lwsl_notice("%s: len %d, flags: %d (saip_server_t %p)\n", __func__, (int)len, flags, (void *)sps);
	lwsl_hexdump_notice(buf, len);
	/* lwsl_hexdump_notice(buf, len); */

	memset(&a, 0, sizeof(a));
	a.map_st[0] = lsm_schema_stay;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_schema_stay);
	a.map_st[1] = lsm_schema_pcon_control;
	a.map_entries_st[1] = LWS_ARRAY_SIZE(lsm_schema_pcon_control);
	a.ac_block_size = 512;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	if (lejp_parse(&ctx, (uint8_t *)buf, (int)len) >= 0 && a.dest) {

		if (a.top_schema_index == 1) {
			/* PCON Control */
			sai_pcon_control_t *ctl = (sai_pcon_control_t *)a.dest;
			saip_pcon_t *pc = saip_pcon_by_name(&power, ctl->pcon_name);

			if (pc) {
				lwsl_notice("%s: PCON Control '%s' -> %d\n", __func__, pc->name, ctl->on);
				pc->user_keep_on = ctl->on;
				if (ctl->on) {
					saip_switch(pc, 1);
				} else {
					saip_pcon_start_check();
				}
			} else {
				lwsl_warn("%s: Unknown PCON '%s'\n", __func__, ctl->pcon_name);
			}
		} else {
			/* Stay */
			sai_stay_t *stay = (sai_stay_t *)a.dest;

			// {"schema":"com.warmcat.sai.power.stay","builder_name":"ubuntu_rpi4","stay_on":1}

			lwsl_warn("%s: received stay %s: %d\n", __func__, stay->builder_name, stay->stay_on);

			/*
			 * We received a stay request for a builder.
			 * We need to find which PCON controls this builder and update its manual_stay.
			 * But wait, 'sai_stay_t' is typically per-builder.
			 * We should map this back to the PCON.
			 */

			lws_start_foreach_dll(struct lws_dll2 *, p, power.sai_pcon_owner.head) {
				saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);
				lws_start_foreach_dll(struct lws_dll2 *, b_node, pc->registered_builders_owner.head) {
					saip_builder_t *sb = lws_container_of(b_node, saip_builder_t, list);
					if (!strcmp(sb->name, stay->builder_name)) {
						lwsl_notice("%s: Mapping stay for builder '%s' to PCON '%s'\n",
							    __func__, sb->name, pc->name);
						/* Update PCON stay state */
						pc->server_requested_on = stay->stay_on;

						/* If stay is cleared, schedule power off check */
						if (!stay->stay_on)
							saip_pcon_start_check();
						else {
							/* If stay is set, ensure it is on immediately */
							saip_switch(pc, 1);
						}
						goto found;
					}
				} lws_end_foreach_dll(b_node);
			} lws_end_foreach_dll(p);
		}

found:
		lwsac_free(&a.ac);
		return 0;
	}
	lwsac_free(&a.ac);

	/*
	 * The old logic parsed comma-separated platform names to determine needed state.
	 * We are moving away from that. Sai-server should explicitly request power state
	 * or we should rely on the builder being "needed" implies PCON on.
	 * Actually, the requirement said: "You can no longer ask that a platform stays on, instead, you ask that the power controller stays on"
	 * So sai-server might send stay requests for PCONs directly if we update the UI.
	 * But for now, sai-server logic (s-power.c) sends stay for *builders*.
	 * So the mapping logic above is correct for transition.
	 */

	return 0;
}

static lws_ss_state_return_t
saip_m_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	  int *flags)
{
	saip_server_link_t *pss = (saip_server_link_t *)userobj;
	lws_ss_state_return_t r;

	/*
	 * helper fills tx with next buflist content, and asks to write again
	 * if any left.
	 */

	r = sai_ss_tx_from_buflist_helper(pss->ss, &pss->bl_pwr_to_srv,
					  buf, len, flags);

	if (r == LWSSSSRET_OK)
		sai_dump_stderr(buf, *len);

	return r;
}

static int
cleanup_on_ss_destroy(struct lws_dll2 *d, void *user)
{
	saip_server_link_t *pss = (saip_server_link_t *)user;
	saip_server_t *sps = (saip_server_t *)lws_ss_opaque_from_user(pss);

	(void)sps;


	return 0;
}

static int
cleanup_on_ss_disconnect(struct lws_dll2 *d, void *user)
{
	return 0;
}

static lws_ss_state_return_t
saip_m_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	saip_server_link_t *pss = (saip_server_link_t *)userobj;
	saip_server_t *sps = (saip_server_t *)lws_ss_opaque_from_user(pss);
	const char *pq;
	int n;

	// lwsl_info("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
	//	  (unsigned int)ack);

	switch (state) {

	case LWSSSCS_CREATING:

		lwsl_info("%s: binding ss to %p %s\n", __func__, sps, sps->url);

		if (lws_ss_set_metadata(sps->ss, "url", sps->url, strlen(sps->url)))
			lwsl_warn("%s: unable to set metadata\n", __func__);

		pq = sps->url;
		while (*pq && (pq[0] != '/' || pq[1] != '/'))
			pq++;

		if (*pq) {
			n = 0;
			pq += 2;
			while (pq[n] && pq[n] != '/')
				n++;
		} else {
			pq = sps->url;
			n = (int)strlen(pq);
		}
		break;

	case LWSSSCS_DESTROYING:
		lws_dll2_foreach_safe(&power.sai_server_owner, sps,
				      cleanup_on_ss_destroy);
		break;

	case LWSSSCS_CONNECTED:
		lwsl_ss_notice(sps->ss, "@@@@@@@@@@@@@@ sai-power CONNECTED to server");
		saip_queue_stay_info(sps);
		break;

	case LWSSSCS_DISCONNECTED:
		lws_buflist_destroy_all_segments(&pss->bl_pwr_to_srv);
		lwsl_info("%s: DISCONNECTED\n", __func__);
		lws_dll2_foreach_safe(&power.sai_server_owner, sps,
				      cleanup_on_ss_disconnect);
		break;

	case LWSSSCS_ALL_RETRIES_FAILED:
		lwsl_info("%s: LWSSSCS_ALL_RETRIES_FAILED\n", __func__);
		return lws_ss_request_tx(sps->ss);

	case LWSSSCS_QOS_ACK_REMOTE:
		lwsl_info("%s: LWSSSCS_QOS_ACK_REMOTE\n", __func__);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power", saip_server_link_t)
	.rx		= saip_m_rx,
	.state		= saip_m_state,
	.tx		= saip_m_tx,
};
