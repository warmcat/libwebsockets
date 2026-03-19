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
 * This is the SS link used to communicate with smartplugs (currently
 * tasmota only supported)
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "p-private.h"

LWS_SS_USER_TYPEDEF
} saip_smartplug_t;

static lws_ss_state_return_t
saip_spc_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	saip_smartplug_t *pss = (saip_smartplug_t *)userobj;
	saip_pcon_t *pc = (saip_pcon_t *)lws_ss_opaque_from_user(pss);
	tasmota_parse_t tp;
	struct lws_ss_handle *h = lws_ss_from_user(pss);

	/* We only care about rx on the monitor channel */
	if (h != pc->ss_tasmota_monitor)
		return 0;

	if (pc->monitor_rx_pos + len > sizeof(pc->monitor_rx_buf) - 1) {
		lwsl_warn("%s: monitor rx buffer overflow\n", __func__);
		pc->monitor_rx_pos = 0;
		return 0;
	}

	memcpy(pc->monitor_rx_buf + pc->monitor_rx_pos, buf, len);
	pc->monitor_rx_pos += len;

	if (flags & LWSSS_FLAG_EOM) {
		pc->monitor_rx_buf[pc->monitor_rx_pos] = '\0';

		// lwsl_notice("%s: monitor rx: %s\n", __func__, pc->monitor_rx_buf);

		memset(&tp, 0, sizeof(tp));
		lws_tokenize_init(&tp.ts, pc->monitor_rx_buf,
				  LWS_TOKENIZE_F_NO_FLOATS |
				  LWS_TOKENIZE_F_MINUS_NONTERM);

		int parse_ret = saip_parse_tasmota_status(&tp);
		if (parse_ret == 1) {
			/* Success, update latest data and timestamp */
			pc->latest_data = tp.td;
			pc->last_monitor_time = lws_now_usecs();
			// lwsl_notice("%s: Parsed Tasmota data for %s: %u W, %u V\n",
			//	    __func__, pc->name, pc->latest_data.active_power_w, pc->latest_data.voltage_v);
		} else
			lwsl_warn("%s: Failed to parse Tasmota data for %s (ret %d)\n", __func__, pc->name, parse_ret);
		

		pc->monitor_rx_pos = 0;
	}

	return 0;
}

static lws_ss_state_return_t
saip_spc_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	saip_smartplug_t *pss = (saip_smartplug_t *)userobj;
	saip_pcon_t *pc = (saip_pcon_t *)lws_ss_opaque_from_user(pss);
	const char *op_url = NULL;

	if (lws_ss_from_user(pss) == pc->ss_tasmota_on)
		op_url = pc->url_on;
	else if (lws_ss_from_user(pss) == pc->ss_tasmota_off)
		op_url = pc->url_off;
	else if (lws_ss_from_user(pss) == pc->ss_tasmota_monitor)
		op_url = pc->url_monitor;

	// lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name((int)state),
	//	  (unsigned int)ack);

	switch (state) {

	case LWSSSCS_CREATING:
		if (!op_url) {
			lwsl_err("%s: creating unknown SS\n", __func__);
			return LWSSSSRET_DISCONNECT_ME;
		}
		// lwsl_notice("%s: binding ss to %s\n", __func__, op_url);

		if (lws_ss_set_metadata(lws_ss_from_user(pss),
					"url", op_url, strlen(op_url)))
			lwsl_warn("%s: unable to set metadata\n", __func__);
		break;

	case LWSSSCS_CONNECTED:
		/* If this is a monitor connection, we might want to reset the buffer */
		if (lws_ss_from_user(pss) == pc->ss_tasmota_monitor) {
			pc->monitor_rx_pos = 0;
			/* Note: SS with "GET" method will automatically send request */
		}
		return lws_ss_request_tx(lws_ss_from_user(pss));

	default:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power_smartplug", saip_smartplug_t)
	.state = saip_spc_state,
	.rx = saip_spc_rx,
};

void
saip_ss_create_tasmota()
{
	/* let's create any needed tasmota ss */

	lws_start_foreach_dll(struct lws_dll2 *, px, power.sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(px, saip_pcon_t, list);

		if (pc->type && !strcmp(pc->type, "tasmota") && pc->url) {
			lws_snprintf(pc->url_on, sizeof(pc->url_on),
				     "%s/cm?cmnd=Power%%20On", pc->url);
			if (lws_ss_create(power.context, 0, &ssi_saip_smartplug_t,
					  (void *)pc,
					  &pc->ss_tasmota_on, NULL, NULL))
				lwsl_err("%s: %s: failed to create ON smartplug secure stream %s\n",
					 __func__, pc->name, pc->url_on);

			lws_snprintf(pc->url_off, sizeof(pc->url_off),
				     "%s/cm?cmnd=Power%%20Off", pc->url);
			if (lws_ss_create(power.context, 0, &ssi_saip_smartplug_t,
					  (void *)pc,
					  &pc->ss_tasmota_off, NULL, NULL))
				lwsl_err("%s: %s: failed to create OFF smartplug secure stream %s\n",
					 __func__, pc->name, pc->url_off);

			lws_snprintf(pc->url_monitor, sizeof(pc->url_monitor),
				     "%s/?m=1", pc->url);
			if (lws_ss_create(power.context, 0, &ssi_saip_smartplug_t,
					  (void *)pc,
					  &pc->ss_tasmota_monitor, NULL, NULL))
				lwsl_err("%s: %s: failed to create MONITOR smartplug secure stream %s\n",
					 __func__, pc->name, pc->url_monitor);
			else
				lwsl_ss_warn(pc->ss_tasmota_monitor, "============================ creating monitor SS for %s", pc->url_monitor);
		}

	} lws_end_foreach_dll(px);
}
