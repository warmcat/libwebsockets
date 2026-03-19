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
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "p-private.h"


saip_pcon_t *
saip_pcon_by_name(struct sai_power *power, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, power->sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);

		if (!strcmp(pc->name, name))
			return pc;

	} lws_end_foreach_dll(p);

	return NULL;
}

saip_pcon_t *
saip_pcon_create(struct sai_power *power, const char *name)
{
	saip_pcon_t *pc = lwsac_use_zero(&power->ac_conf_head, sizeof(*pc), 4096);
	if (!pc)
		return NULL;

	pc->name = lwsac_use(&power->ac_conf_head, strlen(name) + 1, 512);
	if (!pc->name)
		return NULL;
	strcpy((char *)pc->name, name);

	lws_dll2_add_tail(&pc->list, &power->sai_pcon_owner);

	lwsl_notice("%s: Created dynamic PCON '%s'\n", __func__, name);

	return pc;
}

void
saip_switch(saip_pcon_t *pc, int on)
{
	struct lws_ss_handle *h = on ? pc->ss_tasmota_on : pc->ss_tasmota_off;
	int wol_fired = 0;

	if (on && pc->mac) {
		char buf[64];
		size_t n = (size_t)lws_snprintf(buf, sizeof(buf), "%s\n", pc->mac);

		if (write(lws_spawn_get_fd_stdxxx(lsp_wol, 0),
			      buf, n) != (ssize_t)n)
			lwsl_err("%s: Write to resume %s failed %d\n",
					__func__, pc->name, errno);
		else {
			lwsl_notice("%s: Resumed %s via WOL\n",
					__func__, pc->name);
			wol_fired = 1;
		}
	}

	if (!h) {
		if (!wol_fired) {
			if (pc->type && !strcmp(pc->type, "wol")) {
				if (on && !pc->mac)
					lwsl_err("%s: %s: WOL type but no MAC configured\n",
						 __func__, pc->name);
				else
					if (!on)
						lwsl_info("%s: %s: WOL pcon ignoring OFF\n",
							  __func__, pc->name);
			} else {
				lwsl_err("%s: %s: no ss handle for %s (type: %s, mac: %s)\n",
					 __func__, pc->name, on ? "ON" : "OFF",
					 pc->type ? pc->type : "null",
					 pc->mac ? pc->mac : "null");
			}
		}
		return;
	}

	if (lws_ss_client_connect(h))
		lwsl_ss_err(h, "failed to connect tasmota %s secure stream",
			    on ? "ON" : "OFF");
}
