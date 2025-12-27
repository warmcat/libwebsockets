/*
 * sai-power
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
 *  This is the h1 API that can be used on the LAN side
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(__linux__)
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/stat.h>	/* for mkdir() */
#include <unistd.h>	/* for chown() */
#endif

#include "p-private.h"

extern struct lws_spawn_piped *lsp_wol;

extern struct sai_power power;


static void
saip_sul_action_power_off(struct lws_sorted_usec_list *sul)
{
	saip_pcon_t *pc = lws_container_of(sul, saip_pcon_t, sul_delay_off);
	lws_ss_state_return_t r;

	saip_notify_server_power_state(pc->name, 0, 1);

	lwsl_warn("%s: powering OFF pcon %s\n", __func__, pc->name);

	/* If type is WOL, we might suspend? Or nothing for now. */
	if (pc->ss_tasmota_off) {
		r = lws_ss_client_connect(pc->ss_tasmota_off);
		if (r)
			lwsl_ss_err(pc->ss_tasmota_off, "failed to connect tasmota OFF secure stream: %d", r);
	}
}

saip_pcon_t *
find_pcon_by_builder_name(struct sai_power *pwr, const char *builder_name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, pwr->sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);

		lws_start_foreach_dll(struct lws_dll2 *, b_node, pc->registered_builders_owner.head) {
			saip_builder_t *sb = lws_container_of(b_node, saip_builder_t, list);

			lwsl_notice("%s: %s %s\n", __func__, sb->name, builder_name);

			if (!strcmp(sb->name, builder_name))
				return pc;

		} lws_end_foreach_dll(b_node);
	} lws_end_foreach_dll(p);

	return NULL;
}

/* Helper to find PCON by name */
saip_pcon_t *
find_pcon(struct sai_power *pwr, const char *pcon_name)
{
	return saip_pcon_by_name(pwr, pcon_name);
}

void
saip_builder_bringup(saip_server_t *sps, saip_pcon_t *pc)
{
	saip_notify_server_power_state(pc->name, 1, 0);

	if (pc->type && !strcmp(pc->type, "wol")) {
		if (pc->mac) {
			lwsl_notice("%s:   triggering WOL for %s\n", __func__, pc->name);
			write(lws_spawn_get_fd_stdxxx(lsp_wol, 0),
			      pc->mac, strlen(pc->mac));
		} else {
			lwsl_err("%s: WOL type but no MAC for %s\n", __func__, pc->name);
		}
	}

	if (pc->ss_tasmota_on) {
		lwsl_ss_notice(pc->ss_tasmota_on, "starting tasmota");
		if (lws_ss_client_connect(pc->ss_tasmota_on))
			lwsl_ss_err(pc->ss_tasmota_on, "failed to connect tasmota ON secure stream");
	}

	saip_queue_stay_info(sps);
}

void
saip_notify_server_stay_state(const char *builder_name, int stay_on)
{
	sai_stay_state_update_t ssu;
	saip_server_link_t *m;
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

	memset(&ssu, 0, sizeof(ssu));
	lws_strncpy(ssu.builder_name, builder_name, sizeof(ssu.builder_name));
	ssu.stay_on = (char)stay_on;

	sai_ss_serialize_queue_helper(sps->ss, &m->bl_pwr_to_srv,
				      lsm_schema_stay_state_update,
				      LWS_ARRAY_SIZE(lsm_schema_stay_state_update),
				      &ssu);
}

void
saip_set_stay(const char *builder_name, int stay_on)
{
	saip_pcon_t *pc = find_pcon_by_builder_name(&power, builder_name);
	/* saip_server_link_t *pss; */ /* Unused? */
	saip_server_t *sps;

	if (!pc) {
		lwsl_warn("%s: Unknown builder %s\n", __func__, builder_name);
		return;
	}

	sps = lws_container_of(power.sai_server_owner.head, saip_server_t, list);
	/* pss = (saip_server_link_t *)lws_ss_to_user_object(sps->ss); */

	pc->user_keep_on = (char)stay_on;
	saip_notify_server_stay_state(builder_name, stay_on | pc->needed);

	/* Trigger state re-eval */
	saip_pcon_start_check();

	if (stay_on | pc->needed) {
		/* Ensure it's on immediately if needed */
		saip_builder_bringup(sps, pc);
	} else {
		/* Cancel pending off */
		lws_sul_cancel(&pc->sul_delay_off);
	}

	saip_queue_stay_info(sps);
}

/*
 * local-side h1 server for builders to connect to
 */

LWS_SS_USER_TYPEDEF
        char                    payload[200];
        size_t                  size;
        size_t                  pos;
	struct lws_struct_args	a;
	struct lejp_ctx		ctx;
	saip_builder_t		*b;
} local_srv_t;

static lws_ss_state_return_t
local_srv_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
            int *flags)
{
        local_srv_t *g = (local_srv_t *)userobj;
        lws_ss_state_return_t r = LWSSSSRET_OK;

        if (g->size == g->pos)
                return LWSSSSRET_TX_DONT_SEND;

        if (*len > g->size - g->pos)
                *len = g->size - g->pos;

        if (!g->pos)
                *flags |= LWSSS_FLAG_SOM;

        memcpy(buf, g->payload + g->pos, *len);
        g->pos += *len;

        if (g->pos != g->size) /* more to do */
                r = lws_ss_request_tx(lws_ss_from_user(g));
        else
                *flags |= LWSSS_FLAG_EOM;

        lwsl_ss_info(lws_ss_from_user(g), "TX %zu, flags 0x%x, r %d", *len,
                                          (unsigned int)*flags, (int)r);

        return r;
}

static lws_ss_state_return_t
local_srv_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	local_srv_t *g = (local_srv_t *)userobj;
	struct lws_ss_handle *h = lws_ss_from_user(g);
	saip_builder_t *b;
	saip_pcon_t *pc;

	lwsl_err("%s: %%%%%%%%%%%%%%%%%%%%%% %.*s\n", __func__, (int)len, (const char *)buf);

	if (!g->ctx.user) { /* first time */
		memset(&g->a, 0, sizeof(g->a));

		g->a.map_st[0]		= lsm_schema_builder_registration;
		g->a.map_entries_st[0] 	= LWS_ARRAY_SIZE(lsm_schema_builder_registration);
		g->a.ac_block_size	= 2048;

		lws_struct_json_init_parse(&g->ctx, NULL, &g->a);
	}

	/*
	 * Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0000: 7B 22 73 63 68 65 6D 61 22 3A 22 63 6F 6D 2E 77    {"schema":"com.w
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0010: 61 72 6D 63 61 74 2E 73 61 69 2E 62 75 69 6C 64    armcat.sai.build
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0020: 65 72 5F 72 65 67 69 73 74 72 61 74 69 6F 6E 22    er_registration"
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0030: 2C 22 70 6C 61 74 66 6F 72 6D 73 22 3A 5B 7B 22    ,"platforms":[{"
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0040: 6E 61 6D 65 22 3A 22 66 72 65 65 62 73 64 2E 66    name":"freebsd.f
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0050: 72 65 65 62 73 64 2F 61 61 72 63 68 36 34 2F 6C    reebsd/aarch64/l
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0060: 6C 76 6D 22 7D 5D 2C 22 62 75 69 6C 64 65 72 5F    lvm"}],"builder_
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0070: 6E 61 6D 65 22 3A 22 66 72 65 65 62 73 64 22 2C    name":"freebsd",
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0080: 22 70 6F 77 65 72 5F 63 6F 6E 74 72 6F 6C 6C 65    "power_controlle
	Dec 02 05:45:31 warmcat.com sai-power[2690328]: 0090: 72 5F 6E 61 6D 65 22 3A 22 70 31 22 7D             r_name":"p1"}
	 *
	 */

	if (lejp_parse(&g->ctx, buf, (int)len) < 0 || !g->a.dest) {
		lwsl_ss_warn(h, "JSON decode failed");
		lwsac_free(&g->a.ac);
		return LWSSSSRET_DISCONNECT_ME;
	}

	if (g->a.top_schema_index == 0) {
		sai_builder_registration_t *r = (sai_builder_registration_t *)g->a.dest;

		lwsl_ss_notice(h, "Registered builder '%s' on pcon '%s'",
			    r->builder_name, r->power_controller_name);

		/* Find the PCON */
		pc = saip_pcon_by_name(&power, r->power_controller_name);
		if (!pc) {
			lwsl_ss_warn(h, "Unknown PCON '%s', creating it", r->power_controller_name);
			/* Dynamically create PCON if missing */
			pc = saip_pcon_create(&power, r->power_controller_name);
		}

		if (pc) {
			/* Check if builder already exists */
			int found = 0;
			lws_start_foreach_dll(struct lws_dll2 *, b_node, pc->registered_builders_owner.head) {
				saip_builder_t *sb = lws_container_of(b_node, saip_builder_t, list);
				if (!strcmp(sb->name, r->builder_name)) {
					lwsl_ss_notice(h, "Builder '%s' re-connected to PCON '%s'", r->builder_name, pc->name);
					/* sb->wsi = ...; */ /* We don't have wsi here easily, but we have SS handle? Not needed for logic. */
					g->b = sb; /* Link user object to builder */
					found = 1;
					break;
				}
			} lws_end_foreach_dll(b_node);

			if (!found) {
				lwsl_ss_notice(h, "Adding builder '%s' to PCON '%s'", r->builder_name, pc->name);
				b = malloc(sizeof(*b));
				if (b) {
					memset(b, 0, sizeof(*b));
					lws_strncpy(b->name, r->builder_name, sizeof(b->name));
					/* b->wsi = ...; */
					g->b = b;
					lws_dll2_add_tail(&b->list, &pc->registered_builders_owner);
				} else {
					lwsl_ss_err(h, "OOM allocating builder");
				}
			}

			/* Store platforms */
			if (g->b) {
				/* Clear existing platforms first? Or just append? */
				lws_dll2_owner_clear(&g->b->platforms_owner); /* Assuming we have a way to free items, but lwsac managed? No, these are manual. */
				/* Actually we used lwsac for deserialization, but we need to PERSIST this data. */
				/* We need to copy from 'r->platforms_owner' to 'g->b->platforms_owner' */

				lws_start_foreach_dll(struct lws_dll2 *, p, r->platforms_owner.head) {
					sai_builder_platform_t *bp = lws_container_of(p, sai_builder_platform_t, list);
					saip_builder_platform_t *sbp = malloc(sizeof(*sbp));
					if (sbp) {
						memset(sbp, 0, sizeof(*sbp));
						lws_strncpy(sbp->name, bp->name, sizeof(sbp->name));
						lws_dll2_add_tail(&sbp->list, &g->b->platforms_owner);
					}
				} lws_end_foreach_dll(p);
			}

			/* Trigger a check since we have a new builder (it's alive!) */
			saip_pcon_start_check();

			/* Send update to sai-server */
			saip_queue_stay_info(lws_container_of(power.sai_server_owner.head, saip_server_t, list));
		}
	}

	lwsac_free(&g->a.ac);
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
local_srv_state(void *userobj, void *sh, lws_ss_constate_t state,
               lws_ss_tx_ordinal_t ack)
{
        local_srv_t *g = (local_srv_t *)userobj;
	char *path = NULL, pn[128];
	saip_pcon_t *pc;
	saip_server_t *sps;
	int apo = 0;
	size_t len;

	// lwsl_ss_user(lws_ss_from_user(g), "state %s", lws_ss_state_name((int)state));

        switch ((int)state) {
        case LWSSSCS_CREATING:
                return lws_ss_request_tx(lws_ss_from_user(g));

        case LWSSSCS_DISCONNECTED:
		if (g->b) {
			/* Mark as offline but don't delete */
			/* g->b->wsi = NULL; */
			g->b = NULL;
		}
		break;

        case LWSSSCS_SERVER_TXN:

		lws_ss_get_metadata(lws_ss_from_user(g), "path", (const void **)&path, &len);
		lwsl_ss_user(lws_ss_from_user(g), "LWSSSCS_SERVER_TXN path '%.*s' (%d)", (int)len, path, (int)len);

		/*
		 * path is containing a string like "/power-off/b32"
		 * match the last part to a known platform and find out how
		 * to power that off
		 */

                if (lws_ss_set_metadata(lws_ss_from_user(g), "mime", "text/html", 9))
                        return LWSSSSRET_DISCONNECT_ME;

                /*
                 * A transaction is starting on an accepted connection.  Say
                 * that we're OK with the transaction, prepare the user
                 * object with the response, and request tx to start sending it.
                 */
                lws_ss_server_ack(lws_ss_from_user(g), 0);

		g->pos = 0;

		if (len == 1 && path[0] == '/') {
			/* print controllable PCONs */

			g->size = 0;

			lws_start_foreach_dll(struct lws_dll2 *, px, power.sai_pcon_owner.head) {
				saip_pcon_t *pc = lws_container_of(px, saip_pcon_t, list);

				if (g->size)
					g->payload[g->size++] = ',';
				g->size = g->size + (size_t)lws_snprintf(g->payload + g->size, sizeof(g->payload) - g->size - 3, "%s", pc->name);

			} lws_end_foreach_dll(px);

			g->payload[g->size] = '\0';
			goto bail;
		}

		if (len > 6 && !strncmp(path, "/stay/", 6)) {
			lws_strnncpy(pn, &path[6], len - 6, sizeof(pn));

			pc = saip_pcon_by_name(&power, pn);
			if (!pc)
				pc = find_pcon_by_builder_name(&power, pn);

			if (pc)
				g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
								"%c", '0' + (pc->user_keep_on | pc->needed));
			else
				g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
								"unknown builder %s", pn);
			goto bail;
		}

		if (len > 10 && !strncmp(path, "/power-on/", 10)) {

			lws_strnncpy(pn, &path[10], len - 10, sizeof(pn));

			pc = saip_pcon_by_name(&power, pn);
			if (!pc)
				pc = find_pcon_by_builder_name(&power, pn);

			if (!pc) {
				g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
                                               "Unable to find PCON for %s", pn);
				goto bail;
			}

			saip_notify_server_power_state(pc->name, 1, 0);

			if (pc->mac) {
				if (write(lws_spawn_get_fd_stdxxx(lsp_wol, 0),
					      pc->mac, strlen(pc->mac)) !=
						(ssize_t)strlen(pc->mac))
					g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
						"Write to resume %s failed %d", pn, errno);
				else
					g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
						"Resumed %s with stay", pn);
				pc->user_keep_on = 1;
				goto bail;
			}

			if (pc->ss_tasmota_on) {
				if (lws_ss_client_connect(pc->ss_tasmota_on)) {
					lwsl_ss_err(pc->ss_tasmota_on, "failed to connect tasmota ON secure stream");
					g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
						"power-on ss failed create %s", pc->name);
					goto bail;
				}
			} else {
				g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
						"no power-controller entry for %s", pn);
				goto bail;
			}

			lwsl_warn("%s: powered on %s\n", __func__, pc->name);

			pc->user_keep_on = 1; /* so builder can understand it's manual */
			saip_notify_server_power_state(pc->name, 1, 0);

			sps = lws_container_of(power.sai_server_owner.head,
						saip_server_t, list);

			saip_queue_stay_info(sps);

			g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
				"Manually powered on %s", pc->name);
			goto bail;
		}

		if (len > 16 && !strncmp(path, "/auto-power-off/", 16)) {
			apo = 1;
			lws_strnncpy(pn, &path[16], len - 16, sizeof(pn));
			goto power_off;
		}

		if (len < 11 || strncmp(path, "/power-off/", 11)) {
			g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
					"URL path needs to start with /power-off/");
			goto bail;
		}

		lws_strnncpy(pn, &path[11], len - 11, sizeof(pn));

power_off:

		/*
		 * Let's have a look at the platform
		 */

		g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
                                               "Unable to find host %s", pn);

		pc = saip_pcon_by_name(&power, pn);
		if (!pc)
			pc = find_pcon_by_builder_name(&power, pn);

		if (pc) {

			if (apo) {
				char needs[128];

				/*
				 * Since it's not a manual request,
				 * we should deny it if any deps still need us
				 */
				/* Deps logic needs to check PARENT or DEPENDENTS?
				   Original logic checked: "if any deps still need us" (us = dependency_list).
				   Current PCON struct has 'parent' and 'depends_on'.
				   If *we* are needed by someone else... we don't have a list of dependents easily.
				   But 'needed' flag should be set if we are needed.
				   Let's trust 'pc->needed' which we update in rx.
				*/

				needs[0] = '\0';
				/*
				lws_start_foreach_dll(struct lws_dll2 *, px1,
						sp->dependencies_owner.head) {
					saip_server_plat_t *sp1 = lws_container_of(px1,
						saip_server_plat_t, dependencies_list);

					if (sp1->needed)
						lws_snprintf(needs,
							     sizeof(needs) - 1 - strlen(needs),
							     "%s ", sp1->name);

				} lws_end_foreach_dll(px1);
				*/

				if (needs[0] || pc->needed) {
					g->size = (size_t)lws_snprintf(g->payload,
						sizeof(g->payload),
						"NAK: %s needed: %d, deps needed: '%s'",
						pn, pc->needed, needs);
					goto bail;
				}
			}

			/*
			 * OK this is it, schedule it to happen
			 */
			lws_sul_schedule(lws_ss_get_context(lws_ss_from_user(g)), 0,
						&pc->sul_delay_off,
						saip_sul_action_power_off,
						SAI_POWERDOWN_HOLDOFF_US);

			lwsl_warn("%s: scheduled powering off pcon %s in %ds\n",
				  __func__, pc->name,
				  (int)(SAI_POWERDOWN_HOLDOFF_US / LWS_USEC_PER_SEC));

			g->size = (size_t)lws_snprintf(g->payload, sizeof(g->payload),
				"ACK: Scheduled powering off pcon %s in %ds",
				pc->name,
				(int)(SAI_POWERDOWN_HOLDOFF_US / LWS_USEC_PER_SEC));

			pc->user_keep_on = 0; /* reset any manual power up */
		}

bail:
                return lws_ss_request_tx_len(lws_ss_from_user(g),
                                             (unsigned long)g->size);
        }

        return LWSSSSRET_OK;
}


LWS_SS_INFO("local", local_srv_t)
        .tx                             = local_srv_tx,
        .rx                             = local_srv_rx,
        .state                          = local_srv_state,
};
