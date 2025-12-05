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
 * The same ws interface is connected-to by builders (on path /builder), and
 * provides the query transport for browsers (on path /browse).
 *
 * There's a single server slite3 database containing events, and a separate
 * sqlite3 database file for each event, it only contains tasks and logs for
 * the event and can be deleted when the event record associated with it is
 * deleted.  This is to keep is scalable when there may be thousands of events
 * and related tasks and logs stored.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>

#include "s-private.h"

int
sais_power_rx(struct vhd *vhd, struct pss *pss, uint8_t *buf,
	      size_t bl, unsigned int ss_flags)
{
	struct lejp_ctx ctx;
	lws_struct_args_t a;
	sai_power_state_t *ps;
	const lws_struct_map_t lsm_schema_map_power[] = {
		LSM_SCHEMA(sai_power_state_t, NULL, lsm_power_state,
			   "com.warmcat.sai.powerstate"),
		LSM_SCHEMA(sai_power_managed_builders_t, NULL,
			   lsm_power_managed_builders_list,
			   "com.warmcat.sai.power_managed_builders"),
		LSM_SCHEMA(sai_stay_state_update_t, NULL,
			   lsm_stay_state_update,
			   "com.warmcat.sai.stay_state_update"),
	};

	/* This is a message from sai-power */
	lwsl_notice("RX from sai-power: %.*s\n", (int)bl, (const char *)buf);

	memset(&a, 0, sizeof(a));
	a.map_st[0] = lsm_schema_map_power;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_schema_map_power);
	a.ac_block_size = 512;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	if (lejp_parse(&ctx, buf, (int)bl) < 0 || !a.dest) {
		lwsl_warn("Failed to parse msg from sai-power\n");
		lwsac_free(&a.ac);
		return 1;
	}

	switch (a.top_schema_index) {
	case 0: /* powerstate */
		ps = (sai_power_state_t *)a.dest;
		lwsl_notice("%s: powerstate received: %d %d\n", __func__, ps->powering_up, ps->powering_down);
		if (ps->powering_up) {
			lwsl_notice("sai-power is powering up: %s\n", ps->host);
			sais_set_builder_power_state(vhd, ps->host, 1, 0);
			break;
		}
		if (ps->powering_down) {
			lwsl_notice("sai-power is powering down: %s\n", ps->host);
			sais_set_builder_power_state(vhd, ps->host, 0, 1);
		}
		break;

	case 1: {
		sai_power_managed_builders_t *pmb = (sai_power_managed_builders_t *)a.dest;
		char q[256];

		/*
		 * We received the PCON topology and registered builders from sai-power.
		 *
		 * 1. Store PCONs in DB.
		 * 2. Update builders' PCON association (if we have a table or column for it).
		 */

		sai_sqlite3_statement(vhd->server.pdb, "BEGIN TRANSACTION", "txn begin");

		lws_start_foreach_dll(struct lws_dll2 *, p, pmb->power_controllers.head) {
			sai_power_controller_t *pc = lws_container_of(p, sai_power_controller_t, list);
			
			/* Insert PCON */
			lws_snprintf(q, sizeof(q),
				     "INSERT OR REPLACE INTO power_controllers (name, type, url, depends_on, state) VALUES ('%s', '%s', '', '%s', %d)",
				     pc->name, pc->type, pc->depends_on, pc->on);
			sai_sqlite3_statement(vhd->server.pdb, q, "insert pcon");

			/* Insert Controlled Builders */
			lws_start_foreach_dll(struct lws_dll2 *, pb, pc->controlled_builders_owner.head) {
				sai_controlled_builder_t *cb = lws_container_of(pb, sai_controlled_builder_t, list);
				lws_snprintf(q, sizeof(q),
					     "INSERT INTO pcon_builders (pcon_name, builder_name) SELECT '%s', '%s' WHERE NOT EXISTS (SELECT 1 FROM pcon_builders WHERE pcon_name = '%s' AND builder_name = '%s')",
					     pc->name, cb->name, pc->name, cb->name);
				lwsl_notice("%s: Inserting pcon_builder: pcon='%s', builder='%s'\n", __func__, pc->name, cb->name);
				sai_sqlite3_statement(vhd->server.pdb, q, "insert pcon_builder");

				/* Update builders table with pcon name */
				/* Note: builders table key is 'name'. */
				lws_snprintf(q, sizeof(q),
					     "UPDATE builders SET pcon = '%s' WHERE name = '%s' OR name LIKE '%s.%%'",
					     pc->name, cb->name, cb->name);
				sai_sqlite3_statement(vhd->server.pdb, q, "update builder pcon");

			} lws_end_foreach_dll(pb);

		} lws_end_foreach_dll(p);

		sai_sqlite3_statement(vhd->server.pdb, "COMMIT", "txn commit");

		sais_list_builders(vhd);

		break;
	}
	case 2:	{
		sai_stay_state_update_t *ssu = (sai_stay_state_update_t *)a.dest;
		sai_plat_t *sp;

		lwsl_notice("%s: Received stay_state_update for %s, stay_on=%d\n",
			    __func__, ssu->builder_name, ssu->stay_on);

		lws_start_foreach_dll(struct lws_dll2 *, p,
				vhd->server.builder_owner.head) {
			sp = lws_container_of(p, sai_plat_t,
					sai_plat_list);

			const char *dot = strchr(sp->name, '.');

			if (dot && !strncmp(sp->name, ssu->builder_name, (size_t)(dot - sp->name))) {
				lwsl_notice("%s: Updating builder %s stay_on from %d to %d\n",
					    __func__, sp->name, sp->stay_on, ssu->stay_on);
				sp->stay_on = ssu->stay_on;
				sais_list_builders(vhd);
				break;
			}
		} lws_end_foreach_dll(p);

		break;
	}
	default:
		lwsl_warn("%s: unknown schema\n", __func__);
		break;
	}

	lwsac_free(&a.ac);
	
	return 0;
}

int
sais_power_tx(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl)
{
	uint8_t *start = buf + LWS_PRE, *p = start, *end = p + bl - LWS_PRE - 1;
	enum lws_write_protocol flags;
	char diff = 0;
	size_t w;
	int n;

	if (pss->stay_owner.head) {
		/*
		 * Pending stay message to send to power
		 */
		sai_stay_t *s = lws_container_of(pss->stay_owner.head,
						   sai_stay_t, list);
		lws_struct_serialize_t *js;

		js = lws_struct_json_serialize_create(lsm_schema_stay,
				LWS_ARRAY_SIZE(lsm_schema_stay), 0, s);
		if (!js) {
			lwsl_warn("%s: failed to serialize stay\n", __func__);
			return 1;
		}

		n = (int)lws_struct_json_serialize(js, p, lws_ptr_diff_size_t(end, p), &w);
		lws_struct_json_serialize_destroy(&js);

		lwsl_wsi_notice(pss->wsi, "%s: server issuing stay notice\n", __func__);
		sai_dump_stderr(start, w);

		lws_dll2_remove(&s->list);
		free(s);

		flags = lws_write_ws_flags(LWS_WRITE_TEXT, 1, 1);

		if (lws_write(pss->wsi, start, w, flags) < 0)
			return -1;

		lws_callback_on_writable(pss->wsi);
		return 0;
	}

	n = 0;
	lws_start_foreach_dll(struct lws_dll2 *, px, vhd->pending_plats.head) {
		sais_plat_t *pl = lws_container_of(px, sais_plat_t, list);
		size_t m;

		if (n)
			*p++ = ',';
		m = strlen(pl->plat);
		if (lws_ptr_diff_size_t(end, p) < m + 2)
			break;
		memcpy(p, pl->plat, m);
		p += m;
		*p = '\0';
		n = 1;

	} lws_end_foreach_dll(px);

	/*
	 * Don't resend the same status over and over
	 */

	if (strncmp(pss->last_power_report, (const char *)start, lws_ptr_diff_size_t(p, start) + 1)) {
		diff = 1;
		memcpy(pss->last_power_report, start, lws_ptr_diff_size_t(p, start) + 1);
	}

	if (diff /* && start != p */) {
		lwsl_notice("%s: detected jobs for %.*s\n", __func__,
				(int)lws_ptr_diff_size_t(p, start), start);

		if (lws_write(pss->wsi, start, lws_ptr_diff_size_t(p, start),
				LWS_WRITE_TEXT) < 0)
			return -1;

		lws_callback_on_writable(pss->wsi);
	}

	return 0;
}

