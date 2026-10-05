/*
 * sai-virt - src/virt/v-ws-server.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 */

#include <libwebsockets.h>
#include <string.h>

#include "v-private.h"

/*
 * When we connect, we masquerade as a builder/pcon and send our platforms
 */
static lws_ss_state_return_t
saiv_server_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	       int *flags)
{
	saiv_server_link_t *g = (saiv_server_link_t *)userobj;
	lws_ss_state_return_t r;

	r = sai_ss_tx_from_buflist_helper(g->ss, &g->bl_tx, buf, len, flags);
	if (r == LWSSSSRET_OK)
		lwsl_notice("%s: Transmitted %zu bytes (flags=%d)\n", __func__, *len, *flags);
	return r;
}

/*
 * Tear down a VM and forget it.  If the hypervisor didn't confirm it's gone,
 * keep the record, so its name stays reserved and it still counts against
 * max_vms, and try again shortly.  Callers should saiv_try_spawn() after.
 */

static void
saiv_vm_reap(saiv_vm_t *vm, const char *why)
{
	lwsl_notice("%s: %s: %s\n", __func__, vm->name, why);

	if (virt.ops && virt.ops->destroy(&virt, vm)) {
		lwsl_err("%s: %s not confirmed destroyed, retrying in %ds\n",
			 __func__, vm->name,
			 (int)(SAIV_DESTROY_RETRY_US / LWS_US_PER_SEC));
		lws_sul_schedule(virt.context, 0, &vm->sul_destroy,
				 saiv_vm_destroy_cb, SAIV_DESTROY_RETRY_US);
		return;
	}

	lws_sul_cancel(&vm->sul_timeout);
	lws_sul_cancel(&vm->sul_destroy);
	lws_dll2_remove(&vm->list);
	virt.running_vms--;
	free(vm);
}

void
saiv_vm_destroy_cb(lws_sorted_usec_list_t *sul)
{
	saiv_vm_t *vm = lws_container_of(sul, saiv_vm_t, sul_destroy);

	saiv_vm_reap(vm, "delayed destruction executing");
	saiv_try_spawn();
}

void
saiv_vm_timeout_cb(lws_sorted_usec_list_t *sul)
{
	saiv_vm_t *vm = lws_container_of(sul, saiv_vm_t, sul_timeout);

	lwsl_err("%s: VM %s timed out, purging\n", __func__, vm->name);

	saiv_vm_reap(vm, "timed out");
	saiv_try_spawn();
}

/*
 * Periodically check the VMs we think we have still exist and can make
 * progress, so we notice ones that died or got stuck without telling us.
 *
 * sai-server only sends us pending tasks when they change, so this is also
 * what retries spawning after a failure.
 */

void
saiv_watch_cb(lws_sorted_usec_list_t *sul)
{
	if (virt.ops && virt.ops->alive) {
		lws_start_foreach_dll(struct lws_dll2 *, d, virt.plat_owner.head) {
			saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);

			lws_start_foreach_dll_safe(struct lws_dll2 *, v, v1,
						   vp->vm_owner.head) {
				saiv_vm_t *vm = lws_container_of(v, saiv_vm_t, list);

				if (!virt.ops->alive(&virt, vm))
					saiv_vm_reap(vm, "domain is gone or stuck");
			} lws_end_foreach_dll_safe(v, v1);
		} lws_end_foreach_dll(d);
	}

	saiv_try_spawn();

	lws_sul_schedule(virt.context, 0, &virt.sul_watch, saiv_watch_cb,
			 SAIV_WATCH_INTERVAL_US);
}

void
saiv_try_spawn(void)
{
	sai_platform_pending_tasks_t *pt = virt.pending_tasks;

	if (!pt || !pt->tasks.head)
		return;

	while (virt.running_vms < virt.max_vms) {
		int total_wheel_weight = 0;

		/* Step 1: Count true demand */
		lws_start_foreach_dll(struct lws_dll2 *, p, pt->tasks.head) {
			sai_platform_pending_task_t *t = lws_container_of(p, sai_platform_pending_task_t, list);

			saiv_plat_t *found_vp = NULL;
			lws_start_foreach_dll(struct lws_dll2 *, d, virt.plat_owner.head) {
				saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);
				const char *pname = vp->platform[0] ? vp->platform : vp->name;
				if (!strcmp(pname, t->plat)) {
					found_vp = vp;
					break;
				}
			} lws_end_foreach_dll(d);

			if (found_vp) {
				int true_demand = (int)t->unmet - (int)found_vp->vm_owner.count;
				if (true_demand > 0) {
					/* Apply wait magnification factor */
					total_wheel_weight += true_demand + found_vp->wait_magnification;
				}
			}
		} lws_end_foreach_dll(p);

		if (total_wheel_weight == 0)
			break;

		/* Step 2: Roll the dice */
		uint32_t r;
		lws_get_random(virt.context, &r, sizeof(r));
		int target = (int)(r % (uint32_t)total_wheel_weight);

		saiv_plat_t *winner = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, p, pt->tasks.head) {
			sai_platform_pending_task_t *t = lws_container_of(p, sai_platform_pending_task_t, list);

			saiv_plat_t *found_vp = NULL;
			lws_start_foreach_dll(struct lws_dll2 *, d, virt.plat_owner.head) {
				saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);
				const char *pname = vp->platform[0] ? vp->platform : vp->name;
				if (!strcmp(pname, t->plat)) {
					found_vp = vp;
					break;
				}
			} lws_end_foreach_dll(d);

			if (found_vp) {
				int true_demand = (int)t->unmet - (int)found_vp->vm_owner.count;
				if (true_demand > 0) {
					target -= (true_demand + found_vp->wait_magnification);
					if (target < 0) {
						winner = found_vp;
						break;
					} else {
						/* This platform wasn't picked, increase its wait magnification */
						found_vp->wait_magnification++;
					}
				}
			}
		} lws_end_foreach_dll(p);

		/* Step 3: Spawn the winner and reset its magnification */
		if (winner && virt.ops) {
			lwsl_notice("%s: Wheel picked platform %s (wait factor %d reset)\n", 
				    __func__, winner->name, winner->wait_magnification);
			
			saiv_vm_t *vm = malloc(sizeof(*vm));
			if (vm) {
				int i;
				memset(vm, 0, sizeof(*vm));
				vm->plat = winner;
				
				/* Find lowest unused index */
				for (i = 0; i < virt.max_vms; i++) {
					int used = 0;
					lws_start_foreach_dll(struct lws_dll2 *, d, winner->vm_owner.head) {
						saiv_vm_t *v = lws_container_of(d, saiv_vm_t, list);
						if (v->vm_index == i) {
							used = 1;
							break;
						}
					} lws_end_foreach_dll(d);
					if (!used)
						break;
				}
				vm->vm_index = i;
				
				lws_snprintf(vm->name, sizeof(vm->name), "sai-vm-%s-%d", winner->name, vm->vm_index);
				lws_dll2_add_tail(&vm->list, &winner->vm_owner);

				virt.running_vms++;
				winner->wait_magnification = 0;
				if (virt.ops->spawn(&virt, vm)) {
					/* saiv_watch_cb() will try again */
					lwsl_err("%s: Failed to spawn VM %s\n", __func__, vm->name);
					lws_dll2_remove(&vm->list);
					free(vm);
					virt.running_vms--;
					break;
				}

				/* Clean up if it never connects and terminates itself */
				lws_sul_schedule(virt.context, 0, &vm->sul_timeout,
						 saiv_vm_timeout_cb,
						 SAIV_VM_FIRST_CONTACT_US);
			} else
				break; /* OOM: don't spin */
		} else {
			break;
		}
	}
}


static lws_ss_state_return_t
saiv_server_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	struct lejp_ctx ctx;
	lws_struct_args_t a;
	int m;

	/*
	 * We receive JSON from sai-server, usually com.warmcat.sai.power.pending_tasks
	 */
	memset(&a, 0, sizeof(a));
	a.map_st[0]		= lsm_schema_pending_tasks;
	a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_pending_tasks);
	a.map_st[1]		= lsm_schema_stay;
	a.map_entries_st[1]	= LWS_ARRAY_SIZE(lsm_schema_stay);
	a.ac_block_size		= 512;

	lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (uint8_t *)buf, (int)len);
	if (m < 0) {
		lwsl_err("%s: JSON decode failed '%s'\n", __func__, lejp_error_to_string(m));
		return LWSSSSRET_OK;
	}

	if (!a.dest) {
		lwsac_free(&a.ac);
		return LWSSSSRET_OK;
	}

	if (a.top_schema_index == 1) {
		sai_stay_t *stay = (sai_stay_t *)a.dest;
		lwsl_notice("%s: Received stay request for platform %s (stay_on=%d)\n", 
			    __func__, stay->builder_name, stay->stay_on);
		/* In Maintenance Mode, we boot the template RW instead of a transient clone */
		/* For this skeleton we'll just mock log it */
		lwsl_notice("%s: Maintenance Mode %s for %s\n", __func__, 
			    stay->stay_on ? "ENABLED (booting RW)" : "DISABLED (destroying)", 
			    stay->builder_name);
	} else if (a.top_schema_index == 0) {
		sai_platform_pending_tasks_t *pt = (sai_platform_pending_tasks_t *)a.dest;
		// lwsl_notice("%s: Pending tasks for pcons: %s\n", __func__, pt->pcons);

		if (virt.pending_tasks_ac)
			lwsac_free(&virt.pending_tasks_ac);

		virt.pending_tasks_ac = a.ac;
		virt.pending_tasks = pt;
		a.ac = NULL;

		saiv_try_spawn();
	}

	if (a.ac)
		lwsac_free(&a.ac);
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saiv_server_state(void *userobj, void *sh, lws_ss_constate_t state,
		  lws_ss_tx_ordinal_t ack)
{
	saiv_server_link_t *g = (saiv_server_link_t *)userobj;
	struct lwsac *ac = NULL;

	switch (state) {
	case LWSSSCS_CREATING:
	{
		saiv_server_t *srv = (saiv_server_t *)g->opaque_data;
		lwsl_notice("%s: CREATING (url: %s)\n", __func__, srv->url);
		if (lws_ss_set_metadata(g->ss, "url", srv->url, strlen(srv->url)))
			return LWSSSSRET_DESTROY_ME;
		break;
	}

	case LWSSSCS_CONNECTED:
		lwsl_notice("%s: Connected to sai-server\n", __func__);

		/*
		 * sai-server refuses to process anything from us until we
		 * prove the fleet link secret, so it has to be the first
		 * message on the (re)connection.
		 */
		{
			uint8_t abuf[LWS_PRE + 256];
			size_t al;

			if (!virt.link_key)
				lwsl_err("%s: no link-key in conf, sai-server "
					 "will refuse us\n", __func__);

			al = (size_t)lws_snprintf((char *)abuf + LWS_PRE,
					sizeof(abuf) - LWS_PRE,
					"{\"schema\":\"" SAI_LINKAUTH_SCHEMA
					"\",\"secret\":\"%s\"}",
					virt.link_key ? virt.link_key : "");

			sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(g->ss,
					&g->bl_tx, abuf + LWS_PRE, al,
					LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);
		}

		sai_power_managed_builders_t pmb;
		memset(&pmb, 0, sizeof(pmb));

		/* Register ourselves as the power controller */
		sai_power_controller_t *pc = lwsac_use_zero(&ac, sizeof(*pc), 512);
		if (pc) {
			lws_strncpy(pc->name, virt.hostname, sizeof(pc->name));
			lws_strncpy(pc->type, "virt", sizeof(pc->type));
			pc->on = 1;
			lws_dll2_add_tail(&pc->list, &pmb.power_controllers);

			/* Register our platforms as the "builders" we manage */
			lws_start_foreach_dll(struct lws_dll2 *, d, virt.plat_owner.head) {
				saiv_plat_t *vp = lws_container_of(d, saiv_plat_t, list);
				sai_controlled_builder_t *c = lwsac_use_zero(&ac, sizeof(*c), 512);
				if (c) {
					const char *pname = vp->platform[0] ? vp->platform : vp->name;
					lws_strncpy(c->name, pname, sizeof(c->name));
					lws_dll2_add_tail(&c->list, &pc->controlled_builders_owner);
				}
			} lws_end_foreach_dll(d);
		}

		sai_ss_serialize_queue_helper(g->ss, &g->bl_tx,
					      lsm_schema_power_managed_builders,
					      LWS_ARRAY_SIZE(lsm_schema_power_managed_builders),
					      &pmb);
		lwsac_free(&ac);
		break;

	case LWSSSCS_DISCONNECTED:
		lwsl_notice("%s: Disconnected\n", __func__);
		lws_buflist_destroy_all_segments(&g->bl_tx);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

const lws_ss_info_t ssi_saiv_server_link_t = {
	.handle_offset		= offsetof(saiv_server_link_t, ss),
	.opaque_user_data_offset = offsetof(saiv_server_link_t, opaque_data),
	.rx			= saiv_server_rx,
	.tx			= saiv_server_tx,
	.state			= saiv_server_state,
	.user_alloc		= sizeof(saiv_server_link_t),
	.streamtype		= "sai_power_client"
};
