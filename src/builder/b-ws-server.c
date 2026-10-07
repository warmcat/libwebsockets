/*
 * sai-builder com-warmcat-sai client protocol implementation
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
 *   b3 --/                      \-- browser
 *    *
 *
 * Builder -> Server Secure Streams ws link
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#ifndef _WIN32
#include <sys/ioctl.h>
#endif

#include "b-private.h"

extern struct lws_spawn_piped *lsp_suspender;

static const lws_struct_map_t lsm_schema_json_loadreport[] = {
	LSM_SCHEMA	(sai_load_report_t, NULL, lsm_load_report_members, "com.warmcat.sai.loadreport"),
};

static const lws_struct_map_t lsm_viewerstate_members[] = {
       LSM_UNSIGNED(sai_viewer_state_t, viewers,       "viewers"),
};

const lws_struct_map_t lsm_schema_map_m_to_b[] = {
	LSM_SCHEMA	(sai_task_t, NULL, lsm_task, "com-warmcat-sai-ta"),
	LSM_SCHEMA	(sai_cancel_t, NULL, lsm_task_cancel, "com.warmcat.sai.taskcan"),
	LSM_SCHEMA	(sai_viewer_state_t, NULL, lsm_viewerstate_members,
						 "com.warmcat.sai.viewerstate"),
	LSM_SCHEMA	(sai_resource_t, NULL, lsm_resource, "com-warmcat-sai-resource"),
	LSM_SCHEMA	(sai_rebuild_t, NULL, lsm_rebuild, "com.warmcat.sai.rebuild"),
	LSM_SCHEMA	(sai_openshell_t, NULL, lsm_openshell, "com.warmcat.sai.openshell"),
	LSM_SCHEMA	(sai_ptydata_t, NULL, lsm_ptydata, "com.warmcat.sai.ptydata")
};

enum {
	SAIB_RX_TASK_ALLOCATION,
	SAIB_RX_TASK_CANCEL,
	SAIB_RX_VIEWERSTATE,
	SAIB_RX_RESOURCE_REPLY,
	SAIB_RX_REBUILD,
	SAIB_RX_OPENSHELL,
	SAIB_RX_PTYDATA
};

/*
 * This is the only path to send things from builder->server.
 *
 * It will copy the incoming buffer fragment into a buflist in order.  So you
 * should dump all your fragments for a message in here one after the other
 * and the message will go out uninterrupted.  Having this as the only tx path
 * allows us to guarantee we won't interrupt the fragment sequencing.
 *
 * The fragment sizing does not have to be related to ss usage sizing, it can
 * be larger and it will be used from the buflist according to what SS wants.
 */

int
saib_srv_queue_tx(struct lws_ss_handle *h, void *buf, size_t len,
                  unsigned int ss_flags)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)lws_ss_to_user_object(h);
	unsigned int *pi = (unsigned int *)((const char *)buf - sizeof(int));

	lwsl_info("%s: queuing %d bytes to server\n", __func__, (int)len);

	*pi = ss_flags;
	
	// lwsl_ss_notice(h, "Queuing builder -> sai-server");
	// lwsl_hexdump_notice(buf, len);

	if (lws_buflist2_append_segment(&spm->bl_to_srv, (uint8_t *)buf - sizeof(int),
					 len + sizeof(int)) < 0) {
		lwsl_err("%s: failed to append\n", __func__);
		spm->tx_corrupted = 1; /* Mark the stream as permanently corrupted */
		return -1;
	}

	if (lws_ss_request_tx(h)) {
		lwsl_ss_err(h, "failed to request tx");
		return -1;
	}

	return 0;
}

int
saib_srv_queue_json_fragments_helper(struct lws_ss_handle *h,
				     const lws_struct_map_t *map,
                                     size_t map_entries, void *object)
{
	unsigned int ssf = LWSSS_FLAG_SOM;
	uint8_t buf[1024 + LWS_PRE];
	lws_struct_serialize_t *js;
	size_t w = 0;

	js = lws_struct_json_serialize_create(map, map_entries, 0, object);
	if (!js) {
		lwsl_notice("TRAP: lws_struct_json_serialize_create failed\n");
		return -1;
	}

	do {
		switch (lws_struct_json_serialize(js, buf + LWS_PRE,
						  sizeof(buf) - LWS_PRE, &w)) {
		case LSJS_RESULT_CONTINUE:
			break;
		case LSJS_RESULT_FINISH:
			ssf |= LWSSS_FLAG_EOM;
			break;
		case LSJS_RESULT_ERROR:
			lwsl_notice("TRAP: lws_struct_json_serialize returned ERROR\n");
			{
				struct sai_plat_server *spm = (struct sai_plat_server *)lws_ss_to_user_object(h);
				spm->tx_corrupted = 1;
			}
			return -1;
		}

		if (saib_srv_queue_tx(h, buf + LWS_PRE, w, ssf) < 0) {
			lwsl_notice("TRAP: saib_srv_queue_tx failed in helper\n");
			lws_struct_json_serialize_destroy(&js);
			return -1;
		}

		ssf &= ~((unsigned int)LWSSS_FLAG_SOM);
	} while (!(ssf & LWSSS_FLAG_EOM));

	lws_struct_json_serialize_destroy(&js);

	return 0;
}

static lws_ss_state_return_t
saib_m_rx(void *userobj, const uint8_t *in, size_t len, int flags)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)userobj;
	sai_plat_t *sp = NULL;
	sai_resource_t *reso;
	sai_rebuild_t *reb;
	sai_cancel_t *can;
	int m;

	lws_ss_validity_confirmed(spm->ss);

	if (flags & LWSSS_FLAG_SOM) {
		memset(&spm->a, 0, sizeof(spm->a));
		spm->a.map_st[0]		= lsm_schema_map_m_to_b;
		spm->a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_map_m_to_b);
		spm->a.ac_block_size		= 512;

		lws_struct_json_init_parse(&spm->ctx, NULL, &spm->a);
	}

	m = lejp_parse(&spm->ctx, (uint8_t *)in, (int)len);
	if (m == LEJP_CONTINUE)
		return LWSSSSRET_OK;

	if (m < 0) {
		lwsl_notice("TRAP: saib_m_rx lejp_parse failed m=%d\n", m);
		lwsl_hexdump_err(in, len);
		lwsl_err("%s: builder rx JSON decode failed '%s'\n",
			    __func__, lejp_error_to_string(m));
		lwsac_free(&spm->a.ac);
		return m;
	}

	if (!spm->a.dest) {
		lwsac_free(&spm->a.ac);
		return LWSSSSRET_OK;
	}

	switch (spm->a.top_schema_index) {

	case SAIB_RX_TASK_ALLOCATION:
		if (saib_consider_allocating_task(spm, &spm->a, in, len, flags))
			break;

		break;

	case SAIB_RX_TASK_CANCEL:

		can = (sai_cancel_t *)spm->a.dest;

		lwsl_notice("%s: received task cancel for %s, erase %d\n", __func__, can->task_uuid, can->erase);

		{
			char vn[16];

			/*
			 * Job dirs are named from the task uuid, they are not
			 * the uuid itself... asking for the uuid deleted just
			 * silently removed nothing.
			 */

			saib_task_jobdir_vn(vn, sizeof(vn), can->task_uuid);

			/* it's not going to get any more steps */
			saib_jobdir_release(vn);

			if (can->erase) {
#if defined(LWS_WITH_STUB)
				if (builder.mgr_deletion &&
				    saib_deletion_request(vn) < 0)
					lwsl_err("%s: failed to queue deletion\n",
						 __func__);
#endif
			}
		}

		lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
					   builder.sai_plat_owner.head) {
			struct sai_plat *sp = lws_container_of(mp, struct sai_plat,
						sai_plat_list);

			lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
						   sp->nspawn_owner.head) {
				struct sai_nspawn *ns = lws_container_of(p,
							struct sai_nspawn, list);

				if (ns->task &&
				    !strcmp(can->task_uuid, ns->task->uuid)) {
					lwsl_notice("%s: trying to cancel %s\n",
						    __func__, can->task_uuid);

					/*
					 * We're going to send a few signals
					 * at 500ms intervals
					 */
					if (can->killed)
						ns->user_killed = 1;
					else
						ns->user_cancel = 1;
					ns->term_budget = 5;

					lws_sul_schedule(ns->builder->context, 0,
							 &ns->sul_task_cancel,
							 saib_sul_task_cancel, 1);
				}

			} lws_end_foreach_dll_safe(p, p1);

		} lws_end_foreach_dll_safe(mp, mp1);

		lws_start_foreach_dll_safe(struct lws_dll2 *, shd, shd1,
					   builder.shell_owner.head) {
			struct sai_shell *sh = lws_container_of(shd, struct sai_shell, list);

			if (!strcmp(can->task_uuid, sh->task_uuid)) {
				lwsl_notice("%s: cancelling shell %s\n", __func__, can->task_uuid);
				if (sh->lsp)
					lws_spawn_piped_kill_child_process(sh->lsp);
				sh->user_cancel = 1;
			}
		} lws_end_foreach_dll_safe(shd, shd1);
		break;

	case SAIB_RX_VIEWERSTATE:
		{
			sai_viewer_state_t *vs = (sai_viewer_state_t *)spm->a.dest;
			char any_busy = 0;

		       lwsl_notice("Received viewer state update: %u viewers\n", vs->viewers);

			spm->viewer_count = vs->viewers;

			if (!vs->viewers) {
			       lwsl_notice("%s: VIEWERSTATE: no viewers -> no load reports\n", __func__);
				lws_sul_cancel(&spm->sul_load_report);
				break;
			}

			/* are there any busy instances */

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						builder.sai_plat_owner.head) {
			       sp = lws_container_of(d, sai_plat_t, sai_plat_list);

				lws_start_foreach_dll(struct lws_dll2 *, d, sp->nspawn_owner.head) {
					 struct sai_nspawn *ns = lws_container_of(d, struct sai_nspawn, list);

					if (ns->state == NSSTATE_EXECUTING_STEPS)
						any_busy = 1;

				} lws_end_foreach_dll(d);
			} lws_end_foreach_dll_safe(d, d1);

			if (!any_busy) {
			       lwsl_notice("%s: VIEWERSTATE: no busy instances -> no load reports\n", __func__);

				lws_sul_cancel(&spm->sul_load_report);
				break;
			}

			/* At least one viewer, start reporting */
		       lwsl_notice("%s: VIEWERSTATE: viewers + busy instances -> load reports\n", __func__);

			lws_sul_schedule(builder.context, 0, &spm->sul_load_report,
					 saib_sul_load_report_cb, 1);
		}
		break;

	case SAIB_RX_OPENSHELL:
	{
		extern int saib_shell_spawn(struct sai_plat_server *spm, const char *task_uuid);
		sai_openshell_t *os = (sai_openshell_t *)spm->a.dest;
		lwsl_notice("%s: OPENSHELL received from server for task %s\n", __func__, os->task_uuid);
		saib_shell_spawn(spm, os->task_uuid);
		break;
	}

		case SAIB_RX_PTYDATA:
		{
			sai_ptydata_t *pd = (sai_ptydata_t *)spm->a.dest;
			struct sai_shell *sh = NULL;

			lws_start_foreach_dll(struct lws_dll2 *, d, builder.shell_owner.head) {
				struct sai_shell *s = lws_container_of(d, struct sai_shell, list);
				if (!strcmp(s->task_uuid, pd->task_uuid)) {
					sh = s;
					break;
				}
			} lws_end_foreach_dll(d);

			if (sh && sh->lsp && (pd->data || (pd->cols && pd->rows))) {
				lws_filefd_type fd = lws_spawn_get_fd_stdxxx(sh->lsp, 0);
				if (fd != LWS_INVALID_FILE) {
					if (pd->cols && pd->rows) {
#ifndef _WIN32
						struct winsize ws;
						memset(&ws, 0, sizeof(ws));
						ws.ws_col = (unsigned short)pd->cols;
						ws.ws_row = (unsigned short)pd->rows;
						if (ioctl(fd, TIOCSWINSZ, &ws) < 0)
							lwsl_err("%s: failed to set pty size\n", __func__);
#endif
					}

					if (pd->data && pd->len > 0) {
						char dec[1024];
						int dl = lws_b64_decode_string(pd->data, dec, sizeof(dec));
						if (dl > 0) {
							// lwsl_notice("%s: PTYDATA received from server (len %d), writing to shell %s\n", __func__, dl, pd->task_uuid);
#if defined(WIN32)
							DWORD written;
							if (!WriteFile(fd, dec, (DWORD)dl, &written, NULL))
#else
							if (write(fd, dec, LWS_POSIX_LENGTH_CAST(dl)) < 0)
#endif
								lwsl_err("%s: failed to write to pty\n", __func__);
						}
					}
				}
			} else {
				lwsl_warn("%s: PTYDATA for unknown shell %s\n", __func__, pd->task_uuid);
			}
			break;
		}

	case SAIB_RX_RESOURCE_REPLY:
		reso = (sai_resource_t *)spm->a.dest;

		lwsl_notice("%s: RESOURCE_REPLY: cookie %s\n",
				__func__, reso->cookie);

		saib_handle_resource_result(spm, (const char *)in, len);
		break;

	case SAIB_RX_REBUILD:
		reb = (sai_rebuild_t *)spm->a.dest;

		lwsl_notice("%s: REBUILD: %s\n", __func__, reb->builder_name);

		if (suspender_exists) {
			uint8_t b = 3;
			int fd = saib_suspender_get_pipe();

			if (write(fd, &b, 1) != 1)
				lwsl_err("%s: Failed to write to suspender\n",
					 __func__);
		}
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

/*
 * We cover requested tx for any instance of a platform that can takes tasks
 * from the same server... it means just by coming here, no particular
 * platform / sai_plat is implied...
 */

static lws_ss_state_return_t
saib_m_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf, size_t *len,
	  int *flags)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)userobj;
	unsigned int *pi = (unsigned int *)lws_buflist2_get_frag_start_or_NULL(&spm->bl_to_srv);
	char som, som1, eom, final = 1;
	size_t fsl, used;

	if (spm->tx_corrupted) {
		lwsl_err("%s: tx_corrupted, dropping connection\n", __func__);
		return LWSSSSRET_DISCONNECT_ME;
	}

	if (!spm->bl_to_srv.owner.head)
		return LWSSSSRET_TX_DONT_SEND;

	fsl = lws_buflist2_next_segment_len(&spm->bl_to_srv, NULL);

	lws_buflist2_fragment_use(&spm->bl_to_srv, NULL, 0, &som, &eom);

	if (som) {
		spm->tx_flags = *pi;
		fsl -= sizeof(int);
		lws_buflist2_fragment_use(&spm->bl_to_srv, buf, sizeof(int), &som1, &eom);
	}
	if (!(spm->tx_flags & LWSSS_FLAG_SOM))
		som = 0;

	if (fsl == 0)
		used = 0;
	else
		used = (size_t)lws_buflist2_fragment_use(&spm->bl_to_srv, (uint8_t *)buf, *len, &som1, &eom);

	if (used < fsl || !(spm->tx_flags & LWSSS_FLAG_EOM))
		final = 0;

	if (!used && !som && !final && fsl > 0)
		return LWSSSSRET_TX_DONT_SEND;

	lwsl_info("%s: sending %d bytes to server (fsl %d, len %d, flags 0x%x)\n", __func__, (int)used, (int)fsl, (int)*len, spm->tx_flags);

	*len = used;
	*flags = (som ? LWSSS_FLAG_SOM : 0) | (final ? LWSSS_FLAG_EOM : 0);

	if (*flags & LWSSS_FLAG_SOM) {
		if (spm->inside_msg) {
			lwsl_err("%s: ILLEGAL SOM! Interrupted previous message starting with: %s\n",
				 __func__, spm->last_msg_start);
			lwsl_hexdump_err(buf, *len);
		}
		lws_strnncpy(spm->last_msg_start, (const char *)buf, *len, sizeof(spm->last_msg_start));
		spm->inside_msg = 1;
	}
	if (*flags & LWSSS_FLAG_EOM)
		spm->inside_msg = 0;

	{
		size_t hysteresis_limit = (LWS_BUFLIST_OOM_LIMIT - (256 * 1024)) / 10;
		if (lws_buflist2_total_len(&spm->bl_to_srv) <= hysteresis_limit) {
			/* buflist drained enough, unpause any backpressured stdwsi */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, builder.sai_plat_owner.head) {
				sai_plat_t *sp = lws_container_of(d, sai_plat_t, sai_plat_list);
				lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, sp->nspawn_owner.head) {
					struct sai_nspawn *ns = lws_container_of(d2, struct sai_nspawn, list);
					if (ns->spm == spm) {
						for (int i = 0; i < 3; i++) {
							if (ns->stdwsi_paused[i] && ns->stdwsi[i]) {
								lwsl_notice("%s: Unpausing ch %d (tot %zu)\n", __func__, i,
									lws_buflist2_total_len(&spm->bl_to_srv));
								ns->stdwsi_paused[i] = 0;
								lws_rx_flow_control(ns->stdwsi[i], 1 | LWS_RXFLOW_REASON_USER_BOOL);
							}
						}
					}
				} lws_end_foreach_dll_safe(d2, d3);
			} lws_end_foreach_dll_safe(d, d1);

			/* unpause any backpressured shell stdwsi */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, builder.shell_owner.head) {
				struct sai_shell *sh = lws_container_of(d, struct sai_shell, list);
				if (sh->spm == spm) {
					for (int i = 0; i < 3; i++) {
						if (sh->stdwsi_paused[i] && sh->stdwsi[i]) {
							lwsl_notice("%s: Unpausing shell %s ch %d (tot %zu)\n", __func__, sh->task_uuid, i,
								lws_buflist2_total_len(&spm->bl_to_srv));
							sh->stdwsi_paused[i] = 0;
							lws_rx_flow_control(sh->stdwsi[i], 1 | LWS_RXFLOW_REASON_USER_BOOL);
						}
					}
				}
			} lws_end_foreach_dll_safe(d, d1);
		}
	}

	if (spm->bl_to_srv.owner.head) {
		lws_ss_state_return_t ret = lws_ss_request_tx(spm->ss);
		if (ret != LWSSSSRET_OK)
			lwsl_err("%s: lws_ss_request_tx returned %d\n", __func__, ret);
		return ret;
	}

	return LWSSSSRET_OK;
}

static int
cleanup_on_ss_destroy(struct lws_dll2 *d, void *user)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)user;
	sai_plat_t *sp = lws_container_of(d, sai_plat_t, sai_plat_list);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   sp->nspawn_owner.head) {
		struct sai_nspawn *ns =
			lws_container_of(d, struct sai_nspawn, list);

		if (ns->spm == spm) {
			lwsl_warn("%s: ns->spm %p, spm %p\n", __func__, ns->spm, spm);
			/*
			 * This pss is about to go away, make sure the ns
			 * can't reference it any more no matter what happens
			 */
			ns->spm = NULL;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return 0;
}

static int
cleanup_on_ss_disconnect(struct lws_dll2 *d, void *user)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)user;
	sai_plat_t *sp = lws_container_of(d, sai_plat_t, sai_plat_list);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   sp->nspawn_owner.head) {
		struct sai_nspawn *ns = lws_container_of(d,
					  struct sai_nspawn, list);

		if (ns->spm == spm) {

			lwsl_notice("%s: orphaning task %s from disconnected spm\n", __func__, ns->task ? ns->task->uuid : "unknown");

			/*
			 * This pss is about to go away, make sure the ns
			 * can't reference it any more no matter what happens
			 */

			ns->spm = NULL;

			if (ns->op && ns->op->lsp) {
				lwsl_notice("%s: killing child process for task %s due to disconnect\n", __func__, ns->task ? ns->task->uuid : "unknown");
				lws_spawn_piped_kill_child_process(ns->op->lsp);
			}
		}
	} lws_end_foreach_dll_safe(d, d1);

	return 0;
}

void
saib_sul_load_report_cb(struct lws_sorted_usec_list *sul)
{
	struct sai_plat_server *spm = lws_container_of(sul,
				       struct sai_plat_server, sul_load_report);
	char any_platform_on_this_spm_active = 0;
	int n;

	/*
	 * This builder process may have multiple platforms, each with
	 * multiple instances. We report on each platform separately so the
	 * UI can distinguish them.
	 *
	 * This SUL is per-server-connection. We iterate all platforms and
	 * for each, see if it's supposed to connect to this server.
	 *
	 * To avoid spamming idle reports, we only report if the platform
	 * is active for this server, OR if it was active the last time we
	 * checked (ie, it has just become idle, so we need to send one last
	 * report with no active tasks to clear the UI).
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, builder.sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(p, sai_plat_t, sai_plat_list);
		sai_plat_server_ref_t *ref = NULL;
		struct lwsac *ac = NULL;
		sai_load_report_t lr;
		char is_active = 0;

		/*
		 * Find the specific ref for this platform and this server
		 * connection (spm)
		 */
		lws_start_foreach_dll(struct lws_dll2 *, s, sp->servers.head) {
			sai_plat_server_ref_t *r = lws_container_of(s,
						sai_plat_server_ref_t, list);
			if (r->spm == spm) {
				ref = r;
				break;
			}
		} lws_end_foreach_dll(s);

		if (!ref) /* This platform doesn't use this server connection */
			continue;

		/*
		 * Check for active tasks on this platform for this server conn
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d, sp->nspawn_owner.head) {
			struct sai_nspawn *ns = lws_container_of(d,
							struct sai_nspawn, list);
			if (ns->spm == spm &&
			    ns->state == NSSTATE_EXECUTING_STEPS && ns->task) {
				is_active = 1;
				break;
			}
		} lws_end_foreach_dll(d);

		if (is_active)
			any_platform_on_this_spm_active = 1;

		if (!is_active && !ref->was_active)
			goto around;

		/* This platform is active for this spm, or just became idle */

		memset(&lr, 0, sizeof(lr));

		lws_strncpy(lr.builder_name, sp->name, sizeof(lr.builder_name));
		lr.core_count			= saib_get_cpu_count();
		lr.initial_free_ram_kib		= saib_get_total_ram_kib();
		lr.initial_free_disk_kib	= saib_get_total_disk_kib(builder.home);
		lr.reserved_ram_kib		= 0;
		lr.reserved_disk_kib		= 0;
		lr.cpu_percent			= (unsigned int)saib_get_system_cpu(&builder);
		lr.active_steps			= 0;
		lws_dll2_owner_clear(&lr.active_tasks);

		if (is_active) {
			lws_start_foreach_dll(struct lws_dll2 *, d, sp->nspawn_owner.head) {
				struct sai_nspawn *ns = lws_container_of(d, struct sai_nspawn, list);

				if (ns->spm == spm &&
				    ns->state == NSSTATE_EXECUTING_STEPS && ns->task) {
					sai_active_task_info_t *ati = lwsac_use_zero(&ac, sizeof(*ati), 512);

					if (ati) {
						lws_strncpy(ati->task_uuid, ns->task->uuid, sizeof(ati->task_uuid));
						lws_strncpy(ati->task_name, ns->task->taskname, sizeof(ati->task_name));
						ati->build_step		= ns->task->build_step;
						ati->total_steps	= ns->task->build_step_count;
						ati->est_peak_mem_kib	= ns->task->est_peak_mem_kib;
						ati->est_disk_kib	= ns->task->est_disk_kib;
						ati->started		= ns->task->started;
						ati->idle		= ns->task->idle;
						if (ns->task->repo_name)
							lws_strncpy(ati->repo_name, ns->task->repo_name, sizeof(ati->repo_name));
						if (ns->task->git_hash)
							lws_strncpy(ati->git_hash, ns->task->git_hash, sizeof(ati->git_hash));
						lws_dll2_add_tail(&ati->list, &lr.active_tasks);
						lr.active_steps++;

						lr.reserved_ram_kib	+= ns->task->est_peak_mem_kib;
						lr.reserved_disk_kib	+= ns->task->est_disk_kib;
					}
				}
			} lws_end_foreach_dll(d);
		}

		n = saib_srv_queue_json_fragments_helper(spm->ss,
				lsm_schema_json_loadreport,
				LWS_ARRAY_SIZE(lsm_schema_json_loadreport), &lr);

		lwsac_free(&ac);

		if (n)
			lwsl_warn("%s: failed to queue fragments\n", __func__);

		ref->was_active = is_active;

around:
		;
	} lws_end_foreach_dll(p);

	if (any_platform_on_this_spm_active)
		/* Reschedule the timer only if at least one active instance */
		lws_sul_schedule(builder.context, 0, &spm->sul_load_report,
			saib_sul_load_report_cb, SAI_LOAD_REPORT_US);
}

static lws_ss_state_return_t
saib_m_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	struct sai_plat_server *spm = (struct sai_plat_server *)userobj;
	struct lejp_ctx *ctx;
	struct jpargs *a;
	const char *pq;
	int n;

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {

	case LWSSSCS_CREATING:
		ctx = (struct lejp_ctx *)spm->opaque_data;
		a = (struct jpargs *)ctx->user;

		/*
		 * Since we're "nailed up", we'll try to initiate the connection
		 * straight away after calling back CREATING... so we need to
		 * initialize any metadata etc here.
		 */

		spm->index = a->next_server_index++;

		/* hook the ss up to the server url */

		spm->url = lwsac_use(&a->builder->conf_head,
				    2 *((unsigned int)ctx->npos + 1), 512);
		memcpy((char *)spm->url, ctx->buf, ctx->npos);
		((char *)spm->url)[ctx->npos] = '\0';

		lwsl_notice("%s: binding ss to %s\n", __func__, spm->url);
		if (lws_ss_set_metadata(spm->ss, "url", spm->url, strlen(spm->url)))
			lwsl_warn("%s: unable to set metadata\n", __func__);

		pq = spm->url;
		while (*pq && (pq[0] != '/' || pq[1] != '/'))
			pq++;

		if (*pq) {
			n = 0;
			pq += 2;
			while (pq[n] && pq[n] != '/')
				n++;
		} else {
			pq = spm->url;
			n = ctx->npos;
		}

		spm->name = spm->url + ctx->npos + 1;
		memcpy((char *)spm->name, pq, (unsigned int)n);
		((char *)spm->name)[n] = '\0';

		lwsl_user("%s: initial spm->name: '%s', url: '%s'\n", __func__, spm->name, spm->url);

		{
			char *p_name = (char *)spm->name;
			char *p_found;

			while ((p_found = strchr(p_name, '.')))
				*p_found = '_';
			while ((p_found = strchr(p_name, '/')))
				*p_found = '_';
		}

		lwsl_user("%s: processed spm->name: '%s'\n", __func__, spm->name);

		/* add us to the builder list of unique servers */
		lws_dll2_add_head(&spm->list, &a->builder->sai_plat_server_owner);

		/* add us to this platforms's list of servers it accepts */
		a->mref->spm = spm;
		spm->refcount++;
		lws_dll2_add_tail(&a->mref->list, &a->sai_plat->servers);

		break;

	case LWSSSCS_DESTROYING:

		/*
		 * If the logical SS itself is going down, every platform that
		 * used us to connect to their server and has nspawns are also
		 * going down
		 */
		lws_dll2_foreach_safe(&builder.sai_plat_owner, spm,
				      cleanup_on_ss_destroy);

		break;

	case LWSSSCS_CONNECTED:
		lwsl_ss_user(spm->ss, "CONNECTED");

		/* Reset corruption flags and discard broken buflist on reconnect */
		spm->tx_corrupted = 0;
		spm->inside_msg = 0;
		spm->last_msg_start[0] = '\0';
		lws_buflist2_destroy_all_segments(&spm->bl_to_srv);

		/* Initialize the load report SUL timer for this server connection */
		lws_sul_schedule(builder.context, 0, &spm->sul_load_report,
				 saib_sul_load_report_cb, 1);

		/*
		 * sai-server refuses to process anything from us until we
		 * prove the fleet link secret, so it has to be the first
		 * message on the (re)connection, ahead of the plats.
		 */
		{
			uint8_t abuf[LWS_PRE + 256];
			size_t al;

			if (!builder.link_key)
				lwsl_err("%s: no link-key in conf, "
					 "sai-server will refuse us\n",
					 __func__);

			al = (size_t)lws_snprintf((char *)abuf + LWS_PRE,
					sizeof(abuf) - LWS_PRE,
					"{\"schema\":\"" SAI_LINKAUTH_SCHEMA
					"\",\"secret\":\"%s\"}",
					builder.link_key ?
						builder.link_key : "");

			if (saib_srv_queue_tx(spm->ss, abuf + LWS_PRE, al,
					      LWSSS_FLAG_SOM |
					      LWSSS_FLAG_EOM))
				return -1;
		}

		if (saib_srv_queue_json_fragments_helper(spm->ss,
				lsm_schema_map_plat,
				LWS_ARRAY_SIZE(lsm_schema_map_plat),
				&builder.sai_plat_owner))
			return -1;

		{
			sai_active_shells_t ash;
			struct lwsac *ac = NULL;
			
			memset(&ash, 0, sizeof(ash));
			lws_start_foreach_dll(struct lws_dll2 *, d, builder.shell_owner.head) {
				struct sai_shell *sh = lws_container_of(d, struct sai_shell, list);
				sai_active_shell_t *s = lwsac_use_zero(&ac, sizeof(*s), 512);
				if (s) {
					lws_strncpy(s->task_uuid, sh->task_uuid, sizeof(s->task_uuid));
					lws_dll2_add_tail(&s->list, &ash.shells);
				}
			} lws_end_foreach_dll(d);

			if (ash.shells.head) {
				saib_srv_queue_json_fragments_helper(spm->ss,
					lsm_schema_map_active_shells,
					LWS_ARRAY_SIZE(lsm_schema_map_active_shells),
					&ash);
			}
			lwsac_free(&ac);
		}

		return 0;

	case LWSSSCS_DISCONNECTED:
		/*
		 * clean up any ongoing spawns related to this connection
		 */

		lwsl_ss_user(spm->ss, "DISCONNECTED");
		lws_sul_cancel(&spm->sul_load_report);
		lws_dll2_foreach_safe(&builder.sai_plat_owner, spm,
				      cleanup_on_ss_disconnect);
		break;

	case LWSSSCS_ALL_RETRIES_FAILED:
		lwsl_user("%s: LWSSSCS_ALL_RETRIES_FAILED\n", __func__);
		return lws_ss_request_tx(spm->ss);

	case LWSSSCS_QOS_ACK_REMOTE:
		lwsl_notice("%s: LWSSSCS_QOS_ACK_REMOTE\n", __func__);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

const lws_ss_info_t ssi_sai_builder = {
	.handle_offset = offsetof(struct sai_plat_server, ss),
	.opaque_user_data_offset = offsetof(struct sai_plat_server, opaque_data),
	.rx = saib_m_rx,
	.tx = saib_m_tx,
	.state = saib_m_state,
	.user_alloc = sizeof(struct sai_plat_server),
	.streamtype = "sai_builder"
};
