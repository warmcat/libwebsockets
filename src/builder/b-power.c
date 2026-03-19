/*
 * sai-builder - src/builder/b-power.c
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
#include <limits.h>
#include <stdlib.h>

#include <sys/types.h>

#include "b-private.h"

extern struct lws_spawn_piped *lsp_suspender;
struct lws_ss_handle *ss_power_client = NULL;

/*
 * Registration message logic
 */

LWS_SS_USER_TYPEDEF
        char                    payload[200];
        size_t                  size;
        size_t                  pos;
	struct lws_buflist	*bl_tx;
} saib_power_client_t;

static lws_ss_state_return_t
saib_power_client_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		     size_t *len, int *flags)
{
	saib_power_client_t *g = (saib_power_client_t *)userobj;

	return sai_ss_tx_from_buflist_helper(ss_power_client, &g->bl_tx,
					     buf, len, flags);
}

static lws_ss_state_return_t
saib_power_client_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	/* We don't really expect RX from sai-power on this link currently
	 * other than maybe stay info if we merged that logic.
	 * For now, ignore.
	 */
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_power_client_state(void *userobj, void *sh, lws_ss_constate_t state,
			lws_ss_tx_ordinal_t ack)
{
	saib_power_client_t *g = (saib_power_client_t *)userobj;
	sai_builder_registration_t r;
	struct lwsac *ac = NULL;

	lwsl_user("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	switch (state) {
	case LWSSSCS_CONNECTED:
		lwsl_notice("%s: Connected to sai-power, sending registration: '%s' '%s'\n", __func__, builder.host, builder.power_controller_name);

		/* Prepare registration message */
		memset(&r, 0, sizeof(r));

		lws_strncpy(r.builder_name, builder.host, sizeof(r.builder_name));
		if (builder.power_controller_name)
			lws_strncpy(r.power_controller_name, builder.power_controller_name, sizeof(r.power_controller_name));
		else
			lws_strncpy(r.power_controller_name, "unknown", sizeof(r.power_controller_name));

		/* Add platforms */
		lws_start_foreach_dll(struct lws_dll2 *, d, builder.sai_plat_owner.head) {
			sai_plat_t *sp = lws_container_of(d, sai_plat_t, sai_plat_list);
			sai_builder_platform_t *bp = lwsac_use_zero(&ac, sizeof(*bp), 512);

			if (bp) {
				lws_strncpy(bp->name, sp->name, sizeof(bp->name));
				lws_dll2_add_tail(&bp->list, &r.platforms_owner);
			}
		} lws_end_foreach_dll(d);

		/* Send it */
		sai_ss_serialize_queue_helper(ss_power_client, &g->bl_tx,
					      lsm_schema_builder_registration,
					      LWS_ARRAY_SIZE(lsm_schema_builder_registration),
					      &r);

		lwsac_free(&ac);
		break;

	case LWSSSCS_DISCONNECTED:
		lwsl_notice("%s: Disconnected from sai-power\n", __func__);
		lws_buflist_destroy_all_segments(&g->bl_tx);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power_client", saib_power_client_t)
	.rx			= saib_power_client_rx,
	.tx			= saib_power_client_tx,
	.state			= saib_power_client_state,
};


int
saib_reassess_idle_situation()
{
	char in_use = 0;

	if (builder.stay) {
		/*
		 * We need to deal with finding we have been manually powered-on.
		 * Just cancel any pending grace period
		 */
		lws_sul_cancel(&builder.sul_idle);

		lwsl_warn("%s: %s: stay applied: cancelled idle grace time\n",
					__func__, builder.host);

		return 0;
	}

	/*
	 * If any plat on this builder has tasks, just leave it
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
				builder.sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(mp, struct sai_plat,
				sai_plat_list);

		if (sp->nspawn_owner.head) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						   sp->nspawn_owner.head) {
				struct sai_nspawn *xns = lws_container_of(d,
							struct sai_nspawn, list);

				if (xns->task)
				lwsl_notice("%s: ongoing task: %s\n", __func__,
							xns->task->uuid);

			} lws_end_foreach_dll_safe(d, d1);

			lws_sul_cancel(&builder.sul_idle);
			in_use = 1;
		}

	} lws_end_foreach_dll_safe(mp, mp1);

	if (in_use) {
		lwsl_warn("%s: cancelling idle grace time as ongoing task steps\n", __func__);

		return 0;
	}

	/*
	* if no ongoing tasks, and we want to go OFF, then start
	* the idle grace timer.  This will get cancelled if
	* we start a task during the grace time, otherwise it will
	* expire and do the power-off or suspend
	*/

	if (lws_dll2_is_detached(&builder.sul_idle.list)) {
		lwsl_warn("%s: %s: no stay: starting idle grace time\n",
			__func__, builder.host);
		lws_sul_schedule(builder.context, 0, &builder.sul_idle,
				 sul_idle_cb, SAI_IDLE_GRACE_US);
	}

	return 0;
}

/*
 * This is used to check with sai-power if we should stay up (due to the power
 * being turned on manually)
 */


LWS_SS_USER_TYPEDEF
        char                    payload[200];
        size_t                  size;
        size_t                  pos;
} saib_power_stay_t;


static lws_ss_state_return_t
saib_power_stay_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	if (len < 1)
		return 0;

	builder.stay = *buf != '0';

	saib_reassess_idle_situation();

	return 0;
}

LWS_SS_INFO("sai_power", saib_power_stay_t)
	.rx				= saib_power_stay_rx,
};


void
sul_stay_cb(lws_sorted_usec_list_t *sul)
{
	lws_ss_state_return_t r;

	/* nothing to do if no sai-power coordinates given */
	if (!builder.url_sai_power)
		return;

	r = lws_ss_client_connect(builder.ss_stay);
	if (r)
		lwsl_ss_err(builder.ss_stay, "Unable to start stay connection (%d)", (int)r);

	lws_sul_schedule(builder.context, 0, &builder.sul_stay,
			 sul_stay_cb, SAI_STAY_POLL_US);
}

int
saib_stay_init(void)
{
	lws_ss_state_return_t r;

	/*
	 * ss used to query sai-power about stay situation
	 */

	if (lws_ss_create(builder.context, 0, &ssi_saib_power_stay_t,
			  NULL, &builder.ss_stay, NULL, NULL)) {
		lwsl_err("%s: failed to create sai-power-stay ss (ignoring)\n", __func__);
		return 0;
	}

	if (!builder.url_sai_power)
		return 0;

	if (!suspender_exists)
		return LWSSSSRET_OK;

	snprintf(builder.path, sizeof(builder.path) - 1, "%s/stay/%s",
		 builder.url_sai_power, builder.host);

	r = lws_ss_set_metadata(builder.ss_stay, "url", builder.path, strlen(builder.path));
	if (r)
		lwsl_err("%s: set_metadata said %d\n", __func__, (int)r);

	lws_sul_schedule(builder.context, 0, &builder.sul_stay,
			 sul_stay_cb, 1000);

	return 0;
}


/*
 * This is used to fire http request to sai-power for power-down
 */

LWS_SS_USER_TYPEDEF
        char                    payload[200];
        size_t                  size;
        size_t                  pos;
} saib_power_link_t;

static lws_ss_state_return_t
saib_power_link_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
#if !defined(WIN32)
	int fd = saib_suspender_get_pipe();
	uint8_t te = 0;
	ssize_t n;

	if (len < 4 || !(flags & LWSSS_FLAG_SOM))
		return 0;

	if (memcmp(buf, "ACK:", 4)) {
		lwsl_warn("%s: sai-power didn't start power-off: %.*s\n",
				__func__, (int)len, (const char *)buf);
		return LWSSSSRET_OK;
	}

	if (!suspender_exists)
		return LWSSSSRET_OK;

	lwsl_notice("%s: sai-power scheduling power-off: doing shutdown...\n", __func__);

	/*
	 * In the grace time for actioning the power-off, we should shutdown
	 * cleanly
	 */

	n = write(fd, &te, 1);
	if (n != 1)
		lwsl_err("%s: unable to request shutdown\n", __func__);
#endif
	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power", saib_power_link_t)
	.rx				= saib_power_link_rx,
};


static void
sul_do_suspend_cb(lws_sorted_usec_list_t *sul)
{
#if !defined(WIN32)
	int fd = saib_suspender_get_pipe();
	uint8_t te = 1;
	ssize_t n;

	lwsl_notice("%s: actioning suspend...\n", __func__);

	n = write(fd, &te, 1);
	if (n == 1) {
#if defined(WIN32)
		Sleep(2000);
#else
		sleep(2);
#endif
		/*
		 * There were 0 tasks ongoing for us to suspend, start off
		 * with the same assumption and set the idle grace time
		 */
		lws_sul_schedule(builder.context, 0, &builder.sul_idle,
				 sul_idle_cb, SAI_IDLE_GRACE_US);
		lwsl_notice("%s: resuming after suspend\n", __func__);
	} else
		lwsl_err("%s: failed to request suspend\n", __func__);
#endif
}

void
sul_shutdown_cb(lws_sorted_usec_list_t *sul)
{
	int fd = saib_suspender_get_pipe();
	uint8_t te = 0;
	ssize_t n;

	lwsl_warn("%s: device shutting down\n", __func__);

	n = write(fd, &te, 1);

	if (n != 1)
		lwsl_err("%s: shutdown request failed\n", __func__);

#if defined(WIN32)
	Sleep(40000);
#else
	sleep(40);
#endif

	lwsl_err("%s: shutdown didn't happen\n", __func__);
}

/*
 * The grace time is up, ask for the suspend
 */

void
sul_idle_cb(lws_sorted_usec_list_t *sul)
{
#if defined(__APPLE__)
	return;
#endif

	lws_ss_state_return_t r;
	char path[256];

#if !defined(WIN32)
	if (builder.stay)
		return;

	lwsl_notice("%s: idle period ended...\n", __func__);

	if (builder.power_off_type &&
	    !strcmp(builder.power_off_type, "suspend")) {

		lwsl_notice("%s: starting suspend...\n", __func__);

		/*
		 * Let everybody know we are trying to power down
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      builder.sai_plat_owner.head) {
			sai_plat_t *p = lws_container_of(d, sai_plat_t,
							 sai_plat_list);
			p->powering_down = 1;
		} lws_end_foreach_dll(d);

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      builder.sai_plat_server_owner.head) {
			struct sai_plat_server *spm = lws_container_of(d,
						struct sai_plat_server, list);

			if (saib_srv_queue_json_fragments_helper(spm->ss,
					lsm_schema_map_plat,
					LWS_ARRAY_SIZE(lsm_schema_map_plat),
					&builder.sai_plat_owner))
				return;

		} lws_end_foreach_dll(d);

		/*
		 * give the event loop a moment to send the notifications out
		 * before we do the blocking suspend part
		 */
		lws_sul_schedule(builder.context, 0, &builder.sul_do_suspend,
				 sul_do_suspend_cb, 2 * LWS_US_PER_SEC);

		return;
	}
#endif

	if (!builder.url_sai_power)
		return;

	/*
	 * We're planning to get ourselves turned off after we have shutdown
	 * cleanly.
	 *
	 * Send the request to sai-power to turn us off after 35s and then
	 * request our suspender process to shutdown the device.
	 */

	snprintf(path, sizeof(path) - 1, "%s/auto-power-off/%s",
		 builder.url_sai_power, builder.host);

	lwsl_notice("%s: setting url metadata %s\n", __func__, path);

	r = lws_ss_set_metadata(builder.ss_power_off, "url", path, strlen(path));
	if (r)
		lwsl_err("%s: set_metadata said %d\n", __func__, (int)r);

	lws_ss_start_timeout(builder.ss_power_off, 3000); /* 3 sec */

	if (lws_ss_request_tx(builder.ss_power_off))
		lwsl_ss_warn(builder.ss_power_off, "Unable to request tx");

	/* allow time for the sai-power transaction to happen */

	lws_sul_schedule(builder.context, 0, &builder.sul_do_shutdown,
			sul_shutdown_cb, 2 * LWS_US_PER_SEC);

	/* let event loop continue for a couple of seconds, then shutdown */
}

int
saib_power_init(void)
{
	/*
	 * Do we have a url for sai-power?  If not, nothing we can do.
	 */

	if (!builder.url_sai_power) {
		lwsl_err("%s: *** missing URL for url_sai_power\n", __func__);
		return 1;
	}

	/* Existing SS creation for power-off logic */
	lwsl_notice("%s: *** creating sai-power ss...\n", __func__);

	if (lws_ss_create(builder.context, 0, &ssi_saib_power_link_t,
			  (void *)builder.host, &builder.ss_power_off, NULL, NULL)) {
		lwsl_err("%s: *** failed to create sai-power ss\n", __func__);
		return 1;
	}

	saib_reassess_idle_situation();

	lwsl_notice("%s: *** creating sai-power client ss...\n", __func__);

	if (lws_ss_create(builder.context, 0, &ssi_saib_power_client_t,
			  NULL, &ss_power_client, NULL, NULL)) {
		lwsl_err("%s: *** failed to create sai-power client ss\n", __func__);

		return 1;
	}

	/*
	 * Set metadata for URL? The policy handles 'sai_power' endpoint.
	 * We might need to ensure the policy matches what we expect.
	 * The existing code assumes 'sai_power' policy exists.
	 */
	lws_ss_state_return_t r;

	lwsl_notice("%s: ****** starting sai-power-client link %s\n", __func__, builder.url_sai_power);

	if (lws_ss_set_metadata(ss_power_client, "url", builder.url_sai_power,
				strlen(builder.url_sai_power)))
		lwsl_warn("%s: unable to set url metadata\n", __func__);

	r = lws_ss_request_tx(ss_power_client);
	if (r)
		lwsl_notice("%s: initial tx request says %d\n", __func__, (int)r);

	return 0;
}

#if defined(__APPLE__)

int
saib_need_wakelock(void)
{
	int r = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
		   builder.sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(d, struct sai_plat, sai_plat_list);

		if (sp->nspawn_owner.head) /* we are busy */
			r = 1;

	} lws_end_foreach_dll(d);

	if (builder.stay) /* there's a manual stay */
		r = 1;

	return r;
}

void
sul_release_wakelock_cb(lws_sorted_usec_list_t *sul)
{
	if (!builder.wakelock_pid)
		return;

	lwsl_notice("%s: releasing wakelock (pid %d)\n", __func__,
			(int)builder.wakelock_pid);

	kill(builder.wakelock_pid, SIGTERM);
	waitpid(builder.wakelock_pid, NULL, 0);
	builder.wakelock_pid = 0;
}

void
saib_wakelock()
{
	int need = saib_need_wakelock();
	pid_t pid;

	if (( need &&  builder.wakelock_pid) ||
	    (!need && !builder.wakelock_pid))
		return;

	if (!need) {
		sul_release_wakelock_cb(NULL);
		return;
	}

	pid = fork();
	switch (pid) {
	case -1:
		lwsl_err("%s: fork for wakelock failed\n", __func__);
		break;
	case 0:
		execl("/usr/bin/caffeinate", "/usr/bin/caffeinate", "-i",
		      (char *)NULL);
		exit(1); /* should not get here */
	default:
		lwsl_notice("%s: acquired wakelock (pid %d)\n", __func__,
			    (int)pid);
		builder.wakelock_pid = pid;
		break;
	}

	/* if there's a pending wakelock release, cancel it */
	lws_sul_cancel(&builder.sul_release_wakelock);
}

#endif
