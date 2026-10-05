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
#include <time.h>

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

	return sai_ss_tx_from_buflist_helper(g->ss, &g->bl_tx,
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
	case LWSSSCS_CREATING:
		lwsl_notice("%s: CREATING sai-power client connection to %s\n", __func__, builder.url_sai_power);
		if (lws_ss_set_metadata(g->ss, "url",
					builder.url_sai_power,
					strlen(builder.url_sai_power)))
			lwsl_err("%s: failed to set metadata\n", __func__);
		break;

	case LWSSSCS_CONNECTED:
		lwsl_notice("%s: Connected to sai-power, sending registration: '%s' '%s'\n", __func__, builder.host ? builder.host : "unknown", builder.power_controller_name ? builder.power_controller_name : "none");

		/* Prepare registration message */
		memset(&r, 0, sizeof(r));

		lws_strncpy(r.builder_name, builder.host, sizeof(r.builder_name));
		if (builder.power_controller_name)
			lws_strncpy(r.power_controller_name, builder.power_controller_name, sizeof(r.power_controller_name));
		else
			lws_strncpy(r.power_controller_name, "unknown", sizeof(r.power_controller_name));

		if (builder.power_on_type)
			lws_strncpy(r.power_on_type, builder.power_on_type, sizeof(r.power_on_type));
		if (builder.power_on_url)
			lws_strncpy(r.power_on_url, builder.power_on_url, sizeof(r.power_on_url));
		if (builder.power_on_mac)
			lws_strncpy(r.power_on_mac, builder.power_on_mac, sizeof(r.power_on_mac));
		if (builder.power_off_type)
			lws_strncpy(r.power_off_type, builder.power_off_type, sizeof(r.power_off_type));
		if (builder.power_off_url)
			lws_strncpy(r.power_off_url, builder.power_off_url, sizeof(r.power_off_url));
		if (builder.power_monitor_url)
			lws_strncpy(r.power_monitor_url, builder.power_monitor_url, sizeof(r.power_monitor_url));

		/*
		 * sai-power refuses the registration without the fleet link
		 * secret
		 */
		if (!builder.link_key)
			lwsl_err("%s: no link-key in conf, sai-power will "
				 "refuse our registration\n", __func__);
		else
			lws_strncpy(r.secret, builder.link_key,
				    sizeof(r.secret));

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
		sai_ss_serialize_queue_helper(g->ss, &g->bl_tx,
					      lsm_schema_builder_registration,
					      LWS_ARRAY_SIZE(lsm_schema_builder_registration),
					      &r);

		lwsac_free(&ac);
		break;

	case LWSSSCS_DISCONNECTED:
		lwsl_notice("%s: Disconnected from sai-power\n", __func__);
		lws_buflist_destroy_all_segments(&g->bl_tx);
		break;

	case LWSSSCS_ALL_RETRIES_FAILED:
		lwsl_err("%s: Failed to connect to sai-power\n", __func__);
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


/*
 * Auto power management
 *
 * Everything that can ask the machine to suspend, shut down or exit, and
 * everything that tells the servers we are going away, is driven from one
 * state machine.  Commands to the suspender helper and requests to sai-power
 * are only ever issued on a state transition, so they cannot be repeated or
 * interleaved with their counter-commands, and nothing in here ever blocks
 * the event loop waiting for the power change to happen.
 *
 *   ACTIVE ------(idle)------> IDLE ---(grace expired)---+
 *     ^  ^                       ^                       |
 *     |  |                   HOLDOFF <---(failed)---+    |
 *     |  |                                          |    v
 *     |  +--(busy)-- SUSPEND_WAIT --(flushed)--> SUSPENDING --(resumed)--> IDLE
 *     |                                             |
 *     +--(one-shot)--- OFF_REQ --(ACK)--> OFF_WAIT -+  (NAK / no reply -> HOLDOFF)
 *
 * Once a suspend byte has been written or sai-power has been asked to cut
 * the power we are committed: platforms are flagged powering_down, offered
 * tasks are rejected BUSY, and a busy event can no longer abort.  If the
 * power change does not happen by its deadline we clear the flags, tell the
 * servers we are back, and hold off before trying again.
 */

static const char * const pwr_state_names[] = {
	"ACTIVE", "IDLE", "HOLDOFF", "SUSPEND_WAIT", "SUSPENDING",
	"OFF_REQ", "OFF_WAIT"
};

static const char * const pwr_ev_names[] = {
	"BUSY", "IDLE", "TIMER", "POWER_ACK", "POWER_NAK"
};

static void
sul_power_cb(lws_sorted_usec_list_t *sul);

/*
 * What, if anything, can we actually do about being idle on this platform
 * with this configuration?
 */

enum {
	SAIB_PWR_CAN_SUSPEND	= (1 << 0), /* suspender helper, suspend type */
	SAIB_PWR_CAN_OFF	= (1 << 1), /* sai-power + suspender to halt */
	SAIB_PWR_CAN_EXIT	= (1 << 2), /* one-shot: just exit the process */
};

static int
saib_power_capable(void)
{
	int caps = 0;

#if defined(__APPLE__)
	/*
	 * macOS sleeps by itself once the wakelock is released at the end of
	 * the last task, see saib_wakelock(): nothing for us to action here
	 */
	return 0;
#endif

	if (builder.one_shot_active)
		caps |= SAIB_PWR_CAN_EXIT;

	if (!suspender_exists)
		return caps;

	if (builder.power_off_type && !strcmp(builder.power_off_type, "suspend"))
		caps |= SAIB_PWR_CAN_SUSPEND;
	else if (builder.url_sai_power)
		caps |= SAIB_PWR_CAN_OFF;

	return caps;
}

/*
 * Tell every server we talk to whether our platforms are on their way down.
 * While powering_down is set, saib_can_accept_task() rejects offers BUSY;
 * re-sending the platforms with it cleared is also what lets the server
 * clear the BUSY marking and offer us work again.
 */

static void
saib_power_notify_servers(int down)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, builder.sai_plat_owner.head) {
		sai_plat_t *p = lws_container_of(d, sai_plat_t, sai_plat_list);

		p->powering_down = down;
	} lws_end_foreach_dll(d);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      builder.sai_plat_server_owner.head) {
		struct sai_plat_server *spm = lws_container_of(d,
					struct sai_plat_server, list);

		if (saib_srv_queue_json_fragments_helper(spm->ss,
					lsm_schema_map_plat,
					LWS_ARRAY_SIZE(lsm_schema_map_plat),
					&builder.sai_plat_owner))
			lwsl_warn("%s: unable to queue plats for %s\n",
				  __func__, spm->name ? spm->name : "?");
	} lws_end_foreach_dll(d);
}

/*
 * Hand a command byte to the suspender helper process, which has the
 * privileges to action it.  0 = shutdown, 1 = suspend, 3 = rebuild.
 */

static int
saib_power_command(uint8_t cmd)
{
	int fd;

	if (!suspender_exists) {
		lwsl_err("%s: no suspender helper on this platform\n", __func__);
		return -1;
	}

	fd = saib_suspender_get_pipe();
	if (fd < 0 || write(fd, &cmd, 1) != 1) {
		lwsl_err("%s: unable to send command %d to suspender\n",
			 __func__, cmd);
		return -1;
	}

	builder.power_action_time	= time(NULL);
	builder.power_action_us		= lws_now_usecs();

	return 0;
}

/*
 * Did the machine actually go away since saib_power_command()?  The lws
 * monotonic clock does not advance while suspended but wall time does, so a
 * large difference between the two elapsed times means we went down and came
 * back.
 */

static int
saib_power_resumed(void)
{
	long long wall = (long long)(time(NULL) - builder.power_action_time),
		  mono = (long long)((lws_now_usecs() - builder.power_action_us) /
				     LWS_US_PER_SEC);

	return wall > mono + 20;
}

static void
saib_power_set_state(enum saib_power_state s, lws_usec_t timeout_us)
{
	lwsl_notice("%s: power state %s -> %s%s\n", __func__,
		    pwr_state_names[builder.power_state], pwr_state_names[s],
		    timeout_us ? " (timer armed)" : "");

	builder.power_state = s;

	lws_sul_cancel(&builder.sul_power);
	if (timeout_us)
		lws_sul_schedule(builder.context, 0, &builder.sul_power,
				 sul_power_cb, timeout_us);
}

static void
saib_power_exit(const char *why)
{
	lwsl_notice("%s: one-shot: %s, exiting builder cleanly\n", __func__, why);
	lws_sul_cancel(&builder.sul_power);
	builder.power_state = SAIB_PWR_ACTIVE;
	interrupted = 1;
	lws_cancel_service(builder.context);
}

/*
 * A power action did not happen.  Withdraw the powering_down claim, and hold
 * off for a while before we consider going idle again, so a broken setup
 * does not spin.
 */

static void
saib_power_failed(const char *why)
{
	builder.power_fail_count++;
	lwsl_err("%s: %s (failure %d)\n", __func__, why,
		 builder.power_fail_count);

	if (builder.one_shot_active) {
		saib_power_exit(why);
		return;
	}

	saib_power_notify_servers(0);
	saib_power_set_state(SAIB_PWR_HOLDOFF, SAI_POWER_RETRY_HOLDOFF_US);
}

/*
 * Grace time is up and nothing came along: start whatever we are able to do
 */

static void
saib_power_start_action(void)
{
	int caps = saib_power_capable();
	lws_ss_state_return_t r;

	if (caps & SAIB_PWR_CAN_SUSPEND) {
		lwsl_notice("%s: idle grace expired, preparing to suspend\n",
			    __func__);
		saib_power_notify_servers(1);
		saib_power_set_state(SAIB_PWR_SUSPEND_WAIT,
				     SAI_POWER_NOTIFY_FLUSH_US);
		return;
	}

	if (!(caps & SAIB_PWR_CAN_OFF) && !builder.url_sai_power) {
		if (caps & SAIB_PWR_CAN_EXIT) {
			saib_power_exit("idle and no sai-power");
			return;
		}

		/* shouldn't get here: the grace timer is only armed if capable */
		saib_power_set_state(SAIB_PWR_ACTIVE, 0);
		return;
	}

	/*
	 * Ask sai-power to cut our power after its holdoff; if it agrees we
	 * shut down cleanly in the meantime.  One-shot VMs go the same way,
	 * the virt host terminates them.
	 */

	lws_snprintf(builder.path_power_off, sizeof(builder.path_power_off),
		     "%s/auto-power-off/%s", builder.url_sai_power,
		     builder.host ? builder.host : "unknown");

	lwsl_notice("%s: idle grace expired, asking sai-power to power us off: %s\n",
		    __func__, builder.path_power_off);

	saib_power_notify_servers(1);
	saib_power_set_state(SAIB_PWR_OFF_REQ, SAI_POWER_OFF_REPLY_US);

	r = lws_ss_set_metadata(builder.ss_power_off, "url",
				builder.path_power_off,
				strlen(builder.path_power_off));
	if (r)
		lwsl_err("%s: set_metadata said %d\n", __func__, (int)r);

	r = lws_ss_client_connect(builder.ss_power_off);
	if (r)
		lwsl_ss_err(builder.ss_power_off,
			    "Unable to connect ss_power_off (%d)", (int)r);

	lws_ss_start_timeout(builder.ss_power_off, 3000); /* 3 sec */

	if (lws_ss_request_tx(builder.ss_power_off))
		lwsl_ss_warn(builder.ss_power_off, "Unable to request tx");
}

void
saib_power_event(enum saib_power_event ev)
{
	enum saib_power_state s = builder.power_state;

	lwsl_info("%s: state %s, event %s\n", __func__, pwr_state_names[s],
		  pwr_ev_names[ev]);

	switch (s) {
	case SAIB_PWR_ACTIVE:
		if (ev != SAIB_PWR_EV_IDLE)
			break;

		if (!saib_power_capable()) {
#if !defined(__APPLE__)
			if (!builder.power_unavailable_logged &&
			    (builder.url_sai_power || builder.power_off_type)) {
				builder.power_unavailable_logged = 1;
				lwsl_warn("%s: idle, but no way to suspend or "
					  "power off on this platform: auto "
					  "power management disabled\n",
					  __func__);
			}
#endif
			break;
		}

		lwsl_notice("%s: %s: no stay and no tasks: starting %ds idle "
			    "grace time\n", __func__,
			    builder.host ? builder.host : "unknown",
			    (int)(SAI_IDLE_GRACE_US / LWS_US_PER_SEC));
		saib_power_set_state(SAIB_PWR_IDLE, SAI_IDLE_GRACE_US);
		break;

	case SAIB_PWR_IDLE:
		if (ev == SAIB_PWR_EV_BUSY) {
			lwsl_notice("%s: busy: cancelling idle grace time\n",
				    __func__);
			saib_power_set_state(SAIB_PWR_ACTIVE, 0);
			break;
		}
		if (ev == SAIB_PWR_EV_TIMER)
			saib_power_start_action();
		break;

	case SAIB_PWR_HOLDOFF:
		if (ev == SAIB_PWR_EV_BUSY) {
			saib_power_set_state(SAIB_PWR_ACTIVE, 0);
			break;
		}
		if (ev == SAIB_PWR_EV_TIMER)
			/* holdoff over, reassess from scratch */
			saib_power_set_state(SAIB_PWR_IDLE, SAI_IDLE_GRACE_US);
		break;

	case SAIB_PWR_SUSPEND_WAIT:
		if (ev == SAIB_PWR_EV_BUSY) {
			/* nothing irreversible done yet: abort */
			lwsl_notice("%s: busy: aborting suspend\n", __func__);
			saib_power_notify_servers(0);
			saib_power_set_state(SAIB_PWR_ACTIVE, 0);
			break;
		}
		if (ev != SAIB_PWR_EV_TIMER)
			break;

		lwsl_notice("%s: actioning suspend\n", __func__);
		if (saib_power_command(1)) {
			saib_power_failed("unable to request suspend");
			break;
		}
		saib_power_set_state(SAIB_PWR_SUSPENDING,
				     SAI_POWER_SUSPEND_DEADLINE_US);
		break;

	case SAIB_PWR_SUSPENDING:
		if (ev != SAIB_PWR_EV_TIMER && ev != SAIB_PWR_EV_BUSY)
			break;

		if (!saib_power_resumed()) {
			if (ev == SAIB_PWR_EV_TIMER)
				saib_power_failed("suspend didn't happen");
			else
				lwsl_warn("%s: busy while suspending, "
					  "too late to abort\n", __func__);
			break;
		}

		lwsl_notice("%s: resumed after suspend\n", __func__);
		builder.power_fail_count = 0;
		saib_power_notify_servers(0);
		saib_power_set_state(ev == SAIB_PWR_EV_BUSY ? SAIB_PWR_ACTIVE :
				     SAIB_PWR_IDLE,
				     ev == SAIB_PWR_EV_BUSY ? 0 : SAI_IDLE_GRACE_US);
		break;

	case SAIB_PWR_OFF_REQ:
		switch (ev) {
		case SAIB_PWR_EV_POWER_ACK:
			lwsl_notice("%s: sai-power scheduled our power-off: "
				    "shutting down\n", __func__);
			if (!suspender_exists && builder.one_shot_active) {
				/* the virt host will terminate us */
				saib_power_set_state(SAIB_PWR_OFF_WAIT,
						     SAI_POWER_OFF_DEADLINE_US);
				break;
			}
			if (saib_power_command(0)) {
				saib_power_failed("unable to request shutdown");
				break;
			}
			saib_power_set_state(SAIB_PWR_OFF_WAIT,
					     SAI_POWER_OFF_DEADLINE_US);
			break;
		case SAIB_PWR_EV_POWER_NAK:
			lwsl_notice("%s: sai-power declined to power us off\n",
				    __func__);
			saib_power_notify_servers(0);
			saib_power_set_state(SAIB_PWR_HOLDOFF,
					     SAI_POWER_RETRY_HOLDOFF_US);
			break;
		case SAIB_PWR_EV_TIMER:
			saib_power_failed("no reply from sai-power");
			break;
		case SAIB_PWR_EV_BUSY:
			lwsl_warn("%s: busy while power-off requested, "
				  "too late to abort\n", __func__);
			break;
		default:
			break;
		}
		break;

	case SAIB_PWR_OFF_WAIT:
		if (ev == SAIB_PWR_EV_TIMER)
			saib_power_failed("shutdown didn't happen");
		else if (ev == SAIB_PWR_EV_BUSY)
			lwsl_warn("%s: busy while shutting down, "
				  "too late to abort\n", __func__);
		break;
	}
}

static void
sul_power_cb(lws_sorted_usec_list_t *sul)
{
	saib_power_event(SAIB_PWR_EV_TIMER);
}

/*
 * Process exit: nothing should fire after this
 */

void
saib_power_shutdown(void)
{
	lws_sul_cancel(&builder.sul_power);
	lws_sul_cancel(&builder.sul_stay);
}

/*
 * Something changed: look at what is going on and feed the state machine
 * with whether we are busy or idle.  Safe to call as often as you like.
 */

int
saib_reassess_idle_situation(void)
{
	unsigned int held;
	char in_use = 0;

	if (builder.stay) {
		/*
		 * We have been manually powered-on: never auto-power-off
		 */
		lwsl_notice("%s: %s: stay applied\n", __func__,
			    builder.host ? builder.host : "unknown");
		saib_power_event(SAIB_PWR_EV_BUSY);

		return 0;
	}

	/*
	 * If any plat on this builder has tasks, just leave it
	 */
	lws_start_foreach_dll(struct lws_dll2 *, mp, builder.sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(mp, struct sai_plat,
						       sai_plat_list);

		lws_start_foreach_dll(struct lws_dll2 *, d, sp->nspawn_owner.head) {
			struct sai_nspawn *xns = lws_container_of(d,
						struct sai_nspawn, list);

			lwsl_notice("%s: plat %s is busy with %s\n", __func__,
				    sp->name, xns->task ? xns->task->uuid :
						"an nspawn (no task uuid)");
			in_use = 1;
		} lws_end_foreach_dll(d);
	} lws_end_foreach_dll(mp);

	held = saib_jobdir_holds_live();
	if (held) {
		/*
		 * Tasks we started are between steps.  Going down would lose
		 * their job dirs (a sai-virt VM's disk goes with it) and the
		 * next step would come to a builder with no src/ tree.
		 */
		lwsl_notice("%s: %u job dirs held for started tasks\n",
			    __func__, held);
		in_use = 1;
	}

	if (builder.shell_owner.head) {
		lwsl_notice("%s: builder has %d active shell sessions\n",
			    __func__, builder.shell_owner.count);
		in_use = 1;
	}

	if (saib_pool_busy()) {
		/* what the last tasks left in their pools isn't synced yet */
		lwsl_notice("%s: pools still syncing\n", __func__);
		in_use = 1;
	}

	saib_power_event(in_use ? SAIB_PWR_EV_BUSY : SAIB_PWR_EV_IDLE);

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
	lwsl_notice("%s: Received stay command: '%c' (stay=%d)\n", __func__, *buf, builder.stay);

	saib_reassess_idle_situation();

	return 0;
}

static lws_ss_state_return_t
saib_power_stay_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		   size_t *len, int *flags)
{
	*len = 0;
	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power", saib_power_stay_t)
	.rx				= saib_power_stay_rx,
	.tx				= saib_power_stay_tx,
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

	if (lws_ss_request_tx(builder.ss_stay))
		lwsl_ss_warn(builder.ss_stay, "Unable to request tx");

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
saib_power_link_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		   size_t *len, int *flags)
{
	lwsl_notice("====== saib_power_link_tx called (GET request firing) ======\n");
	*len = 0;
	*flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_power_link_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	if (len < 4 || !(flags & LWSSS_FLAG_SOM))
		return 0;

	if (memcmp(buf, "ACK:", 4)) {
		lwsl_warn("%s: sai-power didn't start power-off: %.*s\n",
			  __func__, (int)len, (const char *)buf);
		saib_power_event(SAIB_PWR_EV_POWER_NAK);

		return LWSSSSRET_OK;
	}

	lwsl_notice("%s: sai-power: %.*s\n", __func__, (int)len,
		    (const char *)buf);
	saib_power_event(SAIB_PWR_EV_POWER_ACK);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
saib_power_link_state(void *userobj, void *sh, lws_ss_constate_t state,
		      lws_ss_tx_ordinal_t ack)
{
	switch (state) {
	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_TIMEOUT:
		/* the state machine only cares if it is waiting for a reply */
		lwsl_warn("%s: %s: sai-power unreachable\n", __func__,
			  lws_ss_state_name(state));
		saib_power_event(SAIB_PWR_EV_POWER_NAK);
		break;
	default:
		break;
	}

	return LWSSSSRET_OK;
}

LWS_SS_INFO("sai_power", saib_power_link_t)
	.rx				= saib_power_link_rx,
	.tx				= saib_power_link_tx,
	.state				= saib_power_link_state,
};
int
saib_power_init(void)
{
	/*
	 * Do we have a url for sai-power?  If not, nothing we can do.
	 */

	lwsl_notice("====== ENTERED SAIB_POWER_INIT ======\n");

	if (!builder.url_sai_power) {
		lwsl_notice("%s: no url_sai_power: sai-power integration disabled\n",
			    __func__);
		/* we may still be configured to suspend when idle */
		saib_reassess_idle_situation();
		return 0;
	}

	lwsl_notice("====== URL_SAI_POWER IS: %s ======\n", builder.url_sai_power);

	/* Existing SS creation for power-off logic */
	lwsl_notice("%s: *** creating sai-power ss...\n", __func__);

	if (lws_ss_create(builder.context, 0, &ssi_saib_power_link_t,
			  (void *)(builder.host ? builder.host : ""), &builder.ss_power_off, NULL, NULL)) {
		lwsl_err("%s: *** failed to create sai-power ss\n", __func__);
		return 1;
	}

	saib_reassess_idle_situation();

	lwsl_notice("%s: *** creating sai-power client ss...\n", __func__);

	if (!builder.one_shot_active) {
		if (lws_ss_create(builder.context, 0, &ssi_saib_power_client_t,
				  NULL, &ss_power_client, NULL, NULL)) {
			lwsl_err("%s: *** failed to create sai-power client ss\n", __func__);
			return 1;
		}
	} else {
		lwsl_notice("%s: ephemeral VM, skipping sai_power_client websocket registration\n", __func__);
	}

	/*
	 * Set metadata for URL? The policy handles 'sai_power' endpoint.
	 * We might need to ensure the policy matches what we expect.
	 * The existing code assumes 'sai_power' policy exists.
	 */
	lws_ss_state_return_t r;

	if (ss_power_client) {
		lwsl_notice("%s: ****** starting sai-power-client link %s\n", __func__, builder.url_sai_power);

		if (lws_ss_set_metadata(ss_power_client, "url", builder.url_sai_power,
					strlen(builder.url_sai_power)))
			lwsl_warn("%s: unable to set url metadata\n", __func__);

		r = lws_ss_request_tx(ss_power_client);
		if (r)
			lwsl_notice("%s: initial tx request says %d\n", __func__, (int)r);
	}

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
