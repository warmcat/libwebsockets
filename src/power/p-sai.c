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
 *       /----------------------|---
 *      b1 --\  <---WOL--\      |   \
 *            --- [sai-power] --|- sai-server
 *      b2 --/  plug <---/      |   /
 *       \----------------------|---
 *
 * Sai-power is a daemon that runs typically on a machine on the local subnet of
 * the bulders that it is used by.  When idle, laptop-type builders may suspend
 * themselves, but while suspended, they need a helper to watch the sai-server
 * for them to see if any tasks appeared for their platform, and to restart the
 * builder when that is seen, eg, by sending a WOL magic packet.  After that,
 * the builder will reconnect to sai-server and deal with the situation that it
 * finds at sai-server itself, going back to sleep if nothing to do (eg, because
 * another builder for the same platform took the task first).
 *
 * The same situation exists for the case the builder can't suspend (like many
 * SBC) and instead powers off using a smartplug, they also need a helper to
 * talk to the smartplug for powerdown after builder shutdown; to watch the
 * sai-server on the builder's behalf while it is down; and to power the builder
 * back up by switching the builder's smartplug on when tasks for the powered-
 * down builder's platform are seen at sai-server.
 *
 * If there are builders at different sites / subnets (if using WOL) it's no
 * problem to have sai-power helpers for each subnet / site pointing to the same
 * sai-server.
 *
 * See p-comms.c for the secure stream template and callbacks for this.
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

#if defined(WIN32)
#include <initguid.h>
#include <KnownFolders.h>
#include <Shlobj.h>

int getpid(void) { return 0; }

#endif

#include "p-private.h"

static const char *config_dir = "/etc/sai/power";
static int interrupted;
static lws_state_notify_link_t nl;
#if defined(LWS_WITH_SPAWN)
struct lws_spawn_piped *lsp_wol;
#endif

struct sai_power power;

extern const lws_ss_info_t ssi_local_srv_t;

static const char * const default_ss_policy =
	"{"
	  "\"retry\": ["	/* named backoff / retry strategies */
		"{\"default\": {"
			"\"backoff\": ["	 "1000,"
						 "2000,"
						 "3000,"
						 "5000,"
						"10000"
				"],"
			"\"conceal\":"		"99999,"
			"\"jitterpc\":"		"20,"
			"\"svalidping\":"	"100,"
			"\"svalidhup\":"	"110"
		"}}"
	  "],"

	/*
	 * No certs / trust stores because we will validate using system trust
	 * store... metadata.url should be set at runtime to something like
	 * https://warmcat.com/sai
	 */

	  "\"s\": ["
		/*
		 * The main connection to sai-server
		 */
		"{\"sai_power\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"ws\","
			"\"ws_subprotocol\":"	"\"com-warmcat-sai\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"nailed_up\":"        "true,"
			"\"tls\":"		"true,"
			"\"retry\":"		"\"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}},"
		/*
		 * The ws server that builders on the local subnet
		 * connect to for help with power operations
		 */
		"{\"local\": {"
			"\"server\":"		"true,"
			"\"port\":"		"3333,"
			"\"protocol\":"		"\"ws\"," /* Changed to ws */
			"\"ws_subprotocol\":"	"\"com-warmcat-sai-builder\","
			"\"tls\":"		"false,"
			"\"metadata\": ["
				"{\"path\": \"\"},"
				"{\"method\": \"\"},"
				"{\"mime\": \"\"}"
			"]"
		"}},"
		/*
		 * Http operations to smartplugs
		 */
		"{\"sai_power_smartplug\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"port\":"		"80,"
			"\"protocol\":"		"\"h1\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"http_method\":"	"\"GET\","
			"\"tls\":"		"false,"
			"\"retry\":"		"\"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}}"
	"]}"
;

static int
callback_std(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		  void *in, size_t len)
{
	uint8_t buf[128];
	ssize_t amt;

	switch (reason) {
		case LWS_CALLBACK_RAW_RX_FILE:
			amt = read(lws_get_socket_fd(wsi), buf, sizeof(buf));
			/* the string we're getting has the CR on it already */
			lwsl_warn("%s: %.*s", __func__, (int)amt, buf);
			return 0;
		default:
			break;
	}
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}


static const struct lws_protocols protocol_std =
        { "protocol_std", callback_std, 0, 0 };

static const struct lws_protocols *pprotocols[] = {
	&protocol_std,
	NULL
};

/*
 * Check PCON state logic
 * If a PCON has NO registered builders, we default it to ON (Cold Start).
 * If a PCON has registered builders, we defer to the "Stay" logic (which comes from sai-server).
 *
 * However, there is a nuance: If we just started up, we have 0 builders. We should turn everything ON.
 * As builders connect, they register.
 */

void
sul_pcon_check_cb(lws_sorted_usec_list_t *sul)
{
	int any_changed = 0;

	/* Iterate all PCONs */
	lws_start_foreach_dll(struct lws_dll2 *, p, power.sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);
		int target_on = 0;

		/* Rule 1: No builders registered -> Turn ON (Cold start / Discovery) */
		if (!pc->registered_builders_owner.count) {
			/* target_on = 1; */
			/* lwsl_info("%s: PCON %s has 0 builders -> Force ON\n", __func__, pc->name); */
		}

		/* Rule 2: User Keep On -> Turn ON */
		if (pc->flags & SAIP_PCON_F_MANUAL_STAY) {
			target_on = 1;
			lwsl_warn("%s: PCON %s has user keep on -> Force ON\n", __func__, pc->name);
		}
		/* Rule 3: Server Requested -> Turn ON */
		else if (pc->flags & SAIP_PCON_F_NEEDED) {
			target_on = 1;
			lwsl_warn("%s: PCON %s has server request -> Force ON\n", __func__, pc->name);
		}

		lwsl_info("%s: PCON %s check: target=%d, current=%d (flags=0x%x)\n",
			  __func__, pc->name, target_on, pc->on, pc->flags);

		/* If we decide it should be ON, trigger it */
		if (target_on && !pc->on) {
			lwsl_notice("%s: PCON %s ON (target=1, current=%d)\n", __func__, pc->name, pc->on);
			pc->on = 1;
			saip_switch(pc, 1);
			any_changed = 1;
		} else if (!target_on && pc->on) {
			lwsl_notice("%s: PCON %s OFF (target=0, current=%d)\n", __func__, pc->name, pc->on);
			pc->on = 0;
			saip_switch(pc, 0);
			any_changed = 1;
		}

	} lws_end_foreach_dll(p);

	if (any_changed) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
					   power.sai_server_owner.head) {
			saip_server_t *sps = lws_container_of(mp, struct saip_server, list);
			saip_queue_stay_info(sps);
			if (sps->ss) {
				if (lws_ss_request_tx(sps->ss))
					lwsl_warn("%s: failed to request tx\n", __func__);
			}
		} lws_end_foreach_dll_safe(mp, mp1);
	}

	/* Schedule next check */
	lws_sul_schedule(power.context, 0, &power.sul_pcon_check, sul_pcon_check_cb, 5 * LWS_US_PER_SEC);
}

void
sul_broadcast_energy_cb(lws_sorted_usec_list_t *sul)
{
	int polled = 0;

	/* 1. Trigger monitoring on all Tasmota PCONs */
	lws_start_foreach_dll(struct lws_dll2 *, p, power.sai_pcon_owner.head) {
		saip_pcon_t *pc = lws_container_of(p, saip_pcon_t, list);

		if (pc->ss_tasmota_monitor) {
			polled++;
			/* Reset RX position for new response */
			pc->monitor_rx_pos = 0;
			/* SS request triggers the HTTP GET */
			if (lws_ss_request_tx(pc->ss_tasmota_monitor))
				lwsl_warn("%s: Failed to trigger monitor request for %s\n", __func__, pc->name);
			// else
			//	lwsl_notice("%s: Triggered polling for %s\n", __func__, pc->name);
		//} else {
		//	lwsl_warn("%s: PCON %s has no monitor SS\n", __func__, pc->name);
		}

	} lws_end_foreach_dll(p);

	if (!polled)
		lwsl_notice("%s: No PCONs polled\n", __func__);

	/* 2. Queue energy report to server (sends whatever latest data we have) */
	/* We iterate servers, though usually only one */
	lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
				   power.sai_server_owner.head) {
		saip_server_t *sps = lws_container_of(mp, struct saip_server, list);
		int queued = saip_queue_energy_report(sps);
		if (queued) {
			// lwsl_notice("%s: Queued energy report for server\n", __func__);
			if (lws_ss_request_tx(sps->ss)) /* Request write to send the report */
				lwsl_warn("%s: failed to request tx\n", __func__);
		}
	} lws_end_foreach_dll_safe(mp, mp1);

	/* Schedule next check (e.g., every 5 seconds) */
	lws_sul_schedule(power.context, 0, &power.sul_monitor, sul_broadcast_energy_cb, 5 * LWS_US_PER_SEC);
}

void
saip_pcon_start_check(void)
{
	/* Trigger immediate check */
	lws_sul_schedule(power.context, 0, &power.sul_pcon_check, sul_pcon_check_cb, 1);
	/* Trigger immediate energy monitor check */
	lws_sul_schedule(power.context, 0, &power.sul_monitor, sul_broadcast_energy_cb, 1);
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *cx = lws_system_context_from_system_mgr(mgr);

	/*
	 * For the things we care about, let's notice if we are trying to get
	 * past them when we haven't solved them yet, and make the system
	 * state wait while we trigger the dependent action.
	 */
	switch (target) {

	case LWS_SYSTATE_OPERATIONAL:
		if (current != LWS_SYSTATE_OPERATIONAL)
			break;

		lwsl_cx_user(cx, "LWS_SYSTATE_OPERATIONAL");

		/* create our LAN-facing sai-power server / listener */

		if (lws_ss_create(cx, 0, &ssi_local_srv_t, NULL, NULL, NULL, NULL))
			return 1;

		/*
		 * For each server... a single connection
		 */

		lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
				           power.sai_server_owner.head) {
			saip_server_t *sps = lws_container_of(mp,
						struct saip_server, list);

			lwsl_user("%s: OPERATIONAL: server url %p %s\n", __func__, sps, sps->url);

			if (sps->url &&
			    lws_ss_create(cx, 0, &ssi_saip_server_link_t, sps,
					  &sps->ss, NULL, NULL)) {
				lwsl_err("%s: failed to create secure stream\n",
					 __func__);
				return -1;
			}

		} lws_end_foreach_dll_safe(mp, mp1);

		/* Start PCON monitoring */
		saip_pcon_start_check();

		break;
	}

	return 0;
}

/*
 * The grace time is up, ask for the suspend
 */

void
sul_idle_cb(lws_sorted_usec_list_t *sul)
{

}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

void sigint_handler(int sig)
{
	interrupted = 1;
}


int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
#if defined(WIN32)
	char temp[256], stg_config_dir[256];
#endif
	const char *p;

	lws_context_info_defaults(&info, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-s"))) {
		struct lws_context *cx;
		ssize_t n = 0;

		printf("%s: WOL subprocess generation...\n", __func__);

		info.wol_if = argv[2];

		cx = lws_create_context(&info);
		if (!cx) {
			lwsl_err("%s: failed to create wol cx\n", __func__);
			return 1;
		}

		/*
		 * A new process gets started with this option before we drop
		 * privs.  This allows us to do WOL with root privs later.
		 *
		 * We just wait until we get an ascii mac on stdin from the main
		 * process indicating the WOL needed.
		 */

		while (n >= 0) {
			char min[20];
			uint8_t mac[LWS_ETHER_ADDR_LEN];

			n = read(0, min, sizeof(min) - 1);
			lwsl_notice("%s: wol process read returned %d\n", __func__, (int)n);

			if (n <= 0)
				continue;

			min[n] = '\0';

			if (lws_parse_mac(min, mac)) {
				lwsl_user("Failed to parse mac '%s'\n", min);
			} else
                               if (lws_wol(cx, NULL, mac)) {
					lwsl_user("Failed to WOL '%s'\n", min);
				} else {
					lwsl_user("Sent WOL to '%s'\n", min);
				}
		}

		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "-c")))
		config_dir = p;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (lws_cmdline_option(argc, argv, "-D")) {
		if (lws_daemonize("/var/run/sai_power.pid"))
			return 1;
		lws_set_log_level(logs, lwsl_emit_syslog);
	} else
#endif

	lws_set_log_level(logs, NULL);

	lwsl_user("Sai Power - "
		  "Copyright (C) 2019-2025 Andy Green <andy@warmcat.com>\n");
	lwsl_user("   sai-power [-c <config-file>]\n");

#if defined(WIN32)
	{
		PWSTR wdi = NULL;

		if (SHGetKnownFolderPath(&FOLDERID_ProgramData,
					 0, NULL, &wdi) != S_OK) {
			lwsl_err("%s: unable to get config dir\n", __func__);
			return 1;
		}

		if (WideCharToMultiByte(CP_ACP, 0, wdi, -1, temp,
					sizeof(temp), 0, NULL) <= 0) {
			lwsl_err("%s: problem with string encoding\n", __func__);
			return 1;
		}

		lws_snprintf(stg_config_dir, sizeof(stg_config_dir),
				"%s\\sai\\power\\", temp);

		config_dir = stg_config_dir;
		CoTaskMemFree(wdi);
	}
#endif

	/*
	 * Let's parse the global bits out of the config
	 */

	lwsl_notice("%s: config dir %s\n", __func__, config_dir);
	if (saip_config_global(&power, config_dir)) {
		lwsl_err("%s: global config failed\n", __func__);

		return 1;
	}

	info.wol_if			= power.wol_if;
	if (power.wol_if)
		lwsl_notice("%s: WOL bound to interface %s\n", __func__, power.wol_if);

	info.pprotocols = pprotocols;
	//info.uid = 883;
	info.pt_serv_buf_size		= 32 * 1024;
	info.rlimit_nofile		= 20000;
	info.options			|= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	signal(SIGINT, sigint_handler);

	info.pss_policies_json		= default_ss_policy;
	info.fd_limit_per_thread	= 1 + 256 + 1;

	/* hook up our lws_system state notifier */

	nl.name				= "sai-power";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;

	/* create the lws context */

	power.context = lws_create_context(&info);
	if (!power.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	power.vhost = lws_create_vhost(power.context, &info);
	if (!power.vhost) {
		lwsl_err("Failed to create tls vhost\n");
		goto bail;
	}

	saip_ss_create_tasmota();

#if defined(LWS_WITH_SPAWN)
	{
		struct lws_spawn_piped_info info;
		char rpath[PATH_MAX];
		const char * const ea[] = { rpath, "-s", power.wol_if, NULL };

		realpath(argv[0], rpath);

		memset(&info, 0, sizeof(info));

		info.vh			= power.vhost;
		info.exec_array		= ea;
		info.max_log_lines	= 100;
		info.protocol_name	= "protocol_std";

		lsp_wol = lws_spawn_piped(&info);
		if (!lsp_wol)
			lwsl_err("%s: wol spawn failed\n", __func__);
	}
#endif

       lws_finalize_startup(power.context, "sai-power");


	while (!lws_service(power.context, 0) && !interrupted)
		;

bail:

	/* destroy the connections to the servers */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   power.sai_server_owner.head) {
		struct saip_server *sps = lws_container_of(p,
					struct saip_server, list);

		lws_dll2_remove(&sps->list);
		lws_ss_destroy(&sps->ss);

	} lws_end_foreach_dll_safe(p, p1);

	saip_config_destroy(&power);

	lws_context_destroy(power.context);

	return 0;
}
