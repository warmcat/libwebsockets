/*
 * sai-virt
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
#include <signal.h>
#include <unistd.h>

#include "v-private.h"

struct sai_virt virt;
static int interrupted;

static const char * const default_ss_policy =
	"{"
	  "\"release\": \"01234567\","
	  "\"product\": \"sai-virt\","
	  "\"schema-version\": 1,"
	  "\"retry\": ["
		"{\"default\": {"
			"\"backoff\": [1000, 2000, 3000, 5000, 10000],"
			"\"conceal\": 99999,"
			"\"jitterpc\": 20,"
			"\"svalidping\": 15,"
			"\"svalidhup\": 30"
		"}}"
	  "],"
	  "\"s\": ["
		"{\"sai_power_client\": {"
			"\"endpoint\": \"${url}\","
			"\"port\": 443,"
			"\"protocol\": \"ws\","
			"\"tls\": true,"
			"\"nailed_up\": true,"
			"\"ws_subprotocol\": \"com-warmcat-sai\","
			"\"http_url\": \"\","
			"\"retry\": \"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}}"
	"]}"
;

static void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	lwsl_user("Sai Virt - Copyright (C) 2019-2026 Andy Green <andy@warmcat.com>\n");

	if (gethostname(virt.hostname, sizeof(virt.hostname) - 1))
		lws_strncpy(virt.hostname, "unknown", sizeof(virt.hostname));

	virt.max_vms = 4;
	virt.port = 8000;

	const struct lws_protocols *pprotocols[] = {
		&virt_protocols[0],
		NULL
	};

	memset(&info, 0, sizeof info);
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_VALIDATE_UTF8 |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.pprotocols = pprotocols;

	signal(SIGINT, sigint_handler);

	info.pss_policies_json = default_ss_policy;

	virt.context = lws_create_context(&info);
	if (!virt.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* Parse platforms from /etc/sai/virt/conf.d */
	saiv_config(&virt, "/etc/sai/virt/conf.d");

	/*
	 * After the platforms are known, so it can recognize VMs left over
	 * from a previous run.  If the hypervisor isn't reachable now, the
	 * ops reconnect on demand later.
	 */
	virt.ops = &ops_libvirt;
	virt.ops->init(&virt);

	/* Parse global configuration from /etc/sai/virt/conf */
	saiv_config_global(&virt, "/etc/sai/virt/conf");

	/*
	 * The listener the builders in our VMs talk to.  Nothing on it is
	 * authenticated, so it should only be reachable from the VMs'
	 * network.  If the bind interface doesn't exist yet, eg, libvirt
	 * hasn't started its network, lws keeps trying to listen on it.
	 */
	info.port = virt.port;
	info.iface = virt.bind;
	if (virt.bind)
		lwsl_notice("%s: listening for builders on %s port %d\n",
			    __func__, virt.bind, virt.port);
	else
		lwsl_warn("%s: no \"bind\" in conf: listening for builders on "
			  "port %d of every interface, firewall it to the VM "
			  "network\n", __func__, virt.port);

	virt.vhost = lws_create_vhost(virt.context, &info);
	if (!virt.vhost) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	saiv_servers_start(&virt);

	lws_sul_schedule(virt.context, 0, &virt.sul_watch, saiv_watch_cb,
			 SAIV_WATCH_INTERVAL_US);

	while (!lws_service(virt.context, 0) && !interrupted)
		;

	lws_sul_cancel(&virt.sul_watch);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, virt.sai_server_owner.head) {
		saiv_server_t *s = lws_container_of(d, saiv_server_t, list);
		lws_ss_destroy(&s->ss);
		lws_dll2_remove(d);
		free((void *)s->url);
		free(s);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, virt.plat_owner.head) {
		saiv_plat_t *p = lws_container_of(d, saiv_plat_t, list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, v, v1, p->vm_owner.head) {
			saiv_vm_t *vm = lws_container_of(v, saiv_vm_t, list);
			if (virt.ops)
				virt.ops->destroy(&virt, vm);
			lws_dll2_remove(v);
			lws_sul_cancel(&vm->sul_timeout);
			lws_sul_cancel(&vm->sul_destroy);
			free(vm);
		} lws_end_foreach_dll_safe(v, v1);

		lws_dll2_remove(d);
		free(p);
	} lws_end_foreach_dll_safe(d, d1);

	lwsac_free(&virt.pending_tasks_ac);
	lws_context_destroy(virt.context);

	return 0;
}
