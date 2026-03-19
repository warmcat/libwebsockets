/*
 * sai-builder
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
 * Sai-builder uses a secure streams template to make the client connections to
 * the servers listed in /etc/sai/builder/conf JSON config.  The URL in the
 * config is substituted for the endpoint URL at runtime.
 *
 * See b-comms.c for the secure stream template and callbacks for this.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>

#include <sys/types.h>
#if !defined(WIN32)
#include <pwd.h>
#include <grp.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/stat.h>	/* for mkdir() */
#endif

#if defined(WIN32)
#include <initguid.h>
#include <KnownFolders.h>
#include <Shlobj.h>
#include <processthreadsapi.h>
#include <handleapi.h>


#if !defined(PATH_MAX)
#define PATH_MAX MAX_PATH
#endif

int getpid(void) { return 0; }

#endif

#include "b-private.h"

extern struct lws_protocols protocol_suspender_stdxxx;
extern int saib_stay_init(void);
extern int
scan_jobs_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde);
extern void
sul_cleanup_jobs_cb(lws_sorted_usec_list_t *sul);

/*
 * Periodically (eg, once per hour) we walk the jobs dir and find subdirs
 * that are older than a day.
 *
 * These represent failed jobs that were left for inspection, but should now
 * be cleaned up.
 *
 * We are careful not to delete anything that is part of an ongoing job.
 */

struct active_job_uuids {
	lws_dll2_owner_t owner;
};

struct active_job_uuid {
	lws_dll2_t list;
	char uuid[65];
};

static const char *config_dir = "/etc/sai/builder", *argv0;
static int interrupted;
static lws_state_notify_link_t nl;

struct sai_builder builder;

extern struct lws_protocols protocol_stdxxx;
extern struct lws_protocols protocol_suspender_stdxxx;
 
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
			"\"svalidping\":"	"15,"
			"\"svalidhup\":"	"30"
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
		"{\"sai_builder\": {"
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
		 * Ephemeral connections to the same server carrying artifact
		 * JSON + bulk data
		 */
		"{\"sai_artifact\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"ws\","
			"\"ws_subprotocol\":"	"\"com-warmcat-sai\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"tls\":"		"true,"
			"\"opportunistic\":"	"true,"
			"\"ws_binary\":"	"true," /* we're sending binary */
			"\"retry\":"		"\"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}},"
		/*
		 * Used to connect to sai-power to ask for power-off
		 */
		"{\"sai_power\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"protocol\":"		"\"h1\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"http_method\":"	"\"GET\","
			"\"retry\":"		"\"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}},"
		/*
		 * Used to register with sai-power
		 */
		"{\"sai_power_client\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"protocol\":"		"\"ws\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"retry\":"		"\"default\","
			"\"metadata\": ["
				"{\"url\": \"\"}"
			"]"
		"}}"
	"]}"
;

static const struct lws_protocols *pprotocols[] = {
	&protocol_stdxxx,
	&protocol_logproxy,
	&protocol_resproxy,
	&protocol_suspender_stdxxx,
#if defined(LWS_WITH_SYS_METRICS) && defined(LWS_WITH_PLUGINS_BUILTIN)
	&lws_openmetrics_export_protocols[LWSOMPROIDX_PROX_WS_CLIENT],
#else
	NULL,
#endif
	NULL
};

static int lpidx;
static char vhnames[256], *pv = vhnames;

static struct lws_protocol_vhost_options
pvo1c = {
        NULL,                  /* "next" pvo linked-list */
        NULL,                 /* "child" pvo linked-list */
        "ba-secret",        /* protocol name we belong to on this vhost */
        "ok"                     /* set at runtime from conf */
},
pvo1b = {
        &pvo1c,                  /* "next" pvo linked-list */
        NULL,                 /* "child" pvo linked-list */
        "metrics-proxy-path",        /* protocol name we belong to on this vhost */
        "ok"                     /* set at runtime from conf */
},
pvo1a = {
        &pvo1b,                  /* "next" pvo linked-list */
        NULL,                 /* "child" pvo linked-list */
        "ws-server-uri",        /* protocol name we belong to on this vhost */
        "ok"                     /* set at runtime from conf */
},
pvo1 = { /* starting point for metrics proxy */
        NULL,                  /* "next" pvo linked-list */
        &pvo1a,                 /* "child" pvo linked-list */
        "lws-openmetrics-prox-client",        /* protocol name we belong to on this vhost */
        "ok"                     /* ignored */
},

pvo = { /* starting point for logproxy */
        NULL,                  /* "next" pvo linked-list */
        NULL,                 /* "child" pvo linked-list */
        "protocol-logproxy",        /* protocol name we belong to on this vhost */
        "ok"                     /* ignored */
},

pvo_resproxy = { /* starting point for resproxy */
	        NULL,                  /* "next" pvo linked-list */
	        NULL,                 /* "child" pvo linked-list */
	        "protocol-resproxy",        /* protocol name we belong to on this vhost */
	        "ok"                     /* ignored */
	};

int
saib_create_listen_uds(struct lws_context *context, struct saib_logproxy *lp,
		       struct lws_vhost **vhost)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));

	info.vhost_name			= pv;
	pv += lws_snprintf(pv, sizeof(vhnames) - (size_t)(pv - vhnames), "logproxy.%d", lpidx++) + 1;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG |
		       LWS_SERVER_OPTION_UNIX_SOCK;
	info.iface			= lp->sockpath;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "protocol-logproxy";
	info.user			= lp;
	info.pvo			= &pvo;
	info.pprotocols                 = pprotocols;

#if !defined(__linux__)
	unlink(lp->sockpath);
#endif

	lwsl_notice("%s: %s.%s\n", __func__, info.vhost_name, lp->sockpath);

	*vhost = lws_create_vhost(context, &info);
	if (!*vhost) {
		lwsl_notice("%s: failed to create vh %s\n", __func__,
			    info.vhost_name);
		return -1;
	}

	return 0;
}

/*
 * We create one of these per server we connected to
 */

int
saib_create_resproxy_listen_uds(struct lws_context *context,
				struct sai_plat_server *spm)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));

	info.vhost_name			= pv;
	pv += lws_snprintf(pv, sizeof(vhnames) - (size_t)(pv - vhnames),
				"resproxy.%u.%d", (unsigned int)getpid(), spm->index) + 1;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG |
		       LWS_SERVER_OPTION_UNIX_SOCK;

	info.iface			= spm->resproxy_path;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "protocol-resproxy";
	info.user			= spm;
	info.pvo			= &pvo_resproxy;
	info.pprotocols                 = pprotocols;

	lwsl_notice("%s: Created resproxy %s.%s\n", __func__, info.vhost_name,
			spm->resproxy_path);

	if (!lws_create_vhost(context, &info)) {
		lwsl_notice("%s: failed to create vh %s\n", __func__,
			    info.vhost_name);
		return -1;
	}

	return 0;
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	/*
	 * For the things we care about, let's notice if we are trying to get
	 * past them when we haven't solved them yet, and make the system
	 * state wait while we trigger the dependent action.
	 */
	switch (target) {

	case LWS_SYSTATE_CONTEXT_CREATED:
	{
		struct lws_context_creation_info info;

		builder.context = mgr->context;
		
		/*
		 * We have the context, but we haven't dropped privs yet.
		 * 
		 * We need to init the builder vhost, which has the pipes for
		 * the suspender and the metrics client on it, and the
		 * suspender itself.
		 */
		 
		memset(&info, 0, sizeof(info));
		pvo1a.value = builder.metrics_uri;
		pvo1b.value = builder.metrics_path;
		pvo1c.value = builder.metrics_secret;
		info.pvo = &pvo1;
		info.pprotocols = pprotocols;

		builder.vhost = lws_create_vhost(builder.context, &info);
		if (!builder.vhost) {
			lwsl_err("Failed to create tls vhost\n");
			return 1;
		}

		saib_power_init();

#if defined(__linux__) || defined(__NetBSD__) || defined(__APPLE__)
		if (saib_suspender_fork(argv0))
			return 1;
#endif
		break;
	}

	case LWS_SYSTATE_OPERATIONAL:
		if (current != LWS_SYSTATE_OPERATIONAL)
			break;

		if (saib_deletion_init(argv0))
			return 1;
		if (saib_deletion_init(argv0))
			return 1;


		/*
		 * The builder JSON conf listed servers we want to connect to,
		 * let's collect the config, make a ss for each and add the
		 * saim into an lws_dll2 list owned by
		 * builder->builder->sai_plat_owner
		 */

		lwsl_notice("%s: starting platform config\n", __func__);
		if (saib_config(&builder, config_dir)) {
			lwsl_err("%s: config failed\n", __func__);

			return 1;
		}

		/*
		 * For each platform...
		 */


		/*
		 * Create the resource proxy listeners, one per server link
		 */

		lwsl_notice("%s: creating resource proxy listeners\n", __func__);

		lws_start_foreach_dll(struct lws_dll2 *, pxx,
				      builder.sai_plat_server_owner.head) {
			struct sai_plat_server *spm = lws_container_of(pxx, sai_plat_server_t, list);

			lws_snprintf(spm->resproxy_path, sizeof(spm->resproxy_path),
	#if defined(__linux__)
			     UDS_PATHNAME_RESPROXY".%u.%d", getpid(),
	#else
			     UDS_PATHNAME_RESPROXY"/%d",
	#endif
			     spm->index);

			lwsl_notice("%s: creating %s\n", __func__, spm->resproxy_path);

			saib_create_resproxy_listen_uds(builder.context, spm);

		} lws_end_foreach_dll(pxx);

		lwsl_info("%s: platform config completed, calling saib_stay_init\n", __func__);
		if (saib_stay_init())
			return 1;

		lwsl_info("%s: scheduling initial cleanup in 100ms\n", __func__);
		lws_sul_schedule(builder.context, 0, &builder.sul_cleanup_jobs,
			 sul_cleanup_jobs_cb, 100 * LWS_US_PER_MS);

		/* let's sample the best possible free RAM + disk situation,
		 * we will derate it a bit when using it */
		builder.ram_limit_kib	= saib_get_free_ram_kib();
		builder.disk_total_kib	= saib_get_free_disk_kib(builder.home);

		break;
	}

	return 0;
}


static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

#if !defined(LWS_WITHOUT_EXTENSIONS)
static const struct lws_extension extensions[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
		 "; client_no_context_takeover"
		 "; client_max_window_bits"
	},
	{ NULL, NULL, NULL /* terminator */ }
};
#endif

void sigint_handler(int sig)
{
	interrupted = 1;
}

void
sai_ns_destroy(struct sai_nspawn *ns)
{
	lws_dll2_remove(&ns->list);
	free(ns);
}

void saib_app_stop(void)
{
	interrupted = 1;
	lws_cancel_service(builder.context);
}

int
saib_app_run(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
#if defined(WIN32)
	char temp[256], stg_config_dir[256];
#endif
	struct stat sb;
	const char *p;

	argv0 = argv[0];

	if ((p = lws_cmdline_option(argc, argv, "--home")))
		/*
		 * This is the deletion worker process being spawned, it only
		 * needs to know the home dir to clean up inside
		 */
		return sai_deletion_worker(p);

	if ((p = lws_cmdline_option(argc, argv, "-s"))) {
		lwsl_notice("%s: starting shutdown worker\n", __func__);
		/*
		 * This is the suspend / shutdown worker process being spawned
		 */
		return saib_suspender_start();
	}

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, "-c")))
		config_dir = p;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (lws_cmdline_option(argc, argv, "-D")) {
		if (lws_daemonize("/var/run/sai_builder.pid"))
			return 1;
		lws_set_log_level(logs, lwsl_emit_syslog);
	} else
#endif

	lws_set_log_level(logs, NULL);

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
				"%s\\sai\\builder", temp);

		config_dir = stg_config_dir;
		CoTaskMemFree(wdi);
	}
#endif

	/*
	 * Let's parse the global bits out of the config
	 */

	lwsl_notice("%s: config dir %s\n", __func__, config_dir);
	if (saib_config_global(&builder, config_dir)) {
		lwsl_err("%s: global config failed\n", __func__);

		return 1;
	}

	/*
	 * We need to sample the true uid / gid we should use inside
	 * the mountpoint for sai:nobody or sai:sai, by looking at
	 * what the uid and gid are on /home/sai before anything changes
	 * it
	 */
	if (stat(builder.home, &sb)) {
		lwsl_err("%s: Can't find %s\n", __func__, builder.home);
		return 1;
	}

#if defined(__linux__)
	/*
	 * At this point we're still root.  So we should be able
	 * to register our toplevel cgroup OK
	 */
	{
		struct passwd *pwd = getpwuid(sb.st_uid);
		struct group *grp = getgrgid(sb.st_gid);

		if (lws_spawn_prepare_self_cgroup(pwd->pw_name, grp->gr_name)) {
			lwsl_err("%s: failed to initialize cgroup dir %s %s\n", __func__, pwd->pw_name, grp->gr_name);
			return 1;
		}
	}
#endif

#if !defined(__linux__) && !defined(WIN32)
	/* we are still root */
	mkdir(UDS_PATHNAME_LOGPROXY, 0700);
	chown(UDS_PATHNAME_LOGPROXY, sb.st_uid, sb.st_gid);
	mkdir(UDS_PATHNAME_RESPROXY, 0700);
	chown(UDS_PATHNAME_RESPROXY, sb.st_uid, sb.st_gid);
#endif

	/* if we don't do this, libgit2 looks in /root/.gitconfig */
#if defined(WIN32)
	_putenv_s("HOME", builder.home);
#else
	setenv("HOME", builder.home, 1);
#endif

	lwsl_user("Sai Builder - "
		  "Copyright (C) 2019-2020 Andy Green <andy@warmcat.com>\n");
	lwsl_user("   sai-builder [-c <config-file>]\n");

	lwsl_notice("%s: sai-power: %s %s %s %s %s\n",
		  __func__, builder.power_on_type,
		builder.power_on_url,
		builder.power_on_mac,
		builder.power_off_type,
		builder.power_off_url);

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.pprotocols = pprotocols;

	info.pprotocols = pprotocols;

	info.uid = sb.st_uid;
	info.gid = sb.st_gid;



#if !defined(LWS_WITHOUT_EXTENSIONS)
	if (!lws_cmdline_option(argc, argv, "-n"))
		info.extensions = extensions;
#endif
	info.pt_serv_buf_size = 32 * 1024;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_VALIDATE_UTF8 |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.rlimit_nofile = 20000;

	signal(SIGINT, sigint_handler);

	info.pss_policies_json = default_ss_policy;
	info.fd_limit_per_thread = 1 + 256 + 1;

	/* hook up our lws_system state notifier */

	nl.name = "sai-builder";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

	/* create the lws context */

	builder.context = lws_create_context(&info);
	if (!builder.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ... and our vhost... */

	builder.context = lws_create_context(&info);
	if (!builder.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ... and our vhost... */

	while (!lws_service(builder.context, 0) && !interrupted)
		;

	suspender_destroy();


	/* destroy the unique servers */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   builder.sai_plat_server_owner.head) {
		struct sai_plat_server *cm = lws_container_of(p,
					struct sai_plat_server, list);

		lws_dll2_remove(&cm->list);
		lws_ss_destroy(&cm->ss);

	} lws_end_foreach_dll_safe(p, p1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, mp, mp1,
			           builder.sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(mp, struct sai_plat,
					sai_plat_list);

		lws_dll2_remove(&sp->sai_plat_list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
					   sp->nspawn_owner.head) {
			struct sai_nspawn *ns = lws_container_of(p,
						struct sai_nspawn, list);

			sai_ns_destroy(ns);

		} lws_end_foreach_dll_safe(p, p1);

	} lws_end_foreach_dll_safe(mp, mp1);

	saib_config_destroy(&builder);

	lws_sul_cancel(&builder.sul_idle);

	lws_context_destroy(builder.context);

	return 0;
}

#if defined(WIN32)
extern int saib_service_run(int argc, const char **argv);
#endif

int main(int argc, const char **argv)
{
#if defined(WIN32)
	if (lws_cmdline_option(argc, argv, "--service"))
		return saib_service_run(argc, argv);
#endif

	return saib_app_run(argc, argv);
}
