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
#include <fcntl.h>
#include <errno.h>

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
#include <mach-o/dyld.h>
#endif

#if defined(WIN32)
#include <initguid.h>
#include <KnownFolders.h>
#include <Shlobj.h>
#include <processthreadsapi.h>
#include <handleapi.h>
#include <dbghelp.h>


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
int interrupted;
static lws_state_notify_link_t nl;

struct sai_builder builder;

extern struct lws_protocols protocol_stdxxx;
extern struct lws_protocols protocol_saishell;
extern struct lws_protocols protocol_suspender_stdxxx;
extern struct lws_protocols protocol_deletion_stdxxx;

#if defined(LWS_WITH_STUB)
static const struct lws_protocols protocol_stub_client = {
	.name = "lws-stub-client",
	.callback = lws_callback_stub_client,
	.per_session_data_size = 0,
	.rx_buffer_size = 4096,
};
#endif
 
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
		 * Ephemeral connections to the same server syncing a pool,
		 * see b-pool.c
		 */
		"{\"sai_pool\": {"
			"\"endpoint\":"		"\"${url}\","
			"\"port\":"		"443,"
			"\"protocol\":"		"\"ws\","
			"\"ws_subprotocol\":"	"\"com-warmcat-sai\","
			"\"http_url\":"		"\"\"," /* filled in by url */
			"\"tls\":"		"true,"
			"\"opportunistic\":"	"true,"
			"\"ws_binary\":"	"true,"
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
			"\"ws_subprotocol\":"	"\"com-warmcat-sai-builder\","
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
	&protocol_saishell,
	&protocol_logproxy,
	&protocol_resproxy,
	&protocol_suspender_stdxxx,
	&protocol_deletion_stdxxx,
#if defined(LWS_WITH_STUB)
	&protocol_stub_client,
#endif
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

	/*
	 * Security: restrict the listening socket to owner-only.  On Linux the
	 * socket path is in the abstract namespace (leading '@') which has no
	 * filesystem permissions, so chmod is a no-op there; on other platforms
	 * the socket lives on the filesystem and would otherwise inherit the
	 * process umask (often 0755/0777), letting any local user inject forged
	 * log lines into another build's task log channel.  Mirror the 0600
	 * protection applied to the deletion UDS in b-deletion.c.
	 */
	if (lp->sockpath[0] != '@') {
		if (chmod(lp->sockpath, 0600) < 0)
			lwsl_warn("%s: failed to chmod UDS %s: %s\n",
				  __func__, lp->sockpath, strerror(errno));
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

/*
 * A builder VM often boots with a nonsense wall clock and has ntp correct it a
 * moment later.  We should not start work before then: everything we create
 * gets an mtime from the bad clock, and once the step lands those mtimes make
 * the job dirs look as old as the step was big, so the deletion paths remove
 * dirs whose task is still building.  TLS certificate validity is decided by
 * the same clock.
 *
 * So hold the system state below TIME_VALID until the clock is at least
 * plausible.  We rejected the transition, so we own retrying it.
 */

static lws_usec_t clock_wait_started;

static void
sul_clock_wait_cb(lws_sorted_usec_list_t *sul)
{
	lws_state_transition_steps(
		lws_system_get_state_manager(builder.context),
		LWS_SYSTATE_OPERATIONAL);
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

	case LWS_SYSTATE_TIME_VALID:
		if (current >= LWS_SYSTATE_TIME_VALID)
			break;

		if ((uint64_t)lws_now_secs() >= SAI_CLOCK_PLAUSIBLE_AFTER) {
			if (clock_wait_started)
				lwsl_notice("%s: wall clock now reads %llu, "
					    "starting work\n", __func__,
					    (unsigned long long)lws_now_secs());

			/* the clock is believable, this is where we start from */
			saib_clock_baseline();
			break;
		}

		if (!clock_wait_started) {
			clock_wait_started = lws_now_usecs();
			lwsl_warn("%s: wall clock reads %llu, before %llu: it has "
				  "not been set yet, holding off starting work "
				  "for up to %ds\n", __func__,
				  (unsigned long long)lws_now_secs(),
				  (unsigned long long)SAI_CLOCK_PLAUSIBLE_AFTER,
				  SAI_CLOCK_WAIT_MAX_SECS);
		} else
			if (lws_now_usecs() - clock_wait_started >
			    (lws_usec_t)SAI_CLOCK_WAIT_MAX_SECS * LWS_US_PER_SEC) {
				lwsl_err("%s: wall clock still reads %llu after "
					 "%ds: starting work anyway, but expect "
					 "anything that cares about dates to be "
					 "wrong until it is set\n", __func__,
					 (unsigned long long)lws_now_secs(),
					 SAI_CLOCK_WAIT_MAX_SECS);
				saib_clock_baseline();
				break;
			}

		lws_sul_schedule(mgr->context, 0, &builder.sul_clock_wait,
				 sul_clock_wait_cb, 2 * LWS_US_PER_SEC);

		return 1;

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
		info.port = CONTEXT_PORT_NO_LISTEN;
		if (builder.metrics_uri && builder.metrics_path && builder.metrics_secret) {
			pvo1a.value = builder.metrics_uri;
			pvo1b.value = builder.metrics_path;
			pvo1c.value = builder.metrics_secret;
			info.pvo = &pvo1;
		}
		info.pprotocols = pprotocols;

		builder.vhost = lws_create_vhost(builder.context, &info);
		if (!builder.vhost) {
			lwsl_err("Failed to create tls vhost\n");
			return 1;
		}

#if defined(__linux__) || defined(__NetBSD__) || defined(__APPLE__)
		if (saib_suspender_fork(argv0))
			return 1;
#endif
		break;
	}

	case LWS_SYSTATE_OPERATIONAL:
		if (current != LWS_SYSTATE_OPERATIONAL) {
			/*
			 * In a sai-virt VM, we can't do anything until it has
			 * told us which VM we are, see b-whoami.c
			 */
			if (saib_whoami_pending())
				return 1;
			break;
		}

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

		lwsl_notice("====== EXECUTING SAIB_POWER_INIT ======\n");
		saib_power_init();
		lwsl_notice("====== EXECUTED SAIB_POWER_INIT ======\n");

		if (builder.power_controller_name) {
			lws_start_foreach_dll(struct lws_dll2 *, d, builder.sai_plat_owner.head) {
				struct sai_plat *sp = lws_container_of(d, struct sai_plat, sai_plat_list);
				sp->pcon = builder.power_controller_name;
			} lws_end_foreach_dll(d);
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

		/* let's sample the best possible free RAM + disk situation,
		 * we will derate it a bit when using it */
		if (builder.one_shot_active)
			builder.ram_limit_kib	= saib_get_total_ram_kib();
		else
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
	/*
	 * In-flight artifact uploads still reference the ns; their SS handles
	 * outlive it until lws_context_destroy() tears them down, which would
	 * then touch freed ns.  Destroy them first, and mark the ns as already
	 * destroying so their DESTROYING doesn't try to run the full task
	 * teardown from inside builder shutdown.
	 */

	ns->destroying = 1;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   ns->artifact_owner.head) {
		sai_artifact_t *ap = lws_container_of(d, sai_artifact_t, list);
		struct lws_ss_handle *h = ap->ss;

		lws_ss_destroy(&h);
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&ns->list);
	free(ns);
}

void saib_app_stop(void)
{
	interrupted = 1;
	lws_cancel_service(builder.context);
}

#if defined(__linux__) || defined(__APPLE__)
#include <execinfo.h>
void
crash_handler(int signum)
{
	void *array[20];
	int size;
	char **strings;

	lwsl_err("FATAL: Caught signal %d, producing backtrace:\n", signum);

	size = backtrace(array, 20);
	strings = backtrace_symbols(array, size);

	if (strings != NULL) {
		for (int i = 0; i < size; i++)
			lwsl_err("  %s\n", strings[i]);
		free(strings);
	}

	signal(signum, SIG_DFL);
	abort();
}
#endif

#if defined(WIN32)
/*
 * The Debug CRT's abort() (an assert(), or a direct abort()) exits with
 * code 3 and nothing else when there is no console: a service has no
 * stderr, its message boxes are invisible in session 0, and if the
 * debugger attached after startup the CRT report-fault is already off.
 * abort() raises SIGABRT first, so log a symbolised backtrace from here,
 * and hand a debugger the stop it was never given.
 */
static void
win_crash_handler(int signum)
{
	char symbuf[sizeof(SYMBOL_INFO) + 256];
	SYMBOL_INFO *sym = (SYMBOL_INFO *)symbuf;
	HANDLE proc = GetCurrentProcess();
	IMAGEHLP_LINE64 line;
	DWORD64 disp64 = 0;
	void *frames[32];
	DWORD disp = 0;
	USHORT n, i;

	lwsl_err("FATAL: caught signal %d, producing backtrace:\n", signum);

	SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME |
		      SYMOPT_DEFERRED_LOADS);
	SymInitialize(proc, NULL, TRUE);

	n = CaptureStackBackTrace(0, (DWORD)LWS_ARRAY_SIZE(frames), frames,
				  NULL);
	for (i = 0; i < n; i++) {
		DWORD64 a = (DWORD64)(uintptr_t)frames[i];

		memset(symbuf, 0, sizeof(symbuf));
		sym->SizeOfStruct = sizeof(SYMBOL_INFO);
		sym->MaxNameLen = 255;
		memset(&line, 0, sizeof(line));
		line.SizeOfStruct = sizeof(line);

		if (!SymFromAddr(proc, a, &disp64, sym)) {
			lwsl_err("  #%u 0x%llx\n", i, (unsigned long long)a);
			continue;
		}
		if (SymGetLineFromAddr64(proc, a, &disp, &line))
			lwsl_err("  #%u %s+0x%llx (%s:%lu)\n", i, sym->Name,
				 (unsigned long long)disp64, line.FileName,
				 line.LineNumber);
		else
			lwsl_err("  #%u %s+0x%llx\n", i, sym->Name,
				 (unsigned long long)disp64);
	}

	if (IsDebuggerPresent())
		__debugbreak();

	/* let the default disposition finish the job, exit code 3 for abort */
	signal(signum, SIG_DFL);
	raise(signum);
}

static int log_fd = -1;

static void
lwsl_emit_file(int level, const char *line)
{
	if (log_fd >= 0) {
		write(log_fd, line, (unsigned int)strlen(line));
	}
}
#endif

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

#if defined(__APPLE__) || defined(__linux__)
	static char execpath[PATH_MAX];
#endif

	argv0 = argv[0];

#if defined(__APPLE__)
	{
		uint32_t size = sizeof(execpath);
		if (_NSGetExecutablePath(execpath, &size) == 0)
			argv0 = execpath;
	}
#elif defined(__linux__)
	{
		ssize_t n = readlink("/proc/self/exe", execpath, sizeof(execpath) - 1);
		if (n > 0) {
			execpath[n] = '\0';
			argv0 = execpath;
		}
	}
#endif

	if ((p = lws_cmdline_option(argc, argv, "--lws-stub="))) {
		if (!strcmp(p, "sai-deletion")) {
#if defined(LWS_WITH_STUB)
			return sai_deletion_worker(NULL);
#else
			return 1;
#endif
		}
	}

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

	if (lws_cmdline_option(argc, argv, "-E")) {
		builder.event_affinity_active = 1;
		lwsl_notice("%s: event affinity mode enabled (ephemeral VM)\n", __func__);
	}

	if (lws_cmdline_option(argc, argv, "-O")) {
		builder.one_shot_active = 1;
		lwsl_notice("%s: one-shot mode enabled (single task ephemeral VM)\n", __func__);
	}

#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (lws_cmdline_option(argc, argv, "-D")) {
		if (lws_daemonize("/var/run/sai_builder.pid"))
			return 1;
		lws_set_log_level(logs, lwsl_emit_syslog);
	} else
#endif
	{
#if defined(__linux__) || defined(__APPLE__)
		signal(SIGSEGV, crash_handler);
		signal(SIGABRT, crash_handler);
		signal(SIGBUS, crash_handler);
		signal(SIGILL, crash_handler);
		signal(SIGFPE, crash_handler);
#endif
#if defined(WIN32)
		signal(SIGABRT, win_crash_handler);
		signal(SIGSEGV, win_crash_handler);
		signal(SIGILL, win_crash_handler);
		signal(SIGFPE, win_crash_handler);
#endif

		lws_set_log_level(logs, NULL);
	}

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

		if (lws_cmdline_option(argc, argv, "--service")) {
			char logpath[512];
			lws_snprintf(logpath, sizeof(logpath), "%s\\sai-builder-service.log", stg_config_dir);
			log_fd = open(logpath, O_CREAT | O_TRUNC | O_WRONLY, 0600);
			if (log_fd >= 0)
				lws_set_log_level(logs, lwsl_emit_file);
		}

		config_dir = stg_config_dir;
		CoTaskMemFree(wdi);
	}
#endif

	/*
	 * Let's parse the global bits out of the config
	 */

	lwsl_notice("%s: config dir %s\n", __func__, config_dir);
	builder.build_timeout_secs = 30 * 60;
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
		  "Copyright (C) 2019-2026 Andy Green <andy@warmcat.com>\n");
	lwsl_user("   sai-builder [-c <config-file>]\n");

	lwsl_notice("%s: sai-power: %s %s %s %s %s\n",
		  __func__,
		  builder.power_on_type ? builder.power_on_type : "none",
		  builder.power_on_url ? builder.power_on_url : "none",
		  builder.power_on_mac ? builder.power_on_mac : "none",
		  builder.power_off_type ? builder.power_off_type : "none",
		  builder.power_off_url ? builder.power_off_url : "none");

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
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

	info.argc = argc;
	info.argv = argv;

	builder.context = lws_create_context(&info);
	if (!builder.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* ... and our vhost... */

	builder.vhost = lws_create_vhost(builder.context, &info);
	if (!builder.vhost) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (lws_service(builder.context, 0) >= 0 && !interrupted)
		;

	suspender_destroy();

#if defined(LWS_WITH_STUB)
	/*
	 * Take the deletion stub down ourselves, before lws_context_destroy()
	 * does it from the vhost: that way builder.mgr_deletion is cleared
	 * rather than left pointing at a manager lws has freed.
	 */
	if (builder.mgr_deletion)
		lws_stub_destroy(&builder.mgr_deletion);
#endif

	saib_jobdir_holds_destroy();


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

	saib_pool_destroy_all();
	saib_config_destroy(&builder);

	saib_power_shutdown();

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
