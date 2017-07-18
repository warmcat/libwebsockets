/*
 * libwebsockets-test-server-v2.0 - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#include <libwebsockets.h>
#include <string.h>
#include <getopt.h>
#ifndef WIN32
#include <syslog.h>
#endif

/* windows has no SIGUSR1 */
#if !defined(WIN32) && !defined(_WIN32)
#define TEST_DYNAMIC_VHOST
#endif

struct lws_context_creation_info info;
int debug_level = 7;
struct lws_context *context;

#if defined(TEST_DYNAMIC_VHOST)
volatile int dynamic_vhost_enable = 0;
struct lws_vhost *dynamic_vhost;
uv_timer_t timeout_watcher;
#endif

/* http server gets files from this path */
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;

#if defined(LWS_OPENSSL_SUPPORT) && defined(LWS_HAVE_SSL_CTX_set1_param)
char crl_path[1024] = "";
#endif

/*
 * This test server is ONLY this .c file, it's radically simpler than the
 * pre-v2.0 test servers.  For example it has no user callback content or
 * defines any protocols.
 *
 * To achieve that, it uses the LWS protocol plugins.  Those in turn
 * use libuv.  So you must configure with LWS_WITH_PLUGINS (which implies
 * libuv) to get this to build.
 *
 * You can find the individual protocol plugin sources in ../plugins
 */

#if defined(TEST_DYNAMIC_VHOST)

/*
 *  to test dynamic vhost creation, fire a SIGUSR1 at the test server.
 * It will toggle the existence of a second identical vhost at port + 1
 *
 * To synchronize with the event loop, it uses a libuv timer with 0 delay
 * to get the business end called as the next event.
 */

static void
uv_timeout_dynamic_vhost_toggle(uv_timer_t *w
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	if (dynamic_vhost_enable && !dynamic_vhost) {
		lwsl_notice("creating dynamic vhost...\n");
		dynamic_vhost = lws_create_vhost(context, &info);
	} else
		if (!dynamic_vhost_enable && dynamic_vhost) {
			lwsl_notice("destroying dynamic vhost...\n");
			lws_vhost_destroy(dynamic_vhost);
			dynamic_vhost = NULL;
		}
}

void sighandler_USR1(int sig)
{
	dynamic_vhost_enable ^= 1;
	lwsl_notice("SIGUSR1: dynamic_vhost_enable: %d\n",
			dynamic_vhost_enable);
	uv_timer_start(&timeout_watcher,
		       uv_timeout_dynamic_vhost_toggle, 0, 0);
}
#endif

void sighandler(int sig)
{
	lws_cancel_service(context);
}

static const struct lws_extension exts[] = {
	{
		"permessage-deflate",
		lws_extension_callback_pm_deflate,
		"permessage-deflate"
	},
	{
		"deflate-frame",
		lws_extension_callback_pm_deflate,
		"deflate_frame"
	},
	{ NULL, NULL, NULL /* terminator */ }
};

/*
 * mount handlers for sections of the URL space
 */

static const struct lws_http_mount mount_ziptest = {
	NULL,			/* linked-list pointer to next*/
	"/ziptest",		/* mountpoint in URL namespace on this vhost */
	LOCAL_RESOURCE_PATH"/candide.zip",	/* handler */
	NULL,	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_FILE,	/* origin points to a callback */
	8,			/* strlen("/ziptest"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

static const struct lws_http_mount mount_post = {
	(struct lws_http_mount *)&mount_ziptest, /* linked-list pointer to next*/
	"/formtest",		/* mountpoint in URL namespace on this vhost */
	"protocol-post-demo",	/* handler */
	NULL,	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_CALLBACK,	/* origin points to a callback */
	9,			/* strlen("/formtest"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

/*
 * mount a filesystem directory into the URL space at /
 * point it to our /usr/share directory with our assets in
 * stuff from here is autoserved by the library
 */

static const struct lws_http_mount mount = {
	(struct lws_http_mount *)&mount_post,	/* linked-list pointer to next*/
	"/",		/* mountpoint in URL namespace on this vhost */
	LOCAL_RESOURCE_PATH, /* where to go on the filesystem for that */
	"test.html",	/* default filename if none given */
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,
	0,
	0,
	LWSMPRO_FILE,	/* mount type is a directory in a filesystem */
	1,		/* strlen("/"), ie length of the mountpoint */
	NULL,

	{ NULL, NULL } // sentinel
};

/*
 * this sets a per-vhost, per-protocol option name:value pair
 * the effect is to set this protocol to be the default one for the vhost,
 * ie, selected if no Protocol: header is sent with the ws upgrade.
 */
#if 0
static const struct lws_protocol_vhost_options pvo_opt = {
	NULL,
	NULL,
	"default",
	"1"
};
#endif

static const struct lws_protocol_vhost_options pvo_opt4a = {
	NULL,
	NULL,
	"raw", /* indicate we are the protocol that gets raw connections */
	"1"
};

static const struct lws_protocol_vhost_options pvo_opt4 = {
	&pvo_opt4a,
	NULL,
	"fifo-path", /* tell the raw test plugin to open a raw file here */
	"/tmp/lws-test-raw"
};

/*
 * We must enable the plugin protocols we want into our vhost with a
 * linked-list.  We can also give the plugin per-vhost options here.
 */

static const struct lws_protocol_vhost_options pvo_5 = {
	NULL,
	NULL,
	"lws-meta",
	"" /* ignored, just matches the protocol name above */
};

static const struct lws_protocol_vhost_options pvo_4 = {
	&pvo_5,
	&pvo_opt4, /* set us as the protocol who gets raw connections */
	"protocol-lws-raw-test",
	"" /* ignored, just matches the protocol name above */
};

static const struct lws_protocol_vhost_options pvo_3 = {
	&pvo_4,
	NULL,
	"protocol-post-demo",
	"" /* ignored, just matches the protocol name above */
};

static const struct lws_protocol_vhost_options pvo_2 = {
	&pvo_3,
	NULL,
	"lws-status",
	"" /* ignored, just matches the protocol name above */
};

static const struct lws_protocol_vhost_options pvo_1 = {
	&pvo_2,
	NULL,
	"lws-mirror-protocol",
	""
};

static const struct lws_protocol_vhost_options pvo = {
	&pvo_1,
	NULL, // &pvo_opt,
	"dumb-increment-protocol",
	""
};

static void signal_cb(uv_signal_t *watcher, int signum)
{
	lwsl_err("Signal %d caught, exiting...\n", watcher->signum);
	switch (watcher->signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		signal(SIGABRT, SIG_DFL);
		abort();
		break;
	}
	lws_libuv_stop(context);
}

static const struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "ssl-alerts",	no_argument,		NULL, 'S' },
	{ "allow-non-ssl",	no_argument,	NULL, 'a' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "ssl-cert",  required_argument,	NULL, 'C' },
	{ "ssl-key",  required_argument,	NULL, 'K' },
	{ "ssl-ca",  required_argument,		NULL, 'A' },
#if defined(LWS_OPENSSL_SUPPORT)
	{ "ssl-verify-client",  no_argument,		NULL, 'v' },
#if defined(LWS_HAVE_SSL_CTX_set1_param)
	{ "ssl-crl",  required_argument,		NULL, 'R' },
#endif
#endif
#ifndef LWS_NO_DAEMONIZE
	{ "daemonize", 	no_argument,		NULL, 'D' },
#endif
	{ "resource_path", required_argument,	NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

static const char * const plugin_dirs[] = {
		INSTALL_DATADIR"/libwebsockets-test-server/plugins/",
		NULL
};

int main(int argc, char **argv)
{
	struct lws_vhost *vhost;
	char interface_name[128] = "";
	const char *iface = NULL;
	char cert_path[1024] = "";
	char key_path[1024] = "";
	char ca_path[1024] = "";
	int uid = -1, gid = -1;
	int use_ssl = 0;
	int opts = 0;
	int n = 0;
#ifndef _WIN32
	int syslog_options = LOG_PID | LOG_PERROR;
#endif
#ifndef LWS_NO_DAEMONIZE
	int daemonize = 0;
#endif

	/*
	 * take care to zero down the info struct, he contains random garbaage
	 * from the stack otherwise
	 */
	memset(&info, 0, sizeof info);
	info.port = 7681;

	while (n >= 0) {
		n = getopt_long(argc, argv, "i:hsap:d:Dr:C:K:A:R:vu:g:S",
				(struct option *)options, NULL);
		if (n < 0)
			continue;
		switch (n) {
#ifndef LWS_NO_DAEMONIZE
		case 'D':
			daemonize = 1;
			#ifndef _WIN32
			syslog_options &= ~LOG_PERROR;
			#endif
			break;
#endif
		case 'u':
			uid = atoi(optarg);
			break;
		case 'g':
			gid = atoi(optarg);
			break;
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 's':
			use_ssl = 1;
			break;
		case 'S':
#if defined(LWS_OPENSSL_SUPPORT)
			info.ssl_info_event_mask |= SSL_CB_ALERT;
#endif
			break;
		case 'a':
			opts |= LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;
			break;
		case 'p':
			info.port = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			iface = interface_name;
			break;
		case 'r':
			resource_path = optarg;
			printf("Setting resource path to \"%s\"\n", resource_path);
			break;
		case 'C':
			strncpy(cert_path, optarg, sizeof(cert_path) - 1);
			cert_path[sizeof(cert_path) - 1] = '\0';
			break;
		case 'K':
			strncpy(key_path, optarg, sizeof(key_path) - 1);
			key_path[sizeof(key_path) - 1] = '\0';
			break;
		case 'A':
			strncpy(ca_path, optarg, sizeof(ca_path) - 1);
			ca_path[sizeof(ca_path) - 1] = '\0';
			break;
#if defined(LWS_OPENSSL_SUPPORT)
		case 'v':
			use_ssl = 1;
			opts |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
			break;

#if defined(LWS_HAVE_SSL_CTX_set1_param)
		case 'R':
			strncpy(crl_path, optarg, sizeof(crl_path) - 1);
			crl_path[sizeof(crl_path) - 1] = '\0';
			break;
#endif
#endif
		case 'h':
			fprintf(stderr, "Usage: test-server "
					"[--port=<p>] [--ssl] "
					"[-d <log bitfield>] "
					"[--resource_path <path>]\n");
			exit(1);
		}
	}

#if !defined(LWS_NO_DAEMONIZE) && !defined(WIN32)
	/*
	 * normally lock path would be /var/lock/lwsts or similar, to
	 * simplify getting started without having to take care about
	 * permissions or running as root, set to /tmp/.lwsts-lock
	 */
	if (daemonize && lws_daemonize("/tmp/.lwsts-lock")) {
		fprintf(stderr, "Failed to daemonize\n");
		return 10;
	}
#endif

	signal(SIGINT, sighandler);
#if defined(TEST_DYNAMIC_VHOST)
	signal(SIGUSR1, sighandler_USR1);
#endif

#ifndef _WIN32
	/* we will only try to log things according to our debug_level */
	setlogmask(LOG_UPTO (LOG_DEBUG));
	openlog("lwsts", syslog_options, LOG_DAEMON);
#endif

	/* tell the library what debug level to emit and to send it to syslog */
	lws_set_log_level(debug_level, lwsl_emit_syslog);

	lwsl_notice("libwebsockets test server - license LGPL2.1+SLE\n");
	lwsl_notice("(C) Copyright 2010-2017 Andy Green <andy@warmcat.com>\n");

	lwsl_notice(" Using resource path \"%s\"\n", resource_path);

	info.iface = iface;
	info.protocols = NULL; /* all protocols from lib / plugins */
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.gid = gid;
	info.uid = uid;
	info.max_http_header_pool = 16;
	info.options = opts | LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_FALLBACK_TO_RAW |
			LWS_SERVER_OPTION_VALIDATE_UTF8 |
			LWS_SERVER_OPTION_LIBUV; /* plugins require this */

	if (use_ssl) {
		if (strlen(resource_path) > sizeof(cert_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		if (!cert_path[0])
			sprintf(cert_path, "%s/libwebsockets-test-server.pem",
				resource_path);
		if (strlen(resource_path) > sizeof(key_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		if (!key_path[0])
			sprintf(key_path, "%s/libwebsockets-test-server.key.pem",
				resource_path);

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
		if (ca_path[0])
			info.ssl_ca_filepath = ca_path;

		/* redirect guys coming on http */
		info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;
	}

	info.extensions = exts;
	info.timeout_secs = 5;
	info.ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
			       "ECDHE-RSA-AES256-GCM-SHA384:"
			       "DHE-RSA-AES256-GCM-SHA384:"
			       "ECDHE-RSA-AES256-SHA384:"
			       "HIGH:!aNULL:!eNULL:!EXPORT:"
			       "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
			       "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
			       "!DHE-RSA-AES128-SHA256:"
			       "!AES128-GCM-SHA256:"
			       "!AES128-SHA256:"
			       "!DHE-RSA-AES256-SHA256:"
			       "!AES256-GCM-SHA384:"
			       "!AES256-SHA256";

	/* tell lws to look for protocol plugins here */
	info.plugin_dirs = plugin_dirs;

	/* tell lws about our mount we want */
	info.mounts = &mount;
	/*
	 * give it our linked-list of Per-Vhost Options, these control
	 * which protocols (from plugins) are allowed to be enabled on
	 * our vhost
	 */
	info.pvo = &pvo;

	/*
	 * Since we used LWS_SERVER_OPTION_EXPLICIT_VHOSTS, this only creates
	 * the context.  We can modify info and create as many vhosts as we
	 * like subsequently.
	 */
	context = lws_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

	/*
	 *  normally we would adapt at least info.name to reflect the
	 * external hostname for this server.
	 */
	vhost = lws_create_vhost(context, &info);
	if (!vhost) {
		lwsl_err("vhost creation failed\n");
		return -1;
	}

#if defined(TEST_DYNAMIC_VHOST)
	/* our dynamic vhost is on port + 1 */
	info.port++;
#endif

	/* libuv event loop */
	lws_uv_sigint_cfg(context, 1, signal_cb);
	if (lws_uv_initloop(context, NULL, 0)) {
		lwsl_err("lws_uv_initloop failed\n");
		goto bail;
	}

#if defined(TEST_DYNAMIC_VHOST)
	uv_timer_init(lws_uv_getloop(context, 0), &timeout_watcher);
#endif
	lws_libuv_run(context, 0);

#if defined(TEST_DYNAMIC_VHOST)
	uv_timer_stop(&timeout_watcher);
	uv_close((uv_handle_t *)&timeout_watcher, NULL);
#endif

bail:
	/* when we decided to exit the event loop */
	lws_context_destroy(context);
	lws_context_destroy2(context);
	lwsl_notice("libwebsockets-test-server exited cleanly\n");

#ifndef _WIN32
	closelog();
#endif

	return 0;
}
