/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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
 * may be proprietary.	So unlike the library itself, they are licensed
 * Public Domain.
 */

#include "test-server.h"

int close_testing;
int max_poll_elements;
int debug_level = 7;

#ifdef EXTERNAL_POLL
struct lws_pollfd *pollfds;
int *fd_lookup;
int count_pollfds;
#endif
volatile int force_exit = 0, dynamic_vhost_enable = 0;
struct lws_vhost *dynamic_vhost;
struct lws_context *context;
struct lws_plat_file_ops fops_plat;

/* http server gets files from this path */
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;
#if defined(LWS_OPENSSL_SUPPORT) && defined(LWS_HAVE_SSL_CTX_set1_param)
char crl_path[1024] = "";
#endif

/*
 * This demonstrates how to use the clean protocol service separation of
 * plugins, but with static inclusion instead of runtime dynamic loading
 * (which requires libuv).
 *
 * dumb-increment doesn't use the plugin, both to demonstrate how to
 * do the protocols directly, and because it wants libuv for a timer.
 *
 * Please consider using test-server-v2.0.c instead of this: it has the
 * same functionality but
 *
 * 1) uses lws built-in http handling so you don't need to deal with it in
 * your callback
 *
 * 2) Links with libuv and uses the plugins at runtime
 *
 * 3) Uses advanced lws features like mounts to bind parts of the filesystem
 * to the served URL space
 *
 * Another option is lwsws, this operates like test-server-v2,0.c but is
 * configured using JSON, do you do not need to provide any code for the
 * serving action at all, just implement your protocols in plugins.
 */

#define LWS_PLUGIN_STATIC
#include "../plugins/protocol_lws_mirror.c"
#include "../plugins/protocol_lws_status.c"
#include "../plugins/protocol_lws_meta.c"

/* singlethreaded version --> no locks */

void test_server_lock(int care)
{
}
void test_server_unlock(int care)
{
}

/*
 * This demo server shows how to use libwebsockets for one or more
 * websocket protocols in the same server
 *
 * It defines the following websocket protocols:
 *
 *  dumb-increment-protocol:  once the socket is opened, an incrementing
 *				ascii string is sent down it every 50ms.
 *				If you send "reset\n" on the websocket, then
 *				the incrementing number is reset to 0.
 *
 *  lws-mirror-protocol: copies any received packet to every connection also
 *				using this protocol, including the sender
 *
 *  lws-status:			informs connected browsers of who else is
 *				connected.
 */

enum demo_protocols {
	/* always first */
	PROTOCOL_HTTP = 0,

	PROTOCOL_DUMB_INCREMENT,
	PROTOCOL_LWS_MIRROR,
	PROTOCOL_LWS_STATUS,

	PROTOCOL_LWS_META,

	/* always last */
	DEMO_PROTOCOL_COUNT
};

/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",		/* name */
		callback_http,		/* callback */
		sizeof (struct per_session_data__http),	/* per_session_data_size */
		0,			/* max frame size / rx buffer */
	},
	{
		"dumb-increment-protocol",
		callback_dumb_increment,
		sizeof(struct per_session_data__dumb_increment),
		10, /* rx buf size must be >= permessage-deflate rx size
		     * dumb-increment only sends very small packets, so we set
		     * this accordingly.  If your protocol will send bigger
		     * things, adjust this to match */
	},
	LWS_PLUGIN_PROTOCOL_MIRROR,
	LWS_PLUGIN_PROTOCOL_LWS_STATUS,

	LWS_PLUGIN_PROTOCOL_LWS_META,
	{ NULL, NULL, 0, 0 } /* terminator */
};


/* this shows how to override the lws file operations.	You don't need
 * to do any of this unless you have a reason (eg, want to serve
 * compressed files without decompressing the whole archive)
 */
static lws_fop_fd_t
test_server_fops_open(const struct lws_plat_file_ops *fops,
		     const char *vfs_path, const char *vpath,
		     lws_fop_flags_t *flags)
{
	lws_fop_fd_t fop_fd;

	/* call through to original platform implementation */
	fop_fd = fops_plat.open(fops, vfs_path, vpath, flags);

	if (fop_fd)
		lwsl_info("%s: opening %s, ret %p, len %lu\n", __func__,
				vfs_path, fop_fd,
				(long)lws_vfs_get_length(fop_fd));
	else
		lwsl_info("%s: open %s failed\n", __func__, vfs_path);

	return fop_fd;
}

void sighandler(int sig)
{
#if !defined(WIN32) && !defined(_WIN32)
	/* because windows is too dumb to have SIGUSR1... */
	if (sig == SIGUSR1) {
		/*
		 * For testing, you can fire a SIGUSR1 at the test server
		 * to toggle the existence of an identical server on
		 * port + 1
		 */
		dynamic_vhost_enable ^= 1;
		lwsl_notice("SIGUSR1: dynamic_vhost_enable: %d\n",
				dynamic_vhost_enable);
		return;
	}
#endif
	force_exit = 1;
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



static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "allow-non-ssl",	no_argument,	NULL, 'a' },
	{ "interface",	required_argument,	NULL, 'i' },
	{ "closetest",	no_argument,		NULL, 'c' },
	{ "ssl-cert",  required_argument,	NULL, 'C' },
	{ "ssl-key",  required_argument,	NULL, 'K' },
	{ "ssl-ca",  required_argument,		NULL, 'A' },
#if defined(LWS_OPENSSL_SUPPORT)
	{ "ssl-verify-client",	no_argument,		NULL, 'v' },
#if defined(LWS_HAVE_SSL_CTX_set1_param)
	{ "ssl-crl",  required_argument,		NULL, 'R' },
#endif
#endif
	{ "libev",  no_argument,		NULL, 'e' },
#ifndef LWS_NO_DAEMONIZE
	{ "daemonize",	no_argument,		NULL, 'D' },
#endif
	{ "resource_path", required_argument,	NULL, 'r' },
	{ "pingpong-secs", required_argument,	NULL, 'P' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vhost;
	char interface_name[128] = "";
	unsigned int ms, oldms = 0;
	const char *iface = NULL;
	char cert_path[1024] = "";
	char key_path[1024] = "";
	char ca_path[1024] = "";
	int uid = -1, gid = -1;
	int use_ssl = 0;
	int pp_secs = 0;
	int opts = 0;
	int n = 0;
#ifndef _WIN32
/* LOG_PERROR is not POSIX standard, and may not be portable */
#ifdef __sun
	int syslog_options = LOG_PID;
#else	     
	int syslog_options = LOG_PID | LOG_PERROR;
#endif
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
		n = getopt_long(argc, argv, "eci:hsap:d:Dr:C:K:A:R:vu:g:P:k", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'e':
			opts |= LWS_SERVER_OPTION_LIBEV;
			break;
#ifndef LWS_NO_DAEMONIZE
		case 'D':
			daemonize = 1;
			#if !defined(_WIN32) && !defined(__sun)
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
			opts |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
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
		case 'k':
			info.bind_iface = 1;
#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
			info.caps[0] = CAP_NET_RAW;
			info.count_caps = 1;
#endif
			break;
		case 'c':
			close_testing = 1;
			fprintf(stderr, " Close testing mode -- closes on "
					   "client after 50 dumb increments"
					   "and suppresses lws_mirror spam\n");
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
		case 'P':
			pp_secs = atoi(optarg);
			lwsl_notice("Setting pingpong interval to %d\n", pp_secs);
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
#if !defined(WIN32) && !defined(_WIN32)
	/* because windows is too dumb to have SIGUSR1... */
	/* dynamic vhost create / destroy toggle (on port + 1) */
	signal(SIGUSR1, sighandler);
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

	printf("Using resource path \"%s\"\n", resource_path);
#ifdef EXTERNAL_POLL
	max_poll_elements = getdtablesize();
	pollfds = malloc(max_poll_elements * sizeof (struct lws_pollfd));
	fd_lookup = malloc(max_poll_elements * sizeof (int));
	if (pollfds == NULL || fd_lookup == NULL) {
		lwsl_err("Out of memory pollfds=%d\n", max_poll_elements);
		return -1;
	}
#endif

	info.iface = iface;
	info.protocols = protocols;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.ws_ping_pong_interval = pp_secs;

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
	}
	info.gid = gid;
	info.uid = uid;
	info.max_http_header_pool = 256;
	info.options = opts | LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
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
	info.ip_limit_ah = 24; /* for testing */
	info.ip_limit_wsi = 105; /* for testing */

	if (use_ssl)
		/* redirect guys coming on http */
		info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;

	context = lws_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

	vhost = lws_create_vhost(context, &info);
	if (!vhost) {
		lwsl_err("vhost creation failed\n");
		return -1;
	}

	/*
	 * For testing dynamic vhost create / destroy later, we use port + 1
	 * Normally if you were creating more vhosts, you would set info.name
	 * for each to be the hostname external clients use to reach it
	 */

	info.port++;

#if !defined(LWS_NO_CLIENT) && defined(LWS_OPENSSL_SUPPORT)
	lws_init_vhost_client_ssl(&info, vhost);
#endif

	/* this shows how to override the lws file operations.	You don't need
	 * to do any of this unless you have a reason (eg, want to serve
	 * compressed files without decompressing the whole archive)
	 */
	/* stash original platform fops */
	fops_plat = *(lws_get_fops(context));
	/* override the active fops */
	lws_get_fops(context)->open = test_server_fops_open;

	n = 0;
#ifdef EXTERNAL_POLL
	int ms_1sec = 0;
#endif
	while (n >= 0 && !force_exit) {
		struct timeval tv;

		gettimeofday(&tv, NULL);

		/*
		 * This provokes the LWS_CALLBACK_SERVER_WRITEABLE for every
		 * live websocket connection using the DUMB_INCREMENT protocol,
		 * as soon as it can take more packets (usually immediately)
		 */

		ms = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
		if ((ms - oldms) > 50) {
			lws_callback_on_writable_all_protocol(context,
				&protocols[PROTOCOL_DUMB_INCREMENT]);
			oldms = ms;
		}

#ifdef EXTERNAL_POLL
		/*
		 * this represents an existing server's single poll action
		 * which also includes libwebsocket sockets
		 */

		n = poll(pollfds, count_pollfds, 50);
		if (n < 0)
			continue;

		if (n) {
			for (n = 0; n < count_pollfds; n++)
				if (pollfds[n].revents)
					/*
					* returns immediately if the fd does not
					* match anything under libwebsockets
					* control
					*/
					if (lws_service_fd(context,
								  &pollfds[n]) < 0)
						goto done;

			/* if needed, force-service wsis that may not have read all input */
			while (!lws_service_adjust_timeout(context, 1, 0)) {
				lwsl_notice("extpoll doing forced service!\n");
				lws_service_tsi(context, -1, 0);
			}
		} else {
			/* no revents, but before polling again, make lws check for any timeouts */
			if (ms - ms_1sec > 1000) {
				lwsl_notice("1 per sec\n");
				lws_service_fd(context, NULL);
				ms_1sec = ms;
			}
		}
#else
		/*
		 * If libwebsockets sockets are all we care about,
		 * you can use this api which takes care of the poll()
		 * and looping through finding who needed service.
		 *
		 * If no socket needs service, it'll return anyway after
		 * the number of ms in the second argument.
		 */

		n = lws_service(context, 50);
#endif

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

#ifdef EXTERNAL_POLL
done:
#endif

	lws_context_destroy(context);

	lwsl_notice("libwebsockets-test-server exited cleanly\n");

#ifndef _WIN32
	closelog();
#endif

	return 0;
}
