/*
 * lws-minimal-http-server-hls
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;

enum {
	LWS_SW_H2_PRIOR_KNOWLEDGE,
	LWS_SW_D,
	LWS_SW_MEDIA_DIR,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_H2_PRIOR_KNOWLEDGE]	= { "--h2-prior-knowledge", "Enable --h2-prior-knowledge feature" },
	[LWS_SW_D]			= { "-d", "Debug logs (e.g. -d 15)" },
	[LWS_SW_MEDIA_DIR]		= { "--media-dir", "Directory containing media files (default: ./media)" },
	[LWS_SW_HELP]			= { "--help", "Show this help information" },
};

#ifndef INSTALL_DATADIR
#define INSTALL_DATADIR "/usr/local/share"
#endif

static struct lws_protocol_vhost_options pvo_media = {
	NULL, NULL, "media-dir", INSTALL_DATADIR "/libwebsockets-test-server/hls"
};

static const struct lws_protocol_vhost_options pvo_csp = {
        NULL, NULL, "content-security-policy:",
        "default-src 'self'; img-src 'self' data: ; "
        "script-src 'self'; script-src-elem 'self'; font-src 'self'; "
        "style-src 'self'; connect-src 'self' ws: wss:; "
        "worker-src 'self' blob:; child-src 'self' blob:; media-src 'self' blob:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self';"
};

static const struct lws_protocol_vhost_options pvo = {
	NULL, &pvo_media, "lws-hls", ""
};

static const struct lws_http_mount mount_hls = {
	.mount_next		= NULL,
	.mountpoint		= "/hls",		/* mountpoint URL */
	.origin			= INSTALL_DATADIR "/libwebsockets-test-server/hls/mount-origin",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,	/* serve from dir */
	.mountpoint_len		= 4,			/* char count */
};

static const struct lws_http_mount mount_hls_live = {
	.mount_next		= &mount_hls,
	.mountpoint		= "/hls/hls",		/* mountpoint URL */
	.protocol		= "lws-hls",		/* protocol name */
	.origin_protocol	= LWSMPRO_CALLBACK,	/* callback */
	.mountpoint_len		= 8,			/* char count */
};

static const struct lws_protocol_vhost_options pvo_mime_mkv = {
        NULL, NULL, ".mkv", "video/webm"
};

static const struct lws_protocol_vhost_options pvo_mime_mp4 = {
        &pvo_mime_mkv, NULL, ".mp4", "video/mp4"
};

static struct lws_http_mount mount_raw_media = {
        .mount_next             = &mount_hls_live,
        .mountpoint             = "/media",             /* mountpoint URL */
        .origin                 = NULL,                 /* set at runtime */
        .def                    = "index.html",
        .origin_protocol        = LWSMPRO_FILE,         /* serve from dir */
        .mountpoint_len         = 6,                    /* char count */
        .extra_mimetypes        = &pvo_mime_mp4,
};

static const struct lws_http_mount mount = {
        .mount_next             = &mount_raw_media,
        .mountpoint             = "/",                  /* mountpoint URL */
        .origin                 = INSTALL_DATADIR "/libwebsockets-test-server/hls/mount-origin",
        .def                    = "index.html",
        .origin_protocol        = LWSMPRO_FILE,         /* serve from dir */
        .mountpoint_len         = 1,                    /* char count */
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;
	const char *p;
	
#if defined(LWS_WITH_PLUGINS)
	/* LWS searches for plugins in this array of paths */
	static const char * const plugin_dirs[] = {
		"../../lib", /* For running from build/minimal-examples-lowlevel/... */
		"./lib",
		NULL
	};
#endif

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_MEDIA_DIR].sw)))
		pvo_media.value = p;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-i")))
		info.iface = p;
	else
		info.iface = "lo";

	if ((p = lws_cmdline_option(argc, argv, "-b")))
		pvo_media.value = p;

	lwsl_user("LWS minimal http server HLS | visit http://localhost:7681\n");
	lwsl_user("Media dir: %s\n", pvo_media.value);
	if (info.iface)
		lwsl_user("Binding to interface: %s\n", info.iface);

	info.port = 7681;
	
	info.headers = &pvo_csp;
	info.pvo = &pvo;
	mount_raw_media.origin = pvo_media.value;
	info.mounts = &mount;
#if defined(LWS_WITH_PLUGINS)
	info.plugin_dirs = plugin_dirs;
#endif

	info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_H2_PRIOR_KNOWLEDGE].sw))
		info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* We create the vhost explicitly so plugins are loaded and attached */
	struct lws_vhost *vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create vhost\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
