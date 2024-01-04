/*
 * lws-minimal-http-server-systemd-socketact
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws.
 *
 * To keep it simple, it serves stuff from the subdirectory
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;

static const struct lws_http_mount mount = {
	.mountpoint			= "/",		    /* mountpoint URL */
	.origin				= INSTALL_SHARE,    /* serve from dir */
	.def				= "index.html",	  /* default filename */
	.origin_protocol		= LWSMPRO_FILE,	    /* files in a dir */
	.mountpoint_len			= 1,		        /* char count */
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.default_loglevel		= LLL_USER | LLL_ERR | LLL_WARN;
	info.fd_limit_per_thread        = 128;
	if (lws_systemd_inherited_fd(0, &info)) {
		lwsl_err("This example needs to run from systemd "
			 "socket activation (see README.md)\n");
		return 1;
	}
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal http server via socket activation | "
		  "visit http://localhost:%u\n", info.port);

	info.mounts			= &mount;
	info.error_document_404		= "/404.html";
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	n = 0;
	while (n >= 0 && !interrupted)
		n = lws_service(cx, 0);

	lws_context_destroy(cx);

	return 0;
}
