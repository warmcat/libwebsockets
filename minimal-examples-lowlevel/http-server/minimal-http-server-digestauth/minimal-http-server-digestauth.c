/*
 * lws-minimal-http-server-digestauth
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server with a second mount that
 * is protected using an htdigest password file and HTTP Digest Auth.
 *
 * To keep it simple, it serves the static stuff from the subdirectory
 * "./mount-origin" of the directory it was started in.
 *
 * The /secret mount is protected by Digest Auth using the file
 * ./da-passwords (htdigest format: username:realm:HA1hex per line).
 *
 * You can create or manage the password file with the htdigest tool:
 *
 *   htdigest -c ./da-passwords lwsws user
 *
 * The supplied ./da-passwords has credentials user:password for realm lwsws.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;

/* /secret mount protected by Digest Auth */
static const struct lws_http_mount mount_secret = {
	.mountpoint		= "/secret",
	.origin			= "./mount-secret-origin",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 7,
	.basic_auth_login_file	= "./da-passwords",
	.basic_auth_realm	= "lwsws",
	.auth_mask		= LWSAUTHM_DIGEST_AUTH,
};

/* default mount serves the URL space from ./mount-origin */
static const struct lws_http_mount mount = {
	.mount_next		= &mount_secret,
	.mountpoint		= "/",
	.origin			= "./mount-origin",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
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

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal http server digest auth | visit http://localhost:7681\n");

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = 7681;
	info.mounts = &mount;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
