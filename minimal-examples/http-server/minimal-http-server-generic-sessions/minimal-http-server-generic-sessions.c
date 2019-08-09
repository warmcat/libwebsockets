/*
 * lws-minimal-http-server-generic-sessions
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates setting up and using generic sessions
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;
struct lws_context *context;

static const struct lws_protocol_vhost_options
   pvo_mm1 = {
	NULL, NULL, "message-db", (void *)"/var/www/sessions/messageboard.sqlite3"
}, pvo_m1 = {
	NULL, &pvo_mm1, "protocol-lws-messageboard", ""
},

   pvo13 = {
	NULL, NULL, "email-confirm-url-base", (void *)"https://localhost:7681/"
}, pvo12 = {
	&pvo13, NULL, "urlroot", (void *)"https://127.0.0.1:7681/"
}, pvo11 = {
	&pvo12, NULL, "email-contact-person", (void *)"andy@warmcat.com"
}, pvo10 = {
	&pvo11, NULL, "email-helo", (void *)"warmcat.com"
}, pvo9 = {
	&pvo10, NULL, "email-expire", (void *)"3600"
}, pvo8 = {
	&pvo9,  NULL, "email-smtp-ip", (void *)"127.0.0.1"
}, pvo7 = {
	&pvo8,  NULL, "email-from", (void *)"noreply@warmcat.com"
}, pvo6 = {
	&pvo7,  NULL, "confounder", (void *)"some kind of secret confounder"
}, pvo5 = {
	&pvo6,  NULL, "timeout-anon-idle-secs", (void *)"1200"
}, pvo4 = {
	&pvo5,  NULL, "timeout-idle-secs", (void *)"6000"
}, pvo3 = {
	&pvo4,  NULL, "session-db", (void *)"/var/www/sessions/lws.sqlite3"
}, pvo2 = {
	&pvo3, NULL, "admin-password-sha256",
	(void *)"25d08521d996bad92605f5a40fe71179dc968e70f669cb1db6190dcd53258200"	/* pvo value */
}, pvo1 = {
	&pvo2, NULL, "admin-user", (void *)"admin"
}, pvo = {
	&pvo_m1, &pvo1, "protocol-generic-sessions", ""
},

   interpret1 = {
	NULL, NULL, ".js", "protocol-lws-messageboard"
},

   pvo_hsbph[] = {{
	NULL, NULL,		"referrer-policy:", "no-referrer"
}, {
	&pvo_hsbph[0], NULL,	"x-xss-protection:", "1; mode=block"
}, {
	&pvo_hsbph[1], NULL,	"x-content-type-options:", "nosniff"
}, {
	&pvo_hsbph[2], NULL,	"content-security-policy:",
				"default-src 'self'; "
				"img-src https://www.gravatar.com 'self' data: ; "
				"script-src 'self'; "
				"font-src 'self'; "
				"style-src 'self'; "
				"connect-src 'self'; "
				"frame-ancestors 'self'; "
				"base-uri 'none'; "
				"form-action  'self';"
}};

 static const struct lws_http_mount mount2 = {
 	/* .mount_next */		NULL,	/* linked-list "next" */
 	/* .mountpoint */		"/needadmin",		/* mountpoint URL */
 	/* .origin */			"./mount-origin/needadmin", /* serve from dir */
 	/* .def */			"index.html",	/* default filename */
 	/* .protocol */			"protocol-lws-messageboard",
 	/* .cgienv */			NULL,
 	/* .extra_mimetypes */		NULL,
 	/* .interpret */		&interpret1,
 	/* .cgi_timeout */		0,
 	/* .cache_max_age */		0,
 	/* .auth_mask */		7,
 	/* .cache_reusable */		0,
 	/* .cache_revalidate */		0,
 	/* .cache_intermediaries */	0,
 	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
 	/* .mountpoint_len */		1,		/* char count */
 	/* .basic_auth_login_file */	NULL,
 };

 static const struct lws_http_mount mount1 = {
 	/* .mount_next */		&mount2,	/* linked-list "next" */
 	/* .mountpoint */		"/needauth",		/* mountpoint URL */
 	/* .origin */			"./mount-origin/needauth", /* serve from dir */
 	/* .def */			"index.html",	/* default filename */
 	/* .protocol */			"protocol-lws-messageboard",
 	/* .cgienv */			NULL,
 	/* .extra_mimetypes */		NULL,
 	/* .interpret */		&interpret1,
 	/* .cgi_timeout */		0,
 	/* .cache_max_age */		0,
 	/* .auth_mask */		5,
 	/* .cache_reusable */		0,
 	/* .cache_revalidate */		0,
 	/* .cache_intermediaries */	0,
 	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
 	/* .mountpoint_len */		1,		/* char count */
 	/* .basic_auth_login_file */	NULL,
 };

static const struct lws_http_mount mount = {
	/* .mount_next */		&mount1,	/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */			"./mount-origin", /* serve from dir */
	/* .def */			"index.html",	/* default filename */
	/* .protocol */			"protocol-lws-messageboard",
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		&interpret1,
	/* .cgi_timeout */		0,
	/* .cache_max_age */		0,
	/* .auth_mask */		0,
	/* .cache_reusable */		0,
	/* .cache_revalidate */		0,
	/* .cache_intermediaries */	0,
	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
	/* .mountpoint_len */		1,		/* char count */
	/* .basic_auth_login_file */	NULL,
};

void sigint_handler(int sig)
{
	lws_context_destroy(context);

	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *plugin_dirs[] = {
		"/usr/local/share/libwebsockets-test-server/plugins",
		NULL };
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server TLS | visit https://localhost:7681\n");

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.ssl_cert_filepath = "localhost-100y.cert";
	info.ssl_private_key_filepath = "localhost-100y.key";
	info.plugin_dirs = plugin_dirs;
	info.pvo = &pvo;

	if (lws_cmdline_option(argc, argv, "-h"))
		info.options |= LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.headers = &pvo_hsbph[3];

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
