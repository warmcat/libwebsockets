/*
 * lws-minimal-http-server-dynamic
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that can produce dynamic http
 * content as well as static content.
 *
 * To keep it simple, it serves the static stuff from the subdirectory
 * "./mount-origin" of the directory it was started in.
 *
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/*
 * Unlike ws, http is a stateless protocol.  This pss only exists for the
 * duration of a single http transaction.  With http/1.1 keep-alive and http/2,
 * that is unrelated to (shorter than) the lifetime of the network connection.
 */
struct pss {
	char str[128];
	int len;
};

static int interrupted;

static int
callback_dynamic_http(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	time_t t;

	switch (reason) {
	case LWS_CALLBACK_HTTP:

		/* in contains the url part after our mountpoint /dyn, if any */

		t = time(NULL);
		pss->len = lws_snprintf(pss->str, sizeof(pss->str),
				"<html>"
				"<img src=\"/libwebsockets.org-logo.png\">"
				"<br>Dynamic content for '%s' from mountpoint."
				"<br>Time: %s"
				"</html>", (const char *)in, ctime(&t));

		/* prepare and write http headers */
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/html", pss->len, &p, end))
			return 1;
		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		/* write the body separately */
		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:

		if (!pss || !pss->len)
			break;

		/*
		 * Use LWS_WRITE_HTTP for intermediate writes, on http/2
		 * lws uses this to understand to end the stream with this
		 * frame
		 */
		if (lws_write(wsi, (uint8_t *)pss->str, pss->len,
			      LWS_WRITE_HTTP_FINAL) != pss->len)
			return 1;

		/*
		 * HTTP/1.0 no keepalive: close network connection
		 * HTTP/1.1 or HTTP1.0 + KA: wait / process next transaction
		 * HTTP/2: stream ended, parent connection remains up
		 */
		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{ "http", callback_dynamic_http, sizeof(struct pss), 0 },
	{ NULL, NULL, 0, 0 } /* terminator */
};

/* override the default mount for /dyn in the URL space */

static const struct lws_http_mount mount_dyn = {
	/* .mount_next */		NULL,		/* linked-list "next" */
	/* .mountpoint */		"/dyn",		/* mountpoint URL */
	/* .origin */			NULL,	/* protocol */
	/* .def */			NULL,
	/* .protocol */			"http",
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		NULL,
	/* .cgi_timeout */		0,
	/* .cache_max_age */		0,
	/* .auth_mask */		0,
	/* .cache_reusable */		0,
	/* .cache_revalidate */		0,
	/* .cache_intermediaries */	0,
	/* .origin_protocol */		LWSMPRO_CALLBACK, /* dynamic */
	/* .mountpoint_len */		4,		/* char count */
	/* .basic_auth_login_file */	NULL,
};

/* default mount serves the URL space from ./mount-origin */

static const struct lws_http_mount mount = {
	/* .mount_next */	&mount_dyn,		/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */		"./mount-origin",	/* serve from dir */
	/* .def */			"index.html",	/* default filename */
	/* .protocol */			NULL,
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		NULL,
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
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS minimal http server dynamic | visit http://localhost:7681\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.protocols = protocols;
	info.mounts = &mount;

	/* for testing ah queue, not useful in real world */
	if (lws_cmdline_option(argc, argv, "--ah1"))
		info.max_http_header_pool = 1;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 1000);

	lws_context_destroy(context);

	return 0;
}
