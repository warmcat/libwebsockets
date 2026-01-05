/*
 * lws-minimal-http-server-testsfail
 *
 * Written in 2010-2024 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This acts as a local replacement for httpbin.org for the
 * minimal-secure-streams-testsfail example.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>

struct pss {
	struct lws_sorted_usec_list sul;
	struct lws *wsi;

	size_t content_len;
	size_t written;
	int status;

	unsigned int headers_sent:1;
	unsigned int delayed:1;
};

static int interrupted;

static void
sul_cb(struct lws_sorted_usec_list *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul);

	pss->delayed = 0;
	lws_callback_on_writable(pss->wsi);
}

static int
write_headers(struct lws *wsi, struct pss *pss, uint8_t *start, uint8_t *p, uint8_t *end)
{
	if (lws_add_http_common_headers(wsi, (unsigned int)pss->status,
			"text/plain",
			pss->content_len, /* content len */
			&p, end))
		return 1;
	if (lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	pss->headers_sent = 1;
	return 0;
}

static int
callback_httpbin(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	const char *uri;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->wsi = wsi;

		if (lws_hdr_copy(wsi, (char *)buf, sizeof(buf), WSI_TOKEN_GET_URI) < 0)
			return -1;

		uri = (const char *)buf;
		lwsl_notice("HTTP REQ: %s\n", uri);

		if (!strncmp(uri, "/httpbin", 8))
			uri += 8;

		if (!strncmp(uri, "/status/", 8)) {
			pss->status = atoi(uri + 8);
			pss->content_len = 0;
		} else if (!strncmp(uri, "/bytes/", 7)) {
			pss->status = 200;
			pss->content_len = (size_t)atoi(uri + 7);
		} else if (!strncmp(uri, "/delay/", 7)) {
			int delay_sec = atoi(uri + 7);
			pss->status = 200;
			pss->content_len = 0;
			pss->delayed = 1;

			lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul, sul_cb,
					 (lws_usec_t)delay_sec * LWS_US_PER_SEC);
			return 0; /* Wait for sul */
		} else {
			pss->status = 404;
			pss->content_len = 0;
		}

		/* Send headers immediately if not delayed */
		if (write_headers(wsi, pss, start, p, end))
			return -1;

		if (pss->content_len > 0) {
			lws_callback_on_writable(wsi);
		} else {
			if (lws_http_transaction_completed(wsi))
				return -1;
		}
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (pss->delayed)
			return 0;

		/* If delayed, we haven't sent headers yet */
		if (!pss->headers_sent) {
			if (write_headers(wsi, pss, start, p, end))
				return -1;
			if (pss->content_len == 0) {
				if (lws_http_transaction_completed(wsi))
					return -1;
				return 0;
			}
		}

		if (pss->content_len > 0 && pss->written < pss->content_len) {
			size_t chunk = pss->content_len - pss->written;
			if (chunk > 1024)
				chunk = 1024;

			lws_get_random(lws_get_context(wsi), start, chunk);

			if (lws_write(wsi, start, chunk, LWS_WRITE_HTTP) < 0)
				return -1;

			pss->written += chunk;
			if (pss->written < pss->content_len) {
				lws_callback_on_writable(wsi);
				return 0;
			}
		}

		if (pss->written >= pss->content_len) {
			if (lws_http_transaction_completed(wsi))
				return -1;
		}

		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lws_sul_cancel(&pss->sul);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_httpbin, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount = {
	.mountpoint		= "/",		/* mountpoint URL */
	.protocol		= "http",
	.origin_protocol	= LWSMPRO_CALLBACK,
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
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int base_port = 7681;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "--port")))
		base_port = atoi(p);

	lwsl_user("LWS httpbin replacement | port %d (TLS on %d)\n", base_port, base_port + 1);

	memset(&info, 0, sizeof info);
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* http on base_port */
	info.port = base_port;
	info.protocols = protocols;
	info.mounts = &mount;
	info.vhost_name = "http";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create http vhost\n");
		goto bail;
	}

	/* https on base_port + 1 */
	info.port = base_port + 1;
	info.error_document_404 = "/404.html";
#if defined(LWS_WITH_TLS)
	info.ssl_cert_filepath = "libwebsockets-test-server.pem";
	info.ssl_private_key_filepath = "libwebsockets-test-server.key.pem";
#endif
	info.vhost_name = "https";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create https vhost\n");
		goto bail;
	}

	while (lws_service(context, 0) >= 0 && !interrupted)
		;

bail:
	lws_context_destroy(context);

	return 0;
}
