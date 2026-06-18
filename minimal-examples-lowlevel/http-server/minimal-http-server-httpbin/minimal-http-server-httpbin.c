/*
 * lws-minimal-http-server-httpbin
 *
 * Written in 2010-2023 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that mimics basic httpbin.org functionality
 * used by lws ctests for testing offline, e.g. /status/200, /delay/10, /bytes/1000.
 */

#include <libwebsockets.h>

#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

struct pss {
	lws_sorted_usec_list_t sul;
	struct lws *wsi;
	char path[128];
	int status_code;
	int delay_secs;
	size_t bytes_left;
	int headers_sent;
	int writing_bytes;
};

static int interrupted;

static void
delay_cb(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul);
	lwsl_notice("%s: delay over, resuming writable\n", __func__);
	pss->delay_secs = 0;
	lws_callback_on_writable(pss->wsi);
}

static int
callback_httpbin(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;
	const char *uri;

	switch (reason) {
	case LWS_CALLBACK_HTTP: {
		char temp_uri[128];

		uri = (const char *)in;
		if (uri && uri[0] != '/') {
			/* LWS drops the leading slash for the callback, add it back for our logic */
			lws_snprintf(temp_uri, sizeof(temp_uri), "/%s", uri);
			uri = temp_uri;
		}

		if (!strncmp(uri, "/httpbin", 8))
			uri += 8;

		lws_snprintf(pss->path, sizeof(pss->path), "%s", uri);
		uri = pss->path;
		pss->wsi = wsi;
		pss->status_code = 200;
		pss->delay_secs = 0;
		pss->bytes_left = 0;
		pss->headers_sent = 0;
		pss->writing_bytes = 0;

		lwsl_notice("%s: HTTP: URI %s\n", __func__, uri);

		if (!strncmp(uri, "/status/", 8)) {
			pss->status_code = atoi(uri + 8);
		} else if (!strncmp(uri, "/delay/", 7)) {
			pss->delay_secs = atoi(uri + 7);
		} else if (!strncmp(uri, "/bytes/", 7)) {
			pss->bytes_left = (size_t)atoll(uri + 7);
			pss->writing_bytes = 1;
		}

		if (pss->delay_secs > 0) {
			lwsl_notice("%s: delaying %d secs\n", __func__, pss->delay_secs);
			lws_sul_schedule(lws_get_context(wsi), 0, &pss->sul, delay_cb,
					 (lws_usec_t)(pss->delay_secs * LWS_US_PER_SEC));
			return 0;
		}

		lws_callback_on_writable(wsi);
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:

		if (!pss || pss->delay_secs)
			break;

		if (!pss->headers_sent) {
			if (lws_add_http_common_headers(wsi, (unsigned int)pss->status_code,
					"text/plain",
					pss->writing_bytes ? pss->bytes_left : 0,
					&p, end))
				return 1;
			if (lws_finalize_http_header(wsi, &p, end))
				return 1;
			pss->headers_sent = 1;

			int flags = LWS_WRITE_HTTP_HEADERS;
			if (!pss->writing_bytes)
				flags |= LWS_WRITE_H2_STREAM_END;

			n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start), (enum lws_write_protocol)flags);
			if (n < 0)
				return 1;

			if (!pss->writing_bytes) {
				if (lws_http_transaction_completed(wsi))
					return -1;
				return 0;
			}

			lws_callback_on_writable(wsi);
			return 0;
		}

		if (pss->writing_bytes) {
			size_t chunk = pss->bytes_left;
			if (chunk > sizeof(buf) - LWS_PRE)
				chunk = sizeof(buf) - LWS_PRE;

			memset(start, 'A', chunk);

			n = lws_write(wsi, start, chunk, (pss->bytes_left == chunk) ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP);
			if (n < 0)
				return 1;

			pss->bytes_left -= (size_t)n;

			if (pss->bytes_left == 0) {
				if (lws_http_transaction_completed(wsi))
					return -1;
			} else {
				lws_callback_on_writable(wsi);
			}
		}
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss)
			lws_sul_cancel(&pss->sul);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols defprot =
	{ "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 }, protocol =
	{ "http", callback_httpbin, sizeof(struct pss), 0, 0, NULL, 0 };

static const struct lws_protocols *pprotocols[] = { &defprot, &protocol, NULL };

static const struct lws_http_mount mount_dyn = {
	.mountpoint		= "/",
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
	int n = 0;
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS minimal http server httpbin\n");

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if (lws_cmdline_option(argc, argv, "-s")) {
		info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

#if defined(LWS_WITH_TLS)
	if (lws_cmdline_option(argc, argv, "-s")) {
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
	}
#endif

	info.port = 7681;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		{
			int __pt = atoi(p);
			if (__pt < 0 || __pt > 65535) {
				lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
				return 1;
			}
			info.port = __pt;
		}

	info.pprotocols = pprotocols;
	info.mounts = &mount_dyn;
	info.vhost_name = "http";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create vhost\n");
		goto bail;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	return 0;
}
