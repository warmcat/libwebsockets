/*
 * lws-api-test-http-cgi-stdin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests the CGI stdin proxying path end-to-end at its boundary condition.
 *
 * A server vhost mounts a CGI script (cgi.sh next to this file, a small
 * POSIX sh script that counts the bytes arriving on its stdin and answers
 * with that count).  An h1 client POSTs a body sized in exact multiples of
 * the server's largest possible single h1 body read on the direct-read
 * path (pt_serv_buf_size - LWS_PRE bytes), so that body chunks are handed
 * to LWS_CALLBACK_CGI_STDIN_DATA ending exactly at the end of pt->serv_buf.
 *
 * This is the exact shaping of security audit finding F-001: the CGI stdin
 * handling in lws_callback_http_dummy() historically NUL-terminated
 * args->data[args->len] there, writing one byte past pt->serv_buf into the
 * same pt's fakewsi.  The regression guard here is that the CGI process
 * receives the complete body intact (exact byte count reported back) and
 * the http transaction completes normally with 200.
 *
 * With --chunked, the client sends the same body with Transfer-Encoding:
 * chunked instead of a Content-Length, one chunk per write: the server must
 * decode it, hand the CGI only the payload, and close the CGI's stdin at the
 * last-chunk so the script's read sees EOF.
 *
 * The test fails if
 *  - the client connection or transaction errors out,
 *  - the response status is not 200,
 *  - the CGI does not report receiving every byte of the POST body,
 *  - no completion is seen inside the watchdog period.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/*
 * This must match info.pt_serv_buf_size set in main(): the biggest body
 * chunk the server can deliver in one go from the direct read path fills
 * pt->serv_buf from LWS_PRE to the end, exactly.
 */
#define SERV_BUF_SIZE	4096
#define CHUNK		(SERV_BUF_SIZE - LWS_PRE)
#define CHUNKS		4

static struct lws_context *context;
static int done;
static int chunked;
static int result = 1;
static int status;
static int port_tcp = 7681;
static lws_sorted_usec_list_t sul_timeout;

static char rx[128];
static size_t rx_len;

static uint8_t body[LWS_PRE + CHUNK];

static const char cgi_script_path[] = CGI_SCRIPT_PATH;

static const struct lws_http_mount mount = {
	.mountpoint		= "/",			/* mountpoint URL */
	.origin			= cgi_script_path,	/* cgi script */
	.def			= "/",
	.origin_protocol	= LWSMPRO_CGI,
	.mountpoint_len		= 1,			/* char count */
};

struct pss {
	int chunks_done;
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	if (!done)
		lwsl_err("--- watchdog: cgi stdin roundtrip did not complete ---\n");
	done = 1;
	lws_default_loop_exit(context);
}

static void
evaluate_response(void)
{
	const char *p = strstr(rx, "bytes=");
	unsigned long expect = (unsigned long)CHUNKS * CHUNK, seen = 0;

	if (status != 200) {
		lwsl_err("--- response status %d, expected 200 ---\n", status);
		goto fail;
	}

	if (!p) {
		lwsl_err("--- no byte count in response, rx '%s' ---\n", rx);
		goto fail;
	}

	for (p += 6; *p >= '0' && *p <= '9'; p++)
		seen = (seen * 10) + (unsigned long)(*p - '0');

	if (seen != expect) {
		lwsl_err("--- cgi received %lu bytes, expected %lu ---\n",
			 seen, expect);
		goto fail;
	}

	lwsl_user("--- cgi stdin received all %lu bytes.  Test passed. ---\n",
		  seen);
	result = 0;
	done = 1;
	lws_default_loop_exit(context);

	return;

fail:
	result = 1;
	done = 1;
	lws_default_loop_exit(context);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE];
	uint8_t **pp, *end;
	int n;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("--- client: connection error: %s ---\n",
			 in ? (const char *)in : "(null)");
		lws_default_loop_exit(context);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: client established, response status %d\n",
			  __func__, status);
		break;

	/* ...callbacks related to generating the POST body... */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		pp = (uint8_t **)in;
		end = (*pp) + len;

		if (chunked) {
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(const uint8_t *)"chunked", 7, pp, end))
				return -1;
		} else
			/*
			 * Give the exact body size, so the server side takes
			 * the bounded content-length path through LRS_BODY
			 */
			if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)CHUNKS * CHUNK,
						pp, end))
				return -1;

		/* ... we are going to send the body next ... */
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (pss->chunks_done >= CHUNKS)
			return 0;

		/*
		 * Send the body one serv_buf-sized chunk per trip around
		 * the event loop, so the server meets body reads that fill
		 * its read buffer exactly
		 */
		n = LWS_WRITE_HTTP;
		if (pss->chunks_done == CHUNKS - 1) {
			/* this is the last piece */
			lws_client_http_body_pending(wsi, 0);
			n = LWS_WRITE_HTTP_FINAL;
		}

		if (chunked) {
			/*
			 * Frame this piece as one chunk, with the last-chunk
			 * and trailer terminator after the final piece
			 */
			static uint8_t fbuf[LWS_PRE + 16 + CHUNK + 8];
			size_t o;

			o = (size_t)lws_snprintf((char *)&fbuf[LWS_PRE], 16,
						 "%x\x0d\x0a", (unsigned int)CHUNK);
			memcpy(&fbuf[LWS_PRE + o], &body[LWS_PRE], CHUNK);
			o += CHUNK;
			fbuf[LWS_PRE + o++] = '\x0d';
			fbuf[LWS_PRE + o++] = '\x0a';
			if (n == LWS_WRITE_HTTP_FINAL) {
				memcpy(&fbuf[LWS_PRE + o], "0\x0d\x0a\x0d\x0a", 5);
				o += 5;
			}

			if (lws_write(wsi, &fbuf[LWS_PRE], o,
				      (enum lws_write_protocol)n) != (int)o)
				return -1;
		} else
			if (lws_write(wsi, &body[LWS_PRE], CHUNK,
				      (enum lws_write_protocol)n) != CHUNK)
				return -1;

		pss->chunks_done++;

		if (n != LWS_WRITE_HTTP_FINAL)
			lws_callback_on_writable(wsi);
		break;

	/* ...callbacks related to receiving the result... */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		size_t o = 0;

		/* accumulate the tiny cgi response body */
		while (o < len && rx_len + 1 < sizeof(rx))
			rx[rx_len++] = ((const char *)in)[o++];
		rx[rx_len] = '\0';

		lwsl_user("%s: read %d\n", __func__, (int)len);

		return 0; /* don't passthru */
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = (int)(sizeof(buf) - LWS_PRE);
		if (lws_http_client_read(wsi, &start, &n) < 0)
			return -1;

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		evaluate_response();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!done)
			lwsl_err("--- client: closed before completion ---\n");
		lws_default_loop_exit(context);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http", callback_cli, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
	const char *p;
	size_t n;
	int n_int = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_tcp = atoi(p);

	chunked = !!lws_cmdline_option(argc, argv, "--chunked");

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: POST body -> CGI stdin at serv_buf "
		  "boundary%s\n", chunked ? " (chunked)" : "");

	/* deterministic body content */
	for (n = 0; n < CHUNK; n++)
		body[LWS_PRE + n] = (uint8_t)('A' + (n % 26));

	/*
	 * Pin the server read buffer size, so the body chunk boundary math
	 * above stays valid
	 */
	info.pt_serv_buf_size = SERV_BUF_SIZE;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* server vhost serving the cgi script at / */

	info.port = port_tcp;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	info.mounts = &mount;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	/* client vhost, no listener */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh;
	p = "127.0.0.1";
	{
		const char *cs = lws_cmdline_option(argc, argv, "--server");
		if (cs)
			p = cs;
	}
	i.address = p;
	i.port = port_tcp;
	i.path = "/";
	i.host = p;
	i.origin = p;
	i.method = "POST";
	i.protocol = protocols_cli[0].name;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("client connect failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	while (n_int >= 0)
		n_int = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
