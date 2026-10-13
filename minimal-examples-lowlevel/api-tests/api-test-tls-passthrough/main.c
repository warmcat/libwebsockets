/*
 * lws-api-test-tls-passthrough
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * End to end test of tls passthrough and PROXY v2, all in one process:
 *
 *  - "backend" terminates tls itself, and trusts 127.0.0.1 (where the front
 *    connects from) to send a PROXY v2 header first.  Its http answer says
 *    who it believes the client is, from lws_get_peer_simple();
 *
 *  - "front.test" terminates tls on the front port, and answers "front";
 *
 *  - "pass.test", on the same front port, has no certificate: its
 *    connections are passed to the backend undecrypted, with a PROXY v2
 *    header naming the client;
 *
 *  - "capture" is a raw listener, that a tls client is pointed at only to
 *    record a real ClientHello naming pass.test, for the raw scenarios.
 *
 * In order, it checks:
 *
 *  - a client naming front.test is served by the front itself;
 *
 *  - a client naming pass.test is served by the backend, through the front,
 *    and the backend sees the real client: where the build has IPv6, the
 *    client dials the front on ::1 while the front reaches the backend from
 *    127.0.0.1, so ::1 can only have come from the PROXY v2 header;
 *
 *  - the recorded ClientHello, split into three tls records sent as three
 *    tcp writes a little apart, is still seen as naming pass.test and passed
 *    through: the backend answers it with a ServerHello;
 *
 *  - straight to the backend from 127.0.0.1, which it trusts, without a
 *    PROXY v2 header, the connection is dropped unanswered;
 *
 *  - straight to the backend from ::1, which it does not trust, a forged
 *    PROXY v2 header is not believed, just tls garbage: no ServerHello;
 *
 *  - a forged PROXY v2 header sent to the front ahead of the ClientHello is
 *    not passed through at all: the backend never even sees a connection.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	ST_TERMINATED,
	ST_PASSTHROUGH,
	ST_CAPTURE,
	ST_MULTIRECORD,
	ST_TRUSTED_NO_HEADER,
	ST_UNTRUSTED_FORGED,
	ST_FRONT_FORGED,
	ST_DONE
};

static const char * const step_names[] = {
	"a client naming front.test is served by the front",
	"a client naming pass.test is served by the backend, which sees "
		"the real client",
	"a real ClientHello for pass.test is recorded",
	"a ClientHello in three records and three writes is passed through",
	"a trusted peer without a PROXY v2 header is dropped",
	"a forged PROXY v2 header from an untrusted peer is not believed",
	"a forged PROXY v2 header sent to the front is not passed through",
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_step, sul_send;
static int port_front, port_back, port_capture, step, tests, fail, done;
static int backend_accepts, accepts_at_step;
static const char *certs = ".";

/* what the current step's client saw */
static char body[256];
static size_t body_len;
static int got_server_hello, rx_bytes, step_closed;

/* the ClientHello the capture listener recorded */
static uint8_t hello[16384];
static size_t hello_len;

/* what the raw client sends, in pieces */
static uint8_t tx[16384 + 64];
static size_t tx_len, tx_pos, tx_piece;

static void
expect(const char *what, int ok)
{
	tests++;
	if (!ok)
		fail++;
	lwsl_user("  %s: %s\n", ok ? "PASS" : "FAIL", what);
}

/* ------------------------------------------------------------- servers */

static int
answer(struct lws *wsi, const char *who)
{
	uint8_t buf[LWS_PRE + 512], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	char peer[64], b[128];
	int n;

	lws_get_peer_simple(wsi, peer, sizeof(peer));
	n = lws_snprintf(b, sizeof(b), "%s %s", who, peer);

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)n, &p, end) ||
	    lws_finalize_http_header(wsi, &p, end))
		return 1;
	memcpy(p, b, (size_t)n);
	p += n;
	if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_FINAL) < 0)
		return 1;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

static int
callback_backend(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		backend_accepts++;
		break;
	case LWS_CALLBACK_HTTP:
		return answer(wsi, "backend");
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_front(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_HTTP)
		return answer(wsi, "front");

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
step_next(void);

static int
callback_capture(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (hello_len + len > sizeof(hello))
			return -1;
		memcpy(hello + hello_len, in, len);
		hello_len += len;
		/* the first record whole is all we want */
		if (hello_len >= 5 &&
		    hello_len >= 5 + (((size_t)hello[3] << 8) | hello[4]))
			return -1;
		break;
	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------- clients */

static void
send_piece(lws_sorted_usec_list_t *sul);

/* the current step's client connection: the earlier ones are done with */
static struct lws *step_wsi;

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char *px;
	int alen;

	if (wsi != step_wsi)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {

	/* the https steps */

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: step %d: connection error: %s\n", __func__,
			    step, in ? (const char *)in : "?");
		step_closed = 1;
		lws_sul_schedule(context, 0, &sul_step, (sul_cb_t)step_next, 1);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[LWS_PRE + 1024];

		px = buf + LWS_PRE;
		alen = (int)sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len < sizeof(body)) {
			memcpy(body + body_len, in, len);
			body_len += len;
			body[body_len] = '\0';
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!step_closed) {
			step_closed = 1;
			lws_sul_schedule(context, 0, &sul_step,
					 (sul_cb_t)step_next, 1);
		}
		break;

	/* the raw steps */

	case LWS_CALLBACK_RAW_CONNECTED:
		tx_pos = 0;
		lws_sul_schedule(context, 0, &sul_send, send_piece, 1);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!rx_bytes && len >= 1 && ((uint8_t *)in)[0] == 0x16)
			got_server_hello = 1;
		rx_bytes += (int)len;
		if (got_server_hello)
			/* that is the answer we were waiting for */
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE: {
		uint8_t buf[LWS_PRE + sizeof(tx)];
		size_t n = tx_piece;

		if (tx_pos + n > tx_len)
			n = tx_len - tx_pos;
		if (!n)
			break;
		memcpy(buf + LWS_PRE, tx + tx_pos, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) < (int)n)
			return -1;
		tx_pos += n;
		if (tx_pos < tx_len)
			/* the next piece a little later, as its own segment */
			lws_sul_schedule(context, 0, &sul_send, send_piece,
					 30 * LWS_US_PER_MS);
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE:
		lws_sul_cancel(&sul_send);
		if (!step_closed) {
			step_closed = 1;
			lws_sul_schedule(context, 0, &sul_step,
					 (sul_cb_t)step_next, 1);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
send_piece(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	if (step_wsi)
		lws_callback_on_writable(step_wsi);
}

static int
https_get(const char *address, int port, const char *host)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= address;
	i.port			= port;
	i.host			= host;
	i.origin		= host;
	i.path			= "/";
	i.method		= "GET";
	i.alpn			= "http/1.1";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_ALLOW_INSECURE;
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.pwsi			= &step_wsi;

	return !lws_client_connect_via_info(&i);
}

/* a raw connection that sends tx[] in pieces of piece bytes */
static int
raw_send(const char *address, int port, size_t piece)
{
	struct lws_client_connect_info i;

	tx_piece = piece;
	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= address;
	i.port			= port;
	i.host			= address;
	i.method		= "RAW";
	i.local_protocol_name	= "cli";
	i.pwsi			= &step_wsi;

	return !lws_client_connect_via_info(&i);
}

/* a forged PROXY v2 header claiming the client is 192.0.2.66, into tx */
static size_t
forged_header(void)
{
	lws_proxy_v2_t pv;
	int n;

	memset(&pv, 0, sizeof(pv));
	if (lws_sa46_parse_numeric_address("192.0.2.66", &pv.src) ||
	    lws_sa46_parse_numeric_address("192.0.2.1", &pv.dst))
		return 0;
	n = lws_proxy_v2_render(&pv, tx, sizeof(tx));

	return n > 0 ? (size_t)n : 0;
}

/* ------------------------------------------------------------- sequence */

static const char *
loopback6(void)
{
#if defined(LWS_WITH_IPV6)
	return "::1";
#else
	return "127.0.0.1";
#endif
}

static void
step_start(void)
{
	size_t n, rl, part, pos;

	body_len = 0;
	body[0] = '\0';
	got_server_hello = 0;
	rx_bytes = 0;
	step_closed = 0;
	step_wsi = NULL;
	accepts_at_step = backend_accepts;

	switch (step) {
	case ST_TERMINATED:
		if (https_get("127.0.0.1", port_front, "front.test"))
			goto fail;
		break;

	case ST_PASSTHROUGH:
		if (https_get(loopback6(), port_front, "pass.test"))
			goto fail;
		break;

	case ST_CAPTURE:
		/* it fails, the capture listener hangs up once it has it */
		if (https_get("127.0.0.1", port_capture, "pass.test"))
			goto fail;
		break;

	case ST_MULTIRECORD:
		/*
		 * The recorded ClientHello's handshake message, re-framed as
		 * three records, each sent as its own write
		 */
		rl = hello_len - 5;
		part = (rl + 2) / 3;
		tx_len = 0;
		for (pos = 0; pos < rl; pos += part) {
			n = rl - pos < part ? rl - pos : part;
			tx[tx_len++] = 0x16;
			tx[tx_len++] = hello[1];
			tx[tx_len++] = hello[2];
			tx[tx_len++] = (uint8_t)(n >> 8);
			tx[tx_len++] = (uint8_t)n;
			memcpy(tx + tx_len, hello + 5 + pos, n);
			tx_len += n;
		}
		if (raw_send("127.0.0.1", port_front, 5 + part))
			goto fail;
		break;

	case ST_TRUSTED_NO_HEADER:
		memcpy(tx, hello, hello_len);
		tx_len = hello_len;
		if (raw_send("127.0.0.1", port_back, tx_len))
			goto fail;
		break;

	case ST_UNTRUSTED_FORGED:
	case ST_FRONT_FORGED:
		n = forged_header();
		if (!n)
			goto fail;
		memcpy(tx + n, hello, hello_len);
		tx_len = n + hello_len;
		if (raw_send(step == ST_FRONT_FORGED ? "127.0.0.1" : loopback6(),
			     step == ST_FRONT_FORGED ? port_front : port_back,
			     tx_len))
			goto fail;
		break;
	}

	return;

fail:
	expect(step_names[step], 0);
	done = 1;
	lws_cancel_service(context);
}

static void
step_next(void)
{
	int ok = 0;

	switch (step) {
	case ST_TERMINATED:
		ok = !strncmp(body, "front ", 6);
		break;
	case ST_PASSTHROUGH:
		lwsl_user("  passed through, the backend said '%s'\n", body);
		ok = !strncmp(body, "backend ", 8) &&
		     !strcmp(body + 8, loopback6());
		break;
	case ST_CAPTURE:
		ok = hello_len >= 5 && hello[0] == 0x16 &&
		     hello_len >= 5 + (((size_t)hello[3] << 8) | hello[4]);
		/* only the first record */
		if (ok)
			hello_len = 5 + (((size_t)hello[3] << 8) | hello[4]);
		break;
	case ST_MULTIRECORD:
		/*
		 * The front's own tls would answer with a ServerHello too, if
		 * the name were not found: it must be the backend's
		 */
		ok = got_server_hello && backend_accepts > accepts_at_step;
		break;
	case ST_TRUSTED_NO_HEADER:
		ok = !got_server_hello && !rx_bytes;
		break;
	case ST_UNTRUSTED_FORGED:
		ok = !got_server_hello;
		break;
	case ST_FRONT_FORGED:
		ok = !got_server_hello && backend_accepts == accepts_at_step;
		break;
	}

	expect(step_names[step], ok);
	if (!ok || ++step == ST_DONE) {
		done = 1;
		lws_cancel_service(context);
		return;
	}

#if !defined(LWS_WITH_IPV6)
	if (step == ST_UNTRUSTED_FORGED)
		/* nowhere to connect from that the backend does not trust */
		step++;
#endif

	step_start();
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

static const struct lws_protocols
	pcol_backend = { "backend", callback_backend, 0, 0, 0, NULL, 0 },
	pcol_front = { "front", callback_front, 0, 0, 0, NULL, 0 },
	pcol_capture = { "capture", callback_capture, 0, 0, 0, NULL, 0 },
	pcol_cli = { "cli", callback_cli, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pp_backend[] = { &pcol_backend, NULL },
	*pp_front[] = { &pcol_front, NULL },
	*pp_capture[] = { &pcol_capture, NULL },
	*pp_cli[] = { &pcol_cli, NULL };

static const struct lws_http_mount
	mount_backend = {
		.mountpoint		= "/",
		.protocol		= "backend",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	},
	mount_front = {
		.mountpoint		= "/",
		.protocol		= "front",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 1,
	};

static lws_sorted_usec_list_t sul_deadline;

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	expect(step < ST_DONE ? step_names[step] : "deadline", 0);
	done = 1;
	lws_cancel_service(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char cert[256], key[256], target[64];
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	port_front = 7681;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_front = atoi(p);
	port_back = port_front + 1;
	port_capture = port_front + 2;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;

	lwsl_user("LWS API selftest: tls passthrough and PROXY v2\n");

	lws_snprintf(cert, sizeof(cert), "%s/localhost-100y.cert", certs);
	lws_snprintf(key, sizeof(key), "%s/localhost-100y.key", certs);
	lws_snprintf(target, sizeof(target), "127.0.0.1:%d", port_back);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the backend: terminates its own tls, trusts the front's PROXY v2 */
	info.vhost_name			= "backend";
	info.port			= port_back;
	info.pprotocols			= pp_backend;
	info.mounts			= &mount_backend;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.proxy_v2_trusted		= "127.0.0.1";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.proxy_v2_trusted		= NULL;

	/* the front's own tls vhost, made first so it owns the listener */
	info.vhost_name			= "front.test";
	info.port			= port_front;
	info.pprotocols			= pp_front;
	info.mounts			= &mount_front;
	if (!lws_create_vhost(context, &info))
		goto bail;

	/* the passed through vhost, on the same port, with no tls of its own */
	info.vhost_name			= "pass.test";
	info.pprotocols			= NULL;
	info.mounts			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.tls_passthrough		= target;
	info.tls_passthrough_proxy_v2	= 1;
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.tls_passthrough		= NULL;
	info.tls_passthrough_proxy_v2	= 0;

	/* records a ClientHello */
	info.vhost_name			= "capture";
	info.port			= port_capture;
	info.pprotocols			= pp_capture;
	info.options			|= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "capture";
	if (!lws_create_vhost(context, &info))
		goto bail;
	info.options			&= ~(uint64_t)LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;

	info.vhost_name			= "cli";
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols			= pp_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb,
			 60 * LWS_US_PER_SEC);

	step = 0;
	step_start();

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	expect("every step ran", step == ST_DONE);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  !tests || fail ? "FAIL" : "PASS", tests, fail);

	return !tests || fail;
}
