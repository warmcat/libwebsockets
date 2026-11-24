/*
 * lws-api-test-ws-pmd-drain
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests that permessage-deflate delivers every byte of messages that
 * inflate to many times the extension's rx buffer (1024 bytes by default),
 * in both directions.
 *
 * The inflater hands its output over one rx buffer at a time, and says it
 * has more pending until the compressed input it was given is used up.
 * Everything after the first buffer's worth is delivered by draining the
 * extension.  When a compressed frame is bigger than one read, the server
 * inflates what it read of it on its bulk payload path and must drain the
 * rest mid-frame, with frame payload still to come: a drain there whose
 * output did not reach the user callback lost exactly one rx buffer of the
 * message, while the first / final fragment flags still looked normal
 * (GitHub issue #3694).
 *
 * A ws server and client run in one process, both with permessage-deflate,
 * and the client offers what the reporter's browser did.  The client sends
 * messages of several sizes, from less than one rx buffer to about 200KiB,
 * made of words from a small vocabulary so they deflate to a few times
 * smaller, like JSON or text.  The server checks each message against what
 * was sent as it arrives, and echoes it back; the client checks the echo
 * the same way.
 *
 * This is done on two connections: on the first, both ends deflate into
 * lws' default 1KiB frames, which a read rarely splits.  On the second,
 * both ends deflate into frames of up to 128KiB, as browsers send, so each
 * large message goes as one compressed frame that takes several reads.
 *
 * The test fails if
 *  - any message in either direction was not compressed (RSV1),
 *  - any message the server receives, or echo the client receives, is not
 *    exactly the one sent,
 *  - a connection fails, or
 *  - it doesn't all complete in time.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/* the largest, the size of the reporter's message */
#define MSG_MAX		206021

static const size_t sizes[] = {
	1, 1023, 1024, 1025, 4113, 65536, MSG_MAX
};

/* the pmd tx_buf_size, as a power of 2, each end uses on each connection */
static const char * const tx_pwr2[] = {
	NULL,	/* the default, 1KiB */
	"17",	/* 128KiB: needs a protocol rx_buffer_size at least as big */
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_next, sul_timeout;
static struct lws_vhost *vh_cli;
static const char *server_address = "localhost";
static int port = 7681, result = 1;
static size_t scenario;
static uint8_t msg[MSG_MAX];

/* one connection at a time: keep its buffers out of the pss / pcs */
static uint8_t srv_buf[LWS_PRE + MSG_MAX], cli_rx[MSG_MAX];

/* per-connection client state */
struct pcs {
	size_t		rx_len;
	size_t		sent;
	size_t		echoed;
	int		rsv;
};

/* per-connection server state */
struct pss {
	size_t		len;
	size_t		received;
	int		pending;
	int		rsv;
};

static void
fail(const char *why)
{
	lwsl_err("--- connection %d: %s ---\n", (int)scenario, why);
	lws_default_loop_exit(context);
}

/* deflate into frames as big as this connection's scenario says */

static int
set_tx_size(struct lws *wsi)
{
	if (!tx_pwr2[scenario])
		return 0;

	if (lws_set_extension_option(wsi, "permessage-deflate", "tx_buf_size",
				     tx_pwr2[scenario])) {
		fail("unable to set pmd tx_buf_size");
		return 1;
	}

	return 0;
}

/*
 * Copy one received piece of message number idx into buf at *pos, checking
 * it is the next part of the message sent
 */

static int
take(uint8_t *buf, size_t *pos, size_t idx, const void *in, size_t len)
{
	if (idx >= LWS_ARRAY_SIZE(sizes) || *pos + len > sizes[idx])
		return 1;

	/* an empty piece may come with no buffer at all */
	if (len) {
		memcpy(buf + *pos, in, len);
		if (memcmp(buf + *pos, msg + *pos, len))
			return 1;
	}
	*pos += len;

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	int n;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		if (set_tx_size(wsi))
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			pss->len = 0;
			pss->rsv = 0;
		}
		if (pss->pending ||
		    take(srv_buf + LWS_PRE, &pss->len, pss->received, in, len)) {
			fail("server received a message other than the one sent");
			return -1;
		}
		/* only the message's first frame has RSV1 */
		pss->rsv |= lws_get_reserved_bits(wsi);
		if (!lws_is_final_fragment(wsi))
			break;

		if (!(pss->rsv & 0x40)) {
			fail("client sent uncompressed");
			return -1;
		}
		if (pss->len != sizes[pss->received]) {
			lwsl_err("server: message %d: %d of %d bytes\n",
				 (int)pss->received, (int)pss->len,
				 (int)sizes[pss->received]);
			fail("server received a short message");
			return -1;
		}
		pss->received++;
		pss->pending = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->pending)
			break;
		n = lws_write(wsi, srv_buf + LWS_PRE, pss->len,
			      LWS_WRITE_TEXT);
		if (n < (int)pss->len) {
			fail("server write failed");
			return -1;
		}
		pss->pending = 0;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_connection(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= "/";
	i.host			= i.address;
	i.origin		= i.address;
	i.protocol		= "pmdd";
	i.local_protocol_name	= "pmdd";

	lwsl_user("connection %d: deflating into %d-byte frames\n",
		  (int)scenario,
		  1 << (tx_pwr2[scenario] ? atoi(tx_pwr2[scenario]) : 10));

	if (!lws_client_connect_via_info(&i))
		fail("client connect failed");
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pcs *pcs = (struct pcs *)user;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (set_tx_size(wsi))
			return -1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		uint8_t *buf;
		size_t n;

		/* one message at a time: the next once the last is echoed */
		if (pcs->sent != pcs->echoed ||
		    pcs->sent == LWS_ARRAY_SIZE(sizes))
			break;

		/* lws_write() may mask the payload in place: use a copy */
		n = sizes[pcs->sent];
		buf = malloc(LWS_PRE + n);
		if (!buf) {
			fail("OOM");
			return -1;
		}
		memcpy(buf + LWS_PRE, msg, n);
		if (lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_TEXT) < (int)n) {
			free(buf);
			fail("client write failed");
			return -1;
		}
		free(buf);
		pcs->sent++;
		break;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			pcs->rx_len = 0;
			pcs->rsv = 0;
		}
		if (take(cli_rx, &pcs->rx_len, pcs->echoed, in, len)) {
			fail("client received an echo other than the message");
			return -1;
		}
		pcs->rsv |= lws_get_reserved_bits(wsi);
		if (!lws_is_final_fragment(wsi))
			break;

		if (!(pcs->rsv & 0x40)) {
			fail("server sent uncompressed");
			return -1;
		}
		if (pcs->rx_len != sizes[pcs->echoed]) {
			lwsl_err("client: echo %d: %d of %d bytes\n",
				 (int)pcs->echoed, (int)pcs->rx_len,
				 (int)sizes[pcs->echoed]);
			fail("client received a short echo");
			return -1;
		}
		lwsl_user("%d bytes intact each way\n", (int)pcs->rx_len);

		if (++pcs->echoed < LWS_ARRAY_SIZE(sizes)) {
			lws_callback_on_writable(wsi);
			break;
		}

		if (++scenario == LWS_ARRAY_SIZE(tx_pwr2)) {
			lwsl_user("--- all messages intact ---\n");
			result = 0;
			lws_default_loop_exit(context);
		} else
			lws_sul_schedule(context, 0, &sul_next,
					 next_connection, 1);

		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		fail(in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		/* we close it ourselves once it's done; any other close fails */
		if (!pcs || pcs->echoed != LWS_ARRAY_SIZE(sizes))
			fail("connection closed early");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	fail("timed out");
}

/*
 * pmd caps its rx and tx buffers at the protocol's rx_buffer_size; the
 * reporter's server took up to 128KiB too
 */
static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "pmdd", callback_srv, sizeof(struct pss), 128 * 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "pmdd", callback_cli, sizeof(struct pcs), 128 * 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* the server takes whatever it is offered */
static const struct lws_extension extensions_srv[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate" },
	{ NULL, NULL, NULL }
};

static const struct lws_extension extensions_cli[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate; client_no_context_takeover; "
	  "client_max_window_bits" },
	{ NULL, NULL, NULL }
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const char * const words[] = {
		"{\"id\":", "\"name\":", "\"value\":", "\"items\":[", "],",
		"},", "true,", "false,", "null,", "12345,", "\"text\",",
		"\"websocket\",", "\"deflate\",", " ", "\n"
	};
	struct lws_context_creation_info info;
	uint32_t r = 0x12345678;
	size_t n = 0, w;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws permessage-deflate drain\n");

	/*
	 * Text-like: words picked by xorshift, the same each run, so it
	 * deflates a few times smaller but no two rx buffers of it inflate the
	 * same, and a lost one shows as a mismatch, not only as a short message
	 */
	while (n < MSG_MAX) {
		/* mask off what each shift would discard, so none is lost */
		r ^= (r & 0x0007ffffu) << 13;
		r ^= r >> 17;
		r ^= (r & 0x07ffffffu) << 5;
		p = words[r % LWS_ARRAY_SIZE(words)];
		w = strlen(p);
		if (w > MSG_MAX - n)
			w = MSG_MAX - n;
		memcpy(msg + n, p, w);
		n += w;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	info.extensions = extensions_srv;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.extensions = extensions_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_connection, 1);
	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
