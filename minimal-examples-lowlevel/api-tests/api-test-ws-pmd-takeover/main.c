/*
 * lws-api-test-ws-pmd-takeover
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests permessage-deflate context takeover (RFC 7692 7.1.1) in both
 * directions, for each way a client can negotiate it.
 *
 * RFC 7692 names the parameters after the endpoint whose compressor they
 * constrain: server_no_context_takeover says the server resets its deflate
 * context after each message, so only the client may reset its inflate
 * context; client_no_context_takeover the other way around.  Each endpoint
 * must pick the peer's parameter for its inflater and its own for its
 * deflater, according to its role.
 *
 * A ws server and client run in one process, both with permessage-deflate.
 * For each offer, the client sends the same message several times and the
 * server echoes each one back.  The message is noise that does not compress
 * by itself, so wherever an endpoint keeps its deflate context, every
 * message after the first is sent as back-references into the one before.
 * An inflater that dropped its context when the peer kept its deflate
 * context cannot resolve those and fails the connection; a deflater that
 * kept its context after agreeing not to fails the peer's inflater the
 * same way, if the peer relies on it.  lws does rely on it: it drops its
 * inflate context whenever the peer agreed not to take it over.
 *
 * Each connection ends with an empty message each way.  Straight after a
 * whole message, zlib refuses to sync flush again with nothing new, and the
 * sender must still produce a valid empty compressed message.
 *
 * The test fails if
 *  - the offer does not reach the server as sent,
 *  - any message in either direction was not compressed (RSV1),
 *  - any echo differs from what was sent, or the connection fails, or
 *  - it doesn't all complete in time.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define MSG_LEN		2048
#define MSG_COUNT	4
/* ...and then one empty message */
#define MSG_TOTAL	(MSG_COUNT + 1)

/* what the client offers on each connection, in turn */
static const char * const offers[] = {
	"permessage-deflate",
	"permessage-deflate; server_no_context_takeover",
	"permessage-deflate; client_no_context_takeover",
	("permessage-deflate; server_no_context_takeover; "
		"client_no_context_takeover"),
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[LWS_ARRAY_SIZE(offers)];
static lws_sorted_usec_list_t sul_next, sul_timeout;
static const char *server_address = "localhost";
static int port = 7681, result = 1;
static size_t scenario;
static uint8_t msg[MSG_LEN];

/* per-connection client state */
struct pcs {
	uint8_t		rx[MSG_LEN];
	size_t		rx_len;
	int		sent;
	int		echoed;
	int		rsv;
};

/* per-connection server state */
struct pss {
	uint8_t		buf[LWS_PRE + MSG_LEN];
	size_t		len;
	int		pending;
	int		rsv;
};

static void
fail(const char *why)
{
	lwsl_err("--- offer %d \"%s\": %s ---\n", (int)scenario,
		 offers[scenario], why);
	lws_default_loop_exit(context);
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	char buf[256];
	int n;

	switch (reason) {
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		/* it has to be negotiating what we think it is */
		if (lws_hdr_copy(wsi, buf, sizeof(buf),
				 WSI_TOKEN_EXTENSIONS) <= 0 ||
		    strcmp(buf, offers[scenario])) {
			fail("offer not seen by server");
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			pss->len = 0;
			pss->rsv = 0;
		}
		if (pss->pending || pss->len + len > MSG_LEN) {
			fail("server rx overflow");
			return -1;
		}
		memcpy(pss->buf + LWS_PRE + pss->len, in, len);
		pss->len += len;
		/*
		 * the rsv bits are the frame's we are in, and only the
		 * message's first frame has RSV1: see if we were in it
		 */
		pss->rsv |= lws_get_reserved_bits(wsi);
		if (lws_is_final_fragment(wsi)) {
			if (!(pss->rsv & 0x40)) {
				fail("client sent uncompressed");
				return -1;
			}
			pss->pending = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->pending)
			break;
		n = lws_write(wsi, pss->buf + LWS_PRE, pss->len,
			      LWS_WRITE_BINARY);
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
	i.vhost			= vh_cli[scenario];
	i.address		= server_address;
	i.port			= port;
	i.path			= "/";
	i.host			= i.address;
	i.origin		= i.address;
	i.protocol		= "pmdt";
	i.local_protocol_name	= "pmdt";

	lwsl_user("offer %d: \"%s\"\n", (int)scenario, offers[scenario]);

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
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		uint8_t buf[LWS_PRE + MSG_LEN];

		size_t n = pcs->sent < MSG_COUNT ? MSG_LEN : 0;

		/* one message at a time: the next once the last is echoed */
		if (pcs->sent != pcs->echoed || pcs->sent == MSG_TOTAL)
			break;

		memcpy(buf + LWS_PRE, msg, n);
		if (lws_write(wsi, buf + LWS_PRE, n,
			      LWS_WRITE_BINARY) < (int)n) {
			fail("client write failed");
			return -1;
		}
		pcs->sent++;
		break;
	}

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			pcs->rx_len = 0;
			pcs->rsv = 0;
		}
		if (pcs->rx_len + len > MSG_LEN) {
			fail("client rx overflow");
			return -1;
		}
		memcpy(pcs->rx + pcs->rx_len, in, len);
		pcs->rx_len += len;
		pcs->rsv |= lws_get_reserved_bits(wsi);
		if (!lws_is_final_fragment(wsi))
			break;

		if (!(pcs->rsv & 0x40)) {
			fail("server sent uncompressed");
			return -1;
		}

		if (pcs->rx_len != (pcs->echoed < MSG_COUNT ? MSG_LEN : 0) ||
		    memcmp(pcs->rx, msg, pcs->rx_len)) {
			fail("echo differs");
			return -1;
		}
		if (++pcs->echoed < MSG_TOTAL) {
			lws_callback_on_writable(wsi);
			break;
		}

		lwsl_user("offer %d: %d messages and an empty one each way "
			  "intact\n", (int)scenario, MSG_COUNT);
		if (++scenario == LWS_ARRAY_SIZE(offers)) {
			lwsl_user("--- all offers passed ---\n");
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
		if (!pcs || pcs->echoed != MSG_TOTAL)
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

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	{ "pmdt", callback_srv, sizeof(struct pss), 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "pmdt", callback_cli, sizeof(struct pcs), 1024, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* the server takes whatever it is offered */
static const struct lws_extension extensions_srv[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate" },
	{ NULL, NULL, NULL }
};

/* each client vhost offers one of offers[] */
static struct lws_extension extensions_cli[LWS_ARRAY_SIZE(offers)][2];
static char vh_names[LWS_ARRAY_SIZE(offers)][8];

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	uint32_t r = 0x12345678;
	const char *p;
	size_t n;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws permessage-deflate context takeover\n");

	/* noise: deflate can only shrink it by referring to an earlier copy */
	for (n = 0; n < MSG_LEN; n++) {
		r = r * 1103515245u + 12345u;
		msg[n] = (uint8_t)(r >> 16);
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
	info.protocols = protocols_cli;
	for (n = 0; n < LWS_ARRAY_SIZE(offers); n++) {
		extensions_cli[n][0].name = "permessage-deflate";
		extensions_cli[n][0].callback = lws_extension_callback_pm_deflate;
		extensions_cli[n][0].client_offer = offers[n];
		lws_snprintf(vh_names[n], sizeof(vh_names[n]), "cli%d", (int)n);
		info.vhost_name = vh_names[n];
		info.extensions = extensions_cli[n];
		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create client vhost\n");
			goto bail;
		}
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
