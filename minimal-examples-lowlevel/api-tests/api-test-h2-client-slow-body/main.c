/*
 * lws-api-test-h2-client-slow-body
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h2 client connection carrying a response body must stay up for as long
 * as the context's timeout_secs allows between pieces of that body, not just
 * the vhost's keepalive_timeout, which is about how long a server will wait
 * on an idle client.  On a lossy link (eg, wifi with TCP retransmit backoff)
 * multi-second gaps inside a body are normal.
 *
 * The "server" is a raw tcp fixture speaking just enough h2 to answer the
 * client's request with a 200, a first DATA frame, and then, after a stall
 * longer than the client's keepalive_timeout but shorter than its
 * timeout_secs, the last DATA frame with END_STREAM.  It sends nothing at all
 * during the stall, so nothing renews the client's timeouts.
 *
 * The request must complete with the whole body.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SB_TIMEOUT_S		5	/* context timeout_secs */
#define SB_KEEPALIVE_S		1	/* client vhost keepalive_timeout */
#define SB_STALL_MS		3000	/* > keepalive, < timeout_secs */
#define SB_WATCHDOG_S		15

/* h2 frame types and flags the fixture deals in */
#define SB_H2_DATA		0
#define SB_H2_HEADERS		1
#define SB_H2_SETTINGS		4
#define SB_H2_PING		6
#define SB_H2F_ACK		1
#define SB_H2F_END_STREAM	1
#define SB_H2F_END_HEADERS	4
#define SB_H2_PREFACE_LEN	24

static const char body1[] = "the first part of the body, ",
		  body2[] = "and the part after the stall";

/* one fixture connection */
struct fx_pss {
	struct lws		*wsi;
	lws_sorted_usec_list_t	sul_stall;
	uint8_t			rx[1024];
	uint8_t			tx[LWS_PRE + 512];
	size_t			rxlen;
	size_t			txlen;
	uint32_t		sid;
	uint8_t			preface_done;
	uint8_t			answered;
};

static struct {
	int		status;
	size_t		rx;
	lws_usec_t	first_rx;
	lws_usec_t	last_rx;
	uint8_t		error;
	uint8_t		completed;
} cli;

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static int result = 1, port = 7681, done;
static const char *server_addr = "127.0.0.1";

static void
finish(int fail)
{
	if (done)
		return;
	done = 1;
	result = fail;
	lws_sul_cancel(&sul_watchdog);
	lws_default_loop_exit(context);
}

/*
 * the fixture
 */

static void
fx_tx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	    const void *pl, size_t len)
{
	size_t room = sizeof(p->tx) - LWS_PRE;
	uint8_t *h;

	if (len > room - 9 || p->txlen > room - 9 - len) {
		lwsl_err("%s: fixture tx overflow\n", __func__);
		return;
	}

	h = p->tx + LWS_PRE + p->txlen;

	h[0] = (uint8_t)(len >> 16);
	h[1] = (uint8_t)(len >> 8);
	h[2] = (uint8_t)len;
	h[3] = type;
	h[4] = flags;
	lws_ser_wu32be(&h[5], sid);
	if (len)
		memcpy(h + 9, pl, len);
	p->txlen += 9 + len;

	lws_callback_on_writable(p->wsi);
}

static void
fx_stall_cb(lws_sorted_usec_list_t *sul)
{
	struct fx_pss *p = lws_container_of(sul, struct fx_pss, sul_stall);

	lwsl_user("%s: fixture: stall over, sending the rest\n", __func__);
	fx_tx_frame(p, SB_H2_DATA, SB_H2F_END_STREAM, p->sid, body2,
		    sizeof(body2) - 1);
}

/* a whole frame from the client */
static void
fx_frame(struct fx_pss *p, uint8_t type, uint8_t flags, uint32_t sid,
	 const uint8_t *pl, size_t len)
{
	uint8_t st200 = 0x88; /* hpack: indexed :status 200 */

	switch (type) {
	case SB_H2_SETTINGS:
		if (!(flags & SB_H2F_ACK))
			fx_tx_frame(p, SB_H2_SETTINGS, SB_H2F_ACK, 0, NULL, 0);
		break;

	case SB_H2_PING:
		if (!(flags & SB_H2F_ACK) && len == 8)
			fx_tx_frame(p, SB_H2_PING, SB_H2F_ACK, 0, pl, len);
		break;

	case SB_H2_HEADERS:
		if (p->answered)
			break;
		p->answered = 1;
		p->sid = sid;
		lwsl_user("%s: fixture: answering sid %u, then stalling %dms\n",
			  __func__, (unsigned int)sid, SB_STALL_MS);
		fx_tx_frame(p, SB_H2_HEADERS, SB_H2F_END_HEADERS, sid,
			    &st200, 1);
		fx_tx_frame(p, SB_H2_DATA, 0, sid, body1, sizeof(body1) - 1);
		lws_sul_schedule(context, 0, &p->sul_stall, fx_stall_cb,
				 SB_STALL_MS * LWS_US_PER_MS);
		break;

	default:
		break;
	}
}

static int
fx_rx(struct fx_pss *p, const uint8_t *in, size_t len)
{
	if (p->rxlen + len > sizeof(p->rx)) {
		lwsl_err("%s: fixture rx overflow\n", __func__);
		return -1;
	}
	memcpy(p->rx + p->rxlen, in, len);
	p->rxlen += len;

	if (!p->preface_done) {
		if (p->rxlen < SB_H2_PREFACE_LEN)
			return 0;
		if (memcmp(p->rx, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
			   SB_H2_PREFACE_LEN)) {
			lwsl_err("%s: fixture: not an h2 preface\n", __func__);
			return -1;
		}
		p->rxlen -= SB_H2_PREFACE_LEN;
		memmove(p->rx, p->rx + SB_H2_PREFACE_LEN, p->rxlen);
		p->preface_done = 1;
	}

	while (p->rxlen >= 9) {
		size_t fl = ((size_t)p->rx[0] << 16) |
			    ((size_t)p->rx[1] << 8) | p->rx[2], o, rest;

		if (fl > sizeof(p->rx) - 9) {
			lwsl_err("%s: fixture: frame too big\n", __func__);
			return -1;
		}
		if (p->rxlen < 9 + fl)
			break;

		fx_frame(p, p->rx[3], p->rx[4],
			 lws_ser_ru32be(&p->rx[5]) & 0x7fffffff,
			 p->rx + 9, fl);

		/*
		 * what follows the frame, bounded itself before it's moved,
		 * from where it starts inside the buffer: a frame filling the
		 * buffer leaves o one past its end, with nothing to move
		 */
		o = 9 + fl;
		rest = p->rxlen - o;
		if (rest) {
			if (o >= sizeof(p->rx) || rest > sizeof(p->rx) - o) {
				lwsl_err("%s: fixture: rx accounting\n",
					 __func__);
				return -1;
			}
			memmove(p->rx, p->rx + o, rest);
		}
		p->rxlen = rest;
	}

	return 0;
}

static int
callback_fx(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct fx_pss *p = (struct fx_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		p->wsi = wsi;
		/* the server preface: an empty SETTINGS */
		fx_tx_frame(p, SB_H2_SETTINGS, 0, 0, NULL, 0);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (fx_rx(p, (const uint8_t *)in, len))
			return -1;
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!p->txlen)
			break;
		if (lws_write(wsi, p->tx + LWS_PRE, p->txlen,
			      LWS_WRITE_RAW) != (int)p->txlen) {
			lwsl_err("%s: fixture write failed\n", __func__);
			return -1;
		}
		p->txlen = 0;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lws_sul_cancel(&p->sul_stall);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * the client
 */

static void
evaluate(void)
{
	int fail = 0;

	if (cli.error) {
		lwsl_err("%s: request failed after %u of %u body bytes\n",
			 __func__, (unsigned int)cli.rx,
			 (unsigned int)(sizeof(body1) + sizeof(body2) - 2));
		fail = 1;
	} else {
		if (cli.status != 200) {
			lwsl_err("%s: status %d\n", __func__, cli.status);
			fail = 1;
		}
		if (cli.rx != sizeof(body1) + sizeof(body2) - 2) {
			lwsl_err("%s: got %u body bytes\n", __func__,
				 (unsigned int)cli.rx);
			fail = 1;
		}
		/* the stall must really have been inside the body */
		if (cli.last_rx - cli.first_rx <
				(SB_STALL_MS * LWS_US_PER_MS * 9) / 10) {
			lwsl_err("%s: body arrived without the stall\n",
				 __func__);
			fail = 1;
		}
	}

	lwsl_user("%s: %s: a %dms stall inside an h2 body, keepalive_timeout "
		  "%ds, timeout_secs %ds\n", __func__, fail ? "FAIL" : "PASS",
		  SB_STALL_MS, SB_KEEPALIVE_S, SB_TIMEOUT_S);

	finish(fail);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: no outcome: status %d, %u body bytes\n", __func__,
		 cli.status, (unsigned int)cli.rx);
	finish(1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	char rbuf[LWS_PRE + 256], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli.error = 1;
		evaluate();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: status %d\n", __func__, cli.status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!cli.rx)
			cli.first_rx = lws_now_usecs();
		cli.last_rx = lws_now_usecs();
		cli.rx += len;
		lwsl_user("%s: %u body bytes\n", __func__, (unsigned int)len);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("%s: completed\n", __func__);
		cli.completed = 1;
		evaluate();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* closed without completing is a failure */
		if (!cli.completed && !done) {
			lwsl_user("%s: closed before completion\n", __func__);
			cli.error = 1;
			evaluate();
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "fake-h2", callback_fx, sizeof(struct fx_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h2-slow-body", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh_cli;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;
	info.timeout_secs = SB_TIMEOUT_S;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 client body with a stall inside it\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the raw fixture "server" */

	info.port = port;
	info.vhost_name = "fx";
	info.protocols = protocols_srv;
	info.options |= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "fake-h2";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create fixture vhost\n");
		goto bail;
	}

	/* client vhost, no listener, with a short keepalive_timeout */

	info.options &= ~(uint64_t)
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.keepalive_timeout = SB_KEEPALIVE_S;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 SB_WATCHDOG_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = port;
	i.path = "/";
	i.method = "GET";
	i.protocol = "h2-slow-body";
	i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		goto bail;
	}

	while (!lws_service(context, 0))
		;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
