/*
 * lws-api-test-keep-warm
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An lws client and an lws server in one process confirm that a client
 * connection is kept warm after its request completes, and that a request
 * to the same origin inside the keep-warm time rides it while one after the
 * keep-warm time finds it gone and opens a new connection.
 *
 * The same shapes are run over every http transport the build has: h1
 * keepalive (cleartext and over tls), h2 (cleartext with prior knowledge and
 * over tls by alpn) and h3, both on a vhost that only listens for quic and
 * on the udp listener a tls vhost opens beside its tcp one.  For h1 the
 * kept-warm connection is handed from the idle wsi to the new one; for h2
 * and h3 the shared connection is kept warm after its last stream closed
 * and the new request joins it as a new stream.  Each request is checked to
 * have gone over the transport its case is about (a stream on a shared
 * connection or not, over udp or not), so a client that was quietly taken
 * to another protocol, eg, by a learned alt-svc, cannot pass as the one it
 * was asked for.
 *
 * The server stamps every network connection with an ordinal when it serves
 * its first request and answers each request with "conn=<ordinal>", so the
 * client can see from the response which server connection served it,
 * whatever the transport.  On top of that the client counts the connection
 * attempts it made (LWS_CALLBACK_CONNECTING), checks the link the request
 * used is the one before (the same socket for h1, the same network wsi for
 * h2 / h3), and the server counts the connections it saw and the connections
 * that went away: a case is over only when every connection it opened has
 * closed, which is the kept-warm connection idling out in good order, and
 * means no case can ride a connection an earlier case left warm.
 *
 * Shapes, per transport:
 *
 *  - a second request inside the keep-warm time rides the connection
 *  - a second request after the keep-warm time opens a new connection
 *  - three requests each inside the keep-warm time all ride one connection
 *    (the keep-warm rearms after a ride)
 *  - a second request rides, a third after the keep-warm time opens a new
 *    connection (the keep-warm timeout rearms after a ride)
 *  - a request answered 302 to the same origin, followed by the same wsi:
 *    an h1 wsi's connection is its own and is torn down with the
 *    retargeting, so the follow-up opens a new one; an h2 / h3 stream's
 *    connection is kept warm when the stream closes, so the follow-up
 *    should ride it
 *
 * and for cleartext h1, a request without LCCSCF_PIPELINE: the client sends
 * connection: close, the server closes after answering, and a second
 * request inside the keep-warm time necessarily opens a new connection.
 *
 * The test fails if any case does not complete as expected inside the
 * watchdog period.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#if !defined(WIN32) && !defined(_WIN32)
#include <sys/socket.h>
#endif

#define CASE_TIMEOUT_S	30
#define KEEP_WARM_S	1
#define INSIDE_MS	200	/* well inside KEEP_WARM_S */
#define OUTSIDE_MS	2000	/* well outside it */
#define MAX_REQ		3

enum xport {
	XP_H1,		/* cleartext h1 keepalive */
	XP_H1_TLS,	/* h1 over tls, alpn http/1.1 */
	XP_H2C,		/* cleartext h2, prior knowledge */
	XP_H2_TLS,	/* h2 over tls, alpn h2 */
	XP_H3,		/* h3 over quic, on the h3 vhost */
	XP_H3_ALT,	/* h3 over quic on the tls vhost's own port, the
			 * udp listener a tls vhost opens beside its tcp one
			 * and advertises by alt-svc */
};

#define XP_IS_MUX(xp) ((xp) != XP_H1 && (xp) != XP_H1_TLS)
#define XP_IS_QUIC(xp) ((xp) == XP_H3 || (xp) == XP_H3_ALT)

struct xcase {
	const char	*name;
	uint8_t		xport;
	uint8_t		nreq;
	uint16_t	delay_ms[MAX_REQ]; /* before request n, counted from
					    * request n - 1 completing */
	uint8_t		rides[MAX_REQ];	/* 1: request n must be served by the
					 * connection that served n - 1 */
	uint8_t		no_pipeline;	/* h1 without LCCSCF_PIPELINE */
	uint8_t		redirect;	/* ask /redir, answered 302 -> /hello */
	uint8_t		made;		/* connections the client must open */
};

/*
 * The five shapes each transport gets.  The 302 case's follow-up rides the
 * kept-warm h2 / h3 connection but has to open a new one on h1, where the
 * wsi's connection was its own.
 */
#define KW_SHAPES(xp, pfx, made_redir) \
	{ pfx ": second request inside the keep-warm time rides the connection", \
	  xp, 2, { 0, INSIDE_MS }, { 0, 1 }, 0, 0, 1 }, \
	{ pfx ": second request after the keep-warm time opens a new connection", \
	  xp, 2, { 0, OUTSIDE_MS }, { 0, 0 }, 0, 0, 2 }, \
	{ pfx ": three requests inside the keep-warm time all ride one connection", \
	  xp, 3, { 0, INSIDE_MS, INSIDE_MS }, { 0, 1, 1 }, 0, 0, 1 }, \
	{ pfx ": second request rides, third after the keep-warm time opens a new one", \
	  xp, 3, { 0, INSIDE_MS, OUTSIDE_MS }, { 0, 1, 0 }, 0, 0, 2 }, \
	{ pfx ": 302 to the same origin, followed on the same wsi", \
	  xp, 1, { 0 }, { 0 }, 0, 1, made_redir }

static const struct xcase cases[] = {
	KW_SHAPES(XP_H1, "h1", 2),
	{ "h1: without LCCSCF_PIPELINE the second request opens a new connection",
	  XP_H1, 2, { 0, INSIDE_MS }, { 0, 0 }, 1, 0, 2 },
#if defined(LWS_WITH_TLS)
	KW_SHAPES(XP_H1_TLS, "h1 tls", 2),
#endif
#if defined(LWS_WITH_HTTP2)
	KW_SHAPES(XP_H2C, "h2c", 1),
#if defined(LWS_WITH_TLS)
	KW_SHAPES(XP_H2_TLS, "h2 tls", 1),
#endif
#endif
#if defined(LWS_ROLE_H3)
	KW_SHAPES(XP_H3, "h3", 1),
	KW_SHAPES(XP_H3_ALT, "h3 on the tls vhost port", 1),
#endif
};

/* one request of the case, as the client saw it */

struct req {
	int		status;
	int		established;	/* ESTABLISHED_CLIENT_HTTP count */
	int		completed;
	int		closed;
	int		error;
	int		srv_conn;	/* the server connection ordinal from
					 * the response body, 0 if none */
	struct lws	*nwsi;		/* the network wsi it was served over */
	lws_sockfd_type	fd;		/* ... and its socket */
	int		mux;		/* it was a stream on a shared connection */
	int		dgram;		/* ... whose socket is udp */
	char		body[64];
	size_t		body_len;
};

/* per server connection... h1 keeps it across keepalive transactions */

struct pss_srv {
	uint8_t		resp[LWS_PRE + 32]; /* the body after LWS_PRE headroom */
	size_t		resp_len;
};

/* the server's view */

static struct {
	int		accepted;	/* connections that arrived */
	int		destroyed;	/* stamped connections that went away */
	int		requests;	/* LWS_CALLBACK_HTTP count */
	int		next_id;	/* last connection ordinal handed out */
} srv;

/* the client's view */

static struct {
	int		made;		/* LWS_CALLBACK_CONNECTING count */
	int		started;	/* requests issued so far */
} cli;

static struct req reqs[MAX_REQ];

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_req, sul_poll;
static int result, cur = -1, failures, only_case = -1, last_case = -1,
	   case_done,
	   port_h1 = 7681, port_tls = 7682, port_h2c = 7683, port_h3 = 7684;
static const char *server_addr = "127.0.0.1";

#if defined(LWS_ROLE_H3)
static struct lws_vhost *vh_h3;
#endif

#if defined(LWS_WITH_TLS)
/* the tls vhosts: a self-signed test cert does for the client's alpn */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";
#endif

/* the server */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t hbuf[LWS_PRE + 256], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];
	const char *path = (const char *)in;
	struct lws *nwsi;
	int id;

	switch (reason) {

	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		/* a tcp connection accepted, h1 or h2 */
		srv.accepted++;
		break;

#if defined(LWS_ROLE_H3)
	case LWS_CALLBACK_WSI_CREATE:
		/*
		 * A quic connection is not accepted, so is not seen by
		 * FILTER_NETWORK_CONNECTION: count it by the connection wsi
		 * the quic listener creates for it, tagged "quic child"
		 */
		if (lws_wsi_tag(wsi) && strstr(lws_wsi_tag(wsi), "quic child")) {
			srv.accepted++;
			lwsl_wsi_info(wsi, "quic connection %d", srv.accepted);
		}
		break;
#endif

	case LWS_CALLBACK_WSI_DESTROY:
		/*
		 * The network connection of a stamped connection going away.
		 * A mux stream's network wsi is its parent, so streams are
		 * not counted; listeners are never stamped
		 */
		if (lws_get_network_wsi(wsi) == wsi &&
		    lws_get_opaque_user_data(wsi)) {
			srv.destroyed++;
			lwsl_wsi_info(wsi, "server connection %d gone (%d of %d)",
				      (int)(intptr_t)lws_get_opaque_user_data(wsi),
				      srv.destroyed, srv.accepted);
		}
		break;

	case LWS_CALLBACK_HTTP:
		srv.requests++;

		/*
		 * Stamp the network connection with an ordinal the first
		 * time it brings us a request: for h1 that is the connection
		 * wsi itself, for h2 / h3 the parent of the stream
		 */
		nwsi = lws_get_network_wsi(wsi);
		if (!lws_get_opaque_user_data(nwsi))
			lws_set_opaque_user_data(nwsi,
					(void *)(intptr_t)++srv.next_id);
		id = (int)(intptr_t)lws_get_opaque_user_data(nwsi);

		lwsl_user("%s: server: HTTP %s on connection %d\n", __func__,
			  path ? path : "", id);

		if (path && !strcmp(path, "/redir")) {
			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (const unsigned char *)"/hello",
					      6, &p, end) < 0 ||
			    lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}

		pss->resp_len = (size_t)lws_snprintf((char *)&pss->resp[LWS_PRE],
						     sizeof(pss->resp) - LWS_PRE,
						     "conn=%d\n", id);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain",
						(lws_filepos_t)pss->resp_len,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->resp_len)
			break;
		if (lws_write(wsi, &pss->resp[LWS_PRE], pss->resp_len,
			      LWS_WRITE_HTTP_FINAL) != (int)pss->resp_len)
			return -1;
		pss->resp_len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the client */

static void
case_finish(int ok, const char *why)
{
	lwsl_user("--- case %d: %s: %s%s%s ---\n", cur, cases[cur].name,
		  ok ? "PASS" : "FAIL", why ? ": " : "", why ? why : "");
	if (!ok)
		failures++;
	case_done = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_req);
	lws_sul_cancel(&sul_poll);
}

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_evaluate(void)
{
	const struct xcase *c = &cases[cur];
	char why[128];
	int n;

	for (n = 0; n < c->nreq; n++) {
		struct req *r = &reqs[n];

		if (r->error || !r->completed || r->status != 200) {
			lws_snprintf(why, sizeof(why), "request %d: error %d, "
				     "completed %d, status %d", n, r->error,
				     r->completed, r->status);
			goto fail;
		}
		if (r->srv_conn <= 0) {
			lws_snprintf(why, sizeof(why), "request %d: no server "
				     "connection ordinal in the response", n);
			goto fail;
		}
		/* it went over the transport the case is about */
		if (r->mux != XP_IS_MUX(c->xport)) {
			lws_snprintf(why, sizeof(why), "request %d: %s a stream "
				     "on a shared connection", n,
				     r->mux ? "was" : "was not");
			goto fail;
		}
#if !defined(WIN32) && !defined(_WIN32)
		if (r->dgram != XP_IS_QUIC(c->xport)) {
			lws_snprintf(why, sizeof(why), "request %d: %s over udp",
				     n, r->dgram ? "went" : "did not go");
			goto fail;
		}
#endif
		if (!n)
			continue;

		if (c->rides[n]) {
			if (r->srv_conn != reqs[n - 1].srv_conn) {
				lws_snprintf(why, sizeof(why), "request %d "
					     "served by connection %d, expected "
					     "to ride %d", n, r->srv_conn,
					     reqs[n - 1].srv_conn);
				goto fail;
			}
			if (XP_IS_MUX(c->xport) && r->nwsi != reqs[n - 1].nwsi) {
				lws_snprintf(why, sizeof(why), "request %d rode "
					     "the server connection but on a "
					     "different network wsi", n);
				goto fail;
			}
			if (!XP_IS_MUX(c->xport) && r->fd != reqs[n - 1].fd) {
				lws_snprintf(why, sizeof(why), "request %d rode "
					     "the server connection but on a "
					     "different socket", n);
				goto fail;
			}
		} else
			if (r->srv_conn == reqs[n - 1].srv_conn) {
				lws_snprintf(why, sizeof(why), "request %d "
					     "rode connection %d, expected a "
					     "new one", n, r->srv_conn);
				goto fail;
			}
	}

	if (cli.made != c->made) {
		lws_snprintf(why, sizeof(why), "client made %d connections, "
			     "expected %d", cli.made, c->made);
		goto fail;
	}
	if (srv.accepted != c->made) {
		lws_snprintf(why, sizeof(why), "server saw %d connections, "
			     "expected %d", srv.accepted, c->made);
		goto fail;
	}
	if (srv.destroyed != srv.accepted) {
		lws_snprintf(why, sizeof(why), "%d of %d server connections "
			     "closed", srv.destroyed, srv.accepted);
		goto fail;
	}
	if (srv.requests != c->nreq + c->redirect) {
		lws_snprintf(why, sizeof(why), "server saw %d requests, "
			     "expected %d", srv.requests, c->nreq + c->redirect);
		goto fail;
	}

	case_finish(1, NULL);
	goto next;

fail:
	case_finish(0, why);

next:
	lws_sul_schedule(context, 0, &sul_next, next_case, 100 * LWS_US_PER_MS);
}

/*
 * After the last request completed: the case is over when every connection
 * the server saw has gone, ie, the kept-warm connection has idled out and
 * closed in good order
 */

static void
poll_cb(lws_sorted_usec_list_t *sul)
{
	const struct xcase *c = &cases[cur];
	int n;

	for (n = 0; n < c->nreq; n++)
		if (reqs[n].error) {
			case_evaluate();
			return;
		}

	if (srv.accepted && srv.destroyed == srv.accepted) {
		case_evaluate();
		return;
	}

	lws_sul_schedule(context, 0, &sul_poll, poll_cb, 50 * LWS_US_PER_MS);
}

static int
req_start(int n);

static void
req_cb(lws_sorted_usec_list_t *sul)
{
	if (req_start(cli.started))
		case_evaluate();
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct req *r = (struct req *)lws_get_opaque_user_data(wsi);
	char rbuf[LWS_PRE + 256], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n;

	if (!r)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	n = (int)(r - &reqs[0]);

	switch (reason) {

	case LWS_CALLBACK_CONNECTING:
		cli.made++;
		lwsl_wsi_user(wsi, "client: request %d connecting (%d so far)",
			      n, cli.made);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: request %d connection error: %s\n",
			  __func__, n, in ? (const char *)in : "(null)");
		r->error = 1;
		/* the poll sees the error and ends the case */
		if (!case_done)
			lws_sul_schedule(context, 0, &sul_poll, poll_cb,
					 50 * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/*
		 * A request that joins a kept-warm h2 / h3 connection is told
		 * ESTABLISHED at the join, before it sent anything, with no
		 * status: the response headers bring a second one.  Only the
		 * one carrying a status is the response
		 */
		r->established++;
		if (!lws_http_client_http_response(wsi)) {
			lwsl_wsi_user(wsi, "client: request %d joined a warm "
				      "connection", n);
			break;
		}
		r->status = (int)lws_http_client_http_response(wsi);
		r->nwsi = lws_get_network_wsi(wsi);
		r->fd = lws_get_socket_fd(r->nwsi);
		r->mux = r->nwsi != wsi;
#if !defined(WIN32) && !defined(_WIN32)
		{
			int st = 0;
			socklen_t sl = sizeof(st);

			if (!getsockopt(r->fd, SOL_SOCKET, SO_TYPE, &st, &sl))
				r->dgram = st == SOCK_DGRAM;
		}
#endif
		lwsl_wsi_user(wsi, "client: request %d status %d", n, r->status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (r->body_len + len < sizeof(r->body) - 1) {
			memcpy(r->body + r->body_len, in, len);
			r->body_len += len;
			r->body[r->body_len] = '\0';
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (r->completed)
			break;
		r->completed = 1;
		if (!strncmp(r->body, "conn=", 5))
			r->srv_conn = atoi(r->body + 5);
		lwsl_wsi_user(wsi, "client: request %d completed, status %d, "
			      "served by server connection %d", n, r->status,
			      r->srv_conn);

		if (case_done)
			break;

		if (cli.started < cases[cur].nreq)
			lws_sul_schedule(context, 0, &sul_req, req_cb,
				 cases[cur].delay_ms[cli.started] *
							LWS_US_PER_MS);
		else
			lws_sul_schedule(context, 0, &sul_poll, poll_cb,
					 50 * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		r->closed = 1;
		lwsl_wsi_user(wsi, "client: request %d closed", n);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
req_start(int n)
{
	const struct xcase *c = &cases[cur];
	struct lws_client_connect_info i;
	struct req *r = &reqs[n];

	memset(r, 0, sizeof(*r));
	cli.started = n + 1;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.path = c->redirect ? "/redir" : "/hello";
	i.method = "GET";
	i.protocol = "keep-warm";
	i.opaque_user_data = r;
	i.keep_warm_secs = KEEP_WARM_S;
	if (!c->no_pipeline)
		i.ssl_connection = LCCSCF_PIPELINE;

	switch (c->xport) {
	case XP_H1:
		i.port = port_h1;
		break;
#if defined(LWS_WITH_TLS)
	case XP_H1_TLS:
		i.port = port_tls;
		i.alpn = "http/1.1";
		i.ssl_connection |= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
#if defined(LWS_WITH_HTTP2)
	case XP_H2C:
		i.port = port_h2c;
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
		break;
#if defined(LWS_WITH_TLS)
	case XP_H2_TLS:
		i.port = port_tls;
		i.alpn = "h2";
		i.ssl_connection |= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
#endif
#if defined(LWS_ROLE_H3)
	case XP_H3:
	case XP_H3_ALT:
		i.port = c->xport == XP_H3 ? port_h3 : port_tls;
		i.alpn = "h3";
		i.ssl_connection |= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				    LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
		break;
#endif
	default:
		lwsl_err("%s: transport not in this build\n", __func__);
		return 1;
	}

	lwsl_user("%s: client: request %d starting\n", __func__, n);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		r->error = 1;
		return 1;
	}

	return 0;
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("watchdog: client made %d, server saw %d, %d gone, %d "
		 "requests\n", cli.made, srv.accepted, srv.destroyed,
		 srv.requests);
	case_finish(0, "watchdog: case did not complete");
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	/* --case n, or --case n-m: only those */
	if (only_case >= 0 && cur >= last_case)
		cur = (int)LWS_ARRAY_SIZE(cases) - 1;
	cur++;
	if (only_case >= 0 && cur < only_case)
		cur = only_case;

	if (cur == (int)LWS_ARRAY_SIZE(cases)) {
		result = failures ? 1 : 0;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== case %d: %s ===\n", cur, cases[cur].name);

	memset(&srv, 0, sizeof(srv));
	memset(&cli, 0, sizeof(cli));
	memset(reqs, 0, sizeof(reqs));
	case_done = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CASE_TIMEOUT_S * LWS_US_PER_SEC);

	if (req_start(0))
		case_evaluate();
}

static const struct lws_protocols protocols_srv[] = {
	{ "keep-warm", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "keep-warm", callback_cli, 0, 0, 0, NULL, 0 },
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
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/*
	 * The defaults budget 8 fds per thread, sized for a lone client: we
	 * have up to four listeners (v4 + v6) and both ends of every
	 * connection.  Past the budget lws stops servicing the listeners.
	 */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tls-port")))
		port_tls = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2c-port")))
		port_h2c = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h3-port")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--case"))) {
		only_case = atoi(p);
		last_case = only_case;
		if (strchr(p, '-'))
			last_case = atoi(strchr(p, '-') + 1);
		if (only_case < 0 || last_case < only_case ||
		    last_case >= (int)LWS_ARRAY_SIZE(cases)) {
			lwsl_err("--case: %d cases, 0 - %d\n",
				 (int)LWS_ARRAY_SIZE(cases),
				 (int)LWS_ARRAY_SIZE(cases) - 1);
			return 1;
		}
	}

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: kept-warm client connections\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
#if defined(LWS_WITH_TLS)
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* h1 server vhost, cleartext */

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	/* h2 server vhost, cleartext with prior knowledge */

	info.port = port_h2c;
	info.vhost_name = "srv-h2c";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h2c server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

#if defined(LWS_WITH_TLS)
	/*
	 * tls server vhost: the client's alpn picks h1 or h2 on it.  The
	 * vhost's default alpn offers h2 when the build has it
	 */

	info.port = port_tls;
	info.vhost_name = "srv-tls";
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create tls server vhost\n");
		goto bail;
	}

#if defined(LWS_ROLE_H3)
	/* h3 server vhost: a quic listener on udp, tls with the test cert */

	info.port = CONTEXT_PORT_NO_LISTEN_SERVER;
	info.vhost_name = "srv-h3";
	info.listen_accept_role = "quic";
	info.listen_accept_protocol = "keep-warm";
	info.alpn = "h3";

	vh_h3 = lws_create_vhost(context, &info);
	if (!vh_h3) {
		lwsl_err("Failed to create h3 server vhost\n");
		goto bail;
	}

	if (!lws_create_adopt_udp(vh_h3, server_addr, port_h3, LWS_CAUDP_BIND,
				  "keep-warm", NULL, NULL, NULL, NULL,
				  "quic_listen")) {
		lwsl_err("Failed to bind the quic listener\n");
		goto bail;
	}

	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.alpn = NULL;
#endif

	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;
#endif

	/* client vhost, no listener */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(cases));

	return result;
}
