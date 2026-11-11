/*
 * lws-api-test-proxy-fixture
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A ctest fixture, not a test: a minimal http CONNECT and SOCKS5 proxy in one
 * process, so the tests can exercise lws' client proxy connects without any
 * external infrastructure.  It's built on lws raw sockets, both the accepted
 * client and the onward connection.
 *
 *   lws-api-test-proxy-fixture --port P [--auth-port Q] [--log FILE] [-d N]
 *
 * Port P accepts both "CONNECT host:port HTTP/1.1" and SOCKS5 with the
 * no-authentication method.  Port Q, if given, only speaks SOCKS5 selecting
 * the username/password method, accepting only user "user", password "pass".
 * Both listen on 127.0.0.1.  After the handshake, the bytes are relayed as
 * they are, both ways, with each direction flow-controlled against the other
 * side's backlog.  When one side closes, what is still waiting for the other
 * is written before that closes too.
 *
 * Every connection is logged as it goes, to stderr and, with --log, to FILE:
 * who connected, what it asked for, how long the onward connect took or why
 * it failed, and how the relay ended, with the bytes each way.  The tests
 * using the fixture take the same FILE as --proxy-log and print it when they
 * fail, since ctest only shows a fixture's own output when the fixture fails.
 * The lines are in the lws log format, marked P:, so the two read together.
 * These lines don't depend on lws logging, so they are there even when lws
 * was built without logs.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

enum {
	LWS_SW_PORT,
	LWS_SW_AUTH_PORT,
	LWS_SW_LOG,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]		= { "--port",		"Port for http CONNECT and SOCKS5 without auth (required)" },
	[LWS_SW_AUTH_PORT]	= { "--auth-port",	"Port for SOCKS5 with username / password only, user \"user\" password \"pass\"" },
	[LWS_SW_LOG]		= { "--log",		"Also write what the proxy saw to this file" },
	[LWS_SW_D]		= { "-d",		"lws log level (e.g. -d 15)" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

/* the largest handshake we take, http CONNECT request or SOCKS5 message */
#define HS_MAX			1024
/* a connection gets this long to finish its handshake */
#define HS_TIMEOUT_S		10
/* and when one side closed, the other this long to take what's left */
#define FLUSH_TIMEOUT_S		5
/* rx from a side stops when this much is waiting for the other side */
#define FLOW_HIGH		(256 * 1024)
#define FLOW_LOW		(FLOW_HIGH / 4)

enum { ACC, ONW }; /* the accepted client, and our onward connection */

enum hs_state {
	HS_SNIFF,		/* the first byte says which */
	HS_HTTP,		/* collecting the CONNECT request */
	HS_S5_GREETING,
	HS_S5_AUTH,
	HS_S5_REQUEST,
	HS_CONNECTING,		/* the onward connection is underway */
	HS_TUNNEL,
};

struct conn {
	struct lws		*wsi[2];
	struct lws_buflist	*tx[2];		/* waiting to be written to
						 * wsi[side] */
	lws_usec_t		t0;
	size_t			count[2];	/* relayed, read from side */
	uint8_t			hs[HS_MAX];
	size_t			hs_len;
	const char		*why;		/* why the relay ended */
	enum hs_state		state;
	unsigned int		cid;
	char			host[256];
	uint16_t		port;
	char			require_auth;
	char			socks;
	char			closed[2];
	char			close_after_tx;	/* the ACC side, after a refusal */
	char			refused;	/* and we logged why */
	char			rx_off[2];
};

static struct lws_context *context;
static unsigned int conn_seq;
static int log_fd = -1;

static const uint8_t s5_ok[] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 },
		     s5_refused[] = { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 },
		     s5_cmd_unsupported[] = { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 };
static const char http_ok[] = "HTTP/1.1 200 Connection established\r\n\r\n",
		  http_bad_gateway[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n",
		  http_bad_request[] = "HTTP/1.1 400 Bad Request\r\n\r\n",
		  http_not_allowed[] = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";

/*
 * One line of what the proxy saw, to stderr and to the --log file, in the lws
 * log format but marked P:
 */

static void
plog(const char *fmt, ...)
{
	char line[640];
	struct timeval tv;
	struct tm tm;
	va_list ap;
	time_t t;
	int n;

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	if (!localtime_r(&t, &tm))
		memset(&tm, 0, sizeof(tm));

	n = lws_snprintf(line, sizeof(line),
			 "[%04d/%02d/%02d %02d:%02d:%02d:%04d] P: ",
			 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			 tm.tm_hour, tm.tm_min, tm.tm_sec,
			 (int)(tv.tv_usec / 100));

	va_start(ap, fmt);
	n += vsnprintf(line + n, sizeof(line) - (size_t)n - 1, fmt, ap);
	va_end(ap);
	if (n > (int)sizeof(line) - 2)
		n = (int)sizeof(line) - 2;
	line[n++] = '\n';

	if (write(2, line, (size_t)n) != n)
		{ /* nowhere to say so */ }
	if (log_fd >= 0 && write(log_fd, line, (size_t)n) != n)
		{ /* the stderr copy is still there */ }
}

static int
ms_since(lws_usec_t t0)
{
	return (int)((lws_now_usecs() - t0) / LWS_US_PER_MS);
}

static int
side_of(struct conn *conn, struct lws *wsi)
{
	return wsi == conn->wsi[ACC] ? ACC : ONW;
}

/* queue bytes to be written to a side when it's writeable */

static int
conn_queue(struct conn *conn, int side, const void *buf, size_t len)
{
	if (!len)
		return 0;

	if (lws_buflist_append_segment(&conn->tx[side], buf, len) < 0) {
		plog("c%u: OOM", conn->cid);
		return 1;
	}

	if (conn->wsi[side] && !conn->closed[side])
		lws_callback_on_writable(conn->wsi[side]);

	return 0;
}

/*
 * Refuse the accepted client: send it the reply, if any, then close it, see
 * close_after_tx.  Any onward connection then goes too, see conn_side_gone().
 */

static void
conn_refuse(struct conn *conn, const void *reply, size_t len, const char *why)
{
	plog("c%u: failed after %dms: %s", conn->cid, ms_since(conn->t0), why);

	conn->refused = 1;
	conn->close_after_tx = 1;
	if (conn_queue(conn, ACC, reply, len))
		lws_buflist_destroy_all_segments(&conn->tx[ACC]);
	lws_set_timeout(conn->wsi[ACC], PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE,
			FLUSH_TIMEOUT_S);
}

static void
conn_onward(struct conn *conn)
{
	struct lws_client_connect_info i;

	plog("c%u: connecting on to %s:%u", conn->cid, conn->host,
	     (unsigned int)conn->port);

	conn->state = HS_CONNECTING;
	conn->closed[ONW] = 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost(conn->wsi[ACC]);
	i.method		= "RAW";
	i.address		= conn->host;
	i.port			= conn->port;
	i.host			= conn->host;
	i.origin		= conn->host;
	i.path			= "/";
	i.local_protocol_name	= "proxy-fixture";
	i.opaque_user_data	= conn;
	i.pwsi			= &conn->wsi[ONW];

	if (!lws_client_connect_via_info(&i) && !conn->closed[ONW]) {
		/* it failed without telling us in CLIENT_CONNECTION_ERROR */
		conn->closed[ONW] = 1;
		conn->wsi[ONW] = NULL;
		conn_refuse(conn, conn->socks ? (const void *)s5_refused :
					       (const void *)http_bad_gateway,
			    conn->socks ? sizeof(s5_refused) :
					  strlen(http_bad_gateway),
			    "onward connect failed early");
	}
}

/* a CONNECT target, "host:port" or "[v6]:port", into conn */

static int
conn_set_target(struct conn *conn, const char *p, size_t len)
{
	const char *colon = NULL, *h = p, *e;
	size_t hl, n;
	unsigned int port = 0;

	if (len && *p == '[') {
		e = memchr(p, ']', len);
		if (!e || (size_t)(e - p) + 1 >= len || e[1] != ':')
			return 1;
		h = p + 1;
		hl = (size_t)(e - h);
		colon = e + 1;
	} else {
		for (n = 0; n < len; n++)
			if (p[n] == ':')
				colon = p + n;
		if (!colon)
			return 1;
		hl = (size_t)(colon - p);
	}

	if (!hl || hl >= sizeof(conn->host))
		return 1;

	e = p + len;
	if (colon + 1 == e || e - (colon + 1) > 5)
		return 1;
	for (p = colon + 1; p < e; p++) {
		if (*p < '0' || *p > '9')
			return 1;
		port = (port * 10) + (unsigned int)(*p - '0');
	}
	if (!port || port > 65535)
		return 1;

	for (n = 0; n < hl; n++)
		if (h[n] <= ' ' || h[n] > '~')
			return 1;

	memcpy(conn->host, h, hl);
	conn->host[hl] = '\0';
	conn->port = (uint16_t)port;

	return 0;
}

/*
 * http CONNECT: once the request's headers have all come, the request line
 * must be "CONNECT <authority> HTTP/1.x"
 */

static int
hs_http(struct conn *conn)
{
	const char *p = (const char *)conn->hs, *sp, *eol;
	size_t n, used = 0, ll;

	for (n = 3; n < conn->hs_len; n++)
		if (!memcmp(conn->hs + n - 3, "\r\n\r\n", 4)) {
			used = n + 1;
			break;
		}

	if (!used) {
		if (conn->hs_len == sizeof(conn->hs)) {
			conn_refuse(conn, http_bad_request,
				    strlen(http_bad_request),
				    "CONNECT request too large");
			return 1;
		}

		return 0; /* wait for more */
	}

	eol = memchr(p, '\r', used);
	ll = (size_t)(eol - p);

	if (ll < 8 || memcmp(p, "CONNECT ", 8)) {
		conn_refuse(conn, http_not_allowed, strlen(http_not_allowed),
			    "not a CONNECT");
		return 1;
	}

	sp = memchr(p + 8, ' ', ll - 8);
	if (!sp || (size_t)(eol - (sp + 1)) < 7 || memcmp(sp + 1, "HTTP/1.", 7) ||
	    conn_set_target(conn, p + 8, (size_t)(sp - (p + 8)))) {
		conn_refuse(conn, http_bad_request, strlen(http_bad_request),
			    "bad CONNECT request line");
		return 1;
	}

	plog("c%u: http %.*s, %dms after accept", conn->cid, (int)ll, p,
	     ms_since(conn->t0));

	/* anything the client sent after its request is for the target */
	if (conn_queue(conn, ONW, conn->hs + used, conn->hs_len - used))
		return 1;
	conn->hs_len = 0;

	conn_onward(conn);

	return 1;
}

static void
hs_consume(struct conn *conn, size_t n)
{
	memmove(conn->hs, conn->hs + n, conn->hs_len - n);
	conn->hs_len -= n;
}

/* SOCKS5, RFC 1928, and its username / password auth, RFC 1929 */

static int
hs_socks5(struct conn *conn)
{
	const uint8_t *p = conn->hs;
	uint8_t want, ul, pl, r[2];
	char ads[64];
	size_t n, need;

	switch (conn->state) {
	case HS_S5_GREETING:
		if (conn->hs_len < 2 || conn->hs_len < 2u + p[1])
			return 0;
		want = conn->require_auth ? 2 : 0;
		for (n = 0; n < p[1]; n++)
			if (p[2 + n] == want)
				break;
		if (n == p[1]) {
			r[0] = 5;
			r[1] = 0xff;
			conn_refuse(conn, r, 2, conn->require_auth ?
				"client did not offer method 2" :
				"client did not offer method 0");
			return 1;
		}
		r[0] = 5;
		r[1] = want;
		if (conn_queue(conn, ACC, r, 2))
			return 1;
		hs_consume(conn, 2u + p[1]);
		conn->state = conn->require_auth ? HS_S5_AUTH : HS_S5_REQUEST;
		return -1; /* go on with what's left */

	case HS_S5_AUTH:
		if (conn->hs_len < 2)
			return 0;
		ul = p[1];
		if (conn->hs_len < 3u + ul)
			return 0;
		pl = p[2 + ul];
		if (conn->hs_len < 3u + ul + pl)
			return 0;
		if (p[0] != 1 || ul != 4 || memcmp(p + 2, "user", 4) ||
		    pl != 4 || memcmp(p + 3 + ul, "pass", 4)) {
			r[0] = 1;
			r[1] = 1;
			conn_refuse(conn, r, 2, "bad credentials");
			return 1;
		}
		r[0] = 1;
		r[1] = 0;
		if (conn_queue(conn, ACC, r, 2))
			return 1;
		hs_consume(conn, 3u + ul + pl);
		conn->state = HS_S5_REQUEST;
		return -1;

	case HS_S5_REQUEST:
		if (conn->hs_len < 5)
			return 0;
		if (p[0] != 5 || p[1] != 1) {
			conn_refuse(conn, s5_cmd_unsupported,
				    sizeof(s5_cmd_unsupported),
				    "not a CONNECT");
			return 1;
		}
		switch (p[3]) {
		case 1: /* ipv4 */
			need = 4 + 4 + 2;
			if (conn->hs_len < need)
				return 0;
			if (lws_write_numeric_address(p + 4, 4, ads,
						      sizeof(ads)) < 0)
				goto bad;
			lws_strncpy(conn->host, ads, sizeof(conn->host));
			break;
		case 3: /* a name, length first */
			need = 4 + 1 + (size_t)p[4] + 2;
			if (conn->hs_len < need)
				return 0;
			if (!p[4])
				goto bad;
			for (n = 0; n < p[4]; n++)
				if (p[5 + n] <= ' ' || p[5 + n] > '~')
					goto bad;
			memcpy(conn->host, p + 5, p[4]);
			conn->host[p[4]] = '\0';
			break;
		case 4: /* ipv6 */
			need = 4 + 16 + 2;
			if (conn->hs_len < need)
				return 0;
			if (lws_write_numeric_address(p + 4, 16, ads,
						      sizeof(ads)) < 0)
				goto bad;
			lws_strncpy(conn->host, ads, sizeof(conn->host));
			break;
		default:
			goto bad;
		}
		conn->port = (uint16_t)((p[need - 2] << 8) | p[need - 1]);

		plog("c%u: socks5%s CONNECT %s:%u, %dms after accept",
		     conn->cid, conn->require_auth ? " (auth)" : "",
		     conn->host, (unsigned int)conn->port, ms_since(conn->t0));

		if (conn_queue(conn, ONW, conn->hs + need, conn->hs_len - need))
			return 1;
		conn->hs_len = 0;

		conn_onward(conn);
		return 1;

	default:
		break;
	}

	return 1;

bad:
	conn_refuse(conn, s5_cmd_unsupported, sizeof(s5_cmd_unsupported),
		    "bad SOCKS5 address");

	return 1;
}

/* handshake bytes from the accepted client */

static void
hs_rx(struct conn *conn, const uint8_t *in, size_t len)
{
	int r;

	if (len > sizeof(conn->hs) - conn->hs_len) {
		conn_refuse(conn, NULL, 0, "handshake too large");
		return;
	}
	memcpy(conn->hs + conn->hs_len, in, len);
	conn->hs_len += len;

	if (conn->state == HS_SNIFF) {
		if (conn->hs[0] == 5) {
			conn->socks = 1;
			conn->state = HS_S5_GREETING;
		} else {
			if (conn->require_auth) {
				conn_refuse(conn, NULL, 0,
					    "auth port only speaks socks5");
				return;
			}
			conn->state = HS_HTTP;
		}
	}

	do {
		if (conn->state == HS_HTTP)
			r = hs_http(conn);
		else
			r = hs_socks5(conn);
	} while (r < 0);
}

/*
 * One side of the connection is gone.  What was waiting for it can't go now;
 * what is waiting for the other side goes, and then that closes too.
 */

static void
conn_side_gone(struct conn *conn, int side)
{
	int other = !side;

	conn->wsi[side] = NULL;
	conn->closed[side] = 1;
	lws_buflist_destroy_all_segments(&conn->tx[side]);

	if (conn->state == HS_TUNNEL && !conn->why)
		conn->why = side == ACC ? "client closed" : "upstream closed";

	if (!conn->closed[other]) {
		/*
		 * While its onward connection is still underway, the client
		 * waits for it to succeed or fail; we don't close it here
		 */
		if (side == ONW && conn->state == HS_CONNECTING)
			return;

		if (!conn->wsi[other])
			/* still connecting: it closes itself when it's up */
			return;

		if (conn->rx_off[other]) {
			lws_rx_flow_control(conn->wsi[other], 1);
			conn->rx_off[other] = 0;
		}

		if (lws_buflist_total_len(&conn->tx[other])) {
			lws_set_timeout(conn->wsi[other],
					PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE,
					FLUSH_TIMEOUT_S);
			lws_callback_on_writable(conn->wsi[other]);
		} else
			lws_set_timeout(conn->wsi[other],
					PENDING_TIMEOUT_KILLED_BY_PARENT,
					LWS_TO_KILL_ASYNC);
		return;
	}

	if (conn->why)
		plog("c%u: relay ended, %s, client->upstream %llu, "
		     "upstream->client %llu, after %dms", conn->cid, conn->why,
		     (unsigned long long)conn->count[ACC],
		     (unsigned long long)conn->count[ONW], ms_since(conn->t0));
	else if (!conn->refused && (conn->state != HS_SNIFF || conn->hs_len))
		plog("c%u: closed during the handshake, after %dms", conn->cid,
		     ms_since(conn->t0));

	lws_buflist_destroy_all_segments(&conn->tx[other]);
	free(conn);
}

static int
callback_proxy(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct conn *conn = (struct conn *)lws_get_opaque_user_data(wsi);
	char peer[64];
	uint8_t *p;
	int side;

	switch (reason) {

	case LWS_CALLBACK_RAW_ADOPT:
		conn = calloc(1, sizeof(*conn));
		if (!conn)
			return -1;
		conn->t0		= lws_now_usecs();
		conn->cid		= ++conn_seq;
		conn->wsi[ACC]		= wsi;
		conn->closed[ONW]	= 1; /* until it's started */
		conn->require_auth	= !!lws_get_vhost_user(lws_get_vhost(wsi));
		lws_set_opaque_user_data(wsi, conn);

		lws_get_peer_simple(wsi, peer, sizeof(peer));
		plog("c%u: accepted from %s on port %d", conn->cid, peer,
		     lws_get_vhost_listen_port(lws_get_vhost(wsi)));

		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, HS_TIMEOUT_S);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!conn || conn->closed[ONW])
			break;
		plog("c%u: onward connect to %s:%u failed after %dms: %s",
		     conn->cid, conn->host, (unsigned int)conn->port,
		     ms_since(conn->t0), in ? (const char *)in : "(null)");
		conn->closed[ONW] = 1;
		conn->wsi[ONW] = NULL;
		lws_buflist_destroy_all_segments(&conn->tx[ONW]);

		if (conn->closed[ACC]) {
			conn_side_gone(conn, ONW);
			break;
		}
		conn_refuse(conn, conn->socks ? (const void *)s5_refused :
					       (const void *)http_bad_gateway,
			    conn->socks ? sizeof(s5_refused) :
					  strlen(http_bad_gateway),
			    "onward connect failed");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		if (!conn)
			return -1;
		conn->wsi[ONW] = wsi;

		lws_get_peer_simple(wsi, peer, sizeof(peer));
		plog("c%u: onward connect to %s:%u (%s) took %dms", conn->cid,
		     conn->host, (unsigned int)conn->port, peer,
		     ms_since(conn->t0));

		if (conn->closed[ACC])
			/* nobody to tunnel for any more */
			return -1;

		conn->state = HS_TUNNEL;
		if (conn_queue(conn, ACC, conn->socks ? (const void *)s5_ok :
							 (const void *)http_ok,
			       conn->socks ? sizeof(s5_ok) : strlen(http_ok)))
			return -1;
		lws_set_timeout(conn->wsi[ACC], NO_PENDING_TIMEOUT, 0);
		plog("c%u: tunnel up, %dms after accept", conn->cid,
		     ms_since(conn->t0));

		if (lws_buflist_total_len(&conn->tx[ONW]))
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!conn)
			return -1;
		side = side_of(conn, wsi);

		if (side == ACC && conn->close_after_tx)
			break; /* refused: what it says now goes nowhere */

		if (side == ACC && conn->state < HS_CONNECTING) {
			hs_rx(conn, in, len);
			/* refused with nothing to say: close now */
			if (conn->close_after_tx &&
			    !lws_buflist_total_len(&conn->tx[ACC]))
				return -1;
			break;
		}

		if (conn->closed[!side])
			break; /* nowhere for it to go */

		/*
		 * In the tunnel, or still connecting: the client's bytes wait
		 * for the onward side to be up
		 */
		conn->count[side] += len;
		if (conn_queue(conn, !side, in, len))
			return -1;

		if (lws_buflist_total_len(&conn->tx[!side]) > FLOW_HIGH &&
		    !conn->rx_off[side]) {
			lws_rx_flow_control(wsi, 0);
			conn->rx_off[side] = 1;
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!conn)
			return -1;
		side = side_of(conn, wsi);

		if (side == ONW && conn->state != HS_TUNNEL)
			break;

		len = lws_buflist_next_segment_len(&conn->tx[side], &p);
		if (len) {
			if (lws_write(wsi, p, len, LWS_WRITE_RAW) < 0)
				return -1;
			lws_buflist_use_segment(&conn->tx[side], len);
		}

		/*
		 * The other side being closed only means we're flushing once
		 * the tunnel was up: before that, the onward side not having
		 * started yet counts as closed too
		 */
		if (lws_buflist_total_len(&conn->tx[side])) {
			lws_callback_on_writable(wsi);
			if (conn->closed[!side] && conn->state == HS_TUNNEL)
				/* flushing: the deadline is per piece */
				lws_set_timeout(wsi,
					PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE,
					FLUSH_TIMEOUT_S);
		} else if ((conn->closed[!side] && conn->state == HS_TUNNEL) ||
			   (side == ACC && conn->close_after_tx))
			return -1; /* all written, nothing more will come */

		/* the other side can send again once this has drained */
		if (conn->rx_off[!side] && !conn->closed[!side] &&
		    lws_buflist_total_len(&conn->tx[side]) < FLOW_LOW) {
			lws_rx_flow_control(conn->wsi[!side], 1);
			conn->rx_off[!side] = 0;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!conn)
			break;
		lws_set_opaque_user_data(wsi, NULL);
		conn_side_gone(conn, side_of(conn, wsi));
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "proxy-fixture", callback_proxy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigterm_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
port_arg(int argc, const char **argv, int sw)
{
	const char *p = lws_cmdline_option(argc, argv, switches[sw].sw);
	int port;

	if (!p)
		return 0;
	port = atoi(p);
	if (port <= 0 || port > 65535) {
		lwsl_err("%s wants a port, not '%s'\n", switches[sw].sw, p);
		return -1;
	}

	return port;
}

static int
listen_on(struct lws_context_creation_info *info, int port, int auth)
{
	static char auth_flag = 1;

	info->port		= port;
	info->vhost_name	= auth ? "socks5-auth" : "proxy";
	info->user		= auth ? &auth_flag : NULL;

	if (!lws_create_vhost(context, info)) {
		lwsl_err("can't listen on 127.0.0.1:%d\n", port);
		return 1;
	}

	plog("pid %d listening on 127.0.0.1:%d%s", (int)getpid(), port,
	     auth ? " (socks5 auth)" : "");

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int port, auth_port, ret = 1;
	const char *p;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	port = port_arg(argc, argv, LWS_SW_PORT);
	auth_port = port_arg(argc, argv, LWS_SW_AUTH_PORT);
	if (port <= 0 || auth_port < 0) {
		if (!port)
			lwsl_err("--port is required\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_LOG].sw))) {
		log_fd = lws_open(p, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY,
				  0600);
		if (log_fd < 0) {
			lwsl_err("can't open --log %s\n", p);
			return 1;
		}
	}

	signal(SIGINT, sigterm_handler);
	signal(SIGTERM, sigterm_handler);

	/* the vhosts are made below, one per port */
	info.options		|= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
				   LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.protocols		= protocols;
	info.listen_accept_role	= "raw-skt";
	info.listen_accept_protocol = "proxy-fixture";
	info.iface		= "127.0.0.1";
	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail;
	}

	if (listen_on(&info, port, 0) ||
	    (auth_port && listen_on(&info, auth_port, 1)))
		goto bail1;

	lws_context_default_loop_run_destroy(context);
	ret = 0;
	goto bail;

bail1:
	lws_context_destroy(context);
bail:
	if (log_fd >= 0)
		close(log_fd);

	return ret;
}
