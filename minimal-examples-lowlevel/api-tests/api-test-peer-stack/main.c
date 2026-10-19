/*
 * lws-api-test-peer-stack
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The peer address stack (lws_peer_walk() and friends): who a connection's
 * peer is, layer by layer, each tagged with how far it can be believed.
 *
 *  - the formatter, on entries made up here: both formats, IPv6 brackets,
 *    AF_UNIX, the names, cutting short, and a single proven entry given
 *    bare, as lws's own logs give the usual peer, while a single entry that
 *    is not proven keeps its cred;
 *
 *  - the effective entry rule, on entries made up here: a hearsay entry
 *    above a believable one is never the effective entry;
 *
 *  - a plain TCP connection: the server sees one entry, the socket's peer,
 *    ROUTABLE, which is also the effective entry, and the client sees the
 *    server the same way once connected.  The client resets the connection,
 *    and when the server closes it, it is still described as it was: from
 *    the stack, not by asking the socket, which no longer knows;
 *
 *  - an AF_UNIX connection (adopted from a socketpair) is one LOCAL entry,
 *    described as "unix" in logs and in its access log line, which has no
 *    spaces in its host field;
 *
 *  - with TLS passthrough, a PROXY v2 header from a front the vhost trusts
 *    (loopback): the client it names goes on top, VOUCHED, and being the
 *    first entry from the top at VOUCHED or better it is the effective
 *    entry, which is what lws_get_peer_simple() gives;
 *
 *  - with UDP, a bound socket's peer is the last datagram's source, only
 *    HEARSAY, and the effective entry for want of a better one; it is a
 *    DATAGRAM entry, not a peer the socket is fixed to.  lws_peer_raise()
 *    raises it only for its own address (and port, if given), never lowers
 *    it, and once a datagram from somewhere else has moved the entry on,
 *    evidence about the old source raises nothing.  A connected sender
 *    answered by the receiver keeps its own peer, a SOCKET entry.  A raise
 *    covers only the datagram it was for: the next one, even from the same
 *    address and port, is hearsay again, on both sockets;
 *
 *  - an http client redirected to the same server dials again with the
 *    same wsi: while it dials, the new connection is hearsay, not what the
 *    last one proved, and routable again once connected;
 *
 *  - with LWS_WITH_ACCESS_LOG, the access log line of the plain connection
 *    starts with just the client's address, as access logs always did, and
 *    that of the PROXY v2 one with both layers, as one field.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#define PS_CLIENT	"192.0.2.10"	/* who the PROXY v2 header names */
#define PS_CLIENT_PORT	40000
#define PS_STRANGER	"198.51.100.1"	/* nobody on any stack */
#define PS_PHASE_US	(3 * LWS_US_PER_SEC)

/* AF_UNIX connections are adopted from a socketpair */
#if defined(LWS_WITH_UNIX_SOCK) && !defined(WIN32)
#define PS_UNIX
#include <sys/socket.h>
#include <unistd.h>
#endif

enum {
	PS_PHASE_TCP,
	PS_PHASE_PROXY_V2,
	PS_PHASE_UDP,
	PS_PHASE_REDIRECT,
	PS_PHASE_UNIX,
	PS_PHASE_COUNT
};

static const char * const phase_names[] = {
	"tcp", "proxy-v2", "udp", "redirect", "unix"
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli, *vh_srv, *vh_pv2;
static lws_sorted_usec_list_t sul_phase;
static const char *server = "localhost";
#if defined(LWS_WITH_ACCESS_LOG)
static const char *alog;		/* the servers' access log file */
/* host field of the tcp, proxy-v2 and unix phases' lines */
static char alog_host[PS_PHASE_COUNT][LWS_PEER_DESC_LEN];
#endif
static struct lws *srv_tcp;		/* the server's tcp phase connection */
static char srv_tcp_desc[LWS_PEER_DESC_LEN];	/* ... as it was described */
static int phase = -1, fails, finished, phase_done, srv_checked, udp_port,
	   redirected, redial_seen, srv_tcp_closed;
#if defined(PS_UNIX)
static int unix_fd = -1;		/* our end of the socketpair */
#endif
#if defined(LWS_WITH_UDP)
static lws_peer_entry_t udp_first;	/* the first datagram's source */
static struct lws *udp_tx1;		/* the first sender */
static int udp_rxed, udp_tx1_rxed;
#endif

static void
ps_next(lws_sorted_usec_list_t *sul);

static void
check(int ok, const char *what)
{
	if (ok)
		lwsl_user("  PASS: %s\n", what);
	else {
		lwsl_err("  FAIL: %s\n", what);
		fails++;
	}
}

static void
check_str(const char *got, const char *exp, const char *what)
{
	int ok = !strcmp(got, exp);

	check(ok, what);
	if (!ok)
		lwsl_err("        got '%s', expected '%s'\n", got, exp);
}

static void
ps_phase_end(const char *why)
{
	if (phase_done)
		return;
	phase_done = 1;
	lws_sul_cancel(&sul_phase);

	if (why)
		check(0, why);

	lws_sul_schedule(cx, 0, &sul_phase, ps_next, 1);
}

static void
ps_deadline(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	ps_phase_end("phase did not complete in time");
}

static int
is_loopback(const lws_sockaddr46 *sa46)
{
	lws_sockaddr46 lo;

	if (!lws_sa46_parse_numeric_address("127.0.0.1", &lo) &&
	    !lws_sa46_compare_ads(sa46, &lo))
		return 1;
#if defined(LWS_WITH_IPV6)
	if (!lws_sa46_parse_numeric_address("::1", &lo) &&
	    !lws_sa46_compare_ads(sa46, &lo))
		return 1;
#endif

	return 0;
}

static unsigned int
port_of(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return ntohs(sa46->sa6.sin6_port);
#endif
	return ntohs(sa46->sa4.sin_port);
}

/* what the log format should say for one entry seen on a live connection */
static void
expect_entry(char *buf, size_t len, const lws_peer_entry_t *e, int token)
{
	lws_sockaddr46 sa46 = e->sa46;
	static const char ini[] = "nhvrc";
	char ads[64];

	lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads));

	if (token)
		lws_snprintf(buf, len,
			     sa46.sa4.sin_family == AF_INET6 ? "[%s]:%u~%c" :
							       "%s:%u~%c",
			     ads, port_of(&sa46), ini[e->cred]);
	else
		lws_snprintf(buf, len,
			     sa46.sa4.sin_family == AF_INET6 ? "[%s]:%u %s/%s" :
							       "%s:%u %s/%s",
			     ads, port_of(&sa46),
			     lws_peer_kind_name((lws_peer_kind_t)e->kind),
			     lws_peer_cred_name((lws_peer_cred_t)e->cred));
}

static void
entry(lws_peer_entry_t *e, const char *ads, unsigned int port,
      lws_peer_kind_t kind, lws_peer_cred_t cred)
{
	memset(e, 0, sizeof(*e));
	if (ads && lws_sa46_parse_numeric_address(ads, &e->sa46))
		lwsl_err("%s: can't parse %s\n", __func__, ads);
	if (ads)
		sa46_sockport(&e->sa46, htons((uint16_t)port));
	e->kind = (uint8_t)kind;
	e->cred = (uint8_t)cred;
}

/* the formatter, on entries made up here */

static void
ps_formatter(void)
{
	static const char full[] = "192.0.2.10:40000 proxy-v2/vouched < "
				   "10.0.0.2:40122 socket/routable";
	lws_peer_entry_t e[2];
	char buf[128];

	lwsl_user("formatter:\n");

	entry(&e[0], "192.0.2.10", 40000, LWS_PEER_KIND_PROXY_V2,
	      LWS_PEER_CRED_VOUCHED);
	entry(&e[1], "10.0.0.2", 40122, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_ROUTABLE);

	check_str(lws_peer_entries_describe(e, 2, buf, sizeof(buf), 0), full,
		  "a claim over a socket, for logs");
	check_str(lws_peer_entries_describe(e, 2, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN),
		  "192.0.2.10:40000~v<10.0.0.2:40122~r",
		  "a claim over a socket, as one token");
	check_str(lws_peer_entries_describe(&e[1], 1, buf, sizeof(buf), 0),
		  "10.0.0.2:40122 socket/routable", "a socket, for logs");
	check_str(lws_peer_entries_describe(&e[1], 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN),
		  "10.0.0.2:40122~r", "a socket, as a token");

	/* the usual case in logs and access logs: just the address */
	check_str(lws_peer_entries_describe(&e[1], 1, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2", "a single entry, bare, for logs");
	check_str(lws_peer_entries_describe(&e[1], 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2", "a single entry, bare, as a token");
	check_str(lws_peer_entries_describe(e, 2, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE), full,
		  "bare single: a claim over a socket is still in full");
	check_str(lws_peer_entries_describe(e, 2, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "192.0.2.10:40000~v<10.0.0.2:40122~r",
		  "bare single: and in full as one token");

	entry(&e[0], "10.0.0.2", 0, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_HEARSAY);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN),
		  "10.0.0.2~h", "hearsay, no port, as a token");

	/* a lone entry is bare only if it is proven */
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2 socket/hearsay",
		  "bare single: lone hearsay keeps its cred, for logs");
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2~h", "bare single: and as a token");
	entry(&e[0], "10.0.0.2", 53, LWS_PEER_KIND_DATAGRAM,
	      LWS_PEER_CRED_HEARSAY);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2:53~h", "bare single: a datagram's source too");
	entry(&e[0], "192.0.2.10", 40000, LWS_PEER_KIND_PROXY_V2,
	      LWS_PEER_CRED_VOUCHED);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "192.0.2.10:40000~v", "bare single: lone vouched too");
	entry(&e[0], "10.0.0.2", 443, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_CRYPTO);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE),
		  "10.0.0.2", "bare single: lone crypto is bare");

#if defined(LWS_WITH_IPV6)
	entry(&e[0], "2001:db8::1", 443, LWS_PEER_KIND_RELAY,
	      LWS_PEER_CRED_CRYPTO);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf), 0),
		  "[2001:db8::1]:443 relay/crypto",
		  "IPv6 with a port is bracketed");
	entry(&e[0], "2001:db8::1", 0, LWS_PEER_KIND_XFF,
	      LWS_PEER_CRED_HEARSAY);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf), 0),
		  "2001:db8::1 xff/hearsay", "IPv6 without a port is bare");
#endif

	entry(&e[0], NULL, 0, LWS_PEER_KIND_LOCAL, LWS_PEER_CRED_ROUTABLE);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf), 0),
		  "unix local/routable", "AF_UNIX, for logs");
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN),
		  "unix~r", "AF_UNIX, as a token");
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE),
		  "unix", "AF_UNIX, bare");

	/* no address family lws can write: no spaces in a token either */
	entry(&e[0], NULL, 0, LWS_PEER_KIND_SOCKET, LWS_PEER_CRED_HEARSAY);
	check_str(lws_peer_entries_describe(e, 1, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN),
		  "unknown~h", "an unset address, as a token");

	check_str(lws_peer_entries_describe(e, 0, buf, sizeof(buf), 0),
		  "unknown", "no entries");

	/* cut short */

	entry(&e[0], "192.0.2.10", 40000, LWS_PEER_KIND_PROXY_V2,
	      LWS_PEER_CRED_VOUCHED);
	entry(&e[1], "10.0.0.2", 40122, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_ROUTABLE);

	lws_peer_entries_describe(e, 2, buf, sizeof(full), 0);
	check_str(buf, full, "exactly fitting is not cut");

	lws_peer_entries_describe(e, 2, buf, sizeof(full) - 1, 0);
	check(strlen(buf) == sizeof(full) - 2 &&
	      !strncmp(buf, full, sizeof(full) - 5) &&
	      !strcmp(buf + sizeof(full) - 5, "..."),
	      "one byte short ends with ...");

	lws_peer_entries_describe(e, 2, buf, 20, 0);
	check(strlen(buf) == 19 && !strncmp(buf, full, 16) &&
	      !strcmp(buf + 16, "..."), "a small buffer ends with ...");

	lws_peer_entries_describe(e, 2, buf, 3, 0);
	check_str(buf, "19", "no room for ..., still terminated");

	buf[0] = 'x';
	lws_peer_entries_describe(e, 2, buf, 1, 0);
	check(!buf[0], "a one byte buffer is just the NUL");

	buf[0] = 'x';
	lws_peer_entries_describe(e, 2, buf, 0, 0);
	check(buf[0] == 'x', "a zero length buffer is left alone");

	check_str(lws_peer_cred_name(LWS_PEER_CRED_VOUCHED), "vouched",
		  "cred name");
	check_str(lws_peer_cred_name((lws_peer_cred_t)99), "?",
		  "unknown cred name");
	check_str(lws_peer_kind_name(LWS_PEER_KIND_PROXY_V2), "proxy-v2",
		  "kind name");
	check_str(lws_peer_kind_name((lws_peer_kind_t)99), "?",
		  "unknown kind name");
}

/*
 * The effective entry, on stacks made up here: stacks lws does not build yet
 * (a hearsay claim above a believable entry) must follow the rule too
 */

static void
ps_effective(void)
{
	lws_peer_entry_t e[3];

	lwsl_user("effective:\n");

	entry(&e[0], "198.51.100.7", 0, LWS_PEER_KIND_XFF,
	      LWS_PEER_CRED_HEARSAY);
	entry(&e[1], "192.0.2.10", 40000, LWS_PEER_KIND_PROXY_V2,
	      LWS_PEER_CRED_VOUCHED);
	entry(&e[2], "10.0.0.2", 40122, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_ROUTABLE);
	check(lws_peer_entries_effective(e, 3) == 1,
	      "hearsay above a vouched claim: the claim");
	check(lws_peer_entries_effective(&e[1], 2) == 0,
	      "a vouched claim above a routable socket: the claim");

	e[1] = e[2];
	check(lws_peer_entries_effective(e, 2) == 1,
	      "hearsay above a routable socket: the socket");

	entry(&e[1], "10.0.0.2", 40122, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_CRYPTO);
	check(lws_peer_entries_effective(e, 2) == 1,
	      "hearsay above a crypto socket: the socket");

	entry(&e[0], "198.51.100.7", 40000, LWS_PEER_KIND_RELAY,
	      LWS_PEER_CRED_HEARSAY);
	entry(&e[1], "10.0.0.2", 40122, LWS_PEER_KIND_SOCKET,
	      LWS_PEER_CRED_HEARSAY);
	check(lws_peer_entries_effective(e, 2) == 0,
	      "nothing believable: the top entry");

	check(lws_peer_entries_effective(e, 0) == -1,
	      "no entries: none is effective");
}

/* the http server: what it sees of the peer, then a 200 */

static void
ps_srv_check(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX], eff;
	char buf[192], exp[192], t[96], ads[64];
	lws_sockaddr46 sa46;
	int n;

	n = lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX);

	if (phase == PS_PHASE_TCP) {
		check(n == 1, "server: one entry");
		if (n != 1)
			return;
		check(e[0].kind == LWS_PEER_KIND_SOCKET &&
		      e[0].cred == LWS_PEER_CRED_ROUTABLE,
		      "server: the socket's peer, routable");
		check(is_loopback(&e[0].sa46) && port_of(&e[0].sa46),
		      "server: it is the client's loopback address and port");

		check(!lws_peer_effective(wsi, &eff) &&
		      !memcmp(&eff, &e[0], sizeof(eff)),
		      "server: the socket's peer is the effective entry");

		sa46 = e[0].sa46;
		lws_sa46_write_numeric_address(&sa46, ads, sizeof(ads));
		check_str(lws_get_peer_simple(wsi, t, sizeof(t)), ads,
			  "server: lws_get_peer_simple() gives it");

		expect_entry(exp, sizeof(exp), &e[0], 0);
		check_str(lws_peer_describe(wsi, buf, sizeof(buf), 0), exp,
			  "server: described for logs");
		expect_entry(exp, sizeof(exp), &e[0], 1);
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN), exp,
			  "server: as a token");

		/* how lws's own logs and access log describe him */
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE), t,
			  "server: bare, what lws_get_peer_simple() gives");
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE), t,
			  "server: bare as a token, the same");
#if defined(LWS_WITH_ACCESS_LOG)
		/* what an access log line has always started with */
		lws_strncpy(alog_host[PS_PHASE_TCP], t,
			    sizeof(alog_host[PS_PHASE_TCP]));
#endif
		/* to compare with how it is described when it is closed */
		srv_tcp = wsi;
		lws_strncpy(srv_tcp_desc, t, sizeof(srv_tcp_desc));
		return;
	}

#if defined(PS_UNIX)
	if (phase == PS_PHASE_UNIX) {
		check(n == 1 && e[0].kind == LWS_PEER_KIND_LOCAL &&
		      e[0].cred == LWS_PEER_CRED_ROUTABLE,
		      "server: an AF_UNIX peer, one local entry");
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE), "unix",
			  "server: an AF_UNIX peer is unix in logs");
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_TOKEN |
					    LWS_PEER_DESC_BARE_SINGLE), "unix",
			  "server: and as a token, with no spaces");
#if defined(LWS_WITH_ACCESS_LOG)
		lws_strncpy(alog_host[PS_PHASE_UNIX], "unix",
			    sizeof(alog_host[PS_PHASE_UNIX]));
#endif
		return;
	}
#endif

	/* PS_PHASE_PROXY_V2 */

	check(n == 2, "server: two entries");
	if (n != 2)
		return;

	lws_sa46_write_numeric_address(&e[0].sa46, ads, sizeof(ads));
	check(e[0].kind == LWS_PEER_KIND_PROXY_V2 &&
	      e[0].cred == LWS_PEER_CRED_VOUCHED &&
	      !strcmp(ads, PS_CLIENT) &&
	      port_of(&e[0].sa46) == PS_CLIENT_PORT,
	      "server: the client the front named is on top, vouched");
	check(e[1].kind == LWS_PEER_KIND_SOCKET &&
	      e[1].cred == LWS_PEER_CRED_ROUTABLE &&
	      is_loopback(&e[1].sa46),
	      "server: the front itself is under it, routable");

	check(!lws_peer_effective(wsi, &eff) &&
	      !memcmp(&eff, &e[0], sizeof(eff)),
	      "server: the client named is the effective entry");
	check_str(lws_get_peer_simple(wsi, t, sizeof(t)), PS_CLIENT,
		  "server: lws_get_peer_simple() gives the client named");
	check_str(lws_get_peer_host_key(wsi, t, sizeof(t)), PS_CLIENT,
		  "server: and so does lws_get_peer_host_key()");

	expect_entry(t, sizeof(t), &e[1], 0);
	lws_snprintf(exp, sizeof(exp), PS_CLIENT ":%u proxy-v2/vouched < %s",
		     PS_CLIENT_PORT, t);
	check_str(lws_peer_describe(wsi, buf, sizeof(buf), 0), exp,
		  "server: both described for logs, top first");
	expect_entry(t, sizeof(t), &e[1], 1);
	lws_snprintf(exp, sizeof(exp), PS_CLIENT ":%u~v<%s", PS_CLIENT_PORT, t);
	check_str(lws_peer_describe(wsi, buf, sizeof(buf),
				    LWS_PEER_DESC_TOKEN), exp,
		  "server: both as one token");
	check_str(lws_peer_describe(wsi, buf, sizeof(buf),
				    LWS_PEER_DESC_TOKEN |
				    LWS_PEER_DESC_BARE_SINGLE), exp,
		  "server: bare single, both as one token still");
#if defined(LWS_WITH_ACCESS_LOG)
	lws_strncpy(alog_host[PS_PHASE_PROXY_V2], exp,
		    sizeof(alog_host[PS_PHASE_PROXY_V2]));
#endif
	expect_entry(t, sizeof(t), &e[1], 0);
	lws_snprintf(exp, sizeof(exp), PS_CLIENT ":%u proxy-v2/vouched < %s",
		     PS_CLIENT_PORT, t);
	check_str(lws_peer_describe(wsi, buf, sizeof(buf),
				    LWS_PEER_DESC_BARE_SINGLE), exp,
		  "server: bare single, both described for logs still");

	if (lws_sa46_parse_numeric_address(PS_STRANGER, &sa46))
		return;
	check(lws_peer_raise(wsi, &sa46, LWS_PEER_CRED_CRYPTO) &&
	      lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 2 &&
	      e[0].cred == LWS_PEER_CRED_VOUCHED &&
	      e[1].cred == LWS_PEER_CRED_ROUTABLE,
	      "server: evidence about another address raises nothing");
}

static int
ps_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];

	if (reason == LWS_CALLBACK_HTTP) {
		if (phase == PS_PHASE_REDIRECT) {
			if (!strcmp((const char *)in, "/redir")) {
				redirected = 1;
				if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
						(const unsigned char *)"/", 1,
						&p, end) < 0)
					return -1;
				return lws_http_transaction_completed(wsi) ?
									-1 : 0;
			}
		} else
			ps_srv_check(wsi);
		srv_checked = 1;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		/* nobody reads the answer on the socketpair */
		if (phase == PS_PHASE_UNIX)
			ps_phase_end(NULL);

		return lws_http_transaction_completed(wsi) ? -1 : 0;
	}

	if (reason == LWS_CALLBACK_CLOSED_HTTP && wsi == srv_tcp) {
		char buf[LWS_PEER_DESC_LEN];

		/*
		 * The client reset the connection: asked now, the socket no
		 * longer knows who it was connected to, but the stack does
		 */
		check_str(lws_peer_describe(wsi, buf, sizeof(buf),
					    LWS_PEER_DESC_BARE_SINGLE),
			  srv_tcp_desc,
			  "server: described the same after a reset, at close");
		srv_tcp = NULL;
		srv_tcp_closed = 1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the client: a raw connection sending (a PROXY v2 header and) a GET */

static int
ps_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	  void *in, size_t len)
{
	uint8_t tx[LWS_PRE + LWS_PROXY_V2_MAX + 64];
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];
	int n = 0;

	(void)user;

	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(phase + 1))
		return 0;

	switch (reason) {
	case LWS_CALLBACK_RAW_CONNECTED:
		if (phase == PS_PHASE_TCP) {
			n = lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX);
			check(n == 1 && e[0].kind == LWS_PEER_KIND_SOCKET &&
			      e[0].cred == LWS_PEER_CRED_ROUTABLE &&
			      is_loopback(&e[0].sa46) &&
			      (int)port_of(&e[0].sa46) ==
				      lws_get_vhost_listen_port(vh_srv),
			      "client: the server it connected to, routable");
		}
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
#if defined(LWS_WITH_TLS_PASSTHROUGH)
		if (phase == PS_PHASE_PROXY_V2) {
			lws_proxy_v2_t pv;

			memset(&pv, 0, sizeof(pv));
			if (lws_sa46_parse_numeric_address(PS_CLIENT,
							   &pv.src) ||
			    lws_sa46_parse_numeric_address("192.0.2.1",
							   &pv.dst))
				return -1;
			sa46_sockport(&pv.src, htons(PS_CLIENT_PORT));
			sa46_sockport(&pv.dst, htons(443));
			n = lws_proxy_v2_render(&pv, tx + LWS_PRE,
						LWS_PROXY_V2_MAX);
			if (n <= 0)
				return -1;
		}
#endif
		n += lws_snprintf((char *)tx + LWS_PRE + n,
				  sizeof(tx) - LWS_PRE - (size_t)n,
				  "GET / HTTP/1.1\x0d\x0aHost: ps\x0d\x0a"
				  "\x0d\x0a");
		if (lws_write(wsi, tx + LWS_PRE, (size_t)n, LWS_WRITE_RAW) != n)
			return -1;
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len < 12 || strncmp((const char *)in, "HTTP/1.1 200", 12))
			ps_phase_end("unexpected answer");
		else
			ps_phase_end(srv_checked ? NULL :
					"answered without the server's checks");
		if (phase == PS_PHASE_TCP) {
			struct linger lin;

			/* a raw socket is closed at once: this resets it */
			lin.l_onoff	= 1;
			lin.l_linger	= 0;
			if (setsockopt(lws_get_socket_fd(wsi), SOL_SOCKET,
				       SO_LINGER, (const char *)&lin,
				       sizeof(lin)))
				check(0, "client: set to reset on close");
		}
		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		ps_phase_end("closed unanswered");
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ps_phase_end(in ? (const char *)in : "connection error");
		break;

	default:
		break;
	}

	return 0;
}

/*
 * An http client sent a redirect to the same server: the reused wsi dials
 * again, and while it does, what the last connection proved is not taken
 * for the new one
 */

static void
ps_http_dialling(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
	      e[0].kind == LWS_PEER_KIND_SOCKET &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY &&
	      is_loopback(&e[0].sa46) &&
	      (int)port_of(&e[0].sa46) == lws_get_vhost_listen_port(vh_srv),
	      redirected ? "redirect: dialling again is hearsay again" :
			   "redirect: dialling is hearsay");
	if (redirected)
		redial_seen = 1;
}

static int
ps_http_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(phase + 1))
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CONNECTING:
		ps_http_dialling(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!redirected || !redial_seen) {
			ps_phase_end("redirect: answered without redialling");
			return -1;
		}
		check(lws_http_client_http_response(wsi) == HTTP_STATUS_OK,
		      "redirect: the redirected request is answered");
		check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
		      e[0].kind == LWS_PEER_KIND_SOCKET &&
		      e[0].cred == LWS_PEER_CRED_ROUTABLE,
		      "redirect: connected again, it is routable again");
		ps_phase_end(NULL);
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ps_phase_end(in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		ps_phase_end("redirect: closed unanswered");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#if defined(LWS_WITH_UDP)

/* UDP: a bound receiver, and two senders on sockets of their own */

/* numeric, so the receiver and the senders can't resolve to other families */
#if defined(LWS_WITH_IPV4)
#define PS_UDP_ADS	"127.0.0.1"
#else
#define PS_UDP_ADS	"::1"
#endif

static struct lws *
ps_udp_sender(const char *name)
{
	struct lws *wsi;

	wsi = lws_create_adopt_udp(vh_cli, PS_UDP_ADS, udp_port, 0,
				   "ps-udp-tx", NULL, NULL, NULL, NULL, name);
	if (!wsi)
		ps_phase_end("creating a UDP sender failed");

	return wsi;
}

static void
ps_udp_rx_first(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX], eff;
	char buf[128], exp[128];
	lws_sockaddr46 sa46;

	check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
	      e[0].kind == LWS_PEER_KIND_DATAGRAM &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY &&
	      is_loopback(&e[0].sa46) && port_of(&e[0].sa46),
	      "udp: the datagram's source, as a hearsay datagram entry");
	udp_first = e[0];

	check(!lws_peer_effective(wsi, &eff) &&
	      !memcmp(&eff, &e[0], sizeof(eff)),
	      "udp: with nothing better, the top entry is the effective one");

	expect_entry(exp, sizeof(exp), &e[0], 0);
	check_str(lws_peer_describe(wsi, buf, sizeof(buf), 0), exp,
		  "udp: described for logs");
	check_str(lws_peer_describe(wsi, buf, sizeof(buf),
				    LWS_PEER_DESC_BARE_SINGLE), exp,
		  "udp: hearsay, so lws's logs show its cred");

	/* raising: only on evidence from that address */

	if (lws_sa46_parse_numeric_address(PS_STRANGER, &sa46))
		return;
	check(lws_peer_raise(wsi, &sa46, LWS_PEER_CRED_ROUTABLE) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY,
	      "udp: evidence from another address raises nothing");

	sa46 = udp_first.sa46;
	sa46_sockport(&sa46, htons((uint16_t)(port_of(&sa46) ^ 1)));
	check(lws_peer_raise(wsi, &sa46, LWS_PEER_CRED_ROUTABLE) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY,
	      "udp: evidence from another port raises nothing");

	check(!lws_peer_raise(wsi, &udp_first.sa46, LWS_PEER_CRED_ROUTABLE) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_ROUTABLE,
	      "udp: evidence from its address and port raises it");
	lws_sa46_write_numeric_address(&e[0].sa46, exp, sizeof(exp));
	check_str(lws_peer_describe(wsi, buf, sizeof(buf),
				    LWS_PEER_DESC_BARE_SINGLE), exp,
		  "udp: proven, lws's logs show it bare");

	check(!lws_peer_raise(wsi, &udp_first.sa46, LWS_PEER_CRED_HEARSAY) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_ROUTABLE,
	      "udp: a raise never lowers");

	check(lws_peer_raise(wsi, &udp_first.sa46, LWS_PEER_CRED_NONE),
	      "udp: NONE is not a level to raise to");

	sa46 = udp_first.sa46;
	sa46_sockport(&sa46, 0);
	check(!lws_peer_raise(wsi, &sa46, LWS_PEER_CRED_CRYPTO) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_CRYPTO,
	      "udp: evidence naming only the address matches any port");

	/* answer it: the sender's peer is the one it is connected to */
	lws_callback_on_writable(wsi);
}

/* the first sender again, after a protocol raised its first datagram */
static void
ps_udp_rx_again(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
	      e[0].kind == LWS_PEER_KIND_DATAGRAM &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY &&
	      !lws_sa46_compare_ads(&e[0].sa46, &udp_first.sa46) &&
	      port_of(&e[0].sa46) == port_of(&udp_first.sa46),
	      "udp: the next datagram from the same source is hearsay again");

	lws_callback_on_writable(wsi);
}

static void
ps_udp_rx_second(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
	      e[0].kind == LWS_PEER_KIND_DATAGRAM &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY &&
	      is_loopback(&e[0].sa46) &&
	      port_of(&e[0].sa46) != port_of(&udp_first.sa46),
	      "udp: another source replaces it, starting as hearsay");

	check(lws_peer_raise(wsi, &udp_first.sa46, LWS_PEER_CRED_ROUTABLE) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_HEARSAY,
	      "udp: evidence about the old source raises nothing now");

	ps_phase_end(NULL);
}

static int
ps_udp_rx_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 4];

	(void)user;
	(void)in;
	(void)len;

	if (reason == LWS_CALLBACK_RAW_WRITEABLE) {
		/* back to whoever sent the last datagram */
		memcpy(buf + LWS_PRE, "back", 4);
		if (lws_write(wsi, buf + LWS_PRE, 4, LWS_WRITE_RAW) != 4)
			ps_phase_end("udp answer failed");
		return 0;
	}

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	switch (udp_rxed++) {
	case 0:
		ps_udp_rx_first(wsi);
		break;
	case 1:
		ps_udp_rx_again(wsi);
		break;
	case 2:
		ps_udp_rx_second(wsi);
		break;
	default:
		break;
	}

	return 0;
}

/* the first sender hears the receiver's answers */
static void
ps_udp_tx1_rx(struct lws *wsi)
{
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];
	int ok;

	ok = lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
	     e[0].kind == LWS_PEER_KIND_SOCKET &&
	     e[0].cred == LWS_PEER_CRED_HEARSAY &&
	     is_loopback(&e[0].sa46) &&
	     (int)port_of(&e[0].sa46) == udp_port;

	if (udp_tx1_rxed++) {
		check(ok, "udp sender: a raise does not cover the next answer");

		/* now a datagram from somewhere else */
		ps_udp_sender("ps-udp-tx2");
		return;
	}

	check(ok, "udp sender: an answer leaves it its own peer, a socket entry");

	check(!lws_peer_raise(wsi, &e[0].sa46, LWS_PEER_CRED_ROUTABLE) &&
	      lws_peer_walk(wsi, e, 1) == 1 &&
	      e[0].cred == LWS_PEER_CRED_ROUTABLE,
	      "udp sender: evidence about the answer raises it");

	/* and send again: the receiver's raise must not cover it either */
	lws_callback_on_writable(wsi);
}

static int
ps_udp_tx_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 4];
	lws_peer_entry_t e[LWS_PEER_WALK_MAX];

	(void)user;
	(void)in;
	(void)len;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		/* a connected datagram socket: who it aims at, as hearsay */
		check(lws_peer_walk(wsi, e, LWS_PEER_WALK_MAX) == 1 &&
		      e[0].cred == LWS_PEER_CRED_HEARSAY &&
		      is_loopback(&e[0].sa46) &&
		      (int)port_of(&e[0].sa46) == udp_port,
		      "udp sender: the address it sends to, as hearsay");
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		memcpy(buf + LWS_PRE, "peer", 4);
		if (lws_write(wsi, buf + LWS_PRE, 4, LWS_WRITE_RAW) != 4)
			ps_phase_end("udp write failed");
		break;

	case LWS_CALLBACK_RAW_RX:
		if (wsi == udp_tx1 && udp_tx1_rxed < 2)
			ps_udp_tx1_rx(wsi);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (wsi == udp_tx1)
			udp_tx1 = NULL;
		break;

	default:
		break;
	}

	return 0;
}
#endif

static const struct lws_protocols ps_srv_protocols[] = {
	{ "ps-srv", ps_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols ps_cli_protocols[] = {
	{ "ps-cli", ps_cli_cb, 0, 0, 0, NULL, 0 },
	{ "ps-http", ps_http_cb, 0, 0, 0, NULL, 0 },
#if defined(LWS_WITH_UDP)
	{ "ps-udp-rx", ps_udp_rx_cb, 0, 0, 0, NULL, 0 },
	{ "ps-udp-tx", ps_udp_tx_cb, 0, 0, 0, NULL, 0 },
#endif
	LWS_PROTOCOL_LIST_TERM
};

static void
ps_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	struct lws_vhost *vh;

	(void)sul;

	do {
		if (++phase == PS_PHASE_COUNT) {
			finished = 1;
			lws_cancel_service(cx);
			return;
		}
	} while (
#if !defined(LWS_WITH_TLS_PASSTHROUGH)
		phase == PS_PHASE_PROXY_V2 ||
#endif
#if !defined(LWS_WITH_UDP)
		phase == PS_PHASE_UDP ||
#endif
#if !defined(PS_UNIX)
		phase == PS_PHASE_UNIX ||
#endif
		0);

	lwsl_user("%s:\n", phase_names[phase]);
	phase_done	= 0;
	srv_checked	= 0;

	lws_sul_schedule(cx, 0, &sul_phase, ps_deadline, PS_PHASE_US);

#if defined(LWS_WITH_UDP)
	if (phase == PS_PHASE_UDP) {
		if (!lws_create_adopt_udp(vh_cli, PS_UDP_ADS, udp_port,
					  LWS_CAUDP_BIND, "ps-udp-rx", NULL,
					  NULL, NULL, NULL, "ps-udp-rx")) {
			ps_phase_end("binding the UDP receiver failed");
			return;
		}
		udp_tx1 = ps_udp_sender("ps-udp-tx1");
		return;
	}
#endif

#if defined(PS_UNIX)
	if (phase == PS_PHASE_UNIX) {
		static const char get[] = "GET / HTTP/1.1\x0d\x0aHost: ps\x0d\x0a"
					  "\x0d\x0a";
		int sv[2];

		/* the request waits in the socketpair for the server */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
			ps_phase_end("socketpair failed");
			return;
		}
		unix_fd = sv[0];
		if (write(sv[0], get, sizeof(get) - 1) !=
						(ssize_t)(sizeof(get) - 1) ||
		    !lws_adopt_socket_vhost(vh_srv, sv[1]))
			/* the adopt closed sv[1] if it failed */
			ps_phase_end("adopting the AF_UNIX connection failed");
		return;
	}
#endif

	vh = phase == PS_PHASE_PROXY_V2 ? vh_pv2 : vh_srv;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh_cli;
	i.address		= server;
	i.host			= server;
	i.port			= lws_get_vhost_listen_port(vh);
	if (phase == PS_PHASE_REDIRECT) {
		i.method		= "GET";
		i.path			= "/redir";
		i.local_protocol_name	= ps_cli_protocols[1].name;
	} else {
		i.method		= "RAW";
		i.protocol		= ps_cli_protocols[0].name;
		i.local_protocol_name	= ps_cli_protocols[0].name;
	}
	i.opaque_user_data	= (void *)(intptr_t)(phase + 1);

	if (!lws_client_connect_via_info(&i))
		ps_phase_end("connect failed");
}

#if defined(LWS_WITH_ACCESS_LOG)

/*
 * The servers' access log, once the context has closed it: a line for the
 * plain connection's GET whose host field is just the address, as it always
 * was, and one for the PROXY v2 connection's with both layers as one field
 */

static void
ps_access_log_line(char *log, int phase_idx, const char *what)
{
	static const char get_ok[] = "] \"GET / HTTP/1.1\" 200 ";
	char want[LWS_PEER_DESC_LEN + 8];
	const char *p = log, *eol;
	size_t wl;

	lws_snprintf(want, sizeof(want), "%s - - [", alog_host[phase_idx]);
	wl = strlen(want);

	while (*p) {
		eol = strchr(p, '\n');
		if (!eol)
			break;
		if (!strncmp(p, want, wl) &&
		    lws_nstrstr(p, lws_ptr_diff_size_t(eol, p),
				get_ok, sizeof(get_ok) - 1)) {
			check(1, what);
			return;
		}
		p = eol + 1;
	}

	check(0, what);
	lwsl_err("        no line starting '%s' in:\n%s\n", want, log);
}

static void
ps_access_log(void)
{
	char log[4096];
	int n;

	lwsl_user("access log:\n");

	n = lws_plat_read_file(alog, log, sizeof(log) - 1);
	if (n <= 0) {
		check(0, "the access log was written");
		return;
	}
	log[n] = '\0';

	check(!!alog_host[PS_PHASE_TCP][0], "the plain connection was seen");
	if (alog_host[PS_PHASE_TCP][0])
		ps_access_log_line(log, PS_PHASE_TCP,
				   "a plain connection's line starts with "
				   "just its address");
#if defined(PS_UNIX)
	check(!!alog_host[PS_PHASE_UNIX][0], "the AF_UNIX connection was seen");
	if (alog_host[PS_PHASE_UNIX][0])
		ps_access_log_line(log, PS_PHASE_UNIX,
				   "an AF_UNIX connection's line starts with "
				   "unix");
#endif
#if defined(LWS_WITH_TLS_PASSTHROUGH)
	check(!!alog_host[PS_PHASE_PROXY_V2][0],
	      "the PROXY v2 connection was seen");
	if (alog_host[PS_PHASE_PROXY_V2][0])
		ps_access_log_line(log, PS_PHASE_PROXY_V2,
				   "a PROXY v2 connection's line starts with "
				   "both layers");
#endif
}
#endif

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int m = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		udp_port = atoi(p);
	else
		udp_port = 7691;
#if defined(LWS_WITH_ACCESS_LOG)
	alog = lws_cmdline_option(argc, argv, "--access-log");
	/* only this run's lines in it */
	if (alog && lws_plat_write_file(alog, (void *)"", 0)) {
		lwsl_err("can't truncate %s\n", alog);
		return 1;
	}
#endif

	lwsl_user("LWS API selftest: peer address stack\n");

	ps_formatter();
	ps_effective();

	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread	= 0;
	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port		= 0;
	info.protocols		= ps_srv_protocols;
	info.vhost_name		= "ps-srv";
#if defined(LWS_WITH_ACCESS_LOG)
	info.log_filepath	= alog;
#endif
	vh_srv = lws_create_vhost(cx, &info);
	if (!vh_srv)
		goto bail;

#if defined(LWS_WITH_TLS_PASSTHROUGH)
	info.vhost_name		= "ps-pv2";
	/* every connection of ours comes from loopback, our "front" */
#if defined(LWS_WITH_IPV6)
	info.proxy_v2_trusted	= "127.0.0.1, ::1";
#else
	info.proxy_v2_trusted	= "127.0.0.1";
#endif
	vh_pv2 = lws_create_vhost(cx, &info);
	if (!vh_pv2)
		goto bail;
	info.proxy_v2_trusted	= NULL;
#endif

#if defined(LWS_WITH_ACCESS_LOG)
	info.log_filepath	= NULL;
#endif
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= ps_cli_protocols;
	info.vhost_name		= "ps-cli";
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(cx, 0, &sul_phase, ps_next, 1);

	while (m >= 0 && !finished)
		m = lws_service(cx, 0);

	if (!finished) {
		lwsl_err("service loop ended early\n");
		fails++;
	}

	lws_sul_cancel(&sul_phase);
	lws_context_destroy(cx);
#if defined(PS_UNIX)
	if (unix_fd >= 0)
		close(unix_fd);
#endif

	/* by the time the context is gone, the server closed it */
	check(srv_tcp_closed, "server: the reset connection was closed");

#if defined(LWS_WITH_ACCESS_LOG)
	/* the vhosts flushed and closed it */
	if (alog)
		ps_access_log();
#endif

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;

bail:
	lwsl_err("setup failed\n");
	lws_context_destroy(cx);

	return 1;
}
