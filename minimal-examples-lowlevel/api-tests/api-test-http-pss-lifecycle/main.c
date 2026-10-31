/*
 * lws-api-test-http-pss-lifecycle
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks that LWS_CALLBACK_HTTP_BIND_PROTOCOL and
 * LWS_CALLBACK_HTTP_DROP_PROTOCOL bracket every per-transaction allocation
 * (pss) an http server protocol is given, over several transactions riding
 * one connection (G-556).
 *
 * The server protocols allocate a resource in the pss at LWS_CALLBACK_HTTP
 * and free it at LWS_CALLBACK_HTTP_DROP_PROTOCOL, the way an app keeps an
 * lws_spa, an fd or an lwsac for the transaction.  That is only safe if
 *
 *  - BIND reaches the protocol before any other callback carrying the pss,
 *  - DROP follows every BIND exactly once, before the pss is freed: at the
 *    end of a keepalive transaction, when another protocol is bound, or when
 *    the connection closes.
 *
 * The requests the vhost's protocols[0] answers itself are the ones that used
 * to miss out: a path in a file mount with no such file falls through to
 * protocols[0]'s LWS_CALLBACK_HTTP (as the form examples' /form1 does), and
 * the first transaction of an h1 connection, or any h2 stream, reached it
 * with a pss that was never bound, so no DROP ever came for it and the
 * resource leaked.  A protocol bound by a callback mount always got its
 * BIND / DROP pair; that must not change.
 *
 * Legs, each a series of GET and POST requests from an lws client in the
 * same process, all riding one kept-warm connection:
 *
 *  - h1 to a path in the file mount answered by protocols[0]
 *  - h1 to a callback mount bound to its own protocol
 *  - the same two over h2 (cleartext, prior knowledge), each request a stream
 *
 * After each leg's connection has closed, the protocol under test must have
 * seen LWS_CALLBACK_HTTP for every request, each on a pss that had been bound
 * and was then dropped exactly once, with every resource freed, and no
 * callback on a pss that had not been bound.  The leg also checks every
 * request rode the same server connection.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define BODY_LEN	16
#define LEG_TIMEOUT_S	20
#define KEEP_WARM_S	1

enum {
	PSS_UNBOUND,		/* zeroed by lws: no BIND seen yet */
	PSS_BOUND,
	PSS_DROPPED,
};

struct pss_srv {
	char		*res;		/* the transaction's resource */
	uint8_t		state;
	uint8_t		had_http;	/* this pss carried a request */
	uint8_t		respond;	/* we asked for WRITEABLE to answer */
};

/* what one server protocol saw during the leg in flight */

struct pstats {
	const char	*name;
	int		bind, drop, http;
	int		drop_of_txn;	/* DROPs of a pss that carried a request */
	int		unbound_use;	/* callback on a pss that had no BIND */
	int		bad_bind;	/* BIND on a pss already bound */
	int		bad_drop;	/* DROP on a pss that was not bound */
	int		reused;		/* request on a pss that had one before */
	int		live;		/* resources allocated and not freed */
};

static struct pstats st_pcol0 = { .name = "pcol0" }, st_mnt = { .name = "mnt" };

static struct lws_context *context;
static struct lws_vhost *vh_cli;

static int port_h1 = 7681;
static int port_h2 = 7682;
static const char *server_addr = "127.0.0.1";

static int result = 1, failures, cur_leg = -1, eval_tries;
static int conn_next_id, conn_first_id, conns_gone, reqs_done, cli_failed;

static lws_sorted_usec_list_t sul_next, sul_req, sul_watchdog, sul_eval;

static const struct leg {
	const char	*name;
	const char	*path;
	struct pstats	*st;		/* the protocol taking the requests */
	int		h2;
	int		nreq;
} legs[] = {
	{ "h1 keepalive, protocols[0] via file mount", "/form1", &st_pcol0, 0, 4 },
	{ "h1 keepalive, callback mount",	 "/mnt/x", &st_mnt,   0, 3 },
#if defined(LWS_ROLE_H2)
	{ "h2 streams, protocols[0] via file mount",   "/form1", &st_pcol0, 1, 4 },
	{ "h2 streams, callback mount",		 "/mnt/x", &st_mnt,   1, 3 },
#endif
};

static const char *
req_method(int n)
{
	/* alternate, so each leg has both bodyless and body transactions */
	return (n & 1) ? "POST" : "GET";
}

/* ---- server side ---- */

static int
respond(struct lws *wsi)
{
	static const char body[] = "ok\n";
	uint8_t hbuf[LWS_PRE + 256], *start = &hbuf[LWS_PRE], *p = start,
		*end = &hbuf[sizeof(hbuf) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)sizeof(body) - 1,
					&p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	memcpy(start, body, sizeof(body) - 1);

	if (lws_write(wsi, start, sizeof(body) - 1,
		      LWS_WRITE_HTTP_FINAL) != (int)(sizeof(body) - 1))
		return 1;

	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	const struct lws_protocols *pcol = lws_get_protocol(wsi);
	struct pstats *s = pcol ? (struct pstats *)pcol->user : NULL;
	struct pss_srv *pss = (struct pss_srv *)user;
	struct lws *nwsi;
	char *uri;
	int n;

	switch (reason) {

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (!s || !pss)
			break;
		s->bind++;
		if (pss->state != PSS_UNBOUND)
			s->bad_bind++;
		pss->state = PSS_BOUND;
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (!s || !pss)
			break;
		s->drop++;
		if (pss->state != PSS_BOUND)
			s->bad_drop++;
		if (pss->had_http)
			s->drop_of_txn++;
		if (pss->res) {
			free(pss->res);
			pss->res = NULL;
			s->live--;
		}
		pss->state = PSS_DROPPED;
		break;

	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLOSED_HTTP:
		/* any callback given a pss must come after its BIND */
		if (s && pss && pss->state == PSS_UNBOUND) {
			lwsl_wsi_err(wsi, "%s: reason %d on an unbound pss",
				     s->name, (int)reason);
			s->unbound_use++;
		}
		break;

	case LWS_CALLBACK_HTTP:
		if (!s || !pss) {
			lwsl_wsi_err(wsi, "request with no protocol or pss");
			cli_failed = 1;
			return -1;
		}
		s->http++;
		if (pss->state != PSS_BOUND) {
			lwsl_wsi_err(wsi, "%s: LWS_CALLBACK_HTTP on a pss with "
				     "no BIND", s->name);
			s->unbound_use++;
		}
		if (pss->had_http)
			s->reused++;
		pss->had_http = 1;

		/*
		 * Stamp the network connection the first time it brings us a
		 * request: for h1 that is the connection wsi itself, for h2
		 * the parent of the stream
		 */
		nwsi = lws_get_network_wsi(wsi);
		if (!lws_get_opaque_user_data(nwsi))
			lws_set_opaque_user_data(nwsi,
					(void *)(intptr_t)++conn_next_id);

		/* the per-transaction resource DROP is responsible for */
		pss->res = malloc(64);
		if (!pss->res)
			return -1;
		s->live++;

		lwsl_user("%s: %s: HTTP %s\n", __func__, s->name,
			  in ? (const char *)in : "");

		if (lws_http_get_uri_and_method(wsi, &uri, &n) == LWSHUMETH_POST)
			/* answer once the body is in */
			return 0;

		pss->respond = 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_WSI_DESTROY:
		/*
		 * A stamped network connection going away: a mux stream's
		 * network wsi is its parent, so streams are not counted
		 */
		if (lws_get_network_wsi(wsi) == wsi &&
		    lws_get_opaque_user_data(wsi))
			conns_gone++;
		break;

	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (pss) {
			pss->respond = 1;
			lws_callback_on_writable(wsi);
		}
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->respond)
			/* not one we asked for: nothing to answer yet */
			return 0;
		pss->respond = 0;
		return respond(wsi);

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	/* protocols[0]: takes whatever the mounts don't bind elsewhere */
	{ "pcol0", callback_srv, sizeof(struct pss_srv), 0, 0, &st_pcol0, 0 },
	{ "mnt", callback_srv, sizeof(struct pss_srv), 0, 0, &st_mnt, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount_mnt = {
	.mountpoint		= "/mnt",
	.origin			= "mnt",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

/*
 * Files from the test's own directory: the requests name a file that is not
 * there, so the file mount hands them to protocols[0]'s LWS_CALLBACK_HTTP
 */
static const struct lws_http_mount mount_files = {
	.mount_next		= &mount_mnt,
	.mountpoint		= "/",
	.origin			= ".",
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

/* ---- client side ---- */

static void req_cb(lws_sorted_usec_list_t *sul);
static void leg_eval_cb(lws_sorted_usec_list_t *sul);

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t sbuf[LWS_PRE + BODY_LEN], **pp, *end;
	char rbuf[LWS_PRE + 512], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n, post;

	post = !strcmp(req_method(reqs_done), "POST");

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!post)
			break;
		pp = (uint8_t **)in;
		end = (*pp) + len;
		if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)BODY_LEN,
						pp, end))
			return -1;
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!post)
			break;
		for (n = 0; n < BODY_LEN; n++)
			sbuf[LWS_PRE + n] = (uint8_t)('a' + n);
		lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, &sbuf[LWS_PRE], BODY_LEN,
			      LWS_WRITE_HTTP_FINAL) != BODY_LEN)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		n = (int)lws_http_client_http_response(wsi);
		/* joining a warm h2 connection is ESTABLISHED with no status */
		if (n && n != HTTP_STATUS_OK) {
			lwsl_err("%s: client: status %d\n", __func__, n);
			cli_failed = 1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		reqs_done++;
		if (reqs_done < legs[cur_leg].nreq)
			/* the next request rides the kept-warm connection */
			lws_sul_schedule(context, 0, &sul_req, req_cb, 1);
		else
			/*
			 * The connection idles out of its keep-warm and
			 * closes: the server then drops the pss it bound
			 * for a next request that never came
			 */
			lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
					 50 * LWS_US_PER_MS);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ---- leg sequencing ---- */

static void next_leg(lws_sorted_usec_list_t *sul);

static void
req_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= legs[cur_leg].h2 ? port_h2 : port_h1;
	i.path			= legs[cur_leg].path;
	i.method		= req_method(reqs_done);
	i.protocol		= "cli";
	i.keep_warm_secs	= KEEP_WARM_S;
	i.ssl_connection	= LCCSCF_PIPELINE;
#if defined(LWS_ROLE_H2)
	if (legs[cur_leg].h2)
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
#endif

	lwsl_user("%s: request %d: %s %s\n", __func__, reqs_done, i.method,
		  i.path);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		cli_failed = 1;
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
	}
}

static int
check(const char *leg, const struct pstats *s, const char *what, int got,
      int want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: %s: %s: %s %d, expected %d\n", __func__, leg, s->name,
		 what, got, want);

	return 1;
}

static int
check_protocol(const char *leg, const struct pstats *s, int nreq)
{
	int f = 0;

	lwsl_user("%s: %s: bind %d, drop %d, http %d, drops of a request's "
		  "pss %d\n", leg, s->name, s->bind, s->drop, s->http,
		  s->drop_of_txn);

	f |= check(leg, s, "requests", s->http, nreq);
	f |= check(leg, s, "drops of a transaction's pss", s->drop_of_txn,
		   nreq);
	f |= check(leg, s, "drops minus binds", s->drop - s->bind, 0);
	f |= check(leg, s, "callbacks on an unbound pss", s->unbound_use, 0);
	f |= check(leg, s, "binds of a bound pss", s->bad_bind, 0);
	f |= check(leg, s, "drops of an unbound pss", s->bad_drop, 0);
	f |= check(leg, s, "requests on a reused pss", s->reused, 0);
	f |= check(leg, s, "resources leaked", s->live, 0);

	return f;
}

static void
leg_evaluate(void)
{
	const struct leg *l = &legs[cur_leg];
	int ok = !cli_failed;

	lws_sul_cancel(&sul_watchdog);

	if (reqs_done != l->nreq) {
		lwsl_err("%s: %s: %d of %d requests completed\n", __func__,
			 l->name, reqs_done, l->nreq);
		ok = 0;
	}

	/* every request rode the one connection */
	if (conn_next_id - conn_first_id != 1) {
		lwsl_err("%s: %s: requests came on %d server connections, "
			 "expected 1\n", __func__, l->name,
			 conn_next_id - conn_first_id);
		ok = 0;
	}

	if (check_protocol(l->name, l->st, l->nreq))
		ok = 0;

	/*
	 * On a callback mount, protocols[0] still holds the pss between
	 * transactions, and the gates' callbacks for each request: whatever
	 * it was bound for, it must be dropped
	 */
	if (l->st == &st_mnt &&
	    check_protocol(l->name, &st_pcol0, 0))
		ok = 0;

	lwsl_user("--- %s: %s ---\n", l->name, ok ? "PASS" : "FAIL");
	if (!ok)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_leg, 1);
}

static void
leg_eval_cb(lws_sorted_usec_list_t *sul)
{
	int conns = conn_next_id - conn_first_id;

	/*
	 * Wait for the leg's connection to be closed on the server side, its
	 * last pss dropped with it, before judging
	 */
	if (!cli_failed && (!conns || conns_gone < conns)) {
		if (eval_tries++ < (KEEP_WARM_S + 5) * 20) {
			lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
					 50 * LWS_US_PER_MS);
			return;
		}
		lwsl_err("%s: server connection did not close\n", __func__);
		cli_failed = 1;
	}

	leg_evaluate();
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: leg did not complete\n", __func__);
	failures++;
	result = 1;
	lws_default_loop_exit(context);
}

static void
next_leg(lws_sorted_usec_list_t *sul)
{
	struct pstats *s[] = { &st_pcol0, &st_mnt };
	size_t n;

	cur_leg++;

	if (cur_leg == (int)LWS_ARRAY_SIZE(legs)) {
		result = failures ? 1 : 0;
		lws_default_loop_exit(context);

		return;
	}

	lwsl_user("=== leg %d: %s ===\n", cur_leg, legs[cur_leg].name);

	/* each leg is judged on what it alone did */
	for (n = 0; n < LWS_ARRAY_SIZE(s); n++) {
		const char *name = s[n]->name;

		memset(s[n], 0, sizeof(*s[n]));
		s[n]->name = name;
	}

	reqs_done = 0;
	cli_failed = 0;
	eval_tries = 0;
	conn_first_id = conn_next_id;
	conns_gone = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 LEG_TIMEOUT_S * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_req, req_cb, 1);
}

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
	/* listeners (h1 + h2, v4 + v6) and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: http pss BIND / DROP lifecycle\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;
	info.mounts = &mount_files;

	info.port = port_h1;
	info.vhost_name = "srv-h1";

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_ROLE_H2)
	info.port = port_h2;
	info.vhost_name = "srv-h2";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h2 server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	/* client vhost, no listener */

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	result = 1;
	lws_sul_schedule(context, 0, &sul_next, next_leg, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d legs failed)\n",
		  result ? "FAIL" : "PASS", failures,
		  (int)LWS_ARRAY_SIZE(legs));

	return result;
}
