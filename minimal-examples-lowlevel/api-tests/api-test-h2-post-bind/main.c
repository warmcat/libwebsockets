/*
 * lws-api-test-h2-post-bind
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks the protocol callback ordering for a request served by the default
 * protocol fallback on a vhost with no mounts, for every role and method.
 *
 * Whatever carried the request, the protocol taking the transaction must be
 * bound first: LWS_CALLBACK_HTTP_BIND_PROTOCOL with the freshly-made
 * per-session allocation to initialize, before LWS_CALLBACK_HTTP delivers
 * the request, and the matching LWS_CALLBACK_HTTP_DROP_PROTOCOL once the
 * transaction is over.  Code that initializes per-session state at the bind
 * and frees it at the drop depends on that, identically for HTTP/1.1 and
 * HTTP/2 and for GET and POST.
 *
 * HTTP/2 POST requests are dispatched by the h2 role itself rather than by
 * lws_http_action(); a regression on that path skipped the bind for the
 * no-mount case entirely, so the app got LWS_CALLBACK_HTTP on a per-session
 * area no callback had had the chance to initialize (and never saw the
 * matching drop either).
 *
 * Four legs, each a single request from an lws client in the same context to
 * a mountless vhost: h1 GET, h1 POST, h2 GET, h2 POST (cleartext, prior
 * knowledge).  A leg fails unless the server protocol saw exactly
 *
 *   bind -> http [-> body... -> body completion] -> drop
 *
 * against one and the same per-session pointer, with a marker set at the bind
 * still intact when LWS_CALLBACK_HTTP ran.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define BODY_LEN	16
#define PSS_MAGIC	0x600dca11
#define LEG_TIMEOUT_S	20

struct pss_srv {
	uint32_t	magic;
};

/* what the server protocol saw for the leg in flight */

struct seen {
	int		bind, http, drop, body, body_compl;
	void		*bind_user, *http_user, *drop_user;
	int		magic_ok;	/* the bind's marker intact at HTTP */
	size_t		body_bytes;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;

static int port_h1 = 7681;
static int port_h2 = 7682;
static const char *server_addr = "127.0.0.1";

static struct seen seen;
static int cur_leg = -1;
static int result = 1, failures, eval_tries;
static int cli_status, cli_completed, cli_error;

static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_eval;

static const struct leg {
	const char	*name;
	const char	*method;
	int		h2;
} legs[] = {
	{ "h1 GET",	"GET",	0 },
	{ "h1 POST",	"POST",	0 },
#if defined(LWS_ROLE_H2)
	{ "h2 GET",	"GET",	1 },
	{ "h2 POST",	"POST",	1 },
#endif
};

/* ---- server side: the default protocol on a mountless vhost ---- */

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
	struct pss_srv *pss = (struct pss_srv *)user;
	char *uri;
	int n;

	switch (reason) {

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		seen.bind++;
		seen.bind_user = user;
		/* the per-session init this callback exists for */
		pss->magic = PSS_MAGIC;
		break;

	case LWS_CALLBACK_HTTP:
		seen.http++;
		seen.http_user = user;
		seen.magic_ok = pss->magic == PSS_MAGIC;

		lwsl_user("%s: server: HTTP %s\n", __func__,
			  in ? (const char *)in : "");

		if (lws_http_get_uri_and_method(wsi, &uri, &n) == LWSHUMETH_POST)
			/* the body decides the response, wait for it */
			return 0;

		return respond(wsi);

	case LWS_CALLBACK_HTTP_BODY:
		seen.body++;
		seen.body_bytes += len;
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		seen.body_compl++;
		return respond(wsi);

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		seen.drop++;
		seen.drop_user = user;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	/* protocols[0] is the default protocol fallback under test */
	{ "rec", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ---- client side ---- */

static void leg_eval_cb(lws_sorted_usec_list_t *sul);

static void
leg_client_terminal(void)
{
	/*
	 * Give the server side a moment to close its end and deliver the
	 * drop before judging the leg.
	 */
	eval_tries = 0;
	lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t sbuf[LWS_PRE + BODY_LEN], **pp, *end;
	char rbuf[LWS_PRE + 512], *px = &rbuf[LWS_PRE];
	int lenx = sizeof(rbuf) - LWS_PRE, n;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: client: connection error: %s\n", __func__,
			  in ? (const char *)in : "(null)");
		cli_error = 1;
		leg_client_terminal();
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		pp = (uint8_t **)in;
		end = (*pp) + len;

		if (strcmp(legs[cur_leg].method, "POST"))
			break;

		if (lws_add_http_header_content_length(wsi,
						(lws_filepos_t)BODY_LEN,
						pp, end))
			return -1;
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (strcmp(legs[cur_leg].method, "POST"))
			break;

		for (n = 0; n < BODY_LEN; n++)
			sbuf[LWS_PRE + n] = (uint8_t)('a' + n);

		lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, &sbuf[LWS_PRE], BODY_LEN,
			      LWS_WRITE_HTTP_FINAL) != BODY_LEN)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli_status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cli_completed = 1;
		leg_client_terminal();
		/*
		 * We are done with the connection: close it now rather than
		 * leave it idling in keepalive, so the server side delivers
		 * its drop for this leg promptly
		 */
		return -1;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "rec", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* ---- leg sequencing ---- */

static void next_leg(lws_sorted_usec_list_t *sul);

static void
leg_evaluate(void)
{
	const struct leg *l = &legs[cur_leg];
	int ok = 1;

	if (cli_error)
		ok = 0;
	else {
		if (cli_status != HTTP_STATUS_OK) {
			lwsl_err("%s: %s: response status %d\n", __func__,
				 l->name, cli_status);
			ok = 0;
		}
		if (!cli_completed) {
			lwsl_err("%s: %s: response did not complete\n", __func__,
				 l->name);
			ok = 0;
		}
	}

	if (seen.bind != 1) {
		lwsl_err("%s: %s: %d protocol binds, expected 1\n", __func__,
			 l->name, seen.bind);
		ok = 0;
	}
	if (seen.http != 1) {
		lwsl_err("%s: %s: %d LWS_CALLBACK_HTTP, expected 1\n", __func__,
			 l->name, seen.http);
		ok = 0;
	}
	if (!seen.bind_user || seen.bind_user != seen.http_user) {
		lwsl_err("%s: %s: per-session pointer moved between bind and "
			 "http\n", __func__, l->name);
		ok = 0;
	}
	if (seen.http && !seen.magic_ok) {
		lwsl_err("%s: %s: per-session state set at the bind was not "
			 "intact at LWS_CALLBACK_HTTP\n", __func__, l->name);
		ok = 0;
	}
	if (!strcmp(l->method, "POST")) {
		if (seen.body_bytes != BODY_LEN || !seen.body_compl) {
			lwsl_err("%s: %s: server decoded %u body bytes in %d "
				 "completions, expected %d in 1\n", __func__,
				 l->name, (unsigned int)seen.body_bytes,
				 seen.body_compl, BODY_LEN);
			ok = 0;
		}
	} else if (seen.body || seen.body_compl) {
		lwsl_err("%s: %s: GET saw body callbacks\n", __func__, l->name);
		ok = 0;
	}
	if (seen.drop != 1 || seen.drop_user != seen.bind_user) {
		lwsl_err("%s: %s: %d protocol drops, expected 1 on the same "
			 "per-session pointer\n", __func__, l->name,
			 seen.drop);
		ok = 0;
	}

	lwsl_user("--- %s: %s ---\n", l->name, ok ? "PASS" : "FAIL");
	if (!ok)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_leg,
			 100 * LWS_US_PER_MS);
}

static void
leg_eval_cb(lws_sorted_usec_list_t *sul)
{
	/*
	 * The client has closed its end; the server's drop follows the FIN.
	 * It should not take long, but a loaded CI box can need a few spins
	 * of the loop, so poll for it a little before judging.
	 */

	if (!seen.drop && !cli_error && eval_tries++ < 40) {
		lws_sul_schedule(context, 0, &sul_eval, leg_eval_cb,
				 50 * LWS_US_PER_MS);

		return;
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
	struct lws_client_connect_info i;

	cur_leg++;

	if (cur_leg == (int)LWS_ARRAY_SIZE(legs)) {
		result = failures ? 1 : 0;
		lws_default_loop_exit(context);

		return;
	}

	lwsl_user("=== leg %d: %s ===\n", cur_leg, legs[cur_leg].name);

	memset(&seen, 0, sizeof(seen));
	cli_status = 0;
	cli_completed = 0;
	cli_error = 0;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 LEG_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost		= vh_cli;
	i.address		= server_addr;
	i.host		= server_addr;
	i.origin		= server_addr;
	i.port		= legs[cur_leg].h2 ? port_h2 : port_h1;
	i.path		= "/";
	i.method		= legs[cur_leg].method;
	i.protocol		= "rec";
#if defined(LWS_ROLE_H2)
	if (legs[cur_leg].h2)
		i.ssl_connection |= LCCSCF_H2_PRIOR_KNOWLEDGE;
#endif

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		failures++;
		lws_sul_schedule(context, 0, &sul_next, next_leg, 1);
	}
}

void sigint_handler(int sig)
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
	 * The defaults budget 8 fds per thread, sized for a lone client.  We
	 * have four listen sockets (h1 + h2, v4 + v6) plus the system fds, and
	 * legs can overlap with the previous leg's closing connection.
	 */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: protocol bind ordering on a mountless "
		  "vhost\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* h1 server vhost, no mounts: everything falls through to rec */

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_ROLE_H2)
	/* h2 server vhost, cleartext with prior knowledge, no mounts either */

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
