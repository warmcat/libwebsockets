/*
 * lws-api-test-openmetrics-prox
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The "lws-openmetrics-prox-server" half of the openmetrics proxy collects a
 * joined client's metrics dump, one ws message that may come in many
 * fragments, into an lwsac with a chunk per fragment.  What one client's dump
 * may make the server hold is capped, and the cap has to bound the memory the
 * chunks really take, not only their payload (G-250):
 *
 *  - a dump of one byte followed by many empty continuation fragments: they
 *    carry nothing, and must not cost the server anything;
 *
 *  - a dump sent as many one-byte fragments: the server must drop the client
 *    once the chunks reach the cap, long before their payload would.
 *
 * The plugin is built in, and its server protocol is wrapped so the test can
 * see what the dump holds after each fragment the server is given.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_openmetrics_export.c"

/* fragments sent after the first, in each case */
#define OMP_FRAGMENTS		40000
/* fragments written per WRITEABLE */
#define OMP_BATCH		64
#define OMP_CASE_US		(20 * LWS_US_PER_SEC)

enum {
	CASE_EMPTY,
	CASE_ONE_BYTE,

	CASE_COUNT
};

static const char * const case_names[] = {
	"a dump continued by empty fragments",
	"a dump sent as one-byte fragments",
};

static struct lws_context *cx;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server = "localhost";
static int port, tcase = -1, fails, finished;

/* what the server side made of the current case */
static unsigned int srv_rx;	/* dump fragments it was given */
static uint64_t srv_peak;	/* the most its lwsac for the dump held */
static char judged;

/* the client side of the current case */
static unsigned int cli_sent;
static char cli_greeted;

static void
finish(void)
{
	if (finished)
		return;
	finished = 1;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_default_loop_exit(cx);
}

static void
fail(const char *why)
{
	lwsl_err("case %d (%s): %s\n", tcase, case_names[tcase], why);
	fails++;
	finish();
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	fail("timed out");
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++tcase == CASE_COUNT) {
		finish();
		return;
	}

	lwsl_user("%s: case %d: %s\n", __func__, tcase, case_names[tcase]);

	srv_rx = 0;
	srv_peak = 0;
	judged = 0;
	cli_sent = 0;
	cli_greeted = 0;

	lws_sul_schedule(cx, 0, &sul_watchdog, watchdog_cb, OMP_CASE_US);

	memset(&i, 0, sizeof(i));
	i.context	= cx;
	i.vhost		= vh_cli;
	i.address	= server;
	i.host		= server;
	i.origin	= server;
	i.port		= port;
	i.path		= "/";
	i.protocol	= "lws-openmetrics-prox-server";

	if (!lws_client_connect_via_info(&i))
		fail("connect failed");
}

/*
 * The server's prox-server protocol, as the plugin has it, but looking at what
 * the client's dump holds after each fragment it is given.  Once the case is
 * judged, the server drops the client, and the next case starts when the
 * client sees its close.
 */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint64_t held;
	int greet, n;

	greet = reason == LWS_CALLBACK_RECEIVE && pss && pss->greet;

	n = callback_lws_openmetrics_prox_server(wsi, reason, user, in, len);

	if (reason != LWS_CALLBACK_RECEIVE || greet || !pss || finished)
		return n;

	if (judged)
		return -1;

	srv_rx++;
	held = lwsac_total_alloc(pss->ac);
	if (held > srv_peak)
		srv_peak = held;

	if (srv_peak > OM_MAX_DUMP_SIZE) {
		lwsl_err("%s: dump holds %llu after %u fragments\n", __func__,
			 (unsigned long long)srv_peak, srv_rx);
		fail("the dump took more memory than the cap");

		return -1;
	}

	switch (tcase) {
	case CASE_EMPTY:
		if (n) {
			fail("dropped for fragments that carry nothing");
			return -1;
		}
		if (srv_rx < 1 + OMP_FRAGMENTS)
			return 0;
		lwsl_user("%s: %u fragments held in %llu\n", __func__,
			  srv_rx, (unsigned long long)srv_peak);
		break;

	case CASE_ONE_BYTE:
		if (!n) {
			if (srv_rx == 1 + OMP_FRAGMENTS)
				fail("never dropped at the cap");
			return 0;
		}
		lwsl_user("%s: dropped after %u fragments holding %llu\n",
			  __func__, srv_rx, (unsigned long long)srv_peak);
		break;
	}

	judged = 1;

	return -1;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 16];
	size_t l;
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: %s\n", __func__, in ? (const char *)in : "?");
		fail("connection error");
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (!cli_greeted) {
			/* the path the scraper would ask for us by */
			l = (size_t)lws_snprintf((char *)buf + LWS_PRE,
						 sizeof(buf) - LWS_PRE,
						 "omp-%d", tcase);
			if (lws_write(wsi, buf + LWS_PRE, l,
				      LWS_WRITE_TEXT) < (int)l)
				return -1;
			cli_greeted = 1;
			lws_callback_on_writable(wsi);
			break;
		}

		for (n = 0; n < OMP_BATCH && cli_sent <= OMP_FRAGMENTS; n++) {
			/* the dump is never finished */
			l = (size_t)(!cli_sent || tcase == CASE_ONE_BYTE);
			/* the client masks its payload in place */
			buf[LWS_PRE] = 'x';
			if (lws_write(wsi, buf + LWS_PRE, l,
				      (enum lws_write_protocol)
				      lws_write_ws_flags(LWS_WRITE_TEXT,
							 !cli_sent, 0)) < (int)l)
				return -1;
			cli_sent++;
			if (lws_send_pipe_choked(wsi))
				break;
		}

		if (cli_sent <= OMP_FRAGMENTS)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		if (finished)
			break;
		if (!judged) {
			fail("closed before the case was judged");
			break;
		}
		lws_sul_schedule(cx, 0, &sul_next, next_case, 1);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_LWS_OPENMETRICS_EXPORT,
	LWS_PLUGIN_PROTOCOL_LWS_OPENMETRICS_PROX_AGG,
	{ "lws-openmetrics-prox-server", callback_srv, sizeof(struct pss),
	  1024, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_LWS_OPENMETRICS_PROX_CLIENT,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "lws-openmetrics-prox-server", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	static const struct lws_protocol_vhost_options pvo_bind = {
		NULL, NULL, "proxy-side-bind-name", "omp"
	}, pvo = {
		NULL, &pvo_bind, "lws-openmetrics-prox-server", ""
	};
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we are both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	lwsl_user("LWS API selftest: openmetrics proxy server dump cap\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	info.vhost_name	= "om-server";
	info.port	= 0;
	info.protocols	= protocols_srv;
	info.pvo	= &pvo;
	vh = lws_create_vhost(cx, &info);
	if (!vh)
		goto bail;
	port = lws_get_vhost_listen_port(vh);

	info.vhost_name	= "om-client";
	info.port	= CONTEXT_PORT_NO_LISTEN;
	info.protocols	= protocols_cli;
	info.pvo	= NULL;
	vh_cli = lws_create_vhost(cx, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(cx, 0, &sul_next, next_case, 1);

	while (n >= 0 && !finished)
		n = lws_service(cx, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(cx);

	if (fails || tcase != CASE_COUNT) {
		lwsl_user("Completed: failed\n");

		return 1;
	}

	lwsl_user("Completed: OK\n");

	return 0;
}
