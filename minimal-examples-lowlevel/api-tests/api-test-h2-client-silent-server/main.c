/*
 * lws-api-test-h2-client-silent-server
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h2 client connection whose transport is up, but which goes away before
 * the server's SETTINGS arrived, must still tell the user it failed.
 *
 * Until the server's SETTINGS comes, the user's request has not been moved on
 * to its own stream: the network connection is still the user's wsi, and
 * there is no child stream to report anything for it.  A close then, by
 * timeout, by the server hanging up, or by lws culling the connection when
 * its route changes, used to say nothing at all, leaving the user waiting
 * forever on a connection that no longer exists.
 *
 * The "server" is a raw tcp fixture that takes the client's h2 preface and
 * never answers it.  In the first leg it stays silent until the client's
 * timeout_secs closes the connection, in the second it hangs up as soon as
 * the preface arrives.  Both legs must end in CLIENT_CONNECTION_ERROR.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define SS_TIMEOUT_S		2	/* context timeout_secs */
#define SS_WATCHDOG_S		10	/* per leg */
#define SS_H2_PREFACE_LEN	24

enum {
	SS_LEG_SILENT,		/* never answers, client times out */
	SS_LEG_HANGUP,		/* closes on getting the preface */

	SS_LEG_COUNT
};

static const char * const leg_names[] = {
	"server stays silent",
	"server hangs up after the preface",
};

/* one fixture connection */
struct fx_pss {
	size_t			rxlen;
};

static struct {
	lws_usec_t	start;
	uint8_t		error;
	uint8_t		established;
	uint8_t		closed;
} cli;

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog, sul_next;
static int result, port = 7681, leg, done;
static const char *server_addr = "127.0.0.1";

static void
finish(int fail)
{
	if (done)
		return;
	done = 1;
	result |= fail;
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_default_loop_exit(context);
}

/*
 * the fixture
 */

static int
callback_fx(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct fx_pss *p = (struct fx_pss *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		/* whatever the client sends, nothing ever comes back */
		p->rxlen += len;
		if (leg == SS_LEG_HANGUP && p->rxlen >= SS_H2_PREFACE_LEN) {
			lwsl_user("%s: fixture: hanging up\n", __func__);
			return -1;
		}
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
start_leg(void);

static void
next_leg_cb(lws_sorted_usec_list_t *sul)
{
	if (++leg == SS_LEG_COUNT) {
		finish(0);
		return;
	}

	start_leg();
}

static void
leg_result(int fail, const char *why)
{
	lwsl_user("%s: leg %d (%s): %s%s%s\n", __func__, leg, leg_names[leg],
		  fail ? "FAIL" : "PASS", why ? ": " : "", why ? why : "");
	lws_sul_cancel(&sul_watchdog);

	if (fail) {
		finish(1);
		return;
	}

	/* the next leg from the event loop, not from inside this close */
	lws_sul_schedule(context, 0, &sul_next, next_leg_cb, 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	leg_result(1, "the client was never told anything");
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: connection error: %s, after %dms\n", __func__,
			  in ? (const char *)in : "(null)",
			  (int)((lws_now_usecs() - cli.start) / LWS_US_PER_MS));
		if (cli.error || cli.closed) {
			leg_result(1, "told twice");
			break;
		}
		cli.error = 1;
		leg_result(cli.established, cli.established ?
				"established with no SETTINGS" : NULL);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.established = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (cli.error || cli.closed || done)
			break;
		cli.closed = 1;
		/* he heard about it, but it never was established */
		leg_result(1, "CLOSED, not CONNECTION_ERROR");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
start_leg(void)
{
	struct lws_client_connect_info i;

	lwsl_user("%s: leg %d: %s\n", __func__, leg, leg_names[leg]);

	memset(&cli, 0, sizeof(cli));
	cli.start = lws_now_usecs();

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 SS_WATCHDOG_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = port;
	i.path = "/";
	i.method = "GET";
	i.protocol = "h2-silent-server";
	i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;

	if (!lws_client_connect_via_info(&i))
		/* a failure inside the call has already been told */
		if (!cli.error && !cli.closed)
			leg_result(1, "connect failed");
}

static const struct lws_protocols protocols_srv[] = {
	{ "silent-h2", callback_fx, sizeof(struct fx_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "h2-silent-server", callback_cli, 0, 0, 0, NULL, 0 },
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
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;
	info.timeout_secs = SS_TIMEOUT_S;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: h2 client told when it goes away before "
		  "the server's SETTINGS\n");

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
	info.listen_accept_protocol = "silent-h2";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create fixture vhost\n");
		result = 1;
		goto bail;
	}

	/* client vhost, no listener */

	info.options &= ~(uint64_t)
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		result = 1;
		goto bail;
	}

	start_leg();

	while (!done && !lws_service(context, 0))
		;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
