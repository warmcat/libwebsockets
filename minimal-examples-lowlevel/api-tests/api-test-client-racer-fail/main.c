/*
 * lws-api-test-client-racer-fail
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A client connection racing its address families (happy eyeballs, RFC 8305)
 * has two sockets in flight, the primary and the racer, and only one wsi.
 * While the racer is being started, its socket is swapped into the wsi and
 * the primary's is held aside, and once a racer wins it becomes the primary.
 * This tests that a connection failing on those paths closes both sockets
 * and leaves nothing pointing at the wsi it frees (GitHub PR #3695).
 *
 * A raw client connects to our own raw listener, on every address
 * "localhost" has, with fault injection starting each racer straight after
 * the primary (`he_race_fast`), so that it exists while the primary is
 * still connecting.  For each scenario, the connection must fail, telling
 * the client once, and then every connection the listener accepted from it
 * must be closed: a socket the client lost track of stays connected.
 *
 *  - the app's LWS_CALLBACK_CONNECTING refuses the racer, the second
 *    attempt.  The racer's socket was still in the wsi then, and the close
 *    lost the primary's, still in the fds table pointing at the freed wsi.
 *
 *  - each attempt that connects is refused as having an incompatible IPv6
 *    source scope (fault injection `conn_scope_rej`).  On FreeBSD, a racer
 *    connecting to loopback can connect inside connect() and is promoted at
 *    once: its refusal then "restored" the primary already closed at the
 *    promotion.  Linux never connects synchronously, so there it covers
 *    the refusal of an attempt that connected later.
 *
 * Where "localhost" has only one address family there is no racer and the
 * first scenario can't happen; it is reported and skipped.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

/* how long the listener's connections get to be closed after the failure */
#define SETTLE_US	(3 * LWS_US_PER_SEC)
#define DEADLINE_US	(20 * LWS_US_PER_SEC)

enum {
	SC_REJECT_RACER_CONNECTING,
	SC_REJECT_CONNECTED,

	SC_COUNT
};

static const char * const sc_names[] = {
	"app refuses the racer's CONNECTING",
	"every attempt that connects is refused (conn_scope_rej)",
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_settle, sul_deadline;
static const char *server_address = "localhost";
static int port = 7681, result = 1, scenario = -1, finished;
static int connecting, errors, connected, srv_live;
static lws_usec_t settle_start;

static void
destroy_cb(lws_sorted_usec_list_t *sul)
{
	/*
	 * Not lws_default_loop_exit(): with an event lib like libuv, service
	 * only returns once the context is destroyed
	 */
	lws_context_destroy(context);
	context = NULL;
}

static void
finish(int pass)
{
	if (finished)
		return;

	finished = 1;
	result = !pass;
	lws_sul_schedule(context, 0, &sul_next, destroy_cb, 1);
}

static void
fail(const char *why)
{
	lwsl_err("--- scenario %d \"%s\": %s ---\n", scenario,
		 scenario >= 0 ? sc_names[scenario] : "", why);
	finish(0);
}

static void
next_scenario(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	lws_fi_t fi;

	if (++scenario == SC_COUNT) {
		lwsl_user("--- all scenarios passed ---\n");
		finish(1);
		return;
	}

	connecting = errors = connected = 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.host			= server_address;
	i.port			= port;
	i.method		= "RAW";
	i.protocol		= "racer";
	i.local_protocol_name	= "racer";

	/* start the racer while the primary is still connecting */
	memset(&fi, 0, sizeof(fi));
	fi.name = "he_race_fast";
	fi.type = LWSFI_ALWAYS;
	if (lws_fi_add(&i.fic, &fi)) {
		fail("fi add failed");
		return;
	}
	if (scenario == SC_REJECT_CONNECTED) {
		fi.name = "conn_scope_rej";
		if (lws_fi_add(&i.fic, &fi)) {
			lws_fi_destroy(&i.fic);
			fail("fi add failed");
			return;
		}
	}

	lwsl_user("scenario %d: %s\n", scenario, sc_names[scenario]);

	if (!lws_client_connect_via_info(&i)) {
		/* the client wsi takes the faults, unless there wasn't one */
		lws_fi_destroy(&i.fic);
		/*
		 * Failing inside the call is fine as long as it told us, which
		 * it did before returning: CLIENT_CONNECTION_ERROR started the
		 * settle wait already
		 */
		if (!errors)
			fail("connect failed without telling us");
	}
}

/*
 * After the client heard its connection failed, every connection the
 * listener accepted from it must close, since the client closed every
 * socket it had
 */

static void
settle_check(lws_sorted_usec_list_t *sul)
{
	if (!srv_live) {
		lwsl_user("scenario %d: failed once, %d attempts, nothing "
			  "left connected\n", scenario, connecting);
		lws_sul_schedule(context, 0, &sul_next, next_scenario, 1);
		return;
	}

	if (lws_now_usecs() - settle_start > SETTLE_US) {
		lwsl_err("%d accepted connections still open\n", srv_live);
		fail("the client left a socket connected");
		return;
	}

	lws_sul_schedule(context, 0, &sul_settle, settle_check,
			 10 * LWS_US_PER_MS);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CONNECTING:
		/* one for each attempt: the second is the racer */
		connecting++;
		if (scenario == SC_REJECT_RACER_CONNECTING && connecting == 2) {
			lwsl_user("refusing attempt 2, the racer\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		connected++;
		if (scenario == SC_REJECT_RACER_CONNECTING && connecting == 1) {
			/* nothing raced it: the scenario can't happen here */
			lwsl_user("scenario %d: not applicable, \"%s\" has only "
				  "one address family\n", scenario,
				  server_address);
			lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
			settle_start = lws_now_usecs();
			lws_sul_schedule(context, 0, &sul_settle, settle_check,
					 10 * LWS_US_PER_MS);
			break;
		}
		fail("connected although it should have failed");
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("connection error: %s\n",
			  in ? (const char *)in : "(none)");
		if (++errors != 1) {
			fail("told of the failure more than once");
			break;
		}
		settle_start = lws_now_usecs();
		lws_sul_schedule(context, 0, &sul_settle, settle_check,
				 10 * LWS_US_PER_MS);
		break;

	default:
		break;
	}

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		srv_live++;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		srv_live--;
		break;

	default:
		break;
	}

	return 0;
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	fail("timed out");
}

static const struct lws_protocols protocols_srv[] = {
	{ "racer-srv", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "racer", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: client happy eyeballs racer failures\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	if (lws_cmdline_option(argc, argv, "--uv"))
		/* event libs keep watchers of their own for each racer */
		info.options |= LWS_SERVER_OPTION_LIBUV;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the listener, on every address family */
	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols_srv;
	info.options			= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "racer-srv";
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name			= "cli";
	info.protocols			= protocols_cli;
	info.options			= 0;
	info.listen_accept_role		= NULL;
	info.listen_accept_protocol	= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_scenario, 1);
	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb, DEADLINE_US);

	while (context && lws_service(context, 0) >= 0)
		;

bail:
	if (context)
		lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
