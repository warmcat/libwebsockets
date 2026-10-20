/*
 * lws-api-test-listen-any-port
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A server vhost asking for any free port (info.port 0) on a dual-stack
 * build listens on IPv4 and IPv6.  The first address family's bind chooses
 * the port, and the other family's bind must take the same port number,
 * which something else may already have in that family: on Sai's macOS, a
 * test's vhost failed to come up with EADDRINUSE that way.  lws must give
 * that port up and start again with another.
 *
 * The vhost here is given the "listen_port_taken" fault once, so the second
 * family's bind finds the port taken.  It must still come up, on a port both
 * families listen on: a client of 127.0.0.1 and one of ::1 must each get an
 * http response from it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LAP_TIMEOUT_S		5

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static int answered[2], errors, timed_out;

static const char * const lap_ads[] = { "127.0.0.1", "::1" };

/* each client was answered, or failed */

static void
lap_check_done(struct lws_context *cx)
{
	if (answered[0] + answered[1] + errors == (int)LWS_ARRAY_SIZE(lap_ads))
		lws_default_loop_exit(cx);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	int *idx = (int *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* any answer will do: the server has no mounts */
		lwsl_user("%s: %s answered %u\n", __func__, lap_ads[*idx],
			  lws_http_client_http_response(wsi));
		answered[*idx] = 1;
		lap_check_done(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: %s: %s\n", __func__, lap_ads[*idx],
			 in ? (const char *)in : "connection error");
		errors++;
		lap_check_done(lws_get_context(wsi));
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "lap-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	static int idx[LWS_ARRAY_SIZE(lap_ads)];
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh, *vh_cli;
	int port, result = 1;
	lws_fi_t fi;
	size_t n;

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: a vhost on any port, with that port "
		  "taken in its second address family\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server, on any free port, the first one it binds found taken */

	info.port		= 0;
	info.vhost_name		= "any";
	info.protocols		= protocols_srv;

	memset(&fi, 0, sizeof(fi));
	fi.name			= "listen_port_taken";
	fi.type			= LWSFI_DETERMINISTIC;
	fi.count		= 1;
	if (lws_fi_add(&info.fic, &fi)) {
		lwsl_err("can't add the fault\n");
		goto bail;
	}

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("FAIL: the vhost on any port didn't come up\n");
		goto bail;
	}

	port = lws_get_vhost_listen_port(vh);
	lwsl_user("the vhost listens on port %d\n", port);
	if (port <= 0) {
		lwsl_err("FAIL: no port\n");
		goto bail;
	}

	/* a client of each family */

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(lap_ads); n++) {
		idx[n] = (int)n;

		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.vhost			= vh_cli;
		i.address		= lap_ads[n];
		i.host			= lap_ads[n];
		i.port			= port;
		i.path			= "/";
		i.method		= "GET";
		i.protocol		= protocols_cli[0].name;
		i.local_protocol_name	= protocols_cli[0].name;
		i.opaque_user_data	= &idx[n];

		if (!lws_client_connect_via_info(&i))
			/* failing at once, it was told of it already */
			lwsl_err("%s: can't connect\n", lap_ads[n]);
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 LAP_TIMEOUT_S * LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0)
		;

	result = 0;
	if (timed_out) {
		lwsl_err("FAIL: not answered inside %ds\n", LAP_TIMEOUT_S);
		result = 1;
	}
	for (n = 0; n < LWS_ARRAY_SIZE(lap_ads); n++)
		if (!answered[n]) {
			lwsl_err("FAIL: nothing listens on %s port %d\n",
				 lap_ads[n], port);
			result = 1;
		}

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", !result ? "PASS" : "FAIL");

	return result;
}
