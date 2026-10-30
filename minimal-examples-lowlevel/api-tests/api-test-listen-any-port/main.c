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
 * Two vhosts here are given faults that make the second family's bind find
 * the port taken:
 *
 *  - "listen_port_taken" once: starting again once with another port is
 *    enough;
 *
 *  - "listen_port_taken_v6" every time: IPv6 has every port IPv4 chooses,
 *    as it had 8 in a row on Sai's macOS.  Starting again with IPv4
 *    choosing is never enough: IPv6 must choose.
 *
 * Each must still come up, on a port both families listen on: a client of
 * 127.0.0.1 and one of ::1 must each get an http response from it.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LAP_TIMEOUT_S		5

static const struct lap_vhost {
	const char		*name;
	const char		*fault;
	char			type;	/* LWSFI_* */
} lap_vhosts[] = {
	{ "any",	"listen_port_taken",	LWSFI_DETERMINISTIC },
	{ "any-v6",	"listen_port_taken_v6",	LWSFI_ALWAYS },
};

static const char * const lap_ads[] = { "127.0.0.1", "::1" };

#define LAP_CLIENTS (LWS_ARRAY_SIZE(lap_vhosts) * LWS_ARRAY_SIZE(lap_ads))

struct lap_client {
	const struct lap_vhost	*v;
	const char		*ads;
	int			port;
	int			answered;
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_watchdog;
static struct lap_client clients[LAP_CLIENTS];
static int done, timed_out;

/* each client was answered, or failed */

static void
lap_check_done(struct lws_context *cx)
{
	if (++done == (int)LAP_CLIENTS)
		lws_default_loop_exit(cx);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct lap_client *c = (struct lap_client *)
					lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* any answer will do: the server has no mounts */
		lwsl_user("%s: %s: %s answered %u\n", __func__, c->v->name,
			  c->ads, lws_http_client_http_response(wsi));
		c->answered = 1;
		lap_check_done(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: %s: %s: %s\n", __func__, c->v->name, c->ads,
			 in ? (const char *)in : "connection error");
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
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh, *vh_cli;
	int port, result = 1;
	struct lap_client *c;
	lws_fi_t fi;
	size_t n, m;

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

	/* the clients' vhost: the server vhosts' faults are on their info */

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;

	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	/* the servers, on any free port, the second family's bind faulted */

	for (n = 0; n < LWS_ARRAY_SIZE(lap_vhosts); n++) {
		info.port		= 0;
		info.vhost_name		= lap_vhosts[n].name;
		info.protocols		= protocols_srv;

		/* the vhost takes the faults on info.fic, leaving it empty */
		memset(&fi, 0, sizeof(fi));
		fi.name			= lap_vhosts[n].fault;
		fi.type			= lap_vhosts[n].type;
		fi.count		= 1;
		if (lws_fi_add(&info.fic, &fi)) {
			lwsl_err("can't add the fault\n");
			goto bail;
		}

		vh = lws_create_vhost(context, &info);
		/* ... unless it failed before it took them */
		lws_fi_destroy(&info.fic);
		if (!vh) {
			lwsl_err("FAIL: %s: the vhost on any port didn't come "
				 "up\n", lap_vhosts[n].name);
			goto bail;
		}

		port = lws_get_vhost_listen_port(vh);
		lwsl_user("%s listens on port %d\n", lap_vhosts[n].name, port);
		if (port <= 0) {
			lwsl_err("FAIL: %s: no port\n", lap_vhosts[n].name);
			goto bail;
		}

		for (m = 0; m < LWS_ARRAY_SIZE(lap_ads); m++) {
			c = &clients[n * LWS_ARRAY_SIZE(lap_ads) + m];
			c->v	= &lap_vhosts[n];
			c->ads	= lap_ads[m];
			c->port	= port;
		}
	}

	/* a client of each family, for each server */

	for (n = 0; n < LAP_CLIENTS; n++) {
		c = &clients[n];

		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.vhost			= vh_cli;
		i.address		= c->ads;
		i.host			= c->ads;
		i.port			= c->port;
		i.path			= "/";
		i.method		= "GET";
		i.protocol		= protocols_cli[0].name;
		i.local_protocol_name	= protocols_cli[0].name;
		i.opaque_user_data	= c;

		if (!lws_client_connect_via_info(&i))
			/* failing at once, it was told of it already */
			lwsl_err("%s: %s: can't connect\n", c->v->name, c->ads);
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
	for (n = 0; n < LAP_CLIENTS; n++)
		if (!clients[n].answered) {
			lwsl_err("FAIL: %s: nothing listens on %s port %d\n",
				 clients[n].v->name, clients[n].ads,
				 clients[n].port);
			result = 1;
		}

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", !result ? "PASS" : "FAIL");

	return result;
}
