/*
 * lws-api-test-client-no-vhost
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A client connection given no vhost in its connect info goes on the
 * "default" vhost, else the first vhost that isn't lws's own "system" one.
 * In a context with LWS_SERVER_OPTION_EXPLICIT_VHOSTS (which
 * lws_context_info_defaults() sets) where the app has created no vhost, there
 * is none: lws_client_connect_via_info() must return NULL cleanly, freeing
 * the wsi it began (G-694).
 *
 * Wherever lws's own protocols (eg, async dns, stdin) need one, which is any
 * networked unix or windows build, the context has a "system" vhost and it is
 * the only one: so this is the case where the first vhost is "system" and
 * there is no next one.  On platforms without them there is no vhost at all,
 * the other way to have none.  Either way the connect must fail cleanly, eg,
 * without touching a NULL vhost to inherit its fault injection.
 *
 * With Secure Streams, such a context also has a vhost "_ss_default" for SS's
 * own clients, so the app's clients don't need one.  We destroy that first, as
 * an app that has no use for it could, to leave the context with none.
 *
 *  - an http GET, a TLS GET and a ws upgrade are each refused with NULL
 *
 * Then the app creates a vhost of its own, and the same http GET, to a port
 * nothing listens on, must be taken (non-NULL) and later end with
 * LWS_CALLBACK_CLIENT_CONNECTION_ERROR on that vhost's protocol: the NULLs
 * were for the missing vhost, not for the connect info.
 */

#include <libwebsockets.h>
#include <string.h>

enum {
	CNV_SW_PORT,
	CNV_SW_SERVER,
	CNV_SW_HELP,
};

static const struct lws_switches switches[] = {
	[CNV_SW_PORT]	= { "--port", "A port nothing listens on, for the "
				      "connection that is taken (default 7681)" },
	[CNV_SW_SERVER]	= { "--server", "Address the clients connect to "
					"(default localhost)" },
	[CNV_SW_HELP]	= { "--help", "Show this help information" },
};

#define CNV_DEADLINE_US		(10 * LWS_US_PER_SEC)

struct cnv_case {
	const char		*label;
	const char		*method;	/* NULL: ws */
	int			ssl;
};

static const struct cnv_case cnv_cases[] = {
	{ "http GET", "GET", 0 },
#if defined(LWS_WITH_TLS)
	{ "tls GET", "GET", LCCSCF_USE_SSL },
#endif
#if defined(LWS_ROLE_WS)
	{ "ws upgrade", NULL, 0 },
#endif
};

static struct lws_context *cnv_cx;
static lws_sorted_usec_list_t cnv_sul_deadline;
static const char *cnv_server = "localhost";
static int cnv_port = 7681, cnv_fails, cnv_conn_errors, cnv_done;

static int
cnv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
       void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("taken connection: CONNECTION_ERROR: %s\n",
			  in ? (const char *)in : "(null)");
		cnv_conn_errors++;
		cnv_done = 1;
		lws_cancel_service(cnv_cx);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_err("taken connection: connected to a port nothing "
			 "should listen on\n");
		cnv_fails++;
		cnv_done = 1;
		lws_cancel_service(cnv_cx);
		return -1;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols cnv_protocols[] = {
	{ "cnv", cnv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
cnv_deadline(lws_sorted_usec_list_t *sul)
{
	lwsl_err("taken connection: no final callback by the deadline\n");
	cnv_fails++;
	cnv_done = 1;
	lws_cancel_service(cnv_cx);
}

static struct lws *
cnv_connect(const struct cnv_case *c)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cnv_cx;
	/* no i.vhost: lws chooses one */
	i.address		= cnv_server;
	i.host			= cnv_server;
	i.origin		= cnv_server;
	i.port			= cnv_port;
	i.path			= "/";
	i.method		= c->method;
	i.ssl_connection	= c->ssl;
	i.protocol		= c->method ? NULL : "cnv";
	i.local_protocol_name	= "cnv";

	return lws_client_connect_via_info(&i);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	size_t n;
	int m = 0;

	/* before the builtins, which have a --help of their own */
	if (lws_cmdline_option(argc, argv, switches[CNV_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[CNV_SW_PORT].sw)))
		cnv_port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[CNV_SW_SERVER].sw)))
		cnv_server = p;

	lwsl_user("LWS API selftest: client connect with no vhost\n");

	/* the defaults have EXPLICIT_VHOSTS: we make no vhost at first */
	if (!(info.options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS)) {
		lwsl_err("expected EXPLICIT_VHOSTS from the defaults\n");
		return 1;
	}
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cnv_cx = lws_create_context(&info);
	if (!cnv_cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	/* nothing is bound to it yet, so it goes at once */
	vh = lws_get_vhost_by_name(cnv_cx, "_ss_default");
	if (vh) {
		lwsl_user("destroying the Secure Streams vhost\n");
		lws_vhost_destroy(vh);
		if (lws_get_vhost_by_name(cnv_cx, "_ss_default")) {
			lwsl_err("the Secure Streams vhost is still there\n");
			cnv_fails++;
			goto bail;
		}
	}

	lwsl_user("vhosts: %s\n", lws_get_vhost_by_name(cnv_cx, "system") ?
		  "only \"system\"" : "none at all");

	for (n = 0; n < LWS_ARRAY_SIZE(cnv_cases); n++) {
		int taken = !!cnv_connect(&cnv_cases[n]);

		lwsl_user("%s with no vhost: %s\n", cnv_cases[n].label,
			  taken ? "taken" : "refused");
		if (taken) {
			lwsl_err("%s: FAIL: taken with no vhost to bind to\n",
				 cnv_cases[n].label);
			cnv_fails++;
		}
	}

	/* the same connect is taken once there is a vhost of the app's own */

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.protocols		= cnv_protocols;
	info.vhost_name		= "cnv";
	if (!lws_create_vhost(cnv_cx, &info)) {
		lwsl_err("vhost creation failed\n");
		cnv_fails++;
		goto bail;
	}

	if (!cnv_connect(&cnv_cases[0])) {
		lwsl_err("FAIL: connect not taken with a vhost\n");
		cnv_fails++;
		goto bail;
	}

	lws_sul_schedule(cnv_cx, 0, &cnv_sul_deadline, cnv_deadline,
			 CNV_DEADLINE_US);

	while (m >= 0 && !cnv_done)
		m = lws_service(cnv_cx, 0);

	if (cnv_conn_errors != 1) {
		lwsl_err("FAIL: %d CONNECTION_ERRORs for the taken "
			 "connection\n", cnv_conn_errors);
		cnv_fails++;
	}

bail:
	lws_sul_cancel(&cnv_sul_deadline);
	lws_context_destroy(cnv_cx);

	lwsl_user("Completed: %s (%d failed)\n", cnv_fails ? "FAIL" : "PASS",
		  cnv_fails);

	return !!cnv_fails;
}
