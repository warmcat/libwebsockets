/*
 * lws-api-test-close-decided
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_wsi_close(wsi, LWS_TO_KILL_ASYNC) decides a wsi is to be closed, and
 * the close happens when the event loop next runs.  Until then the wsi can
 * still move on, eg, a client connection whose connect completes sets a
 * timeout for its next phase, or cancels the one it had.  That must not undo
 * the decision: the wsi may have been closed for a reason that means it can't
 * do its job any more, eg, the route to its peer went away.
 *
 * Two clients connect to a server in the same context.  Each is decided
 * closed straight after it was created, and then, as its connect would, has
 * its timeout replaced, or cancelled.  Both must be closed before they ever
 * get a response from the server.
 */

#include <libwebsockets.h>
#include <string.h>

static int interrupted, port = 7681, closed, responded;
static const char *server = "localhost";
static struct lws_context *cx;
static lws_sorted_usec_list_t sul_deadline;

#define CD_CLIENTS		2
/* the closes happen on the next pass of the event loop, long before this */
#define CD_DEADLINE_US		(3 * LWS_US_PER_SEC)

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: %d of %d clients closed\n", __func__, closed, CD_CLIENTS);
	interrupted = 1;
	lws_cancel_service(cx);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_err("%s: a client decided closed got a response\n",
			 __func__);
		responded++;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_user("%s: client closed (%d)\n", __func__, closed + 1);
		if (++closed == CD_CLIENTS) {
			interrupted = 1;
			lws_cancel_service(cx);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "cd", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
	struct lws *wsi;
	const char *p;
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* the defaults budget fds for a lone client; we have both ends */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	lwsl_user("LWS API selftest: a decided close stands\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server, and the clients using the same vhost */

	info.port		= port;
	info.protocols		= protocols;
	info.vhost_name		= "cd";

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	for (n = 0; n < CD_CLIENTS; n++) {
		memset(&i, 0, sizeof(i));
		i.context		= cx;
		i.vhost			= vh;
		i.port			= port;
		i.address		= server;
		i.path			= "/";
		i.host			= i.address;
		i.origin		= i.address;
		i.method		= "GET";
		i.protocol		= protocols[0].name;
		i.local_protocol_name	= protocols[0].name;
		i.alpn			= "http/1.1";

		wsi = lws_client_connect_via_info(&i);
		if (!wsi) {
			lwsl_err("%s: client connect failed\n", __func__);
			goto bail;
		}

		lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);

		if (n)
			/* ... and then its timeout is cancelled */
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		else
			/* ... and then it sets one for its next phase */
			lws_set_timeout(wsi,
					PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
					20);
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, CD_DEADLINE_US);

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

bail:
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	n = closed == CD_CLIENTS && !responded;
	lwsl_user("Completed: %s\n", n ? "PASS" : "FAIL");

	return !n;
}
