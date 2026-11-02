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
 * Phase 1: two clients connect to a server in the same context.  Each is
 * decided closed straight after it was created, and then, as its connect
 * would, has its timeout replaced, or cancelled.  Both must be closed before
 * they ever get a response from the server.
 *
 * Phase 2: but the decided close must still be carried out.  Two pipelined h1
 * clients share one connection, the second queued behind the first.  The
 * first is decided closed from its last body read, just before its
 * transaction completes.  The completion hands the connection on to the
 * second, cancelling the first's timers, and then closes the first itself:
 * it must really be closed then, not left with no socket and no timeout
 * until the context is destroyed.  The second must get its whole response.
 */

#include <libwebsockets.h>
#include <string.h>

static int interrupted, port = 7681, closed, responded, phase, failed;
static const char *server = "localhost";
static struct lws_context *cx;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_deadline;

#define CD_CLIENTS		2
/* the closes happen on the next pass of the event loop, long before this */
#define CD_DEADLINE_US		(3 * LWS_US_PER_SEC)

/* the server sends its response body in two writes */
static const char body1[] = "the first part of the body, ",
		  body2[] = "and the last part of it";
#define CD_BODY_LEN		(sizeof(body1) - 1 + sizeof(body2) - 1)

/* a phase 2 client, found by its opaque_user_data */
struct pl_client {
	size_t		rx;
	int		destroyed;
	int		completed;
};

static struct pl_client pl[CD_CLIENTS];

/* a server connection, our protocol's per-session data */
struct pss {
	int		part;
};

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: phase %d: %d of %d clients closed, leader %s, follower "
		 "%s\n", __func__, phase, closed, CD_CLIENTS,
		 pl[0].destroyed ? "destroyed" : "not destroyed",
		 pl[1].completed ? "completed" : "not completed");
	failed = 1;
	interrupted = 1;
	lws_cancel_service(cx);
}

static struct lws *
client(int pipeline, struct pl_client *c)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh;
	i.port			= port;
	i.address		= server;
	i.path			= "/";
	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "GET";
	i.protocol		= "cd";
	i.local_protocol_name	= "cd";
	i.alpn			= "http/1.1";
	i.opaque_user_data	= c;
	if (pipeline)
		i.ssl_connection = LCCSCF_PIPELINE;

	return lws_client_connect_via_info(&i);
}

static void
phase2_start(void)
{
	int n;

	lwsl_user("%s: a decided close is carried out across a pipeline "
		  "handoff\n", __func__);

	phase = 2;

	/* the second finds the first's connection and queues on it */
	for (n = 0; n < CD_CLIENTS; n++)
		if (!client(1, &pl[n])) {
			lwsl_err("%s: client connect failed\n", __func__);
			failed = 1;
			interrupted = 1;
			lws_cancel_service(cx);
			return;
		}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, CD_DEADLINE_US);
}

static void
phase2_check(void)
{
	if (!pl[0].destroyed || !pl[1].completed)
		return;

	lws_sul_cancel(&sul_deadline);
	interrupted = 1;
	lws_cancel_service(cx);
}

static int
callback_cd(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	struct pl_client *c = (struct pl_client *)lws_get_opaque_user_data(wsi);
	struct pss *pss = (struct pss *)user;

	switch (reason) {

	/* the server side */

	case LWS_CALLBACK_HTTP:
		pss->part = 0;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", CD_BODY_LEN,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->part++) {
			memcpy(start, body1, sizeof(body1) - 1);
			if (lws_write(wsi, start, sizeof(body1) - 1,
				      LWS_WRITE_HTTP) != sizeof(body1) - 1)
				return 1;
			lws_callback_on_writable(wsi);

			return 0;
		}

		memcpy(start, body2, sizeof(body2) - 1);
		if (lws_write(wsi, start, sizeof(body2) - 1,
			      LWS_WRITE_HTTP_FINAL) != sizeof(body2) - 1)
			return 1;

		/* keep the connection for the next pipelined request */
		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	/* the client side */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (phase == 1) {
			lwsl_err("%s: a client decided closed got a response\n",
				 __func__);
			responded++;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char rb[1024 + LWS_PRE], *px = rb + LWS_PRE;
			int lenx = sizeof(rb) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!c)
			break;
		c->rx += len;
		if (c == &pl[0] && c->rx == CD_BODY_LEN) {
			/*
			 * The leader's user is done with it on its last read,
			 * eg, a streaming consumer cancelling: its transaction
			 * completes, and hands the connection on, right after
			 */
			lwsl_user("%s: leader decided closed on its last read\n",
				  __func__);
			lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
		}
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (c == &pl[1]) {
			lwsl_user("%s: follower completed, %u of %u\n",
				  __func__, (unsigned int)c->rx,
				  (unsigned int)CD_BODY_LEN);
			if (c->rx != CD_BODY_LEN)
				failed = 1;
			c->completed = 1;
			phase2_check();
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (c) {
			lwsl_err("%s: phase 2 client connection error: %s\n",
				 __func__, in ? (const char *)in : "");
			failed = 1;
			break;
		}
		/* fallthru */
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (phase != 1 || c)
			break;
		lwsl_user("%s: client closed (%d)\n", __func__, closed + 1);
		if (++closed == CD_CLIENTS) {
			lws_sul_cancel(&sul_deadline);
			if (responded) {
				interrupted = 1;
				lws_cancel_service(cx);
				break;
			}
			phase2_start();
		}
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		if (c == &pl[0] && !interrupted) {
			lwsl_user("%s: leader destroyed\n", __func__);
			c->destroyed = 1;
			phase2_check();
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "cd", callback_cd, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
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

	phase = 1;

	for (n = 0; n < CD_CLIENTS; n++) {
		wsi = client(0, NULL);
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

	/* judged before the context destroy closes whatever was left over */
	n = !failed && closed == CD_CLIENTS && !responded &&
	    pl[0].destroyed && pl[1].completed;

	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", n ? "PASS" : "FAIL");

	return !n;
}
