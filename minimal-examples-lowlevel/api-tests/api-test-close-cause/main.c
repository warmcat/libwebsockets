/*
 * lws-api-test-close-cause
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * When a connection goes down, lws_wsi_close_cause() says why, as seen from
 * each end.  Two ws clients connect to a server in the same context:
 *
 *  - /timeout: the server gives the connection a 1s timeout that nothing
 *    clears.  The server's end goes because it timed out, and the client
 *    sees its peer close.
 *
 *  - /refuse: the server sends a message the client's callback refuses,
 *    giving a ws close status saying why.  The client's end goes because it
 *    closed it with that status, and the server sees the peer's ws close
 *    with it.
 *
 * Each end checks the cause it sees in its CLOSED callback.
 */

#include <libwebsockets.h>
#include <string.h>

static int interrupted, port = 7681, closes, good;
static const char *server = "localhost";
static struct lws_context *cx;
static lws_sorted_usec_list_t sul_deadline;

/* both ends of both connections */
#define CC_CLOSES		4
#define CC_DEADLINE_US		(10 * LWS_US_PER_SEC)

enum {
	CC_TIMEOUT,
	CC_REFUSE,
};

struct pss {
	int		which;
};

static const char * const paths[] = { "/timeout", "/refuse" };

/* what each end should see */
static const char * const expect_srv[] = {
	"timed out, pending timeout", "peer sent ws close, status 1008" },
		  * const expect_cli[] = {
	"peer closed", "closing with ws status 1008" };

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: only %d of %d ends closed\n", __func__, closes,
		 CC_CLOSES);
	interrupted = 1;
	lws_cancel_service(cx);
}

static void
check(struct lws *wsi, const char *end, int which, const char *expect)
{
	char cause[64];

	lws_wsi_close_cause(wsi, cause, sizeof(cause));

	if (!strncmp(cause, expect, strlen(expect))) {
		lwsl_user("%s: %s end of %s: \"%s\"\n", __func__, end,
			  paths[which], cause);
		good++;
	} else
		lwsl_err("%s: %s end of %s: \"%s\", expected \"%s\"\n",
			 __func__, end, paths[which], cause, expect);

	if (++closes == CC_CLOSES) {
		interrupted = 1;
		lws_cancel_service(cx);
	}
}

static int
callback_cc(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 16];
	char uri[32];
	int n;

	switch (reason) {

	/* the server's end */

	case LWS_CALLBACK_ESTABLISHED:
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) < 0)
			return -1;
		pss->which = !strcmp(uri, paths[CC_REFUSE]) ? CC_REFUSE :
							      CC_TIMEOUT;
		if (pss->which == CC_TIMEOUT)
			lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, 1);
		else
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		memcpy(buf + LWS_PRE, "refuse me", 9);
		if (lws_write(wsi, buf + LWS_PRE, 9, LWS_WRITE_TEXT) != 9)
			return -1;
		break;

	case LWS_CALLBACK_CLOSED:
		check(wsi, "server", pss->which, expect_srv[pss->which]);
		break;

	/* the clients' ends */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		pss->which = (int)(intptr_t)lws_get_opaque_user_data(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		/* the one message there is, is refused, saying why */
		lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION,
				 (unsigned char *)"refused", 7);
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection failed: %s\n", __func__,
			 in ? (const char *)in : "");
		n = (int)(intptr_t)lws_get_opaque_user_data(wsi);
		check(wsi, "client", n, "(connected)");
		/* the server's end never existed either */
		check(wsi, "server", n, "(connected)");
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		check(wsi, "client", pss->which, expect_cli[pss->which]);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "cc", callback_cc, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_vhost *vh;
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

	lwsl_user("LWS API selftest: why a connection closed\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the server, and the clients using the same vhost */

	info.port		= port;
	info.protocols		= protocols;
	info.vhost_name		= "cc";

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(paths); n++) {
		memset(&i, 0, sizeof(i));
		i.context		= cx;
		i.vhost			= vh;
		i.port			= port;
		i.address		= server;
		i.path			= paths[n];
		i.host			= i.address;
		i.origin		= i.address;
		i.protocol		= protocols[0].name;
		i.local_protocol_name	= protocols[0].name;
		i.alpn			= "http/1.1";
		i.opaque_user_data	= (void *)(intptr_t)n;

		if (!lws_client_connect_via_info(&i)) {
			lwsl_err("%s: client connect failed\n", __func__);
			goto bail;
		}
	}

	lws_sul_schedule(cx, 0, &sul_deadline, deadline_cb, CC_DEADLINE_US);

	while (!interrupted)
		if (lws_service(cx, 0) < 0)
			break;

bail:
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(cx);

	n = good == CC_CLOSES;
	lwsl_user("Completed: %s\n", n ? "PASS" : "FAIL");

	return !n;
}
