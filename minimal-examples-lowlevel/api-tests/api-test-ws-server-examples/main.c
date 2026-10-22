/*
 * lws-api-test-ws-server-examples
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The ws-server minimal examples are copied into real servers, so their
 * protocols must stay safe whatever a peer sends them.  Each example's
 * protocol is built exactly as the example builds it, and served on its own
 * vhost (chosen by Host:) on one port, with ws clients in the same process.
 *
 * minimal-ws-server-pmd-corner sends the corner case chosen by the URL
 *
 *  - "/1" gets the first corner case, one BINARY message of 1012 bytes
 *  - URLs that don't name a corner case, "/-1", "/0", "/6", a huge number,
 *    or one followed by junk, get nothing, and the server carries on
 *
 * The test fails if any of that doesn't happen, or it doesn't all complete
 * in time.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "examples.h"

/* the URLs the pmd-corner example must ignore, after its one good one */
static const char * const corner_paths[] = {
	"/1", "/-1", "/0", "/6", "/-2147483648", "/4294967297", "/1x", "/",
};

/* the connections, by index in conns[] */
enum {
	WSE_C_CORNER,
	WSE_C_COUNT = WSE_C_CORNER + LWS_ARRAY_SIZE(corner_paths)
};

enum {
	WSE_P_CORNER,
	WSE_P_CORNER_CHECK,

	WSE_P_DONE
};

struct wse_conn {
	struct lws		*wsi;
	char			path[48];
	uint8_t			msg[8192];	/* message being reassembled */
	size_t			msg_len;
	size_t			last_len;	/* length of last whole message */
	int			msgs;		/* complete messages received */
	char			est;
	char			closed;
	char			msg_binary;
	char			last_binary;
	char			msg_overflow;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_phase, sul_timeout;
static struct wse_conn conns[WSE_C_COUNT];
static const char *server_address = "localhost";
static int port = 7681, phase, result = 1, failed, interrupted;

static void
wse_fail(const char *why)
{
	lwsl_err("FAIL: phase %d: %s\n", phase, why);
	failed = 1;
	interrupted = 1;
	lws_cancel_service(context);
}

static int
wse_connect(int idx, const char *vhost_name, const char *proto,
	    const char *path)
{
	struct wse_conn *c = &conns[idx];
	struct lws_client_connect_info i;

	lws_strncpy(c->path, path, sizeof(c->path));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= c->path;
	i.host			= vhost_name; /* selects the example's vhost */
	i.origin		= vhost_name;
	i.protocol		= proto;
	i.local_protocol_name	= "wse-client";
	i.opaque_user_data	= c;
	i.pwsi			= &c->wsi;

	if (!lws_client_connect_via_info(&i)) {
		wse_fail("connect failed");
		return 1;
	}

	return 0;
}

static void
wse_phase_cb(lws_sorted_usec_list_t *sul);

static void
wse_schedule(lws_usec_t us)
{
	lws_sul_schedule(context, 0, &sul_phase, wse_phase_cb, us);
}

/*
 * Each phase starts by being called here, then waits for its connections
 * and checks, and schedules the next phase
 */

static void
wse_phase_cb(lws_sorted_usec_list_t *sul)
{
	size_t n;

	switch (phase) {
	case WSE_P_CORNER:
		for (n = 0; n < LWS_ARRAY_SIZE(corner_paths); n++)
			if (wse_connect(WSE_C_CORNER + (int)n, "corner",
					"lws-minimal", corner_paths[n]))
				return;
		/* give them all time to get whatever they will get */
		phase++;
		wse_schedule(LWS_US_PER_SEC);
		break;

	case WSE_P_CORNER_CHECK:
		for (n = 0; n < LWS_ARRAY_SIZE(corner_paths); n++) {
			struct wse_conn *c = &conns[WSE_C_CORNER + n];

			lwsl_user("corner %s: est %d, closed %d, msgs %d, "
				  "len %d\n", c->path, c->est, c->closed,
				  c->msgs, (int)c->last_len);

			if (!c->est || c->closed) {
				wse_fail("corner connection didn't stay up");
				return;
			}
			if (!n) {
				/* "/1": the first corner case only */
				if (c->msgs != 1 || !c->last_binary ||
				    c->last_len != 1012) {
					wse_fail("/1 didn't get its corner case");
					return;
				}
				continue;
			}
			if (c->msgs) {
				wse_fail("corner case sent for a bad URL");
				return;
			}
		}
		phase++;
		wse_schedule(1);
		break;

	case WSE_P_DONE:
		result = 0;
		interrupted = 1;
		lws_cancel_service(context);
		break;
	}
}

static void
wse_timeout_cb(lws_sorted_usec_list_t *sul)
{
	wse_fail("timed out");
}

static int
callback_wse_client(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct wse_conn *c = (struct wse_conn *)lws_get_opaque_user_data(wsi);

	if (!c)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		c->est = 1;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			c->msg_len = 0;
			c->msg_binary = (char)lws_frame_is_binary(wsi);
			c->msg_overflow = 0;
		}
		if (len > sizeof(c->msg) - c->msg_len)
			c->msg_overflow = 1;
		else {
			memcpy(c->msg + c->msg_len, in, len);
			c->msg_len += len;
		}
		if (!lws_is_final_fragment(wsi))
			break;

		c->msgs++;
		c->last_len = c->msg_len;
		c->last_binary = c->msg_binary;
		if (c->msg_overflow)
			wse_fail("message too large");
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		c->closed = 1;
		c->wsi = NULL;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "wse-client", callback_wse_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* one vhost per example, all on one port, chosen by Host: */

static const struct {
	const char			*vhost_name;
	const struct lws_protocols	*protocol;
} examples[] = {
	{ "corner",	&wse_protocol_pmd_corner },
};

static struct lws_protocols protocols_srv[LWS_ARRAY_SIZE(examples)][3];

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	size_t m;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: ws-server example protocols\n");

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* there are no pvos to instantiate the protocols one by one */
	info.options |= LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
	info.port = port;

	for (m = 0; m < LWS_ARRAY_SIZE(examples); m++) {
		protocols_srv[m][0] = (struct lws_protocols){ "http",
				lws_callback_http_dummy, 0, 0, 0, NULL, 0 };
		protocols_srv[m][1] = *examples[m].protocol;
		protocols_srv[m][2] = (struct lws_protocols)
							LWS_PROTOCOL_LIST_TERM;

		info.vhost_name = examples[m].vhost_name;
		info.protocols = protocols_srv[m];
		if (!lws_create_vhost(context, &info)) {
			lwsl_err("Failed to create vhost %s\n",
				 examples[m].vhost_name);
			goto bail;
		}
	}

	info.options &= ~LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	wse_schedule(1);
	lws_sul_schedule(context, 0, &sul_timeout, wse_timeout_cb,
			 30 * LWS_US_PER_SEC);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);

	if (failed)
		result = 1;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
