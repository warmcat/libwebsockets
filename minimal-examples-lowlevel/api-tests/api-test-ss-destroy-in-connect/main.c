/*
 * lws-api-test-ss-destroy-in-connect
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Stream whose connection attempt fails inside
 * lws_ss_client_connect(), and whose state callback gives up on it then,
 * returning LWSSSSRET_DESTROY_ME for UNREACHABLE, is destroyed once, by
 * whoever asked for the connection, when lws_ss_client_connect() hands the
 * DESTROY_ME back to it.  The connect call still uses the handle until it
 * returns, so it must not be destroyed under it.
 *
 * Over h3, the quic connection's tls session is made as its transport comes
 * up, which for a numeric address is inside the connect call.  The
 * tls_client_bio_create fault fails it, as running out of heap for it would,
 * and the wsi is closed there and then, before the stream heard of it.  That
 * close used to destroy the handle itself: the connect call went on with the
 * freed handle, and the caller destroyed it again.
 *
 * Nothing is listening: the connection never gets as far as sending anything.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

LWS_SS_USER_TYPEDEF
	int			unused;
} dic_t;

static struct lws_context *cx;
static int unreachable, destroying, others, result = 1;

static lws_ss_state_return_t
dic_state(void *userobj, void *h_src, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	lwsl_user("%s: %s\n", __func__, lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_CREATING:
	case LWSSSCS_CONNECTING:
		break;

	case LWSSSCS_UNREACHABLE:
		unreachable++;
		/* the stream is no use to us now */
		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_DESTROYING:
		destroying++;
		break;

	default:
		others++;
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("dic", dic_t)
	.state				= dic_state,
};

static const char * const policy =
	"{\"release\":\"1\",\"product\":\"ss-destroy-in-connect\","
	 "\"schema-version\":1,"
	 "\"retry\":[{\"none\":{\"backoff\":[],"
		"\"conceal\":0,\"jitterpc\":0,"
		"\"svalidping\":30,\"svalidhup\":35}}],"
	 "\"s\":[{\"dic\":{"
		"\"endpoint\":\"127.0.0.1\","
		"\"port\":443,"
		"\"protocol\":\"h3\","
		"\"http_method\":\"GET\","
		"\"http_url\":\"\","
		"\"tls\":true,"
		"\"retry\":\"none\","
		"\"timeout_ms\":5000"
	 "}}]}";

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_ss_handle *h;
	lws_ss_state_return_t r;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: ss destroyed inside its connect\n");

	/* every client wsi fails to make its tls session */
	lws_fi_deserialize(&info.fic, "wsi/tls_client_bio_create");

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.pss_policies_json = policy;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	if (lws_ss_create(cx, 0, &ssi_dic_t, NULL, &h, NULL, NULL)) {
		lwsl_err("%s: unable to create the stream\n", __func__);
		goto bail;
	}

	r = lws_ss_client_connect(h);
	lwsl_user("%s: lws_ss_client_connect() %d\n", __func__, (int)r);

	/* as dlo's font fetch does: a stream that failed to connect goes */
	if (r != LWSSSSRET_OK)
		lws_ss_destroy(&h);

	/* anything left pending happens now */
	lws_service(cx, 0);
	lws_service(cx, 0);

	if (r != LWSSSSRET_DESTROY_ME)
		lwsl_err("%s: connect returned %d, not DESTROY_ME\n", __func__,
			 (int)r);
	else if (unreachable != 1 || destroying != 1 || others)
		lwsl_err("%s: UNREACHABLE %d, DESTROYING %d, others %d\n",
			 __func__, unreachable, destroying, others);
	else
		result = 0;

bail:
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
