/*
 * lws-api-test-jrpc
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * sanity tests for jrpc
 */

#include <libwebsockets.h>

/*
 * These came from https://www.jsonrpc.org/specification but amended since we
 * do not support batch
 */

static const char * const jrpc_request_tests[] = {

	"{" /* req 1 */
		"\"jsonrpc\":"	"\"2.0\", "
		"\"method\":"	"\"subtract\", "
		"\"params\":"	"[42, 23], "
		"\"id\":"	"1"
	"}",
	"{" /* req 2 */
		"\"jsonrpc\":"	"\"2.0\", "
		"\"method\":"	"\"subtract\", "
		"\"params\":"	"[23, 42], "
		"\"id\":"	"2"
	"}",
	"{" /* req 3 */
		"\"jsonrpc\":"	"\"2.0\", "
		"\"method\":"	"\"subtract\", "
		"\"params\":"	"{"
			"\"subtrahend\":"	"23, "
			"\"minuend\":"		"42"
		"}, \"id\":"	"3"
	"}",
	/* req 4 */
	"{\"jsonrpc\": \"2.0\","
	  "\"method\": \"update\", "
	  "\"params\": [1,2,3,4,5]}",

	/* req 5 */
	"{\"jsonrpc\": \"2.0\", \"method\": \"foobar\"}",

	/* req 6: unknown method: well-known error -32601 Method Not Found */
	"{\"jsonrpc\": \"2.0\", \"method\": \"noexist\", \"id\": \"1\"}",

	/* req 7: Invalid JSON should yield well-known error -32700 Parse Error */
	"{\"jsonrpc\": \"2.0\", \"method\": \"foobar, \"params\": \"bar\", \"baz]",

	/* req 8: Invalid req (method must be string): wke -32600 Invalid Request */
	"{\"jsonrpc\": \"2.0\", \"method\": 1, \"params\": \"bar\"}",

	/* req 9: Incomplete JSON, just -32700 Parse Error */
	"{\"jsonrpc\": \"2.0\", \"method\"}",

	/* req 10: OK */
	"{\"jsonrpc\": \"2.0\", \"method\": \"sum\", \"params\": [1,2,4], \"id\": \"1\"}",

	/* req 11: OK (notify) */
	"{\"jsonrpc\": \"2.0\", \"method\": \"notify_hello\", \"params\": [7]}",

	/* req 12: OK */
	"{\"jsonrpc\": \"2.0\", \"method\": \"subtract\", \"params\": [42,23], \"id\": \"2\"}",

	/* req 13: -32600 */
	"{\"foo\": \"boo\"}",

	/* req 14: -32601 */
	"{\"jsonrpc\": \"2.0\", \"method\": \"noexist\", \"params\": {\"name\": \"myself\"}, \"id\": \"5\"}",

	/* req 15: OK */
	"{\"jsonrpc\": \"2.0\", \"method\": \"get_data\", \"id\": \"9\"}",

	/* req 16: OK (notify) */
	"{\"jsonrpc\": \"2.0\", \"method\": \"notify_sum\", \"params\": [1,2,4]}",

	/* req 17: OK (notify) */
	"{\"jsonrpc\": \"2.0\", \"method\": \"notify_hello\", \"params\": [7]}",
};

static const char * const jrpc_response_tests[] = {

	"{" /* req 1 */
		"\"jsonrpc\":"	"\"2.0\","
		"\"id\":"	"1, "
		"\"response\":"	"\"string\""
	"}",
	"{" /* req 2 */
		"\"jsonrpc\":"	"\"2.0\","
		"\"id\":"	"2, "
		"\"response\":"	"123"
	"}",
	"{" /* req 3 */
		"\"jsonrpc\":"	"\"2.0\","
		"\"id\":"	"3, "
		"\"response\":"	"[1,2,3]"
	"}",
	"{" /* req 4 */
		"\"jsonrpc\":"	"\"2.0\","
		"\"id\":"	"4, "
		"\"response\":"	"{\"a\": \"b\"}"
	"}",
	"{" /* req 5 */
		"\"jsonrpc\":"	"\"2.0\","
		"\"error\": {"
			"\"code\":	-32601,"
			"\"message\":"	"\"Method not found\""
		"},"
		"\"id\": \"5\""
	"}",
};

static int expected_parse_result[] = {
	/*  1 */	0,
	/*  2 */	0,
	/*  3 */	0,
	/*  4 */	0,
	/*  5 */	0,
	/*  6 */	LWSJRPCWKE__METHOD_NOT_FOUND,
	/*  7 */	LWSJRPCWKE__PARSE_ERROR,
	/*  8 */	LWSJRPCWKE__INVALID_REQUEST,
	/*  9 */	LWSJRPCWKE__PARSE_ERROR,
	/* 10 */	0,
	/* 11 */	0,
	/* 12 */	0,
	/* 13 */	LWSJRPCWKE__INVALID_REQUEST,
	/* 14 */	LWSJRPCWKE__METHOD_NOT_FOUND,
	/* 15 */	0,
	/* 16 */	0,
	/* 17 */	0,
};

static int expected_parse_result_response[] = {
	/*  1 */	0,
	/*  2 */	0,
	/*  3 */	0,
	/*  4 */	0,
	/*  5 */	0,
};

/*
 * The Method-specific parser is an lejp parser callback that only sees the
 * subtree in request "params":
 */

static const char * const paths_s1[] = {
	"subtrahend",
	"minuend",
	"[]"
};
static const char * const paths_s2[] = {
	"subtrahend",
	"minuend",
	"[]"
};

static signed char
parse_s1(struct lejp_ctx *ctx, char reason)
{
	// struct lws_jrpc_obj *r;

	/*
	 * In the canonical examples, this can take either an array like
	 *   [1,2]
	 * or an object like
	 *   {"subtrahend":23, "minuend":42 }
	 */

	lwsl_notice("%s: reason %d, path %s, buf %.*s sp %d, pst_sp %d\n",
		    __func__, reason, ctx->path, ctx->npos, ctx->buf, ctx->sp,
		    ctx->pst_sp);

	return 0;
}

static signed char
parse_s2(struct lejp_ctx *ctx, char reason)
{
	return 0;
}

static const lws_jrpc_method_t methods[] = {
		/* list methods used by the tests that are expected to exist */
	{ "subtract",		paths_s1, parse_s1, LWS_ARRAY_SIZE(paths_s1) },
	{ "foobar",		paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ "update",		paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ "sum",		paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ "get_data",		paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ "notify_hello",	paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ "notify_sum",		paths_s2, parse_s2, LWS_ARRAY_SIZE(paths_s2) },
	{ NULL,			NULL, NULL, 0 } /* sentinel */
};

int main(int argc, const char **argv)
{
	int n, m, e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_jrpc_obj *req;
	struct lws_jrpc *jrpc;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: JSON-RPC\n");

	for (m = 0; m < (int)LWS_ARRAY_SIZE(jrpc_request_tests); m++) {

		lwsl_notice("%s: ++++++++++++++++ request %d\n", __func__, m + 1);

		jrpc = lws_jrpc_create(methods, NULL);
		if (!jrpc) {
			lwsl_err("%s: unable to create JRPC context\n", __func__);
			e++;
			continue;
		}

		req = NULL;
		n = lws_jrpc_obj_parse(jrpc, LWSJRPC_PARSE_REQUEST, NULL,
				       jrpc_request_tests[m],
				       strlen(jrpc_request_tests[m]), &req);

		lwsl_info("%s: %d\n", __func__, n);

		if (n != expected_parse_result[m]) {
			lwsl_err("%s: got %d, expected %d\n", __func__,
				    n, expected_parse_result[m]);
			e++;
		}

		lws_jrpc_destroy(&jrpc);
	}

	if (e)
		goto bail;

	for (m = 0; m < (int)LWS_ARRAY_SIZE(jrpc_response_tests); m++) {

		lwsl_notice("%s: ++++++++++++++++ response %d\n", __func__, m + 1);

		jrpc = lws_jrpc_create(methods, NULL);
		if (!jrpc) {
			lwsl_err("%s: unable to create JRPC context\n", __func__);
			e++;
			continue;
		}

		req = NULL;
		n = lws_jrpc_obj_parse(jrpc, LWSJRPC_PARSE_RESPONSE, NULL,
				       jrpc_response_tests[m],
				       strlen(jrpc_response_tests[m]), &req);

		lwsl_info("%s: %d\n", __func__, n);

		if (n != expected_parse_result_response[m]) {
			lwsl_err("%s: got %d, expected %d\n", __func__, n,
				 expected_parse_result[m]);
			e++;
		}

		lws_jrpc_destroy(&jrpc);
	}

	if (e)
		goto bail;

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
