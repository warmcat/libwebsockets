/*
 * lws-minimal-http-client-openhitls-policy-override-positive
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Verifies supported positive OpenHiTLS client-policy overrides by pairing
 * each scenario with:
 *
 * - an initial connection without the policy flag that must fail
 * - a second connection with the intended policy flag that must succeed
 *
 * Covered scenarios:
 *
 * - self-signed certificate via LCCSCF_ALLOW_SELFSIGNED
 * - invalid CA certificate via LCCSCF_ALLOW_INSECURE
 * - hostname mismatch via LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK
 * - expired certificate via LCCSCF_ALLOW_EXPIRED
 */

#include <libwebsockets.h>
#include <hitls_error.h>
#include <hitls_pki_errno.h>
#include <hitls_pki_x509.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#ifndef LWS_TEST_SERVER_CERT_PEM
#define LWS_TEST_SERVER_CERT_PEM "libwebsockets-test-server.pem"
#endif

#ifndef LWS_TEST_SERVER_KEY_PEM
#define LWS_TEST_SERVER_KEY_PEM "libwebsockets-test-server.key.pem"
#endif

#define DEFAULT_SELFSIGNED_PORT 7840
#define DEFAULT_INVALIDCA_PORT 7850
#define DEFAULT_HOSTNAME_PORT 7860
#define DEFAULT_EXPIRED_PORT 7870

#define INVALIDCA_ROOT_CERT "policy-invalidca-root.cert"
#define INVALIDCA_SERVER_CHAIN "policy-invalidca-server-chain.pem"
#define INVALIDCA_SERVER_KEY "policy-invalidca-server.key"
#define HOSTNAME_CERT \
	"../minimal-http-client-openhitls-certfail/wronghost.example.com.cert"
#define HOSTNAME_KEY \
	"../minimal-http-client-openhitls-certfail/wronghost.example.com.key"
#define HOSTNAME_CA \
	"../minimal-http-client-openhitls-certfail/wronghost.example.com.cert"
#define EXPIRED_CA "policy-expired-ca.cert"
#define EXPIRED_CERT "policy-expired-server.cert"
#define EXPIRED_KEY "policy-expired-server.key"

struct pss_http {
	char body[LWS_PRE + 128];
	size_t body_len;
};

enum scenario_id {
	SCENARIO_SELFSIGNED,
	SCENARIO_INVALIDCA,
	SCENARIO_HOSTNAME,
	SCENARIO_EXPIRED,
};

struct scenario_desc {
	enum scenario_id id;
	const char *name;
	int default_port;
	const char *server_cert;
	const char *server_key;
	const char *client_ca;
	const char *address;
	const char *host;
	const char *expected_cn;
	const char *body;
	const char *expected_error_text;
	unsigned int policy_flag;
};

struct attempt_state {
	unsigned int expect_success;
	unsigned int started;
	unsigned int saw_connection_error;
	unsigned int saw_established;
	unsigned int saw_completed;
	unsigned int saw_verify_cb;
	unsigned int verify_preverify_ok;
	unsigned int peer_verified;
	int32_t verify_error;
	int response_status;
	char peer_cn[128];
	char body[128];
	char conn_error[256];
	size_t body_len;
};

static const struct scenario_desc scenarios[] = {
	{
		SCENARIO_SELFSIGNED,
		"selfsigned",
		DEFAULT_SELFSIGNED_PORT,
		LWS_TEST_SERVER_CERT_PEM,
		LWS_TEST_SERVER_KEY_PEM,
		NULL,
		"localhost",
		"localhost",
		"localhost",
		"policy-selfsigned ok\n",
		"tls=invalidca",
		LCCSCF_ALLOW_SELFSIGNED,
	},
	{
		SCENARIO_INVALIDCA,
		"invalidca",
		DEFAULT_INVALIDCA_PORT,
		INVALIDCA_SERVER_CHAIN,
		INVALIDCA_SERVER_KEY,
		INVALIDCA_ROOT_CERT,
		"localhost",
		"localhost",
		"localhost",
		"policy-invalidca ok\n",
		"tls=invalidca",
		LCCSCF_ALLOW_INSECURE,
	},
	{
		SCENARIO_HOSTNAME,
		"hostname",
		DEFAULT_HOSTNAME_PORT,
		HOSTNAME_CERT,
		HOSTNAME_KEY,
		HOSTNAME_CA,
		"localhost",
		"localhost",
		"wronghost.example.com",
		"policy-hostname ok\n",
		"tls=hostname",
		LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK,
	},
	{
		SCENARIO_EXPIRED,
		"expired",
		DEFAULT_EXPIRED_PORT,
		EXPIRED_CERT,
		EXPIRED_KEY,
		EXPIRED_CA,
		"localhost",
		"localhost",
		"localhost",
		"policy-expired ok\n",
		"tls=expired",
		LCCSCF_ALLOW_EXPIRED,
	},
};

static struct lws_context *context;
static struct lws *client_wsi;
static lws_sorted_usec_list_t sul_next_attempt;
static int interrupted, bad, completed, server_only;
static int single_attempt_mode;
static int single_attempt_expect_success;
static int test_port;
static unsigned int attempt_idx;
static const struct scenario_desc *scenario;
static struct attempt_state attempts[2];

static void
reset_attempt(struct attempt_state *as)
{
	memset(as, 0, sizeof(*as));
	as->verify_error = HITLS_X509_V_OK;
}

static void
cancel_service(void)
{
	if (context) {
		lws_cancel_service(context);
	}
}

static void
fail_test(const char *why)
{
	lwsl_err("%s\n", why);
	bad = 1;
	completed = 1;
	cancel_service();
}

static const struct scenario_desc *
find_scenario(const char *name)
{
	unsigned int n;

	for (n = 0; n < LWS_ARRAY_SIZE(scenarios); n++) {
		if (!strcmp(name, scenarios[n].name)) {
			return &scenarios[n];
		}
	}

	return NULL;
}

static int
copy_cert_cn(struct lws *wsi, char *dest, size_t dest_len, unsigned int *verified)
{
	union lws_tls_cert_info_results ir;

	if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
				   sizeof(ir.ns.name))) {
		return -1;
	}

	lws_strncpy(dest, ir.ns.name, dest_len);

	if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VERIFIED, &ir, 0)) {
		return -1;
	}

	*verified = ir.verified;

	return 0;
}

static int
verify_error_matches(const struct scenario_desc *sc, int32_t err)
{
	switch (sc->id) {
	case SCENARIO_SELFSIGNED:
		return err == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND;

	case SCENARIO_INVALIDCA:
		return err == HITLS_X509_ERR_VFY_INVALID_CA;

	case SCENARIO_HOSTNAME:
		return err == HITLS_X509_ERR_VFY_HOSTNAME_FAIL;

	case SCENARIO_EXPIRED:
		return err == HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED ||
		       err == HITLS_X509_ERR_TIME_EXPIRED;
	}

	return 0;
}

static const char *
verify_error_label(int32_t err)
{
	switch (err) {
	case HITLS_X509_V_OK:
		return "ok";
	case HITLS_X509_ERR_VFY_HOSTNAME_FAIL:
		return "hostname";
	case HITLS_X509_ERR_VFY_INVALID_CA:
		return "invalidca";
	case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
		return "issue-not-found";
	case HITLS_X509_ERR_ROOT_CERT_NOT_FOUND:
		return "root-not-found";
	case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
		return "expired";
	case HITLS_X509_ERR_TIME_EXPIRED:
		return "time-expired";
	default:
		return "other";
	}
}

static int
start_attempt(void);

static void
assert_positive_attempt(struct attempt_state *as);

static void
assert_negative_attempt(struct attempt_state *as);

static void
start_attempt_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	if (start_attempt()) {
		fail_test("failed to start client connection");
	}
}

static void
advance_to_next_attempt(void)
{
	attempt_idx++;
	if (attempt_idx == LWS_ARRAY_SIZE(attempts)) {
		completed = 1;
		cancel_service();
		return;
	}

	reset_attempt(&attempts[attempt_idx]);
	attempts[attempt_idx].expect_success = 1;
	lws_sul_schedule(context, 0, &sul_next_attempt, start_attempt_cb,
			 100 * LWS_US_PER_MS);
}

static void
finalize_single_attempt(struct attempt_state *as)
{
	if (as->expect_success) {
		assert_positive_attempt(as);
	} else {
		assert_negative_attempt(as);
	}

	if (!bad) {
		completed = 1;
		cancel_service();
	}
}

static void
assert_positive_attempt(struct attempt_state *as)
{
	if (!as->saw_established) {
		fail_test("policy-enabled attempt never established");
		return;
	}

	if (as->response_status != HTTP_STATUS_OK) {
		fail_test("unexpected HTTP status in policy-enabled attempt");
		return;
	}

	if (strcmp(as->peer_cn, scenario->expected_cn)) {
		fail_test("unexpected peer CN in policy-enabled attempt");
		return;
	}

	if (strcmp(as->body, scenario->body)) {
		fail_test("unexpected response body in policy-enabled attempt");
		return;
	}
}

static void
assert_negative_attempt(struct attempt_state *as)
{
	if (as->saw_established) {
		fail_test("policy-disabled attempt unexpectedly established");
		return;
	}

	if (!as->saw_connection_error) {
		fail_test("policy-disabled attempt did not fail as expected");
		return;
	}

	if (as->saw_verify_cb && verify_error_matches(scenario, as->verify_error)) {
		return;
	}

	if (scenario->expected_error_text &&
	    strstr(as->conn_error, scenario->expected_error_text)) {
		return;
	}

	fail_test("policy-disabled attempt did not expose the expected verify result");
}

static void
finalize_positive_attempt(void)
{
	assert_negative_attempt(&attempts[0]);
	if (bad) {
		return;
	}

	assert_positive_attempt(&attempts[1]);
	if (bad) {
		return;
	}

	lwsl_user("%s: negative=%s(0x%x) positive=%s(0x%x) verified=%u\n",
		  scenario->name,
		  verify_error_label(attempts[0].verify_error),
		  attempts[0].verify_error,
		  verify_error_label(attempts[1].verify_error),
		  attempts[1].verify_error,
		  attempts[1].peer_verified);

	completed = 1;
	cancel_service();
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	struct pss_http *pss = (struct pss_http *)user;
	struct attempt_state *as = &attempts[attempt_idx];
	uint8_t headers[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = &headers[LWS_PRE], *p = start,
		*end = &headers[sizeof(headers) - 1];

	switch (reason) {
	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
	{
		int32_t err = HITLS_X509_V_OK;

		as->saw_verify_cb = 1;
		as->verify_preverify_ok = (unsigned int)!!len;
		if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)user,
					    HITLS_X509_STORECTX_GET_ERROR, &err,
					    (uint32_t)sizeof(err)) ==
		    HITLS_PKI_SUCCESS) {
			as->verify_error = err;
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP:
		pss->body_len = strlen(scenario->body);
		memcpy(&pss->body[LWS_PRE], scenario->body, pss->body_len);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
						(lws_filepos_t)pss->body_len,
						&p, end)) {
			return 1;
		}

		if (lws_finalize_write_http_header(wsi, start, &p, end)) {
			return 1;
		}

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (lws_write(wsi, (unsigned char *)&pss->body[LWS_PRE],
			      (unsigned int)pss->body_len,
			      LWS_WRITE_HTTP_FINAL) != (int)pss->body_len) {
			return 1;
		}

		if (lws_http_transaction_completed(wsi)) {
			return -1;
		}
		return 0;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		as->saw_connection_error = 1;
		if (in) {
			lws_strncpy(as->conn_error, (const char *)in,
				    sizeof(as->conn_error));
		}
		client_wsi = NULL;
		lwsl_user("%s attempt %u connection error: %s\n",
			  scenario->name, attempt_idx,
			  in ? (const char *)in : "(null)");
		if (as->expect_success) {
			fail_test("policy-enabled attempt failed");
			return 0;
		}

		assert_negative_attempt(as);
		if (bad) {
			return 0;
		}

		if (single_attempt_mode) {
			completed = 1;
			cancel_service();
		} else {
			advance_to_next_attempt();
		}
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		as->saw_established = 1;
		as->response_status = (int)lws_http_client_http_response(wsi);
		if (copy_cert_cn(wsi, as->peer_cn, sizeof(as->peer_cn),
				 &as->peer_verified)) {
			fail_test("failed to read peer certificate info");
			return 0;
		}
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (as->body_len + len >= sizeof(as->body)) {
			fail_test("response body exceeded test buffer");
			return -1;
		}

		memcpy(as->body + as->body_len, in, len);
		as->body_len += len;
		as->body[as->body_len] = '\0';
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	{
		unsigned char buf[LWS_PRE + 128], *pp = &buf[LWS_PRE];
		int n = (int)sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, (char **)&pp, &n) < 0) {
			fail_test("lws_http_client_read failed");
			return -1;
		}

		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		as->saw_completed = 1;
		client_wsi = NULL;
		if (!as->expect_success) {
			fail_test("policy-disabled attempt unexpectedly completed");
			return 0;
		}

		if (single_attempt_mode) {
			finalize_single_attempt(as);
		} else {
			finalize_positive_attempt();
		}
		return 0;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		if (as->expect_success && !completed) {
			if (single_attempt_mode) {
				finalize_single_attempt(as);
			} else {
				finalize_positive_attempt();
			}
		}
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		sizeof(struct pss_http),
		0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	(void)sig;

	interrupted = 1;
	cancel_service();
}

static int
start_attempt(void)
{
	struct lws_client_connect_info i;
	unsigned int flags = LCCSCF_USE_SSL;
	struct attempt_state *as = &attempts[attempt_idx];

	reset_attempt(as);
	as->started = 1;
	as->expect_success = single_attempt_mode ?
			     !!single_attempt_expect_success :
			     attempt_idx != 0;

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.address = scenario->address;
	i.host = scenario->host;
	i.origin = scenario->host;
	i.path = "/";
	i.method = "GET";
	i.port = test_port;
	i.protocol = protocols[0].name;
	i.pwsi = &client_wsi;

	if (as->expect_success) {
		flags |= scenario->policy_flag;
	}
	i.ssl_connection = (int)flags;

	lwsl_user("%s attempt %u: flags=0x%x expect=%s\n",
		  scenario->name, attempt_idx,
		  (unsigned int)i.ssl_connection,
		  as->expect_success ? "success" : "failure");

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("lws_client_connect_via_info failed\n");
		return -1;
	}

	return 0;
}

static int
create_client_context(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *policy;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS |
		       LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE;
	info.fd_limit_per_thread = 3;
	info.client_ssl_ca_filepath = scenario->client_ca;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	p = lws_cmdline_option(argc, argv, "--port");
	test_port = scenario->default_port;
	if (p) {
		test_port = atoi(p);
	}

	reset_attempt(&attempts[0]);
	reset_attempt(&attempts[1]);
	attempt_idx = 0;

	policy = lws_cmdline_option(argc, argv, "--policy");
	if (policy) {
		single_attempt_mode = 1;
		if (!strcmp(policy, "on")) {
			single_attempt_expect_success = 1;
		} else if (!strcmp(policy, "off")) {
			single_attempt_expect_success = 0;
		} else {
			lwsl_err("unknown --policy value '%s'\n", policy);
			return 1;
		}
	}

	if (start_attempt()) {
		return 1;
	}

	return 0;
}

static int
create_server_context(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	p = lws_cmdline_option(argc, argv, "--port");
	test_port = scenario->default_port;
	if (p) {
		test_port = atoi(p);
	}

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.protocols = protocols;
	info.port = test_port;
	info.ssl_cert_filepath = scenario->server_cert;
	info.ssl_private_key_filepath = scenario->server_key;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	const char *mode;
	int n = 0;
	int ret = 1;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	mode = lws_cmdline_option(argc, argv, "--server-only");
	if (mode) {
		server_only = 1;
	} else {
		mode = lws_cmdline_option(argc, argv, "--test");
	}

	if (!mode) {
		lwsl_err("Usage: %s [--server-only <scenario> | --test <scenario> [--policy on|off]] [--port <port>]\n",
			 argv[0]);
		return 1;
	}

	scenario = find_scenario(mode);
	if (!scenario) {
		lwsl_err("unknown scenario '%s'\n", mode);
		return 1;
	}

	lwsl_user("LWS minimal http client openhitls policy override %s %s\n",
		  server_only ? "--server-only" : "--test", scenario->name);

	if (server_only) {
		if (create_server_context(argc, argv)) {
			return 1;
		}

		while (!interrupted) {
			(void)lws_service(context, 0);
		}

		return 0;
	}

	if (create_client_context(argc, argv)) {
		lws_context_destroy(context);
		return 1;
	}

	while (n >= 0 && !interrupted && !completed) {
		n = lws_service(context, 0);
	}

	if (!interrupted) {
		ret = bad ? 1 : 0;
	}

	lws_context_destroy(context);

	if (!bad && !interrupted) {
		lwsl_user("Completed: %s OK\n", scenario->name);
	}

	return ret;
}
