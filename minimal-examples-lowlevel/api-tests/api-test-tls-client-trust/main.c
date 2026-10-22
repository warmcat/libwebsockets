/*
 * lws-api-test-tls-client-trust
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A CA added to one client vhost with lws_tls_client_vhost_extra_cert_mem()
 * must be trusted by that vhost only.  Some tls backends share one client tls
 * ctx between vhosts created with the same client tls configuration, and the
 * trust store belongs to the ctx: before G-392, trust added to one vhost
 * reached every vhost sharing its ctx, and every one created like it later.
 *
 * A server vhost "srv" presents the self-signed localhost-100y cert.  Client
 * vhosts trust only unrelated-ca.crt, and the OS trust store is off, so a
 * vhost reaches srv only if localhost-100y.cert was added to it:
 *
 *  - "a", then "b" created the same way.  b is given localhost-100y.cert
 *    afterwards.  Where b shares a's ctx, that is refused; where it does not,
 *    b trusts it alone.  Either way, a must still refuse srv
 *  - "c", created the same way but with .client_ssl_ctx_unshared, is given
 *    localhost-100y.cert, which must work: c reaches srv
 *  - "d", created the same way afterwards, must not have joined c: refused
 *  - "e", created with unrelated-ca.crt by its path instead (a configuration
 *    nobody else has), is given localhost-100y.cert, which must work since
 *    it shares with nobody: e reaches srv
 *  - "f", created the same way as e afterwards, must not have joined e,
 *    whose trust is now its own: refused
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define CTT_CASE_TIMEOUT_S	10

enum {
	CTT_VH_A,
	CTT_VH_B,
	CTT_VH_C,
	CTT_VH_D,
	CTT_VH_E,
	CTT_VH_F,
	CTT_VH_COUNT
};

static const struct {
	const char	*name;
	char		ca_path;	/* created with the CA's path */
	char		unshared;	/* .client_ssl_ctx_unshared */
	char		add_trust;	/* given localhost-100y.cert */
	char		must_add;	/* ...and the add must work */
	char		served;		/* expected to reach srv */
} vhs[] = {
	{ "a", 0, 0, 0, 0, 0 },
	{ "b", 0, 0, 1, 0, 0 /* not checked */ },
	{ "c", 0, 1, 1, 1, 1 },
	{ "d", 0, 0, 0, 0, 0 },
	{ "e", 1, 0, 1, 1, 1 },
	{ "f", 1, 0, 0, 0, 0 },
};

/* b's outcome depends on whether the backend shares ctxs, it isn't checked */
static const int cases[] = { CTT_VH_A, CTT_VH_C, CTT_VH_D, CTT_VH_E, CTT_VH_F };

#define CTT_CASE_COUNT ((int)LWS_ARRAY_SIZE(cases))

static struct lws_context *context;
static struct lws_vhost *vh_cli[CTT_VH_COUNT];
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
static int port = 7681, cur = -1, failures, result = 1, status;
static char case_over;

static void next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(const char *why)
{
	const char *name = vhs[cases[cur]].name;
	int want = vhs[cases[cur]].served;

	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);

	if (why) {
		lwsl_err("vh %s: FAIL: %s\n", name, why);
		failures++;
	} else if (!!status != want) {
		lwsl_err("vh %s: FAIL: expected to be %s, but %s\n", name,
			 want ? "served" : "refused",
			 status ? "was served" : "was refused");
		failures++;
	} else
		lwsl_user("vh %s: PASS (%s)\n", name,
			  want ? "served" : "refused");

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish("the case did not complete in time");
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	/* only the current case's connection has anything to say */

	if (cur < 0 || (intptr_t)lws_get_opaque_user_data(wsi) != cur + 1)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* the server cert was accepted */
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: vh %s: status %d\n", __func__,
			  vhs[cases[cur]].name, status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		case_finish(NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("%s: vh %s: connection error: %s\n", __func__,
			  vhs[cases[cur]].name,
			  in ? (const char *)in : "(null)");
		case_finish(NULL);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++cur >= CTT_CASE_COUNT) {
		result = !!failures;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("=== vh %s to srv ===\n", vhs[cases[cur]].name);

	status = 0;
	case_over = 0;
	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 CTT_CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli[cases[cur]];
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "ctt";
	i.alpn			= "http/1.1";
	i.opaque_user_data	= (void *)(intptr_t)(cur + 1);
	/* the server cert is verified for real: no relaxations */
	i.ssl_connection	= LCCSCF_USE_SSL;

	if (!lws_client_connect_via_info(&i))
		/* he failed without a connection error callback */
		case_finish(NULL);
}

static const struct lws_protocols protocols[] = {
	{ "ctt", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int main(int argc, const char **argv)
{
	uint8_t *ca_der = NULL, *trust_der = NULL;
	lws_filepos_t ca_der_len, trust_der_len;
	char srv_cert[256], srv_key[256], ca[256];
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a listener and both ends of the connections */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: client vhost trust stays its own\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the CA the client vhosts are created with */

	lws_snprintf(ca, sizeof(ca), "%s/unrelated-ca.crt", certs);
	if (lws_tls_alloc_pem_to_der_file(context, ca, NULL, 0, &ca_der,
					  &ca_der_len)) {
		lwsl_err("Unable to read %s\n", ca);
		goto bail;
	}

	/* the server's cert, which only the vhosts given it trust */

	lws_snprintf(srv_cert, sizeof(srv_cert), "%s/localhost-100y.cert",
		     certs);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/localhost-100y.key", certs);

	if (lws_tls_alloc_pem_to_der_file(context, srv_cert, NULL, 0,
					  &trust_der, &trust_der_len)) {
		lwsl_err("Unable to read %s\n", srv_cert);
		goto bail;
	}

	info.port			= port;
	info.vhost_name			= "srv";
	info.protocols			= protocols;
	info.ssl_cert_filepath		= srv_cert;
	info.ssl_private_key_filepath	= srv_key;
	info.alpn			= "http/1.1";

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	/* the client vhosts, in order, no listener */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.options			|=
				LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS;

	for (n = 0; n < CTT_VH_COUNT; n++) {
		info.vhost_name = vhs[n].name;
		info.client_ssl_ctx_unshared = (uint8_t)vhs[n].unshared;
		if (vhs[n].ca_path) {
			info.client_ssl_ca_filepath = ca;
			info.client_ssl_ca_mem = NULL;
			info.client_ssl_ca_mem_len = 0;
		} else {
			info.client_ssl_ca_filepath = NULL;
			info.client_ssl_ca_mem = ca_der;
			info.client_ssl_ca_mem_len = (unsigned int)ca_der_len;
		}

		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n]) {
			lwsl_err("Failed to create client vhost %s\n",
				 vhs[n].name);
			goto bail;
		}

		if (!vhs[n].add_trust)
			continue;

		if (lws_tls_client_vhost_extra_cert_mem(vh_cli[n], trust_der,
						(size_t)trust_der_len)) {
			if (vhs[n].must_add) {
				lwsl_err("FAIL: adding trust to vh %s failed\n",
					 vhs[n].name);
				goto bail;
			}
			lwsl_user("vh %s: adding trust refused (it shares "
				  "its client ctx)\n", vhs[n].name);
		} else
			lwsl_user("vh %s: trust added\n", vhs[n].name);
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	n = 0;
	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	if (ca_der)
		lws_realloc(ca_der, 0, "ctt der");
	if (trust_der)
		lws_realloc(trust_der, 0, "ctt der");

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures, CTT_CASE_COUNT);

	return result;
}
