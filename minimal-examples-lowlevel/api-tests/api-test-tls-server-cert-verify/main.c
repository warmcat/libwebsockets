/*
 * lws-api-test-tls-server-cert-verify
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * With mbedTLS, a tls client is given each cert of the server's chain in
 * LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION, with mbedtls' flags
 * for it, and can refuse it, eg, to pin the server's public key, or accept a
 * cert mbedtls refused.
 *
 * A server vhost "srv" presents the self-signed localhost-100y cert.  Client
 * vhost "trusted" has that cert as its CA, "untrusted" has only an unrelated
 * CA.  Each case connects to srv, the client's callback acting on the
 * server's cert, at depth 0, as the case says:
 *
 *  - observe: nothing, the backend's verdict stands
 *  - pin: compare the SHA-256 of its SubjectPublicKeyInfo with a pin,
 *    returning nonzero if it differs
 *  - pin-accept: the same, but clearing its flags if it matches, so it is
 *    accepted even though nothing we trust signed it
 *  - flag: set MBEDTLS_X509_BADCERT_OTHER in its flags, returning 0
 *
 * Every case must also see the callback made for the server's cert: if the
 * backend didn't make it, a pin would be silently ignored.
 *
 * The cases are run over http/1.1 on tls over tcp, and again over http/3 on
 * QUIC if lws was built with it, since a QUIC client connection makes its tls
 * session differently.  For h3, srv is a second vhost "srv-h3", listening
 * for QUIC only, on its own port, so a case can't pass by being quietly
 * retried over TCP.
 */

#include <libwebsockets.h>
#include <mbedtls/x509_crt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SCV_CASE_TIMEOUT_S	10

enum {
	SCV_VH_TRUSTED,
	SCV_VH_UNTRUSTED,
	SCV_VH_COUNT
};

enum scv_act {
	SCV_OBSERVE,
	SCV_PIN,
	SCV_PIN_ACCEPT,
	SCV_FLAG,
};

/*
 * SHA-256 of the SubjectPublicKeyInfo of localhost-100y.cert, ie,
 *
 * openssl x509 -in localhost-100y.cert -pubkey -noout | \
 *	openssl pkey -pubin -outform der | openssl dgst -sha256
 */

static const uint8_t pin_good[] = {
	0xe6, 0xa6, 0x8a, 0x98, 0xd5, 0x56, 0x91, 0x3a,
	0x6c, 0x03, 0x28, 0x2e, 0x23, 0xe6, 0xa1, 0x22,
	0xa2, 0x24, 0xb5, 0xe2, 0xfc, 0xcb, 0x0a, 0x33,
	0x73, 0xa7, 0xee, 0x0d, 0x0f, 0xc8, 0x15, 0x84
}, pin_bad[] = { /* the same with the last byte changed */
	0xe6, 0xa6, 0x8a, 0x98, 0xd5, 0x56, 0x91, 0x3a,
	0x6c, 0x03, 0x28, 0x2e, 0x23, 0xe6, 0xa1, 0x22,
	0xa2, 0x24, 0xb5, 0xe2, 0xfc, 0xcb, 0x0a, 0x33,
	0x73, 0xa7, 0xee, 0x0d, 0x0f, 0xc8, 0x15, 0x85
};

static const struct {
	const char	*name;
	int		vh;		/* the client vhost it connects from */
	enum scv_act	act;		/* what the callback does at depth 0 */
	const uint8_t	*pin;
	char		insecure;	/* LCCSCF_ALLOW_INSECURE */
	char		served;		/* expected to reach srv */
	const char	*err;		/* if refused, in the connection error */
} cases[] = {
	{ "observe",		   SCV_VH_TRUSTED,   SCV_OBSERVE,    NULL,
	  0, 1, NULL },
	{ "pin-match",		   SCV_VH_TRUSTED,   SCV_PIN,	     pin_good,
	  0, 1, NULL },
	{ "pin-mismatch",	   SCV_VH_TRUSTED,   SCV_PIN,	     pin_bad,
	  0, 0, "refused by callback" },
	{ "pin-mismatch-insecure", SCV_VH_TRUSTED,   SCV_PIN,	     pin_bad,
	  1, 0, "refused by callback" },
	{ "flag",		   SCV_VH_TRUSTED,   SCV_FLAG,	     NULL,
	  0, 0, NULL },
	{ "untrusted",		   SCV_VH_UNTRUSTED, SCV_OBSERVE,    NULL,
	  0, 0, NULL },
	{ "untrusted-pinned",	   SCV_VH_UNTRUSTED, SCV_PIN_ACCEPT, pin_good,
	  0, 1, NULL },
};

static int port = 7681, port_h3 = 7682;

/*
 * The transports the cases are each run over.  Each has its own server
 * vhost, listening for nothing else: if a client were quietly taken over
 * another transport, it would find nothing to connect to.
 */

static const struct {
	const char	*alpn;
	int		*port;
} transports[] = {
	{ "http/1.1",	&port },
#if defined(LWS_ROLE_H3)
	{ "h3",		&port_h3 },
#endif
};

#define SCV_RUNS (LWS_ARRAY_SIZE(cases) * LWS_ARRAY_SIZE(transports))

static struct lws_context *context;
static struct lws_vhost *vh_cli[SCV_VH_COUNT];
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static const char *server_addr = "localhost", *certs = ".";
/* run counts through each case on each transport, cur is the case */
static int run = -1, cur, failures, result = 1, status;
static char case_over, seen_depth0, err[128];
static volatile int interrupted, finished;

static void next_case(lws_sorted_usec_list_t *sul);

static void
case_finish(const char *why)
{
	const char *name = cases[cur].name,
		   *tr = transports[(unsigned int)run /
				    LWS_ARRAY_SIZE(cases)].alpn;
	int want = cases[cur].served;

	if (case_over)
		return;
	case_over = 1;
	lws_sul_cancel(&sul_watchdog);

	if (!why && !seen_depth0)
		why = "the callback was not made for the server's cert";
	if (!why && !!status != want)
		why = want ? "expected to be served, but was refused" :
			     "expected to be refused, but was served";
	if (!why && !status && cases[cur].err && !strstr(err, cases[cur].err))
		why = "the connection error doesn't say the callback refused it";

	if (why) {
		lwsl_err("%s (%s): FAIL: %s\n", name, tr, why);
		failures++;
	} else
		lwsl_user("%s (%s): PASS (%s)\n", name, tr,
			  want ? "served" : "refused");

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_finish("the case did not complete in time");
}

/*
 * Is the SHA-256 of the cert's SubjectPublicKeyInfo the pin?  This is what a
 * client pinning the server's public key does: the key survives the cert
 * being renewed, if the server keeps it.
 */

static int
spki_matches(const mbedtls_x509_crt *x509, const uint8_t *pin)
{
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;

	if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256))
		return 0;

	if (lws_genhash_update(&ctx, x509->pk_raw.p, x509->pk_raw.len)) {
		lws_genhash_destroy(&ctx, NULL);
		return 0;
	}

	if (lws_genhash_destroy(&ctx, hash))
		return 0;

	return !lws_timingsafe_bcmp(hash, pin, (uint32_t)sizeof(pin_good));
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;
	const mbedtls_x509_crt *x509;
	uint32_t *flags;

	/* only the current case's connection has anything to say */

	if (run < 0 || (intptr_t)lws_get_opaque_user_data(wsi) != run + 1)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
		x509 = (const mbedtls_x509_crt *)user;
		flags = (uint32_t *)in;

		lwsl_user("%s: %s: depth %d, flags 0x%x\n", __func__,
			  cases[cur].name, (int)len, (unsigned int)*flags);

		if (len)
			/* we pin the server's own cert, at depth 0 */
			return 0;

		seen_depth0 = 1;

		switch (cases[cur].act) {
		case SCV_OBSERVE:
			break;
		case SCV_PIN:
			if (!spki_matches(x509, cases[cur].pin))
				return 1;
			break;
		case SCV_PIN_ACCEPT:
			if (!spki_matches(x509, cases[cur].pin))
				return 1;
			/* it's the key we pinned, whoever signed it */
			*flags = 0;
			break;
		case SCV_FLAG:
			*flags |= MBEDTLS_X509_BADCERT_OTHER;
			break;
		}

		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		/* the server cert was accepted */
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("%s: %s: status %d\n", __func__, cases[cur].name,
			  status);
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
		lws_strncpy(err, in ? (const char *)in : "(null)", sizeof(err));
		lwsl_user("%s: %s: connection error: %s\n", __func__,
			  cases[cur].name, err);
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

	unsigned int t;

	if (++run >= (int)SCV_RUNS) {
		result = !!failures;
		finished = 1;
		lws_cancel_service(context);
		return;
	}

	cur = run % (int)LWS_ARRAY_SIZE(cases);
	t = (unsigned int)run / LWS_ARRAY_SIZE(cases);

	lwsl_user("=== %s (%s) ===\n", cases[cur].name, transports[t].alpn);

	status = 0;
	case_over = 0;
	seen_depth0 = 0;
	err[0] = '\0';
	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 SCV_CASE_TIMEOUT_S * LWS_US_PER_SEC);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli[cases[cur].vh];
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= *transports[t].port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "scv";
	i.local_protocol_name	= "scv";
	i.alpn			= transports[t].alpn;
	i.disable_h3_fallback	= 1;
	i.opaque_user_data	= (void *)(intptr_t)(run + 1);
	i.ssl_connection	= LCCSCF_USE_SSL;
	if (cases[cur].insecure)
		i.ssl_connection |= LCCSCF_ALLOW_INSECURE;

	if (!lws_client_connect_via_info(&i))
		/* he failed without a connection error callback */
		case_finish(NULL);
}

static const struct lws_protocols protocols[] = {
	{ "scv", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	char srv_cert[256], srv_key[256], ca[256];
	struct lws_context_creation_info info;
	const char *p;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-h3")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--certs")))
		certs = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: server cert verification callback\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_snprintf(srv_cert, sizeof(srv_cert), "%s/localhost-100y.cert",
		     certs);
	lws_snprintf(srv_key, sizeof(srv_key), "%s/localhost-100y.key", certs);
	lws_snprintf(ca, sizeof(ca), "%s/unrelated-ca.crt", certs);

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

#if defined(LWS_ROLE_H3)
	{
		struct lws_vhost *vh_h3;

		/* the same, as a quic listener on udp only */

		info.port			= CONTEXT_PORT_NO_LISTEN_SERVER;
		info.vhost_name			= "srv-h3";
		info.listen_accept_role		= "quic";
		info.listen_accept_protocol	= "scv";
		info.alpn			= "h3";

		vh_h3 = lws_create_vhost(context, &info);
		if (!vh_h3 ||
		    !lws_create_adopt_udp(vh_h3, server_addr, port_h3,
					  LWS_CAUDP_BIND, "scv", NULL, NULL,
					  NULL, NULL, "quic_listen")) {
			lwsl_err("Failed to create the h3 server vhost\n");
			goto bail;
		}

		info.listen_accept_role		= NULL;
		info.listen_accept_protocol	= NULL;
	}
#endif

	/* the client vhosts, no listener */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;

	info.vhost_name			= "trusted";
	info.client_ssl_ca_filepath	= srv_cert;
	vh_cli[SCV_VH_TRUSTED] = lws_create_vhost(context, &info);

	info.vhost_name			= "untrusted";
	info.client_ssl_ca_filepath	= ca;
	vh_cli[SCV_VH_UNTRUSTED] = lws_create_vhost(context, &info);

	if (!vh_cli[SCV_VH_TRUSTED] || !vh_cli[SCV_VH_UNTRUSTED]) {
		lwsl_err("Failed to create the client vhosts\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (!finished && !interrupted && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_context_destroy(context);

	lwsl_user("Completed: %s (%d of %d cases failed)\n",
		  result ? "FAIL" : "PASS", failures, (int)SCV_RUNS);

	return result;
}
