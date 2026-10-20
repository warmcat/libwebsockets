/*
 * lws-api-test-ss-redirect
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Streams client whose policy allows redirects sends what its policy
 * and metadata put in its headers again to wherever a redirect takes it.  So a
 * stream carrying credentials in them (here the device serial, as "x-dsn:",
 * or an api key in a metadata-bound "x-api-key:") follows a redirect only
 * over https with strict verification, to the host it started with or a
 * subdomain of it, or to a host its policy's "redirect_credentials_to" names.
 * Otherwise the redirect is refused, however it is spelled:
 *
 *  - a relative path, an absolute URI naming our host, and a network-path
 *    reference ("//host:port/path") naming our host are followed
 *
 *  - an absolute URI, or a network-path reference, naming another host is
 *    refused: the second is not a path, it names another authority as much
 *    as the first does
 *
 *  - our own host, but over http, is refused
 *
 *  - another host the policy names in "redirect_credentials_to" is followed
 *
 *  - a stream carrying no credentials, only ordinary headers (an "accept:"
 *    from metadata), follows a redirect to another host
 *
 * A small raw socket server in the same process, over tls and also on a
 * plaintext port, answers "/start/<phase>" with that phase's redirect, and
 * anything else with a 200, noting what it was asked for.  Each phase is a
 * stream of its own, with no retries.  The server is "srv.localhost" and the
 * "other" host is "other.localhost", another name for the same server, which
 * its certificate is also valid for, so a redirect to it that was followed
 * would reach the server, and be seen.  lws resolves both to loopback itself,
 * and they are names, not addresses, so every tls backend can check them.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_PORT,
	LWS_SW_PORT_PLAIN,
	LWS_SW_CERT,
	LWS_SW_KEY,
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "-p",	"Port for the tls test server "
					"(default 7681)" },
	[LWS_SW_PORT_PLAIN] = { "--port-plain", "Port for the plaintext test "
					"server (default 7682)" },
	[LWS_SW_CERT]	= { "--cert",	"The test server's certificate "
					"(default ss-redirect-100y.cert)" },
	[LWS_SW_KEY]	= { "--key",	"The test server's key "
					"(default ss-redirect-100y.key)" },
	[LWS_SW_SERVER]	= { "--server",	"Address the client connects to "
					"(default srv.localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

typedef struct phase {
	const char		*name;
	const char		*streamtype;
	const char		*loc;		/* a format taking a host and
						 * the server's port */
	char			other;		/* the host is not ours */
	char			plain;		/* the plaintext server's port */
	const char		*target;	/* followed: what the server
						 * must be asked for after, or
						 * NULL: refused */
} phase_t;

static const phase_t phases[] = {
	{ "relative path",		"redir", "/same",	0, 0, "/same" },
	{ "absolute URI, our host",	"redir", "https://%s:%d/abs",
					0, 0, "/abs" },
	{ "//host:port/path, our host",	"redir", "//%s:%d/np",	0, 0, "/np" },
	{ "absolute URI, another host",	"redir", "https://%s:%d/x",
					1, 0, NULL },
	{ "//host:port/path, another host", "redir", "//%s:%d/x", 1, 0, NULL },
	{ "our host, over http",	"redir", "http://%s:%d/down",
					0, 1, NULL },
	{ "another host the policy names", "redir-allow", "https://%s:%d/allow",
					1, 0, "/allow" },
	{ "another host, no credentials", "redir-anon", "https://%s:%d/anon",
					1, 0, "/anon" },
	{ "api key, another host",	"redir-key", "https://%s:%d/x",
					1, 0, NULL },
	{ "api key, our host",		"redir-key", "/key",	0, 0, "/key" },
};

static const char * const phase_md[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
};

/* the test server's certificate, as the client's trust store */
static const char self_localhost_der_b64[] =
	"MIIDkjCCAnqgAwIBAgIUHBQ5uhiSLoIH0S2UZsjERBrnQeQwDQYJKoZIhvcNAQELBQAwNTEbMBkGA1UECgwSbGlid2Vic29ja2V0cy10ZXN0MRYwFAYDVQQDDA1zcnYubG9jYWxob3N0MCAXDTI2MTAyMDA5MDQwOFoYDzIxMjYwOTI2MDkwNDA4WjA1MRswGQYDVQQKDBJsaWJ3ZWJzb2NrZXRzLXRlc3QxFjAUBgNVBAMMDXNydi5sb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCYoU8tBbhl1iSZItdhSL1ZJqI0addrRV1Wj94EA0+09uo7awzpXa9Gkllzou/ctAGJprAj5eX5Q/p++SkcwNU16SdXJl0KNC4/k9udlAiS53IbHHAZgCMKVz0SP/Ao4NMhFubiSvWsYdwjHNWKEpo6EZEx1ggXFQ6qeqa03kDKoNUC8P4+mradUA1a2EYsAT2Qkv/dkoPVaCNbzbW/OHUNJwcN8W0snSdwdUiyzoA/DmPkJjKYXe0o9iR6Llwhb0OObZgqd35qMqD/qU5ekaDizcOa1pUGVj6KlXkNOu9PSCEMKYBPVHOilAqQ+yp6NdqyPZBZLu5M52sgXzxiossdAgMBAAGjgZcwgZQwHQYDVR0OBBYEFIKRYvaoCN6OS/MrQc4Z1DsxuJNQMB8GA1UdIwQYMBaAFIKRYvaoCN6OS/MrQc4Z1DsxuJNQMA8GA1UdEwEB/wQFMAMBAf8wQQYDVR0RBDowOIINc3J2LmxvY2FsaG9zdIIPb3RoZXIubG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBAQBrzJJp4TYDzpQet0oj0UQuP7GHj/FhAmOE2GtLVH9ZZiIUBPFtuB7XoU6LvZ7SIxCgmNnIqFCzNTyoEJLSKvwoLvtgT6YD/Fez2GL0i5KOgrSc74mqD6/V9zaQYWSPQ/FoGrfYYfNhDDAV75eViwhrGIauUAyaUfordZaV5Tt/PaTdW/wQzTvLZ8Fs99IaBYv3GuOw1ZdaScTA/EkEdhnTNitVLJ+DI1f4AvhEHGB9dod31Ae5l8FwE+fQB3YdEelZ8vGSO+bnwJXwX+4FLF4jjdL2WI7OGDpOA1OD0fw1kJTEHVh1K/yZC/JvJHGcQ32sMx4sXFGxrAdHPf5gl1fW";

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_next;
/*
 * Siblings under "localhost", which lws resolves to loopback itself: the other
 * host must not be a subdomain of ours, where credentials may follow
 */
static const char *server_ads = "srv.localhost",
		  *other_ads = "other.localhost";
static unsigned int cur_phase;
static int failed, port = 7681, port_plain = 7682, phase_ok;
static char asked[64];			/* the last thing the server was asked */

static void
finish(int fail)
{
	if (fail)
		failed = 1;
	lws_default_loop_exit(context);
}

/*
 * The raw socket server side
 */

typedef struct srv_pss {
	char			req[1024];
	char			resp[256];
	size_t			req_len;
	int			resp_len;
} srv_pss_t;

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	srv_pss_t *pss = (srv_pss_t *)user;
	uint8_t buf[LWS_PRE + sizeof(pss->resp)];
	const char *sp1, *sp2, *ads;
	char loc[128], host[64];
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->resp_len)
			break;

		if (len > sizeof(pss->req) - 1 - pss->req_len) {
			lwsl_err("%s: request too large\n", __func__);
			return -1;
		}
		memcpy(pss->req + pss->req_len, in, len);
		pss->req_len += len;
		pss->req[pss->req_len] = '\0';

		if (!strstr(pss->req, "\r\n\r\n"))
			break; /* wait for the rest of the request headers */

		/* the request line is "GET <target> HTTP/1.1" */

		sp1 = strchr(pss->req, ' ');
		sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
		if (!sp2) {
			lwsl_err("%s: bad request line\n", __func__);
			return -1;
		}
		lws_strnncpy(asked, sp1 + 1, lws_ptr_diff_size_t(sp2, sp1 + 1),
			     sizeof(asked));
		lwsl_user("%s: server was asked for %s\n", __func__, asked);

		if (!strncmp(asked, "/start/", 7)) {
			n = atoi(asked + 7);
			if (n < 0 || n >= (int)LWS_ARRAY_SIZE(phases))
				return -1;
			ads = phases[n].other ? other_ads : server_ads;
			/* an IPv6 literal goes in a URI in brackets */
			lws_snprintf(host, sizeof(host),
				     strchr(ads, ':') ? "[%s]" : "%s", ads);
			lws_snprintf(loc, sizeof(loc), phases[n].loc, host, /* NOSONAR: const test table */
				     phases[n].plain ? port_plain : port);
			pss->resp_len = lws_snprintf(pss->resp,
					sizeof(pss->resp),
					"HTTP/1.1 302 Found\r\n"
					"Location: %s\r\n"
					"Content-Length: 0\r\n"
					"Connection: close\r\n\r\n", loc);
		} else
			pss->resp_len = lws_snprintf(pss->resp,
					sizeof(pss->resp),
					"HTTP/1.1 200 OK\r\n"
					"Content-Length: 2\r\n"
					"Connection: close\r\n\r\nok");

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->resp_len)
			break;
		if (pss->resp_len < 0)
			/* the response has gone out, it said we close */
			return -1;

		memcpy(buf + LWS_PRE, pss->resp, (size_t)pss->resp_len);
		if (lws_write(wsi, buf + LWS_PRE, (size_t)pss->resp_len,
			      LWS_WRITE_RAW) != pss->resp_len)
			return -1;

		pss->resp_len = -1;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "redir-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The Secure Streams client side
 */

typedef struct cli {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} cli_t;

static void
start_phase(lws_sorted_usec_list_t *sul);

/* the phase ended one way or the other: judge it, and go on to the next */

static lws_ss_state_return_t
phase_end(int completed)
{
	const phase_t *ph = &phases[cur_phase];
	int ok;

	if (phase_ok)
		return LWSSSSRET_OK;
	phase_ok = 1;

	if (ph->target)
		ok = completed && !strcmp(asked, ph->target);
	else
		ok = !completed && !strncmp(asked, "/start/", 7);

	lwsl_user("--- phase %s: %s (completed %d, server last asked %s) ---\n",
		  ph->name, ok ? "PASS" : "FAIL", completed, asked);
	if (!ok)
		failed = 1;

	if (++cur_phase == LWS_ARRAY_SIZE(phases))
		finish(0);
	else
		lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return LWSSSSRET_DESTROY_ME;
}

static lws_ss_state_return_t
cli_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
cli_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	cli_t *m = (cli_t *)userobj;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_QOS_ACK_REMOTE:
		return phase_end(1);

	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		return phase_end(0);

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.streamtype			= "redir",
	.rx				= cli_rx,
	.state				= cli_state,
	.user_alloc			= sizeof(cli_t),
};

static void
start_phase(lws_sorted_usec_list_t *sul)
{
	lws_ss_info_t ssi = ssi_cli;
	struct lws_ss_handle *ss;

	lwsl_user("=== phase %s ===\n", phases[cur_phase].name);
	phase_ok = 0;
	asked[0] = '\0';

	ssi.streamtype = phases[cur_phase].streamtype;

	if (lws_ss_create(context, 0, &ssi, NULL, &ss, NULL, NULL) ||
	    lws_ss_set_metadata(ss, "phase", phase_md[cur_phase], 1) ||
	    (!strcmp(ssi.streamtype, "redir-key") &&
	     lws_ss_set_metadata(ss, "apikey", "secret-key", 10)) ||
	    (!strcmp(ssi.streamtype, "redir-anon") &&
	     lws_ss_set_metadata(ss, "acc", "text/plain", 10)) ||
	    lws_ss_client_connect(ss)) {
		lwsl_err("%s: unable to start phase\n", __func__);
		finish(1);
	}
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/*
	 * Start from the event loop, so the server vhost is certainly
	 * listening by then
	 */
	lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in phase %s ---\n",
		 cur_phase < LWS_ARRAY_SIZE(phases) ?
				phases[cur_phase].name : "(end)");
	finish(1);
}

static void
sigint_handler(int sig)
{
	finish(1);
}

/* the streamtypes, all of them like this, differing in what they carry */

#define SSR_ST(name, extra) \
	"{\"" name "\":{" \
	"\"endpoint\":\"%s\",\"port\":%d,\"protocol\":\"h1\"," \
	"\"http_method\":\"GET\",\"http_url\":\"start/${phase}\"," \
	"\"allow_redirects\":true,\"retry\":\"none\"," \
	"\"tls\":true,\"tls_trust_store\":\"self\"," extra "}}"

int
main(int argc, const char **argv)
{
	const char *cert = "ss-redirect-100y.cert", *key = "ss-redirect-100y.key";
	struct lws_context_creation_info info;
	char *policy;
	const char *p;
	size_t pl;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT_PLAIN].sw)))
		port_plain = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CERT].sw)))
		cert = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KEY].sw)))
		key = p;
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS redirects keep credentials home\n");

	/* no retries: a refused redirect ends the phase at once */

	pl = sizeof(self_localhost_der_b64) + 4096;
	policy = malloc(pl);
	if (!policy)
		return 1;

	lws_snprintf(policy, pl,
		"{\"release\":\"01234567\",\"product\":\"myproduct\","
		 "\"schema-version\":1,"
		 "\"retry\":[{\"none\":{\"backoff\":[],"
			"\"conceal\":0,\"jitterpc\":0,"
			"\"svalidping\":30,\"svalidhup\":35}}],"
		 "\"certs\":[{\"self_localhost\":\"%s\"}],"
		 "\"trust_stores\":[{\"name\":\"self\","
			"\"stack\":[\"self_localhost\"]}],"
		 "\"s\":["
		  SSR_ST("redir", "\"metadata\":[{\"phase\":\"\"}],"
				  "\"http_dsn_header\":\"x-dsn:\"") ","
		  SSR_ST("redir-allow", "\"metadata\":[{\"phase\":\"\"}],"
				  "\"http_dsn_header\":\"x-dsn:\","
				  "\"redirect_credentials_to\":"
					"[\"other.example\",\"%s\"]") ","
		  SSR_ST("redir-anon", "\"metadata\":[{\"phase\":\"\"},"
					"{\"acc\":\"accept:\"}]") ","
		  SSR_ST("redir-key", "\"metadata\":[{\"phase\":\"\"},"
					"{\"apikey\":\"x-api-key:\"}]")
		 "]}",
		self_localhost_der_b64,
		server_ads, port, server_ads, port, other_ads,
		server_ads, port, server_ads, port);

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		free(policy);
		return 1;
	}

	/* the identity the stream's headers carry */

	lws_system_blob_direct_set(lws_system_get_blob(context,
				   LWS_SYSBLOB_TYPE_DEVICE_SERIAL, 0),
				   (const uint8_t *)"serial-1234", 11);

	/* the raw socket server vhosts, over tls and plaintext */

	info.protocols	= protocols_srv;
	info.options	= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			  LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "redir-srv";

	info.vhost_name	= "redir-srv";
	info.port	= port;
	info.ssl_cert_filepath = cert;
	info.ssl_private_key_filepath = key;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}

	info.vhost_name	= "redir-srv-plain";
	info.port	= port_plain;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create plaintext server vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 30 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);
	free(policy);

	if (cur_phase != LWS_ARRAY_SIZE(phases))
		failed = 1;

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;

bail:
	lws_context_destroy(context);
	free(policy);

	return 1;
}
