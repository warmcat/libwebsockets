/*
 * lws-minimal-http-client-post-form
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http client using lws to POST a form,
 * using the newer client multipart form generation apis
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 0, status, completed;
static lws_state_notify_link_t nl;
static struct lws *client_wsi;

struct pss {
	struct lws_http_mp_sm	*hmp; /* opaque */
};

/*
 * This allows lws_http_mp_sm to get its form elements from commandline options
 */

int
form_cb(struct lws_context *cx, char *ft, size_t ft_len, const char **last)
{
	const char *p = lws_cmdline_options_cx(cx, "--form", *last);

	if (!p)
		return 1;

	*last = p;
	lws_strnncpy(ft, *last, strlen(*last), ft_len);

	return 0;
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];
	int n;

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		bad = 1;
		completed++;
		lws_cancel_service(lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		bad |= status != 200;
		completed++;
		lws_http_mp_sm_destroy(&pss->hmp);
		lws_cancel_service(lws_get_context(wsi));
		break;

	/* ...callbacks related to receiving the result... */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		lwsl_user("Connected with server response: %d\n", status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		lwsl_hexdump_notice(in, len);
		return 0; /* don't passthru */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = sizeof(buf) - LWS_PRE;
		if (lws_http_client_read(wsi, (char **)&p, &n) < 0)
			return -1;

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		bad |= status != 200;
		/*
		 * Do this to mark us as having processed the completion
		 * so close doesn't duplicate (with pipelining, completion !=
		 * connection close
		 */
		client_wsi = NULL;
		lws_cancel_service(lws_get_context(wsi));
		break;

	/* ...callbacks related to generating the POST... */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	{
		uint8_t **pin = (unsigned char **)in, *endin = (*pin) + len;

		pss->hmp = NULL;

		if (lws_http_is_redirected_to_get(wsi)) {
			lwsl_user("%s: LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: redirected to GET\n", __func__);
			break;
		}

		pss->hmp = lws_http_mp_sm_init(wsi, form_cb, pin, endin);
		if (!pss->hmp)
			return 1;

		lwsl_user("%s: doing POST body\n", __func__);

		/*
		 * Tell lws we are going to send the body next...
		 */

		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (lws_http_is_redirected_to_get(wsi))
			break;

		if (!pss->hmp)
			return 0;

		n = lws_http_mp_sm_fill(pss->hmp, &p, end);
		if (n < 0)
			return 0;
		if (!n) {
			lws_client_http_body_pending(wsi, 0);
			lws_http_mp_sm_destroy(&pss->hmp);
		}

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      n ? LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) != lws_ptr_diff(p, start))
			return 1;

		if (n)
			lws_callback_on_writable(wsi);

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
		sizeof(struct pss),
		0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};


static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
	const char *p, *prot = NULL, *url = "https://libwebsockets.org:443/testserver/formtest";
	struct lws_client_connect_info i;
	static char urlcp[128];

	switch (target) {
	case LWS_SYSTATE_OPERATIONAL:
		if (current != LWS_SYSTATE_OPERATIONAL)
			break;

		memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
		i.context			= cx;
		i.ssl_connection		= LCCSCF_USE_SSL; /* notice must NOT use multipart flag */

		if (lws_cmdline_option_cx(cx, "-l")) {
			url			= "https://localhost:7681/formtest";
			i.ssl_connection	|= LCCSCF_ALLOW_SELFSIGNED;
		}

		p = lws_cmdline_option_cx(cx, NULL);
		if (p) {
			url = p;
			lwsl_notice("%s: setting url to %s\n", __func__, p);
		}

		strncpy(urlcp, url, sizeof(urlcp));
		if (lws_parse_uri(urlcp, &prot, &i.address, &i.port, &i.path)) {
			lwsl_err("%s: URL like https://warmcat.com/mypath needed\n", __func__);
			return 1;
		}

		p = lws_cmdline_option_cx(cx, "--port");
		if (p)
			i.port = atoi(p);

		if (lws_cmdline_option_cx(cx, "--form1"))
			i.path			= "/form1";

		i.host				= i.address;
		i.origin			= i.address;
		i.method			= "POST";

		/* force h1 even if h2 available */
		if (lws_cmdline_option_cx(cx, "--h1"))
			i.alpn			= "http/1.1";

		i.protocol			= protocols[0].name;
		i.pwsi				= &client_wsi;

		lwsl_user("%s: connecting to https://%s:%d/%s\n", __func__, i.address, i.port, i.path);
		if (!lws_client_connect_via_info(&i))
			completed++;
		break;
	}

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};


static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS minimal http client form - POST [-d<verbosity>] [-l] [--h1] https://libwebsockets.org/testserver/formtest\n");

	info.options			= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols;

	/* integrate us with lws system state management when context created */
	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;
	info.register_notifier_list	= app_notifier_list;
	info.fd_limit_per_thread = (unsigned int)(1 + 1 + 1);

#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	if (!lws_cmdline_option(argc, argv, "-l"))
		info.client_ssl_ca_filepath = "./libwebsockets.org.cer";
#endif

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (lws_system_adopt_stdin(context, LWS_SAS_FLAG__APPEND_COMMANDLINE)) {
		lwsl_err("%s: failed to adopt stdin\n", __func__);
		goto bail;
	}

	/*
	 * Init continues in app_system_state_nf() above after we reach system
	 * state OPERATIONAL
	 */

	while (n >= 0 && completed != 1 && !interrupted)
		n = lws_service(context, 0);

bail:
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}
