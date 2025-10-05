/*
 * lws-minimal-http-client-post-form
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http client using lws to POST a form.
 *
 * https://scan.coverity.com/builds?project=warmcat%2Flibwebsockets
 * --form file=@xxx.bin
 * --form version=f2dcc4ea
 * --form description="lws qa"
 * --form token=mytoken
 * --form email=my@email.com
 *
 * We want it to emit this kind of thing:
 *
 * POST /builds?project=warmcat%2Flibwebsockets HTTP/1.1
 * Host: 127.0.0.1
 * User-Agent: lws
 * Accept: * / *
 * Content-Length: 698
 * Content-Type: multipart/form-data; boundary=------------------------dbe229171d826cc3
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="file"; filename="xxx.bin"
 * Content-Type: application/octet-stream
 *
 * #!/bin/bash -x
 * xxx
 * exit $?
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="version"
 *
 * f2dcc4ea
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="description"
 * 
 * lws qa
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="token"
 *
 * mytoken
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="email"
 *
 * my@email.com
 * --------------------------dbe229171d826cc3--
 *
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 0, status, completed;
static lws_state_notify_link_t nl;
static struct lws *client_wsi;

typedef enum {
	LWS_POST_STATE__NEXT,
	LWS_POST_STATE__BOUNDARY,
	LWS_POST_STATE__MULTIHDR,
	LWS_POST_STATE__FILE,
	LWS_POST_STATE__DATA,
	LWS_POST_STATE__TERM
} post_state;

struct pss {
	char		body_part;
	char		boundary[24 + 16 + 1];
	char		ft[256];
	char		*eq;
	int		fd;
	lws_filepost_t	pos;
	lws_filepost_t  total;
	const char	*a; /* last hit */
	post_state	ps;
};

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1], mph[512];
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
		if (lws_http_client_read(wsi, &p, &n) < 0)
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
		/* abort poll wait */
		lws_cancel_service(lws_get_context(wsi));
		break;

	/* ...callbacks related to generating the POST... */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	{
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		char cla[32 + sizeof(pss->boundary)], ft[256], *eq;
		lws_filepost_t cl = 0;
		const char *a = NULL;
		struct stat s;

		/* create 40-char random pss->boundary */

		for (n = 0; n < 24; n++)
			pss->boundary[n] = '-';
		lws_hex_random(lws_get_context(wsi), pss->boundary + 24, 16);
		pss->boundary[24 + 16] = '\0';

		n = lws_snprintf(cla, sizeof(cla), "multipart/form-data; boundary=%s", pss->boundary);
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
			     (const uint8_t *)cla, n, p, end))
			 return -1;

		/*
		 * We have to now add together the length of everything we will put in
		 * the body, in order to know the content-length now at header-time.
		 *
		 * That includes the multipart boundaries, headers, and CRLF delimiters.
		 */

		do {
			a = lws_cmdline_options_cx(lws_get_context(wsi), "--form", &a);
			if (!a)
				break;
			lws_strnncpy(ft, a, strlen(a), sizeof(ft));
			eq = strchr(ft, '=');
			if (eq) {
				*eq = '\0';
				eq++;
			} /* ft contains the lhs of the = (now NUL) and eq the rhs sz */

			cl += 2 /* -- */ + strlen(pss->boundary) + 2 /* CRLF */;
			if (*eq == '@') { /* ie, form file contents */
				cl += lws_snprintf(mph, sizeof(mph),
						   "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\x0d\x0a"
						   "Content-Type: application/octet-stream\x0d\x0a\x0d\x0a",
						   ft, eq + 1);
				if (stat(eq + 1, &s)) {
					lwsl_warn("%s: failed to stat %s\n", __func__, eq + 1);
					return -1;
				}

				cl += s.st_size;
				continue;
			}

			/* form data */

			cl += lws_snprintf(mph, sizeof(mph),
					   "Content-Disposition: form-data; name=\"%s\"\x0d\x0a\x0d\x0a", ft);
			cl += strlen(eq) + 2 /* CRLF */;

		} while (1);

		cl += 2 /* -- */ + strlen(pss->boundary) + 2 /* -- */ + 2 /* CRLF */;

		if (lws_add_http_header_content_length(wsi, cl, p, end))
			return -1;

		pss->a		= NULL;
		pss->pos	= 0;
		pss->total	= 0;

		/*
		 * Tell lws we are going to send the body next...
		 */

		if (!lws_http_is_redirected_to_get(wsi)) {
			lwsl_user("%s: doing POST flow\n", __func__);
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		} else
			lwsl_user("%s: doing GET flow\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (lws_http_is_redirected_to_get(wsi))
			break;

		lwsl_user("LWS_CALLBACK_CLIENT_HTTP_WRITEABLE\n");
		n = LWS_WRITE_HTTP;

		do {
			switch (pss->ps) {
			case LWS_POST_STATE__NEXT:
				pss->a = lws_cmdline_options_cx(lws_get_context(wsi), "--form", &pss->a);
				if (!a)
					break;
				lws_strnncpy(ft, a, strlen(a), sizeof(ft));
				eq = strchr(ft, '=');
				if (eq) {
					*eq = '\0';
					eq++;
				} /* ft contains the lhs of the = (now NUL) and eq the rhs sz */

				cl += 2 /* -- */ + strlen(pss->boundary) + 2 /* CRLF */;
				if (*eq == '@') { /* ie, form file contents */
					cl += lws_snprintf(mph, sizeof(mph),
							   "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\x0d\x0a"
							   "Content-Type: application/octet-stream\x0d\x0a\x0d\x0a",
							   ft, eq + 1);
					pss->fd = open(eq + 1, O_RDONLY);
					if (pss->fd == -1) {
						lwsl_warn("%s: unable to open '%s'\n", __func__, eq + 1);
						return -1;
					}
					if (fstat(pss->fd, &s)) {
						lwsl_warn("%s: failed to stat %s\n", __func__, eq + 1);
						return -1;
					}
					cl += s.st_size;
					continue;
				}

				/* form data */

				cl += lws_snprintf(mph, sizeof(mph),
					   "Content-Disposition: form-data; name=\"%s\"\x0d\x0a\x0d\x0a", ft);
				cl += strlen(eq) + 2 /* CRLF */;

				break;

			case LWS_POST_STATE__BOUNDARY:
			case LWS_POST_STATE__MULTIHDR:
			case LWS_POST_STATE__FILE: {
				size_t chunk = lws_ptr_diff_size_t(end, p);
				ssize_t r;

				r = read(pss->fd, p, chunk);
				if (r < 0) {
					lwsl_warn("%s: unable to read\n", __func__);
					return -1;
				}
				p += chunk;
				break;
			}
			case LWS_POST_STATE__DATA:
			case LWS_POST_STATE__TERM:
			}

		do {
		} while (1);



		switch (pss->body_part++) {
		case 0:
			if (lws_client_http_multipart(wsi, "text", NULL, NULL,
						      &p, end))
				return -1;
			/* notice every usage of the boundary starts with -- */
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "my text field\xd\xa");
			break;
		case 1:
			if (lws_client_http_multipart(wsi, "file", "myfile.txt",
						      "text/plain", &p, end))
				return -1;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"This is the contents of the "
					"uploaded file.\xd\xa"
					"\xd\xa");
			break;
		case 2:
			if (lws_client_http_multipart(wsi, NULL, NULL, NULL,
						      &p, end))
				return -1;
			lws_client_http_body_pending(wsi, 0);
			 /* necessary to support H2, it means we will write no
			  * more on this stream */
			n = LWS_WRITE_HTTP_FINAL;
			break;

		default:
			/*
			 * We can get extra callbacks here, if nothing to do,
			 * then do nothing.
			 */
			return 0;
		}

		if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(p, start), (enum lws_write_protocol)n)
				!= lws_ptr_diff(p, start))
			return 1;

		if (n != LWS_WRITE_HTTP_FINAL)
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
		i.ssl_connection		= LCCSCF_USE_SSL | LCCSCF_HTTP_MULTIPART_MIME;

		if (lws_cmdline_option_cx(cx, "-l")) {
			url = "https://libwebsockets.org:443/testserver/formtest";
			i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
		}

		p = lws_cmdline_option_cx(cx, NULL);
		if (p)
			url = p;

		strncpy(urlcp, url, sizeof(urlcp));
		if (lws_parse_uri(urlcp, &prot, &i.address, &i.port, &i.path)) {
			lwsl_err("%s: URL like https://warmcat.com/mypath needed\n", __func__);
			return 1;
		}


		if (lws_cmdline_option_cx(cx, "--form1"))
			i.path				= "/form1";

		i.host				= i.address;
		i.origin			= i.address;
		i.method = "POST";

		/* force h1 even if h2 available */
		if (lws_cmdline_option_cx(cx, "--h1"))
			i.alpn			= "http/1.1";

		i.protocol = protocols[0].name;

		i.pwsi = &client_wsi;
		lwsl_user("%s: connecting to %s\n", __func__, url);
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
	lwsl_user("LWS minimal http client - POST [-d<verbosity>] [-l] [--h1] https://libwebsockets.org/testserver/formtest\n");

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
