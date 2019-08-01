/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"
#include "lextable-strings.h"


const unsigned char *
lws_token_to_string(enum lws_token_indexes token)
{
	if ((unsigned int)token >= LWS_ARRAY_SIZE(set))
		return NULL;

	return (unsigned char *)set[token];
}

int
lws_add_http_header_by_name(struct lws *wsi, const unsigned char *name,
			    const unsigned char *value, int length,
			    unsigned char **p, unsigned char *end)
{
#ifdef LWS_WITH_HTTP2
	if (lwsi_role_h2(wsi) || lwsi_role_h2_ENCAPSULATION(wsi))
		return lws_add_http2_header_by_name(wsi, name,
						    value, length, p, end);
#else
	(void)wsi;
#endif
	if (name) {
		while (*p < end && *name)
			*((*p)++) = *name++;
		if (*p == end)
			return 1;
		*((*p)++) = ' ';
	}
	if (*p + length + 3 >= end)
		return 1;

	memcpy(*p, value, length);
	*p += length;
	*((*p)++) = '\x0d';
	*((*p)++) = '\x0a';

	return 0;
}

int lws_finalize_http_header(struct lws *wsi, unsigned char **p,
			     unsigned char *end)
{
#ifdef LWS_WITH_HTTP2
	if (lwsi_role_h2(wsi) || lwsi_role_h2_ENCAPSULATION(wsi))
		return 0;
#else
	(void)wsi;
#endif
	if ((lws_intptr_t)(end - *p) < 3)
		return 1;
	*((*p)++) = '\x0d';
	*((*p)++) = '\x0a';

	return 0;
}

int
lws_finalize_write_http_header(struct lws *wsi, unsigned char *start,
			       unsigned char **pp, unsigned char *end)
{
	unsigned char *p;
	int len;

	if (lws_finalize_http_header(wsi, pp, end))
		return 1;

	p = *pp;
	len = lws_ptr_diff(p, start);

	if (lws_write(wsi, start, len, LWS_WRITE_HTTP_HEADERS) != len)
		return 1;

	return 0;
}

int
lws_add_http_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end)
{
	const unsigned char *name;
#ifdef LWS_WITH_HTTP2
	if (lwsi_role_h2(wsi) || lwsi_role_h2_ENCAPSULATION(wsi))
		return lws_add_http2_header_by_token(wsi, token, value,
						     length, p, end);
#endif
	name = lws_token_to_string(token);
	if (!name)
		return 1;

	return lws_add_http_header_by_name(wsi, name, value, length, p, end);
}

int
lws_add_http_header_content_length(struct lws *wsi,
				   lws_filepos_t content_length,
				   unsigned char **p, unsigned char *end)
{
	char b[24];
	int n;

	n = lws_snprintf(b, sizeof(b) - 1, "%llu", (unsigned long long)content_length);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
					 (unsigned char *)b, n, p, end))
		return 1;
	wsi->http.tx_content_length = content_length;
	wsi->http.tx_content_remain = content_length;

	lwsl_info("%s: wsi %p: tx_content_length/remain %llu\n", __func__,
			wsi, (unsigned long long)content_length);

	return 0;
}

int
lws_add_http_common_headers(struct lws *wsi, unsigned int code,
			    const char *content_type, lws_filepos_t content_len,
			    unsigned char **p, unsigned char *end)
{
	const char *ka[] = { "close", "keep-alive" };
	int types[] = { HTTP_CONNECTION_CLOSE, HTTP_CONNECTION_KEEP_ALIVE },
			t = 0;

	if (lws_add_http_header_status(wsi, code, p, end))
		return 1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
		    			(unsigned char *)content_type,
		    			(int)strlen(content_type), p, end))
		return 1;

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (!wsi->http.lcs &&
	    (!strncmp(content_type, "text/", 5) ||
	     !strcmp(content_type, "application/javascript") ||
	     !strcmp(content_type, "image/svg+xml")))
		lws_http_compression_apply(wsi, NULL, p, end, 0);
#endif

	/*
	 * if we decided to compress it, we don't know the content length...
	 * the compressed data will go out chunked on h1
	 */
	if (
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    !wsi->http.lcs &&
#endif
	     content_len != LWS_ILLEGAL_HTTP_CONTENT_LEN) {
		if (lws_add_http_header_content_length(wsi, content_len,
						       p, end))
			return 1;
	} else {
		/* there was no length... it normally means CONNECTION_CLOSE */
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)

		if (!wsi->http2_substream && wsi->http.lcs) {
			/* so...
			 *  - h1 connection
			 *  - http compression transform active
			 *  - did not send content length
			 *
			 * then mark as chunked...
			 */
			wsi->http.comp_ctx.chunking = 1;
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(unsigned char *)"chunked", 7, p, end))
				return -1;

			/* ... but h1 compression is chunked, if active we can
			 * still pipeline
			 */
			if (wsi->http.lcs &&
			    wsi->http.conn_type == HTTP_CONNECTION_KEEP_ALIVE)
				t = 1;
		}
#endif
		if (!wsi->http2_substream) {
			if (lws_add_http_header_by_token(wsi,
						 WSI_TOKEN_CONNECTION,
						 (unsigned char *)ka[t],
						 (int)strlen(ka[t]), p, end))
				return 1;

			wsi->http.conn_type = types[t];
		}
	}

	return 0;
}

static const char * const err400[] = {
	"Bad Request",
	"Unauthorized",
	"Payment Required",
	"Forbidden",
	"Not Found",
	"Method Not Allowed",
	"Not Acceptable",
	"Proxy Auth Required",
	"Request Timeout",
	"Conflict",
	"Gone",
	"Length Required",
	"Precondition Failed",
	"Request Entity Too Large",
	"Request URI too Long",
	"Unsupported Media Type",
	"Requested Range Not Satisfiable",
	"Expectation Failed"
};

static const char * const err500[] = {
	"Internal Server Error",
	"Not Implemented",
	"Bad Gateway",
	"Service Unavailable",
	"Gateway Timeout",
	"HTTP Version Not Supported"
};

/* security best practices from Mozilla Observatory */

static const
struct lws_protocol_vhost_options pvo_hsbph[] = {{
	NULL, NULL, "referrer-policy:", "no-referrer"
}, {
	&pvo_hsbph[0], NULL, "x-frame-options:", "deny"
}, {
	&pvo_hsbph[1], NULL, "x-xss-protection:", "1; mode=block"
}, {
	&pvo_hsbph[2], NULL, "x-content-type-options:", "nosniff"
}, {
	&pvo_hsbph[3], NULL, "content-security-policy:",
	"default-src 'none'; img-src 'self' data: ; "
		"script-src 'self'; font-src 'self'; "
		"style-src 'self'; connect-src 'self'; "
		"frame-ancestors 'none'; base-uri 'none';"
		"form-action 'self';"
}};

int
lws_add_http_header_status(struct lws *wsi, unsigned int _code,
			   unsigned char **p, unsigned char *end)
{
	static const char * const hver[] = {
		"HTTP/1.0", "HTTP/1.1", "HTTP/2"
	};
	const struct lws_protocol_vhost_options *headers;
	unsigned int code = _code & LWSAHH_CODE_MASK;
	const char *description = "", *p1;
	unsigned char code_and_desc[60];
	int n;

#ifdef LWS_WITH_ACCESS_LOG
	wsi->http.access_log.response = code;
#endif

#ifdef LWS_WITH_HTTP2
	if (lwsi_role_h2(wsi) || lwsi_role_h2_ENCAPSULATION(wsi)) {
		n = lws_add_http2_header_status(wsi, code, p, end);
		if (n)
			return n;
	} else
#endif
	{
		if (code >= 400 && code < (400 + LWS_ARRAY_SIZE(err400)))
			description = err400[code - 400];
		if (code >= 500 && code < (500 + LWS_ARRAY_SIZE(err500)))
			description = err500[code - 500];

		if (code == 100)
			description = "Continue";
		if (code == 200)
			description = "OK";
		if (code == 304)
			description = "Not Modified";
		else
			if (code >= 300 && code < 400)
				description = "Redirect";

		if (wsi->http.request_version < LWS_ARRAY_SIZE(hver))
			p1 = hver[wsi->http.request_version];
		else
			p1 = hver[0];

		n = lws_snprintf((char *)code_and_desc, sizeof(code_and_desc) - 1, "%s %u %s", p1, code,
			    description);

		if (lws_add_http_header_by_name(wsi, NULL, code_and_desc, n, p,
						end))
			return 1;
	}

	headers = wsi->vhost->headers;
	while (headers) {
		if (lws_add_http_header_by_name(wsi,
				(const unsigned char *)headers->name,
				(unsigned char *)headers->value,
				(int)strlen(headers->value), p, end))
			return 1;

		headers = headers->next;
	}

	if (wsi->vhost->options &
	    LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE) {
		headers = &pvo_hsbph[LWS_ARRAY_SIZE(pvo_hsbph) - 1];
		while (headers) {
			if (lws_add_http_header_by_name(wsi,
					(const unsigned char *)headers->name,
					(unsigned char *)headers->value,
					(int)strlen(headers->value), p, end))
				return 1;

			headers = headers->next;
		}
	}

	if (wsi->context->server_string &&
	    !(_code & LWSAHH_FLAG_NO_SERVER_NAME))
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
				(unsigned char *)wsi->context->server_string,
				wsi->context->server_string_len, p, end))
			return 1;

	if (wsi->vhost->options & LWS_SERVER_OPTION_STS)
		if (lws_add_http_header_by_name(wsi, (unsigned char *)
				"Strict-Transport-Security:",
				(unsigned char *)"max-age=15768000 ; "
				"includeSubDomains", 36, p, end))
			return 1;

	if (*p >= (end - 2)) {
		lwsl_err("%s: reached end of buffer\n", __func__);

		return 1;
	}

	return 0;
}

LWS_VISIBLE int
lws_return_http_status(struct lws *wsi, unsigned int code,
		       const char *html_body)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	unsigned char *p = pt->serv_buf + LWS_PRE;
	unsigned char *start = p;
	unsigned char *end = p + context->pt_serv_buf_size - LWS_PRE;
	char *body = (char *)start + context->pt_serv_buf_size - 512;
	int n = 0, m = 0, len;
	char slen[20];

	if (!wsi->vhost) {
		lwsl_err("%s: wsi not bound to vhost\n", __func__);

		return 1;
	}
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (!wsi->handling_404 &&
	    wsi->vhost->http.error_document_404 &&
	    code == HTTP_STATUS_NOT_FOUND)
		/* we should do a redirect, and do the 404 there */
		if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
			       (uint8_t *)wsi->vhost->http.error_document_404,
			       (int)strlen(wsi->vhost->http.error_document_404),
			       &p, end) > 0)
			return 0;
#endif

	/* if the redirect failed, just do a simple status */
	p = start;

	if (!html_body)
		html_body = "";

	if (lws_add_http_header_status(wsi, code, &p, end))
		return 1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)"text/html", 9,
					 &p, end))
		return 1;

	len = lws_snprintf(body, 510, "<html><head>"
		"<meta charset=utf-8 http-equiv=\"Content-Language\" "
			"content=\"en\"/>"
		"<link rel=\"stylesheet\" type=\"text/css\" "
			"href=\"/error.css\"/>"
		"</head><body><h1>%u</h1>%s</body></html>", code, html_body);


	n = lws_snprintf(slen, 12, "%d", len);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
					 (unsigned char *)slen, n, &p, end))
		return 1;

	if (lws_finalize_http_header(wsi, &p, end))
		return 1;

#if defined(LWS_WITH_HTTP2)
	if (wsi->http2_substream) {

		/*
		 * for HTTP/2, the headers must be sent separately, since they
		 * go out in their own frame.  That puts us in a bind that
		 * we won't always be able to get away with two lws_write()s in
		 * sequence, since the first may use up the writability due to
		 * the pipe being choked or SSL_WANT_.
		 *
		 * However we do need to send the human-readable body, and the
		 * END_STREAM.
		 *
		 * Solve it by writing the headers now...
		 */
		m = lws_write(wsi, start, lws_ptr_diff(p, start),
			      LWS_WRITE_HTTP_HEADERS);
		if (m != lws_ptr_diff(p, start))
			return 1;

		/*
		 * ... but stash the body and send it as a priority next
		 * handle_POLLOUT
		 */
		wsi->http.tx_content_length = len;
		wsi->http.tx_content_remain = len;

		wsi->h2.pending_status_body = lws_malloc(len + LWS_PRE + 1,
							"pending status body");
		if (!wsi->h2.pending_status_body)
			return -1;

		strcpy(wsi->h2.pending_status_body + LWS_PRE, body);
		lws_callback_on_writable(wsi);

		return 0;
	} else
#endif
	{
		/*
		 * for http/1, we can just append the body after the finalized
		 * headers and send it all in one go.
		 */

		n = lws_ptr_diff(p, start) + len;
		memcpy(p, body, len);
		m = lws_write(wsi, start, n, LWS_WRITE_HTTP);
		if (m != n)
			return 1;
	}

	return m != n;
}

LWS_VISIBLE int
lws_http_redirect(struct lws *wsi, int code, const unsigned char *loc, int len,
		  unsigned char **p, unsigned char *end)
{
	unsigned char *start = *p;

	if (lws_add_http_header_status(wsi, code, p, end))
		return -1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, loc, len,
					 p, end))
		return -1;
	/*
	 * if we're going with http/1.1 and keepalive, we have to give fake
	 * content metadata so the client knows we completed the transaction and
	 * it can do the redirect...
	 */
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)"text/html", 9, p,
					 end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
					 (unsigned char *)"0", 1, p, end))
		return -1;

	if (lws_finalize_http_header(wsi, p, end))
		return -1;

	return lws_write(wsi, start, *p - start, LWS_WRITE_HTTP_HEADERS |
						 LWS_WRITE_H2_STREAM_END);
}

#if !defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
LWS_VISIBLE int
lws_http_compression_apply(struct lws *wsi, const char *name,
			   unsigned char **p, unsigned char *end, char decomp)
{
	(void)wsi;
	(void)name;
	(void)p;
	(void)end;
	(void)decomp;

	return 0;
}
#endif

int
lws_http_headers_detach(struct lws *wsi)
{
	return lws_header_table_detach(wsi, 0);
}
