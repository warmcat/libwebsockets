/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"

#include "lextable-strings.h"


const unsigned char *lws_token_to_string(enum lws_token_indexes token)
{
	if ((unsigned int)token >= ARRAY_SIZE(set))
		return NULL;

	return (unsigned char *)set[token];
}

int
lws_add_http_header_by_name(struct lws *wsi, const unsigned char *name,
			    const unsigned char *value, int length,
			    unsigned char **p, unsigned char *end)
{
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWSCM_HTTP2_SERVING)
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
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWSCM_HTTP2_SERVING)
		return 0;
#else
	(void)wsi;
#endif
	if ((long)(end - *p) < 3)
		return 1;
	*((*p)++) = '\x0d';
	*((*p)++) = '\x0a';

	return 0;
}

int
lws_add_http_header_by_token(struct lws *wsi, enum lws_token_indexes token,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end)
{
	const unsigned char *name;
#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWSCM_HTTP2_SERVING)
		return lws_add_http2_header_by_token(wsi, token, value, length, p, end);
#endif
	name = lws_token_to_string(token);
	if (!name)
		return 1;
	return lws_add_http_header_by_name(wsi, name, value, length, p, end);
}

int lws_add_http_header_content_length(struct lws *wsi,
				       unsigned long content_length,
				       unsigned char **p, unsigned char *end)
{
	char b[24];
	int n;

	n = sprintf(b, "%lu", content_length);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
					 (unsigned char *)b, n, p, end))
		return 1;
	wsi->u.http.content_length = content_length;
	wsi->u.http.content_remain = content_length;

	return 0;
}

STORE_IN_ROM static const char * const err400[] = {
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

STORE_IN_ROM static const char * const err500[] = {
	"Internal Server Error",
	"Not Implemented",
	"Bad Gateway",
	"Service Unavailable",
	"Gateway Timeout",
	"HTTP Version Not Supported"
};

int
lws_add_http_header_status(struct lws *wsi, unsigned int code,
			   unsigned char **p, unsigned char *end)
{
	const struct lws_protocol_vhost_options *headers;
	unsigned char code_and_desc[60];
	const char *description = "", *p1;
	int n;
	STORE_IN_ROM static const char * const hver[] = {
		"HTTP/1.0", "HTTP/1.1", "HTTP/2"
	};

#ifdef LWS_WITH_ACCESS_LOG
	wsi->access_log.response = code;
#endif

#ifdef LWS_USE_HTTP2
	if (wsi->mode == LWSCM_HTTP2_SERVING)
		return lws_add_http2_header_status(wsi, code, p, end);
#endif
	if (code >= 400 && code < (400 + ARRAY_SIZE(err400)))
		description = err400[code - 400];
	if (code >= 500 && code < (500 + ARRAY_SIZE(err500)))
		description = err500[code - 500];

	if (code == 200)
		description = "OK";

	if (code == 304)
		description = "Not Modified";
	else
		if (code >= 300 && code < 400)
			description = "Redirect";

	if (wsi->u.http.request_version < ARRAY_SIZE(hver))
		p1 = hver[wsi->u.http.request_version];
	else
		p1 = hver[0];

	n = sprintf((char *)code_and_desc, "%s %u %s",
		    p1, code, description);

	if (lws_add_http_header_by_name(wsi, NULL, code_and_desc,
					   n, p, end))
		return 1;

	headers = wsi->vhost->headers;
	while (headers) {
		if (lws_add_http_header_by_name(wsi,
				(const unsigned char *)headers->name,
				(unsigned char *)headers->value,
				strlen(headers->value), p, end))
			return 1;

		headers = headers->next;
	}

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
					 (unsigned char *)
					 	 wsi->context->server_string,
					 wsi->context->server_string_len,
					 p, end))
		return 1;

	if (wsi->vhost->options & LWS_SERVER_OPTION_STS)
		if (lws_add_http_header_by_name(wsi, (unsigned char *)
				"Strict-Transport-Security:",
				(unsigned char *)"max-age=15768000 ; "
				"includeSubDomains", 36, p, end))
			return 1;

	return 0;
}

LWS_VISIBLE int
lws_return_http_status(struct lws *wsi, unsigned int code,
		       const char *html_body)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	unsigned char *p = pt->serv_buf + LWS_PRE;
	unsigned char *start = p, *body = p + 512;
	unsigned char *end = p + context->pt_serv_buf_size - LWS_PRE;
	int n, m, len;
	char slen[20];

	if (!html_body)
		html_body = "";

	len = sprintf((char *)body, "<html><body><h1>%u</h1>%s</body></html>",
		      code, html_body);

	if (lws_add_http_header_status(wsi, code, &p, end))
		return 1;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)"text/html", 9,
					 &p, end))
		return 1;
	n = sprintf(slen, "%d", len);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
					 (unsigned char *)slen, n,
					 &p, end))
		return 1;

	if (lws_finalize_http_header(wsi, &p, end))
		return 1;

	m = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
	if (m != (int)(p - start))
		return 1;

	m = lws_write(wsi, body, len, LWS_WRITE_HTTP);

	return m != n;
}

LWS_VISIBLE int
lws_http_redirect(struct lws *wsi, int code, const unsigned char *loc, int len,
		  unsigned char **p, unsigned char *end)
{
	unsigned char *start = *p;
	int n;

	if (lws_add_http_header_status(wsi, code, p, end))
		return -1;

	if (lws_add_http_header_by_token(wsi,
			WSI_TOKEN_HTTP_LOCATION,
			loc, len, p, end))
		return -1;
	/*
	 * if we're going with http/1.1 and keepalive,
	 * we have to give fake content metadata so the
	 * client knows we completed the transaction and
	 * it can do the redirect...
	 */
	if (lws_add_http_header_by_token(wsi,
			WSI_TOKEN_HTTP_CONTENT_TYPE,
			(unsigned char *)"text/html", 9,
			p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi,
			WSI_TOKEN_HTTP_CONTENT_LENGTH,
			(unsigned char *)"0", 1, p, end))
		return -1;

	if (lws_finalize_http_header(wsi, p, end))
		return -1;

	n = lws_write(wsi, start, *p - start,
			LWS_WRITE_HTTP_HEADERS);

	return n;
}
