/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Notice that the lws_pthread... locking apis are all zero-footprint
 * NOPs in the case LWS_MAX_SMP == 1, which is the default.  When lws
 * is built for multiple service threads though, they resolve to their
 * pthreads equivalents.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>

/*
 * The url arg value is attacker-controlled and is echoed into a text/html
 * body, so it has to be escaped.  Every input character costs at most 6 output
 * characters ("&quot;"), so the escaped body buffer is sized 6x the raw arg
 * buffer and the escaping cannot truncate.
 */

#define URLARG_MAX_ARG	2048

struct per_session_data__lws_urlarg {
	/* the escaped body we will send, from + LWS_PRE */
	char	body[LWS_PRE + (URLARG_MAX_ARG * 6) + 1];
	char	arg[URLARG_MAX_ARG];
	int	blen;	/* length of the body at body + LWS_PRE */
	unsigned int	status;
	char	h;
	char	sent_body;
};

static const char * const urlarg_no_arg =
	"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/>"
	"<title>lws urlarg demo</title></head><body>"
	"<p>Give the text to echo in the <code>x</code> url argument, eg, "
	"<code>?x=hello</code></p></body></html>";

/*
 * Escape the five characters that can break out of HTML text or of a quoted
 * attribute value.  We only start another character while there is room for
 * the longest expansion (6) plus the NUL, so we can never emit a partial
 * entity; with the buffer sizing above we never actually reach that limit.
 */

static int
urlarg_html_escape(const char *in, char *out, size_t out_size)
{
	char *p = out;

	while (*in && p + 6 < out + out_size) {
		if (*in == '<') { memcpy(p, "&lt;", 4); p += 4; }
		else if (*in == '>') { memcpy(p, "&gt;", 4); p += 4; }
		else if (*in == '&') { memcpy(p, "&amp;", 5); p += 5; }
		else if (*in == '"') { memcpy(p, "&quot;", 6); p += 6; }
		else if (*in == '\'') { memcpy(p, "&#39;", 5); p += 5; }
		else *p++ = *in;
		in++;
	}

	*p = '\0';

	return lws_ptr_diff(p, out);
}

static int
callback_lws_urlarg(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_urlarg *pss =
			(struct per_session_data__lws_urlarg *)user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_info("%s: CALLBACK_HTTP\n", __func__);

		if (lws_get_urlarg_by_name_safe(wsi, "x", pss->arg,
						sizeof(pss->arg)) < 0) {
			/*
			 * No "x" arg at all, or it was too big for us... say
			 * so, rather than announce a body we will never send
			 */
			lwsl_debug("%s: no usable x url arg\n", __func__);
			pss->status = HTTP_STATUS_BAD_REQUEST;
			pss->blen = (int)strlen(lws_strncpy(pss->body + LWS_PRE,
						urlarg_no_arg,
						sizeof(pss->body) - LWS_PRE));
		} else {
			pss->status = HTTP_STATUS_OK;
			pss->blen = urlarg_html_escape(pss->arg,
						pss->body + LWS_PRE,
						sizeof(pss->body) - LWS_PRE);
		}

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_info("%s: CALLBACK_HTTP_WRITEABLE\n", __func__);

		if (!pss->h) {
			unsigned char headers[2048],
				      *p = headers + LWS_PRE, *start = p,
				      *end = p + sizeof(headers) - LWS_PRE - 1;

			if (lws_add_http_header_status(wsi, pss->status, &p,
						       end))
				goto bail;

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(unsigned char *)"text/html", 9,
					&p, end))
				goto bail;

			if (lws_add_http_header_content_length(wsi,
					(lws_filepos_t)(unsigned int)pss->blen,
					&p, end))
				goto bail;

			if (lws_finalize_http_header(wsi, &p, end))
				goto bail;

			/* first send the headers ... */
			if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
				      LWS_WRITE_HTTP_HEADERS) < 0)
				goto bail;

			pss->h = 1;

			lws_callback_on_writable(wsi);
			break;
		}

		if (pss->sent_body)
			break;

		pss->sent_body = 1;

		if (pss->blen &&
		    lws_write(wsi, (unsigned char *)pss->body + LWS_PRE,
			      (size_t)pss->blen, LWS_WRITE_HTTP) < 0)
			return -1;

		goto bail;

	default:
		break;
	}

	return 0;

bail:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_URLARG { \
		"lws-urlarg-protocol", \
		callback_lws_urlarg, \
		sizeof(struct per_session_data__lws_urlarg), \
		4096, /* rx buf size must be >= permessage-deflate rx size */ \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_urlarg_protocols[] = {
	LWS_PLUGIN_PROTOCOL_URLARG
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t urlarg = {
	.hdr = {
		.name = "lws urlarg",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_urlarg_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_urlarg_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
