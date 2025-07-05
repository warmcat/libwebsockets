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

struct per_session_data__lws_urlarg {
	char	urlarg[16384];
	int	alen;
	int	wlen;
	char	h;
};

static int
callback_lws_urlarg(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_urlarg *pss =
			(struct per_session_data__lws_urlarg *)user;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_info("%s: CALLBACK_HTTP\n", __func__);
		pss->alen = lws_get_urlarg_by_name_safe(wsi, "x", pss->urlarg + LWS_PRE,
					        sizeof(pss->urlarg) - LWS_PRE - 1);
		if (pss->alen < 0) {
			lwsl_debug("get urlarg failed\n");
			pss->urlarg[0] = '\0';
		}

		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_info("%s: CALLBACK_HTTP_WRITEABLE\n", __func__);

		if (!pss->h) {
			unsigned char headers[2048], *p = headers + LWS_PRE, *start = p, *end = p + sizeof(headers) - LWS_PRE - 1;
			int n;

			if (lws_add_http_header_status(wsi, HTTP_STATUS_OK,
                                                       &p, end))
                                goto bail;

                        if (lws_add_http_header_by_token(wsi,
                                        WSI_TOKEN_HTTP_CONTENT_TYPE,
                                        (unsigned char *)"text/html", 9,
                                        &p, end))
                                goto bail;
                        if (lws_add_http_header_content_length(wsi, (unsigned int)pss->alen, &p, end))
                                goto bail;
                        if (lws_finalize_http_header(wsi, &p, end))
                                goto bail;

                        /* first send the headers ... */
                        n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
                                      LWS_WRITE_HTTP_HEADERS);
                        if (n < 0)
                                goto bail;

			pss->h = 1;

			lws_callback_on_writable(wsi);
			break;
		}

		if (pss->alen >= 0 && pss->alen != pss->wlen) {
			lws_write(wsi, (unsigned char *)(pss->urlarg + LWS_PRE), (size_t)pss->alen, LWS_WRITE_HTTP);

			pss->wlen = pss->alen;


bail:
			if (lws_http_transaction_completed(wsi))
				return -1;

			return 0;
		}
		break;

	default:
		break;
	}

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

LWS_VISIBLE const lws_plugin_protocol_t urlarg = {
	.hdr = {
		"lws urlarg",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_urlarg_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_urlarg_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
