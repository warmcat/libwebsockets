/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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
 *
 *  This is included from core/private.h if LWS_WITH_HTTP_STREAM_COMPRESSION
 */

#include <zlib.h>
#if defined(LWS_WITH_HTTP_BROTLI)
#include <brotli/encode.h>
#include <brotli/decode.h>
#endif

/*
 * struct holding union of all the available compression methods' context data,
 * and state if it's compressing or decompressing
 */

typedef struct lws_compression_ctx {
	union {

#if defined(LWS_WITH_HTTP_BROTLI)
		BrotliEncoderState *br_en;
		BrotliDecoderState *br_de;
#endif
		z_stream *deflate;
		void *generic_ctx_ptr;
	} u;

	struct lws_buflist *buflist_comp;

	unsigned int is_decompression:1;
	unsigned int final_on_input_side:1;
	unsigned int may_have_more:1;
	unsigned int chunking:1;
} lws_comp_ctx_t;

/* generic structure defining the interface to a compression method */

struct lws_compression_support {
	/** compression name as used by, eg, content-ecoding */
	const char *encoding_name;
	/** create a compression context for the compression method, or NULL */
	int (*init_compression)(lws_comp_ctx_t *ctx, int decomp);
	/** pass data into the context to be processed */
	int (*process)(lws_comp_ctx_t *ctx, const void *in, size_t *ilen_iused,
		       void *out, size_t *olen_oused);
	/** destroy the de/compression context */
	void (*destroy)(lws_comp_ctx_t *ctx);
};

extern struct lws_compression_support lcs_deflate;
extern struct lws_compression_support lcs_brotli;

int
lws_http_compression_validate(struct lws *wsi);

int
lws_http_compression_transform(struct lws *wsi, unsigned char *buf,
			       size_t len, enum lws_write_protocol *wp,
			       unsigned char **outbuf, size_t *olen_oused);

void
lws_http_compression_destroy(struct lws *wsi);
