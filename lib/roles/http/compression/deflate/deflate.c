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
 */

#include "core/private.h"

static int
lcs_init_compression_deflate(lws_comp_ctx_t *ctx, int decomp)
{
	int n;

	ctx->is_decompression = decomp;
	ctx->u.deflate = lws_malloc(sizeof(*ctx->u.deflate), __func__);

	if (!ctx->u.deflate)
		return 2;

	memset(ctx->u.deflate, 0, sizeof(*ctx->u.deflate));

	if (!decomp &&
	    (n = deflateInit2(ctx->u.deflate, 1, Z_DEFLATED, -15, 8,
			 Z_DEFAULT_STRATEGY)) != Z_OK) {
		lwsl_err("deflate init failed: %d\n", n);
		lws_free_set_NULL(ctx->u.deflate);

		return 1;
	}

	if (decomp &&
	    inflateInit2(ctx->u.deflate, 16 + 15) != Z_OK) {
		lws_free_set_NULL(ctx->u.deflate);
		return 1;
	}

	return 0;
}

static int
lcs_process_deflate(lws_comp_ctx_t *ctx, const void *in, size_t *ilen_iused,
		    void *out, size_t *olen_oused)
{
	size_t olen_oused_in = *olen_oused;
	int n;

	ctx->u.deflate->next_in = (void *)in;
	ctx->u.deflate->avail_in = *ilen_iused;

	ctx->u.deflate->next_out = out;
	ctx->u.deflate->avail_out = *olen_oused;

	if (!ctx->is_decompression)
		n = deflate(ctx->u.deflate, Z_SYNC_FLUSH);
	else
		n = inflate(ctx->u.deflate, Z_SYNC_FLUSH);

	switch (n) {
	case Z_NEED_DICT:
	case Z_STREAM_ERROR:
	case Z_DATA_ERROR:
	case Z_MEM_ERROR:
		lwsl_err("zlib error inflate %d\n", n);
		return -1;
	}

	*ilen_iused -= ctx->u.deflate->avail_in;
	*olen_oused -= ctx->u.deflate->avail_out;

	/* it's ambiguous with zlib... */
	ctx->may_have_more = (*olen_oused == olen_oused_in);

	return n == Z_STREAM_END;
}

static void
lcs_destroy_deflate(lws_comp_ctx_t *ctx)
{
	if (!ctx)
		return;

	if (!(*ctx).is_decompression)
		deflateEnd((*ctx).u.deflate);
	else
		inflateEnd((*ctx).u.deflate);

	lws_free_set_NULL(ctx->u.deflate);
}

struct lws_compression_support lcs_deflate = {
	/* .encoding_name */		"deflate",
	/* .init_compression */		lcs_init_compression_deflate,
	/* .process */			lcs_process_deflate,
	/* .destroy */			lcs_destroy_deflate,
};
