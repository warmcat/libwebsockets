/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * CBC buffering and PKCS#7 padding, done once here for every backend.  The
 * backends only provide lws_genaes_cbc_blocks(), which runs CBC over whole
 * blocks, chained in the ctx from the iv this code leaves in ctx->tag.
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"

int
lws_genaes_create_common(struct lws_genaes_ctx *ctx, enum enum_aes_modes mode,
			 enum enum_aes_padding padding)
{
	/*
	 * Only CBC knows what to do with padding.  ECB did once on some
	 * backends, inconsistently, and losing the last block: refuse it
	 */

	if (mode == LWS_GAESM_ECB && padding == LWS_GAESP_WITH_PADDING) {
		lwsl_err("%s: ECB does not support padding\n", __func__);

		return -1;
	}

	ctx->padding = padding;
	ctx->cbc_total = 0;
	ctx->buf_len = 0;
	ctx->cbc_iv_set = 0;
	ctx->cbc_final = 0;

	return 0;
}

int
lws_genaes_cbc_crypt(struct lws_genaes_ctx *ctx, const uint8_t *in,
		     size_t len, uint8_t *out, const uint8_t *iv,
		     size_t *olen)
{
	size_t w = 0, n;

	if (olen)
		*olen = 0;

	if (ctx->cbc_final || (len && (!in || !out))) {
		lwsl_err("%s: bad args or already final\n", __func__);

		return -1;
	}

	if (!ctx->cbc_iv_set) {
		if (!iv) {
			lwsl_err("%s: CBC needs an iv\n", __func__);

			return -1;
		}
		memcpy(ctx->tag, iv, LWS_AES_CBC_BLOCKLEN);
		ctx->cbc_iv_set = 1;
	}

	if (ctx->padding != LWS_GAESP_WITH_PADDING ||
	    ctx->op == LWS_GAESO_DEC) {

		/* whole blocks in, the same amount out */

		if (len % LWS_AES_CBC_BLOCKLEN) {
			lwsl_err("%s: len %d not a multiple of the block size\n",
				 __func__, (int)len);

			return -1;
		}

		if (!len)
			goto done;

		if (lws_genaes_cbc_blocks(ctx, in, len, out))
			return -1;

		w = len;

		if (ctx->padding == LWS_GAESP_WITH_PADDING) {
			/* keep the last plaintext block to check its padding */
			memcpy(ctx->buf, out + len - LWS_AES_CBC_BLOCKLEN,
			       LWS_AES_CBC_BLOCKLEN);
			ctx->buf_len = LWS_AES_CBC_BLOCKLEN;
		}

		goto done;
	}

	/*
	 * Encrypting with padding: complete and send any partial block we
	 * kept from before, then the whole blocks of this input, and keep
	 * what is left over for next time or lws_genaes_final()
	 */

	if (ctx->buf_len) {
		n = LWS_AES_CBC_BLOCKLEN - (size_t)ctx->buf_len;
		if (n > len)
			n = len;
		memcpy(ctx->buf + ctx->buf_len, in, n);
		ctx->buf_len += (int)n;
		in += n;
		len -= n;

		if (ctx->buf_len < LWS_AES_CBC_BLOCKLEN)
			goto done;

		if (lws_genaes_cbc_blocks(ctx, ctx->buf, LWS_AES_CBC_BLOCKLEN,
					  out))
			return -1;

		w = LWS_AES_CBC_BLOCKLEN;
		ctx->buf_len = 0;
	}

	n = len - (len % LWS_AES_CBC_BLOCKLEN);
	if (n) {
		if (lws_genaes_cbc_blocks(ctx, in, n, out + w))
			return -1;
		w += n;
	}

	if (len - n) {
		memcpy(ctx->buf, in + n, len - n);
		ctx->buf_len = (int)(len - n);
	}

done:
	ctx->cbc_total += w;
	if (olen)
		*olen = w;

	return 0;
}

int
lws_genaes_final(struct lws_genaes_ctx *ctx, uint8_t *out, size_t out_max,
		 size_t *total_len)
{
	unsigned int p, bad, i;
	int ret = -1;

	if (total_len)
		*total_len = 0;

	if (ctx->mode != LWS_GAESM_CBC || ctx->cbc_final) {
		lwsl_err("%s: not CBC, or already final\n", __func__);

		return -1;
	}

	ctx->cbc_final = 1;

	if (ctx->padding != LWS_GAESP_WITH_PADDING) {
		ret = 0;
		goto bail;
	}

	if (ctx->op == LWS_GAESO_ENC) {
		if (!ctx->cbc_iv_set || !out || out_max < LWS_AES_CBC_BLOCKLEN) {
			lwsl_err("%s: no iv given, or no room for final block\n",
				 __func__);
			goto bail;
		}

		/* PKCS#7: 1 to 16 bytes, each the count of pad bytes */

		p = (unsigned int)(LWS_AES_CBC_BLOCKLEN - ctx->buf_len);
		memset(ctx->buf + ctx->buf_len, (int)p, p);

		if (lws_genaes_cbc_blocks(ctx, ctx->buf, LWS_AES_CBC_BLOCKLEN,
					  out))
			goto bail;

		ctx->cbc_total += LWS_AES_CBC_BLOCKLEN;
		ret = 0;
		goto bail;
	}

	if (ctx->buf_len != LWS_AES_CBC_BLOCKLEN) {
		lwsl_err("%s: no ciphertext\n", __func__);
		goto bail;
	}

	/*
	 * The padding is valid if the last byte p is 1 .. 16 and the last p
	 * bytes all equal p.  Check without branching on the data, so the
	 * time taken does not show where it went wrong.
	 */

	p = ctx->buf[LWS_AES_CBC_BLOCKLEN - 1];
	/* top bits set if p == 0 or p > 16 */
	bad = ((p - 1u) | (LWS_AES_CBC_BLOCKLEN - p)) >> 8;

	for (i = 0; i < LWS_AES_CBC_BLOCKLEN; i++) {
		/* all ones if byte i is inside the padding, else 0 */
		unsigned int in_pad = ((i + p - LWS_AES_CBC_BLOCKLEN) >> 31) - 1u;

		bad |= (ctx->buf[i] ^ p) & in_pad;
	}

	if (bad) {
		lwsl_info("%s: invalid padding\n", __func__);
		goto bail;
	}

	ctx->cbc_total -= p;
	ret = 0;

bail:
	if (!ret && total_len)
		*total_len = ctx->cbc_total;

	lws_explicit_bzero(ctx->buf, sizeof(ctx->buf));
	ctx->buf_len = 0;

	return ret;
}

int
lws_genaes_cbc_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag,
		       size_t tlen)
{
	int n = 0;

	if (ctx->mode != LWS_GAESM_CBC)
		return 0;

	/*
	 * Before lws_genaes_final() existed, the final block of a padded
	 * encrypt came out into destroy()'s tag on most backends: keep doing
	 * that for callers that don't call lws_genaes_final()
	 */

	if (ctx->padding == LWS_GAESP_WITH_PADDING &&
	    ctx->op == LWS_GAESO_ENC && ctx->cbc_iv_set && !ctx->cbc_final &&
	    tag && tlen >= LWS_AES_CBC_BLOCKLEN)
		n = lws_genaes_final(ctx, tag, tlen, NULL);

	lws_explicit_bzero(ctx->buf, sizeof(ctx->buf));
	lws_explicit_bzero(ctx->tag, sizeof(ctx->tag));
	ctx->buf_len = 0;
	ctx->cbc_final = 1;

	return n;
}
