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
 * lws_genkem: the backend-independent part.
 *
 * Everything coming in is checked here, the same way whatever the backend,
 * before it reaches the backend's ML-KEM or the lws one.  The ctx then uses
 * the backend's ML-KEM if there is one that works, or else keeps its own
 * copies of the keys for the lws implementation.
 */

#include "private-lib-core.h"
#include "private-genkem.h"

static const struct lws_genkem_info genkem_info[] = {
	{ "ML-KEM-512",   800, 1632,  768 },
	{ "ML-KEM-768",  1184, 2400, 1088 },
	{ "ML-KEM-1024", 1568, 3168, 1568 },
};

const struct lws_genkem_info *
lws_genkem_info(enum lws_genkem_alg alg)
{
	if ((unsigned int)alg >= LWS_ARRAY_SIZE(genkem_info))
		return NULL;

	return &genkem_info[alg];
}

int
lws_genkem_create(struct lws_genkem_ctx *ctx, struct lws_context *context,
		  enum lws_genkem_alg alg)
{
	/* the caller must hand us a zeroed ctx; a still-live ctx is a misuse */
	if (ctx->created_mark == LWS_GENKEM_CTX_CREATED_MARK)
		return -1;

	if (!lws_genkem_info(alg))
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->context = context;
	ctx->alg = alg;
	ctx->created_mark = LWS_GENKEM_CTX_CREATED_MARK;

	return 0;
}

/* drop any key the ctx has, so a new one can be applied */
static void
genkem_drop_key(struct lws_genkem_ctx *ctx)
{
	const struct lws_genkem_info *info = lws_genkem_info(ctx->alg);

#if defined(LWS_GENKEM_HAVE_BACKEND)
	if (ctx->engine)
		lws_genkem_backend_destroy(ctx);
#endif
	ctx->engine = NULL;

	if (ctx->ek) {
		lws_explicit_bzero(ctx->ek, info->ek_len);
		lws_free_set_NULL(ctx->ek);
	}
	if (ctx->dk) {
		lws_explicit_bzero(ctx->dk, info->dk_len);
		lws_free_set_NULL(ctx->dk);
	}
}

static int
genkem_dup(uint8_t **dest, const uint8_t *src, size_t len)
{
	*dest = lws_malloc(len, "genkem");
	if (!*dest)
		return -1;

	memcpy(*dest, src, len);

	return 0;
}

/*
 * Applies a key that has passed its checks: exactly one of seed, dk or ek.
 * If ek_out / dk_out are given, they are filled with the resulting keys.
 */
static int
genkem_apply(struct lws_genkem_ctx *ctx, const uint8_t *seed,
	     const uint8_t *dk, const uint8_t *ek, uint8_t *ek_out,
	     uint8_t *dk_out)
{
	const struct lws_genkem_info *info = lws_genkem_info(ctx->alg);

	genkem_drop_key(ctx);

#if defined(LWS_GENKEM_HAVE_BACKEND)
	{
		int n = lws_genkem_backend_set_key(ctx, seed, dk, ek, ek_out,
						   dk_out);

		/* 1 means the backend can't do it, so we do it ourselves */
		if (n <= 0)
			return n;
	}
#endif

	if (seed) {
		ctx->ek = lws_malloc(info->ek_len, "genkem");
		ctx->dk = lws_malloc(info->dk_len, "genkem");
		if (!ctx->ek || !ctx->dk ||
		    lws_mlkem_keypair_derand(ctx->alg, seed, ctx->ek, ctx->dk))
			goto bail;
	} else if (dk) {
		/* the dk contains the ek, at offset 384k == dk_len - ek_len - 64 */
		if (genkem_dup(&ctx->dk, dk, info->dk_len) ||
		    genkem_dup(&ctx->ek, dk + info->dk_len - info->ek_len - 64,
			       info->ek_len))
			goto bail;
	} else {
		if (genkem_dup(&ctx->ek, ek, info->ek_len))
			goto bail;
	}

	if (ek_out)
		memcpy(ek_out, ctx->ek, info->ek_len);
	if (dk_out && ctx->dk)
		memcpy(dk_out, ctx->dk, info->dk_len);

	return 0;

bail:
	genkem_drop_key(ctx);

	return -1;
}

int
lws_genkem_new_keypair(struct lws_genkem_ctx *ctx, const uint8_t *seed,
		       struct lws_gencrypto_keyelem *el)
{
	const struct lws_genkem_info *info;
	uint8_t s[LWS_GENKEM_SEED_LEN];
	int n = -1;

	if (ctx->created_mark != LWS_GENKEM_CTX_CREATED_MARK)
		return -1;
	info = lws_genkem_info(ctx->alg);

	if (seed)
		memcpy(s, seed, sizeof(s));
	else
		if (lws_get_random(ctx->context, s, sizeof(s)) != sizeof(s))
			goto bail;

	if (!el) {
		n = genkem_apply(ctx, s, NULL, NULL, NULL, NULL);
		goto bail;
	}

	el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf = lws_malloc(info->ek_len, "genkem");
	el[LWS_GENCRYPTO_KEM_KEYEL_DK].buf = lws_malloc(info->dk_len, "genkem");
	el[LWS_GENCRYPTO_KEM_KEYEL_SEED].buf = lws_malloc(sizeof(s), "genkem");
	if (!el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf ||
	    !el[LWS_GENCRYPTO_KEM_KEYEL_DK].buf ||
	    !el[LWS_GENCRYPTO_KEM_KEYEL_SEED].buf)
		goto bail_el;

	el[LWS_GENCRYPTO_KEM_KEYEL_EK].len = info->ek_len;
	el[LWS_GENCRYPTO_KEM_KEYEL_DK].len = info->dk_len;
	el[LWS_GENCRYPTO_KEM_KEYEL_SEED].len = sizeof(s);
	memcpy(el[LWS_GENCRYPTO_KEM_KEYEL_SEED].buf, s, sizeof(s));

	n = genkem_apply(ctx, s, NULL, NULL, el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf,
			 el[LWS_GENCRYPTO_KEM_KEYEL_DK].buf);
	if (!n)
		goto bail;

bail_el:
	lws_genkem_destroy_elements(el);
	n = -1;

bail:
	lws_explicit_bzero(s, sizeof(s));

	return n;
}

int
lws_genkem_set_key(struct lws_genkem_ctx *ctx,
		   const struct lws_gencrypto_keyelem *el)
{
	const struct lws_gencrypto_keyelem *e;
	const struct lws_genkem_info *info;

	if (ctx->created_mark != LWS_GENKEM_CTX_CREATED_MARK || !el)
		return -1;
	info = lws_genkem_info(ctx->alg);

	e = &el[LWS_GENCRYPTO_KEM_KEYEL_SEED];
	if (e->buf && e->len) {
		if (e->len != LWS_GENKEM_SEED_LEN)
			return -1;

		return genkem_apply(ctx, e->buf, NULL, NULL, NULL, NULL);
	}

	e = &el[LWS_GENCRYPTO_KEM_KEYEL_DK];
	if (e->buf && e->len) {
		const struct lws_gencrypto_keyelem *ek =
					&el[LWS_GENCRYPTO_KEM_KEYEL_EK];

		/* FIPS 203 7.3 decapsulation key checks */

		if (e->len != info->dk_len ||
		    lws_mlkem_check_dk(ctx->alg, e->buf))
			return -1;

		/* an EK given alongside must be the one in the DK */

		if (ek->buf && ek->len &&
		    (ek->len != info->ek_len ||
		     memcmp(ek->buf, e->buf + info->dk_len - info->ek_len - 64,
			    info->ek_len)))
			return -1;

		return genkem_apply(ctx, NULL, e->buf, NULL, NULL, NULL);
	}

	e = &el[LWS_GENCRYPTO_KEM_KEYEL_EK];
	if (e->buf && e->len) {
		/* FIPS 203 7.2 encapsulation key checks */

		if (e->len != info->ek_len ||
		    lws_mlkem_check_ek(ctx->alg, e->buf))
			return -1;

		return genkem_apply(ctx, NULL, NULL, e->buf, NULL, NULL);
	}

	return -1;
}

int
lws_genkem_encapsulate(struct lws_genkem_ctx *ctx, uint8_t *ct, size_t ct_max,
		       uint8_t *ss)
{
	const struct lws_genkem_info *info;
	uint8_t m[32];
	int n;

	if (ctx->created_mark != LWS_GENKEM_CTX_CREATED_MARK)
		return -1;
	info = lws_genkem_info(ctx->alg);

	if (ct_max < info->ct_len)
		return -1;

#if defined(LWS_GENKEM_HAVE_BACKEND)
	if (ctx->engine)
		return lws_genkem_backend_encapsulate(ctx, ct, ss);
#endif

	if (!ctx->ek)
		return -1;

	if (lws_get_random(ctx->context, m, sizeof(m)) != sizeof(m))
		return -1;

	n = lws_mlkem_encaps_derand(ctx->alg, ctx->ek, m, ct, ss);
	lws_explicit_bzero(m, sizeof(m));

	return n;
}

int
lws_genkem_decapsulate(struct lws_genkem_ctx *ctx, const uint8_t *ct,
		       size_t ct_len, uint8_t *ss)
{
	const struct lws_genkem_info *info;

	if (ctx->created_mark != LWS_GENKEM_CTX_CREATED_MARK)
		return -1;
	info = lws_genkem_info(ctx->alg);

	if (ct_len != info->ct_len)
		return -1;

#if defined(LWS_GENKEM_HAVE_BACKEND)
	if (ctx->engine)
		return lws_genkem_backend_decapsulate(ctx, ct, ss);
#endif

	if (!ctx->dk)
		return -1;

	return lws_mlkem_decaps(ctx->alg, ctx->dk, ct, ss);
}

void
lws_genkem_destroy(struct lws_genkem_ctx *ctx)
{
	if (ctx->created_mark != LWS_GENKEM_CTX_CREATED_MARK)
		return;

	genkem_drop_key(ctx);
	memset(ctx, 0, sizeof(*ctx));
}

void
lws_genkem_destroy_elements(struct lws_gencrypto_keyelem *el)
{
	int n;

	for (n = 0; n < LWS_GENCRYPTO_KEM_KEYEL_COUNT; n++) {
		if (el[n].buf) {
			lws_explicit_bzero(el[n].buf, el[n].len);
			lws_free_set_NULL(el[n].buf);
		}
		el[n].len = 0;
	}
}
