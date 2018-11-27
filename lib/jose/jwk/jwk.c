/*
 * libwebsockets - JSON Web Key support
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
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

#include <fcntl.h>
#include <unistd.h>

static const char * const kyt_names[] = {
	"unknown",	/* LWS_JWK_KYT_UNKNOWN */
	"oct",		/* LWS_JWK_KYT_OCT */
	"RSA",		/* LWS_JWK_KYT_RSA */
	"EC"		/* LWS_JWK_KYT_EC */
};

/*
 * These are the entire legal token set for names in jwk.
 *
 * The first version is used to parse a detached single jwk that don't have any
 * parent JSON context.  The second version is used to parse full jwk objects
 * that has a "keys": [ ] array containing the keys.
 */

static const char * const jwk_tok[] = {
	"keys[]",			/* dummy */
	"e", "n", "d", "p", "q", "dp", "dq", "qi", /* RSA */
	"kty",				/* generic */
	"k",				/* symmetric oct key data */
	"crv", "x", "y",		/* EC (also "D") */
	"kid",				/* generic */
	"use"				/* mutually exclusive with "key_ops" */,
	"key_ops"			/* mutually exclusive with "use" */,
	"x5c",				/* generic */
	"alg"				/* generic */
}, * const jwk_outer_tok[] = {
	"keys[]",
	"keys[].e", "keys[].n", "keys[].d", "keys[].p", "keys[].q", "keys[].dp",
	"keys[].dq", "keys[].qi",

	"keys[].kty", "keys[].k",		/* generic */
	"keys[].crv", "keys[].x", "keys[].y",	/* EC (also "D") */
	"keys[].kid", "keys[].use"	/* mutually exclusive with "key_ops" */,
	"keys[].key_ops",		/* mutually exclusive with "use" */
	"keys[].x5c", "keys[].alg"
};

/* information about each token declared above */

#define FLAG_META	(1 << 12)
#define FLAG_RSA	(1 << 13)
#define FLAG_EC		(1 << 14)
#define FLAG_OCT	(1 << 15)

unsigned short tok_map[] = {
	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | 0, /* padding */
	FLAG_RSA |				    JWK_RSA_KEYEL_E,
	FLAG_RSA |				    JWK_RSA_KEYEL_N,
	FLAG_RSA | FLAG_EC |			    JWK_RSA_KEYEL_D,
	FLAG_RSA |				    JWK_RSA_KEYEL_P,
	FLAG_RSA |				    JWK_RSA_KEYEL_Q,
	FLAG_RSA |				    JWK_RSA_KEYEL_DP,
	FLAG_RSA |				    JWK_RSA_KEYEL_DQ,
	FLAG_RSA |				    JWK_RSA_KEYEL_QI,

	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_KTY,
			     FLAG_OCT |		    JWK_OCT_KEYEL_K,

		   FLAG_EC |			    JWK_EC_KEYEL_CRV,
		   FLAG_EC |			    JWK_EC_KEYEL_X,
		   FLAG_EC |			    JWK_EC_KEYEL_Y,

	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_KID,
	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_USE,

	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_KEY_OPS,
	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_X5C,
	FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_ALG,
};

struct cb_lws_jwk {
	struct lws_jwk *s;
	char *b64;
	lws_jwk_key_import_callback per_key_cb;
	void *user;
	int b64max;
	int pos;
	unsigned short possible;
};

static int
_lws_jwk_set_element_jwk(struct lws_jwk_elements *e, char *in, int len)
{
	e->buf = lws_malloc(len + 1, "jwk");
	if (!e->buf)
		return -1;

	memcpy(e->buf, in, len);
	e->buf[len] = '\0';
	e->len = len;

	return 0;
}

static int
_lws_jwk_set_element_jwk_b64(struct lws_jwk_elements *e, char *in, int len)
{
	int dec_size = ((len * 3) / 4) + 4, n;

	e->buf = lws_malloc(dec_size, "jwk");
	if (!e->buf)
		return -1;

	n = lws_b64_decode_string_len(in, len, (char *)e->buf, dec_size - 1);
	if (n < 0)
		return -1;
	e->len = n;

	return 0;
}

void
lws_jwk_destroy_elements(struct lws_jwk_elements *el, int m)
{
	int n;

	for (n = 0; n < m; n++)
		if (el[n].buf)
			lws_free_set_NULL(el[n].buf);
}

LWS_VISIBLE void
lws_jwk_destroy(struct lws_jwk *s)
{
	lws_jwk_destroy_elements(s->e, LWS_ARRAY_SIZE(s->e));
	lws_jwk_destroy_elements(s->meta, LWS_ARRAY_SIZE(s->meta));
}

static signed char
cb_jwk(struct lejp_ctx *ctx, char reason)
{
	struct cb_lws_jwk *cbs = (struct cb_lws_jwk *)ctx->user;
	struct lws_jwk *s = cbs->s;
	int idx, poss;

	if (reason == LEJPCB_VAL_STR_START)
		cbs->pos = 0;

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == 0 + 1)
		/*
		 * new keys[] member is starting
		 *
		 * Until we see some JSON names, it could be anything...
		 * there is no requirement for kty to be given first and eg,
		 * ACME specifies the keys must be ordered in lexographic
		 * order - where kty is not first.
		 */
		cbs->possible = FLAG_RSA | FLAG_EC | FLAG_OCT;

	if (reason == LEJPCB_OBJECT_END && ctx->path_match == 0 + 1) {
		/* we completed parsing a key */
		if (cbs->per_key_cb && cbs->possible) {
			if (cbs->per_key_cb(cbs->s, cbs->user)) {

				lwsl_notice("%s: user cb halts import\n", __func__);

				return -2;
			}

			/* clear it down */
			lws_jwk_destroy(cbs->s);
			cbs->possible = 0;
		}
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (ctx->path_match == 0 + 1)
		return 0;

	idx = tok_map[ctx->path_match - 1];

	switch (idx) {
	/* note: kty is not necessarily first... we have to keep track of
	 * what could match given which element names have already been
	 * seen.  Once kty comes, we confirm it's still possible (ie, it's
	 * not trying to tell us that it's RSA when we saw a "crv"
	 * already) and then reduce the possibilities to just the one that
	 * kty told. */
	case FLAG_RSA | FLAG_EC | FLAG_OCT | FLAG_META | JWK_META_KTY:

		if (!strcmp(ctx->buf, "oct")) {
			if (!(cbs->possible & FLAG_OCT))
				goto elements_mismatch;
			s->kty = LWS_JWK_KYT_OCT;
			cbs->possible = FLAG_OCT;
			break;
		}
		if (!strcmp(ctx->buf, "RSA")) {
			if (!(cbs->possible & FLAG_RSA))
				goto elements_mismatch;
			s->kty = LWS_JWK_KYT_RSA;
			cbs->possible = FLAG_RSA;
			break;
		}
		if (!strcmp(ctx->buf, "EC")) {
			if (!(cbs->possible & FLAG_EC))
				goto elements_mismatch;
			s->kty = LWS_JWK_KYT_EC;
			cbs->possible = FLAG_EC;
			break;
		}
		lwsl_err("%s: Unknown KTY '%s'\n", __func__, ctx->buf);
		return -1;

	default:

		if (cbs->pos + ctx->npos >= cbs->b64max)
			goto bail;

		memcpy(cbs->b64 + cbs->pos, ctx->buf, ctx->npos);
		cbs->pos += ctx->npos;

		if (reason == LEJPCB_VAL_STR_CHUNK)
			return 0;

		/* chunking has been collated */

		poss = idx & (FLAG_RSA | FLAG_EC | FLAG_OCT);
		cbs->possible &= poss;
		if (!cbs->possible)
			goto elements_mismatch;

		if (idx & FLAG_META) {
			if (_lws_jwk_set_element_jwk(&s->meta[idx & 0x7f],
						     cbs->b64, cbs->pos) < 0)
				goto bail;

			break;
		}

		/* key data... do the base64 decode then */

		if (_lws_jwk_set_element_jwk_b64(&s->e[idx & 0x7f],
						 cbs->b64, cbs->pos) < 0)
			goto bail;

		break;
	}

	return 0;

elements_mismatch:
	lwsl_err("%s: jwk elements mismatch\n", __func__);

bail:
	lwsl_err("%s: element failed\n", __func__);

	return -1;
}

LWS_VISIBLE int
lws_jwk_import(struct lws_jwk *s, lws_jwk_key_import_callback cb, void *user,
	       const char *in, size_t len)
{
	struct lejp_ctx jctx;
	struct cb_lws_jwk cbs;
	const int b64max = (((8192 / 8) * 4) / 3) + 1;  /* enough for 8K key */
	const char * const *tok = jwk_outer_tok;
	char b64[b64max];
	int m;

	memset(s, 0, sizeof(*s));
	cbs.s = s;
	cbs.b64 = b64;
	cbs.b64max = b64max;
	cbs.pos = 0;
	cbs.per_key_cb = cb;
	cbs.user = user;
	cbs.possible = FLAG_RSA | FLAG_EC | FLAG_OCT;

	if (cb == NULL)
		tok = jwk_tok;

	lejp_construct(&jctx, cb_jwk, &cbs, tok, LWS_ARRAY_SIZE(jwk_tok));
	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)in, len);
	lejp_destruct(&jctx);

	if (m < 0) {
		lwsl_notice("%s: parse got %d\n", __func__, m);

		return -1;
	}

	if (s->kty == LWS_JWK_KYT_UNKNOWN) {
		lwsl_notice("%s: missing or unknown kyt\n", __func__);
		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jwk_export(struct lws_jwk *s, int private, char *p, size_t len)
{
	char *start = p, *end = &p[len - 1];
	int n, limit = LWS_COUNT_JWK_ELEMENTS;

	/* RFC7638 lexicographic order requires
	 *  RSA: e -> kty -> n
	 *  oct: k -> kty
	 */

	p += lws_snprintf(p, end - p, "{");

	switch (s->kty) {

	case LWS_JWK_KYT_OCT:
		if (!s->e[JWK_OCT_KEYEL_K].buf)
			return -1;

		p += lws_snprintf(p, end - p, "\"k\":\"");
		n = lws_jws_base64_enc((const char *)s->e[JWK_OCT_KEYEL_K].buf,
				s->e[JWK_OCT_KEYEL_K].len, p, end - p - 4);
		if (n < 0) {
			lwsl_notice("%s: enc failed\n", __func__);
			return -1;
		}
		p += n;

		p += lws_snprintf(p, end - p, "\",\"kty\":\"%s\"}",
				  kyt_names[s->kty]);

		return p - start;

	case LWS_JWK_KYT_RSA:
		if (!s->e[JWK_RSA_KEYEL_E].buf ||
		    !s->e[JWK_RSA_KEYEL_N].buf ||
		    (private && (!s->e[JWK_RSA_KEYEL_D].buf ||
				 !s->e[JWK_RSA_KEYEL_P].buf ||
				 !s->e[JWK_RSA_KEYEL_Q].buf))
		) {
			lwsl_notice("%s: not enough elements filled\n",
				    __func__);
			return -1;
		}

		if (!private)
			limit = JWK_RSA_KEYEL_N + 1;

		for (n = 0; n < limit; n++) {
			int m;

			if (!s->e[n].buf)
				continue;
			lwsl_info("%d: len %d\n", n, s->e[n].len);

			if (n)
				p += lws_snprintf(p, end - p, ",");
			p += lws_snprintf(p, end - p, "\"%s\":\"", jwk_tok[n]);
			m = lws_jws_base64_enc((const char *)s->e[n].buf,
						      s->e[n].len, p,
						      end - p - 4);
			if (m < 0) {
				lwsl_notice("%s: enc fail inlen %d outlen %d\n",
						__func__, (int)s->e[n].len,
						lws_ptr_diff(end, p) - 4);
				return -1;
			}
			p += m;
			*p++ = '\"';

			if (!n) /* RFC7638 lexicographic order */
				p += lws_snprintf(p, end - p, ",\"kty\":\"%s\"",
						  kyt_names[s->kty]);
		}

		p += lws_snprintf(p, end - p, "}");

		return p - start;

	case LWS_JWK_KYT_EC:
		return p - start;

	default:
		break;
	}

	lwsl_err("%s: unknown key type %d\n", __func__, s->kty);

	return -1;
}

LWS_VISIBLE int
lws_jwk_rfc7638_fingerprint(struct lws_jwk *s, char *digest32)
{
	struct lws_genhash_ctx hash_ctx;
	int tmpsize = 2536, n;
	char *tmp;

	tmp = lws_malloc(tmpsize, "rfc7638 tmp");

	n = lws_jwk_export(s, 0, tmp, tmpsize);
	if (n < 0)
		goto bail;

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256))
		goto bail;

	if (lws_genhash_update(&hash_ctx, tmp, n)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail;
	}
	lws_free(tmp);

	if (lws_genhash_destroy(&hash_ctx, digest32))
		return -1;

	return 0;

bail:
	lws_free(tmp);

	return -1;
}

LWS_VISIBLE int
lws_jwk_load(struct lws_jwk *s, const char *filename,
	     lws_jwk_key_import_callback cb, void *user)
{
	int buflen = 4096;
	char *buf = lws_malloc(buflen, "jwk-load");
	int n;

	if (!buf)
		return -1;

	n = lws_plat_read_file(filename, buf, buflen);
	if (n < 0)
		goto bail;

	n = lws_jwk_import(s, cb, user, buf, n);
	lws_free(buf);

	return n;
bail:
	lws_free(buf);

	return -1;
}

LWS_VISIBLE int
lws_jwk_save(struct lws_jwk *s, const char *filename)
{
	int buflen = 4096;
	char *buf = lws_malloc(buflen, "jwk-save");
	int n, m;

	if (!buf)
		return -1;

	n = lws_jwk_export(s, 1, buf, buflen);
	if (n < 0)
		goto bail;

	m = lws_plat_write_file(filename, buf, n);

	lws_free(buf);
	if (m)
		return -1;

	return 0;

bail:
	lws_free(buf);

	return -1;
}
