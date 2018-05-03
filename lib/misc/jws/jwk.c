/*
 * libwebsockets - JSON Web Key support
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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

static const char * const jwk_tok[] = {
	"e", "n", "d", "p", "q", "dp", "dq", "qi", "kty", "k",
};

static int
_lws_jwk_set_element(struct lws_genrsa_element *e, char *in, int len)
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

struct cb_lws_jwk {
	struct lws_jwk *s;
	char *b64;
	int b64max;
	int pos;
};

static signed char
cb_jwk(struct lejp_ctx *ctx, char reason)
{
	struct cb_lws_jwk *cbs = (struct cb_lws_jwk *)ctx->user;
	struct lws_jwk *s = cbs->s;
	int idx;

	if (reason == LEJPCB_VAL_STR_START)
		cbs->pos = 0;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JWK_KTY:
		lws_strncpy(s->keytype, ctx->buf, sizeof(s->keytype));
		if (!strcmp(ctx->buf, "oct")) {
			break;
		}
		if (!strcmp(ctx->buf, "RSA")) {
			break;
		}
		return -1;

	case JWK_KEY:
//		if (strcmp(s->keytype, "oct"))
//			return -1;
		idx = JWK_KEY_E;
		goto read_element1;

	case JWK_KEY_N:
	case JWK_KEY_E:
	case JWK_KEY_D:
	case JWK_KEY_P:
	case JWK_KEY_Q:
	case JWK_KEY_DP:
	case JWK_KEY_DQ:
	case JWK_KEY_QI:
		idx = ctx->path_match - 1;
		goto read_element;
	}

	return 0;

read_element:
/* kty is no longer first in lex order */
//	if (strcmp(s->keytype, "RSA"))
//		return -1;

read_element1:

	if (cbs->pos + ctx->npos >= cbs->b64max)
		return -1;

	memcpy(cbs->b64 + cbs->pos, ctx->buf, ctx->npos);
	cbs->pos += ctx->npos;

	if (reason == LEJPCB_VAL_STR_CHUNK)
		return 0;

	if (_lws_jwk_set_element(&s->el.e[idx], cbs->b64, cbs->pos) < 0) {
		lws_jwk_destroy_genrsa_elements(&s->el);

		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jwk_import(struct lws_jwk *s, const char *in, size_t len)
{
	struct lejp_ctx jctx;
	struct cb_lws_jwk cbs;
	const int b64max = (((8192 / 8) * 4) / 3) + 1;  /* enough for 8K key */
	char b64[b64max];
	int m;

	memset(s, 0, sizeof(*s));
	cbs.s = s;
	cbs.b64 = b64;
	cbs.b64max = b64max;
	cbs.pos = 0;
	lejp_construct(&jctx, cb_jwk, &cbs, jwk_tok, ARRAY_SIZE(jwk_tok));
	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)in, len);
	lejp_destruct(&jctx);

	if (m < 0) {
		lwsl_notice("%s: parse got %d\n", __func__, m);

		return -1;
	}

	return 0;
}

LWS_VISIBLE void
lws_jwk_destroy(struct lws_jwk *s)
{
	lws_jwk_destroy_genrsa_elements(&s->el);
}

LWS_VISIBLE int
lws_jwk_export(struct lws_jwk *s, int private, char *p, size_t len)
{
	char *start = p, *end = &p[len - 1];
	int n, m, limit = LWS_COUNT_RSA_ELEMENTS;

	/* RFC7638 lexicographic order requires
	 *  RSA: e -> kty -> n
	 *  oct: k -> kty
	 */

	p += lws_snprintf(p, end - p, "{");

	if (!strcmp(s->keytype, "oct")) {
		if (!s->el.e[JWK_KEY_E].buf)
			return -1;

		p += lws_snprintf(p, end - p, "\"k\":\"");
		n = lws_jws_base64_enc((const char *)s->el.e[JWK_KEY_E].buf,
					      s->el.e[JWK_KEY_E].len, p,
					      end - p - 4);
		if (n < 0) {
			lwsl_notice("%s: enc failed\n", __func__);
			return -1;
		}
		p += n;

		p += lws_snprintf(p, end - p, "\",\"kty\":\"%s\"}", s->keytype);

		return p - start;
	}

	if (!strcmp(s->keytype, "RSA")) {
		if (!s->el.e[JWK_KEY_E].buf ||
		    !s->el.e[JWK_KEY_N].buf ||
		    (private && (!s->el.e[JWK_KEY_D].buf ||
				 !s->el.e[JWK_KEY_P].buf ||
				 !s->el.e[JWK_KEY_Q].buf))
		) {
			lwsl_notice("%s: not enough elements filled\n",
				    __func__);
			return -1;
		}

		if (!private)
			limit = JWK_KEY_N + 1;

		for (n = 0; n < limit; n++) {
			if (!s->el.e[n].buf)
				continue;
			lwsl_info("%d: len %d\n", n, s->el.e[n].len);

			if (n)
				p += lws_snprintf(p, end - p, ",");
			p += lws_snprintf(p, end - p, "\"%s\":\"", jwk_tok[n]);
			m = lws_jws_base64_enc((const char *)s->el.e[n].buf,
						      s->el.e[n].len, p,
						      end - p - 4);
			if (m < 0) {
				lwsl_notice("%s: enc fail inlen %d outlen %d\n",
						__func__, (int)s->el.e[n].len,
						lws_ptr_diff(end, p) - 4);
				return -1;
			}
			p += m;
			*p++ = '\"';

			if (!n) /* RFC7638 lexicographic order */
				p += lws_snprintf(p, end - p, ",\"kty\":\"%s\"",
						  s->keytype);
		}

		p += lws_snprintf(p, end - p, "}");

		return p - start;
	}

	lwsl_err("%s: unknown key type %s\n", __func__, s->keytype);

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
lws_jwk_load(struct lws_jwk *s, const char *filename)
{
	int buflen = 4096;
	char *buf = lws_malloc(buflen, "jwk-load");
	int n;

	if (!buf)
		return -1;

	n = lws_plat_read_file(filename, buf, buflen);
	if (n < 0)
		goto bail;

	n = lws_jwk_import(s, buf, n);
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
