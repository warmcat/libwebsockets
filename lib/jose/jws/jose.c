/*
 * libwebsockets - JSON Web Signature support
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
 *
 * JOSE is actually specified as part of JWS RFC7515.  JWE references RFC7515
 * to specify its JOSE JSON object.  So it lives in ./lib/jose/jws/jose.c.
 */

#include "core/private.h"

#include <stdint.h>

static const char * const jws_jose[] = {
	"alg", /* REQUIRED */
	"jku",
	"jwk",
	"kid",
	"x5u",
	"x5c",
	"x5t",
	"x5t#S256",
	"typ",
	"cty",
	"crit",

	/* valid for JWE only below here */

	"enc",
	"zip", /* ("DEF" = deflate) */

	"epk", /* valid for JWE ECDH only */
	"apu", /* valid for JWE ECDH only */
	"apv", /* valid for JWE ECDH only */
	"iv",  /* valid for JWE AES only */
	"tag", /* valid for JWE AES only */
	"p2s", /* valid for JWE PBES2 only */
	"p2c"  /* valid for JWE PBES2 only */
};

struct jose_cb_args {
	const struct lws_jose_jwe_alg **args;
	const struct lws_jose_jwe_alg **enc_args; /* null for jws case */
	int is_jwe;
};

static signed char
lws_jws_jose_cb(struct lejp_ctx *ctx, char reason)
{
	struct jose_cb_args *args = (struct jose_cb_args *)ctx->user;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {

	/* strings */

	case LJJHI_ALG: /* REQUIRED */

		/*
		 * look up whether we support this alg and point the caller at
		 * its definition if so
		 */

		if (!args->is_jwe &&
		    lws_gencrypto_jws_alg_to_definition(ctx->buf, args->args)) {
			lwsl_notice("%s: unknown alg '%s'\n", __func__,
				    ctx->buf);

			return -1;
		}

		if (args->is_jwe &&
		    lws_gencrypto_jwe_alg_to_definition(ctx->buf, args->args)) {
			lwsl_notice("%s: unknown alg '%s'\n", __func__,
				    ctx->buf);

			return -1;
		}

		return 0;

	case LJJHI_TYP: /* Optional: string: media type */
		if (strcmp(ctx->buf, "JWT"))
			return -1;
		break;

	case LJJHI_JKU:	/* Optional: string */
	case LJJHI_KID:	/* Optional: string */
	case LJJHI_X5U:	/* Optional: string: url of public key cert / chain */
	case LJJHI_CTY:	/* Optional: string: content media type */

	/* base64 */

	case LJJHI_X5C:	/* Optional: base64 (NOT -url): actual cert */

	/* base64-url */

	case LJJHI_X5T:	/* Optional: base64url: SHA-1 of actual cert */
	case LJJHI_X5T_S256: /* Optional: base64url: SHA-256 of actual cert */

	/* array of strings */

	case LJJHI_CRIT: /* Optional for send, REQUIRED: array of strings:
			  * mustn't contain standardized strings or null set */
		break;

	/* jwk child */

	case LJJHI_JWK:	/* Optional: jwk JSON object: public key: */

	/* past here, JWE only */

	case LJJHI_ENC:	/* JWE only: Optional: string */
		if (!args->is_jwe)
			return -1;
		if (lws_gencrypto_jwe_enc_to_definition(ctx->buf,
							args->enc_args)) {
			lwsl_notice("%s: unknown enc '%s'\n", __func__,
				    ctx->buf);

			return -1;
		}
		break;

	case LJJHI_ZIP:	/* JWE only: Optional: string ("DEF" = deflate) */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_EPK:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_APU:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_APV:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_IV:  /* Additional arg for JWE AES */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_TAG:	/* Additional arg for JWE AES */
		if (!args->is_jwe)
			return -1;
		break;

	case LJJHI_P2S:	/* Additional arg for JWE PBES2 */
		if (!args->is_jwe)
			return -1;
		break;
	case LJJHI_P2C:	/* Additional arg for JWE PBES2 */
		if (!args->is_jwe)
			return -1;
		break;

	/* ignore what we don't understand */

	default:
		return 0;
	}

	return 0;
}


static int
lws_jose_parse(const struct lws_jose_jwe_alg **_args,
	       const struct lws_jose_jwe_alg **enc_args,
	       uint8_t *buf, int n, int is_jwe)
{
	struct lejp_ctx jctx;
	struct jose_cb_args args;
	int m;

	args.args = _args;
	args.enc_args = enc_args;
	args.is_jwe = is_jwe;

	lejp_construct(&jctx, lws_jws_jose_cb, &args, jws_jose,
		       LWS_ARRAY_SIZE(jws_jose));

	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)buf, n);
	lejp_destruct(&jctx);
	if (m < 0) {
		lwsl_notice("parse got %d\n", m);
		return -1;
	}

	return 0;
}

int
lws_jws_parse_jose(const struct lws_jose_jwe_alg **args,
		   uint8_t *buf, int n)
{
	return lws_jose_parse(args, NULL, buf, n, 0);
}

int
lws_jwe_parse_jose(const struct lws_jose_jwe_alg **args,
		   const struct lws_jose_jwe_alg **enc_args,
		   uint8_t *buf, int n)
{
	return lws_jose_parse(args, enc_args, buf, n, 1);
}
