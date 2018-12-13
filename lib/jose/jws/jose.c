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
#include "jose/private.h"

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
	struct lws_jose *jose;
	struct lejp_ctx jwk_jctx; /* fake lejp context used to parse epk */
	struct lws_jwk_parse_state jps; /* fake jwk parse state */
	char *temp;
	int *temp_len;
	int is_jwe;
};

static signed char
lws_jws_jose_cb(struct lejp_ctx *ctx, char reason)
{
	struct jose_cb_args *args = (struct jose_cb_args *)ctx->user;
	int n;

	/*
	 * In JOSE JSON, the element "epk" contains a fully-formed JWK.
	 *
	 * For JOSE paths beginning "epk.", we pass them through to a JWK
	 * LEJP subcontext to parse using the JWK parser directly.
	 */

	if (args->is_jwe && !strncmp(ctx->path, "epk.", 4)) {
		memcpy(args->jwk_jctx.path, ctx->path + 4,
		       sizeof(ctx->path) - 4);
		memcpy(args->jwk_jctx.buf, ctx->buf, ctx->npos);
		args->jwk_jctx.npos = ctx->npos;

		if (!ctx->path_match)
			args->jwk_jctx.path_match = 0;
		lejp_check_path_match(&args->jwk_jctx);

		if (args->jwk_jctx.path_match)
			args->jwk_jctx.callback(&args->jwk_jctx, reason);
	}

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
		    lws_gencrypto_jws_alg_to_definition(ctx->buf,
						        &args->jose->alg)) {
			lwsl_notice("%s: unknown alg '%s'\n", __func__,
				    ctx->buf);

			return -1;
		}

		if (args->is_jwe &&
		    lws_gencrypto_jwe_alg_to_definition(ctx->buf,
						        &args->jose->alg)) {
			lwsl_notice("%s: unknown JWE alg '%s'\n", __func__,
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

	case LJJHI_ENC:	/* JWE only: Mandatory: string */
		if (!args->is_jwe) {
			lwsl_info("%s: enc in jws\n", __func__);
			return -1;
		}
		if (lws_gencrypto_jwe_enc_to_definition(ctx->buf,
							&args->jose->enc_alg)) {
			lwsl_notice("%s: unknown enc '%s'\n", __func__,
				    ctx->buf);

			return -1;
		}
		break;

	case LJJHI_ZIP:	/* JWE only: Optional: string ("DEF" = deflate) */
		if (!args->is_jwe)
			return -1;
		goto append_string;

	case LJJHI_EPK:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		/* Ephemeral key... this JSON subsection is actually a JWK */
		lwsl_err("LJJHI_EPK\n");
		break;

	case LJJHI_APU:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		/* Agreement Party U */
		goto append_string;

	case LJJHI_APV:	/* Additional arg for JWE ECDH */
		if (!args->is_jwe)
			return -1;
		/* Agreement Party V */
		goto append_string;

	case LJJHI_IV:  /* Additional arg for JWE AES */
		if (!args->is_jwe)
			return -1;
		goto append_string;

	case LJJHI_TAG:	/* Additional arg for JWE AES */
		if (!args->is_jwe)
			return -1;
		goto append_string;

	case LJJHI_P2S:	/* Additional arg for JWE PBES2 */
		if (!args->is_jwe)
			return -1;
		goto append_string;
	case LJJHI_P2C:	/* Additional arg for JWE PBES2 */
		if (!args->is_jwe)
			return -1;
		goto append_string;

	/* ignore what we don't understand */

	default:
		return 0;
	}

	return 0;

append_string:

	if (*args->temp_len < ctx->npos) {
		lwsl_err("%s: out of parsing space\n", __func__);
		return -1;
	}

	if (!args->jose->e[ctx->path_match - 1].buf) {
		args->jose->e[ctx->path_match - 1].buf = (uint8_t *)args->temp;
		args->jose->e[ctx->path_match - 1].len = 0;
	}

	memcpy(args->temp, ctx->buf, ctx->npos);
	args->temp += ctx->npos;
	*args->temp_len -= ctx->npos;
	args->jose->e[ctx->path_match - 1].len += ctx->npos;

	if (reason == LEJPCB_VAL_STR_END) {
		n = lws_b64_decode_string_len(
			(const char *)args->jose->e[ctx->path_match - 1].buf,
			args->jose->e[ctx->path_match - 1].len,
			(char *)args->jose->e[ctx->path_match - 1].buf,
			args->jose->e[ctx->path_match - 1].len + 1);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed\n", __func__);
			return -1;
		}

		args->temp -= args->jose->e[ctx->path_match - 1].len - n - 1;
		*args->temp_len +=
			args->jose->e[ctx->path_match - 1].len - n - 1;

		args->jose->e[ctx->path_match - 1].len = n;
	}

	return 0;
}

void
lws_jose_init(struct lws_jose *jose)
{
	memset(jose, 0, sizeof(*jose));
}

void
lws_jose_destroy(struct lws_jose *jose)
{
//	lws_gencrypto_destroy_elements(jose->e, LWS_ARRAY_SIZE(jose->e));
	lws_jwk_destroy(&jose->jwk_ephemeral);
}


static int
lws_jose_parse(struct lws_jose *jose, const uint8_t *buf, int n,
	       char *temp, int *temp_len, int is_jwe)
{
	struct lejp_ctx jctx;
	struct jose_cb_args args;
	int m;

	if (is_jwe)
		/* prepare a context for JOSE epk ephemeral jwk parsing */
		lws_jwk_init_jps(&args.jwk_jctx, &args.jps,
				 &jose->jwk_ephemeral, NULL, NULL);

	args.is_jwe = is_jwe;
	args.temp = temp;
	args.temp_len = temp_len;
	args.jose = jose;

	lejp_construct(&jctx, lws_jws_jose_cb, &args, jws_jose,
		       LWS_ARRAY_SIZE(jws_jose));

	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)buf, n);
	lejp_destruct(&jctx);
	if (m < 0) {
		lwsl_notice("%s: parse %.*s returned %d\n", __func__, n, buf, m);
		return -1;
	}

	return 0;
}

int
lws_jws_parse_jose(struct lws_jose *jose,
		   const char *buf, int len, char *temp, int *temp_len)
{
	return lws_jose_parse(jose, (const uint8_t *)buf, len,
			temp, temp_len, 0);
}

int
lws_jwe_parse_jose(struct lws_jose *jose,
		   const char *buf, int len, char *temp, int *temp_len)
{
	return lws_jose_parse(jose,
			      (const uint8_t *)buf, len, temp, temp_len, 1);
}
