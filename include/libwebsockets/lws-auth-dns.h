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
 */

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

struct lws_auth_dns_sign_info {
	const char			*input_filepath;
	const char			*output_filepath;
	const char			*jws_filepath;      /* Path to output signed JWS of the zone */
	const char			*zsk_jwk_filepath;  /* Path to ZSK JWK config */
	const char			*ksk_jwk_filepath;  /* Path to KSK JWK config */
	const char			**subst_names;      /* For lws_strexp */
	const char			**subst_values;
	time_t				sign_validity_start_time; /* 0 = now */
	uint32_t			sign_validity_duration;   /* 0 = 30 days */
	int				num_substs;
	struct lws_context		*cx;                /* For logging/alloc */
};

/**
 * lws_auth_dns_sign_zone() - read, sign and output an authoritative DNS zone
 *
 * \param info: the params for configuring the sign operation
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_sign_zone(struct lws_auth_dns_sign_info *info);

/**
 * lws_auth_dns_verify_zone() - read, parse and verify RRSIGs from an authoritative DNS zone
 *
 * \param info: the params for configuring the verify operation
 */
LWS_VISIBLE LWS_EXTERN int
lws_auth_dns_verify_zone(struct lws_auth_dns_sign_info *info);

#endif
