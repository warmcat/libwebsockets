/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"
#include "private-lib-tls-mbedtls.h"
#include <mbedtls/ssl_ciphersuites.h>

void
lws_tls_err_describe_clear(void)
{
}

int
lws_context_init_ssl_library(struct lws_context *cx,
			     const struct lws_context_creation_info *info)
{

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		lwsl_info(" SSL disabled: no "
			  "LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT");

	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{

}

/*
 * mbedtls only considers a memory buffer to be PEM if it is NUL-terminated
 * and the length passed in includes that NUL; otherwise it goes straight to
 * DER and a PEM buffer fails with MBEDTLS_ERR_X509_INVALID_FORMAT.  Callers
 * naturally hand us the strlen() of a PEM without the terminator, so if the
 * buffer parses as neither, retry it as a NUL-terminated copy.
 */

int
lws_mbedtls_x509_crt_parse_mem(mbedtls_x509_crt *crt, const void *mem,
			       size_t len)
{
	uint8_t *tmp;
	int n;

	if (!mem || !len)
		return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

	n = mbedtls_x509_crt_parse(crt, mem, len);
	if (!n || !((const uint8_t *)mem)[len - 1])
		return n;

	tmp = lws_malloc(len + 1, __func__);
	if (!tmp)
		return n;

	memcpy(tmp, mem, len);
	tmp[len] = '\0';
	n = mbedtls_x509_crt_parse(crt, tmp, len + 1);
	lws_free(tmp);

	return n;
}

int
lws_mbedtls_pk_parse_key_mem(struct lws_context *cx, mbedtls_pk_context *key,
			     const void *mem, size_t len)
{
	uint8_t *tmp;
	int n;

	(void)cx;

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && \
    !defined(LWS_HAVE_MBEDTLS_V4)
#define lws_mbedtls_pkpk(_k, _b, _l) \
	mbedtls_pk_parse_key(_k, _b, _l, NULL, 0, \
			     lws_gencrypto_mbedtls_rngf, cx)
#else
#define lws_mbedtls_pkpk(_k, _b, _l) \
	mbedtls_pk_parse_key(_k, _b, _l, NULL, 0)
#endif

	if (!mem || !len)
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

	n = lws_mbedtls_pkpk(key, mem, len);
	if (!n || !((const uint8_t *)mem)[len - 1])
		return n;

	tmp = lws_malloc(len + 1, __func__);
	if (!tmp)
		return n;

	memcpy(tmp, mem, len);
	tmp[len] = '\0';
	n = lws_mbedtls_pkpk(key, tmp, len + 1);
	lws_explicit_bzero(tmp, len + 1); /* it's private key material */
	lws_free(tmp);

	return n;

#undef lws_mbedtls_pkpk
}

/*
 * Parity with the openssl backend (C-406): put the protocol floor at (D)TLS
 * 1.2 and refuse peer-initiated renegotiation, on every config we create,
 * server, client, QUIC and DTLS alike.
 *
 * RFC 8996 deprecates TLS 1.0 / 1.1, which drag in the SHA1 / CBC-with-
 * implicit-IV record layer and are a downgrade target.  Peer-initiated
 * renegotiation is a cheap asymmetric CPU amplifier and, on the client side,
 * lets a server swap its certificate after the peer identity check latched.
 *
 * OVERRIDE: this backend has no SSL_CTX_set_options(), so the info members
 * .ssl_options_clear (server) / .ssl_client_options_clear (client) are
 * honoured directly here, matching what the same bits do on openssl:
 *
 *  - SSL_OP_NO_TLSv1 in _clear   lowers the floor to (D)TLS 1.0
 *  - SSL_OP_NO_TLSv1_1 in _clear lowers the floor to (D)TLS 1.1
 *  - SSL_OP_NO_RENEGOTIATION in _clear re-enables renegotiation
 *
 * (mbedtls 3.x has no TLS 1.0 / 1.1 code at all, so there the floor is
 * already 1.2 and only the renegotiation part can do anything.)
 */

void
lws_mbedtls_conf_floor(mbedtls_ssl_config *conf, long options_clear)
{
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000

	/*
	 * mbedtls >= 3.0 dropped TLS 1.0 / 1.1 entirely, there is nothing for
	 * _clear to lower to; the floor is 1.2 regardless
	 */

	mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);

#else
	{
		unsigned long long oc = (unsigned long long)options_clear;
		int minor = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */

		if (oc & (unsigned long long)SSL_OP_NO_TLSv1)
			minor = MBEDTLS_SSL_MINOR_VERSION_1; /* TLS 1.0 */
		else
			if (oc & (unsigned long long)SSL_OP_NO_TLSv1_1)
				minor = MBEDTLS_SSL_MINOR_VERSION_2;

		mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3,
					     minor);
	}
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
	mbedtls_ssl_conf_renegotiation(conf,
			((unsigned long long)options_clear &
			 (unsigned long long)SSL_OP_NO_RENEGOTIATION) ?
				MBEDTLS_SSL_RENEGOTIATION_ENABLED :
				MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

	(void)conf;
	(void)options_clear;
}

#if defined(LWS_HAVE_mbedtls_ssl_conf_alpn_protocols)

/*
 * mbedtls_ssl_conf_alpn_protocols() stores the array of pointers we give it,
 * it does not copy anything... so the strings and the pointer array have to
 * live as long as the config does, and only the owner of that config may
 * write them.
 */

static int
lws_mbedtls_alpn_list(mbedtls_ssl_config *conf, char *strings, size_t strings_len,
		      const char **protocols, size_t protocols_len,
		      const char *alpn_comma)
{
	int count = 0, r;
	char *p, *start;

	lws_strncpy(strings, alpn_comma, strings_len);
	start = strings;

	while (count < (int)protocols_len - 1) {
		p = strchr(start, ',');
		if (p)
			*p = '\0';

		if (*start)
			protocols[count++] = start;

		if (!p)
			break;
		start = p + 1;
	}

	protocols[count] = NULL;

	if (!count)
		return 1;

	r = mbedtls_ssl_conf_alpn_protocols(conf, protocols);
	if (r) {
		lwsl_err("%s: mbedtls_ssl_conf_alpn_protocols: %d\n",
			 __func__, r);

		return 1;
	}

	lwsl_info("%s: set %d ALPN protocols (first: %s)\n", __func__, count,
		  protocols[0]);

	return 0;
}

void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
	/*
	 * the vhost may legitimately have no ctx, eg, it was created with
	 * LWS_SERVER_OPTION_IGNORE_MISSING_CERT and the cert has not turned
	 * up yet
	 */
	if (!ctx || !alpn_comma)
		return;

	lws_mbedtls_alpn_list(&ctx->conf, ctx->alpn_strings,
			      sizeof(ctx->alpn_strings), ctx->alpn_protocols,
			      LWS_ARRAY_SIZE(ctx->alpn_protocols), alpn_comma);
}

#if defined(LWS_WITH_CLIENT)
int
lws_mbedtls_conn_set_alpn(struct lws_tls_conn *conn, const char *alpn_comma)
{
	if (!conn || !conn->ctx || !alpn_comma)
		return 1;

	/*
	 * The ALPN list is per-connection, but the vhost's mbedtls_ssl_config
	 * is shared by every client connection on the vhost... writing the
	 * list into that would let one connection change what another one
	 * offers, and change what a completed connection reads back as the
	 * negotiated protocol (which selects the h1 / h2 / h3 role).
	 *
	 * mbedtls only ever reads ssl->conf, so give this connection a
	 * private copy of the config to hang its own list on.  It aliases the
	 * vhost config's contents by design and must never be freed with
	 * mbedtls_ssl_config_free().
	 */

	conn->conf = conn->ctx->conf;

	if (lws_mbedtls_alpn_list(&conn->conf, conn->alpn_strings,
				  sizeof(conn->alpn_strings),
				  conn->alpn_protocols,
				  LWS_ARRAY_SIZE(conn->alpn_protocols),
				  alpn_comma))
		return 1;

	conn->own_conf = 1;

	return 0;
}
#endif

#else
void lws_mbedtls_set_alpn(struct lws_tls_ctx *ctx, const char *alpn_comma)
{
	(void)ctx;
	(void)alpn_comma;
}
#if defined(LWS_WITH_CLIENT)
int
lws_mbedtls_conn_set_alpn(struct lws_tls_conn *conn, const char *alpn_comma)
{
	(void)conn;
	(void)alpn_comma;

	return 1;
}
#endif
#endif

/*
 * OpenSSL, IANA and mbedtls each spell the ciphersuites differently, and
 * mbedtls only understands its own spelling (or the IANA id):
 *
 *   OpenSSL   ECDHE-ECDSA-AES128-GCM-SHA256
 *   IANA      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *   mbedtls   TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
 *
 *   IANA      TLS_AES_128_GCM_SHA256			(TLS1.3)
 *   mbedtls   TLS1-3-AES-128-GCM-SHA256
 *
 * Rather than carry a table of every suite in three spellings, both the name
 * we were given and mbedtls' own names are reduced to a canonical form (see
 * lws_mbedtls_cs_canon()) and matched on that; only the handful of OpenSSL
 * names that are not a regular transformation need a table entry.
 *
 * The resulting ids are applied with mbedtls_ssl_conf_ciphersuites(), so a
 * cipher list in the info or the config actually takes effect on this
 * backend.  A list entry that names nothing we can use fails the vhost,
 * rather than leaving the operator believing a restriction is in force while
 * the mbedtls PRESET_DEFAULT suite list is what is really running.
 */

static const struct {
	const char *ossl;
	const char *mbed;
} lws_mbedtls_cs_alias[] = {
	/*
	 * OpenSSL leaves the SHA256 off the ChaCha20-Poly1305 suite names,
	 * which no canonical match can put back
	 */
	{ "ECDHE-RSA-CHACHA20-POLY1305",
	  "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"			},
	{ "ECDHE-ECDSA-CHACHA20-POLY1305",
	  "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"		},
	{ "DHE-RSA-CHACHA20-POLY1305",
	  "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"			},
	{ "ECDHE-PSK-CHACHA20-POLY1305",
	  "TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256"			},
	{ "DHE-PSK-CHACHA20-POLY1305",
	  "TLS-DHE-PSK-WITH-CHACHA20-POLY1305-SHA256"			},
	{ "RSA-PSK-CHACHA20-POLY1305",
	  "TLS-RSA-PSK-WITH-CHACHA20-POLY1305-SHA256"			},
	{ "PSK-CHACHA20-POLY1305",
	  "TLS-PSK-WITH-CHACHA20-POLY1305-SHA256"			},
};

static char
lws_mbedtls_cs_uc(char c)
{
	return (c >= 'a' && c <= 'z') ? (char)(c - ('a' - 'A')) : c;
}

static int
lws_mbedtls_cs_tokis(const char *tok, size_t len, const char *uclit)
{
	size_t n;

	if (strlen(uclit) != len)
		return 0;

	for (n = 0; n < len; n++)
		if (lws_mbedtls_cs_uc(tok[n]) != uclit[n])
			return 0;

	return 1;
}

/*
 * Reduce a ciphersuite name to a spelling-independent form: uppercase, with
 * the '-' / '_' separators removed along with the tokens that only some of
 * the spellings carry, ie, the leading "TLS" or "TLS1" "3", the "WITH", and
 * the "CBC" that OpenSSL omits.
 *
 *   "ECDHE-ECDSA-AES128-GCM-SHA256"		  \
 *   "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"	  |  ECDHEECDSAAES128GCMSHA256
 *
 * Returns nonzero if the name did not fit in \p out.
 */

static int
lws_mbedtls_cs_canon(char *out, size_t out_len, const char *in)
{
	size_t o = 0, tok = 0;
	int tls13 = 0;

	while (*in) {
		const char *e = in;
		size_t l;
		int skip;

		while (*e && *e != '-' && *e != '_')
			e++;
		l = lws_ptr_diff_size_t(e, in);

		if (!tok && lws_mbedtls_cs_tokis(in, l, "TLS1")) {
			tls13 = 1;
			skip = 1;
		} else
			skip = (!tok && lws_mbedtls_cs_tokis(in, l, "TLS")) ||
			       (tok == 1 && tls13 &&
				lws_mbedtls_cs_tokis(in, l, "3")) ||
			       lws_mbedtls_cs_tokis(in, l, "WITH") ||
			       lws_mbedtls_cs_tokis(in, l, "CBC");

		if (!skip) {
			if (o + l >= out_len)
				return 1;

			while (in < e)
				out[o++] = lws_mbedtls_cs_uc(*in++);
		}

		tok++;
		in = e;
		if (*in)
			in++;
	}

	out[o] = '\0';

	return 0;
}

/*
 * Resolve one cipher name, in any of the three spellings, to an mbedtls
 * ciphersuite id.  Returns 0 if it does not name a suite this mbedtls build
 * can provide.
 */

static int
lws_mbedtls_cs_id(const char *name)
{
	char canon[80], t[96], *p;
	const int *sl;
	size_t n;
	int id, pass;

	/* 1) mbedtls' own spelling */

	id = mbedtls_ssl_get_ciphersuite_id(name);
	if (id)
		return id;

	/* 2) the OpenSSL names that are not a regular transformation */

	for (n = 0; n < LWS_ARRAY_SIZE(lws_mbedtls_cs_alias); n++)
		if (!strcmp(name, lws_mbedtls_cs_alias[n].ossl))
			return mbedtls_ssl_get_ciphersuite_id(
					lws_mbedtls_cs_alias[n].mbed);

	/*
	 * 3) IANA spelling.  It maps to mbedtls' by separator alone, so unlike
	 *    the OpenSSL spelling it can be transformed exactly, and must be:
	 *    the TLS1.3 TLS_AES_256_GCM_SHA384 and the OpenSSL name for
	 *    TLS-RSA-WITH-AES-256-GCM-SHA384 ("AES256-GCM-SHA384") share a
	 *    canonical form, so only the exact transform can tell them apart.
	 */

	if (!strncmp(name, "TLS_", 4)) {
		lws_snprintf(t, sizeof(t), "%s%s",
			     strstr(name, "_WITH_") ? "TLS-" : "TLS1-3-",
			     name + 4);

		for (p = t; *p; p++)
			if (*p == '_')
				*p = '-';

		return mbedtls_ssl_get_ciphersuite_id(t);
	}

	/*
	 * The mbedtls TLS1.3 spelling could only have matched at 1)... the
	 * canonical form drops the "TLS1-3-", so it must not go on to be
	 * matched against the TLS1.2 suites, where TLS1-3-AES-128-GCM-SHA256
	 * would otherwise pass for the plain-RSA TLS-RSA-WITH-AES-128-GCM-SHA256
	 */

	if (!strncmp(name, "TLS1-3-", 7))
		return 0;

	/* 4) OpenSSL spelling, by canonical match against what mbedtls has */

	if (lws_mbedtls_cs_canon(canon, sizeof(canon), name))
		return 0;

	sl = mbedtls_ssl_list_ciphersuites();

	for (pass = 0; pass < 2; pass++) {
		int hit = 0;

		/*
		 * OpenSSL leaves the key exchange out of the plain-RSA suite
		 * names, ie, "AES128-GCM-SHA256" is mbedtls'
		 * TLS-RSA-WITH-AES-128-GCM-SHA256... so if the name did not
		 * match as it stands, try it again as if it had said RSA
		 */

		if (pass)
			lws_snprintf(t, sizeof(t), "RSA%s", canon);
		else
			lws_strncpy(t, canon, sizeof(t));

		for (n = 0; sl[n]; n++) {
			char c2[80];

			/* an OpenSSL cipher list never names a TLS1.3 suite */

			if ((sl[n] & 0xff00) == 0x1300)
				continue;

			if (lws_mbedtls_cs_canon(c2, sizeof(c2),
					mbedtls_ssl_get_ciphersuite_name(sl[n])))
				continue;

			if (strcmp(c2, t))
				continue;

			if (hit && hit != sl[n]) {
				lwsl_err("%s: '%s' is ambiguous\n", __func__,
					 name);

				return 0;
			}

			hit = sl[n];
		}

		if (hit)
			return hit;
	}

	return 0;
}

/*
 * An OpenSSL cipher list also carries things that are not suite names at all:
 * the '!' (remove) / '-' (disable) / '+' (move to the end) / '@' (ordering
 * and seclevel directives) modifiers, and class aliases like HIGH, aNULL,
 * kEECDH+AESGCM or TLSv1.2.  We apply an explicit list of suites, there is no
 * mbedtls equivalent of a class selector, so these can only be noted and
 * skipped... a suite name always has a separator in it, a class alias never
 * does.
 */

static int
lws_mbedtls_cs_is_selector(const char *name)
{
	return *name == '!' || *name == '-' || *name == '+' || *name == '@' ||
	       strchr(name, '+') || strchr(name, '@') ||
	       (!strchr(name, '-') && !strchr(name, '_'));
}

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
/*
 * TLS1.3 suites are spelled TLS1-3-... by mbedtls and TLS_... without a
 * _WITH_ by IANA (and OpenSSL, which uses the IANA names for them); nothing
 * else starts that way
 */

static int
lws_mbedtls_cs_is_tls13_name(const char *name)
{
	return !strncmp(name, "TLS1-3-", 7) ||
	       (!strncmp(name, "TLS_", 4) && !strstr(name, "_WITH_"));
}
#endif

static int
lws_mbedtls_cs_addlist(int *ids, size_t *count, const char *list,
		       const char *vhname, const char *what)
{
	char name[96];

	while (*list) {
		const char *e = list;
		size_t l, n;
		int id;

		while (*e && *e != ':' && *e != ',')
			e++;
		l = lws_ptr_diff_size_t(e, list);

		if (!l)
			goto next;

		if (l >= sizeof(name)) {
			lwsl_err("%s: vh %s: %s: cipher name too long\n",
				 __func__, vhname, what);

			return 1;
		}

		lws_strnncpy(name, list, l, sizeof(name));

		id = lws_mbedtls_cs_id(name);
		if (!id) {
			if (lws_mbedtls_cs_is_selector(name)) {
				lwsl_notice("%s: vh %s: %s: no mbedtls "
					    "equivalent for cipher selector "
					    "'%s', ignored\n", __func__,
					    vhname, what, name);
				goto next;
			}

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
			/*
			 * This mbedtls cannot negotiate TLS1.3 at all, so a
			 * TLS1.3 suite in the list neither restricts nor
			 * enables anything, the same as on an OpenSSL without
			 * SSL_CTX_set_ciphersuites()
			 */

			if (lws_mbedtls_cs_is_tls13_name(name)) {
				lwsl_notice("%s: vh %s: %s: '%s' names a TLS1.3 "
					    "suite, this mbedtls has no TLS1.3, "
					    "ignored\n", __func__, vhname, what,
					    name);
				goto next;
			}
#endif

			lwsl_err("%s: vh %s: %s: '%s' does not name any "
				 "ciphersuite this mbedtls provides\n",
				 __func__, vhname, what, name);

			return 1;
		}

		/* the same suite may legitimately appear in both lists */

		for (n = 0; n < *count; n++)
			if (ids[n] == id)
				break;

		if (n != *count)
			goto next;

		if (*count >= LWS_MBEDTLS_CS_MAX) {
			lwsl_err("%s: vh %s: %s: more than %d ciphersuites\n",
				 __func__, vhname, what, LWS_MBEDTLS_CS_MAX);

			return 1;
		}

		ids[(*count)++] = id;

next:
		list = e;
		if (*list)
			list++;
	}

	return 0;
}

/*
 * Apply the vhost's configured cipher lists to \p ctx.
 *
 * \p iana is the cross-library .tls_ciphers_iana list, which if given
 * replaces both of the others; \p list12 the OpenSSL-style TLS1.2-and-below
 * list; \p list13 the TLS1.3-and-above list.  Any of them may be NULL, and
 * entries may be separated by ':' or ','.
 *
 * mbedtls has a single ciphersuite list covering both TLS1.2 and TLS1.3, so
 * unlike openssl the two lws lists land in the same place.  That means a
 * vhost that only set the TLS1.2 list (much the commonest case, and what the
 * lwsws config produces) would silently lose TLS1.3 altogether, so when no
 * TLS1.3 list was given the default TLS1.3 suites are added back.  The
 * reverse case, a TLS1.3 list and no TLS1.2 list, does restrict the vhost to
 * TLS1.3 and says so.
 *
 * An mbedtls built without TLS1.3 (all of 2.x) has no suite any TLS1.3 name
 * could refer to; there \p list13 is ignored with a notice and TLS1.3 names
 * in the other lists are skipped, as OpenSSL builds without
 * SSL_CTX_set_ciphersuites() ignore the TLS1.3 list.
 *
 * Returns 0 if the ctx is left in a state we can serve with, else nonzero and
 * the vhost creation should fail.
 */

int
lws_mbedtls_conf_ciphers(struct lws_tls_ctx *ctx, const char *vhname,
			 const char *iana, const char *list12,
			 const char *list13)
{
	size_t count = 0, n;

	if (!vhname)
		vhname = "?";

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
	if (ctx && list13 && !iana) {
		lwsl_notice("%s: vh %s: this mbedtls has no TLS1.3, the TLS1.3 "
			    "cipher list is ignored\n", __func__, vhname);
		list13 = NULL;
	}
#endif

	if (!ctx || (!iana && !list12 && !list13))
		return 0; /* nothing configured, mbedtls' own defaults apply */

	if (iana) {
		if (list12 || list13)
			lwsl_notice("%s: vh %s: tls_ciphers_iana given, the "
				    "cipher list fields are ignored\n",
				    __func__, vhname);

		if (lws_mbedtls_cs_addlist(ctx->ciphersuites, &count, iana,
					   vhname, "iana"))
			return 1;
	} else {
		if (list13 && lws_mbedtls_cs_addlist(ctx->ciphersuites, &count,
						     list13, vhname, "tls1.3"))
			return 1;

		if (list12 && lws_mbedtls_cs_addlist(ctx->ciphersuites, &count,
						     list12, vhname, "tls1.2"))
			return 1;
	}

	/*
	 * A list that was entirely class selectors and modifiers restricts
	 * nothing... refuse it rather than fall back to the default suites
	 */

	if (!count) {
		lwsl_err("%s: vh %s: the configured cipher list did not name "
			 "any usable ciphersuite\n", __func__, vhname);

		return 1;
	}

	if (!iana) {
		if (list13) {
			if (!list12)
				lwsl_notice("%s: vh %s: only a TLS1.3 cipher "
					    "list was given, mbedtls has one "
					    "suite list, so this vhost is "
					    "TLS1.3-only\n", __func__, vhname);
		} else {
			/*
			 * The given list only speaks about TLS1.2 and below,
			 * so keep TLS1.3 available at its defaults (the
			 * relative order of suites for different protocol
			 * versions has no meaning, the version is negotiated
			 * before the suite)
			 */

			const int *sl = mbedtls_ssl_list_ciphersuites();

			for (n = 0; sl[n]; n++) {
				size_t m;

				if ((sl[n] & 0xff00) != 0x1300 ||
				    count >= LWS_MBEDTLS_CS_MAX)
					continue;

				for (m = 0; m < count; m++)
					if (ctx->ciphersuites[m] == sl[n])
						break;

				if (m == count)
					ctx->ciphersuites[count++] = sl[n];
			}
		}
	}

	ctx->ciphersuites[count] = 0;

	mbedtls_ssl_conf_ciphersuites(&ctx->conf, ctx->ciphersuites);

	lwsl_info("%s: vh %s: %d ciphersuites, first %s\n", __func__, vhname,
		  (int)count,
		  mbedtls_ssl_get_ciphersuite_name(ctx->ciphersuites[0]));

	return 0;
}
