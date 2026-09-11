/*
 * lws-api-test-gencrypto - lws-mbedtls-cipherlist
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * mbedtls only knows its own ciphersuite spellings and ids, so lws maps the
 * OpenSSL and IANA spellings a vhost may be configured with onto mbedtls
 * ciphersuite ids and applies them with mbedtls_ssl_conf_ciphersuites().
 *
 * That mapping is only reachable from outside the library by creating a vhost
 * with a cipher list on it, which is what this checks: a list lws can map
 * brings the vhost up, and a list with an entry naming no suite this mbedtls
 * has must fail the vhost, rather than quietly leaving the mbedtls default
 * suite list in force while the operator believes a restriction took effect.
 *
 * An mbedtls without TLS1.3 (2.x, or 3.x configured without it) has no suite
 * a TLS1.3 name could mean: there the TLS1.3 list is ignored and TLS1.3 names
 * in the other lists are skipped, as OpenSSL does when it has no
 * SSL_CTX_set_ciphersuites(), so a list is only as good as its TLS1.2 part.
 */

#include <libwebsockets.h>
#include <string.h>

#if defined(LWS_WITH_MBEDTLS) && defined(LWS_WITH_TLS) && \
    defined(LWS_WITH_NETWORK) && defined(LWS_WITH_CLIENT)

/* a list naming only TLS1.3 suites restricts nothing on an mbedtls without */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#define HAS13 1
#else
#define HAS13 0
#endif

static const struct {
	const char	*l12;	/* client_ssl_cipher_list */
	const char	*l13;	/* client_tls_1_3_plus_cipher_list */
	const char	*iana;	/* client_tls_ciphers_iana */
	char		expect;	/* 1 = vhost must come up, 0 = must fail */
} cipherlist_tests[] = {

	/* the OpenSSL spelling, including the irregular names */

	{ "ECDHE-ECDSA-AES128-GCM-SHA256",		NULL, NULL, 1 },
	{ "ECDHE-RSA-AES256-SHA384",			NULL, NULL, 1 },
	{ "AES128-GCM-SHA256",				NULL, NULL, 1 },
	{ "ECDHE-RSA-CHACHA20-POLY1305",		NULL, NULL, 1 },
	{ "ECDHE-ECDSA-AES128-CCM8",			NULL, NULL, 1 },

	/*
	 * mbedtls' own spelling, TLS1.2 and TLS1.3... without TLS1.3 the
	 * second must fail, not pass for TLS-RSA-WITH-AES-128-GCM-SHA256
	 */

	{ "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",	NULL, NULL, 1 },
	{ "TLS1-3-AES-128-GCM-SHA256",			NULL, NULL, HAS13 },

	/*
	 * the IANA spelling, ',' separated as .tls_ciphers_iana is documented;
	 * with no TLS1.3 the first still has its TLS1.2 suite, the second is
	 * a TLS1.3 list that is ignored altogether, and the third names
	 * nothing usable
	 */

	{ NULL, NULL, "TLS_AES_256_GCM_SHA384,"
		      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",	      1 },
	{ NULL, "TLS_CHACHA20_POLY1305_SHA256",		      NULL,   1 },
	{ "TLS_AES_128_GCM_SHA256",			NULL, NULL, HAS13 },

	/*
	 * What the lwsws config produces: four suites, then OpenSSL cipher
	 * class selectors and '!' modifiers that mbedtls has no equivalent
	 * for and which are noted and skipped
	 */

	{ "ECDHE-ECDSA-AES256-GCM-SHA384:"
	  "ECDHE-RSA-AES256-GCM-SHA384:"
	  "DHE-RSA-AES256-GCM-SHA384:"
	  "ECDHE-RSA-AES256-SHA384:"
	  "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!SHA1",
							NULL, NULL, 1 },

	/* an entry that names no suite must fail the vhost */

	{ "ECDHE-ECDSA-AES128-GCM-SHA255",		NULL, NULL, 0 },
	{ "DES-CBC3-SHA",				NULL, NULL, 0 },
	{ "ECDHE-ECDSA-AES128-GCM-SHA256:NOT-A-SUITE",	NULL, NULL, 0 },
	{ NULL, NULL, "TLS_AES_999_GCM_SHA384",			    0 },

	/* ... and so must a list that restricts nothing at all */

	{ "HIGH:!aNULL",				NULL, NULL, 0 },

	/* no list is not an error, mbedtls' own defaults apply */

	{ NULL,						NULL, NULL, 1 },
};

int
test_mbedtls_cipherlist(struct lws_context *context)
{
	size_t n;
	int ret = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(cipherlist_tests); n++) {
		struct lws_context_creation_info i;
		struct lws_vhost *vh;
		char name[32];

		memset(&i, 0, sizeof(i));
		lws_snprintf(name, sizeof(name), "cipherlist-%d", (int)n);
		i.vhost_name = name;
		i.port = CONTEXT_PORT_NO_LISTEN;
		i.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		i.client_ssl_cipher_list = cipherlist_tests[n].l12;
		i.client_tls_1_3_plus_cipher_list = cipherlist_tests[n].l13;
		i.client_tls_ciphers_iana = cipherlist_tests[n].iana;

		vh = lws_create_vhost(context, &i);

		if (!!vh != !!cipherlist_tests[n].expect) {
			lwsl_err("%s: '%s' / '%s' / '%s': vhost %s\n", __func__,
				 cipherlist_tests[n].l12 ?
					 cipherlist_tests[n].l12 : "",
				 cipherlist_tests[n].l13 ?
					 cipherlist_tests[n].l13 : "",
				 cipherlist_tests[n].iana ?
					 cipherlist_tests[n].iana : "",
				 vh ? "came up but should not have" :
				      "failed but should have come up");
			ret = 1;
		}

		if (vh)
			lws_vhost_destroy(vh);
	}

	if (ret) {
		lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

		return 1;
	}

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;
}

#endif
