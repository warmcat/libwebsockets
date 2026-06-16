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

#if !defined(__LWS_OPENHITLS_PRIVATE_H__)
#define __LWS_OPENHITLS_PRIVATE_H__

#include <stdio.h>

#include <hitls.h>
#include <hitls_config.h>
#include <hitls_alpn.h>
#include <hitls_sni.h>

#include <hitls_session.h>
#include <hitls_debug.h>

#include <hitls_cert.h>

#include <crypt_errno.h>
#include <crypt_types.h>
#include <crypt_params_key.h>
#include <crypt_eal_init.h>

#include <bsl_err.h>

#include <bsl_sal.h>

#include <hitls_pki_cert.h>
#include <hitls_pki_types.h>
#include <hitls_pki_x509.h>
#include <hitls_pki_errno.h>
#include <bsl_uio.h>

struct lws_x509_cert {
	HITLS_X509_Cert *cert;
};

typedef HITLS_Ctx lws_tls_conn;
typedef HITLS_Config lws_tls_ctx;
typedef BSL_UIO lws_tls_bio;

/*
 * Session reuse structure for client context caching
 * One per different client context; cc_owner is in lws_context.lws_context_tls
 */
struct lws_tls_client_reuse {
	lws_tls_ctx *ssl_client_ctx;
	uint8_t hash[32];
	struct lws_dll2 cc_list;
	int refcount;
	int index;
};

#define LWS_OPENHITLS_HOSTNAME_VERIFY_FLAGS 0u

int
lws_openhitls_describe_cipher(struct lws *wsi);

#if defined(LWS_WITH_TLS_KEYLOG)
void
lws_openhitls_klog_dump(HITLS_Ctx *ctx, const char *line);
#endif

CRYPT_MD_AlgId
lws_genhash_type_to_hitls_md_id(enum lws_genhash_types hash_type);

CRYPT_CIPHER_AlgId
lws_genaes_mode_to_hitls_cipher_id(enum enum_aes_modes mode, size_t keylen);

int
lws_tls_openhitls_cert_info(HITLS_X509_Cert *x509,
			    enum lws_tls_cert_info type,
			    union lws_tls_cert_info_results *buf, size_t len);

#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0x08000000L
#endif

#ifndef SSL_OP_NO_TLSv1_3
#define SSL_OP_NO_TLSv1_3 0x20000000L
#endif

int
lws_openhitls_apply_tls_version_by_ssl_options(HITLS_Config *config, long set,
					       long clear, const char *who);

static LWS_INLINE HITLS_Config *
lws_openhitls_server_config_from_ssl_ctx(void *ssl_ctx)
{
	return (HITLS_Config *)ssl_ctx;
}

static LWS_INLINE void
lws_openhitls_trim_ws(char **start, char **end)
{
	while (*start < *end && (**start == ' ' || **start == '\t'))
		(*start)++;

	while (*end > *start &&
	       ((*(*end - 1) == ' ') || (*(*end - 1) == '\t')))
		(*end)--;
}

static LWS_INLINE int
lws_openhitls_apply_cipher_suites(HITLS_Config *config, const char *list,
				  const char *who)
{
	const HITLS_Cipher *c;
	uint16_t suites[64];
	const char *p, *d;
	size_t count = 0;
	char token[192];
	uint16_t id;
	int bad = 0;

	if (!config || !list || !*list)
		return 0;

	p = list;
	while (*p) {
		const char *d2;
		const char *d3;
		char *ts, *te;
		size_t tl;

		d = strchr(p, ':');
		d2 = strchr(p, ',');
		d3 = strchr(p, ' ');
		if (!d || (d2 && d2 < d))
			d = d2;
		if (!d || (d3 && d3 < d))
			d = d3;
		if (!d)
			d = p + strlen(p);
		tl = (size_t)(d - p);
		if (tl >= sizeof(token))
			tl = sizeof(token) - 1;
		memcpy(token, p, tl);
		token[tl] = '\0';

		ts = token;
		te = token + strlen(token);
		lws_openhitls_trim_ws(&ts, &te);
		*te = '\0';

		if (*ts) {
			c = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)ts);
			if (!c) {
				lwsl_warn("%s: unknown IANA cipher '%s'\n",
					  who, ts);
				bad = 1;
			} else if (HITLS_CFG_GetCipherSuite(c, &id) !=
				   HITLS_SUCCESS) {
				lwsl_warn("%s: unable to get cipher id for '%s'\n",
					  who, ts);
				bad = 1;
			} else if (count < LWS_ARRAY_SIZE(suites)) {
				size_t i;
				int dup = 0;

				for (i = 0; i < count; i++)
					if (suites[i] == id) {
						dup = 1;
						break;
					}
				if (!dup) {
					suites[count++] = id;
				}
			} else {
				lwsl_warn("%s: too many IANA ciphers in '%s'\n",
					  who, list);
				bad = 1;
			}
		}

		p = *d ? d + 1 : d;
	}

	if (!count || bad)
		return -1;

	/* OpenHiTLS backend now consumes only RFC/IANA suite names from
	 * tls_ciphers_iana / client_tls_ciphers_iana; OpenSSL cipher
	 * expression and alias conversion is intentionally not provided.
	 */
	return HITLS_CFG_SetCipherSuites(config, suites, (uint32_t)count) ==
		       HITLS_SUCCESS
		       ? 0
		       : -1;
}

#endif
