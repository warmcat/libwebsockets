/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
#include "private-lib-tls.h"
#include <gnutls/x509.h>

int
lws_x509_create_self_signed(struct lws_context *context,
			    uint8_t **cert_buf, size_t *cert_len,
			    uint8_t **key_buf, size_t *key_len,
			    const char *san, int key_bits)
{
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	int ret = 1;
	gnutls_datum_t data;
	const char *cn = san ? san : "localhost";

	(void)context;

	if (gnutls_x509_privkey_init(&key))
		return 1;
	if (gnutls_x509_crt_init(&crt)) {
		gnutls_x509_privkey_deinit(key);
		return 1;
	}

	if (gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, (unsigned int)key_bits, 0))
		goto bail;

	gnutls_x509_crt_set_key(crt, key);
	gnutls_x509_crt_set_version(crt, 3);
	gnutls_x509_crt_set_serial(crt, "\x01", 1);
	gnutls_x509_crt_set_activation_time(crt, time(NULL));
	gnutls_x509_crt_set_expiration_time(crt, time(NULL) + (365 * 24 * 3600));

	gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn, (unsigned int)strlen(cn));
	gnutls_x509_crt_set_issuer_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn, (unsigned int)strlen(cn));

	/* Extensions */
	gnutls_x509_crt_set_basic_constraints(crt, 0, -1);
	gnutls_x509_crt_set_key_usage(crt, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT);

	if (san)
		gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_DNSNAME, san, (unsigned int)strlen(san), 0);

	/* Self-sign */
	if (gnutls_x509_crt_sign2(crt, crt, key, GNUTLS_DIG_SHA256, 0))
		goto bail;

	/* Export Cert */
	if (gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data))
		goto bail;

	*cert_buf = malloc((size_t)data.size);
	if (!*cert_buf) {
		gnutls_free(data.data);
		goto bail;
	}
	memcpy(*cert_buf, data.data, (size_t)data.size);
	*cert_len = (size_t)data.size;
	gnutls_free(data.data);

	/* Export Key */
	if (gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_DER, &data)) {
		free(*cert_buf);
		goto bail;
	}
	*key_buf = malloc((size_t)data.size);
	if (!*key_buf) {
		gnutls_free(data.data);
		free(*cert_buf);
		goto bail;
	}
	memcpy(*key_buf, data.data, (size_t)data.size);
	*key_len = (size_t)data.size;
	gnutls_free(data.data);

	ret = 0;

bail:
	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(key);

	return ret;
}
