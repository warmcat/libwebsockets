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
#include <mbedtls/x509_csr.h>
#include <errno.h>

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	int verify_options = SSL_VERIFY_PEER;

	/* as a server, are we requiring clients to identify themselves? */
	if (!lws_check_opt(vh->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)) {
		lwsl_notice("no client cert required\n");
		return 0;
	}

	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
		verify_options = SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	lwsl_notice("%s: vh %s requires client cert %d\n", __func__, vh->name,
		    verify_options);

	SSL_CTX_set_verify(vh->tls.ssl_ctx, verify_options, NULL);

	return 0;
}

static int
lws_mbedtls_sni_cb(void *arg, mbedtls_ssl_context *mbedtls_ctx,
		   const unsigned char *servername, size_t len)
{
	SSL *ssl = SSL_SSL_from_mbedtls_ssl_context(mbedtls_ctx);
	struct lws_context *context = (struct lws_context *)arg;
	struct lws_vhost *vhost, *vh;

	lwsl_notice("%s: %s\n", __func__, servername);

	/*
	 * We can only get ssl accepted connections by using a vhost's ssl_ctx
	 * find out which listening one took us and only match vhosts on the
	 * same port.
	 */
	vh = context->vhost_list;
	while (vh) {
		if (!vh->being_destroyed &&
		    vh->tls.ssl_ctx == SSL_get_SSL_CTX(ssl))
			break;
		vh = vh->vhost_next;
	}

	if (!vh) {
		assert(vh); /* can't match the incoming vh? */
		return 0;
	}

	vhost = lws_select_vhost(context, vh->listen_port,
				 (const char *)servername);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername, vh->listen_port);

		return 0;
	}

	lwsl_info("SNI: Found: %s:%d at vhost '%s'\n", servername,
					vh->listen_port, vhost->name);

	if (!vhost->tls.ssl_ctx) {
		lwsl_err("%s: vhost %s matches SNI but no valid cert\n",
				__func__, vh->name);

		return 1;
	}

	/* select the ssl ctx from the selected vhost for this conn */
	SSL_set_SSL_CTX(ssl, vhost->tls.ssl_ctx);

	return 0;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t mem_cert_len,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	lws_filepos_t flen;
	uint8_t *p = NULL;
	long err;
	int n;

	if ((!cert || !private_key) && (!mem_cert || !mem_privkey)) {
		lwsl_notice("%s: no usable input\n", __func__);
		return 0;
	}

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey))
		return 0;

	/*
	 * we can't read the root-privs files.  But if mem_cert is provided,
	 * we should use that.
	 */
	if (n == LWS_TLS_EXTANT_NO)
		n = LWS_TLS_EXTANT_ALTERNATIVE;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey))
		return 1; /* no alternative */

	if (n == LWS_TLS_EXTANT_ALTERNATIVE) {
		/*
		 * Although we have prepared update certs, we no longer have
		 * the rights to read our own cert + key we saved.
		 *
		 * If we were passed copies in memory buffers, use those
		 * instead.
		 *
		 * The passed memory-buffer cert image is in DER, and the
		 * memory-buffer private key image is PEM.
		 */
		cert = NULL;
		private_key = NULL;
	}
	if (lws_tls_alloc_pem_to_der_file(vhost->context, cert, mem_cert,
					  mem_cert_len, &p, &flen)) {
		lwsl_err("couldn't find cert file %s\n", cert);

		return 1;
	}

	err = SSL_CTX_use_certificate_ASN1(vhost->tls.ssl_ctx, (int)flen, p);
	lws_free_set_NULL(p);
	if (!err) {
		lwsl_err("Problem loading cert\n");
		return 1;
	}

	if (lws_tls_alloc_pem_to_der_file(vhost->context, private_key,
					  (char *)mem_privkey, mem_privkey_len,
					  &p, &flen)) {
		lwsl_err("couldn't find private key\n");

		return 1;
	}

	err = SSL_CTX_use_PrivateKey_ASN1(0, vhost->tls.ssl_ctx, p, (long)flen);
	lws_free_set_NULL(p);
	if (!err) {
		lwsl_err("Problem loading key\n");

		return 1;
	}

	vhost->tls.skipped_certs = 0;

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	const SSL_METHOD *method = TLS_server_method();
	uint8_t *p;
	lws_filepos_t flen;
	int n;

	vhost->tls.ssl_ctx = SSL_CTX_new(method, &vhost->context->mcdc);	/* create context */
	if (!vhost->tls.ssl_ctx) {
		lwsl_err("problem creating ssl context\n");
		return 1;
	}

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	if (info->ssl_ca_filepath) {
		lwsl_notice("%s: vh %s: loading CA filepath %s\n", __func__,
			    vhost->name, info->ssl_ca_filepath);
		if (lws_tls_alloc_pem_to_der_file(vhost->context,
				info->ssl_ca_filepath, NULL, 0, &p, &flen)) {
			lwsl_err("couldn't find client CA file %s\n",
					info->ssl_ca_filepath);

			return 1;
		}

		if (SSL_CTX_add_client_CA_ASN1(vhost->tls.ssl_ctx, (int)flen, p) != 1) {
			lwsl_err("%s: SSL_CTX_add_client_CA_ASN1 unhappy\n",
				 __func__);
			free(p);
			return 1;
		}
		free(p);
	} else {
		if (info->server_ssl_ca_mem && info->server_ssl_ca_mem_len &&
		    SSL_CTX_add_client_CA_ASN1(vhost->tls.ssl_ctx,
					       (int)info->server_ssl_ca_mem_len,
					       info->server_ssl_ca_mem) != 1) {
			lwsl_err("%s: mem SSL_CTX_add_client_CA_ASN1 unhappy\n",
				 __func__);
			return 1;
		}
		lwsl_notice("%s: vh %s: mem CA OK\n", __func__, vhost->name);
	}

	n = lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
				      info->ssl_private_key_filepath,
				      info->server_ssl_cert_mem,
				      info->server_ssl_cert_mem_len,
				      info->server_ssl_private_key_mem,
				      info->server_ssl_private_key_mem_len);
	if (n)
		return n;

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	errno = 0;
	wsi->tls.ssl = SSL_new(wsi->a.vhost->tls.ssl_ctx);
	if (wsi->tls.ssl == NULL) {
		lwsl_err("SSL_new failed: errno %d\n", errno);

		lws_tls_err_describe_clear();
		return 1;
	}

	SSL_set_fd(wsi->tls.ssl, (int)accept_fd);

	if (wsi->a.vhost->tls.ssl_info_event_mask)
		SSL_set_info_callback(wsi->tls.ssl, lws_ssl_info_callback);

	SSL_set_sni_callback(wsi->tls.ssl, lws_mbedtls_sni_cb, wsi->a.context);

	return 0;
}

#if defined(LWS_AMAZON_RTOS)
enum lws_ssl_capable_status
#else
int
#endif
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->tls.use_ssl)
		__lws_tls_shutdown(wsi);
	
	SSL_free(wsi->tls.ssl);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	union lws_tls_cert_info_results ir;
	int m, n;

	n = SSL_accept(wsi->tls.ssl);

	wsi->skip_fallback = 1;
	if (n == 1) {

		if (strstr(wsi->a.vhost->name, ".invalid")) {
			lwsl_notice("%s: vhost has .invalid, "
				    "rejecting accept\n", __func__);

			return LWS_SSL_CAPABLE_ERROR;
		}

		n = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					   &ir, sizeof(ir.ns.name));
		if (!n)
			lwsl_notice("%s: client cert CN '%s'\n",
				    __func__, ir.ns.name);
		else
			lwsl_info("%s: couldn't get client cert CN\n",
				  __func__);
		return LWS_SSL_CAPABLE_DONE;
	}

	m = SSL_get_error(wsi->tls.ssl, n);
	lwsl_debug("%s: %s: accept SSL_get_error %d errno %d\n", __func__,
		    lws_wsi_tag(wsi), m, errno);

	// mbedtls wrapper only
	if (m == SSL_ERROR_SYSCALL && errno == 11)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

#if defined(__APPLE__)
	if (m == SSL_ERROR_SYSCALL && errno == 35)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
#endif

#if defined(WIN32)
	if (m == SSL_ERROR_SYSCALL && errno == 0)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
#endif

	if (m == SSL_ERROR_SYSCALL || m == SSL_ERROR_SSL)
		return LWS_SSL_CAPABLE_ERROR;

	if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->tls.ssl)) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		lwsl_info("SSL_ERROR_WANT_READ\n");
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->tls.ssl)) {
		lwsl_debug("%s: WANT_WRITE\n", __func__);

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n",
				  __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

#if defined(LWS_WITH_ACME)
/*
 * mbedtls doesn't support SAN for cert creation.  So we use a known-good
 * tls-sni-01 cert from OpenSSL that worked on Let's Encrypt, and just replace
 * the pubkey n part and the signature part.
 *
 * This will need redoing for tls-sni-02...
 */

static uint8_t ss_cert_leadin[] = {
	0x30, 0x82,
	  0x05, 0x56, /* total length: LEN1 (+2 / +3) (correct for 513 + 512)*/

	0x30, 0x82, /* length: LEN2  (+6 / +7) (correct for 513) */
		0x03, 0x3e,

	/* addition: v3 cert (+5 bytes)*/
	0xa0, 0x03,
		0x02, 0x01, 0x02,

	0x02, 0x01, 0x01,
	0x30, 0x0d, 0x06, 0x09, 0x2a,
	0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x3f,
	0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47,
	0x42, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b,
	0x73, 0x6f, 0x6d, 0x65, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x31,
	0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11, 0x74, 0x65,
	0x6d, 0x70, 0x2e, 0x61, 0x63, 0x6d, 0x65, 0x2e, 0x69, 0x6e, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x30, 0x1e, 0x17, 0x0d,

	/* from 2017-10-29 ... */
	0x31, 0x37, 0x31, 0x30, 0x32, 0x39, 0x31, 0x31, 0x34, 0x39, 0x34, 0x35,
	0x5a, 0x17, 0x0d,

	/* thru 2049-10-29 we immediately discard the private key, no worries */
	0x34, 0x39, 0x31, 0x30, 0x32, 0x39, 0x31, 0x32, 0x34, 0x39, 0x34, 0x35,
	0x5a,

	0x30, 0x3f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x47, 0x42, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a,
	0x0c, 0x0b, 0x73, 0x6f, 0x6d, 0x65, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e,
	0x79, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
	0x74, 0x65, 0x6d, 0x70, 0x2e, 0x61, 0x63, 0x6d, 0x65, 0x2e, 0x69, 0x6e,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x30,

	0x82,
		0x02, 0x22, /* LEN3 (+C3 / C4) */
	0x30, 0x0d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
	0x03,

	0x82,
		0x02, 0x0f, /* LEN4 (+D6 / D7) */

	0x00, 0x30, 0x82,

		0x02, 0x0a, /* LEN5 (+ DB / DC) */

	0x02, 0x82,

	//0x02, 0x01, /* length of n in bytes (including leading 00 if any) */
	},

	/* 1 + (keybits / 8) bytes N */

	ss_cert_san_leadin[] = {
		/* e - fixed */
		0x02, 0x03, 0x01, 0x00, 0x01,

		0xa3, 0x5d, 0x30, 0x5b, 0x30, 0x59, 0x06, 0x03, 0x55, 0x1d,
		0x11, 0x04, 0x52, 0x30, 0x50, /* <-- SAN length + 2 */

		0x82, 0x4e, /* <-- SAN length */
	},

	/* 78 bytes of SAN (tls-sni-01)
	0x61, 0x64, 0x34, 0x31, 0x61, 0x66, 0x62, 0x65, 0x30, 0x63, 0x61, 0x34,
	0x36, 0x34, 0x32, 0x66, 0x30, 0x61, 0x34, 0x34, 0x39, 0x64, 0x39, 0x63,
	0x61, 0x37, 0x36, 0x65, 0x62, 0x61, 0x61, 0x62, 0x2e, 0x32, 0x38, 0x39,
	0x34, 0x64, 0x34, 0x31, 0x36, 0x63, 0x39, 0x38, 0x33, 0x66, 0x31, 0x32,
	0x65, 0x64, 0x37, 0x33, 0x31, 0x61, 0x33, 0x30, 0x66, 0x35, 0x63, 0x34,
	0x34, 0x37, 0x37, 0x66, 0x65, 0x2e, 0x61, 0x63, 0x6d, 0x65, 0x2e, 0x69,
	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, */

	/* end of LEN2 area */

	ss_cert_sig_leadin[] = {
		/* it's saying that the signature is SHA256 + RSA */
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
		0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,

		0x82,
			0x02, 0x01,
		0x00,
	};

	/* (keybits / 8) bytes signature to end of LEN1 area */

#define SAN_A_LENGTH 78

int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	int buflen = 0x560;
	uint8_t *buf = lws_malloc((unsigned int)buflen, "tmp cert buf"), *p = buf, *pkey_asn1;
	struct lws_genrsa_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_RSA_KEYEL_COUNT];
	uint8_t digest[32];
	struct lws_genhash_ctx hash_ctx;
	int pkey_asn1_len = 3 * 1024;
	int n, m, keybits = lws_plat_recommended_rsa_bits(), adj;

	if (!buf)
		return 1;

	n = lws_genrsa_new_keypair(vhost->context, &ctx, LGRSAM_PKCS1_1_5,
				   &el[0], keybits);
	if (n < 0) {
		lws_genrsa_destroy_elements(&el[0]);
		goto bail1;
	}

	n = sizeof(ss_cert_leadin);
	memcpy(p, ss_cert_leadin, (unsigned int)n);
	p += n;

	adj = (0x0556 - 0x401) + (keybits / 4) + 1;
	buf[2] = (uint8_t)(adj >> 8);
	buf[3] = (uint8_t)(adj & 0xff);

	adj = (0x033e - 0x201) + (keybits / 8) + 1;
	buf[6] = (uint8_t)(adj >> 8);
	buf[7] = (uint8_t)(adj & 0xff);

	adj = (0x0222 - 0x201) + (keybits / 8) + 1;
	buf[0xc3] = (uint8_t)(adj >> 8);
	buf[0xc4] = (uint8_t)(adj & 0xff);

	adj = (0x020f - 0x201) + (keybits / 8) + 1;
	buf[0xd6] = (uint8_t)(adj >> 8);
	buf[0xd7] = (uint8_t)(adj & 0xff);

	adj = (0x020a - 0x201) + (keybits / 8) + 1;
	buf[0xdb] = (uint8_t)(adj >> 8);
	buf[0xdc] = (uint8_t)(adj & 0xff);

	*p++ = (uint8_t)(((keybits / 8) + 1) >> 8);
	*p++ = (uint8_t)(((keybits / 8) + 1) & 0xff);

	/* we need to drop 1 + (keybits / 8) bytes of n in here, 00 + key */

	*p++ = 0x00;
	memcpy(p, el[LWS_GENCRYPTO_RSA_KEYEL_N].buf, el[LWS_GENCRYPTO_RSA_KEYEL_N].len);
	p += el[LWS_GENCRYPTO_RSA_KEYEL_N].len;

	memcpy(p, ss_cert_san_leadin, sizeof(ss_cert_san_leadin));
	p += sizeof(ss_cert_san_leadin);

	/* drop in 78 bytes of san_a */

	memcpy(p, san_a, SAN_A_LENGTH);
	p += SAN_A_LENGTH;
	memcpy(p, ss_cert_sig_leadin, sizeof(ss_cert_sig_leadin));

	p[17] = (uint8_t)(((keybits / 8) + 1) >> 8);
	p[18] = (uint8_t)(((keybits / 8) + 1) & 0xff);

	p += sizeof(ss_cert_sig_leadin);

	/* hash the cert plaintext */

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256))
		goto bail2;

	if (lws_genhash_update(&hash_ctx, buf, lws_ptr_diff_size_t(p, buf))) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail2;
	}
	if (lws_genhash_destroy(&hash_ctx, digest))
		goto bail2;

	/* sign the hash */

	n = lws_genrsa_hash_sign(&ctx, digest, LWS_GENHASH_TYPE_SHA256, p,
				 (size_t)((size_t)buflen - lws_ptr_diff_size_t(p, buf)));
	if (n < 0)
		goto bail2;
	p += n;

	pkey_asn1 = lws_malloc((unsigned int)pkey_asn1_len, "mbed crt tmp");
	if (!pkey_asn1)
		goto bail2;

	m = lws_genrsa_render_pkey_asn1(&ctx, 1, pkey_asn1, (size_t)pkey_asn1_len);
	if (m < 0) {
		lws_free(pkey_asn1);
		goto bail2;
	}

//	lwsl_hexdump_level(LLL_DEBUG, buf, lws_ptr_diff(p, buf));
	n = SSL_CTX_use_certificate_ASN1(vhost->tls.ssl_ctx,
				 lws_ptr_diff(p, buf), buf);
	if (n != 1) {
		lws_free(pkey_asn1);
		lwsl_err("%s: generated cert failed to load 0x%x\n",
				__func__, -n);
	} else {
		//lwsl_debug("private key\n");
		//lwsl_hexdump_level(LLL_DEBUG, pkey_asn1, n);

		/* and to use our generated private key */
		n = SSL_CTX_use_PrivateKey_ASN1(0, vhost->tls.ssl_ctx,
						pkey_asn1, m);
		lws_free(pkey_asn1);
		if (n != 1) {
			lwsl_err("%s: SSL_CTX_use_PrivateKey_ASN1 failed\n",
				    __func__);
		}
	}

	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(&el[0]);

	lws_free(buf);

	return n != 1;

bail2:
	lws_genrsa_destroy(&ctx);
	lws_genrsa_destroy_elements(&el[0]);
bail1:
	lws_free(buf);

	return -1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
}

#if defined(LWS_WITH_JOSE)
static int
_rngf(void *context, unsigned char *buf, size_t len)
{
	if ((size_t)lws_get_random(context, buf, len) == len)
		return 0;

	return -1;
}

static const char *x5[] = { "C", "ST", "L", "O", "CN" };

/*
 * CSR is output formatted as b64url(DER)
 * Private key is output as a PEM in memory
 */
int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *dcsr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	mbedtls_x509write_csr csr;
	mbedtls_pk_context mpk;
	int buf_size = 4096, n;
	char subject[200], *p = subject, *end = p + sizeof(subject) - 1;
	uint8_t *buf = malloc((unsigned int)buf_size); /* malloc because given to user code */

	if (!buf)
		return -1;

	mbedtls_x509write_csr_init(&csr);

	mbedtls_pk_init(&mpk);
	if (mbedtls_pk_setup(&mpk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) {
		lwsl_notice("%s: pk_setup failed\n", __func__);
		goto fail;
	}

	n = mbedtls_rsa_gen_key(mbedtls_pk_rsa(mpk), _rngf, context,
				(unsigned int)lws_plat_recommended_rsa_bits(), 65537);
	if (n) {
		lwsl_notice("%s: failed to generate keys\n", __func__);

		goto fail1;
	}

	/* subject must be formatted like "C=TW,O=warmcat,CN=myserver" */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(x5); n++) {
		if (p != subject)
			*p++ = ',';
		if (elements[n])
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s=%s", x5[n],
					  elements[n]);
	}

	if (mbedtls_x509write_csr_set_subject_name(&csr, subject))
		goto fail1;

	mbedtls_x509write_csr_set_key(&csr, &mpk);
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

	/*
	 * data is written at the end of the buffer! Use the
	 * return value to determine where you should start
	 * using the buffer
	 */
	n = mbedtls_x509write_csr_der(&csr, buf, (size_t)buf_size, _rngf, context);
	if (n < 0) {
		lwsl_notice("%s: write csr der failed\n", __func__);
		goto fail1;
	}

	/* we have it in DER, we need it in b64URL */

	n = lws_jws_base64_enc((char *)(buf + buf_size) - n, (size_t)n,
			       (char *)dcsr, csr_len);
	if (n < 0)
		goto fail1;

	/*
	 * okay, the CSR is done, last we need the private key in PEM
	 * re-use the DER CSR buf as the result buffer since we cn do it in
	 * one step
	 */

	if (mbedtls_pk_write_key_pem(&mpk, buf, (size_t)buf_size)) {
		lwsl_notice("write key pem failed\n");
		goto fail1;
	}

	*privkey_pem = (char *)buf;
	*privkey_len = strlen((const char *)buf);

	mbedtls_pk_free(&mpk);
	mbedtls_x509write_csr_free(&csr);

	return n;

fail1:
	mbedtls_pk_free(&mpk);
fail:
	mbedtls_x509write_csr_free(&csr);
	free(buf);

	return -1;
}
#endif
#endif
