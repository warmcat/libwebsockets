/*
 * libwebsockets - mbedTLS-specific server functions
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"
#include <mbedtls/x509_csr.h>

int
lws_tls_server_client_cert_verify_config(struct lws_context_creation_info *info,
					 struct lws_vhost *vh)
{
	int verify_options = SSL_VERIFY_PEER;

	/* as a server, are we requiring clients to identify themselves? */

	if (!lws_check_opt(info->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT))
		return 0;

	if (lws_check_opt(info->options, LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
		verify_options = SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	SSL_CTX_set_verify(vh->ssl_ctx, verify_options, NULL);

	return 0;
}

#if defined(LWS_WITH_ESP32)
int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
	       lws_filepos_t *amount)
{
	nvs_handle nvh;
	size_t s;
	int n = 0;

	ESP_ERROR_CHECK(nvs_open("lws-station", NVS_READWRITE, &nvh));
	if (nvs_get_blob(nvh, filename, NULL, &s) != ESP_OK) {
		n = 1;
		goto bail;
	}
	*buf = lws_malloc(s, "alloc_file");
	if (!*buf) {
		n = 2;
		goto bail;
	}
	if (nvs_get_blob(nvh, filename, (char *)*buf, &s) != ESP_OK) {
		lws_free(*buf);
		n = 1;
		goto bail;
	}

	*amount = s;

bail:
	nvs_close(nvh);

	return n;
}
#else
int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
		lws_filepos_t *amount)
{
	FILE *f;
	size_t s;
	int n = 0;

	f = fopen(filename, "rb");
	if (f == NULL) {
		n = 1;
		goto bail;
	}

	if (fseek(f, 0, SEEK_END) != 0) {
		n = 1;
		goto bail;
	}

	s = ftell(f);
	if (s == (size_t)-1) {
		n = 1;
		goto bail;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		n = 1;
		goto bail;
	}

	*buf = lws_malloc(s, "alloc_file");
	if (!*buf) {
		n = 2;
		goto bail;
	}

	if (fread(*buf, s, 1, f) != 1) {
		lws_free(*buf);
		n = 1;
		goto bail;
	}

	*amount = s;

bail:
	if (f)
		fclose(f);

	return n;

}
#endif

static int
alloc_pem_to_der_file(struct lws_context *context, const char *filename,
		      uint8_t **buf, lws_filepos_t *amount)
{
	uint8_t *pem, *p, *q, *end;
	lws_filepos_t len;
	int n;

	n = alloc_file(context, filename, &pem, &len);
	if (n)
		return n;

	/* trim the first line */

	p = pem;
	end = p + len;
	if (strncmp((char *)p, "-----", 5))
		goto bail;
	p += 5;
	while (p < end && *p != '\n' && *p != '-')
		p++;

	if (*p != '-')
		goto bail;

	while (p < end && *p != '\n')
		p++;

	if (p >= end)
		goto bail;

	p++;

	/* trim the last line */

	q = end - 2;

	while (q > pem && *q != '\n')
		q--;

	if (*q != '\n')
		goto bail;

	*q = '\0';

	*amount = lws_b64_decode_string((char *)p, (char *)pem, len);
	*buf = pem;

	return 0;

bail:
	lws_free(pem);

	return 4;
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
		    vh->ssl_ctx == SSL_get_SSL_CTX(ssl))
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

	lwsl_notice("SNI: Found: %s:%d\n", servername, vh->listen_port);

	/* select the ssl ctx from the selected vhost for this conn */
	SSL_set_SSL_CTX(ssl, vhost->ssl_ctx);

	return 0;
}

int
lws_tls_server_vhost_backend_init(struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	const SSL_METHOD *method = TLS_server_method();
	uint8_t *p;
	lws_filepos_t flen;
	int n, m, err;

	vhost->ssl_ctx = SSL_CTX_new(method);	/* create context */
	if (!vhost->ssl_ctx) {
		lwsl_err("problem creating ssl context\n");
		return 1;
	}

	if (!vhost->use_ssl || !info->ssl_cert_filepath)
		return 0;

	/*
	 * The user code can choose to either pass the cert and
	 * key filepaths using the info members like this, or it can
	 * leave them NULL; force the vhost SSL_CTX init using the info
	 * options flag LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX; and
	 * set up the cert himself using the user callback
	 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, which
	 * happened just above and has the vhost SSL_CTX * in the user
	 * parameter.
	 */
	n = lws_tls_use_any_upgrade_check_extant(info->ssl_cert_filepath);
	if (n == LWS_TLS_EXTANT_ALTERNATIVE)
		return 1;
	m = lws_tls_use_any_upgrade_check_extant(info->ssl_private_key_filepath);
	if (m == LWS_TLS_EXTANT_ALTERNATIVE)
		return 1;
	if ((n == LWS_TLS_EXTANT_NO || m == LWS_TLS_EXTANT_NO) &&
	    (info->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
		lwsl_notice("Ignoring missing %s or %s\n",
				info->ssl_cert_filepath,
				info->ssl_private_key_filepath);
		vhost->skipped_certs = 1;
		return 0;
	}

	if (alloc_pem_to_der_file(vhost->context, info->ssl_cert_filepath, &p,
					&flen)) {
		lwsl_err("couldn't find cert file %s\n",
			 info->ssl_cert_filepath);

		return 1;
	}
	err = SSL_CTX_use_certificate_ASN1(vhost->ssl_ctx, flen, p);
	if (!err) {
		lwsl_err("Problem loading cert\n");
		return 1;
	}
#if !defined(LWS_WITH_ESP32)
	free(p);
	p = NULL;
#endif

	if (info->ssl_private_key_filepath) {
		if (alloc_pem_to_der_file(vhost->context,
					  info->ssl_private_key_filepath,
					  &p, &flen)) {
			lwsl_err("couldn't find cert file %s\n",
				 info->ssl_cert_filepath);

			return 1;
		}
		err = SSL_CTX_use_PrivateKey_ASN1(0, vhost->ssl_ctx, p, flen);
		if (!err) {
			lwsl_err("Problem loading key\n");

			return 1;
		}
	}

#if !defined(LWS_WITH_ESP32)
	free(p);
	p = NULL;
#endif

	if (!info->ssl_private_key_filepath && vhost->protocols[0].callback(wsi,
			LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY,
			vhost->ssl_ctx, NULL, 0)) {
		lwsl_err("ssl private key not set\n");

		return 1;
	}

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	errno = 0;
	wsi->ssl = SSL_new(wsi->vhost->ssl_ctx);
	if (wsi->ssl == NULL) {
		lwsl_err("SSL_new failed: errno %d\n", errno);

		lws_ssl_elaborate_error();
		return 1;
	}

	SSL_set_fd(wsi->ssl, accept_fd);

	if (wsi->vhost->ssl_info_event_mask)
		SSL_set_info_callback(wsi->ssl, lws_ssl_info_callback);

	SSL_set_sni_callback(wsi->ssl, lws_mbedtls_sni_cb, wsi->context);

	return 0;
}

int
lws_tls_server_abort_connection(struct lws *wsi)
{
	lws_tls_shutdown(wsi);
	SSL_free(wsi->ssl);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	union lws_tls_cert_info_results ir;
	int m, n = SSL_accept(wsi->ssl);

	if (n == 1) {
		n = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir,
					   sizeof(ir.ns.name));
		if (!n)
			lwsl_notice("%s: client cert CN '%s'\n",
				    __func__, ir.ns.name);
		else
			lwsl_info("%s: couldn't get client cert CN\n", __func__);
		return LWS_SSL_CAPABLE_DONE;
	}

	m = SSL_get_error(wsi->ssl, n);

	// mbedtls wrapper only
	if (m == SSL_ERROR_SYSCALL && errno == 11)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	if (m == SSL_ERROR_SYSCALL || m == SSL_ERROR_SSL)
		return LWS_SSL_CAPABLE_ERROR;

	if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->ssl)) {
		if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		lwsl_info("SSL_ERROR_WANT_READ\n");
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}
	if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->ssl)) {
		lwsl_debug("%s: WANT_WRITE\n", __func__);

		if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}

/*
 * mbedtls doesn't support SAN for cert creation.  So we use a known-good
 * tls-sni-01 cert from OpenSSL that worked on Let's Encrypt, and just replace
 * the pubkey n part and the signature part.
 *
 * This will need redoing for tls-sni-02...
 */

static uint8_t ss_cert_leadin[] = {
	0x30, 0x82,
	  0x05, 0x51 + 5, /* total length */

	0x30, 0x82, 0x03, 0x39 + 5,

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

	/* thru 2049 (we immediately discard the private key, no worries */
	0x34, 0x39, 0x31, 0x30, 0x32, 0x39, 0x31, 0x32, 0x34, 0x39, 0x34, 0x35,
	0x5a,

	0x30, 0x3f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x47, 0x42, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a,
	0x0c, 0x0b, 0x73, 0x6f, 0x6d, 0x65, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e,
	0x79, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
	0x74, 0x65, 0x6d, 0x70, 0x2e, 0x61, 0x63, 0x6d, 0x65, 0x2e, 0x69, 0x6e,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
	0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82,

	0x02, 0x01, /* length of n in bytes (including leading 00 if any) */
	},

	/* 513 bytes - 0x00 + 512-byte n */

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
	ss_cert_sig_leadin[] = {
		/* it's saying that the signature is SHA256 + RSA */
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
		0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00,
	};

	/* 512-byte / 4096-bit signature to end */

LWS_VISIBLE int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	int buflen = 0x560;
	uint8_t *buf = lws_malloc(buflen, "temp cert buf"), *p = buf, *pkey_asn1;
	struct lws_genrsa_ctx ctx;
	struct lws_genrsa_elements el;
	uint8_t digest[32];
	struct lws_genhash_ctx hash_ctx;
	int pkey_asn1_len = 3 * 1024;
	int n;

	if (!buf)
		return 1;

	n = lws_genrsa_new_keypair(vhost->context, &ctx, &el, 4096);
	if (n < 0) {
		lws_jwk_destroy_genrsa_elements(&el);
		goto bail1;
	}

	memcpy(p, ss_cert_leadin, sizeof(ss_cert_leadin));
	p += sizeof(ss_cert_leadin);

	/* we need to drop 513 bytes of n in here 00 + 512-bytes */

	*p++ = 0x00;
	memcpy(p, el.e[JWK_KEY_N].buf, el.e[JWK_KEY_N].len);
	p += 512;

	memcpy(p, ss_cert_san_leadin, sizeof(ss_cert_san_leadin));
	p += sizeof(ss_cert_san_leadin);

	/* drop in 78 bytes of san_a */

	memcpy(p, san_a, 78);
	p += 78;
	memcpy(p, ss_cert_sig_leadin, sizeof(ss_cert_sig_leadin));
	p += sizeof(ss_cert_sig_leadin);

	/* hash the cert plaintext */

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256))
		goto bail2;

	if (lws_genhash_update(&hash_ctx, buf, lws_ptr_diff(p, buf))) {
		lws_genhash_destroy(&hash_ctx, NULL);

		goto bail2;
	}
	if (lws_genhash_destroy(&hash_ctx, digest))
		goto bail2;

	/* sign the hash */

	n = lws_genrsa_public_sign(&ctx, digest, LWS_GENHASH_TYPE_SHA256, p,
				 buflen - lws_ptr_diff(p, buf));
	if (n < 0)
		goto bail2;
	p += n;

	pkey_asn1 = lws_malloc(pkey_asn1_len, "mbed crt tmp");
	if (!pkey_asn1)
		goto bail2;

	n = lws_genrsa_render_pkey_asn1(&ctx, 1, pkey_asn1, pkey_asn1_len);
	if (n < 0) {
		lws_free(pkey_asn1);
		goto bail2;
	}
	lwsl_debug("private key\n");
	lwsl_hexdump_level(LLL_DEBUG, pkey_asn1, n);

	/* and to use our generated private key */
	n = SSL_CTX_use_PrivateKey_ASN1(0, vhost->ssl_ctx, pkey_asn1, n);
	lws_free(pkey_asn1);
	if (n != 1) {
		lwsl_notice("%s: SSL_CTX_use_PrivateKey_ASN1 failed\n",
			    __func__);
	}

	lws_genrsa_destroy(&ctx);
	lws_jwk_destroy_genrsa_elements(&el);

	lwsl_hexdump_level(LLL_DEBUG, buf, lws_ptr_diff(p, buf));

	n = SSL_CTX_use_certificate_ASN1(vhost->ssl_ctx,
					 lws_ptr_diff(p, buf), buf);
	if (n != 1)
		lwsl_notice("%s: generated cert failed to load 0x%x\n",
			    __func__, -n);

	lws_free(buf);

	return n != 1;

bail2:
	lws_genrsa_destroy(&ctx);
	lws_jwk_destroy_genrsa_elements(&el);
bail1:
	lws_free(buf);

	return -1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
}

#if defined(LWS_WITH_JWS)
static int
_rngf(void *context, unsigned char *buf, size_t len)
{
	if ((size_t)lws_get_random(context, buf, len) == len)
		return 0;

	return -1;
}

/*
 * CSR is output formatted as b64url(DER)
 * Private key is output as a PEM in memory
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *dcsr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	mbedtls_x509write_csr csr;
	char subject[200];
	mbedtls_pk_context mpk;
	int buf_size = 4096, n;
	uint8_t *buf = malloc(buf_size); /* malloc because given to user code */

	if (!buf)
		return -1;

	mbedtls_x509write_csr_init(&csr);

	mbedtls_pk_init(&mpk);
	if (mbedtls_pk_setup(&mpk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) {
		lwsl_notice("%s: pk_setup failed\n", __func__);
		goto fail;
	}

	n = mbedtls_rsa_gen_key(mbedtls_pk_rsa(mpk), _rngf, context,
				4096, 65537);
	if (n) {
		lwsl_notice("%s: failed to generate keys\n", __func__);

		goto fail1;
	}

	/* subject must be formatted like "C=TW,O=warmcat,CN=myserver" */

	lws_snprintf(subject, sizeof(subject) - 1,
		     "C=%s,ST=%s,L=%s,O=%s,CN=%s",
		     elements[LWS_TLS_REQ_ELEMENT_COUNTRY],
		     elements[LWS_TLS_REQ_ELEMENT_STATE],
		     elements[LWS_TLS_REQ_ELEMENT_LOCALITY],
		     elements[LWS_TLS_REQ_ELEMENT_ORGANIZATION],
		     elements[LWS_TLS_REQ_ELEMENT_COMMON_NAME]);
	if (mbedtls_x509write_csr_set_subject_name(&csr, subject))
		goto fail1;

	mbedtls_x509write_csr_set_key(&csr, &mpk);
	mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

	/*
	 * data is written at the end of the buffer! Use the
	 * return value to determine where you should start
	 * using the buffer
	 */
	n = mbedtls_x509write_csr_der(&csr, buf, buf_size, _rngf, context);
	if (n < 0) {
		lwsl_notice("%s: write csr der failed\n", __func__);
		goto fail1;
	}

	/* we have it in DER, we need it in b64URL */

	n = lws_jws_base64_enc((char *)(buf + buf_size) - n, n,
			       (char *)dcsr, csr_len);
	if (n < 0)
		goto fail1;

	/*
	 * okay, the CSR is done, last we need the private key in PEM
	 * re-use the DER CSR buf as the result buffer since we cn do it in
	 * one step
	 */

	if (mbedtls_pk_write_key_pem(&mpk, buf, buf_size)) {
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
