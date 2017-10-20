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

int
lws_tls_server_client_cert_verify_config(struct lws_context_creation_info *info,
					 struct lws_vhost *vh)
{
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

int
lws_tls_server_vhost_backend_init(struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	const SSL_METHOD *method = TLS_server_method();
	uint8_t *p;
	lws_filepos_t flen;
	int err;

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
	int m, n = SSL_accept(wsi->ssl);

	if (n == 1)
		return LWS_SSL_CAPABLE_DONE;

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


