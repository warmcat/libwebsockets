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
#include "private-lib-tls.h"
#if defined(LWS_WITH_OPENHITLS)
#include "openhitls/private.h"
#endif

#if defined(LWS_WITH_TLS_KEYLOG) && !defined(LWS_WITH_OPENHITLS) && \
	!defined(LWS_WITH_GNUTLS) && !defined(LWS_WITH_MBEDTLS) && \
	!defined(LWS_WITH_BEARSSL) && !defined(LWS_WITH_SCHANNEL)
void
lws_klog_dump(const SSL *ssl, const char *line)
{
	struct lws *wsi = (struct lws *)SSL_get_ex_data(ssl,
					  openssl_websocket_private_data_index);
	char path[128], hdr[128], ts[64];
	size_t w = 0, wx = 0;
	int fd, t;

	if (!wsi || !wsi->a.context->keylog_file[0] || !wsi->a.vhost)
		return;

	lws_snprintf(path, sizeof(path), "%s.%s", wsi->a.context->keylog_file,
			wsi->a.vhost->name);

	fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (fd == -1) {
		lwsl_vhost_warn(wsi->a.vhost, "Failed to append %s", path);
		return;
	}

	/* the first item in the chunk */
	if (!strncmp(line, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31)) {
		w += (size_t)write(fd, "\n# ", 3);
		wx += 3;
		t = lwsl_timestamp(LLL_WARN, ts, sizeof(ts));
		wx += (size_t)t;
		w += (size_t)write(fd, ts, (size_t)t);

		t = lws_snprintf(hdr, sizeof(hdr), "%s\n", wsi->lc.gutag);
		w += (size_t)write(fd, hdr, (size_t)t);
		wx += (size_t)t;

		lwsl_vhost_warn(wsi->a.vhost, "appended ssl keylog: %s", path);
	}

	wx += strlen(line) + 1;
	w += (size_t)write(fd, line,
#if defined(WIN32)
			(unsigned int)
#endif
			strlen(line));
	w += (size_t)write(fd, "\n", 1);
	close(fd);

	if (w != wx) {
		lwsl_vhost_warn(wsi->a.vhost, "Failed to write %s", path);
		return;
	}
}
#endif


#if defined(LWS_WITH_NETWORK)
#if (!defined(LWS_WITH_MBEDTLS) && !defined(LWS_WITH_BEARSSL) && \
	!defined(LWS_WITH_SCHANNEL) && !defined(LWS_WITH_OPENHITLS) && \
	defined(OPENSSL_VERSION_NUMBER) && \
				  OPENSSL_VERSION_NUMBER >= 0x10002000L)
static int
alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
	const unsigned char *in, unsigned int inlen, void *arg)
{
#if !defined(LWS_WITH_MBEDTLS) && !defined(LWS_WITH_BEARSSL)
	struct alpn_ctx *alpn_ctx = (struct alpn_ctx *)arg;

	if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_ctx->data,
				  alpn_ctx->len, in, inlen) !=
	    OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_NOACK;
#endif

	return SSL_TLSEXT_ERR_OK;
}
#endif

#if defined(LWS_WITH_OPENHITLS)
static int32_t
alpn_cb_openhitls(HITLS_Ctx *ctx, uint8_t **selectedProto,
		  uint8_t *selectedProtoLen, uint8_t *clientAlpnList,
		  uint32_t clientAlpnListSize, void *arg)
{
	const struct alpn_ctx *alpn_ctx = (const struct alpn_ctx *)arg;
	int32_t ret;

	(void)ctx;

	if (!selectedProto || !selectedProtoLen || !alpn_ctx ||
	    !alpn_ctx->len)
		return HITLS_ALPN_ERR_ALERT_FATAL;

	if (!clientAlpnList || !clientAlpnListSize)
		return HITLS_ALPN_ERR_NOACK;

	*selectedProto = NULL;
	*selectedProtoLen = 0;

	ret = HITLS_SelectAlpnProtocol(selectedProto, selectedProtoLen,
				       alpn_ctx->data, alpn_ctx->len,
				       clientAlpnList, clientAlpnListSize);
	if (ret == HITLS_SUCCESS)
		return (*selectedProto && *selectedProtoLen) ?
				HITLS_ALPN_ERR_OK : HITLS_ALPN_ERR_NOACK;

	if (ret == HITLS_NULL_INPUT || ret == HITLS_CONFIG_INVALID_LENGTH) {
		lwsl_err("%s: openHiTLS ALPN select failed: 0x%x\n",
			 __func__, (unsigned int)ret);
		return HITLS_ALPN_ERR_ALERT_FATAL;
	}

	lwsl_info("%s: openHiTLS ALPN had no protocol match: 0x%x\n",
		  __func__, (unsigned int)ret);

	return HITLS_ALPN_ERR_NOACK;
}
#endif

int
lws_tls_restrict_borrow(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;

	if (cx->simultaneous_ssl_restriction &&
	    cx->simultaneous_ssl >= cx->simultaneous_ssl_restriction) {
		lwsl_notice("%s: tls connection limit %d\n", __func__,
			    cx->simultaneous_ssl);
		return 1;
	}

	if (cx->simultaneous_ssl_handshake_restriction &&
	    cx->simultaneous_ssl_handshake >=
			    cx->simultaneous_ssl_handshake_restriction) {
		lwsl_notice("%s: tls handshake limit %d\n", __func__,
			    cx->simultaneous_ssl_handshake);
		return 1;
	}

	cx->simultaneous_ssl++;
	cx->simultaneous_ssl_handshake++;
	wsi->tls_borrowed_hs = 1;
	wsi->tls_borrowed = 1;

	lwsl_info("%s: %d -> %d\n", __func__,
		  cx->simultaneous_ssl - 1,
		  cx->simultaneous_ssl);

	assert(!cx->simultaneous_ssl_restriction ||
			cx->simultaneous_ssl <=
				cx->simultaneous_ssl_restriction);
	assert(!cx->simultaneous_ssl_handshake_restriction ||
			cx->simultaneous_ssl_handshake <=
				cx->simultaneous_ssl_handshake_restriction);

#if defined(LWS_WITH_SERVER)
	lws_gate_accepts(cx,
			(cx->simultaneous_ssl_restriction &&
			 cx->simultaneous_ssl == cx->simultaneous_ssl_restriction) ||
			(cx->simultaneous_ssl_handshake_restriction &&
			 cx->simultaneous_ssl_handshake == cx->simultaneous_ssl_handshake_restriction));
#endif

	return 0;
}

static void
_lws_tls_restrict_return(struct lws *wsi)
{
#if defined(LWS_WITH_SERVER)
	struct lws_context *cx = wsi->a.context;

	assert(cx->simultaneous_ssl_handshake >= 0);
	assert(cx->simultaneous_ssl >= 0);

	lws_gate_accepts(cx,
			(cx->simultaneous_ssl_restriction &&
			 cx->simultaneous_ssl == cx->simultaneous_ssl_restriction) ||
			(cx->simultaneous_ssl_handshake_restriction &&
			 cx->simultaneous_ssl_handshake == cx->simultaneous_ssl_handshake_restriction));
#endif
}

void
lws_tls_restrict_return_handshake(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;

	/* we're just returning the hs part */

	if (!wsi->tls_borrowed_hs)
		return;

	wsi->tls_borrowed_hs = 0; /* return it one time per wsi */
	cx->simultaneous_ssl_handshake--;

	lwsl_info("%s:  %d -> %d\n", __func__,
		  cx->simultaneous_ssl_handshake + 1,
		  cx->simultaneous_ssl_handshake);

	_lws_tls_restrict_return(wsi);
}

void
lws_tls_restrict_return(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;

	if (!wsi->tls_borrowed)
		return;

	wsi->tls_borrowed = 0;
	cx->simultaneous_ssl--;

	lwsl_info("%s: %d -> %d\n", __func__,
		  cx->simultaneous_ssl + 1,
		  cx->simultaneous_ssl);

	/* We're returning everything, even if hs didn't complete */

	if (wsi->tls_borrowed_hs)
		lws_tls_restrict_return_handshake(wsi);
	else
		_lws_tls_restrict_return(wsi);
}

void
lws_context_init_alpn(struct lws_vhost *vhost)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_BEARSSL) || (defined(OPENSSL_VERSION_NUMBER) && \
				  OPENSSL_VERSION_NUMBER >= 0x10002000L) || \
				  defined(LWS_WITH_GNUTLS) || defined(LWS_WITH_OPENHITLS)
	const char *alpn_comma = vhost->context->tls.alpn_default;

	if (vhost->tls.alpn)
		alpn_comma = vhost->tls.alpn;

	lwsl_notice("%s: alpn_comma = '%s'\n", __func__, alpn_comma ? alpn_comma : "NULL");

	lwsl_info(" Server '%s' advertising ALPN: %s\n",
		    vhost->name, alpn_comma);

	vhost->tls.alpn_ctx.len = (uint8_t)lws_alpn_comma_to_openssl(alpn_comma,
					vhost->tls.alpn_ctx.data,
					sizeof(vhost->tls.alpn_ctx.data) - 1);

#if defined(LWS_WITH_GNUTLS)
	/* GnuTLS ALPN is set per-session, nothing to do here for CTX */
#elif defined(LWS_WITH_BEARSSL)
	/* BearSSL ALPN is set per-session, nothing to do here for CTX */
#elif defined(LWS_WITH_MBEDTLS)
	/* mbedTLS ALPN is configured per-vhost */
	lws_mbedtls_set_alpn(vhost->tls.ssl_ctx, alpn_comma);
#elif defined(LWS_WITH_OPENHITLS)
	HITLS_CFG_SetAlpnProtosSelectCb(vhost->tls.ssl_ctx, alpn_cb_openhitls,
					&vhost->tls.alpn_ctx);
#else
	SSL_CTX_set_alpn_select_cb(vhost->tls.ssl_ctx, alpn_cb,
				   &vhost->tls.alpn_ctx);
#endif
#else
#if !defined(LWS_WITH_SCHANNEL) && !defined(LWS_WITH_GNUTLS)
	lwsl_err(" HTTP2 / ALPN configured "
		 "but not supported by OpenSSL 0x%lx\n",
		 OPENSSL_VERSION_NUMBER);
#endif
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}

int
lws_tls_server_conn_alpn(struct lws *wsi)
{
#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_BEARSSL) || (defined(OPENSSL_VERSION_NUMBER) && \
				  OPENSSL_VERSION_NUMBER >= 0x10002000L) || \
				  defined(LWS_WITH_GNUTLS) || defined(LWS_WITH_OPENHITLS)
	const unsigned char *name = NULL;
	char cstr[10];
	unsigned int len = 0;

	lwsl_info("%s\n", __func__);

	if (!wsi->tls.ssl) {
		lwsl_err("%s: non-ssl\n", __func__);
		return 0;
	}

#if defined(LWS_WITH_GNUTLS)
	{
		gnutls_datum_t selected;
		if (gnutls_alpn_get_selected_protocol((gnutls_session_t)wsi->tls.ssl, &selected) == 0) {
			name = selected.data;
			len = selected.size;
		}
	}
#elif defined(LWS_WITH_OPENHITLS)
	{
		uint8_t *proto;
		uint32_t protoLen;
		if (HITLS_GetSelectedAlpnProto((HITLS_Ctx *)wsi->tls.ssl,
						       &proto, &protoLen) == HITLS_SUCCESS) {
			name = proto;
			len = protoLen;
		}
	}
#elif defined(LWS_WITH_BEARSSL)
	{
		struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
		name = (const unsigned char *)br_ssl_engine_get_selected_protocol(&conn->u.engine);
		len = name ? (unsigned int)strlen((const char *)name) : 0;
	}
#elif defined(LWS_WITH_MBEDTLS)
	name = (const unsigned char *)mbedtls_ssl_get_alpn_protocol(&wsi->tls.ssl->ssl);
	len = name ? (unsigned int)strlen((const char *)name) : 0;
#else
	SSL_get0_alpn_selected(wsi->tls.ssl, &name, &len);
#endif
	if (!len) {
		lwsl_info("no ALPN upgrade\n");
		return 0;
	}

	if (len > sizeof(cstr) - 1)
		len = sizeof(cstr) - 1;

	memcpy(cstr, name, len);
	cstr[len] = '\0';

	lwsl_info("%s: negotiated '%s' using ALPN\n", __func__, cstr);
	wsi->tls.use_ssl |= LCCSCF_USE_SSL;

#if defined(LWS_WITH_CLIENT)
	/* record the successful ALPN in the cache */
	if (wsi->cli_hostname_copy && wsi->a.context->alpn_cache && wsi->c_port) {
		char key[256];
		void *p;
		lws_snprintf(key, sizeof(key), "alpn_%s_%u", wsi->cli_hostname_copy, wsi->c_port);
		/* cache it with a TTL, e.g. 1 hour (3600 seconds) */
		lws_cache_write_through(wsi->a.context->alpn_cache, key, (const uint8_t *)cstr, len + 1,
					lws_now_usecs() + (lws_usec_t)(3600ULL * 1000000ULL), &p);
		lwsl_wsi_notice(wsi, "wrote ALPN %s to cache for %s", cstr, key);
	}
#endif

	return lws_role_call_alpn_negotiated(wsi, (const char *)cstr);

#elif defined(LWS_WITH_SCHANNEL)
       return lws_tls_schannel_server_conn_alpn(wsi);
#else
	lwsl_err("%s: openssl/gnutls too old\n", __func__);
#endif

	return 0;
}
#endif

#if !defined(LWS_PLAT_OPTEE) && !defined(OPTEE_DEV_KIT)
#if defined(LWS_PLAT_FREERTOS) && !defined(LWS_AMAZON_RTOS)
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
	*buf = lws_malloc(s + 1, "alloc_file");
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
	(*buf)[s] = '\0';

	lwsl_notice("%s: nvs: read %s, %d bytes\n", __func__, filename, (int)s);

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
	ssize_t m;
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

	m = (ssize_t)ftell(f);
	if (m == -1l) {
		n = 1;
		goto bail;
	}
	s = (size_t)m;

	if (fseek(f, 0, SEEK_SET) != 0) {
		n = 1;
		goto bail;
	}

	*buf = lws_malloc(s + 1, "alloc_file");
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

/*
 * filename: NULL means use buffer inbuf length inlen directly, otherwise
 *           load the file "filename" into an allocated buffer.
 *
 * Allocates a separate DER output buffer if inbuf / inlen are the input,
 * since the
 *
 * Contents may be PEM or DER: returns with buf pointing to DER and amount
 * set to the DER length.
 */

LWS_VISIBLE int
lws_tls_alloc_pem_to_der_file(struct lws_context *context, const char *filename,
			      const char *inbuf, lws_filepos_t inlen,
			      uint8_t **buf, lws_filepos_t *amount)
{
	uint8_t *pem = NULL, *p, *end;
	lws_filepos_t len;
	uint8_t *q;
	int n;

	if (filename) {
		n = alloc_file(context, filename, (uint8_t **)&pem, &len);
		if (n)
			return n;
	} else {
		pem = (uint8_t *)inbuf;
		len = inlen;
	}

	if (len && pem[len - 1] == '\0')
		len--;

	p = pem;
	end = p + len;

	if (strncmp((char *)p, "-----", 5)) {

		/* take it as being already DER */

		pem = lws_malloc((size_t)inlen, "alloc_der");
		if (!pem)
			return 1;

		memcpy(pem, inbuf, (size_t)inlen);

		*buf = pem;
		*amount = inlen;

		return 0;
	}

	/* PEM -> DER */

	if (!filename) {
		/* we don't know if it's in const memory... alloc the output */
		pem = lws_malloc(((size_t)(inlen + 3) * 3) / 4, "alloc_der");
		if (!pem) {
			lwsl_err("a\n");
			return 1;
		}


	} /* else overwrite the allocated, b64 input with decoded DER */

	/* trim the first line */

	p += 5;
	while (p < end && *p != '\n' && *p != '-')
		p++;

	if (*p != '-') {
		goto bail;
	}

	while (p < end && *p != '\n')
		p++;

	if (p >= end) {
		goto bail;
	}

	p++;

	/* find the end of the base64 block */

	q = p;
	while (q < end && strncmp((const char *)q, "-----END", 8))
		q++;

	if (q == end)
		goto bail;

	/* we can't write into the input buffer for mem, since it may be in RO
	 * const segment
	 */
	if (filename)
		*q = '\0';

	n = lws_ptr_diff(q, p);
	if (n == -1) /* coverity */
		goto bail;

    lwsl_info("%s: PEM payload len %d\n", __func__, n);
    lwsl_hexdump_info(p, (size_t)n);

	n = lws_b64_decode_string_len((char *)p, n,
				      (char *)pem, (int)(long long)len);
	if (n < 0) {
		lwsl_err("%s: base64 pem decode failed\n", __func__);
		goto bail;
	}

	*amount = (unsigned int)n;
	*buf = (uint8_t *)pem;

	return 0;

bail:
	lws_free((uint8_t *)pem);

	return 4;
}


#endif

#if !defined(LWS_PLAT_FREERTOS) && !defined(LWS_PLAT_OPTEE) && !defined(OPTEE_DEV_KIT)


static int
lws_tls_extant(const char *name)
{
	/* it exists if we can open it... */
	int fd = open(name, O_RDONLY);
	char buf[1];
	ssize_t n;

	if (fd < 0)
		return 1;

	/* and we can read at least one byte out of it */
	n = read(fd, buf, 1);
	close(fd);

	return n != 1;
}
#endif
/*
 * Returns 0 if the filepath "name" exists and can be read from.
 *
 * In addition, if "name".upd exists, backup "name" to "name.old.1"
 * and rename "name".upd to "name" before reporting its existence.
 *
 * There are four situations and three results possible:
 *
 * 1) LWS_TLS_EXTANT_NO: There are no certs at all (we are waiting for them to
 *    be provisioned).  We also feel like this if we need privs we don't have
 *    any more to look in the directory.
 *
 * 2) There are provisioned certs written (xxx.upd) and we still have root
 *    privs... in this case we rename any existing cert to have a backup name
 *    and move the upd cert into place with the correct name.  This then becomes
 *    situation 4 for the caller.
 *
 * 3) LWS_TLS_EXTANT_ALTERNATIVE: There are provisioned certs written (xxx.upd)
 *    but we no longer have the privs needed to read or rename them.  In this
 *    case, indicate that the caller should use temp copies if any we do have
 *    rights to access.  This is normal after we have updated the cert.
 *
 *    But if we dropped privs, we can't detect the provisioned xxx.upd cert +
 *    key, because we can't see in the dir.  So we have to upgrade NO to
 *    ALTERNATIVE when we actually have the in-memory alternative.
 *
 * 4) LWS_TLS_EXTANT_YES: The certs are present with the correct name and we
 *    have the rights to read them.
 */

enum lws_tls_extant
lws_tls_use_any_upgrade_check_extant(const char *name)
{
#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_AMAZON_RTOS)

	int n;

#if !defined(LWS_PLAT_FREERTOS)
	char buf[256];

	lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
	if (!lws_tls_extant(buf)) {
		/* ah there is an updated file... how about the desired file? */
		if (!lws_tls_extant(name)) {
			/* rename the desired file */
			for (n = 0; n < 50; n++) {
				lws_snprintf(buf, sizeof(buf) - 1,
					     "%s.old.%d", name, n);
				if (!rename(name, buf))
					break;
			}
			if (n == 50) {
				lwsl_notice("unable to rename %s\n", name);

				return LWS_TLS_EXTANT_ALTERNATIVE;
			}
			lws_snprintf(buf, sizeof(buf) - 1, "%s.upd", name);
		}
		/* desired file is out of the way, rename the updated file */
		if (rename(buf, name)) {
			lwsl_notice("unable to rename %s to %s\n", buf, name);

			return LWS_TLS_EXTANT_ALTERNATIVE;
		}
	}

	if (lws_tls_extant(name))
		return LWS_TLS_EXTANT_NO;
#else
	nvs_handle nvh;
	size_t s = 8192;

	if (nvs_open("lws-station", NVS_READWRITE, &nvh)) {
		lwsl_notice("%s: can't open nvs\n", __func__);
		return LWS_TLS_EXTANT_NO;
	}

	n = nvs_get_blob(nvh, name, NULL, &s);
	nvs_close(nvh);

	if (n)
		return LWS_TLS_EXTANT_NO;
#endif
#endif
	return LWS_TLS_EXTANT_YES;
}

LWS_VISIBLE int
lws_tls_cert_get_x509_remaining(struct lws_context *context, const char *filepath, int *days_left, int *total_days)
{
	struct lws_x509_cert *x = NULL;
	union lws_tls_cert_info_results cri, cri1;
	uint8_t *p;
	lws_filepos_t amount;
	int res = -1;

	*days_left = 0;
	*total_days = 0;

	if (alloc_file(context, filepath, &p, &amount))
		return 1;

	p[amount] = '\0';

	if (lws_x509_create(&x))
		goto bail;

	if (lws_x509_parse_from_pem(x, p, (size_t)amount))
		goto bail_destroy;

	if (!lws_x509_info(x, LWS_TLS_CERT_INFO_VALIDITY_FROM, &cri, 0) &&
	    !lws_x509_info(x, LWS_TLS_CERT_INFO_VALIDITY_TO, &cri1, 0)) {
		time_t now = time(NULL);

		*days_left = (int)((cri1.time - now) / (24 * 3600));
		*total_days = (int)((cri1.time - cri.time) / (24 * 3600));
		res = 0;
	}

bail_destroy:
	lws_x509_destroy(&x);
bail:
	lws_free(p);

	return res;
}

int
lws_x509_cert_fingerprint(struct lws_x509_cert *x509, int type,
			  uint8_t *buf, size_t len)
{
	union lws_tls_cert_info_results *res;
	struct lws_genhash_ctx hctx;
	size_t hash_len;
	uint8_t *der;
	int ret = -1;

	hash_len = lws_genhash_size(type);
	if (!hash_len || len < hash_len)
		return -1;

	der = lws_malloc(4096, "cert_fingerprint_der");
	if (!der)
		return -1;

	res = (union lws_tls_cert_info_results *)der;

	if (lws_x509_info(x509, LWS_TLS_CERT_INFO_DER_RAW, res, 4096))
		goto bail;

	if (lws_genhash_init(&hctx, type))
		goto bail;

	if (lws_genhash_update(&hctx, res->ns.name, (size_t)res->ns.len)) {
		lws_genhash_destroy(&hctx, NULL);
		goto bail;
	}

	if (lws_genhash_destroy(&hctx, buf))
		goto bail;

	ret = (int)hash_len;

bail:
	lws_free(der);
	return ret;
}

int
lws_tls_cert_get_x509_validity(struct lws_context *context, const char *filepath,
			       time_t *not_before, time_t *not_after)
{
	struct lws_x509_cert *x = NULL;
	union lws_tls_cert_info_results cri, cri1;
	uint8_t *p;
	lws_filepos_t amount;
	int res = -1;

	if (alloc_file(context, filepath, &p, &amount))
		return 1;

	p[amount] = '\0';

	if (lws_x509_create(&x))
		goto bail;

	if (lws_x509_parse_from_pem(x, p, (size_t)amount))
		goto bail_destroy;

	if (!lws_x509_info(x, LWS_TLS_CERT_INFO_VALIDITY_FROM, &cri, 0) &&
	    !lws_x509_info(x, LWS_TLS_CERT_INFO_VALIDITY_TO, &cri1, 0)) {
		if (not_before)
			*not_before = cri.time;
		if (not_after)
			*not_after = cri1.time;
		res = 0;
	}

bail_destroy:
	lws_x509_destroy(&x);
bail:
	lws_free(p);

	return res;
}

#if defined(LWS_WITH_DIR)
struct versioned_certs_scan {
	const char *prefix;
	const char *suffix;
	char newest[256];
	char previous[256];
	int count;
};

static int
lws_tls_versioned_certs_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct versioned_certs_scan *scan = (struct versioned_certs_scan *)user;
	size_t len_prefix = strlen(scan->prefix);
	size_t len_name = strlen(lde->name);
	size_t len_suffix = strlen(scan->suffix);

	(void)dirpath;

	/* Filter files that start with prefix, end with suffix, and have YYYYMMDD-HHMMSS in between */
	if (lde->type == LDOT_FILE &&
	    len_name == len_prefix + 16 + len_suffix &&
	    !strncmp(lde->name, scan->prefix, len_prefix) &&
	    !strcmp(lde->name + len_name - len_suffix, scan->suffix) &&
	    lde->name[len_prefix] == '-') {
		/* Check timestamp format: -YYYYMMDD-HHMMSS */
		const char *ts = lde->name + len_prefix + 1;
		int i;
		int ok = 1;
		for (i = 0; i < 15; i++) {
			if (i == 8) {
				if (ts[i] != '-') { ok = 0; break; }
			} else {
				if (ts[i] < '0' || ts[i] > '9') { ok = 0; break; }
			}
		}
		if (ok) {
			/* Since lws_dir sorts alphabetically, each match is newer than the previous one */
			lws_strncpy(scan->previous, scan->newest, sizeof(scan->previous));
			lws_strncpy(scan->newest, lde->name, sizeof(scan->newest));
			scan->count++;
		}
	}
	return 0;
}

static void
lws_tls_find_versioned_certs(const char *filepath, char *dirpath, size_t dirpath_len,
			     char *newest, size_t newest_len,
			     char *previous, size_t previous_len)
{
	struct versioned_certs_scan scan;
	char file_prefix[128];
	const char *suffix = NULL;
	const char *p;

	newest[0] = '\0';
	previous[0] = '\0';
	dirpath[0] = '\0';

	/* Find last separator to split path into directory and file */
	p = strrchr(filepath, '/');
#if defined(WIN32)
	if (!p)
		p = strrchr(filepath, '\\');
#endif
	if (!p)
		return;

	lws_strncpy(dirpath, filepath, lws_ptr_diff_size_t(p, filepath) + 2);

	/* Determine suffix */
	if (strstr(p, "-latest-fullchain.crt")) {
		suffix = "-fullchain.crt";
	} else if (strstr(p, "-latest.crt")) {
		suffix = ".crt";
	} else if (strstr(p, "-latest.key")) {
		suffix = ".key";
	} else {
		/* Not a versioned path suffix we support */
		return;
	}

	/* Extract prefix */
	p++; /* skip separator */
	const char *latest_ptr = strstr(p, "-latest");
	if (!latest_ptr || lws_ptr_diff_size_t(latest_ptr, p) >= sizeof(file_prefix))
		return;

	lws_strncpy(file_prefix, p, lws_ptr_diff_size_t(latest_ptr, p) + 1);

	memset(&scan, 0, sizeof(scan));
	scan.prefix = file_prefix;
	scan.suffix = suffix;

	lws_dir(dirpath, &scan, lws_tls_versioned_certs_cb);

	if (scan.newest[0])
		lws_snprintf(newest, newest_len, "%s%s", dirpath, scan.newest);
	if (scan.previous[0])
		lws_snprintf(previous, previous_len, "%s%s", dirpath, scan.previous);
}
#endif

int
lws_tls_resolve_grace_period_certs(struct lws_context *context,
				   const char *certpath, const char *keypath,
				   char *resolved_cert, size_t resolved_cert_len,
				   char *resolved_key, size_t resolved_key_len)
{
#if defined(LWS_WITH_DIR)
	char dirpath_cert[256], newest_cert[256], previous_cert[256];
	char dirpath_key[256], newest_key[256], previous_key[256];
	time_t now = time(NULL);
	time_t newest_not_before = 0;
	time_t previous_not_after = 0;
#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_FILE_OPS)
	lws_system_policy_t *policy = NULL;
#endif
	char d_path[1024];
	int grace_period = 900; /* 15 mins default */
	int fd_cfg;
#endif

	lws_strncpy(resolved_cert, certpath, resolved_cert_len);
	lws_strncpy(resolved_key, keypath, resolved_key_len);

#if defined(LWS_WITH_DIR)
	/* Check if it is a versioned path */
	if (!strstr(certpath, "-latest.crt") && !strstr(certpath, "-latest-fullchain.crt"))
		return 0;

	lws_tls_find_versioned_certs(certpath, dirpath_cert, sizeof(dirpath_cert),
				     newest_cert, sizeof(newest_cert),
				     previous_cert, sizeof(previous_cert));

	lws_tls_find_versioned_certs(keypath, dirpath_key, sizeof(dirpath_key),
				     newest_key, sizeof(newest_key),
				     previous_key, sizeof(previous_key));

	if (!newest_cert[0] || !newest_key[0])
		return 0;

	if (lws_tls_cert_get_x509_validity(context, newest_cert, &newest_not_before, NULL)) {
		/* Failed to read newest cert validity, fallback to newest on disk */
		lws_strncpy(resolved_cert, newest_cert, resolved_cert_len);
		lws_strncpy(resolved_key, newest_key, resolved_key_len);
		return 0;
	}

	lws_snprintf(d_path, sizeof(d_path), "/etc/lwsws/acme/acme_config.json");
#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_FILE_OPS)
	if (lws_system_parse_policy(context, "/etc/lwsws/policy", &policy) == 0 && policy) {
		lws_snprintf(d_path, sizeof(d_path), "%s/acme_config.json", policy->dns_base_dir);
		lws_system_policy_free(policy);
	}
#endif

	fd_cfg = open(d_path, O_RDONLY);
	if (fd_cfg >= 0) {
		char buf[1024];
		ssize_t nr = read(fd_cfg, buf, sizeof(buf) - 1);
		if (nr > 0) {
			buf[nr] = '\0';
			const char *grace_ptr = strstr(buf, "\"rotation-grace-period\"");
			if (!grace_ptr)
				grace_ptr = strstr(buf, "\"rotation_grace_period\"");
			if (grace_ptr) {
				const char *num_ptr = strchr(grace_ptr, ':');
				if (num_ptr) {
					num_ptr++;
					while (*num_ptr == ' ' || *num_ptr == '\t')
						num_ptr++;
					if (*num_ptr >= '0' && *num_ptr <= '9')
						grace_period = atoi(num_ptr);
				}
			}
		}
		close(fd_cfg);
	}

	/* If previous cert exists and is still valid, and we are within the grace period of the new cert */
	if (previous_cert[0] && previous_key[0] &&
	    !lws_tls_cert_get_x509_validity(context, previous_cert, NULL, &previous_not_after) &&
	    now < previous_not_after &&
	    now < newest_not_before + grace_period) {
		lwsl_notice("%s: Deferring to previous cert %s (grace period: %llds left)\n",
			    __func__, previous_cert, (long long)(newest_not_before + grace_period - now));
		lws_strncpy(resolved_cert, previous_cert, resolved_cert_len);
		lws_strncpy(resolved_key, previous_key, resolved_key_len);
	} else {
		lwsl_notice("%s: Using newest cert %s\n", __func__, newest_cert);
		lws_strncpy(resolved_cert, newest_cert, resolved_cert_len);
		lws_strncpy(resolved_key, newest_key, resolved_key_len);
	}
#endif

	return 0;
}


