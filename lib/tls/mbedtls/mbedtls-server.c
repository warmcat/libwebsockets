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

#include "private-lib-core.h"
#include "private-lib-tls-mbedtls.h"
#include <mbedtls/x509_csr.h>
#include <errno.h>

extern int lws_plat_mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len);
extern int lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	int verify_options = MBEDTLS_SSL_VERIFY_OPTIONAL;

	if (lws_check_opt(vh->options,
			  LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE)) {
		lwsl_notice("%s: vh %s can verify client cert post-handshake\n",
				__func__, vh->name);
		/* mbedtls does not easily support post-handshake auth without custom code */
		return 0;
	}

	if (!lws_check_opt(vh->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT)) {
		lwsl_notice("no client cert required\n");
		return 0;
	}

	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED))
		verify_options = MBEDTLS_SSL_VERIFY_REQUIRED;

	lwsl_notice("%s: vh %s requires client cert %d\n", __func__, vh->name,
		    verify_options);

	mbedtls_ssl_conf_authmode(&vh->tls.ssl_ctx->conf, verify_options);

	return 0;
}

static int
lws_mbedtls_sni_cb(void *arg, mbedtls_ssl_context *mbedtls_ctx,
		   const unsigned char *servername, size_t len)
{
	struct lws_context *context = (struct lws_context *)arg;
	struct lws_vhost *vhost, *vh;
	/* get the wsi via user_data if we need it, but we can just find vhost */

	lwsl_notice("%s: %s\n", __func__, servername);

	/*
	 * find out which listening one took us and only match vhosts on the
	 * same port.
	 * mbedtls does not have SSL_get_SSL_CTX.
	 * But we can just search all vhosts.
	 */
	vh = context->vhost_list;
	while (vh) {
		if (!vh->being_destroyed && vh->tls.ssl_ctx && &vh->tls.ssl_ctx->conf == mbedtls_ctx->MBEDTLS_PRIVATE(conf))
			break;
		vh = vh->vhost_next;
	}

	if (!vh) {
		/* Not strictly found, maybe just use first vhost with TLS */
		vh = context->vhost_list;
		while (vh && !vh->tls.ssl_ctx)
			vh = vh->vhost_next;
		if (!vh)
			return 0;
	}

	char sn_str[128];
	if (len >= sizeof(sn_str))
		len = sizeof(sn_str) - 1;
	memcpy(sn_str, servername, len);
	sn_str[len] = '\0';

	vhost = lws_select_vhost(context, vh->listen_port, sn_str);
	if (!vhost) {
		lwsl_info("SNI: none: %s:%d\n", servername, vh->listen_port);
		return 0;
	}

	lwsl_info("SNI: Found: %s:%d at vhost '%s'\n", servername,
					vh->listen_port, vhost->name);

	if (!vhost->tls.ssl_ctx) {
		lwsl_err("%s: vhost %s matches SNI but no valid cert\n",
				__func__, vh->name);
		return -1;
	}

	mbedtls_ssl_set_hs_own_cert(mbedtls_ctx, vhost->tls.ssl_ctx->chain, vhost->tls.ssl_ctx->key);
	if (vhost->tls.ssl_ctx->ca_chain)
		mbedtls_ssl_set_hs_ca_chain(mbedtls_ctx, vhost->tls.ssl_ctx->ca_chain, NULL);
	mbedtls_ssl_set_hs_authmode(mbedtls_ctx, vhost->tls.ssl_ctx->conf.MBEDTLS_PRIVATE(authmode));

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
	int n;

	if ((!cert || !private_key) && (!mem_cert || !mem_privkey)) {
		lwsl_notice("%s: no usable input\n", __func__);
		return 0;
	}

	n = (int)lws_tls_generic_cert_checks(vhost, cert, private_key);

	if (n == LWS_TLS_EXTANT_NO && (!mem_cert || !mem_privkey))
		return 0;

	if (n == LWS_TLS_EXTANT_NO)
		n = LWS_TLS_EXTANT_ALTERNATIVE;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE && (!mem_cert || !mem_privkey))
		return 1;

	if (n == LWS_TLS_EXTANT_ALTERNATIVE) {
		cert = NULL;
		private_key = NULL;
	}

	vhost->tls.ssl_ctx->chain = lws_zalloc(sizeof(*vhost->tls.ssl_ctx->chain), "chain");
	vhost->tls.ssl_ctx->key = lws_zalloc(sizeof(*vhost->tls.ssl_ctx->key), "key");
	if (!vhost->tls.ssl_ctx->chain || !vhost->tls.ssl_ctx->key)
		return 1;

	mbedtls_x509_crt_init(vhost->tls.ssl_ctx->chain);
	mbedtls_pk_init(vhost->tls.ssl_ctx->key);

	if (cert) {
#if !defined(LWS_PLAT_OPTEE)
		n = mbedtls_x509_crt_parse_file(vhost->tls.ssl_ctx->chain, cert);
		if (n != 0) {
			lwsl_err("problem loading cert %s: %d\n", cert, n);
			return 1;
		}
#endif
	} else {
		if (lws_tls_alloc_pem_to_der_file(vhost->context, cert, mem_cert,
						  mem_cert_len, &p, &flen)) {
			lwsl_err("couldn't load mem cert\n");
			return 1;
		}
		n = mbedtls_x509_crt_parse(vhost->tls.ssl_ctx->chain, p, (size_t)flen);
		lws_free(p);
		if (n != 0) {
			lwsl_err("problem interpreting cert: %d\n", n);
			return 1;
		}
	}

	if (private_key) {
#if !defined(LWS_PLAT_OPTEE)
#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL, lws_gencrypto_mbedtls_rngf, vhost->context);
#else
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL);
#endif
#else
		n = mbedtls_pk_parse_keyfile(vhost->tls.ssl_ctx->key, private_key, NULL);
#endif
		if (n != 0) {
			lwsl_err("problem loading key %s: %d\n", private_key, n);
			return 1;
		}
#endif
	} else {
		if (lws_tls_alloc_pem_to_der_file(vhost->context, private_key,
						  (char *)mem_privkey, mem_privkey_len,
						  &p, &flen)) {
			lwsl_err("couldn't find private key\n");
			return 1;
		}
#if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0, lws_gencrypto_mbedtls_rngf, vhost->context);
#else
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0);
#endif
#else
		n = mbedtls_pk_parse_key(vhost->tls.ssl_ctx->key, p, (size_t)flen, NULL, 0);
#endif
		lws_free(p);
		if (n != 0) {
			lwsl_err("Problem loading mem key: %d\n", n);
			return 1;
		}
	}

	mbedtls_ssl_conf_own_cert(&vhost->tls.ssl_ctx->conf, vhost->tls.ssl_ctx->chain, vhost->tls.ssl_ctx->key);

	vhost->tls.skipped_certs = 0;

	return 0;
}

int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost)
{
	struct lws_tls_ctx *ctx;
	int n;


	ctx = lws_zalloc(sizeof(*ctx), "mbedtls server ctx");
	if (!ctx)
		return 1;

	vhost->tls.ssl_ctx = ctx;

	mbedtls_ssl_config_init(&ctx->conf);

	if (mbedtls_ssl_config_defaults(&ctx->conf,
					MBEDTLS_SSL_IS_SERVER,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) {
		lwsl_err("mbedtls_ssl_config_defaults failed\n");
		return 1;
	}

#if !defined(LWS_HAVE_MBEDTLS_V4)
	mbedtls_ssl_conf_rng(&ctx->conf, lws_gencrypto_mbedtls_rngf, vhost->context);
#endif

	if (vhost->tls.cfg_ssl_ca_filepath) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
#if !defined(LWS_PLAT_OPTEE)
		n = mbedtls_x509_crt_parse_file(ctx->ca_chain, vhost->tls.cfg_ssl_ca_filepath);
		if (n != 0) {
			lwsl_err("couldn't load CA file %s: %d\n", vhost->tls.cfg_ssl_ca_filepath, n);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
#endif
	} else if (vhost->tls.cfg_server_ssl_ca_mem && vhost->tls.cfg_server_ssl_ca_mem_len) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
		n = mbedtls_x509_crt_parse(ctx->ca_chain, vhost->tls.cfg_server_ssl_ca_mem, vhost->tls.cfg_server_ssl_ca_mem_len);
		if (n != 0) {
			lwsl_err("%s: mem CA parse unhappy: %d\n", __func__, n);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
	}

	return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	int n;

	if (lws_tls_vhost_backend_create_ctx(vhost))
		return 1;

	mbedtls_ssl_conf_sni(&vhost->tls.ssl_ctx->conf, lws_mbedtls_sni_cb, vhost->context);

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	n = (int)lws_tls_generic_cert_checks(vhost, info->ssl_cert_filepath,
					     info->ssl_private_key_filepath);

	if (n == LWS_TLS_EXTANT_NO &&
	    (vhost->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT)) {
		lwsl_notice("No certs found, continuing without SSL_CTX\n");
		lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);
		vhost->tls.ssl_ctx = NULL;
		return 0;
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
	struct lws_tls_conn *conn;

	errno = 0;
	wsi->tls.ctx_ref = lws_tls_ctx_ref_get(wsi->a.vhost);
	if (!wsi->tls.ctx_ref && !wsi->a.vhost->tls.ssl_ctx) {
		lwsl_err("No TLS context\n");
		return 1;
	}

	conn = lws_zalloc(sizeof(*conn), "mbedtls server conn");
	if (!conn)
		return 1;

	wsi->tls.ssl = (lws_tls_conn *)conn;
	conn->ctx = wsi->tls.ctx_ref ? wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;

	mbedtls_ssl_init(&conn->ssl);
	mbedtls_net_init(&conn->net);

	if (mbedtls_ssl_setup(&conn->ssl, &conn->ctx->conf)) {
		mbedtls_ssl_free(&conn->ssl);
		lws_free(conn);
		wsi->tls.ssl = NULL;
		return 1;
	}

	conn->net.MBEDTLS_PRIVATE_V30_ONLY(fd) = accept_fd;
	mbedtls_ssl_set_bio(&conn->ssl, &conn->net, lws_plat_mbedtls_net_send, lws_plat_mbedtls_net_recv, NULL);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	if (wsi->tls.use_ssl)
		__lws_tls_shutdown(wsi);
	
#if defined(LWS_ROLE_QUIC)
	mbedtls_quic_bio_free(wsi);
#endif

	if (wsi->tls.ssl) {
		mbedtls_ssl_free(&wsi->tls.ssl->ssl);
		lws_free(wsi->tls.ssl);
		wsi->tls.ssl = NULL;
	}

	return 0;
}

#if defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	union lws_tls_cert_info_results ir;
	int n, en;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _o_mbed_ssl_acc_start = lws_now_usecs();
#endif

	n = mbedtls_ssl_handshake(&wsi->tls.ssl->ssl);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _o_mbed_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _o_mbed_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	wsi->skip_fallback = 1;
	if (n == 0) {
		if ((char *)strstr(wsi->a.vhost->name, ".invalid")) {
			lwsl_notice("%s: vhost has .invalid, rejecting accept\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}

		n = lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					   &ir, sizeof(ir.ns.name));
		if (!n)
			lwsl_notice("%s: client cert CN '%s'\n", __func__, ir.ns.name);
		else
			lwsl_info("%s: couldn't get client cert CN\n", __func__);

		return LWS_SSL_CAPABLE_DONE;
	}

	en = errno;
	lwsl_debug("%s: %s: accept mbedtls_ssl_handshake %d errno %d\n", __func__,
		    lws_wsi_tag(wsi), n, en);

	if (n == MBEDTLS_ERR_SSL_WANT_READ) {
		if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			lwsl_info("%s: WANT_READ change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
		if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
			lwsl_info("%s: WANT_WRITE change_pollfd failed\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
	}

	return LWS_SSL_CAPABLE_ERROR;
}
#endif

#if defined(LWS_WITH_ACME)
int
lws_tls_acme_sni_cert_create(struct lws_vhost *vhost, const char *san_a,
			     const char *san_b)
{
	/* The previous OpenSSL ASN1 wrapper based generation is removed.
	 * Native mbedTLS ACME integration should be done via mbedtls_x509write_crt.
	 */
	return -1;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
}
#endif

#if defined(LWS_WITH_JOSE)
static int
_rngf(void *context, unsigned char *buf, size_t len)
{
	if ((size_t)lws_get_random(context, buf, len) == len)
		return 0;
	return -1;
}

int
lws_tls_acme_sni_csr_create(struct lws_context *context, const char *elements[],
			    uint8_t *dcsr, size_t csr_len, char **privkey_pem,
			    size_t *privkey_len)
{
	/* This will be updated if JOSE is used */
	return -1;
}
#endif
