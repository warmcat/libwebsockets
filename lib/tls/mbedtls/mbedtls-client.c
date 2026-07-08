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

const char *mbedtls_client_preload_filepath;
#include "private-lib-tls-mbedtls.h"

extern int lws_plat_mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len);
extern int lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

int ERR_get_error(void)
{
	return 0;
}



int
lws_ssl_client_bio_create(struct lws *wsi)
{
	struct lws_tls_conn *conn;
	char hostname[128], *p;
	char temp_alpn[128];
	const char *alpn_comma = wsi->a.context->tls.alpn_default;

	if (wsi->stash)
		lws_strncpy(hostname, wsi->stash->cis[CIS_HOST], sizeof(hostname));
	else
		if (lws_hdr_copy(wsi, hostname, sizeof(hostname),
				_WSI_TOKEN_CLIENT_HOST) <= 0) {
			lwsl_err("%s: Unable to get hostname\n", __func__);
			return -1;
		}

	p = hostname;
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			break;
		}
		p++;
	}

	conn = lws_zalloc(sizeof(*conn), "mbedtls client conn");
	if (!conn) {
		lwsl_info("%s: conn alloc failed\n", __func__);
		return -1;
	}

	wsi->tls.ssl = (lws_tls_conn *)conn;
	conn->ctx = wsi->a.vhost->tls.ssl_client_ctx;

	mbedtls_ssl_init(&conn->ssl);
	mbedtls_net_init(&conn->net);

	if (mbedtls_ssl_setup(&conn->ssl, &conn->ctx->conf)) {
		lwsl_info("%s: mbedtls_ssl_setup failed\n", __func__);
		mbedtls_ssl_free(&conn->ssl);
		lws_free(conn);
		wsi->tls.ssl = NULL;
		return -1;
	}

#if defined(LWS_WITH_TLS_SESSIONS)
	if (!(wsi->a.vhost->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE))
		lws_tls_reuse_session(wsi);
#endif

	if (!(wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		lwsl_info("%s: setting hostname %s\n", __func__, hostname);
		if (mbedtls_ssl_set_hostname(&conn->ssl, hostname)) {
			return -1;
		}
	}

	if (wsi->a.vhost->tls.alpn)
		alpn_comma = wsi->a.vhost->tls.alpn;

	if (wsi->stash) {
		if (wsi->stash->cis[CIS_ALPN])
			alpn_comma = wsi->stash->cis[CIS_ALPN];
	} else {
		if (lws_hdr_copy(wsi, temp_alpn, sizeof(temp_alpn),
				_WSI_TOKEN_CLIENT_ALPN) > 0)
			alpn_comma = temp_alpn;
	}

	if (alpn_comma) {
		lwsl_info("%s: %s: client conn sending ALPN list '%s'\n",
			  __func__, lws_wsi_tag(wsi), alpn_comma);
		lws_mbedtls_set_alpn(conn->ctx, alpn_comma);
	}

	conn->net.MBEDTLS_PRIVATE_V30_ONLY(fd) = (int)wsi->desc.sockfd;
	mbedtls_ssl_set_bio(&conn->ssl, &conn->net, lws_plat_mbedtls_net_send, lws_plat_mbedtls_net_recv, NULL);

	return 0;
}

#if defined(LWS_WITH_TCP_TLS)
enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t elen)
{
	int n, en;

	n = mbedtls_ssl_handshake(&wsi->tls.ssl->ssl);

	if (n == 0) {
		lws_tls_server_conn_alpn(wsi);
#if defined(LWS_WITH_TLS_SESSIONS)
		lws_tls_session_new_mbedtls(wsi);
#endif
		lwsl_info("%s: client connect OK\n", __func__);
		return LWS_SSL_CAPABLE_DONE;
	}

	en = (int)LWS_ERRNO;

	if (n == MBEDTLS_ERR_SSL_WANT_READ)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

#if defined(MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
	if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
#endif

	if (n == MBEDTLS_ERR_SSL_WANT_WRITE)
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	lws_snprintf(errbuf, elen, "mbedtls connect err %d %d", n, en);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	uint32_t flags;

	if (!wsi->tls.ssl)
		return -1;

	flags = mbedtls_ssl_get_verify_result(&wsi->tls.ssl->ssl);
	if (flags == 0)
		return 0;

	if (wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)
		flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED)
		flags &= ~((uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED | (uint32_t)MBEDTLS_X509_BADCERT_BAD_MD);

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_EXPIRED)
		flags &= ~((uint32_t)MBEDTLS_X509_BADCERT_EXPIRED | (uint32_t)MBEDTLS_X509_BADCERT_FUTURE);
	if (wsi->tls.use_ssl & LCCSCF_ALLOW_INSECURE)
		flags = 0;

	if (flags != 0) {
		mbedtls_x509_crt_verify_info(ebuf, ebuf_len, "  ! ", flags);
		lwsl_info("%s: cert problem: %s\n", __func__, ebuf);
		return -1;
	}

	return 0;
}
#endif

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    const struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const void *ca_mem,
				    unsigned int ca_mem_len,
				    const char *cert_filepath,
				    const void *cert_mem,
				    unsigned int cert_mem_len,
				    const char *private_key_filepath,
					const void *key_mem,
					unsigned int key_mem_len
					)
{
	struct lws_tls_ctx *ctx;
	int n;

#if defined(LWS_WITH_TLS_SESSIONS)
	vh->tls_session_cache_max = info->tls_session_cache_max ?
				    info->tls_session_cache_max : 10;
	lws_tls_session_cache(vh, info->tls_session_timeout);
#endif

	ctx = lws_zalloc(sizeof(*ctx), "mbedtls client ctx");
	if (!ctx)
		return 1;

	vh->tls.ssl_client_ctx = ctx;

	mbedtls_ssl_config_init(&ctx->conf);

	if (mbedtls_ssl_config_defaults(&ctx->conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) {
		lwsl_err("mbedtls_ssl_config_defaults failed\n");
		return 1;
	}

	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

#if !defined(LWS_HAVE_MBEDTLS_V4)
	mbedtls_ssl_conf_rng(&ctx->conf, lws_gencrypto_mbedtls_rngf, vh->context);
#endif

	if (ca_filepath || mbedtls_client_preload_filepath) {
#if !defined(LWS_PLAT_OPTEE)
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);

		if (ca_filepath) {
			n = mbedtls_x509_crt_parse_file(ctx->ca_chain, ca_filepath);
			if (n != 0) {
				lwsl_err("problem interpreting client ca: %d\n", n);
				return 1;
			}
		}

		if (mbedtls_client_preload_filepath) {
			n = mbedtls_x509_crt_parse_file(ctx->ca_chain, mbedtls_client_preload_filepath);
			if (n != 0) {
				lwsl_err("problem interpreting preload client ca: %d\n", n);
			}
		}
#endif
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
	} else if (ca_mem && ca_mem_len) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
		n = mbedtls_x509_crt_parse(ctx->ca_chain, ca_mem, ca_mem_len);
		if (n != 0) {
			lwsl_err("client CA: x509 parse failed: %d\n", n);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
		lwsl_info("%s: using mem client CA cert %d\n", __func__, ca_mem_len);
	}

	if (cert_filepath || (cert_mem && cert_mem_len)) {
		ctx->chain = lws_zalloc(sizeof(*ctx->chain), "chain");
		ctx->key = lws_zalloc(sizeof(*ctx->key), "key");
		if (!ctx->chain || !ctx->key)
			return 1;

		mbedtls_x509_crt_init(ctx->chain);
		mbedtls_pk_init(ctx->key);

		if (cert_filepath) {
#if !defined(LWS_PLAT_OPTEE)
			n = mbedtls_x509_crt_parse_file(ctx->chain, cert_filepath);
			if (n != 0) {
				lwsl_err("problem %d getting cert '%s'\n", n, cert_filepath);
				return 1;
			}
#endif
		} else {
			n = mbedtls_x509_crt_parse(ctx->chain, cert_mem, cert_mem_len);
			if (n != 0) {
				lwsl_err("problem interpreting client cert: %d\n", n);
				return 1;
			}
		}

		if (private_key_filepath) {
#if !defined(LWS_PLAT_OPTEE)
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
			n = mbedtls_pk_parse_keyfile(ctx->key, private_key_filepath, NULL, lws_gencrypto_mbedtls_rngf, vh->context);
#else
			n = mbedtls_pk_parse_keyfile(ctx->key, private_key_filepath, NULL);
#endif
			if (n != 0) {
				lwsl_err("problem %d getting private key '%s'\n", n, private_key_filepath);
				return 1;
			}
#endif
		} else if (key_mem && key_mem_len) {
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000 && !defined(LWS_HAVE_MBEDTLS_V4)
			n = mbedtls_pk_parse_key(ctx->key, key_mem, key_mem_len, NULL, 0, lws_gencrypto_mbedtls_rngf, vh->context);
#else
			n = mbedtls_pk_parse_key(ctx->key, key_mem, key_mem_len, NULL, 0);
#endif
			if (n != 0) {
				lwsl_err("problem interpreting private key: %d\n", n);
				return 1;
			}
		}

		mbedtls_ssl_conf_own_cert(&ctx->conf, ctx->chain, ctx->key);
	}

	return 0;
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
                const uint8_t *der, size_t der_len)
{
	struct lws_tls_ctx *ctx = vh->tls.ssl_client_ctx;
	int n;

	if (!ctx)
		return 1;

	if (!ctx->ca_chain) {
		ctx->ca_chain = lws_zalloc(sizeof(*ctx->ca_chain), "ca_chain");
		if (!ctx->ca_chain)
			return 1;
		mbedtls_x509_crt_init(ctx->ca_chain);
		mbedtls_ssl_conf_ca_chain(&ctx->conf, ctx->ca_chain, NULL);
	}

	n = mbedtls_x509_crt_parse_der(ctx->ca_chain, der, der_len);
	if (n != 0) {
		lwsl_err("%s: failed: %d\n", __func__, n);
		return 1;
	}

	return 0;
}
