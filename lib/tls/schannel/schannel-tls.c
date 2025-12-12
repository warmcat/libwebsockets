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
#include "private.h"

int
lws_context_init_ssl_library(struct lws_context *cx,
			     const struct lws_context_creation_info *info)
{
	cx->tls_ops = &tls_ops_schannel;
	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len)
{
    PCCERT_CONTEXT pCertCtx = NULL;
    SCHANNEL_CRED schannel_cred = { 0 };
    SECURITY_STATUS status;
    TimeStamp tsExpiry;

    if (!cert && !mem_cert)
        return 0;

    if (lws_tls_schannel_cert_info_load(vhost->context, cert, private_key,
                                        mem_cert, len_mem_cert,
                                        mem_privkey, mem_privkey_len, &pCertCtx)) {
        lwsl_err("%s: Failed to load server certs\n", __func__);
        return 1;
    }

    vhost->tls.ssl_ctx = lws_zalloc(sizeof(*vhost->tls.ssl_ctx), "schannel_ctx");
    if (!vhost->tls.ssl_ctx) {
        CertFreeCertificateContext(pCertCtx);
        return 1;
    }

    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.cCreds = 1;
    schannel_cred.paCred = &pCertCtx;
    /* Allow all protocol versions by default */
    schannel_cred.grbitEnabledProtocols = 0;

    status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL,
                                      &schannel_cred, NULL, NULL,
                                      &vhost->tls.ssl_ctx->cred, &tsExpiry);

    CertFreeCertificateContext(pCertCtx);

    if (status != SEC_E_OK) {
        lwsl_err("%s: AcquireCredentialsHandle failed 0x%x\n", __func__, (int)status);
        lws_free(vhost->tls.ssl_ctx);
        vhost->tls.ssl_ctx = NULL;
        return 1;
    }

    vhost->tls.ssl_ctx->initialized = 1;
    lwsl_vhost_notice(vhost, "vhost %p: server ctx %p created", vhost, vhost->tls.ssl_ctx);

	return 0;
}

void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost)
{
}

void
lws_ssl_destroy(struct lws_vhost *vhost)
{
    if (vhost->tls.ssl_ctx) {
        if (vhost->tls.ssl_ctx->initialized)
            FreeCredentialsHandle(&vhost->tls.ssl_ctx->cred);
        lws_free(vhost->tls.ssl_ctx);
        vhost->tls.ssl_ctx = NULL;
    }
    if (vhost->tls.ssl_client_ctx) {
        if (vhost->tls.ssl_client_ctx->initialized)
            FreeCredentialsHandle(&vhost->tls.ssl_client_ctx->cred);
        lws_free(vhost->tls.ssl_client_ctx);
        vhost->tls.ssl_client_ctx = NULL;
    }
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
    lws_ssl_destroy(vhost);
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
    if (!wsi) return NULL;
    if (wsi->a.vhost) return wsi->a.vhost->tls.ssl_ctx;
	return NULL;
}

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
				    unsigned int key_mem_len)
{
    SCHANNEL_CRED schannel_cred = { 0 };
    SECURITY_STATUS status;
    TimeStamp tsExpiry;
    PCCERT_CONTEXT pCertCtx = NULL;

    vh->tls.ssl_client_ctx = lws_zalloc(sizeof(*vh->tls.ssl_client_ctx), "schannel_client_ctx");
    if (!vh->tls.ssl_client_ctx) return 1;

    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

    if (cert_filepath || cert_mem) {
        schannel_cred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        if (lws_tls_schannel_cert_info_load(vh->context, cert_filepath, private_key_filepath,
                                            cert_mem, cert_mem_len,
                                            key_mem, key_mem_len, &pCertCtx) == 0) {
            schannel_cred.cCreds = 1;
            schannel_cred.paCred = &pCertCtx;
        }
    }

    status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                      &schannel_cred, NULL, NULL,
                                      &vh->tls.ssl_client_ctx->cred, &tsExpiry);

    if (status == SEC_E_NO_CREDENTIALS && schannel_cred.cCreds > 0) {
        lwsl_warn("%s: client cert rejected by SChannel, retrying without\n", __func__);
        schannel_cred.cCreds = 0;
        schannel_cred.paCred = NULL;
        schannel_cred.dwFlags &= ~SCH_CRED_NO_DEFAULT_CREDS;
        status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                          &schannel_cred, NULL, NULL,
                                          &vh->tls.ssl_client_ctx->cred, &tsExpiry);
    }

    if (pCertCtx) CertFreeCertificateContext(pCertCtx);

    if (status != SEC_E_OK) {
        lwsl_err("%s: AcquireCredentialsHandle failed 0x%x\n", __func__, (int)status);
        lws_free(vh->tls.ssl_client_ctx);
        vh->tls.ssl_client_ctx = NULL;
        return 1;
    }

    vh->tls.ssl_client_ctx->initialized = 1;
    return 0;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
    return lws_tls_server_certs_load(vhost, wsi,
                                     info->ssl_cert_filepath,
                                     info->ssl_private_key_filepath,
                                     info->server_ssl_cert_mem,
                                     info->server_ssl_cert_mem_len,
                                     info->server_ssl_private_key_mem,
                                     info->server_ssl_private_key_mem_len);
}
