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

/*
 * A CA the app pinned.  It goes in ctx->ca_store, which
 * lws_tls_schannel_chain_engine() then makes the *only* trust root for
 * chains built with this ctx: pinning a CA has to mean the OS ROOT store
 * stops being trusted, otherwise "trust only my private CA" quietly means
 * "trust my private CA and every public CA as well".
 */

int
lws_tls_schannel_ca_add(struct lws_tls_schannel_ctx *ctx, const uint8_t *der,
			size_t der_len)
{
	if (!ctx)
		return 1;

	if (!ctx->ca_store) {
		ctx->ca_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0,
					      NULL);
		if (!ctx->ca_store) {
			lwsl_err("%s: CertOpenStore failed: 0x%x\n", __func__,
				 (unsigned int)GetLastError());

			return 1;
		}
	}

	if (!CertAddEncodedCertificateToStore(ctx->ca_store,
					      X509_ASN_ENCODING |
					      PKCS_7_ASN_ENCODING, der,
					      (DWORD)der_len,
					      CERT_STORE_ADD_REPLACE_EXISTING,
					      NULL)) {
		lwsl_err("%s: CertAddEncodedCertificateToStore failed: 0x%x\n",
			 __func__, (unsigned int)GetLastError());

		return 1;
	}

	/* it has to be rebuilt now the trust set changed */

	if (ctx->chain_engine) {
		CertFreeCertificateChainEngine(ctx->chain_engine);
		ctx->chain_engine = NULL;
	}

	return 0;
}

/*
 * Walk PEM blocks (or a bare DER blob) and add each certificate to the ctx's
 * pinned CA store.  Returns nonzero if nothing could be added.
 */

static int
lws_tls_schannel_ca_parse(struct lws_context *cx,
			  struct lws_tls_schannel_ctx *ctx,
			  const uint8_t *p, size_t len)
{
	static const char beg[] = "-----BEGIN", end[] = "-----END";
	const uint8_t *e = p + len;
	lws_filepos_t der_len;
	uint8_t *der;
	int count = 0, first = 1;

	if (!p || !len)
		return 1;

	while (p < e) {
		const uint8_t *b = NULL, *f = NULL, *q;

		for (q = p; q + sizeof(beg) - 1 <= e; q++)
			if (!memcmp(q, beg, sizeof(beg) - 1)) {
				b = q;
				break;
			}

		if (!b) {
			if (!first)
				break;

			/* no PEM header at all: take it as raw DER */

			return lws_tls_schannel_ca_add(ctx, p, len);
		}

		first = 0;

		for (q = b; q + sizeof(end) - 1 <= e; q++)
			if (!memcmp(q, end, sizeof(end) - 1)) {
				f = q;
				break;
			}

		if (!f)
			break;

		/* step over the "-----END ...-----" line */

		f += sizeof(end) - 1;
		while (f < e && *f != '\n')
			f++;
		if (f < e)
			f++;

		der = NULL;
		der_len = 0;
		if (!lws_tls_alloc_pem_to_der_file(cx, NULL, (const char *)b,
						   (lws_filepos_t)
						   lws_ptr_diff_size_t(f, b),
						   &der, &der_len)) {
			if (der && der_len &&
			    !lws_tls_schannel_ca_add(ctx, der, (size_t)der_len))
				count++;
			if (der)
				lws_free(der);
		}

		p = f;
	}

	if (!count) {
		lwsl_err("%s: no CA certs could be parsed\n", __func__);

		return 1;
	}

	lwsl_info("%s: loaded %d CA cert(s)\n", __func__, count);

	return 0;
}

/*
 * Load the pinned CA set from a file and / or a memory blob
 */

static int
lws_tls_schannel_ca_load(struct lws_context *cx,
			 struct lws_tls_schannel_ctx *ctx,
			 const char *filepath, const void *mem,
			 unsigned int mem_len)
{
	lws_filepos_t amount;
	uint8_t *buf;
	int n;

	if (filepath) {
		if (alloc_file(cx, filepath, &buf, &amount)) {
			lwsl_err("%s: cannot read CA %s\n", __func__, filepath);

			return 1;
		}

		n = lws_tls_schannel_ca_parse(cx, ctx, buf, (size_t)amount);
		lws_free(buf);

		if (n)
			return 1;
	}

	if (mem && mem_len)
		return lws_tls_schannel_ca_parse(cx, ctx, mem, mem_len);

	return 0;
}

HCERTCHAINENGINE
lws_tls_schannel_chain_engine(struct lws_tls_schannel_ctx *ctx)
{
	LWS_CERT_CHAIN_ENGINE_CONFIG cfg;

	if (!ctx || !ctx->ca_store)
		return NULL; /* ie, the default engine: the OS ROOT store */

	if (ctx->chain_engine)
		return ctx->chain_engine;

	memset(&cfg, 0, sizeof(cfg));
	cfg.hExclusiveRoot = ctx->ca_store;
	cfg.hExclusiveTrustedPeople = NULL;

	/*
	 * Win8 and later also let a pinned *intermediate* terminate the
	 * chain; ask for that first and fall back to the Win7 config, which
	 * requires the pinned cert to be the chain's root, if the OS does not
	 * know that member
	 */

	cfg.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
	cfg.cbSize = sizeof(cfg);

	if (CertCreateCertificateChainEngine(
			(PCERT_CHAIN_ENGINE_CONFIG)&cfg, &ctx->chain_engine))
		return ctx->chain_engine;

	cfg.dwExclusiveFlags = 0;
	cfg.cbSize = (DWORD)offsetof(LWS_CERT_CHAIN_ENGINE_CONFIG,
				     dwExclusiveFlags);

	if (CertCreateCertificateChainEngine(
			(PCERT_CHAIN_ENGINE_CONFIG)&cfg, &ctx->chain_engine))
		return ctx->chain_engine;

	/*
	 * We cannot build a chain engine that trusts only the pinned CA.  The
	 * caller must treat NULL-with-a-ca_store as a failure rather than as
	 * "use the default engine", which would silently widen the trust back
	 * out to the whole OS root store
	 */

	lwsl_err("%s: cannot create pinned chain engine: 0x%x\n", __func__,
		 (unsigned int)GetLastError());

	ctx->chain_engine = NULL;

	return NULL;
}

void
lws_tls_schannel_ca_destroy(struct lws_tls_schannel_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->chain_engine) {
		CertFreeCertificateChainEngine(ctx->chain_engine);
		ctx->chain_engine = NULL;
	}

	if (ctx->ca_store) {
		CertCloseStore(ctx->ca_store, 0);
		ctx->ca_store = NULL;
	}
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
    LWS_SCH_CREDENTIALS schannel_cred = { 0 };
    SECURITY_STATUS status;
    TimeStamp tsExpiry;

    if (!cert && !mem_cert)
        return 0;

    if (!vhost->tls.ssl_ctx)
        return 1;

    if (lws_tls_schannel_cert_info_load(vhost->context, cert, private_key,
                                        mem_cert, len_mem_cert,
                                        mem_privkey, mem_privkey_len, &pCertCtx,
                                        &vhost->tls.ssl_ctx->store,
                                        (void **)&vhost->tls.ssl_ctx->u.key_prov,
                                        &vhost->tls.ssl_ctx->key_type,
                                        vhost->tls.ssl_ctx->key_container_name)) {
        lwsl_err("%s: Failed to load server certs\n", __func__);

        /*
         * We do not own vhost->tls.ssl_ctx: on the cert rotation path
         * lws_tls_cert_updated() already created an lws_tls_ctx_ref for it
         * and unrefs it when we return nonzero, which is what actually
         * tears it down (and does it properly, releasing the credential,
         * the key container and the stores).  Freeing it here left that ref
         * pointing at freed memory.
         */

        return 1;
    }

    /*
     * The CA we check client certificates against, if the vhost configured
     * one.  This is also what makes the pinned CA the exclusive trust root
     * for that check rather than the machine's whole root store.
     */

    if ((vhost->tls.cfg_ssl_ca_filepath ||
         vhost->tls.cfg_server_ssl_ca_mem) &&
        lws_tls_schannel_ca_load(vhost->context, vhost->tls.ssl_ctx,
                                 vhost->tls.cfg_ssl_ca_filepath,
                                 vhost->tls.cfg_server_ssl_ca_mem,
                                 vhost->tls.cfg_server_ssl_ca_mem_len)) {
        lwsl_err("%s: Failed to load vhost CA\n", __func__);
        CertFreeCertificateContext(pCertCtx);

        return 1;
    }

    schannel_cred.dwVersion = SCH_CREDENTIALS_VERSION;
    schannel_cred.cCreds = 1;
    schannel_cred.paCred = &pCertCtx;
#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO 0x00400000
#endif
#ifndef SP_PROT_TLS1_3_SERVER
#define SP_PROT_TLS1_3_SERVER 0x00001000
#endif
#ifndef SP_PROT_TLS1_2_SERVER
#define SP_PROT_TLS1_2_SERVER 0x00000400
#endif
    LWS_TLS_PARAMETERS tls_params = { 0 };
    tls_params.grbitDisabledProtocols = (DWORD)~SP_PROT_TLS1_3_SERVER;

    /*
     * SCH_CRED_MANUAL_CRED_VALIDATION: any client certificate is checked by
     * lws_tls_schannel_server_client_cert() against the vhost's own CA, not
     * by Schannel against the machine root store
     */

    schannel_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SYSTEM_MAPPER |
                            SCH_CRED_MANUAL_CRED_VALIDATION | SCH_USE_STRONG_CRYPTO;
    schannel_cred.cTlsParameters = 1;
    schannel_cred.pTlsParameters = &tls_params;

    status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL,
                                      &schannel_cred, NULL, NULL,
                                      &vhost->tls.ssl_ctx->cred, &tsExpiry);

    if (status == SEC_E_UNKNOWN_CREDENTIALS || status == SEC_E_INVALID_PARAMETER) {
        SCHANNEL_CRED old_cred = { 0 };
        old_cred.dwVersion = SCHANNEL_CRED_VERSION;
        old_cred.cCreds = 1;
        old_cred.paCred = &pCertCtx;
        old_cred.dwFlags = schannel_cred.dwFlags;
        /*
         * The SCH_CREDENTIALS path restricts us to TLS1.3 via
         * pTlsParameters; leaving grbitEnabledProtocols at 0 here would
         * quietly drop back to the OS default set, which can still include
         * SSL3 / TLS1.0 / TLS1.1
         */
        old_cred.grbitEnabledProtocols = SP_PROT_TLS1_3_SERVER |
                                         SP_PROT_TLS1_2_SERVER;
        status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL,
                                          &old_cred, NULL, NULL,
                                          &vhost->tls.ssl_ctx->cred, &tsExpiry);
    }

    CertFreeCertificateContext(pCertCtx);

    if (status != SEC_E_OK) {
        lwsl_err("%s: AcquireCredentialsHandle failed 0x%x\n", __func__, (int)status);

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
        lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);
        vhost->tls.ssl_ctx = NULL;
    }
    if (vhost->tls.ssl_client_ctx) {
        if (vhost->tls.ssl_client_ctx->initialized)
            FreeCredentialsHandle(&vhost->tls.ssl_client_ctx->cred);
        /* Client context might not have key_prov set if we passed NULL, but if it does (future use), use CryptReleaseContext if it was CAPI?
           Wait, lws_tls_client_create_vhost_context passes NULL for phProv currently.
           But if it passed a pointer, it would get an HCRYPTPROV.
           Let's assume CAPI.
        */
        if (vhost->tls.ssl_client_ctx->key_type == 0) {
             if (vhost->tls.ssl_client_ctx->u.key_prov)
                 CryptReleaseContext(vhost->tls.ssl_client_ctx->u.key_prov, 0);
        } else {
             if (vhost->tls.ssl_client_ctx->u.key_cng)
                 NCryptFreeObject(vhost->tls.ssl_client_ctx->u.key_cng);
        }

        lws_tls_schannel_ca_destroy(vhost->tls.ssl_client_ctx);

        if (vhost->tls.ssl_client_ctx->store)
            CertCloseStore(vhost->tls.ssl_client_ctx->store, 0);
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
    LWS_SCH_CREDENTIALS schannel_cred = { 0 };
    SECURITY_STATUS status;
    TimeStamp tsExpiry;
    PCCERT_CONTEXT pCertCtx = NULL;

    vh->tls.ssl_client_ctx = lws_zalloc(sizeof(*vh->tls.ssl_client_ctx), "schannel_client_ctx");
    if (!vh->tls.ssl_client_ctx) return 1;

    schannel_cred.dwVersion = SCH_CREDENTIALS_VERSION;
#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO 0x00400000
#endif
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif
#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#endif

    LWS_TLS_PARAMETERS tls_params = { 0 };
    tls_params.grbitDisabledProtocols = (DWORD)~SP_PROT_TLS1_3_CLIENT;

    schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    schannel_cred.cTlsParameters = 1;
    schannel_cred.pTlsParameters = &tls_params;

    /*
     * The CA the app pinned.  Since the credential carries
     * SCH_CRED_MANUAL_CRED_VALIDATION, all the checking is ours to do, and
     * lws_tls_schannel_confirm_cert() makes this store the exclusive trust
     * root: an app that pinned one CA is not asking us to keep trusting
     * every CA in the machine's root store as well.  These parameters used
     * to be ignored altogether.
     */

    if (ca_filepath || (ca_mem && ca_mem_len)) {
        if (lws_tls_schannel_ca_load(vh->context, vh->tls.ssl_client_ctx,
                                     ca_filepath, ca_mem, ca_mem_len)) {
            lwsl_err("%s: Unable to load client CA\n", __func__);
            goto bail;
        }
    } else
        if (lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS)) {
            /*
             * No CA and no OS CAs either: an empty exclusive root store, so
             * nothing verifies, rather than quietly using the OS roots
             */
            lwsl_notice("%s: vh %s: OS CA certs disabled\n", __func__,
                        vh->name);
            vh->tls.ssl_client_ctx->ca_store =
                    CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
            if (!vh->tls.ssl_client_ctx->ca_store)
                goto bail;
        }

    if (cipher_list)
        lwsl_info("%s: vh %s: cipher_list is not settable on schannel\n",
                  __func__, vh->name);

    if (cert_filepath || cert_mem) {
        if (lws_tls_schannel_cert_info_load(vh->context, cert_filepath, private_key_filepath,
                                            cert_mem, cert_mem_len,
                                            key_mem, key_mem_len, &pCertCtx,
                                            &vh->tls.ssl_client_ctx->store,
                                            (void **)&vh->tls.ssl_client_ctx->u.key_prov,
                                            &vh->tls.ssl_client_ctx->key_type,
                                            NULL) == 0) {
            schannel_cred.cCreds = 1;
            schannel_cred.paCred = &pCertCtx;
        }
    }

    status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
                                      &schannel_cred, NULL, NULL,
                                      &vh->tls.ssl_client_ctx->cred, &tsExpiry);

    if (status == SEC_E_UNKNOWN_CREDENTIALS || status == SEC_E_INVALID_PARAMETER) {
        lwsl_err("%s: SCH_CREDENTIALS failed with 0x%x! Falling back to SCHANNEL_CRED (QUIC will fail!)\n", __func__, (int)status);
        SCHANNEL_CRED old_cred = { 0 };
        old_cred.dwVersion = SCHANNEL_CRED_VERSION;
        old_cred.dwFlags = schannel_cred.dwFlags;
        old_cred.cCreds = schannel_cred.cCreds;
        old_cred.paCred = schannel_cred.paCred;
        /* do not let the fallback quietly reintroduce SSL3 / TLS1.0 / 1.1 */
        old_cred.grbitEnabledProtocols = SP_PROT_TLS1_3_CLIENT |
                                         SP_PROT_TLS1_2_CLIENT;
        status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
                                          &old_cred, NULL, NULL,
                                          &vh->tls.ssl_client_ctx->cred, &tsExpiry);
    }

    if (status == SEC_E_NO_CREDENTIALS && schannel_cred.cCreds > 0) {
        lwsl_warn("%s: client cert rejected by SChannel, retrying without\n", __func__);
        schannel_cred.cCreds = 0;
        schannel_cred.paCred = NULL;
        schannel_cred.dwFlags &= ~SCH_CRED_NO_DEFAULT_CREDS;
        status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
                                          &schannel_cred, NULL, NULL,
                                          &vh->tls.ssl_client_ctx->cred, &tsExpiry);
        if (status == SEC_E_UNKNOWN_CREDENTIALS || status == SEC_E_INVALID_PARAMETER) {
            SCHANNEL_CRED old_cred = { 0 };
            old_cred.dwVersion = SCHANNEL_CRED_VERSION;
            old_cred.dwFlags = schannel_cred.dwFlags;
            status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
                                              &old_cred, NULL, NULL,
                                              &vh->tls.ssl_client_ctx->cred, &tsExpiry);
        }
    }

    if (pCertCtx) {
        CertFreeCertificateContext(pCertCtx);
        pCertCtx = NULL;
    }

    if (status != SEC_E_OK) {
        lwsl_err("%s: AcquireCredentialsHandle failed 0x%x\n", __func__, (int)status);
        goto bail;
    }

    vh->tls.ssl_client_ctx->initialized = 1;

    return 0;

bail:
    if (pCertCtx)
        CertFreeCertificateContext(pCertCtx);
    lws_tls_schannel_ca_destroy(vh->tls.ssl_client_ctx);
    if (vh->tls.ssl_client_ctx->store)
        CertCloseStore(vh->tls.ssl_client_ctx->store, 0);
    lws_free(vh->tls.ssl_client_ctx);
    vh->tls.ssl_client_ctx = NULL;

    return 1;
}

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret)
{
}

void
lws_tls_vhost_backend_free_ctx(lws_tls_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->initialized)
        FreeCredentialsHandle(&ctx->cred);

    if (ctx->key_type == 0) {
        if (ctx->u.key_prov) {
            CryptReleaseContext(ctx->u.key_prov, 0);
            if (ctx->key_container_name[0]) {
                 HCRYPTPROV hProv;
                 if (CryptAcquireContext(&hProv, ctx->key_container_name, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_DELETEKEYSET | CRYPT_SILENT)) {
                 }
            }
        }
    } else {
        if (ctx->u.key_cng) {
             NCryptFreeObject(ctx->u.key_cng);
        }
        if (ctx->key_container_name[0]) {
             NCRYPT_PROV_HANDLE hProv = 0;
             if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
                  NCRYPT_KEY_HANDLE hKey = 0;
                  WCHAR wName[128];
                  if (MultiByteToWideChar(CP_UTF8, 0, ctx->key_container_name, -1, wName, 128)) {
                       if (NCryptOpenKey(hProv, &hKey, wName, 0, 0) == ERROR_SUCCESS) {
                            NCryptDeleteKey(hKey, 0);
                       }
                  }
                  NCryptFreeObject(hProv);
             }
        }
    }

    lws_tls_schannel_ca_destroy(ctx);

    if (ctx->store)
        CertCloseStore(ctx->store, 0);
    lws_free(ctx);
}

int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost)
{
    vhost->tls.ssl_ctx = lws_zalloc(sizeof(*vhost->tls.ssl_ctx), "schannel_ctx");
    if (!vhost->tls.ssl_ctx)
        return 1;

    lws_snprintf(vhost->tls.ssl_ctx->key_container_name, sizeof(vhost->tls.ssl_ctx->key_container_name),
                 "lws_vhost_%p_%lu", vhost, (unsigned long)lws_now_usecs());

    return 0;
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
    int n;

    if (lws_tls_vhost_backend_create_ctx(vhost))
        return 1;

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

    n = lws_tls_server_certs_load(vhost, wsi,
                                     info->ssl_cert_filepath,
                                     info->ssl_private_key_filepath,
                                     info->server_ssl_cert_mem,
                                     info->server_ssl_cert_mem_len,
                                     info->server_ssl_private_key_mem,
                                     info->server_ssl_private_key_mem_len);
    if (n) {
        lwsl_err("%s: failed to load certs\n", __func__);
        /*
         * No lws_tls_ctx_ref exists yet on this path, so the ctx is ours
         * to tear down... and it must be the backend teardown, not a bare
         * lws_free(), or the credential / key container / stores leak
         */
        lws_tls_vhost_backend_free_ctx(vhost->tls.ssl_ctx);
        vhost->tls.ssl_ctx = NULL;

        return 1;
    }

    return 0;
}
