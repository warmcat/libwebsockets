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

#if defined(LWS_WITH_SCHANNEL)

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include "private-lib-tls.h"
#include "private.h"

#ifndef SP_PROT_DTLS1_0_SERVER
#define SP_PROT_DTLS1_0_SERVER 0x00020000
#endif
#ifndef SP_PROT_DTLS1_0_CLIENT
#define SP_PROT_DTLS1_0_CLIENT 0x00010000
#endif
#ifndef SP_PROT_DTLS1_2_SERVER
#define SP_PROT_DTLS1_2_SERVER 0x00080000
#endif
#ifndef SP_PROT_DTLS1_2_CLIENT
#define SP_PROT_DTLS1_2_CLIENT 0x00040000
#endif

/*
 * Schannel implementation notes:
 * - Uses SSPI (InitializeSecurityContext / AcceptSecurityContext)
 * - Needs manual buffer management (SECBUFFER_TOKEN, SECBUFFER_DATA)
 * - State machine drivers needed for handshake and data
 */

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info)
{
	struct lws_context *context = info->context;
	enum lws_gendtls_conn_mode mode = info->mode;

    memset(ctx, 0, sizeof(*ctx));
    ctx->context = context;
    ctx->mode = mode;

    /* Generate a unique container name for this context to persist keys if needed */
    lws_snprintf(ctx->key_container_name, sizeof(ctx->key_container_name),
                 "lws_dtls_%p_%u", ctx, (unsigned int)lws_now_secs());

    ctx->schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    ctx->schannel_cred.grbitEnabledProtocols = SP_PROT_DTLS1_0_CLIENT | SP_PROT_DTLS1_0_SERVER |
                                               SP_PROT_DTLS1_2_CLIENT | SP_PROT_DTLS1_2_SERVER;

    ctx->schannel_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

    if (mode == LWS_GENDTLS_MODE_SERVER)
        ctx->schannel_cred.dwFlags |= SCH_CRED_REVOCATION_CHECK_END_CERT;

    /* Delayed AcquireCredentialsHandle until cert is set OR handshake starts if client */
    if (mode == LWS_GENDTLS_MODE_CLIENT) {
        SECURITY_STATUS status;
        TimeStamp ts_expiry;

        status = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
                                          NULL, &ctx->schannel_cred, NULL, NULL, &ctx->cred, &ts_expiry);
        if (status != SEC_E_OK) {
            lwsl_err("%s: AcquireCredentialsHandle failed: 0x%x\n", __func__, (unsigned int)status);
            return -1;
        }
        ctx->cred_init = 1;
    }

    return 0;
}

void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx)
{
    DeleteSecurityContext(&ctx->ctxt);
    if (ctx->cred_init)
		FreeCredentialsHandle(&ctx->cred);

	if (ctx->key_container_name[0]) {
		/* Delete named key */
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
    if (ctx->key_cng) {
        NCryptFreeObject(ctx->key_cng);
        ctx->key_cng = 0;
    }

    if (ctx->cert_ctxt) CertFreeCertificateContext(ctx->cert_ctxt);
    if (ctx->store) CertCloseStore(ctx->store, 0);
    lws_buflist_destroy_all_segments(&ctx->rx_head);
    lws_buflist_destroy_all_segments(&ctx->tx_head);

    if (ctx->cert_mem) lws_free(ctx->cert_mem);
    if (ctx->key_mem) lws_free(ctx->key_mem);
}

static int
lws_gendtls_schannel_update_creds(struct lws_gendtls_ctx *ctx)
{
    SECURITY_STATUS status;
    TimeStamp ts_expiry;

    if (!ctx->cert_mem || !ctx->key_mem)
        return 0;

    if (ctx->cred_init) {
        /* The handle stays with the cert. Keep provider alive as well. */
        FreeCredentialsHandle(&ctx->cred);
        ctx->cred_init = 0;
    }
    if (ctx->cert_ctxt) {
        CertFreeCertificateContext(ctx->cert_ctxt);
        ctx->cert_ctxt = NULL;
    }
    if (ctx->key_cng) {
        NCryptFreeObject(ctx->key_cng);
        ctx->key_cng = 0;
    }
    if (ctx->store) {
        CertCloseStore(ctx->store, 0);
        ctx->store = NULL;
    }

    /* Use the existing schannel-x509.c helper to load and link cert+key */
    if (lws_tls_schannel_cert_info_load(ctx->context, NULL, NULL,
                                        (char *)ctx->cert_mem, ctx->cert_len,
                                        (char *)ctx->key_mem, ctx->key_len,
                                        &ctx->cert_ctxt, &ctx->store,
                                        (void**)&ctx->key_cng, NULL,
                                        ctx->key_container_name)) {
        lwsl_err("%s: Failed to load cert/key pair\n", __func__);
        return -1;
    }

    SCHANNEL_CRED sch_cred = {0};
    sch_cred.dwVersion = SCHANNEL_CRED_VERSION;
    sch_cred.cCreds = 1;
    sch_cred.paCred = &ctx->cert_ctxt;

    /* Enable DTLS protocols */
    sch_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS |
                       SCH_CRED_MANUAL_CRED_VALIDATION |
                       SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                       SCH_CRED_IGNORE_REVOCATION_OFFLINE;
/*
 * We use 0 (all enabled) to allow SChannel to negotiate.
 */

    /* Let OS handle protocol enablement for DTLS */
    sch_cred.grbitEnabledProtocols = 0;

    status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A,
                                      ctx->mode == LWS_GENDTLS_MODE_SERVER ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                      NULL, &sch_cred, NULL, NULL, &ctx->cred, &ts_expiry);

    if (status != SEC_E_OK) {
        lwsl_err("%s: AcquireCredentialsHandle failed: 0x%x\n", __func__, (unsigned int)status);
        return -1;
    }
    ctx->cred_init = 1;

    return 0;
}

int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len)
{
    if (ctx->cert_mem) lws_free(ctx->cert_mem);
    ctx->cert_mem = lws_malloc(len, "gendtls cert");
    if (!ctx->cert_mem) return -1;
    memcpy(ctx->cert_mem, cert, len);
    ctx->cert_len = len;

    return lws_gendtls_schannel_update_creds(ctx);
}

int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len)
{
    if (ctx->key_mem) lws_free(ctx->key_mem);
    ctx->key_mem = lws_malloc(len, "gendtls key");
    if (!ctx->key_mem) return -1;
    memcpy(ctx->key_mem, key, len);
    ctx->key_len = len;

    return lws_gendtls_schannel_update_creds(ctx);
}

int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
    return lws_buflist_append_segment(&ctx->rx_head, in, len) < 0 ? -1 : 0;
}

void
lws_gendtls_schannel_set_client_addr(struct lws_gendtls_ctx *ctx,
				     const struct sockaddr *sa, size_t sa_len)
{
    if (sa_len > sizeof(ctx->client_addr))
        sa_len = sizeof(ctx->client_addr);

    memcpy(&ctx->client_addr, sa, sa_len);
    ctx->client_addr_len = sa_len;
}

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	/* Need to implement SSPI loop here: */
	SecBufferDesc in_desc, out_desc;
	SecBuffer in_bufs[3], out_bufs[1];
	unsigned long attr, req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
				     ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
				     ISC_REQ_DATAGRAM;
	TimeStamp ts;
	SECURITY_STATUS status;
	uint8_t *p;
	size_t avail;
	int ret;

	if (ctx->mode == LWS_GENDTLS_MODE_SERVER)
		req_flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
			    ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY |
			    ASC_REQ_DATAGRAM;

	int getting_fragments = 0;
	while (!ctx->handshake_done) {
		uint8_t *flat_buf = NULL;

		avail = lws_buflist_total_len(&ctx->rx_head);
		if (!avail && !getting_fragments) {
			/* If no input, and we're not explicitly getting fragments... */
			if (ctx->mode == LWS_GENDTLS_MODE_SERVER || ctx->tx_head) {
				/* Servers, and Clients that have already sent a token, shouldn't re-initiate with NULL! */
				return 0;
			}
		}

		size_t pass_avail = 0;
		if (avail && !getting_fragments) {
			pass_avail = avail;
			flat_buf = lws_malloc(pass_avail, "gendtls_hs");
			if (!flat_buf) return -1;
			lws_buflist_linear_copy(&ctx->rx_head, 0, flat_buf, pass_avail);
			p = flat_buf;
		} else {
			p = NULL;
		}

		/* Prepare input buffers */
		in_desc.ulVersion = SECBUFFER_VERSION;
		in_desc.cBuffers = 3;
		in_desc.pBuffers = in_bufs;
		in_bufs[0].BufferType = pass_avail ? SECBUFFER_TOKEN : SECBUFFER_EMPTY;
		in_bufs[0].pvBuffer = (void *)p;
		in_bufs[0].cbBuffer = (unsigned long)pass_avail;
		in_bufs[1].BufferType = SECBUFFER_EMPTY;
		in_bufs[1].pvBuffer = NULL;
		in_bufs[1].cbBuffer = 0;

		/* For SChannel DTLS, we MUST pass the remote peer's SOCKADDR in a SECBUFFER_EXTRA
		   otherwise AcceptSecurityContext (and maybe InitializeSecurityContext) fails
           with SEC_E_ALGORITHM_MISMATCH / SEC_E_DATAGRAM_CONNECTION_ID_INCORRECT */
		in_bufs[2].BufferType = SECBUFFER_EXTRA;
		if (ctx->client_addr_len > 0) {
			in_bufs[2].pvBuffer = &ctx->client_addr;
			in_bufs[2].cbBuffer = (unsigned long)ctx->client_addr_len;
		} else {
			/* Fallback for safety if not set */
			in_bufs[2].pvBuffer = NULL;
			in_bufs[2].cbBuffer = 0;
		}

		/* Prepare output buffers */
		out_desc.ulVersion = SECBUFFER_VERSION;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = out_bufs;
		out_bufs[0].BufferType = SECBUFFER_TOKEN;
		out_bufs[0].pvBuffer = NULL;
		out_bufs[0].cbBuffer = 0;

		if (ctx->mode == LWS_GENDTLS_MODE_CLIENT) {
            if (!ctx->cred_init) {
                 lwsl_err("%s: Credentials not initialized\n", __func__);
                 if (flat_buf) lws_free(flat_buf);
                 return -1;
            }
			status = InitializeSecurityContext(&ctx->cred,
							   ctx->ctxt.dwLower || ctx->ctxt.dwUpper ? &ctx->ctxt : NULL,
							   NULL, req_flags, 0, SECURITY_NATIVE_DREP,
							   pass_avail ? &in_desc : NULL, 0, &ctx->ctxt,
							   &out_desc, &attr, &ts);
		} else {
            if (!ctx->cred_init) {
                 lwsl_err("%s: Server credentials not initialized (needs cert)\n", __func__);
                 if (flat_buf) lws_free(flat_buf);
                 return -1;
            }
			status = AcceptSecurityContext(&ctx->cred,
						       ctx->ctxt.dwLower || ctx->ctxt.dwUpper ? &ctx->ctxt : NULL,
						       &in_desc, req_flags, SECURITY_NATIVE_DREP,
						       &ctx->ctxt, &out_desc, &attr, &ts);
		}

		if (status == SEC_E_OK ||
		    status == SEC_I_CONTINUE_NEEDED ||
		    status == SEC_I_MESSAGE_FRAGMENT) {

			/* Consume used input */
			if (pass_avail) {
				size_t consumed = pass_avail;
				if (in_bufs[1].BufferType == SECBUFFER_EXTRA) {
					consumed = pass_avail - in_bufs[1].cbBuffer;
				}
				if (consumed)
					lws_buflist_use_segment(&ctx->rx_head, consumed);
			}

			if (flat_buf) lws_free(flat_buf);

			/* Validate output token */
			if (out_bufs[0].cbBuffer > 0 && out_bufs[0].pvBuffer) {
				if (lws_buflist_append_segment(&ctx->tx_head, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer) < 0) {
					FreeContextBuffer(out_bufs[0].pvBuffer);
					return -1;
				}
				FreeContextBuffer(out_bufs[0].pvBuffer);
			}

			if (status == SEC_E_OK) {
				ctx->handshake_done = 1;
			}

			if (status == SEC_I_MESSAGE_FRAGMENT) {
				getting_fragments = 1;
				continue;
			}
			getting_fragments = 0;

			/* If handshake is done, STOP looping so the remainder gets processed by DecryptMessage */
			if (ctx->handshake_done) {
				return 0;
			}

			/* Loop to consume the next record if we have an extra buffer remaining */
			if (in_bufs[1].BufferType == SECBUFFER_EXTRA && in_bufs[1].cbBuffer > 0) {
				continue;
			}

			return 0;
		}

		if (flat_buf) lws_free(flat_buf);

		if (status == SEC_E_INCOMPLETE_MESSAGE) {
			return 0; /* Need more data */
		}

		lwsl_err("%s: %s Handshake failed: 0x%x\n", __func__,
                         ctx->mode == LWS_GENDTLS_MODE_SERVER ? "Server" : "Client",
                         (unsigned int)status);
		return -1;
	}

	/* Decrypt Logic */
	/* SSPI requires contiguous buffer. Flatten entire rx buflist to temp buffer. */
	size_t total = lws_buflist_total_len(&ctx->rx_head);
	if (total == 0) return 0;

	uint8_t *buf = lws_malloc(total, "gendtls_rx_flat");
	if (!buf) return -1;

	if (lws_buflist_linear_copy(&ctx->rx_head, 0, buf, total) != total) {
		lws_free(buf);
		return -1;
	}

	SecBufferDesc desc;
	SecBuffer bufs[4];

	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = bufs;

	bufs[0].BufferType = SECBUFFER_DATA;
	bufs[0].pvBuffer = buf;
	bufs[0].cbBuffer = (unsigned long)total;

	bufs[1].BufferType = SECBUFFER_EMPTY;
	bufs[2].BufferType = SECBUFFER_EMPTY;
	bufs[3].BufferType = SECBUFFER_EMPTY;

	status = DecryptMessage(&ctx->ctxt, &desc, 0, NULL);

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		lws_free(buf);
		return 0; /* Wait for more */
	}

	if (status != SEC_E_OK) {
		lwsl_err("%s: %s DecryptMessage failed: 0x%x\n", __func__,
            ctx->mode == LWS_GENDTLS_MODE_SERVER ? "Server" : "Client", (unsigned int)status);
		lws_free(buf);
		return -1;
	}

	/* Find the decrypted data */
	SecBuffer *pData = NULL;
	SecBuffer *pExtra = NULL;

	for (int i = 0; i < 4; i++) {
		if (bufs[i].BufferType == SECBUFFER_DATA) pData = &bufs[i];
		if (bufs[i].BufferType == SECBUFFER_EXTRA) pExtra = &bufs[i];
	}

	if (pData) {
		size_t copied = pData->cbBuffer;
		if (copied > max_len) copied = max_len;
		memcpy(out, pData->pvBuffer, copied);
		ret = (int)copied;
	} else {
		ret = 0;
	}

	/* Consume used data from buflist */
	size_t used = total;
	if (pExtra) {
		used -= pExtra->cbBuffer;
	}

	/* Consume 'used' bytes from rx_head segments */
	while (used > 0) {
		size_t seg_len = lws_buflist_next_segment_len(&ctx->rx_head, NULL);
		if (!seg_len) break; /* Should not happen */

		size_t chunk = (used > seg_len) ? seg_len : used;
		lws_buflist_use_segment(&ctx->rx_head, chunk);
		used -= chunk;
	}

	lws_free(buf);
	return ret;
}

int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	SecPkgContext_StreamSizes sizes;
	SECURITY_STATUS status;
	SecBufferDesc desc;
	SecBuffer bufs[4];
	uint8_t *msg;

	if (!ctx->handshake_done) return -1;

	status = QueryContextAttributes(&ctx->ctxt, SECPKG_ATTR_STREAM_SIZES, &sizes);
	if (status != SEC_E_OK) return -1;

	if (len > sizes.cbMaximumMessage) len = sizes.cbMaximumMessage;

	msg = lws_malloc(sizes.cbHeader + len + sizes.cbTrailer, "gendtls_tx");
	if (!msg) return -1;

	memcpy(msg + sizes.cbHeader, in, len);

	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = bufs;

	bufs[0].BufferType = SECBUFFER_TOKEN;
	bufs[0].pvBuffer = msg;
	bufs[0].cbBuffer = sizes.cbHeader;

	bufs[1].BufferType = SECBUFFER_DATA;
	bufs[1].pvBuffer = msg + sizes.cbHeader;
	bufs[1].cbBuffer = (unsigned long)len;

	bufs[2].BufferType = SECBUFFER_TOKEN;
	bufs[2].pvBuffer = msg + sizes.cbHeader + len;
	bufs[2].cbBuffer = sizes.cbTrailer;

	bufs[3].BufferType = SECBUFFER_EMPTY;
	bufs[3].cbBuffer = 0; bufs[3].pvBuffer = NULL;

	status = EncryptMessage(&ctx->ctxt, 0, &desc, 0);
	if (status != SEC_E_OK) {
        lwsl_err("%s: EncryptMessage failed: 0x%x (len %d)\n", __func__, (unsigned int)status, (int)len);
		lws_free(msg);
		return -1;
	}

    lwsl_notice("%s: EncryptMessage success, Total generated: %d\n", __func__,
                (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer));

	/* Append encrypted blob to tx_head */
	if (lws_buflist_append_segment(&ctx->tx_head, msg,
					bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer) < 0) {
		lws_free(msg);
		return -1;
	}

	lws_free(msg);
	return 0;
}

int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	/* Read from tx_head buflist where push() wrote encrypted data */
	if (!ctx->tx_head)
		return 0;

	size_t avail;
	const uint8_t *p;

	avail = lws_buflist_next_segment_len(&ctx->tx_head, (uint8_t **)&p);
	if (max_len > avail)
		max_len = avail;

	memcpy(out, p, max_len);
	lws_buflist_use_segment(&ctx->tx_head, max_len);

	return (int)max_len;
}

int
lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx, const char *label,
				   size_t label_len, const uint8_t *context,
				   size_t context_len, uint8_t *out, size_t out_len)
{
    /* Not straightforward in Schannel compared to OpenSSL/GnuTLS */
    return -1;
}

int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx)
{
	return ctx->handshake_done;
}

int
lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx)
{
	return !ctx->tx_head && !ctx->rx_head;
}

#endif
