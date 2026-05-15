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
#include "private-lib-tls.h"
#include "private.h"

#if defined(LWS_WITH_TLS) && defined(LWS_WITH_SCHANNEL)

int
lws_tls_quic_vhost_init(lws_tls_ctx *ctx)
{
	/* No context-wide init needed for QUIC under Schannel */
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	if (!wsi || !wsi->tls.ssl)
		return -1;

	wsi->tls.quic_secret_cb = cb;

	/* Schannel handles its own buffers, but we might set up a custom bio if needed */
	return 0;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
#if defined(SECPKG_ATTR_APPLICATION_PROTOCOL) || defined(SECPKG_ATTR_APP_DATA)
	/*
	 * Transport parameter exchange on Windows using Schannel for QUIC
	 * typically requires MsQuic or newer Windows 11 / Server 2022 APIs.
	 */
	wsi->tls.quic_tp_send = tp;
	wsi->tls.quic_tp_send_len = tp_len;
	return 0;
#else
	return -1;
#endif
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	if (!wsi->tls.quic_tp_recv) {
		if (tp_len)
			*tp_len = 0;
		return -1;
	}

	*tp = wsi->tls.quic_tp_recv;
	if (tp_len)
		*tp_len = wsi->tls.quic_tp_recv_len;

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
	struct lws_tls_schannel_conn *conn = (struct lws_tls_schannel_conn *)wsi->tls.ssl;
	SecBufferDesc in_desc, out_desc;
	SecBuffer in_bufs[2], out_bufs[1];
	DWORD flags = 0, req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
				      ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
				      ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
	SECURITY_STATUS status;

	if (!conn)
		return -1;

	/* In Schannel, QUIC handshake uses InitializeSecurityContext/AcceptSecurityContext */
	if (in && in_len) {
		in_bufs[0].BufferType = SECBUFFER_TOKEN;
		in_bufs[0].cbBuffer = (unsigned long)in_len;
		in_bufs[0].pvBuffer = (void *)in;

		in_bufs[1].BufferType = SECBUFFER_EMPTY;
		in_bufs[1].cbBuffer = 0;
		in_bufs[1].pvBuffer = NULL;

		in_desc.ulVersion = SECBUFFER_VERSION;
		in_desc.cBuffers = 2;
		in_desc.pBuffers = in_bufs;
	}

	out_bufs[0].BufferType = SECBUFFER_TOKEN;
	out_bufs[0].cbBuffer = 0;
	out_bufs[0].pvBuffer = NULL;

	out_desc.ulVersion = SECBUFFER_VERSION;
	out_desc.cBuffers = 1;
	out_desc.pBuffers = out_bufs;

	if (lwsi_role_client(wsi) || !wsi->a.vhost->listen_port) {
		status = InitializeSecurityContextA(
			&wsi->a.vhost->tls.ssl_client_ctx->cred,
			conn->f_context_init ? &conn->ctxt : NULL,
			conn->hostname,
			req_flags,
			0, 0,
			(in && in_len) ? &in_desc : NULL,
			0,
			conn->f_context_init ? NULL : &conn->ctxt,
			&out_desc,
			&flags,
			NULL);
		conn->f_context_init = 1;
	} else {
		struct lws_tls_schannel_ctx *ctx = wsi->tls.ctx_ref ?
			(struct lws_tls_schannel_ctx *)wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;
		status = AcceptSecurityContext(
			&ctx->cred,
			conn->f_context_init ? &conn->ctxt : NULL,
			(in && in_len) ? &in_desc : NULL,
			req_flags,
			0,
			conn->f_context_init ? NULL : &conn->ctxt,
			&out_desc,
			&flags,
			NULL);
		conn->f_context_init = 1;
	}

	if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
		if (out && out_len && *out_len >= out_bufs[0].cbBuffer) {
			memcpy(out, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
			*out_len = out_bufs[0].cbBuffer;
		}
		FreeContextBuffer(out_bufs[0].pvBuffer);
	} else {
		if (out_len)
			*out_len = 0;
	}

#if defined(SECPKG_ATTR_TLS_TRAFFIC_SECRETS)
	/*
	 * Extract secrets if available. SChannel populates traffic secrets
	 * dynamically during the handshake steps for QUIC TLS 1.3
	 */
	if (wsi->tls.quic_secret_cb && (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED)) {
		SEC_TRAFFIC_SECRETS secrets;
		if (QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_TLS_TRAFFIC_SECRETS, &secrets) == SEC_E_OK) {
			/* Map the TRAFFIC_SECRET_TYPE to lws_tls_quic_secret_type */
			/* Notice: This requires recent Windows SDKs where these types are defined. */
			wsi->tls.quic_secret_cb(wsi, (enum lws_tls_quic_secret_type)secrets.TrafficSecretType,
						secrets.TrafficSecret, secrets.TrafficSecretSize);
		}
	}
#endif

	if (status == SEC_I_CONTINUE_NEEDED)
		return 1;

	if (status == SEC_E_OK) {
		conn->f_handshake_finished = 1;
		return 0;
	}

	lwsl_err("%s: Schannel handshake error: 0x%lx\n", __func__, (unsigned long)status);
	return -1;
}

int
lws_tls_quic_api_test(void)
{
#if !defined(SECPKG_ATTR_TLS_TRAFFIC_SECRETS)
	lwsl_notice("%s: SDK too old for SChannel TLS 1.3 QUIC secrets\n", __func__);
	return 0;
#else
	PCCERT_CONTEXT pCertCtx = NULL;
	SCHANNEL_CRED srv_cred = { 0 }, cli_cred = { 0 };
	CredHandle hSrvCred, hCliCred;
	CtxtHandle hSrvCtxt, hCliCtxt;
	TimeStamp ts;
	SECURITY_STATUS st;
	BYTE subject_name[] = { 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74 };
	CERT_NAME_BLOB subject = { sizeof(subject_name), subject_name };
	int srv_init = 0, cli_init = 0, i;
	int secrets_found = 0;
	uint8_t c2s[4096];
	uint8_t s2c[4096];
	ULONG c2s_len = 0, s2c_len = 0;
	ULONG req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY;
	ULONG ret_flags;

	pCertCtx = CertCreateSelfSignCertificate(NULL, &subject, 0, NULL, NULL, NULL, NULL, NULL);
	if (!pCertCtx) {
		lwsl_err("%s: Failed to create self signed cert\n", __func__);
		return 1;
	}

	srv_cred.dwVersion = SCHANNEL_CRED_VERSION;
	srv_cred.cCreds = 1;
	srv_cred.paCred = &pCertCtx;
	srv_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
	st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &srv_cred, NULL, NULL, &hSrvCred, &ts);
	if (st != SEC_E_OK) { CertFreeCertificateContext(pCertCtx); return 1; }

	cli_cred.dwVersion = SCHANNEL_CRED_VERSION;
	cli_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
	st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cli_cred, NULL, NULL, &hCliCred, &ts);
	if (st != SEC_E_OK) { FreeCredentialsHandle(&hSrvCred); CertFreeCertificateContext(pCertCtx); return 1; }

	for (i = 0; i < 10; i++) {
		SecBufferDesc in_desc = { SECBUFFER_VERSION, 0, NULL }, out_desc = { SECBUFFER_VERSION, 0, NULL };
		SecBuffer in_bufs[2] = { 0 }, out_bufs[1] = { 0 };

		/* Client side */
		if (s2c_len > 0 || !cli_init) {
			if (s2c_len > 0) {
				in_bufs[0].BufferType = SECBUFFER_TOKEN;
				in_bufs[0].pvBuffer = s2c;
				in_bufs[0].cbBuffer = s2c_len;
				in_desc.cBuffers = 1;
				in_desc.pBuffers = in_bufs;
			}
			out_bufs[0].BufferType = SECBUFFER_TOKEN;
			out_desc.cBuffers = 1;
			out_desc.pBuffers = out_bufs;

			st = InitializeSecurityContextA(&hCliCred, cli_init ? &hCliCtxt : NULL, (SEC_CHAR *)"localhost", req_flags, 0, 0,
				s2c_len ? &in_desc : NULL, 0, cli_init ? NULL : &hCliCtxt, &out_desc, &ret_flags, NULL);

			cli_init = 1;
			s2c_len = 0;

			if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
				SEC_TRAFFIC_SECRETS secrets;
				if (QueryContextAttributes(&hCliCtxt, SECPKG_ATTR_TLS_TRAFFIC_SECRETS, &secrets) == SEC_E_OK) {
					secrets_found++;
				}
				if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
					memcpy(c2s, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
					c2s_len = out_bufs[0].cbBuffer;
					FreeContextBuffer(out_bufs[0].pvBuffer);
				}
			} else {
				break;
			}
		}

		/* Server side */
		if (c2s_len > 0) {
			in_bufs[0].BufferType = SECBUFFER_TOKEN;
			in_bufs[0].pvBuffer = c2s;
			in_bufs[0].cbBuffer = c2s_len;
			in_desc.cBuffers = 1;
			in_desc.pBuffers = in_bufs;

			out_bufs[0].BufferType = SECBUFFER_TOKEN;
			out_bufs[0].cbBuffer = 0;
			out_bufs[0].pvBuffer = NULL;
			out_desc.cBuffers = 1;
			out_desc.pBuffers = out_bufs;

			st = AcceptSecurityContext(&hSrvCred, srv_init ? &hSrvCtxt : NULL, &in_desc, req_flags, 0,
				srv_init ? NULL : &hSrvCtxt, &out_desc, &ret_flags, NULL);

			srv_init = 1;
			c2s_len = 0;

			if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
				SEC_TRAFFIC_SECRETS secrets;
				if (QueryContextAttributes(&hSrvCtxt, SECPKG_ATTR_TLS_TRAFFIC_SECRETS, &secrets) == SEC_E_OK) {
					secrets_found++;
				}
				if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
					memcpy(s2c, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
					s2c_len = out_bufs[0].cbBuffer;
					FreeContextBuffer(out_bufs[0].pvBuffer);
				}
			} else {
				break;
			}
		}

		if (st == SEC_E_OK && c2s_len == 0 && s2c_len == 0)
			break;
	}

	if (cli_init) DeleteSecurityContext(&hCliCtxt);
	if (srv_init) DeleteSecurityContext(&hSrvCtxt);
	FreeCredentialsHandle(&hCliCred);
	FreeCredentialsHandle(&hSrvCred);
	CertFreeCertificateContext(pCertCtx);

	lwsl_notice("%s: API test completed, secrets extracted: %d\n", __func__, secrets_found);
	return secrets_found > 0 ? 0 : 1;
#endif
}

#endif
