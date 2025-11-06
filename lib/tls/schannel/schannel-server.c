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
#include "private-lib-tls-schannel.h"

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost, struct lws *wsi)
{
	/*
	 * This is a placeholder implementation and has not been tested.
	 * It is based on the SChannel documentation and is intended to be a
	 * starting point for a functional implementation.
	 */

	SCHANNEL_CRED cred;
	CERT_CONTEXT *pCertContext = NULL;
	HCERTSTORE hCertStore;
	SECURITY_STATUS status;

	// Open the "MY" certificate store, which is the personal certificate store.
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
		CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
	if (!hCertStore) {
		lwsl_err("Failed to open certificate store\n");
		return -1;
	}

	// Find the certificate by its subject name (CN).
	pCertContext = CertFindCertificateInStore(hCertStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
		CERT_FIND_SUBJECT_STR, vhost->name, NULL);
	if (!pCertContext) {
		lwsl_err("Failed to find certificate for %s\n", vhost->name);
		CertCloseStore(hCertStore, 0);
		return -1;
	}

	// Prepare the SCHANNEL_CRED structure.
	memset(&cred, 0, sizeof(cred));
	cred.dwVersion = SCHANNEL_CRED_VERSION;
	cred.cCreds = 1;
	cred.paCred = &pCertContext;
	cred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
	cred.dwFlags = SCH_USE_STRONG_CRYPTO;

	// Get a handle to the SSPI credential.
	status = AcquireCredentialsHandle(NULL, UNISP_NAME,
		SECPKG_CRED_INBOUND, NULL, &cred, NULL, NULL,
		&vhost->tls.ssl_ctx, &vhost->tls.ssl_ctx_expiry);
	if (status != SEC_E_OK) {
		lwsl_err("AcquireCredentialsHandle failed with error %d\n", status);
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hCertStore, 0);
		return -1;
	}

	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	/*
	 * This is a placeholder implementation and has not been tested.
	 * It is based on the SChannel documentation and is intended to be a
	 * starting point for a functional implementation.
	 */

	struct lws_schannel_wsi *sc = (struct lws_schannel_wsi *)wsi->tls.ssl;
	SECURITY_STATUS status;
	SecBufferDesc in_buf_desc;
	SecBuffer in_bufs[2];
	SecBufferDesc out_buf_desc;
	SecBuffer out_bufs[1];
	DWORD flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
		ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
		ASC_REQ_STREAM;
	int ret = 0;
	size_t len;
	const uint8_t *in;

	if (!sc) {
		sc = lws_zalloc(sizeof(*sc), "schannel wsi");
		if (!sc)
			return LWS_SSL_CAPABLE_ERROR;
		wsi->tls.ssl = (lws_tls_conn *)sc;

		sc->in_buf_len = 8192;
		sc->in_buf = lws_malloc(sc->in_buf_len, "schannel in_buf");
		if (!sc->in_buf)
			goto fail;

		sc->out_buf_len = 8192;
		sc->out_buf = lws_malloc(sc->out_buf_len, "schannel out_buf");
		if (!sc->out_buf)
			goto fail;
	}

	// Consume data from the lws rx ringbuffer and append it to our input buffer
	while ((in = lws_buflist_next_segment_len(&wsi->buflist, &len))) {
		if (sc->in_buf_used + len > sc->in_buf_len) {
			lwsl_err("SChannel input buffer overflow\n");
			return LWS_SSL_CAPABLE_ERROR;
		}
		memcpy(sc->in_buf + sc->in_buf_used, in, len);
		sc->in_buf_used += len;
		lws_buflist_use_segment(&wsi->buflist, len);
	}

	// Set up the input buffers. Buffer 0 is for inbound data.
	in_buf_desc.ulVersion = SECBUFFER_VERSION;
	in_buf_desc.cBuffers = 2;
	in_buf_desc.pBuffers = in_bufs;

	in_bufs[0].pvBuffer = sc->in_buf;
	in_bufs[0].cbBuffer = sc->in_buf_used;
	in_bufs[0].BufferType = SECBUFFER_TOKEN;

	// Buffer 1 is for "extra" data that SChannel might not have consumed.
	in_bufs[1].pvBuffer = NULL;
	in_bufs[1].cbBuffer = 0;
	in_bufs[1].BufferType = SECBUFFER_EMPTY;

	// Set up the output buffer.
	out_buf_desc.ulVersion = SECBUFFER_VERSION;
	out_buf_desc.cBuffers = 1;
	out_buf_desc.pBuffers = out_bufs;

	out_bufs[0].pvBuffer = sc->out_buf + sc->out_buf_used;
	out_bufs[0].cbBuffer = sc->out_buf_len - sc->out_buf_used;
	out_bufs[0].BufferType = SECBUFFER_TOKEN;

	status = AcceptSecurityContext(
		&wsi->a.vhost->tls.ssl_ctx, // Credential handle
		sc->hContext.dwLower || sc->hContext.dwUpper ? &sc->hContext : NULL, // Existing context handle
		&in_buf_desc,        // Input buffer
		flags,               // Context requirements
		0,                   // Target data representation
		&sc->hContext,       // New context handle
		&out_buf_desc,       // Output buffer
		&flags,              // Context attributes
		NULL                 // Expiration time
	);

	// Handle the output token, if any.
	if (out_bufs[0].cbBuffer > 0) {
		sc->out_buf_used += out_bufs[0].cbBuffer;
		lws_callback_on_writable(wsi); // Ask lws to call our write handler
	}

	// Handle leftover input data
	if (in_bufs[1].BufferType == SECBUFFER_EXTRA) {
		memmove(sc->in_buf, sc->in_buf + (sc->in_buf_used - in_bufs[1].cbBuffer), in_bufs[1].cbBuffer);
		sc->in_buf_used = in_bufs[1].cbBuffer;
	} else {
		sc->in_buf_used = 0;
	}

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (status == SEC_I_CONTINUE_NEEDED) {
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (status != SEC_E_OK) {
		lwsl_err("AcceptSecurityContext failed with error %d\n", status);
		return LWS_SSL_CAPABLE_ERROR;
	}

	// Handshake is complete. Query the stream sizes.
	status = QueryContextAttributes(&sc->hContext, SECPKG_ATTR_STREAM_SIZES, &sc->sizes);
	if (status != SEC_E_OK) {
		lwsl_err("QueryContextAttributes for stream sizes failed with error %d\n", status);
		return LWS_SSL_CAPABLE_ERROR;
	}

	return LWS_SSL_CAPABLE_DONE;

fail:
	if (sc) {
		if (sc->in_buf)
			lws_free(sc->in_buf);
		if (sc->out_buf)
			lws_free(sc->out_buf);
		lws_free(sc);
	}
	wsi->tls.ssl = NULL;

	return LWS_SSL_CAPABLE_ERROR;
}
