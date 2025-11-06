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
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	/*
	 * This is a placeholder implementation and has not been tested.
	 * It is based on the SChannel documentation and is intended to be a
	 * starting point for a functional implementation.
	 */
	struct lws_schannel_wsi *sc = (struct lws_schannel_wsi *)wsi->tls.ssl;
	SECURITY_STATUS status;
	SecBufferDesc buf_desc;
	SecBuffer bufs[4];
	size_t in_len;
	const uint8_t *in;
	int i;

	if (!sc)
		return LWS_SSL_CAPABLE_ERROR;

	// Consume data from the lws rx ringbuffer and append it to our input buffer
	while ((in = lws_buflist_next_segment_len(&wsi->buflist, &in_len))) {
		if (sc->in_buf_used + in_len > sc->in_buf_len) {
			lwsl_err("SChannel input buffer overflow\n");
			return LWS_SSL_CAPABLE_ERROR;
		}
		memcpy(sc->in_buf + sc->in_buf_used, in, in_len);
		sc->in_buf_used += in_len;
		lws_buflist_use_segment(&wsi->buflist, in_len);
	}

	buf_desc.ulVersion = SECBUFFER_VERSION;
	buf_desc.cBuffers = 4;
	buf_desc.pBuffers = bufs;

	bufs[0].pvBuffer = sc->in_buf;
	bufs[0].cbBuffer = sc->in_buf_used;
	bufs[0].BufferType = SECBUFFER_DATA;

	bufs[1].BufferType = SECBUFFER_EMPTY;
	bufs[2].BufferType = SECBUFFER_EMPTY;
	bufs[3].BufferType = SECBUFFER_EMPTY;

	status = DecryptMessage(&sc->hContext, &buf_desc, 0, NULL);

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	if (status != SEC_E_OK) {
		lwsl_err("DecryptMessage failed with error %d\n", status);
		return LWS_SSL_CAPABLE_ERROR;
	}

	// Find the decrypted data buffer
	for (i = 0; i < 4; i++) {
		if (bufs[i].BufferType == SECBUFFER_DATA) {
			if (bufs[i].cbBuffer > len) {
				lwsl_err("Decrypted data too large for buffer\n");
				return LWS_SSL_CAPABLE_ERROR;
			}
			memcpy(buf, bufs[i].pvBuffer, bufs[i].cbBuffer);
			return bufs[i].cbBuffer;
		}
	}

	return 0;
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	/*
	 * This is a placeholder implementation and has not been tested.
	 * It is based on the SChannel documentation and is intended to be a
	 * starting point for a functional implementation.
	 */

	struct lws_schannel_wsi *sc = (struct lws_schannel_wsi *)wsi->tls.ssl;
	SECURITY_STATUS status;
	SecBufferDesc buf_desc;
	SecBuffer bufs[4];
	unsigned char *out_ptr;

	if (!sc)
		return LWS_SSL_CAPABLE_ERROR;

	if (sc->out_buf_used + sc->sizes.cbHeader + len + sc->sizes.cbTrailer > sc->out_buf_len) {
		lwsl_err("SChannel output buffer overflow\n");
		return LWS_SSL_CAPABLE_ERROR;
	}

	out_ptr = sc->out_buf + sc->out_buf_used;

	// Copy the plaintext data to our output buffer
	memcpy(out_ptr + sc->sizes.cbHeader, buf, len);

	buf_desc.ulVersion = SECBUFFER_VERSION;
	buf_desc.cBuffers = 4;
	buf_desc.pBuffers = bufs;

	// Header
	bufs[0].pvBuffer = out_ptr;
	bufs[0].cbBuffer = sc->sizes.cbHeader;
	bufs[0].BufferType = SECBUFFER_STREAM_HEADER;

	// Data
	bufs[1].pvBuffer = out_ptr + sc->sizes.cbHeader;
	bufs[1].cbBuffer = len;
	bufs[1].BufferType = SECBUFFER_DATA;

	// Trailer
	bufs[2].pvBuffer = out_ptr + sc->sizes.cbHeader + len;
	bufs[2].cbBuffer = sc->sizes.cbTrailer;
	bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;

	bufs[3].BufferType = SECBUFFER_EMPTY;

	status = EncryptMessage(&sc->hContext, 0, &buf_desc, 0);

	if (status != SEC_E_OK) {
		lwsl_err("EncryptMessage failed with error %d\n", status);
		return LWS_SSL_CAPABLE_ERROR;
	}

	sc->out_buf_used += bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
	lws_callback_on_writable(wsi);

	return len;
}

int
lws_ssl_close(struct lws *wsi)
{
	/*
	 * This is a placeholder implementation and has not been tested.
	 * It is based on the SChannel documentation and is intended to be a
	 * starting point for a functional implementation.
	 */
	struct lws_schannel_wsi *sc = (struct lws_schannel_wsi *)wsi->tls.ssl;
	SECURITY_STATUS status;
	SecBufferDesc out_buf_desc;
	SecBuffer out_bufs[1];
	DWORD type = SCHANNEL_SHUTDOWN;

	if (!sc)
		return 0;

	out_buf_desc.ulVersion = SECBUFFER_VERSION;
	out_buf_desc.cBuffers = 1;
	out_buf_desc.pBuffers = out_bufs;

	out_bufs[0].pvBuffer = &type;
	out_bufs[0].cbBuffer = sizeof(type);
	out_bufs[0].BufferType = SECBUFFER_TOKEN;

	status = ApplyControlToken(&sc->hContext, &out_buf_desc);
	if (status != SEC_E_OK) {
		lwsl_err("ApplyControlToken failed with error %d\n", status);
	}

	DeleteSecurityContext(&sc->hContext);
	if (sc->in_buf)
		lws_free(sc->in_buf);
	if (sc->out_buf)
		lws_free(sc->out_buf);
	lws_free(sc);
	wsi->tls.ssl = NULL;

	return 0;
}

static int
tops_fake_POLLIN_for_buffered_schannel(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_schannel = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_schannel,
};
