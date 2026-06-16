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
 *
 * OpenHiTLS generic DTLS operations
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"
#include "private.h"

#include <bsl_errno.h>
#include <bsl_err.h>
#include <hitls_error.h>

#define LWS_OPENHITLS_GENDTLS_QUEUE_LIMIT	(64 * 1024)
#define LWS_OPENHITLS_GENDTLS_MTU_DEFAULT	1400
#define LWS_OPENHITLS_GENDTLS_TIMEOUT_DEFAULT	1000

struct lws_openhitls_gendtls_uio_wrap {
	struct lws_gendtls_ctx *gctx;
	struct sockaddr_storage peer_addr;
	uint32_t peer_addr_len;
	int is_connected;
	int is_accept;
	int is_connect_mode;
};

static int32_t
lws_openhitls_gendtls_uio_create(BSL_UIO *uio)
{
	struct lws_openhitls_gendtls_uio_wrap *wrap =
			lws_zalloc(sizeof(*wrap), "openhitls-gendtls-uio");

	if (!wrap)
		return BSL_UIO_MEM_ALLOC_FAIL;

	BSL_UIO_SetCtx(uio, wrap);
	BSL_UIO_SetInit(uio, true);

	return BSL_SUCCESS;
}

static int32_t
lws_openhitls_gendtls_uio_destroy(BSL_UIO *uio)
{
	struct lws_openhitls_gendtls_uio_wrap *wrap =
			(struct lws_openhitls_gendtls_uio_wrap *)BSL_UIO_GetCtx(uio);

	lws_free_set_NULL(wrap);
	BSL_UIO_SetCtx(uio, NULL);

	return BSL_SUCCESS;
}

static int32_t
lws_openhitls_gendtls_uio_write(BSL_UIO *uio, const void *buf, uint32_t len,
				uint32_t *write_len)
{
	struct lws_openhitls_gendtls_uio_wrap *wrap =
			(struct lws_openhitls_gendtls_uio_wrap *)BSL_UIO_GetCtx(uio);
	struct lws_gendtls_ctx *ctx = wrap ? wrap->gctx : NULL;

	if (!ctx || !buf || !write_len)
		return BSL_INVALID_ARG;

	if (lws_buflist_total_len(&ctx->tx_head) + len >
	    LWS_OPENHITLS_GENDTLS_QUEUE_LIMIT)
		return BSL_UIO_IO_EXCEPTION;

	if (lws_buflist_append_segment(&ctx->tx_head, (const uint8_t *)buf,
				       len) < 0)
		return BSL_UIO_IO_EXCEPTION;

	*write_len = len;

	return BSL_SUCCESS;
}

static int32_t
lws_openhitls_gendtls_uio_read(BSL_UIO *uio, void *buf, uint32_t len,
			       uint32_t *read_len)
{
	struct lws_openhitls_gendtls_uio_wrap *wrap =
			(struct lws_openhitls_gendtls_uio_wrap *)BSL_UIO_GetCtx(uio);
	struct lws_gendtls_ctx *ctx = wrap ? wrap->gctx : NULL;
	const uint8_t *p;
	size_t avail;

	if (!ctx || !buf || !read_len)
		return BSL_INVALID_ARG;

	if (!ctx->rx_head) {
		*read_len = 0;
		return BSL_SUCCESS;
	}

	avail = lws_buflist_next_segment_len(&ctx->rx_head, (uint8_t **)&p);
	if (!avail) {
		*read_len = 0;
		return BSL_SUCCESS;
	}

	if (avail > len)
		avail = len;

	memcpy(buf, p, avail);
	lws_buflist_use_segment(&ctx->rx_head, avail);
	*read_len = (uint32_t)avail;

	return BSL_SUCCESS;
}

static int32_t
lws_openhitls_gendtls_uio_ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg,
			       void *parg)
{
	struct lws_openhitls_gendtls_uio_wrap *wrap =
			(struct lws_openhitls_gendtls_uio_wrap *)BSL_UIO_GetCtx(uio);
	struct lws_gendtls_ctx *ctx = wrap ? wrap->gctx : NULL;
	uint64_t *v64 = (uint64_t *)parg;

	if (!ctx || !wrap)
		return BSL_UIO_FAIL;

	switch (cmd) {
	case BSL_UIO_FLUSH:
		return BSL_SUCCESS;
	case BSL_UIO_SET_CONNECT_MODE:
		wrap->is_connect_mode = 1;
		return BSL_SUCCESS;
	case BSL_UIO_SET_ACCEPT:
		wrap->is_accept = 1;
		return BSL_SUCCESS;
	case BSL_UIO_UDP_SET_CONNECTED:
		wrap->is_connected = parg != NULL;
		if (parg != NULL && larg > 0 &&
		    (uint32_t)larg <= sizeof(wrap->peer_addr)) {
			memcpy(&wrap->peer_addr, parg, (size_t)larg);
			wrap->peer_addr_len = (uint32_t)larg;
		}
		return BSL_SUCCESS;
	case BSL_UIO_SET_PEER_IP_ADDR:
		if (!parg || larg <= 0 ||
		    (uint32_t)larg > sizeof(wrap->peer_addr))
			return BSL_INVALID_ARG;
		memcpy(&wrap->peer_addr, parg, (size_t)larg);
		wrap->peer_addr_len = (uint32_t)larg;
		return BSL_SUCCESS;
	case BSL_UIO_GET_PEER_IP_ADDR:
		if (!parg || larg < 0 ||
		    (uint32_t)larg < wrap->peer_addr_len)
			return BSL_INVALID_ARG;
		memcpy(parg, &wrap->peer_addr, wrap->peer_addr_len);
		return BSL_SUCCESS;
	case BSL_UIO_PENDING:
		if (larg != (int32_t)sizeof(*v64) || !v64)
			return BSL_INVALID_ARG;
		*v64 = (uint64_t)lws_buflist_total_len(&ctx->rx_head);
		return BSL_SUCCESS;
	case BSL_UIO_WPENDING:
		if (larg != (int32_t)sizeof(*v64) || !v64)
			return BSL_INVALID_ARG;
		*v64 = (uint64_t)lws_buflist_total_len(&ctx->tx_head);
		return BSL_SUCCESS;
	default:
		return BSL_UIO_FAIL;
	}
}

static BSL_UIO_Method *
lws_openhitls_gendtls_uio_method_create(void)
{
	BSL_UIO_Method *meth = BSL_UIO_NewMethod();

	if (!meth)
		return NULL;

	if (BSL_UIO_SetMethodType(meth, BSL_UIO_UDP) != BSL_SUCCESS ||
	    BSL_UIO_SetMethod(meth, BSL_UIO_CREATE_CB,
			      lws_openhitls_gendtls_uio_create) != BSL_SUCCESS ||
	    BSL_UIO_SetMethod(meth, BSL_UIO_DESTROY_CB,
			      lws_openhitls_gendtls_uio_destroy) != BSL_SUCCESS ||
	    BSL_UIO_SetMethod(meth, BSL_UIO_WRITE_CB,
			      lws_openhitls_gendtls_uio_write) != BSL_SUCCESS ||
	    BSL_UIO_SetMethod(meth, BSL_UIO_READ_CB,
			      lws_openhitls_gendtls_uio_read) != BSL_SUCCESS ||
	    BSL_UIO_SetMethod(meth, BSL_UIO_CTRL_CB,
			      lws_openhitls_gendtls_uio_ctrl) != BSL_SUCCESS) {
		BSL_UIO_FreeMethod(meth);
		return NULL;
	}

	return meth;
}

static int
lws_openhitls_gendtls_is_retryable(struct lws_gendtls_ctx *ctx, int ret)
{
	int n = HITLS_GetError(ctx->ctx, ret);

	return n == HITLS_WANT_READ || n == HITLS_WANT_WRITE ||
	       n == HITLS_WANT_CONNECT || n == HITLS_WANT_ACCEPT;
}

static int
lws_openhitls_gendtls_drive_handshake(struct lws_gendtls_ctx *ctx)
{
	uint8_t done = 0;
	int ret;

	if (!ctx->ctx)
		return -1;

	if (HITLS_IsHandShakeDone(ctx->ctx, &done) == HITLS_SUCCESS && done) {
		ctx->handshake_done = 1;
		return 0;
	}

	ret = ctx->mode == LWS_GENDTLS_MODE_CLIENT ?
	      HITLS_Connect(ctx->ctx) : HITLS_Accept(ctx->ctx);
	if (ret == HITLS_SUCCESS) {
		ctx->handshake_done = 1;
		return 0;
	}

	if (lws_openhitls_gendtls_is_retryable(ctx, ret))
		return 0;

	lwsl_err("%s: handshake failed: 0x%x\n", __func__, ret);
	
	const char *file = NULL, *desc = NULL;
	uint32_t line = 0;
	int32_t err = BSL_ERR_GetErrAll(&file, &line, &desc);

	if (err != BSL_SUCCESS)
		lwsl_err("%s: err stack: 0x%x %s (%s:%u)\n", __func__,
				(unsigned int)err, desc ? desc : "(no desc)",
				file ? file : "(no file)", (unsigned int)line);
	
	lws_tls_err_describe_clear();

	return -1;
}

int
lws_gendtls_create(struct lws_gendtls_ctx *ctx,
		   const struct lws_gendtls_creation_info *info)
{
	unsigned int mtu = info->mtu ? info->mtu :
				      LWS_OPENHITLS_GENDTLS_MTU_DEFAULT;
	int ret;

	memset(ctx, 0, sizeof(*ctx));

	ctx->context = info->context;
	ctx->mode = (int)info->mode;
	ctx->mtu = mtu;
	ctx->timeout_ms = info->timeout_ms ? info->timeout_ms :
					     LWS_OPENHITLS_GENDTLS_TIMEOUT_DEFAULT;

	/* OpenHiTLS supports plain DTLS here; DTLS-SRTP is an explicit gap. */
	if (info->use_srtp) {
		lwsl_err("%s: OpenHiTLS DTLS-SRTP is not supported\n",
			 __func__);
		return -1;
	}

	ctx->config = HITLS_CFG_NewDTLSConfig();
	if (!ctx->config) {
		lwsl_err("%s: HITLS_CFG_NewDTLSConfig failed\n", __func__);
		return -1;
	}

	(void)HITLS_CFG_SetVerifyNoneSupport(ctx->config, true);
	(void)HITLS_CFG_SetReadAhead(ctx->config, 1);
	(void)HITLS_CFG_SetDtlsCookieExchangeSupport(ctx->config, false);

	ctx->uio_method = lws_openhitls_gendtls_uio_method_create();
	if (!ctx->uio_method) {
		lwsl_err("%s: unable to create DTLS UIO method\n", __func__);
		goto bail;
	}

	ctx->uio = BSL_UIO_New(ctx->uio_method);
	if (!ctx->uio) {
		lwsl_err("%s: unable to create DTLS UIO\n", __func__);
		goto bail;
	}
	
	struct lws_openhitls_gendtls_uio_wrap *wrap =
		(struct lws_openhitls_gendtls_uio_wrap *)BSL_UIO_GetCtx(ctx->uio);
	struct sockaddr_in sin;

	if (!wrap) {
		lwsl_err("%s: DTLS UIO wrapper missing\n", __func__);
		goto bail;
	}

	wrap->gctx = ctx;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(9);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (info->mode == LWS_GENDTLS_MODE_CLIENT) {
		(void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SET_CONNECT_MODE, 0, NULL);
		(void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_UDP_SET_CONNECTED,
					(int32_t)sizeof(sin), &sin);
	} else {
		(void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SET_ACCEPT, 0, NULL);
		(void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SET_PEER_IP_ADDR,
					(int32_t)sizeof(sin), &sin);
	}
	ctx->ctx = HITLS_New(ctx->config);
	if (!ctx->ctx) {
		lwsl_err("%s: HITLS_New failed\n", __func__);
		goto bail;
	}

	if (HITLS_SetUio(ctx->ctx, ctx->uio) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetUio failed\n", __func__);
		goto bail;
	}

	if (HITLS_SetNoQueryMtu(ctx->ctx, true) != HITLS_SUCCESS ||
	    HITLS_SetLinkMtu(ctx->ctx, (uint16_t)mtu) != HITLS_SUCCESS ||
	    HITLS_SetMtu(ctx->ctx, (uint16_t)mtu) != HITLS_SUCCESS) {
		lwsl_err("%s: unable to configure DTLS MTU %u\n", __func__, mtu);
		goto bail;
	}

	ret = HITLS_SetEndPoint(ctx->ctx,
				info->mode == LWS_GENDTLS_MODE_CLIENT);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_SetEndPoint failed: 0x%x\n", __func__, ret);
		goto bail;
	}

	return 0;

bail:
	lws_gendtls_destroy(ctx);
	return -1;
}

void
lws_gendtls_destroy(struct lws_gendtls_ctx *ctx)
{
	if (ctx->ctx) {
		HITLS_Free(ctx->ctx);
		ctx->ctx = NULL;
	}

	if (ctx->uio) {
		BSL_UIO_Free(ctx->uio);
		ctx->uio = NULL;
	}

	if (ctx->uio_method) {
		BSL_UIO_FreeMethod(ctx->uio_method);
		ctx->uio_method = NULL;
	}

	if (ctx->config) {
		HITLS_CFG_FreeConfig(ctx->config);
		ctx->config = NULL;
	}

	lws_buflist_destroy_all_segments(&ctx->rx_head);
	lws_buflist_destroy_all_segments(&ctx->tx_head);
	ctx->handshake_done = 0;
}

int
lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert,
			 size_t len)
{
	int ret;

	if (!ctx->ctx || !cert || !len)
		return -1;

	ret = HITLS_LoadCertBuffer(ctx->ctx, cert, (uint32_t)len,
				   TLS_PARSE_FORMAT_PEM);
	if (ret != HITLS_SUCCESS)
		ret = HITLS_LoadCertBuffer(ctx->ctx, cert, (uint32_t)len,
					   TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_LoadCertBuffer failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	return 0;
}

int
lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key,
			size_t len)
{
	int ret;

	if (!ctx->ctx || !key || !len)
		return -1;

	ret = HITLS_LoadKeyBuffer(ctx->ctx, key, (uint32_t)len,
				  TLS_PARSE_FORMAT_PEM);
	if (ret != HITLS_SUCCESS)
		ret = HITLS_LoadKeyBuffer(ctx->ctx, key, (uint32_t)len,
					  TLS_PARSE_FORMAT_ASN1);
	if (ret != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_LoadKeyBuffer failed: 0x%x\n",
			 __func__, ret);
		return -1;
	}

	if (HITLS_CheckPrivateKey(ctx->ctx) != HITLS_SUCCESS) {
		lwsl_err("%s: HITLS_CheckPrivateKey failed\n", __func__);
		return -1;
	}

	return 0;
}

int
lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	if (!ctx || !in || !len)
		return -1;

	if (lws_buflist_total_len(&ctx->rx_head) + len >
	    LWS_OPENHITLS_GENDTLS_QUEUE_LIMIT) {
		lwsl_err("%s: rx queue limit exceeded\n", __func__);
		return -1;
	}

	if (lws_buflist_append_segment(&ctx->rx_head, in, len) < 0)
		return -1;

	return 0;
}

int
lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	uint32_t read_len = 0;
	int ret;

	if (!ctx || !ctx->ctx || !out || !max_len)
		return -1;

	if (!ctx->handshake_done) {
		if (!ctx->rx_head)
			return 0;
		if (lws_openhitls_gendtls_drive_handshake(ctx))
			return -1;
		if (!ctx->handshake_done)
			return 0;
	}

	if (max_len > UINT32_MAX)
		max_len = UINT32_MAX;

	ret = HITLS_Read(ctx->ctx, out, (uint32_t)max_len, &read_len);
	if (ret == HITLS_SUCCESS)
		return (int)read_len;

	if (lws_openhitls_gendtls_is_retryable(ctx, ret))
		return 0;

	lwsl_err("%s: HITLS_Read failed: 0x%x\n", __func__, ret);
	lws_tls_err_describe_clear();

	return -1;
}

int
lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len)
{
	uint32_t written = 0;
	int ret;

	if (!ctx || !ctx->ctx || !in || !len)
		return -1;

	if (!ctx->handshake_done) {
		if (lws_openhitls_gendtls_drive_handshake(ctx))
			return -1;
		if (!ctx->handshake_done)
			return 0;
	}

	while (len) {
		size_t chunk = len > UINT32_MAX ? UINT32_MAX : len;

		ret = HITLS_Write(ctx->ctx, in, (uint32_t)chunk, &written);
		if (ret != HITLS_SUCCESS) {
			if (lws_openhitls_gendtls_is_retryable(ctx, ret))
				return 0;
			lwsl_err("%s: HITLS_Write failed: 0x%x\n",
				 __func__, ret);
			lws_tls_err_describe_clear();
			return -1;
		}

		in += written;
		len -= written;
	}

	return 0;
}

int
lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len)
{
	const uint8_t *p;
	size_t avail;

	if (!ctx || !out || !max_len)
		return -1;

	if (!ctx->tx_head && !ctx->handshake_done &&
	    lws_openhitls_gendtls_drive_handshake(ctx))
		return -1;

	if (!ctx->tx_head)
		return 0;

	avail = lws_buflist_next_segment_len(&ctx->tx_head, (uint8_t **)&p);
	if (avail > max_len) {
		lwsl_err("%s: record %zu exceeds buffer %zu\n", __func__,
			 avail, max_len);
		return -1;
	}

	memcpy(out, p, avail);
	lws_buflist_use_segment(&ctx->tx_head, avail);

	return (int)avail;
}

int
lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx,
				   const char *label, size_t label_len,
				   const uint8_t *context, size_t context_len,
				   uint8_t *out, size_t out_len)
{
	int use_context = context && context_len;

	if (!ctx || !ctx->ctx || !label || !out || !out_len ||
	    !ctx->handshake_done)
		return -1;

	if (HITLS_ExportKeyingMaterial(ctx->ctx, out, out_len, label, label_len,
				       context, context_len, use_context) !=
	    HITLS_SUCCESS)
		return -1;

	return 0;
}

int
lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx)
{
	uint8_t done = 0;

	if (!ctx || !ctx->ctx)
		return 0;

	if (ctx->handshake_done)
		return 1;

	if (HITLS_IsHandShakeDone(ctx->ctx, &done) == HITLS_SUCCESS && done) {
		ctx->handshake_done = 1;
		return 1;
	}

	return 0;
}

int
lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx)
{
	bool pending = false;

	if (!ctx || !ctx->ctx)
		return 1;

	(void)HITLS_ReadHasPending(ctx->ctx, &pending);

	return !(ctx->rx_head || ctx->tx_head || pending ||
		 HITLS_GetReadPendingBytes(ctx->ctx));
}

const char *
lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx)
{
	(void)ctx;

	return NULL;
}
