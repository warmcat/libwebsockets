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
#include "private-lib-tls-bearssl.h"

int lws_gendtls_create(struct lws_gendtls_ctx *ctx, const struct lws_gendtls_creation_info *info) { return -1; }
void lws_gendtls_destroy(struct lws_gendtls_ctx *ctx) {}
int lws_gendtls_set_cert_mem(struct lws_gendtls_ctx *ctx, const uint8_t *cert, size_t len) { return -1; }
int lws_gendtls_set_key_mem(struct lws_gendtls_ctx *ctx, const uint8_t *key, size_t len) { return -1; }
int lws_gendtls_put_rx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len) { return -1; }
int lws_gendtls_get_rx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len) { return -1; }
int lws_gendtls_put_tx(struct lws_gendtls_ctx *ctx, const uint8_t *in, size_t len) { return -1; }
int lws_gendtls_get_tx(struct lws_gendtls_ctx *ctx, uint8_t *out, size_t max_len) { return -1; }
int lws_gendtls_export_keying_material(struct lws_gendtls_ctx *ctx, const char *label, size_t label_len, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len) { return -1; }
int lws_gendtls_handshake_done(struct lws_gendtls_ctx *ctx) { return 0; }
int lws_gendtls_is_clean(struct lws_gendtls_ctx *ctx) { return 1; }
const char *lws_gendtls_get_srtp_profile(struct lws_gendtls_ctx *ctx) { return NULL; }
