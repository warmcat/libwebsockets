/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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

#ifndef _LWS_STUN_H_
#define _LWS_STUN_H_

#define LWS_STUN_MAGIC_COOKIE		0x2112A442
#define LWS_STUN_FINGERPRINT_XOR	0x5354554e

enum lws_stun_req_type {
	LWS_STUNREQ_BINDING = 1,
};

enum lws_stun_attr_type {
	LWS_STUN_ATTR_USERNAME = 0x0006,
};

/*
 * This is the public API for the STUN packet processing
 */

LWS_VISIBLE LWS_EXTERN int
lws_stun_req_pack(struct lws *wsi, enum lws_stun_req_type type,
		  struct sockaddr_in *sa4, uint8_t *buf, size_t len,
		  void *cookie);

/*
 * Validates incoming STUN packet against password (HMAC) and generates reply.
 * Returns length of reply in 'out', or 0 if validation fails or nothing to send.
 */
LWS_VISIBLE LWS_EXTERN int
lws_stun_validate_and_reply(struct lws *wsi, uint8_t *in, size_t in_len,
			    uint8_t *out, size_t out_len,
			    const char *password, const struct sockaddr_in *peer_sin);

#endif
