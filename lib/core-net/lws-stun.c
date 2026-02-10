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

#include "private-lib-core.h"

int
lws_stun_validate_and_reply(struct lws *wsi, uint8_t *in, size_t in_len,
			    uint8_t *out, size_t out_len,
			    const char *password, const struct sockaddr_in *peer_sin)
{
	uint32_t magic = LWS_STUN_MAGIC_COOKIE;
	uint16_t type, attr_type, attr_len;
	uint8_t *p = (uint8_t *)in, *op = out;
	uint8_t mi[20], *mi_ptr = NULL;
	uint32_t fp;
	struct lws_genhmac_ctx hmac_ctx;
	size_t i, mi_offset = 0;

	/*
	 * 1. Validate incoming STUN Request
	 */

	if (in_len < 20)
		return 0;

	type = (uint16_t)((p[0] << 8) | p[1]);
	if (type != 0x0001) /* Binding Request */
		return 0;

	if (0x21 != p[4] || 0x12 != p[5] || 0xA4 != p[6] || 0x42 != p[7])
		return 0; /* bad magic */

	/* Parse attributes to find MI and Fingerprint */
	i = 20;
	while (i + 4 <= in_len) {
		attr_type = (uint16_t)((in[i] << 8) | in[i + 1]);
		attr_len = (uint16_t)((in[i + 2] << 8) | in[i + 3]);

		if (attr_type == 0x0008) { /* MESSAGE-INTEGRITY */
			mi_ptr = &in[i + 4];
			mi_offset = i;
		}

		i += 4 + attr_len;
		i = (i + 3) & ~3U; /* Align to 4 bytes */
	}

	/* Verify the REQUEST's Message Integrity if password provided */
	if (password && mi_ptr) {
		uint8_t req_mi[20];
		uint8_t saved_l1 = in[2], saved_l2 = in[3];
		uint16_t adj_len = (uint16_t)(mi_offset + 24 - 20);

		in[2] = (uint8_t)(adj_len >> 8);
		in[3] = (uint8_t)(adj_len & 0xff);

		/*
		 * Note: password length is passed blindly.
		 * Ideally we should take password_len as arg.
		 * Assuming NULL terminated string for now.
		 */
		if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, (uint8_t *)password, strlen(password)) ||
		    lws_genhmac_update(&hmac_ctx, in, mi_offset) ||
		    lws_genhmac_destroy(&hmac_ctx, req_mi)) {
			lwsl_err("Failed to compute request HMAC\n");
			/* We proceed, but maybe we should fail? */
		} else {
			if (memcmp(req_mi, mi_ptr, 20)) {
				lwsl_err("STUN Request MESSAGE-INTEGRITY MISMATCH!\n");
				/* RFC: If MI fails, discard silently */
				return 0;
			}
		}
		in[2] = saved_l1; in[3] = saved_l2;
	}


	/*
	 * 2. Generate Binding Success Response
	 */

	if (out_len < 256) /* Rough check */
		return 0;

	*op++ = 0x01; *op++ = 0x01; /* Binding Success Response */
	*op++ = 0x00; *op++ = 0x00; /* Placeholder for length */
	memcpy(op, in + 4, 16);    /* Copy magic and transaction ID from request */
	op += 16;

	/* 1. XOR-MAPPED-ADDRESS (Type 0x0020, Length 8) */
	if (peer_sin) {
		uint16_t port = ntohs(peer_sin->sin_port);
		uint32_t addr = ntohl(peer_sin->sin_addr.s_addr);

		*op++ = 0x00; *op++ = 0x20;
		*op++ = 0x00; *op++ = 0x08;
		*op++ = 0x00; /* Reserved */
		*op++ = 0x01; /* Family IPv4 */

		uint16_t xport = (uint16_t)(port ^ (uint16_t)(magic >> 16));
		*op++ = (uint8_t)(xport >> 8);
		*op++ = (uint8_t)(xport & 0xff);

		uint32_t xaddr = addr ^ magic;
		*op++ = (uint8_t)(xaddr >> 24);
		*op++ = (uint8_t)(xaddr >> 16);
		*op++ = (uint8_t)(xaddr >> 8);
		*op++ = (uint8_t)(xaddr & 0xff);
	}

	/* 2. ICE-CONTROLLED (Type 0x8029, Length 8) */
	*op++ = 0x80; *op++ = 0x29;
	*op++ = 0x00; *op++ = 0x08;
	lws_get_random(lws_get_context(wsi), op, 8);
	op += 8;

	/*
	 * MESSAGE-INTEGRITY (Type 0x0008, Length 20)
	 * RFC 5389 15.4: Length field MUST include the MI attribute itself (24 bytes).
	 */
	if (password) {
		size_t mi_offset = (size_t)(op - out);
		out[2] = 0;
		out[3] = (uint8_t)(mi_offset + 24 - 20); /* Length up to start of MI attr */

		if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, (uint8_t *)password, strlen(password)) ||
		    lws_genhmac_update(&hmac_ctx, out, mi_offset) ||
		    lws_genhmac_destroy(&hmac_ctx, mi)) {
			lwsl_err("Failed to compute response HMAC\n");
			return 0;
		}

		/* Write MI Attribute */
		*op++ = 0x00; *op++ = 0x08;
		*op++ = 0x00; *op++ = 20;
		memcpy(op, mi, 20);
		op += 20;
	}

	/*
	 * FINGERPRINT (Type 0x8028, Length 4)
	 * Attributes: XOR(12) + ICE(12) + MI(24) + FP(8) = 56 bytes.
	 */
	out[2] = 0;
	out[3] = (uint8_t)(op - out + 8 - 20);

	fp = lws_crc32(0, out, (size_t)(op - out));
	fp ^= LWS_STUN_FINGERPRINT_XOR;
	*op++ = 0x80; *op++ = 0x28;
	*op++ = 0x00; *op++ = 0x04;
	*op++ = (uint8_t)(fp >> 24);
	*op++ = (uint8_t)(fp >> 16);
	*op++ = (uint8_t)(fp >> 8);
	*op++ = (uint8_t)(fp & 0xff);

	lwsl_info("Sending STUN Binding Success Response (%d bytes)\n", (int)(op - out));
	lwsl_hexdump_info(out, (size_t)(op - out));

	return (int)(op - out);
}

int
lws_stun_req_pack(struct lws *wsi, enum lws_stun_req_type type,
		 struct sockaddr_in *sa4, uint8_t *buf, size_t len,
		 void *cookie)
{
	/* Placeholder for client request generation */
	/*
	 * Need to implement proper Binding Request generation with
	 * Transaction ID, UFRAG, PWD (if needed), FINGERPRINT.
	 */
	return 0;
}
