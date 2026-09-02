/*
 * lws-api-test-xip
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the xip clipboard plugin's sender-side clip chunker against
 * its receiver-side streaming parser and reassembler: chunked frames must
 * parse back to the original payload, mime and hash, including mimes that
 * need JSON escaping, empty clips, exact chunk-multiple payloads, and caps
 * too small to hold a frame.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

#include "chunk.h"
#include "hash.h"
#include "proto.h"

static char frame[XIP_FRAME_MAX];
static uint8_t payload[XIP_CHUNK_RAW * 2 + 12345];

/* chunk a payload, then parse and reassemble the frames it produced */
static int
roundtrip(const char *name, const uint8_t *data, size_t len,
	  const char *mime, unsigned seq)
{
	struct xip_chunker ch;
	struct xip_parser p;
	struct xip_reasm r;
	char hash[XIP_HASH_HEX];
	size_t fl, expect_chunks;
	int chunks = 0, done = 0, m, ret = 0;

	xip_hash_hex(data, len, hash);

	if (xip_chunker_init(&ch, data, len, mime, seq)) {
		lwsl_err("%s: %s: chunker init failed\n", __func__, name);
		return 1;
	}

	xip_parser_init(&p);
	memset(&r, 0, sizeof(r));

	while (xip_chunker_next(&ch, frame, sizeof(frame), &fl) == 1) {
		chunks++;

		m = xip_parser_feed(&p, frame, fl);
		if (m != 1 || p.msg.type != XIP_MSG_CLIP) {
			lwsl_err("%s: %s: chunk %d did not parse (r %d)\n",
				 __func__, name, chunks, m);
			ret = 1;
			goto bail;
		}

		m = xip_reasm_add(&r, &p.msg, XIP_MAX_BYTES_DEFAULT);
		xip_parser_reset(&p);
		if (m < 0) {
			lwsl_err("%s: %s: chunk %d rejected by reasm\n",
				 __func__, name, chunks);
			ret = 1;
			goto bail;
		}
		if (m == 1)
			done = 1;
	}

	expect_chunks = (len + XIP_CHUNK_RAW - 1) / XIP_CHUNK_RAW;
	if (!expect_chunks)
		expect_chunks = 1;		/* empty clip = one empty chunk */

	if (chunks != (int)expect_chunks || !done) {
		lwsl_err("%s: %s: %d chunks (expected %d), done %d\n",
			 __func__, name, chunks, (int)expect_chunks, done);
		ret = 1;
	}

	if (r.len != len || (len && memcmp(r.data, data, len)) ||
	    strcmp(r.mime, mime) || strcmp(r.hash, hash)) {
		lwsl_err("%s: %s: reassembled clip mismatch (len %zu/%zu)\n",
			 __func__, name, r.len, len);
		ret = 1;
	}

bail:
	xip_parser_reset(&p);
	xip_reasm_destroy(&r);

	return ret;
}

static int
test_small_caps(void)
{
	struct xip_chunker ch;
	char tiny[32], mid[512];
	size_t fl;
	int m;

	if (xip_chunker_init(&ch, payload, XIP_CHUNK_RAW,
			     XIP_MIME_TEXT_UTF8, 1)) {
		lwsl_err("%s: chunker init failed\n", __func__);
		return 1;
	}

	/* the envelope alone cannot fit */
	m = xip_chunker_next(&ch, tiny, sizeof(tiny), &fl);
	if (m != -1) {
		lwsl_err("%s: tiny cap accepted (r %d)\n", __func__, m);
		return 1;
	}

	/* the envelope fits, but the base64 expansion cannot */
	m = xip_chunker_next(&ch, mid, sizeof(mid), &fl);
	if (m != -1) {
		lwsl_err("%s: mid cap accepted (r %d)\n", __func__, m);
		return 1;
	}

	return 0;
}

static int
test_build_clip(void)
{
	struct xip_parser p;
	int n, m, ret = 0;

	n = xip_build_clip(frame, sizeof(frame), XIP_MIME_TEXT_UTF8,
			   "0123456789abcdef", 7, 0, 1, "QUJD", 4);
	if (n < 0) {
		lwsl_err("%s: build failed\n", __func__);
		return 1;
	}

	xip_parser_init(&p);
	m = xip_parser_feed(&p, frame, (size_t)n);
	if (m != 1 || p.msg.type != XIP_MSG_CLIP || !p.msg.have_hash ||
	    p.msg.seq != 7 || p.msg.i != 0 || p.msg.n != 1 ||
	    p.msg.data_len != 3 || !p.msg.data ||
	    memcmp(p.msg.data, "ABC", 3) ||
	    strcmp(p.msg.mime, XIP_MIME_TEXT_UTF8) ||
	    strcmp(p.msg.hash, "0123456789abcdef")) {
		lwsl_err("%s: parsed clip mismatch\n", __func__);
		ret = 1;
	}
	xip_parser_reset(&p);

	return ret;
}

int main(int argc, const char **argv)
{
	int n, fails = 0;

	(void)argc;
	(void)argv;

	lwsl_user("LWS API selftest: xip clip chunking\n");

	for (n = 0; n < (int)sizeof(payload); n++)
		payload[n] = (uint8_t)(n * 7 + (n >> 6));

	fails += roundtrip("multi-chunk", payload, sizeof(payload),
			   XIP_MIME_TEXT_UTF8, 1);
	fails += roundtrip("exact multiple", payload, XIP_CHUNK_RAW * 2,
			   XIP_MIME_TEXT_UTF8, 2);
	fails += roundtrip("single chunk", payload, 100,
			   XIP_MIME_TEXT_UTF8, 3);
	fails += roundtrip("empty clip", payload, 0, XIP_MIME_TEXT_UTF8, 4);
	fails += roundtrip("escaped mime", payload, 5000,
			   "weird/mime\"\\ \x01", 0xFFFFFFFFu);
	fails += test_build_clip();
	fails += test_small_caps();

	if (fails)
		lwsl_user("LWS API selftest: xip clip chunking: FAIL: %d\n",
			  fails);
	else
		lwsl_user("LWS API selftest: xip clip chunking: PASS\n");

	return fails ? 1 : 0;
}
