/*
 * libwebsockets - libFuzzer target for ws server rx with permessage-deflate
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
 * Same as fuzz-ws, but the canned upgrade handshake negotiates
 * permessage-deflate, so the fuzz input (client frames) reaches the RSV1
 * inflate path in lib/roles/ws/ext/extension-permessage-deflate.c on its
 * way to the ws frame parser.  Compressed frames, fragmented compressed
 * messages, control frames interleaved with them, and zip-bomb-shaped
 * payloads all live here.
 */

#include "../peer.h"

static const uint8_t prelude[] =
	"GET / HTTP/1.1\x0d\x0a"
	"Host: fuzz\x0d\x0a"
	"Connection: Upgrade\x0d\x0a"
	"Upgrade: websocket\x0d\x0a"
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\x0d\x0a"
	"Sec-WebSocket-Version: 13\x0d\x0a"
	"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\x0d\x0a"
	"\x0d\x0a";

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (getenv("LWS_FUZZ_VERBOSE"))
		/* all lws logs, for triage */
		lws_set_log_level(0x7fff, NULL);
	else
		lws_set_log_level(0, NULL);

	if (fuzz_peer_init())
		return 1;

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_peer_session(prelude, sizeof(prelude) - 1, data, size);

	return 0;
}
