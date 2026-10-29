/*
 * lws fuzz target: a ws client connection, with the fuzzer as the server,
 * the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The 101 has to carry the accept value of the key the client chose, which
 * the fuzzer can't compute, so the harness answers the upgrade itself, and
 * the input says how:
 *
 *   input[0]:	the client application's config (../sansio-cli-app.h)
 *   input[1]:	bit 0 the 101 takes permessage-deflate, and bits 1 - 3 which
 *		of its parameters; bit 4 it names the subprotocol, bit 5 a
 *		wrong one; bit 6 the accept value is spoiled
 *   input[2]:	how many bytes of the input follow as more headers of the
 *		101, then those bytes
 *
 * then the server's program (../sansio-peer.h): its frames to the client,
 * with what it sends after the 101 in the same read if it begins at once.
 */

#define FZP_CLIENT
#include "../sansio-peer.h"
#include "../sansio-cli-app.h"

static const uint8_t *
find(const uint8_t *hay, size_t hlen, const char *needle)
{
	size_t n = strlen(needle), i;

	for (i = 0; i + n <= hlen; i++)
		if (!memcmp(hay + i, needle, n))
			return hay + i;

	return NULL;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	return fzc_init();
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char * const pmd[] = {
		"", "; client_no_context_takeover",
		"; server_no_context_takeover", "; client_max_window_bits=9",
		"; server_max_window_bits=10", "; client_max_window_bits=15",
		"; server_max_window_bits=8", "; bogus=1",
	};
	char key[24 + 36 + 1], accept[32], resp[1024];
	struct fzp_transport *t;
	const uint8_t *k;
	size_t extra, n;
	uint8_t sha[20];
	int r;

	if (size < 3)
		return 0;

	t = fzc_connect(data[0] | 3, 1, 0);
	if (!t)
		return 0;

	k = find(t->tx, t->tx_len, "\r\nSec-WebSocket-Key: ");
	if (!k || k + 21 + 24 > t->tx + t->tx_len) {
		/* no request to answer: just let the program at it */
		fzp_client_end(t, data + 1, size - 1);
		return 0;
	}

	memcpy(key, k + 21, 24);
	memcpy(key + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 37);
	if (data[1] & 0x40)
		key[0] ^= 1;
	lws_SHA1((const uint8_t *)key, 24 + 36, sha);
	lws_b64_encode_string((const char *)sha, 20, accept, sizeof(accept));

	r = lws_snprintf(resp, sizeof(resp),
			 "HTTP/1.1 101 Switching Protocols\r\n"
			 "Upgrade: websocket\r\nConnection: Upgrade\r\n"
			 "Sec-WebSocket-Accept: %s\r\n%s%s%s%s%s",
			 accept,
			 (data[1] & 1) ?
				"Sec-WebSocket-Extensions: permessage-deflate" :
				"",
			 (data[1] & 1) ? pmd[(data[1] >> 1) & 7] : "",
			 (data[1] & 1) ? "\r\n" : "",
			 (data[1] & 0x10) ? "Sec-WebSocket-Protocol: " : "",
			 (data[1] & 0x10) ? ((data[1] & 0x20) ? "nope\r\n" :
							      "echo\r\n") : "");
	n = (size_t)r;
	extra = data[2];
	if (extra > size - 3)
		extra = size - 3;
	if (extra > sizeof(resp) - 3 - n)
		extra = sizeof(resp) - 3 - n;
	memcpy(resp + n, data + 3, extra);
	n += extra;
	memcpy(resp + n, "\r\n", 2);
	n += 2;

	fzp_rx(t, (const uint8_t *)resp, n);
	fzp_client_end(t, data + 3 + extra, size - 3 - extra);

	return 0;
}
