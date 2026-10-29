/*
 * lws fuzz target: an h2 client connection, with the fuzzer as the server,
 * the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The client speaks h2 by prior knowledge (LCCSCF_H2_PRIOR_KNOWLEDGE), so
 * it's plaintext and on our transport.  input[0] is the client
 * application's config (../sansio-cli-app.h); the server's empty SETTINGS
 * is sent for it, and the rest of the input is the server's program
 * (../sansio-peer.h), whose op 7 is h2 framing done right
 * (../sansio-h2.h), answers with hpack that decodes among them: the
 * response's HEADERS and CONTINUATION, its DATA against the client's
 * window, SETTINGS changes, PUSH_PROMISE, RST_STREAM, GOAWAY and PING.
 */

#define FZP_CLIENT
#include "../sansio-peer.h"
#include "../sansio-cli-app.h"
#include "../sansio-h2.h"

static const uint8_t settings[] =
	"\x00\x00\x00" "\x04" "\x00" "\x00\x00\x00\x00";

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	h2_peer_is_server = 1;
	fzp_op_hook = h2_op;

	return fzc_init();
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fzp_transport *t;

	if (!size)
		return 0;

	t = fzc_connect(data[0], 0, LCCSCF_H2_PRIOR_KNOWLEDGE);
	if (!t)
		return 0;

	fzp_rx(t, settings, sizeof(settings) - 1);
	fzp_client_end(t, data + 1, size - 1);

	return 0;
}
