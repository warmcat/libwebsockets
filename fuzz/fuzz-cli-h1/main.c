/*
 * lws fuzz target: an h1 client connection, with the fuzzer as the server,
 * the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * input[0] is the client application's config (../sansio-cli-app.h): GET,
 * HEAD or POST, and whether it pulls the body at once.  The rest is the
 * server's program (../sansio-peer.h), so the response's status line,
 * headers, body framing (content-length, chunked, until the close), the
 * interim responses before it and what comes after it all meet the client
 * as the server splits and times them.
 */

#define FZP_CLIENT
#include "../sansio-peer.h"
#include "../sansio-cli-app.h"

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
	struct fzp_transport *t;

	if (!size)
		return 0;

	t = fzc_connect(data[0], 0, 0);
	if (t)
		fzp_client_end(t, data + 1, size - 1);

	return 0;
}
