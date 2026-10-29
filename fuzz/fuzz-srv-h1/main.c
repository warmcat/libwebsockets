/*
 * lws fuzz target: an h1 server connection, and ws on it, on the sansIO
 * transport with the fuzzer as the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The input is the peer's program (../sansio-peer.h): what it sends and
 * how it's split, when the time moves on, how much of lws' writes the
 * transport takes, and when the peer finishes or resets.  The server is an
 * application that answers (../sansio-srv-app.h): request bodies through
 * lws_spa, answers in pieces, a file mount, status pages and redirects, and
 * a ws echo with permessage-deflate on offer, so the h1 parser, the ws
 * upgrade and frame parser, the inflater and the tx side they share all
 * meet what the peer does.
 */

#define FZP_SERVER
#include "../sansio-peer.h"
#include "../sansio-srv-app.h"

static struct lws_vhost *vh;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	vh = fza_init(0);

	return !vh;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fzp_server_session(vh, NULL, 0, data, size);

	return 0;
}
