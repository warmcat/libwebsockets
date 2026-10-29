/*
 * lws fuzz target: an h2 server connection, its streams and ws over them,
 * on the sansIO transport with the fuzzer as the network and the clock
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The vhost takes h2 by prior knowledge, and the client preface and an
 * empty SETTINGS are sent for the peer before its program
 * (../sansio-peer.h).  The server is the application of ../sansio-srv-app.h.
 * The program's op 7 is h2 framing done right (../sansio-h2.h); the raw RX
 * ops are still there for anything else.
 */

#define FZP_SERVER
#include "../sansio-peer.h"
#include "../sansio-srv-app.h"
#include "../sansio-h2.h"

static struct lws_vhost *vh;

static const uint8_t preface[] =
	"PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a"
	"\x00\x00\x00" "\x04" "\x00" "\x00\x00\x00\x00"; /* empty SETTINGS */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	vh = fza_init(LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE);
	fzp_op_hook = h2_op;

	return !vh;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fzp_server_session(vh, preface, sizeof(preface) - 1, data, size);

	return 0;
}
