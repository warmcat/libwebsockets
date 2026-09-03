/*
 * lws fuzz target: ws server-side frame parsing
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The connection is first upgraded to ws with a valid handshake, then the
 * fuzz input is parsed as client ws frames: opcode and masking rules,
 * fragmentation and continuation state machine, control frame size limits,
 * and close handling.
 */

#include "../peer.h"

static const uint8_t prelude[] =
	"GET / HTTP/1.1\x0d\x0a"
	"Host: fuzz\x0d\x0a"
	"Connection: Upgrade\x0d\x0a"
	"Upgrade: websocket\x0d\x0a"
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\x0d\x0a"
	"Sec-WebSocket-Version: 13\x0d\x0a"
	"\x0d\x0a";

/*
 * Fuzzing means constantly feeding the parser garbage, so its rejection
 * logs are expected noise that dominates the runtime.  Set LWS_FUZZ_VERBOSE=1
 * to get them back (eg, when replaying a crash artifact).
 */

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
