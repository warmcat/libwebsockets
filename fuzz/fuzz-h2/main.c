/*
 * lws fuzz target: h2 framing and hpack parsing (server side)
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The connection is first walked through a plaintext h2c upgrade
 * (RFC 7540 3.2) and the client connection preface, so the fuzz input is
 * pure h2: frame headers, hpack header blocks in HEADERS and CONTINUATION,
 * hpack dynamic table instructions, stream state transitions, and the rest
 * of the untrusted peer surface of the h2 role.
 */

#include "../peer.h"

static const uint8_t prelude[] =
	"GET / HTTP/1.1\x0d\x0a"
	"Host: fuzz\x0d\x0a"
	"Connection: Upgrade\x0d\x0a"
	"Upgrade: h2c\x0d\x0a"
	"HTTP2-Settings: AAEAABAAAAMAAACAAAQAAP//AAUAAEAA\x0d\x0a"
	"\x0d\x0a"
	"PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a"
	"\x00\x00" "\x04" "\x00" "\x00\x00\x00\x00"; /* empty SETTINGS */

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
