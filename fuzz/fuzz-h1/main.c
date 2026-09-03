/*
 * lws fuzz target: h1 server-side header and body parsing
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The input is raw h1 request bytes from an untrusted client, fed to a real
 * adopted server connection.  Everything the h1 server parser touches is
 * covered: header tokenizing into the ah, URL and query parsing, body and
 * chunked body handling, and upgrade requests (ws and h2c role transitions).
 */

#include "../peer.h"

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
	fuzz_peer_session(NULL, 0, data, size);

	return 0;
}
