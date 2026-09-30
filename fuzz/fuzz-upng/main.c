/*
 * lws fuzz target: upng stateful PNG stream decoder
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The whole input is fed to the stateful decoder, once with hold_at_metadata
 * clear and once with it set, until it completes, fails, or stops making
 * progress.  (Taking the flag from the first input byte, as this used to,
 * meant every seed's signature byte set the flag and the decoder was fed
 * from byte 1, so it failed the signature check at once and nothing past it
 * was ever exercised.)  This covers the chunked IDAT inflate path as well as
 * the PNG framing itself.
 */

#include <libwebsockets.h>
#include <stdlib.h>

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

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	return 0;
}

#define MAX_LINES (100000)

static void
run(const uint8_t *data, size_t size, char hold)
{
	const uint8_t *buf = data, *pix, *before;
	size_t len = size;
	lws_stateful_ret_t r;
	lws_upng_t *u;
	int n = 0;

	u = lws_upng_new();
	if (!u)
		return;

	while (n++ < MAX_LINES) {
		before = buf;
		r = lws_upng_emit_next_line(u, &pix, &buf, &len, hold);

		if (r & LWS_SRET_FATAL || r == LWS_SRET_OK)
			break;

		/* stalled with nothing consumed and nothing left? */

		if (r == LWS_SRET_WANT_INPUT && (!len || buf == before))
			break;
	}

	lws_upng_free(&u);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!size)
		return 0;

	run(data, size, 0);
	run(data, size, 1);

	return 0;
}
