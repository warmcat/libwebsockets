/*
 * lws fuzz target: upng stateful PNG stream decoder
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The first input byte's LSB is used as the hold_at_metadata flag and the
 * rest is fed to the stateful decoder until it completes, fails, or stops
 * making progress.  This covers the chunked IDAT inflate path as well as
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

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *buf, *pix, *before;
	size_t len;
	lws_upng_t *u;
	lws_stateful_ret_t r;
	int n = 0;

	if (!size)
		return 0;

	u = lws_upng_new();
	if (!u)
		return 0;

	buf = data + 1;
	len = size - 1;

	while (n++ < MAX_LINES) {
		before = buf;
		r = lws_upng_emit_next_line(u, &pix, &buf, &len, data[0] & 1);

		if (r & LWS_SRET_FATAL || r == LWS_SRET_OK)
			break;

		/* stalled with nothing consumed and nothing left? */

		if (r == LWS_SRET_WANT_INPUT && (!len || buf == before))
			break;
	}

	lws_upng_free(&u);

	return 0;
}
