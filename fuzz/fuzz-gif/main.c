/*
 * libwebsockets - libFuzzer target for the stateful GIF decoder
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Same shape as fuzz-jpeg: the first input byte selects hold_at_metadata,
 * the rest is gif data fed to the stateful decoder a row at a time until it
 * completes, fails, or stalls wanting input we no longer have.  The input is
 * then decoded a second time after lws_gif_restart() with the hold flag
 * clear, which is the flow the dlo integration drives for interlaced rows,
 * and ends the pass holding a row in the shared pool.
 */

#include <libwebsockets.h>
#include <stdlib.h>

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
	lws_stateful_ret_t r;
	lws_gif_t *g;
	size_t len;
	int n;

	if (!size)
		return 0;

	g = lws_gif_new();
	if (!g)
		return 0;

	for (n = 0; n < 2; n++) {
		int lines = 0;

		buf = data + 1;
		len = size - 1;

		while (lines++ < MAX_LINES) {
			before = buf;
			r = lws_gif_emit_next_line(g, &pix, NULL, &buf, &len,
						   (data[0] & 1) && !n);

			if (r & LWS_SRET_FATAL || r == LWS_SRET_OK)
				break;

			/* stalled with nothing consumed and nothing left? */

			if (r == LWS_SRET_WANT_INPUT &&
			    (!len || buf == before))
				break;
		}

		/* second pass runs from a clean restart, hold flag clear */

		lws_gif_restart(g);
	}

	lws_gif_free(&g);

	return 0;
}
