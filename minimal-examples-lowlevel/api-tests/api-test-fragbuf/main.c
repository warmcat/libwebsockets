/*
 * lws api test fragbuf
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>

#define UNITS		17
#define UNIT_SIZE	100

/*
 * Fill every unit with a pattern derived from its byte offset, then check it
 * back both ways round: by unit, and by walking byte offsets.  Whether the
 * buffer came back in one piece or seventeen must not change a single byte.
 */

static int
fill_and_check(lws_fragbuf_t *fb, const char *hint, unsigned int exp_pieces)
{
	size_t n, m, ofs, avail;
	uint8_t *p;
	int e = 0;

	if (lws_fragbuf_pieces(fb) != exp_pieces) {
		lwsl_err("%s: %s: %u pieces, expected %u\n", __func__, hint,
			 lws_fragbuf_pieces(fb), exp_pieces);
		e++;
	}

	for (n = 0; n < UNITS; n++) {
		p = lws_fragbuf_unit(fb, n);
		if (!p) {
			lwsl_err("%s: %s: no unit %u\n", __func__, hint,
				 (unsigned int)n);

			return e + 1;
		}

		for (m = 0; m < UNIT_SIZE; m++)
			p[m] = (uint8_t)((n * UNIT_SIZE + m) & 0xff);
	}

	/* read it back by unit */

	for (n = 0; n < UNITS; n++) {
		p = lws_fragbuf_unit(fb, n);

		for (m = 0; m < UNIT_SIZE; m++)
			if (p[m] != (uint8_t)((n * UNIT_SIZE + m) & 0xff)) {
				lwsl_err("%s: %s: unit %u byte %u\n", __func__,
					 hint, (unsigned int)n,
					 (unsigned int)m);
				e++;

				break;
			}
	}

	/* ... and by walking byte offsets, the way a stream consumer would */

	ofs = 0;
	while (ofs < UNITS * UNIT_SIZE) {
		p = lws_fragbuf_at(fb, ofs, &avail);

		if (!p || !avail) {
			lwsl_err("%s: %s: at(%u) empty\n", __func__, hint,
				 (unsigned int)ofs);

			return e + 1;
		}

		/* a run may never cross the end of the buffer */

		if (ofs + avail > UNITS * UNIT_SIZE) {
			lwsl_err("%s: %s: at(%u) run %u overruns\n", __func__,
				 hint, (unsigned int)ofs, (unsigned int)avail);
			e++;

			return e;
		}

		for (m = 0; m < avail; m++)
			if (p[m] != (uint8_t)((ofs + m) & 0xff)) {
				lwsl_err("%s: %s: at(%u)[%u]\n", __func__, hint,
					 (unsigned int)ofs, (unsigned int)m);
				e++;

				break;
			}

		ofs += avail;
	}

	if (ofs != UNITS * UNIT_SIZE) {
		lwsl_err("%s: %s: walk ended at %u\n", __func__, hint,
			 (unsigned int)ofs);
		e++;
	}

	/* out of range must be refused, not guessed at */

	if (lws_fragbuf_unit(fb, UNITS)) {
		lwsl_err("%s: %s: unit past the end\n", __func__, hint);
		e++;
	}

	if (lws_fragbuf_at(fb, UNITS * UNIT_SIZE, &avail) || avail) {
		lwsl_err("%s: %s: at past the end\n", __func__, hint);
		e++;
	}

	return e;
}

int
main(int argc, const char **argv)
{
	int e = 0, n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	static const size_t caps[] = { 0, 1, 2, 5, 16, 17, 100 };
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_fragbuf\n");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(caps); n++) {
		unsigned int exp = caps[n] && caps[n] < UNITS ?
			(unsigned int)((UNITS + caps[n] - 1) / caps[n]) : 1;
		lws_fragbuf_t *fb = lws_fragbuf_create_cap(UNITS, UNIT_SIZE,
							   caps[n]);
		char hint[32];

		lws_snprintf(hint, sizeof(hint), "cap %u",
			     (unsigned int)caps[n]);

		if (!fb) {
			lwsl_err("%s: %s: create failed\n", __func__, hint);
			e++;

			continue;
		}

		e += fill_and_check(fb, hint, exp);

		lws_fragbuf_destroy(&fb);

		if (fb) {
			lwsl_err("%s: %s: destroy did not clear\n", __func__,
				 hint);
			e++;
		}
	}

	/* degenerate asks are refused rather than half-honoured */

	if (lws_fragbuf_create(0, 100) || lws_fragbuf_create(100, 0)) {
		lwsl_err("%s: zero-sized create was allowed\n", __func__);
		e++;
	}

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
