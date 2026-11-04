/*
 * lws api test buflist
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>

#define TOTAL		1000

/* the segments the content is added in: uneven, and one of a single byte */

static const size_t seglens[] = { 100, 1, 257, 64, 300, 278 };

static uint8_t
pattern(size_t ofs)
{
	return (uint8_t)((ofs * 7 + 3) & 0xff);
}

/*
 * Walk the buflist by byte offset with lws_buflist_at(), the way a consumer
 * reading it in place does, from skip bytes in: every run must lie inside a
 * segment, hold the right bytes, and the runs must cover the rest exactly
 */

static int
walk(struct lws_buflist **bl, size_t skip, const char *hint)
{
	size_t ofs = 0, avail, m;
	const uint8_t *p;

	while (ofs < TOTAL - skip) {
		p = lws_buflist_at(bl, ofs, &avail);
		if (!p || !avail) {
			lwsl_err("%s: %s: at(%u) empty\n", __func__, hint,
				 (unsigned int)ofs);
			return 1;
		}

		if (ofs + avail > TOTAL - skip) {
			lwsl_err("%s: %s: at(%u) run %u overruns\n", __func__,
				 hint, (unsigned int)ofs, (unsigned int)avail);
			return 1;
		}

		for (m = 0; m < avail; m++)
			if (p[m] != pattern(skip + ofs + m)) {
				lwsl_err("%s: %s: at(%u)[%u]\n", __func__,
					 hint, (unsigned int)ofs,
					 (unsigned int)m);
				return 1;
			}

		/* a run may start partway into a segment too */

		if (avail > 1) {
			const uint8_t *p1 = lws_buflist_at(bl, ofs + 1, &m);

			if (p1 != p + 1 || m != avail - 1) {
				lwsl_err("%s: %s: at(%u) mid-run\n", __func__,
					 hint, (unsigned int)ofs + 1);
				return 1;
			}
		}

		ofs += avail;
	}

	/* nothing is guessed at past the end */

	if (lws_buflist_at(bl, TOTAL - skip, &avail) || avail) {
		lwsl_err("%s: %s: at past the end\n", __func__, hint);
		return 1;
	}

	/* and nothing was consumed */

	if (lws_buflist_total_len(bl) != TOTAL - skip) {
		lwsl_err("%s: %s: content changed\n", __func__, hint);
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_buflist *bl = NULL;
	uint8_t buf[300];
	size_t n, m, ofs = 0, avail;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_buflist\n");

	if (lws_buflist_at(&bl, 0, &avail) || avail) {
		lwsl_err("%s: empty buflist gave a byte\n", __func__);
		e++;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(seglens); n++) {
		for (m = 0; m < seglens[n]; m++)
			buf[m] = pattern(ofs + m);

		if (lws_buflist_append_segment(&bl, buf, seglens[n]) < 0) {
			lwsl_err("%s: append failed\n", __func__);
			e++;
			goto bail;
		}
		ofs += seglens[n];
	}

	e += walk(&bl, 0, "whole");

	/*
	 * Part of the head segment used: offsets are from what is left of it,
	 * then all of it, which frees it
	 */

	lws_buflist_use_segment(&bl, 40);
	e += walk(&bl, 40, "head part used");

	lws_buflist_use_segment(&bl, 60);
	e += walk(&bl, 100, "head used up");

bail:
	lws_buflist_destroy_all_segments(&bl);

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
