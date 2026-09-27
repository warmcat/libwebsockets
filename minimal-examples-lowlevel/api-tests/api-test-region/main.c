/*
 * lws api test region
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises lws_region the way a shared scratch buffer is used: a reader
 * claims what it read, parses a prefix and trims it off, a composer claims
 * the consumed part below the live tail, then the reader hands the rest on
 * by pointer and a stale handle must not disturb whoever took the slot.
 *
 * The region is created without LWS_REGION_F_ABORT, so violations come back
 * as return codes we can check, instead of stopping the process.
 */

#include <libwebsockets.h>
#include <string.h>

#define BUF_SIZE	1024
#define SLOTS		3

static uint8_t buf[BUF_SIZE];

static int
expect(const char *what, int got, int want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: %s: got %d, expected %d\n", __func__, what, got, want);

	return 1;
}

int
main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	lws_region_claim_t claims[SLOTS];
	int rd, comp, h, h2, h3;
	uint8_t outside[16];
	lws_region_t r;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lws_region\n");

	/* degenerate slot tables are refused */

	e += expect("init 0 slots", lws_region_init(&r, "buf", buf,
			sizeof(buf), claims, 0, 0), -1);
	e += expect("init 256 slots", lws_region_init(&r, "buf", buf,
			sizeof(buf), claims, 256, 0), -1);

	e += expect("init", lws_region_init(&r, "buf", buf, sizeof(buf),
					   claims, LWS_ARRAY_SIZE(claims), 0), 0);
	e += expect("idle at start", lws_region_idle(&r, "start"), 0);

	/* storage that is not the buffer is not tracked, and releasing it
	 * is harmless */

	h = lws_region_claim(&r, outside, sizeof(outside), "outside");
	e += expect("outside claim", h, LWS_REGION_NOT_TRACKED);
	lws_region_release(&r, h);
	e += expect("idle after outside", lws_region_idle(&r, "outside"), 0);

	/* nothing may claim past the end, including by a wrapping length */

	e += expect("overrun", lws_region_claim(&r, buf + 1000, 25, "overrun"),
		    LWS_REGION_E_OVERRUN);
	e += expect("wrapping len", lws_region_claim(&r, buf + 1, (size_t)-1,
						    "wrap"),
		    LWS_REGION_E_OVERRUN);
	h = lws_region_claim(&r, buf + BUF_SIZE - 24, 24, "to the end");
	e += expect("claim to the end", h >= 0, 1);
	lws_region_release(&r, h);

	/* a reader claims what it read, at +16..+528 */

	rd = lws_region_claim(&r, buf + 16, 512, "reader");
	e += expect("reader claim", rd >= 0, 1);
	e += expect("idle while held", lws_region_idle(&r, "held"), -1);

	/* while it holds that, nothing may overlap it at either edge */

	e += expect("overlap below", lws_region_claim(&r, buf, 17, "below"),
		    LWS_REGION_E_OVERLAP);
	e += expect("overlap above", lws_region_claim(&r, buf + 527, 8,
						     "above"),
		    LWS_REGION_E_OVERLAP);

	/* but adjacent ranges are fine */

	h = lws_region_claim(&r, buf, 16, "abutting below");
	e += expect("abutting below", h >= 0, 1);
	lws_region_release(&r, h);
	h = lws_region_claim(&r, buf + 528, 16, "abutting above");
	e += expect("abutting above", h >= 0, 1);
	lws_region_release(&r, h);

	/* the reader parses 200 bytes and gives them back: a composer may
	 * now use the consumed part while the unparsed tail stays live */

	lws_region_trim(&r, buf + 216);
	comp = lws_region_claim(&r, buf + 16, 200, "composer");
	e += expect("composer in trimmed part", comp >= 0, 1);
	e += expect("composer into live tail", lws_region_claim(&r, buf + 16,
								201, "greedy"),
		    LWS_REGION_E_OVERLAP);

	/* all the slots in use: a third claim fits, a fourth has no slot */

	h = lws_region_claim(&r, buf + 600, 10, "third");
	e += expect("third claim", h >= 0, 1);
	e += expect("no free slot", lws_region_claim(&r, buf + 700, 10,
						    "fourth"),
		    LWS_REGION_E_FULL);
	lws_region_release(&r, h);
	lws_region_release(&r, comp);

	/* the reader parks its tail somewhere else and hands the buffer on by
	 * any pointer inside what it still holds, without its handle */

	lws_region_release_containing(&r, buf + 400);
	e += expect("idle after hand-on", lws_region_idle(&r, "hand-on"), 0);

	/* a new claim reuses the reader's slot... */

	h2 = lws_region_claim(&r, buf + 16, 64, "next user");
	e += expect("next user", h2 >= 0, 1);
	e += expect("same slot", (h2 & 0xff) == (rd & 0xff), 1);

	/* ...and the reader's own release by its now stale handle must not
	 * free it: the next user's claim still blocks an overlap */

	lws_region_release(&r, rd);
	e += expect("stale release ignored", lws_region_claim(&r, buf + 20, 4,
							     "overlap"),
		    LWS_REGION_E_OVERLAP);

	/* trimming a claim to its end gives it up entirely */

	lws_region_trim(&r, buf + 80);
	e += expect("trim to end", lws_region_idle(&r, "trimmed"), 0);

	/* its handle is then stale too, even with nothing in the slot, and
	 * a pointer in no claim is ignored by trim and release_containing */

	lws_region_release(&r, h2);
	lws_region_trim(&r, buf + 900);
	lws_region_release_containing(&r, buf + 900);

	h3 = lws_region_claim(&r, buf, BUF_SIZE, "everything");
	e += expect("whole buffer", h3 >= 0, 1);
	lws_region_release(&r, h3);
	e += expect("idle at end", lws_region_idle(&r, "end"), 0);

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
