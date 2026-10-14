/*
 * lws-api-test-fault-injection-rules
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A fault injection rule says on which calls of lws_fi() for its name the
 * fault is injected.  Check, call by call, that each kind of rule injects
 * exactly where it says:
 *
 *  - LWSFI_DETERMINISTIC: .pre calls without the fault, then .count with it,
 *    then no more.  It used to count from 1, so it injected a call early, and
 *    with .pre 0 never at all.
 *
 *  - LWSFI_ALWAYS: every call
 *
 *  - LWSFI_PATTERN: by the bits of the pattern, the first call the first bit,
 *    repeating every .count calls
 */

#include <libwebsockets.h>
#include <string.h>

typedef struct {
	const char	*name;
	lws_fi_t	fi;
	const char	*want;	/* 'X' where the call must inject, '.' not */
} fir_case_t;

static const uint8_t pat[] = { 0x05 }; /* bits 0 and 2: "X.X." */

static const fir_case_t cases[] = {
	{ "deterministic, first call only",
	  { .name = "f", .type = LWSFI_DETERMINISTIC, .pre = 0, .count = 1 },
	  "X......." },
	{ "deterministic, two clean then three",
	  { .name = "f", .type = LWSFI_DETERMINISTIC, .pre = 2, .count = 3 },
	  "..XXX..." },
	{ "deterministic, no count",
	  { .name = "f", .type = LWSFI_DETERMINISTIC, .pre = 1, .count = 0 },
	  "........" },
	{ "always",
	  { .name = "f", .type = LWSFI_ALWAYS },
	  "XXXXXXXX" },
	{ "pattern X.X., repeating",
	  { .name = "f", .type = LWSFI_PATTERN, .pattern = pat, .count = 4 },
	  "X.X.X.X." },
};

int
main(int argc, const char **argv)
{
	int fail = 0;
	size_t c, n;

	lws_set_log_level(LLL_USER | LLL_ERR, NULL);
	lwsl_user("LWS API selftest: fault injection rules\n");

	for (c = 0; c < LWS_ARRAY_SIZE(cases); c++) {
		char got[16];
		lws_fi_ctx_t fic;

		memset(&fic, 0, sizeof(fic));
		if (lws_fi_add(&fic, &cases[c].fi)) {
			lwsl_err("%s: unable to add rule\n", cases[c].name);
			return 1;
		}

		for (n = 0; n < strlen(cases[c].want); n++)
			got[n] = lws_fi(&fic, "f") ? 'X' : '.';
		got[n] = '\0';

		/* a name with no rule never injects */
		if (lws_fi(&fic, "g"))
			got[0] = '!';

		lws_fi_destroy(&fic);

		if (strcmp(got, cases[c].want)) {
			lwsl_err("%s: injected %s, wanted %s\n", cases[c].name,
				 got, cases[c].want);
			fail = 1;
		} else
			lwsl_user("%s: %s: PASS\n", cases[c].name, got);
	}

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
