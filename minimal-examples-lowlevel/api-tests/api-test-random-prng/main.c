/*
 * lws-api-test-random-prng
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fault injection can put a seeded PRNG in place of the platform's random
 * source, so a test run draws the same bytes from the same seed: see
 * READMEs/README.fault-injection.md.
 */

#include <libwebsockets.h>
#include <string.h>

/*
 * The first bytes lws_fi_random_seed(cx, 1234) gives: xoshiro256** seeded
 * by splitmix64, each 64-bit result little-endian.  A port replaying lws'
 * transcripts has to produce the same.
 */
static const uint8_t vector_1234[16] = {
	0x6b, 0x42, 0x89, 0x9e, 0xa3, 0x63, 0xa1, 0xa3,
	0x24, 0x60, 0x07, 0xbb, 0xb7, 0x67, 0x64, 0xdc,
};

/*
 * A context with random_prng in its creation fic seeded with seed, or with
 * no fault at all if seed is 0; draws a and b from it, with coins draws of
 * a probabilistic fault from the fault context's own PRNG between them
 */
static int
draw(uint64_t seed, int coins, uint8_t *a, uint8_t *b, size_t len)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	lws_fi_t fi;
	int n;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;

	if (seed) {
		memset(&fi, 0, sizeof(fi));
		fi.name = "random_prng";
		fi.type = LWSFI_ALWAYS;
		if (lws_fi_add(&info.fic, &fi))
			return 1;

		fi.name = "coin";
		fi.type = LWSFI_PROBABILISTIC;
		fi.pre = 50;
		if (lws_fi_add(&info.fic, &fi))
			return 1;

		lws_xos_init(&info.fic.xos, seed);
	}

	cx = lws_create_context(&info);
	if (!cx) {
		lws_fi_destroy(&info.fic);
		return 1;
	}

	n = lws_get_random(cx, a, len) != len;
	while (coins--)
		(void)lws_fi_user_context_fi(cx, "coin");
	n |= lws_get_random(cx, b, len) != len;

	lws_context_destroy(cx);

	return n;
}

int
main(int argc, const char **argv)
{
	uint8_t a1[48], b1[48], a2[48], b2[48], a3[48], b3[48];
	int logs = LLL_USER | LLL_ERR, e = 0;
	struct lws_context_creation_info info;
	struct lws_context *cx;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: seeded random source\n");

	/* 1: the same fault seed, the same bytes */
	if (draw(1234, 0, a1, b1, sizeof(a1)) ||
	    draw(1234, 0, a2, b2, sizeof(a2))) {
		lwsl_err("case 1: context failed\n");
		return 1;
	}
	if (memcmp(a1, a2, sizeof(a1)) || memcmp(b1, b2, sizeof(b1))) {
		lwsl_err("case 1: same seed, different bytes\n");
		e++;
	}
	if (!memcmp(a1, b1, sizeof(a1))) {
		lwsl_err("case 1: the stream repeated itself\n");
		e++;
	}

	/* 2: another seed, other bytes */
	if (draw(4321, 0, a3, b3, sizeof(a3))) {
		lwsl_err("case 2: context failed\n");
		return 1;
	}
	if (!memcmp(a1, a3, sizeof(a1))) {
		lwsl_err("case 2: different seeds, same bytes\n");
		e++;
	}

	/* 3: other faults drawing on the fault PRNG do not move the stream */
	if (draw(1234, 7, a3, b3, sizeof(a3))) {
		lwsl_err("case 3: context failed\n");
		return 1;
	}
	if (memcmp(a1, a3, sizeof(a1)) || memcmp(b1, b3, sizeof(b1))) {
		lwsl_err("case 3: other faults moved the random stream\n");
		e++;
	}

	/* 4: seeded by the api on a context created without the fault, the
	 * known vector */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("case 4: context failed\n");
		return 1;
	}
	lws_fi_random_seed(cx, 1234);
	if (lws_get_random(cx, a2, sizeof(a2)) != sizeof(a2) ||
	    memcmp(a2, vector_1234, sizeof(vector_1234))) {
		lwsl_err("case 4: not the known vector\n");
		lwsl_hexdump_err(a2, sizeof(vector_1234));
		e++;
	}

	/* reseeding starts the stream again */
	lws_fi_random_seed(cx, 1234);
	if (lws_get_random(cx, a3, sizeof(a3)) != sizeof(a3) ||
	    memcmp(a2, a3, sizeof(a2))) {
		lwsl_err("case 4: reseed did not restart the stream\n");
		e++;
	}
	lws_context_destroy(cx);

	/* 5: without either, it is the platform's random */
	if (draw(0, 0, a3, b3, sizeof(a3))) {
		lwsl_err("case 5: context failed\n");
		return 1;
	}
	if (!memcmp(a1, a3, sizeof(a1)) || !memcmp(a3, b3, sizeof(a3))) {
		lwsl_err("case 5: not the platform's random\n");
		e++;
	}

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return e;
}
