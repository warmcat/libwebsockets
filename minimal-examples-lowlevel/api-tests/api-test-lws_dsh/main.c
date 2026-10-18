/*
 * lws-api-test-lws_dsh
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>


enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

int
test1(void)
{
	struct lws_dsh *dsh;
	size_t size;
	void *a1;

	/*
	 * test 1: single dsh, alloc 2 kinds and free everything back to a
	 *         single free obj
	 */

	dsh = lws_dsh_create(NULL, 16384, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "hello", 5, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 1, "some other string", 17, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 2\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "hello again", 11, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 3\n", __func__);

		goto bail;
	}

	if (lws_dsh_get_head(dsh, 1, &a1, &size)) {
		lwsl_err("%s: no head 1\n", __func__);

		goto bail;
	}
	if (size != 17 || memcmp(a1, "some other string", 17)) {
		lwsl_err("%s: test 1 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 2\n", __func__);

		goto bail;
	}
	if (size != 5 || memcmp(a1, "hello", 5)) {
		lwsl_err("%s: test 2 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 3\n", __func__);

		goto bail;
	}
	if (size != 11 || memcmp(a1, "hello again", 11)) {
		lwsl_err("%s: test 3 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	lws_dsh_destroy(&dsh);

	return 0;
bail:
	lws_dsh_destroy(&dsh);

	return 1;
}

int
test3(void)
{
	struct lws_dsh *dsh, *dsh2;
	lws_dll2_owner_t owner;
	/* big enough that the umeetable 5000-byte request below is a real,
	 * in-bounds source: the request must fail because the 4096-byte dsh
	 * cannot hold it, not because the caller lied about the length */
	uint8_t blob[8192];

	memset(blob, 0, sizeof(blob));

	/*
	 * test 3: multiple dsh, umeetable allocation request
	 */

	lws_dll2_owner_clear(&owner);

	dsh = lws_dsh_create(&owner, 4096, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh1\n", __func__);

		return 1;
	}

	dsh2 = lws_dsh_create(&owner, 4096, 2);
	if (!dsh2) {
		lwsl_err("%s: Failed to create dsh2\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 0, blob, 4000, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail2;
	}

	if (lws_dsh_alloc_tail(dsh2, 0, "hello", 5, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 2\n", __func__);

		goto bail2;
	}

	/*
	 * There's just no room for this, we expect it to fail
	 */

	if (!lws_dsh_alloc_tail(dsh, 0, blob, 5000, NULL, 0)) {
		lwsl_err("%s: Didn't fail to alloc as expected\n", __func__);

		goto bail2;
	}

	if (lws_dsh_alloc_tail(dsh2, 0, "hello again", 11, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 4\n", __func__);

		goto bail2;
	}

	lws_dsh_destroy(&dsh2);
	lws_dsh_destroy(&dsh);

	return 0;

bail2:
	lws_dsh_destroy(&dsh2);

bail:
	lws_dsh_destroy(&dsh);

	return 1;
}

int
test4(void)
{
	uint8_t blob[4096];
	struct lws_dsh *dsh;
	size_t size;
	void *a1;

	memset(blob, 0, sizeof(blob));

	/*
	 * test 4: use up whole free list, then recover and alloc something
	 *	   else
	 */

	dsh = lws_dsh_create(NULL, 4096, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (lws_dsh_alloc_tail(dsh, 0, blob, 4000, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail;
	}

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 1\n", __func__);

		goto bail;
	}
	if (size != 4000) {
		lwsl_err("%s: test 1 mismatch %d\n", __func__, (int)size);

		goto bail;
	}
	lws_dsh_free(&a1);

	if (lws_dsh_alloc_tail(dsh, 0, "some other string", 17, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 2\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "hello again", 11, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 3\n", __func__);

		goto bail;
	}

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 4\n", __func__);

		goto bail;
	}
	if (size != 17 || memcmp(a1, "some other string", 17)) {
		/* it may (should...) coalesce */
		if (size != 28 || memcmp(a1, "some other stringhello again", 28)) {
			lwsl_err("%s: test 4 mismatch %d\n", __func__, (int)size);

			goto bail;
		}
	}
	lws_dsh_free(&a1);

	lws_dsh_destroy(&dsh);

	return 0;
bail:
	lws_dsh_destroy(&dsh);

	return 1;
}

int
test5(void)
{
	struct lws_dsh *dsh;
	unsigned int budget;
	uint8_t blob[4096];
	lws_xos_t xos;
	size_t size;
	void *a1;

	memset(blob, 0, sizeof(blob));
	lws_xos_init(&xos, 0x123456789abcdef0ull);

	budget = (unsigned int)(lws_xos(&xos) % 4000) + 4000;

	lwsl_notice("%s: budget %u\n", __func__, budget);


	/*
	 * test 5: PRNG-based spamming and erratic bidi draining
	 */

	dsh = lws_dsh_create(NULL, 409600, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	do {

		if (lws_xos_percent(&xos, 60)) {
			/* kind 0 is going to try to write */

			size = (size_t)((lws_xos(&xos) & 127) + 1);

			if (!lws_dsh_alloc_tail(dsh, 0, blob, size, NULL, 0))
				lwsl_notice("%s: kind 0 alloc %d\n", __func__, (int)size);
		}

		if (lws_xos_percent(&xos, 80)) {
			/* kind 1 is going to try to write */

			size = (size_t)((lws_xos(&xos) & 127) + 1);

			if (!lws_dsh_alloc_tail(dsh, 1, blob, size, NULL, 0))
				lwsl_notice("%s: kind 1 alloc %d\n", __func__, (int)size);
		}

		if (lws_xos_percent(&xos, 40)) {
			/* kind 0 is going to try to read */

			while (!lws_dsh_get_head(dsh, 0, &a1, &size)) {
				lwsl_notice("%s: kind 0 read %d\n", __func__, (int)size);
				lws_dsh_free(&a1);
			}
		}

		if (lws_xos_percent(&xos, 30)) {
			/* kind 1 is going to try to read */

			while (!lws_dsh_get_head(dsh, 1, &a1, &size)) {
				lwsl_notice("%s: kind 1 read %d\n", __func__, (int)size);
				lws_dsh_free(&a1);
			}
		}

	} while (budget--);

	while (!lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_notice("%s: kind 0 read %d\n", __func__, (int)size);
		lws_dsh_free(&a1);
	}

	while (!lws_dsh_get_head(dsh, 1, &a1, &size)) {
		lwsl_notice("%s: kind 1 read %d\n", __func__, (int)size);
		lws_dsh_free(&a1);
	}

#if defined(_DEBUG)
	lws_dsh_describe(dsh, "test dsh end state");
#endif

	lws_dsh_destroy(&dsh);

	return 0;
}

int
test6(void)
{
	struct lws_dsh *dsh;
	size_t size;
	void *a1;

	/*
	 * test 6: confirm sequential coalescing
	 */

	dsh = lws_dsh_create(NULL, 16384, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "hello", 5, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 1, "some other string", 17, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 2\n", __func__);

		goto bail;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "hello again", 11, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 3\n", __func__);

		goto bail;
	}

	if (lws_dsh_get_head(dsh, 1, &a1, &size)) {
		lwsl_err("%s: no head 1\n", __func__);

		goto bail;
	}
	if (size != 17 || memcmp(a1, "some other string", 17)) {
		lwsl_err("%s: test 1 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 2\n", __func__);

		goto bail;
	}
	if (size != 5 || memcmp(a1, "hello", 5)) {
		lwsl_err("%s: test 2 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head 3\n", __func__);

		goto bail;
	}
	if (size != 11 || memcmp(a1, "hello again", 11)) {
		lwsl_err("%s: test 3 mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	lws_dsh_destroy(&dsh);

	return 0;
bail:
#if defined(_DEBUG)
	lws_dsh_describe(dsh, "test6 fail");
#endif
	lws_dsh_destroy(&dsh);

	return 1;
}

int
test7(void)
{
	static uint8_t big[3000];
	struct lws_dsh *dsh;
	size_t size;
	void *a1;

	/*
	 * test 7: an allocation may leave less free space than its own size,
	 * that's fine as long as it fit; one that doesn't fit is refused
	 */

	memset(big, 0x5a, sizeof(big));

	dsh = lws_dsh_create(NULL, 4096, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (lws_dsh_alloc_tail(dsh, 0, big, sizeof(big), NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail;
	}

	if (!lws_dsh_alloc_tail(dsh, 1, big, sizeof(big), NULL, 0)) {
		lwsl_err("%s: alloc 2 should not have fit\n", __func__);

		goto bail;
	}

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head\n", __func__);

		goto bail;
	}
	if (size != sizeof(big) || memcmp(a1, big, sizeof(big))) {
		lwsl_err("%s: mismatch\n", __func__);

		goto bail;
	}
	lws_dsh_free(&a1);

	lws_dsh_destroy(&dsh);

	return 0;
bail:
#if defined(_DEBUG)
	lws_dsh_describe(dsh, "test7 fail");
#endif
	lws_dsh_destroy(&dsh);

	return 1;
}

int
test8(void)
{
	static uint8_t big[3000];
	struct lws_dsh *dsh;
	size_t size;
	void *a1;

	/*
	 * test 8: consume an object partially, then the rest of it, and
	 * confirm all its space came back
	 */

	memset(big, 0xa5, sizeof(big));

	dsh = lws_dsh_create(NULL, 4096, 2);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (lws_dsh_alloc_tail(dsh, 0, "0123456789", 10, NULL, 0)) {
		lwsl_err("%s: Failed to alloc 1\n", __func__);

		goto bail;
	}

	lws_dsh_consume(dsh, 0, 4);

	if (lws_dsh_get_head(dsh, 0, &a1, &size)) {
		lwsl_err("%s: no head\n", __func__);

		goto bail;
	}
	if (size != 6 || memcmp(a1, "456789", 6)) {
		lwsl_err("%s: partial consume mismatch\n", __func__);

		goto bail;
	}

	lws_dsh_consume(dsh, 0, 6);

	if (!lws_dsh_get_head(dsh, 0, &a1, &size) ||
	    lws_dsh_get_size(dsh, 0)) {
		lwsl_err("%s: object still there after full consume\n",
			 __func__);

		goto bail;
	}

	/* the whole buffer must be available again */

	if (lws_dsh_alloc_tail(dsh, 1, big, sizeof(big), NULL, 0)) {
		lwsl_err("%s: space not recovered\n", __func__);

		goto bail;
	}

	lws_dsh_destroy(&dsh);

	return 0;
bail:
#if defined(_DEBUG)
	lws_dsh_describe(dsh, "test8 fail");
#endif
	lws_dsh_destroy(&dsh);

	return 1;
}

/*
 * the head object of kind must be exactly len bytes of exp
 */

static int
test9_head(struct lws_dsh *dsh, int kind, const char *exp, size_t len)
{
	size_t size;
	void *a1;

	if (lws_dsh_get_head(dsh, kind, &a1, &size)) {
		lwsl_err("%s: kind %d: no head\n", __func__, kind);

		return 1;
	}
	if (size != len || memcmp(a1, exp, len)) {
		lwsl_err("%s: kind %d: head is %d bytes, expected %d\n",
			 __func__, kind, (int)size, (int)len);

		return 1;
	}

	return 0;
}

int
test9(void)
{
	struct lws_dsh *dsh;
	int n;

	/*
	 * test 9: COALESCE given at create applies to every kind, but a kind
	 * can be given its own flags... kind 0 here holds records, that must
	 * stay one object per allocation, kind 1 a byte stream that may be
	 * coalesced.  The per-kind flags must survive lws_dsh_empty().
	 */

	dsh = lws_dsh_create(NULL, 4096, 2 | LWS_DSHFLAG_ENABLE_COALESCE);
	if (!dsh) {
		lwsl_err("%s: Failed to create dsh\n", __func__);

		return 1;
	}

	if (!lws_dsh_set_kind_flags(dsh, 2, 0) ||
	    !lws_dsh_set_kind_flags(dsh, -1, 0) ||
	    !lws_dsh_set_kind_flags(dsh, 0, 1)) {
		lwsl_err("%s: bad kind or flags accepted\n", __func__);

		goto bail;
	}

	if (lws_dsh_set_kind_flags(dsh, 0, 0)) {
		lwsl_err("%s: set kind flags failed\n", __func__);

		goto bail;
	}

	for (n = 0; n < 2; n++) {
		if (lws_dsh_alloc_tail(dsh, 0, "abc", 3, NULL, 0) ||
		    lws_dsh_alloc_tail(dsh, 0, "defg", 4, NULL, 0) ||
		    lws_dsh_alloc_tail(dsh, 1, "hij", 3, NULL, 0) ||
		    lws_dsh_alloc_tail(dsh, 1, "klmn", 4, NULL, 0)) {
			lwsl_err("%s: Failed to alloc\n", __func__);

			goto bail;
		}

		/* the records stay separate, the stream is coalesced */

		if (test9_head(dsh, 0, "abc", 3) ||
		    test9_head(dsh, 1, "hijklmn", 7))
			goto bail;

		lws_dsh_consume(dsh, 0, 3);

		if (test9_head(dsh, 0, "defg", 4))
			goto bail;

		/* and again with the same flags, after emptying it */

		lws_dsh_empty(dsh);
	}

	lws_dsh_destroy(&dsh);

	return 0;
bail:
#if defined(_DEBUG)
	lws_dsh_describe(dsh, "test9 fail");
#endif
	lws_dsh_destroy(&dsh);

	return 1;
}

int main(int argc, const char **argv)
{
	
	int ret = 0, n;
	(void)switches;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}



	lwsl_user("LWS API selftest: lws_dsh\n");

	n = test1();
	lwsl_user("%s: test1: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test3();
	lwsl_user("%s: test3: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test4();
	lwsl_user("%s: test4: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test5();
	lwsl_user("%s: test5: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test6();
	lwsl_user("%s: test6: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test7();
	lwsl_user("%s: test7: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test8();
	lwsl_user("%s: test8: %d\n", __func__, n);
	ret |= n;
	if (ret)
		goto bail;

	n = test9();
	lwsl_user("%s: test9: %d\n", __func__, n);
	ret |= n;

bail:
	lwsl_user("Completed: %s\n", ret ? "FAIL" : "PASS");

	return ret;
}
