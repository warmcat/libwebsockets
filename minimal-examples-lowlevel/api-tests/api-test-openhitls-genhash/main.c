/*
 * lws-api-test-openhitls-genhash
 *
 * unit tests for OpenHiTLS generic hash / HMAC abstraction
 *
 * Tests lws_genhash_init/update/destroy for MD5, SHA1, SHA256, SHA384, SHA512
 * and lws_genhmac_init/update/destroy for SHA256, SHA384, SHA512.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS)

#include "private-lib-core.h"
#include "private-lib-tls.h"

#include <string.h>

/*
 * Helpers
 */

static int
hex2byte(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int
hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
	size_t i;

	for (i = 0; i < out_len; i++) {
		int hi, lo;

		hi = hex2byte(hex[2 * i]);
		lo = hex2byte(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return 1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}

	return 0;
}

static void
print_hex(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		lwsl_err("%02x", buf[i]);
}

/*
 * Test a single hash: init -> update(data, len) -> destroy(result),
 * then compare against expected hex string.
 */
static int
test_hash(enum lws_genhash_types type, const void *data, size_t data_len,
	  const char *expected_hex)
{
	struct lws_genhash_ctx ctx;
	uint8_t result[LWS_GENHASH_LARGEST];
	size_t hsize = lws_genhash_size(type);
	size_t hex_len = strlen(expected_hex);
	int ret = 0;

	if (hex_len != hsize * 2) {
		lwsl_err("%s: expected hex length %zu != %zu*2 for type %d\n",
			 __func__, hex_len, hsize, type);
		return 1;
	}

	if (lws_genhash_init(&ctx, type)) {
		lwsl_err("%s: init failed for type %d\n", __func__, type);
		return 1;
	}

	if (lws_genhash_update(&ctx, data, data_len)) {
		lwsl_err("%s: update failed for type %d\n", __func__, type);
		lws_genhash_destroy(&ctx, NULL);
		return 1;
	}

	if (lws_genhash_destroy(&ctx, result)) {
		lwsl_err("%s: destroy failed for type %d\n", __func__, type);
		return 1;
	}

	/* decode expected hex and compare */
	{
		uint8_t expected[LWS_GENHASH_LARGEST];

		if (hex_decode(expected_hex, expected, hsize)) {
			lwsl_err("%s: bad hex input for type %d\n",
				 __func__, type);
			return 1;
		}

		if (memcmp(result, expected, hsize)) {
			lwsl_err("%s: mismatch for type %d\n  got:      ",
				 __func__, type);
			print_hex(result, hsize);
			lwsl_err("\n  expected: %s\n", expected_hex);
			ret = 1;
		}
	}

	return ret;
}

/* ------------------------------------------------------------------ */
/* Known test vectors                                                  */
/* ------------------------------------------------------------------ */

/* MD5 test vectors */
static const char md5_empty[]    = "d41d8cd98f00b204e9800998ecf8427e";
static const char md5_abc[]      = "900150983cd24fb0d6963f7d28e17f72";

/* SHA-1 test vectors */
static const char sha1_empty[]   = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
static const char sha1_abc[]     = "a9993e364706816aba3e25717850c26c9cd0d89d";

/* SHA-256 test vectors */
static const char sha256_empty[] =
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char sha256_abc[]   =
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/* SHA-384 test vectors */
static const char sha384_empty[] =
	"38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
	"4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
static const char sha384_abc[]   =
	"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
	"1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";

/* SHA-512 test vectors */
static const char sha512_empty[] =
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715d"
	"c83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec"
	"2f63b931bd47417a81a538327af927da3e";
static const char sha512_abc[]   =
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea"
	"20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
	"454d4423643ce80e2a9ac94fa54ca49f";

/* NIST SHA-1 448-bit (two-block) test vector */
static const char nist_long[] =
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char sha1_nist_long[] =
	"84983e441c3bd26ebaae4aa1f95129e5e54670f1";

/* ------------------------------------------------------------------ */
/* Hash tests                                                          */
/* ------------------------------------------------------------------ */

static int
test_genhash_all(void)
{
	int e = 0;

	lwsl_user("  Hash: MD5\n");
	e |= test_hash(LWS_GENHASH_TYPE_MD5, "", 0, md5_empty);
	e |= test_hash(LWS_GENHASH_TYPE_MD5, "abc", 3, md5_abc);

	lwsl_user("  Hash: SHA-1\n");
	e |= test_hash(LWS_GENHASH_TYPE_SHA1, "", 0, sha1_empty);
	e |= test_hash(LWS_GENHASH_TYPE_SHA1, "abc", 3, sha1_abc);
	e |= test_hash(LWS_GENHASH_TYPE_SHA1, nist_long, strlen(nist_long),
		       sha1_nist_long);

	lwsl_user("  Hash: SHA-256\n");
	e |= test_hash(LWS_GENHASH_TYPE_SHA256, "", 0, sha256_empty);
	e |= test_hash(LWS_GENHASH_TYPE_SHA256, "abc", 3, sha256_abc);

	lwsl_user("  Hash: SHA-384\n");
	e |= test_hash(LWS_GENHASH_TYPE_SHA384, "", 0, sha384_empty);
	e |= test_hash(LWS_GENHASH_TYPE_SHA384, "abc", 3, sha384_abc);

	lwsl_user("  Hash: SHA-512\n");
	e |= test_hash(LWS_GENHASH_TYPE_SHA512, "", 0, sha512_empty);
	e |= test_hash(LWS_GENHASH_TYPE_SHA512, "abc", 3, sha512_abc);

	return e;
}

/* ------------------------------------------------------------------ */
/* Edge-case / code-path coverage tests                                */
/* ------------------------------------------------------------------ */

static int
test_genhash_edge_cases(void)
{
	struct lws_genhash_ctx ctx;
	uint8_t result[LWS_GENHASH_LARGEST];
	int e = 0;

	/* --- lws_genhash_update with len=0 returns 0 (early return) --- */
	lwsl_user("  Edge: update with len=0\n");
	if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: init failed\n", __func__);
		return 1;
	}
	/* update with len=0 should succeed without touching the hash */
	if (lws_genhash_update(&ctx, "irrelevant", 0)) {
		lwsl_err("%s: update(len=0) returned nonzero\n", __func__);
		e |= 1;
	}
	/* destroy with result to verify hash of empty string is correct */
	if (lws_genhash_destroy(&ctx, result)) {
		lwsl_err("%s: destroy after update(len=0) failed\n", __func__);
		e |= 1;
	} else {
		uint8_t expected[32];
		hex_decode(sha256_empty, expected, 32);
		if (memcmp(result, expected, 32)) {
			lwsl_err("%s: hash mismatch after update(len=0)\n",
				 __func__);
			e |= 1;
		}
	}

	/* --- lws_genhash_destroy with NULL result (just frees) --- */
	lwsl_user("  Edge: destroy with NULL result\n");
	if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: init failed for NULL-result test\n", __func__);
		return 1;
	}
	if (lws_genhash_update(&ctx, "abc", 3)) {
		lwsl_err("%s: update failed for NULL-result test\n", __func__);
		lws_genhash_destroy(&ctx, NULL);
		return 1;
	}
	/* destroy with NULL should just free and return 0 */
	if (lws_genhash_destroy(&ctx, NULL)) {
		lwsl_err("%s: destroy(NULL result) returned nonzero\n",
			 __func__);
		e |= 1;
	}

	/* --- lws_genhash_destroy on already-freed ctx (ctx->ctx == NULL) --- */
	lwsl_user("  Edge: destroy on already-freed ctx\n");
	/* ctx was already destroyed above, so ctx.ctx is now NULL */
	if (lws_genhash_destroy(&ctx, result)) {
		lwsl_err("%s: destroy on already-freed ctx returned nonzero\n",
			 __func__);
		e |= 1;
	}

	/* --- multi-update: hash in two parts --- */
	lwsl_user("  Edge: multi-update hash\n");
	if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: init failed for multi-update\n", __func__);
		return 1;
	}
	if (lws_genhash_update(&ctx, "ab", 2) ||
	    lws_genhash_update(&ctx, "c", 1)) {
		lwsl_err("%s: multi-update failed\n", __func__);
		lws_genhash_destroy(&ctx, NULL);
		return 1;
	}
	if (lws_genhash_destroy(&ctx, result)) {
		lwsl_err("%s: destroy after multi-update failed\n", __func__);
		e |= 1;
	} else {
		uint8_t expected[32];
		hex_decode(sha256_abc, expected, 32);
		if (memcmp(result, expected, 32)) {
			lwsl_err("%s: multi-update hash mismatch\n", __func__);
			print_hex(result, 32);
			lwsl_err("\n  expected: %s\n", sha256_abc);
			e |= 1;
		}
	}

	return e;
}

/* ------------------------------------------------------------------ */
/* HMAC tests                                                          */
/* ------------------------------------------------------------------ */

/*
 * HMAC test vectors from RFC 4231, Test Case 1:
 *   Key       = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
 *   Data      = "Hi There" (8 bytes)
 */
static const uint8_t hmac_key[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b
};
static const uint8_t hmac_data[] = "Hi There";

/* HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 */
static const char hmac256_expected[] =
	"b0344c61d8db38535ca8afceaf0bf12b"
	"881dc200c9833da726e9376c2e32cff7";

/* HMAC-SHA-384 = afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6 */
static const char hmac384_expected[] =
	"afd03944d84895626b0825f4ab46907f"
	"15f9dadbe4101ec682aa034c7cebc59c"
	"faea9ea9076ede7f4af152e8b2fa9cb6";

/* HMAC-SHA-512 = 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854 */
static const char hmac512_expected[] =
	"87aa7cdea5ef619d4ff0b4241a1d6cb0"
	"2379f4e2ce4ec2787ad0b30545e17cde"
	"daa833b7d6b8a702038b274eaea3f4e4"
	"be9d914eeb61f1702e696c203a126854";

static int
test_hmac(enum lws_genhmac_types type, const uint8_t *key, size_t key_len,
	  const uint8_t *data, size_t data_len, const char *expected_hex)
{
	struct lws_genhmac_ctx ctx;
	uint8_t result[64]; /* LWS_GENHASH_LARGEST */
	size_t hsize = lws_genhmac_size(type);
	uint8_t expected[64];
	int ret = 0;

	if (hsize == 0) {
		lwsl_err("%s: unknown hmac type %d\n", __func__, type);
		return 1;
	}

	if (hex_decode(expected_hex, expected, hsize)) {
		lwsl_err("%s: bad hex for hmac type %d\n", __func__, type);
		return 1;
	}

	if (lws_genhmac_init(&ctx, type, key, key_len)) {
		lwsl_err("%s: hmac init failed for type %d\n", __func__, type);
		return 1;
	}

	if (lws_genhmac_update(&ctx, data, data_len)) {
		lwsl_err("%s: hmac update failed for type %d\n",
			 __func__, type);
		lws_genhmac_destroy(&ctx, NULL);
		return 1;
	}

	if (lws_genhmac_destroy(&ctx, result)) {
		lwsl_err("%s: hmac destroy failed for type %d\n",
			 __func__, type);
		return 1;
	}

	if (memcmp(result, expected, hsize)) {
		lwsl_err("%s: hmac mismatch for type %d\n  got:      ",
			 __func__, type);
		print_hex(result, hsize);
		lwsl_err("\n  expected: %s\n", expected_hex);
		ret = 1;
	}

	return ret;
}

static int
test_genhmac_all(void)
{
	int e = 0;

	lwsl_user("  HMAC: SHA-256\n");
	e |= test_hmac(LWS_GENHMAC_TYPE_SHA256,
		       hmac_key, sizeof(hmac_key),
		       hmac_data, sizeof(hmac_data) - 1,
		       hmac256_expected);

	lwsl_user("  HMAC: SHA-384\n");
	e |= test_hmac(LWS_GENHMAC_TYPE_SHA384,
		       hmac_key, sizeof(hmac_key),
		       hmac_data, sizeof(hmac_data) - 1,
		       hmac384_expected);

	lwsl_user("  HMAC: SHA-512\n");
	e |= test_hmac(LWS_GENHMAC_TYPE_SHA512,
		       hmac_key, sizeof(hmac_key),
		       hmac_data, sizeof(hmac_data) - 1,
		       hmac512_expected);

	return e;
}

static int
test_genhmac_edge_cases(void)
{
	struct lws_genhmac_ctx ctx;
	int e = 0;

	/* --- lws_genhmac_destroy with NULL result calls MacDeinit --- */
	lwsl_user("  Edge: hmac destroy with NULL result\n");
	if (lws_genhmac_init(&ctx, LWS_GENHMAC_TYPE_SHA256,
			     hmac_key, sizeof(hmac_key))) {
		lwsl_err("%s: hmac init failed for NULL-result test\n",
			 __func__);
		return 1;
	}
	if (lws_genhmac_update(&ctx, hmac_data, sizeof(hmac_data) - 1)) {
		lwsl_err("%s: hmac update failed for NULL-result test\n",
			 __func__);
		lws_genhmac_destroy(&ctx, NULL);
		return 1;
	}
	/* destroy with NULL should call MacDeinit then free, return 0 */
	if (lws_genhmac_destroy(&ctx, NULL)) {
		lwsl_err("%s: hmac destroy(NULL) returned nonzero\n",
			 __func__);
		e |= 1;
	}

	/* --- lws_genhmac_destroy on already-freed ctx (ctx->ctx == NULL) --- */
	lwsl_user("  Edge: hmac destroy on already-freed ctx\n");
	if (lws_genhmac_destroy(&ctx, NULL)) {
		lwsl_err("%s: hmac destroy on freed ctx returned nonzero\n",
			 __func__);
		e |= 1;
	}

	return e;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int e = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: OpenHiTLS genhash / genhmac\n");

	memset(&info, 0, sizeof(info));
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lwsl_user("Testing genhash...\n");
	e |= test_genhash_all();
	e |= test_genhash_edge_cases();

	lwsl_user("Testing genhmac...\n");
	e |= test_genhmac_all();
	e |= test_genhmac_edge_cases();

	if (e)
		lwsl_err("%s: FAILED\n", __func__);
	else
		lwsl_user("%s: PASS\n", __func__);

	lws_context_destroy(context);

	return e;
}

#else /* !LWS_WITH_OPENHITLS */

int
main(void)
{
	lwsl_err("This test requires LWS_WITH_OPENHITLS\n");
	return 0;
}

#endif /* LWS_WITH_OPENHITLS */
