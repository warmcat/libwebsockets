/*
 * lws-api-test-genkem
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Selftests for the generic KEM (ML-KEM, FIPS 203) apis, which work the same
 * whatever the TLS backend, using its ML-KEM if it has one, or lws's own.
 *
 * For each of ML-KEM-512, -768 and -1024 we check:
 *
 *  - known answers made by a different implementation (OpenSSL 3.5's): the
 *    keypair from a fixed seed, decapsulating a fixed ciphertext to its
 *    shared secret, and the implicit rejection shared secret for a tampered
 *    copy of it
 *  - restoring the keypair from its seed, its DK, and using just its EK
 *  - round trips with random keypairs
 *  - that bad keys, lengths and api misuse are refused
 */

#include <libwebsockets.h>
#include "kat-vectors.h"

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

struct kat {
	enum lws_genkem_alg	alg;
	const char		*ek_sha256;
	const char		*dk_sha256;
	const char		*ct;
	const char		*ss;
	const char		*rej_ss;
};

static const struct kat kats[] = {
	{ LWS_GENKEM_ML_KEM_512, kat512_ek_sha256, kat512_dk_sha256,
	  kat512_ct, kat512_ss, kat512_rej_ss },
	{ LWS_GENKEM_ML_KEM_768, kat768_ek_sha256, kat768_dk_sha256,
	  kat768_ct, kat768_ss, kat768_rej_ss },
	{ LWS_GENKEM_ML_KEM_1024, kat1024_ek_sha256, kat1024_dk_sha256,
	  kat1024_ct, kat1024_ss, kat1024_rej_ss },
};

static uint8_t seed[LWS_GENKEM_SEED_LEN], ct[LWS_GENKEM_MAX_CT_LEN],
	       ct2[LWS_GENKEM_MAX_CT_LEN], bad[LWS_GENKEM_MAX_DK_LEN];

#define CHECK(_c) if (!(_c)) { \
		lwsl_err("%s: %s: line %d: failed: %s\n", __func__, \
			 info->name, __LINE__, #_c); goto bail; }

static int
hex_matches(const char *hex, const uint8_t *buf, size_t len)
{
	uint8_t want[LWS_GENKEM_MAX_CT_LEN];

	if (lws_hex_to_byte_array(hex, want, sizeof(want)) != (int)len)
		return 0;

	return !memcmp(want, buf, len);
}

static int
sha256_matches(const char *hex, const uint8_t *buf, size_t len)
{
	struct lws_genhash_ctx h;
	uint8_t dig[32];

	if (lws_genhash_init(&h, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&h, buf, len) ||
	    lws_genhash_destroy(&h, dig))
		return 0;

	return hex_matches(hex, dig, sizeof(dig));
}

/* decapsulates the KAT ciphertext, and a tampered copy, with a ready ctx */
static int
check_kat_decaps(struct lws_genkem_ctx *ctx, const struct kat *k,
		 const struct lws_genkem_info *info)
{
	uint8_t ss[LWS_GENKEM_SS_LEN];

	CHECK(lws_hex_to_byte_array(k->ct, ct, sizeof(ct)) ==
							(int)info->ct_len);

	CHECK(!lws_genkem_decapsulate(ctx, ct, info->ct_len, ss));
	CHECK(hex_matches(k->ss, ss, sizeof(ss)));

	/* FIPS 203 implicit rejection: no error, but J(z || c) */

	ct[5] ^= 1;
	CHECK(!lws_genkem_decapsulate(ctx, ct, info->ct_len, ss));
	CHECK(hex_matches(k->rej_ss, ss, sizeof(ss)));
	ct[5] ^= 1;

	return 0;

bail:
	return 1;
}

static int
test_kat(struct lws_context *context, const struct kat *k)
{
	const struct lws_genkem_info *info = lws_genkem_info(k->alg);
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_KEM_KEYEL_COUNT],
				     el2[LWS_GENCRYPTO_KEM_KEYEL_COUNT];
	uint8_t ss[LWS_GENKEM_SS_LEN], ss2[LWS_GENKEM_SS_LEN];
	struct lws_genkem_ctx ctx, ctx2;
	unsigned int n;

	memset(&ctx, 0, sizeof(ctx));
	memset(&ctx2, 0, sizeof(ctx2));
	memset(el, 0, sizeof(el));
	memset(el2, 0, sizeof(el2));

	for (n = 0; n < sizeof(seed); n++)
		seed[n] = (uint8_t)n;

	/* the keypair from the KAT seed */

	CHECK(!lws_genkem_create(&ctx, context, k->alg));
	CHECK(!lws_genkem_new_keypair(&ctx, seed, el));
	lwsl_user("%s: %s using %s ML-KEM\n", __func__, info->name,
		  ctx.engine ? "the TLS library's" : "lws's");

	CHECK(el[LWS_GENCRYPTO_KEM_KEYEL_EK].len == info->ek_len);
	CHECK(el[LWS_GENCRYPTO_KEM_KEYEL_DK].len == info->dk_len);
	CHECK(el[LWS_GENCRYPTO_KEM_KEYEL_SEED].len == sizeof(seed));
	CHECK(!memcmp(el[LWS_GENCRYPTO_KEM_KEYEL_SEED].buf, seed,
		      sizeof(seed)));
	CHECK(sha256_matches(k->ek_sha256, el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf,
			     info->ek_len));
	CHECK(sha256_matches(k->dk_sha256, el[LWS_GENCRYPTO_KEM_KEYEL_DK].buf,
			     info->dk_len));

	CHECK(!check_kat_decaps(&ctx, k, info));

	/* restored from just the seed */

	CHECK(!lws_genkem_create(&ctx2, context, k->alg));
	el2[LWS_GENCRYPTO_KEM_KEYEL_SEED] = el[LWS_GENCRYPTO_KEM_KEYEL_SEED];
	CHECK(!lws_genkem_set_key(&ctx2, el2));
	CHECK(!check_kat_decaps(&ctx2, k, info));

	/* restored from just the DK, and the DK with its own EK */

	memset(el2, 0, sizeof(el2));
	el2[LWS_GENCRYPTO_KEM_KEYEL_DK] = el[LWS_GENCRYPTO_KEM_KEYEL_DK];
	CHECK(!lws_genkem_set_key(&ctx2, el2));
	CHECK(!check_kat_decaps(&ctx2, k, info));
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK] = el[LWS_GENCRYPTO_KEM_KEYEL_EK];
	CHECK(!lws_genkem_set_key(&ctx2, el2));
	CHECK(!check_kat_decaps(&ctx2, k, info));

	/* just the EK can encapsulate to the keypair, but not decapsulate */

	memset(el2, 0, sizeof(el2));
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK] = el[LWS_GENCRYPTO_KEM_KEYEL_EK];
	CHECK(!lws_genkem_set_key(&ctx2, el2));
	CHECK(lws_genkem_encapsulate(&ctx2, ct, info->ct_len - 1u, ss));
	CHECK(!lws_genkem_encapsulate(&ctx2, ct, sizeof(ct), ss));
	CHECK(!lws_genkem_decapsulate(&ctx, ct, info->ct_len, ss2));
	CHECK(!memcmp(ss, ss2, sizeof(ss)));
	CHECK(lws_genkem_decapsulate(&ctx2, ct, info->ct_len, ss2));

	/* encapsulation is randomized */

	CHECK(!lws_genkem_encapsulate(&ctx2, ct2, sizeof(ct2), ss2));
	CHECK(memcmp(ct, ct2, info->ct_len) && memcmp(ss, ss2, sizeof(ss)));

	/* wrong ciphertext lengths */

	CHECK(lws_genkem_decapsulate(&ctx, ct, info->ct_len - 1u, ss2));
	CHECK(lws_genkem_decapsulate(&ctx, ct, info->ct_len + 1u, ss2));

	/* an EK with a coefficient that is not < q (FIPS 203 7.2) */

	memcpy(bad, el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf, info->ek_len);
	bad[0] = 0xff;
	bad[1] = (uint8_t)(bad[1] | 0x0f);	/* first coefficient 0xfff */
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK].buf = bad;
	CHECK(lws_genkem_set_key(&ctx2, el2));

	/* an EK of the wrong length */

	el2[LWS_GENCRYPTO_KEM_KEYEL_EK] = el[LWS_GENCRYPTO_KEM_KEYEL_EK];
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK].len--;
	CHECK(lws_genkem_set_key(&ctx2, el2));

	/* a DK whose embedded H(ek) is wrong (FIPS 203 7.3) */

	memset(el2, 0, sizeof(el2));
	memcpy(bad, el[LWS_GENCRYPTO_KEM_KEYEL_DK].buf, info->dk_len);
	bad[info->dk_len - 64] ^= 1;
	el2[LWS_GENCRYPTO_KEM_KEYEL_DK].buf = bad;
	el2[LWS_GENCRYPTO_KEM_KEYEL_DK].len = info->dk_len;
	CHECK(lws_genkem_set_key(&ctx2, el2));

	/* a DK given with an EK that is not its own */

	bad[info->dk_len - 64] ^= 1;
	CHECK(!lws_genkem_set_key(&ctx2, el2));
	memcpy(ct2, el[LWS_GENCRYPTO_KEM_KEYEL_EK].buf, info->ek_len);
	ct2[info->ek_len - 1] ^= 1;
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK].buf = ct2;
	el2[LWS_GENCRYPTO_KEM_KEYEL_EK].len = info->ek_len;
	CHECK(lws_genkem_set_key(&ctx2, el2));

	/* a seed of the wrong length, and no key at all */

	memset(el2, 0, sizeof(el2));
	el2[LWS_GENCRYPTO_KEM_KEYEL_SEED].buf = seed;
	el2[LWS_GENCRYPTO_KEM_KEYEL_SEED].len = sizeof(seed) - 1;
	CHECK(lws_genkem_set_key(&ctx2, el2));
	memset(el2, 0, sizeof(el2));
	CHECK(lws_genkem_set_key(&ctx2, el2));

	/* creating over a live ctx is refused, a destroyed one is fine */

	CHECK(lws_genkem_create(&ctx2, context, k->alg));
	lws_genkem_destroy(&ctx2);
	CHECK(!lws_genkem_create(&ctx2, context, k->alg));

	/* a ctx without a key can do nothing */

	CHECK(lws_genkem_encapsulate(&ctx2, ct, sizeof(ct), ss));
	CHECK(lws_genkem_decapsulate(&ctx2, ct, info->ct_len, ss));

	lws_genkem_destroy(&ctx2);
	lws_genkem_destroy(&ctx);
	lws_genkem_destroy_elements(el);

	return 0;

bail:
	lws_genkem_destroy(&ctx2);
	lws_genkem_destroy(&ctx);
	lws_genkem_destroy_elements(el);

	return 1;
}

static int
test_random(struct lws_context *context, enum lws_genkem_alg alg)
{
	const struct lws_genkem_info *info = lws_genkem_info(alg);
	uint8_t ss[LWS_GENKEM_SS_LEN], ss2[LWS_GENKEM_SS_LEN];
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_KEM_KEYEL_COUNT],
				     el_peer[LWS_GENCRYPTO_KEM_KEYEL_COUNT];
	struct lws_genkem_ctx ctx, peer;
	int n;

	memset(&ctx, 0, sizeof(ctx));
	memset(&peer, 0, sizeof(peer));
	memset(el, 0, sizeof(el));
	memset(el_peer, 0, sizeof(el_peer));

	for (n = 0; n < 8; n++) {
		CHECK(!lws_genkem_create(&ctx, context, alg));
		CHECK(!lws_genkem_new_keypair(&ctx, NULL, el));

		/* the peer only gets our EK */

		CHECK(!lws_genkem_create(&peer, context, alg));
		el_peer[LWS_GENCRYPTO_KEM_KEYEL_EK] =
					el[LWS_GENCRYPTO_KEM_KEYEL_EK];
		CHECK(!lws_genkem_set_key(&peer, el_peer));

		CHECK(!lws_genkem_encapsulate(&peer, ct, sizeof(ct), ss));
		CHECK(!lws_genkem_decapsulate(&ctx, ct, info->ct_len, ss2));
		CHECK(!memcmp(ss, ss2, sizeof(ss)));

		lws_genkem_destroy(&peer);
		lws_genkem_destroy(&ctx);
		lws_genkem_destroy_elements(el);
	}

	/* a keypair without taking a copy of the elements */

	CHECK(!lws_genkem_create(&ctx, context, alg));
	CHECK(!lws_genkem_new_keypair(&ctx, NULL, NULL));
	CHECK(!lws_genkem_encapsulate(&ctx, ct, sizeof(ct), ss));
	CHECK(!lws_genkem_decapsulate(&ctx, ct, info->ct_len, ss2));
	CHECK(!memcmp(ss, ss2, sizeof(ss)));
	lws_genkem_destroy(&ctx);

	return 0;

bail:
	lws_genkem_destroy(&peer);
	lws_genkem_destroy(&ctx);
	lws_genkem_destroy_elements(el);

	return 1;
}

int main(int argc, const char **argv)
{
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	unsigned int n;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS genkem apis tests\n");

	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (lws_genkem_info(LWS_GENKEM_COUNT)) {
		lwsl_err("info for an unknown alg\n");
		result = 1;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(kats); n++) {
		result |= test_kat(context, &kats[n]);
		result |= test_random(context, kats[n].alg);
	}

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}
