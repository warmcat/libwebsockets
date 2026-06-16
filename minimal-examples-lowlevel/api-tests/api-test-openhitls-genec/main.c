/*
 * lws-api-test-openhitls-genec
 *
 * Unit tests for OpenHiTLS EC cryptography (lws-genec.c):
 *   - ECDH key generation and shared secret computation
 *   - ECDSA sign / verify roundtrip
 *   - Curve interoperability (P-256, P-384)
 *   - Edge-case and error handling
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_OPENHITLS) && defined(LWS_WITH_GENCRYPTO)

#include "private-lib-core.h"
#include "private-lib-tls.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void
destroy_el(struct lws_gencrypto_keyelem *el)
{
	lws_genec_destroy_elements(el);
	memset(el, 0, sizeof(*el) * LWS_GENCRYPTO_EC_KEYEL_COUNT);
}

/*
 * Build a public-only key element set (CRV, X, Y -- no D) from a
 * full key element array.  The pointers are shared (not copied), so
 * the source el must outlive the peer.
 */
static void
copy_pub_only(struct lws_gencrypto_keyelem *dst,
	      const struct lws_gencrypto_keyelem *src)
{
	memset(dst, 0, sizeof(*dst) * LWS_GENCRYPTO_EC_KEYEL_COUNT);

	dst[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = src[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
	dst[LWS_GENCRYPTO_EC_KEYEL_CRV].len = src[LWS_GENCRYPTO_EC_KEYEL_CRV].len;
	dst[LWS_GENCRYPTO_EC_KEYEL_X].buf = src[LWS_GENCRYPTO_EC_KEYEL_X].buf;
	dst[LWS_GENCRYPTO_EC_KEYEL_X].len = src[LWS_GENCRYPTO_EC_KEYEL_X].len;
	dst[LWS_GENCRYPTO_EC_KEYEL_Y].buf = src[LWS_GENCRYPTO_EC_KEYEL_Y].buf;
	dst[LWS_GENCRYPTO_EC_KEYEL_Y].len = src[LWS_GENCRYPTO_EC_KEYEL_Y].len;
	/* D is NULL / 0 -- public-only */
}

/* ------------------------------------------------------------------ */
/* A) ECDH key generation + shared secret (P-256)                    */
/* ------------------------------------------------------------------ */

static int
test_ecdh_p256(struct lws_context *context)
{
	struct lws_genec_ctx ctx_a, ctx_b;
	struct lws_gencrypto_keyelem el_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem el_b[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem peer_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem peer_b[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t ss_a[64], ss_b[64];
	int ss_a_len, ss_b_len;

	lwsl_user("  A) ECDH P-256 key gen + shared secret\n");

	memset(el_a, 0, sizeof(el_a));
	memset(el_b, 0, sizeof(el_b));
	memset(peer_a, 0, sizeof(peer_a));
	memset(peer_b, 0, sizeof(peer_b));

	/* Create two ECDH contexts */
	if (lws_genecdh_create(&ctx_a, context, NULL) ||
	    lws_genecdh_create(&ctx_b, context, NULL)) {
		lwsl_err("%s: create failed\n", __func__);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/* Generate keypairs on both sides */
	if (lws_genecdh_new_keypair(&ctx_a, LDHS_OURS, "P-256", el_a)) {
		lwsl_err("%s: keypair A failed\n", __func__);
		goto bail;
	}
	if (lws_genecdh_new_keypair(&ctx_b, LDHS_OURS, "P-256", el_b)) {
		lwsl_err("%s: keypair B failed\n", __func__);
		destroy_el(el_a);
		goto bail;
	}

	/*
	 * Exchange public keys: pass B's public key to A's THEIRS side
	 * and A's public key to B's THEIRS side, using public-only copies
	 * (no private D element) so the import path handles public keys
	 * correctly.
	 */
	copy_pub_only(peer_a, el_b); /* B's pub -> A's THEIRS */
	copy_pub_only(peer_b, el_a); /* A's pub -> B's THEIRS */

	if (lws_genecdh_set_key(&ctx_a, peer_a, LDHS_THEIRS)) {
		lwsl_err("%s: set_key A theirs failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}
	if (lws_genecdh_set_key(&ctx_b, peer_b, LDHS_THEIRS)) {
		lwsl_err("%s: set_key B theirs failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	/* Compute shared secrets */
	ss_a_len = (int)sizeof(ss_a);
	ss_b_len = (int)sizeof(ss_b);
	if (lws_genecdh_compute_shared_secret(&ctx_a, ss_a, &ss_a_len)) {
		lwsl_err("%s: compute_shared_secret A failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}
	if (lws_genecdh_compute_shared_secret(&ctx_b, ss_b, &ss_b_len)) {
		lwsl_err("%s: compute_shared_secret B failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	/* Verify both shared secrets match */
	if (ss_a_len != ss_b_len || ss_a_len != 32 ||
	    lws_timingsafe_bcmp(ss_a, ss_b, (uint32_t)ss_a_len)) {
		lwsl_err("%s: shared secrets don't match (len %d vs %d)\n",
			 __func__, ss_a_len, ss_b_len);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	lwsl_user("    P-256 shared secret: %d bytes, both sides match OK\n",
		  ss_a_len);

	destroy_el(el_a);
	destroy_el(el_b);
	lws_genec_destroy(&ctx_a);
	lws_genec_destroy(&ctx_b);
	return 0;

bail:
	lws_genec_destroy(&ctx_a);
	lws_genec_destroy(&ctx_b);
	return 1;
}

/* ------------------------------------------------------------------ */
/* B) ECDSA sign + verify roundtrip (P-256)                          */
/* ------------------------------------------------------------------ */

static int
test_ecdsa_p256(struct lws_context *context)
{
	struct lws_genec_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_genhash_ctx hash_ctx;
	uint8_t hash[32], sig[64], wrong_hash[32];
	int n;

	lwsl_user("  B) ECDSA P-256 sign + verify roundtrip\n");

	memset(el, 0, sizeof(el));

	/* Create ECDSA context */
	if (lws_genecdsa_create(&ctx, context, NULL)) {
		lwsl_err("%s: lws_genecdsa_create failed\n", __func__);
		return 1;
	}

	/* Generate keypair */
	if (lws_genecdsa_new_keypair(&ctx, "P-256", el)) {
		lwsl_err("%s: new_keypair failed\n", __func__);
		lws_genec_destroy(&ctx);
		return 1;
	}

	/* Hash a test message with SHA-256 */
	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
		lwsl_err("%s: hash init failed\n", __func__);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}
	if (lws_genhash_update(&hash_ctx, "test message for ecdsa signing", 30)) {
		lws_genhash_destroy(&hash_ctx, NULL);
		lwsl_err("%s: hash update failed\n", __func__);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}
	if (lws_genhash_destroy(&hash_ctx, hash)) {
		lwsl_err("%s: hash final failed\n", __func__);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}

	/* Sign the hash */
	n = lws_genecdsa_hash_sign_jws(&ctx, hash, LWS_GENHASH_TYPE_SHA256,
					256, sig, sizeof(sig));
	if (n) {
		lwsl_err("%s: hash_sign_jws failed: %d\n", __func__, n);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}

	/* Verify with correct hash -- must succeed */
	n = lws_genecdsa_hash_sig_verify_jws(&ctx, hash,
					      LWS_GENHASH_TYPE_SHA256,
					      256, sig, sizeof(sig));
	if (n) {
		lwsl_err("%s: verify with correct hash failed: %d\n",
			 __func__, n);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}

	/* Verify with wrong hash -- must fail */
	memset(wrong_hash, 0xAA, sizeof(wrong_hash));
	n = lws_genecdsa_hash_sig_verify_jws(&ctx, wrong_hash,
					      LWS_GENHASH_TYPE_SHA256,
					      256, sig, sizeof(sig));
	if (n == 0) {
		lwsl_err("%s: verify with WRONG hash unexpectedly succeeded\n",
			 __func__);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}

	lwsl_user("    sign + verify OK, wrong-hash rejection OK\n");

	destroy_el(el);
	lws_genec_destroy(&ctx);
	return 0;
}

/* ------------------------------------------------------------------ */
/* C) ECDH P-384 curve test                                          */
/* ------------------------------------------------------------------ */

static int
test_ecdh_p384(struct lws_context *context)
{
	struct lws_genec_ctx ctx_a, ctx_b;
	struct lws_gencrypto_keyelem el_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem el_b[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem peer_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem peer_b[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t ss_a[96], ss_b[96];
	int ss_a_len, ss_b_len;

	lwsl_user("  C) ECDH P-384 key gen + shared secret\n");

	memset(el_a, 0, sizeof(el_a));
	memset(el_b, 0, sizeof(el_b));
	memset(peer_a, 0, sizeof(peer_a));
	memset(peer_b, 0, sizeof(peer_b));

	if (lws_genecdh_create(&ctx_a, context, NULL) ||
	    lws_genecdh_create(&ctx_b, context, NULL)) {
		lwsl_err("%s: create failed\n", __func__);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	if (lws_genecdh_new_keypair(&ctx_a, LDHS_OURS, "P-384", el_a)) {
		lwsl_err("%s: keypair A failed\n", __func__);
		goto bail;
	}
	if (lws_genecdh_new_keypair(&ctx_b, LDHS_OURS, "P-384", el_b)) {
		lwsl_err("%s: keypair B failed\n", __func__);
		destroy_el(el_a);
		goto bail;
	}

	/* Exchange public-only keys */
	copy_pub_only(peer_a, el_b);
	copy_pub_only(peer_b, el_a);

	if (lws_genecdh_set_key(&ctx_a, peer_a, LDHS_THEIRS)) {
		lwsl_err("%s: set_key A theirs failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}
	if (lws_genecdh_set_key(&ctx_b, peer_b, LDHS_THEIRS)) {
		lwsl_err("%s: set_key B theirs failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	ss_a_len = (int)sizeof(ss_a);
	ss_b_len = (int)sizeof(ss_b);
	if (lws_genecdh_compute_shared_secret(&ctx_a, ss_a, &ss_a_len)) {
		lwsl_err("%s: compute_shared_secret A failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}
	if (lws_genecdh_compute_shared_secret(&ctx_b, ss_b, &ss_b_len)) {
		lwsl_err("%s: compute_shared_secret B failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	if (ss_a_len != 48 || ss_b_len != 48 ||
	    lws_timingsafe_bcmp(ss_a, ss_b, (uint32_t)ss_a_len)) {
		lwsl_err("%s: P-384 shared secret mismatch (len %d vs %d)\n",
			 __func__, ss_a_len, ss_b_len);
		destroy_el(el_a);
		destroy_el(el_b);
		goto bail;
	}

	lwsl_user("    P-384 shared secret: %d bytes, both sides match OK\n",
		  ss_a_len);

	destroy_el(el_a);
	destroy_el(el_b);
	lws_genec_destroy(&ctx_a);
	lws_genec_destroy(&ctx_b);
	return 0;

bail:
	lws_genec_destroy(&ctx_a);
	lws_genec_destroy(&ctx_b);
	return 1;
}

/* ------------------------------------------------------------------ */
/* D) Edge cases                                                     */
/* ------------------------------------------------------------------ */

static int
test_edge_cases(struct lws_context *context)
{
	struct lws_genec_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t ss[64];
	int ss_len, n;

	lwsl_user("  D) Edge cases\n");

	/*
	 * D.1: lws_genecdh_create with NULL curve_table should use
	 * default lws_ec_curves -- verify by generating a P-256 keypair.
	 */
	memset(el, 0, sizeof(el));
	if (lws_genecdh_create(&ctx, context, NULL)) {
		lwsl_err("%s: D.1 create NULL curve_table failed\n", __func__);
		return 1;
	}
	if (lws_genecdh_new_keypair(&ctx, LDHS_OURS, "P-256", el)) {
		lwsl_err("%s: D.1 keypair on default table failed\n", __func__);
		lws_genec_destroy(&ctx);
		return 1;
	}
	destroy_el(el);
	lws_genec_destroy(&ctx);
	lwsl_user("    D.1 NULL curve_table -> default table OK\n");

	/*
	 * D.2: lws_genecdh_compute_shared_secret with only one side set
	 * (only OURS, no THEIRS) should return -1.
	 */
	memset(el, 0, sizeof(el));
	if (lws_genecdh_create(&ctx, context, NULL)) {
		lwsl_err("%s: D.2 create failed\n", __func__);
		return 1;
	}
	if (lws_genecdh_new_keypair(&ctx, LDHS_OURS, "P-256", el)) {
		lwsl_err("%s: D.2 keypair failed\n", __func__);
		lws_genec_destroy(&ctx);
		return 1;
	}
	ss_len = (int)sizeof(ss);
	n = lws_genecdh_compute_shared_secret(&ctx, ss, &ss_len);
	if (n != -1) {
		lwsl_err("%s: D.2 compute_shared_secret with only OURS "
			 "should return -1, got %d\n", __func__, n);
		destroy_el(el);
		lws_genec_destroy(&ctx);
		return 1;
	}
	destroy_el(el);
	lws_genec_destroy(&ctx);
	lwsl_user("    D.2 compute_shared_secret with one side -> -1 OK\n");

	/*
	 * D.3: Wrong algorithm type.
	 *   a) lws_genecdh_set_key on an ECDSA context -> -1
	 *   b) lws_genecdsa_set_key on an ECDH context -> -1
	 */
	{
		const char *crv = "P-256";
		struct lws_gencrypto_keyelem dummy[LWS_GENCRYPTO_EC_KEYEL_COUNT];

		/* D.3a: ECDH set_key on ECDSA ctx */
		if (lws_genecdsa_create(&ctx, context, NULL)) {
			lwsl_err("%s: D.3a ecdsa create failed\n", __func__);
			return 1;
		}
		memset(dummy, 0, sizeof(dummy));
		dummy[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = (uint8_t *)crv;
		dummy[LWS_GENCRYPTO_EC_KEYEL_CRV].len = 6;
		n = lws_genecdh_set_key(&ctx, dummy, LDHS_OURS);
		if (n != -1) {
			lwsl_err("%s: D.3a ECDH set_key on ECDSA ctx: "
				 "expected -1, got %d\n", __func__, n);
			lws_genec_destroy(&ctx);
			return 1;
		}
		lws_genec_destroy(&ctx);

		/* D.3b: ECDSA set_key on ECDH ctx */
		if (lws_genecdh_create(&ctx, context, NULL)) {
			lwsl_err("%s: D.3b ecdh create failed\n", __func__);
			return 1;
		}
		memset(dummy, 0, sizeof(dummy));
		dummy[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = (uint8_t *)crv;
		dummy[LWS_GENCRYPTO_EC_KEYEL_CRV].len = 6;
		n = lws_genecdsa_set_key(&ctx, dummy);
		if (n != -1) {
			lwsl_err("%s: D.3b ECDSA set_key on ECDH ctx: "
				 "expected -1, got %d\n", __func__, n);
			lws_genec_destroy(&ctx);
			return 1;
		}
		lws_genec_destroy(&ctx);
	}
	lwsl_user("    D.3 wrong algorithm type -> -1 OK\n");

	/*
	 * D.4: lws_genec_destroy handles zeroed / NULL-ctx-pointer contexts
	 * without crashing.
	 */
	{
		struct lws_genec_ctx clean;
		memset(&clean, 0, sizeof(clean));
		/* Must not crash */
		lws_genec_destroy(&clean);
	}
	lwsl_user("    D.4 lws_genec_destroy with NULL ctx pointers OK\n");

	return 0;
}

/* ------------------------------------------------------------------ */
/* E) ECDH set_key with imported key elements (P-256)                */
/* ------------------------------------------------------------------ */

static int
test_ecdh_set_key(struct lws_context *context)
{
	struct lws_genec_ctx ctx_a, ctx_b;
	struct lws_gencrypto_keyelem el_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem el_b_theirs[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem peer_for_a[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t ss_a[64], ss_b[64];
	int ss_a_len, ss_b_len, n;

	lwsl_user("  E) ECDH set_key with imported key elements (P-256)\n");

	memset(el_a, 0, sizeof(el_a));
	memset(el_b_theirs, 0, sizeof(el_b_theirs));
	memset(peer_for_a, 0, sizeof(peer_for_a));

	/* Generate keypair A */
	if (lws_genecdh_create(&ctx_a, context, NULL)) {
		lwsl_err("%s: genecdh_create A failed\n", __func__);
		return 1;
	}
	if (lws_genecdh_new_keypair(&ctx_a, LDHS_OURS, "P-256", el_a)) {
		lwsl_err("%s: new_keypair A failed\n", __func__);
		lws_genec_destroy(&ctx_a);
		return 1;
	}

	/* Create new ECDH context B */
	if (lws_genecdh_create(&ctx_b, context, NULL)) {
		lwsl_err("%s: genecdh_create B failed\n", __func__);
		destroy_el(el_a);
		lws_genec_destroy(&ctx_a);
		return 1;
	}

	/*
	 * Set B's OURS key from A's key elements using lws_genecdh_set_key.
	 * This exercises the import path with externally-provided key
	 * elements (CRV, X, Y, D) including the private key.
	 */
	n = lws_genecdh_set_key(&ctx_b, el_a, LDHS_OURS);
	if (n) {
		lwsl_err("%s: set_key B from A elements failed: %d\n",
			 __func__, n);
		destroy_el(el_a);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/*
	 * Now both ctx_a and ctx_b share the same private key for OURS.
	 * Generate a fresh THEIRS side on ctx_b and use that as THEIRS on
	 * ctx_a as well, then verify the shared secrets match.
	 */
	if (lws_genecdh_new_keypair(&ctx_b, LDHS_THEIRS, "P-256",
				    el_b_theirs)) {
		lwsl_err("%s: new_keypair B THEIRS failed\n", __func__);
		destroy_el(el_a);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/* Set B's THEIRS public key as A's THEIRS (public-only) */
	copy_pub_only(peer_for_a, el_b_theirs);
	n = lws_genecdh_set_key(&ctx_a, peer_for_a, LDHS_THEIRS);
	if (n) {
		lwsl_err("%s: set_key A THEIRS failed: %d\n", __func__, n);
		destroy_el(el_a);
		destroy_el(el_b_theirs);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/* Compute shared secret on A */
	ss_a_len = (int)sizeof(ss_a);
	if (lws_genecdh_compute_shared_secret(&ctx_a, ss_a, &ss_a_len)) {
		lwsl_err("%s: compute_shared_secret A failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b_theirs);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/* Compute shared secret on B */
	ss_b_len = (int)sizeof(ss_b);
	if (lws_genecdh_compute_shared_secret(&ctx_b, ss_b, &ss_b_len)) {
		lwsl_err("%s: compute_shared_secret B failed\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b_theirs);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	/* Verify both shared secrets match */
	if (ss_a_len != ss_b_len ||
	    lws_timingsafe_bcmp(ss_a, ss_b, (uint32_t)ss_a_len)) {
		lwsl_err("%s: imported-key shared secrets differ\n", __func__);
		destroy_el(el_a);
		destroy_el(el_b_theirs);
		lws_genec_destroy(&ctx_a);
		lws_genec_destroy(&ctx_b);
		return 1;
	}

	lwsl_user("    set_key from imported elements OK, "
		  "shared secrets match (%d bytes)\n", ss_a_len);

	destroy_el(el_a);
	destroy_el(el_b_theirs);
	lws_genec_destroy(&ctx_a);
	lws_genec_destroy(&ctx_b);
	return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
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
	lwsl_user("LWS API selftest: OpenHiTLS genec (EC crypto)\n");

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

	/* A) ECDH P-256 */
	e |= test_ecdh_p256(context);

	/* B) ECDSA P-256 sign + verify */
	e |= test_ecdsa_p256(context);

	/* C) ECDH P-384 */
	e |= test_ecdh_p384(context);

	/* D) Edge cases */
	e |= test_edge_cases(context);

	/* E) ECDH set_key with imported key elements */
	e |= test_ecdh_set_key(context);

	lws_context_destroy(context);

	if (e)
		lwsl_err("%s: FAILED\n", __func__);
	else
		lwsl_user("%s: pass\n", __func__);

	return e;
}

#else /* !LWS_WITH_OPENHITLS || !LWS_WITH_GENCRYPTO */

int
main(void)
{
	lwsl_user("LWS API selftest: OpenHiTLS genec: skipped "
		  "(LWS_WITH_OPENHITLS or LWS_WITH_GENCRYPTO not enabled)\n");

	return 0;
}

#endif /* LWS_WITH_OPENHITLS && LWS_WITH_GENCRYPTO */
