/*
 * lws-api-test-gencrypto - lws-genec
 *
 * Written in 2010-2018 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

static const uint8_t
	*jwk_ec1 = (uint8_t *)
		"{\"kty\":\"EC\","
		  "\"crv\":\"P-256\","
		  "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
		  "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
		  "\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","
		  "\"use\":\"enc\","
		  "\"kid\":\"rfc7517-A.2-example private key\"}"
;

static int
test_genec1(struct lws_context *context)
{
	struct lws_genec_ctx ctx;
	struct lws_jwk jwk;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	//uint8_t res[32], res1[32];
	int n;

	memset(el, 0, sizeof(el));

	if (lws_genecdh_create(&ctx, context, NULL))
		return 1;

	/* let's create a new key */

	if (lws_genecdh_new_keypair(&ctx, LDHS_OURS, "P-256", el)) {
		lwsl_err("%s: lws_genec_new_keypair failed\n", __func__);
		return 1;
	}

	lws_genec_dump(el);
	lws_genec_destroy_elements(el);

	lws_genec_destroy(&ctx);

	if (lws_jwk_import(&jwk, NULL, NULL, (char *)jwk_ec1,
			   strlen((char *)jwk_ec1)) < 0) {
		lwsl_notice("Failed to decode JWK test key\n");
		return 1;
	}

	lws_jwk_dump(&jwk);

	if (jwk.kty != LWS_GENCRYPTO_KTY_EC) {
		lws_jwk_destroy(&jwk);
		lwsl_err("%s: jwk is not an EC key\n", __func__);
		return 1;
	}

	if (lws_genecdh_create(&ctx, context, NULL))
		return 1;

	n = lws_genecdh_set_key(&ctx, jwk.e, LDHS_OURS);
	if (n) {
		lws_jwk_destroy(&jwk);
		lwsl_err("%s: lws_genec_create failed: %d\n", __func__, n);
		return 1;
	}
#if 0
	if (lws_genec_crypt(&ctx, cbc256, 16, res, (uint8_t *)cbc256_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genec_crypt failed\n", __func__);
		goto bail;
	}

	if (lws_timingsafe_bcmp(cbc256_enc, res, 16)) {
		lwsl_err("%s: lws_genec_crypt encoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}

	lws_genec_destroy(&ctx);

	if (lws_genec_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_CBC, &e, NULL)) {
		lwsl_err("%s: lws_genec_create dec failed\n", __func__);
		return -1;
	}

	if (lws_genec_crypt(&ctx, res, 16, res1, (uint8_t *)cbc256_iv,
			     NULL, NULL)) {
		lwsl_err("%s: lws_genec_crypt dec failed\n", __func__);
		goto bail;
	}

	if (lws_timingsafe_bcmp(cbc256, res1, 16)) {
		lwsl_err("%s: lws_genec_crypt decoding mismatch\n", __func__);
		lwsl_hexdump_notice(res, 16);
		goto bail;
	}
#endif
	lws_genec_destroy(&ctx);

	lws_jwk_destroy(&jwk);

	return 0;

//bail:
//	lws_genec_destroy(&ctx);

//	return -1;
}

/*
 * F-036 regression: setting both sides of an ECDH ctx, then re-setting
 * either side, must free the displaced key (no leak) and leave the ctx
 * with last-set-wins state that derives the same secret as a fresh ctx
 * built with the same keys
 */
static int
test_genec2(struct lws_context *context)
{
	struct lws_genec_ctx ctx, fresh, ecdsa, kp[3];
	struct lws_gencrypto_keyelem el[3][LWS_GENCRYPTO_EC_KEYEL_COUNT];
	struct lws_gencrypto_keyelem pub[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	uint8_t hash[32], sig[64];
	uint8_t s_ab[32], s_ac[32], s_ac_fresh[32], s_cc[32], s_cc_fresh[32];
	int ss_len, n;

	memset(el, 0, sizeof(el));
	memset(&ctx, 0, sizeof(ctx));
	memset(&fresh, 0, sizeof(fresh));
	memset(&ecdsa, 0, sizeof(ecdsa));
	memset(kp, 0, sizeof(kp));

	/* three independent P-256 keypairs, exported to elements */

	for (n = 0; n < 3; n++) {
		if (lws_genecdh_create(&kp[n], context, NULL) ||
		    lws_genecdh_new_keypair(&kp[n], LDHS_OURS, "P-256", el[n]))
			goto bail;

		/* the element buffers are copies, the keygen ctx is done */
		lws_genec_destroy(&kp[n]);
	}

	/* a peer-side element set has only the public parts */

	memset(pub, 0, sizeof(pub));
	pub[LWS_GENCRYPTO_EC_KEYEL_CRV] = el[1][LWS_GENCRYPTO_EC_KEYEL_CRV];
	pub[LWS_GENCRYPTO_EC_KEYEL_X]   = el[1][LWS_GENCRYPTO_EC_KEYEL_X];
	pub[LWS_GENCRYPTO_EC_KEYEL_Y]   = el[1][LWS_GENCRYPTO_EC_KEYEL_Y];

	if (lws_genecdh_create(&ctx, context, NULL) ||
	    lws_genecdh_set_key(&ctx, el[0], LDHS_OURS) ||
	    lws_genecdh_set_key(&ctx, pub, LDHS_THEIRS))
		goto bail;

	ss_len = (int)sizeof(s_ab);
	if (lws_genecdh_compute_shared_secret(&ctx, s_ab, &ss_len) ||
	    ss_len != (int)sizeof(s_ab)) {
		lwsl_err("%s: derive 0x1 failed\n", __func__);
		goto bail;
	}

	/* re-set the peer side to keypair 2's public */

	pub[LWS_GENCRYPTO_EC_KEYEL_CRV] = el[2][LWS_GENCRYPTO_EC_KEYEL_CRV];
	pub[LWS_GENCRYPTO_EC_KEYEL_X]   = el[2][LWS_GENCRYPTO_EC_KEYEL_X];
	pub[LWS_GENCRYPTO_EC_KEYEL_Y]   = el[2][LWS_GENCRYPTO_EC_KEYEL_Y];

	if (lws_genecdh_set_key(&ctx, pub, LDHS_THEIRS))
		goto bail;

	ss_len = (int)sizeof(s_ac);
	if (lws_genecdh_compute_shared_secret(&ctx, s_ac, &ss_len) ||
	    ss_len != (int)sizeof(s_ac)) {
		lwsl_err("%s: derive 0x2 failed\n", __func__);
		goto bail;
	}

	/* a different peer must yield a different shared secret */

	if (!memcmp(s_ab, s_ac, sizeof(s_ab))) {
		lwsl_err("%s: peer re-set had no effect\n", __func__);
		goto bail;
	}

	/* ...and the re-set ctx must derive what a fresh ctx derives */

	if (lws_genecdh_create(&fresh, context, NULL) ||
	    lws_genecdh_set_key(&fresh, el[0], LDHS_OURS) ||
	    lws_genecdh_set_key(&fresh, pub, LDHS_THEIRS))
		goto bail;

	ss_len = (int)sizeof(s_ac_fresh);
	if (lws_genecdh_compute_shared_secret(&fresh, s_ac_fresh, &ss_len))
		goto bail;

	if (lws_timingsafe_bcmp(s_ac, s_ac_fresh, sizeof(s_ac))) {
		lwsl_err("%s: re-set peer state != fresh state\n", __func__);
		goto bail;
	}

	lws_genec_destroy(&fresh);

	/* re-set our side to keypair 2 as well (self-agreement) */

	if (lws_genecdh_set_key(&ctx, el[2], LDHS_OURS))
		goto bail;

	ss_len = (int)sizeof(s_cc);
	if (lws_genecdh_compute_shared_secret(&ctx, s_cc, &ss_len) ||
	    ss_len != (int)sizeof(s_cc)) {
		lwsl_err("%s: derive 0x2x0x2 failed\n", __func__);
		goto bail;
	}

	if (!memcmp(s_cc, s_ac, sizeof(s_cc))) {
		lwsl_err("%s: our-side re-set had no effect\n", __func__);
		goto bail;
	}

	if (lws_genecdh_create(&fresh, context, NULL) ||
	    lws_genecdh_set_key(&fresh, el[2], LDHS_OURS) ||
	    lws_genecdh_set_key(&fresh, pub, LDHS_THEIRS))
		goto bail;

	ss_len = (int)sizeof(s_cc_fresh);
	if (lws_genecdh_compute_shared_secret(&fresh, s_cc_fresh, &ss_len))
		goto bail;

	if (lws_timingsafe_bcmp(s_cc, s_cc_fresh, sizeof(s_cc))) {
		lwsl_err("%s: re-set our-side state != fresh state\n", __func__);
		goto bail;
	}

	lws_genec_destroy(&fresh);
	lws_genec_destroy(&ctx);

	/* ECDSA re-set: last-set-wins keeps the ctx usable for signing */

	for (n = 0; n < (int)sizeof(hash); n++)
		hash[n] = (uint8_t)(n * 7);

	if (lws_genecdsa_create(&ecdsa, context, NULL) ||
	    lws_genecdsa_set_key(&ecdsa, el[0]) ||
	    lws_genecdsa_set_key(&ecdsa, el[1]))
		goto bail;

	/* sign returns the sig length, or zero, depending on backend */

	n = lws_genecdsa_hash_sign_jws(&ecdsa, hash,
				       LWS_GENHASH_TYPE_SHA256, 256,
				       sig, sizeof(sig));
	if (n < 0) {
		lwsl_err("%s: sign after ECDSA re-set failed\n", __func__);
		goto bail;
	}

	lws_genec_destroy(&ecdsa);

	for (n = 0; n < 3; n++)
		lws_genec_destroy_elements(el[n]);

	return 0;

bail:
	for (n = 0; n < 3; n++) {
		lws_genec_destroy(&kp[n]);
		lws_genec_destroy_elements(el[n]);
	}
	lws_genec_destroy(&ctx);
	lws_genec_destroy(&fresh);
	lws_genec_destroy(&ecdsa);

	return 1;
}

/*
 * F-040 regression: the v4/PSA import built the peer EC point using X's
 * length for both the X and the Y memcpy, so a full-length X with a short Y
 * read past the end of the Y element's heap allocation.  Elements whose
 * lengths disagree with the curve (or with each other) must be rejected
 * cleanly on every backend.
 */
static int
test_genec3(struct lws_context *context)
{
	static const struct {
		/* element lengths in bytes; 0 for a missing d */
		uint32_t xl, yl, dl;
		const char *crv;
		enum enum_lws_dh_side side;
	} cases[] = {
		/* the finding's worst case: P-521 X with a 1-byte Y */
		{ 66, 1,  0, "P-521", LDHS_THEIRS },
		/* X shorter than the curve length */
		{ 1,  32, 0, "P-256", LDHS_THEIRS },
		/* d present but not at the curve length */
		{ 32, 32, 1, "P-256", LDHS_OURS   },
	};
	struct lws_genec_ctx ctx;
	struct lws_gencrypto_keyelem el[LWS_GENCRYPTO_EC_KEYEL_COUNT];
	char crv[8];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {

		memset(el, 0, sizeof(el));
		memset(&ctx, 0, sizeof(ctx));
		memset(crv, 0, sizeof(crv));
		lws_strncpy(crv, cases[n].crv, sizeof(crv));

		el[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = (uint8_t *)crv;
		el[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(crv) + 1;

		/*
		 * Exact-size heap allocations, so an overlong copy of any
		 * element shows up as an OOB read under ASAN.  The elements
		 * stay owned by the test; the import must only read them.
		 */

		el[LWS_GENCRYPTO_EC_KEYEL_X].buf = malloc(cases[n].xl);
		el[LWS_GENCRYPTO_EC_KEYEL_Y].buf = malloc(cases[n].yl);
		if (cases[n].dl)
			el[LWS_GENCRYPTO_EC_KEYEL_D].buf = malloc(cases[n].dl);
		if (!el[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !el[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
		    (cases[n].dl && !el[LWS_GENCRYPTO_EC_KEYEL_D].buf))
			goto bail;

		memset(el[LWS_GENCRYPTO_EC_KEYEL_X].buf, 0x5a, cases[n].xl);
		memset(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf, 0xa5, cases[n].yl);
		if (cases[n].dl)
			memset(el[LWS_GENCRYPTO_EC_KEYEL_D].buf, 0x33,
			       cases[n].dl);

		el[LWS_GENCRYPTO_EC_KEYEL_X].len = cases[n].xl;
		el[LWS_GENCRYPTO_EC_KEYEL_Y].len = cases[n].yl;
		el[LWS_GENCRYPTO_EC_KEYEL_D].len = cases[n].dl;

		if (lws_genecdh_create(&ctx, context, NULL))
			goto bail;

		if (lws_genecdh_set_key(&ctx, el, cases[n].side) >= 0) {
			lws_genec_destroy(&ctx);
			lwsl_err("%s: case %u lengths accepted\n", __func__,
				 (unsigned int)n);
			goto bail;
		}

		/* the failed ctx must still be destroyable */

		lws_genec_destroy(&ctx);

		free(el[LWS_GENCRYPTO_EC_KEYEL_X].buf);
		free(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf);
		if (cases[n].dl)
			free(el[LWS_GENCRYPTO_EC_KEYEL_D].buf);
	}

	return 0;

bail:
	lws_genec_destroy(&ctx);
	free(el[LWS_GENCRYPTO_EC_KEYEL_X].buf);
	free(el[LWS_GENCRYPTO_EC_KEYEL_Y].buf);
	if (cases[n].dl)
		free(el[LWS_GENCRYPTO_EC_KEYEL_D].buf);

	return 1;
}

int
test_genec(struct lws_context *context)
{
	if (test_genec1(context))
		goto bail;

	if (test_genec2(context))
		goto bail;

	if (test_genec3(context))
		goto bail;

	/* end */

	lwsl_notice("%s: selftest OK\n", __func__);

	return 0;

bail:
	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}
