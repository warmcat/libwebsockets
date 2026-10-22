/*
 * lws-api-test-srtp
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Known-answer and round trip tests for the SRTP / SRTCP implementation
 * (lib/core-net/lws-srtp.c), run against whichever TLS library provides
 * the generic AES and HMAC apis in this build.
 *
 * Covered behaviours:
 *
 *  - lws_srtp_init() derives the SRTP session cipher key, salt and auth key
 *    from the RFC 3711 B.3 master key and salt as the RFC says
 *  - SRTP AES-CM encryption produces the RFC 3711 B.2 keystream for the
 *    B.2 session key and salt, at SSRC 0 / index 0
 *  - RTP protect / unprotect round trips, for an SSRC with its top bit set
 *  - SRTCP protect sets the E bit on the index word, and protect /
 *    unprotect round trips for an SSRC with its top bit set
 *  - a tampered SRTP / SRTCP packet is refused (-2), and a replayed one,
 *    once the original was accepted, is refused (-3)
 *
 * The SSRC and SRTCP index were once composed with signed int shifts
 * (byte << 24), undefined for a byte >= 0x80: every encrypted SRTCP packet
 * has one (the E bit), and so does half of all random SSRCs.  Built with
 * LWS_WITH_ASAN (UBSan with trap-on-error), that killed the process at the
 * first such packet; here, at the first SRTCP protect.
 */

#include <libwebsockets.h>
#include <libwebsockets/lws-srtp.h>
#include <string.h>

static int fails, oks;

/* RFC 3711 B.3 key derivation test vectors */

static const uint8_t
b3_master_key[] = {
	0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
	0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39
}, b3_master_salt[] = {
	0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
	0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
}, b3_cipher_key[] = {
	0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee,
	0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7, 0xa0, 0x87
}, b3_cipher_salt[] = {
	0x30, 0xcb, 0xbc, 0x08, 0x86, 0x3d, 0x8c, 0x85,
	0xd4, 0x9d, 0xb3, 0x4a, 0x9a, 0xe1
}, b3_auth_key[] = { /* the first 160 bits, all HMAC-SHA1 uses */
	0xce, 0xbe, 0x32, 0x1f, 0x6f, 0xf7, 0x71, 0x6b,
	0x6f, 0xd4, 0xab, 0x49, 0xaf, 0x25, 0x6a, 0x15,
	0x6d, 0x38, 0xba, 0xa4
};

/* RFC 3711 B.2 AES-CM test vectors */

static const uint8_t
b2_session_key[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
}, b2_session_salt[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
}, b2_keystream[] = {
	0xe0, 0x3e, 0xad, 0x09, 0x35, 0xc9, 0x5e, 0x80,
	0xe1, 0x66, 0xb1, 0x6d, 0xd9, 0x2b, 0x4e, 0xb4,
	0xd2, 0x35, 0x13, 0x16, 0x2b, 0x02, 0xd0, 0xf7,
	0x2a, 0x43, 0xa2, 0xfe, 0x4a, 0x5f, 0x97, 0xab,
	0x41, 0xe9, 0x5b, 0x3b, 0xb0, 0xa2, 0xe8, 0xdd,
	0x47, 0x79, 0x01, 0xe4, 0xfc, 0xa8, 0x94, 0xc0
};

static void
result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

static int
test_kdf(void)
{
	struct lws_srtp_ctx ctx;

	if (lws_srtp_init(&ctx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
			  b3_master_key, b3_master_salt)) {
		lwsl_err("%s: init failed\n", __func__);
		return 1;
	}

	if (memcmp(ctx.session_key, b3_cipher_key, sizeof(b3_cipher_key))) {
		lwsl_err("%s: session cipher key\n", __func__);
		lwsl_hexdump_err(ctx.session_key, sizeof(b3_cipher_key));
		return 1;
	}

	if (memcmp(ctx.session_salt, b3_cipher_salt, sizeof(b3_cipher_salt))) {
		lwsl_err("%s: session salt\n", __func__);
		lwsl_hexdump_err(ctx.session_salt, sizeof(b3_cipher_salt));
		return 1;
	}

	if (memcmp(ctx.session_auth, b3_auth_key, sizeof(b3_auth_key))) {
		lwsl_err("%s: session auth key\n", __func__);
		lwsl_hexdump_err(ctx.session_auth, sizeof(b3_auth_key));
		return 1;
	}

	return 0;
}

static int
test_aes_cm(void)
{
	uint8_t pkt[12 + sizeof(b2_keystream) + 10];
	struct lws_srtp_ctx ctx;
	size_t len = 12 + sizeof(b2_keystream);

	if (lws_srtp_init(&ctx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
			  b3_master_key, b3_master_salt))
		return 1;

	/* replace the derived session keys with the B.2 ones */

	memcpy(ctx.session_key, b2_session_key, sizeof(b2_session_key));
	memcpy(ctx.session_salt, b2_session_salt, sizeof(b2_session_salt));

	/*
	 * SSRC 0, seq 0 and ROC 0 make the counter the salt << 16, as B.2 has
	 * it, so a zero payload encrypts to the keystream itself
	 */

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x80;
	pkt[1] = 96;

	if (lws_srtp_protect_rtp(&ctx, pkt, &len, sizeof(pkt)) ||
	    len != sizeof(pkt)) {
		lwsl_err("%s: protect failed\n", __func__);
		return 1;
	}

	if (memcmp(pkt + 12, b2_keystream, sizeof(b2_keystream))) {
		lwsl_err("%s: keystream mismatch\n", __func__);
		lwsl_hexdump_err(pkt + 12, sizeof(b2_keystream));
		return 1;
	}

	return 0;
}

static int
test_rtp(enum lws_srtp_profiles profile)
{
	uint8_t pkt[128], orig[128], t[128];
	struct lws_srtp_ctx tx, rx;
	size_t len, olen = 112, tl;
	int n;

	if (lws_srtp_init(&tx, profile, b3_master_key, b3_master_salt) ||
	    lws_srtp_init(&rx, profile, b3_master_key, b3_master_salt))
		return 1;

	/* v2, pt 96, seq 0x1234, ts 0x01000000, SSRC 0xdeadbeef */

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x80;
	pkt[1] = 96;
	pkt[2] = 0x12;
	pkt[3] = 0x34;
	pkt[4] = 1;
	lws_ser_wu32be(pkt + 8, 0xdeadbeef);
	for (n = 12; n < (int)olen; n++)
		pkt[n] = (uint8_t)n;
	memcpy(orig, pkt, olen);
	len = olen;

	if (lws_srtp_protect_rtp(&tx, pkt, &len, sizeof(pkt))) {
		lwsl_err("%s: protect failed\n", __func__);
		return 1;
	}

	if (len != olen + (profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80 ?
							10u : 4u) ||
	    memcmp(pkt, orig, 12) || !memcmp(pkt + 12, orig + 12, olen - 12)) {
		lwsl_err("%s: protected packet has the wrong shape\n", __func__);
		return 1;
	}

	/* a flipped bit in the payload must fail authentication */

	memcpy(t, pkt, len);
	t[20] ^= 1;
	tl = len;
	if (lws_srtp_unprotect_rtp(&rx, t, &tl) != -2) {
		lwsl_err("%s: tampered packet not refused\n", __func__);
		return 1;
	}

	memcpy(t, pkt, len);
	tl = len;
	if (lws_srtp_unprotect_rtp(&rx, pkt, &len)) {
		lwsl_err("%s: unprotect failed\n", __func__);
		return 1;
	}

	if (len != olen || memcmp(pkt, orig, olen)) {
		lwsl_err("%s: round trip mismatch\n", __func__);
		return 1;
	}

	if (lws_srtp_unprotect_rtp(&rx, t, &tl) != -3) {
		lwsl_err("%s: replay not refused\n", __func__);
		return 1;
	}

	return 0;
}

static int
test_rtcp(void)
{
	uint8_t pkt[96], orig[96], t[96];
	struct lws_srtp_ctx tx, rx;
	size_t len, olen = 40, tl;
	int n;

	if (lws_srtp_init(&tx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
			  b3_master_key, b3_master_salt) ||
	    lws_srtp_init(&rx, LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80,
			  b3_master_key, b3_master_salt))
		return 1;

	/* SR, length 9 words, SSRC 0x80000001 */

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x80;
	pkt[1] = 200;
	pkt[3] = 9;
	lws_ser_wu32be(pkt + 4, 0x80000001);
	for (n = 8; n < (int)olen; n++)
		pkt[n] = (uint8_t)(n * 3);
	memcpy(orig, pkt, olen);
	len = olen;

	if (lws_srtp_protect_rtcp(&tx, pkt, &len, sizeof(pkt))) {
		lwsl_err("%s: protect failed\n", __func__);
		return 1;
	}

	/* header in clear, payload not, then index 0 with the E bit set */

	if (len != olen + 4 + 10 ||
	    memcmp(pkt, orig, 8) || !memcmp(pkt + 8, orig + 8, olen - 8) ||
	    lws_ser_ru32be(pkt + olen) != 0x80000000) {
		lwsl_err("%s: protected packet has the wrong shape\n", __func__);
		lwsl_hexdump_err(pkt, len);
		return 1;
	}

	memcpy(t, pkt, len);
	t[10] ^= 0x40;
	tl = len;
	if (lws_srtp_unprotect_rtcp(&rx, t, &tl) != -2) {
		lwsl_err("%s: tampered packet not refused\n", __func__);
		return 1;
	}

	memcpy(t, pkt, len);
	tl = len;
	if (lws_srtp_unprotect_rtcp(&rx, pkt, &len)) {
		lwsl_err("%s: unprotect failed\n", __func__);
		return 1;
	}

	if (len != olen || memcmp(pkt, orig, olen)) {
		lwsl_err("%s: round trip mismatch\n", __func__);
		return 1;
	}

	if (lws_srtp_unprotect_rtcp(&rx, t, &tl) != -3) {
		lwsl_err("%s: replay not refused\n", __func__);
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: SRTP / SRTCP\n");

	result("kdf (RFC 3711 B.3)", test_kdf());
	result("aes-cm (RFC 3711 B.2)", test_aes_cm());
	result("rtp sha1-80", test_rtp(LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80));
	result("rtp sha1-32", test_rtp(LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_32));
	result("rtcp", test_rtcp());

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
