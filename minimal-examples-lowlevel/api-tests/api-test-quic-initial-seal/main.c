/*
 * lws-api-test-quic-initial-seal
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_quic_seal_client_initial() protects a client Initial the way its
 * client would, with the keys anyone can derive from its DCID (RFC 9001
 * 5.2).  We give it the unprotected client Initial of RFC 9001 Appendix
 * A.2, and check:
 *
 *  1: the client's Initial keys the DCID gives are the ones of Appendix A.1
 *
 *  2: the protected header is the one of Appendix A.2: the header protection
 *     mask is made from a sample of the ciphertext, so this is the AEAD's
 *     output too
 *
 *  3: the whole packet opens again, with those keys and genaes, to the
 *     plaintext it was made from, and its tag checks
 *
 *  4: an Initial sent after the server answered, to the server's SCID, is
 *     protected with the keys of the first Initial's DCID, given as odcid:
 *     it opens with those keys
 *
 *  5: lws_quic_seal_packet(), given the traffic secret of RFC 9001 A.5,
 *     protects its short header ChaCha20-Poly1305 packet to the packet there
 *
 *  6: after a key update, the payload is protected with the keys of the
 *     "ku" secret of A.5, and the header with the hp key of the secret
 *     itself, as RFC 9001 6.1 has it
 *
 *  7: what isn't a client v1 Initial it can protect is refused, and what
 *     lws_quic_seal_packet() can't protect with the secret it is given
 */

#include <libwebsockets.h>
#include <string.h>

/* RFC 9001 A.1 */
static const uint8_t dcid[] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
	salt[] = {
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
	},
	key[] = {
		0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
		0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
	},
	iv[] = {
		0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
		0x46, 0xfb, 0x25, 0x5c
	},
	hp[] = {
		0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
		0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
	};

/*
 * RFC 9001 A.2: the unprotected header, its packet number 2 in 4 bytes, and
 * the payload's start: a CRYPTO frame of the ClientHello.  The rest of the
 * 1162-byte payload is PADDING.  The header's first byte is c3 there: the
 * packet number length bits are set by the seal.
 */
static const uint8_t hdr[] = {
		0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
		0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
		0x44, 0x9e, 0x00, 0x00, 0x00, 0x02
	},
	payload_start[] = {
		0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed,
		0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29
	},
	/* RFC 9001 A.2: the protected header */
	protected_hdr[] = {
		0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
		0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
		0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34
	};

/* RFC 9001 A.5: a 1-RTT PING, its packet number 654360564 in 3 bytes */
static const uint8_t cc_secret[] = {
		0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
		0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
		0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
		0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b
	},
	cc_plain[] = { 0x40, 0x00, 0xbf, 0xf4, 0x01 },
	cc_protected[] = {
		0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5,
		0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79,
		0x99, 0xc2, 0x5a, 0x5b, 0xfb
	},
	/* the next phase's secret, and the hp key, which stays */
	cc_ku[] = {
		0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55,
		0x63, 0x42, 0xee, 0x93, 0x61, 0xd2, 0x53, 0x42,
		0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3, 0xc7, 0x14,
		0x86, 0x84, 0xb3, 0x6b, 0x71, 0x48, 0x81, 0xf9
	},
	cc_hp[] = {
		0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
		0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
		0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
		0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4
	};

#define CC_PN		654360564u

#define PN_OFFSET	18
#define PN_LEN		4
#define PAYLOAD_LEN	1162
#define PKT_LEN		(sizeof(hdr) + PAYLOAD_LEN)

static uint8_t pkt[PKT_LEN + 16], plain[PKT_LEN], long_cid[21];

static int
check_keys(void)
{
	uint8_t initial[32], client[32], k[16], i[12], h[16];

	if (lws_genhkdf_extract(LWS_GENHMAC_TYPE_SHA256, salt, sizeof(salt),
				dcid, sizeof(dcid), initial) ||
	    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, initial, 32,
				     "client in", NULL, 0, client, 32) ||
	    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client, 32,
				     "quic key", NULL, 0, k, sizeof(k)) ||
	    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client, 32,
				     "quic iv", NULL, 0, i, sizeof(i)) ||
	    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client, 32,
				     "quic hp", NULL, 0, h, sizeof(h))) {
		lwsl_err("%s: derivation failed\n", __func__);
		return 1;
	}

	if (memcmp(k, key, sizeof(k)) || memcmp(i, iv, sizeof(i)) ||
	    memcmp(h, hp, sizeof(h))) {
		lwsl_err("%s: keys differ from RFC 9001 A.1\n", __func__);
		return 1;
	}

	return 0;
}

/* take the header protection off, and open the payload to plain's */
static int
open_pkt(void)
{
	struct lws_gencrypto_keyelem el_hp = { (uint8_t *)hp, sizeof(hp) },
				     el_key = { (uint8_t *)key, sizeof(key) };
	uint8_t mask[16], nonce[12], tag[16];
	struct lws_genaes_ctx ctx;
	size_t ivl = sizeof(nonce);
	int n, r = 1;

	if (lws_genaes_create(&ctx, LWS_GAESO_ENC, LWS_GAESM_ECB, &el_hp,
			      LWS_GAESP_NO_PADDING, NULL))
		return 1;
	n = lws_genaes_crypt(&ctx, &pkt[PN_OFFSET + 4], 16, mask, NULL, NULL,
			     NULL, 0);
	lws_genaes_destroy(&ctx, NULL, 0);
	if (n)
		return 1;

	pkt[0] ^= mask[0] & 0x0f;
	for (n = 0; n < PN_LEN; n++)
		pkt[PN_OFFSET + n] ^= mask[1 + n];

	if (pkt[0] != 0xc3 || memcmp(pkt + 1, plain + 1, sizeof(hdr) - 1)) {
		lwsl_err("%s: header did not unprotect\n", __func__);
		return 1;
	}

	/* the nonce is the iv xor the packet number, 2 */
	memcpy(nonce, iv, sizeof(nonce));
	nonce[11] ^= 2;
	memcpy(tag, &pkt[PKT_LEN], sizeof(tag));

	if (lws_genaes_create(&ctx, LWS_GAESO_DEC, LWS_GAESM_GCM, &el_key,
			      LWS_GAESP_NO_PADDING, NULL))
		return 1;
	if (!lws_genaes_crypt(&ctx, pkt, sizeof(hdr), NULL, nonce, tag, &ivl,
			      sizeof(tag)) &&
	    !lws_genaes_crypt(&ctx, &pkt[sizeof(hdr)], PAYLOAD_LEN,
			      &pkt[sizeof(hdr)], nonce, tag, &ivl, sizeof(tag)))
		r = 0;
	if (lws_genaes_destroy(&ctx, NULL, 0))
		r = 1;
	if (r) {
		lwsl_err("%s: payload did not authenticate\n", __func__);
		return 1;
	}

	if (memcmp(pkt + sizeof(hdr), plain + sizeof(hdr), PAYLOAD_LEN)) {
		lwsl_err("%s: payload opened differently\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * The A.5 packet, a key update on: its header must unprotect with the hp
 * key of the secret before, and its payload open with the keys of the
 * "ku" secret
 */
static int
key_update(void)
{
	struct lws_gencrypto_keyelem el = { (uint8_t *)cc_hp, sizeof(cc_hp) };
	uint8_t a[sizeof(cc_protected)], mask[5], k[32], nonce[12];
	static const uint8_t zeroes[5];
	struct lws_genchacha_ctx ctx;
	int n;

	memcpy(a, cc_plain, sizeof(cc_plain));
	a[0] |= 4; /* key phase 1 */

	if (lws_quic_seal_packet(a, sizeof(cc_plain), 1, 3, CC_PN,
				 LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				 cc_secret, sizeof(cc_secret), 1) !=
							(int)sizeof(a))
		return 1;

	/* the mask is ChaCha20 of zeros, its counter and nonce the sample */
	if (lws_genchacha_create(&ctx, LWS_GAESO_ENC, &el, NULL))
		return 1;
	n = lws_genchacha_stream(&ctx, zeroes, sizeof(zeroes), mask, &a[5], 16);
	lws_genchacha_destroy(&ctx);
	if (n)
		return 1;

	a[0] ^= mask[0] & 0x1f;
	for (n = 0; n < 3; n++)
		a[1 + n] ^= mask[1 + n];
	if (a[0] != 0x46 || memcmp(a + 1, cc_plain + 1, 3)) {
		lwsl_err("%s: header not under the first phase's hp key\n",
			 __func__);
		return 1;
	}

	/* the nonce is the ku iv xor the packet number */
	if (lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, cc_ku,
				     sizeof(cc_ku), "quic key", NULL, 0, k,
				     sizeof(k)) ||
	    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, cc_ku,
				     sizeof(cc_ku), "quic iv", NULL, 0, nonce,
				     sizeof(nonce)))
		return 1;
	for (n = 0; n < 4; n++)
		nonce[11 - n] ^= (uint8_t)(CC_PN >> (n * 8));

	el.buf = k;
	el.len = sizeof(k);
	if (lws_genchacha_create(&ctx, LWS_GAESO_DEC, &el, NULL))
		return 1;
	n = lws_genchacha_crypt(&ctx, &a[4], 1, &a[4], nonce, a, 4, &a[5], 16);
	if (lws_genchacha_destroy(&ctx))
		n = 1;
	if (n || a[4] != 0x01) {
		lwsl_err("%s: payload not under the next phase's keys\n",
			 __func__);
		return 1;
	}

	return 0;
}

/* the RFC packet, unprotected */
static void
make_plain(void)
{
	memset(plain, 0, sizeof(plain));
	memcpy(plain, hdr, sizeof(hdr));
	memcpy(plain + sizeof(hdr), payload_start, sizeof(payload_start));
	memcpy(pkt, plain, sizeof(plain));
}

int
main(int argc, const char **argv)
{
	int e = 0, n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: quic client Initial protection\n");

	/* 1 */
	if (check_keys()) {
		lwsl_err("case 1: FAIL\n");
		return 1;
	}
	lwsl_user("case 1: client Initial keys: PASS\n");

	/* 2 */
	make_plain();
	n = lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2, NULL,
					 0);
	if (n != (int)PKT_LEN + 16) {
		lwsl_err("case 2: seal returned %d\n", n);
		return 1;
	}
	if (memcmp(pkt, protected_hdr, sizeof(protected_hdr))) {
		lwsl_err("case 2: protected header differs from RFC 9001 A.2\n");
		lwsl_hexdump_err(pkt, sizeof(protected_hdr));
		return 1;
	}
	lwsl_user("case 2: protected header: PASS\n");

	/* 3 */
	if (open_pkt()) {
		lwsl_err("case 3: FAIL\n");
		return 1;
	}
	lwsl_user("case 3: opens to its plaintext: PASS\n");

	/* 4: to another DCID, with the keys of the RFC's */
	make_plain();
	memset(plain + 6, 0x5a, sizeof(dcid));
	memcpy(pkt, plain, sizeof(plain));
	n = lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					 dcid, sizeof(dcid));
	if (n != (int)PKT_LEN + 16 || open_pkt()) {
		lwsl_err("case 4: FAIL\n");
		return 1;
	}
	lwsl_user("case 4: keys of the first Initial's DCID: PASS\n");

	/* 5 */
	memcpy(pkt, cc_plain, sizeof(cc_plain));
	n = lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				 LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				 cc_secret, sizeof(cc_secret), 0);
	if (n != (int)sizeof(cc_protected) ||
	    memcmp(pkt, cc_protected, sizeof(cc_protected))) {
		lwsl_err("case 5: seal returned %d, not the packet of RFC 9001 "
			 "A.5\n", n);
		lwsl_hexdump_err(pkt, sizeof(cc_protected));
		return 1;
	}
	lwsl_user("case 5: short header from its traffic secret: PASS\n");

	/* 6 */
	if (key_update()) {
		lwsl_err("case 6: FAIL\n");
		return 1;
	}
	lwsl_user("case 6: a key update: PASS\n");

	/* 7: refusals */
	make_plain();
	pkt[4] = 2; /* another version */
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  NULL, 0) != -1;
	make_plain();
	pkt[0] = 0xe0; /* a Handshake packet */
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  NULL, 0) != -1;
	make_plain();
	pkt[0] = 0xc1; /* pn length bits already set */
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  NULL, 0) != -1;
	make_plain();
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, 0, 2, NULL,
					  0) != -1;
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, 5, 2, NULL,
					  0) != -1;
	/* no room for the 16 bytes header protection samples */
	e |= lws_quic_seal_client_initial(pkt, PN_OFFSET + 3, PN_OFFSET, 1,
					  2, NULL, 0) != -1;
	pkt[5] = 21; /* a DCID longer than QUIC allows */
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  NULL, 0) != -1;
	make_plain();
	pkt[5] = 13; /* a DCID running into the packet number */
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  NULL, 0) != -1;
	make_plain();
	/* an odcid longer than QUIC allows */
	memset(long_cid, 0x5a, sizeof(long_cid));
	e |= lws_quic_seal_client_initial(pkt, PKT_LEN, PN_OFFSET, PN_LEN, 2,
					  long_cid, sizeof(long_cid)) != -1;

	memcpy(pkt, cc_plain, sizeof(cc_plain));
	/* a secret the length of another hash than its suite's */
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_AES_256_GCM, cc_secret,
				  sizeof(cc_secret), 0) != -1;
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_UNKNOWN, cc_secret,
				  sizeof(cc_secret), 0) != -1;
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305, NULL,
				  sizeof(cc_secret), 0) != -1;
	/* no room for the sample */
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain) - 1, 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				  cc_secret, sizeof(cc_secret), 0) != -1;
	pkt[0] = 0x00; /* no fixed bit */
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				  cc_secret, sizeof(cc_secret), 0) != -1;
	pkt[0] = 0x42; /* pn length bits already set */
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				  cc_secret, sizeof(cc_secret), 0) != -1;
	pkt[0] = 0x40; /* a key phase bit that isn't the key update's */
	e |= lws_quic_seal_packet(pkt, sizeof(cc_plain), 1, 3, CC_PN,
				  LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305,
				  cc_secret, sizeof(cc_secret), 1) != -1;
	if (e) {
		lwsl_err("case 7: something that should be refused was not\n");
		return 1;
	}
	lwsl_user("case 7: refusals: PASS\n");

	lwsl_user("Completed: PASS\n");

	(void)argc;
	(void)argv;

	return 0;
}
