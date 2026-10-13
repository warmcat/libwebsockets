/*
 * lws-api-test-dnssec-root-anchors
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms the built-in DNSSEC trust anchors, the DS records for the ICANN
 * root zone's KSKs, really are the DS of those keys.
 *
 * A mistyped anchor digest doesn't show up until the root signs with that key,
 * and then every validation fails: KSK-2024's digest was wrong from when the
 * table was added until the root moved to signing its DNSKEY RRset with it
 * alone, on 2026-10-11 (GitHub issue #3677).
 *
 * We hold the root KSKs' public keys, as IANA publishes them in
 * https://data.iana.org/root-anchors/root-anchors.xml, and check that
 *
 *  - each anchor in the library's table is the key tag, algorithm and SHA-256
 *    DS digest (RFC 4034 5.1.4) of one of those keys,
 *  - each of those keys has an anchor in the table.
 *
 * Key and digest are transcribed separately, so a mistake in either shows up
 * as a mismatch.  When the root's KSKs change, the new key goes in both the
 * table and here.
 *
 * Nothing leaves the machine.
 */

#include <libwebsockets.h>
#include <string.h>

/* the library's built-in anchors, lws_adns_root_ds[] */
#include "private-lib-async-dns-root-anchors.h"

/* root-anchors.xml's DNSKEY fields for each root KSK it lists */
static const struct {
	const char	*name;
	uint16_t	key_tag;
	uint16_t	flags;
	uint8_t		algorithm;
	const char	*pubkey_b64;
} ksks[] = {
	{ "KSK-2017", 20326, 257, 8,
	  "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq"
	  "7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI"
	  "DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb"
	  "9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId"
	  "sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qih"
	  "ylGa8subX2Nn6UwNR1AkUTV74bU=" },
	{ "KSK-2024", 38696, 257, 8,
	  "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyG"
	  "wCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8"
	  "e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/"
	  "dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO"
	  "HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2"
	  "vaF18UYH9Z9GNUUeayffKC73PYc=" },
};

/* a DNSKEY's DS, as an anchor would hold it */
struct ds {
	uint8_t		digest[32];
	uint16_t	key_tag;
	uint8_t		algorithm;
};

/* RFC 4034 Appendix B, over the whole DNSKEY RDATA */

static uint16_t
key_tag(const uint8_t *rd, size_t len)
{
	uint32_t ac = 0;
	size_t i;

	for (i = 0; i < len; i++)
		ac += (i & 1) ? rd[i] : (uint32_t)rd[i] << 8;
	ac += (ac >> 16) & 0xffff;

	return (uint16_t)ac;
}

/*
 * The SHA-256 DS of a root DNSKEY: the digest is over the owner name in wire
 * form, for the root just its terminating zero-length label, then the RDATA
 */

static int
ksk_ds(size_t k, struct ds *ds)
{
	uint8_t rd[4 + 1024], root = 0;
	struct lws_genhash_ctx hc;
	int n;

	lws_ser_wu16be(rd, ksks[k].flags);
	rd[2] = 3; /* protocol, always 3 */
	rd[3] = ksks[k].algorithm;

	n = lws_b64_decode_string(ksks[k].pubkey_b64, (char *)rd + 4,
				  (int)sizeof(rd) - 4);
	if (n <= 0) {
		lwsl_err("%s: %s: bad public key\n", __func__, ksks[k].name);
		return 1;
	}

	ds->key_tag = key_tag(rd, 4 + (size_t)n);
	ds->algorithm = ksks[k].algorithm;

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_SHA256))
		return 1;

	if (lws_genhash_update(&hc, &root, 1) ||
	    lws_genhash_update(&hc, rd, 4 + (size_t)n)) {
		lws_genhash_destroy(&hc, NULL);
		return 1;
	}

	return lws_genhash_destroy(&hc, ds->digest);
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, result = 0;
	struct ds ds[LWS_ARRAY_SIZE(ksks)];
	uint8_t covered[LWS_ARRAY_SIZE(ksks)];
	struct lws_context_creation_info info;
	struct lws_context *context;
	uint8_t digest[32];
	char hex[65];
	const char *p;
	size_t a, k;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: built-in DNSSEC root trust anchors\n");

	/* for the crypto library's init */
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

	for (k = 0; k < LWS_ARRAY_SIZE(ksks); k++) {
		if (ksk_ds(k, &ds[k])) {
			result = 1;
			goto bail;
		}

		/* the transcribed key must at least be the key it says */
		if (ds[k].key_tag != ksks[k].key_tag) {
			lwsl_err("%s: public key's tag is %u, not %u\n",
				 ksks[k].name, ds[k].key_tag, ksks[k].key_tag);
			result = 1;
		}
	}

	memset(covered, 0, sizeof(covered));

	for (a = 0; a < LWS_ARRAY_SIZE(lws_adns_root_ds); a++) {
		int found = 0;

		if (lws_adns_root_ds[a].digest_type != 2 ||
		    strlen(lws_adns_root_ds[a].digest_hex) != 64 ||
		    lws_hex_to_byte_array(lws_adns_root_ds[a].digest_hex,
					  digest, sizeof(digest)) !=
							(int)sizeof(digest)) {
			lwsl_err("anchor %u (tag %u): not a SHA-256 DS\n",
				 (unsigned int)a, lws_adns_root_ds[a].keytag);
			result = 1;
			continue;
		}

		for (k = 0; k < LWS_ARRAY_SIZE(ksks); k++) {
			if (ds[k].key_tag != lws_adns_root_ds[a].keytag)
				continue;

			found = 1;
			covered[k] = 1;

			lws_hex_from_byte_array(ds[k].digest, sizeof(ds[k].digest),
						hex, sizeof(hex));

			if (ds[k].algorithm != lws_adns_root_ds[a].algo ||
			    memcmp(ds[k].digest, digest, sizeof(digest))) {
				lwsl_err("anchor tag %u: alg %u, %s\n",
					 lws_adns_root_ds[a].keytag,
					 lws_adns_root_ds[a].algo,
					 lws_adns_root_ds[a].digest_hex);
				lwsl_err("  but %s is: alg %u, %s\n",
					 ksks[k].name, ds[k].algorithm, hex);
				result = 1;
				continue;
			}

			lwsl_user("anchor tag %u: %s: OK\n",
				  lws_adns_root_ds[a].keytag, ksks[k].name);
		}

		if (!found) {
			lwsl_err("anchor tag %u: no published root KSK has it\n",
				 lws_adns_root_ds[a].keytag);
			result = 1;
		}
	}

	for (k = 0; k < LWS_ARRAY_SIZE(ksks); k++)
		if (!covered[k]) {
			lwsl_err("%s (tag %u): no anchor for it\n",
				 ksks[k].name, ksks[k].key_tag);
			result = 1;
		}

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
