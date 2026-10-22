/*
 * lws-api-test-auth-dns-glue
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * G-288: a zone the auth-dns plugin serves can come from the DHT, ie, be
 * shaped by an attacker, and per-query work on it is paid on the event loop
 * for every (spoofable, UDP) query.  So looking names up in the zone must
 * not cost a walk of the whole zone per NS RR of a cut, or per label of a
 * qname.
 *
 * The plugin is built into this test, which counts the owner name compares
 * its lookups make.  A zone with a cut of GLUE_NS NS RRs, A and AAAA glue
 * for each, and FILLER more A RRsets, is installed as the plugin does, and
 *
 *  - a referral to the cut carries every NS RR and all the glue, for a few
 *    compares per NS RR, not one per NS RR per RRset in the zone
 *  - names are found in the zone, and absent names are not, for a few
 *    compares each
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>

static unsigned long ops;
#define AUTH_DNS_TEST_OP() ops++

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c"

/* the plugin's protocol, as an application building it in would list it */
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_AUTH_DNS,
	LWS_PROTOCOL_LIST_TERM
};

#define GLUE_NS		100
#define FILLER		4000
/* generous: a binary search of the zone is ~13 compares, plus the matches */
#define OPS_PER_LOOKUP	32

static int fails;

static int
glue_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static char *
glue_zone(size_t *len)
{
	size_t alloc = 128 * (GLUE_NS * 3 + FILLER + 8), n = 0;
	char *z = malloc(alloc);
	int i;

	if (!z)
		return NULL;

	n += (size_t)lws_snprintf(z + n, alloc - n,
		"$ORIGIN glue.example.\n"
		"$TTL 300\n"
		"@ IN SOA ns.glue.example. admin.glue.example. "
				"1 3600 600 86400 300\n"
		"@ IN NS ns.glue.example.\n"
		"ns IN A 192.0.2.1\n");

	/* the cut, delegating big.glue.example. */

	for (i = 0; i < GLUE_NS; i++)
		n += (size_t)lws_snprintf(z + n, alloc - n,
			"big IN NS ns%03d.big.glue.example.\n", i);

	/* the glue, interleaved with filler, so it is all over the zone */

	for (i = 0; i < FILLER; i++) {
		n += (size_t)lws_snprintf(z + n, alloc - n,
			"h%05d IN A 198.51.100.%d\n", i, i & 0xff);
		if (i % (FILLER / GLUE_NS) || i / (FILLER / GLUE_NS) >= GLUE_NS)
			continue;
		n += (size_t)lws_snprintf(z + n, alloc - n,
			"ns%03d.big IN A 192.0.2.%d\n"
			"ns%03d.big IN AAAA 2001:db8::%x\n",
			i / (FILLER / GLUE_NS), i & 0xff,
			i / (FILLER / GLUE_NS), i);
	}

	*len = n;

	return z;
}

int
main(int argc, const char **argv)
{
	static const char *qn[] = { "foo", "big", "glue", "example" };
	struct per_vhost_data__auth_dns vhd;
	struct auth_dns_cache_entry *ce;
	struct auth_dns_rrset *cut;
	uint8_t q[64], *dbuf, *rp;
	size_t zlen, ql = 0;
	char *zt;
	int n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: %s glue and owner lookups\n",
		  protocols[0].name);
	(void)argc;
	(void)argv;

	memset(&vhd, 0, sizeof(vhd));
	lws_dll2_owner_clear(&vhd.zones);

	zt = glue_zone(&zlen);
	ce = calloc(1, sizeof(*ce));
	dbuf = malloc(65535);
	if (!zt || !ce || !dbuf) {
		lwsl_err("OOM\n");
		free(zt);
		free(ce);
		free(dbuf);

		return 1;
	}

	n = lws_auth_dns_parse_zone_buf(zt, zlen, &ce->zone);
	free(zt);
	if (glue_expect(!n && !auth_dns_ce_add(&vhd, ce), "zone installed")) {
		lws_auth_dns_free_zone(&ce->zone);
		free(ce);
		free(dbuf);

		return 1;
	}

	glue_expect(ce->idx.count == (size_t)(4 + FILLER + 2 * GLUE_NS),
		    "every RRset indexed");

	/* the question: foo.big.glue.example. A IN */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(qn); n++) {
		size_t l = strlen(qn[n]);

		q[ql++] = (uint8_t)l;
		memcpy(q + ql, qn[n], l);
		ql += l;
	}
	q[ql++] = 0;
	lws_ser_wu16be(q + ql, 1);
	lws_ser_wu16be(q + ql + 2, 1);
	ql += 4;

	cut = lws_auth_dns_zone_cut(&ce->zone, "foo.big.glue.example");
	if (glue_expect(!!cut, "foo.big is below a cut"))
		goto bail;

	/* the referral, at TCP's size so the whole of it fits */

	ops = 0;
	memset(dbuf, 0, 12);
	rp = auth_dns_referral(dbuf, dbuf, 65535, 0, q, ql, &ce->zone,
			       &ce->idx, cut, 0, 1);
	lwsl_user("%s: referral took %lu compares\n", __func__, ops);

	glue_expect(rp && !(lws_ser_ru16be(dbuf + 2) & 0x0200) &&
		    lws_ser_ru16be(dbuf + 8) == GLUE_NS &&
		    lws_ser_ru16be(dbuf + 10) == 2 * GLUE_NS + 1,
		    "referral has every NS RR, all the glue and the OPT");
	glue_expect(ops <= (unsigned long)GLUE_NS * OPS_PER_LOOKUP,
		    "glue lookup costs a few compares per NS RR");

	/* single lookups, as the NSEC3 closest encloser search makes */

	ops = 0;
	glue_expect(auth_dns_name_exists(&ce->idx, "h01234.glue.example.") &&
		    auth_dns_name_exists(&ce->idx, "NS042.Big.Glue.Example") &&
		    auth_dns_name_exists(&ce->idx, "glue.example") &&
		    !auth_dns_name_exists(&ce->idx, "nope.glue.example") &&
		    !auth_dns_name_exists(&ce->idx, "big.glue.example.x"),
		    "names found by owner, absent ones not");
	glue_expect(ops <= 5 * OPS_PER_LOOKUP,
		    "an owner lookup costs a few compares");

bail:
	auth_dns_ce_destroy(ce);
	free(dbuf);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
