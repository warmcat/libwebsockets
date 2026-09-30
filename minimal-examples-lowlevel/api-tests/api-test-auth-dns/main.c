/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(WIN32) || defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

/*
 * A zone file may write $ORIGIN with or without the trailing root dot.  The
 * parser has to bring both to the same, fully-qualified owner names: a
 * dotless origin that reached the signer as-is would be appended to names
 * that already end in it, and the whole NSEC3 chain would be hashed over
 * "x.example.com.example.com".
 *
 * So we sign the same zone body under both spellings of $ORIGIN, and require
 * the two signed zones to agree on every owner name and on every non-RRSIG
 * rdata (which is where the NSEC3 owner hashes and next-hashes live).  The
 * RRSIG rdata carries a fresh ECDSA signature each time, so it is compared
 * only for its owner name and type.
 */

static const char *zone_body =
	"$TTL 1200\n"
	"@ IN SOA ns1.example.com. hostmaster.example.com. (\n"
	"        2026090801 60 120 1209600 120 )\n"
	"@			IN	NS	ns1.example.com.\n"
	"ns1			IN	A	127.0.0.1\n"
	"ns1			IN	LOC	42 21 54 N 71 6 18 W -24m 30m 200m 15m\n"
	"ns1			IN	TYPE44	\\# 22 0101 0123456789abcdef0123456789abcdef01234567\n"
	"www			IN	A	127.0.0.2\n"
	"x.deeper		IN	A	127.0.0.3\n"
	"@			IN	TXT	\"v=spf1 -all\"\n";

static int
write_zone(const char *path, const char *origin_line)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600), r = 1;
	size_t l = strlen(origin_line), b = strlen(zone_body);

	if (fd < 0)
		return 1;

	if (write(fd, origin_line, l) == (ssize_t)l &&
	    write(fd, zone_body, b) == (ssize_t)b)
		r = 0;

	close(fd);

	return r;
}

static int
load_zone(struct auth_dns_zone *z, const char *path)
{
	int fd = open(path, LWS_O_RDONLY), r = 1;
	struct stat st;
	char *buf;

	memset(z, 0, sizeof(*z));

	if (fd < 0)
		return 1;

	if (fstat(fd, &st) || st.st_size <= 0) {
		close(fd);

		return 1;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);

		return 1;
	}

	if (read(fd, buf, (size_t)st.st_size) == st.st_size) {
		buf[st.st_size] = '\0';
		r = lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, z);
	}

	free(buf);
	close(fd);

	return r;
}

/* sign \p in to \p out with a fixed validity, so the result is reproducible */

static int
sign_zone_to(struct lws_context *cx, const char *in, const char *out,
	     const char *jws)
{
	struct lws_auth_dns_sign_info info;

	memset(&info, 0, sizeof(info));
	info.cx			= cx;
	info.input_filepath	= in;
	info.output_filepath	= out;
	info.jws_filepath	= jws;
	info.ksk_jwk_filepath	= "./ksk.jwk";
	info.zsk_jwk_filepath	= "./zsk.jwk";
	info.sign_validity_start_time = (time_t)1767225600;
	info.sign_validity_duration = 30 * 24 * 3600;

	return lws_auth_dns_sign_zone(&info);
}

static int
test_dotless_origin(struct lws_context *cx)
{
	struct auth_dns_zone zd, zn;
	struct lws_dll2 *p, *q;
	int r = 1, nsec3 = 0;
	size_t l;

	if (write_zone("./test-dotted.zone.in", "$ORIGIN example.com.\n") ||
	    write_zone("./test-dotless.zone.in", "$ORIGIN example.com\n")) {
		lwsl_err("%s: unable to write test zones\n", __func__);

		return 1;
	}

	if (sign_zone_to(cx, "./test-dotted.zone.in", "./test-dotted.zone.signed",
			 "./test-dotted.zone.signed.jws") ||
	    sign_zone_to(cx, "./test-dotless.zone.in", "./test-dotless.zone.signed",
			 "./test-dotless.zone.signed.jws")) {
		lwsl_err("%s: signing failed\n", __func__);

		return 1;
	}

	memset(&zd, 0, sizeof(zd));
	memset(&zn, 0, sizeof(zn));

	if (load_zone(&zd, "./test-dotted.zone.signed") ||
	    load_zone(&zn, "./test-dotless.zone.signed")) {
		lwsl_err("%s: unable to reload signed zones\n", __func__);
		goto bail;
	}

	/* the dotless origin must have been normalised */

	l = strlen(zn.origin);
	if (!l || zn.origin[l - 1] != '.' || strcmp(zn.origin, zd.origin)) {
		lwsl_err("%s: origin '%s' not normalised\n", __func__, zn.origin);
		goto bail;
	}

	if (lws_dll2_get_head(&zd.rrset_list) == NULL ||
	    lws_dll2_count(&zd.rrset_list) != lws_dll2_count(&zn.rrset_list)) {
		lwsl_err("%s: rrset count %u vs %u\n", __func__,
			 (unsigned int)lws_dll2_count(&zd.rrset_list),
			 (unsigned int)lws_dll2_count(&zn.rrset_list));
		goto bail;
	}

	p = lws_dll2_get_head(&zd.rrset_list);
	q = lws_dll2_get_head(&zn.rrset_list);

	while (p && q) {
		struct auth_dns_rrset *a = lws_container_of(p,
						struct auth_dns_rrset, list);
		struct auth_dns_rrset *b = lws_container_of(q,
						struct auth_dns_rrset, list);
		struct lws_dll2 *ra, *rb;

		l = strlen(b->name);
		if (!l || b->name[l - 1] != '.') {
			lwsl_err("%s: owner name '%s' not fully qualified\n",
				 __func__, b->name);
			goto bail;
		}

		if (strcmp(a->name, b->name) || a->type != b->type) {
			lwsl_err("%s: '%s'/%u vs '%s'/%u\n", __func__,
				 a->name, a->type, b->name, b->type);
			goto bail;
		}

		if (a->type == 50)
			nsec3++;

		/* RRSIG rdata is a fresh signature each run, don't compare */

		if (a->type != 46) {
			ra = lws_dll2_get_head(&a->rr_list);
			rb = lws_dll2_get_head(&b->rr_list);

			while (ra && rb) {
				struct auth_dns_rr *x = lws_container_of(ra,
						struct auth_dns_rr, list);
				struct auth_dns_rr *y = lws_container_of(rb,
						struct auth_dns_rr, list);

				if (!x->rdata || !y->rdata ||
				    strcmp(x->rdata, y->rdata)) {
					lwsl_err("%s: %s rdata '%s' vs '%s'\n",
						 __func__, a->name,
						 x->rdata ? x->rdata : "(null)",
						 y->rdata ? y->rdata : "(null)");
					goto bail;
				}

				ra = lws_dll2_get_next(ra);
				rb = lws_dll2_get_next(rb);
			}

			if (ra || rb) {
				lwsl_err("%s: %s rr count differs\n", __func__,
					 a->name);
				goto bail;
			}
		}

		p = lws_dll2_get_next(p);
		q = lws_dll2_get_next(q);
	}

	if (!nsec3) {
		lwsl_err("%s: no NSEC3 rrsets to compare\n", __func__);
		goto bail;
	}

	lwsl_user("dotless $ORIGIN normalisation: ok (%d NSEC3 rrsets)\n", nsec3);
	r = 0;

bail:
	lws_auth_dns_free_zone(&zd);
	lws_auth_dns_free_zone(&zn);

	return r;
}

/*
 * The RFC 1876 LOC record has to survive the whole sign / reload path: the
 * parser must type it as 29, the writer must label it LOC again, and the
 * wire form the RRSIG is computed over must be the RFC's encoding of the
 * presentation values.
 */

static int
test_loc(struct lws_context *cx)
{
	static const char *loc_rdata = "42 21 54 N 71 6 18 W -24m 30m 200m 15m";
	struct auth_dns_zone z;
	struct auth_dns_rrset *rs = NULL;
	struct auth_dns_rr *rr;
	uint32_t lat = 0x80000000u + (42u * 3600u + 21u * 60u + 54u) * 1000u;
	uint32_t lon = 0x80000000u - (71u * 3600u + 6u * 60u + 18u) * 1000u;
	uint32_t alt = 10000000u - 2400u; /* RFC 1876: cm from -100000m */
	int r = 1;

	if (write_zone("./test-loc.zone.in", "$ORIGIN example.com.\n") ||
	    sign_zone_to(cx, "./test-loc.zone.in", "./test-loc.zone.signed",
			 "./test-loc.zone.signed.jws")) {
		lwsl_err("%s: signing failed\n", __func__);

		return 1;
	}

	if (load_zone(&z, "./test-loc.zone.signed")) {
		lwsl_err("%s: unable to reload signed zone\n", __func__);

		return 1;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
						struct auth_dns_rrset, list);
		if (s->type == 29 && !strcmp(s->name, "ns1.example.com.")) {
			rs = s;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!rs) {
		lwsl_err("%s: no LOC rrset for ns1.example.com.\n", __func__);
		goto bail;
	}

	rr = lws_container_of(lws_dll2_get_head(&rs->rr_list),
			      struct auth_dns_rr, list);

	if (!rr->rdata || strcmp(rr->rdata, loc_rdata)) {
		lwsl_err("%s: LOC rdata '%s' not preserved\n", __func__,
			 rr->rdata ? rr->rdata : "(null)");
		goto bail;
	}

	if (!rr->wire_rdata || rr->wire_rdata_len != 16 || rr->wire_rdata[0]) {
		lwsl_err("%s: LOC wire form wrong (%zu bytes)\n", __func__,
			 rr->wire_rdata_len);
		goto bail;
	}

	if (rr->wire_rdata[4]  != (uint8_t)(lat >> 24) ||
	    rr->wire_rdata[5]  != (uint8_t)(lat >> 16) ||
	    rr->wire_rdata[6]  != (uint8_t)(lat >> 8)  ||
	    rr->wire_rdata[7]  != (uint8_t)lat         ||
	    rr->wire_rdata[8]  != (uint8_t)(lon >> 24) ||
	    rr->wire_rdata[9]  != (uint8_t)(lon >> 16) ||
	    rr->wire_rdata[10] != (uint8_t)(lon >> 8)  ||
	    rr->wire_rdata[11] != (uint8_t)lon         ||
	    rr->wire_rdata[12] != (uint8_t)(alt >> 24) ||
	    rr->wire_rdata[13] != (uint8_t)(alt >> 16) ||
	    rr->wire_rdata[14] != (uint8_t)(alt >> 8)  ||
	    rr->wire_rdata[15] != (uint8_t)alt) {
		lwsl_err("%s: LOC angle / altitude encoding wrong\n", __func__);
		goto bail;
	}

	lwsl_user("LOC rrset encoding: ok\n");
	r = 0;

bail:
	lws_auth_dns_free_zone(&z);

	return r;
}

/*
 * Readers of the raw zonefile (eg, the dnssec-monitor's inventory) parse it
 * with its ${...} substitutions unexpanded.  Those records must survive as
 * text with no wire form, not fail the parse, while the literal ones still
 * encode.
 */

static int
test_unexpanded(void)
{
	static const char *raw =
		"$ORIGIN example.com.\n"
		"$TTL 3600\n"
		"@ IN A ${EXTIP4}\n"
		"_443._tcp IN TLSA ${DANE0}\n"
		"www IN A 192.0.2.1\n";
	struct auth_dns_zone z;
	int r = 1, seen = 0;

	memset(&z, 0, sizeof(z));
	if (lws_auth_dns_parse_zone_buf(raw, strlen(raw), &z)) {
		lwsl_err("%s: raw zone parse failed\n", __func__);
		goto bail;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
						struct auth_dns_rrset, list);
		struct auth_dns_rr *rr = lws_container_of(
				lws_dll2_get_head(&s->rr_list),
				struct auth_dns_rr, list);

		if (!rr->rdata)
			continue;

		if (strstr(rr->rdata, "${")) {
			if (rr->wire_rdata) {
				lwsl_err("%s: %s: '%s' was wire-encoded\n",
					 __func__, s->name, rr->rdata);
				goto bail;
			}
			seen++;
		} else if (!strcmp(s->name, "www.example.com.") &&
			   (!rr->wire_rdata || rr->wire_rdata_len != 4)) {
			lwsl_err("%s: literal A not encoded\n", __func__);
			goto bail;
		}
	} lws_end_foreach_dll(d);

	if (seen != 2) {
		lwsl_err("%s: %d unexpanded records kept, expected 2\n",
			 __func__, seen);
		goto bail;
	}

	lwsl_user("unexpanded substitutions kept as text: ok\n");
	r = 0;

bail:
	lws_auth_dns_free_zone(&z);

	return r;
}

/* canonical wire form of a text name, "." or "" is the root */

static size_t
t_name_to_wire(const char *name, uint8_t *w, size_t max)
{
	const char *p = name;
	size_t o = 0;

	while (*p && *p != '.') {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p), n;

		if (l > 63 || o + 1 + l + 1 > max)
			return 0;
		w[o++] = (uint8_t)l;
		for (n = 0; n < l; n++)
			w[o++] = (uint8_t)tolower((unsigned char)p[n]);
		p = dot ? dot + 1 : p + l;
	}
	w[o++] = 0;

	return o;
}

static void
t_b32hex(const uint8_t *in, size_t len, char *out)
{
	static const char tab[] = "0123456789abcdefghijklmnopqrstuv";
	uint32_t acc = 0;
	int bits = 0;

	while (len--) {
		acc = (acc << 8) | *in++;
		bits += 8;
		while (bits >= 5) {
			*out++ = tab[(acc >> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits)
		*out++ = tab[(acc << (5 - bits)) & 31];
	*out = '\0';
}

static int
t_nsec3_b32(const char *name, const uint8_t *salt, size_t salt_len,
	    unsigned int it, char *b32)
{
	uint8_t w[256], h[LWS_AUTH_DNS_NSEC3_HASH_LEN];
	size_t wl = t_name_to_wire(name, w, sizeof(w));

	if (!wl || lws_auth_dns_nsec3_hash(w, wl, salt, salt_len, it, h))
		return 1;
	t_b32hex(h, sizeof(h), b32);

	return 0;
}

/* find the signed zone's NSEC3 parameters from its NSEC3PARAM */

static int
t_nsec3param(struct auth_dns_zone *z, uint8_t *salt, size_t salt_max,
	     int *salt_len, int *it)
{
	*it = -1;
	*salt_len = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
						struct auth_dns_rrset, list);
		struct auth_dns_rr *rr = lws_container_of(
				lws_dll2_get_head(&s->rr_list),
				struct auth_dns_rr, list);
		const char *f;
		int k;

		if (s->type != 51 || !rr->rdata)
			continue;

		/* "alg flags iterations salt": skip to the iterations field */
		f = rr->rdata;
		for (k = 0; k < 2 && f; k++)
			if ((f = strchr(f, ' ')))
				f++;
		if (!f)
			break;
		*it = atoi(f);
		if (!(f = strchr(f, ' ')))
			break;
		f++;
		if (strcmp(f, "-"))
			*salt_len = lws_hex_to_byte_array(f, salt, (int)salt_max);
	} lws_end_foreach_dll(d);

	return *it < 0 || *salt_len < 0;
}

/* the NSEC3 rrset named by the hash of \p owner, or NULL */

static struct auth_dns_rrset *
t_nsec3_of(struct auth_dns_zone *z, const char *owner, const uint8_t *salt,
	   int salt_len, int it)
{
	char want[40];
	size_t wl, k;

	if (t_nsec3_b32(owner, salt, (size_t)salt_len, (unsigned int)it, want))
		return NULL;
	wl = strlen(want);

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *n3 = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (n3->type != 50 || strlen(n3->name) <= wl ||
		    n3->name[wl] != '.')
			continue;
		for (k = 0; k < wl; k++)
			if (tolower((unsigned char)n3->name[k]) != want[k])
				break;
		if (k == wl)
			return n3;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * NSEC3 owner names must be the RFC 5155 hash, or no resolver can match a
 * denial of existence to the query name: every negative answer from a
 * signed zone then fails validation (SERVFAIL).  Check the hash against the
 * RFC's own Appendix A examples, then check that the zone signed above
 * names each of its NSEC3 by that hash of a real owner, for every owner.
 */

static int
test_nsec3(void)
{
	static const uint8_t rfc_salt[] = { 0xaa, 0xbb, 0xcc, 0xdd };
	static const struct { const char *name, *b32; } kat[] = {
		{ "example",	 "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
		{ "a.example",	 "35mthgpgcu1qg68fab165klnsnk3dpvl" },
		{ "ai.example",	 "gjeqe526plbf1g8mklp59enfd789njgi" },
		{ "ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
		{ "w.example",	 "k8udemvp1j2f7eg6jebps17vp3n8i58h" },
	};
	uint8_t salt[255];
	char b32[40];
	struct auth_dns_zone z;
	int it, salt_len, owners = 0, r = 1;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(kat); n++)
		if (t_nsec3_b32(kat[n].name, rfc_salt, sizeof(rfc_salt), 12,
				b32) || strcmp(b32, kat[n].b32)) {
			lwsl_err("%s: RFC 5155 hash of %s is %s, expected %s\n",
				 __func__, kat[n].name, b32, kat[n].b32);
			return 1;
		}

	if (load_zone(&z, "./test.zone.signed")) {
		lwsl_err("%s: unable to reload signed zone\n", __func__);
		return 1;
	}

	if (t_nsec3param(&z, salt, sizeof(salt), &salt_len, &it)) {
		lwsl_err("%s: no usable NSEC3PARAM in signed zone\n", __func__);
		goto bail;
	}

	/* every owner has an NSEC3 named by its hash ... */

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (s->type == 50 || s->type == 46)
			continue;

		if (!t_nsec3_of(&z, s->name, salt, salt_len, it)) {
			lwsl_err("%s: no NSEC3 for owner %s\n", __func__,
				 s->name);
			goto bail;
		}
		owners++;
	} lws_end_foreach_dll(d);

	lwsl_user("NSEC3 hashes (RFC 5155 examples, %d signed owners): ok\n",
		  owners);
	r = 0;

bail:
	lws_auth_dns_free_zone(&z);

	return r;
}

/* is \p type set in the type bitmaps of NSEC3 wire rdata \p w? */

static int
t_nsec3_has_type(const uint8_t *w, size_t len, uint16_t type)
{
	size_t o = 5;

	/* alg, flags, iterations, salt length + salt, hash length + hash */
	if (len < o || (o += w[4]) >= len || (o += 1u + w[o]) > len)
		return 0;

	while (o + 2 <= len) {
		uint8_t win = w[o], blen = w[o + 1];

		if (o + 2 + blen > len)
			return 0;
		if (win == type >> 8)
			return (type & 0xff) / 8 < blen &&
			       (w[o + 2 + (type & 0xff) / 8] &
					(0x80 >> (type & 7)));
		o += 2u + blen;
	}

	return 0;
}

/*
 * Each owner's NSEC3 must list every type the zone serves there, or it is a
 * signed denial of records that exist.  ns1 has a LOC and a record given in
 * RFC 3597 TYPEnnn form (SSHFP), besides its A; the apex carries the
 * DNSKEYs and NSEC3PARAM the signer adds itself.  The TYPEnnn record must
 * also come back from the signed zone as the same type and RDATA.
 */

static int
test_nsec3_types(void)
{
	static const struct {
		const char	*owner;
		uint16_t	type;
	} want[] = {
		{ "ns1.example.com.",	1 },	/* A */
		{ "ns1.example.com.",	29 },	/* LOC */
		{ "ns1.example.com.",	44 },	/* SSHFP, as TYPE44 */
		{ "ns1.example.com.",	46 },	/* RRSIG */
		{ "example.com.",	6 },	/* SOA */
		{ "example.com.",	48 },	/* DNSKEY */
		{ "example.com.",	51 },	/* NSEC3PARAM */
	};
	struct auth_dns_rrset *n3;
	struct auth_dns_rr *rr;
	struct auth_dns_zone z;
	int it, salt_len, r = 1, sshfp = 0;
	uint8_t salt[255];
	size_t n;

	if (load_zone(&z, "./test-loc.zone.signed")) {
		lwsl_err("%s: unable to reload signed zone\n", __func__);

		return 1;
	}

	if (t_nsec3param(&z, salt, sizeof(salt), &salt_len, &it)) {
		lwsl_err("%s: no usable NSEC3PARAM in signed zone\n", __func__);
		goto bail;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(want); n++) {
		n3 = t_nsec3_of(&z, want[n].owner, salt, salt_len, it);
		if (!n3) {
			lwsl_err("%s: no NSEC3 for %s\n", __func__,
				 want[n].owner);
			goto bail;
		}
		rr = lws_container_of(lws_dll2_get_head(&n3->rr_list),
				      struct auth_dns_rr, list);
		if (!rr->wire_rdata ||
		    !t_nsec3_has_type(rr->wire_rdata, rr->wire_rdata_len,
				      want[n].type)) {
			lwsl_err("%s: NSEC3 for %s denies type %u (%s)\n",
				 __func__, want[n].owner,
				 (unsigned int)want[n].type,
				 rr->rdata ? rr->rdata : "");
			goto bail;
		}
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (s->type != 44 || strcmp(s->name, "ns1.example.com."))
			continue;

		rr = lws_container_of(lws_dll2_get_head(&s->rr_list),
				      struct auth_dns_rr, list);
		if (rr->wire_rdata && rr->wire_rdata_len == 22 &&
		    rr->wire_rdata[0] == 1 && rr->wire_rdata[1] == 1 &&
		    rr->wire_rdata[2] == 0x01 && rr->wire_rdata[21] == 0x67)
			sshfp = 1;
	} lws_end_foreach_dll(d);

	if (!sshfp) {
		lwsl_err("%s: TYPE44 rrset not preserved\n", __func__);
		goto bail;
	}

	lwsl_user("NSEC3 type bitmaps: ok\n");
	r = 0;

bail:
	lws_auth_dns_free_zone(&z);

	return r;
}

/*
 * What the registrar is told must be what the signer publishes: check
 * lws_auth_dns_key_records() against the RFC 6605 example DNSKEY / DS pairs
 * (from public-only JWKs), and that the KSK DNSKEY it describes is the one
 * the zone signed above actually carries.
 */

static int
test_key_records(void)
{
	static const struct {
		const char *jwk, *dnskey, *ds;
	} kat[] = {
		{ /* RFC 6605 6.1 */
			"{\"kty\":\"EC\",\"crv\":\"P-256\","
			"\"x\":\"GojIhhXUN_u4v54ZQqGSnyhWJwaubCvTmeexv7bR6ec\","
			"\"y\":\"W5K0qkKReuHGG3Ae8DXD_nvjAJy6_lovcTFskC3PDQA\"}",
			"257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSq"
			"QpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
			"55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E27"
			"70CE6D6E37DF61D17"
		},
		{ /* RFC 6605 6.2 */
			"{\"kty\":\"EC\",\"crv\":\"P-384\","
			"\"x\":\"xKYaNhWdGOfJ-nPrL8_arkwf2EY3MDJ-SErKivBVSum1w_eg"
			"sXvSADtNJhyem5RC\","
			"\"y\":\"OpgQ6K8X1DRSEkrbYQ-OB-v8_uX45NBwY8rp65F6Glur8I_m"
			"lVNgF6W_qTI37m40\"}",
			"257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/eg"
			"sXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6"
			"Glur8I/mlVNgF6W/qTI37m40",
			"10771 14 4 72D7B62976CE06438E9C0BF319013CF801F09ECC84B8D7E"
			"9495F27E305C6A9B0563A9B5F4D288405C3008A946DF983D6"
		},
	};
	struct lws_auth_dns_key_records kr;
	struct auth_dns_zone z;
	struct lws_jwk jwk;
	int found = 0;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(kat); n++) {
		if (lws_jwk_import(&jwk, NULL, NULL, kat[n].jwk,
				   strlen(kat[n].jwk))) {
			lwsl_err("%s: kat %d: jwk import failed\n", __func__,
				 (int)n);
			return 1;
		}
		if (lws_auth_dns_key_records(&jwk, "example.net.", 257, &kr) ||
		    strcmp(kr.dnskey, kat[n].dnskey) || strcmp(kr.ds, kat[n].ds)) {
			lwsl_err("%s: kat %d: got DNSKEY '%s' DS '%s'\n",
				 __func__, (int)n, kr.dnskey, kr.ds);
			lws_jwk_destroy(&jwk);
			return 1;
		}
		lws_jwk_destroy(&jwk);
	}

	if (lws_jwk_load(&jwk, "./ksk.jwk", NULL, NULL))
		return 1;
	n = (size_t)lws_auth_dns_key_records(&jwk, "warmcat.com.", 257, &kr);
	lws_jwk_destroy(&jwk);
	if (n || load_zone(&z, "./test.zone.signed")) {
		lwsl_err("%s: unable to describe ksk.jwk or load zone\n",
			 __func__);
		return 1;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
		struct auth_dns_rrset *s = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (s->type != 48)
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d1,
				      lws_dll2_get_head(&s->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d1,
						struct auth_dns_rr, list);

			if (!strcmp(rr->rdata, kr.dnskey))
				found = 1;
		} lws_end_foreach_dll(d1);
	} lws_end_foreach_dll(d);

	lws_auth_dns_free_zone(&z);

	if (!found) {
		lwsl_err("%s: signed zone does not carry DNSKEY %s\n",
			 __func__, kr.dnskey);
		return 1;
	}

	lwsl_user("%s: ok (KSK DS %s)\n", __func__, kr.ds);

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info cx_info;
	struct lws_auth_dns_sign_info info;
	struct lws_context *cx;
	
	int res = 1;

	lws_context_info_defaults(&cx_info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &cx_info);

	cx_info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&cx_info);
	if (!cx)
		return 1;

	memset(&info, 0, sizeof(info));
	info.cx = cx;
	info.input_filepath	= "./test.zone.in";
	info.output_filepath	= "./test.zone.signed";
	info.jws_filepath	= "./test.zone.signed.jws";
	info.ksk_jwk_filepath	= "./ksk.jwk";
	info.zsk_jwk_filepath	= "./zsk.jwk";

	const char *sn[] = { "EXTIP4" };
	const char *sv[] = { "127.0.0.1" };
	info.subst_names = sn;
	info.subst_values = sv;
	info.num_substs = 1;

	lwsl_user("Starting test for LWS Authoritative DNS Zone Signer\n");

	if (lws_auth_dns_sign_zone(&info)) {
		lwsl_err("lws_auth_dns_sign_zone failed\n");
		goto bail;
	}

	lwsl_user("lws_auth_dns_sign_zone: ok\n");

	/* Verify the generated zone file RRSIGs directly */
	memset(&info, 0, sizeof(info));
	info.cx = cx;
	info.input_filepath	= "./test.zone.signed";
	info.jws_filepath	= "./test.zone.signed.jws";
	info.zsk_jwk_filepath	= "./zsk.jwk";
	info.ksk_jwk_filepath	= "./ksk.jwk";

	if (lws_auth_dns_verify_zone(&info)) {
		lwsl_err("lws_auth_dns_verify_zone failed\n");
		goto bail;
	}

	lwsl_user("lws_auth_dns_verify_zone: ok\n");

	/* Verify the outer JWS signature */
	{
		struct lws_jwk jwk;
		struct lws_jws_map map;
		char temp[32768];
		int temp_len = sizeof(temp);
		struct stat st;

		int fd = open(info.jws_filepath, LWS_O_RDONLY);
		if (fd < 0 || fstat(fd, &st) < 0) {
			lwsl_err("Failed to open JWS file\n");
			goto bail;
		}

		char *buf = malloc((size_t)st.st_size + 1);
		if (!buf || read(fd, buf, (size_t)st.st_size) != st.st_size) {
			if (buf) free(buf);
			close(fd);
			lwsl_err("Failed to read JWS file\n");
			goto bail;
		}
		buf[st.st_size] = '\0';
		close(fd);

		if (lws_jwk_load(&jwk, info.ksk_jwk_filepath, NULL, NULL)) {
			free(buf);
			lwsl_err("Failed to load JWK for verification\n");
			goto bail;
		}

		if (lws_jws_sig_confirm_compact_b64(buf, (size_t)st.st_size, &map, &jwk, cx, temp, &temp_len)) {
			lws_jwk_destroy(&jwk);
			free(buf);
			lwsl_err("Failed to verify outer JWS signature\n");
			goto bail;
		}

		lwsl_user("JWS signature verified: ok\n");
		lws_jwk_destroy(&jwk);
		free(buf);
	}

	if (test_dotless_origin(cx))
		goto bail;

	if (test_loc(cx))
		goto bail;

	if (test_unexpanded())
		goto bail;

	if (test_nsec3())
		goto bail;

	if (test_nsec3_types())
		goto bail;

	if (test_key_records())
		goto bail;

	res = 0;

bail:
	lws_context_destroy(cx);
	return res;
}
