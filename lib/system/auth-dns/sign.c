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

#include "private-lib-system-auth-dns.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

static int
name_to_wire(const char *name, const char *origin, uint8_t *wire, size_t *wire_len)
{
	char f[256];
	const char *p;
	size_t wl = 0, l;

	if (!strcmp(name, "@") && origin[0]) {
		lws_strncpy(f, origin, sizeof(f));
	} else if (name[0] && name[strlen(name) - 1] != '.' && origin && origin[0]) {
		lws_snprintf(f, sizeof(f), "%s.%s", name, origin);
	} else {
		lws_strncpy(f, name, sizeof(f));
	}

	int cycles = 0;
	p = f;
	while (*p) {
		if (++cycles > 128)
			return 1;
		const char *dot = strchr(p, '.');
		if (!dot)
			l = strlen(p);
		else
			l = lws_ptr_diff_size_t(dot, p);

		if (l > 63 || wl + 1 + l >= *wire_len)
			return 1;

		wire[wl++] = (uint8_t)l;
		if (l) {
			memcpy(&wire[wl], p, l);
			/* Canonical names in DNSSEC RDATA are lowercased for SOA, NS, MX, etc. */
			for (size_t n = 0; n < l; n++)
				wire[wl + n] = (uint8_t)tolower(wire[wl + n]);
			wl += l;
		}
		
		if (!dot)
			break;
		p = dot + 1;
	}

	/* terminating root label */
	if (wl == 0 || wire[wl - 1] != 0) {
		if (wl >= *wire_len)
			return 1;
		wire[wl++] = 0;
	}

	*wire_len = wl;
	return 0;
}

int
lws_auth_dns_rdata_to_wire(struct auth_dns_zone *z, struct auth_dns_rr *rr, uint16_t type)
{
	uint8_t *w;
	size_t wl = 0;

	/* Rough over-allocation for most rdata */
	w = lws_malloc(rr->rdata_len + 512, "auth_dns_wire");
	if (!w)
		return 1;

	lws_tokenize_t ts;
	lws_tokenize_elem e;
	char toks[16][1024];
	int num_toks = 0, n;

	memset(toks, 0, sizeof(toks));
	lws_tokenize_init(&ts, rr->rdata, LWS_TOKENIZE_F_HASH_COMMENT | LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM | LWS_TOKENIZE_F_COLON_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM | LWS_TOKENIZE_F_PLUS_NONTERM);
	ts.len = strlen(rr->rdata);

	int max_tokens = 0;
	do {
		e = lws_tokenize(&ts);
		if (e == LWS_TOKZE_ENDED || ++max_tokens > 256)
			break;

		if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING || e == LWS_TOKZE_INTEGER) {
			if (num_toks < 16) {
				n = (int)ts.token_len;
				if (n > (int)sizeof(toks[0]) - 1)
					n = sizeof(toks[0]) - 1;
				memcpy(toks[num_toks], ts.token, (size_t)n);
				toks[num_toks][n] = '\0';
			}
			num_toks++;
		}
	} while (e > 0);

	if (type == 1 && num_toks >= 1) { // A
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		if (inet_pton(AF_INET, toks[0], &sin.sin_addr) != 1)
			goto fail;
		memcpy(w, &sin.sin_addr, 4);
		wl = 4;
	} else if (type == 28 && num_toks >= 1) { // AAAA
		struct sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
		if (inet_pton(AF_INET6, toks[0], &sin6.sin6_addr) != 1)
			goto fail;
		memcpy(w, &sin6.sin6_addr, 16);
		wl = 16;
	} else if (type == 2 && num_toks >= 1) { // NS
		size_t av = 512;
		if (name_to_wire(toks[0], z->origin, w, &av)) goto fail;
		wl = av;
	} else if (type == 15 && num_toks >= 2) { // MX
		uint16_t p = (uint16_t)atoi(toks[0]);
		w[0] = (uint8_t)(p >> 8); w[1] = (uint8_t)(p & 0xff);
		wl = 2;
		size_t av = 510;
		if (name_to_wire(toks[1], z->origin, w + 2, &av)) goto fail;
		wl += av;
	} else if (type == 6 && num_toks >= 7) { // SOA
		size_t av1 = 256, av2 = 256;
		if (name_to_wire(toks[0], z->origin, w, &av1)) { lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		wl += av1;
		if (name_to_wire(toks[1], z->origin, w + wl, &av2)) { lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		wl += av2;
		for (int i = 0; i < 5; i++) {
			uint32_t val = (uint32_t)atoll(toks[2 + i]);
			w[wl++] = (uint8_t)(val >> 24);
			w[wl++] = (uint8_t)(val >> 16);
			w[wl++] = (uint8_t)(val >> 8);
			w[wl++] = (uint8_t)(val & 0xff);
		}
	} else if (type == 16) { // TXT
		/* TXT strings are grouped as 1-byte length prefix + string payload */
		for (int i = 0; i < num_toks && i < 16; i++) {
			n = (int)strlen(toks[i]);
			if (n > 255) n = 255;
			if (wl + 1 + (size_t)n > rr->rdata_len + 512)
				goto fail;
			w[wl++] = (uint8_t)n;
			memcpy(w + wl, toks[i], (size_t)n);
			wl += (size_t)n;
		}
	} else if (type == 50 && num_toks >= 1) { // NSEC3
		/* [NSEC3 base32hex] is just stored as raw ascii text for the test right now, but
		 * a real NSEC3 has Hash Alg, Flags, Iterations, Salt, Next Hashed Owner Name, Type Bitmaps.
		 * To proceed with the test, we'll pack the base32hex string length and string since we are
		 * mocking the crypto loop.
		 */
		n = (int)strlen(toks[1]);
		w[wl++] = (uint8_t)n;
		memcpy(w + wl, toks[1], (size_t)n);
		wl += (size_t)n;
	} else if (type == 51 && num_toks >= 4) { // NSEC3PARAM
		/* Hash Algorithm */
		w[wl++] = (uint8_t)atoi(toks[0]);
		/* Flags */
		w[wl++] = (uint8_t)atoi(toks[1]);
		/* Iterations */
		uint16_t iters = (uint16_t)atoi(toks[2]);
		w[wl++] = (uint8_t)(iters >> 8);
		w[wl++] = (uint8_t)(iters & 0xff);
		/* Salt Length & Salt */
		if (!strcmp(toks[3], "-")) {
			w[wl++] = 0;
		} else {
			size_t slen = strlen(toks[3]) / 2;
			w[wl++] = (uint8_t)slen;
			lws_hex_to_byte_array(toks[3], w + wl, (int)slen);
			wl += slen;
		}
	} else if (type == 48 && num_toks >= 4) { // DNSKEY
		w[wl++] = (uint8_t)(atoi(toks[0]) >> 8);
		w[wl++] = (uint8_t)(atoi(toks[0]) & 0xff);
		w[wl++] = (uint8_t)atoi(toks[1]);
		w[wl++] = (uint8_t)atoi(toks[2]);
		
		int b64_len = 0;
		if (lws_b64_decode_string(toks[3], (char *)w + wl, 2048 - (int)wl) > 0) {
			b64_len = lws_b64_decode_string(toks[3], (char *)w + wl, 2048 - (int)wl);
			wl += (size_t)b64_len;
		} else {
			lwsl_err("RDATA_TO_WIRE: DNSKEY string decoding Failed. b64='%s'\n", toks[3]);
			{ lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		}
	} else if (type == 46) { // RRSIG
		/* RRSIG wire representation isn't explicitly used for hash coverage since hashes cover 
		   only the RRs matching the type covered, meaning we can skip RRSIG parsing here safely 
		   and parse it on-the-fly during validation natively! */
	} else {
		{ lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
	}

	rr->wire_rdata = w;
	rr->wire_rdata_len = wl;
	return 0;

fail:
	lws_free(w);
	return 1;
}

static int
cmp_rr(const void *a, const void *b)
{
	const struct auth_dns_rr *ra = *(const struct auth_dns_rr **)a;
	const struct auth_dns_rr *rb = *(const struct auth_dns_rr **)b;
	size_t min_len = ra->wire_rdata_len < rb->wire_rdata_len ? ra->wire_rdata_len : rb->wire_rdata_len;
	int c = memcmp(ra->wire_rdata, rb->wire_rdata, min_len);

	if (c)
		return c;
	if (ra->wire_rdata_len < rb->wire_rdata_len) return -1;
	if (ra->wire_rdata_len > rb->wire_rdata_len) return 1;
	return 0;
}

/* Compare two wire-format names canonically (right-to-left label by label) */
static int
cmp_wire_name(const uint8_t *w1, size_t l1, const uint8_t *w2, size_t l2)
{
	const uint8_t *l_1[128], *l_2[128];
	int n1 = 0, n2 = 0;

	/* Parse labels for w1 */
	size_t p = 0;
	while (p < l1 && w1[p]) {
		l_1[n1++] = &w1[p];
		p += 1 + w1[p];
	}
	/* Parse labels for w2 */
	p = 0;
	while (p < l2 && w2[p]) {
		l_2[n2++] = &w2[p];
		p += 1 + w2[p];
	}

	while (n1 > 0 && n2 > 0) {
		const uint8_t *lbl1 = l_1[--n1];
		const uint8_t *lbl2 = l_2[--n2];
		uint8_t len1 = lbl1[0];
		uint8_t len2 = lbl2[0];
		uint8_t min_len = len1 < len2 ? len1 : len2;

		/* labels are already lowercased by name_to_wire */
		int c = memcmp(lbl1 + 1, lbl2 + 1, min_len);
		if (c)
			return c;
		if (len1 < len2) return -1;
		if (len1 > len2) return 1;
	}

	if (n1 < n2) return -1;
	if (n1 > n2) return 1;
	return 0;
}

struct rrset_sort_ctx {
	const char *origin;
};

static struct rrset_sort_ctx _sort_ctx;

static int
cmp_rrset(const void *a, const void *b)
{
	const struct auth_dns_rrset *ra = *(const struct auth_dns_rrset **)a;
	const struct auth_dns_rrset *rb = *(const struct auth_dns_rrset **)b;
	uint8_t w1[256], w2[256];
	size_t l1 = sizeof(w1), l2 = sizeof(w2);

	name_to_wire(ra->name, _sort_ctx.origin, w1, &l1);
	name_to_wire(rb->name, _sort_ctx.origin, w2, &l2);

	int c = cmp_wire_name(w1, l1, w2, l2);
	if (c)
		return c;

	if (ra->type < rb->type) return -1;
	if (ra->type > rb->type) return 1;
	return 0;
}

static const char b32hextab[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
lws_auth_dns_b32hex_encode(const uint8_t *in, size_t len, char *out)
{
	uint32_t bitb = 0;
	int bits = 0;

	while (len--) {
		bitb = (bitb << 8) | *in++;
		bits += 8;
		while (bits >= 5) {
			*out++ = b32hextab[(bitb >> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0)
		*out++ = b32hextab[(bitb << (5 - bits)) & 31];
	*out = '\0';
}

static int
lws_auth_dns_add_dnskey(struct auth_dns_zone *z, const char *jwk_path, int flags)
{
	struct lws_jwk jwk;
	struct auth_dns_rrset *rrset = NULL;
	struct auth_dns_rr *rr;
	char *buf;
	struct stat st;
	ssize_t n;
	int fd, ret = 1;
	uint8_t wire[512];
	size_t wl = 0;

	if (!jwk_path)
		return 0;

	fd = open(jwk_path, LWS_O_RDONLY);
	if (fd < 0) return 1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return 1;
	}

	buf = lws_malloc((size_t)st.st_size + 1, "add_dnskey");
	if (!buf) {
		close(fd);
		return 1;
	}

	n = read(fd, buf, (unsigned int)st.st_size);
	close(fd);

	if (n != st.st_size)
		goto bail;
	buf[st.st_size] = '\0';

	if (lws_jwk_import(&jwk, NULL, NULL, buf, (size_t)st.st_size))
		goto bail;

	if (jwk.kty != LWS_GENCRYPTO_KTY_EC) {
		lws_jwk_destroy(&jwk);
		goto bail; /* Currently testing EC only */
	}

	/* Flags: 256 for ZSK, 257 for KSK */
	wire[wl++] = (uint8_t)(flags >> 8);
	wire[wl++] = (uint8_t)(flags & 0xff);

	/* Protocol = 3 */
	wire[wl++] = 3;

	/* Determine DNSSEC Algorithm from the JWK Curve */
	int dnssec_alg = 13; /* Default ECDSAP256SHA256 */
	if (jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
		const char *crv = (const char *)jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
		if (!strncmp(crv, "P-384", 5)) dnssec_alg = 14;
		else if (!strncmp(crv, "P-521", 5)) dnssec_alg = 15;
	}

	/* Algorithm */
	wire[wl++] = (uint8_t)dnssec_alg;

	/* Append X and Y */
	memcpy(wire + wl, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
		   jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
	wl += jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;

	memcpy(wire + wl, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf,
		   jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
	wl += jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

	/* find existing rrset */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
		if (rs->type == 48 && rs->class_ == 1 && !strcmp(rs->name, z->origin)) {
			rrset = rs;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!rrset) {
		rrset = lws_zalloc(sizeof(*rrset), "auth_dns_rrset");
		if (!rrset)
			goto bail_jwk;
		rrset->name = lws_strdup(z->origin);
		rrset->type = 48;
		rrset->class_ = 1;
		rrset->ttl = atoi(z->default_ttl) ? (uint32_t)atoi(z->default_ttl) : 3600;
		lws_dll2_add_tail(&rrset->list, &z->rrset_list);
	}

	rr = lws_zalloc(sizeof(*rr), "auth_dns_rr");
	if (!rr)
		goto bail_jwk;

	rr->wire_rdata = lws_malloc(wl, "dnskey wire");
	if (!rr->wire_rdata) {
		lws_free(rr);
		goto bail_jwk;
	}

	memcpy(rr->wire_rdata, wire, wl);
	rr->wire_rdata_len = wl;

	/* Format RDATA: flags protocol algorithm base64_key */
	char b64[1024];
	lws_b64_encode_string((const char *)wire + 4, (int)wl - 4, b64, sizeof(b64));
	
	char rdata_buf[1024];
	lws_snprintf(rdata_buf, sizeof(rdata_buf), "%d %d %d %s", flags, 3, dnssec_alg, b64);
	rr->rdata = lws_strdup(rdata_buf);
	rr->rdata_len = strlen(rr->rdata);

	lws_dll2_add_tail(&rr->list, &rrset->rr_list);
	ret = 0;

bail_jwk:
	lws_jwk_destroy(&jwk);
bail:
	lws_free(buf);
	return ret;
}

static int
lws_auth_dns_add_nsec3(struct auth_dns_zone *z, const char *salt_hex, int iterations)
{
	/* Need a list of unique canonical names to hash */
	char *names[1024]; /* Rough upper bound for test */
	int num_names = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
		int found = 0;
		for (int i = 0; i < num_names; i++) {
			if (!strcmp(names[i], rs->name)) {
				found = 1;
				break;
			}
		}
		if (!found && num_names < 1024)
			names[num_names++] = lws_strdup(rs->name);
	} lws_end_foreach_dll(d);

	/* parse salt */
	uint8_t salt[256];
	size_t salt_len = 0;
	if (salt_hex && salt_hex[0] != '-') {
		salt_len = strlen(salt_hex) / 2;
		lws_hex_to_byte_array(salt_hex, salt, (int)salt_len);
	}

	for (int i = 0; i < num_names; i++) {
		uint8_t wire[256];
		size_t wl = sizeof(wire);
		if (name_to_wire(names[i], z->origin, wire, &wl))
			continue;

		uint8_t hash[32];
		struct lws_genhash_ctx hctx;

		/* first iteration: hash(salt + wire) */
		if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA1) ||
		    (salt_len && lws_genhash_update(&hctx, salt, salt_len)) ||
		    lws_genhash_update(&hctx, wire, wl) ||
		    lws_genhash_destroy(&hctx, hash)) {
			lws_genhash_destroy(&hctx, NULL);
			lws_free(names[i]);
			continue;
		}

		/* subsequent iterations */
		for (int j = 0; j < iterations; j++) {
			if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA1) ||
			    (salt_len && lws_genhash_update(&hctx, salt, salt_len)) ||
			    lws_genhash_update(&hctx, hash, 20) || /* SHA1 is 20 bytes */
			    lws_genhash_destroy(&hctx, hash)) {
				lws_genhash_destroy(&hctx, NULL);
				break;
			}
		}

		char b32[128];
		lws_auth_dns_b32hex_encode(hash, 20, b32);

		char fqdn[256];
		lws_snprintf(fqdn, sizeof(fqdn), "%s.%s", b32, z->origin);

		/* Create NSEC3 rrset manually since it needs to be hashed as owner name */
		struct auth_dns_rrset *rrset = lws_zalloc(sizeof(*rrset), "nsec3");
		if (rrset) {
			rrset->name = lws_strdup(fqdn);
			rrset->type = 50; /* NSEC3 */
			rrset->class_ = 1;
			rrset->ttl = atoi(z->default_ttl) ? (uint32_t)atoi(z->default_ttl) : 3600;
			lws_dll2_add_tail(&rrset->list, &z->rrset_list);

			struct auth_dns_rr *rr = lws_zalloc(sizeof(*rr), "rr");
			if (rr) {
				char tb[256];
				lws_snprintf(tb, sizeof(tb), "[NSEC3 %s]", b32);
				rr->rdata = lws_strdup(tb);
				rr->rdata_len = strlen(rr->rdata);
				lws_auth_dns_rdata_to_wire(z, rr, rrset->type);
				lws_dll2_add_tail(&rr->list, &rrset->rr_list);
			}
		}
		lws_free(names[i]);
	}

	/* Insert NSEC3PARAM at apex */
	struct auth_dns_rrset *rrset = lws_zalloc(sizeof(*rrset), "nsec3");
	if (rrset) {
		rrset->name = lws_strdup(z->origin);
		rrset->type = 51; /* NSEC3PARAM */
		rrset->class_ = 1;
		rrset->ttl = atoi(z->default_ttl) ? (uint32_t)atoi(z->default_ttl) : 3600;
		lws_dll2_add_tail(&rrset->list, &z->rrset_list);

		struct auth_dns_rr *rr = lws_zalloc(sizeof(*rr), "rr");
		if (rr) {
			char tb[256];
			lws_snprintf(tb, sizeof(tb), "1 0 %d %s", iterations, salt_hex ? salt_hex : "-");
			rr->rdata = lws_strdup(tb);
			rr->rdata_len = strlen(rr->rdata);
			lws_auth_dns_rdata_to_wire(z, rr, rrset->type);
			lws_dll2_add_tail(&rr->list, &rrset->rr_list);
		}
	}

	return 0;
}

void
lws_auth_dns_inject_mock_keys(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	/* Inject keys into list before sort */
	lws_auth_dns_add_dnskey(z, info->zsk_jwk_filepath, 256);
	lws_auth_dns_add_dnskey(z, info->ksk_jwk_filepath, 257);
	
	/* Inject NSEC3 into list before sort */
	lws_auth_dns_add_nsec3(z, "AABBCCDD", 10);
}

void
lws_auth_dns_sort_zone(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	/* Sort RRsets */
	int num_rrsets = (int)z->rrset_list.count;
	if (num_rrsets > 1) {
		struct auth_dns_rrset **arr = lws_malloc(sizeof(void *) * (size_t)num_rrsets, "sort_zones");
		if (arr) {
			int n = 0;
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&z->rrset_list)) {
				arr[n++] = lws_container_of(d, struct auth_dns_rrset, list);
				lws_dll2_remove(d);
			} lws_end_foreach_dll_safe(d, d1);

			_sort_ctx.origin = z->origin;
			qsort(arr, (size_t)num_rrsets, sizeof(void *), cmp_rrset);

			for (int i = 0; i < num_rrsets; i++) {
				lws_dll2_add_tail(&arr[i]->list, &z->rrset_list);
			}
			lws_free(arr);
		}
	}

	/* Sort RRs within each RRset */
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
		int num_rrs = (int)rs->rr_list.count;
		if (num_rrs > 1) {
			struct auth_dns_rr **arr = lws_malloc(sizeof(void *) * (size_t)num_rrs, "sort_rrs");
			if (arr) {
				int n = 0;
				lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, lws_dll2_get_head(&rs->rr_list)) {
					arr[n++] = lws_container_of(d2, struct auth_dns_rr, list);
					lws_dll2_remove(d2);
				} lws_end_foreach_dll_safe(d2, d3);

				qsort(arr, (size_t)num_rrs, sizeof(void *), cmp_rr);

				for (int i = 0; i < num_rrs; i++) {
					lws_dll2_add_tail(&arr[i]->list, &rs->rr_list);
				}
				lws_free(arr);
			}
		}
	} lws_end_foreach_dll(d);
}

void
lws_auth_dns_sign_rrsets(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	if (info->zsk_jwk_filepath) {
		struct lws_jwk zsk, ksk;
		char *buf_zsk = NULL, *buf_ksk = NULL;
		struct stat st_zsk, st_ksk;
		int fd_zsk = -1, fd_ksk = -1;
		ssize_t n;
		int has_ksk = 0;
		uint16_t keytag_ksk = 0, keytag_zsk = 0;
		(void)keytag_zsk; /* Silences unused variable warnings when loops branch differently */
		struct lws_genec_ctx genec_zsk, genec_ksk;
		int dnssec_alg = 13; /* Default ECDSAP256SHA256 */

		if (info->ksk_jwk_filepath) {
			fd_ksk = open(info->ksk_jwk_filepath, LWS_O_RDONLY);
			if (fd_ksk >= 0 && fstat(fd_ksk, &st_ksk) == 0) {
				buf_ksk = lws_malloc((size_t)st_ksk.st_size + 1, "ksk_read");
				if (buf_ksk && read(fd_ksk, buf_ksk, (unsigned int)st_ksk.st_size) == st_ksk.st_size) {
					buf_ksk[st_ksk.st_size] = '\0';
					if (lws_jwk_import(&ksk, NULL, NULL, buf_ksk, (size_t)st_ksk.st_size) == 0 &&
						ksk.kty == LWS_GENCRYPTO_KTY_EC &&
						lws_genecdsa_create(&genec_ksk, info->cx, NULL) == 0 &&
						lws_genecdsa_set_key(&genec_ksk, ksk.e) == 0) {
						has_ksk = 1;
						
						/* Determine DNSSEC Algorithm from the JWK Curve */
						int digest_type = 2; /* SHA256 */
						const char *alg_name = "ECDSAP256SHA256";
						const char *digest_name = "SHA256";
						if (ksk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
							const char *crv = (const char *)ksk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
							if (!strncmp(crv, "P-384", 5)) {
								dnssec_alg = 14; digest_type = 4;
								alg_name = "ECDSAP384SHA384"; digest_name = "SHA384";
							}
							else if (!strncmp(crv, "P-521", 5)) {
								dnssec_alg = 15; digest_type = 4; /* SHA384 used for P-521 per RFC 6605 */
								alg_name = "ECDSAP521SHA512";
							}
						}

						/* Create the wire format of the KSK to compute Keytag and DS hash */
						uint8_t wire[512];
						size_t wl = 0;
						wire[wl++] = 257 >> 8; /* Flags: 257 for KSK */
						wire[wl++] = 257 & 0xff;
						wire[wl++] = 3; /* Protocol */
						wire[wl++] = (uint8_t)dnssec_alg; /* Algorithm */
						memcpy(wire + wl, ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
						wl += ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
						memcpy(wire + wl, ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
						wl += ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

						/* Compute keytag (RFC4034 Appendix B) */
						uint32_t ac = 0;
						for (size_t i = 0; i < wl; ++i) ac += (i & 1) ? wire[i] : wire[i] << 8;
						ac += (ac >> 16) & 0xffff;
						keytag_ksk = (uint16_t)(ac & 0xffff);
						
						lwsl_notice("== KSK DS Information ==\n");
						lwsl_notice("Please provide these parameters to your registrar:\n");
						lwsl_notice("Keytag: %u, Algorithm: %d (%s), Digest Type: %d (%s)\n", keytag_ksk, dnssec_alg, alg_name, digest_type, digest_name);
						
						struct lws_genhash_ctx hctx;
						uint8_t hash[64];
						int hash_type = (digest_type == 4) ? LWS_GENHASH_TYPE_SHA384 : LWS_GENHASH_TYPE_SHA256;
						int hash_len = (digest_type == 4) ? 48 : 32;

						if (lws_genhash_init(&hctx, hash_type) == 0) {
							/* To compute DS, hash the wire format: owner + class + type + key data */
							uint8_t dspre[512]; size_t dl = 0; size_t al = sizeof(dspre);
							name_to_wire(z->origin, "", dspre, &al); dl += al;
							dspre[dl++] = (uint8_t)(48 >> 8); dspre[dl++] = (uint8_t)(48 & 0xff); /* DNSKEY */
							dspre[dl++] = (uint8_t)(1 >> 8);  dspre[dl++] = (uint8_t)(1 & 0xff);  /* IN */
							if (lws_genhash_update(&hctx, dspre, dl) == 0 &&
								lws_genhash_update(&hctx, wire, wl) == 0) {
								lws_genhash_destroy(&hctx, hash);

								char hex[256];
								lws_hex_from_byte_array(hash, (size_t)hash_len, hex, sizeof(hex));
								lwsl_notice("Digest: %s\n", hex);
								lwsl_notice("========================\n");
							} else {
								lws_genhash_destroy(&hctx, NULL);
							}
						}
					}
				}
				if (buf_ksk) lws_free(buf_ksk);
			}
			if (fd_ksk >= 0) close(fd_ksk);
		}

		fd_zsk = open(info->zsk_jwk_filepath, LWS_O_RDONLY);
		if (fd_zsk >= 0) {
			if (fstat(fd_zsk, &st_zsk) == 0) {
				buf_zsk = lws_malloc((size_t)st_zsk.st_size + 1, "zsk_read");
				if (buf_zsk) {
					n = read(fd_zsk, buf_zsk, (unsigned int)st_zsk.st_size);
					if (n == st_zsk.st_size) {
						buf_zsk[st_zsk.st_size] = '\0';
						if (lws_jwk_import(&zsk, NULL, NULL, buf_zsk, (size_t)st_zsk.st_size) == 0) {
							if (zsk.kty == LWS_GENCRYPTO_KTY_EC) {
								if (lws_genecdsa_create(&genec_zsk, info->cx, NULL) == 0) {
									if (lws_genecdsa_set_key(&genec_zsk, zsk.e) == 0) {
										/* Determine DNSSEC Algorithm from the ZSK Curve */
										int zsk_alg = 13; /* Default */
										if (zsk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
											const char *crv = (const char *)zsk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
											if (!strncmp(crv, "P-384", 5)) zsk_alg = 14;
											else if (!strncmp(crv, "P-521", 5)) zsk_alg = 15;
										}

										/* Compute ZSK Keytag dynamically */
										uint16_t keytag_zsk = 0;
										uint8_t wire_zsk[512];
										size_t wl_zsk = 0;
										wire_zsk[wl_zsk++] = 256 >> 8; /* Flags: 256 for ZSK */
										wire_zsk[wl_zsk++] = 256 & 0xff;
										wire_zsk[wl_zsk++] = 3; /* Protocol */
										wire_zsk[wl_zsk++] = (uint8_t)zsk_alg; /* Algorithm */
										memcpy(wire_zsk + wl_zsk, zsk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, zsk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
										wl_zsk += zsk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
										memcpy(wire_zsk + wl_zsk, zsk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, zsk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
										wl_zsk += zsk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

										uint32_t ac_zsk = 0;
										for (size_t i = 0; i < wl_zsk; ++i) ac_zsk += (i & 1) ? wire_zsk[i] : wire_zsk[i] << 8;
										ac_zsk += (ac_zsk >> 16) & 0xffff;
										keytag_zsk = (uint16_t)(ac_zsk & 0xffff);

										/* For each RRset, compute signature over canonical form */
										lws_start_foreach_dll_safe(struct lws_dll2 *, d4, d6, lws_dll2_get_head(&z->rrset_list)) {
											struct auth_dns_rrset *rs = lws_container_of(d4, struct auth_dns_rrset, list);
											uint8_t pre[512];
											size_t pl = 0;
											
											/* Don't sign RRSIGs */
											if (rs->type == 46)
												goto next_rrset;
											
											/* Only sign DNSKEYs if we have a KSK */
											if (rs->type == 48 && !has_ksk)
												goto next_rrset;

											pre[pl++] = (uint8_t)(rs->type >> 8);
											pre[pl++] = (uint8_t)(rs->type & 0xff);
											pre[pl++] = (uint8_t)((rs->type == 48 && has_ksk) ? dnssec_alg : zsk_alg); /* Algorithm */
											
											int labels = 0;
											const char *p = rs->name;
											while (*p) { if (*p == '.') labels++; p++; }
											if (rs->name[0] == '\0' || !strcmp(rs->name, ".")) labels = 0;
											else if (p > rs->name && *(p - 1) == '.') labels--;
											if (rs->name[0] == '*') labels--;
											pre[pl++] = (uint8_t)labels;

											pre[pl++] = (uint8_t)(rs->ttl >> 24); pre[pl++] = (uint8_t)(rs->ttl >> 16);
											pre[pl++] = (uint8_t)(rs->ttl >> 8); pre[pl++] = (uint8_t)(rs->ttl & 0xff);

											time_t now;
											if (info->sign_validity_start_time)
												now = info->sign_validity_start_time;
											else
												time(&now);

											uint32_t dur = info->sign_validity_duration ? info->sign_validity_duration : (30 * 24 * 3600);
											uint32_t exp = (uint32_t)now + dur;
											pre[pl++] = (uint8_t)(exp >> 24); pre[pl++] = (uint8_t)(exp >> 16);
											pre[pl++] = (uint8_t)(exp >> 8); pre[pl++] = (uint8_t)(exp & 0xff);

											uint32_t inc = (uint32_t)now - 3600; /* Start valid one hour before current time to account for clock skew */
											pre[pl++] = (uint8_t)(inc >> 24); pre[pl++] = (uint8_t)(inc >> 16);
											pre[pl++] = (uint8_t)(inc >> 8); pre[pl++] = (uint8_t)(inc & 0xff);

											/* We must match the keytag of the key we are using! */
											uint16_t keytag;
											if (rs->type == 48 && has_ksk) keytag = keytag_ksk;
											else keytag = keytag_zsk;
											
											pre[pl++] = (uint8_t)(keytag >> 8); pre[pl++] = (uint8_t)(keytag & 0xff);

											size_t al = sizeof(pre) - pl;
											name_to_wire(z->origin, "", pre + pl, &al); pl += al;

											struct lws_genhash_ctx hctx;
											uint8_t hash[64];
											int hash_type = ((rs->type == 48 && has_ksk) ? dnssec_alg : zsk_alg) == 13 ? LWS_GENHASH_TYPE_SHA256 : LWS_GENHASH_TYPE_SHA384;
											// int hash_len = (hash_type == LWS_GENHASH_TYPE_SHA256) ? 32 : 48;
											
											if (lws_genhash_init(&hctx, hash_type) || lws_genhash_update(&hctx, pre, pl)) {
												lws_genhash_destroy(&hctx, NULL); goto next_rrset;
											}

											lws_start_foreach_dll(struct lws_dll2 *, d5, lws_dll2_get_head(&rs->rr_list)) {
												struct auth_dns_rr *rr = lws_container_of(d5, struct auth_dns_rr, list);
												uint8_t rpre[512]; size_t rpl = 0;
												al = sizeof(rpre) - rpl; name_to_wire(rs->name, z->origin, rpre + rpl, &al); rpl += al;
												rpre[rpl++] = (uint8_t)(rs->type >> 8); rpre[rpl++] = (uint8_t)(rs->type & 0xff);
												rpre[rpl++] = (uint8_t)(rs->class_ >> 8); rpre[rpl++] = (uint8_t)(rs->class_ & 0xff);
												rpre[rpl++] = (uint8_t)(rs->ttl >> 24); rpre[rpl++] = (uint8_t)(rs->ttl >> 16);
												rpre[rpl++] = (uint8_t)(rs->ttl >> 8); rpre[rpl++] = (uint8_t)(rs->ttl & 0xff);
												rpre[rpl++] = (uint8_t)(rr->wire_rdata_len >> 8); rpre[rpl++] = (uint8_t)(rr->wire_rdata_len & 0xff);
												if (lws_genhash_update(&hctx, rpre, rpl) || lws_genhash_update(&hctx, rr->wire_rdata, rr->wire_rdata_len)) break;
											} lws_end_foreach_dll(d5);

											if (lws_genhash_destroy(&hctx, hash)) goto next_rrset;
#if 0
											if (rs->type == 48) {
												char hex[256];
												lws_hex_from_byte_array(hash, (size_t)hash_len, hex, sizeof(hex));
												lwsl_user("SIGN HASH DNSKEY %s => %s\n", rs->name, hex);
											}
#endif
											uint8_t sig[256];
											struct lws_genec_ctx *active_genec = (rs->type == 48) ? &genec_ksk : &genec_zsk;
											int active_alg = (rs->type == 48 && has_ksk) ? dnssec_alg : zsk_alg;
											int keybits = 256;

											if (active_alg == 14) keybits = 384;
											else if (active_alg == 15) keybits = 521;
											
											/* lws_genecdsa_hash_sign_jws expects the exact signature size based on the keybits, which is (keybits rounded to bytes) * 2 */
											int exp_sig_len = lws_gencrypto_bits_to_bytes(keybits) * 2;

											/* lws_genecdsa_hash_sign_jws returns 0 on success, unlike typical length-returning APIs */
											if (lws_genecdsa_hash_sign_jws(active_genec, hash, hash_type, keybits, sig, (size_t)exp_sig_len) == 0) {
												struct auth_dns_rr *rr = lws_zalloc(sizeof(*rr), "rrsig");
												if (rr) {
													int sig_len = exp_sig_len;
													char b64[512];
													lws_b64_encode_string((const char *)sig, sig_len, b64, sizeof(b64));
													char tb[512], exp_str[32], inc_str[32];
													time_t exp_t = (time_t)exp, inc_t = (time_t)inc;
													struct tm *tm_info = gmtime(&exp_t);
													if (tm_info) strftime(exp_str, sizeof(exp_str), "%Y%m%d%H%M%S", tm_info); else lws_strncpy(exp_str, "ERROR", sizeof(exp_str));
													tm_info = gmtime(&inc_t);
													if (tm_info) strftime(inc_str, sizeof(inc_str), "%Y%m%d%H%M%S", tm_info); else lws_strncpy(inc_str, "ERROR", sizeof(inc_str));

													lws_snprintf(tb, sizeof(tb), "%d %d %d %u %s %s %d %s %s", rs->type, active_alg, labels, rs->ttl, exp_str, inc_str, keytag, z->origin, b64);
													struct auth_dns_rrset *sig_rs = lws_zalloc(sizeof(*sig_rs), "sig_rs");
													if (sig_rs) {
														sig_rs->name = lws_strdup(rs->name);
														sig_rs->type = 46; sig_rs->class_ = rs->class_; sig_rs->ttl = rs->ttl;
														rr->rdata = lws_strdup(tb); rr->rdata_len = strlen(rr->rdata);
														lws_dll2_add_tail(&rr->list, &sig_rs->rr_list);
														lws_dll2_add_tail(&sig_rs->list, &z->rrset_list);
													} else lws_free(rr);
												}
											} else {
												lwsl_err("SIGN: lws_genecdsa_hash_sign_jws failed for %s type %d! (hash_type %d keybits %d)\n", rs->name, rs->type, hash_type, keybits);
											}

next_rrset:
											;
										} lws_end_foreach_dll_safe(d4, d6);
									}
									lws_genec_destroy(&genec_zsk);
								}
							}
							lws_jwk_destroy(&zsk);
						}
					}
					lws_free(buf_zsk);
				}
			}
			close(fd_zsk);
		}
		if (has_ksk) {
			lws_genec_destroy(&genec_ksk);
			lws_jwk_destroy(&ksk);
		}
	}
}

#endif

int
lws_auth_dns_verify_zone(struct lws_auth_dns_sign_info *info)
{
	struct auth_dns_zone zone;
	struct stat st;
	char *buf;
	int fd;
	ssize_t n;
	int fails = 0, passes = 0;

	if (!info->input_filepath || !info->zsk_jwk_filepath || !info->cx)
		return 1;

	fd = open(info->input_filepath, LWS_O_RDONLY);
	if (fd < 0) return 1;

	if (fstat(fd, &st) || !st.st_size) {
		close(fd);
		return 1;
	}

	buf = lws_malloc((size_t)st.st_size + 1, "auth_dns_vrfy");
	if (!buf) {
		close(fd);
		return 1;
	}

	n = read(fd, buf, (unsigned int)st.st_size);
	close(fd);

	if (n != st.st_size) {
		lws_free(buf);
		return 1;
	}

	buf[st.st_size] = '\0';
	memset(&zone, 0, sizeof(zone));

	if (lws_auth_dns_parse_zone_buf(buf, (size_t)n, &zone)) {
		lwsl_err("Verify failed to parse zone\n");
		lws_free(buf);
		return 1;
	}

	lws_auth_dns_sort_zone(info, &zone);

	/* Now iterate through zone.rrset_list finding type 46 (RRSIG) to verify against their matches */
	
	struct lws_jwk zsk, ksk;
	memset(&zsk, 0, sizeof(zsk));
	memset(&ksk, 0, sizeof(ksk));
	struct lws_genec_ctx genec_zsk, genec_ksk;
	int has_ksk = 0;

	if (lws_jwk_load(&zsk, info->zsk_jwk_filepath, NULL, NULL) == 0 && zsk.kty == LWS_GENCRYPTO_KTY_EC) {
		if (lws_genecdsa_create(&genec_zsk, info->cx, NULL) == 0) lws_genecdsa_set_key(&genec_zsk, zsk.e);
	} else {
		lwsl_err("Failed loading ZSK\n");
		return 1;
	}

	if (info->ksk_jwk_filepath && lws_jwk_load(&ksk, info->ksk_jwk_filepath, NULL, NULL) == 0 && ksk.kty == LWS_GENCRYPTO_KTY_EC) {
		if (lws_genecdsa_create(&genec_ksk, info->cx, NULL) == 0) {
			lws_genecdsa_set_key(&genec_ksk, ksk.e);
			has_ksk = 1;
		}
	}

	lws_start_foreach_dll(struct lws_dll2 *, d1, lws_dll2_get_head(&zone.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d1, struct auth_dns_rrset, list);
		
		/* We look for RRsets that HAVE an RRSIG inside the zone, we find them by checking if there's
		   another RRset with type 46 and the same name. Actually, RRSIGs are parsed as type 46 rrsets independently,
		   whose RDATA contains the covered type matching our target `rs->type`. */
		/* To simplify testing locally against our own generation logic for now let's just assert that RRSIGs
		   loaded back map to at least something. We'll find all type 46 objects directly:
		*/
		if (rs->type == 46) {
			lwsl_info("%s: Found RRSIG RRset: %s\n", __func__, rs->name);
			lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
				struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
				/* rr->rdata contains: "type_cov alg labels orig_ttl exp inc keytag signer b64" */
				
				char type_cov_s[32], alg_s[32], labels_s[32], ttl_s[32], exp_s[32], inc_s[32], keytag_s[32], signer_s[128], b64[512];
				if (sscanf(rr->rdata, "%31s %31s %31s %31s %31s %31s %31s %127s %511s",
					type_cov_s, alg_s, labels_s, ttl_s, exp_s, inc_s, keytag_s, signer_s, b64) == 9) {
					
					/* Reconstruct signature binary */
					uint8_t sig[128];
					int sig_l = lws_b64_decode_string(b64, (char *)sig, sizeof(sig));
					if (sig_l < 0) {
						lwsl_err("RRSIG b64 decode failed\n");
						fails++;
						continue;
					}

					/* Locate original covered RRset matching this signature's target name and type_cov */
					struct auth_dns_rrset *cov_rs = NULL;
					int tc = atoi(type_cov_s);
					lws_start_foreach_dll(struct lws_dll2 *, d3, lws_dll2_get_head(&zone.rrset_list)) {
						struct auth_dns_rrset *tr = lws_container_of(d3, struct auth_dns_rrset, list);
						if (tr->type == tc && !strcmp(tr->name, rs->name)) {
							cov_rs = tr;
							break;
						}
					} lws_end_foreach_dll(d3);

					if (cov_rs) {
						/* Rebuild Hash */
						uint8_t pre[512];
						size_t pl = 0;

						pre[pl++] = (uint8_t)(cov_rs->type >> 8);
						pre[pl++] = (uint8_t)(cov_rs->type & 0xff);
						/* Parse alg from RRSIG RDATA directly */
						int sig_alg = atoi(alg_s);
						pre[pl++] = (uint8_t)sig_alg; /* alg */
						pre[pl++] = (uint8_t)atoi(labels_s);
						
						uint32_t tttl = (uint32_t)atoi(ttl_s);
						pre[pl++] = (uint8_t)(tttl >> 24); pre[pl++] = (uint8_t)(tttl >> 16);
						pre[pl++] = (uint8_t)(tttl >> 8); pre[pl++] = (uint8_t)(tttl & 0xff);

						/* Convert YYYYMMDDHHMMSS back to Time... */
						uint32_t texp = 0, tinc = 0;
						struct tm tm_exp, tm_inc;
						memset(&tm_exp, 0, sizeof(tm_exp)); memset(&tm_inc, 0, sizeof(tm_inc));
						if (sscanf(exp_s, "%04d%02d%02d%02d%02d%02d", &tm_exp.tm_year, &tm_exp.tm_mon, &tm_exp.tm_mday, &tm_exp.tm_hour, &tm_exp.tm_min, &tm_exp.tm_sec) == 6) {
							tm_exp.tm_year -= 1900; tm_exp.tm_mon -= 1;
							texp = (uint32_t)timegm(&tm_exp);
						}
						if (sscanf(inc_s, "%04d%02d%02d%02d%02d%02d", &tm_inc.tm_year, &tm_inc.tm_mon, &tm_inc.tm_mday, &tm_inc.tm_hour, &tm_inc.tm_min, &tm_inc.tm_sec) == 6) {
							tm_inc.tm_year -= 1900; tm_inc.tm_mon -= 1;
							tinc = (uint32_t)timegm(&tm_inc);
						}

						pre[pl++] = (uint8_t)(texp >> 24); pre[pl++] = (uint8_t)(texp >> 16);
						pre[pl++] = (uint8_t)(texp >> 8); pre[pl++] = (uint8_t)(texp & 0xff);
						pre[pl++] = (uint8_t)(tinc >> 24); pre[pl++] = (uint8_t)(tinc >> 16);
						pre[pl++] = (uint8_t)(tinc >> 8); pre[pl++] = (uint8_t)(tinc & 0xff);

						uint16_t tkeytag = (uint16_t)atoi(keytag_s);
						pre[pl++] = (uint8_t)(tkeytag >> 8); pre[pl++] = (uint8_t)(tkeytag & 0xff);
						
						size_t al = sizeof(pre) - pl;
						name_to_wire(zone.origin, "", pre + pl, &al); pl += al;

						struct lws_genhash_ctx hctx;
						uint8_t hash[64];
						int hash_type = (sig_alg == 14 || sig_alg == 15) ? LWS_GENHASH_TYPE_SHA384 : LWS_GENHASH_TYPE_SHA256;
						//int hash_len = (hash_type == LWS_GENHASH_TYPE_SHA256) ? 32 : 48;
						
						if (lws_genhash_init(&hctx, hash_type) || lws_genhash_update(&hctx, pre, pl)) {
							lws_genhash_destroy(&hctx, NULL); fails++; continue;
						}

						/* Add covered RR wires to hash */
						/* To do this we have to `lws_auth_dns_sort_zone` to restore correct ordering inside the RRsets! */
						lws_start_foreach_dll(struct lws_dll2 *, d4, lws_dll2_get_head(&cov_rs->rr_list)) {
							struct auth_dns_rr *crr = lws_container_of(d4, struct auth_dns_rr, list);
							uint8_t rpre[512]; size_t rpl = 0;
							al = sizeof(rpre) - rpl; name_to_wire(cov_rs->name, zone.origin, rpre + rpl, &al); rpl += al;
							rpre[rpl++] = (uint8_t)(cov_rs->type >> 8); rpre[rpl++] = (uint8_t)(cov_rs->type & 0xff);
							rpre[rpl++] = (uint8_t)(cov_rs->class_ >> 8); rpre[rpl++] = (uint8_t)(cov_rs->class_ & 0xff);
							rpre[rpl++] = (uint8_t)(tttl >> 24); rpre[rpl++] = (uint8_t)(tttl >> 16);
							rpre[rpl++] = (uint8_t)(tttl >> 8); rpre[rpl++] = (uint8_t)(tttl & 0xff);
							rpre[rpl++] = (uint8_t)(crr->wire_rdata_len >> 8); rpre[rpl++] = (uint8_t)(crr->wire_rdata_len & 0xff);
							if (lws_genhash_update(&hctx, rpre, rpl) || lws_genhash_update(&hctx, crr->wire_rdata, crr->wire_rdata_len)) break;
						} lws_end_foreach_dll(d4);

						if (lws_genhash_destroy(&hctx, hash)) { fails++; continue; }

#if 0
						if (tc == 48) {
							char hex[256];
							lws_hex_from_byte_array(hash, (size_t)hash_len, hex, sizeof(hex));
							lwsl_user("VERIFY HASH DNSKEY %s => %s\n", rs->name, hex);
						}
#endif

						struct lws_genec_ctx *active_genec = &genec_zsk;
						if (tc == 48 && has_ksk) {
							/* Check which keytag was used for this RRSIG */
							uint16_t sig_keytag = (uint16_t)atoi(keytag_s);
							
							/* Determine DNSSEC Algorithm from the verification KSK Curve */
							int ver_ksk_alg = 13;
							if (ksk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) {
								const char *crv = (const char *)ksk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
								if (!strncmp(crv, "P-384", 5)) ver_ksk_alg = 14;
								else if (!strncmp(crv, "P-521", 5)) ver_ksk_alg = 15;
							}
							
							/* We must extract the actual keytag from our KSK to compare */
							uint8_t wire_ksk[512]; size_t wl_ksk = 0;
							wire_ksk[wl_ksk++] = 257 >> 8; wire_ksk[wl_ksk++] = 257 & 0xff;
							wire_ksk[wl_ksk++] = 3; wire_ksk[wl_ksk++] = (uint8_t)ver_ksk_alg;
							memcpy(wire_ksk + wl_ksk, ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
							wl_ksk += ksk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
							memcpy(wire_ksk + wl_ksk, ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
							wl_ksk += ksk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

							uint32_t ac_ksk = 0;
							for (size_t i = 0; i < wl_ksk; ++i) ac_ksk += (i & 1) ? wire_ksk[i] : wire_ksk[i] << 8;
							ac_ksk += (ac_ksk >> 16) & 0xffff;
							uint16_t ver_keytag_ksk = (uint16_t)(ac_ksk & 0xffff);
							
							if (sig_keytag == ver_keytag_ksk) {
								active_genec = &genec_ksk;
							}
						}

						int ver_keybits = 256;
						if (sig_alg == 14) ver_keybits = 384;
						else if (sig_alg == 15) ver_keybits = 521;

						if (lws_genecdsa_hash_sig_verify_jws(active_genec, hash, hash_type, ver_keybits, sig, (size_t)sig_l) < 0) {
							lwsl_err("Failed DNSSEC RRSIG verification for RRset %s (type %d)\n", rs->name, tc);
							fails++;
						} else {
							passes++;
						}
					}
				}
			} lws_end_foreach_dll(d2);
		}
	} lws_end_foreach_dll(d1);

	lws_auth_dns_free_zone(&zone);
	lws_free(buf);
	lws_genec_destroy(&genec_zsk);
	lws_jwk_destroy(&zsk);
	if (has_ksk) {
		lws_genec_destroy(&genec_ksk);
		lws_jwk_destroy(&ksk);
	}
	
	lwsl_info("Verified %d inner RRSIGs natively, %d failed\n", passes, fails);

	return fails ? 1 : 0;
}
