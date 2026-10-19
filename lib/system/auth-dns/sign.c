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
#include <ctype.h>
#include <math.h>

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

/*
 * The one table of RR type mnemonics the signer understands.  The zone
 * parser, the signed zone writer, NSEC3 type bitmaps and RRSIG type covered
 * all go through it, so they cannot disagree about a type: NSEC3 bitmaps
 * built from a table that had fallen behind the parser used to deny LOC and
 * every TYPEnnn RRset that the zone was actually serving.  Types not in the
 * table are written and read in the RFC 3597 "TYPEnnn" form.
 */

static const struct {
	const char	*name;
	uint16_t	type;
} auth_dns_types[] = {
	{ "A",		1 },
	{ "NS",		2 },
	{ "CNAME",	5 },
	{ "SOA",	6 },
	{ "MX",		15 },
	{ "TXT",	16 },
	{ "AAAA",	28 },
	{ "LOC",	29 },
	{ "DS",		43 },
	{ "RRSIG",	46 },
	{ "DNSKEY",	48 },
	{ "NSEC3",	50 },
	{ "NSEC3PARAM",	51 },
	{ "TLSA",	52 },
	{ "HTTPS",	65 },
	{ "CAA",	257 },
};

/* a decimal number 0..max and nothing else: 0 if so, with it in *v */

static int
auth_dns_decimal(const char *s, uint32_t max, uint32_t *v)
{
	uint64_t t = 0; /* <= max before each step, so it cannot overflow */

	if (!*s)
		return 1;

	while (*s >= '0' && *s <= '9') {
		t = (t * 10) + (uint64_t)(*s++ - '0');
		if (t > max)
			return 1;
	}

	if (*s)
		return 1;

	*v = (uint32_t)t;

	return 0;
}

/* a decimal RR type 1..65535 and nothing else, or 0 */

static uint16_t
auth_dns_type_decimal(const char *s)
{
	uint32_t t;

	return auth_dns_decimal(s, 0xffff, &t) ? 0 : (uint16_t)t;
}

uint16_t
lws_auth_dns_type_from_str(const char *s)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(auth_dns_types); n++)
		if (!strcasecmp(s, auth_dns_types[n].name))
			return auth_dns_types[n].type;

	if (!strncasecmp(s, "TYPE", 4))
		return auth_dns_type_decimal(s + 4);

	return 0;
}

const char *
lws_auth_dns_type_to_str(uint16_t type, char *buf, size_t len)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(auth_dns_types); n++)
		if (auth_dns_types[n].type == type)
			return auth_dns_types[n].name;

	lws_snprintf(buf, len, "TYPE%u", (unsigned int)type);

	return buf;
}

/*
 * A type inside RDATA (NSEC3 bitmap, RRSIG type covered) may also be plain
 * decimal, which is how the signer has always written RRSIG type covered
 */

static uint16_t
auth_dns_rdata_type(const char *s)
{
	uint16_t t = lws_auth_dns_type_from_str(s);

	return t ? t : auth_dns_type_decimal(s);
}

static int
lws_auth_dns_b32hex_decode(const char *in, uint8_t *out, size_t out_max)
{
	uint32_t bitb = 0;
	int bits = 0;
	size_t olen = 0;

	while (*in) {
		int val = -1;
		if (*in >= '0' && *in <= '9') val = *in - '0';
		else if (*in >= 'A' && *in <= 'V') val = *in - 'A' + 10;
		else if (*in >= 'a' && *in <= 'v') val = *in - 'a' + 10;

		if (val >= 0) {
			bitb = (bitb << 5) | (uint32_t)val;
			bits += 5;
			if (bits >= 8) {
				if (olen >= out_max) return -1;
				out[olen++] = (uint8_t)(bitb >> (bits - 8));
				bits -= 8;
			}
		}
		in++;
	}
	return (int)olen;
}

/*
 * Scratch for one RDATA conversion.  It is heap-allocated because it is far
 * too big for the stack of an event-loop thread (the zone text this is driven
 * from can come from the network, see the DHT DNSSEC plugin).
 *
 * `w` is sized for the largest RDATA the DNS wire format can express, and
 * every write into it below is bounds-checked with WCHK() before it happens.
 * Sizing the output from the length of the presentation text (which is what we
 * used to do) is not safe: several types emit more wire bytes than they
 * consume text bytes, eg, an NSEC3 type bitmap costs 34 wire bytes per ~5
 * bytes of token, an SVCB ipv6hint 16 wire bytes per 2-byte "::", and an SOA
 * emits two 256-byte names and 20 bytes of integers for as little as 13 bytes
 * of text when $ORIGIN is long.
 */

/* the most presentation tokens one RDATA is read as */
#define AUTH_DNS_RDATA_MAX_TOKS 64

struct auth_dns_rdata_scratch {
	char		toks[AUTH_DNS_RDATA_MAX_TOKS][1024];
	char		accum[65536];	/* hex / base64 reassembly */
	uint8_t		window_blocks[256][32]; /* NSEC3: 256 windows, 32B max */
	uint8_t		window_max[256];
	uint8_t		w[65535];	/* max RDATA the wire format allows */
};

/* bail unless there is room for _n more bytes of wire RDATA */
#define WCHK(_n) do { if (wl + (size_t)(_n) > sizeof(sc->w)) goto fail; } while (0)

/*
 * Decode a hex presentation field into exactly len bytes at w, or fail.
 *
 * The callers size the RDATA from the length of the text and then copy all of
 * it out of the (not cleared) scratch, so a field that stops decoding part of
 * the way through, or has an odd digit left over, must fail the RR rather
 * than leave the tail of its bytes holding whatever the scratch held before.
 */

static int
hex_to_wire(const char *hex, uint8_t *w, size_t len)
{
	return strlen(hex) != len * 2 ||
	       lws_hex_to_byte_array(hex, w, (int)len) != (int)len;
}

/*
 * LOC (RFC 1876) helpers
 *
 * The presentation format spells an angle as up to three numeric tokens
 * (degrees [minutes [seconds]]) followed by a single direction letter, and a
 * distance as a decimal count of metres with an optional 'm' suffix.  On the
 * wire, latitude and longitude are unsigned 32-bit counts of
 * milliarcseconds biased by 2^31 (the equator / prime meridian), and
 * altitude is an unsigned 32-bit count of centimetres from 100000m below the
 * reference spheroid, ie, biased by 10000000cm.  Size and precision fields
 * are centimetres compressed to one byte as a decimal mantissa (0..9) and
 * exponent (0..9), so they are at most 9e9cm.
 *
 * strtod() also accepts "nan", "inf" and values far past anything the wire
 * can hold, so every value is checked finite and in range before it is
 * converted, and the conversions are done in 64 bits: long is only 32 bits
 * on some of our platforms.
 */

/* parse one dms group, advancing *ti past it; returns the angle in degrees */

static int
loc_dms(char (*toks)[1024], int *ti, int num_toks, double *degrees)
{
	double v[3] = { 0, 0, 0 };
	char dir;
	int n = 0;

	while (*ti < num_toks && n < 3) {
		char *e;

		if (!strcasecmp(toks[*ti], "N") || !strcasecmp(toks[*ti], "S") ||
		    !strcasecmp(toks[*ti], "E") || !strcasecmp(toks[*ti], "W"))
			break;

		v[n] = strtod(toks[*ti], &e);
		if (e == toks[*ti] || *e || !isfinite(v[n]) || v[n] < 0.0)
			return 1;
		n++;
		(*ti)++;
	}

	if (*ti >= num_toks || toks[*ti][1])
		return 1;

	dir = (char)toupper((unsigned char)toks[*ti][0]);
	if (dir != 'N' && dir != 'S' && dir != 'E' && dir != 'W')
		return 1;
	(*ti)++;

	/* only whole degrees, or degrees and minutes, or all three are legal */

	if (n == 2 && v[1] >= 60.0)
		return 1;
	if (n == 3 && (v[1] >= 60.0 || v[2] >= 60.0))
		return 1;

	*degrees = v[0];
	if (n > 1)
		*degrees += v[1] / 60.0;
	if (n > 2)
		*degrees += v[2] / 3600.0;

	if (dir == 'S' || dir == 'W')
		*degrees = -*degrees;

	return 0;
}

/* parse one metre-valued token, eg "-24m" or "0.00m"; returns 0 if it is one */

static int
loc_metres(const char *t, double *m)
{
	char *e;
	double d = strtod(t, &e);

	if (e == t)
		return 1;
	if (*e == 'm')
		e++;

	if (*e || !isfinite(d))
		return 1;

	*m = d;

	return 0;
}

/*
 * compress a centimetre count into the RFC 1876 mantissa / exponent byte,
 * the caller has checked it is within 0 .. 9e9
 */

static uint8_t
loc_encode_cm(double cm)
{
	uint64_t mant = (uint64_t)llround(cm);
	uint8_t e = 0;

	while (mant > 9) {
		mant /= 10;
		e++;
	}

	return (uint8_t)((mant << 4) | e);
}

static void
loc_put_u32(uint8_t *w, uint32_t v)
{
	w[0] = (uint8_t)(v >> 24);
	w[1] = (uint8_t)(v >> 16);
	w[2] = (uint8_t)(v >> 8);
	w[3] = (uint8_t)v;
}


int
lws_auth_dns_rdata_to_wire(struct auth_dns_zone *z, struct auth_dns_rr *rr, uint16_t type)
{
	struct auth_dns_rdata_scratch *sc;
	char (*toks)[1024];
	uint8_t *w;
	size_t wl = 0;

	if (!rr->rdata)
		return 1;

	sc = lws_malloc(sizeof(*sc), "auth_dns_wire");
	if (!sc)
		return 1;

	w = sc->w;
	toks = sc->toks;

	lws_tokenize_t ts;
	lws_tokenize_elem e;
	int num_toks = 0, n;

	memset(sc->toks, 0, sizeof(sc->toks));
	lws_tokenize_init(&ts, rr->rdata, LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM | LWS_TOKENIZE_F_COLON_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM | LWS_TOKENIZE_F_PLUS_NONTERM | LWS_TOKENIZE_F_CHUNK);
	ts.len = strlen(rr->rdata);

	int max_tokens = 0;
	int tok_ofs = 0;
	do {
		e = lws_tokenize(&ts);
		if (e == LWS_TOKZE_ENDED)
			break;
		max_tokens++;
		if (max_tokens > 2048)
			break;

		if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING || e == LWS_TOKZE_INTEGER ||
		    e == LWS_TOKZE_TOKEN_CHUNK || e == LWS_TOKZE_QUOTED_STRING_CHUNK) {
			if (num_toks < AUTH_DNS_RDATA_MAX_TOKS) {
				n = (int)ts.token_len;
				if (n > (int)sizeof(toks[0]) - 1 - tok_ofs)
					n = (int)sizeof(toks[0]) - 1 - tok_ofs;
				if (n > 0) {
					memcpy(toks[num_toks] + tok_ofs, ts.token, (size_t)n);
					toks[num_toks][tok_ofs + n] = '\0';
					tok_ofs += n;
				}
			}

			if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_QUOTED_STRING || e == LWS_TOKZE_INTEGER) {
				if (num_toks < AUTH_DNS_RDATA_MAX_TOKS)
					num_toks++;
				tok_ofs = 0;
			}
		}
	} while (e > 0);

	/* Check for generic RFC 3597 representation: starts with \# */
	const char *rd_start = rr->rdata;
	while (*rd_start == ' ' || *rd_start == '\t') rd_start++;
	if (rd_start[0] == '\\' && rd_start[1] == '#') {
		if (num_toks < 2) goto fail;
		int gen_len = atoi(toks[0]);
		if (gen_len < 0 || gen_len > 65535) goto fail;

		sc->accum[0] = '\0';
		for (int i = 1; i < num_toks; i++) {
			strncat(sc->accum, toks[i], sizeof(sc->accum) - strlen(sc->accum) - 1);
		}
		WCHK(gen_len);
		if (hex_to_wire(sc->accum, w, (size_t)gen_len)) {
			lwsl_err("generic RDATA is not %d bytes of hex\n", gen_len);
			goto fail;
		}
		wl = (size_t)gen_len;

		goto done;
	}

	if (type == 1 && num_toks >= 1) { // A
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		if (inet_pton(AF_INET, toks[0], &sin.sin_addr) != 1)
			goto fail;
		WCHK(4);
		memcpy(w, &sin.sin_addr, 4);
		wl = 4;
	} else if (type == 28 && num_toks >= 1) { // AAAA
		struct sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
		if (inet_pton(AF_INET6, toks[0], &sin6.sin6_addr) != 1)
			goto fail;
		WCHK(16);
		memcpy(w, &sin6.sin6_addr, 16);
		wl = 16;
	} else if (type == 2 && num_toks >= 1) { // NS
		size_t av = sizeof(sc->w);
		if (name_to_wire(toks[0], z->origin, w, &av)) goto fail;
		wl = av;
	} else if (type == 29 && num_toks >= 4) { // LOC, RFC 1876
		static const double mas_bias = 2147483648.0;  /* 2^31 mas  */
		static const double alt_bias = 10000000.0;  /* 100000m in cm */
		double lat, lon, d, alt = 0, siz = 1, hp = 10000, vp = 10;
		int64_t latw, lonw, altw;
		int ti = 0;

		if (loc_dms(toks, &ti, num_toks, &lat) ||
		    loc_dms(toks, &ti, num_toks, &lon) ||
		    fabs(lat) > 90.0 || fabs(lon) > 180.0)
			goto fail;

		/* altitude, size, horizontal and vertical precision are
		 * optional and default per RFC 1876 section "Presentation
		 * format"; anything left after them is not LOC rdata
		 */

		if (ti < num_toks && !loc_metres(toks[ti], &d)) { alt = d; ti++; }
		if (ti < num_toks && !loc_metres(toks[ti], &d)) { siz = d; ti++; }
		if (ti < num_toks && !loc_metres(toks[ti], &d)) { hp  = d; ti++; }
		if (ti < num_toks && !loc_metres(toks[ti], &d)) { vp  = d; ti++; }
		if (ti != num_toks)
			goto fail;

		/*
		 * RFC 1876 limits altitude to -100000.00 .. 42849672.95m and
		 * size and precisions to 0 .. 90000000.00m
		 */
		if (alt < -100000.0 || alt > 42849672.95 ||
		    siz < 0.0 || siz > 90000000.0 ||
		    hp  < 0.0 || hp  > 90000000.0 ||
		    vp  < 0.0 || vp  > 90000000.0)
			goto fail;

		latw = (int64_t)llround(mas_bias + lat * 3600000.0);
		lonw = (int64_t)llround(mas_bias + lon * 3600000.0);
		altw = (int64_t)llround(alt_bias + alt * 100.0);
		if (latw < 0 || latw > (int64_t)UINT32_MAX ||
		    lonw < 0 || lonw > (int64_t)UINT32_MAX ||
		    altw < 0 || altw > (int64_t)UINT32_MAX)
			goto fail;

		WCHK(16);
		w[0] = 0; /* version 0 */
		w[1] = loc_encode_cm(siz * 100.0);
		w[2] = loc_encode_cm(hp * 100.0);
		w[3] = loc_encode_cm(vp * 100.0);
		loc_put_u32(&w[4],  (uint32_t)latw);
		loc_put_u32(&w[8],  (uint32_t)lonw);
		loc_put_u32(&w[12], (uint32_t)altw);
		wl = 16;
	} else if (type == 5 && num_toks >= 1) { // CNAME
		size_t av = sizeof(sc->w);
		if (name_to_wire(toks[0], z->origin, w, &av)) goto fail;
		wl = av;
	} else if (type == 15 && num_toks >= 2) { // MX
		uint16_t p = (uint16_t)atoi(toks[0]);
		WCHK(2);
		w[0] = (uint8_t)(p >> 8); w[1] = (uint8_t)(p & 0xff);
		wl = 2;
		size_t av = sizeof(sc->w) - wl;
		if (name_to_wire(toks[1], z->origin, w + 2, &av)) goto fail;
		wl += av;
	} else if (type == 6 && num_toks >= 7) { // SOA
		/*
		 * name_to_wire() bounds itself only against the space we tell
		 * it about, so it must be told what is actually left
		 */
		size_t av1 = sizeof(sc->w), av2;
		if (name_to_wire(toks[0], z->origin, w, &av1)) { lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		wl += av1;
		av2 = sizeof(sc->w) - wl;
		if (name_to_wire(toks[1], z->origin, w + wl, &av2)) { lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		wl += av2;
		WCHK(5 * 4);
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
			WCHK(1 + (size_t)n);
			w[wl++] = (uint8_t)n;
			memcpy(w + wl, toks[i], (size_t)n);
			wl += (size_t)n;
		}
	} else if (type == 52 && num_toks >= 4) { // TLSA
		WCHK(3);
		w[wl++] = (uint8_t)atoi(toks[0]); /* Usage */
		w[wl++] = (uint8_t)atoi(toks[1]); /* Selector */
		w[wl++] = (uint8_t)atoi(toks[2]); /* Matching Type */

		sc->accum[0] = '\0';
		for (int i = 3; i < num_toks; i++) {
			strncat(sc->accum, toks[i], sizeof(sc->accum) - strlen(sc->accum) - 1);
		}
		size_t hlen = strlen(sc->accum) / 2;
		WCHK(hlen);
		if (hex_to_wire(sc->accum, w + wl, hlen))
			goto fail;
		wl += hlen;
	} else if (type == 43 && num_toks >= 4) { // DS, RFC 4034 5.3
		uint32_t keytag, alg, dtype;
		size_t hlen;

		if (auth_dns_decimal(toks[0], 0xffff, &keytag) ||
		    auth_dns_decimal(toks[1], 0xff, &alg) ||
		    auth_dns_decimal(toks[2], 0xff, &dtype))
			goto fail;

		/* the digest may be split into several tokens */
		sc->accum[0] = '\0';
		for (int i = 3; i < num_toks; i++)
			strncat(sc->accum, toks[i],
				sizeof(sc->accum) - strlen(sc->accum) - 1);

		hlen = strlen(sc->accum) / 2;
		if (!hlen)
			goto fail;

		WCHK(4 + hlen);
		lws_ser_wu16be(w, (uint16_t)keytag);
		w[2] = (uint8_t)alg;
		w[3] = (uint8_t)dtype;
		wl = 4;
		if (hex_to_wire(sc->accum, w + wl, hlen))
			goto fail;
		wl += hlen;
	} else if (type == 50 && num_toks >= 5) { // NSEC3
		int tidx = 0;
		if (!strcasecmp(toks[tidx], "NSEC3"))
			tidx++;
		if (num_toks - tidx < 5) goto fail;

		/* Format: HashAlg Flags Iterations Salt NextB32 Type1 Type2 ... */
		WCHK(4);
		w[wl++] = (uint8_t)atoi(toks[tidx + 0]); /* Hash Alg */
		w[wl++] = (uint8_t)atoi(toks[tidx + 1]); /* Flags */
		uint16_t iters = (uint16_t)atoi(toks[tidx + 2]); /* Iterations */
		w[wl++] = (uint8_t)(iters >> 8);
		w[wl++] = (uint8_t)(iters & 0xff);

		/* Salt Length & Salt */
		if (!strcmp(toks[tidx + 3], "-")) {
			WCHK(1);
			w[wl++] = 0;
		} else {
			size_t slen = strlen(toks[tidx + 3]) / 2;
			if (slen > 255) goto fail;
			WCHK(1 + slen);
			w[wl++] = (uint8_t)slen;
			if (hex_to_wire(toks[tidx + 3], w + wl, slen))
				goto fail;
			wl += slen;
		}

		/* Hash Length & Next Hashed Owner Name */
		/* The NextHashedOwnerName is base32hex encoded without padding. */
		/* We need to decode it back into binary. */
		uint8_t nxt_hash[64];
		int nxt_len = lws_auth_dns_b32hex_decode(toks[tidx + 4], nxt_hash, sizeof(nxt_hash));
		if (nxt_len < 0) goto fail;
		WCHK(1 + (size_t)nxt_len);
		w[wl++] = (uint8_t)nxt_len;
		memcpy(w + wl, nxt_hash, (size_t)nxt_len);
		wl += (size_t)nxt_len;

		/* Type Bit Maps */
		/* Build the type bit maps from the remaining tokens */
		uint8_t (*window_blocks)[32] = sc->window_blocks;
		uint8_t *window_max = sc->window_max;
		memset(sc->window_blocks, 0, sizeof(sc->window_blocks));
		memset(sc->window_max, 0, sizeof(sc->window_max));

		for (int i = tidx + 5; i < num_toks; i++) {
			uint16_t ty = auth_dns_rdata_type(toks[i]);
			int win, byte_idx, bit_idx;

			/*
			 * a type we cannot place would silently vanish from
			 * the signed bitmap, ie, be denied: refuse the RR
			 */
			if (!ty) {
				lwsl_err("%s: NSEC3 bitmap type '%s' unknown\n",
					 __func__, toks[i]);
				goto fail;
			}

			win = ty / 256;
			byte_idx = (ty % 256) / 8;
			bit_idx = 7 - (ty % 8);
			window_blocks[win][byte_idx] |= (uint8_t)(1u << bit_idx);
			if (byte_idx >= window_max[win]) window_max[win] = (uint8_t)(byte_idx + 1);
		}

		for (int win = 0; win < 256; win++) {
			if (window_max[win] > 0) {
				WCHK(2 + window_max[win]);
				w[wl++] = (uint8_t)win; /* Window Block number */
				w[wl++] = window_max[win]; /* Bitmap Length */
				memcpy(w + wl, window_blocks[win], window_max[win]);
				wl += window_max[win];
			}
		}
	} else if (type == 51 && num_toks >= 4) { // NSEC3PARAM
		int tidx = 0;
		if (!strcasecmp(toks[tidx], "NSEC3PARAM"))
			tidx++;
		if (num_toks - tidx < 4) goto fail;

		/* Hash Algorithm */
		WCHK(4);
		w[wl++] = (uint8_t)atoi(toks[tidx + 0]);
		/* Flags */
		w[wl++] = (uint8_t)atoi(toks[tidx + 1]);
		/* Iterations */
		uint16_t iters = (uint16_t)atoi(toks[tidx + 2]);
		w[wl++] = (uint8_t)(iters >> 8);
		w[wl++] = (uint8_t)(iters & 0xff);
		/* Salt Length & Salt */
		if (!strcmp(toks[tidx + 3], "-")) {
			WCHK(1);
			w[wl++] = 0;
		} else {
			size_t slen = strlen(toks[tidx + 3]) / 2;
			if (slen > 255) goto fail;
			WCHK(1 + slen);
			w[wl++] = (uint8_t)slen;
			if (hex_to_wire(toks[tidx + 3], w + wl, slen))
				goto fail;
			wl += slen;
		}
	} else if (type == 48 && num_toks >= 4) { // DNSKEY
		WCHK(4);
		w[wl++] = (uint8_t)(atoi(toks[0]) >> 8);
		w[wl++] = (uint8_t)(atoi(toks[0]) & 0xff);
		w[wl++] = (uint8_t)atoi(toks[1]);
		w[wl++] = (uint8_t)atoi(toks[2]);

		/* The remaining toks are fragments of the base64 key due to chunking/whitespace. Reassemble them first. */
		sc->accum[0] = '\0';
		for (int i = 3; i < num_toks; i++) {
			strncat(sc->accum, toks[i], sizeof(sc->accum) - strlen(sc->accum) - 1);
		}

		/* the decode must be bounded by what is left of w, not by 4096 */
		int b64_len = lws_b64_decode_string(sc->accum, (char *)w + wl,
						    (int)(sizeof(sc->w) - wl));
		if (b64_len <= 0) {
			lwsl_err("RDATA_TO_WIRE: DNSKEY string decoding Failed. b64='%s'\n", sc->accum);
			{ lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
		}
		wl += (size_t)b64_len;
	} else if (type == 46 && num_toks >= 9) { // RRSIG
		/* Type Covered */
		uint16_t tc = auth_dns_rdata_type(toks[0]);

		if (!tc)
			goto fail;

		/* type covered, alg, labels, orig ttl, exp, inc, keytag */
		WCHK(2 + 1 + 1 + 4 + 4 + 4 + 2);

		w[wl++] = (uint8_t)(tc >> 8); w[wl++] = (uint8_t)(tc & 0xff);
		w[wl++] = (uint8_t)atoi(toks[1]); /* Algorithm */
		w[wl++] = (uint8_t)atoi(toks[2]); /* Labels */

		uint32_t o_ttl = (uint32_t)atoll(toks[3]);
		w[wl++] = (uint8_t)(o_ttl >> 24); w[wl++] = (uint8_t)(o_ttl >> 16); w[wl++] = (uint8_t)(o_ttl >> 8); w[wl++] = (uint8_t)(o_ttl & 0xff);

		/* Expiration & Inception: YYYYMMDDHHMMSS -> Unix timestamp */
		struct tm tm;
		memset(&tm, 0, sizeof(tm));
		if (strlen(toks[4]) == 14 && sscanf(toks[4], "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
			tm.tm_year -= 1900; tm.tm_mon -= 1;
			uint64_t _exp64 = (uint64_t)timegm(&tm);
			uint32_t exp = (uint32_t)_exp64;
			w[wl++] = (uint8_t)(exp >> 24); w[wl++] = (uint8_t)(exp >> 16); w[wl++] = (uint8_t)(exp >> 8); w[wl++] = (uint8_t)(exp & 0xff);
		} else goto fail;

		memset(&tm, 0, sizeof(tm));
		if (strlen(toks[5]) == 14 && sscanf(toks[5], "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
			tm.tm_year -= 1900; tm.tm_mon -= 1;
			uint64_t _inc64 = (uint64_t)timegm(&tm);
			uint32_t inc = (uint32_t)_inc64;
			w[wl++] = (uint8_t)(inc >> 24); w[wl++] = (uint8_t)(inc >> 16); w[wl++] = (uint8_t)(inc >> 8); w[wl++] = (uint8_t)(inc & 0xff);
		} else goto fail;

		uint16_t kt = (uint16_t)atoi(toks[6]);
		w[wl++] = (uint8_t)(kt >> 8); w[wl++] = (uint8_t)(kt & 0xff);

		size_t av = sizeof(sc->w) - wl;
		if (name_to_wire(toks[7], z->origin, w + wl, &av)) goto fail;
		wl += av;

		sc->accum[0] = '\0';
		for (int i = 8; i < num_toks; i++) {
			strncat(sc->accum, toks[i], sizeof(sc->accum) - strlen(sc->accum) - 1);
		}

		/* the decode must be bounded by what is left of w, not by 4096 */
		int sig_len = lws_b64_decode_string(sc->accum, (char *)w + wl,
						    (int)(sizeof(sc->w) - wl));
		if (sig_len <= 0) goto fail;
		wl += (size_t)sig_len;
	} else if (type == 257 && num_toks >= 3) { // CAA
		size_t tag_len = strlen(toks[1]), val_len = strlen(toks[2]);
		const char *val = toks[2];

		if (tag_len > 255)
			goto fail;

		/* The value might be enclosed in quotes like "letsencrypt.org", if so strip them */
		if (val_len >= 2 && val[0] == '"' && val[val_len - 1] == '"') {
			val++;
			val_len -= 2;
		}

		WCHK(2 + tag_len + val_len);

		/* Flags */
		w[wl++] = (uint8_t)atoi(toks[0]);
		/* Tag Length + Tag */
		w[wl++] = (uint8_t)tag_len;
		memcpy(w + wl, toks[1], tag_len);
		wl += tag_len;
		/* Value */
		memcpy(w + wl, val, val_len);
		wl += val_len;
	} else if (type == 65 && num_toks >= 2) { // HTTPS
		uint16_t priority = (uint16_t)atoi(toks[0]);
		WCHK(2);
		w[wl++] = (uint8_t)(priority >> 8);
		w[wl++] = (uint8_t)(priority & 0xff);

		size_t av = sizeof(sc->w) - wl;
		if (name_to_wire(toks[1], z->origin, w + wl, &av)) goto fail;
		wl += av;

		for (int i = 2; i < num_toks; i++) {
			const char *eq = strchr(toks[i], '=');
			const char *key = toks[i];
			const char *val = "";
			char key_name[128];
			if (eq) {
				size_t klen = lws_ptr_diff_size_t(eq, key);
				if (klen >= sizeof(key_name)) klen = sizeof(key_name) - 1;
				memcpy(key_name, key, klen);
				key_name[klen] = '\0';
				val = eq + 1;
			} else {
				lws_strncpy(key_name, key, sizeof(key_name));
			}

			char val_clean[1024];
			lws_strncpy(val_clean, val, sizeof(val_clean));
			size_t vlen = strlen(val_clean);
			if (vlen >= 2 && val_clean[0] == '"' && val_clean[vlen - 1] == '"') {
				memmove(val_clean, val_clean + 1, vlen - 2);
				val_clean[vlen - 2] = '\0';
				vlen -= 2;
			}

			uint16_t param_key = 0xffff;
			if (!strcasecmp(key_name, "alpn")) param_key = 1;
			else if (!strcasecmp(key_name, "no-default-alpn")) param_key = 2;
			else if (!strcasecmp(key_name, "port")) param_key = 3;
			else if (!strcasecmp(key_name, "ipv4hint")) param_key = 4;
			else if (!strcasecmp(key_name, "ech")) param_key = 5;
			else if (!strcasecmp(key_name, "ipv6hint")) param_key = 6;
			else if (!strncasecmp(key_name, "key", 3)) param_key = (uint16_t)atoi(key_name + 3);

			if (param_key == 0xffff) continue;

			if (param_key == 1) { /* alpn */
				size_t alpn_wire_len = 0;
				const char *p_alpn = val_clean;
				while (*p_alpn) {
					const char *comma = strchr(p_alpn, ',');
					size_t len_item = comma ? lws_ptr_diff_size_t(comma, p_alpn) : strlen(p_alpn);
					if (len_item > 255) goto fail;
					alpn_wire_len += 1 + len_item;
					if (!comma) break;
					p_alpn = comma + 1;
				}

				WCHK(4 + alpn_wire_len);

				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				w[wl++] = (uint8_t)(alpn_wire_len >> 8);
				w[wl++] = (uint8_t)(alpn_wire_len & 0xff);

				p_alpn = val_clean;
				while (*p_alpn) {
					const char *comma = strchr(p_alpn, ',');
					size_t len_item = comma ? lws_ptr_diff_size_t(comma, p_alpn) : strlen(p_alpn);
					w[wl++] = (uint8_t)len_item;
					memcpy(w + wl, p_alpn, len_item);
					wl += len_item;
					if (!comma) break;
					p_alpn = comma + 1;
				}
			} else if (param_key == 2) { /* no-default-alpn */
				WCHK(4);
				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				w[wl++] = 0;
				w[wl++] = 0;
			} else if (param_key == 3) { /* port */
				uint16_t port_val = (uint16_t)atoi(val_clean);
				WCHK(6);
				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				w[wl++] = 0;
				w[wl++] = 2;
				w[wl++] = (uint8_t)(port_val >> 8);
				w[wl++] = (uint8_t)(port_val & 0xff);
			} else if (param_key == 4) { /* ipv4hint */
				int ip_count = 0;
				const char *p_ip = val_clean;
				while (*p_ip) {
					ip_count++;
					const char *comma = strchr(p_ip, ',');
					if (!comma) break;
					p_ip = comma + 1;
				}

				WCHK(4 + (ip_count * 4));

				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				uint16_t vlen_bytes = (uint16_t)(ip_count * 4);
				w[wl++] = (uint8_t)(vlen_bytes >> 8);
				w[wl++] = (uint8_t)(vlen_bytes & 0xff);

				p_ip = val_clean;
				while (*p_ip) {
					char ip_str[64];
					const char *comma = strchr(p_ip, ',');
					size_t len_item = comma ? lws_ptr_diff_size_t(comma, p_ip) : strlen(p_ip);
					if (len_item >= sizeof(ip_str)) goto fail;
					memcpy(ip_str, p_ip, len_item);
					ip_str[len_item] = '\0';

					struct sockaddr_in sin;
					if (inet_pton(AF_INET, ip_str, &sin.sin_addr) != 1) goto fail;
					memcpy(w + wl, &sin.sin_addr, 4);
					wl += 4;

					if (!comma) break;
					p_ip = comma + 1;
				}
			} else if (param_key == 6) { /* ipv6hint */
				int ip_count = 0;
				const char *p_ip = val_clean;
				while (*p_ip) {
					ip_count++;
					const char *comma = strchr(p_ip, ',');
					if (!comma) break;
					p_ip = comma + 1;
				}

				WCHK(4 + (ip_count * 16));

				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				uint16_t vlen_bytes = (uint16_t)(ip_count * 16);
				w[wl++] = (uint8_t)(vlen_bytes >> 8);
				w[wl++] = (uint8_t)(vlen_bytes & 0xff);

				p_ip = val_clean;
				while (*p_ip) {
					char ip_str[128];
					const char *comma = strchr(p_ip, ',');
					size_t len_item = comma ? lws_ptr_diff_size_t(comma, p_ip) : strlen(p_ip);
					if (len_item >= sizeof(ip_str)) goto fail;
					memcpy(ip_str, p_ip, len_item);
					ip_str[len_item] = '\0';

					struct sockaddr_in6 sin6;
					if (inet_pton(AF_INET6, ip_str, &sin6.sin6_addr) != 1) goto fail;
					memcpy(w + wl, &sin6.sin6_addr, 16);
					wl += 16;

					if (!comma) break;
					p_ip = comma + 1;
				}
			} else if (param_key == 5) { /* ech (base64) */
				size_t dec_max = strlen(val_clean);
				uint8_t *dec_buf = lws_malloc(dec_max, "ech_dec");
				if (!dec_buf) goto fail;
				int dec_len = lws_b64_decode_string(val_clean, (char *)dec_buf, (int)dec_max);
				if (dec_len < 0) {
					lws_free(dec_buf);
					goto fail;
				}

				size_t dlen = (size_t)dec_len;

				if (wl + 4 + dlen > sizeof(sc->w)) {
					lws_free(dec_buf);
					goto fail;
				}

				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				w[wl++] = (uint8_t)(dlen >> 8);
				w[wl++] = (uint8_t)(dlen & 0xff);
				memcpy(w + wl, dec_buf, dlen);
				wl += dlen;
				lws_free(dec_buf);
			} else { /* generic custom keys (raw string) */
				WCHK(4 + vlen);
				w[wl++] = (uint8_t)(param_key >> 8);
				w[wl++] = (uint8_t)(param_key & 0xff);
				w[wl++] = (uint8_t)(vlen >> 8);
				w[wl++] = (uint8_t)(vlen & 0xff);
				memcpy(w + wl, val_clean, vlen);
				wl += vlen;
			}
		}
	} else {
		{ lwsl_err("FAIL on rdata: %s (toks[0]: %s)", rr->rdata, toks[0]); goto fail; }
	}

done:
	/* keep only what we actually used */
	rr->wire_rdata = lws_malloc(wl + 1, "auth_dns_wire");
	if (!rr->wire_rdata)
		goto fail;

	memcpy(rr->wire_rdata, w, wl);
	rr->wire_rdata_len = wl;
	lws_free(sc);

	return 0;

fail:
	lws_free(sc);

	return 1;
}

#undef WCHK

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
	uint8_t w1[256] = {0}, w2[256] = {0};
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

int
lws_auth_dns_nsec3_hash(const uint8_t *wire, size_t wire_len,
			const uint8_t *salt, size_t salt_len,
			unsigned int iterations, uint8_t *hash)
{
	struct lws_genhash_ctx hctx;
	const uint8_t *in = wire;
	size_t in_len = wire_len;
	unsigned int n;

	/*
	 * RFC 5155 5: IH(salt, x, 0) = H(x || salt) and
	 * IH(salt, x, k) = H(IH(salt, x, k - 1) || salt): the salt always
	 * goes after what is being hashed
	 */
	for (n = 0; n <= iterations; n++) {
		if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA1) ||
		    lws_genhash_update(&hctx, in, in_len) ||
		    (salt_len && lws_genhash_update(&hctx, salt, salt_len)) ||
		    lws_genhash_destroy(&hctx, hash)) {
			lws_genhash_destroy(&hctx, NULL);

			return 1;
		}
		in = hash;
		in_len = LWS_AUTH_DNS_NSEC3_HASH_LEN;
	}

	return 0;
}

/*
 * Compose the DNSKEY RDATA (RFC 4034 2.1 / RFC 3110) for an imported public
 * key into `wire`, returning the length used or 0 if it will not fit.
 *
 * The key element lengths come from the JWK exactly as it was imported and
 * are not bounded by anything else, so eg an RSA-4096 key (a perfectly legal
 * DNSSEC key) must not be allowed to run off the end of the caller's buffer.
 */

#define LWS_AUTH_DNS_DNSKEY_WIRE LWS_AUTH_DNS_DNSKEY_WIRE_MAX

/*
 * The DNSSEC algorithm number for a JWK, or 0 if it has none.  P-521 has no
 * DNSSEC algorithm: 15 is Ed25519.
 */

static int
lws_auth_dns_jwk_alg(const struct lws_jwk *jwk)
{
	const char *crv;

	if (jwk->kty == LWS_GENCRYPTO_KTY_RSA)
		return 8; /* RSASHA256 */

	if (jwk->kty != LWS_GENCRYPTO_KTY_EC)
		return 0;

	crv = (const char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf;
	if (!crv || !strncmp(crv, "P-256", 5))
		return 13; /* ECDSAP256SHA256 */
	if (!strncmp(crv, "P-384", 5))
		return 14; /* ECDSAP384SHA384 */

	return 0;
}

static size_t
lws_auth_dns_dnskey_wire(struct lws_jwk *jwk, int flags, int dnssec_alg,
			 uint8_t *wire, size_t wire_max)
{
	size_t wl = 0;

	if (wire_max < 4)
		return 0;

	/* Flags: 256 for ZSK, 257 for KSK */
	wire[wl++] = (uint8_t)(flags >> 8);
	wire[wl++] = (uint8_t)(flags & 0xff);
	wire[wl++] = 3; /* Protocol */
	wire[wl++] = (uint8_t)dnssec_alg; /* Algorithm */

	if (jwk->kty == LWS_GENCRYPTO_KTY_EC) {
		size_t xl = jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].len,
		       yl = jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
		    wl + xl + yl > wire_max)
			return 0;

		/* Append X and Y */
		memcpy(wire + wl, jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf, xl);
		wl += xl;
		memcpy(wire + wl, jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, yl);
		wl += yl;

		return wl;
	}

	if (jwk->kty == LWS_GENCRYPTO_KTY_RSA) {
		/* RFC 3110 RSA Public Key Format */
		uint8_t *e_buf = jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
			*n_buf = jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
		size_t e_len = jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len,
		       n_len = jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;

		if (!e_buf || !n_buf || !e_len || !n_len)
			return 0;

		/* Remove leading zero bytes from E and N if any */
		while (e_len > 1 && *e_buf == 0) {
			e_buf++;
			e_len--;
		}
		while (n_len > 1 && *n_buf == 0) {
			n_buf++;
			n_len--;
		}

		if (e_len > 0xffff ||
		    wl + (e_len <= 255 ? 1u : 3u) + e_len + n_len > wire_max)
			return 0;

		if (e_len <= 255)
			wire[wl++] = (uint8_t)e_len;
		else {
			wire[wl++] = 0;
			wire[wl++] = (uint8_t)(e_len >> 8);
			wire[wl++] = (uint8_t)(e_len & 0xff);
		}

		memcpy(wire + wl, e_buf, e_len);
		wl += e_len;
		memcpy(wire + wl, n_buf, n_len);
		wl += n_len;

		return wl;
	}

	return 0;
}

int
lws_auth_dns_key_records(struct lws_jwk *jwk, const char *origin, int flags,
			 struct lws_auth_dns_key_records *r)
{
	uint8_t wire[LWS_AUTH_DNS_DNSKEY_WIRE], owner[256], hash[48];
	enum lws_genhash_types ht;
	struct lws_genhash_ctx hctx;
	size_t wl, ol = sizeof(owner), hl;
	char *p;
	int m;

	memset(r, 0, sizeof(*r));

	r->alg = (uint8_t)lws_auth_dns_jwk_alg(jwk);
	if (!r->alg)
		return 1;

	wl = lws_auth_dns_dnskey_wire(jwk, flags, r->alg, wire, sizeof(wire));
	if (!wl)
		return 1;

	r->keytag = lws_dnssec_key_tag(wire, wl);

	/* DNSKEY presentation RDATA */

	m = lws_snprintf(r->dnskey, sizeof(r->dnskey), "%d 3 %d ", flags,
			 r->alg);
	/* a truncated result is reported as the whole size */
	if (m >= (int)sizeof(r->dnskey) - 1)
		return 1;
	if (lws_b64_encode_string((const char *)wire + 4, (int)wl - 4,
				  r->dnskey + m, (int)(sizeof(r->dnskey) -
							(size_t)m)) < 0)
		return 1;

	/* DS (RFC 4034 5.1.4): the digest of owner name | DNSKEY RDATA */

	if (r->alg == 14) {
		r->digest_type = 4;
		ht = LWS_GENHASH_TYPE_SHA384;
		hl = 48;
	} else {
		r->digest_type = 2;
		ht = LWS_GENHASH_TYPE_SHA256;
		hl = 32;
	}

	if (name_to_wire(origin, "", owner, &ol) ||
	    lws_genhash_init(&hctx, ht))
		return 1;
	if (lws_genhash_update(&hctx, owner, ol) ||
	    lws_genhash_update(&hctx, wire, wl)) {
		lws_genhash_destroy(&hctx, NULL);
		return 1;
	}
	if (lws_genhash_destroy(&hctx, hash))
		return 1;

	lws_hex_from_byte_array(hash, hl, r->digest, sizeof(r->digest));
	/* DS digests are conventionally shown in uppercase */
	for (p = r->digest; *p; p++)
		*p = (char)toupper(*p);

	lws_snprintf(r->ds, sizeof(r->ds), "%u %u %u %s", r->keytag, r->alg,
		     r->digest_type, r->digest);

	return 0;
}

/*
 * Import the JWK at \p path, whose text usually holds a private key, without
 * leaving that text anywhere in memory.  Returns 0 on success, when \p jwk
 * must later be destroyed.
 */

static int
auth_dns_jwk_load(const char *path, struct lws_jwk *jwk)
{
	struct stat st;
	int fd, ret = 1;
	ssize_t n;
	char *buf;

	fd = open(path, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: Failed to open JWK file at '%s'\n", __func__, path);
		return 1;
	}

	if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 65536) {
		close(fd);
		lwsl_err("%s: Unusable JWK file %s\n", __func__, path);
		return 1;
	}

	buf = lws_malloc((size_t)st.st_size + 1, "auth_dns_jwk");
	if (!buf) {
		close(fd);
		return 1;
	}

	n = read(fd, buf, (unsigned int)st.st_size);
	close(fd);

	if (n != st.st_size)
		lwsl_err("%s: Read size mismatch on %s\n", __func__, path);
	else {
		buf[st.st_size] = '\0';
		ret = lws_jwk_import(jwk, NULL, NULL, buf, (size_t)st.st_size);
		if (ret) /* which leaves nothing to destroy */
			lwsl_err("%s: Failed to import JWK from %s\n",
				 __func__, path);
	}

	/* this held the JWK JSON, ie, the private key in the clear */
	lws_explicit_bzero(buf, (size_t)st.st_size);
	lws_free(buf);

	return ret;
}

static int
lws_auth_dns_add_dnskey(struct auth_dns_zone *z, const char *jwk_path, int flags)
{
	struct auth_dns_rrset *rrset = NULL;
	uint8_t wire[LWS_AUTH_DNS_DNSKEY_WIRE];
	char b64[(LWS_AUTH_DNS_DNSKEY_WIRE * 4) / 3 + 16];
	char rdata_buf[sizeof(b64) + 32];
	struct auth_dns_rr *rr;
	struct lws_jwk jwk;
	int dnssec_alg, ret = 1;
	size_t wl;

	if (!jwk_path)
		return 0;

	if (auth_dns_jwk_load(jwk_path, &jwk))
		return 1;

	dnssec_alg = lws_auth_dns_jwk_alg(&jwk);
	if (!dnssec_alg) {
		lwsl_err("%s: %s: key has no DNSSEC algorithm\n", __func__,
			 jwk_path);
		goto bail_jwk;
	}

	wl = lws_auth_dns_dnskey_wire(&jwk, flags, dnssec_alg, wire, sizeof(wire));
	if (!wl) {
		lwsl_err("%s: %s key too large for DNSKEY RDATA\n", __func__,
			 jwk_path);
		goto bail_jwk;
	}

	/* Format RDATA: flags protocol algorithm base64_key */
	if (lws_b64_encode_string((const char *)wire + 4, (int)wl - 4, b64,
				  (int)sizeof(b64)) < 0) {
		lwsl_err("%s: %s key base64 overflow\n", __func__, jwk_path);
		goto bail_jwk;
	}

	lws_snprintf(rdata_buf, sizeof(rdata_buf), "%d %d %d %s", flags, 3,
		     dnssec_alg, b64);

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

	rr->rdata = lws_strdup(rdata_buf);
	rr->rdata_len = strlen(rr->rdata);

	lws_dll2_add_tail(&rr->list, &rrset->rr_list);
	ret = 0;

bail_jwk:
	lws_jwk_destroy(&jwk);

	return ret;
}

/*
 * Zone cuts
 *
 * RFC 4034 / RFC 4035 2.2: an NS RRset at an owner below the apex makes that
 * owner a delegation point, a zone cut.  What is at and below a cut belongs
 * to the child zone, apart from
 *
 *  - the NS RRset at the cut, which the parent holds but is not
 *    authoritative for, so does not sign
 *  - the DS RRset at the cut, which is the parent's own data, and signed
 *  - glue: addresses of name servers whose names are at or below a cut,
 *    which the parent carries so the child can be reached, and does not sign
 *
 * Anything else at or below a cut is occluded: no resolver would ever be
 * given it by the parent, and nobody can sign it.  We do not let such data
 * into a zone at all, rather than carry records that the signer would leave
 * unsigned and the server could only serve unsigned.  A DS anywhere but at
 * a cut (including at the apex, where the DS is the parent's) is the same.
 *
 * The signer and the verifier decide all this here, so they cannot disagree
 * about which RRsets are signed.
 */

enum auth_dns_role {
	AUTH_DNS_ROLE_AUTH,	/* this zone's own data, signed */
	AUTH_DNS_ROLE_DELEG,	/* the NS RRset at a cut, not signed */
	AUTH_DNS_ROLE_GLUE,	/* a name server's address at / below a cut */
	AUTH_DNS_ROLE_OCCLUDED,	/* not data this zone may hold */
};

struct auth_dns_cuts {
	const struct auth_dns_rrset	**ns;	 /* every NS RRset, apex too */
	int				count;
};

/* is \p name strictly below \p anc?  Both are fully-qualified */

static int
auth_dns_name_below(const char *name, const char *anc)
{
	size_t nl = strlen(name), al = strlen(anc);

	return nl > al && name[nl - al - 1] == '.' &&
	       !strcasecmp(name + nl - al, anc);
}

static void
auth_dns_cuts_destroy(struct auth_dns_cuts *c)
{
	lws_free_set_NULL(c->ns);
	c->count = 0;
}

/*
 * Collect the zone's NS RRsets.  The ones below the apex are the cuts, and
 * the names all of them point to are the ones that can have glue.
 */

static int
auth_dns_cuts_find(const struct auth_dns_zone *z, struct auth_dns_cuts *c)
{
	int n = 0;

	memset(c, 0, sizeof(*c));

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		if (lws_container_of(d, struct auth_dns_rrset, list)->type == 2)
			c->count++;
	} lws_end_foreach_dll(d);

	if (!c->count)
		return 0;

	c->ns = lws_malloc(sizeof(*c->ns) * (size_t)c->count, "auth_dns_cuts");
	if (!c->ns) {
		c->count = 0;
		return 1;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (rs->type == 2)
			c->ns[n++] = rs;
	} lws_end_foreach_dll(d);

	return 0;
}

/* is \p name the target of any NS RR in the zone? */

static int
auth_dns_ns_target(const struct auth_dns_zone *z, const struct auth_dns_cuts *c,
		   const char *name)
{
	uint8_t w[256];
	size_t wl = sizeof(w);
	int n;

	if (name_to_wire(name, z->origin, w, &wl))
		return 0;

	for (n = 0; n < c->count; n++)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&c->ns[n]->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d,
						struct auth_dns_rr, list);

			/* both sides are canonical (lowercase) wire names */
			if (rr->wire_rdata && rr->wire_rdata_len == wl &&
			    !memcmp(rr->wire_rdata, w, wl))
				return 1;
		} lws_end_foreach_dll(d);

	return 0;
}

static enum auth_dns_role
auth_dns_rrset_role(const struct auth_dns_zone *z,
		    const struct auth_dns_cuts *c,
		    const struct auth_dns_rrset *rs)
{
	int n, at = 0, addr = rs->type == 1 || rs->type == 28;

	/*
	 * NSEC3 owners are hashes, one label below the apex, and the chain is
	 * always the zone's own (RFC 5155 7.1)
	 */
	if (rs->type == 50)
		return AUTH_DNS_ROLE_AUTH;

	for (n = 0; n < c->count; n++) {
		const char *cut = c->ns[n]->name;

		if (!strcasecmp(cut, z->origin))
			continue;

		/* below any cut, including below a cut below a cut */
		if (auth_dns_name_below(rs->name, cut))
			return addr && auth_dns_ns_target(z, c, rs->name) ?
				AUTH_DNS_ROLE_GLUE : AUTH_DNS_ROLE_OCCLUDED;

		if (!strcasecmp(rs->name, cut))
			at = 1;
	}

	if (at) {
		if (rs->type == 2)
			return AUTH_DNS_ROLE_DELEG;
		if (rs->type == 43)
			return AUTH_DNS_ROLE_AUTH;

		return addr && auth_dns_ns_target(z, c, rs->name) ?
			AUTH_DNS_ROLE_GLUE : AUTH_DNS_ROLE_OCCLUDED;
	}

	return rs->type == 43 ? AUTH_DNS_ROLE_OCCLUDED : AUTH_DNS_ROLE_AUTH;
}

/*
 * An NSEC3's types follow its five other fields and are read back through
 * lws_auth_dns_rdata_to_wire(), so this is the most one can carry
 */
#define NSEC3_MAX_TYPES (AUTH_DNS_RDATA_MAX_TOKS - 5)

struct nsec3_node {
	char		*name;
	uint8_t		hash[LWS_AUTH_DNS_NSEC3_HASH_LEN];
	char		b32[64];
	uint16_t	types[NSEC3_MAX_TYPES]; /* ascending, no duplicates */
	int		num_types;
	char		is_signed; /* has an RRset the signer signs */
};

/*
 * The covered types are kept as numbers and only named when the NSEC3 text
 * is rendered, by the same table the bitmap is parsed back with, so every
 * type the zone parser accepts ends up in the signed bitmap.  Anything left
 * out would be an authenticated denial of a type the zone actually serves.
 */

static int
nsec3_node_add_type(struct nsec3_node *n, uint16_t type)
{
	int i = 0;

	while (i < n->num_types && n->types[i] < type)
		i++;

	if (i < n->num_types && n->types[i] == type)
		return 0;

	if (n->num_types == NSEC3_MAX_TYPES) {
		lwsl_err("%s: %s has more than %d types\n", __func__,
			 n->name, NSEC3_MAX_TYPES);

		return 1;
	}

	memmove(&n->types[i + 1], &n->types[i],
		(size_t)(n->num_types - i) * sizeof(n->types[0]));
	n->types[i] = type;
	n->num_types++;

	return 0;
}

static int
cmp_nsec3_node(const void *a, const void *b)
{
	const struct nsec3_node *na = *(const struct nsec3_node **)a;
	const struct nsec3_node *nb = *(const struct nsec3_node **)b;
	return strcmp(na->b32, nb->b32);
}

/*
 * Add an rrset of \p type at \p name, holding one rr with rdata \p text, to
 * the zone.  The zone owns whatever was added even if this then fails.
 */

static int
nsec3_add_rr(struct auth_dns_zone *z, const char *name, uint16_t type,
	     const char *text)
{
	struct auth_dns_rrset *rrset;
	struct auth_dns_rr *rr;

	rrset = lws_zalloc(sizeof(*rrset), "nsec3");
	if (!rrset)
		return 1;

	rrset->type = type;
	rrset->class_ = 1;
	rrset->ttl = atoi(z->default_ttl) ? (uint32_t)atoi(z->default_ttl) : 3600;
	lws_dll2_add_tail(&rrset->list, &z->rrset_list);

	rrset->name = lws_strdup(name);
	if (!rrset->name)
		return 1;

	rr = lws_zalloc(sizeof(*rr), "rr");
	if (!rr)
		return 1;
	lws_dll2_add_tail(&rr->list, &rrset->rr_list);

	rr->rdata = lws_strdup(text);
	if (!rr->rdata)
		return 1;
	rr->rdata_len = strlen(rr->rdata);

	return lws_auth_dns_rdata_to_wire(z, rr, type);
}

/*
 * Build the NSEC3 chain and NSEC3PARAM.  Each owner name must be in the
 * chain with all of its types, or the zone would carry a signed denial of
 * something it serves, so any failure fails the whole thing.
 *
 * RFC 5155 7.1: names below a zone cut (glue owners) are not in the chain,
 * and a cut's NSEC3 lists only the types the parent has there (NS, and DS
 * with RRSIG if there is a DS), never the glue at it (RFC 4035 2.3).
 */

static int
lws_auth_dns_add_nsec3(struct auth_dns_zone *z, const char *salt_hex, int iterations)
{
	int max_names = (int)lws_dll2_count(&z->rrset_list), num_names = 0,
	    ret = -1, i, n;
	struct nsec3_node **nodes;
	struct auth_dns_cuts cuts;
	size_t salt_len = 0;
	uint8_t salt[256];
	char tb[1024];

	if (salt_hex && salt_hex[0] != '-') {
		/*
		 * The salt is caller-supplied hex of any length; RFC 5155
		 * limits it to 255 octets and salt[] is on the stack, so
		 * bound it by the buffer rather than by strlen() of the input
		 */
		n = lws_hex_to_byte_array(salt_hex, salt, (int)sizeof(salt));
		if (n < 0) {
			lwsl_err("%s: bad nsec3 salt\n", __func__);

			return -1;
		}
		salt_len = (size_t)n;
	}

	if (auth_dns_cuts_find(z, &cuts))
		return -1;

	/* there cannot be more owner names than rrsets */

	nodes = lws_zalloc(sizeof(*nodes) * (size_t)(max_names + 1), "nsec3_nodes");
	if (!nodes) {
		auth_dns_cuts_destroy(&cuts);
		return -1;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
		enum auth_dns_role role = auth_dns_rrset_role(z, &cuts, rs);
		int found = -1;

		if (role != AUTH_DNS_ROLE_AUTH && role != AUTH_DNS_ROLE_DELEG)
			continue;

		for (i = 0; i < num_names; i++)
			if (!strcmp(nodes[i]->name, rs->name)) {
				found = i;
				break;
			}

		if (found < 0) {
			nodes[num_names] = lws_zalloc(sizeof(**nodes), "nsec3_node");
			if (!nodes[num_names])
				goto bail;
			found = num_names++;
			nodes[found]->name = lws_strdup(rs->name);
			if (!nodes[found]->name)
				goto bail;
		}

		/* type 0 is what the parser gives a type it cannot read */
		if (rs->type && nsec3_node_add_type(nodes[found], rs->type))
			goto bail;
		if (role == AUTH_DNS_ROLE_AUTH)
			nodes[found]->is_signed = 1;
	} lws_end_foreach_dll(d);

	for (i = 0; i < num_names; i++) {
		uint8_t wire[256];
		size_t wl = sizeof(wire);

		/*
		 * Every owner with an RRset the signer signs gets RRSIGs (an
		 * unsigned delegation is only its NS), and the apex also gets
		 * the NSEC3PARAM added below
		 */
		if ((nodes[i]->is_signed && nsec3_node_add_type(nodes[i], 46)) ||
		    (!strcmp(nodes[i]->name, z->origin) &&
		     nsec3_node_add_type(nodes[i], 51)))
			goto bail;

		if (name_to_wire(nodes[i]->name, z->origin, wire, &wl) ||
		    lws_auth_dns_nsec3_hash(wire, wl, salt, salt_len,
					    (unsigned int)iterations,
					    nodes[i]->hash)) {
			lwsl_err("%s: unable to hash %s\n", __func__,
				 nodes[i]->name);
			goto bail;
		}

		lws_auth_dns_b32hex_encode(nodes[i]->hash,
					   sizeof(nodes[i]->hash), nodes[i]->b32);
	}

	/* Sort nodes by b32 hash */
	qsort(nodes, (size_t)num_names, sizeof(void *), cmp_nsec3_node);

	for (i = 0; i < num_names; i++) {
		struct nsec3_node *nx = nodes[(i + 1) % num_names];
		char fqdn[256];
		int t;

		lws_snprintf(fqdn, sizeof(fqdn), "%s.%s", nodes[i]->b32, z->origin);

		/* Format: HashAlg Flags Iterations Salt NextB32 Type1 Type2 ... */
		n = lws_snprintf(tb, sizeof(tb), "1 0 %d %s %s", iterations,
				 salt_hex ? salt_hex : "-", nx->b32);
		for (t = 0; t < nodes[i]->num_types; t++) {
			char tn[16];

			n += lws_snprintf(tb + n, sizeof(tb) - (size_t)n, " %s",
					  lws_auth_dns_type_to_str(nodes[i]->types[t],
							tn, sizeof(tn)));
		}

		if ((size_t)n >= sizeof(tb) - 1 ||
		    nsec3_add_rr(z, fqdn, 50, tb)) {
			lwsl_err("%s: unable to add NSEC3 for %s\n", __func__,
				 nodes[i]->name);
			goto bail;
		}
	}

	/* Insert NSEC3PARAM at apex */
	lws_snprintf(tb, sizeof(tb), "1 0 %d %s", iterations, salt_hex ? salt_hex : "-");
	if (nsec3_add_rr(z, z->origin, 51, tb)) {
		lwsl_err("%s: unable to add NSEC3PARAM\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	/*
	 * the chain references earlier nodes while wrapping around the end,
	 * so the nodes can only be freed once it is all built
	 */
	for (i = 0; i < num_names; i++) {
		lws_free(nodes[i]->name);
		lws_free(nodes[i]);
	}
	lws_free(nodes);
	auth_dns_cuts_destroy(&cuts);

	return ret;
}

int
lws_auth_dns_inject_mock_keys(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	struct auth_dns_cuts cuts;
	int bad = 0;

	/*
	 * Refuse a zone holding data it cannot hold: it could only be signed
	 * as something lws_auth_dns_verify_zone() then rejects
	 */
	if (auth_dns_cuts_find(z, &cuts))
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (auth_dns_rrset_role(z, &cuts, rs) == AUTH_DNS_ROLE_OCCLUDED) {
			lwsl_err("%s: %s type %d is occluded by a delegation, "
				 "or is a DS away from one\n", __func__,
				 rs->name, rs->type);
			bad = 1;
		}
	} lws_end_foreach_dll(d);

	auth_dns_cuts_destroy(&cuts);
	if (bad)
		return 1;

	/* Inject keys into list before sort */
	lws_auth_dns_add_dnskey(z, info->zsk_jwk_filepath, 256);
	lws_auth_dns_add_dnskey(z, info->ksk_jwk_filepath, 257);

	/* Inject NSEC3 into list before sort */
	return lws_auth_dns_add_nsec3(z, "AABBCCDD", 10);
}

void
lws_auth_dns_sort_zone(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	/* Sort RRsets */
	int num_rrsets = (int)lws_dll2_count(&z->rrset_list);
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
		int num_rrs = (int)lws_dll2_count(&rs->rr_list);
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

/*
 * The RRSIG Labels field for an owner name (RFC 4034 3.1.3): its labels, not
 * counting the root, nor the leftmost "*" of a wildcard
 */

static int
auth_dns_rrsig_labels(const char *name)
{
	const char *p = name;
	int labels;

	if (!name[0] || !strcmp(name, "."))
		return 0;

	labels = 1;
	while (*p) {
		if (*p == '.' && p[1])
			labels++;
		p++;
	}

	if (name[0] == '*' && name[1] == '.')
		labels--;

	return labels;
}

/*
 * The length of the uncompressed wire name at \p p, including its root label,
 * or -1 if it does not end inside \p len or is longer than a name can be
 */

static int
auth_dns_wire_name_len(const uint8_t *p, size_t len)
{
	size_t n = 0;

	while (n < len && n < 255) {
		if (!p[n])
			return (int)n + 1;
		if (p[n] > 63)
			return -1; /* compression is not allowed in RRSIG */
		n += 1u + p[n];
	}

	return -1;
}

/*
 * RFC 4034 3.1.8.1: hash what an RRSIG over \p rs signs, that is
 *
 *    RRSIG RDATA up to the signature (with the signer name canonical) |
 *    each RR of the set in canonical form and order (RFC 4034 6.2, 6.3),
 *    with the RRSIG's Original TTL in place of the RR's own
 *
 * \p sig_rdata / \p sig_rdata_len is the RRSIG RDATA up to and including the
 * signer name.  The RRs of \p rs must already be in canonical order, as
 * lws_auth_dns_sort_zone() leaves them.  The signer and the verifier both
 * hash with this, so they cannot disagree about what was signed.
 *
 * Returns 0 and the digest in \p hash, or nonzero.
 */

static int
auth_dns_rrset_hash(struct auth_dns_zone *z, const struct auth_dns_rrset *rs,
		    const uint8_t *sig_rdata, size_t sig_rdata_len,
		    enum lws_genhash_types ht, uint8_t *hash)
{
	const struct auth_dns_rr *prev = NULL;
	struct lws_genhash_ctx hctx;
	uint8_t owner[256], hdr[10];
	size_t ol = sizeof(owner);

	if (sig_rdata_len < 19 || name_to_wire(rs->name, z->origin, owner, &ol))
		return 1;

	/* type | class | original TTL | (rdlength filled per RR) */
	lws_ser_wu16be(hdr, rs->type);
	lws_ser_wu16be(hdr + 2, rs->class_);
	memcpy(hdr + 4, sig_rdata + 4, 4);

	if (lws_genhash_init(&hctx, ht))
		return 1;

	if (lws_genhash_update(&hctx, sig_rdata, sig_rdata_len))
		goto bail;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&rs->rr_list)) {
		const struct auth_dns_rr *rr = lws_container_of(d,
						struct auth_dns_rr, list);

		if (!rr->wire_rdata || rr->wire_rdata_len > 0xffff)
			goto bail;

		/* RFC 4034 6.3: an RRset never holds the same RR twice */
		if (prev && prev->wire_rdata_len == rr->wire_rdata_len &&
		    !memcmp(prev->wire_rdata, rr->wire_rdata,
			    rr->wire_rdata_len))
			continue;
		prev = rr;

		lws_ser_wu16be(hdr + 8, (uint16_t)rr->wire_rdata_len);
		if (lws_genhash_update(&hctx, owner, ol) ||
		    lws_genhash_update(&hctx, hdr, sizeof(hdr)) ||
		    lws_genhash_update(&hctx, rr->wire_rdata,
				       rr->wire_rdata_len))
			goto bail;
	} lws_end_foreach_dll(d);

	return lws_genhash_destroy(&hctx, hash);

bail:
	lws_genhash_destroy(&hctx, NULL);

	return 1;
}

int
lws_auth_dns_sign_rrsets(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	struct auth_dns_cuts cuts;

	if (auth_dns_cuts_find(z, &cuts))
		return 1;

	if (info->zsk_jwk_filepath) {
		struct lws_jwk zsk, ksk;
		memset(&zsk, 0, sizeof(zsk));
		memset(&ksk, 0, sizeof(ksk));
		char *buf_zsk = NULL, *buf_ksk = NULL;
		struct stat st_zsk, st_ksk;
		int fd_zsk = -1, fd_ksk = -1;
		ssize_t n;
		int has_ksk = 0, ksk_ctx = 0;
		uint16_t keytag_ksk = 0, keytag_zsk = 0;
		(void)keytag_zsk; /* Silences unused variable warnings when loops branch differently */
		struct lws_genec_ctx genec_zsk, genec_ksk;
		struct lws_genrsa_ctx genrsa_zsk, genrsa_ksk;
		memset(&genec_zsk, 0, sizeof(genec_zsk));
		memset(&genec_ksk, 0, sizeof(genec_ksk));
		memset(&genrsa_zsk, 0, sizeof(genrsa_zsk));
		memset(&genrsa_ksk, 0, sizeof(genrsa_ksk));
		int dnssec_alg = 13; /* Default ECDSAP256SHA256 */

		if (info->ksk_jwk_filepath) {
			fd_ksk = open(info->ksk_jwk_filepath, LWS_O_RDONLY);
			if (fd_ksk >= 0 && fstat(fd_ksk, &st_ksk) == 0) {
				buf_ksk = lws_malloc((size_t)st_ksk.st_size + 1, "ksk_read");
				if (buf_ksk && read(fd_ksk, buf_ksk, (unsigned int)st_ksk.st_size) == st_ksk.st_size) {
					buf_ksk[st_ksk.st_size] = '\0';
					/*
					 * an import that succeeded still owns key elements even
					 * if we reject the kty below, so the jwk is destroyed
					 * unconditionally at the end of the function
					 */
					if (lws_jwk_import(&ksk, NULL, NULL, buf_ksk,
							   (size_t)st_ksk.st_size) == 0 &&
						(ksk.kty == LWS_GENCRYPTO_KTY_EC || ksk.kty == LWS_GENCRYPTO_KTY_RSA)) {

						if (ksk.kty == LWS_GENCRYPTO_KTY_EC) {
							if (lws_genecdsa_create(&genec_ksk, info->cx, NULL) == 0 && lws_genecdsa_set_key(&genec_ksk, ksk.e) == 0) {
								has_ksk = 1;
								ksk_ctx = 1;
							}
						} else if (ksk.kty == LWS_GENCRYPTO_KTY_RSA) {
							if (lws_genrsa_create(&genrsa_ksk, ksk.e, info->cx, LGRSAM_PKCS1_1_5, LWS_GENHASH_TYPE_UNKNOWN) == 0) {
								has_ksk = 1;
								ksk_ctx = 1;
							}
						}

						if (has_ksk) {
						struct lws_auth_dns_key_records kr;

						if (lws_auth_dns_key_records(&ksk, z->origin, 257, &kr)) {
							/*
							 * we cannot express this key as DNSKEY
							 * RDATA, so we cannot compute a valid
							 * keytag for it either... fail closed
							 * rather than sign with a bogus one
							 */
							lwsl_err("%s: KSK unusable as DNSKEY RDATA\n", __func__);
							has_ksk = 0;
						} else {
							dnssec_alg = kr.alg;
							keytag_ksk = kr.keytag;

							lwsl_notice("== KSK DS Information ==\n");
							lwsl_notice("Please provide these parameters to your registrar:\n");
							lwsl_notice("Keytag: %u, Algorithm: %u, Digest Type: %u\n",
								    kr.keytag, kr.alg, kr.digest_type);
							lwsl_notice("Digest: %s\n", kr.digest);
							lwsl_notice("DNSKEY: %s\n", kr.dnskey);
							lwsl_notice("========================\n");
						}
					}
					if (buf_ksk) {
						/* this held the private key in the clear */
						lws_explicit_bzero(buf_ksk, (size_t)st_ksk.st_size);
						lws_free(buf_ksk);
						buf_ksk = NULL;
					}
			} else {
				lwsl_err("%s: Failed to read KSK at %s\n", __func__, info->ksk_jwk_filepath);
				lws_free(buf_ksk);
				buf_ksk = NULL;
			}
			if (fd_ksk >= 0) {
				close(fd_ksk);
				fd_ksk = -1;
			}
		}

		fd_zsk = open(info->zsk_jwk_filepath, LWS_O_RDONLY);
		if (fd_zsk >= 0) {
			if (fstat(fd_zsk, &st_zsk) == 0) {
				buf_zsk = lws_malloc((size_t)st_zsk.st_size + 1, "zsk_read");
				if (buf_zsk) {
					n = read(fd_zsk, buf_zsk, (unsigned int)st_zsk.st_size);
					if (n == st_zsk.st_size) {
						buf_zsk[st_zsk.st_size] = '\0';
						if (lws_jwk_import(&zsk, NULL, NULL, buf_zsk, (size_t)st_zsk.st_size) == 0 &&
							(zsk.kty == LWS_GENCRYPTO_KTY_EC || zsk.kty == LWS_GENCRYPTO_KTY_RSA)) {
							int zsk_ready = 0;

							if (zsk.kty == LWS_GENCRYPTO_KTY_EC) {
								if (lws_genecdsa_create(&genec_zsk, info->cx, NULL) == 0 &&
									lws_genecdsa_set_key(&genec_zsk, zsk.e) == 0) {
									zsk_ready = 1;
								}
							} else if (zsk.kty == LWS_GENCRYPTO_KTY_RSA) {
								if (lws_genrsa_create(&genrsa_zsk, zsk.e, info->cx, LGRSAM_PKCS1_1_5, LWS_GENHASH_TYPE_UNKNOWN) == 0) {
									zsk_ready = 1;
								}
							}

							if (zsk_ready) {
								/*
								 * the same algorithm add_dnskey()
								 * published the ZSK DNSKEY with, or
								 * none if it could not publish one
								 */
								int zsk_alg = lws_auth_dns_jwk_alg(&zsk);

								if (!zsk_alg) {
									lwsl_err("%s: ZSK has no DNSSEC algorithm\n", __func__);
									goto zsk_done;
								}

								/* Compute ZSK Keytag dynamically */
								uint16_t keytag_zsk = 0;
								uint8_t wire_zsk[LWS_AUTH_DNS_DNSKEY_WIRE];
								size_t wl_zsk = lws_auth_dns_dnskey_wire(&zsk, 256,
											zsk_alg, wire_zsk, sizeof(wire_zsk));

								if (!wl_zsk) {
									lwsl_err("%s: ZSK unusable as DNSKEY RDATA\n", __func__);
									goto zsk_done;
								}

								keytag_zsk = lws_dnssec_key_tag(wire_zsk, wl_zsk);

										/* For each RRset, compute signature over canonical form */
										lws_start_foreach_dll_safe(struct lws_dll2 *, d4, d6, lws_dll2_get_head(&z->rrset_list)) {
											struct auth_dns_rrset *rs = lws_container_of(d4, struct auth_dns_rrset, list);
											uint8_t pre[18 + 256], hash[64];
											size_t pl, al;
											enum lws_genhash_types hash_type;
											int active_alg, labels;

											/* Don't sign RRSIGs */
											if (rs->type == 46)
												goto next_rrset;

											/*
											 * RFC 4035 2.2: nor a delegation's
											 * NS RRset or glue
											 */
											if (auth_dns_rrset_role(z, &cuts, rs) !=
													AUTH_DNS_ROLE_AUTH)
												goto next_rrset;

											/* Only sign DNSKEYs if we have a KSK */
											if (rs->type == 48 && !has_ksk)
												goto next_rrset;

											active_alg = (rs->type == 48 && has_ksk) ? dnssec_alg : zsk_alg;
											labels = auth_dns_rrsig_labels(rs->name);

											if (lws_dnssec_alg_hash((uint8_t)active_alg, &hash_type)) {
												lwsl_err("%s: no hash for alg %d\n", __func__, active_alg);
												goto next_rrset;
											}

											time_t now;
											if (info->sign_validity_start_time)
												now = info->sign_validity_start_time;
											else
												time(&now);

											uint32_t dur = info->sign_validity_duration ? info->sign_validity_duration : (30 * 24 * 3600);
											uint64_t exp = (uint64_t)now + dur;
											uint64_t inc = (uint64_t)now - 3600; /* Start valid one hour before current time to account for clock skew */

											/* We must match the keytag of the key we are using! */
											uint16_t keytag;
											if (rs->type == 48 && has_ksk) keytag = keytag_ksk;
											else keytag = keytag_zsk;

											/* the RRSIG RDATA up to the signature, RFC 4034 3.1 */
											lws_ser_wu16be(pre, rs->type);
											pre[2] = (uint8_t)active_alg;
											pre[3] = (uint8_t)labels;
											lws_ser_wu32be(pre + 4, rs->ttl);
											lws_ser_wu32be(pre + 8, (uint32_t)exp);
											lws_ser_wu32be(pre + 12, (uint32_t)inc);
											lws_ser_wu16be(pre + 16, keytag);
											al = sizeof(pre) - 18;
											if (name_to_wire(z->origin, "", pre + 18, &al))
												goto next_rrset;
											pl = 18 + al;

											if (auth_dns_rrset_hash(z, rs, pre, pl, hash_type, hash)) {
												lwsl_err("%s: unable to hash %s type %d\n", __func__,
													 rs->name, rs->type);
												goto next_rrset;
											}

											int keybits = active_alg == 14 ? 384 : 256;

											/* lws_genecdsa_hash_sign_jws expects the exact signature size based on the keybits, which is (keybits rounded to bytes) * 2 */
											int exp_sig_len = lws_gencrypto_bits_to_bytes(keybits) * 2;

											/* RSA signatures are as long as the modulus, up to 8192 bits */
											/* Compute signature based on algorithm */
											uint8_t sig[1024];
											int sig_ret = -1;
											struct auth_dns_rr *rr = NULL;

											if (rs->type == 48 && has_ksk) {
												if (active_alg == 8) {
													sig_ret = lws_genrsa_hash_sign(&genrsa_ksk, hash, hash_type, sig, sizeof(sig));
												} else {
													sig_ret = lws_genecdsa_hash_sign_jws(&genec_ksk, hash, hash_type, keybits, sig, (size_t)exp_sig_len);
												}
											} else {
												if (active_alg == 8) {
													sig_ret = lws_genrsa_hash_sign(&genrsa_zsk, hash, hash_type, sig, sizeof(sig));
												} else {
													sig_ret = lws_genecdsa_hash_sign_jws(&genec_zsk, hash, hash_type, keybits, sig, (size_t)exp_sig_len);
												}
											}

											if (sig_ret >= 0 || (active_alg != 8 && sig_ret == 0)) {
												rr = lws_zalloc(sizeof(*rr), "rrsig");
												if (rr) {
													int sig_len = (active_alg == 8) ? sig_ret : exp_sig_len;
													char b64[((sizeof(sig) + 2) / 3) * 4 + 1];
													lws_b64_encode_string((const char *)sig, sig_len, b64, sizeof(b64));
													char tb[sizeof(b64) + 512], exp_str[32], inc_str[32];
													time_t exp_t = (time_t)exp, inc_t = (time_t)inc;
#if defined(LWS_HAVE_GMTIME_R)
													struct tm tm_info_s;
													struct tm *tm_info = gmtime_r(&exp_t, &tm_info_s);
#else
													struct tm *tm_info = gmtime(&exp_t);
#endif
													if (tm_info) strftime(exp_str, sizeof(exp_str), "%Y%m%d%H%M%S", tm_info); else lws_strncpy(exp_str, "ERROR", sizeof(exp_str));
#if defined(LWS_HAVE_GMTIME_R)
													tm_info = gmtime_r(&inc_t, &tm_info_s);
#else
													tm_info = gmtime(&inc_t);
#endif
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
												lwsl_err("SIGN: Signing failed for %s type %d! (hash_type %d keybits %d alg %d)\n", rs->name, rs->type, hash_type, keybits, active_alg);
											}

next_rrset:
											;
										} lws_end_foreach_dll_safe(d4, d6);

zsk_done:
									;
								}
								if (zsk_ready && zsk.kty == LWS_GENCRYPTO_KTY_EC) lws_genec_destroy(&genec_zsk);
								if (zsk_ready && zsk.kty == LWS_GENCRYPTO_KTY_RSA) lws_genrsa_destroy(&genrsa_zsk);
							}
						}
						/*
						 * unconditionally: an import that failed partway,
						 * or one we rejected on kty, can still own
						 * allocated key elements
						 */
						lws_jwk_destroy(&zsk);
					}
				}
				if (buf_zsk) {
					/* this held the private key in the clear */
					lws_explicit_bzero(buf_zsk, (size_t)st_zsk.st_size);
					lws_free(buf_zsk);
				}
			}
		}
			if (fd_zsk >= 0)
				close(fd_zsk);
		} else {
			lwsl_err("%s: Failed to open ZSK at %s\n", __func__, info->zsk_jwk_filepath);
		}
		if (ksk_ctx) {
			/*
			 * `has_ksk` can have been cleared after the ctx was created,
			 * and the jwk must go even if we rejected its kty or its
			 * import failed partway
			 */
			if (ksk.kty == LWS_GENCRYPTO_KTY_EC) lws_genec_destroy(&genec_ksk);
			if (ksk.kty == LWS_GENCRYPTO_KTY_RSA) lws_genrsa_destroy(&genrsa_ksk);
		}
		lws_jwk_destroy(&ksk);
		if (fd_ksk >= 0)
			close(fd_ksk);
	}

	auth_dns_cuts_destroy(&cuts);

	return 0;
}

/*
 * Zone verification, against the keys the caller says the zone is signed by
 */

struct auth_dns_verify {
	struct lws_context		*cx;
	struct auth_dns_zone		*z;
	const struct auth_dns_rrset	*keyset; /* the apex DNSKEY RRset */
	const struct auth_dns_rr	*ksk;	 /* the given KSK, in keyset */
	struct auth_dns_cuts		cuts;
	uint8_t				apex[256];
	size_t				apex_len;
	uint32_t			now;
	int				passes;
};

/*
 * Is \p type in the NSEC3 type bitmap \p b / \p len?  1 if so, 0 if not, -1
 * if the bitmap is malformed
 */

static int
auth_dns_bitmap_has(const uint8_t *b, size_t len, uint16_t type)
{
	unsigned int win = (unsigned int)type >> 8,
		     oct = ((unsigned int)type & 0xff) >> 3;

	while (len) {
		size_t bl;

		if (len < 2 || !b[1] || b[1] > 32 || len < 2u + b[1])
			return -1;
		bl = b[1];

		if (b[0] == win && oct < bl &&
		    (b[2 + oct] & (0x80u >> ((unsigned int)type & 7))))
			return 1;

		b += 2 + bl;
		len -= 2 + bl;
	}

	return 0;
}

/*
 * A zone cut is only one if the signed zone says it is: the NSEC3 for the
 * cut's name, made with the apex NSEC3PARAM's parameters, must be in the zone
 * with NS, and not SOA, in its type bitmap (RFC 5155 7.2.7 / 8.9, RFC 4035
 * 2.3).  Like every NSEC3 it must then also be validly signed, which the main
 * pass checks.
 *
 * Without this, anybody able to edit the zone text could add an NS RRset at
 * any owner and so exempt everything there from being signed.  The cost is
 * that a zone using NSEC3 opt-out, with no NSEC3 at its insecure cuts, does
 * not verify; lws' signer does not use opt-out.
 */

static int
auth_dns_verify_cut(struct auth_dns_verify *v, const char *cut)
{
	const struct auth_dns_rrset *param = NULL;
	const uint8_t *pw = NULL, *salt;
	uint8_t w[256], h[LWS_AUTH_DNS_NSEC3_HASH_LEN];
	char b32[40], owner[sizeof(b32) + sizeof(v->z->origin)];
	unsigned int iterations;
	size_t wl = sizeof(w), salt_len;
	int found = 0;

	/* the apex NSEC3PARAM says how the zone hashes its owner names */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&v->z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (rs->type == 51 && !strcasecmp(rs->name, v->z->origin))
			param = rs;
	} lws_end_foreach_dll(d);

	if (param)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&param->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d,
						struct auth_dns_rr, list);

			/* SHA-1, flags 0 (RFC 5155 4.1.2), and well-formed */
			if (rr->wire_rdata_len >= 5 && rr->wire_rdata[0] == 1 &&
			    !rr->wire_rdata[1] &&
			    rr->wire_rdata_len == 5u + rr->wire_rdata[4]) {
				pw = rr->wire_rdata;
				break;
			}
		} lws_end_foreach_dll(d);

	if (!pw) {
		lwsl_err("%s: delegation %s, but no usable NSEC3PARAM\n",
			 __func__, cut);
		return 1;
	}

	iterations = lws_ser_ru16be(pw + 2);
	salt_len = pw[4];
	salt = pw + 5;

	/* each cut costs a hash of this many rounds, the zone chooses it */
	if (iterations > LWS_AUTH_DNS_MAX_NSEC3_ITERATIONS) {
		lwsl_err("%s: NSEC3PARAM iterations %u > %d\n", __func__,
			 iterations, LWS_AUTH_DNS_MAX_NSEC3_ITERATIONS);
		return 1;
	}

	if (name_to_wire(cut, v->z->origin, w, &wl) ||
	    lws_auth_dns_nsec3_hash(w, wl, salt, salt_len, iterations, h))
		return 1;

	lws_auth_dns_b32hex_encode(h, sizeof(h), b32);
	lws_snprintf(owner, sizeof(owner), "%s.%s", b32, v->z->origin);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&v->z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		if (rs->type != 50 || strcasecmp(rs->name, owner))
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, d2,
				      lws_dll2_get_head(&rs->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);
			const uint8_t *r = rr->wire_rdata;
			size_t len = rr->wire_rdata_len, o;
			int ns, soa;

			/* alg flags iterations(2) salt-len salt hash-len hash */
			if (len < 6 || 6u + r[4] > len ||
			    6u + r[4] + r[5u + r[4]] > len)
				goto malformed;
			o = 6u + r[4] + r[5u + r[4]];

			/* RFC 5155 4.1.1: one with other parameters is ignored */
			if (r[0] != 1 || lws_ser_ru16be(r + 2) != iterations ||
			    r[4] != salt_len || memcmp(r + 5, salt, salt_len))
				continue;

			ns = auth_dns_bitmap_has(r + o, len - o, 2);
			soa = auth_dns_bitmap_has(r + o, len - o, 6);
			if (ns < 0 || soa < 0)
				goto malformed;

			if (!ns || soa) {
				lwsl_err("%s: %s has an NS RRset, but the "
					 "zone's NSEC3 for it says it is not "
					 "a delegation\n", __func__, cut);
				return 1;
			}

			found = 1;
		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);

	if (!found)
		lwsl_err("%s: %s has an NS RRset, but the zone has no NSEC3 "
			 "for it attesting a delegation\n", __func__, cut);

	return !found;

malformed:
	lwsl_err("%s: malformed NSEC3 for %s\n", __func__, cut);

	return 1;
}

/*
 * Check one RRSIG RR, \p w / \p len, over \p rs, the way RFC 4035 5.3.1
 * has a validator check it: it has to be from this zone, for this owner's
 * labels and TTL, inside its validity period, and its signature has to verify
 * with a zone key of a supported algorithm in the zone's own DNSKEY RRset.
 *
 * Returns 0 if so, setting *key to the DNSKEY RR that verified it.
 */

static int
auth_dns_verify_rrsig(struct auth_dns_verify *v, const struct auth_dns_rrset *rs,
		      const uint8_t *w, size_t len,
		      const struct auth_dns_rr **key)
{
	enum lws_genhash_types ht;
	uint32_t sexp, sinc;
	uint8_t hash[64];
	int n;

	if (lws_dnssec_alg_hash(w[2], &ht)) {
		lwsl_err("%s: %s type %d: unsupported RRSIG algorithm %d\n",
			 __func__, rs->name, rs->type, w[2]);
		return 1;
	}

	if (w[3] != auth_dns_rrsig_labels(rs->name) ||
	    lws_ser_ru32be(w + 4) != rs->ttl) {
		lwsl_err("%s: %s type %d: RRSIG labels / TTL do not match\n",
			 __func__, rs->name, rs->type);
		return 1;
	}

	/* RFC 4034 3.1.5, in RFC 1982 serial arithmetic */
	sexp = lws_ser_ru32be(w + 8);
	sinc = lws_ser_ru32be(w + 12);
	if ((int32_t)(v->now - sinc) < 0 || (int32_t)(sexp - v->now) < 0) {
		lwsl_err("%s: %s type %d: RRSIG is outside its validity "
			 "period\n", __func__, rs->name, rs->type);
		return 1;
	}

	n = auth_dns_wire_name_len(w + 18, len - 18);
	if (n < 0 || len - 18 - (size_t)n < 1 || (size_t)n != v->apex_len ||
	    memcmp(w + 18, v->apex, v->apex_len)) {
		lwsl_err("%s: %s type %d: RRSIG signer is not the zone\n",
			 __func__, rs->name, rs->type);
		return 1;
	}

	if (auth_dns_rrset_hash(v->z, rs, w, 18 + (size_t)n, ht, hash))
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&v->keyset->rr_list)) {
		const struct auth_dns_rr *k = lws_container_of(d,
						struct auth_dns_rr, list);

		if (k->wire_rdata &&
		    lws_dnssec_key_usable(k->wire_rdata, k->wire_rdata_len,
					  w[2], lws_ser_ru16be(w + 16)) &&
		    !lws_dnssec_sig_verify(v->cx, w[2], k->wire_rdata,
					   k->wire_rdata_len, hash,
					   w + 18 + n, len - 18 - (size_t)n)) {
			*key = k;

			return 0;
		}
	} lws_end_foreach_dll(d);

	lwsl_err("%s: %s type %d: RRSIG does not verify with any zone key\n",
		 __func__, rs->name, rs->type);

	return 1;
}

/*
 * Check the RRset \p rs against the RRSIGs at its owner, \p sigs (or NULL if
 * there are none).  Every RRSIG over it must verify, an authoritative RRset
 * must have at least one, and the apex DNSKEY RRset must have one made by
 * the KSK we were given.
 */

static int
auth_dns_verify_rrset(struct auth_dns_verify *v, const struct auth_dns_rrset *rs,
		      const struct auth_dns_rrset *sigs)
{
	enum auth_dns_role role = auth_dns_rrset_role(v->z, &v->cuts, rs);
	int verified = 0, by_ksk = 0;

	if (role == AUTH_DNS_ROLE_OCCLUDED) {
		lwsl_err("%s: %s type %d is occluded by a delegation, or is a "
			 "DS away from one\n", __func__, rs->name, rs->type);
		return 1;
	}

	if (role != AUTH_DNS_ROLE_AUTH) {
		/* RFC 4035 2.2: the delegation NS RRset and glue are unsigned */
		if (sigs)
			lws_start_foreach_dll(struct lws_dll2 *, d,
					      lws_dll2_get_head(&sigs->rr_list)) {
				const struct auth_dns_rr *rr = lws_container_of(d,
							struct auth_dns_rr, list);

				if (lws_ser_ru16be(rr->wire_rdata) == rs->type) {
					lwsl_err("%s: %s type %d is a delegation's "
						 "NS or glue, and is signed\n",
						 __func__, rs->name, rs->type);
					return 1;
				}
			} lws_end_foreach_dll(d);

		return 0;
	}

	if (sigs)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&sigs->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d,
						struct auth_dns_rr, list);
			const struct auth_dns_rr *key = NULL;

			if (lws_ser_ru16be(rr->wire_rdata) != rs->type)
				continue;

			if (auth_dns_verify_rrsig(v, rs, rr->wire_rdata,
						  rr->wire_rdata_len, &key))
				return 1;

			verified++;
			if (key == v->ksk)
				by_ksk = 1;
		} lws_end_foreach_dll(d);

	v->passes += verified;

	if (rs == v->keyset && !by_ksk) {
		lwsl_err("%s: the DNSKEY RRset is not signed by the KSK\n",
			 __func__);
		return 1;
	}

	if (!verified) {
		lwsl_err("%s: %s type %d is not signed\n", __func__, rs->name,
			 rs->type);
		return 1;
	}

	return 0;
}

/*
 * Find the DNSKEY RR for the key in JWK \p path, as a DNSKEY with \p flags, in
 * the zone's DNSKEY RRset.  Returns NULL if it is not there.
 */

static const struct auth_dns_rr *
auth_dns_verify_find_key(struct auth_dns_verify *v, const char *path, int flags)
{
	uint8_t wire[LWS_AUTH_DNS_DNSKEY_WIRE];
	struct lws_jwk jwk;
	int alg;
	size_t wl;

	if (auth_dns_jwk_load(path, &jwk))
		return NULL;

	alg = lws_auth_dns_jwk_alg(&jwk);
	wl = alg ? lws_auth_dns_dnskey_wire(&jwk, flags, alg, wire,
					    sizeof(wire)) : 0;
	lws_jwk_destroy(&jwk);

	if (!wl) {
		lwsl_err("%s: %s cannot be a DNSKEY\n", __func__, path);
		return NULL;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&v->keyset->rr_list)) {
		const struct auth_dns_rr *k = lws_container_of(d,
						struct auth_dns_rr, list);

		if (k->wire_rdata_len == wl && !memcmp(k->wire_rdata, wire, wl))
			return k;
	} lws_end_foreach_dll(d);

	lwsl_err("%s: the zone does not publish %s as its %s\n", __func__,
		 path, flags == 257 ? "KSK" : "ZSK");

	return NULL;
}

static int
auth_dns_verify(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z)
{
	struct auth_dns_verify v;
	struct lws_dll2 *d, *e;
	int ret = 1, n = 0;

	memset(&v, 0, sizeof(v));
	v.cx	= info->cx;
	v.z	= z;
	v.now	= (uint32_t)(info->verify_time ? info->verify_time :
						  time(NULL));
	v.apex_len = sizeof(v.apex);
	if (name_to_wire(z->origin, "", v.apex, &v.apex_len))
		return 1;

	/*
	 * Everything we hash must have a wire form, and a type we know it by:
	 * a record we cannot read is a record we cannot say was signed.  Find
	 * the apex DNSKEY RRset while we are at it.
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d1,
			      lws_dll2_get_head(&z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d1,
						struct auth_dns_rrset, list);
		int apex = !strcasecmp(rs->name, z->origin);

		if (!rs->type) {
			lwsl_err("%s: %s has an unknown type\n", __func__,
				 rs->name);
			return 1;
		}

		lws_start_foreach_dll(struct lws_dll2 *, d2,
				      lws_dll2_get_head(&rs->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);

			if (!rr->wire_rdata ||
			    (rs->type == 46 && rr->wire_rdata_len < 19)) {
				lwsl_err("%s: %s type %d has unusable RDATA\n",
					 __func__, rs->name, rs->type);
				return 1;
			}
		} lws_end_foreach_dll(d2);

		if (apex && rs->type == 48)
			v.keyset = rs;
	} lws_end_foreach_dll(d1);

	if (!v.keyset) {
		lwsl_err("%s: zone has no DNSKEY RRset\n", __func__);
		return 1;
	}

	/*
	 * The delegation points: owners below the apex with an NS RRset, but
	 * only those the zone's signed NSEC3 chain says are delegations
	 */

	if (auth_dns_cuts_find(z, &v.cuts))
		return 1;

	for (n = 0; n < v.cuts.count; n++)
		if (strcasecmp(v.cuts.ns[n]->name, z->origin) &&
		    auth_dns_verify_cut(&v, v.cuts.ns[n]->name))
			goto bail;

	/* the zone must publish the keys we were given */

	v.ksk = auth_dns_verify_find_key(&v, info->ksk_jwk_filepath, 257);
	if (!v.ksk || (info->zsk_jwk_filepath &&
		       !auth_dns_verify_find_key(&v, info->zsk_jwk_filepath,
						 256)))
		goto bail;

	/*
	 * lws_auth_dns_sort_zone() left the RRsets in canonical order, so
	 * each owner's RRsets, including its RRSIGs, are together: take one
	 * owner at a time
	 */

	d = lws_dll2_get_head(&z->rrset_list);
	while (d) {
		const struct auth_dns_rrset *first = lws_container_of(d,
						struct auth_dns_rrset, list),
					    *sigs = NULL;

		for (e = d; e; e = lws_dll2_get_next(e)) {
			const struct auth_dns_rrset *rs = lws_container_of(e,
						struct auth_dns_rrset, list);

			if (strcasecmp(rs->name, first->name))
				break;
			if (rs->type == 46)
				sigs = rs;
		}

		/* an RRSIG over nothing at its owner is not part of the zone */

		if (sigs)
			lws_start_foreach_dll(struct lws_dll2 *, d2,
					      lws_dll2_get_head(&sigs->rr_list)) {
				const struct auth_dns_rr *rr = lws_container_of(
					d2, struct auth_dns_rr, list);
				uint16_t tc = lws_ser_ru16be(rr->wire_rdata);
				struct lws_dll2 *f;

				for (f = d; f != e; f = lws_dll2_get_next(f))
					if (tc != 46 && lws_container_of(f,
						struct auth_dns_rrset,
						list)->type == tc)
						break;

				if (f == e) {
					lwsl_err("%s: %s: RRSIG over type %u, "
						 "which it does not have\n",
						 __func__, first->name, tc);
					goto bail;
				}
			} lws_end_foreach_dll(d2);

		for (; d != e; d = lws_dll2_get_next(d)) {
			const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

			if (rs->type != 46 && auth_dns_verify_rrset(&v, rs, sigs))
				goto bail;
		}
	}

	lwsl_info("%s: %d RRSIGs verified\n", __func__, v.passes);
	ret = 0;

bail:
	auth_dns_cuts_destroy(&v.cuts);

	return ret;
}

int
lws_auth_dns_verify_zone(struct lws_auth_dns_sign_info *info)
{
	struct auth_dns_zone zone;
	struct stat st;
	int fd, ret = 1;
	ssize_t n;
	char *buf;

	if (!info->input_filepath || !info->ksk_jwk_filepath || !info->cx)
		return 1;

	fd = open(info->input_filepath, LWS_O_RDONLY);
	if (fd < 0)
		return 1;

	if (fstat(fd, &st) || st.st_size <= 0 || st.st_size > 1024 * 1024) {
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
		lwsl_err("%s: failed to parse zone\n", __func__);
		goto bail;
	}

	/* signatures over a zone are only as good as its identity */
	if (lws_auth_dns_zone_check_origin(&zone, info->domain)) {
		lwsl_err("%s: zone is not %s\n", __func__,
			 info->domain ? info->domain : "coherent");
		goto bail;
	}

	lws_auth_dns_sort_zone(info, &zone);

	ret = auth_dns_verify(info, &zone);

bail:
	lws_auth_dns_free_zone(&zone);
	lws_free(buf);

	return ret;
}

#endif
