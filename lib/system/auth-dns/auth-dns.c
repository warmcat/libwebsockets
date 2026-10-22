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

#include "private-lib-core.h"
#include "private-lib-system-auth-dns.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

static int
strexp_cb(void *priv, const char *name, char *out, size_t *pos,
	  size_t olen, size_t *exp_ofs)
{
	struct lws_auth_dns_sign_info *info = (struct lws_auth_dns_sign_info *)priv;
	int n;
	size_t l;
	const char *val = NULL;

	if (info->subst_cb) {
		lwsl_notice("%s: attempting substitution for macro name: '%s'\n", __func__, name);
		val = info->subst_cb(info, name);
	}

	if (!val) {
		for (n = 0; n < info->num_substs; n++) {
			if (!strcmp(name, info->subst_names[n])) {
				val = info->subst_values[n];
				break;
			}
		}
	}

	if (!val) {
		lwsl_warn("%s: unknown substitution variable: %s\n", __func__, name);
		return LSTRX_FATAL_NAME_UNKNOWN;
	}

	if (val[0] == '\0') {
		info->skip_line = 1;
		return LSTRX_DONE;
	}

	l = strlen(val);

	if (*exp_ofs >= l)
		return LSTRX_DONE;

	if (*pos >= olen)
		return LSTRX_FILLED_OUT;

	l -= *exp_ofs;
	if (l > olen - *pos)
		l = olen - *pos;

	memcpy(out + *pos, val + *exp_ofs, l);
	*pos += l;
	*exp_ofs += l;

	if (*exp_ofs == strlen(val))
		return LSTRX_DONE;

	return LSTRX_FILLED_OUT;
}

/*
 * Zone files may write $ORIGIN with or without the trailing root dot, but
 * everything downstream (the signer's name_to_wire(), the NSEC3 hashing, the
 * plugin's answer serialization) decides whether a name still needs the
 * origin appended by looking for that dot.  A dotless origin therefore makes
 * an already-qualified owner name get the origin appended a second time, eg
 * "x.example.com" under "$ORIGIN example.com" hashes and encodes as
 * "x.example.com.example.com".
 *
 * So we normalise here, once, at the only place zones enter the library: the
 * origin always ends in a dot, and every owner name is stored fully
 * qualified with a trailing dot.
 */

static void
auth_dns_origin_normalise(char *origin, size_t len)
{
	size_t l = strlen(origin);

	if (!l || origin[l - 1] == '.' || l + 2 > len)
		return;

	origin[l] = '.';
	origin[l + 1] = '\0';
}

/*
 * Bring one owner name to fully-qualified form: "@" is the origin, a name
 * that already ends in a dot is left alone, and anything else gets the
 * (already normalised) origin appended.  Without an origin there is nothing
 * to qualify against, so the name is left as it was.
 *
 * Fails if the qualified name would not fit: cut down, it is another name.
 */

static int
auth_dns_name_qualify(char *name, size_t len, const char *origin)
{
	size_t l = strlen(name), ol = strlen(origin);
	char t[256];

	if (!strcmp(name, "@")) {
		if (ol >= len)
			return 1;
		if (ol)
			lws_strncpy(name, origin, len);

		return 0;
	}

	if (!l || name[l - 1] == '.' || !ol)
		return 0;

	if (!strcmp(origin, ".")) {
		if (l + 2 > sizeof(t) || l + 2 > len)
			return 1;
		lws_snprintf(t, sizeof(t), "%s.", name);
	} else {
		if (l + 1 + ol + 1 > sizeof(t) || l + 1 + ol + 1 > len)
			return 1;
		lws_snprintf(t, sizeof(t), "%s.%s", name, origin);
	}

	lws_strncpy(name, t, len);

	return 0;
}

/*
 * Read one domain name field of a master file (RFC 1035 5.1), \p len bytes
 * at \p in, into the plain form auth-dns keeps names in, at \p out: labels
 * joined by '.', with every escape (\X, \DDD) resolved, and a trailing '.' if
 * the name is absolute.  "@" and "." are returned as they are.
 *
 * Everything downstream (owner lookups, zone cuts, RRSIG label counts, the
 * NSEC3 closest encloser walk, the signed zone the signer writes out and
 * parses back) takes every '.' in that form as a label boundary and the
 * text as what the master file said, so a label is refused if it would need
 * an escape to be written: a '.' (eg, from "\." or "\046"), '\', '"', '(',
 * ')', ';', whitespace or a byte that is not printable ASCII.  So is an
 * empty label anywhere but the root, which would encode as the root label in
 * the middle of the name, a label over 63 bytes or a name over 255 on the
 * wire, a '*' anywhere but as the whole leftmost label (RFC 4592 2.1.1), and
 * a name starting with '$', which would read back as a directive.
 *
 * Returns NULL if the name is good, else what is wrong with it.
 */

const char *
lws_auth_dns_name_canon(const char *in, size_t len, char *out, size_t olen)
{
	size_t i = 0, o = 0, ll = 0, wl = 1;
	int leftmost = 1, star = 0;

	if (!len || olen < 2)
		return "empty name";

	if (len == 1 && (in[0] == '@' || in[0] == '.')) {
		out[0] = in[0];
		out[1] = '\0';

		return NULL;
	}

	while (i < len) {
		unsigned int c = (unsigned char)in[i++];
		int esc = 0;

		if (c == '.') {
			if (!ll)
				return "empty label";

			wl += 1 + ll;
			if (o + 2 > olen)
				return "name too long";
			out[o++] = '.';
			ll = 0;
			leftmost = 0;
			star = 0;
			continue;
		}

		if (c == '\\') {
			if (i == len)
				return "'\\' at the end of the name";

			esc = 1;
			c = (unsigned char)in[i++];
			if (c >= '0' && c <= '9') {
				if (i + 2 > len ||
				    in[i] < '0' || in[i] > '9' ||
				    in[i + 1] < '0' || in[i + 1] > '9')
					return "\\DDD needs three decimal digits";

				c = (c - '0') * 100 +
				    (unsigned int)(in[i] - '0') * 10 +
				    (unsigned int)(in[i + 1] - '0');
				i += 2;
				if (c > 255)
					return "\\DDD is more than 255";
			}
		}

		if (c == '*') {
			if (!leftmost || ll)
				return "'*' is only allowed as the whole "
				       "leftmost label";
			star = 1;
		} else if (star)
			return "'*' is only allowed as the whole leftmost label";

		if (c <= ' ' || c >= 0x7f || strchr(".\\\"();", (int)c))
			return esc && c == '.' ?
				"a '.' inside a label is not supported" :
				"a label holds a byte that needs escaping, "
				"which is not supported";

		if (!o && c == '$')
			return "a name can't start with '$'";

		if (++ll > 63)
			return "label longer than 63 bytes";
		if (o + 2 > olen)
			return "name too long";
		out[o++] = (char)c;
	}

	if (ll)
		wl += 1 + ll;
	if (wl > 255)
		return "name longer than 255 bytes on the wire";

	out[o] = '\0';

	return NULL;
}

/* is name (with or without its trailing dot) the origin, or below it? */

static int
auth_dns_name_in_origin(const char *name, const char *origin, size_t ol)
{
	size_t nl = strlen(name);

	if (nl && name[nl - 1] == '.')
		nl--;

	if (!ol) /* the root: every name is below it */
		return 1;

	if (nl == ol)
		return !strncasecmp(name, origin, ol);

	return nl > ol && name[nl - ol - 1] == '.' &&
	       !strncasecmp(name + nl - ol, origin, ol);
}

int
lws_auth_dns_zone_check_origin(const struct auth_dns_zone *z,
			       const char *domain)
{
	size_t ol = strlen(z->origin), dl;

	/*
	 * No $ORIGIN leaves relative names unqualified, and more than one
	 * makes the zone's identity depend on which one a reader takes
	 */
	if (z->origin_lines != 1 || !ol) {
		lwsl_warn("%s: zone must set its origin exactly once (%u "
			  "$ORIGIN lines)\n", __func__, z->origin_lines);
		return 1;
	}

	if (z->origin[ol - 1] == '.')
		ol--;

	if (domain) {
		dl = strlen(domain);
		if (dl && domain[dl - 1] == '.')
			dl--;

		if (dl != ol || strncasecmp(domain, z->origin, ol)) {
			lwsl_warn("%s: zone origin %s is not %s\n", __func__,
				  z->origin, domain);
			return 1;
		}
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (!rs->name ||
		    !auth_dns_name_in_origin(rs->name, z->origin, ol)) {
			lwsl_warn("%s: owner %s is outside zone %s\n", __func__,
				  rs->name ? rs->name : "(none)", z->origin);
			return 1;
		}
	} lws_end_foreach_dll(d);

	return 0;
}

/* the length of the uncompressed wire name at w, or -1 */

static int
auth_dns_wire_name_skip(const uint8_t *w, size_t len)
{
	size_t p = 0;

	while (p < len && w[p]) {
		if (w[p] & 0xc0) /* compression has no place in zone RDATA */
			return -1;
		p += 1u + w[p];
	}

	return p < len ? (int)p + 1 : -1;
}

/* an RRSIG time, RFC 1982 serial number, as the instant nearest now */

static time_t
auth_dns_rrsig_time(uint32_t t, time_t now)
{
	return now + (time_t)(int32_t)(t - (uint32_t)now);
}

int
lws_auth_dns_zone_validity(const struct auth_dns_zone *z, time_t now,
			   unsigned int skew,
			   struct lws_auth_dns_zone_validity *v)
{
	int have_serial = 0, apex, ret = LWS_AUTH_DNS_ZV_OK;

	memset(v, 0, sizeof(*v));

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		const struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);

		apex = rs->name && !strcasecmp(rs->name, z->origin);

		lws_start_foreach_dll(struct lws_dll2 *, d2,
				      lws_dll2_get_head(&rs->rr_list)) {
			const struct auth_dns_rr *rr = lws_container_of(d2,
						struct auth_dns_rr, list);
			const uint8_t *w = rr->wire_rdata;
			size_t l = rr->wire_rdata_len;
			time_t inc, exp;
			int n, m;

			if (!w)
				continue;

			if (rs->type == 6 && apex && !have_serial) { /* SOA */
				n = auth_dns_wire_name_skip(w, l);
				m = n < 0 ? -1 : auth_dns_wire_name_skip(w + n,
							l - (size_t)n);
				if (m >= 0 && (size_t)(n + m) + 4 <= l) {
					v->serial = lws_ser_ru32be(w + n + m);
					have_serial = 1;
				}
				continue;
			}

			/* RRSIG: covered(2) alg labels ttl(4) exp(4) inc(4) */
			if (rs->type != 46 || l < 18)
				continue;

			exp = auth_dns_rrsig_time(lws_ser_ru32be(w + 8), now);
			inc = auth_dns_rrsig_time(lws_ser_ru32be(w + 12), now);

			if (!v->rrsigs++ || exp < v->expiration)
				v->expiration = exp;
			if (v->rrsigs == 1 || inc > v->inception)
				v->inception = inc;

			if (apex && lws_ser_ru16be(w) == 6) {
				if (!v->soa_signed || inc > v->soa_inception)
					v->soa_inception = inc;
				v->soa_signed = 1;
			}
		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);

	if (!have_serial)
		ret = LWS_AUTH_DNS_ZV_NO_SOA;
	else if (!v->soa_signed)
		ret = LWS_AUTH_DNS_ZV_UNSIGNED;
	else if (v->inception > now + (time_t)skew)
		ret = LWS_AUTH_DNS_ZV_NOT_YET_VALID;
	else if (v->expiration <= now - (time_t)skew)
		ret = LWS_AUTH_DNS_ZV_EXPIRED;

	return ret;
}

struct auth_dns_rrset *
lws_auth_dns_zone_cut(struct auth_dns_zone *z, const char *name)
{
	struct auth_dns_rrset *cut = NULL;
	size_t ol = strlen(z->origin);

	if (ol && z->origin[ol - 1] == '.')
		ol--;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
						struct auth_dns_rrset, list);
		size_t l;

		if (rs->type != 2 || !rs->name)
			continue;

		l = strlen(rs->name);
		if (l && rs->name[l - 1] == '.')
			l--;

		/* only an owner strictly below the apex is a cut */
		if (!l || l <= ol ||
		    !auth_dns_name_in_origin(rs->name, z->origin, ol) ||
		    !auth_dns_name_in_origin(name, rs->name, l))
			continue;

		/* everything below the topmost cut is the child's */
		if (!cut || strlen(rs->name) < strlen(cut->name))
			cut = rs;
	} lws_end_foreach_dll(d);

	return cut;
}

#if (_LWS_ENABLED_LOGS & LLL_ERR)
/*
 * The zone text can come from anyone publishing a zone over the DHT: what
 * is quoted from it in a log is made printable first
 */

static const char *
auth_dns_log_text(char *out, size_t olen, const char *in, size_t len)
{
	char t[256];

	lws_strnncpy(t, in, len, sizeof(t));
	lws_json_purify(out, t, (int)olen, NULL);

	return out;
}
#endif

/*
 * One logical line of a master file (comments, quotes, escapes and the
 * parentheses that continue it over physical lines already dealt with):
 * a $ORIGIN or $TTL directive, or one RR.  \p last_name is the owner of
 * the RR before, which a line starting with whitespace takes for its own.
 *
 * Returns nonzero if the zone is to be refused.
 */

static int
auth_dns_zone_line(struct auth_dns_zone *zone, const char *line, size_t len,
		   char *last_name, size_t last_len, unsigned int line_no)
{
	const char *s = line, *e = line + len, *f, *rd, *why;
	struct auth_dns_rrset *rrset = NULL;
	int have_ttl = 0, have_class = 0, r;
	struct auth_dns_rr *rr;
	char cur_name[256], tok[32];
	uint16_t class_ = 1, type = 0;
	lws_tokenize_elem te;
	lws_tokenize_t ts;
	uint32_t ttl = 0;
#if (_LWS_ENABLED_LOGS & LLL_ERR)
	char pt[128];
#endif

	while (s < e && (*s == ' ' || *s == '\t'))
		s++;
	if (s == e)
		return 0; /* nothing but whitespace */

	if (*line == '$') {
		/* the directive is the first field, its value the second */

		f = line;
		while (f < e && *f != ' ' && *f != '\t')
			f++;
		s = f;
		while (s < e && (*s == ' ' || *s == '\t'))
			s++;
		rd = s;
		while (rd < e && *rd != ' ' && *rd != '\t')
			rd++;

		if (lws_ptr_diff_size_t(f, line) == 7 &&
		    !strncmp(line, "$ORIGIN", 7)) {
			/*
			 * each one changes the origin for the records after
			 * it: count them, so a zone's identity can be checked
			 * by lws_auth_dns_zone_check_origin()
			 */
			zone->origin_lines++;
			why = lws_auth_dns_name_canon(s, lws_ptr_diff_size_t(rd, s),
						      zone->origin,
						      sizeof(zone->origin));
			if (!why && (zone->origin[0] == '@' ||
				     zone->origin[0] == '*'))
				why = "not a domain";
			if (why) {
				zone->origin[0] = '\0';
				lwsl_err("%s: line %u: $ORIGIN '%s': %s\n",
					 __func__, line_no,
					 auth_dns_log_text(pt, sizeof(pt), s,
						lws_ptr_diff_size_t(rd, s)), why);

				return 1;
			}
			auth_dns_origin_normalise(zone->origin,
						  sizeof(zone->origin));

			return 0;
		}

		if (lws_ptr_diff_size_t(f, line) == 4 &&
		    !strncmp(line, "$TTL", 4)) {
			lws_strnncpy(zone->default_ttl, s,
				     lws_ptr_diff_size_t(rd, s),
				     sizeof(zone->default_ttl));

			return 0;
		}

		lwsl_err("%s: line %u: unsupported directive '%s'\n",
			 __func__, line_no,
			 auth_dns_log_text(pt, sizeof(pt), line,
					   lws_ptr_diff_size_t(f, line)));

		return 1;
	}

	if (*line != ' ' && *line != '\t') {
		/* the owner is the first field, up to unescaped whitespace */

		f = s = line;
		while (s < e && *s != ' ' && *s != '\t') {
			if (*s == '\\' && s + 1 < e)
				s++;
			s++;
		}

		why = lws_auth_dns_name_canon(f, lws_ptr_diff_size_t(s, f),
					      cur_name, sizeof(cur_name));
		if (!why && auth_dns_name_qualify(cur_name, sizeof(cur_name),
						  zone->origin))
			why = "name too long with the origin";
		if (why) {
			lwsl_err("%s: line %u: owner '%s': %s\n", __func__,
				 line_no, auth_dns_log_text(pt, sizeof(pt), f,
						lws_ptr_diff_size_t(s, f)), why);

			return 1;
		}

		/* canonicalize name: fully qualified, then lowercase */
		for (char *c = cur_name; *c; c++)
			*c = (char)tolower((unsigned char)*c);

		lws_strncpy(last_name, cur_name, last_len);
	} else {
		if (!last_name[0]) {
			lwsl_err("%s: line %u: no owner to carry on from\n",
				 __func__, line_no);

			return 1;
		}
		lws_strncpy(cur_name, last_name, sizeof(cur_name));
	}

	/*
	 * Then the TTL and class, either way around and both optional, and
	 * the type.  Anything else there is refused: dropping it would read
	 * the fields after it as different ones.
	 */

	lws_tokenize_init(&ts, s, LWS_TOKENIZE_F_NO_INTEGERS |
				  LWS_TOKENIZE_F_NO_FLOATS);
	ts.len = lws_ptr_diff_size_t(e, s);

	do {
		te = lws_tokenize(&ts);
		if (te != LWS_TOKZE_TOKEN || ts.token_len >= sizeof(tok)) {
			lwsl_err("%s: line %u: %s: %s\n", __func__, line_no,
				 cur_name, te == LWS_TOKZE_ENDED ? "no type" :
				 "malformed TTL, class or type");

			return 1;
		}
		lws_strnncpy(tok, ts.token, ts.token_len, sizeof(tok));

		if (!have_ttl && tok[0] >= '0' && tok[0] <= '9') {
			uint64_t v = 0;
			const char *cp = tok;

			while (*cp >= '0' && *cp <= '9' && v <= 0x7fffffff)
				v = (v * 10) + (uint64_t)(*cp++ - '0');
			if (*cp || v > 0x7fffffff) { /* RFC 2181 8 */
				lwsl_err("%s: line %u: bad TTL '%s'\n",
					 __func__, line_no, tok);

				return 1;
			}
			ttl = (uint32_t)v;
			have_ttl = 1;
			continue;
		}

		if (!have_class && !strcasecmp(tok, "IN")) {
			class_ = 1;
			have_class = 1;
			continue;
		}

		/* 0 if it is not a type we can read */
		type = lws_auth_dns_type_from_str(tok);
		break;
	} while (1);

	if (!have_ttl && zone->default_ttl[0])
		ttl = (uint32_t)atoi(zone->default_ttl);

	/* find existing rrset */
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&zone->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d,
					struct auth_dns_rrset, list);

		if (rs->type == type && rs->class_ == class_ &&
		    !strcmp(rs->name, cur_name)) {
			rrset = rs;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!rrset) {
		rrset = lws_zalloc(sizeof(*rrset), "auth_dns_rrset");
		if (!rrset)
			return 1;
		rrset->type = type;
		rrset->class_ = class_;
		rrset->ttl = ttl;
		lws_dll2_add_tail(&rrset->list, &zone->rrset_list);
		rrset->name = lws_strdup(cur_name);
		if (!rrset->name)
			return 1;
	}

	rr = lws_zalloc(sizeof(*rr), "auth_dns_rr");
	if (!rr)
		return 1;
	lws_dll2_add_tail(&rr->list, &rrset->rr_list);

	/* The remainder of the line is rdata. */

	rd = ts.start;
	while (rd < e && (*rd == ' ' || *rd == '\t'))
		rd++;

	{
		size_t rdlen = lws_ptr_diff_size_t(e, rd);

		/* Strip surrounding quotes if present (TXT records) */
		if (rdlen >= 2 && rd[0] == '"' && rd[rdlen - 1] == '"') {
			rd++;
			rdlen -= 2;
		}

		rr->rdata = lws_malloc(rdlen + 1, "auth_dns_rdata");
		if (!rr->rdata)
			return 1;
		memcpy(rr->rdata, rd, rdlen);
		rr->rdata[rdlen] = '\0';
		rr->rdata_len = rdlen;
	}

	/*
	 * The signer expands ${...} substitutions before it parses, so rdata
	 * still holding one comes from a reader of the raw zonefile (eg, the
	 * monitor's inventory), which only wants the text: keep it as that,
	 * there is no wire form to fail at
	 */
	if (strstr(rr->rdata, "${")) {
		lwsl_info("%s: %s: unexpanded '%s' kept as text\n",
			  __func__, rrset->name, rr->rdata);

		return 0;
	}

	r = lws_auth_dns_rdata_to_wire(zone, rr, rrset->type);
	if (r == LWS_AUTH_DNS_RDATA_MALFORMED) {
		lwsl_err("%s: line %u: %s: malformed rdata '%s'\n", __func__,
			 line_no, rrset->name,
			 auth_dns_log_text(pt, sizeof(pt), rr->rdata,
					   rr->rdata_len));

		return 1;
	}
	if (r)
		lwsl_err("Failed to wire-encode rdata for %s\n", rrset->name);

	lwsl_info("Parsed RR: name=%s type=%d ttl=%u rdata=%s\n", rrset->name,
		  rrset->type, rrset->ttl, rr->rdata);

	return 0;
}

int
lws_auth_dns_parse_zone_buf(const char *buf, size_t len, struct auth_dns_zone *zone)
{
	unsigned int line = 1, line_start = 1;
	const char *p = buf, *end = buf + len;
	int in_parens = 0, in_comment = 0, in_quote = 0, esc = 0;
	char last_name[256] = "";
	char line_accum[16384];
	size_t lptr = 0;

	lwsl_notice("%s: Parsing zone buffer of length %zu\n", __func__, len);

	/*
	 * Gather each logical line (RFC 1035 5.1): ';' starts a comment and
	 * parentheses continue a line over newlines, except inside a quoted
	 * string or escaped with '\'.  The parentheses themselves separate
	 * fields the same as whitespace.  Quotes and escapes are kept for the
	 * fields to be read with.
	 */

	for (p = buf; p <= end; p++) {
		char c = p < end ? *p : '\n';

		if (!c) {
			lwsl_err("%s: line %u: NUL in zone text\n", __func__,
				 line);

			return 1;
		}

		if (c == '\n' && (p == end || !in_parens)) {
			line_accum[lptr] = '\0';

			if (lptr && auth_dns_zone_line(zone, line_accum, lptr,
						       last_name,
						       sizeof(last_name),
						       line_start))
				return 1;

			lptr = 0;
			in_comment = in_quote = esc = in_parens = 0;
			line_start = ++line;
			continue;
		}

		if (c == '\n') {
			/* inside parentheses: the line goes on */
			line++;
			in_comment = esc = 0;
			c = ' ';
		}

		if (in_comment || c == '\r')
			continue;

		if (esc)
			esc = 0;
		else if (c == '\\')
			esc = 1;
		else if (c == '"')
			in_quote = !in_quote;
		else if (!in_quote) {
			if (c == ';') {
				in_comment = 1;
				continue;
			}
			if (c == '(' || c == ')') {
				in_parens = c == '(';
				c = ' ';
			}
		}

		if (lptr == sizeof(line_accum) - 1) {
			lwsl_err("%s: line %u: logical line too long\n",
				 __func__, line_start);

			return 1;
		}

		line_accum[lptr++] = c;
	}

	return 0;
}

void
lws_auth_dns_free_zone(struct auth_dns_zone *z)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&z->rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
			lws_dll2_remove(&rr->list);
			if (rr->rdata)
				lws_free(rr->rdata);
			if (rr->wire_rdata)
				lws_free(rr->wire_rdata);
			lws_free(rr);
		} lws_end_foreach_dll_safe(d2, d3);

		lws_dll2_remove(&rs->list);
		if (rs->name)
			lws_free(rs->name);
		lws_free(rs);
	} lws_end_foreach_dll_safe(d, d1);
}

/*
 * write() may legally return short or fail, eg, on ENOSPC or a signal.
 * Loop until everything is out, or fail.
 */
static int
auth_dns_write_all(int fd, const void *p, size_t len)
{
	const uint8_t *q = (const uint8_t *)p;

	while (len) {
		ssize_t w = write(fd, q, len);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		q += w;
		len -= (size_t)w;
	}

	return 0;
}

int
lws_auth_dns_sign_zone(struct lws_auth_dns_sign_info *info)
{
	char obuf[8192]; /* simple large enough buffer for test */
	int fd, n, ofd = -1, res_wr, temp_len = 0, temp_max = 0, ret = 1;
	size_t uout = 0;
	struct stat st;
	char *buf, *expbuf;
	ssize_t ns;
	struct lws_jwk jwk;
	struct lws_jose jose;
	struct lws_jws jws;
	struct stat ost;
	char *outbuf = NULL, *compact = NULL, *temp = NULL;

	/* it is logged below even if the fstat did not happen */
	memset(&ost, 0, sizeof(ost));

	lwsl_info("%s: starting zone signing from %s\n", __func__, info->input_filepath);

	fd = open(info->input_filepath, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, info->input_filepath);
		return 1;
	}

	if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 1024 * 1024) {
		close(fd);
		return 1;
	}

	buf = lws_malloc((size_t)st.st_size + 1, "auth_dns_in");
	if (!buf) {
		close(fd);
		return 1;
	}

	ns = read(fd, buf, (unsigned int)st.st_size);
	close(fd);

	if (ns != st.st_size) {
		lws_free(buf);
		return 1;
	}

	buf[st.st_size] = '\0';

	expbuf = lws_malloc((size_t)st.st_size * 2, "auth_dns_exp");
	if (!expbuf) {
		lws_free(buf);
		return 1;
	}

	char *lb = buf;
	uout = 0;
	while (lb < buf + st.st_size) {
		char *le = (char *)strchr(lb, '\n');
		if (!le)
			le = buf + st.st_size;
		else
			le++; /* Include newline */

		info->curr_line = lb;
		info->curr_line_len = (size_t)(le - lb);
		info->skip_line = 0;

		/* Expand current line */
		char line_exp[4096];
		lws_strexp_t exp_line;
		size_t uin_line = 0, uout_line = 0;

		lws_strexp_init(&exp_line, info, strexp_cb, line_exp, sizeof(line_exp));
		if (lws_strexp_expand(&exp_line, lb, info->curr_line_len, &uin_line, &uout_line) != LSTRX_DONE && !info->skip_line) {
			lwsl_err("%s: lws_strexp_expand failed or filled out buffer on line\n", __func__);
			goto bail;
		}

		if (!info->skip_line && uout_line > 0) {
			if (uout + uout_line >= (size_t)st.st_size * 2) {
				lwsl_err("%s: expbuf overflow\n", __func__);
				goto bail;
			}
			memcpy(expbuf + uout, line_exp, uout_line);
			uout += uout_line;
		}

		lb = le;
	}

	expbuf[uout] = '\0';

	struct auth_dns_zone zone;
	memset(&zone, 0, sizeof(zone));

	if (lws_auth_dns_parse_zone_buf(expbuf, uout, &zone)) {
		lwsl_err("Failed to parse zone\n");
		goto bail_zone;
	}

	/*
	 * The signed output carries one $ORIGIN, the last one the input had,
	 * so whatever the input said its domain was elsewhere, only signing
	 * input that is exactly the one zone we were asked to sign means the
	 * signature binds to what it says
	 */
	if (lws_auth_dns_zone_check_origin(&zone, info->domain)) {
		lwsl_err("%s: refusing to sign zone %s\n", __func__,
			 info->domain ? info->domain : zone.origin);
		goto bail_zone;
	}

	if (lws_auth_dns_inject_mock_keys(info, &zone)) {
		lwsl_err("%s: unable to prepare the zone for signing\n",
			 __func__);
		goto bail_zone;
	}
	lws_auth_dns_sort_zone(info, &zone);
	if (lws_auth_dns_sign_rrsets(info, &zone)) {
		lwsl_err("%s: unable to sign the zone\n", __func__);
		goto bail_zone;
	}

	/* Write canonical sorted and combined zone into output_filepath (or fallback to user output string dump) */
	fd = open(info->output_filepath ? info->output_filepath : "signed.zone", LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (fd < 0) {
		lwsl_err("Failed to open output file for signing results\n");
		goto bail_zone;
	}

	/* Write generic setup string at top */
	n = lws_snprintf(obuf, sizeof(obuf), "$ORIGIN %s\n$TTL %u\n\n", zone.origin, atoi(zone.default_ttl) ? atoi(zone.default_ttl) : 3600);
	if (n > (int)sizeof(obuf) - 1)
		n = (int)sizeof(obuf) - 1;
	if (auth_dns_write_all(fd, obuf, (size_t)n)) {
		lwsl_err("%s: write failed on signed zone\n", __func__);
		goto bail_fd;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&zone.rrset_list)) {
		struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);

		char tn[16];
		const char *ts = lws_auth_dns_type_to_str(rs->type, tn, sizeof(tn));

		lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
			struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);

			n = lws_snprintf(obuf, sizeof(obuf), "%-30s\t%u\tIN\t%s\t%s\n",
				rs->name, rs->ttl, ts, rr->rdata ? rr->rdata : "");
			if (n > (int)sizeof(obuf) - 1)
				n = (int)sizeof(obuf) - 1;
			if (auth_dns_write_all(fd, obuf, (size_t)n)) {
				lwsl_err("%s: write failed on signed zone\n", __func__);
				goto bail_fd;
			}
		} lws_end_foreach_dll(d2);
	} lws_end_foreach_dll(d);

	if (close(fd)) {
		lwsl_err("%s: close failed on signed zone\n", __func__);
		goto bail_zone;
	}
	lwsl_info("lws_auth_dns_sign_zone succeeded! Wrote to %s\n", info->output_filepath ? info->output_filepath : "signed.zone");

	if (!info->jws_filepath || !info->ksk_jwk_filepath) {
		lwsl_err("Missing jws_filepath or ksk_jwk_filepath\n");
		goto bail_jws;
	}

	lwsl_info("Starting JWS generation for %s (using KSK)\n", info->jws_filepath);

	if (lws_jwk_load(&jwk, info->ksk_jwk_filepath, NULL, NULL)) {
		lwsl_err("Failed loading KSK jwk\n");
		goto bail_jws;
	}

	ofd = open(info->output_filepath ? info->output_filepath : "signed.zone", LWS_O_RDONLY);
	if (ofd < 0 || fstat(ofd, &ost) || ost.st_size <= 0 || ost.st_size >= 1048576) {
		lwsl_err("Failed file open/stat ofd=%d st_size=%ld\n", ofd, (long)ost.st_size);
		goto bail_ofd;
	}

	outbuf = lws_malloc((size_t)ost.st_size, "auth_dns_out_jws");
	if (!outbuf || read(ofd, outbuf, (unsigned int)ost.st_size) != ost.st_size) {
		lwsl_err("Failed read or malloc\n");
		goto bail_ofd;
	}

	compact = lws_malloc((size_t)ost.st_size * 2 + 1024, "jws_compact");
	if (!compact) {
		lwsl_err("Failed alloc compact\n");
		goto bail_ofd;
	}

	temp_max = temp_len = (int)(ost.st_size * 2 + 4096);
	temp = lws_malloc((size_t)temp_len, "jws_temp");
	if (!temp) {
		lwsl_err("Failed alloc temp\n");
		goto bail_ofd;
	}

	lws_jws_init(&jws, &jwk, info->cx);
	lws_jose_init(&jose);

	if (lws_jws_alloc_element(&jws.map, LJWS_JOSE, (temp + temp_max - temp_len), &temp_len, 2048, 0)) {
		lwsl_err("Failed JWS alloc JOSE\n");
		goto bail_jose;
	}

	const char *alg = "ES256";
	if (jwk.kty == LWS_GENCRYPTO_KTY_EC) {
		if (jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len == 48) alg = "ES384";
		else if (jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len == 66) alg = "ES512";
	} else if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
		if (jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len <= 256) alg = "RS256";
		else if (jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len <= 384) alg = "RS384";
		else alg = "RS512";
	}

	{
		char jwk_pub[1024];
		int jwk_pub_len = sizeof(jwk_pub);

		if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF /* pure public components without newlines */, jwk_pub, &jwk_pub_len) < 0) {
			lwsl_err("Failed to export public JWK for JWS header\n");
			goto bail_jose;
		}

		/* Write both alg and the fully exported JSON Web Key into the JOSE header */
		int n = lws_snprintf((char *)jws.map.buf[LJWS_JOSE], 2048, "{\"alg\":\"%s\",\"jwk\":%s}", alg, jwk_pub);
		if (n >= 2048) {
			lwsl_err("JWS JOSE header exceeded maximum length\n");
			goto bail_jose;
		}
		jws.map.len[LJWS_JOSE] = (uint32_t)n;
	}

	jws.map.buf[LJWS_PYLD] = (const char *)outbuf;
	jws.map.len[LJWS_PYLD] = (uint32_t)ost.st_size;

	if (lws_jws_encode_b64_element(&jws.map_b64, LJWS_PYLD, (temp + temp_max - temp_len), &temp_len, jws.map.buf[LJWS_PYLD], jws.map.len[LJWS_PYLD]) ||
		lws_jws_encode_b64_element(&jws.map_b64, LJWS_JOSE, (temp + temp_max - temp_len), &temp_len, jws.map.buf[LJWS_JOSE], jws.map.len[LJWS_JOSE])) {
		lwsl_err("Failed JWS b64 encode\n");
		goto bail_jose;
	}

	lwsl_notice("JWS Header String: '%s'\n", (const char *)jws.map.buf[LJWS_JOSE]);

	if (lws_jws_parse_jose(&jose, (const char *)jws.map.buf[LJWS_JOSE], (int)jws.map.len[LJWS_JOSE], (temp + temp_max - temp_len), &temp_len) < 0) {
		lwsl_err("Failed JWS parse JOSE\n");
		goto bail_jose;
	}

	if (lws_jws_alloc_element(&jws.map_b64, LJWS_SIG, (temp + temp_max - temp_len), &temp_len, 512, 0)) {
		lwsl_err("Failed JWS alloc SIG\n");
		goto bail_jose;
	}

	n = lws_jws_sign_from_b64(&jose, &jws, (char *)jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);
	if (n < 0) {
		lwsl_err("Failed JWS sign from b64: %d\n", n);
		goto bail_jose;
	}

	jws.map_b64.len[LJWS_SIG] = (uint32_t)n;
	res_wr = lws_jws_write_compact(&jws, compact, (size_t)ost.st_size * 2 + 1024);
	if (res_wr) {
		lwsl_err("Failed JWS compact write\n");
		goto bail_jose;
	}

	{
		int jfd = open(info->jws_filepath, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);

		if (jfd < 0) {
			lwsl_err("Failed opening JWS output file\n");
			goto bail_jose;
		}

		if (auth_dns_write_all(jfd, compact, strlen(compact))) {
			lwsl_err("%s: write failed on JWS output\n", __func__);
			close(jfd);
			goto bail_jose;
		}

		if (close(jfd)) {
			lwsl_err("%s: close failed on JWS output\n", __func__);
			goto bail_jose;
		}

		lwsl_info("Wrote outer signature JWS to %s\n", info->jws_filepath);
	}

	lws_free_set_NULL(compact);
	lws_free_set_NULL(temp);

	/* the only way to get here is with both output files fully written */
	ret = 0;

bail_jose:
	lws_jose_destroy(&jose);
bail_ofd:
	/* NULL on the success path, which already freed them */
	lws_free(compact);
	lws_free(temp);
	if (outbuf)
		lws_free(outbuf);
	if (ofd >= 0)
		close(ofd);
	lws_jwk_destroy(&jwk);
bail_jws:
bail_zone:
	/* every path here has a zone that must be freed */
	lws_auth_dns_free_zone(&zone);
	lws_free(expbuf);
	lws_free(buf);

	return ret;

bail_fd:
	close(fd);
	goto bail_zone;

bail:
	if (expbuf)
		lws_free(expbuf);
	if (buf)
		lws_free(buf);

	return 1;
}

#endif
