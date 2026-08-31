/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Canonicalization of untrusted whois JSON.  whois data can arrive from
 * peers we do not trust to send schema-shaped content: this parses it
 * against a fixed member whitelist with type, charset and range checks,
 * and re-emits only the validated members in a canonical form, so
 * consumers get a bounded, predictable schema no matter what was sent.
 */

#include "private-lib-core.h"

#include <libwebsockets/lws-whois.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

/* max nameserver entries kept in the canonical form */
#define MAX_NS			16
/* max length of one nameserver string (DNS name cap) */
#define MAX_NS_LEN		253
/* canonical dnssec / ds_data lengths, matching struct lws_whois_results */
#define MAX_DNSSEC_LEN		64
#define MAX_DS_LEN		512
/* unix-second dates above this are nonsense */
#define MAX_DATE_S		(1ull << 48)

/* hard cap on the canonical output; emission stops and flags a problem */
#define WJP_CANON_MAX		LWS_WHOIS_CANON_MAX

/*
 * lejp paths we are interested in.  Everything else in the input is
 * dropped from the output and flagged via the problems indicator.
 */
static const char * const canon_paths[] = {
	"creation_date",
	"expiry_date",
	"updated_date",
	"nameservers[]",
	"dnssec",
	"ds_data",
};

enum canon_paths_idx {
	CPI_CREATION,
	CPI_EXPIRY,
	CPI_UPDATED,
	CPI_NS,
	CPI_DNSSEC,
	CPI_DSDATA,
};

struct canon {
	/* validated member values */
	unsigned long long	creation_date, expiry_date, updated_date;
	char			ns[MAX_NS][MAX_NS_LEN + 1];
	char			dnssec[MAX_DNSSEC_LEN + 1];
	char			ds_data[MAX_DS_LEN + 1];

	/* string accumulation across lejp chunks */
	char			acc[MAX_DS_LEN + 8];
	size_t			acc_len;
	unsigned char		acc_bad;

	unsigned int		ns_count;

	/* bit per present canonical member, so absent ones stay absent */
	unsigned char		seen_mask;

	unsigned char		complete;
	unsigned char		problems;
};

/* member presence bits in seen_mask */
#define SEEN_CREATION	1
#define SEEN_EXPIRY	2
#define SEEN_UPDATED	4
#define SEEN_NS		8
#define SEEN_DNSSEC	16
#define SEEN_DSDATA	32

static int
charset_ok(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
		      c == '_' || c == ':'))
			return 0;
	}

	return 1;
}

static int
printable_ok(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (s[i] < 0x20 || s[i] > 0x7e)
			return 0;

	return 1;
}

static void
member_seen(struct canon *c, unsigned char bit)
{
	c->seen_mask |= bit;
}

static signed char
canon_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct canon *c = (struct canon *)ctx->user;
	size_t len = ctx->npos; /* string value length on VAL_STR_* */

	switch (reason) {

	case LEJPCB_COMPLETE:
		c->complete = 1;
		break;

	case LEJPCB_VAL_STR_START:
		c->acc_len = 0;
		c->acc_bad = 0;
		break;

	case LEJPCB_VAL_STR_CHUNK:
	case LEJPCB_VAL_STR_END:
		/*
		 * Accumulate the (possibly chunked) string; anything that
		 * overflows the widest canonical member is a problem.
		 */
		if (!ctx->path_match) {
			/* a string somewhere we don't map: drop it */
			c->problems = 1;
			break;
		}

		if (c->acc_len + len > MAX_DS_LEN) {
			c->acc_bad = 1;
			if (reason == LEJPCB_VAL_STR_CHUNK)
				break;
		}

		if (reason == LEJPCB_VAL_STR_CHUNK) {
			if (!c->acc_bad) {
				memcpy(c->acc + c->acc_len, ctx->buf, len);
				c->acc_len += len;
			}
			break;
		}

		if (c->acc_bad) {
			c->problems = 1;
			break;
		}
		memcpy(c->acc + c->acc_len, ctx->buf, len);
		c->acc_len += len;
		c->acc[c->acc_len] = '\0';
		len = c->acc_len;

		switch (ctx->path_match - 1) {
		case CPI_CREATION:
		case CPI_EXPIRY:
		case CPI_UPDATED:
			/* dates must be numbers, not strings */
			c->problems = 1;
			break;

		case CPI_NS:
			if (c->ns_count >= MAX_NS) {
				c->problems = 1;
				break;
			}
			if (!len || len > MAX_NS_LEN ||
			    !charset_ok(c->acc, len)) {
				c->problems = 1;
				break;
			}
			memcpy(c->ns[c->ns_count], c->acc, len);
			c->ns[c->ns_count][len] = '\0';
			c->ns_count++;
			member_seen(c, SEEN_NS);
			break;

		case CPI_DNSSEC:
			if (!len || len > MAX_DNSSEC_LEN ||
			    !printable_ok(c->acc, len)) {
				c->problems = 1;
				break;
			}
			memcpy(c->dnssec, c->acc, len);
			c->dnssec[len] = '\0';
			member_seen(c, SEEN_DNSSEC);
			break;

		case CPI_DSDATA:
			if (!len || len > MAX_DS_LEN ||
			    !printable_ok(c->acc, len)) {
				c->problems = 1;
				break;
			}
			memcpy(c->ds_data, c->acc, len);
			c->ds_data[len] = '\0';
			member_seen(c, SEEN_DSDATA);
			break;
		}
		break;

	case LEJPCB_VAL_NUM_INT:
		if (!ctx->path_match) {
			c->problems = 1;
			break;
		}
		switch (ctx->path_match - 1) {
		case CPI_CREATION:
		case CPI_EXPIRY:
		case CPI_UPDATED: {
			char *end = NULL;
			unsigned long long v;

			if (ctx->buf[0] == '-') {
				c->problems = 1;
				break;
			}

			errno = 0;
			v = strtoull(ctx->buf, &end, 10);
			if (errno == ERANGE || !end || *end ||
			    v > MAX_DATE_S) {
				c->problems = 1;
				break;
			}

			switch (ctx->path_match - 1) {
			case CPI_CREATION:
				c->creation_date = v;
				member_seen(c, SEEN_CREATION);
				break;
			case CPI_EXPIRY:
				c->expiry_date = v;
				member_seen(c, SEEN_EXPIRY);
				break;
			default:
				c->updated_date = v;
				member_seen(c, SEEN_UPDATED);
				break;
			}
			break;
		}

		default:
			/* number where a string member belongs */
			c->problems = 1;
			break;
		}
		break;

	case LEJPCB_VAL_NUM_FLOAT:
	case LEJPCB_VAL_TRUE:
	case LEJPCB_VAL_FALSE:
	case LEJPCB_VAL_NULL:
		/* no canonical member has these types */
		c->problems = 1;
		break;
	}

	return 0;
}

struct canon_emit {
	char			*buf;
	size_t			len;
	size_t			truncated;
};

static void
emit(struct canon_emit *e, const char *s, size_t n)
{
	if (e->truncated)
		return;

	if (e->len + n > WJP_CANON_MAX) {
		e->truncated = 1;
		return;
	}

	memcpy(e->buf + e->len, s, n);
	e->len += n;
}

/* emit a canonical string member value, JSON-escaped */
static void
emit_str(struct canon_emit *e, const char *s)
{
	char esc[MAX_DS_LEN * 6 + 8];

	lws_json_purify(esc, s, sizeof(esc), NULL);
	emit(e, "\"", 1);
	emit(e, esc, strlen(esc));
	emit(e, "\"", 1);
}

static void
emit_date(struct canon_emit *e, const char *name, unsigned long long v)
{
	char b[64];
	int n = lws_snprintf(b, sizeof(b), "\"%s\":%llu,", name, v);
	emit(e, b, (size_t)n);
}

int
lws_whois_json_purify(char *out, size_t out_len, const char *in,
		      size_t in_len, int *problems)
{
	struct canon c;
	struct lejp_ctx jctx;
	struct canon_emit e;
	int r;
	size_t i;

	memset(&c, 0, sizeof(c));
	memset(&e, 0, sizeof(e));
	e.buf = out;

	if (problems)
		*problems = 0;

	if (!out || out_len < WJP_CANON_MAX + 1) {
		if (problems)
			*problems = 1;
		return -1;
	}

	lejp_construct(&jctx, canon_lejp_cb, &c, canon_paths,
		       LWS_ARRAY_SIZE(canon_paths));
	/*
	 * Match paths as soon as they are complete: without this, lejp
	 * does not path-match the first item of an array value until after
	 * it has been parsed
	 */
	jctx.flags |= LEJP_FLAG_FEAT_LEADING_WC;
	r = lejp_parse(&jctx, (const uint8_t *)in, (int)in_len);
	lejp_destruct(&jctx);

	if ((r < 0 && r != LEJP_REJECT_UNKNOWN) || !in_len || !c.complete)
		return -1;

	emit(&e, "{", 1);
	if (c.seen_mask & SEEN_CREATION)
		emit_date(&e, "creation_date", c.creation_date);
	if (c.seen_mask & SEEN_EXPIRY)
		emit_date(&e, "expiry_date", c.expiry_date);
	if (c.seen_mask & SEEN_UPDATED)
		emit_date(&e, "updated_date", c.updated_date);
	if (c.seen_mask & SEEN_NS) {
		emit(&e, "\"nameservers\":[", 15);
		for (i = 0; i < (size_t)c.ns_count; i++) {
			if (i)
				emit(&e, ",", 1);
			emit_str(&e, c.ns[i]);
		}
		emit(&e, "],", 2);
	}
	if (c.seen_mask & SEEN_DNSSEC) {
		emit(&e, "\"dnssec\":", 9);
		emit_str(&e, c.dnssec);
		emit(&e, ",", 1);
	}
	if (c.seen_mask & SEEN_DSDATA) {
		emit(&e, "\"ds_data\":", 10);
		emit_str(&e, c.ds_data);
		emit(&e, ",", 1);
	}

	/*
	 * If we ran out of canonical space the partial object is not valid
	 * JSON; fall back to the empty canonical object.
	 */
	if (e.truncated) {
		out[0] = '{';
		out[1] = '}';
		out[2] = '\0';
		e.len = 2;
		c.problems = 1;
	} else {
		/*
		 * Trim the trailing member comma if we emitted any members;
		 * if nothing was emitted this is just "{}".
		 */
		if (e.len > 1)
			e.len--;

		emit(&e, "}", 1);
		out[e.len] = '\0';
	}

	if (problems)
		*problems = c.problems;

	return (int)e.len;
}
