/*
 * lws fuzz target: streaming markdown to events renderer (lws-md)
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The whole input is markdown.  It is rendered four times:
 *
 *  - reference events: one fragment, an event sink that accepts everything
 *
 *  - stress events: fragments of pseudo-random size (including 0 and 1
 *    bytes) with a sink that pseudo-randomly defers events, retried as the
 *    API requires
 *
 *  - reference html: one fragment through the stock html sink (with the
 *    lws-hl fence bridge when built in) and a writer that accepts all
 *
 *  - stress html: fragmented, with a writer that pseudo-randomly defers
 *
 * The event streams (consecutive data events of one kind merged, since
 * piece boundaries legitimately follow the delivery) and the html outputs
 * must be identical between reference and stress: the driver claims a
 * transaction re-run after deferral re-issues exactly the unaccepted
 * events, and the sink claims each event's markup is emitted atomically.
 * The event sink also checks BEGIN / END nesting and that finish leaves
 * nothing open.  Any violation abort()s, which libFuzzer reports like a
 * crash.
 *
 * The fragmentation / deferral pattern derives from a hash of the input, so
 * every corpus entry is a fixed, reproducible pattern and mutation explores
 * new ones.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	return 0;
}

static uint32_t
xs32(uint32_t *s)
{
	uint32_t x = *s;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*s = x ? x : 0x9e3779b9u;

	return *s;
}

/* growable byte buffer with an amplification cap */

struct gb {
	uint8_t		*p;
	size_t		len;
	size_t		max;
	size_t		cap;		/* abort past this: runaway output */
};

static void
gb_put(struct gb *g, const void *d, size_t l)
{
	if (!l || !d)
		/* spares memcpy(dst, NULL, 0) from !buf && !len callers */
		return;

	if (g->len + l > g->cap)
		abort();

	if (g->len + l > g->max) {
		size_t nm = (g->max + l) * 2 + 64;
		uint8_t *np = realloc(g->p, nm);

		if (!np)
			abort();
		g->p	= np;
		g->max	= nm;
	}

	memcpy(g->p + g->len, d, l);
	g->len += l;
}

#define NEST_MAX	128

struct rec {
	struct gb	out;
	uint32_t	rng;
	uint8_t		defer_on;
	uint8_t		deferred;	/* last event / write deferred: accept */
	uint8_t		last_data;	/* data event kind being merged, or 0 */
	uint8_t		stack[NEST_MAX];
	size_t		depth;
};

static int
want_defer(struct rec *r)
{
	if (r->defer_on && !r->deferred && !(xs32(&r->rng) & 3)) {
		r->deferred = 1;
		return 1;
	}
	r->deferred = 0;

	return 0;
}

static lws_stateful_ret_t
ev_cb(void *user, lws_md_ev_t ev, lws_md_el_t el, unsigned int aux,
      const uint8_t *data, size_t len)
{
	struct rec *r = (struct rec *)user;
	uint8_t hdr[3];

	if (ev < LMD_EV_TEXT || ev > LMD_EV_END || len > LMD_TEXT_PIECE ||
	    (!data && len))
		abort();	/* sink contract broken */

	if (want_defer(r))
		return LWS_SRET_WANT_OUTPUT;

	switch (ev) {
	case LMD_EV_BEGIN:
		if (el <= LMD_EL_NONE || el > LMD_EL_IMG || r->depth >= NEST_MAX)
			abort();
		r->stack[r->depth++] = (uint8_t)el;
		break;
	case LMD_EV_END:
		if (!r->depth || r->stack[r->depth - 1] != (uint8_t)el) {
			if (getenv("LWS_FUZZ_VERBOSE"))
				fprintf(stderr, "END el %d but open top is %d "
					"(depth %zu)\n", el, r->depth ?
					r->stack[r->depth - 1] : -1, r->depth);
			abort();	/* mismatched nesting */
		}
		r->depth--;
		break;
	default:
		if (el != LMD_EL_NONE)
			abort();
		break;
	}

	if (ev == LMD_EV_BEGIN || ev == LMD_EV_END) {
		hdr[0] = (uint8_t)ev;
		hdr[1] = (uint8_t)el;
		hdr[2] = (uint8_t)aux;
		gb_put(&r->out, hdr, 3);
		r->last_data = 0;

		return LWS_SRET_OK;
	}

	/* data: merge with a preceding data event of the same kind */

	if (r->last_data != (uint8_t)ev) {
		hdr[0] = (uint8_t)ev;
		hdr[1] = 0;
		hdr[2] = 0;
		gb_put(&r->out, hdr, 3);
		r->last_data = (uint8_t)ev;
	}
	gb_put(&r->out, data, len);

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
write_cb(void *user, const uint8_t *buf, size_t len)
{
	struct rec *r = (struct rec *)user;

	if (!buf && len)
		abort();

	if (want_defer(r))
		return LWS_SRET_WANT_OUTPUT;

	if (buf)
		gb_put(&r->out, buf, len);

	return LWS_SRET_OK;
}

static size_t
frag_grow(struct rec *r)
{
	uint32_t x = xs32(&r->rng);

	if (!(x & 0xf))
		return 1 + ((x >> 4) % 700);

	return (x >> 4) & 7;	/* 0..7 */
}

/*
 * Drive one render of the input; html nonzero routes events through the
 * stock html sink (its writer is our recorder), else events are recorded
 * directly.
 */

static void
feed(const uint8_t *in, size_t len, struct rec *r, int stress, int html)
{
	static lws_md_ctx_t ctx;		/* ~16KB: keep off the stack */
	static lws_md_html_t hs;
	const uint8_t *p = in, *end = in + len, *fend = stress ? in : end;
	size_t iters = 0, l, was;
	lws_stateful_ret_t ret;

	r->out.len	= 0;
	r->defer_on	= (uint8_t)stress;
	r->deferred	= 0;
	r->last_data	= 0;
	r->depth	= 0;

	if (html) {
		if (lws_md_html_construct(&hs, write_cb, r, NULL, NULL) ||
		    lws_md_construct(&ctx, lws_md_html_event, &hs))
			abort();
	} else
		if (lws_md_construct(&ctx, ev_cb, r))
			abort();

	while (1) {
		if (++iters > 64 * len + 256)
			abort();	/* no progress: stuck */

		l = (size_t)(fend - p);
		if (!l) {
			if (fend == end)
				break;
			fend += frag_grow(r);
			if (fend > end)
				fend = end;
			/* zero growth: a zero-length poke, harmless... it may
			 * still defer, since a pending transaction runs */
			ret = lws_md_parse(&ctx, &p, &l);
			if (ret && ret != LWS_SRET_WANT_OUTPUT)
				abort();
			continue;
		}

		was = l;
		if (stress && getenv("LWS_FUZZ_TRACE"))
			fprintf(stderr, "parse %zu bytes at %zu\n", l,
				(size_t)(p - in));
		ret = lws_md_parse(&ctx, &p, &l);
		if (stress && getenv("LWS_FUZZ_TRACE"))
			fprintf(stderr, "  -> ret %d, %zu left, txn %d fence %d "
				"over %d llen %u\n", (int)ret, l, ctx.txn,
				ctx.fence, ctx.over, (unsigned)ctx.llen);
		if (ret == LWS_SRET_WANT_OUTPUT)
			continue;	/* retry the same fragment */
		if (ret)
			abort();

		if (l < was)
			continue;	/* progress: keep going on this fragment */

		/* nothing consumed: it is holding a CR for the next input */

		if (l > 1)
			abort();	/* contract: at most one held byte */
		if (fend == end)
			break;		/* finish resolves it */
		fend += 1 + frag_grow(r);
		if (fend > end)
			fend = end;
	}

	while ((ret = lws_md_finish(&ctx)) == LWS_SRET_WANT_OUTPUT)
		if (++iters > 64 * len + 256)
			abort();
	if (ret)
		abort();

	if (html) {
		while ((ret = lws_md_html_close(&hs)) == LWS_SRET_WANT_OUTPUT)
			if (++iters > 64 * len + 256)
				abort();
		if (ret)
			abort();
	} else
		if (r->depth) {
			if (getenv("LWS_FUZZ_VERBOSE")) {
				size_t n;

				fprintf(stderr, "finish left open:");
				for (n = 0; n < r->depth; n++)
					fprintf(stderr, " el %d", r->stack[n]);
				fprintf(stderr, "\n");
			}
			abort();	/* finish left structure open */
		}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct rec ref, st;
	uint32_t seed = 0x811c9dc5u;
	size_t n;
	int html;

	/* fnv-1a of the input picks the fragmentation / deferral pattern */

	for (n = 0; n < size; n++)
		seed = (seed ^ data[n]) * 0x01000193u;

	ref.out.cap = st.out.cap = 64 * size + 4096;

	for (html = 0; html < 2; html++) {
		ref.rng = seed;
		feed(data, size, &ref, 0, html);

		st.rng = seed;
		feed(data, size, &st, 1, html);

		if (ref.out.len != st.out.len ||
		    (ref.out.len && memcmp(ref.out.p, st.out.p, ref.out.len))) {
			if (getenv("LWS_FUZZ_VERBOSE")) {
				size_t n = 0;

				while (n < ref.out.len && n < st.out.len &&
				       ref.out.p[n] == st.out.p[n])
					n++;
				fprintf(stderr, "%s: ref %zu vs stress %zu "
					"bytes, first difference at %zu\n",
					html ? "html" : "events", ref.out.len,
					st.out.len, n);
				n = n > 40 ? n - 40 : 0;
				fprintf(stderr, "ref:    '%.*s'\nstress: '%.*s'\n",
					(int)(ref.out.len - n > 120 ? 120 :
						ref.out.len - n), ref.out.p + n,
					(int)(st.out.len - n > 120 ? 120 :
						st.out.len - n), st.out.p + n);
			}
			abort();	/* delivery changed the result */
		}
	}

	return 0;
}
