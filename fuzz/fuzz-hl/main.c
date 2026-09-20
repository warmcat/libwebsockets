/*
 * lws fuzz target: streaming syntax highlighting tokenizer (lws-hl)
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The whole input is source text.  For each language driver it is run
 * twice:
 *
 *  - reference pass: one fragment, a sink that accepts every piece
 *
 *  - stress pass: fragments of pseudo-random size (including 0 and 1
 *    bytes) with a sink that pseudo-randomly defers pieces, retried as the
 *    API requires
 *
 * Both passes record the token bytes and a class per byte.  The tokenizer
 * is expected to pass every input byte through exactly once with the same
 * classification whatever the fragmentation and deferral pattern, and to
 * hold back at most one decision byte when it returns OK without consuming
 * everything (the markdown fence bridge relies on that), so any difference
 * is a bug: the harness abort()s, which libFuzzer reports like a crash.
 *
 * The html markup sink and the escape helper then run once over the same
 * input with a discarding writer, so they see ASan too.
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

struct rec {
	uint8_t		*out;		/* token bytes, in order */
	uint8_t		*cls;		/* class of each byte in out */
	size_t		len;
	size_t		max;		/* == input length */
	uint32_t	rng;
	uint8_t		defer_on;
	uint8_t		deferred;	/* last piece was deferred: accept */
	uint8_t		trace;		/* LWS_FUZZ_TRACE: dump the stress pass */
};

static lws_stateful_ret_t
rec_cb(void *user, lws_hl_class_t cls, const uint8_t *tok, size_t len)
{
	struct rec *r = (struct rec *)user;

	if (cls >= LHL_CLS_COUNT || len > LHL_PIECE_MAX || (!tok && len))
		abort();	/* sink contract broken */

	if (r->defer_on && !r->deferred && !(xs32(&r->rng) & 3)) {
		r->deferred = 1;
		return LWS_SRET_WANT_OUTPUT;
	}
	r->deferred = 0;

	if (r->trace)
		fprintf(stderr, "  piece cls %d len %zu '%.*s'\n", cls, len,
			(int)len, (const char *)tok);

	if (r->len + len > r->max)
		abort();	/* more output than input: duplication */

	memcpy(r->out + r->len, tok, len);
	memset(r->cls + r->len, (int)cls, len);
	r->len += len;

	return LWS_SRET_OK;
}

static size_t
frag_grow(struct rec *r)
{
	uint32_t x = xs32(&r->rng);

	if (!(x & 0xf))
		return 1 + ((x >> 4) % 300);

	return (x >> 4) & 7;	/* 0..7 */
}

static void
feed(const lws_hl_ops_t *ops, const uint8_t *in, size_t len, struct rec *r,
     int stress)
{
	lws_hl_ctx_t ctx;
	const uint8_t *p = in, *end = in + len, *fend = stress ? in : end;
	size_t iters = 0, l, was;
	lws_stateful_ret_t ret;

	r->len		= 0;
	r->defer_on	= (uint8_t)stress;
	r->deferred	= 0;
	r->trace	= (uint8_t)(stress && getenv("LWS_FUZZ_TRACE"));

	if (lws_hl_construct(&ctx, ops, rec_cb, r))
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
			/* zero growth: a zero-length poke, harmless */
			ret = lws_hl_parse(&ctx, &p, &l);
			if (ret)
				abort();
			continue;
		}

		was = l;
		if (r->trace)
			fprintf(stderr, "parse %zu bytes at %zu: '%.*s'\n", l,
				(size_t)(p - in), (int)l, (const char *)p);
		ret = lws_hl_parse(&ctx, &p, &l);
		if (r->trace)
			fprintf(stderr, "  -> ret %d, %zu left\n", (int)ret, l);
		if (ret == LWS_SRET_WANT_OUTPUT)
			continue;	/* retry the same fragment */
		if (ret)
			abort();

		if (l < was)
			continue;	/* progress: keep going on this fragment */

		/* nothing consumed: it is holding a decision byte for the next input */

		if (l > 1)
			abort();	/* contract: at most one held byte */
		if (fend == end)
			break;		/* finish resolves it */
		fend += 1 + frag_grow(r);
		if (fend > end)
			fend = end;
	}

	while ((ret = lws_hl_finish(&ctx)) == LWS_SRET_WANT_OUTPUT)
		if (++iters > 64 * len + 256)
			abort();
	if (ret)
		abort();

	/* every byte through exactly once, in order */

	if (r->len != len || (len && memcmp(r->out, in, len)))
		abort();
}

static lws_stateful_ret_t
discard(void *user, const uint8_t *buf, size_t len)
{
	(void)user;

	if (!buf && len)
		abort();

	return LWS_SRET_OK;
}

static void
html_pass(const lws_hl_ops_t *ops, const uint8_t *in, size_t len)
{
	lws_hl_html_t h;
	lws_hl_ctx_t ctx;
	const uint8_t *p = in;
	size_t l = len;

	if (lws_hl_html_construct(&h, discard, NULL, NULL) ||
	    lws_hl_construct(&ctx, ops, lws_hl_html_token, &h))
		abort();

	while (l) {
		size_t was = l;

		if (lws_hl_parse(&ctx, &p, &l) || l == was)
			break;
	}
	if (lws_hl_finish(&ctx) || lws_hl_html_close(&h))
		abort();
}

static void
run_lang(const lws_hl_ops_t *ops, const uint8_t *in, size_t len,
	 struct rec *ref, struct rec *st, uint32_t seed)
{
	ref->rng = seed;
	feed(ops, in, len, ref, 0);

	st->rng = seed;
	feed(ops, in, len, st, 1);

	/* identical classification whatever the delivery */

	if (len && memcmp(ref->cls, st->cls, len)) {
		if (getenv("LWS_FUZZ_VERBOSE")) {
			size_t n = 0, m;

			while (ref->cls[n] == st->cls[n])
				n++;
			fprintf(stderr, "%s: class differs at %zu: "
				"ref %d vs stress %d, context: '", ops->name,
				n, ref->cls[n], st->cls[n]);
			for (m = n > 24 ? n - 24 : 0; m < len && m < n + 8; m++)
				fputc(in[m] < 32 || in[m] > 126 ? '.' :
				      (int)in[m], stderr);
			fprintf(stderr, "'\n");
		}
		abort();
	}

	html_pass(ops, in, len);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rec ref, st;
	uint32_t seed = 0x811c9dc5u;
	size_t n;

	memset(&ref, 0, sizeof(ref));
	memset(&st, 0, sizeof(st));

	/* fnv-1a of the input picks the fragmentation / deferral pattern */

	for (n = 0; n < size; n++)
		seed = (seed ^ data[n]) * 0x01000193u;

	ref.out = malloc(size + 1);
	ref.cls = malloc(size + 1);
	st.out	= malloc(size + 1);
	st.cls	= malloc(size + 1);
	if (!ref.out || !ref.cls || !st.out || !st.cls)
		abort();
	ref.max = st.max = size;

#if defined(LWS_WITH_HL_LANG_C)
	run_lang(lws_hl_lang_c(), data, size, &ref, &st, seed);
#endif
#if defined(LWS_WITH_HL_LANG_DIFF)
	run_lang(lws_hl_lang_diff(), data, size, &ref, &st, seed);
#endif

	if (lws_html_escape(discard, NULL, data, size))
		abort();

	free(ref.out);
	free(ref.cls);
	free(st.out);
	free(st.cls);

	return 0;
}
