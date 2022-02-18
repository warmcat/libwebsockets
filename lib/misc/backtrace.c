/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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

#define _GNU_SOURCE
#include <unwind.h>

static _Unwind_Reason_Code
uwcb(struct _Unwind_Context* uctx, void *arg)
{
	lws_backtrace_info_t *si = (lws_backtrace_info_t *)arg;

	if (si->sp == LWS_ARRAY_SIZE(si->st))
		return _URC_END_OF_STACK;

	if (!si->pre) {
		if (_Unwind_GetIP(uctx))
			si->st[si->sp++] = _Unwind_GetIP(uctx);
	} else
		si->pre--;

	return _URC_NO_REASON;
}

int
lws_backtrace(lws_backtrace_info_t *si, uint8_t pre, uint8_t post)
{
	_Unwind_Reason_Code r;

	si->sp = 0;
	si->pre = pre; /* skip the top couple of backtrace results */
	si->post = post;

	r = _Unwind_Backtrace(uwcb, si);

	if (si->sp > si->post)
		si->sp -= si->post;

	return r != _URC_END_OF_STACK;
}

int
lws_backtrace_compression_stream(lws_backtrace_comp_t *c, uintptr_t v,
				 unsigned int bits)
{
	int nbits = (int)bits;

	while (nbits-- >= 0) {
		if (!(c->pos & 7))
			c->comp[c->pos >> 3] = 0;
		if (v & (1 << nbits))
			c->comp[c->pos >> 3] |= (1 << (7 - (c->pos & 7)));

		c->pos++;

		if ((c->pos >> 3) == c->len) {
			lwsl_err("%s: overrun %u\n", __func__, (unsigned int)c->len);
			return 1;
		}
	}

	return 0;
}

int
lws_backtrace_compression_destream(lws_backtrace_comp_t *c, uintptr_t *_v,
				   unsigned int bits)
{
	int nbits = (int)bits;
	uintptr_t v = 0;

	while (nbits-- >= 0) {
		if ((c->pos >> 3) == c->len)
			return 1;
		if (c->comp[c->pos >> 3] & (1 << (7 - (c->pos & 7))))
			v |= (1 << nbits);
		c->pos++;
	}

	*_v = v;

	return 0;
}

void
lws_backtrace_compression_stream_init(lws_backtrace_comp_t *c,
				      uint8_t *comp, size_t comp_len)
{
	*comp = 0;
	c->pos = 0;
	c->comp = comp;
	c->len = comp_len;
}

int
lws_backtrace_compress_backtrace(lws_backtrace_info_t *si,
				 lws_backtrace_comp_t *c)
{
	int n;

	lws_backtrace_compression_stream(c, si->sp, 5);

	for (n = 0; n < si->sp; n++) { /* go through each in turn */
		uintptr_t delta = (uintptr_t)~0ll, d1;
		char hit = -1, sign, _sign;
		unsigned int q, ql;
		int m;

		if (n > 8)
			m = n - 8;
		else
			m = 0;

		/* we can look for 1 to 8 back */
		for (; m < n; m++) {
			if (si->st[n] > si->st[m]) {
				d1 = si->st[n] - si->st[m];
				_sign = 0;
			} else {
				d1 = si->st[m] - si->st[n];
				_sign = 1;
			}
			if (d1 < delta) {
				delta = d1;
				hit = (char)m;
				sign = _sign;
			}
		}

		q = lws_sigbits(delta);
		ql = lws_sigbits(si->st[n]);

		/*
		 * Bitwise compression:
		 *
		 *   0: zzzzzz             literal (number of bits following)
		 *   1: xxx: y: zzzzzz     delta (base index is (xxx + 1) back
		 *   				from this index)
		 *   			   y == 1 == subtract from base,
		 *   			        zzzzzz delta bits follow
		 */

		if (n && hit && q + 11 < ql + 7) {
			/* shorter to issue a delta froma previous address */
			lws_backtrace_compression_stream(c, 1, 1);
			lws_backtrace_compression_stream(c, (uintptr_t)((n - hit) - 1), 3);
			lws_backtrace_compression_stream(c, (uintptr_t)sign, 1);
			lws_backtrace_compression_stream(c, q, 6);

			if (lws_backtrace_compression_stream(c, delta, q))
				return 1;
		} else {
			/* shorter to issue a literal */
			lws_backtrace_compression_stream(c, 0, 1);
			lws_backtrace_compression_stream(c, ql, 6);

			if (lws_backtrace_compression_stream(c, si->st[n], ql))
				return 1;
		}
	}

	return 0;
}


void
lws_alloc_metadata_gen(size_t size, uint8_t *comp, size_t comp_len,
		       size_t *adj, size_t *cl)
{
	lws_backtrace_info_t si;
	lws_backtrace_comp_t c;
	unsigned int q, ql;

	/**< We need enough here to take the compressed results of however many
	 * callstack Instruction Pointers are allowed, currently 16.
	 */

	lws_backtrace_compression_stream_init(&c, comp, comp_len);

	lws_backtrace(&si, LWS_COMPRESSED_BACKTRACES_SNIP_PRE,
			   LWS_COMPRESSED_BACKTRACES_SNIP_POST);

	/*
	 * We have the result stack, let's compress it
	 *
	 *  - (implicit alignment)
	 *  - call stack len (5b) / call stack literal [ { literal | delta } ... ]
	 *  - bitcount(6), alloc size literal
	 *
	 *  - 2 bytes MSB-first at end on byte boundary, total compressed length
	 *    behind it.
	 *  - lws_dll2_t
	 */

	if (!lws_backtrace_compress_backtrace(&si, &c)) {

		lws_backtrace_compression_stream(&c, lws_sigbits(size), 6);
		lws_backtrace_compression_stream(&c, size, lws_sigbits(size));

		q = (unsigned int)(c.pos >> 3);
		if (c.pos & 7)
			q++;

		if (q + 2 >= c.len) {
			lwsl_err("ovf\n");
			goto nope;
		}

		ql = q + 2;
		c.comp[q++] = (uint8_t)((ql >> 8) & 0xff);
		c.comp[q++] = (uint8_t)(ql & 0xff);

		/*
		 * So we have it compressed along with our additional data.
		 */

		/* pointer-aligned total overallocation */
		*adj = sizeof(lws_dll2_t) +
		       ((q + sizeof(void *) - 1) / sizeof(void *)) *
						   sizeof(void *);
		/* compression buf contents amount */
		*cl = q;
	} else {
		/* put an explicit zero-length prepend for want of anything else */
nope:
		c.comp[0] = 0;
		c.comp[1] = 0;
		c.pos = 16; /* bits */
		*cl = 2;
		*adj = sizeof(lws_dll2_t) + sizeof(void *);
	}
}

/* incoming *v is the true allocation */

void
_lws_alloc_metadata_adjust(lws_dll2_owner_t *active, void **v, size_t adj,
			   uint8_t *comp, unsigned int cl)
{
	/*
	 * Lie about the alloc start in order to conceal our metadata behind
	 * what was asked for.  Incoming v is the real
	 *
	 * True alloc /Comp                    Reported alloc
	 * V                                                V
	 * <compressed>  <16-bit MSB len to comp> lws_dll2_t
	 */

	*v = (void *)((uint8_t *)(*v) + adj - sizeof(lws_dll2_t));
	memcpy((uint8_t *)(*v) - cl, comp, cl);
	lws_dll2_clear((*v));
	lws_dll2_add_tail((*v), active);
	*v = (void *)((uint8_t *)(*v) + sizeof(lws_dll2_t));
}

void
_lws_alloc_metadata_trim(void **ptr, uint8_t **comp, uint16_t *complen)
{
	const uint8_t *p = ((const uint8_t *)*ptr) - sizeof(lws_dll2_t);
	uint16_t cofs = p[-1] | (p[-2] << 8);
	size_t adj = ((sizeof(lws_dll2_t) + cofs + sizeof(void *) - 1) /
					    sizeof(void *)) * sizeof(void *);

	//lwsl_hexdump_notice((uint8_t *)(*ptr) - adj, adj);

	if (comp)
		*comp = (uint8_t *)p - cofs; /* start of compressed area */
	if (complen)
		*complen = cofs - 2;

	lws_dll2_remove((lws_dll2_t *)p);
	*ptr = (void *)((uint8_t *)*ptr - adj); /* original alloc point */
}

/* past_len: after the 16-bit len, pointing at the lws_dll2_t at the end */

int
lws_alloc_metadata_parse(lws_backtrace_info_t *si, const uint8_t *past_len)
{
	const uint8_t *p = (const uint8_t *)past_len;
	uintptr_t n, entries, ri, sign, field;
	uint16_t cofs = p[-1] | (p[-2] << 8);
	lws_backtrace_comp_t c;

	c.comp = (uint8_t *)p - cofs;
	c.pos = 0;
	c.len = cofs - 2;
	si->sp = 0;

	/* 5-bit bitfield contains callstack depth */
	if (lws_backtrace_compression_destream(&c, &entries, 5))
		return 1;

	while (si->sp != entries) {

		if (lws_backtrace_compression_destream(&c, &n, 1))
			return 1;

		if (n) { /* delta: 3-bit refidx, 1-bit delta sign, 6-bit fieldlen, field */

			assert(si->sp); /* first must be literal */

			if (lws_backtrace_compression_destream(&c, &ri, 3))
				return 1;
			if (lws_backtrace_compression_destream(&c, &sign, 1))
				return 1;
			if (lws_backtrace_compression_destream(&c, &n, 6))
				return 1;
			if (lws_backtrace_compression_destream(&c, &field, (unsigned int)n))
				return 1;

			if (si->sp < si->sp - ri - 1 ) {
				lwsl_err("ref err\n");
				return 1;
			}

			if (sign) /* backwards from ref */
				si->st[si->sp] = si->st[si->sp - (ri + 1)] - field;
			else /* forwards from ref */
				si->st[si->sp] = si->st[si->sp - (ri + 1)] + field;

		} else { /* literal */
			if (lws_backtrace_compression_destream(&c, &n, 6))
				return 1;
			if (lws_backtrace_compression_destream(&c, &field, (unsigned int)n))
				return 1;

			si->st[si->sp] = field;
		}

		si->sp++;
	}

	/* 6-bit bitlength, then allocated size */
	if (lws_backtrace_compression_destream(&c, &n, 6))
		return 1;
	if (lws_backtrace_compression_destream(&c, &si->asize, (unsigned int)n))
		return 1;

	return 0;
}

int
lws_alloc_metadata_dump_stdout(struct lws_dll2 *d, void *user)
{
	char ab[192];

	const uint8_t *p = (const uint8_t *)d;
	uint16_t cofs = p[-1] | (p[-2] << 8);

	p = (uint8_t *)p - cofs;

	ab[0] = '~';
	ab[1] = 'm';
	ab[2] = '#';
	lws_b64_encode_string((const char *)p, (int)cofs,
			      ab + 3, (int)sizeof(ab) - 4);

	puts(ab);

	return 0;
}

void
_lws_alloc_metadata_dump(lws_dll2_owner_t *active, lws_dll2_foreach_cb_t cb,
			 void *arg)
{
	lws_dll2_foreach_safe(active, arg, cb);
}

