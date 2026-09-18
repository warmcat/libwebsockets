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
 *
 * Private helpers shared between the highlighting language drivers.  These
 * carry the piece-restartability invariants: epos only advances over pieces
 * the sink accepted, scratch is only cleared after its piece is accepted,
 * and chunk-relative cursors are reset per lws_hl_parse() call.
 */

#if !defined(__LWS_PRIVATE_LIB_MISC_HL_H__)
#define __LWS_PRIVATE_LIB_MISC_HL_H__

/*
 * emit [epos..pos) as cls, in bounded pieces... epos advances only over
 * pieces the sink accepted, so a deferred piece is retried, not lost or
 * duplicated
 */

static inline lws_stateful_ret_t
hl_emit_span(lws_hl_ctx_t *c, lws_hl_class_t cls)
{
	while (c->epos < c->pos) {
		size_t take = c->pos - c->epos;
		lws_stateful_ret_t r;

		if (take > LHL_PIECE_MAX)
			take = LHL_PIECE_MAX;

		r = c->cb(c->user, cls, c->chunk + c->epos, take);
		if (r)
			return r;

		c->epos += take;
	}

	c->tok = c->epos;

	return LWS_SRET_OK;
}

/*
 * emit stashed bytes (a token prefix like a quote or directive name, or a
 * straddling identifier piece) as cls... single piece, atomic.  The caller
 * clears scratch_pos only after this returns LWS_SRET_OK.
 */

static inline lws_stateful_ret_t
hl_emit_scratch(lws_hl_ctx_t *c, lws_hl_class_t cls)
{
	return c->cb(c->user, cls, c->scratch, c->scratch_pos);
}

static inline lws_stateful_ret_t
hl_emit_prefix(lws_hl_ctx_t *c, lws_hl_class_t cls)
{
	lws_stateful_ret_t r;

	if (!c->scratch_pos)
		return LWS_SRET_OK;

	r = hl_emit_scratch(c, cls);
	if (r)
		return r;

	c->scratch_pos = 0;

	return LWS_SRET_OK;
}

#endif
