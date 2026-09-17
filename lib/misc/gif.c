/*
 * lws gif
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
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
 * Stateful, linewise GIF decoder for the first frame.  See lws-gif.h for the
 * api contract.  All allocations are fixed-size except the single shared row
 * buffer: the LZW code tables are bounded by the format's 12-bit codes and
 * the colour tables by the 256-entry palette, so heap use does not scale
 * with the compressed or uncompressed size of the image at all.
 *
 * Strings are emitted by walking the prefix chain twice: once for the length
 * (and the root byte, which is what the table add needs), and once writing
 * the bytes backwards into their row columns.  A string that spans a row
 * boundary is not completed with a stack: the residue of a partially emitted
 * string is itself always the string of the chain node the walk stopped at,
 * so the suspension state is a single code plus a progress index.
 */

#include <private-lib-core.h>

enum gif_state {
	GIFS_HDR,		/* streaming match on "GIF8?a" */
	GIFS_LSD,		/* 7-byte logical screen descriptor */
	GIFS_GCT,		/* global colour table payload */
	GIFS_BLOCK,		/* block introducer */
	GIFS_ID,		/* 9-byte image descriptor (first image) */
	GIFS_ID2,		/* 9-byte image descriptor (later image) */
	GIFS_LCT,		/* local colour table payload */
	GIFS_MCS,		/* lzw minimum code size (first image) */
	GIFS_MCS2,		/* lzw minimum code size (later image, skipped) */
	GIFS_SBLEN,		/* sub-block length byte of image data */
	GIFS_LZW,		/* lzw payload bytes of image data */
	GIFS_EXTYPE,		/* extension label byte */
	GIFS_GCE,		/* 6-byte graphic control extension */
	GIFS_SKIPLEN,		/* sub-block length byte of skipped payload */
	GIFS_SKIPDATA,		/* skipped payload bytes */
	GIFS_PREROW,		/* bg rows above the image rectangle */
	GIFS_POSTROW,		/* bg rows below the image rectangle */
	GIFS_DONE,		/* trailer seen */
};

enum {
	GIF_MAX_CODES		= 4096,
	GIF_MIN_ROW_POOL	= 256,
};

/*
 * One row emit buffer shared by every live gif object: the row carries no
 * state between lines (or between objects), so the only thing that matters
 * is capacity, and one allocation serves any number of simultaneously-live
 * images.  Refcounted on the live objects; freed with the last gif.  This
 * is the same discipline as the svg rasterization scratch.
 */

struct gif_scratch {
	lws_dll2_owner_t	live;		/* live gif objects */
	uint8_t			*row;		/* the shared row buffer */
	size_t			row_size;	/* allocated bytes */
	int			refs;		/* live gif objects */
};

static struct gif_scratch gif_scratch;

struct lws_gif {
	/* on gif_scratch.live; largest row this object needed */

	lws_dll2_t		scratch_list;
	size_t			row_need;

	/* the 12-bit lzw code tables, one allocation: prefix then suffix */

	uint16_t		*prefix;
	uint8_t			*suffix;

	uint8_t			gct[256 * 3];
	uint8_t			lct[256 * 3];

	/* logical screen */

	uint16_t		sw, sh;
	uint16_t		bgidx;
	uint16_t		gct_entries;

	/* first image geometry, in logical screen coordinate space */

	uint16_t		ileft, itop, iw, ih;
	uint16_t		lct_entries;

	/* fixed-field accumulation (biggest user is the image descriptor) */

	uint8_t			buf[9];

	/* lzw state */

	uint32_t		acc;		/* lsb-first bit accumulator */
	uint16_t		next_code;
	uint16_t		clear_code, eoi_code;
	uint16_t		sb_left;	/* bytes left in current sub-block */
	uint16_t		count;		/* fixed-field bytes remaining */
	uint8_t			nbits;		/* bits currently in acc */
	uint8_t			code_width;	/* current code size in bits */
	uint8_t			mcs;		/* lzw minimum code size */
	int16_t			prev;		/* -1 = none since clear */
	uint8_t			prev_first;	/* first byte of string(prev) */

	/* string emission suspension: residue of string(pend_code) */

	int32_t			pend_code;	/* -1 = none */
	int32_t			pend_j, pend_L;

	/* row state */

	uint16_t		fx;		/* fill column in current row */
	uint16_t		ycur;		/* current image row being filled */
	uint16_t		ypass, ystep;	/* interlace pass state */
	uint16_t		prerows, postrows; /* bg rows around the frame */
	int			last_row_y;	/* y of the last issued row */
	int			trans_index;	/* -1 = none */

	uint8_t			state;
	uint8_t			sub;		/* header matcher step */

	/* flags */

	char			has_gct, has_lct, lct_active;
	char			interlaced;
	char			image1_started, image1_done;
	char			lzw_ended;	/* eoi code seen */
	char			fatal;
	char			dims;		/* logical screen parsed */
	char			prefill;	/* next row needs bg fill first */
	char			rowvis;		/* current row visible in screen */
	char			post_then_skip;	/* resume sub-block skip after postrows */
};

static void
gif_scratch_ref(void)
{
	gif_scratch.refs++;
}

/*
 * Called with the dying object already removed from the live list: work out
 * the largest row the remaining objects can need and shrink the pool to the
 * smallest doubling step that covers it (only when the pool is more than one
 * step oversized, to avoid churn).  Shrinking is best-effort; on failure the
 * larger buffer just stays.
 */

static void
gif_scratch_unref(void)
{
	size_t need = 0;

	if (!gif_scratch.refs ||
	    --gif_scratch.refs)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&gif_scratch.live)) {
		lws_gif_t *g = lws_container_of(d, lws_gif_t, scratch_list);

		if (g->row_need > need)
			need = g->row_need;
	} lws_end_foreach_dll(d);

	if (gif_scratch.row_size / 2 >= need &&
	    gif_scratch.row_size / 2 >= GIF_MIN_ROW_POOL) {
		uint8_t *n = (uint8_t *)lws_realloc(gif_scratch.row,
				gif_scratch.row_size / 2, __func__);

		if (n) {
			gif_scratch.row = n;
			gif_scratch.row_size /= 2;
		}
	}

	if (!gif_scratch.refs && !gif_scratch.live.count) {

		/* the last gif is gone: the pool itself can go */

		lws_free(gif_scratch.row);
		gif_scratch.row = NULL;
		gif_scratch.row_size = 0;
	}
}

static int
gif_scratch_row_grow(size_t need)
{
	if (need <= gif_scratch.row_size)
		return 0;

	{
		size_t ns = gif_scratch.row_size ?
				gif_scratch.row_size * 2 : GIF_MIN_ROW_POOL;
		uint8_t *n;

		while (ns < need)
			ns *= 2;

		n = (uint8_t *)lws_realloc(gif_scratch.row, ns, __func__);
		if (!n)
			return 1;

		gif_scratch.row = n;
		gif_scratch.row_size = ns;
	}

	return 0;
}

/*
 * Issue a whole row of background: used for the screen rows above and below
 * the image rectangle, so every logical screen row is issued exactly once.
 */

static void
gif_solid_row(lws_gif_t *g, int y)
{
	uint8_t bg = 0;

	if (g->has_gct && g->bgidx < g->gct_entries)
		bg = (uint8_t)g->bgidx;

	memset(gif_scratch.row, bg, g->sw);
	g->last_row_y = y;
}

/*
 * Interlace pass starts and steps: pass 0 rows 0, 8, 16..., pass 1 rows
 * 4, 12..., pass 2 rows 2, 6, 10..., pass 3 rows 1, 3, 5...
 */

static const uint16_t gif_ipass[4][2] = {
	{ 0, 8 }, { 4, 8 }, { 2, 4 }, { 1, 2 },
};

/*
 * Start filling the row at ycur: work out if it is visible in the logical
 * screen, and if it is, prefill the shared row buffer with the background
 * index so parts not covered by the image rectangle come out as background.
 * The image rectangle itself is clipped to the screen by the writers.
 */

static void
gif_row_begin(lws_gif_t *g)
{
	uint32_t sy = (uint32_t)g->itop + g->ycur;

	g->fx = 0;
	g->rowvis = sy < g->sh;

	if (g->rowvis) {
		uint8_t bg = 0;

		if (g->has_gct && g->bgidx < g->gct_entries)
			bg = (uint8_t)g->bgidx;

		memset(gif_scratch.row, bg, g->sw);
	}
}

/*
 * The row at ycur just completed: advance the row counter, interlaced or
 * not.  Returns the completed row's y in logical screen coordinates, or -1
 * if it fell outside the screen (nothing to issue).
 */

static int
gif_row_advance(lws_gif_t *g)
{
	uint32_t sy = (uint32_t)g->itop + g->ycur;
	int ret = sy < g->sh ? (int)sy : -1;

	if (g->interlaced) {
		g->ycur = (uint16_t)(g->ycur + g->ystep);
		while (g->ypass < 4 && g->ycur >= g->ih) {
			g->ypass++;
			if (g->ypass < 4) {
				g->ycur  = gif_ipass[g->ypass][0];
				g->ystep = gif_ipass[g->ypass][1];
			}
		}
	} else
		g->ycur = (uint16_t)(g->ycur + 1);

	return ret;
}

/*
 * Emit len bytes of string(code) at consecutive pixel positions, starting
 * with byte j of the string (0 for a fresh string, pend_j to resume).  The
 * string bytes in order are the prefix chain of code walked towards the
 * root, reversed.  Within one row the bytes occupy consecutive columns, so
 * they are written backwards while walking the chain forwards; a row that
 * completes suspends the walk, the residue being the string of the node the
 * walk stopped at, recorded as (pend_code, pend_j, pend_L).
 *
 * Returns 1 if a visible row became ready (suspend: the row is at
 * gif_scratch.row with its y at g->last_row_y), 0 if the string completed,
 * or a negative LWS_SRET_FATAL-qualified code.
 */

static int
gif_emit_string(lws_gif_t *g, int32_t code, int32_t j, int32_t L)
{
	while (j < L) {
		uint32_t space = (uint32_t)g->iw - g->fx;
		uint32_t seg = (uint32_t)(L - j);
		uint32_t n, col;
		int32_t node, skip;
		int sy;
		char vis = g->rowvis;

		if (g->ycur >= g->ih) {
			/* every row already issued: broken trailing data */

			break;
		}

		if (seg > space)
			seg = space;

		if (!seg) {
			/* fx == iw cannot persist here */

			break;
		}

		/*
		 * Locate the node holding byte j + seg - 1 by skipping the
		 * L - j - seg chain nodes above it
		 */

		node = code;
		for (skip = L - j - (int32_t)seg; skip > 0; skip--)
			node = g->prefix[node];

		/* write the segment bytes at descending screen columns */

		col = (uint32_t)g->ileft + g->fx + seg - 1;
		n = seg;

		while (n--) {
			uint8_t b = node < g->clear_code ?
					(uint8_t)node : g->suffix[node];

			if (vis && col < g->sw)
				gif_scratch.row[col] = b;

			if (n)
				node = g->prefix[node];
			col--;
		}

		g->fx = (uint16_t)(g->fx + seg);
		j += (int32_t)seg;

		if (g->fx < g->iw)
			continue;

		/* the row completed: advance and issue it if visible */

		sy = gif_row_advance(g);

		if (sy >= 0) {
			g->pend_code = code;
			g->pend_j = j;
			g->pend_L = L;
			g->prefill = 1;	/* deferred: the row is still live */
			g->last_row_y = sy;

			return 1;
		}

		/* invisible row: carry on with the next one */

		gif_row_begin(g);
	}

	g->pend_code = -1;

	return 0;
}

/*
 * Process one decompressed code.  Returns 1 if a visible row became ready
 * (suspended mid-string), 0 normally, or a negative FATAL-qualified code.
 */

static int
gif_lzw_code(lws_gif_t *g, uint32_t code)
{
	int32_t node, L = 1;
	uint16_t k;

	if (code == g->clear_code) {
		g->next_code = (uint16_t)(g->eoi_code + 1);
		g->code_width = (uint8_t)(g->mcs + 1);
		g->prev = -1;

		return 0;
	}

	if (code == g->eoi_code) {
		/*
		 * The pixel data is logically over; the rest of the current
		 * sub-block and any further ones are skipped structurally
		 * until the terminator by the caller
		 */

		g->lzw_ended = 1;

		return 0;
	}

	if (code > g->next_code)
		/* references an entry that cannot exist yet */

		return -(LWS_SRET_FATAL + 30);

	if (g->prev < 0) {
		/* the first code after a clear must be a root */

		if (code >= g->clear_code)
			return -(LWS_SRET_FATAL + 31);

		k = (uint16_t)code;
	} else {
		int kw = code == g->next_code;

		if (kw) {
			/*
			 * KwKwK: the code references the entry being defined
			 * by this very code, string(prev) + first(prev).  Add
			 * it first so the chain walk below can descend through
			 * it like any other entry.
			 */

			g->prefix[g->next_code] = (uint16_t)g->prev;
			g->suffix[g->next_code] = g->prev_first;
			g->next_code++;
			if (g->next_code == (1u << g->code_width) &&
			    g->code_width < 12)
				g->code_width++;
		}

		/* chain length of string(code) and its root byte */

		node = (int32_t)code;
		while (node > g->eoi_code) {
			node = g->prefix[node];
			L++;
		}
		k = (uint16_t)node;

		if (!kw && g->next_code < GIF_MAX_CODES) {
			g->prefix[g->next_code] = (uint16_t)g->prev;
			g->suffix[g->next_code] = (uint8_t)k;
			g->next_code++;
			if (g->next_code == (1u << g->code_width) &&
			    g->code_width < 12)
				g->code_width++;
		}
	}

	g->prev = (int16_t)code;
	g->prev_first = (uint8_t)k;

	return gif_emit_string(g, (int32_t)code, 0, L);
}

/*
 * Consume the payload bytes of the first image's data sub-blocks through the
 * lzw state machine until a visible row completes or the input runs out.
 */

static lws_stateful_ret_t
gif_state_lzw(lws_gif_t *g, const uint8_t **buf, size_t *len)
{
	int r;

	if (g->prefill) {
		/* starting the row after the one just issued */

		gif_row_begin(g);
		g->prefill = 0;
	}

	/*
	 * Drain any suspended string first: it needs no input, and it blocks
	 * code extraction
	 */

	while (g->pend_code >= 0) {
		r = gif_emit_string(g, g->pend_code, g->pend_j, g->pend_L);
		if (r < 0)
			return (lws_stateful_ret_t)(-r);
		if (r)
			return LWS_SRET_WANT_OUTPUT;
	}

	for (;;) {
		uint32_t code;

		/*
		 * Feed a byte only when no complete code is waiting: a code
		 * whose string suspends across rows returns with the
		 * accumulator still holding later codes, and feeding more
		 * into it then could push it past 32 bits on images narrow
		 * enough for one string to straddle many rows
		 */

		if ((int)g->nbits < (int)g->code_width) {
			uint8_t b;

			if (!g->sb_left || !*len) {
				if (!g->sb_left)
					g->state = GIFS_SBLEN;

				return LWS_SRET_WANT_INPUT;
			}

			b = *(*buf)++;
			(*len)--;
			g->sb_left--;

			g->acc |= (uint32_t)b << g->nbits;
			g->nbits = (uint8_t)(g->nbits + 8);

			continue;
		}

		code = g->acc & ((1u << g->code_width) - 1);
		g->acc >>= g->code_width;
		g->nbits = (uint8_t)(g->nbits - g->code_width);

		r = gif_lzw_code(g, code);
		if (r < 0)
			return (lws_stateful_ret_t)(-r);
		if (r)
			return LWS_SRET_WANT_OUTPUT;

		if (g->lzw_ended) {
			/* skip the rest of the image data */

			g->image1_done = 1;
			if (g->postrows) {
				g->post_then_skip = 1;
				g->state = GIFS_POSTROW;
			} else
				g->state = GIFS_SKIPDATA;

			return LWS_SRET_WANT_INPUT;
		}
	}
}

/* the same ceiling upng applies to its dimensions */
#define LWS_GIF_MAX_DIM 16384

static lws_stateful_ret_t
gif_got_lsd(lws_gif_t *g, char hold)
{
	g->sw = (uint16_t)(g->buf[0] | (g->buf[1] << 8));
	g->sh = (uint16_t)(g->buf[2] | (g->buf[3] << 8));
	g->bgidx = g->buf[5];

	if (!g->sw || !g->sh)
		return LWS_SRET_FATAL + 20;

	/*
	 * The logical screen sets how many background rows we synthesize
	 * for the area outside the image rectangle, each a memset of a
	 * screen width, from no input at all: a 24-byte file describing a
	 * 65535 x 65535 screen costs 4GB of writes, times the sweep height
	 * when interlaced.  Bound it as upng bounds its dimensions.
	 */
	if (g->sw > LWS_GIF_MAX_DIM || g->sh > LWS_GIF_MAX_DIM)
		return LWS_SRET_FATAL + 21;

	g->gct_entries = (uint16_t)(2u << (g->buf[4] & 7));
	g->has_gct = !!(g->buf[4] & 0x80);
	g->dims = 1;

	if (g->has_gct) {
		g->count = (uint16_t)(g->gct_entries * 3u);
		g->state = GIFS_GCT;
	} else
		g->state = GIFS_BLOCK;

	/*
	 * With hold_at_metadata, stop consuming as soon as the dimensions
	 * are known, so the caller can size layout before committing to the
	 * decode allocations
	 */

	if (hold)
		return LWS_SRET_OK;

	return LWS_SRET_WANT_INPUT;
}

static lws_stateful_ret_t
gif_got_id(lws_gif_t *g)
{
	g->ileft = (uint16_t)(g->buf[0] | (g->buf[1] << 8));
	g->itop  = (uint16_t)(g->buf[2] | (g->buf[3] << 8));
	g->iw    = (uint16_t)(g->buf[4] | (g->buf[5] << 8));
	g->ih    = (uint16_t)(g->buf[6] | (g->buf[7] << 8));

	if (!g->iw || !g->ih)
		return LWS_SRET_FATAL + 21;

	g->interlaced = !!(g->buf[8] & 0x40);
	g->ycur = 0;
	g->ypass = 0;
	g->ystep = gif_ipass[0][1];

	if (!g->image1_done) {
		g->image1_started = 1;
		g->has_lct = !!(g->buf[8] & 0x80);
		if (g->has_lct) {
			g->lct_entries = (uint16_t)(2u << (g->buf[8] & 7));
			g->count = (uint16_t)(g->lct_entries * 3u);
			g->state = GIFS_LCT;
		} else
			g->state = GIFS_MCS;

		return LWS_SRET_WANT_INPUT;
	}

	/* a later image: its colour table and data are skipped */

	if (g->buf[8] & 0x80) {
		g->lct_entries = (uint16_t)(2u << (g->buf[8] & 7));
		g->count = (uint16_t)(g->lct_entries * 3u);
		g->state = GIFS_LCT;
	} else
		g->state = GIFS_MCS2;

	return LWS_SRET_WANT_INPUT;
}

lws_stateful_ret_t
lws_gif_emit_next_line(lws_gif_t *g, const uint8_t **ppix, int *py,
		       const uint8_t **buf, size_t *len, char hold_at_metadata)
{
	if (ppix)
		*ppix = NULL;
	if (py)
		*py = -1;

	if (!g || !ppix || !buf || !len)
		return LWS_SRET_FATAL + 1;

	if (g->fatal)
		return LWS_SRET_FATAL + 2;

	if (g->state == GIFS_DONE)
		return LWS_SRET_OK;

	if (hold_at_metadata && g->dims)
		return LWS_SRET_OK;

	while (*len) {
		lws_stateful_ret_t r;

		switch (g->state) {
		case GIFS_HDR:
			while (*len && g->sub < 6) {
				static const char m[6] = { 'G','I','F','8' };
				uint8_t c = *(*buf)++;

				(*len)--;

				if ((g->sub < 4 && c != (uint8_t)m[g->sub]) ||
				    (g->sub == 4 && c != '7' && c != '9') ||
				    (g->sub == 5 && c != 'a')) {
					g->fatal = 1;
					return LWS_SRET_FATAL + 3;
				}
				g->sub++;
			}
			if (g->sub == 6) {
				g->count = 7;
				g->state = GIFS_LSD;
			}
			break;

		case GIFS_LSD:
			while (*len && g->count) {
				g->buf[7 - g->count--] = *(*buf)++;
				(*len)--;
			}
			if (!g->count) {
				r = gif_got_lsd(g, hold_at_metadata);
				if (r & LWS_SRET_FATAL) {
					g->fatal = 1;
					return r;
				}
				if (hold_at_metadata)
					return LWS_SRET_OK;
			}
			break;

		case GIFS_GCT:
			while (*len && g->count) {
				g->gct[(uint16_t)(g->gct_entries * 3u) -
				       g->count--] = *(*buf)++;
				(*len)--;
			}
			if (!g->count)
				g->state = GIFS_BLOCK;
			break;

		case GIFS_BLOCK: {
			uint8_t c = *(*buf)++;

			(*len)--;

			switch (c) {
			case 0x2c:
				g->count = 9;
				g->state = g->image1_done ? GIFS_ID2 : GIFS_ID;
				break;
			case 0x21:
				g->state = GIFS_EXTYPE;
				break;
			case 0x3b:
				g->state = GIFS_DONE;
				return LWS_SRET_OK;
			default:
				g->fatal = 1;
				return LWS_SRET_FATAL + 4;
			}
			break;
		}

		case GIFS_ID:
		case GIFS_ID2:
			while (*len && g->count) {
				g->buf[9 - g->count--] = *(*buf)++;
				(*len)--;
			}
			if (!g->count) {
				r = gif_got_id(g);
				if (r & LWS_SRET_FATAL) {
					g->fatal = 1;
					return r;
				}
			}
			break;

		case GIFS_LCT:
			if (g->image1_done) {
				/* later image: discard the table */

				size_t take = *len;

				if (take > g->count)
					take = g->count;
				*buf += take;
				*len -= take;
				g->count = (uint16_t)(g->count - (uint16_t)take);

				if (!g->count)
					g->state = GIFS_MCS2;
				break;
			}

			while (*len && g->count) {
				g->lct[(uint16_t)(g->lct_entries * 3u) -
				       g->count--] = *(*buf)++;
				(*len)--;
			}
			if (!g->count) {
				g->lct_active = 1;
				g->state = GIFS_MCS;
			}
			break;

		case GIFS_MCS: {
			uint8_t mcs = *(*buf)++;

			(*len)--;

			if (mcs < 2 || mcs > 8) {
				g->fatal = 1;
				return LWS_SRET_FATAL + 5;
			}

			g->mcs = mcs;
			g->clear_code = (uint16_t)(1u << mcs);
			g->eoi_code = (uint16_t)(g->clear_code + 1);
			g->next_code = (uint16_t)(g->eoi_code + 1);
			g->code_width = (uint8_t)(mcs + 1);
			g->prev = -1;
			g->acc = 0;
			g->nbits = 0;
			g->pend_code = -1;

			/* the decode allocations are committed to now */

			if (!g->prefix) {
				g->prefix = (uint16_t *)lws_malloc(
					GIF_MAX_CODES *
					(sizeof(*g->prefix) + 1), __func__);
				if (!g->prefix) {
					g->fatal = 1;
					return LWS_SRET_FATAL + 6;
				}
				g->suffix = (uint8_t *)&g->prefix[GIF_MAX_CODES];
			}

			g->row_need = g->sw;
			if (gif_scratch_row_grow(g->sw)) {
				g->fatal = 1;
				return LWS_SRET_FATAL + 7;
			}

			/*
			 * Screen rows above and below the image rectangle
			 * are background: issue them so every screen row
			 * comes out exactly once
			 */

			g->prerows = g->itop < g->sh ? g->itop : g->sh;
			g->postrows = (uint32_t)g->itop + g->ih > g->sh ? 0 :
					(uint16_t)(g->sh - g->itop - g->ih);

			gif_row_begin(g);

			g->state = g->prerows ? GIFS_PREROW : GIFS_SBLEN;
			break;
		}

		case GIFS_MCS2:
			/* skip a later image's minimum code size */

			(*buf)++;
			(*len)--;
			g->state = GIFS_SKIPLEN;
			break;

		case GIFS_SBLEN: {
			uint8_t c = *(*buf)++;

			(*len)--;

			if (!c) {
				/* image data over: the terminator block */

				g->image1_done = 1;
				if (g->postrows) {
					g->post_then_skip = 0;
					g->state = GIFS_POSTROW;
				} else
					g->state = GIFS_BLOCK;
				break;
			}

			g->sb_left = c;
			g->state = GIFS_LZW;
			break;
		}

		case GIFS_LZW:
			r = gif_state_lzw(g, buf, len);
			if (r & LWS_SRET_FATAL) {
				g->fatal = 1;
				return r;
			}
			if (r == LWS_SRET_WANT_OUTPUT) {
				*ppix = gif_scratch.row;
				if (py)
					*py = g->last_row_y;
				return r;
			}
			break;

		case GIFS_EXTYPE: {
			uint8_t label = *(*buf)++;

			(*len)--;

			if (label == 0xf9 && !g->image1_started) {
				g->count = 6;
				g->state = GIFS_GCE;
			} else
				g->state = GIFS_SKIPLEN;
			break;
		}

		case GIFS_GCE:
			g->buf[6 - g->count--] = *(*buf)++;
			(*len)--;

			if (g->count)
				break;

			if (g->buf[0] != 4 || g->buf[5] != 0) {
				g->fatal = 1;
				return LWS_SRET_FATAL + 8;
			}

			g->trans_index = (g->buf[1] & 1) ? g->buf[4] : -1;
			g->state = GIFS_BLOCK;
			break;

		case GIFS_SKIPLEN: {
			uint8_t c = *(*buf)++;

			(*len)--;

			if (!c) {
				/* end of the skipped block sequence */

				g->state = GIFS_BLOCK;
				break;
			}

			g->sb_left = c;
			g->state = GIFS_SKIPDATA;
			break;
		}

		case GIFS_PREROW: {
			int y;

			g->prerows--;
			/*
			 * counted from the clipped total, so an image whose
			 * top lies below the screen still issues rows 0..sh-1
			 * rather than rows beyond it
			 */
			y = (int)(g->itop < g->sh ? g->itop : g->sh) -
			    (int)g->prerows - 1;

			gif_solid_row(g, y);
			*ppix = gif_scratch.row;
			if (py)
				*py = y;

			if (!g->prerows)
				g->state = GIFS_SBLEN;

			return LWS_SRET_WANT_OUTPUT;
		}

		case GIFS_POSTROW: {
			int y;

			g->postrows--;
			y = (int)g->sh - (int)g->postrows - 1;

			gif_solid_row(g, y);
			*ppix = gif_scratch.row;
			if (py)
				*py = y;

			if (!g->postrows)
				g->state = g->post_then_skip ?
						GIFS_SKIPDATA : GIFS_BLOCK;

			return LWS_SRET_WANT_OUTPUT;
		}

		case GIFS_SKIPDATA: {
			size_t take = *len;

			if (take > g->sb_left)
				take = g->sb_left;

			*buf += take;
			*len -= take;
			g->sb_left = (uint16_t)(g->sb_left - (uint16_t)take);

			if (!g->sb_left)
				g->state = GIFS_SKIPLEN;
			break;
		}

		default:
			g->fatal = 1;
			return LWS_SRET_FATAL + 9;
		}
	}

	return LWS_SRET_WANT_INPUT;
}

lws_gif_t *
lws_gif_new(void)
{
	lws_gif_t *g = (lws_gif_t *)lws_zalloc(sizeof(*g), __func__);

	if (!g)
		return NULL;

	g->pend_code = -1;
	g->prev = -1;
	g->trans_index = -1;

	gif_scratch_ref();
	lws_dll2_add_tail(&g->scratch_list, &gif_scratch.live);

	return g;
}

void
lws_gif_free(lws_gif_t **gif)
{
	lws_gif_t *g = *gif;

	if (!g)
		return;

	lws_dll2_remove(&g->scratch_list);
	gif_scratch_unref();

	lws_free(g->prefix);
	lws_free(g);

	*gif = NULL;
}

void
lws_gif_restart(lws_gif_t *g)
{
	if (!g)
		return;

	/*
	 * Everything goes back to expecting a header, but allocations stay:
	 * this exists so retained input can be re-decoded (eg, to reach a
	 * different row of an interlaced image) without churning the heap.
	 * The shared pool claim stays live too; it will be re-sized when the
	 * logical screen descriptor reparses.
	 */

	g->state = GIFS_HDR;
	g->sub = 0;
	g->count = 0;
	g->sw = g->sh = 0;
	g->bgidx = 0;
	g->gct_entries = 0;
	g->ileft = g->itop = g->iw = g->ih = 0;
	g->lct_entries = 0;
	g->acc = 0;
	g->nbits = 0;
	g->code_width = 0;
	g->mcs = 0;
	g->next_code = g->clear_code = g->eoi_code = 0;
	g->sb_left = 0;
	g->prev = -1;
	g->prev_first = 0;
	g->pend_code = -1;
	g->pend_j = g->pend_L = 0;
	g->fx = 0;
	g->ycur = g->ypass = g->ystep = 0;
	g->prerows = g->postrows = 0;
	g->post_then_skip = 0;
	g->last_row_y = -1;
	g->trans_index = -1;

	g->has_gct = 0;
	g->has_lct = 0;
	g->lct_active = 0;
	g->interlaced = 0;
	g->image1_started = 0;
	g->image1_done = 0;
	g->lzw_ended = 0;
	g->fatal = 0;
	g->dims = 0;
	g->prefill = 0;
	g->rowvis = 0;
}

unsigned int
lws_gif_get_width(const lws_gif_t *gif)
{
	return gif->sw;
}

unsigned int
lws_gif_get_height(const lws_gif_t *gif)
{
	return gif->sh;
}

char
lws_gif_get_interlaced(const lws_gif_t *gif)
{
	return gif->interlaced;
}

const uint8_t *
lws_gif_get_palette(const lws_gif_t *gif)
{
	if (gif->lct_active)
		return gif->lct;

	if (gif->has_gct)
		return gif->gct;

	return NULL;
}

unsigned int
lws_gif_get_palette_count(const lws_gif_t *gif)
{
	if (gif->lct_active)
		return gif->lct_entries;

	if (gif->has_gct)
		return gif->gct_entries;

	return 0;
}

int
lws_gif_get_transparent_index(const lws_gif_t *gif)
{
	return gif->trans_index;
}

unsigned int
lws_gif_get_bpp(const lws_gif_t *gif)
{
	return 8;
}

unsigned int
lws_gif_get_bitdepth(const lws_gif_t *gif)
{
	return 8;
}

unsigned int
lws_gif_get_components(const lws_gif_t *gif)
{
	return 1;
}

unsigned int
lws_gif_get_pixelsize(const lws_gif_t *gif)
{
	return 8;
}
