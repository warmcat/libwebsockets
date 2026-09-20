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
 * Streaming markdown to structured events renderer
 *
 * Lines are staged into the context so input fragments may have any size.
 * Block structure with one line of lookahead (pipe tables) is held in a side
 * buffer; past the hold cap the held line is reclassified as text, never
 * dropped.
 *
 * Deferral: if the event sink stops an event (for example, the http write
 * side is full), rendering must resume by re-issuing exactly that event.  A
 * transaction (rendering one staged line, flushing a held line, or closing
 * out at end of input) is deterministic, so it is simply re-run from its
 * start; an accept watermark (evdone) counts the events the sink already
 * accepted and they are skipped on the re-run.  For the re-run to reproduce
 * the same decisions, the block state it reads and mutates is a working copy
 * re-initialized from the live state on every entry; the live state is only
 * updated when the transaction completes.  State mutations happen only after
 * the event they belong to was accepted.
 */

#include "private-lib-core.h"
#include <string.h>

/* bounded prefix compare (no NUL-terminated input assumptions) */

static int
md_starts(const char *s, size_t len, const char *pfx)
{
	size_t n = 0;

	while (n < len && pfx[n] && s[n] == pfx[n])
		n++;

	return !pfx[n] && n <= len;
}

static int
md_is_blank(const char *s, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		if (s[n] != ' ' && s[n] != '\t')
			return 0;

	return 1;
}

static int
md_fence_len(const char *s, size_t len, char fc)
{
	size_t n = 0;

	while (n < len && s[n] == fc)
		n++;

	return n >= 3 ? (int)n : 0;
}

static int
md_ind(const char *s, size_t len)
{
	size_t n = 0;

	while (n < len && s[n] == ' ')
		n++;

	return (int)n;
}

static int
md_is_hr(const char *s, size_t len)
{
	size_t n = 0, count = 0;
	char ch = 0;

	while (n < len && (s[n] == ' ' || s[n] == '\t'))
		n++;

	if (n == len)
		return 0;

	ch = s[n];
	if (ch != '-' && ch != '*' && ch != '_')
		return 0;

	for (; n < len; n++) {
		if (s[n] == ch)
			count++;
		else if (s[n] != ' ' && s[n] != '\t')
			return 0;
	}

	return count >= 3;
}

/* table separator line like " | --- | :---: | " */

static int
md_is_table_sep(const char *s, size_t len)
{
	size_t n;
	int dashes = 0, pipes = 0;

	for (n = 0; n < len; n++) {
		if (s[n] == '-')
			dashes++;
		else if (s[n] == '|')
			pipes++;
		else if (s[n] != ' ' && s[n] != '\t' && s[n] != ':')
			return 0;
	}

	return dashes >= 3 && pipes >= 1;
}

/*
 * Event plumbing: md_ev() is the only caller of the sink.  Events already
 * accepted in an earlier pass of this transaction are counted past; the
 * first unaccepted event is re-issued.
 */

static lws_stateful_ret_t
md_ev(lws_md_ctx_t *c, lws_md_ev_t ev, lws_md_el_t el, unsigned int aux,
      const uint8_t *data, size_t len)
{
	lws_stateful_ret_t r;

	if (c->evseq < c->evdone) {
		c->evseq++;
		return LWS_SRET_OK;
	}

	r = c->cb(c->user, ev, el, aux, data, len);
	if (r)
		return r;

	c->evdone = ++c->evseq;

	return LWS_SRET_OK;
}

/* text data in bounded, atomic pieces */

static lws_stateful_ret_t
md_text(lws_md_ctx_t *c, const void *_s, size_t len)
{
	const uint8_t *s = (const uint8_t *)_s;
	lws_stateful_ret_t r;
	size_t o = 0;

	while (o < len) {
		size_t l = len - o;

		if (l > LMD_TEXT_PIECE)
			l = LMD_TEXT_PIECE;

		r = md_ev(c, LMD_EV_TEXT, LMD_EL_NONE, 0, s + o, l);
		if (r)
			return r;

		o += l;
	}

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
md_el(lws_md_ctx_t *c, int begin, lws_md_el_t el, unsigned int aux)
{
	return md_ev(c, begin ? LMD_EV_BEGIN : LMD_EV_END, el, aux, NULL, 0);
}

/* inline stage */

static int
md_autolink_len(const char *s, size_t len)
{
	size_t n;

	if (len < 8)
		return 0;
	if (!md_starts(s, len, "http://") && !md_starts(s, len, "https://"))
		return 0;

	for (n = 0; n < len; n++) {
		char ch = s[n];

		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '<' ||
		    ch == '>' || ch == '"' || ch == ')' || ch == '\'')
			break;
	}

	return (int)n;
}

/*
 * Find the end of a markdown link destination that may be <wrapped> or bare,
 * honoring balanced parens.  Returns end pointer or NULL.
 */

static const char *
md_link_dest(const char *s, size_t len, size_t *out_len)
{
	const char *p = s, *end = s + len;
	int depth = 0;

	*out_len = 0;

	if (p == end)
		return NULL;

	if (*p == '<') {
		const char *e2;

		p++;
		e2 = memchr(p, '>', (size_t)(end - p));
		if (!e2)
			return NULL;
		*out_len = (size_t)(e2 - p);

		return e2 + 1 <= end ? e2 + 1 : NULL;
	}

	while (p < end) {
		char ch = *p;

		if (ch == ' ' || ch == '\t' || ch == '\n')
			break;
		if (ch == '(')
			depth++;
		if (ch == ')') {
			if (!depth)
				break;
			depth--;
		}
		p++;
	}

	*out_len = (size_t)(p - s);

	return p;
}

#define LMD_INLINE_DEPTH			  32

static lws_stateful_ret_t
md_inline(lws_md_ctx_t *c, const char *s, size_t len, int depth);

/*
 * Try to render a link or image at s (just after the '[' or '![').  On
 * success *consumed is set to the bytes through the closing ')'; 0 means
 * there is no well-formed construct here.  A nonzero return defers.
 */

static lws_stateful_ret_t
md_try_linkish(lws_md_ctx_t *c, const char *s, size_t len, int is_image,
	       int depth, size_t *consumed)
{
	const char *close = NULL, *u, *uend;
	size_t n, text_len, ulen, remain;
	lws_stateful_ret_t r;

	*consumed = 0;

	/*
	 * Find the matching unescaped ']', skipping nested bracket pairs so
	 * linked images like [![alt](img)](url) resolve to the outer link
	 * with the image inside its text.
	 */

	{
		int bdepth = 0;

		for (n = 0; n < len; n++) {
			if (s[n] == '\\' && n + 1 < len) {
				n++;
				continue;
			}
			if (s[n] == '[') {
				bdepth++;
				continue;
			}
			if (s[n] == ']') {
				if (!bdepth) {
					close = s + n;
					break;
				}
				bdepth--;
			}
		}
	}

	if (!close)
		return LWS_SRET_OK;

	text_len = (size_t)(close - s);

	if (text_len + 2 >= len || close[1] != '(')
		return LWS_SRET_OK;

	u = close + 2;
	remain = len - (size_t)(u - s);

	uend = md_link_dest(u, remain, &ulen);
	if (!uend || uend == u + remain || *uend != ')')
		return LWS_SRET_OK;

	if (is_image) {
		if ((r = md_el(c, 1, LMD_EL_IMG, 0)) ||
		    (r = md_ev(c, LMD_EV_URL, LMD_EL_NONE, 0,
			       (const uint8_t *)u, ulen)) ||
		    (r = md_ev(c, LMD_EV_ALT, LMD_EL_NONE, 0,
			       (const uint8_t *)s, text_len)) ||
		    (r = md_el(c, 0, LMD_EL_IMG, 0)))
			return r;
	} else {
		/*
		 * A link inside link text would nest <a> elements; inner
		 * links render literally, inner images are fine.
		 */

		if (c->in_link)
			return LWS_SRET_OK;

		if ((r = md_el(c, 1, LMD_EL_A, 0)) ||
		    (r = md_ev(c, LMD_EV_URL, LMD_EL_NONE, 0,
			       (const uint8_t *)u, ulen)))
			return r;

		c->in_link++;
		r = md_inline(c, s, text_len, depth + 1);
		c->in_link--;
		if (r)
			return r;

		if ((r = md_el(c, 0, LMD_EL_A, 0)))
			return r;
	}

	*consumed = (size_t)(uend - s) + 1; /* through ')' */

	return LWS_SRET_OK;
}

static lws_stateful_ret_t
md_inline(lws_md_ctx_t *c, const char *s, size_t len, int depth)
{
	size_t n = 0, k, consumed;
	lws_stateful_ret_t r;

	while (n < len) {
		char ch = s[n];

		if (ch == '\\' && n + 1 < len) {
			/* escaped punctuation renders as itself */

			if ((r = md_text(c, s + n + 1, 1)))
				return r;
			n += 2;
			continue;
		}

		if (ch == '`') {
			const char *f = memchr(s + n + 1, '`', len - n - 1);

			if (f) {
				if ((r = md_el(c, 1, LMD_EL_CS, 0)) ||
				    (r = md_text(c, s + n + 1,
						 (size_t)(f - (s + n + 1)))) ||
				    (r = md_el(c, 0, LMD_EL_CS, 0)))
					return r;
				n = (size_t)(f - s) + 1;
				continue;
			}
		}

		if (ch == '!' && n + 1 < len && s[n + 1] == '[') {
			r = md_try_linkish(c, s + n + 2, len - n - 2, 1,
					   depth, &consumed);
			if (r)
				return r;
			if (consumed) {
				n += consumed + 2;
				continue;
			}
		}

		if (ch == '[') {
			r = md_try_linkish(c, s + n + 1, len - n - 1, 0,
					   depth, &consumed);
			if (r)
				return r;
			if (consumed) {
				n += consumed + 1;
				continue;
			}
		}

		k = (size_t)md_autolink_len(s + n, len - n);
		if (k) {
			if ((r = md_el(c, 1, LMD_EL_A, 0)) ||
			    (r = md_ev(c, LMD_EV_URL, LMD_EL_NONE, 0,
				       (const uint8_t *)(s + n), k)) ||
			    (r = md_text(c, s + n, k)) ||
			    (r = md_el(c, 0, LMD_EL_A, 0)))
				return r;
			n += k;
			continue;
		}

		/*
		 * Nesting beyond the cap renders its markers literally; the
		 * content is never affected.
		 */

		if (depth < LMD_INLINE_DEPTH && ch == '*' && n + 1 < len &&
		    s[n + 1] == '*') {
			for (k = n + 2; k + 1 < len; k++)
				if (s[k] == '*' && s[k + 1] == '*')
					break;

			if (k + 1 < len && k > n + 2) {
				if ((r = md_el(c, 1, LMD_EL_STRONG, 0)))
					return r;
				r = md_inline(c, s + n + 2, k - n - 2,
					      depth + 1);
				if (r)
					return r;
				if ((r = md_el(c, 0, LMD_EL_STRONG, 0)))
					return r;
				n = k + 2;
				continue;
			}
		}

		if (depth < LMD_INLINE_DEPTH && ch == '*' && n + 1 < len) {
			for (k = n + 1; k < len; k++)
				if (s[k] == '*')
					break;

			if (k < len && k > n + 1) {
				if ((r = md_el(c, 1, LMD_EL_EM, 0)))
					return r;
				r = md_inline(c, s + n + 1, k - n - 1,
					      depth + 1);
				if (r)
					return r;
				if ((r = md_el(c, 0, LMD_EL_EM, 0)))
					return r;
				n = k + 1;
				continue;
			}
		}

		/* plain run up to the next byte needing a decision */

		k = n;
		while (k < len) {
			char d = s[k];

			if (d == '\\' || d == '`' || d == '!' || d == '[' ||
			    d == '*')
				break;

			if (d == 'h' && len - k >= 8 &&
			    (md_starts(s + k, len - k, "http://") ||
			     md_starts(s + k, len - k, "https://")))
				break;

			k++;
		}

		if (k == n)
			k = n + 1;	/* an unparsed construct byte renders
					 * literally: always make progress */

		if ((r = md_text(c, s + n, k - n)))
			return r;
		n = k;
	}

	return LWS_SRET_OK;
}

/*
 * Block stage.  During a transaction the block state fields below are a
 * working copy re-initialized from the live state at every entry (see
 * md_run_txn()); mutations land only after their event was accepted.
 */

static lws_stateful_ret_t
md_close_flow(lws_md_ctx_t *c)
{
	lws_stateful_ret_t r;

	if (c->table) {
		if ((r = md_el(c, 0, LMD_EL_TABLE, 0)))
			return r;
		c->table = 0;
	}

	if (c->li) {
		if ((r = md_el(c, 0, LMD_EL_LI, 0)))
			return r;
		c->li = 0;
	}

	if (c->list) {
		if ((r = md_el(c, 0, (lws_md_el_t)c->list, 0)))
			return r;
		c->list = 0;
	}

	if (c->para) {
		if ((r = md_el(c, 0, LMD_EL_P, 0)))
			return r;
		c->para = 0;
	}

	return LWS_SRET_OK;
}

/* one table row: cell splitting on unescaped '|', inline per cell */

static lws_stateful_ret_t
md_emit_row(lws_md_ctx_t *c, const char *s, size_t len, int header)
{
	lws_stateful_ret_t r;
	size_t cs, ce, i;

	if ((r = md_el(c, 1, LMD_EL_TR, 0)))
		return r;

	/* skip a leading pipe */

	cs = 0;
	while (cs < len && s[cs] == ' ')
		cs++;
	if (cs < len && s[cs] == '|')
		cs++;

	/* split the row on unescaped '|' */

	i = cs;
	while (i <= len) {
		if (i > cs && i < len && s[i - 1] == '\\') {
			i++;
			continue;
		}

		if (i == len || s[i] == '|') {
			ce = i;

			/* trim surrounding spaces */

			while (ce > cs &&
			       (s[ce - 1] == ' ' || s[ce - 1] == '\t'))
				ce--;
			while (cs < ce && s[cs] == ' ')
				cs++;

			/*
			 * The cell after a trailing pipe is an artifact of
			 * the split, not content: "| a | b |" has two cells.
			 */

			if (i == len && cs == ce) {
				cs = i + 1;
				goto next;
			}

			if ((r = md_el(c, 1, LMD_EL_CELL, header ? 1u : 0u)))
				return r;
			r = md_inline(c, s + cs, ce - cs, 0);
			if (r)
				return r;
			if ((r = md_el(c, 0, LMD_EL_CELL, header ? 1u : 0u)))
				return r;

			cs = i + 1;
		}

next:
		if (i == len)
			break;
		i++;
	}

	return md_el(c, 0, LMD_EL_TR, 0);
}

static lws_stateful_ret_t
md_para_line(lws_md_ctx_t *c, const char *s, size_t len)
{
	lws_stateful_ret_t r;
	size_t off = 0;

	if (!c->para) {
		if ((r = md_el(c, 1, LMD_EL_P, 0)))
			return r;
		c->para = 1;
	} else
		if ((r = md_text(c, "\n", 1)))
			return r;

	/* strip the leading indent */

	while (off < len && s[off] == ' ')
		off++;

	return md_inline(c, s + off, len - off, 0);
}

static lws_stateful_ret_t
md_icode_line(lws_md_ctx_t *c, const char *s, size_t len)
{
	lws_stateful_ret_t r;
	size_t off;

	if (!c->code_ind) {
		if ((r = md_el(c, 1, LMD_EL_CODE, 0)))
			return r;
		if ((r = md_ev(c, LMD_EV_INFO, LMD_EL_NONE, 0, NULL, 0)))
			return r;
		c->code_ind = 1;
	}

	/* remove the code indent; blank lines contribute just the newline */

	off = len < 4 ? len : 4;

	if ((r = md_text(c, s + off, len - off)) ||
	    (r = md_text(c, "\n", 1)))
		return r;

	return LWS_SRET_OK;
}

/* open a list with its first item; s points at the bullet or digits */

static lws_stateful_ret_t
md_list_open(lws_md_ctx_t *c, const char *s, size_t len, int ordered)
{
	lws_stateful_ret_t r;
	size_t d = ordered ? 0 : 1;	/* the bullet, or the digits + '.' */

	if ((r = md_close_flow(c)))
		return r;

	if ((r = md_el(c, 1, ordered ? LMD_EL_OL : LMD_EL_UL, 0)))
		return r;
	c->list = ordered ? LMD_EL_OL : LMD_EL_UL;

	if ((r = md_el(c, 1, LMD_EL_LI, 0)))
		return r;
	c->li = 1;

	if (ordered) {
		while (d < len && s[d] >= '0' && s[d] <= '9')
			d++;
		d++;	/* the '.' */
	}

	/* plus the space after the marker */

	return md_inline(c, s + d + 1, len - d - 1, 0);
}

static int
md_is_bullet(const char *s, size_t len, int *indent)
{
	int i = md_ind(s, len);

	*indent = i;

	return i < (int)len &&
	       (s[i] == '-' || s[i] == '*' || s[i] == '+') &&
	       i + 1 < (int)len && s[i + 1] == ' ';
}

static int
md_is_ordered(const char *s, size_t len, int *indent)
{
	size_t d;
	int i = md_ind(s, len);

	*indent = i;

	if (i >= (int)len || s[i] < '0' || s[i] > '9')
		return 0;

	d = (size_t)i;
	while (d < len && s[d] >= '0' && s[d] <= '9')
		d++;

	return d < len && s[d] == '.' && d + 1 < len && s[d + 1] == ' ';
}

/* can this line join the open paragraph? */

static int
md_para_cont(const char *s, size_t len)
{
	return !md_is_blank(s, len) &&
	       !md_fence_len(s, len, '`') && !md_fence_len(s, len, '~') &&
	       (!len || s[0] != '#') && (!len || s[0] != '>') &&
	       md_ind(s, len) < 4 && !md_is_hr(s, len);
}

/*
 * Classify a content line (blockquote markers already stripped): paragraph
 * continuation, fence, heading, rule, table hold, lists, indented code,
 * paragraph.
 */

static lws_stateful_ret_t
md_classify(lws_md_ctx_t *c, const char *s, size_t len)
{
	lws_stateful_ret_t r;
	size_t k, io, ie;
	int fl, i, level;

	if (c->para && md_para_cont(s, len))
		return md_para_line(c, s, len);

	if (c->para) {
		if ((r = md_el(c, 0, LMD_EL_P, 0)))
			return r;
		c->para = 0;
	}

	/* a blank line interrupts, and renders nothing itself */

	if (md_is_blank(s, len))
		return LWS_SRET_OK;

	/* fenced code opener */

	fl = md_fence_len(s, len, '`');
	if (!fl)
		fl = md_fence_len(s, len, '~');
	if (fl) {
		if ((r = md_el(c, 1, LMD_EL_CODE, 0)))
			return r;

		/* info string: the rest of the opener, trimmed */

		io = (size_t)fl;
		while (io < len && (s[io] == ' ' || s[io] == '\t'))
			io++;
		ie = len;
		while (ie > io && (s[ie - 1] == ' ' || s[ie - 1] == '\t'))
			ie--;
		k = ie - io;
		if (k > LMD_INFO_MAX - 1)
			k = LMD_INFO_MAX - 1;
		memcpy(c->info, s + io, k);
		c->infolen = (uint32_t)k;

		if ((r = md_ev(c, LMD_EV_INFO, LMD_EL_NONE, 0,
			       (const uint8_t *)c->info, c->infolen)))
			return r;

		c->fence	= 1;
		c->fchr		= (uint8_t)s[0];
		c->flen		= (uint8_t)(fl > 255 ? 255 : fl);
		c->fbol		= 1;
		c->fmatch	= 0;

		return LWS_SRET_OK;
	}

	/* heading */

	if (len && s[0] == '#') {
		level = 0;

		while (level < (int)len && s[level] == '#' && level < 6)
			level++;

		if (level < (int)len && s[level] == ' ') {
			const char *hs = s + level;
			size_t hl = len - (size_t)level;

			while (hl && (hs[0] == ' ' || hs[0] == '\t')) {
				hs++;
				hl--;
			}
			while (hl && hs[hl - 1] == '#')
				hl--;
			while (hl && hs[hl - 1] == ' ')
				hl--;

			if ((r = md_el(c, 1, LMD_EL_H, (unsigned)level)))
				return r;
			r = md_inline(c, hs, hl, 0);
			if (r)
				return r;
			if ((r = md_el(c, 0, LMD_EL_H, (unsigned)level)))
				return r;

			return LWS_SRET_OK;
		}
	}

	/* horizontal rule */

	if (md_is_hr(s, len)) {
		if ((r = md_el(c, 1, LMD_EL_HR, 0)))
			return r;
		return LWS_SRET_OK;
	}

	/* table header candidate: hold for the one-line lookahead */

	if (!c->hold && memchr(s, '|', len) && len <= LMD_HOLD_MAX) {
		memcpy(c->holdb, s, len);
		c->hold = 1;
		c->hlen = (uint32_t)len;

		return LWS_SRET_OK;
	}

	i = md_ind(s, len);

	if (md_is_bullet(s, len, &i))
		return md_list_open(c, s + i, len - (size_t)i, 0);

	if (md_is_ordered(s, len, &i))
		return md_list_open(c, s + i, len - (size_t)i, 1);

	if (i >= 4)
		return md_icode_line(c, s, len);

	return md_para_line(c, s, len);
}

/* process a raw (unstripped) line: blockquote markers then classification */

static lws_stateful_ret_t
md_process_line(lws_md_ctx_t *c, const char *s, size_t len)
{
	lws_stateful_ret_t r;

	if (len && s[0] == '>') {
		size_t o = 0;
		unsigned depth = 0;

		while (o < len && s[o] == '>' && depth < LMD_NEST_MAX) {
			o++;
			depth++;
			if (o < len && s[o] == ' ')
				o++;
		}

		if (depth > c->bq) {
			unsigned m;

			if ((r = md_close_flow(c)))
				return r;

			for (m = c->bq; m < depth; m++) {
				if ((r = md_el(c, 1, LMD_EL_BQ, 0)))
					return r;
				c->bq++;
			}
		} else if (depth < c->bq) {
			if ((r = md_close_flow(c)))
				return r;
			while (c->bq > depth) {
				if ((r = md_el(c, 0, LMD_EL_BQ, 0)))
					return r;
				c->bq--;
			}
		}

		/* a blank rest just closes the inner flow, keeping the quote */

		if (md_is_blank(s + o, len - o))
			return md_close_flow(c);

		return md_classify(c, s + o, len - o);
	}

	/* a line with no markers closes any open quote */

	if (c->bq) {
		if ((r = md_close_flow(c)))
			return r;
		while (c->bq) {
			if ((r = md_el(c, 0, LMD_EL_BQ, 0)))
				return r;
			c->bq--;
		}
	}

	return md_classify(c, s, len);
}

/* tail classification for a held line whose follower was not a separator */

static lws_stateful_ret_t
md_tail(lws_md_ctx_t *c, const char *s, size_t len)
{
	lws_stateful_ret_t r;
	int i;

	if ((r = md_close_flow(c)))
		return r;

	i = md_ind(s, len);

	if (md_is_bullet(s, len, &i))
		return md_list_open(c, s + i, len - (size_t)i, 0);

	if (md_is_ordered(s, len, &i))
		return md_list_open(c, s + i, len - (size_t)i, 1);

	if (i >= 4)
		return md_icode_line(c, s, len);

	return md_para_line(c, s, len);
}

/* the staged line completed: run list / table / code state, then classify */

static lws_stateful_ret_t
md_line_txn(lws_md_ctx_t *c)
{
	const char *s = c->line;
	size_t len = c->llen;
	lws_stateful_ret_t r;
	int ci;

	if (c->table) {
		if (!md_is_blank(s, len) && memchr(s, '|', len))
			return md_emit_row(c, s, len, 0);

		if ((r = md_el(c, 0, LMD_EL_TABLE, 0)))
			return r;
		c->table = 0;
		/* the interrupting line classifies fresh below */
	}

	if (c->list) {
		ci = md_ind(s, len);

		if (md_is_blank(s, len)) {
			if ((r = md_close_flow(c)))
				return r;
			/* the blank line classifies below */
		} else if (ci && c->li) {
			/* more-indented continuation line of the item */

			if ((r = md_text(c, "\n", 1)))
				return r;

			return md_inline(c, s + ci, len - (size_t)ci, 0);
		} else if ((c->list == LMD_EL_UL && md_is_bullet(s, len, &ci)) ||
			   (c->list == LMD_EL_OL && md_is_ordered(s, len, &ci))) {
			int skip = 1;	/* the bullet or digits + '.' */

			if (c->list == LMD_EL_OL) {
				while (s[ci + skip] >= '0' &&
				       s[ci + skip] <= '9')
					skip++;
				skip++;		/* the '.' */
			}

			if (c->li) {
				if ((r = md_el(c, 0, LMD_EL_LI, 0)))
					return r;
				c->li = 0;
			}
			if ((r = md_el(c, 1, LMD_EL_LI, 0)))
				return r;
			c->li = 1;

			return md_inline(c, s + ci + skip + 1,
					 len - (size_t)(ci + skip + 1), 0);
		} else {
			/*
			 * A fresh block (or a list of the other type) ends
			 * the list; the line classifies fresh below.
			 */

			if ((r = md_close_flow(c)))
				return r;
		}

		if (c->list || c->li)
			return LWS_SRET_OK;
	}

	if (c->code_ind) {
		if (md_is_blank(s, len) || md_ind(s, len) >= 4)
			return md_icode_line(c, s, len);

		if ((r = md_el(c, 0, LMD_EL_CODE, 0)))
			return r;
		c->code_ind = 0;
		/* the interrupting line classifies fresh below */
	}

	return md_process_line(c, s, len);
}

/* transaction plumbing */

static void
md_set_txn(lws_md_ctx_t *c, uint8_t t)
{
	c->txn = t;
	c->evdone = 0;
}

static lws_stateful_ret_t
md_txn_body(lws_md_ctx_t *c);

/*
 * Transaction runner.  The block state fields the transaction reads and
 * mutates are re-initialized to the entry state on every call, by restoring
 * the entry copies if the body deferred; a re-run after a deferred event
 * then reproduces the same decisions and hence the same event sequence.
 * When the body completes, the mutated fields stand as the committed state.
 */

static lws_stateful_ret_t
md_run_txn(lws_md_ctx_t *c)
{
	uint8_t para = c->para, list = c->list, li = c->li, table = c->table,
		hold = c->hold, bq = c->bq, code_ind = c->code_ind,
		fin_n = c->fin_n;
	lws_stateful_ret_t r;

	c->evseq = 0;

	r = md_txn_body(c);
	if (r) {
		c->para		= para;
		c->list		= list;
		c->li		= li;
		c->table	= table;
		c->hold		= hold;
		c->bq		= bq;
		c->code_ind	= code_ind;
		c->fin_n	= fin_n;
	}

	return r;
}

static lws_stateful_ret_t
md_txn_body(lws_md_ctx_t *c)
{
	lws_stateful_ret_t r;
	uint8_t next = 0;	/* txn to run after this one completes */

	c->in_link = 0;

	switch (c->txn) {
	case 1:
		r = md_line_txn(c);
		if (r)
			return r;
		c->llen = 0;
		break;

	case 2:	/* flush the held line, then the staged line follows */

		r = md_tail(c, c->holdb, c->hlen);
		if (r)
			return r;
		c->hold = 0;
		c->hlen = 0;
		next = c->llen ? 1 : 0;
		break;

	case 3:	/* end-of-input closers */

		while (c->fin_n) {
			lws_md_el_t el = (lws_md_el_t)c->fin_list[c->fin_n - 1];

			if ((r = md_el(c, 0, el, 0)))
				return r;	/* retried from this closer */
			c->fin_n--;
		}
		c->code_ind = 0;
		c->li = 0;
		c->list = 0;
		c->table = 0;
		c->para = 0;
		c->bq = 0;
		break;

	case 4:	/* the held line is a table header, the staged line its sep */

		if ((r = md_el(c, 1, LMD_EL_TABLE, 0)))
			return r;
		c->table = 1;

		r = md_emit_row(c, c->holdb, c->hlen, 1);
		if (r)
			return r;

		c->hold = 0;
		c->hlen = 0;
		c->llen = 0;
		break;

	case 5:	/* overlong line: give up structure, stream as paragraph */

		if ((r = md_close_flow(c)))
			return r;
		if ((r = md_el(c, 1, LMD_EL_P, 0)))
			return r;
		c->para = 1;
		r = md_text(c, c->line, c->llen);
		if (r)
			return r;
		c->llen = 0;
		c->over = 1;
		break;

	default:
		return LWS_SRET_FATAL;
	}

	/*
	 * The transaction completed: commit the working state, and enter any
	 * follow-on transaction (the staged line after a hold flush) with a
	 * fresh accept watermark.  The caller's loop runs it.
	 */

	c->txn = next;
	c->evdone = 0;

	return LWS_SRET_OK;
}

/*
 * Stream an unstaged run as text pieces, advancing the caller's cursor over
 * each accepted piece: a deferral then resumes at the deferred piece, not at
 * the start of the run (which would re-issue the accepted pieces, since no
 * transaction watermark applies outside a transaction).
 */

static lws_stateful_ret_t
md_stream(lws_md_ctx_t *c, const uint8_t **p, const uint8_t *q)
{
	lws_stateful_ret_t r;

	while (*p < q) {
		size_t l = (size_t)(q - *p);

		if (l > LMD_TEXT_PIECE)
			l = LMD_TEXT_PIECE;

		r = md_ev(c, LMD_EV_TEXT, LMD_EL_NONE, 0, *p, l);
		if (r)
			return r;

		*p += l;
	}

	return LWS_SRET_OK;
}

/* fence body: streamed straight through, not staged */

static lws_stateful_ret_t
md_fence_body(lws_md_ctx_t *c, const uint8_t **buf, size_t *len)
{
	const uint8_t *p = *buf, *end = p + *len;
	lws_stateful_ret_t r;

	while (p < end) {
		uint8_t b = *p;

		if (c->fbol && !c->fclose) {
			if (b == c->fchr) {
				/* stage the run: it may be a closing fence */

				if (c->llen < LMD_LINE_MAX)
					c->line[c->llen++] = (char)b;
				c->fmatch++;
				p++;

				if (c->fmatch >= c->flen) {
					c->fclose = 1;
					c->llen = 0; /* closer, not body */
				}
				continue;
			}

			/* not a closer after all: the staged run is body */

			if (c->llen) {
				r = md_text(c, c->line, c->llen);
				if (r)
					goto bail;
				c->llen = 0;
			}
			c->fmatch = 0;
			c->fbol = 0;
		}

		if (c->fclose) {
			if (b == '\n') {
				if ((r = md_el(c, 0, LMD_EL_CODE, 0)))
					goto bail;
				p++;
				c->fence = 0;
				c->fclose = 0;
				c->fbol = 1;
				c->fmatch = 0;
				goto out;
			}
			if (b == '\r' && p + 1 == end)
				break;	/* decide CR at the next fragment */
			p++;		/* swallow the rest of the closer line */
			continue;
		}

		if (b == '\r') {
			if (p + 1 == end)
				break;	/* decide CR at the next fragment */

			if (p[1] == '\n') {
				if ((r = md_text(c, "\n", 1)))
					goto bail;
				p += 2;
				c->fbol = 1;
				c->fmatch = 0;
				continue;
			}

			if ((r = md_text(c, "\r", 1)))
				goto bail;
			p++;
			continue;
		}

		if (b == '\n') {
			if ((r = md_text(c, "\n", 1)))
				goto bail;
			p++;
			c->fbol = 1;
			c->fmatch = 0;
			continue;
		}

		/* plain body run up to the next decision byte */

		{
			const uint8_t *q = p;

			while (q < end && *q != '\n' && *q != '\r')
				q++;

			r = md_stream(c, &p, q);
			if (r)
				goto bail;
		}
	}

out:
	*buf = p;
	*len = (size_t)(end - p);

	return LWS_SRET_OK;

bail:
	*buf = p;
	*len = (size_t)(end - p);

	return r;
}

/* overlong line body: streamed as paragraph text, structure given up */

static lws_stateful_ret_t
md_over_body(lws_md_ctx_t *c, const uint8_t **buf, size_t *len)
{
	const uint8_t *p = *buf, *end = p + *len;
	lws_stateful_ret_t r;

	while (p < end) {
		const uint8_t *q = p;
		uint8_t b;

		while (q < end && *q != '\n' && *q != '\r')
			q++;

		if (q > p) {
			r = md_stream(c, &p, q);
			if (r)
				goto bail;
		}

		if (p == end)
			break;

		b = *p;

		if (b == '\r' && p + 1 == end)
			break;		/* decide CR at the next fragment */

		if (b == '\r' && p[1] != '\n') {
			if ((r = md_text(c, "\r", 1)))
				goto bail;
			p++;
			continue;
		}

		/* the line end: the next line joins with its own newline */

		p += (b == '\r') ? 2 : 1;
		c->over = 0;
		break;
	}

	*buf = p;
	*len = (size_t)(end - p);

	return LWS_SRET_OK;

bail:
	*buf = p;
	*len = (size_t)(end - p);

	return r;
}

/* stage bytes into the line buffer until the newline */

static lws_stateful_ret_t
md_stage(lws_md_ctx_t *c, const uint8_t **buf, size_t *len)
{
	const uint8_t *p = *buf, *end = p + *len;

	while (p < end) {
		uint8_t b = *p;

		if (b == '\n') {
			p++;

			/* tolerate CRLF */

			if (c->llen && c->line[c->llen - 1] == '\r')
				c->llen--;

			*buf = p;
			*len = (size_t)(end - p);

			if (c->hold) {
				if (md_is_table_sep(c->line, c->llen)) {
					/* the held line is a table header */
					md_set_txn(c, 4);
					return LWS_SRET_OK;
				}
				/* flush the held line, then this one */
				md_set_txn(c, 2);
				return LWS_SRET_OK;
			}

			md_set_txn(c, 1);
			return LWS_SRET_OK;
		}

		if (c->llen < LMD_LINE_MAX) {
			c->line[c->llen++] = (char)b;
			p++;
			continue;
		}

		/*
		 * Past the staging cap the line cannot be classified (nor
		 * held); give up on its structure and stream it as
		 * paragraph text.  Nothing is dropped.
		 */

		*buf = p;
		*len = (size_t)(end - p);
		md_set_txn(c, 5);

		return LWS_SRET_OK;
	}

	*buf = p;
	*len = 0;

	return LWS_SRET_OK;
}

int
lws_md_construct(lws_md_ctx_t *ctx, lws_md_ev_cb cb, void *user)
{
	if (!ctx || !cb)
		return 1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->cb		= cb;
	ctx->user	= user;

	return 0;
}

lws_stateful_ret_t
lws_md_parse(lws_md_ctx_t *c, const uint8_t **buf, size_t *len)
{
	lws_stateful_ret_t r;

	if (!c || !c->cb || !buf || !len)
		return LWS_SRET_FATAL;

	while (1) {
		size_t was;

		while (c->txn) {
			r = md_run_txn(c);
			if (r)
				return r;
		}

		if (!*len)
			return LWS_SRET_OK;

		was = *len;

		if (c->fence)
			r = md_fence_body(c, buf, len);
		else if (c->over)
			r = md_over_body(c, buf, len);
		else
			r = md_stage(c, buf, len);

		if (r)
			return r;

		/* keep going while input is consumed (eg, after a fence
		 * closed); only a held CR legitimately stops progress */

		if (!c->txn && *len == was)
			return LWS_SRET_OK;
	}
}

lws_stateful_ret_t
lws_md_finish(lws_md_ctx_t *c)
{
	lws_stateful_ret_t r;
	lws_md_ev_cb cb;
	void *user;

	if (!c || !c->cb)
		return LWS_SRET_FATAL;

	/*
	 * Close out staged and held input.  Rendering the last line can
	 * itself hold it (a pipe table candidate with no follower), so loop
	 * until nothing new is staged or held.
	 */

	while (c->txn || c->fence || c->over || c->llen || c->hold) {
		while (c->txn) {
			r = md_run_txn(c);
			if (r)
				return r;
		}

		/*
		 * Events issued directly below are made restartable by the
		 * state they change once accepted, not by the transaction
		 * watermark: start both counters fresh, else a watermark left
		 * by accepted fence body events skips them.
		 */

		c->evseq = c->evdone = 0;

		if (c->fence) {
			/* an unterminated run at end of input is body */

			if (c->llen && !c->fclose) {
				r = md_text(c, c->line, c->llen);
				if (r)
					return r;
				c->llen = 0;
			}

			if ((r = md_el(c, 0, LMD_EL_CODE, 0)))
				return r;

			c->fence = 0;
			c->fclose = 0;
			c->fbol = 1;
			c->fmatch = 0;
			continue;
		}

		if (c->over) {
			/* a trailing CR is stripped like a CRLF remnant */

			c->over = 0;
			continue;
		}

		if (c->llen) {
			/* no terminator arrived for the last line */

			if (c->line[c->llen - 1] == '\r')
				c->llen--;

			if (c->hold) {
				if (md_is_table_sep(c->line, c->llen)) {
					/* the held line is a table header */
					md_set_txn(c, 4);
				} else
					md_set_txn(c, 2);
			} else
				md_set_txn(c, 1);
			continue;
		}

		if (c->hold) {
			/* no follower arrived: never a table */

			md_set_txn(c, 2);
			continue;
		}
	}

	/* close out anything left open, innermost first */

	if (c->code_ind || c->li || c->list || c->table || c->para || c->bq) {
		uint8_t *f = c->fin_list;
		unsigned n;

		/* append outermost-first: the list is popped in reverse */

		for (n = 0; n < c->bq; n++)
			*f++ = LMD_EL_BQ;
		if (c->table)
			*f++ = LMD_EL_TABLE;
		if (c->para)
			*f++ = LMD_EL_P;
		if (c->list)
			*f++ = c->list;
		if (c->li)
			*f++ = LMD_EL_LI;
		if (c->code_ind)
			*f++ = LMD_EL_CODE;

		c->fin_n = (uint8_t)(f - c->fin_list);
		md_set_txn(c, 3);

		r = md_run_txn(c);
		if (r)
			return r;
	}

	/* reset for reuse */

	cb = c->cb;
	user = c->user;
	memset(c, 0, sizeof(*c));
	c->cb = cb;
	c->user = user;

	return LWS_SRET_OK;
}
