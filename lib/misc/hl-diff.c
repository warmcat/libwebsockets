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
 * Hostile-input-hardened streaming diff (unified diff / git diff) tokenizer.
 * It only colours diff markup: whole lines (including their newline) are
 * classified by their prefix as added, removed, hunk header or file metadata,
 * and everything else, including context lines, is plain.  It does not
 * attempt to syntax-highlight the source inside the diff.
 *
 * Line classification is by first bytes, with the same restartability rules
 * as the other drivers: marker prefixes are stashed in scratch until the
 * line's class is decidable, classified lines are memoryless on re-delivery,
 * and a decision that needs the next byte holds it unconsumed.
 */

#include "private-lib-core.h"
#include "misc/private-lib-misc-hl.h"
#include <string.h>

enum {
	LDS_PFX,		/* at line start, first bytes undecided */
	LDS_AT1,		/* at an unconsumed '@' that may start "@@" */
	LDS_WORD,		/* accumulating a word to match for metadata */
	LDS_PLUS2,		/* '+' stashed, deciding +++ vs + */
	LDS_PLUS3,		/* '++' stashed, deciding +++ vs ++ */
	LDS_MINUS2,		/* '-' stashed, deciding --- vs - */
	LDS_MINUS3,		/* '--' stashed, deciding --- vs -- */
	LDS_PBOUND,		/* '+++' stashed, boundary byte decides */
	LDS_MBOUND,		/* '---' stashed, boundary byte decides */
	LDS_PLAIN,		/* inside a plain line */
	LDS_ADD,		/* inside an added line */
	LDS_REM,		/* inside a removed line */
	LDS_HUNK,		/* inside a hunk header line */
	LDS_META,		/* inside a file header / metadata line */
};

/* longest metadata word we will try to match */

#define LDS_WORD_MAX			  16

#define d_is_wordc(_c)	(((_c) >= 'a' && (_c) <= 'z') || \
			 ((_c) >= 'A' && (_c) <= 'Z'))

/* lines starting with these words are file header / metadata */

static const char * const meta_words[] = {
	"diff", "index", "old", "new", "deleted", "copy", "rename",
	"similarity", "dissimilarity", "Binary", "GIT",
};

static int
meta_word_match(const uint8_t *w, size_t len)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(meta_words); n++)
		if (len == strlen(meta_words[n]) &&
		    !memcmp(meta_words[n], w, len))
			return 1;

	return 0;
}

static lws_hl_class_t
line_cls(lws_hl_ctx_t *c)
{
	switch (c->state) {
	case LDS_ADD:		return LHL_CLS_DIFF_ADD;
	case LDS_REM:		return LHL_CLS_DIFF_REM;
	case LDS_HUNK:		return LHL_CLS_DIFF_HUNK;
	case LDS_META:		return LHL_CLS_DIFF_META;
	default:		return LHL_CLS_PLAIN;
	}
}

static int
hl_diff_construct(lws_hl_ctx_t *c)
{
	c->state = LDS_PFX;

	return 0;
}

static lws_stateful_ret_t
hl_diff_parse(lws_hl_ctx_t *c, const uint8_t **buf, size_t *len)
{
	size_t olen = *len;
	lws_stateful_ret_t r = LWS_SRET_OK;

	c->chunk = *buf;
	c->pos = c->tok = c->epos = 0;

	while (c->pos < olen) {
		uint8_t b = c->chunk[c->pos];

		switch (c->state) {

		case LDS_PFX:
			switch (b) {
			case '+':
			case '-':
				c->scratch[0] = b;
				c->scratch_pos = 1;
				c->pos++;
				c->epos = c->tok = c->pos;
				c->state = (b == '+') ? LDS_PLUS2 : LDS_MINUS2;
				continue;

			case '\\':	/* "\ No newline at end of file" */
				c->scratch[0] = '\\';
				c->scratch_pos = 1;
				c->pos++;
				c->epos = c->tok = c->pos;
				c->state = LDS_META;
				continue;

			case '@':
				if (c->pos + 1 >= olen) {
					/* "@@" vs '@' needs the next byte */
					c->state = LDS_AT1;
					goto chunk_end;
				}
				if (c->chunk[c->pos + 1] == '@') {
					c->scratch[0] = '@';
					c->scratch[1] = '@';
					c->scratch_pos = 2;
					c->pos += 2;
					c->epos = c->tok = c->pos;
					c->state = LDS_HUNK;
					continue;
				}
				c->state = LDS_PLAIN;	/* '@' unconsumed */
				continue;

			default:
				if (d_is_wordc(b)) {
					c->scratch[0] = b;
					c->scratch_pos = 1;
					c->pos++;
					c->epos = c->tok = c->pos;
					c->state = LDS_WORD;
					continue;
				}
				c->state = LDS_PLAIN;	/* b unconsumed */
				continue;
			}

		case LDS_AT1:
			/* at an unconsumed '@' */
			if (c->pos + 1 >= olen)
				goto chunk_end;	/* still can't decide */
			if (c->chunk[c->pos + 1] == '@') {
				c->scratch[0] = '@';
				c->scratch[1] = '@';
				c->scratch_pos = 2;
				c->pos += 2;
				c->epos = c->tok = c->pos;
				c->state = LDS_HUNK;
				continue;
			}
			c->state = LDS_PLAIN;		/* '@' unconsumed */
			continue;

		case LDS_WORD:
			if (d_is_wordc(b)) {
				if (c->scratch_pos < LDS_WORD_MAX) {
					c->scratch[c->scratch_pos++] = b;
					c->pos++;
					c->epos = c->tok = c->pos;
					continue;
				}
				/* too long to be a metadata word */
				r = hl_emit_scratch(c, LHL_CLS_PLAIN);
				if (r)
					goto bail;
				c->scratch_pos = 0;
				c->state = LDS_PLAIN;
				c->epos = c->tok = c->pos;
				continue;	/* b unconsumed */
			}

			/* the word ended... metadata word, or plain? */

			if (meta_word_match(c->scratch, c->scratch_pos)) {
				c->state = LDS_META;
				/* scratch stays as the line prefix */
			} else {
				r = hl_emit_scratch(c, LHL_CLS_PLAIN);
				if (r)
					goto bail;
				c->scratch_pos = 0;
				c->state = LDS_PLAIN;
				c->epos = c->tok = c->pos;
			}
			continue;		/* b unconsumed */

		case LDS_PLUS2:
		case LDS_PLUS3:
		case LDS_MINUS2:
		case LDS_MINUS3:
			if (b == c->scratch[0] && c->scratch_pos < 3) {
				c->scratch[c->scratch_pos++] = b;
				c->pos++;
				c->epos = c->tok = c->pos;
				if (c->scratch_pos == 3)
					/* +++ / --- only mean file headers
					 * when a boundary byte follows */
					c->state = (c->scratch[0] == '+') ?
							LDS_PBOUND : LDS_MBOUND;
				else
					c->state = (c->scratch[0] == '+') ?
							LDS_PLUS3 : LDS_MINUS3;
				continue;
			}
			/* +/- line content... added or removed */
			c->state = (c->scratch[0] == '+') ?
					LDS_ADD : LDS_REM;
			continue;		/* b unconsumed */

		case LDS_PBOUND:
		case LDS_MBOUND:
			if (b == ' ' || b == '\t' || b == '\n') {
				/* file header line */
				c->state = LDS_META;
				continue;	/* b unconsumed */
			}
			/* removed line containing "--...", or added line
			 * containing "++..." */
			c->state = (c->scratch[0] == '+') ?
					LDS_ADD : LDS_REM;
			continue;		/* b unconsumed */

		case LDS_PLAIN:
		case LDS_ADD:
		case LDS_REM:
		case LDS_HUNK:
		case LDS_META: {
			lws_hl_class_t lc = line_cls(c);

			if (b == '\n') {
				c->pos++;
				r = hl_emit_prefix(c, lc);
				if (r)
					goto bail;
				r = hl_emit_span(c, lc);
				if (r)
					goto bail;
				c->state = LDS_PFX;
				continue;
			}
			c->pos++;	/* line continues */
			continue;
		}

		default:
			c->state = LDS_PFX;
			continue;
		}
	}

chunk_end:
	/* input exhausted... classify what we safely can, keep the state */

	switch (c->state) {
	case LDS_PLAIN:
	case LDS_ADD:
	case LDS_REM:
	case LDS_HUNK:
	case LDS_META: {
		lws_hl_class_t lc = line_cls(c);

		r = hl_emit_prefix(c, lc);
		if (!r)
			r = hl_emit_span(c, lc);
		if (r)
			goto bail;
		break;
	}

	default:
		/* PFX, AT1, WORD, PLUS*, MINUS*: holding bytes in scratch or
		 * unconsumed until the class is decidable */
		break;
	}

bail:
	*buf = c->chunk + c->epos;
	*len = olen - c->epos;

	return r;
}

static lws_stateful_ret_t
hl_diff_finish(lws_hl_ctx_t *c)
{
	static const uint8_t at = '@';
	lws_stateful_ret_t r;

	switch (c->state) {
	case LDS_PLUS2:
	case LDS_PLUS3:		/* unterminated '+' prefix: best guess */
		r = c->cb(c->user, LHL_CLS_DIFF_ADD,
			  c->scratch, c->scratch_pos);
		if (r)
			return r;
		break;

	case LDS_MINUS2:
	case LDS_MINUS3:
		r = c->cb(c->user, LHL_CLS_DIFF_REM,
			  c->scratch, c->scratch_pos);
		if (r)
			return r;
		break;

	case LDS_PBOUND:
	case LDS_MBOUND:	/* "+++"/"---" at eos: best guess a header */
		r = c->cb(c->user, LHL_CLS_DIFF_META,
			  c->scratch, c->scratch_pos);
		if (r)
			return r;
		break;

	case LDS_WORD:		/* unterminated word: metadata or plain */
		r = c->cb(c->user,
			  meta_word_match(c->scratch, c->scratch_pos) ?
				LHL_CLS_DIFF_META : LHL_CLS_PLAIN,
			  c->scratch, c->scratch_pos);
		if (r)
			return r;
		break;

	case LDS_AT1:		/* held decision byte */
		r = c->cb(c->user, LHL_CLS_PLAIN, &at, 1);
		if (r)
			return r;
		break;

	default:
		/* classified lines already emitted everything they had;
		 * an unterminated add or remove line just ends as itself */
		break;
	}

	/* reset for reuse */

	c->state	= LDS_PFX;
	c->scratch_pos	= 0;
	c->pos = c->tok = c->epos = 0;

	return LWS_SRET_OK;
}

static const lws_hl_ops_t lang_diff_ops = {
	.name		= "diff",
	.construct	= hl_diff_construct,
	.parse		= hl_diff_parse,
	.finish		= hl_diff_finish,
};

const lws_hl_ops_t *
lws_hl_lang_diff(void)
{
	return &lang_diff_ops;
}
