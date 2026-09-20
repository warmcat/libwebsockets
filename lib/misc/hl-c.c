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
 * Hostile-input-hardened streaming C tokenizer
 *
 * Principles:
 *
 *  - it never revises or backtracks over an emitted decision
 *
 *  - O(1) state for any input: identifiers are classified from scratch if
 *    they fit, and flushed as plain identifier pieces once they are too long
 *    to be a keyword
 *
 *  - it is restartable at any byte boundary: content states are memoryless
 *    (their re-entry behaviour is identical to their scanning behaviour) and
 *    decision states hold their byte unconsumed, so deferred token pieces can
 *    be retried without duplication
 *
 *  - guesses for broken input are deterministic: strings and char literals
 *    end at a newline if unterminated, an unterminated block comment at end
 *    of input is a comment, numbers use the pp-number maximal munch rule so
 *    they can never fail
 */

#include "private-lib-core.h"
#include "misc/private-lib-misc-hl.h"
#include <string.h>

/* driver states */

enum {
	LCS_PLAIN,		/* plain run: ws, operators, punctuation */
	LCS_IDENT,		/* identifier in progress */
	LCS_NUM,		/* pp-number in progress */
	LCS_NUM_SIGN,		/* pp-number, last byte was e/E/p/P */
	LCS_STR,		/* inside "..." */
	LCS_STR_ESC,		/* inside string, at '\' with no pair yet */
	LCS_CHR,		/* inside '...' */
	LCS_CHR_ESC,
	LCS_LINE_COM,		/* inside // comment */
	LCS_LINE_COM_BS,	/* inside // comment, at '\' */
	LCS_BLOCK_COM,		/* inside block comment */
	LCS_BLOCK_COM_STAR,	/* inside block comment, saw '*' */
	LCS_SLASH,		/* at '/', comment start not yet decidable */
	LCS_DOT,		/* at '.', number start not yet decidable */
	LCS_PPHASH,		/* in # directive name (held in scratch) */
	LCS_BS,			/* at '\' on a pp line, splice undecided */
	LCS_HEADER,		/* inside <...> after #include */
};

/* driver flags */

#define LHF_BOL				1	/* only ws since line start */
#define LHF_PPLINE			2	/* in a preprocessor line */
#define LHF_PPINC			4	/* pp line is an #include */
#define LHF_IDKNOW			8	/* ident class in tokcls */
#define LHF_PPNAME			16	/* pp directive name started */

/* longest keyword or type name in the tables below */

#define KW_MAXLEN			  16

/* byte classes... explicit ranges, no locale dependency */

#define c_is_id(_c)	((_c) == '_' || ((_c) >= 'a' && (_c) <= 'z') || \
			 ((_c) >= 'A' && (_c) <= 'Z') || (_c) >= 0x80)
#define c_is_idc(_c)	(c_is_id(_c) || ((_c) >= '0' && (_c) <= '9'))
#define c_is_dig(_c)	((_c) >= '0' && (_c) <= '9')
#define c_is_ws(_c)	((_c) == ' ' || (_c) == '\t' || (_c) == '\v' || \
			 (_c) == '\f' || (_c) == '\r')
/* pp-number continuation bytes */
#define c_is_numc(_c)	(c_is_idc(_c) || (_c) == '.' || (_c) == '\'')
#define c_is_exp(_c)	((_c) == 'e' || (_c) == 'E' || (_c) == 'p' || (_c) == 'P')

struct hl_kw {
	const char	*name;
	uint8_t		len;
	uint8_t		cls;
};

#define KW(_s, _c)	{ _s, sizeof(_s) - 1, _c }

static const struct hl_kw kwtable[] = {
	/* keywords */
	KW("auto",			LHL_CLS_KEYWORD),
	KW("break",			LHL_CLS_KEYWORD),
	KW("case",			LHL_CLS_KEYWORD),
	KW("const",			LHL_CLS_KEYWORD),
	KW("continue",			LHL_CLS_KEYWORD),
	KW("default",			LHL_CLS_KEYWORD),
	KW("do",			LHL_CLS_KEYWORD),
	KW("else",			LHL_CLS_KEYWORD),
	KW("enum",			LHL_CLS_KEYWORD),
	KW("extern",			LHL_CLS_KEYWORD),
	KW("false",			LHL_CLS_KEYWORD),
	KW("for",			LHL_CLS_KEYWORD),
	KW("goto",			LHL_CLS_KEYWORD),
	KW("if",				LHL_CLS_KEYWORD),
	KW("inline",			LHL_CLS_KEYWORD),
	KW("nullptr",			LHL_CLS_KEYWORD),
	KW("register",			LHL_CLS_KEYWORD),
	KW("restrict",			LHL_CLS_KEYWORD),
	KW("return",			LHL_CLS_KEYWORD),
	KW("sizeof",			LHL_CLS_KEYWORD),
	KW("static",			LHL_CLS_KEYWORD),
	KW("struct",			LHL_CLS_KEYWORD),
	KW("switch",			LHL_CLS_KEYWORD),
	KW("typedef",			LHL_CLS_KEYWORD),
	KW("true",			LHL_CLS_KEYWORD),
	KW("union",			LHL_CLS_KEYWORD),
	KW("volatile",			LHL_CLS_KEYWORD),
	KW("while",			LHL_CLS_KEYWORD),
	KW("_Alignas",			LHL_CLS_KEYWORD),
	KW("_Alignof",			LHL_CLS_KEYWORD),
	KW("_Atomic",			LHL_CLS_KEYWORD),
	KW("_BitInt",			LHL_CLS_KEYWORD),
	KW("_Bool",			LHL_CLS_TYPE),
	KW("_Complex",			LHL_CLS_KEYWORD),
	KW("_Generic",			LHL_CLS_KEYWORD),
	KW("_Noreturn",			LHL_CLS_KEYWORD),
	KW("_Static_assert",		LHL_CLS_KEYWORD),
	KW("_Thread_local",		LHL_CLS_KEYWORD),
	KW("alignas",			LHL_CLS_KEYWORD),
	KW("alignof",			LHL_CLS_KEYWORD),
	KW("constexpr",			LHL_CLS_KEYWORD),
	KW("static_assert",		LHL_CLS_KEYWORD),
	KW("thread_local",		LHL_CLS_KEYWORD),

	/* types... builtin and common well-known typedefs */
	KW("char",			LHL_CLS_TYPE),
	KW("double",			LHL_CLS_TYPE),
	KW("float",			LHL_CLS_TYPE),
	KW("int",			LHL_CLS_TYPE),
	KW("long",			LHL_CLS_TYPE),
	KW("short",			LHL_CLS_TYPE),
	KW("signed",			LHL_CLS_TYPE),
	KW("unsigned",			LHL_CLS_TYPE),
	KW("void",			LHL_CLS_TYPE),
	KW("bool",			LHL_CLS_TYPE),
	KW("size_t",			LHL_CLS_TYPE),
	KW("ssize_t",			LHL_CLS_TYPE),
	KW("ptrdiff_t",			LHL_CLS_TYPE),
	KW("intptr_t",			LHL_CLS_TYPE),
	KW("uintptr_t",			LHL_CLS_TYPE),
	KW("intmax_t",			LHL_CLS_TYPE),
	KW("uintmax_t",			LHL_CLS_TYPE),
	KW("int8_t",			LHL_CLS_TYPE),
	KW("int16_t",			LHL_CLS_TYPE),
	KW("int32_t",			LHL_CLS_TYPE),
	KW("int64_t",			LHL_CLS_TYPE),
	KW("uint8_t",			LHL_CLS_TYPE),
	KW("uint16_t",			LHL_CLS_TYPE),
	KW("uint32_t",			LHL_CLS_TYPE),
	KW("uint64_t",			LHL_CLS_TYPE),
	KW("off_t",			LHL_CLS_TYPE),
	KW("time_t",			LHL_CLS_TYPE),
};

static uint8_t
kw_match(const uint8_t *name, size_t len)
{
	size_t n;

	if (len > KW_MAXLEN)
		return LHL_CLS_IDENT;

	for (n = 0; n < LWS_ARRAY_SIZE(kwtable); n++)
		if (kwtable[n].len == len &&
		    !memcmp(kwtable[n].name, name, len))
			return kwtable[n].cls;

	return LHL_CLS_IDENT;
}

static int
pp_is_include(const uint8_t *name, size_t len)
{
	return (len == 7 && !memcmp(name, "include", len)) ||
	       (len == 6 && !memcmp(name, "import", len)) ||
	       (len == 13 && !memcmp(name, "include_next", len));
}

/*
 * Restartability.  The scan runs ahead of the sink: state and flags at the
 * cursor describe the byte at pos, but a deferred piece is retried from epos,
 * the emitted watermark.  Two rules keep the retry identical to the first
 * scan:
 *
 *  - every content run is emitted before it can exceed one piece, and only
 *    between units (an escape pair, a "\\\n" splice), so an emission either
 *    moves epos up to pos or leaves it where it was... never part way
 *
 *  - whenever epos catches up to pos, the state and flags at that point are
 *    snapshotted; a deferral restores the snapshot, so the retry starts at
 *    epos exactly as the first scan did (eg, a '#' is not made a directive
 *    by the newline after it that the failed scan already saw)
 */

#define HL_BOUND			  (LHL_PIECE_MAX - 2)

static int
hl_c_construct(lws_hl_ctx_t *c)
{
	c->state	= LCS_PLAIN;
	c->flags	= LHF_BOL;

	return 0;
}

static lws_stateful_ret_t
hl_c_parse(lws_hl_ctx_t *c, const uint8_t **buf, size_t *len)
{
	size_t olen = *len;
	lws_stateful_ret_t r = LWS_SRET_OK;
	uint8_t estate = c->state, eflags = c->flags;

	c->chunk = *buf;
	c->pos = c->tok = c->epos = 0;

	while (c->pos < olen) {
		uint8_t b = c->chunk[c->pos];

		if (c->epos == c->pos) {
			/* everything before this byte was accepted: a
			 * deferred piece resumes here, in this state */
			estate = c->state;
			eflags = c->flags;
		}

		switch (c->state) {

		case LCS_PLAIN:
			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_span(c, LHL_CLS_PLAIN);
				if (r)
					goto bail;
				continue;
			}
			if (b == '\n') {
				c->flags |= LHF_BOL;
				c->flags &= (uint8_t)~(LHF_PPLINE | LHF_PPINC);
				c->pos++;
				continue;
			}
			if (c_is_ws(b)) {
				c->pos++;
				continue;
			}

			/*
			 * Anything that starts a token or holds a decision
			 * byte first emits the plain run before it and ends
			 * the iteration: the next one then starts with epos at
			 * this byte and snapshots the state it is seen in.
			 */
			if (c->pos > c->tok &&
			    ((b == '#' && (c->flags & LHF_BOL)) ||
			     (b == '<' && (c->flags & LHF_PPLINE) &&
					  (c->flags & LHF_PPINC)) ||
			     (b == '\\' && (c->flags & LHF_PPLINE) &&
					   c->pos + 1 >= olen) ||
			     b == '"' || b == '\'' || c_is_idc(b) ||
			     b == '.' || b == '/')) {
				r = hl_emit_span(c, LHL_CLS_PLAIN);
				if (r)
					goto bail;
				continue;
			}

			if (b == '#' && (c->flags & LHF_BOL)) {
				c->scratch[0] = '#';
				c->scratch_pos = 1;
				c->state = LCS_PPHASH;
				c->flags &= (uint8_t)~LHF_BOL;
				c->pos++;
				c->epos = c->tok = c->pos;
				continue;
			}
			c->flags &= (uint8_t)~LHF_BOL;

			if (b == '<' && (c->flags & LHF_PPLINE) &&
			    (c->flags & LHF_PPINC)) {
				c->state = LCS_HEADER;
				c->pos++;
				continue;
			}

			if (b == '\\' && (c->flags & LHF_PPLINE)) {
				if (c->pos + 1 < olen) {
					/* line splice or stray backslash */
					c->pos += (c->chunk[c->pos + 1] == '\n') ? 2 : 1;
					continue;
				}
				/* hold only the backslash (the run before it
				 * was emitted above), so at most one byte is
				 * left unconsumed */
				c->state = LCS_BS;
				goto chunk_end;
			}

			if (b == '"' || b == '\'') {
				/* hold the opening quote in scratch, so a
				 * deferred first piece replays without the
				 * quote looking like a terminator */
				c->scratch[0] = b;
				c->scratch_pos = 1;
				c->state = (b == '"') ? LCS_STR : LCS_CHR;
				c->pos++;
				c->epos = c->tok = c->pos;
				continue;
			}

			if (c_is_dig(b) || c_is_id(b)) {
				c->scratch_pos = 0;
				c->flags &= (uint8_t)~LHF_IDKNOW;
				c->state = c_is_dig(b) ? LCS_NUM : LCS_IDENT;
				c->pos++;
				continue;
			}

			if (b == '.') {
				c->state = LCS_DOT;
				continue;	/* leave '.' unconsumed */
			}

			if (b == '/') {
				c->state = LCS_SLASH;
				continue;	/* leave '/' unconsumed */
			}

			c->pos++;	/* any other plain byte */
			continue;

		case LCS_SLASH:
			/* at a '/': comment only if followed by '/' or '*' */
			if (c->pos + 1 < olen) {
				uint8_t d = c->chunk[c->pos + 1];

				if (d == '/' || d == '*') {
					c->state = (d == '/') ? LCS_LINE_COM
							      : LCS_BLOCK_COM;
					c->pos += 2;
					continue;
				}
				c->state = LCS_PLAIN;
				c->pos++;	/* plain '/' byte */
				continue;
			}
			goto chunk_end;		/* decision needs a byte */

		case LCS_DOT:
			/* at a '.': a number only if followed by a digit */
			if (c->pos + 1 < olen) {
				if (c_is_dig(c->chunk[c->pos + 1])) {
					c->state = LCS_NUM;
					c->pos++;
					continue;
				}
				c->state = LCS_PLAIN;
				c->pos++;	/* plain '.' byte */
				continue;
			}
			goto chunk_end;

		case LCS_BS:
			/* at a '\' on a pp line */
			if (c->pos + 1 < olen) {
				if (c->chunk[c->pos + 1] == '\n')
					c->pos += 2;	/* splice */
				else
					c->pos++;	/* stray backslash */
				c->state = LCS_PLAIN;
				continue;
			}
			goto chunk_end;

		case LCS_STR:
		case LCS_CHR: {
			lws_hl_class_t lc = (c->state == LCS_STR) ?
					LHL_CLS_STRING : LHL_CLS_CHARLIT;

			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_prefix(c, lc);
				if (r)
					goto bail;
				r = hl_emit_span(c, lc);
				if (r)
					goto bail;
				continue;
			}

			if (b == '"' || b == '\'') {
				if ((b == '"') == (c->state == LCS_STR)) {
					c->pos++;
					r = hl_emit_prefix(c, lc);
					if (r)
						goto bail;
					r = hl_emit_span(c, lc);
					if (r)
						goto bail;
					c->state = LCS_PLAIN;
					continue;
				}
				/* mismatched quote: treat as content */
				c->pos++;
				continue;
			}
			if (b == '\\') {
				if (c->pos + 1 < olen) {
					c->pos += 2;	/* escape pair */
					continue;
				}
				c->state = (c->state == LCS_STR) ?
						LCS_STR_ESC : LCS_CHR_ESC;
				goto chunk_end;	/* hold '\' */
			}
			if (b == '\n') {
				/* unterminated literal... best guess ends it */
				r = hl_emit_prefix(c, lc);
				if (r)
					goto bail;
				r = hl_emit_span(c, lc);
				if (r)
					goto bail;
				c->state = LCS_PLAIN;
				continue;	/* reprocess '\n' as ws */
			}
			c->pos++;
			continue;
		}

		case LCS_STR_ESC:
		case LCS_CHR_ESC:
			/* at a '\' whose pair is now available */
			if (c->pos + 1 < olen) {
				c->pos += 2;
				c->state = (c->state == LCS_STR_ESC) ?
						LCS_STR : LCS_CHR;
				continue;
			}
			goto chunk_end;

		case LCS_LINE_COM:
			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_span(c, LHL_CLS_COMMENT);
				if (r)
					goto bail;
				continue;
			}
			if (b == '\n') {
				r = hl_emit_span(c, LHL_CLS_COMMENT);
				if (r)
					goto bail;
				c->state = LCS_PLAIN;
				continue;	/* '\n' reprocessed as ws */
			}
			if (b == '\\') {
				if (c->pos + 1 >= olen) {
					c->state = LCS_LINE_COM_BS;
					goto chunk_end;	/* hold '\' */
				}
				if (c->chunk[c->pos + 1] == '\n') {
					c->pos += 2;	/* line splice */
					continue;
				}
			}
			c->pos++;
			continue;

		case LCS_LINE_COM_BS:
			/* at a '\' in a line comment */
			if (c->pos + 1 < olen) {
				c->pos += (c->chunk[c->pos + 1] == '\n') ? 2 : 1;
				c->state = LCS_LINE_COM;
				continue;
			}
			goto chunk_end;

		case LCS_BLOCK_COM:
		case LCS_BLOCK_COM_STAR:
			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_span(c, LHL_CLS_COMMENT);
				if (r)
					goto bail;
				continue;
			}
			if (c->state == LCS_BLOCK_COM_STAR) {
				if (b == '/') {
					c->pos++;
					r = hl_emit_span(c, LHL_CLS_COMMENT);
					if (r)
						goto bail;
					c->state = LCS_PLAIN;
					continue;
				}
				if (b != '*')
					c->state = LCS_BLOCK_COM; /* handles *** / */
				c->pos++;
				continue;
			}
			if (b == '*') {
				c->state = LCS_BLOCK_COM_STAR;
				c->pos++;
				continue;
			}
			if (b == '\n')
				c->flags |= LHF_BOL;	/* for a '#' after */
			c->pos++;
			continue;

		case LCS_NUM:
		case LCS_NUM_SIGN:
			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_span(c, LHL_CLS_NUMBER);
				if (r)
					goto bail;
				continue;
			}
			/* pp-number maximal munch */
			if (c_is_numc(b)) {
				c->pos++;
				c->state = c_is_exp(b) ? LCS_NUM_SIGN : LCS_NUM;
				continue;
			}
			if (c->state == LCS_NUM_SIGN &&
			    (b == '+' || b == '-')) {
				c->pos++;
				c->state = LCS_NUM;
				continue;
			}
			r = hl_emit_span(c, LHL_CLS_NUMBER);
			if (r)
				goto bail;
			c->state = LCS_PLAIN;
			continue;	/* b reprocessed */

		case LCS_PPHASH:
			/* the directive name (and any ws before it)
			 * accumulates in scratch, so every input byte is
			 * retained */
			if (c_is_idc(b) ||
			    (!(c->flags & LHF_PPNAME) && c_is_ws(b) &&
			     b != '\n' && b != '\v' && b != '\f')) {
				if (c->scratch_pos >= LHL_SCRATCH_SIZE - 1) {
					/* stupidly long directive lead-in:
					 * stop treating the line specially
					 * beyond marking it a pp line */
					r = hl_emit_scratch(c, LHL_CLS_PREPROC);
					if (r)
						goto bail;
					c->scratch_pos = 0;
					c->flags |= LHF_PPLINE;
					c->flags &= (uint8_t)~(LHF_PPINC |
							       LHF_PPNAME);
					c->state = LCS_PLAIN;
					c->epos = c->tok = c->pos;
					continue;
				}
				if (c_is_idc(b))
					c->flags |= LHF_PPNAME;
				c->scratch[c->scratch_pos++] = b;
				c->pos++;
				c->epos = c->tok = c->pos;
				continue;
			}
			{
				/* directive name complete... b ends it */

				size_t ns = 1, nl;	/* skip '#' */
				int inc;

				while (ns < c->scratch_pos && !c_is_idc(
						c->scratch[ns]))
					ns++;
				nl = c->scratch_pos - ns;
				inc = pp_is_include(c->scratch + ns, nl);

				r = hl_emit_scratch(c, LHL_CLS_PREPROC);
				if (r)
					goto bail;
				c->scratch_pos = 0;
				c->flags |= LHF_PPLINE;
				if (inc)
					c->flags |= LHF_PPINC;
				else
					c->flags &= (uint8_t)~LHF_PPINC;
				c->flags &= (uint8_t)~LHF_PPNAME;
				c->state = LCS_PLAIN;
				c->epos = c->tok = c->pos;
				continue;
			}

		case LCS_HEADER:
			if (c->pos - c->epos >= HL_BOUND) {
				r = hl_emit_span(c, LHL_CLS_PREPROC);
				if (r)
					goto bail;
				continue;
			}
			if (b == '>' || b == '\n') {
				if (b == '>')
					c->pos++;
				r = hl_emit_span(c, LHL_CLS_PREPROC);
				if (r)
					goto bail;
				c->state = LCS_PLAIN;
				continue;	/* '\n' reprocessed as ws */
			}
			c->pos++;
			continue;

		case LCS_IDENT:
			if (c->pos - c->epos >= HL_BOUND) {
				/* longer than any keyword: flush as identifier
				 * pieces, the stashed prefix first */
				c->flags |= LHF_IDKNOW;
				c->tokcls = LHL_CLS_IDENT;
				if (c->scratch_pos) {
					r = hl_emit_scratch(c, LHL_CLS_IDENT);
					if (r)
						goto bail;
					c->scratch_pos = 0;
					/* accepted: the tail resumes as known */
					estate = c->state;
					eflags = c->flags;
				}
				r = hl_emit_span(c, LHL_CLS_IDENT);
				if (r)
					goto bail;
				continue;
			}
			if (c_is_idc(b)) {
				c->pos++;
				continue;
			}

			/* the identifier ended... classify and emit it */

			if (c->scratch_pos) {
				if (c->scratch_pos + (c->pos - c->tok) <
							LHL_SCRATCH_SIZE) {
					/* whole ident fits in scratch */
					memcpy(c->scratch + c->scratch_pos,
					       c->chunk + c->tok,
					       c->pos - c->tok);
					c->scratch_pos = (uint8_t)
							(c->scratch_pos +
							 (c->pos - c->tok));
					c->epos = c->tok = c->pos;
					/* the whole identifier is in scratch
					 * now: a retry resumes at b with it */
					estate = c->state;
					eflags = c->flags;

					if (!(c->flags & LHF_IDKNOW))
						c->tokcls = kw_match(
							c->scratch,
							c->scratch_pos);

					r = hl_emit_scratch(c, c->tokcls);
					if (r)
						goto bail;
					c->scratch_pos = 0;
					c->state = LCS_PLAIN;
					c->flags &= (uint8_t)~LHF_IDKNOW;
					continue;
				}

				/* too long for a keyword... emit the stashed
				 * part, then the chunk part below */

				r = hl_emit_scratch(c, LHL_CLS_IDENT);
				if (r)
					goto bail;
				c->scratch_pos = 0;
				c->flags |= LHF_IDKNOW;
				c->tokcls = LHL_CLS_IDENT;
				/* accepted: the tail resumes as known */
				estate = c->state;
				eflags = c->flags;
			}

			if (!(c->flags & LHF_IDKNOW)) {
				c->tokcls = kw_match(c->chunk + c->tok,
						     c->pos - c->tok);
				if (c->pos - c->tok > LHL_PIECE_MAX)
					/* multi-piece: fix the class so a
					 * deferred later piece replays
					 * without reclassifying a fragment */
					c->flags |= LHF_IDKNOW;
			}
			r = hl_emit_span(c, c->tokcls);
			if (r)
				goto bail;
			c->state = LCS_PLAIN;
			c->flags &= (uint8_t)~LHF_IDKNOW;
			continue;

		default:
			c->state = LCS_PLAIN;
			continue;
		}
	}

chunk_end:
	/* input exhausted (or a held decision byte at the end of it)...
	 * stash or emit what we have and keep the state for next time */

	if (c->epos == c->pos) {
		/* as at the loop top: the loop may not have run again
		 * since epos caught up */
		estate = c->state;
		eflags = c->flags;
	}

	switch (c->state) {
	case LCS_PLAIN:
		/* emit any pending plain run... it continues next chunk if
		 * more input comes */
		r = hl_emit_span(c, LHL_CLS_PLAIN);
		if (r)
			goto bail;
		break;

	case LCS_IDENT:
		/* move the in-chunk part into scratch, flushing ident pieces
		 * if it does not fit */

		while (c->tok < c->pos) {
			size_t take = c->pos - c->tok;
			size_t room = LHL_SCRATCH_SIZE - c->scratch_pos;

			if (!room) {
				r = hl_emit_scratch(c, LHL_CLS_IDENT);
				if (r)
					goto bail;
				c->scratch_pos = 0;
				/* longer than any keyword: the tail that
				 * lands in scratch must not be matched */
				c->flags |= LHF_IDKNOW;
				c->tokcls = LHL_CLS_IDENT;
				continue;
			}
			if (take > room)
				take = room;
			memcpy(c->scratch + c->scratch_pos,
			       c->chunk + c->tok, take);
			c->scratch_pos = (uint8_t)(c->scratch_pos + take);
			c->tok += take;
			/* stashed bytes are consumed: a deferred flush of
			 * the full scratch must not stash them again */
			c->epos = c->tok;
			estate = c->state;
			eflags = c->flags;
		}
		if (c->scratch_pos > KW_MAXLEN) {
			/* can't be a keyword any more */
			c->flags |= LHF_IDKNOW;
			c->tokcls = LHL_CLS_IDENT;
		}
		break;

	case LCS_STR:
	case LCS_STR_ESC:
		r = hl_emit_prefix(c, LHL_CLS_STRING);
		if (!r)
			r = hl_emit_span(c, LHL_CLS_STRING);
		if (r)
			goto bail;
		break;

	case LCS_CHR:
	case LCS_CHR_ESC:
		r = hl_emit_prefix(c, LHL_CLS_CHARLIT);
		if (!r)
			r = hl_emit_span(c, LHL_CLS_CHARLIT);
		if (r)
			goto bail;
		break;

	case LCS_NUM:
	case LCS_NUM_SIGN:
		r = hl_emit_span(c, LHL_CLS_NUMBER);
		if (r)
			goto bail;
		break;

	case LCS_LINE_COM:
	case LCS_LINE_COM_BS:
	case LCS_BLOCK_COM:
	case LCS_BLOCK_COM_STAR:
		r = hl_emit_span(c, LHL_CLS_COMMENT);
		if (r)
			goto bail;
		break;

	case LCS_HEADER:
		r = hl_emit_span(c, LHL_CLS_PREPROC);
		if (r)
			goto bail;
		break;

	default:
		/* SLASH, DOT, BS, PPHASH: nothing pending that can be
		 * emitted (decision bytes are held unconsumed) */
		break;
	}

bail:
	if (r) {
		/* resume at epos as the first scan did */
		c->state = estate;
		c->flags = eflags;
	}

	*buf = c->chunk + c->epos;
	*len = olen - c->epos;

	return r;
}

static lws_stateful_ret_t
hl_c_finish(lws_hl_ctx_t *c)
{
	static const uint8_t slash = '/', dot = '.', bslash = '\\';
	lws_stateful_ret_t r;

	switch (c->state) {
	case LCS_IDENT:
		if (c->scratch_pos) {
			uint8_t cls = (c->flags & LHF_IDKNOW) ? c->tokcls :
					kw_match(c->scratch, c->scratch_pos);

			r = c->cb(c->user, cls, c->scratch, c->scratch_pos);
			if (r)
				return r;
		}
		break;

	case LCS_PPHASH:
		/* unterminated directive name */
		r = c->cb(c->user, LHL_CLS_PREPROC, c->scratch, c->scratch_pos);
		if (r)
			return r;
		break;

	case LCS_SLASH:		/* held decision bytes */
	case LCS_DOT:
	case LCS_BS:
		r = c->cb(c->user, LHL_CLS_PLAIN,
			  c->state == LCS_SLASH ? &slash :
			  c->state == LCS_DOT ? &dot : &bslash, 1);
		if (r)
			return r;
		break;

	case LCS_STR:
	case LCS_STR_ESC:
		r = hl_emit_prefix(c, LHL_CLS_STRING);
		if (r)
			return r;
		if (c->state == LCS_STR_ESC) {
			/* dangling '\' belongs to the string */
			r = c->cb(c->user, LHL_CLS_STRING, &bslash, 1);
			if (r)
				return r;
		}
		break;

	case LCS_CHR:
	case LCS_CHR_ESC:
		r = hl_emit_prefix(c, LHL_CLS_CHARLIT);
		if (r)
			return r;
		if (c->state == LCS_CHR_ESC) {
			r = c->cb(c->user, LHL_CLS_CHARLIT, &bslash, 1);
			if (r)
				return r;
		}
		break;

	case LCS_LINE_COM_BS:
		r = c->cb(c->user, LHL_CLS_COMMENT, &bslash, 1);
		if (r)
			return r;
		break;

	default:
		/* content states already emitted everything they had;
		 * an unterminated block comment just ends as a comment */
		break;
	}

	/* reset for reuse */

	c->state	= LCS_PLAIN;
	c->flags	= LHF_BOL;
	c->scratch_pos	= 0;
	c->pos = c->tok = c->epos = 0;

	return LWS_SRET_OK;
}

static const lws_hl_ops_t lang_c_ops = {
	.name		= "c",
	.construct	= hl_c_construct,
	.parse		= hl_c_parse,
	.finish		= hl_c_finish,
};

const lws_hl_ops_t *
lws_hl_lang_c(void)
{
	return &lang_c_ops;
}
