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
 * Stock html markup sink for the streaming markdown renderer
 *
 * All markup is issued from this file: the driver can only produce structural
 * events and data.  Text and attribute data is entity-escaped here, urls go
 * through a scheme policy (schemes are matched case-insensitively, and only
 * http(s), mailto, fragments and root- or resolver-produced paths survive)
 * and each event's output is emitted as single write callback calls, so a
 * deferred event is retried whole.
 *
 * When lws was built with LWS_WITH_HL, fenced code blocks with a known info
 * string are bridged through the lws-hl tokenizer; the highlighted spans nest
 * inside the <pre><code> the sink issued, under the same strict CSP.
 */

#include "private-lib-core.h"
#include <string.h>
#include <ctype.h>

/* worst-case escaped size of one byte (C0 -> "&#65533;") */
#define MD_ESCAPE_MAX			  8

static size_t
md_esc_byte(char *dest, uint8_t b, int attr)
{
	switch (b) {
	case '<':
		memcpy(dest, "&lt;", 4);
		return 4;
	case '>':
		memcpy(dest, "&gt;", 4);
		return 4;
	case '&':
		memcpy(dest, "&amp;", 5);
		return 5;
	case '"':
		if (attr) {
			memcpy(dest, "&quot;", 6);
			return 6;
		}
		break;
	default:
		if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') {
			memcpy(dest, "&#65533;", 8);
			return 8;
		}
		break;
	}

	*dest = (char)b;

	return 1;
}

/*
 * Escape a bounded data piece (driver data events are capped at
 * LMD_TEXT_PIECE) and emit it as a single write.  Bytes >= 0x80 pass
 * through unmodified; the caller must serve the result as utf-8.
 */

static lws_stateful_ret_t
md_esc_emit(lws_md_html_t *h, const uint8_t *data, size_t len, int attr)
{
	size_t n, o = 0;

	if (!h->wc)
		return LWS_SRET_FATAL;

	for (n = 0; n < len; n++) {
		size_t m = md_esc_byte(h->buf + o, data[n], attr);
		if (o + m > sizeof(h->buf))
			return LWS_SRET_FATAL;
		o += m;
	}

	if (!o)
		return LWS_SRET_OK;

	return h->wc(h->user, (const uint8_t *)h->buf, o);
}

static lws_stateful_ret_t
mdw(lws_md_html_t *h, const char *s)
{
	return h->wc(h->user, (const uint8_t *)s, strlen(s));
}

static int
md_is_url_safe(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '-' ||
	       c == '_' || c == '~' || c == '!' || c == '$' || c == '&' ||
	       c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' ||
	       c == ',' || c == ';' || c == '=' || c == ':' || c == '@' ||
	       c == '%' || c == '#' || c == '?';
}

/*
 * Classify a url's scheme prefix: 0 = no scheme (relative), 1 = a scheme
 * we allow through untouched, -1 = anything else.  A ':' before any '/',
 * '?' or '#' introduces a scheme.
 */

static int
md_scheme_state(const char *u, size_t len)
{
	static const char * const ok[] = { "http", "https", "mailto" };
	char sch[8];
	size_t n, m;

	for (n = 0; n < len; n++) {
		if (u[n] == ':')
			break;
		if (u[n] == '/' || u[n] == '?' || u[n] == '#')
			return 0;	/* no scheme: relative */
	}

	if (n == len)
		return 0;		/* no ':' at all: relative */
	if (!n || n >= sizeof(sch))
		return -1;		/* degenerate or overlong scheme */

	for (m = 0; m < n; m++)
		sch[m] = (char)tolower((int)u[m]);
	sch[n] = '\0';

	for (m = 0; m < LWS_ARRAY_SIZE(ok); m++)
		if (!strncmp(sch, ok[m], sizeof(sch)))
			return 1;

	return -1;
}

/*
 * Compose the url attribute value for the accumulated url datum into h->buf:
 * scheme policy, the caller's resolver for relative urls, percent-encoding
 * of url-unsafe bytes, and attr-escaping of what survives.  Returns the
 * composed length.
 */

static size_t
md_url_policy(lws_md_html_t *h, int is_image, size_t off)
{
	static const char hx[] = "0123456789ABCDEF";
	char res[LMD_URL_MAX];
	const char *emit = h->url;
	size_t emit_len = h->url_len, o = off, n;
	char c;

	if (!emit_len) {
		emit	= "#";
		emit_len = 1;
		goto emit_url;
	}

	switch (md_scheme_state(h->url, h->url_len)) {
	case -1:
		/* javascript:, data:, or anything else unrecognized */

		emit	= "#";
		emit_len = 1;
		goto emit_url;
	case 1:
		/* absolute with an allowed scheme: passes untouched */

		goto emit_url;
	default:
		break;
	}

	/*
	 * Relative (no scheme): the resolver gets a shot at rewriting it to
	 * a site url; if it declines, the url passes through unchanged.
	 */

	if (h->url[0] != '/' && h->url[0] != '#' && h->resolve) {
		size_t rl = h->resolve(h->resolve_user, is_image,
				       h->url, h->url_len,
				       res, sizeof(res) - 1);

		if (rl) {
			res[rl] = '\0';

			if (md_scheme_state(res, rl) >= 0) {
				emit	= res;
				emit_len = rl;
			} else {
				emit	= "#";
				emit_len = 1;
			}
		}
	}

emit_url:
	/* belt and braces: percent-encode anything url-unsafe */

	if (emit_len > sizeof(h->buf) - off - 64)
		emit_len = sizeof(h->buf) - off - 64;

	for (n = 0; n < emit_len && o + 8 < sizeof(h->buf); n++) {
		c = emit[n];

		if (md_is_url_safe(c)) {
			if (c == '&') {
				memcpy(h->buf + o, "&amp;", 5);
				o += 5;
			} else
				h->buf[o++] = c;
		} else {
			h->buf[o++] = '%';
			h->buf[o++] = hx[((uint8_t)c) >> 4];
			h->buf[o++] = hx[((uint8_t)c) & 15];
		}
	}

	return o;
}

#if defined(LWS_WITH_HL)

static int
md_tag_eq(const char *tag, size_t len, const char *want, size_t wlen)
{
	size_t n;

	if (len != wlen)
		return 0;

	for (n = 0; n < len; n++)
		if (tolower((int)tag[n]) != want[n])
			return 0;

	return 1;
}

#define md_tag_is(_s)	md_tag_eq(h->info, h->infolen, _s, sizeof(_s) - 1)

static const lws_hl_ops_t *
md_hl_for_tag(lws_md_html_t *h)
{
#if defined(LWS_WITH_HL_LANG_C)
	if (md_tag_is("c") || md_tag_is("h") || md_tag_is("cpp") ||
	    md_tag_is("cc") || md_tag_is("cxx") || md_tag_is("c++") ||
	    md_tag_is("hpp"))
		return lws_hl_lang_c();
#endif
#if defined(LWS_WITH_HL_LANG_DIFF)
	if (md_tag_is("diff") || md_tag_is("patch"))
		return lws_hl_lang_diff();
#endif

	return NULL;
}

/*
 * Feed an event's code content through the bridged tokenizer.  lws-hl may
 * hold its last input byte for a decision that needs the next byte, so the
 * sink keeps it back and prepends it to the next event; at end of the block
 * lws_hl_finish() resolves it.
 */

static lws_stateful_ret_t
md_hl_feed(lws_md_html_t *h, const uint8_t *data, size_t len)
{
	size_t staged, fed;
	const uint8_t *p;
	size_t l, was_hold = h->hl_hold;
	lws_stateful_ret_t r;

	staged = 0;
	if (h->hl_hold)
		h->buf[staged++] = (char)h->hl_holdb;

	memcpy(h->buf + staged, data + h->hl_off, len - h->hl_off);
	staged += len - h->hl_off;

	p = (const uint8_t *)h->buf;
	l = staged;
	while (l) {
		size_t was = l;

		r = lws_hl_parse(&h->hlctx, &p, &l);
		if (r)
			goto defer;

		if (l == was)
			break;	/* held decision byte... more input decides */
	}

	/* everything fed except possibly one held byte at the end */

	h->hl_hold = (l == 1);
	if (l == 1)
		h->hl_holdb = (uint8_t)h->buf[staged - 1];
	h->hl_off = 0;

	return LWS_SRET_OK;

defer:
	fed = staged - l;	if (fed >= was_hold) {
		h->hl_hold = 0;
		fed -= was_hold;
	} else
		fed = 0;

	h->hl_off += fed;

	return r;
}

static lws_stateful_ret_t
md_hl_end(lws_md_html_t *h)
{
	lws_stateful_ret_t r;

	/*
	 * A held byte is still the tokenizer's: it kept the decision byte
	 * unconsumed in its own state and lws_hl_finish() emits it with its
	 * best-guess class, so emitting it here too would duplicate it.
	 */

	h->hl_hold = 0;

	if (!h->hl_fin) {
		r = lws_hl_finish(&h->hlctx);
		if (r)
			return r;
		h->hl_fin = 1;
	}

	if (!h->hl_closed) {
		r = lws_hl_html_close(&h->hlhtml);
		if (r)
			return r;
		h->hl_closed = 1;
	}

	h->hl_on = 0;

	return LWS_SRET_OK;
}

#endif /* LWS_WITH_HL */

/* the <pre><code> for a fence, and the tokenizer bridge if the tag is known */

static lws_stateful_ret_t
md_code_prologue(lws_md_html_t *h)
{
	lws_stateful_ret_t r;

	if (h->pre_done)
		return LWS_SRET_OK;

#if defined(LWS_WITH_HL)
	if (!h->hl_on) {
		const lws_hl_ops_t *ops = md_hl_for_tag(h);

		if (ops &&
		    !lws_hl_html_construct(&h->hlhtml, h->wc, h->user, NULL) &&
		    !lws_hl_construct(&h->hlctx, ops,
				      lws_hl_html_token, &h->hlhtml)) {
			h->hl_on	= 1;
			h->hl_fin	= 0;
			h->hl_closed	= 0;
			h->hl_off	= 0;
			h->hl_hold	= 0;
		}
	}
#endif

	if ((r = mdw(h, "<pre><code>")))
		return r;
	h->pre_done = 1;

	return LWS_SRET_OK;
}

/*
 * The first content event for a link (text, an image, inline code,
 * emphasis...) opens its <a href="..."> tag: the url datum has all
 * arrived by then.  Deferred writes retry the whole event.
 */

static lws_stateful_ret_t
md_flush_a(lws_md_html_t *h)
{
	lws_stateful_ret_t r;
	size_t ul;

	if (h->pending != 1 || h->a_open)
		return LWS_SRET_OK;

	memcpy(h->buf, "<a href=\"", 9);
	ul = md_url_policy(h, 0, 9);
	memcpy(h->buf + ul, "\">", 2);

	r = h->wc(h->user, (const uint8_t *)h->buf, ul + 2);
	if (r)
		return r;

	h->a_open = 1;

	return LWS_SRET_OK;
}

int
lws_md_html_construct(lws_md_html_t *h, lws_md_write_cb wc, void *user,
		      lws_md_resolve_cb resolve, void *resolve_user)
{
	if (!h || !wc)
		return 1;

	memset(h, 0, sizeof(*h));
	h->wc		= wc;
	h->user		= user;
	h->resolve	= resolve;
	h->resolve_user	= resolve_user;

	return 0;
}

lws_stateful_ret_t
lws_md_html_event(void *user, lws_md_ev_t ev, lws_md_el_t el,
		  unsigned int aux, const uint8_t *data, size_t len)
{
	lws_md_html_t *h = (lws_md_html_t *)user;
	lws_stateful_ret_t r;
	char tbuf[24];
	size_t ul;
	int lvl;

	if (!h || !h->wc || (!data && len))
		return LWS_SRET_FATAL;

	switch (ev) {
	case LMD_EV_BEGIN:
		switch (el) {
		case LMD_EL_H:
			lvl = (int)(aux & 0xff);
			if (lvl < 1)
				lvl = 1;
			if (lvl > 6)
				lvl = 6;
			lws_snprintf(&tbuf[0], sizeof(tbuf), "<h%d>", lvl);
			return mdw(h, tbuf);
		case LMD_EL_P:		return mdw(h, "<p>");
		case LMD_EL_BQ:		return mdw(h, "<blockquote>");
		case LMD_EL_UL:		return mdw(h, "<ul>");
		case LMD_EL_OL:		return mdw(h, "<ol>");
		case LMD_EL_LI:		return mdw(h, "<li>");
		case LMD_EL_TABLE:	return mdw(h, "<table>");
		case LMD_EL_TR:		return mdw(h, "<tr>");
		case LMD_EL_CELL:	return mdw(h, (aux & 1) ? "<th>" : "<td>");
		case LMD_EL_HR:		return mdw(h, "<hr>");
		case LMD_EL_CODE:
			h->code_open	= 1;
			h->pre_done	= 0;
			h->info[0]	= '\0';
			h->infolen	= 0;
			return LWS_SRET_OK;
		case LMD_EL_EM:
			if ((r = md_flush_a(h)))
				return r;
			return mdw(h, "<em>");
		case LMD_EL_STRONG:
			if ((r = md_flush_a(h)))
				return r;
			return mdw(h, "<strong>");
		case LMD_EL_CS:
			if ((r = md_flush_a(h)))
				return r;
			return mdw(h, "<code>");
		case LMD_EL_A:
			h->pending	= 1;
			h->a_open	= 0;
			h->url_len	= 0;
			return LWS_SRET_OK;
		case LMD_EL_IMG:
			/*
			 * Content events open a pending link first: a linked
			 * image like [![alt](img)](url) needs the <a href>
			 * before the <img>.
			 */

			if ((r = md_flush_a(h)))
				return r;
			h->pending	= 2;
			h->alt_open	= 0;
			h->url_len	= 0;
			return LWS_SRET_OK;
		default:
			return LWS_SRET_OK;
		}

	case LMD_EV_END:
		switch (el) {
		case LMD_EL_H:
			lvl = (int)(aux & 0xff);
			if (lvl < 1)
				lvl = 1;
			if (lvl > 6)
				lvl = 6;
			lws_snprintf(&tbuf[0], sizeof(tbuf), "</h%d>", lvl);
			return mdw(h, tbuf);
		case LMD_EL_P:		return mdw(h, "</p>");
		case LMD_EL_BQ:		return mdw(h, "</blockquote>");
		case LMD_EL_UL:		return mdw(h, "</ul>");
		case LMD_EL_OL:		return mdw(h, "</ol>");
		case LMD_EL_LI:		return mdw(h, "</li>");
		case LMD_EL_TABLE:	return mdw(h, "</table>");
		case LMD_EL_TR:		return mdw(h, "</tr>");
		case LMD_EL_CELL:	return mdw(h, (aux & 1) ? "</th>" : "</td>");
		case LMD_EL_HR:
			return LWS_SRET_OK;	/* issued at BEGIN */
		case LMD_EL_CODE:
			if (!h->code_open)
				return LWS_SRET_OK;
			/* an empty fence issues its prologue here, which may
			 * bring the tokenizer up: end it after, not before */
			if ((r = md_code_prologue(h)))
				return r;
#if defined(LWS_WITH_HL)
			if (h->hl_on) {
				r = md_hl_end(h);
				if (r)
					return r;
			}
#endif
			if ((r = mdw(h, "</code></pre>")))
				return r;
			h->code_open = 0;
			return LWS_SRET_OK;
		case LMD_EL_EM:		return mdw(h, "</em>");
		case LMD_EL_STRONG:	return mdw(h, "</strong>");
		case LMD_EL_CS:		return mdw(h, "</code>");
		case LMD_EL_A:
			if (h->pending == 1) {
				/* no content arrived: open the tag at the end */

				if ((r = md_flush_a(h)))
					return r;
				h->pending = 0;
			}
			return mdw(h, "</a>");
		case LMD_EL_IMG:
			if (h->pending == 2) {
				if (!h->alt_open) {
					/* no alt text arrived at all */

					memcpy(h->buf, "<img src=\"", 10);
					ul = md_url_policy(h, 1, 10);
					memcpy(h->buf + ul, "\" alt=\"\">", 9);
					r = h->wc(h->user,
						  (const uint8_t *)h->buf,
						  ul + 9);
					if (r)
						return r;
					h->alt_open = 1;
				} else
					if ((r = mdw(h, "\">")))
						return r;
				h->pending = 0;
			}
			return LWS_SRET_OK;
		default:
			return LWS_SRET_OK;
		}

	case LMD_EV_INFO:
		if (!h->code_open)
			return LWS_SRET_OK;
		if (len > LMD_INFO_MAX - 1)
			len = LMD_INFO_MAX - 1;
		/* an indented code block has no info string: NULL, 0 */
		if (len)
			memcpy(h->info, data, len);
		h->info[len] = '\0';
		h->infolen = (uint8_t)len;

		return md_code_prologue(h);

	case LMD_EV_URL:
		if (h->pending && h->url_len + len < LMD_URL_MAX - 1) {
			memcpy(h->url + h->url_len, data, len);
			h->url_len += len;
		}
		return LWS_SRET_OK;

	case LMD_EV_ALT:
		if (h->pending == 2 && !h->alt_open) {
			/* the first alt piece opens the tag */

			memcpy(h->buf, "<img src=\"", 10);
			ul = md_url_policy(h, 1, 10);
			memcpy(h->buf + ul, "\" alt=\"", 7);
			r = h->wc(h->user, (const uint8_t *)h->buf, ul + 7);
			if (r)
				return r;
			h->alt_open = 1;
		}

		return md_esc_emit(h, data, len, 1);

	case LMD_EV_TEXT:
		/* a link flushes its open tag at the first content piece */

		if ((r = md_flush_a(h)))
			return r;

		if (h->code_open) {
			if ((r = md_code_prologue(h)))
				return r;
#if defined(LWS_WITH_HL)
			if (h->hl_on)
				return md_hl_feed(h, data, len);
#endif
		}

		return md_esc_emit(h, data, len, 0);

	default:
		return LWS_SRET_OK;
	}
}

lws_stateful_ret_t
lws_md_html_close(lws_md_html_t *h)
{
	lws_stateful_ret_t r;

	if (!h || !h->wc)
		return LWS_SRET_FATAL;

	/* the driver closes well-formed structure itself */

	if (h->pending == 2 && h->alt_open) {
		if ((r = mdw(h, "\">")))
			return r;
		h->alt_open = 0;
	}

	if (h->pending == 1 && h->a_open) {
		if ((r = mdw(h, "</a>")))
			return r;
		h->a_open = 0;
	}

	if (h->code_open) {
		if ((r = md_code_prologue(h)))
			return r;
#if defined(LWS_WITH_HL)
		if (h->hl_on) {
			r = md_hl_end(h);
			if (r)
				return r;
		}
#endif
		if ((r = mdw(h, "</code></pre>")))
			return r;
		h->code_open = 0;
	}

	h->pending = 0;

	return LWS_SRET_OK;
}
