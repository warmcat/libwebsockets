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
 * Stock html markup sink for the highlighting tokenizer
 */

#include "private-lib-core.h"
#include <string.h>

/* stock css class names... NULL entries are emitted unwrapped */

static const char * const stock_cls[LHL_CLS_COUNT] = {
	/* LHL_CLS_PLAIN     */	NULL,
	/* LHL_CLS_IDENT     */	NULL,
	/* LHL_CLS_KEYWORD   */	"hl-k",
	/* LHL_CLS_TYPE      */	"hl-t",
	/* LHL_CLS_NUMBER    */	"hl-n",
	/* LHL_CLS_STRING    */	"hl-s",
	/* LHL_CLS_CHARLIT   */	"hl-ch",
	/* LHL_CLS_COMMENT   */	"hl-cm",
	/* LHL_CLS_PREPROC   */	"hl-pp",
	/* LHL_CLS_DIFF_ADD  */	"hl-da",
	/* LHL_CLS_DIFF_REM  */	"hl-dr",
	/* LHL_CLS_DIFF_HUNK */	"hl-dh",
	/* LHL_CLS_DIFF_META */	"hl-dm",
};

/* worst-case escaped size of one byte (NUL -> "&#65533;") */
#define ESCAPE_MAX			  8

static size_t
hl_esc_byte(char *dest, uint8_t c)
{
	switch (c) {
	case '<':
		memcpy(dest, "&lt;", 4);
		return 4;
	case '>':
		memcpy(dest, "&gt;", 4);
		return 4;
	case '&':
		memcpy(dest, "&amp;", 5);
		return 5;
	default:
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			memcpy(dest, "&#65533;", 8);
			return 8;
		}
		*dest = (char)c;
		return 1;
	}
}

int
lws_hl_html_construct(lws_hl_html_t *h, lws_hl_write_cb wc, void *user,
		      const char * const *cls)
{
	if (!h || !wc)
		return 1;

	memset(h, 0, sizeof(*h));
	h->wc		= wc;
	h->user		= user;
	h->cls		= cls ? cls : stock_cls;
	h->last		= LHL_CLS_COUNT;

	return 0;
}

lws_stateful_ret_t
lws_hl_html_token(void *user, lws_hl_class_t cls, const uint8_t *tok,
		  size_t len)
{
	lws_hl_html_t *h = (lws_hl_html_t *)user;
	lws_stateful_ret_t r;
	size_t n, room;
	uint8_t now_open = 0;
	int hdr;

	if (!h || !h->wc || cls >= LHL_CLS_COUNT || (!tok && len))
		return LWS_SRET_FATAL;

	hdr = (cls != h->last);
	h->buflen = 0;

	if (hdr) {
		const char *name = h->cls[cls];

		if (h->open) {
			memcpy(h->buf, "</span>", 7);
			h->buflen = 7;
		}

		if (name) {
			/* only wrap if header + worst-case escape of the
			 * piece fits... otherwise emit bare */

			if (h->buflen + 16 + strlen(name) +
					LHL_PIECE_MAX * ESCAPE_MAX + 8 <=
							sizeof(h->buf)) {
				h->buflen += (size_t)lws_snprintf(
						h->buf + h->buflen,
						sizeof(h->buf) - h->buflen,
						"<span class=\"%s\">", name);
				now_open = 1;
			}
		}
	}

	/* token pieces are capped at LHL_PIECE_MAX, and we only added the
	 * header if the worst case fit, so this cannot overflow */

	room = sizeof(h->buf) - h->buflen;
	for (n = 0; n < len; n++) {
		size_t m = hl_esc_byte(h->buf + h->buflen, tok[n]);
		if (m > room)
			return LWS_SRET_FATAL;
		h->buflen += m;
		room -= m;
	}

	if (h->buflen) {
		r = h->wc(h->user, (const uint8_t *)h->buf, h->buflen);
		if (r)
			return r;
	}

	h->last	= cls;
	if (hdr)
		h->open = now_open;

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_hl_html_close(lws_hl_html_t *h)
{
	lws_stateful_ret_t r;

	if (!h || !h->wc)
		return LWS_SRET_FATAL;

	if (!h->open)
		return LWS_SRET_OK;

	r = h->wc(h->user, (const uint8_t *)"</span>", 7);
	if (r)
		return r;

	h->open = 0;

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_html_escape(lws_hl_write_cb wc, void *user, const uint8_t *src,
		size_t len)
{
	char buf[512];
	lws_stateful_ret_t r;
	size_t n = 0, bl = 0;

	if (!wc || (!src && len))
		return LWS_SRET_FATAL;

	for (n = 0; n < len; n++) {
		if (bl + ESCAPE_MAX > sizeof(buf)) {
			r = wc(user, (const uint8_t *)buf, bl);
			if (r)
				return r;
			bl = 0;
		}
		bl += hl_esc_byte(buf + bl, src[n]);
	}

	if (bl) {
		r = wc(user, (const uint8_t *)buf, bl);
		if (r)
			return r;
	}

	return LWS_SRET_OK;
}
