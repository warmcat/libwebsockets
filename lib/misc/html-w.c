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
 * Writing html into a buffer, escaping what isn't the caller's own markup
 */

#include "private-lib-core.h"

void
lws_html_w_init(lws_html_w_t *w, char *buf, size_t len)
{
	w->p = buf;
	w->end = buf + len;
	w->full = !len;
	if (len)
		*buf = '\0';
}

static void
html_w_vprintf(lws_html_w_t *w, const char *fmt, va_list ap)
{
	size_t room = lws_ptr_diff_size_t(w->end, w->p);
	int n;

	if (w->full)
		return;

	n = vsnprintf(w->p, room, fmt, ap);
	if (n < 0 || (size_t)n >= room) {
		/* what did go in is not used, but leave it terminated */
		*w->p = '\0';
		w->full = 1;
		return;
	}

	w->p += n;
}

void
lws_html_w_printf(lws_html_w_t *w, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	html_w_vprintf(w, fmt, ap);
	va_end(ap);
}

void
lws_html_w_text(lws_html_w_t *w, const char *s, size_t max)
{
	size_t n;

	if (!s)
		return;

	for (n = 0; n < max && s[n] && !w->full; n++) {
		unsigned char c = (unsigned char)s[n];

		switch (c) {
		case '&':
			lws_html_w_printf(w, "&amp;");
			break;
		case '<':
			lws_html_w_printf(w, "&lt;");
			break;
		case '>':
			lws_html_w_printf(w, "&gt;");
			break;
		case '"':
			lws_html_w_printf(w, "&quot;");
			break;
		case '\'':
			lws_html_w_printf(w, "&#39;");
			break;
		default:
			if (c < 0x20 || c == 0x7f)
				c = '?';
			lws_html_w_printf(w, "%c", c);
			break;
		}
	}
}

void
lws_html_w_urlarg(lws_html_w_t *w, const char *s, size_t max)
{
	size_t n;

	if (!s)
		return;

	for (n = 0; n < max && s[n] && !w->full; n++) {
		unsigned char c = (unsigned char)s[n];

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~')
			lws_html_w_printf(w, "%c", c);
		else
			lws_html_w_printf(w, "%%%02X", c);
	}
}

int
lws_html_w_len(const lws_html_w_t *w, const char *buf)
{
	if (w->full)
		return -1;

	return (int)lws_ptr_diff(w->p, buf);
}
