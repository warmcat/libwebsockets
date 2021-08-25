/*
 * pico-sspc-binance
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Since LWS_ONLY_SSPC chops down libwebsockets.a to have just the pieces needed
 * for SSPC, we need to bring in our own copies of any other lws apis we use in
 * the user Binance SS code
 */

#include "private.h"

const char *
lws_nstrstr(const char *buf, size_t len, const char *name, size_t nl)
{
	const char *end = buf + len - nl + 1;
	size_t n;

	if (nl > len)
		/* it cannot be found if the needle is longer than the haystack */
		return NULL;

	while (buf < end) {
		if (*buf != name[0]) {
			buf++;
			continue;
		}

		if (nl == 1)
			/* single char match, we are done */
			return buf;

		if (buf[nl - 1] == name[nl - 1]) {
			/*
			 * This is looking interesting then... the first
			 * and last chars match, let's check the insides
			 */
			n = 1;
			while (n < nl && buf[n] == name[n])
				n++;

			if (n == nl)
				/* it's a hit */
				return buf;
		}

		buf++;
	}

	return NULL;
}


const char *
lws_json_simple_find(const char *buf, size_t len, const char *name, size_t *alen)
{
	size_t nl = strlen(name);
	const char *np = lws_nstrstr(buf, len, name, nl),
		   *end = buf + len, *as;
	int qu = 0;

	if (!np)
		return NULL;

	np += nl;

	while (np < end && (*np == ' ' || *np == '\t'))
		np++;

	if (np >= end)
		return NULL;

	/*
	 * The arg could be lots of things after "name": with JSON, commonly a
	 * string like "mystring", true, false, null, [...] or {...} ... we want
	 * to handle common, simple cases cheaply with this; the user can choose
	 * a full JSON parser like lejp if it's complicated.  So if no opening
	 * quote, return until a terminator like , ] }.  If there's an opening
	 * quote, return until closing quote, handling escaped quotes.
	 */

	if (*np == '\"') {
		qu = 1;
		np++;
	}

	as = np;
	while (np < end &&
	       (!qu || *np != '\"') && /* end quote is EOT if quoted */
	       (qu || (*np != '}' && *np != ']' && *np != ',')) /* delimiters */
	) {
		if (qu && *np == '\\') /* skip next char if quoted escape */
			np++;
		np++;
	}

	*alen = (unsigned int)lws_ptr_diff(np, as);

	return as;
}

void
lwsl_hexdump_level(int hexdump_level, const void *vbuf, size_t len)
{
	unsigned char *buf = (unsigned char *)vbuf;
	unsigned int n;

	for (n = 0; n < len;) {
		unsigned int start = n, m;
		char line[80], *p = line;

		p += snprintf(p, 10, "%04X: ", start);

		for (m = 0; m < 16 && n < len; m++)
			p += snprintf(p, 5, "%02X ", buf[n++]);
		while (m++ < 16)
			p += snprintf(p, 5, "   ");

		p += snprintf(p, 6, "   ");

		for (m = 0; m < 16 && (start + m) < len; m++) {
			if (buf[start + m] >= ' ' && buf[start + m] < 127)
				*p++ = (char)buf[start + m];
			else
				*p++ = '.';
		}
		while (m++ < 16)
			*p++ = ' ';

		*p++ = '\n';
		*p = '\0';
		_lws_log(hexdump_level, "%s", line);
		(void)line;
	}

	_lws_log(hexdump_level, "\n");
}

uint64_t
get_us_timeofday(void)
{
	return lws_now_usecs() + tm->us_unixtime_peer;
}
