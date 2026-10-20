/*
 * libwebsockets ACME client protocol plugin
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
 * Which name a dns-01 challenge is about, and so where its TXT goes
 *
 * A cert's config lives in domains/<zone>/conf.d, and everything about it,
 * the cert, its key, and for dns-01 the challenge TXT, is kept under that
 * zone's directory, whatever the cert's own name is.  The TXT is published
 * at _acme-challenge.<the cert's name> (RFC 8555 8.4), which for a cert on a
 * subdomain is a name in the zone, not a zone of its own: the challenge for
 * dist.example.com once went looking for a domains/dist.example.com
 * directory that did not exist.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>

#include "private-acme-client.h"

int
acme_dns01_name(const char *zone, const char *cn, char *name, size_t len)
{
	size_t zl, nl;

	if (!zone || !cn || !len)
		return 1;

	/* a wildcard's challenge is about the name it is under */
	if (!strncmp(cn, "*.", 2))
		cn += 2;

	/* either may be given absolute */
	nl = strlen(cn);
	if (nl && cn[nl - 1] == '.')
		nl--;
	zl = strlen(zone);
	if (zl && zone[zl - 1] == '.')
		zl--;

	if (!zl || nl < zl || nl >= len ||
	    strncasecmp(cn + nl - zl, zone, zl))
		return 1;

	/* the apex, or at least one whole label more */
	if (nl != zl && (nl < zl + 2 || cn[nl - zl - 1] != '.'))
		return 1;

	memcpy(name, cn, nl);
	name[nl] = '\0';

	return 0;
}
