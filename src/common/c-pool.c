/*
 * Sai - ./src/common/c-pool.c
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * Pool sync helpers shared by sai-builder and sai-server, see
 * READMEs/README-pool.md.
 *
 * Everything a pool record names ends up as a path component on the builder,
 * and in the server's db, so both sides check names with these before using
 * them, whoever sent them.
 */

#include <libwebsockets.h>
#include <string.h>

#include "include/private.h"

/*
 * A pool name, from .sai.json: short, lowercase alnum plus - and _
 */

int
sai_pool_name_ok(const char *name)
{
	size_t n = 0;

	if (!name || !*name)
		return 0;

	while (name[n]) {
		char c = name[n];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		      c == '-' || c == '_'))
			return 0;
		if (++n > 32)
			return 0;
	}

	return 1;
}

static int
sai_pool_safe_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

/*
 * The subdir part of an entry name, eg, "corpus-h2".  It's a single path
 * component that can't be hidden, ".." or anything else special.
 */

int
sai_pool_sub_ok(const char *sub, size_t len)
{
	size_t n;

	if (!len || len > 32 || sub[0] == '.')
		return 0;

	for (n = 0; n < len; n++)
		if (!sai_pool_safe_char(sub[n]))
			return 0;

	return 1;
}

/*
 * A whole entry name, "<sub>/<name>".  In the content addressed namespaces the
 * name is the 40 char lowercase hex sha1 of the content; findings can be named
 * anything safe, that isn't hidden.
 */

int
sai_pool_entry_name_ok(int ns, const char *name, size_t len)
{
	const char *sl = memchr(name, '/', len);
	size_t sub_len, nl, n;
	const char *nm;

	if (!sl)
		return 0;

	sub_len = lws_ptr_diff_size_t(sl, name);
	if (!sai_pool_sub_ok(name, sub_len))
		return 0;

	nm = sl + 1;
	nl = len - sub_len - 1;

	if (ns == SAI_POOL_NS_FINDINGS) {
		if (!nl || nl > 64 || nm[0] == '.')
			return 0;
		for (n = 0; n < nl; n++)
			if (!sai_pool_safe_char(nm[n]))
				return 0;

		return 1;
	}

	if (nl != 40)
		return 0;

	for (n = 0; n < nl; n++)
		if (!((nm[n] >= '0' && nm[n] <= '9') ||
		      (nm[n] >= 'a' && nm[n] <= 'f')))
			return 0;

	return 1;
}

/* is the content really what its content addressed name says? */

int
sai_pool_content_matches(const uint8_t *data, size_t len, const char *sha1hex)
{
	uint8_t md[20];
	char hex[41];
	int n;

	lws_SHA1(data, len, md);
	for (n = 0; n < 20; n++)
		lws_snprintf(hex + (n * 2), 3, "%02x", md[n]);

	return !memcmp(hex, sha1hex, 40);
}

void
sai_pool_rec_hdr_write(uint8_t *p, int type, int ns, size_t name_len,
		       size_t len)
{
	p[0] = (uint8_t)type;
	p[1] = (uint8_t)ns;
	p[2] = (uint8_t)(name_len >> 8);
	p[3] = (uint8_t)name_len;
	p[4] = (uint8_t)(len >> 24);
	p[5] = (uint8_t)(len >> 16);
	p[6] = (uint8_t)(len >> 8);
	p[7] = (uint8_t)len;
}

void
sai_pool_rec_hdr_read(const uint8_t *p, sai_pool_rec_hdr_t *h)
{
	h->type		= p[0];
	h->ns		= p[1];
	h->name_len	= (uint16_t)((p[2] << 8) | p[3]);
	h->len		= ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
			  ((uint32_t)p[6] << 8) | (uint32_t)p[7];
}

/* the most data a record of this type and namespace may carry */

size_t
sai_pool_rec_max(int ns, int type)
{
	switch (type) {
	case SAI_POOL_REC_PULL:
	case SAI_POOL_REC_PULL_END:
		return 8;
	case SAI_POOL_REC_OFFER:
	case SAI_POOL_REC_WANT:
		return SAI_POOL_OFFER_MAX;
	case SAI_POOL_REC_REPLACE:
		return SAI_POOL_LIST_MAX;
	case SAI_POOL_REC_PUT:
	case SAI_POOL_REC_ENTRY:
		return ns == SAI_POOL_NS_FINDINGS ? SAI_POOL_FINDING_MAX :
						    SAI_POOL_ENTRY_MAX;
	}

	return 0;
}

void
sai_pool_u64_write(uint8_t *p, uint64_t v)
{
	int n;

	for (n = 7; n >= 0; n--) {
		p[n] = (uint8_t)v;
		v >>= 8;
	}
}

uint64_t
sai_pool_u64_read(const uint8_t *p)
{
	uint64_t v = 0;
	int n;

	for (n = 0; n < 8; n++)
		v = (v << 8) | p[n];

	return v;
}
