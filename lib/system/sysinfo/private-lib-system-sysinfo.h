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
 */

/*
 * What the platforms fill a snapshot with, see sysinfo.c
 */

#if !defined(__LWS_PRIVATE_LIB_SYSTEM_SYSINFO_H__)
#define __LWS_PRIVATE_LIB_SYSTEM_SYSINFO_H__

struct lws_sysinfo {
	struct lws_context	*cx;
	struct lwsac		*ac;
	lws_dll2_owner_t	items;
};

/*
 * Add an item: name and s are copied, either may be NULL.  Returns the item
 * to fill in the address or flags of, or NULL on OOM.
 */
lws_sysinfo_item_t *
lws_sysinfo_add(struct lws_sysinfo *si, lws_sysinfo_type_t type,
		const char *name, const char *s, uint64_t u);

/* add an interface address from a sockaddr, with its netmask if known */
lws_sysinfo_item_t *
lws_sysinfo_add_iface(struct lws_sysinfo *si, const char *name,
		      const struct sockaddr *sa, const struct sockaddr *mask,
		      int prefix, uint32_t flags);

/* the platform adds what it knows */
void
lws_plat_sysinfo_fill(struct lws_sysinfo *si);

#endif
