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

#ifndef _PRIVATE_LIB_SYSTEM_AUTH_DNS_H_
#define _PRIVATE_LIB_SYSTEM_AUTH_DNS_H_

#include "private-lib-core.h"

struct auth_dns_rr {
	lws_dll2_t list;

	char *rdata;        // unparsed or raw payload from zone line
	size_t rdata_len;
	
	uint8_t *wire_rdata; // canonical wire format
	size_t wire_rdata_len;
};

struct auth_dns_rrset {
	lws_dll2_t list;
	lws_dll2_owner_t rr_list; // list of auth_dns_rr

	char *name;         
	uint32_t ttl;
	uint16_t class_;    // e.g. 1 for IN
	uint16_t type;      // e.g. 1 for A, 2 for NS, etc
};

struct auth_dns_zone {
	lws_dll2_owner_t rrset_list;
	char default_ttl[16];
	char origin[128];
};

int
lws_auth_dns_rdata_to_wire(struct auth_dns_zone *z, struct auth_dns_rr *rr, uint16_t type);

void
lws_auth_dns_inject_mock_keys(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z);

void
lws_auth_dns_sort_zone(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z);

void
lws_auth_dns_sign_rrsets(struct lws_auth_dns_sign_info *info, struct auth_dns_zone *z);

void
lws_auth_dns_free_zone(struct auth_dns_zone *z);

int
lws_auth_dns_parse_zone_buf(const char *buf, size_t len, struct auth_dns_zone *zone);

#endif
