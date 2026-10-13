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
 * The ICANN root zone KSK DS records, the built-in DNSSEC trust anchors, as
 * published by IANA in https://data.iana.org/root-anchors/root-anchors.xml
 *
 * Only dnssec.c uses them in the library.  They are in their own header so
 * api-test-dnssec-root-anchors can check them against the root KSKs' public
 * keys, since a mistyped digest here fails every validation, but only once the
 * root is signing with that key.
 */

#ifndef __LWS_PRIVATE_LIB_ASYNC_DNS_ROOT_ANCHORS_H__
#define __LWS_PRIVATE_LIB_ASYNC_DNS_ROOT_ANCHORS_H__

static const struct {
	uint16_t keytag;
	uint8_t algo;
	uint8_t digest_type;
	const char *digest_hex;
} lws_adns_root_ds[] = {
	/* Key tag 20326 (KSK-2017) */
	{ 20326, 8, 2, "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d" },
	/* Key tag 38696 (KSK-2024) */
	{ 38696, 8, 2, "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16" }
};

#endif
