/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"
#include "private-lib-async-dns.h"

/*
 * Shared "nameserver" line parser for /etc/resolv.conf-shaped files.
 *
 * The file path is /etc/resolv.conf unless the LWS_ASYNCDNS_RESOLV_CONF env
 * override is set... the override exists so tests can point the whole
 * platform DNS discovery machinery at a scratch file they control.
 */

int
lws_asyncdns_parse_resolv_conf(struct lws_context *context, int index,
			       lws_sockaddr46 *sa46)
{
	lws_tokenize_t ts;
	char ads[48], *r;
	int fd, ns = 0, current = 0;
	ssize_t n;
	const char *env = getenv("LWS_ASYNCDNS_RESOLV_CONF");

	r = (char *)context->pt[0].serv_buf;
	fd = open(env && env[0] ? env : "/etc/resolv.conf", LWS_O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, r, context->pt_serv_buf_size - 1);
	close(fd);
	if (n < 0)
		return -1;

	r[n] = '\0';
	lws_tokenize_init(&ts, r, LWS_TOKENIZE_F_DOT_NONTERM |
					  LWS_TOKENIZE_F_NO_FLOATS |
					  LWS_TOKENIZE_F_NO_INTEGERS |
					  LWS_TOKENIZE_F_MINUS_NONTERM |
					  LWS_TOKENIZE_F_HASH_COMMENT);
	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		if (ts.e != LWS_TOKZE_TOKEN) {
			ns = 0;
			continue;
		}

		if (!ns && !strncmp("nameserver", ts.token, ts.token_len)) {
			ns = 1;
			continue;
		}
		if (!ns)
			continue;

		/* we are a token just after the "nameserver" token */

		ns = 0;
		if (ts.token_len > (int)sizeof(ads) - 1)
			continue;

		memcpy(ads, ts.token, ts.token_len);
		ads[ts.token_len] = '\0';
		if (lws_sa46_parse_numeric_address(ads, sa46) < 0)
			continue;

		if (current++ == index)
			return 0;

	} while (ts.e > 0);

	return -1;
}

#if defined(__APPLE__)
/*
 * On Apple platforms, apple-resolv.c provides the platform function (the
 * native dynamic store, falling back to the parse above); this file only
 * contributes the shared parse helper there.
 */
#else
int
lws_plat_asyncdns_get_server(struct lws_context *context, int index,
			     lws_sockaddr46 *sa46)
{
	return lws_asyncdns_parse_resolv_conf(context, index, sa46);
}
#endif


