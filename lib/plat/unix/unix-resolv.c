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
#include <ctype.h>
#include "private-lib-async-dns.h"

/*
 * Shared "nameserver" line parser for /etc/resolv.conf-shaped files.
 *
 * The file path is /etc/resolv.conf unless the LWS_ASYNCDNS_RESOLV_CONF env
 * override is set... the override exists so tests can point the whole
 * platform DNS discovery machinery at a scratch file they control.
 */

/* generous for a file that holds a handful of nameserver / search lines */
#define LWS_RESOLV_CONF_MAX 4096

/*
 * Read resolv.conf into a NUL-terminated buffer of our own, to free.
 *
 * We parse into our own buffer: we may be called on a non-service thread (eg,
 * on macOS, from the SCDynamicStore dispatch queue when the DNS config
 * changes), so we must not scribble on pt[0]'s serv_buf, which a service
 * thread is receiving into and parsing out of.
 */

static char *
lws_asyncdns_read_resolv_conf(void)
{
	const char *env = getenv("LWS_ASYNCDNS_RESOLV_CONF");
	char *r;
	ssize_t n;
	int fd;

	r = lws_malloc(LWS_RESOLV_CONF_MAX + 1, __func__);
	if (!r)
		return NULL;

	fd = open(env && env[0] ? env : "/etc/resolv.conf", LWS_O_RDONLY);
	if (fd < 0)
		goto bail;

	n = read(fd, r, LWS_RESOLV_CONF_MAX);
	close(fd);
	if (n < 0)
		goto bail;

	r[n] = '\0';

	return r;

bail:
	lws_free(r);

	return NULL;
}

/*
 * resolv.conf is lines of a keyword and its arguments.  Tokenized, the lines
 * run together, so a keyword token is what ends the previous line's
 * arguments.
 *
 * An IPv6 nameserver, eg "::1", is one token only if ':' doesn't end one:
 * without that, every IPv6 nameserver line was dropped.
 */

static void
lws_asyncdns_tokenize_resolv_conf(lws_tokenize_t *ts, char *r)
{
	lws_tokenize_init(ts, r, LWS_TOKENIZE_F_DOT_NONTERM |
				 LWS_TOKENIZE_F_COLON_NONTERM |
				 LWS_TOKENIZE_F_NO_FLOATS |
				 LWS_TOKENIZE_F_NO_INTEGERS |
				 LWS_TOKENIZE_F_MINUS_NONTERM |
				 LWS_TOKENIZE_F_HASH_COMMENT);
}

static int
lws_asyncdns_token_is(const lws_tokenize_t *ts, const char *kw)
{
	size_t kl = strlen(kw);

	return (size_t)ts->token_len == kl && !strncmp(kw, ts->token, kl);
}

int
lws_asyncdns_parse_resolv_conf(struct lws_context *context, int index,
			       lws_sockaddr46 *sa46)
{
	int ns = 0, current = 0, ret = -1;
	char ads[48], *r;
	lws_tokenize_t ts;

	(void)context;

	r = lws_asyncdns_read_resolv_conf();
	if (!r)
		return -1;

	lws_asyncdns_tokenize_resolv_conf(&ts, r);
	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		if (ts.e != LWS_TOKZE_TOKEN) {
			ns = 0;
			continue;
		}

		/*
		 * strncmp() alone would accept any prefix of "nameserver", ie,
		 * a bare "name" line would introduce a nameserver address
		 */

		if (!ns && ts.token_len == 10 &&
		    !strncmp("nameserver", ts.token, 10)) {
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

		if (current++ == index) {
			ret = 0;
			break;
		}

	} while (ts.e > 0);

	lws_free(r);

	return ret;
}

/*
 * The search list is the "search" line's domains, or the "domain" line's
 * one, whichever came last, and ndots is from "options ndots:N".  As with
 * libc, the LOCALDOMAIN env var replaces the file's search list.
 *
 * Libc keeps at most 6 search domains, and the same here: with ndots in
 * play, every one is a round trip a name that doesn't exist costs.
 */

#define LWS_ADNS_SEARCH_MAX_DOMAINS	6

enum {
	RC_NONE,
	RC_NAMESERVER,
	RC_SEARCH,
	RC_OPTIONS,
	RC_OTHER
};

static int
lws_asyncdns_search_add(char *buf, size_t len, size_t *used, int *count,
			const char *dom, size_t dl)
{
	/* an absolute domain is the same without its dot */
	while (dl && dom[dl - 1] == '.')
		dl--;

	if (!dl || *count >= LWS_ADNS_SEARCH_MAX_DOMAINS ||
	    *used + dl + 1 > len)
		return 1;

	/* lowercase, like the names it's appended to */
	while (dl--)
		buf[(*used)++] = (char)tolower((uint8_t)*dom++);
	buf[(*used)++] = '\0';
	(*count)++;

	return 0;
}

int
lws_plat_asyncdns_get_search(struct lws_context *context, char *buf,
			     size_t len, int *ndots)
{
	int state = RC_NONE, count = 0;
	lws_tokenize_t ts;
	const char *env;
	size_t used = 0;
	char *r;

	(void)context;

	*ndots = 1;
	if (len)
		buf[0] = '\0';

	r = lws_asyncdns_read_resolv_conf();
	if (!r)
		return -1;

	lws_asyncdns_tokenize_resolv_conf(&ts, r);
	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		if (ts.e != LWS_TOKZE_TOKEN)
			continue;

		if (lws_asyncdns_token_is(&ts, "nameserver")) {
			state = RC_NAMESERVER;
			continue;
		}
		if (lws_asyncdns_token_is(&ts, "search") ||
		    lws_asyncdns_token_is(&ts, "domain")) {
			/* the last of either wins outright */
			state = RC_SEARCH;
			count = 0;
			used = 0;
			continue;
		}
		if (lws_asyncdns_token_is(&ts, "options")) {
			state = RC_OPTIONS;
			continue;
		}
		if (lws_asyncdns_token_is(&ts, "sortlist")) {
			state = RC_OTHER;
			continue;
		}

		switch (state) {
		case RC_SEARCH:
			lws_asyncdns_search_add(buf, len, &used, &count,
						ts.token, (size_t)ts.token_len);
			break;
		case RC_OPTIONS:
			if (ts.token_len > 6 &&
			    !strncmp(ts.token, "ndots:", 6)) {
				int n = atoi(ts.token + 6);

				/* libc caps it at 15 too */
				if (n < 0)
					n = 0;
				if (n > 15)
					n = 15;
				*ndots = n;
			}
			break;
		default:
			break;
		}

	} while (ts.e > 0);

	lws_free(r);

	env = getenv("LOCALDOMAIN");
	if (env && env[0]) {
		count = 0;
		used = 0;
		while (*env) {
			const char *e;

			while (*env == ' ' || *env == '\t')
				env++;
			e = env;
			while (*env && *env != ' ' && *env != '\t')
				env++;
			if (env > e)
				lws_asyncdns_search_add(buf, len, &used, &count,
							e, (size_t)(env - e));
		}
	}

	return count;
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


