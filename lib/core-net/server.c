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

#if defined(LWS_WITH_SERVER_STATUS)

void
lws_sum_stats(const struct lws_context *ctx, struct lws_conn_stats *cs)
{
	const struct lws_vhost *vh = ctx->vhost_list;

	while (vh) {

		cs->rx += vh->conn_stats.rx;
		cs->tx += vh->conn_stats.tx;
		cs->h1_conn += vh->conn_stats.h1_conn;
		cs->h1_trans += vh->conn_stats.h1_trans;
		cs->h2_trans += vh->conn_stats.h2_trans;
		cs->ws_upg += vh->conn_stats.ws_upg;
		cs->h2_upg += vh->conn_stats.h2_upg;
		cs->h2_alpn += vh->conn_stats.h2_alpn;
		cs->h2_subs += vh->conn_stats.h2_subs;
		cs->rejected += vh->conn_stats.rejected;

		vh = vh->vhost_next;
	}
}

int
lws_json_dump_vhost(const struct lws_vhost *vh, char *buf, int len)
{
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	static const char * const prots[] = {
		"http://",
		"https://",
		"file://",
		"cgi://",
		">http://",
		">https://",
		"callback://"
	};
#endif
	char *orig = buf, *end = buf + len - 1, first;
	int n;

	if (len < 100)
		return 0;

	buf += lws_snprintf(buf, end - buf,
			"{\n \"name\":\"%s\",\n"
			" \"port\":\"%d\",\n"
			" \"use_ssl\":\"%d\",\n"
			" \"sts\":\"%d\",\n"
			" \"rx\":\"%llu\",\n"
			" \"tx\":\"%llu\",\n"
			" \"h1_conn\":\"%lu\",\n"
			" \"h1_trans\":\"%lu\",\n"
			" \"h2_trans\":\"%lu\",\n"
			" \"ws_upg\":\"%lu\",\n"
			" \"rejected\":\"%lu\",\n"
			" \"h2_upg\":\"%lu\",\n"
			" \"h2_alpn\":\"%lu\",\n"
			" \"h2_subs\":\"%lu\""
			,
			vh->name, vh->listen_port,
#if defined(LWS_WITH_TLS)
			vh->tls.use_ssl & LCCSCF_USE_SSL,
#else
			0,
#endif
			!!(vh->options & LWS_SERVER_OPTION_STS),
			vh->conn_stats.rx, vh->conn_stats.tx,
			vh->conn_stats.h1_conn,
			vh->conn_stats.h1_trans,
			vh->conn_stats.h2_trans,
			vh->conn_stats.ws_upg,
			vh->conn_stats.rejected,
			vh->conn_stats.h2_upg,
			vh->conn_stats.h2_alpn,
			vh->conn_stats.h2_subs
	);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (vh->http.mount_list) {
		const struct lws_http_mount *m = vh->http.mount_list;

		buf += lws_snprintf(buf, end - buf, ",\n \"mounts\":[");
		first = 1;
		while (m) {
			if (!first)
				buf += lws_snprintf(buf, end - buf, ",");
			buf += lws_snprintf(buf, end - buf,
					"\n  {\n   \"mountpoint\":\"%s\",\n"
					"  \"origin\":\"%s%s\",\n"
					"  \"cache_max_age\":\"%d\",\n"
					"  \"cache_reuse\":\"%d\",\n"
					"  \"cache_revalidate\":\"%d\",\n"
					"  \"cache_intermediaries\":\"%d\"\n"
					,
					m->mountpoint,
					prots[m->origin_protocol],
					m->origin,
					m->cache_max_age,
					m->cache_reusable,
					m->cache_revalidate,
					m->cache_intermediaries);
			if (m->def)
				buf += lws_snprintf(buf, end - buf,
						",\n  \"default\":\"%s\"",
						m->def);
			buf += lws_snprintf(buf, end - buf, "\n  }");
			first = 0;
			m = m->mount_next;
		}
		buf += lws_snprintf(buf, end - buf, "\n ]");
	}
#endif
	if (vh->protocols) {
		n = 0;
		first = 1;

		buf += lws_snprintf(buf, end - buf, ",\n \"ws-protocols\":[");
		while (n < vh->count_protocols) {
			if (!first)
				buf += lws_snprintf(buf, end - buf, ",");
			buf += lws_snprintf(buf, end - buf,
					"\n  {\n   \"%s\":{\n"
					"    \"status\":\"ok\"\n   }\n  }"
					,
					vh->protocols[n].name);
			first = 0;
			n++;
		}
		buf += lws_snprintf(buf, end - buf, "\n ]");
	}

	buf += lws_snprintf(buf, end - buf, "\n}");

	return buf - orig;
}


int
lws_json_dump_context(const struct lws_context *context, char *buf, int len,
		int hide_vhosts)
{
	char *orig = buf, *end = buf + len - 1, first = 1;
	const struct lws_vhost *vh = context->vhost_list;
	const struct lws_context_per_thread *pt;
	int n, listening = 0, cgi_count = 0, fd;
	struct lws_conn_stats cs;
	double d = 0;
#ifdef LWS_WITH_CGI
	struct lws_cgi * const *pcgi;
#endif

#ifdef LWS_WITH_LIBUV
	uv_uptime(&d);
#endif

	buf += lws_snprintf(buf, end - buf, "{ "
			    "\"version\":\"%s\",\n"
			    "\"uptime\":\"%ld\",\n",
			    lws_get_library_version(),
			    (long)d);

#ifdef LWS_HAVE_GETLOADAVG
#if defined(__sun)
#include <sys/loadavg.h>
#endif
	{
		double d[3];
		int m;

		m = getloadavg(d, 3);
		for (n = 0; n < m; n++) {
			buf += lws_snprintf(buf, end - buf,
				"\"l%d\":\"%.2f\",\n",
				n + 1, d[n]);
		}
	}
#endif

	fd = lws_open("/proc/self/statm", LWS_O_RDONLY);
	if (fd >= 0) {
		char contents[96], pure[96];
		n = read(fd, contents, sizeof(contents) - 1);
		if (n > 0) {
			contents[n] = '\0';
			if (contents[n - 1] == '\n')
				contents[--n] = '\0';
			lws_json_purify(pure, contents, sizeof(pure), NULL);

			buf += lws_snprintf(buf, end - buf,
					  "\"statm\": \"%s\",\n", pure);
		}
		close(fd);
	}

	buf += lws_snprintf(buf, end - buf, "\"heap\":%lld,\n\"contexts\":[\n",
				(long long)lws_get_allocated_heap());

	buf += lws_snprintf(buf, end - buf, "{ "
				"\"context_uptime\":\"%llu\",\n"
				"\"cgi_spawned\":\"%d\",\n"
				"\"pt_fd_max\":\"%d\",\n"
				"\"ah_pool_max\":\"%d\",\n"
				"\"deprecated\":\"%d\",\n"
				"\"wsi_alive\":\"%d\",\n",
				(unsigned long long)(lws_now_usecs() - context->time_up) /
					LWS_US_PER_SEC,
				context->count_cgi_spawned,
				context->fd_limit_per_thread,
				context->max_http_header_pool,
				context->deprecated,
				context->count_wsi_allocated);

	buf += lws_snprintf(buf, end - buf, "\"pt\":[\n ");
	for (n = 0; n < context->count_threads; n++) {
		pt = &context->pt[n];
		if (n)
			buf += lws_snprintf(buf, end - buf, ",");
		buf += lws_snprintf(buf, end - buf,
				"\n  {\n"
				"    \"fds_count\":\"%d\",\n"
				"    \"ah_pool_inuse\":\"%d\",\n"
				"    \"ah_wait_list\":\"%d\"\n"
				"    }",
				pt->fds_count,
				pt->http.ah_count_in_use,
				pt->http.ah_wait_list_length);
	}

	buf += lws_snprintf(buf, end - buf, "]");

	buf += lws_snprintf(buf, end - buf, ", \"vhosts\":[\n ");

	first = 1;
	vh = context->vhost_list;
	listening = 0;
	cs = context->conn_stats;
	lws_sum_stats(context, &cs);
	while (vh) {

		if (!hide_vhosts) {
			if (!first)
				if(buf != end)
					*buf++ = ',';
			buf += lws_json_dump_vhost(vh, buf, end - buf);
			first = 0;
		}
		if (vh->lserv_wsi)
			listening++;
		vh = vh->vhost_next;
	}

	buf += lws_snprintf(buf, end - buf,
			"],\n\"listen_wsi\":\"%d\",\n"
			" \"rx\":\"%llu\",\n"
			" \"tx\":\"%llu\",\n"
			" \"h1_conn\":\"%lu\",\n"
			" \"h1_trans\":\"%lu\",\n"
			" \"h2_trans\":\"%lu\",\n"
			" \"ws_upg\":\"%lu\",\n"
			" \"rejected\":\"%lu\",\n"
			" \"h2_alpn\":\"%lu\",\n"
			" \"h2_subs\":\"%lu\",\n"
			" \"h2_upg\":\"%lu\"",
			listening, cs.rx, cs.tx,
			cs.h1_conn,
			cs.h1_trans,
			cs.h2_trans,
			cs.ws_upg,
			cs.rejected,
			cs.h2_alpn,
			cs.h2_subs,
			cs.h2_upg);

#ifdef LWS_WITH_CGI
	for (n = 0; n < context->count_threads; n++) {
		pt = &context->pt[n];
		pcgi = &pt->http.cgi_list;

		while (*pcgi) {
			pcgi = &(*pcgi)->cgi_list;

			cgi_count++;
		}
	}
#endif
	buf += lws_snprintf(buf, end - buf, ",\n \"cgi_alive\":\"%d\"\n ",
			cgi_count);

	buf += lws_snprintf(buf, end - buf, "}");


	buf += lws_snprintf(buf, end - buf, "]}\n ");

	return buf - orig;
}

#endif
