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

#if defined(LWS_WITH_STATS)

uint64_t
lws_stats_get(struct lws_context *context, int index)
{
	struct lws_context_per_thread *pt = &context->pt[0];

	if (index >= LWSSTATS_SIZE)
		return 0;

	return pt->lws_stats[index];
}

static const char * stat_names[] = {
	"C_CONNECTIONS",
	"C_API_CLOSE",
	"C_API_READ",
	"C_API_LWS_WRITE",
	"C_API_WRITE",
	"C_WRITE_PARTIALS",
	"C_WRITEABLE_CB_REQ",
	"C_WRITEABLE_CB_EFF_REQ",
	"C_WRITEABLE_CB",
	"C_SSL_CONNECTIONS_FAILED",
	"C_SSL_CONNECTIONS_ACCEPTED",
	"C_SSL_CONNECTIONS_ACCEPT_SPIN",
	"C_SSL_CONNS_HAD_RX",
	"C_TIMEOUTS",
	"C_SERVICE_ENTRY",
	"B_READ",
	"B_WRITE",
	"B_PARTIALS_ACCEPTED_PARTS",
	"US_SSL_ACCEPT_LATENCY_AVG",
	"US_WRITABLE_DELAY_AVG",
	"US_WORST_WRITABLE_DELAY",
	"US_SSL_RX_DELAY_AVG",
	"C_PEER_LIMIT_AH_DENIED",
	"C_PEER_LIMIT_WSI_DENIED",
	"C_CONNECTIONS_CLIENT",
	"C_CONNECTIONS_CLIENT_FAILED",
};

static int
quantify(struct lws_context *context, int tsi, char *p, int len, int idx,
	 uint64_t *sum)
{
	const lws_humanize_unit_t *schema = humanize_schema_si;
	struct lws_context_per_thread *pt = &context->pt[tsi];
	uint64_t u, u1;

	lws_pt_stats_lock(pt);
	u = pt->lws_stats[idx];

	/* it's supposed to be an average? */

	switch (idx) {
	case LWSSTATS_US_SSL_ACCEPT_LATENCY_AVG:
		u1 = pt->lws_stats[LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED];
		if (u1)
			u = u / u1;
		break;
	case LWSSTATS_US_SSL_RX_DELAY_AVG:
		u1 = pt->lws_stats[LWSSTATS_C_SSL_CONNS_HAD_RX];
		if (u1)
			u = u / u1;
		break;
	case LWSSTATS_US_WRITABLE_DELAY_AVG:
		u1 = pt->lws_stats[LWSSTATS_C_WRITEABLE_CB];
		if (u1)
			u = u / u1;
		break;
	}
	lws_pt_stats_unlock(pt);

	*sum += u;

	switch (stat_names[idx][0]) {
	case 'U':
		schema = humanize_schema_us;
		break;
	case 'B':
		schema = humanize_schema_si_bytes;
		break;
	}

	return lws_humanize(p, len, u, schema);
}


void
lws_stats_log_dump(struct lws_context *context)
{
	struct lws_vhost *v = context->vhost_list;
	uint64_t summary[LWSSTATS_SIZE];
	char bufline[128], *p, *end = bufline + sizeof(bufline) - 1;
	int n, m;

	if (!context->updated)
		return;

	context->updated = 0;
	memset(summary, 0, sizeof(summary));

	lwsl_notice("\n");
	lwsl_notice("LWS internal statistics dump ----->\n");
	for (n = 0; n < (int)LWS_ARRAY_SIZE(stat_names); n++) {
		uint64_t u = 0;

		/* if it's all zeroes, don't report it */

		for (m = 0; m < context->count_threads; m++) {
			struct lws_context_per_thread *pt = &context->pt[m];

			u |= pt->lws_stats[n];
		}
		if (!u)
			continue;

		p = bufline;
		p += lws_snprintf(p, lws_ptr_diff(end, p), "%28s: ",
				  stat_names[n]);

		for (m = 0; m < context->count_threads; m++)
			quantify(context, m, p, lws_ptr_diff(end, p), n, &summary[n]);

		lwsl_notice("%s\n", bufline);
	}

	lwsl_notice("Simultaneous SSL restriction:  %8d/%d\n",
			context->simultaneous_ssl,
			context->simultaneous_ssl_restriction);

	lwsl_notice("Live wsi:                      %8d\n",
			context->count_wsi_allocated);

	while (v) {
		if (v->lserv_wsi &&
		    v->lserv_wsi->position_in_fds_table != LWS_NO_FDS_POS) {

			struct lws_context_per_thread *pt =
					&context->pt[(int)v->lserv_wsi->tsi];
			struct lws_pollfd *pfd;

			pfd = &pt->fds[v->lserv_wsi->position_in_fds_table];

			lwsl_notice("  Listen port %d actual POLLIN:   %d\n",
				    v->listen_port,
				    (int)pfd->events & LWS_POLLIN);
		}

		v = v->vhost_next;
	}

	for (n = 0; n < context->count_threads; n++) {
		struct lws_context_per_thread *pt = &context->pt[n];
		struct lws *wl;
		int m = 0;

		lwsl_notice("PT %d\n", n + 1);

		lws_pt_lock(pt, __func__);

		lwsl_notice("  AH in use / max:                  %d / %d\n",
				pt->http.ah_count_in_use,
				context->max_http_header_pool);

		wl = pt->http.ah_wait_list;
		while (wl) {
			m++;
			wl = wl->http.ah_wait_list;
		}

		lwsl_notice("  AH wait list count / actual:      %d / %d\n",
				pt->http.ah_wait_list_length, m);

		lws_pt_unlock(pt);
	}

#if defined(LWS_WITH_PEER_LIMITS)
	m = 0;
	for (n = 0; n < (int)context->pl_hash_elements; n++) {
		lws_start_foreach_llp(struct lws_peer **, peer,
				      context->pl_hash_table[n]) {
			m++;
		} lws_end_foreach_llp(peer, next);
	}

	lwsl_notice(" Peers: total active %d\n", m);
	if (m > 10) {
		m = 10;
		lwsl_notice("  (showing 10 peers only)\n");
	}

	if (m) {
		for (n = 0; n < (int)context->pl_hash_elements; n++) {
			char buf[72];

			lws_start_foreach_llp(struct lws_peer **, peer,
					      context->pl_hash_table[n]) {
				struct lws_peer *df = *peer;

				if (!lws_plat_inet_ntop(df->af, df->addr, buf,
							sizeof(buf) - 1))
					strcpy(buf, "unknown");
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
				lwsl_notice("  peer %s: count wsi: %d, count ah: %d\n",
					    buf, df->count_wsi,
					    df->http.count_ah);
#else
				lwsl_notice("  peer %s: count wsi: %d\n",
					    buf, df->count_wsi);
#endif

				if (!--m)
					break;
			} lws_end_foreach_llp(peer, next);
		}
	}
#endif

	lwsl_notice("\n");
}

void
lws_stats_bump(struct lws_context_per_thread *pt, int i, uint64_t bump)
{
	lws_pt_stats_lock(pt);
	pt->lws_stats[i] += bump;
	if (i != LWSSTATS_C_SERVICE_ENTRY) {
		pt->updated = 1;
		pt->context->updated = 1;
	}
	lws_pt_stats_unlock(pt);
}

void
lws_stats_max(struct lws_context_per_thread *pt, int index, uint64_t val)
{
	lws_pt_stats_lock(pt);
	if (val > pt->lws_stats[index]) {
		pt->lws_stats[index] = val;
		pt->updated = 1;
		pt->context->updated = 1;
	}
	lws_pt_stats_unlock(pt);
}

#endif


