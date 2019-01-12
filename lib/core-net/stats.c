/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
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
 */

#include "core/private.h"


#if defined(LWS_WITH_STATS)

LWS_VISIBLE LWS_EXTERN uint64_t
lws_stats_get(struct lws_context *context, int index)
{
	if (index >= LWSSTATS_SIZE)
		return 0;

	return context->lws_stats[index];
}

LWS_VISIBLE LWS_EXTERN void
lws_stats_log_dump(struct lws_context *context)
{
	struct lws_vhost *v = context->vhost_list;
	int n;
#if defined(LWS_WITH_PEER_LIMITS)
	int m;
#endif

	if (!context->updated)
		return;

	context->updated = 0;

	lwsl_notice("\n");
	lwsl_notice("LWS internal statistics dump ----->\n");
	lwsl_notice("LWSSTATS_C_CONNECTIONS:                     %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_CONNECTIONS));
	lwsl_notice("LWSSTATS_C_API_CLOSE:                       %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_API_CLOSE));
	lwsl_notice("LWSSTATS_C_API_READ:                        %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_API_READ));
	lwsl_notice("LWSSTATS_C_API_LWS_WRITE:                   %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_API_LWS_WRITE));
	lwsl_notice("LWSSTATS_C_API_WRITE:                       %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_API_WRITE));
	lwsl_notice("LWSSTATS_C_WRITE_PARTIALS:                  %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_WRITE_PARTIALS));
	lwsl_notice("LWSSTATS_C_WRITEABLE_CB_REQ:                %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_WRITEABLE_CB_REQ));
	lwsl_notice("LWSSTATS_C_WRITEABLE_CB_EFF_REQ:            %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_WRITEABLE_CB_EFF_REQ));
	lwsl_notice("LWSSTATS_C_WRITEABLE_CB:                    %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_WRITEABLE_CB));
	lwsl_notice("LWSSTATS_C_SSL_CONNECTIONS_ACCEPT_SPIN:     %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_SSL_CONNECTIONS_ACCEPT_SPIN));
	lwsl_notice("LWSSTATS_C_SSL_CONNECTIONS_FAILED:          %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_SSL_CONNECTIONS_FAILED));
	lwsl_notice("LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED:        %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED));
	lwsl_notice("LWSSTATS_C_SSL_CONNS_HAD_RX:                %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_SSL_CONNS_HAD_RX));
	lwsl_notice("LWSSTATS_C_PEER_LIMIT_AH_DENIED:            %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_PEER_LIMIT_AH_DENIED));
	lwsl_notice("LWSSTATS_C_PEER_LIMIT_WSI_DENIED:           %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_PEER_LIMIT_WSI_DENIED));

	lwsl_notice("LWSSTATS_C_TIMEOUTS:                        %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_TIMEOUTS));
	lwsl_notice("LWSSTATS_C_SERVICE_ENTRY:                   %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_C_SERVICE_ENTRY));
	lwsl_notice("LWSSTATS_B_READ:                            %8llu\n",
		(unsigned long long)lws_stats_get(context, LWSSTATS_B_READ));
	lwsl_notice("LWSSTATS_B_WRITE:                           %8llu\n",
		(unsigned long long)lws_stats_get(context, LWSSTATS_B_WRITE));
	lwsl_notice("LWSSTATS_B_PARTIALS_ACCEPTED_PARTS:         %8llu\n",
		(unsigned long long)lws_stats_get(context,
					LWSSTATS_B_PARTIALS_ACCEPTED_PARTS));
	lwsl_notice("LWSSTATS_MS_SSL_CONNECTIONS_ACCEPTED_DELAY: %8llums\n",
		(unsigned long long)lws_stats_get(context,
			LWSSTATS_MS_SSL_CONNECTIONS_ACCEPTED_DELAY) / 1000);
	if (lws_stats_get(context, LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED))
		lwsl_notice("  Avg accept delay:                         %8llums\n",
			(unsigned long long)(lws_stats_get(context,
				LWSSTATS_MS_SSL_CONNECTIONS_ACCEPTED_DELAY) /
					lws_stats_get(context,
				LWSSTATS_C_SSL_CONNECTIONS_ACCEPTED)) / 1000);
	lwsl_notice("LWSSTATS_MS_SSL_RX_DELAY:                   %8llums\n",
			(unsigned long long)lws_stats_get(context,
					LWSSTATS_MS_SSL_RX_DELAY) / 1000);
	if (lws_stats_get(context, LWSSTATS_C_SSL_CONNS_HAD_RX))
		lwsl_notice("  Avg accept-rx delay:                      %8llums\n",
			(unsigned long long)(lws_stats_get(context,
					LWSSTATS_MS_SSL_RX_DELAY) /
			lws_stats_get(context,
					LWSSTATS_C_SSL_CONNS_HAD_RX)) / 1000);

	lwsl_notice("LWSSTATS_MS_WRITABLE_DELAY:                 %8lluus\n",
			(unsigned long long)lws_stats_get(context,
					LWSSTATS_MS_WRITABLE_DELAY));
	lwsl_notice("LWSSTATS_MS_WORST_WRITABLE_DELAY:           %8lluus\n",
				(unsigned long long)lws_stats_get(context,
					LWSSTATS_MS_WORST_WRITABLE_DELAY));
	if (lws_stats_get(context, LWSSTATS_C_WRITEABLE_CB))
		lwsl_notice("  Avg writable delay:                       %8lluus\n",
			(unsigned long long)(lws_stats_get(context,
					LWSSTATS_MS_WRITABLE_DELAY) /
			lws_stats_get(context, LWSSTATS_C_WRITEABLE_CB)));
	lwsl_notice("Simultaneous SSL restriction:               %8d/%d\n",
			context->simultaneous_ssl,
			context->simultaneous_ssl_restriction);

	lwsl_notice("Live wsi:                                   %8d\n",
			context->count_wsi_allocated);

	context->updated = 1;

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
lws_stats_atomic_bump(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t bump)
{
	lws_pt_stats_lock(pt);
	context->lws_stats[index] += bump;
	if (index != LWSSTATS_C_SERVICE_ENTRY)
		context->updated = 1;
	lws_pt_stats_unlock(pt);
}

void
lws_stats_atomic_max(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t val)
{
	lws_pt_stats_lock(pt);
	if (val > context->lws_stats[index]) {
		context->lws_stats[index] = val;
		context->updated = 1;
	}
	lws_pt_stats_unlock(pt);
}

#endif


