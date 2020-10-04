/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 * We mainly focus on the routing table / gateways because those are the
 * elements that decide if we can get on to the internet or not.
 *
 * However also we maintain a getifaddrs cache, so we have to invalidate +
 * update that when any addresses are added and removed.
 */

#include <private-lib-core.h>

#if defined(_DEBUG)
void
lws_routing_entry_dump(lws_route_t *rou)
{
	char da[48], gw[48];

	lws_sa46_write_numeric_address(&rou->dest, da, sizeof(da));
	lws_sa46_write_numeric_address(&rou->gateway, gw, sizeof(gw));

	lwsl_info("  %s/%d, gw: %s, ifidx: %d, pri: %d, proto: %d\n",
		    da, rou->dest_len, gw, rou->if_idx, rou->priority,
		    rou->proto);
}

void
lws_routing_table_dump(struct lws_context_per_thread *pt)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);

		lws_routing_entry_dump(rou);
	} lws_end_foreach_dll(d);
}
#endif

int
lws_route_remove(struct lws_context_per_thread *pt, lws_route_t *robj)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);

		if (!lws_sa46_compare_ads(&robj->dest, &rou->dest) &&
		    !lws_sa46_compare_ads(&robj->gateway, &rou->gateway) &&
		    robj->dest_len == rou->dest_len &&
		    robj->if_idx == rou->if_idx &&
		    robj->priority == rou->priority) {
			// lwsl_debug("%s: deleting route\n", __func__);
			lws_dll2_remove(&rou->list);
			lws_free(rou);
			return 0;
		}

	} lws_end_foreach_dll(d);

	return 1;
}

void
lws_route_table_empty(struct lws_context_per_thread *pt)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);
		lws_dll2_remove(&rou->list);
		lws_free(rou);

	} lws_end_foreach_dll_safe(d, d1);
}

void
lws_route_table_ifdown(struct lws_context_per_thread *pt, int idx)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);

		if (rou->if_idx == idx) {
			lws_dll2_remove(&rou->list);
			lws_free(rou);
		}

	} lws_end_foreach_dll_safe(d, d1);
}

int
lws_route_check_wsi(struct lws *wsi, int priority_deleted_route)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int best_gw_priority = INT_MAX;
	char no_gw = 1;

	if (!wsi->sa46_peer.sa4.sin_family ||
	    wsi->desc.sockfd == LWS_SOCK_INVALID)
		/* not a socket or not connected, leave it alone */
		return 0;

	/*
	 * Given its peer address and the current routing table, assess if this
	 * connection is viable
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);
		lws_sockaddr46 *sa46 = &rou->dest;

		if (!sa46->sa4.sin_family)
			sa46 = &rou->gateway;

		if (!lws_sa46_on_net(&wsi->sa46_peer, sa46, rou->dest_len))
			/* yes, he has a network route */
			return 0;

		if (wsi->sa46_peer.sa4.sin_family == rou->dest.sa4.sin_family &&
		    rou->gateway.sa4.sin_family) {
			/* this guy isn't our net, but he has a gateway */
			no_gw = 0;
			if (rou->priority < best_gw_priority)
				best_gw_priority = rou->priority;
		}

	} lws_end_foreach_dll(d);

	/*
	 * No net matched... if also no gateway, he's had it.
	 *
	 * If we're scanning because we just deleted the best gateway route
	 * that, since no net route matched, he would have been using (eg,
	 * switch from wifi to lte) implying external IP change, he's had it.
	 *
	 * Otherwise with no net matched but an unchanged "best" gateway, leave
	 * him be.
	 */

	return no_gw || (priority_deleted_route != -1 &&
			 priority_deleted_route < best_gw_priority);
}

/*
 * priority_deleted_route should be -1 if no deleted route
 */

int
lws_route_pt_close_unroutable(struct lws_context_per_thread *pt,
			      int priority_deleted_route)
{
	struct lws *wsi;
	unsigned int n;

	for (n = 0; n < pt->fds_count; n++) {
		wsi = wsi_from_fd(pt->context, pt->fds[n].fd);
		if (!wsi)
			continue;

		if (lws_route_check_wsi(wsi, priority_deleted_route)) {
			lwsl_info("%s: culling wsi %p\n", __func__, wsi);
			lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
		}
	}

	return 0;
}
