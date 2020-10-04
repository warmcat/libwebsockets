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
 * Everything here is _ because the caller needs to hold the pt lock in order
 * to access the pt routing table safely
 */

#include <private-lib-core.h>

#if defined(_DEBUG)
void
_lws_routing_entry_dump(lws_route_t *rou)
{
	char da[48], gw[48];

	lws_sa46_write_numeric_address(&rou->dest, da, sizeof(da));
	lws_sa46_write_numeric_address(&rou->gateway, gw, sizeof(gw));

	lwsl_info("  (%d)%s/%d, gw: (%d)%s, ifidx: %d, pri: %d, proto: %d\n",
		    rou->dest.sa4.sin_family, da, rou->dest_len,
		    rou->gateway.sa4.sin_family, gw,
		    rou->if_idx, rou->priority, rou->proto);
}

void
_lws_routing_table_dump(struct lws_context_per_thread *pt)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);

		_lws_routing_entry_dump(rou);
	} lws_end_foreach_dll(d);
}
#endif

/*
 * We will provide a "fingerprint ordinal" as the route uidx that is unique in
 * the routing table.  Wsi that connect mark themselves with the uidx of the
 * route they are estimated to be using.
 *
 * This lets us detect things like gw changes, eg when switching from wlan to
 * lte there may still be a valid gateway route, but all existing tcp
 * connections previously using the wlan gateway will be broken, since their
 * connections are from its gateway to the peer.
 *
 * So when we take down a route, we take care to look for any wsi that was
 * estimated to be using that route, eg, for gateway, and close those wsi.
 *
 * It's OK if the route uidx wraps, we explicitly confirm nobody else is using
 * the uidx before assigning one to a new route.
 */

lws_route_uidx_t
_lws_route_get_uidx(struct lws_context_per_thread *pt)
{
	while (1) {
		char again = 0;

		/* Anybody in the table already uses the pt's next uidx? */

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&pt->routing_table)) {
			lws_route_t *rou = lws_container_of(d, lws_route_t, list);

			if (rou->uidx == pt->route_uidx) {
				/* if so, bump and restart the check */
				pt->route_uidx++;
				again = 1;
			}
		} lws_end_foreach_dll(d);

		if (!again)
			return pt->route_uidx++;
	}
}

int
_lws_route_remove(struct lws_context_per_thread *pt, lws_route_t *robj)
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
			_lws_route_pt_close_route_users(pt, robj->uidx);
			lws_dll2_remove(&rou->list);
			lws_free(rou);

			return 0;
		}

	} lws_end_foreach_dll(d);

	return 1;
}

void
_lws_route_table_empty(struct lws_context_per_thread *pt)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);
		lws_dll2_remove(&rou->list);
		lws_free(rou);

	} lws_end_foreach_dll_safe(d, d1);
}

void
_lws_route_table_ifdown(struct lws_context_per_thread *pt, int idx)
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

lws_route_t *
_lws_route_est_outgoing(struct lws_context_per_thread *pt,
		        const lws_sockaddr46 *dest)
{
	lws_route_t *best_gw = NULL;
	int best_gw_priority = INT_MAX;

	if (!dest->sa4.sin_family) {
		lwsl_notice("%s: dest has 0 AF\n", __func__);
		/* leave it alone */
		return NULL;
	}

	/*
	 * Given the dest address and the current routing table, select the
	 * route we think it would go out on
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->routing_table)) {
		lws_route_t *rou = lws_container_of(d, lws_route_t, list);

		// _lws_routing_entry_dump(rou);

		if (rou->dest.sa4.sin_family &&
		    !lws_sa46_on_net(dest, &rou->dest, rou->dest_len)) {
			/*
			 * Yes, he has a matching network route, it beats out
			 * any gateway route.  This is like finding a route for
			 * 192.168.0.0/24 when dest is 192.168.0.1.
			 */

			// lwsl_notice("%s: returning %p\n", __func__, rou);

			return rou;
		}

		lwsl_debug("%s: dest af %d, rou gw af %d, pri %d\n", __func__,
				dest->sa4.sin_family,
				rou->gateway.sa4.sin_family, rou->priority);

		if (rou->gateway.sa4.sin_family &&

			/*
			 *  dest  gw
			 *   4     4    OK
			 *   4     6    OK with ::ffff:x:x
			 *   6     4    not supported directly
			 *   6     6    OK
			 */

		    (dest->sa4.sin_family == rou->gateway.sa4.sin_family ||
			(dest->sa4.sin_family == AF_INET &&
			 rou->gateway.sa4.sin_family == AF_INET6)) &&
		    rou->priority < best_gw_priority) {
			lwsl_info("%s: gw hit\n", __func__);
			best_gw_priority = rou->priority;
			best_gw = rou;
		}

	} lws_end_foreach_dll(d);

	/*
	 * Either best_gw is the best gw route and we set *best_gw_priority to
	 * the best one's priority, or we're returning NULL as no network or
	 * gw route for dest.
	 */

	lwsl_info("%s: returning %p\n", __func__, best_gw);

	return best_gw;
}

int
_lws_route_check_wsi(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	if (!wsi->sa46_peer.sa4.sin_family ||
	    wsi->desc.sockfd == LWS_SOCK_INVALID)
		/* not a socket or not connected, leave it alone */
		return 0; /* OK */

	return !_lws_route_est_outgoing(pt, &wsi->sa46_peer);
}

/*
 * priority_deleted_route should be -1 if no deleted route
 */

int
_lws_route_pt_close_unroutable(struct lws_context_per_thread *pt)
{
	struct lws *wsi;
	unsigned int n;

	if (!pt->context->nl_initial_done ||
	    pt->context->mgr_system.state < LWS_SYSTATE_IFACE_COLDPLUG)
		return 0;

	for (n = 0; n < pt->fds_count; n++) {
		wsi = wsi_from_fd(pt->context, pt->fds[n].fd);
		if (!wsi)
			continue;

		if (_lws_route_check_wsi(wsi)) {
			lwsl_info("%s: culling wsi %p\n", __func__, wsi);
			lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
		}
	}

	return 0;
}

int
_lws_route_pt_close_route_users(struct lws_context_per_thread *pt,
			       lws_route_uidx_t uidx)
{
	struct lws *wsi;
	unsigned int n;

	for (n = 0; n < pt->fds_count; n++) {
		wsi = wsi_from_fd(pt->context, pt->fds[n].fd);
		if (!wsi)
			continue;

		if (wsi->desc.sockfd != LWS_SOCK_INVALID &&
		    wsi->sa46_peer.sa4.sin_family &&
		    wsi->peer_route_uidx == uidx) {
			lwsl_info("%s: culling wsi %p\n", __func__, wsi);
			lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
		}
	}

	return 0;
}
