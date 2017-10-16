/*
 * libwebsockets - peer limits tracking
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"

/* requires context->lock */
static void
__lws_peer_remove_from_peer_wait_list(struct lws_context *context,
				      struct lws_peer *peer)
{
	struct lws_peer *df;

	lws_start_foreach_llp(struct lws_peer **, p, context->peer_wait_list) {
		if (*p == peer) {
			df = *p;

			*p = df->peer_wait_list;
			df->peer_wait_list = NULL;

			return;
		}
	} lws_end_foreach_llp(p, peer_wait_list);
}

/* requires context->lock */
static void
__lws_peer_add_to_peer_wait_list(struct lws_context *context,
				 struct lws_peer *peer)
{
	__lws_peer_remove_from_peer_wait_list(context, peer);

	peer->peer_wait_list = context->peer_wait_list;
	context->peer_wait_list = peer;
}


struct lws_peer *
lws_get_or_create_peer(struct lws_vhost *vhost, lws_sockfd_type sockfd)
{
	struct lws_context *context = vhost->context;
	socklen_t rlen = 0;
	void *q;
	uint8_t *q8;
	struct lws_peer *peer;
	uint32_t hash = 0;
	int n, af = AF_INET;
	struct sockaddr_storage addr;

#ifdef LWS_WITH_IPV6
	if (LWS_IPV6_ENABLED(vhost)) {
		af = AF_INET6;
	}
#endif
	rlen = sizeof(addr);
	if (getpeername(sockfd, (struct sockaddr*)&addr, &rlen))
		return NULL;

	if (af == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		q = &s->sin_addr;
		rlen = sizeof(s->sin_addr);
	} else
#ifdef LWS_WITH_IPV6
	{
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		q = &s->sin6_addr;
		rlen = sizeof(s->sin6_addr);
	}
#else
		return NULL;
#endif

	q8 = q;
	for (n = 0; n < rlen; n++)
		hash = (((hash << 4) | (hash >> 28)) * n) ^ q8[n];

	hash = hash % context->pl_hash_elements;

	lws_context_lock(context); /* <====================================== */

	lws_start_foreach_ll(struct lws_peer *, peerx,
			     context->pl_hash_table[hash]) {
		if (peerx->af == af && !memcmp(q, peerx->addr, rlen)) {
			lws_context_unlock(context); /* === */
			return peerx;
		}
	} lws_end_foreach_ll(peerx, next);

	lwsl_info("%s: creating new peer\n", __func__);

	peer = lws_zalloc(sizeof(*peer), "peer");
	if (!peer) {
		lws_context_unlock(context); /* === */
		return NULL;
	}

	context->count_peers++;
	peer->next = context->pl_hash_table[hash];
	peer->hash = hash;
	peer->af = af;
	context->pl_hash_table[hash] = peer;
	memcpy(peer->addr, q, rlen);
	time(&peer->time_created);
	/*
	 * On creation, the peer has no wsi attached, so is created on the
	 * wait list.  When a wsi is added it is removed from the wait list.
	 */
	time(&peer->time_closed_all);
	__lws_peer_add_to_peer_wait_list(context, peer);

	lws_context_unlock(context); /* ====================================> */

	return peer;
}

/* requires context->lock */
static int
__lws_peer_destroy(struct lws_context *context, struct lws_peer *peer)
{
	lws_start_foreach_llp(struct lws_peer **, p,
			      context->pl_hash_table[peer->hash]) {
		if (*p == peer) {
			struct lws_peer *df = *p;
			*p = df->next;
			lws_free(df);
			context->count_peers--;

			return 0;
		}
	} lws_end_foreach_llp(p, next);

	return 1;
}

void
lws_peer_cull_peer_wait_list(struct lws_context *context)
{
	struct lws_peer *df;
	time_t t;

	time(&t);

	if (context->next_cull && t < context->next_cull)
		return;

	lws_context_lock(context); /* <====================================== */

	context->next_cull = t + 5;

	lws_start_foreach_llp(struct lws_peer **, p, context->peer_wait_list) {
		if (t - (*p)->time_closed_all > 10) {
			df = *p;

			/* remove us from the peer wait list */
			*p = df->peer_wait_list;
			df->peer_wait_list = NULL;

			__lws_peer_destroy(context, df);
			continue; /* we already point to next, if any */
		}
	} lws_end_foreach_llp(p, peer_wait_list);

	lws_context_unlock(context); /* ====================================> */
}

void
lws_peer_add_wsi(struct lws_context *context, struct lws_peer *peer,
		 struct lws *wsi)
{
	if (!peer)
		return;

	lws_context_lock(context); /* <====================================== */

	peer->count_wsi++;
	wsi->peer = peer;
	__lws_peer_remove_from_peer_wait_list(context, peer);

	lws_context_unlock(context); /* ====================================> */
}

void
lws_peer_track_wsi_close(struct lws_context *context, struct lws_peer *peer)
{
	if (!peer)
		return;

	lws_context_lock(context); /* <====================================== */

	assert(peer->count_wsi);
	peer->count_wsi--;

	if (!peer->count_wsi && !peer->count_ah) {
		/*
		 * in order that we can accumulate peer activity correctly
		 * allowing for periods when the peer has no connections,
		 * we don't synchronously destroy the peer when his last
		 * wsi closes.  Instead we mark the time his last wsi
		 * closed and add him to a peer_wait_list to be reaped
		 * later if no further activity is coming.
		 */
		time(&peer->time_closed_all);
		__lws_peer_add_to_peer_wait_list(context, peer);
	}

	lws_context_unlock(context); /* ====================================> */
}

int
lws_peer_confirm_ah_attach_ok(struct lws_context *context, struct lws_peer *peer)
{
	if (!peer)
		return 0;

	if (context->ip_limit_ah && peer->count_ah >= context->ip_limit_ah) {
		lwsl_info("peer reached ah limit %d, deferring\n",
				context->ip_limit_ah);

		return 1;
	}

	return 0;
}

void
lws_peer_track_ah_detach(struct lws_context *context, struct lws_peer *peer)
{
	if (!peer)
		return;

	assert(peer->count_ah);
	peer->count_ah--;
}

