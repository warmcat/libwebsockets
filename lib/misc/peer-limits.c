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
 */

#include <libwebsockets.h>
#include "private-lib-core.h"

/* requires context->lock */
static void
__lws_peer_remove_from_peer_wait_list(struct lws_context *context,
				      struct lws_peer *peer)
{
	if (lws_dll2_is_detached(&peer->wait_list))
		return;

	lws_dll2_remove(&peer->wait_list);

	if(lws_dll2_is_empty(&context->peer_wait_owner))
		lws_sul_cancel(&context->pt[0].sul_peer_limits);
}

void
lws_sul_peer_limits_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_peer_limits);

	lws_peer_cull_peer_wait_list(pt->context);

	lws_sul_schedule(pt->context, 0, &pt->context->pt[0].sul_peer_limits,
			 lws_sul_peer_limits_cb, 10 * LWS_US_PER_SEC);
}

/* requires context->lock */
static void
__lws_peer_add_to_peer_wait_list(struct lws_context *context,
				 struct lws_peer *peer)
{
	/* the unproven pseudo-peer lives as long as the context */
	if (peer == &context->peer_unproven)
		return;

	__lws_peer_remove_from_peer_wait_list(context, peer);

	lws_dll2_add_head(&peer->wait_list, &context->peer_wait_owner);

	if (!lws_dll2_owner(&context->pt[0].sul_peer_limits.list))
		lws_sul_schedule(context, 0, &context->pt[0].sul_peer_limits,
				lws_sul_peer_limits_cb, 10 * LWS_US_PER_SEC);
}


#define LWS_PL_ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define LWS_PL_SIPROUND(v) do { \
		v[0] += v[1]; v[1] = LWS_PL_ROTL(v[1], 13); v[1] ^= v[0]; \
		v[0] = LWS_PL_ROTL(v[0], 32); \
		v[2] += v[3]; v[3] = LWS_PL_ROTL(v[3], 16); v[3] ^= v[2]; \
		v[0] += v[3]; v[3] = LWS_PL_ROTL(v[3], 21); v[3] ^= v[0]; \
		v[2] += v[1]; v[1] = LWS_PL_ROTL(v[1], 17); v[1] ^= v[2]; \
		v[2] = LWS_PL_ROTL(v[2], 32); \
	} while (0)

static uint64_t
lws_pl_le64(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/*
 * SipHash-2-4 (Aumasson and Bernstein) of in, keyed by the context's random
 * pl_hash_key.  The bucket a host's peer goes in must not be predictable:
 * with a fixed function, anyone free to choose the address bits that are
 * hashed (an IPv6 site is routed 2^16 or more /64s) could put all its hosts
 * in one bucket, and have every peer lookup, done under the context lock,
 * walk a chain as long as it likes.
 */
static uint32_t
lws_pl_hash(const struct lws_context *context, const uint8_t *in, size_t len)
{
	uint64_t k0 = lws_pl_le64(context->pl_hash_key),
		 k1 = lws_pl_le64(context->pl_hash_key + 8), m, v[4];
	uint8_t last[8];
	size_t n;

	v[0] = k0 ^ 0x736f6d6570736575ull;
	v[1] = k1 ^ 0x646f72616e646f6dull;
	v[2] = k0 ^ 0x6c7967656e657261ull;
	v[3] = k1 ^ 0x7465646279746573ull;

	for (n = 0; n + 8 <= len; n += 8) {
		m = lws_pl_le64(in + n);
		v[3] ^= m;
		LWS_PL_SIPROUND(v);
		LWS_PL_SIPROUND(v);
		v[0] ^= m;
	}

	/* the last block: what is left of in, and its length in the top byte */
	memset(last, 0, sizeof(last));
	memcpy(last, in + n, len - n);
	last[7] = (uint8_t)len;
	m = lws_pl_le64(last);

	v[3] ^= m;
	LWS_PL_SIPROUND(v);
	LWS_PL_SIPROUND(v);
	v[0] ^= m;

	v[2] ^= 0xff;
	for (n = 0; n < 4; n++)
		LWS_PL_SIPROUND(v);

	m = v[0] ^ v[1] ^ v[2] ^ v[3];

	return (uint32_t)(m ^ (m >> 32));
}

/*
 * The peer for the host of the address in sa46, created if this is the first
 * we heard of it.  A peer is a host, as lws_sa46_host_key() and
 * lws_get_peer_host_key() key it: an IPv4 address, whether it came as one or
 * IPv4-mapped in IPv6, or an IPv6 /64, which one host commands the whole of
 * (2^64 source addresses), so counting each address of it separately would
 * not limit it at all.  The peer's sa46 is that host, eg, with the lower 64
 * bits of an IPv6 address zero, and no port.
 *
 * For connections that have no socket of their own to ask, such as QUIC
 * ones, which share their listener's, or clients named by a trusted PROXY v2
 * sender, as well as for those that do.
 */
struct lws_peer *
lws_get_or_create_peer_sa46(struct lws_vhost *vhost,
			    const lws_sockaddr46 *sa46in)
{
	struct lws_context *context = vhost->context;
	lws_sockaddr46 host;
	const uint8_t *hb;
	struct lws_peer *peer;
	uint32_t hash;
	size_t hlen;

	if (!context->pl_hash_elements)
		return NULL;

	hlen = lws_sa46_host(sa46in, &host, &hb);
	if (!hlen)
		/* neither IPv4 nor IPv6: nothing to count it against */
		return NULL;

	hash = lws_pl_hash(context, hb, hlen) % context->pl_hash_elements;

	lws_context_lock(context, "peer search"); /* <======================= */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      context->pl_hash_table[hash].head) {
		struct lws_peer *peerx = lws_container_of(d, struct lws_peer,
							 hash_list);
		/*
		 * Both are lws_sa46_host() results, zeroed apart from the
		 * family and the host's address bytes, so they are the same
		 * host exactly when they are the same bytes
		 */
		if (!memcmp(&peerx->sa46, &host, sizeof(host))) {
			/*
			 * We are handing out a peer that may be sitting on the
			 * wait list with an old time_closed_all, and the
			 * caller uses it after we drop the lock and before
			 * lws_peer_add_wsi() takes it off the list.  Refresh
			 * the timestamp so the cull (which runs from pt[0] and
			 * needs the peer to have been idle > 10s) cannot free
			 * it in that window.  If the caller then rejects the
			 * connection it stays on the wait list and is culled
			 * normally later.
			 */
			time(&peerx->time_closed_all);

			lws_context_unlock(context); /* === */

			return peerx;
		}
	} lws_end_foreach_dll(d);

	lwsl_info("%s: creating new peer\n", __func__);

	peer = lws_zalloc(sizeof(*peer), "peer");
	if (!peer) {
		lws_context_unlock(context); /* === */
		lwsl_err("%s: OOM for new peer\n", __func__);
		return NULL;
	}

	context->count_peers++;
	peer->hash = hash;
	peer->sa46 = host;
	lws_dll2_add_head(&peer->hash_list, &context->pl_hash_table[hash]);
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

/*
 * The peer a connection is accounted to: its own, from the address it would
 * be keyed on, if that is believable (see lws_io_peer_policy(), where
 * lws_get_peer_host_key() decides the same), else the context's one
 * unproven pseudo-peer, which every peer known only by hearsay shares, with
 * its own limit.  NULL if it has no peer to count.
 */
struct lws_peer *
lws_get_or_create_peer_wsi(struct lws *wsi)
{
	lws_sockaddr46 sa46;

	if (!wsi->a.vhost)
		return NULL;

	switch (lws_io_peer_policy(wsi, &sa46)) {
	case LWS_IO_PEER_POLICY_PROVEN:
		return lws_get_or_create_peer_sa46(wsi->a.vhost, &sa46);
	case LWS_IO_PEER_POLICY_UNPROVEN:
		return &wsi->a.context->peer_unproven;
	}

	return NULL;
}

/*
 * One connection, counted against *ppeer (or nothing, if NULL), is to be
 * counted against peer instead, eg, its address was proven.  Returns nonzero,
 * changing nothing, if peer is at its limit (and the connection must go).
 */
int
lws_peer_move_wsi(struct lws_context *context, struct lws_peer **ppeer,
		  struct lws_peer *peer, lws_sockfd_type sockfd)
{
	if (peer == *ppeer)
		return 0;

	if (lws_peer_wsi_limit_reached(context, peer, sockfd))
		return 1;

	lws_peer_add_wsi(context, peer, NULL);
	lws_peer_track_wsi_close(context, *ppeer);
	*ppeer = peer;

	return 0;
}

/* requires context->lock */
static int
__lws_peer_destroy(struct lws_context *context, struct lws_peer *peer)
{
	if (lws_dll2_is_detached(&peer->hash_list))
		return 1;

	lws_dll2_remove(&peer->hash_list);
	lws_free(peer);
	context->count_peers--;

	return 0;
}

void
lws_peer_cull_peer_wait_list(struct lws_context *context)
{
	struct lws_peer *df;
	time_t t;

	time(&t);

	if (context->next_cull && t < context->next_cull)
		return;

	lws_context_lock(context, "peer cull"); /* <========================= */

	context->next_cull = t + 5;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&context->peer_wait_owner)) {
		df = lws_container_of(d, struct lws_peer, wait_list);

		if (!(t - df->time_closed_all > 10))
			continue;

		/* remove us from the peer wait list */
		lws_dll2_remove(&df->wait_list);

		__lws_peer_destroy(context, df);
	} lws_end_foreach_dll_safe(d, d1);

	lws_context_unlock(context); /* ====================================> */
}

/*
 * Is peer already at ip_limit_wsi (for the unproven pseudo-peer,
 * unproven_limit_wsi), so that a new connection from it must be refused?  If
 * so pl_notify_cb, if any, is told, with sockfd the new connection's socket,
 * or LWS_SOCK_INVALID if it has none of its own, and the peer's address: the
 * one the connection is attributed to, or for the unproven pseudo-peer, none.
 */
int
lws_peer_wsi_limit_reached(struct lws_context *context, struct lws_peer *peer,
			   lws_sockfd_type sockfd)
{
	unsigned int limit = peer == &context->peer_unproven ?
				context->unproven_limit_wsi :
				context->ip_limit_wsi;

	if (!peer || !limit || peer->count_wsi < limit)
		return 0;

	lwsl_info("%s: %s reached wsi limit %u\n", __func__,
		  peer == &context->peer_unproven ? "unproven peers" : "peer",
		  limit);

	if (context->pl_notify_cb)
		context->pl_notify_cb(context, sockfd, &peer->sa46);

	return 1;
}

/*
 * Count a connection against peer.  wsi is the one it belongs to, whose close
 * gives it back, or NULL if the caller holds on to peer and gives it back
 * itself with lws_peer_track_wsi_close(), as a QUIC connection, which moves
 * between wsi in its life, does.
 */
void
lws_peer_add_wsi(struct lws_context *context, struct lws_peer *peer,
		 struct lws *wsi)
{
	if (!peer)
		return;

	lws_context_lock(context, "peer add"); /* <========================== */

	peer->count_wsi++;
	peer->total_wsi++;
	if (wsi)
		wsi->peer = peer;
	__lws_peer_remove_from_peer_wait_list(context, peer);

	lws_context_unlock(context); /* ====================================> */
}

void
lws_peer_dump_from_wsi(struct lws *wsi)
{
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	struct lws_peer *peer;

	if (!wsi || !wsi->peer)
		return;

	peer = wsi->peer;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	lwsl_notice("%s: %s: created %llu: wsi: %d/%d, ah %d/%d\n",
			__func__, lws_wsi_tag(wsi),
			(unsigned long long)peer->time_created,
			peer->count_wsi, peer->total_wsi,
			peer->http.count_ah, peer->http.total_ah);
#else
	lwsl_notice("%s: %s: created %llu: wsi: %d/%d\n", __func__,
			lws_wsi_tag(wsi),
			(unsigned long long)peer->time_created,
			peer->count_wsi, peer->total_wsi);
#endif
#endif
}

void
lws_peer_track_wsi_close(struct lws_context *context, struct lws_peer *peer)
{
	if (!peer)
		return;

	lws_context_lock(context, "peer wsi close"); /* <==================== */

	assert(peer->count_wsi);
	peer->count_wsi--;

	if (!peer->count_wsi
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
			&& !peer->http.count_ah
#endif
	) {
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

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
int
lws_peer_confirm_ah_attach_ok(struct lws_context *context,
			      struct lws_peer *peer)
{
	if (!peer)
		return 0;

	if (context->ip_limit_ah &&
	    peer->http.count_ah >= context->ip_limit_ah) {
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

	lws_context_lock(context, "peer ah detach"); /* <==================== */
	assert(peer->http.count_ah);
	if (peer->http.count_ah)
		peer->http.count_ah--;

	/*
	 * If the wsi that held this ah already closed, lws_peer_track_wsi_close
	 * declined to put the peer on the wait list because the ah was still
	 * outstanding.  Now it isn't, so the peer has nothing left and must go
	 * on the wait list, otherwise it can never be culled.
	 */

	if (!peer->count_wsi && !peer->http.count_ah) {
		time(&peer->time_closed_all);
		__lws_peer_add_to_peer_wait_list(context, peer);
	}

	lws_context_unlock(context); /* ====================================> */
}
#endif
