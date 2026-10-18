/*
 * Copyright (c) 2009-2011 by Juliusz Chroboczek
 * Minor changes (c) 2018 Gwiz <gwiz2009@gmail.com>
 *   Added handler for implied port & hook for dhtdigg
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *   Adaptation for lws, cleaning, modernization
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "private-lib-misc-dht.h"

/* A struct storage stores all the stored peer addresses for a given info hash. */
struct storage *
find_storage(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->storage)) {
		struct storage *st = lws_container_of(d, struct storage, list);

		if (!id_cmp(id, st->id))
			return st;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * The storage for a hash, or a new one started for src, the host that sent
 * the announce or subscription, or for ourselves if src is NULL.
 *
 * The table is global and capped, so each source host (dht_source_key()) may
 * only start ctx->max_hashes_per_source of its entries: otherwise one host,
 * holding a valid token, fills it with made-up hashes and from then on no new
 * hash can be stored for anyone.  Hashes already stored take anyone's peers or
 * subscriptions, within the per-hash shares.
 */
struct storage *
storage_get(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
	    const struct sockaddr *src)
{
	uint8_t key[LWS_DHT_EXTVOTE_KEY_LEN];
	struct storage *st = find_storage(ctx, id);
	unsigned int held = 0;

	if (st)
		return st;

	if (lws_dll2_count(&ctx->storage) >= DHT_MAX_HASHES)
		return NULL;

	if (src) {
		if (dht_source_key(src, key))
			return NULL;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ctx->storage)) {
			st = lws_container_of(d, struct storage, list);

			if (st->src_af == src->sa_family &&
			    !memcmp(st->src, key, sizeof(key)))
				held++;
		} lws_end_foreach_dll(d);

		if (held >= ctx->max_hashes_per_source) {
			lwsl_dht_warn("%s: source has started its share of "
				      "%u hashes\n", __func__, held);
			return NULL;
		}
	}

	st = lws_zalloc(sizeof(struct storage), __func__);
	if (st == NULL)
		return NULL;

	st->id = lws_dht_hash_dup(id);
	if (!st->id) {
		lws_free(st);
		return NULL;
	}

	if (src) {
		memcpy(st->src, key, sizeof(key));
		st->src_af = (uint8_t)src->sa_family;
	}

	lws_dll2_add_head(&st->list, &ctx->storage);

	return st;
}

/* a stored peer's address, as a sockaddr */

static void
storage_peer_sa(const struct peer *p, lws_sockaddr46 *sa46)
{
	memset(sa46, 0, sizeof(*sa46));

	if (p->len == 4) {
		sa46->sa4.sin_family = AF_INET;
		memcpy(&sa46->sa4.sin_addr, p->ip, 4);
		return;
	}
#if defined(LWS_WITH_IPV6)
	sa46->sa6.sin6_family = AF_INET6;
	memcpy(&sa46->sa6.sin6_addr, p->ip, 16);
#endif
}

/*
 * Store sa:port as a peer for the hash id, for the source sa, or for
 * ourselves if ours.
 */
int
storage_store(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		const struct sockaddr *sa, unsigned short port, int ours)
{
	struct sockaddr_in *sin = (struct sockaddr_in*)sa;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
	lws_sockaddr46 psa;
	struct storage *st;
	struct peer *p;
	uint8_t *ip;
	int i, len, from_src = 0;

	switch (sa->sa_family) {
	case AF_INET:
		ip = (uint8_t*)&sin->sin_addr;
		len = 4;
		break;
	case AF_INET6:
		ip = (uint8_t*)&sin6->sin6_addr;
		len = 16;
		break;
	default:
		return -1;
	}

	st = storage_get(ctx, id, ours ? NULL : sa);
	if (!st)
		return -1;

	/*
	 * The announced port comes from the message rather than from the source
	 * socket, so without per-source accounting one host can fill all
	 * DHT_MAX_PEERS slots of every hash by itself.  We are already walking
	 * the array to dedup, so count this source's existing entries in the
	 * same pass and refuse it more than its share.  A source is a host,
	 * dht_source_key(), so an IPv6 /64 is one source however many of its
	 * addresses it announces from.
	 */
	for (i = 0; i < st->numpeers; i++) {
		storage_peer_sa(&st->peers[i], &psa);
		if (!lws_dht_same_host((const struct sockaddr *)&psa, sa))
			continue;

		if (st->peers[i].len == len &&
		    !memcmp(st->peers[i].ip, ip, (size_t)len) &&
		    st->peers[i].port == port)
			break;

		from_src++;
	}

	if (i >= st->numpeers && from_src >= LWS_DHT_MAX_PEERS_PER_SRC) {
		lwsl_dht_warn("%s: source announce limit reached\n", __func__);

		return 0;
	}

	if (i < st->numpeers) {
		/* Already there, only need to refresh */
		st->peers[i].time = ctx->now;

		return 0;
	}

	if (i >= st->maxpeers) {
		/* Need to expand the array. */
		struct peer *new_peers;
		int n;

		if (st->maxpeers >= DHT_MAX_PEERS)
			return 0;
		n = st->maxpeers == 0 ? 2 : 2 * st->maxpeers;
		n = MIN(n, DHT_MAX_PEERS);
		new_peers = lws_realloc(st->peers, (size_t)n * sizeof(struct peer), __func__);
		if (new_peers == NULL)
			return -1;
		st->peers	= new_peers;
		st->maxpeers	= n;
	}

	p		= &st->peers[st->numpeers++];
	p->time		= ctx->now;
	p->len		= (unsigned short)len;
	memcpy(p->ip, ip, (size_t)len);
	p->port		= port;

	return 1;
}

int
expire_storage(struct lws_dht_ctx *ctx)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&ctx->storage)) {
		struct storage *st = lws_container_of(d, struct storage, list);
		int i = 0;

		while (i < st->numpeers) {
			if (st->peers[i].time < ctx->now - 32 * 60) {
				if (i != st->numpeers - 1)
					st->peers[i] = st->peers[st->numpeers - 1];
				st->numpeers--;
				continue;
			}
			i++;
		}

		/*
		 * Nothing else reaps subscribers, so an expired one used to
		 * live until the whole storage object went away.  Drop them
		 * here on their own 1h TTL.
		 */
		lws_start_foreach_dll_safe(struct lws_dll2 *, ds, ds1,
					   lws_dll2_get_head(&st->subscribers)) {
			struct subscriber *sub = lws_container_of(ds,
						struct subscriber, list);

			if (sub->expire <= ctx->now) {
				lws_dll2_remove(ds);
				lws_free(sub);
			}
		} lws_end_foreach_dll_safe(ds, ds1);

		/*
		 * Only retire the storage object once it has neither peers nor
		 * subscribers: destroying it while subscribers remain silently
		 * cancelled subscriptions on a hash with no announced peers.
		 */
		if (st->numpeers == 0 && lws_dll2_is_empty(&st->subscribers)) {
			lws_dll2_remove(d);

			lws_free(st->peers);
			lws_dht_hash_destroy(&st->id);
			lws_free(st);
		}
	} lws_end_foreach_dll_safe(d, d1);

	return 1;
}
