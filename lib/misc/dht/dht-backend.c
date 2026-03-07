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

LWS_VISIBLE int
lws_dht_nodes(struct lws_dht_ctx *ctx, int af, int *good_return, int *dubious_return, int *cached_return,
		int *incoming_return)
{
	int good = 0, dubious = 0, cached = 0, incoming = 0;
	struct bucket *b = af == AF_INET ? ctx->buckets : ctx->buckets6;

	while (b) {
		struct node *n = b->nodes;

		while (n) {
			if (node_good(ctx, n)) {
				good++;
				if (n->time > n->reply_time)
					incoming++;
			} else
				dubious++;

			n = n->next;
		}

		if (b->cached.ss_family > 0)
			cached++;
		b = b->next;
	}
	if (good_return)
		*good_return = good;
	if (dubious_return)
		*dubious_return = dubious;
	if (cached_return)
		*cached_return = cached;
	if (incoming_return)
		*incoming_return = incoming;

	return good + dubious;
}

void
lws_dht_periodic_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_ctx *ctx = lws_container_of(sul, struct lws_dht_ctx, sul);
	time_t tosleep = 10;

	ctx->now.tv_sec = (time_t)lws_now_secs();

	if (ctx->now.tv_sec >= ctx->rotate_secrets_time)
		rotate_secrets(ctx);

	if (ctx->now.tv_sec >= ctx->expire_stuff_time) {
		int soon = 0;

		expire_buckets(ctx, ctx->buckets);
		expire_buckets(ctx, ctx->buckets6);
		expire_storage(ctx);
		expire_searches(ctx);

		soon |= bucket_maintenance(ctx, AF_INET);
		soon |= bucket_maintenance(ctx, AF_INET6);
		ctx->expire_stuff_time = ctx->now.tv_sec + LWS_DHT_IDLE_EXPIRE_SECS;
		if (soon) {
			if (ctx->confirm_nodes_time == 0 ||
			    ctx->confirm_nodes_time > ctx->now.tv_sec + 2)
				ctx->confirm_nodes_time = ctx->now.tv_sec + 2;
		}
	}

	if (ctx->search_time > 0 && ctx->now.tv_sec >= ctx->search_time) {
		struct search *sr;

		sr = ctx->searches;
		while (sr) {
			if (!sr->done && sr->step_time + 5 <= ctx->now.tv_sec) {
				search_step(ctx, sr, ctx->cb, ctx->closure);
			}
			sr = sr->next;
		}

		ctx->search_time = 0;

		sr = ctx->searches;
		while (sr) {
			if (!sr->done) {
				time_t tm = sr->step_time + LWS_DHT_PING_TIMEOUT_SECS + ((lws_get_random(ctx->vhost->context, &tm, sizeof(tm)), tm) % 10);
				if (ctx->search_time == 0 || ctx->search_time > tm)
					ctx->search_time = tm;
			}
			sr = sr->next;
		}
	}

	if (ctx->confirm_nodes_time > 0 && ctx->now.tv_sec >= ctx->confirm_nodes_time) {
		int soon = neighbourhood_maintenance(ctx, AF_INET) |
			   neighbourhood_maintenance(ctx, AF_INET6);

		if (!soon) {
			if (ctx->mybucket_grow_time >= ctx->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(ctx, AF_INET);
			if (ctx->mybucket6_grow_time >= ctx->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(ctx, AF_INET6);
		}

		if (soon)
			ctx->confirm_nodes_time = ctx->now.tv_sec + 5 + ((lws_get_random(ctx->vhost->context, &soon, sizeof(soon)), soon) % 20);
		else
			ctx->confirm_nodes_time = ctx->now.tv_sec + 60 + ((lws_get_random(ctx->vhost->context, &soon, sizeof(soon)), soon) % 120);
	}

	if (ctx->confirm_nodes_time > ctx->now.tv_sec)
		tosleep = ctx->confirm_nodes_time - ctx->now.tv_sec;
	else
		tosleep = 0;

	if (ctx->search_time > 0) {
		if (ctx->search_time <= ctx->now.tv_sec)
			tosleep = 0;
		else if (tosleep > ctx->search_time - ctx->now.tv_sec)
			tosleep = ctx->search_time - ctx->now.tv_sec;
	}

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul,
			 lws_dht_periodic_cb, tosleep * LWS_US_PER_SEC);
}

int
lws_dht_get_nodes(struct lws_dht_ctx *ctx, struct sockaddr_in *sin, int *num,
		  struct sockaddr_in6 *sin6, int *num6)
{
	int i, j;
	struct bucket *b;
	struct node *n;

	i = 0;

	/*
	 * For restoring to work without discarding too many nodes, the list
	 * must start with the contents of our bucket.
	 */
	b = find_bucket(ctx, ctx->myid, AF_INET);
	if (b == NULL)
		goto no_ipv4;

	n = b->nodes;
	while (n && i < *num) {
		if (node_good(ctx, n)) {
			sin[i] = *(struct sockaddr_in*)&n->ss;
			i++;
		}
		n = n->next;
	}

	b = ctx->buckets;
	while (b && i < *num) {
		if (id_cmp(b->first, ctx->myid) <= 0 &&
				(b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0))
		{
			/* skip, handled above */
		} else {
			n = b->nodes;
			while (n && i < *num) {
				if (node_good(ctx, n)) {
					sin[i] = *(struct sockaddr_in*)&n->ss;
					i++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv4:

	j = 0;

	b = find_bucket(ctx, ctx->myid, AF_INET6);
	if (b == NULL)
		goto no_ipv6;

	n = b->nodes;
	while (n && j < *num6) {
		if (node_good(ctx, n)) {
			sin6[j] = *(struct sockaddr_in6*)&n->ss;
			j++;
		}
		n = n->next;
	}

	b = ctx->buckets6;
	while (b && j < *num6) {
		if (id_cmp(b->first, ctx->myid) <= 0 &&
		    (b->next == NULL || id_cmp(ctx->myid, b->next->first) < 0))
		{
			/* skip */
		} else {
			n = b->nodes;
			while (n && j < *num6) {
				if (node_good(ctx, n)) {
					sin6[j] = *(struct sockaddr_in6*)&n->ss;
					j++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv6:

	*num = i;
	*num6 = j;

	return i + j;
}

int
lws_dht_insert_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		    struct sockaddr *sa, size_t salen)
{
	struct node *node;

	switch (sa->sa_family) {
	case AF_INET:
	case AF_INET6:
		/*
		 * confirm=1 means we treat it as if we just heard from it, so it
		 * gets a timestamp and isn't immediately expired.
		 */
		node = maybe_new_node(ctx, id, sa, salen, 1);

		return !!node;
	default:
		break;
	}

	errno = EAFNOSUPPORT;

	return -1;
}
