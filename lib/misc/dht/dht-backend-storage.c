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
	struct storage *st = ctx->storage;

	while (st) {
		if (!id_cmp(id, st->id))
			break;
		st = st->next;
	}

	return st;
}

int
storage_store(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		const struct sockaddr *sa, unsigned short port)
{
	struct sockaddr_in *sin = (struct sockaddr_in*)sa;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
	struct storage *st;
	struct peer *p;
	uint8_t *ip;
	int i, len;

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

	st = find_storage(ctx, id);

	if (st == NULL) {
		if (ctx->numstorage >= DHT_MAX_HASHES)
			return -1;

		st = lws_zalloc(sizeof(struct storage), __func__);
		if (st == NULL)
			return -1;
		st->id			= lws_dht_hash_dup(id);
		if (!st->id) {
			lws_free(st);
			return -1;
		}
		st->next	= ctx->storage;
		ctx->storage	= st;
		ctx->numstorage++;
	}

	for (i = 0; i < st->numpeers; i++)
		if (st->peers[i].port == port && st->peers[i].len == len &&
		    !memcmp(st->peers[i].ip, ip, (size_t)len))
			break;

	if (i < st->numpeers) {
		/* Already there, only need to refresh */
		st->peers[i].time = ctx->now.tv_sec;

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
	p->time		= ctx->now.tv_sec;
	p->len		= (unsigned short)len;
	memcpy(p->ip, ip, (size_t)len);
	p->port		= port;

	return 1;
}

int
expire_storage(struct lws_dht_ctx *ctx)
{
	struct storage *st = ctx->storage, *previous = NULL;
	while (st) {
		int i = 0;
		while (i < st->numpeers) {
			if (st->peers[i].time < ctx->now.tv_sec - 32 * 60) {
				if (i != st->numpeers - 1)
					st->peers[i] = st->peers[st->numpeers - 1];
				st->numpeers--;
				continue;
			}
			i++;
		}

		if (st->numpeers == 0) {
			lws_free(st->peers);
			if (previous)
				previous->next = st->next;
			else
				ctx->storage = st->next;
			lws_dht_hash_destroy(&st->id);
			lws_free(st->peers);
			lws_free(st);
			if (previous)
				st = previous->next;
			else
				st = ctx->storage;
			ctx->numstorage--;
			if (ctx->numstorage < 0) {
				lwsl_dht_err("%s: Eek... numstorage became negative\n", __func__);
				ctx->numstorage = 0;
			}
		} else {
			previous = st;
			st = st->next;
		}
	}
	return 1;
}

