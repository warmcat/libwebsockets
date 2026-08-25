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

struct bucket *
find_bucket(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af)
{
	struct bucket *b = bucket_head(ctx, af);

	if (!b)
		return NULL;

	while (1) {
		struct bucket *nb = bucket_next(b);

		if (!nb || id_cmp(id, nb->first) < 0)
			return b;

		b = nb;
	}
}

struct bucket *
previous_bucket(struct bucket *b)
{
	if (!lws_dll2_get_prev(&b->list))
		return NULL;

	return lws_container_of(lws_dll2_get_prev(&b->list), struct bucket, list);
}

/* Every bucket contains an unordered list of nodes. */
struct node *
find_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int af)
{
	struct bucket *b = find_bucket(ctx, id, af);

	if (!b)
		return NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
		struct node *n = lws_container_of(d, struct node, list);

		if (!id_cmp(n->id, id))
			return n;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* Return a random node in a bucket. */
static struct node *
random_node(struct lws_dht_ctx *ctx, struct bucket *b)
{
	lws_dll2_t *d;
	int nn;

	if (!lws_dll2_count(&b->nodes))
		return NULL;

	nn = (int)(lws_get_random(ctx->vhost->context, &nn, sizeof(nn)) %
		   (unsigned int)lws_dll2_count(&b->nodes));
	d = lws_dll2_get_head(&b->nodes);

	while (nn > 0 && d) {
		d = lws_dll2_get_next(d);
		nn--;
	}

	return d ? lws_container_of(d, struct node, list) : NULL;
}

/* Return the middle id of a bucket. */
static int
bucket_middle(struct bucket *b, lws_dht_hash_t *id_return)
{
	struct bucket *nb = bucket_next(b);
	int bit1 = lowbit(b->first);
	int bit2 = nb ? lowbit(nb->first) : -1;
	int max_bits = id_return->len * 8;
	int bit;
	size_t bidx;

	if (max_bits > 2040)
		max_bits = 2040;

	if (bit1 >= max_bits) bit1 = max_bits - 1;
	if (bit2 >= max_bits) bit2 = max_bits - 1;

	if (bit1 < -1) bit1 = -1;
	if (bit2 < -1) bit2 = -1;

	bit = MAX(bit1, bit2) + 1;
	if (bit < 0 || bit >= max_bits)
		return -1;

	bidx = (size_t)bit / 8u;
	memcpy(id_return->id, b->first->id, b->first->len);
	id_return->id[bidx] = (uint8_t)(id_return->id[bidx] | (0x80 >> (bit % 8)));

	return 1;
}

/* Return a random id within a bucket. */
static int
bucket_random(struct lws_dht_ctx *ctx, struct bucket *b, lws_dht_hash_t *id_return)
{
	struct bucket *nb = bucket_next(b);
	int i, r, bit, bit1 = lowbit(b->first);
	int bit2 = nb ? lowbit(nb->first) : -1;
	int max_bits = id_return->len * 8;
	size_t bidx;

	if (max_bits > 2040)
		max_bits = 2040;

	if (bit1 >= max_bits)
		bit1 = max_bits - 1;
	if (bit2 >= max_bits)
		bit2 = max_bits - 1;

	if (bit1 < -1)
		bit1 = -1;
	if (bit2 < -1)
		bit2 = -1;

	bit = MAX(bit1, bit2) + 1;

	if (bit < 0 || bit >= max_bits) {
		memcpy(id_return->id, b->first->id, b->first->len);
		return 1;
	}

	bidx = (size_t)bit / 8u;
	memcpy(id_return->id, b->first->id, bidx);
	lws_get_random(ctx->vhost->context, &r, sizeof(r));
	id_return->id[bidx] = (uint8_t)(b->first->id[bidx] & (0xFF00 >> (bit % 8)));
	id_return->id[bidx] |= (uint8_t)(r & (0xFF >> (bit % 8)));

	for (i = bit / 8 + 1; i < id_return->len; i++) {
		lws_get_random(ctx->vhost->context, &r, sizeof(r));
		id_return->id[i] = (uint8_t)(r & 0xff);
	}

	return 1;
}

/* Insert a new node into a bucket. */
static struct node *
insert_node(struct lws_dht_ctx *ctx, struct node *node)
{
	struct bucket *b = find_bucket(ctx, node->id, node->ss.ss_family);

	if (b == NULL)
		return NULL;

	lws_dll2_add_head(&node->list, &b->nodes);

	return node;
}

/* This is our definition of a known-good node. */
int
node_good(struct lws_dht_ctx *ctx, struct node *node)
{
	return node->pinged <= 2 &&
		node->reply_time >= ctx->now.tv_sec - LWS_DHT_NODE_EXPIRE_SECS &&
		node->time >= ctx->now.tv_sec - 900;
}

/*
 * The internal blacklist is an LRU cache of nodes that have sent
 * incorrect messages.
 */
void
blacklist_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, const struct sockaddr *sa, size_t salen)
{
	int i;

	lwsl_dht_warn("Blacklisting broken node.\n");

	if (id) {
		struct node *n;

		/* Make the node easy to discard. */
		n = find_node(ctx, id, sa->sa_family);
		if (n) {
			n->pinged = LWS_DHT_MAX_PING_FAILURES;
			mark_as_pinged(ctx, n, NULL);
		}
		/* Discard it from any searches in progress. */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ctx->searches)) {
			struct search *sr = lws_container_of(d, struct search, list);

			for (i = 0; i < sr->numnodes; i++)
				if (id_cmp(sr->nodes[i].id, id) == 0)
					flush_search_node(&sr->nodes[i], sr);
		} lws_end_foreach_dll(d);
	}

	/* And make sure we don't hear from it again. */
	if (ctx->next_blacklisted >= DHT_MAX_BLACKLISTED)
		ctx->next_blacklisted = 0;

	if (salen > sizeof(ctx->blacklist[0]))
		salen = sizeof(ctx->blacklist[0]);

	memcpy(&ctx->blacklist[ctx->next_blacklisted], sa, salen);
	ctx->next_blacklisted++;
}

/* Split a bucket into two equal parts. */
static struct bucket *
split_bucket(struct lws_dht_ctx *ctx, struct bucket *b)
{
	lws_dht_hash_t *new_id;
	struct bucket *new;
	int rc;

	new_id = lws_dht_hash_dup(b->first);
	if (!new_id)
		return NULL;

	rc = bucket_middle(b, new_id);
	if (rc < 0) {
		lws_dht_hash_destroy(&new_id);
		return NULL;
	}

	new = lws_zalloc(sizeof(struct bucket), __func__);
	if (new == NULL) {
		lws_dht_hash_destroy(&new_id);
		return NULL;
	}

	new->af = b->af;

	send_cached_ping(ctx, b);

	new->first = new_id;
	new->time = b->time;

	/* the new bucket takes its place in the chain directly after b */

	lws_dll2_add_insert(&new->list, &b->list);

	/*
	 * redistribute b's nodes between the two buckets.  The loop body
	 * removes the current node and re-adds it, possibly back on to the
	 * head of this same list; the _safe iterator's cached next is never
	 * itself removed, so it keeps walking the original members.
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&b->nodes)) {
		struct node *n = lws_container_of(d, struct node, list);

		lws_dll2_remove(d);
		insert_node(ctx, n);
	} lws_end_foreach_dll_safe(d, d1);

	return b;
}

/*
 * We just learnt about a node, not necessarily a new one.  Confirm is 1 if
 * the node sent a message, 2 if it sent us a reply.
 */
struct node *
maybe_new_node(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		const struct sockaddr *sa, size_t salen,
		int confirm)
{
	struct bucket *b = find_bucket(ctx, id, sa->sa_family);
	struct bucket *nb;
	struct node *n;
	int mybucket, split;

	lwsl_dht_info("%s: id %02x, confirm %d\n", __func__, id->id[0], confirm);

	if (b == NULL) {
		lwsl_dht_warn("%s: bucket not found\n", __func__);
		return NULL;
	}

	nb = bucket_next(b);
	if (id_cmp(id, ctx->myid) == 0) {
		lwsl_dht_warn("%s: same id\n", __func__);
		return NULL;
	}

	if (is_martian(sa) || node_blacklisted(ctx, sa, salen)) {
		char buf[64] = "unknown";
		lws_sa46_write_numeric_address((lws_sockaddr46 *)sa, buf, sizeof(buf));
		lwsl_dht_warn("%s: martian or blacklisted: %s\n", __func__, buf);
		return NULL;
	}

	mybucket = id_cmp(b->first, ctx->myid) <= 0 &&
		   (nb == NULL || id_cmp(ctx->myid, nb->first) < 0);

	if (confirm == 2)
		b->time = (int)ctx->now.tv_sec;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
		n = lws_container_of(d, struct node, list);

		if (!id_cmp(n->id, id)) {
			if (confirm || n->time < ctx->now.tv_sec - LWS_DHT_NODE_MAX_IDLE_SECS) {
				/* Known node.  Update stuff. */
				memcpy((struct sockaddr*)&n->ss, sa, salen);
				if (confirm)
					n->time = ctx->now.tv_sec;
				if (confirm >= 2) {
					n->reply_time = ctx->now.tv_sec;
					n->pinged = 0;
					n->pinged_time = 0;
				}
			}
			return n;
		}
	} lws_end_foreach_dll(d);

	/* New node. */

	if (mybucket) {
		if (sa->sa_family == AF_INET)
			ctx->mybucket_grow_time = ctx->now.tv_sec;
		else
			ctx->mybucket6_grow_time = ctx->now.tv_sec;
	}

	/* First, try to get rid of a known-bad node. */
	lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&b->nodes)) {
		n = lws_container_of(d2, struct node, list);

		if (n->pinged >= LWS_DHT_MAX_PING_FAILURES &&
		    n->pinged_time < ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS) {
			lws_dht_hash_destroy(&n->id);
			n->id = lws_dht_hash_dup(id);
			if (!n->id) {
				// Should we remove node from bucket? For now keep but it's broken
				return NULL;
			}
			memcpy((struct sockaddr*)&n->ss, sa, salen);
			n->time = confirm ? ctx->now.tv_sec : 0;
			n->reply_time = confirm >= 2 ? ctx->now.tv_sec : 0;
			n->pinged_time = 0;
			n->pinged = 0;
			return n;
		}
	} lws_end_foreach_dll(d2);

	if (lws_dll2_count(&b->nodes) >= 8) {
		/* Bucket full.  Ping a dubious node */
		int dubious = 0;

		lws_start_foreach_dll(struct lws_dll2 *, d3, lws_dll2_get_head(&b->nodes)) {
			n = lws_container_of(d3, struct node, list);

			/*
			 * Pick the first dubious node that we haven't pinged in the
			 * last 15 seconds.  This gives nodes the time to reply, but
			 * tends to concentrate on the same nodes, so that we get rid
			 * of bad nodes fast.
			 */
			if (!node_good(ctx, n)) {
				dubious = 1;
				if (n->pinged_time < ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS) {
					uint8_t tid[4];
					lwsl_dht_info("Sending ping to dubious node.\n");
					make_tid(tid, "pn", 0);
					send_ping(ctx, (struct sockaddr*)&n->ss, n->sslen,
							tid, 4);
					mark_as_pinged(ctx, n, b);
					break;
				}
			}
		} lws_end_foreach_dll(d3);

		split = 0;
		if (mybucket) {
			if (!dubious)
				split = 1;
			/*
			 * If there's only one bucket, split eagerly.  This is
			 * incorrect unless there's more than 8 nodes in the DHT.
			 */
			else if (b->af == AF_INET && !bucket_next(bucket_head(ctx, AF_INET)))
				split = 1;
			else if (b->af == AF_INET6 && !bucket_next(bucket_head(ctx, AF_INET6)))
				split = 1;
		}

		if (split) {
			lwsl_dht_info("Splitting.\n");
			b = split_bucket(ctx, b);
			return maybe_new_node(ctx, id, sa, salen, confirm);
		}

		/* No space for this node.  Cache it away for later. */
		if (confirm || b->cached.ss_family == 0) {
			memcpy(&b->cached, sa, salen);
			b->cachedlen = salen;
		}

		return NULL;
	}

	/* Create a new node. */

	n = lws_zalloc(sizeof(struct node), __func__);
	if (!n)
		return NULL;
	n->id = lws_dht_hash_dup(id);
	if (!n->id) {
		lws_free(n);
		return NULL;
	}

	memcpy(&n->ss, sa, (size_t)salen);

	n->sslen		= salen;
	n->time			= confirm ? ctx->now.tv_sec : 0;
	n->reply_time		= confirm >= 2 ? ctx->now.tv_sec : 0;
	n->pinged_time		= 0;
	n->pinged		= 0;

	insert_node(ctx, n);

	return n;
}

/*
 * Called periodically to purge known-bad nodes.  Note that we're very
 * conservative here: broken nodes in the table don't do much harm, we'll
 * recover as soon as we find better ones.
 */
int
expire_buckets(struct lws_dht_ctx *ctx, lws_dll2_owner_t *bo)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(bo)) {
		struct bucket *b = lws_container_of(d, struct bucket, list);
		int changed = 0;

		lws_start_foreach_dll_safe(struct lws_dll2 *, nd, nd1,
					   lws_dll2_get_head(&b->nodes)) {
			struct node *n = lws_container_of(nd, struct node, list);

			if (n->pinged >= LWS_DHT_NODE_DROP_FAILURES) {
				lws_dll2_remove(nd);
				changed = 1;
				lws_dht_hash_destroy(&n->id);
				lws_free(n);
			}
		} lws_end_foreach_dll_safe(nd, nd1);

		if (changed)
			send_cached_ping(ctx, b);

	} lws_end_foreach_dll_safe(d, d1);

	ctx->expire_stuff_time = ctx->now.tv_sec + LWS_DHT_IDLE_EXPIRE_SECS + ((lws_get_random(ctx->vhost->context, &ctx->expire_stuff_time, sizeof(ctx->expire_stuff_time)), ctx->expire_stuff_time) % (2 * LWS_DHT_IDLE_EXPIRE_SECS));

	return 1;
}

static void
dump_bucket(struct lws_dht_ctx *ctx, struct bucket *b)
{
	lwsl_dht_info("Bucket ");
	lwsl_hexdump_dht(b->first->id, b->first->len);
	lwsl_dht_info(" count %u age %d%s%s:\n",
			(unsigned int)lws_dll2_count(&b->nodes),
			(int)(ctx->now.tv_sec - b->time),
			(id_cmp(b->first, ctx->myid) <= 0 &&
			 (bucket_next(b) == NULL ||
			  id_cmp(ctx->myid, bucket_next(b)->first) < 0)) ?
			" (my bucket)" : "",
			b->cached.ss_family ? " (has cached)" : "");

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
		struct node *n = lws_container_of(d, struct node, list);
		char buf[64];
		unsigned short port;

		lwsl_dht_info("    Node ");
		lwsl_hexdump_dht(n->id->id, n->id->len);
		switch (n->ss.ss_family) {
		case AF_INET:
			lws_sa46_write_numeric_address((lws_sockaddr46 *)&n->ss, buf, sizeof(buf));
			port = ntohs(((struct sockaddr_in*)&n->ss)->sin_port);
			lwsl_dht_info(" %s:%d ", buf, port);
			break;
		case AF_INET6:
			lws_sa46_write_numeric_address((lws_sockaddr46 *)&n->ss, buf, sizeof(buf));
			port = ntohs(((struct sockaddr_in6*)&n->ss)->sin6_port);
			lwsl_dht_info(" [%s]:%d ", buf, port);
			break;
		default:
			lwsl_dht_info(" Unknown AF %d ", n->ss.ss_family);
			break;
		}
		if (n->reply_time)
			lwsl_dht_info("age %ld, %ld",
					(long)(ctx->now.tv_sec - n->time),
					(long)(ctx->now.tv_sec - n->reply_time));
		else
			lwsl_dht_info("age %ld", (long)(ctx->now.tv_sec - n->time));
		if (n->pinged)
			lwsl_dht_info(" (%d)", n->pinged);
		if (node_good(ctx, n))
			lwsl_dht_info(" (good)");
		lwsl_dht_info("\n");
	} lws_end_foreach_dll(d);
}

void
lws_dht_dump_tables(struct lws_dht_ctx *ctx)
{
	int i;

	lwsl_dht_info("My id ");
	lwsl_hexdump_dht(ctx->myid->id, ctx->myid->len);
	lwsl_dht_info("\n");

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->buckets)) {
		dump_bucket(ctx, lws_container_of(d, struct bucket, list));
	} lws_end_foreach_dll(d);

	lwsl_dht_info("\n");

	lws_start_foreach_dll(struct lws_dll2 *, d6, lws_dll2_get_head(&ctx->buckets6)) {
		dump_bucket(ctx, lws_container_of(d6, struct bucket, list));
	} lws_end_foreach_dll(d6);

	lws_start_foreach_dll(struct lws_dll2 *, ds, lws_dll2_get_head(&ctx->searches)) {
		struct search *sr = lws_container_of(ds, struct search, list);

		lwsl_dht_info("\nSearch%s id ", sr->af == AF_INET6 ? " (IPv6)" : "");
		lwsl_hexdump_dht(sr->id->id, sr->id->len);
		lwsl_dht_info(" age %d%s\n", (int)(ctx->now.tv_sec - sr->step_time),
				sr->done ? " (done)" : "");
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n = &sr->nodes[i];
			lwsl_dht_info("Node %d id ", i);
			lwsl_hexdump_dht(n->id->id, n->id->len);
			lwsl_dht_info(" bits %d age ", common_bits(sr->id, n->id));
			if (n->request_time)
				lwsl_dht_info("%d, ", (int)(ctx->now.tv_sec - n->request_time));
			lwsl_dht_info("%d", (int)(ctx->now.tv_sec - n->reply_time));
			if (n->pinged)
				lwsl_dht_info(" (%d)", n->pinged);
			lwsl_dht_info("%s%s.\n",
					find_node(ctx, n->id, AF_INET) ? " (known)" : "",
					n->replied ? " (replied)" : "");
		}
	} lws_end_foreach_dll(ds);

	lws_start_foreach_dll(struct lws_dll2 *, dt, lws_dll2_get_head(&ctx->storage)) {
		struct storage *st = lws_container_of(dt, struct storage, list);

		lwsl_dht_info("\nStorage ");
		lwsl_hexdump_dht(st->id->id, st->id->len);
		lwsl_dht_info(" %d/%d nodes:", st->numpeers, st->maxpeers);
		for (i = 0; i < st->numpeers; i++) {
			char buf[64];
			if (st->peers[i].len == 4 || st->peers[i].len == 16) {
				lws_write_numeric_address(st->peers[i].ip, (int)st->peers[i].len, buf, 64);
			} else {
				strcpy(buf, "???");
			}
			lwsl_dht_info(" %s:%u (%ld)",
					buf, st->peers[i].port,
					(long)(ctx->now.tv_sec - st->peers[i].time));
		}
	} lws_end_foreach_dll(dt);

	lwsl_dht_info("\n\n");
}

int
bucket_maintenance(struct lws_dht_ctx *ctx, int af)
{
	lws_dll2_owner_t *bo = af == AF_INET ? &ctx->buckets : &ctx->buckets6;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(bo)) {
		struct bucket *b = lws_container_of(d, struct bucket, list);
		struct bucket *q;

		if (b->time < ctx->now.tv_sec - 600) {
			/*
			 * This bucket hasn't seen any positive confirmation for a long
			 * time.  Pick a random id in this bucket's range, and send
			 * a request to a random node.
			 */
			lws_dht_hash_t *id;
			struct node *n;
			int rc;

			id = lws_dht_hash_create(b->first->type, b->first->len, NULL);
			if (!id)
				return 0;

			rc = bucket_random(ctx, b, id);
			if (rc < 0)
				lws_dht_hash_copy(id, b->first);

			q = b;
			/*
			 * If the bucket is empty, we try to fill it from a neighbour.
			 * We also sometimes do it gratuitiously to recover from
			 * buckets full of broken nodes.
			 */
			if (bucket_next(q) && (lws_dll2_count(&q->nodes) == 0 ||
					((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 7) == 0))
				q = bucket_next(b);
			if (q && (lws_dll2_count(&q->nodes) == 0 ||
					((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 7) == 0)) {
				struct bucket *r = previous_bucket(b);

				if (r && lws_dll2_count(&r->nodes) > 0)
					q = r;
			}

			if (q) {
				n = random_node(ctx, q);
				if (n) {
					uint8_t tid[4];
					int want = 0;

					if (ctx->wsi_v4 && ctx->wsi_v6) {
						struct bucket *otherbucket = find_bucket(ctx, id, af == AF_INET ? AF_INET6 : AF_INET);

						if (otherbucket && lws_dll2_count(&otherbucket->nodes) < 8)
							/*
							 * The corresponding bucket in the other family
							 * is emptyish -- querying both is useful.
							 */
							want = WANT4 | WANT6;
						else if ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) % 37 == 0)
							/*
							 * Most of the time, this just adds overhead.
							 * However, it might help stitch back one of
							 * the DHTs after a network collapse, so query
							 * both, but only very occasionally.
							 */
							want = WANT4 | WANT6;
					}

					lwsl_dht_info("%s: Sending find_node for%s bucket maintenance\n",
							__func__, af == AF_INET6 ? " IPv6" : "");
					make_tid(tid, "fn", 0);
					send_find_node(ctx, (struct sockaddr*)&n->ss, n->sslen,
							tid, 4, id, want,
							n->reply_time >= ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS);
					mark_as_pinged(ctx, n, q);
					/*
					 * In order to avoid sending queries back-to-back,
					 * give up for now and reschedule us soon.
					 */
					lws_dht_hash_destroy(&id);

					return 1;
				}
			}
			lws_dht_hash_destroy(&id);
		}
	} lws_end_foreach_dll(d);

	return 0;
}

int
neighbourhood_maintenance(struct lws_dht_ctx *ctx, int af)
{
	lws_dht_hash_t *id;
	struct bucket *b = find_bucket(ctx, ctx->myid, af);
	struct bucket *q;
	struct node *n;

	if (b == NULL)
		return 0;

	id = lws_dht_hash_dup(ctx->myid);
	if (!id) return 0;
	id->id[id->len - 1] = (uint8_t)((lws_get_random(ctx->vhost->context, &id->id[id->len - 1], 1), id->id[id->len - 1]) & 0xFF);
	q = b;
	if (bucket_next(q) && (lws_dll2_count(&q->nodes) == 0 ||
			((lws_get_random(ctx->vhost->context, &id->id[0], 1), id->id[0]) & 7) == 0))
		q = bucket_next(b);
	if (!q || lws_dll2_count(&q->nodes) == 0 ||
	    ((lws_get_random(ctx->vhost->context, &id->id[0], 1), id->id[0]) & 7) == 0) {
		struct bucket *r = previous_bucket(b);

		if (r && lws_dll2_count(&r->nodes) > 0)
			q = r;
	}

	if (q) {
		/*
		 * Since our node-id is the same in both DHTs, it's probably
		 * profitable to query both families.
		 */
		int want = ctx->wsi_v4 && ctx->wsi_v6 ? (WANT4 | WANT6) : 0;
		n = random_node(ctx, q);
		if (n) {
			uint8_t tid[4];

			lwsl_dht_info("%s: Sending find_node for%s neighborhood maintenance\n",
					__func__, af == AF_INET6 ? " IPv6" : "");
			make_tid(tid, "fn", 0);
			send_find_node(ctx, (struct sockaddr*)&n->ss, n->sslen,
					tid, 4, id, want,
					n->reply_time >= ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS);
			mark_as_pinged(ctx, n, q);
		}
		lws_dht_hash_destroy(&id);

		return 1;
	}
	lws_dht_hash_destroy(&id);

	return 0;
}
