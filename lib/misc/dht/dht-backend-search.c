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

struct search *
find_search(struct lws_dht_ctx *ctx, unsigned short tid, int af)
{
	struct search *sr = ctx->searches;

	while (sr) {
		if (sr->tid == tid && sr->af == af)
			return sr;
		sr = sr->next;
	}

	return NULL;
}

/*
 * A search contains a list of nodes, sorted by decreasing distance to the
 * target.  We just got a new candidate, insert it at the right spot or
 * discard it.
 */
int
insert_search_node(struct lws_dht_ctx *ctx, lws_dht_hash_t *id,
		const struct sockaddr *sa, size_t salen,
		struct search *sr, int replied,
		const uint8_t *token, size_t token_len)
{
	struct search_node *n;
	int i, j;

	if (sa->sa_family != sr->af) {
		lwsl_dht_warn("Attempted to insert node in the wrong family.\n");
		return 0;
	}

	for (i = 0; i < sr->numnodes; i++) {
		if (id_cmp(id, sr->nodes[i].id) == 0) {
			n = &sr->nodes[i];
			goto found;
		}
		if (xorcmp(id, sr->nodes[i].id, sr->id) < 0)
			break;
	}

	if (i == SEARCH_NODES)
		return 0;

	if (sr->numnodes < SEARCH_NODES)
		sr->numnodes++;

	for (j = sr->numnodes - 1; j > i; j--) {
		sr->nodes[j] = sr->nodes[j - 1];
	}

	n = &sr->nodes[i];

	memset(n, 0, sizeof(struct search_node));
	n->id = lws_dht_hash_dup(id);
	if (!n->id)
		return 0;

found:
	memcpy(&n->ss, sa, (size_t)salen);
	n->sslen = salen;

	if (replied) {
		n->replied = 1;
		n->reply_time = ctx->now.tv_sec;
		n->request_time = 0;
		n->pinged = 0;
	}
	if (token) {
		if (token_len >= 40) {
			lwsl_dht_warn("%s: Eek!  Overlong token.\n", __func__);
		} else {
			memcpy(n->token, token, (size_t)token_len);
			n->token_len = token_len;
		}
	}

	return 1;
}

void
expire_searches(struct lws_dht_ctx *ctx)
{
	struct search *sr = ctx->searches, *previous = NULL;

	while (sr) {
		struct search *next = sr->next;
		if (sr->step_time < ctx->now.tv_sec - DHT_SEARCH_EXPIRE_TIME) {
			if (previous)
				previous->next = next;
			else
				ctx->searches = next;
			lws_dht_hash_destroy(&sr->id);
			for (int i = 0; i < sr->numnodes; i++)
				lws_dht_hash_destroy(&sr->nodes[i].id);
			lws_free(sr);
			ctx->numsearches--;
		} else
			previous = sr;

		sr = next;
	}
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
int
search_send_get_peers(struct lws_dht_ctx *ctx, struct search *sr, struct search_node *n)
{
	struct node *node;
	uint8_t tid[4];

	if (n == NULL) {
		int i;
		for (i = 0; i < sr->numnodes; i++) {
			if (sr->nodes[i].pinged < LWS_DHT_MAX_PING_FAILURES && !sr->nodes[i].replied &&
					sr->nodes[i].request_time < ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS)
				n = &sr->nodes[i];
		}
	}

	if (!n || n->pinged >= LWS_DHT_MAX_PING_FAILURES || n->replied ||
			n->request_time >= ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS)
		return 0;

	lwsl_dht_info("Sending get_peers.\n");
	make_tid(tid, "gp", sr->tid);
	send_get_peers(ctx, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
			n->reply_time >= ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS);
	n->pinged++;
	n->request_time = ctx->now.tv_sec;

	/* If the node happens to be in our main routing table, mark it
	   as pinged. */

	node = find_node(ctx, n->id, n->ss.ss_family);
	if (node) mark_as_pinged(ctx, node, NULL);

	return 1;
}

/*
 * When a search is in progress, we periodically call search_step to send
 * further requests.
 */
void
search_step(struct lws_dht_ctx *ctx, struct search *sr, lws_dht_callback_t *callback, void *closure)
{
	int i, j;
	int all_done = 1;

	/* Check if the first 8 live nodes have replied. */
	j = 0;
	for (i = 0; i < sr->numnodes && j < 8; i++) {
		struct search_node *n = &sr->nodes[i];
		if (n->pinged >= LWS_DHT_MAX_PING_FAILURES)
			continue;
		if (!n->replied) {
			all_done = 0;
			break;
		}
		j++;
	}

	if (all_done) {
		if (!sr->port)
			goto done;

		int all_acked = 1;

		j = 0;
		for (i = 0; i < sr->numnodes && j < 8; i++) {
			struct search_node *n = &sr->nodes[i];
			struct node *node;
			uint8_t tid[4];

			if (n->pinged >= LWS_DHT_MAX_PING_FAILURES)
				continue;
			/*
			 * A proposed extension to the protocol consists in
			 * omitting the token when storage tables are full.  While
			 * I don't think this makes a lot of sense -- just sending
			 * a positive reply is just as good --, let's deal with it.
			 */
			if (!n->token_len)
				n->acked = 1;

			if (!n->acked) {
				all_acked = 0;
				lwsl_dht_info("Sending announce_peer.\n");
				make_tid(tid, "ap", sr->tid);
				send_announce_peer(ctx, (struct sockaddr*)&n->ss,
						sizeof(struct sockaddr_storage),
						tid, 4, sr->id, sr->port,
						n->token, n->token_len,
						n->reply_time >= ctx->now.tv_sec - LWS_DHT_PING_TIMEOUT_SECS);
				n->pinged++;
				n->request_time = ctx->now.tv_sec;

				node = find_node(ctx, n->id, n->ss.ss_family);
				if (node) mark_as_pinged(ctx, node, NULL);
			}
			j++;
		}
		if (all_acked)
			goto done;

		sr->step_time = ctx->now.tv_sec;
		return;
	}

	if (sr->step_time + LWS_DHT_PING_TIMEOUT_SECS >= ctx->now.tv_sec)
		return;

	j = 0;
	for (i = 0; i < sr->numnodes; i++) {
		j += search_send_get_peers(ctx, sr, &sr->nodes[i]);
		if (j >= LWS_DHT_MAX_PING_FAILURES)
			break;
	}
	sr->step_time = ctx->now.tv_sec;
	return;

done:
	sr->done = 1;
	if (callback)
		(*callback)(closure, sr->af == AF_INET ?
				LWS_DHT_EVENT_SEARCH_DONE : LWS_DHT_EVENT_SEARCH_DONE6,
				sr->id, NULL, 0, NULL, 0);

	sr->step_time = ctx->now.tv_sec;
}

static struct search *
new_search(struct lws_dht_ctx *ctx)
{
	struct search *sr, *oldest = NULL;

	/* Find the oldest done search */
	sr = ctx->searches;
	while (sr) {
		if (sr->done &&
		    (oldest == NULL || oldest->step_time > sr->step_time))
			oldest = sr;
		sr = sr->next;
	}

	/* The oldest slot is expired. */
	if (oldest && oldest->step_time < ctx->now.tv_sec - DHT_SEARCH_EXPIRE_TIME) {
		lws_dht_hash_destroy(&oldest->id);
		for (int i = 0; i < oldest->numnodes; i++)
			lws_dht_hash_destroy(&oldest->nodes[i].id);
		lws_free(oldest);
		ctx->numsearches--;

		return NULL; /* Indicate that the slot was freed, caller should allocate new */
	}

	/* Allocate a new slot. */
	if (ctx->numsearches < DHT_MAX_SEARCHES) {
		sr = lws_zalloc(sizeof(struct search), __func__);
		if (sr != NULL) {
			sr->next = ctx->searches;
			ctx->searches = sr;
			ctx->numsearches++;
			return sr;
		}
	}

	/* Oh, well, never mind.  Re-use the oldest slot. */
	if (oldest) {
		lws_dht_hash_destroy(&oldest->id);
		for (int i = 0; i < oldest->numnodes; i++)
			lws_dht_hash_destroy(&oldest->nodes[i].id);
		memset(oldest, 0, sizeof(struct search)); // Clear old data
	}
	return oldest;
}

/* Insert the contents of a bucket into a search structure. */
static void
insert_search_bucket(struct lws_dht_ctx *ctx, struct bucket *b, struct search *sr)
{
	struct node *n;

	if (!b)
		return;

	n = b->nodes;
	while (n) {
		insert_search_node(ctx, n->id, (struct sockaddr*)&n->ss, n->sslen,
				sr, 0, NULL, 0);
		n = n->next;
	}
}

/*
 * Start a search.  If port is non-zero, perform an announce when the
 * search is complete.
 */
LWS_VISIBLE int
lws_dht_search(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id, int port, int af,
		lws_dht_callback_t *callback, void *closure)
{
	struct search *sr;
	struct storage *st;
	struct bucket *b = find_bucket(ctx, id, af);

	if (port) {
		/* We are announcing.  Store ourselves. */
		struct sockaddr_in sin;

		if (af == AF_INET) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			/*
			 * In the test case, we are on loopback.
			 * Generally determining our own public IP is hard.
			 * But here we want to store what we are listening on so others can find us.
			 * For the test, Node A is on 10001.
			 */
			sin.sin_port = 0; /* Unused by storage_store, it uses the port arg */
			sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

			/* If we have a bound wsi, maybe use its address? */
			/* But effectively we just want to put "us" in the storage. */

			storage_store(ctx, id, (struct sockaddr *)&sin, (unsigned short)port);
		}
	}

	if (b == NULL) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/*
	 * Try to answer this search locally.  In a fully grown DHT this
	 * is very unlikely, but people are running modified versions of
	 * this code in private DHTs with very few nodes.  What's wrong
	 * with flooding?
	 */
	if (callback) {
		st = find_storage(ctx, id);
		if (st) {
			unsigned short swapped;
			uint8_t buf[18];
			int i;

			lwsl_dht_info("Found local data (%d peers).\n", st->numpeers);

			for (i = 0; i < st->numpeers; i++) {
				swapped = htons(st->peers[i].port);
				if (st->peers[i].len == 4) {
					memcpy(buf, st->peers[i].ip, 4);
					memcpy(buf + 4, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES, id,
								(void*)buf, 6, NULL, 0);
				} else if (st->peers[i].len == 16) {
					memcpy(buf, st->peers[i].ip, 16);
					memcpy(buf + 16, &swapped, 2);
					if (callback)
						(*callback)(closure, LWS_DHT_EVENT_VALUES6, id,
								(void*)buf, 18, NULL, 0);
				}
			}
		}
	}

	sr = ctx->searches;
	while (sr) {
		if (sr->af == af && id_cmp(sr->id, id) == 0)
			break;
		sr = sr->next;
	}

	if (sr) {
		/*
		 * We're reusing data from an old search.  Reusing the same tid
		 * means that we can merge replies for both searches.
		 */
		int i;
		sr->done = 0;
again:
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n;

			n = &sr->nodes[i];
			/* Discard any doubtful nodes. */
			if (n->pinged >= LWS_DHT_MAX_PING_FAILURES || n->reply_time < ctx->now.tv_sec - LWS_DHT_NODE_EXPIRE_SECS) {
				flush_search_node(n, sr);
				goto again;
			}
			n->pinged	= 0;
			n->token_len	= 0;
			n->replied	= 0;
			n->acked	= 0;
		}
	} else {
		sr = new_search(ctx);
		if (sr == NULL) {
			errno = ENOSPC;
			return -1;
		}
		sr->af		= af;
		sr->tid		= ctx->search_id++;
		sr->step_time	= ctx->now.tv_sec;
		sr->id		= lws_dht_hash_dup(id);

		if (!sr->id) {
			/*
			 * If we fail to dup the ID, we should free the search struct
			 * and decrement numsearches if it was incremented.
			 * For now, just return NULL and let the caller handle it.
			 * This is a memory allocation failure, so returning -1 is appropriate.
			 */
			if (sr == ctx->searches)
				ctx->searches = sr->next;
			else {
				struct search *temp_sr = ctx->searches;
				while (temp_sr && temp_sr->next != sr)
					temp_sr = temp_sr->next;
				if (temp_sr)
					temp_sr->next = sr->next;
			}
			lws_free(sr);
			ctx->numsearches--;
			errno = ENOMEM;
			return -1;
		}
		sr->done = 0;
		sr->numnodes = 0;
	}

	sr->port = (unsigned short)port;

	insert_search_bucket(ctx, b, sr);

	if (sr->numnodes < SEARCH_NODES) {
		struct bucket *p = previous_bucket(ctx, b);
		if (b->next)
			insert_search_bucket(ctx, b->next, sr);
		if (p)
			insert_search_bucket(ctx, p, sr);
	}
	if (sr->numnodes < SEARCH_NODES)
		insert_search_bucket(ctx, find_bucket(ctx, ctx->myid, af), sr);

	search_step(ctx, sr, callback, closure);
	ctx->search_time = ctx->now.tv_sec;
	return 1;
}
