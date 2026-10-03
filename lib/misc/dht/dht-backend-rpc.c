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

/* reply: id, ip */

int
send_pong(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:rd2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "e1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_ip(&t, sa) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:re"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	lwsl_warn("%s: failed to generate pong\n", __func__);
	errno = ENOSPC;
	return -1;
}

int
send_cached_ping(struct lws_dht_ctx *ctx, struct bucket *b)
{
	uint8_t tid[4];
	int rc;

	if (!b)
		return 0;

	/* We set family to 0 when there's no cached node. */
	if (b->cached.ss_family == 0)
		return 0;

	lwsl_dht_info("Sending ping to cached node.\n");
	make_tid(tid, "pn", 0);
	rc = send_ping(ctx, (struct sockaddr*)&b->cached, b->cachedlen, tid, 4);

	b->cached.ss_family = 0;
	b->cachedlen = 0;

	return rc;
}

void
mark_as_pinged(struct lws_dht_ctx *ctx, struct node *n, struct bucket *b)
{
	n->pinged++;
	n->pinged_time = ctx->now;
	if (n->pinged >= LWS_DHT_MAX_PING_FAILURES)
		send_cached_ping(ctx, b ? b : find_bucket(ctx, n->id, n->ss.ss_family));
}

void
flush_search_node(struct search_node *n, struct search *sr)
{
	int i = (int)(n - sr->nodes), j;

	lws_dht_hash_destroy(&n->id);
	for (j = i; j < sr->numnodes - 1; j++)
		sr->nodes[j] = sr->nodes[j + 1];
	sr->numnodes--;
}

int
rotate_secrets(struct lws_dht_ctx *ctx)
{
	uint32_t r;
	size_t rc;

	/*
	 * Draw the jitter into an unsigned type: C99 % of a negative signed
	 * random is negative, which would set the next rotation in the past and
	 * rotate again on the very next tick, burning through oldsecret too and
	 * invalidating tokens we handed out seconds earlier.
	 */
	lws_get_random(ctx->vhost->context, &r, sizeof(r));
	ctx->rotate_secrets_time = ctx->now + 900 + (time_t)(r % 1800);

	memcpy(ctx->oldsecret, ctx->secret, sizeof(ctx->secret));

	rc = lws_get_random(ctx->vhost->context, ctx->secret, sizeof(ctx->secret));
	if (rc != sizeof(ctx->secret)) {
		lwsl_dht_err("Failed to get random bytes for secret rotation\n");
		return -1;
	}

	return 1;
}

void
make_token(struct lws_dht_ctx *ctx, const struct sockaddr *sa, int old, uint8_t *token_return)
{
	unsigned short port;
	int iplen;
	void *ip;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		ip = &sin->sin_addr;
		iplen = 4;
		port = htons(sin->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = &sin6->sin6_addr;
		iplen = 16;
		port = htons(sin6->sin6_port);
	} else
		abort();

	lws_dht_hash(ctx, token_return, TOKEN_SIZE,
			old ? ctx->oldsecret : ctx->secret, sizeof(ctx->secret),
			ip, iplen, (uint8_t*)&port, 2);
}

int
token_match(struct lws_dht_ctx *ctx, const uint8_t *token, size_t token_len,
		const struct sockaddr *sa)
{
	uint8_t t[TOKEN_SIZE];

	if (token_len != TOKEN_SIZE)
		return 0;

	make_token(ctx, sa, 0, t);
	if (!lws_timingsafe_bcmp(t, token, TOKEN_SIZE))
		return 1;

	make_token(ctx, sa, 1, t);
	if (!lws_timingsafe_bcmp(t, token, TOKEN_SIZE))
		return 1;

	return 0;
}

static int
insert_closest_node(struct node **nodes, int numnodes,
		const lws_dht_hash_t *id, struct node *n)
{
	int i;

	for (i = 0; i < numnodes; i++) {
		if (id_cmp(n->id, nodes[i]->id) == 0)
			return numnodes;
		if (xorcmp(n->id, nodes[i]->id, id) < 0)
			break;
	}

	if (i == 8)
		return numnodes;

	if (numnodes < 8)
		numnodes++;

	if (i < numnodes - 1)
		memmove(nodes + i + 1, nodes + i,
			(size_t)(numnodes - i - 1) * sizeof(struct node *));

	nodes[i] = n;

	return numnodes;
}

static int
buffer_closest_nodes(struct lws_dht_ctx *ctx, struct node **nodes, int numnodes,
		const lws_dht_hash_t *id, struct bucket *b)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
		struct node *n = lws_container_of(d, struct node, list);

		if (node_good(ctx, n))
			numnodes = insert_closest_node(nodes, numnodes, id, n);
	} lws_end_foreach_dll(d);

	return numnodes;
}

/* the size of one node's compact info in a nodes / nodes6 blob */

static size_t
node_info_len(struct lws_dht_ctx *ctx, const struct node *n, int af)
{
	if (ctx->legacy)
		return af == AF_INET ?
			(size_t)LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN :
			(size_t)LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN;

	return (size_t)LWS_DHT_NODE_INFO_HASH_HDR_VLEN + n->id->len +
	       (af == AF_INET ? (size_t)LWS_DHT_NODE_INFO_IP4_VLEN :
				(size_t)LWS_DHT_NODE_INFO_IP6_VLEN);
}

/*
 * Emit key + the compact info of as many of the nodes (closest first) as
 * fit in the cursor while leaving `reserve` bytes free.
 */

static int
dht_tx_nodes(struct lws_dht_ctx *ctx, dht_txbuf_t *t, const char *key,
	     struct node **nodes, int numnodes, int af, size_t reserve)
{
	size_t blob = 0;
	char pre[12];
	int n, k, rc = 0;

	for (k = numnodes; k > 0; k--) {
		blob = 0;
		for (n = 0; n < k; n++)
			blob += node_info_len(ctx, nodes[n], af);

		rc = lws_snprintf(pre, sizeof(pre), "%zu:", blob);
		if (strlen(key) + (size_t)rc + blob + reserve <= t->size - t->len)
			break;
	}

	if (!k)
		return 0;

	if (dht_tx_lit(t, key) || dht_tx_raw(t, pre, (size_t)rc))
		return -1;

	for (n = 0; n < k; n++) {
		const struct sockaddr_in *sin =
				(const struct sockaddr_in *)&nodes[n]->ss;
		const struct sockaddr_in6 *sin6 =
				(const struct sockaddr_in6 *)&nodes[n]->ss;

		if (dht_tx_id_raw(ctx, t, nodes[n]->id))
			return -1;

		if (af == AF_INET) {
			if (dht_tx_raw(t, &sin->sin_addr, LWS_DHT_IPV4_VLEN) ||
			    dht_tx_raw(t, &sin->sin_port, LWS_DHT_PORT_VLEN))
				return -1;
		} else
			if (dht_tx_raw(t, &sin6->sin6_addr, LWS_DHT_IPV6_VLEN) ||
			    dht_tx_raw(t, &sin6->sin6_port, LWS_DHT_PORT_VLEN))
				return -1;
	}

	return 0;
}

/*
 * reply: id, [nodes], [nodes6], [token], [values], ip
 *
 * dht_send() refuses anything over LWS_DHT_PACKET_SANITY_LIMIT, so the reply
 * is composed to fit in that: a reply that did not fit was simply never sent,
 * and ~40 IPv6 peers announced on a hash (5 source addresses' worth) with a
 * full routing table was enough to make us answer nothing at all, not even
 * the token, for that hash.  The tail and the token always go in; nodes are
 * trimmed from the far end only if they cannot fit with those, and then as
 * many values as fit, starting from a random one as before.
 */

static int
send_nodes_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		 struct lws_dht_mparams *mp,
		 struct node **nodes, int numnodes,
		 struct node **nodes6, int numnodes6,
		 int af, struct storage *st)
{
	char buf[LWS_DHT_PACKET_SANITY_LIMIT], tail[128], pre[12];
	dht_txbuf_t tt = { .buf = tail, .size = sizeof(tail) };
	dht_txbuf_t t = { .buf = buf };
	size_t reserve = 0;
	int rc, j0, j, k, len;

	/* the fixed tail must fit whatever else is left out */

	if (dht_tx_lit(&tt, "e1:t") ||
	    dht_tx_str(&tt, mp->tid, mp->tid_len) ||
	    dht_tx_ip(&tt, sa) ||
	    dht_tx_v(ctx, &tt) ||
	    dht_tx_lit(&tt, "1:y1:re"))
		goto fail;

	t.size = sizeof(buf) - tt.len;

	if (mp->token_len > 0) {
		rc = lws_snprintf(pre, sizeof(pre), "%zu:", mp->token_len);
		reserve = strlen("5:token") + (size_t)rc + mp->token_len;
	}

	if (dht_tx_lit(&t, "d1:rd2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_nodes(ctx, &t, "5:nodes", nodes, numnodes, AF_INET,
			 reserve) ||
	    dht_tx_nodes(ctx, &t, "6:nodes6", nodes6, numnodes6, AF_INET6,
			 reserve))
		goto fail;

	if (mp->token_len > 0) {
		if (dht_tx_lit(&t, "5:token") ||
		    dht_tx_str(&t, mp->token, mp->token_len))
			goto fail;
	}

	len = af == AF_INET ? 4 : 16;
	rc = lws_snprintf(pre, sizeof(pre), "%d:", len + 2);

	/* only start the list if at least one value and its end fit */

	if (st && st->numpeers > 0 &&
	    strlen("6:valuesl") + (size_t)rc + (size_t)len + 2 + 1 <=
							t.size - t.len) {
		unsigned int r;

		lws_get_random(ctx->vhost->context, &r, sizeof(r));
		j0 = (int)(r % (unsigned int)st->numpeers);
		j = j0;
		k = 0;

		if (dht_tx_lit(&t, "6:valuesl"))
			goto fail;
		do {
			if (st->peers[j].len == len) {
				unsigned short swapped = htons(st->peers[j].port);

				/* leave room for the list's closing 'e' */
				if ((size_t)rc + (size_t)len + 2 + 1 >
							t.size - t.len)
					break;

				if (dht_tx_raw(&t, pre, (size_t)rc) ||
				    dht_tx_raw(&t, st->peers[j].ip, (size_t)len) ||
				    dht_tx_raw(&t, &swapped, 2))
					goto fail;
				k++;
			}
			j = (int)(((unsigned int)j + 1) % (unsigned int)st->numpeers);
		} while (j != j0 && k < 50);
		if (dht_tx_lit(&t, "e"))
			goto fail;
	}

	t.size = sizeof(buf);
	if (dht_tx_raw(&t, tail, tt.len))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_closest_nodes(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   struct lws_dht_mparams *mp, const lws_dht_hash_t *id,
		   int af, struct storage *st)
{
	struct node *nodes[8];
	struct node *nodes6[8];
	int numnodes = 0, numnodes6 = 0;
	struct bucket *b;
	int want = mp->want;

	if (!want) {
		switch(sa->sa_family) {
		case AF_INET:
			want = WANT4;
			break;
#if defined(LWS_WITH_IPV6)
		case AF_INET6:
			want = WANT6;
			break;
#endif
		default:
			return -1;
		}
	}

	if ((want & WANT4)) {
		b = find_bucket(ctx, id, AF_INET);
		if (b) {
			struct bucket *nb = bucket_next(b);

			numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
			if (nb)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, nb);
			b = previous_bucket(b);
			if (b)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
		}
	}

	if ((want & WANT6)) {
		b = find_bucket(ctx, id, AF_INET6);
		if (b) {
			struct bucket *nb = bucket_next(b);

			numnodes6 = buffer_closest_nodes(ctx, nodes6, numnodes6, id, b);
			if (nb)
				numnodes6 =
					buffer_closest_nodes(ctx, nodes6, numnodes6, id, nb);
			b = previous_bucket(b);
			if (b)
				numnodes6 = buffer_closest_nodes(ctx, nodes6, numnodes6, id, b);
		}
	}
	lwsl_dht_info("  (%d+%d nodes.)\n", numnodes, numnodes6);

	return send_nodes_peers(ctx, sa, salen, mp, nodes, numnodes,
				nodes6, numnodes6, af, st);
}

int
send_error(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		int code, const char *message)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };
	size_t msg_len = strlen(message);

	/*
	 * Everything but the message is bounded: "d1:el" 5, the code as
	 * "i<n>e" at most 12, the message's length prefix at most 4, "e1:t"
	 * 4, the tid as "<n>:<tid>" at most 19, the optional "v" 9 and
	 * "1:y1:ee" 7; cut the message to leave room for all of that.
	 */
	if (t.size - t.len <= 64u)
		return -1;
	msg_len = MIN(msg_len, t.size - t.len - 64u);

	/*
	 * BEP 5: "e" is a list of the numeric code then the message string,
	 * d1:eli203e24:find_node with no targete1:t2:aa1:y1:ee
	 */
	if (dht_tx_lit(&t, "d1:el") ||
	    dht_tx_int(&t, (uint64_t)(unsigned int)code) ||
	    dht_tx_str(&t, message, msg_len) ||
	    dht_tx_lit(&t, "e1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:ee"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}
