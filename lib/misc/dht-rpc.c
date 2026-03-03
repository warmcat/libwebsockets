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

int
dht_tx_check(size_t size, size_t offset, size_t delta)
{
	if ((ssize_t)delta < 0 || offset + delta > size)
		return -1;

	return 0;
}

int
dht_tx_skip(size_t *offset, size_t size, size_t delta)
{
	if (dht_tx_check(size, *offset, delta))
		return -1;

	*offset += delta;

	return 0;
}

int
dht_tx_id_len(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id)
{
	return (int)(ctx->legacy ? LWS_DHT_SHA1_HASH_LEN : (2 + id->len));
}

void *
dht_memmem(const void *haystack, size_t haystacklen,
	   const void *needle, size_t needlelen)
{
	const uint8_t *h = (const uint8_t *)haystack;
	const uint8_t *n = (const uint8_t *)needle;
	size_t i;

	if (needlelen > haystacklen)
		return NULL;

	for (i = 0; i <= haystacklen - needlelen; i++)
		if (!memcmp(h + i, n, needlelen))
			return (void *)(h + i);

	return NULL;
}

int
dht_tx_copy__advance_offset(char *buf, size_t *offset, size_t size, const void *src, size_t delta)
{
	if (dht_tx_check(size, *offset, delta))
		return -1;

	memcpy(buf + *offset, src, delta);
	*offset += delta;

	return 0;
}

static int
dht_tx_add_v(char *buf, size_t *offset, size_t size, struct lws_dht_ctx *ctx)
{
	if (ctx->have_v)
		return dht_tx_copy__advance_offset(buf, offset, size, ctx->my_v, sizeof(ctx->my_v));

	return 0;
}

int
dht_put_id__advance_offset(struct lws_dht_ctx *ctx, char *buf, size_t *offset, size_t size, const lws_dht_hash_t *id)
{
	if (ctx->legacy) {
		if (id->len >= LWS_DHT_SHA1_HASH_LEN) {
			if (dht_tx_copy__advance_offset(buf, offset, size, id->id, LWS_DHT_SHA1_HASH_LEN))
				goto fail;
			/* offset was advanced by dht_tx_copy__advance_offset */
			return 0;
		}

		if (dht_tx_check(size, *offset, LWS_DHT_SHA1_HASH_LEN))
			goto fail;

		memset(buf + *offset, 0, LWS_DHT_SHA1_HASH_LEN);
		memcpy(buf + *offset, id->id, id->len);
		/* explicitly advance offset */
		*offset += LWS_DHT_SHA1_HASH_LEN;

		return 0;
	}

	if (dht_tx_check(size, *offset, 2 + id->len))
		goto fail;

	buf[(*offset)++] = (char)id->type;
	buf[(*offset)++] = (char)id->len;

	memcpy(buf + *offset, id->id, id->len);
	/* explicitly advance offset */
	*offset += id->len;

	return 0;

fail:
	return -1;
}

static int
dht_tx_add_ip(char *buf, size_t *offset, size_t size, const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
	char tmp[32];
	int rc;

	switch (sa->sa_family) {
	case AF_INET:
		rc = lws_snprintf(tmp, sizeof(tmp), "2:ip6:");
		if (dht_tx_copy__advance_offset(buf, offset, size, tmp, (size_t)rc) ||
		    dht_tx_copy__advance_offset(buf, offset, size, &sin->sin_addr, sizeof(sin->sin_addr)) ||
		    dht_tx_copy__advance_offset(buf, offset, size, &sin->sin_port, sizeof(sin->sin_port)))
			break;
		return 0;
	case AF_INET6:
		rc = lws_snprintf(tmp, sizeof(tmp), "2:ip18:");
		if (dht_tx_copy__advance_offset(buf, offset, size, tmp, (size_t)rc) ||
		    dht_tx_copy__advance_offset(buf, offset, size, &sin6->sin6_addr, sizeof(sin6->sin6_addr)) ||
		    dht_tx_copy__advance_offset(buf, offset, size, &sin6->sin6_port, sizeof(sin6->sin6_port)))
			break;
		return 0;
	default:
		break;
	}

	return -1;
}

void
make_tid(uint8_t *tid_return, const char *prefix, unsigned short seqno)
{
	tid_return[0] = (uint8_t)(prefix[0] & 0xFF);
	tid_return[1] = (uint8_t)(prefix[1] & 0xFF);
	memcpy(tid_return + 2, &seqno, 2);
}

int
tid_match(const uint8_t *tid, const char *prefix,
		unsigned short *seqno_return)
{
	if (tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
		if (seqno_return)
			memcpy(seqno_return, tid + 2, 2);
		return 1;
	}

	return 0;
}

int
node_blacklisted(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen)
{
	int i;

	if (salen > sizeof(struct sockaddr_storage))
		abort();

	if (ctx->blacklist_cb && ctx->blacklist_cb(sa, salen))
		return 1;

	for (i = 0; i < DHT_MAX_BLACKLISTED; i++)
		if (memcmp(&ctx->blacklist[i], sa, (size_t)salen) == 0)
			return 1;

	return 0;
}

int
dht_send(struct lws_dht_ctx *ctx, const void *buf, size_t len,
		const struct sockaddr *sa, size_t salen)
{
	struct lws *wsi = NULL;
#if defined(HDT_VERBOSE)
	char buf_ip[64];

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)sa;

		inet_ntop(AF_INET, &s->sin_addr, buf_ip, sizeof(buf_ip));
		lwsl_dht_info("%s: sending to %s:%d\n", __func__, buf_ip, ntohs(s->sin_port));
	}
#endif

	if (!salen)
		abort();

	if (node_blacklisted(ctx, sa, salen)) {
		lwsl_dht_warn("Attempting to send to blacklisted node.\n");
		errno = EPERM;

		return -1;
	}

	switch	 (sa->sa_family) {
	case AF_INET:
		wsi = ctx->wsi_v4;
		break;
	case AF_INET6:
		wsi = ctx->wsi_v6;
		break;
	default:
		break;
	}

	if (!wsi) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (len > LWS_DHT_PACKET_SANITY_LIMIT) {
		lwsl_dht_warn("%s: excessively long packet\n", __func__);
		return -1;
	}

#if defined(HDT_VERBOSE)
	{
		size_t k;
		fprintf(stderr, "DHT_SEND: ");
		for (k=0; k<len; k++) fprintf(stderr, "%02X ", ((uint8_t *)buf)[k]);
		fprintf(stderr, "\n");
	}
#endif

	int n;

#ifdef _WIN32
	n = (int)sendto(wsi->desc.sockfd, (const char *)buf, (int)len, 0, sa, (socklen_t)salen);
#else
	n = (int)sendto(wsi->desc.sockfd, (const void *)buf, len, 0, sa, (socklen_t)salen);
#endif

	if (n < 0) {
		lwsl_dht_warn("%s: sendto failed: errno %d\n", __func__, errno);
	}
	return n;
}

int
send_ping(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q4:ping1:t%d:", (int)tid_len);

	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

int
send_pong(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len);

	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_ip(buf, &i, sizeof(buf), sa)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re");
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

/* Every bucket caches the address of a likely node.  Ping it. */
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

/*
 * Called whenever we send a request to a node, increases the ping count
 * and, if that reaches 3, sends a ping to a new candidate.
 */
void
mark_as_pinged(struct lws_dht_ctx *ctx, struct node *n, struct bucket *b)
{
	n->pinged++;
	n->pinged_time = ctx->now.tv_sec;
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
send_get_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "9:info_hash%d:", dht_tx_id_len(ctx, infohash));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), infohash)) goto fail;

	if (want) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:wantl%s%se",
				(want & WANT4) ? "2:n4" : "",
				(want & WANT6) ? "2:n6" : "");
		if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	}
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q9:get_peers1:t%d:", (int)tid_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

int
send_announce_peer(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		   unsigned short port, uint8_t *token, size_t token_len, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "9:info_hash%d:", dht_tx_id_len(ctx, infohash));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), infohash)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:porti%ue5:token%d:", (unsigned)port,
			(int)token_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), token, token_len)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q13:announce_peer1:t%d:", (int)tid_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe");
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
rotate_secrets(struct lws_dht_ctx *ctx)
{
	size_t rc;

	ctx->rotate_secrets_time = ctx->now.tv_sec + 900 +
		((lws_get_random(ctx->vhost->context, &ctx->rotate_secrets_time, sizeof(ctx->rotate_secrets_time)), ctx->rotate_secrets_time) % 1800);

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
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;

	make_token(ctx, sa, 1, t);
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;

	return 0;
}

int
send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		const lws_dht_hash_t *target, int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	if (dht_tx_check(sizeof(buf), i, 1)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:target%d:", dht_tx_id_len(ctx, target));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), target)) goto fail;

	if (want) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "4:wantl%s%se",
				(want & WANT4) ? "2:n4" : "",
				(want & WANT6) ? "2:n6" : "");
		if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:q9:find_node1:t%d:", (int)tid_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:qe"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

    return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
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
	struct node *n = b->nodes;
	while (n) {
		if (node_good(ctx, n))
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		n = n->next;
	}
	return numnodes;
}

static int
send_nodes_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		 struct lws_dht_mparams *mp,
		 struct node **nodes, int numnodes,
		 struct node **nodes6, int numnodes6,
		 int af, struct storage *st)
{
	char buf[2048];
	size_t i = 0;
	int rc, j0, j, k, len, n_idx;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	if (numnodes > 0) {
		/* Calculate total length */
		size_t nodes_len = 0;
		for (n_idx = 0; n_idx < numnodes; n_idx++) {
			if (ctx->legacy) nodes_len += LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN;
			else nodes_len += (size_t)(LWS_DHT_NODE_INFO_HASH_HDR_VLEN + nodes[n_idx]->id->len + LWS_DHT_NODE_INFO_IP4_VLEN);
		}

		if (dht_tx_check(sizeof(buf), i, 1)) goto fail;
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "5:nodes%d:", (int)nodes_len);
		if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

		for (n_idx = 0; n_idx < numnodes; n_idx++) {
			struct node *n = nodes[n_idx];
			struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;

			if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), n->id)) goto fail;
			memcpy(buf + i, &sin->sin_addr, LWS_DHT_IPV4_VLEN);
			i += LWS_DHT_IPV4_VLEN;
			memcpy(buf + i, &sin->sin_port, LWS_DHT_PORT_VLEN);
			i += LWS_DHT_PORT_VLEN;
		}
	}

	if (numnodes6 > 0) {
		size_t nodes6_len = 0;

		for (n_idx = 0; n_idx < numnodes6; n_idx++) {
			if (ctx->legacy)
				nodes6_len += LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN;
			else
				nodes6_len += (size_t)(LWS_DHT_NODE_INFO_HASH_HDR_VLEN + nodes6[n_idx]->id->len + LWS_DHT_NODE_INFO_IP6_VLEN);
		}

		if (dht_tx_check(sizeof(buf), i, 1)) goto fail;
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:nodes6%d:", (int)nodes6_len);
		if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

		for (n_idx = 0; n_idx < numnodes6; n_idx++) {
			struct node *n = nodes6[n_idx];
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
			if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), n->id)) goto fail;
			memcpy(buf + i, &sin6->sin6_addr, LWS_DHT_IPV6_VLEN);
			i += LWS_DHT_IPV6_VLEN;
			memcpy(buf + i, &sin6->sin6_port, LWS_DHT_PORT_VLEN);
			i += LWS_DHT_PORT_VLEN;
		}
	}

	/* ... rest of function ... */
	if (mp->token_len > 0) {
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "5:token%d:", (int)mp->token_len);
		if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
		if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), mp->token, mp->token_len)) goto fail;
	}

	if (st && st->numpeers > 0) {
		unsigned int r;
		/* ... existing implementation ... */
		len = af == AF_INET ? 4 : 16;
		lws_get_random(ctx->vhost->context, &r, sizeof(r));
		j0 = (int)(r % (unsigned int)st->numpeers);
		j = j0;
		k = 0;

		rc = lws_snprintf(buf + i, sizeof(buf) - i, "6:valuesl"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
		do {
			if (st->peers[j].len == len) {
				unsigned short swapped;
				swapped = htons(st->peers[j].port);
				rc = lws_snprintf(buf + i, sizeof(buf) - i, "%d:", len + 2);
				if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
				if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), st->peers[j].ip, (size_t)len)) goto fail;
				if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), &swapped, 2)) goto fail;
				k++;
			}
			j = (int)(((unsigned int)j + 1) % (unsigned int)st->numpeers);
		} while (j != j0 && k < 50);
		rc = lws_snprintf(buf + i, sizeof(buf) - i, "e"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	}

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)mp->tid_len); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), mp->tid, mp->tid_len)) goto fail;
	if (dht_tx_add_ip(buf, &i, sizeof(buf), sa)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	return dht_send(ctx, buf, i, sa, salen);

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
			numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
			if (b->next)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b->next);
			b = previous_bucket(ctx, b);
			if (b)
				numnodes = buffer_closest_nodes(ctx, nodes, numnodes, id, b);
		}
	}

	if ((want & WANT6)) {
		b = find_bucket(ctx, id, AF_INET6);
		if (b) {
			numnodes6 = buffer_closest_nodes(ctx, nodes6, numnodes6, id, b);
			if (b->next)
				numnodes6 =
					buffer_closest_nodes(ctx, nodes6, numnodes6, id, b->next);
			b = previous_bucket(ctx, b);
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
	size_t i = 0, msg_len;
	int rc;

	msg_len = strlen(message);
	/* make sure we don't overrun buf */
	if (i + 20u + msg_len > sizeof(buf)) /* roughly account for the rest of the pkt */
		msg_len = sizeof(buf) - i - 20u;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:eli%de%u:",
			code, (unsigned int)msg_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), message, msg_len)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:ee"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_peer_announced(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:rd2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(ctx, buf, &i, sizeof(buf), ctx->myid)) goto fail;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "e1:t%d:", (int)tid_len);
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(buf, &i, sizeof(buf), tid, tid_len)) goto fail;
	if (dht_tx_add_ip(buf, &i, sizeof(buf), sa)) goto fail;
	if (dht_tx_add_v(buf, &i, sizeof(buf), ctx)) goto fail;
	rc = lws_snprintf(buf + i, sizeof(buf) - i, "1:y1:re"); if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;
	return dht_send(ctx, buf, i, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
token_bucket(struct lws_dht_ctx *ctx)
{
	if (ctx->token_bucket_tokens == 0) {
		ctx->token_bucket_tokens = (int)MIN((long)MAX_TOKEN_BUCKET_TOKENS,
				100 * (long)(ctx->now.tv_sec - ctx->token_bucket_time));
		ctx->token_bucket_time = ctx->now.tv_sec;
	}

	if (ctx->token_bucket_tokens == 0)
		return 0;

	ctx->token_bucket_tokens--;
	return 1;
}
