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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "private-lib-misc-dht.h"

/*
 * Bencode emission cursor.  Every TX builder composes its datagram through
 * one of these; each append checks the remaining space and refuses the
 * whole datagram on overflow, so the builders are a flat list of appends
 * with a single failure path.
 */

int
dht_tx_raw(dht_txbuf_t *t, const void *v, size_t vl)
{
	if (vl > t->size - t->len)
		return -1;

	memcpy(t->buf + t->len, v, vl);
	t->len += vl;

	return 0;
}

int
dht_tx_lit(dht_txbuf_t *t, const char *lit)
{
	return dht_tx_raw(t, lit, strlen(lit));
}

int
dht_tx_str(dht_txbuf_t *t, const void *v, size_t vl)
{
	char pre[12];
	int rc = lws_snprintf(pre, sizeof(pre), "%zu:", vl);

	if (rc < 0 || dht_tx_raw(t, pre, (size_t)rc))
		return -1;

	return dht_tx_raw(t, v, vl);
}

int
dht_tx_int(dht_txbuf_t *t, uint64_t n)
{
	char tmp[24];
	int rc = lws_snprintf(tmp, sizeof(tmp), "i%llue",
			      (unsigned long long)n);

	return dht_tx_raw(t, tmp, (size_t)rc);
}

int
dht_tx_id_len(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id)
{
	return (int)(ctx->legacy ? LWS_DHT_SHA1_HASH_LEN : (2 + id->len));
}

/*
 * Emit just the hash encoding bytes of a node id.  Legacy peers only
 * understand the original fixed 20-byte SHA1 shape, which shorter ids
 * are zero-padded to;  the extended shape prepends the two-byte hash
 * type and length header.
 */

int
dht_tx_id_raw(struct lws_dht_ctx *ctx, dht_txbuf_t *t, const lws_dht_hash_t *id)
{
	if (!ctx->legacy) {
		if (dht_tx_raw(t, &id->type, 1) ||
		    dht_tx_raw(t, &id->len, 1))
			return -1;

		return dht_tx_raw(t, id->id, id->len);
	}

	if (id->len >= LWS_DHT_SHA1_HASH_LEN)
		return dht_tx_raw(t, id->id, LWS_DHT_SHA1_HASH_LEN);

	{
		uint8_t tmp[LWS_DHT_SHA1_HASH_LEN];

		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, id->id, id->len);

		return dht_tx_raw(t, tmp, sizeof(tmp));
	}
}

/* ...and as a bencode string value, with the length prefix */

int
dht_tx_id(struct lws_dht_ctx *ctx, dht_txbuf_t *t, const lws_dht_hash_t *id)
{
	char pre[8];
	int rc = lws_snprintf(pre, sizeof(pre), "%d:",
			      dht_tx_id_len(ctx, id));

	if (rc < 0 || dht_tx_raw(t, pre, (size_t)rc))
		return -1;

	return dht_tx_id_raw(ctx, t, id);
}

int
dht_tx_v(struct lws_dht_ctx *ctx, dht_txbuf_t *t)
{
	if (!ctx->have_v)
		return 0;

	return dht_tx_raw(t, ctx->my_v, sizeof(ctx->my_v));
}

/*
 * The "ip" reply member: the peer's idea of our external endpoint as
 * addr || port, in network byte order, as a single bencode string.
 */

int
dht_tx_ip(dht_txbuf_t *t, const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
	uint8_t a[18];
	size_t al;

	if (!sa) {
		lwsl_dht_warn("%s: sa is NULL\n", __func__);
		return -1;
	}

	switch (sa->sa_family) {
	case AF_INET:
		memcpy(a, &sin->sin_addr, 4);
		memcpy(a + 4, &sin->sin_port, 2);
		al = 6;
		break;
	case AF_INET6:
		memcpy(a, &sin6->sin6_addr, 16);
		memcpy(a + 16, &sin6->sin6_port, 2);
		al = 18;
		break;
	default:
		lwsl_dht_warn("%s: unknown sa_family %d\n", __func__,
			      sa->sa_family);
		return -1;
	}

	if (dht_tx_lit(t, "2:ip"))
		return -1;

	return dht_tx_str(t, a, al);
}

int
dht_tx_want(dht_txbuf_t *t, int want)
{
	if (dht_tx_lit(t, "4:wantl") ||
	    ((want & WANT4) && dht_tx_lit(t, "2:n4")) ||
	    ((want & WANT6) && dht_tx_lit(t, "2:n6")))
		return -1;

	return dht_tx_lit(t, "e");
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

/* d1:ad2:id<id>e1:q4:ping1:t<tid>v...1:y1:qe */

int
send_ping(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "e1:q4:ping1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: id, info_hash[, want] */

int
send_get_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		int want, int confirm)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	ctx->stats_current.tx_get_peers++;

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "9:info_hash") ||
	    dht_tx_id(ctx, &t, infohash) ||
	    (want && dht_tx_want(&t, want)) ||
	    dht_tx_lit(&t, "e1:q9:get_peers1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: id, info_hash, port, token */

int
send_announce_peer(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		   unsigned short port, uint8_t *token, size_t token_len, int confirm)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "9:info_hash") ||
	    dht_tx_id(ctx, &t, infohash) ||
	    dht_tx_lit(&t, "4:port") ||
	    dht_tx_int(&t, port) ||
	    dht_tx_lit(&t, "5:token") ||
	    dht_tx_str(&t, token, token_len) ||
	    dht_tx_lit(&t, "e1:q13:announce_peer1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: id, target[, want] */

int
send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		const lws_dht_hash_t *target, int want, int confirm)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	ctx->stats_current.tx_find_node++;

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "6:target") ||
	    dht_tx_id(ctx, &t, target) ||
	    (want && dht_tx_want(&t, want)) ||
	    dht_tx_lit(&t, "e1:q9:find_node1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: id, info_hash[, want] */

LWS_VISIBLE int
lws_dht_send_subscribe(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		int want, int confirm)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "9:info_hash") ||
	    dht_tx_id(ctx, &t, infohash) ||
	    (want && dht_tx_want(&t, want)) ||
	    dht_tx_lit(&t, "e1:q9:subscribe1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: id, info_hash, sha256, token */

LWS_VISIBLE int
lws_dht_send_subscribe_confirm(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		   uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		   uint8_t *token, size_t token_len, const uint8_t *sha256, int confirm)
{
	char buf[512];
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:ad2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "9:info_hash") ||
	    dht_tx_id(ctx, &t, infohash) ||
	    dht_tx_lit(&t, "6:sha256") ||
	    dht_tx_str(&t, sha256, 32) ||
	    dht_tx_lit(&t, "5:token") ||
	    dht_tx_str(&t, token, token_len) ||
	    dht_tx_lit(&t, "e1:q17:subscribe_confirm1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}

/* args: [data], id, info_hash, [sha256] */

LWS_VISIBLE int
lws_dht_send_notify(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		const lws_dht_hash_t *infohash, const uint8_t *sha256,
		const uint8_t *payload, size_t payload_len)
{
	char buf[1024]; /* payload allowance */
	dht_txbuf_t t = { .buf = buf, .size = sizeof(buf) };

	if (dht_tx_lit(&t, "d1:ad") ||
	    (payload && payload_len &&
	     (dht_tx_lit(&t, "4:data") || dht_tx_str(&t, payload, payload_len))) ||
	    dht_tx_lit(&t, "2:id") ||
	    dht_tx_id(ctx, &t, ctx->myid) ||
	    dht_tx_lit(&t, "9:info_hash") ||
	    dht_tx_id(ctx, &t, infohash) ||
	    (sha256 && (dht_tx_lit(&t, "6:sha256") ||
	    		dht_tx_str(&t, sha256, 32))) ||
	    dht_tx_lit(&t, "e1:q6:notify1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_v(ctx, &t) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(ctx, buf, t.len, sa, salen);

fail:
	errno = ENOSPC;

	return -1;
}
