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

int
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

	if (dht_tx_check(size, *offset, (size_t)(2 + id->len)))
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

int
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
send_get_peers(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		uint8_t *tid, size_t tid_len, const lws_dht_hash_t *infohash,
		int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	ctx->stats_current.tx_get_peers++;

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
send_find_node(struct lws_dht_ctx *ctx, const struct sockaddr *sa, size_t salen,
		const uint8_t *tid, size_t tid_len,
		const lws_dht_hash_t *target, int want, int confirm)
{
	char buf[512];
	size_t i = 0;
	int rc;

	rc = lws_snprintf(buf + i, sizeof(buf) - i, "d1:ad2:id%d:", dht_tx_id_len(ctx, ctx->myid));
	if (dht_tx_skip(&i, sizeof(buf), (size_t)(rc))) goto fail;

	ctx->stats_current.tx_find_node++;

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
