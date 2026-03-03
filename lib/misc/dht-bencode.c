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

static const uint8_t *
dht_bencode_get_string(const uint8_t *dict, const uint8_t *end, const char *key, size_t *len_ret);

static unsigned long long
dht_strtoull(const char *p, size_t max_len, char **endptr)
{
	unsigned long long n = 0;
	size_t i = 0;

	while (i < max_len && p[i] >= '0' && p[i] <= '9') {
		n = n * 10 + (unsigned int)(p[i] - '0');
		i++;
	}

	if (endptr)
		*endptr = (char *)p + i;

	return n;
}

static void
parse_hash(const uint8_t *dict, const uint8_t *end, const char *key,
	   lws_dht_hash_t **h_ret)
{
	size_t l;
	const uint8_t *data = dht_bencode_get_string(dict, end, key, &l);

	*h_ret = NULL;
	if (data) {
		int type = 0, len = 0;
		const uint8_t *hash_data = NULL;

		if (l == 20) {
			type = LWS_DHT_HASH_TYPE_SHA1;
			len = 20;
			hash_data = data;
		} else if (l > 2 && data[1] == l - 2) {
			type = data[0];
			len = data[1];
			hash_data = data + 2;
		}

		if (hash_data && lws_dht_hash_validate(type, len)) {
			*h_ret = lws_dht_hash_create(type, len, hash_data);
		} else {
			lwsl_notice("%s: rejecting invalid/unsupported hash type %d len %d\n",
					__func__, type, len);
		}
	}
}

static int
dht_bencode_skip(const uint8_t **pp, const uint8_t *end)
{
	const uint8_t *p = *pp;
	char *q;
	int stack = 0;
	/* 0 = list/single, 1 = dict expecting key, 2 = dict expecting value */
	uint8_t state[32];

	if (p >= end)
		return -1;

	state[0] = 0;

	do {
		if (p >= end)
			return -1;

		if (stack > 0) {
			if (state[stack] == 1) {
				if (*p != 'e')
					state[stack] = 2;
			} else if (state[stack] == 2) {
				if (*p == 'e')
					return -1;
				state[stack] = 1;
			}
		}

		if (*p == 'e') {
			if (stack == 0)
				return -1;
			stack--;
			p++;
			continue;
		}

		switch (*p) {
		case 'd':
			if (stack >= 31)
				return -1;
			p++;
			stack++;
			state[stack] = 1;
			break;

		case 'l':
			if (stack >= 31)
				return -1;
			p++;
			stack++;
			state[stack] = 0;
			break;

		case 'i':
			p++;
			while (p < end && *p != 'e')
				p++;
			if (p >= end || *p != 'e')
				return -1;
			p++;
			break;

		default: /* string N:data */
			if (*p < '0' || *p > '9')
				return -1;

			{
				unsigned long long l = dht_strtoull((const char *)p, lws_ptr_diff_size_t(end, p), &q);

				if (!q || *q != ':')
					return -1;
				p = (uint8_t *)q + 1;
				if (l > lws_ptr_diff_size_t(end, p))
					return -1;
				p += (size_t)l;
			}
			break;
		}
	} while (stack > 0);

	*pp = p;

	return 0;
}

static const uint8_t *
dht_bencode_find_key(const uint8_t *buf, const uint8_t *end, const char *key, size_t *vlen)
{
	const uint8_t *p = buf;
	size_t klen = strlen(key);
	char *q;

	if (p >= end || *p != 'd')
		return NULL;
	p++;

	while (p < end && *p != 'e') {
		unsigned long long l = dht_strtoull((const char *)p, lws_ptr_diff_size_t(end, p), &q);

		if (!q || *q != ':')
			return NULL;
		p = (uint8_t *)q + 1;
		if (l > lws_ptr_diff_size_t(end, p))
			return NULL;

		if ((size_t)l == klen && !memcmp(p, key, klen)) {
			const uint8_t *vstart = p + (size_t)l;
			const uint8_t *vend = vstart;

			if (dht_bencode_skip(&vend, end))
				return NULL;

			if (vlen)
				*vlen = lws_ptr_diff_size_t(vend, vstart);

			return vstart;
		}

		p += (size_t)l;
		if (dht_bencode_skip(&p, end))
			return NULL;
	}

	return NULL;
}

static const uint8_t *
dht_bencode_get_string(const uint8_t *dict, const uint8_t *end, const char *key, size_t *len_ret)
{
	size_t vlen;
	const uint8_t *p = dht_bencode_find_key(dict, end, key, &vlen);
	char *q;

	if (!p)
		return NULL;

	*len_ret = (size_t)dht_strtoull((const char *)p, vlen, &q);
	if (!q || *q != ':')
		return NULL;

	if ((const uint8_t *)q + 1 + *len_ret > end)
		return NULL;

	return (const uint8_t *)q + 1;
}

static unsigned long long
dht_bencode_get_int(const uint8_t *dict, const uint8_t *end, const char *key)
{
	size_t vlen;
	const uint8_t *p = dht_bencode_find_key(dict, end, key, &vlen);
	char *q;

	if (!p || *p != 'i')
		return 0;

	return dht_strtoull((const char *)p + 1, vlen - 1, &q);
}

static int
parse_message(const uint8_t *buf, size_t buflen, struct lws_dht_mparams *mp)
{
	const uint8_t *p, *end = buf + buflen, *meta = NULL, *meta_end = NULL;
	size_t l;
	int message = -1;
	const uint8_t *q_ptr;

	memset(mp, 0, sizeof(*mp));
	mp->tid_len = sizeof(mp->tid);
	mp->token_len = sizeof(mp->token);
	mp->nodes_len = sizeof(mp->nodes);
	mp->nodes6_len = sizeof(mp->nodes6);
	mp->values_len = sizeof(mp->values);
	mp->values6_len = sizeof(mp->values6);
	mp->want = 0;

	if (buflen < 2 || buf[0] != 'd')
		return -1;

	p = dht_bencode_get_string(buf, end, "t", &l);
	if (p && l > 0 && l < sizeof(mp->tid)) {
		memcpy(mp->tid, p, l);
		mp->tid_len = l;
	} else
		mp->tid_len = 0;

	p = dht_bencode_get_string(buf, end, "y", &l);
	if (!p || l != 1)
		return -1;

	switch (*p) {
	case 'r':
		message = DHT_REPLY;
		meta = dht_bencode_find_key(buf, end, "r", &l);
		break;

	case 'q':
		q_ptr = dht_bencode_get_string(buf, end, "q", &l);
		if (!q_ptr)
			return -1;
		if (l == 4 && !memcmp(q_ptr, "ping", 4))
			message = DHT_PING;
		else if (l == 9 && !memcmp(q_ptr, "find_node", 9))
			message = DHT_FIND_NODE;
		else if (l == 9 && !memcmp(q_ptr, "get_peers", 9))
			message = DHT_GET_PEERS;
		else if (l == 13 && !memcmp(q_ptr, "announce_peer", 13))
			message = DHT_ANNOUNCE_PEER;
		else if (l == 4 && !memcmp(q_ptr, "data", 4))
			message = DHT_DATA;
		else
			return -1;

		meta = dht_bencode_find_key(buf, end, "a", &l);
		break;

	case 'e':
		return DHT_ERROR;
	default:
		return -1;
	}

	p = dht_memmem(buf, buflen, "5:token", 7);
	if (p) {
		size_t l;
		char *q;

		l = dht_strtoull((char*)p + 7,
			buflen - lws_ptr_diff_size_t(p + 7, buf), &q);
		if (q && (uint8_t *)q < buf + buflen && *q == ':' && l > 0 && l < mp->token_len) {
			if (l > lws_ptr_diff_size_t(end, (const uint8_t *)(q + 1))) goto fail;
			memcpy(mp->token, q + 1, l);
			mp->token_len = l;
		} else
			mp->token_len = 0;
	}

	if (!meta || *meta != 'd')
		return message;

	meta_end = meta + l;

	parse_hash(meta, meta_end, "id", &mp->id);
	parse_hash(meta, meta_end, "info_hash", &mp->info_hash);
	parse_hash(meta, meta_end, "target", &mp->target);

	if (dht_bencode_find_key(meta, meta_end, "implied_port", &l))
		mp->port = 1;
	else
		mp->port = (unsigned short)dht_bencode_get_int(meta, meta_end, "port");

	p = dht_bencode_get_string(meta, meta_end, "token", &l);
	if (p && l > 0 && l < sizeof(mp->token)) {
		memcpy(mp->token, p, l);
		mp->token_len = l;
	} else
		mp->token_len = 0;

	p = dht_bencode_get_string(meta, meta_end, "nodes", &l);
	if (p && l > 0 && l < sizeof(mp->nodes)) {
		memcpy(mp->nodes, p, l);
		mp->nodes_len = l;
	} else
		mp->nodes_len = 0;

	p = dht_bencode_get_string(meta, meta_end, "nodes6", &l);
	if (p && l > 0 && l < sizeof(mp->nodes6)) {
		memcpy(mp->nodes6, p, l);
		mp->nodes6_len = l;
	} else
		mp->nodes6_len = 0;

	if (message == DHT_DATA) {
		p = dht_bencode_get_string(meta, meta_end, "data", &l);
		if (p) {
			mp->data = p;
			mp->data_len = l;
		}
	}

	if (dht_bencode_find_key(meta, meta_end, "offset", NULL)) {
		mp->offset = dht_bencode_get_int(meta, meta_end, "offset");
		lwsl_debug("%s: Parsed offset %llu\n", __func__, (unsigned long long)mp->offset);
	} else
		lwsl_notice("%s: offset key NOT FOUND in reply\n", __func__);

	if (dht_bencode_find_key(meta, meta_end, "len", NULL))
		mp->len = dht_bencode_get_int(meta, meta_end, "len");

	p = dht_bencode_find_key(meta, meta_end, "sack", &l);
	if (p && *p == 'l') {
		const uint8_t *v = p + 1, *vend = p + l;
		while (v < vend && *v != 'e' && mp->num_sack < 4) {
			const uint8_t *vstart = v, *v_dict_end = v;

			if (*v != 'd')
				break;

			if (dht_bencode_skip(&v_dict_end, vend))
				break;
			mp->sack[mp->num_sack].len = (uint32_t)dht_bencode_get_int(vstart, v_dict_end, "l");
			mp->sack[mp->num_sack].start = dht_bencode_get_int(vstart, v_dict_end, "o");
			mp->num_sack++;
			v = v_dict_end;
		}
	}

	p = dht_bencode_find_key(meta, meta_end, "values", &l);
	if (p && *p == 'l') {
		const uint8_t *v = p + 1, *vend = p + l;
		size_t j = 0, j6 = 0;

		while (v < vend && *v != 'e') {
			size_t slen;
			char *q_ptr;
			unsigned long long sl = dht_strtoull((const char *)v, lws_ptr_diff_size_t(vend, v), &q_ptr);

			if (!q_ptr || *q_ptr != ':')
				break;
			slen = (size_t)sl;
			v = (const uint8_t *)q_ptr + 1;

			if (slen > lws_ptr_diff_size_t(vend, v))
				break;

			if (slen == LWS_DHT_NODE_INFO_IP4_VLEN && j + LWS_DHT_NODE_INFO_IP4_VLEN <= sizeof(mp->values)) {
				memcpy(mp->values + j, v, LWS_DHT_NODE_INFO_IP4_VLEN);
				j += LWS_DHT_NODE_INFO_IP4_VLEN;
			} else if (slen == LWS_DHT_NODE_INFO_IP6_VLEN && j6 + LWS_DHT_NODE_INFO_IP6_VLEN <= sizeof(mp->values6)) {
				memcpy(mp->values6 + j6, v, LWS_DHT_NODE_INFO_IP6_VLEN);
				j6 += LWS_DHT_NODE_INFO_IP6_VLEN;
			}

			v += slen;
		}
		mp->values_len = j;
		mp->values6_len = j6;
	}

	p = dht_bencode_find_key(buf, end, "ip", &l);
	if (!p)
		p = dht_bencode_find_key(buf, end, "you", &l);
	if (p) {
		size_t slen;
		char *q_ptr;
		unsigned long long sl = dht_strtoull((const char *)p, lws_ptr_diff_size_t(end, p), &q_ptr);

		if (q_ptr && *q_ptr == ':' && (sl == LWS_DHT_NODE_INFO_IP4_VLEN || sl == LWS_DHT_NODE_INFO_IP6_VLEN)) {
			slen = (size_t)sl;
			p = (const uint8_t *)q_ptr + 1;
			mp->sender_ip_len = (int)slen - LWS_DHT_PORT_VLEN;
			memcpy(mp->sender_ip, p, (size_t)mp->sender_ip_len);
			memcpy(&mp->sender_port, p + mp->sender_ip_len, 2);
			mp->sender_port = ntohs(mp->sender_port);
		} else
			mp->sender_ip_len = 0;
	} else
		mp->sender_ip_len = 0;

	if (dht_memmem(buf, buflen, "1:y1:r", 6))
		return DHT_REPLY;
	if (dht_memmem(buf, buflen, "1:y1:e", 6))
		return DHT_ERROR;
	if (!dht_memmem(buf, buflen, "1:y1:q", 6))
		return -1;
	/* Parse query type robustly */
	{
		uint8_t *p = dht_memmem(buf, buflen, "1:q", 3);
		if (p) {
			char *endptr;
			long qlen;
			/* Value should be string: "N:value" */
			qlen = (long)dht_strtoull((char*)p + 3,
				buflen - lws_ptr_diff_size_t(p + 3, buf), &endptr);

			if (endptr && (uint8_t *)endptr < buf + buflen && *endptr == ':') {
				p = (uint8_t *)endptr + 1;
				/*
				 * Check bounds? buflen unknown relative to p here easily without math.
				 * Assuming dht_memmem ensures it's within buf.
				 */
				if (qlen == 4 && memcmp(p, "ping", 4) == 0)
					return DHT_PING;
				if (qlen == 9 && memcmp(p, "find_node", 9) == 0)
					return DHT_FIND_NODE;
				if (qlen == 9 && memcmp(p, "get_peers", 9) == 0)
					return DHT_GET_PEERS;
				if (qlen == 13 && memcmp(p, "announce_peer", 13) == 0)
					return DHT_ANNOUNCE_PEER;
				if (qlen == 4 && memcmp(p, "data", 4) == 0)
					return DHT_DATA;

				lwsl_dht_rx_warn("%s: Unknown q: %.*s\n", __func__, (int)qlen, p);
			}
		}
	}

	return message;

fail:
	return -1;
}

static void
lws_dht_reply_pong(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		   const struct sockaddr *from, size_t fromlen)
{
	lwsl_dht_rx("%s: Pong!\n", __func__);
	maybe_new_node(ctx, mp->id, from, fromlen, 2);
}

static void
lws_dht_reply_nodes(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		    const struct sockaddr *from, size_t fromlen)
{
	int gp = 0;
	struct search *sr = NULL;
	unsigned short ttid;
	size_t offset;

	if (tid_match(mp->tid, "gp", &ttid)) {
		gp = 1;
		sr = find_search(ctx, ttid, from->sa_family);
	}

	lwsl_dht_rx("%s: Nodes found (%d+%d)%s\n", __func__, (int)(mp->nodes_len / LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN),
			(int)(mp->nodes6_len / LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN),
			gp ? " for get_peers" : "");

	if (ctx->legacy && (mp->nodes_len % LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN != 0 ||
			    mp->nodes6_len % LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN != 0)) {
		lwsl_dht_rx_warn("%s: Unexpected length for node info\n", __func__);
		blacklist_node(ctx, mp->id, from, fromlen);
		return;
	}

	offset = 0;
	while (offset < mp->nodes_len) {
		uint8_t *ni = (uint8_t *)mp->nodes + offset;
		lws_dht_hash_t *node_id = NULL;
		size_t step = 0;
		uint8_t hash_type;
		uint8_t hash_len;
		const uint8_t *hash_data;

		if (ctx->legacy) {
			if (offset + LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN > mp->nodes_len)
				break;
			hash_type = LWS_DHT_HASH_TYPE_SHA1;
			hash_len = LWS_DHT_SHA1_HASH_LEN;
			hash_data = ni;
			step = LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN;
		} else {
			if (offset + LWS_DHT_NODE_INFO_HASH_HDR_VLEN > mp->nodes_len) break;
			hash_type = ni[0];
			hash_len = ni[1];
			if (offset + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_NODE_INFO_IP4_VLEN > mp->nodes_len) break;
			hash_data = ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN;
			step = (size_t)(LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_NODE_INFO_IP4_VLEN);
		}

		node_id = lws_dht_hash_create(hash_type, hash_len, hash_data);
		if (node_id) {
			if (lws_dht_hash_cmp(node_id, ctx->myid) != 0) {
				struct sockaddr_in sin;

				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				if (ctx->legacy) {
					memcpy(&sin.sin_addr, ni + LWS_DHT_SHA1_HASH_LEN, LWS_DHT_IPV4_VLEN);
					memcpy(&sin.sin_port, ni + LWS_DHT_SHA1_HASH_LEN + LWS_DHT_IPV4_VLEN, LWS_DHT_PORT_VLEN);
				} else {
					memcpy(&sin.sin_addr, ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len, LWS_DHT_IPV4_VLEN);
					memcpy(&sin.sin_port, ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_IPV4_VLEN, LWS_DHT_PORT_VLEN);
				}
				maybe_new_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), 0);
				if (sr && sr->af == AF_INET)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), sr, 0, NULL, 0);

			}
			lws_dht_hash_destroy(&node_id);
		}
		offset += step;
	}

	offset = 0;
	while (offset < mp->nodes6_len) {
		uint8_t *ni = (uint8_t *)mp->nodes6 + offset;
		lws_dht_hash_t *node_id = NULL;
		size_t step = 0;
		uint8_t hash_type;
		uint8_t hash_len;
		const uint8_t *hash_data;

		if (ctx->legacy) {
			if (offset + LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN > mp->nodes6_len)
				break;
			hash_type = LWS_DHT_HASH_TYPE_SHA1;
			hash_len = LWS_DHT_SHA1_HASH_LEN;
			hash_data = ni;
			step = LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN;
		} else {
			if (offset + LWS_DHT_NODE_INFO_HASH_HDR_VLEN > mp->nodes6_len)
				break;
			hash_type = ni[0];
			hash_len = ni[1];
			if (offset + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_NODE_INFO_IP6_VLEN > mp->nodes6_len)
				break;
			hash_data = ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN;
			step = (size_t)(LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_NODE_INFO_IP6_VLEN);
		}

		node_id = lws_dht_hash_create(hash_type, hash_len, hash_data);
		if (node_id) {
			if (lws_dht_hash_cmp(node_id, ctx->myid)) {
				struct sockaddr_in6 sin6;

				memset(&sin6, 0, sizeof(sin6));
				sin6.sin6_family = AF_INET6;

				if (ctx->legacy) {
					memcpy(&sin6.sin6_addr, ni + LWS_DHT_SHA1_HASH_LEN, LWS_DHT_IPV6_VLEN);
					memcpy(&sin6.sin6_port, ni + LWS_DHT_SHA1_HASH_LEN + LWS_DHT_IPV6_VLEN, LWS_DHT_PORT_VLEN);
				} else {
					memcpy(&sin6.sin6_addr, ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len, LWS_DHT_IPV6_VLEN);
					memcpy(&sin6.sin6_port, ni + LWS_DHT_NODE_INFO_HASH_HDR_VLEN + hash_len + LWS_DHT_IPV6_VLEN, LWS_DHT_PORT_VLEN);
				}

				maybe_new_node(ctx, node_id, (struct sockaddr*)&sin6, sizeof(sin6), 0);

				if (sr && sr->af == AF_INET6)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin6,
							sizeof(sin6), sr, 0, NULL, 0);
			}
			lws_dht_hash_destroy(&node_id);
		}

		offset += step;
	}

	if (sr) {
		insert_search_node(ctx, mp->id, from, fromlen, sr, 1, mp->token, mp->token_len);

		if (mp->values_len > 0 || mp->values6_len > 0) {
			lwsl_dht_rx("%s: Got values (%d+%d)\n", __func__, (int)(mp->values_len / LWS_DHT_NODE_INFO_IP4_VLEN), (int)(mp->values6_len / LWS_DHT_NODE_INFO_IP6_VLEN));
			if (ctx->cb) {
				int j;

				for (j = 0; j < (int)mp->values_len; j += LWS_DHT_NODE_INFO_IP4_VLEN)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES, sr->id, mp->values + j, LWS_DHT_NODE_INFO_IP4_VLEN, from, fromlen);
				for (j = 0; j < (int)mp->values6_len; j += LWS_DHT_NODE_INFO_IP6_VLEN)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES6, sr->id, mp->values6 + j, LWS_DHT_NODE_INFO_IP6_VLEN, from, fromlen);
			}
		}
		search_send_get_peers(ctx, sr, NULL);
	}
}

static void
lws_dht_reply_announce(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		       const struct sockaddr *from, size_t fromlen)
{
	unsigned short ttid;
	struct search *sr;
	size_t i;

	lwsl_dht_rx("%s: Got reply to announce_peer\n", __func__);

	if (!tid_match(mp->tid, "ap", &ttid))
		return;

	sr = find_search(ctx, ttid, from->sa_family);
	if (!sr) {
		lwsl_dht_warn("%s: Unknown search!\n", __func__);
		maybe_new_node(ctx, mp->id, from, fromlen, 1);
		return;
	}

	maybe_new_node(ctx, mp->id, from, fromlen, 2);

	for (i = 0; i < (size_t)sr->numnodes; i++)
		if (id_cmp(sr->nodes[i].id, mp->id) == 0) {
			sr->nodes[i].request_time = 0;
			sr->nodes[i].reply_time = (time_t)lws_now_secs();
			sr->nodes[i].acked = 1;
			sr->nodes[i].pinged = 0;
			break;
		}

	search_send_get_peers(ctx, sr, NULL);
}

int
lws_dht_process_packet(struct lws_dht_ctx *ctx, const void *buf, size_t buflen,
			const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_mparams mp;
	int message;

	memset(&mp, 0, sizeof(mp));
	mp.offset = (uint64_t)-1;

	mp.tid_len = sizeof(mp.tid);
	mp.token_len = sizeof(mp.token);
	mp.nodes_len = sizeof(mp.nodes);
	mp.nodes6_len = sizeof(mp.nodes6);
	mp.values_len = sizeof(mp.values);
	mp.values6_len = sizeof(mp.values6);

	ctx->now.tv_sec = (time_t)lws_now_secs();

	if (is_martian(from))
		return 0;

	if (node_blacklisted(ctx, from, fromlen)) {
		lwsl_dht_rx("%s: Received packet from blacklisted node\n", __func__);
		return 0;
	}

	message = parse_message(buf, buflen, &mp);
	if (message < 0 || message == DHT_ERROR || lws_dht_hash_is_zero(mp.id)) {
		lwsl_dht_rx_warn("%s: Unparseable message. msg=%d id_ptr=%p\n", __func__, message, mp.id);
		goto done;
	}

	if (id_cmp(mp.id, ctx->myid) == 0) {
		lwsl_dht_warn("%s: Received message from self. id %02x ctx->myid %02x, ctx %p\n", __func__, mp.id->id[0], ctx->myid->id[0], ctx);
		goto done;
	}

	if (message > DHT_REPLY && message != DHT_DATA) {
		/* Rate limit requests. */
		if (!token_bucket(ctx)) {
			lwsl_dht_warn("%s: Dropping request due to rate limiting\n", __func__);
			goto done;
		}
	} else if (message == DHT_REPLY && mp.sender_ip_len) {
		/* Track reported external address */
		struct sockaddr_storage ss;
		size_t sslen;
		int found = 0, j;

		memset(&ss, 0, sizeof(ss));
		if (mp.sender_ip_len == 4) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, mp.sender_ip, 4);
			sin->sin_port = htons(mp.sender_port);
			sslen = sizeof(*sin);
		} else {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			memcpy(&sin6->sin6_addr, mp.sender_ip, 16);
			sin6->sin6_port = htons(mp.sender_port);
			sslen = sizeof(*sin6);
		}

		for (j = 0; j < ctx->num_reported_ads; j++) {
			if (ctx->reported_ads[j].sslen == sslen &&
			    !memcmp(&ctx->reported_ads[j].ss, &ss, sslen)) {
				ctx->reported_ads[j].count++;
				found = 1;
				if (ctx->reported_ads[j].count >= 3 && !ctx->external_ads_set) {
					lwsl_notice("%s: reached consensus on external address\n", __func__);
					ctx->external_ads_set = 1;
					if (ctx->cb)
						ctx->cb(ctx->closure,
							ss.ss_family == AF_INET ?
								LWS_DHT_EVENT_EXTERNAL_ADDR :
								LWS_DHT_EVENT_EXTERNAL_ADDR6,
							NULL, &ss, sslen, from, fromlen);
				}
				break;
			}
		}
		if (!found && ctx->num_reported_ads < (int)LWS_ARRAY_SIZE(ctx->reported_ads)) {
			ctx->reported_ads[ctx->num_reported_ads].ss = ss;
			ctx->reported_ads[ctx->num_reported_ads].sslen = sslen;
			ctx->reported_ads[ctx->num_reported_ads].count = 1;
			ctx->num_reported_ads++;
		}
	}

	switch(message) {
	case DHT_REPLY:
		if (mp.tid_len != 4) {
			lwsl_dht_rx_warn("%s: Broken node truncates transaction ids\n", __func__);
			blacklist_node(ctx, mp.id, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "pn", NULL)) {
			lws_dht_reply_pong(ctx, &mp, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "fn", NULL) || tid_match(mp.tid, "gp", NULL)) {
			lws_dht_reply_nodes(ctx, &mp, from, fromlen);
			break;
		}
		if (tid_match(mp.tid, "ap", NULL)) {
			lws_dht_reply_announce(ctx, &mp, from, fromlen);
			break;
		}

		if (tid_match(mp.tid, "da", NULL) || tid_match(mp.tid, "sqnc", NULL)) {
			struct lws_transport_sequencer *ts;

			ts = lws_dht_get_ts(ctx, from, fromlen, 0);
			if (ts) {
				lws_transport_sequencer_acknowledge_sack(ts, mp.offset + mp.len,
									 mp.sack, mp.num_sack, mp.status);
			} else {
				char ads[64];
				lws_sa46_write_numeric_address((lws_sockaddr46 *)from, ads, sizeof(ads));
				lwsl_warn("%s: ACK received from %s (len %d) but no sequencer found!\n", __func__, ads, (int)fromlen);
			}
			break;
		}


		lwsl_dht_rx_warn("%s: Unexpected reply\n", __func__);
		blacklist_node(ctx, mp.id, from, fromlen);
		break;

	case DHT_PING:
		lwsl_dht_rx("%s: Ping (%d)!\n", __func__, (int)mp.tid_len);
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
		lwsl_dht_rx("%s: Sending pong\n", __func__);
		send_pong(ctx, from, fromlen, mp.tid, mp.tid_len);
		break;

	case DHT_FIND_NODE:
		lwsl_dht_rx("%s: Find node!\n", __func__);
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
		lwsl_dht_rx("%s: Sending closest nodes (%d)\n", __func__, mp.want);
		send_closest_nodes(ctx, from, fromlen, &mp, mp.target, 0, NULL);
		break;

	case DHT_GET_PEERS:
		lwsl_dht_rx("%s: Get_peers!\n", __func__);
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
		if (lws_dht_hash_is_zero(mp.info_hash)) {
			lwsl_dht_rx_warn("%s: Eek!  Got get_peers with no info_hash.\n", __func__);
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					203, "Get_peers with no info_hash");
			break;
		} else {
			struct storage *st = find_storage(ctx, mp.info_hash);

			make_token(ctx, from, 0, mp.token);
			mp.token_len = TOKEN_SIZE;

			if (st && st->numpeers > 0) {
				lwsl_dht_rx("%s: Sending found%s peers\n", __func__, from->sa_family == AF_INET6 ? " IPv6" : "");
				send_closest_nodes(ctx, from, fromlen, &mp,
						   mp.info_hash, from->sa_family, st);
				break;
			}
			lwsl_dht_rx("%s: Sending nodes for get_peers\n", __func__);
			send_closest_nodes(ctx, from, fromlen, &mp,
					   mp.info_hash, 0, NULL);
			break;
		}
		break;

	case DHT_DATA:
		if (mp.data) {
			struct lws_transport_sequencer *ts;
			lwsl_dht_rx("%s: Received reliable data payload (%d bytes, offset %llu)\n",
				    __func__, (int)mp.data_len, (unsigned long long)mp.offset);
			ts = lws_dht_get_ts(ctx, from, fromlen, 1);
			if (ts)
				lws_transport_sequencer_rx(ts, mp.offset, mp.data, mp.data_len);
		}
		break;
	case DHT_ANNOUNCE_PEER:
		lwsl_dht_rx("%s: Announce peer!\n", __func__);
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
		{
			int is_zero = 1;
			int i;
			for (i = 0; i < mp.info_hash->len; i++)
				if (mp.info_hash->id[i]) {
					is_zero = 0;
					break;
				}
			if (is_zero) {
				lwsl_dht_rx_warn("%s: Announce_peer with no info_hash\n", __func__);
				send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
						203, "Announce_peer with no info_hash");
				break;
			}
		}
		if (!token_match(ctx, mp.token, mp.token_len, from)) {
			lwsl_dht_rx_warn("%s: Incorrect token for announce_peer\n", __func__);
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					   203, "Announce_peer with bad token");
			break;
		}



		lws_dht_capture_announce(ctx, mp.info_hash, from, mp.port ? mp.port : mp.sender_port);
		lws_dht_reply_announce(ctx, &mp, from, fromlen);

		if (mp.port == 0) {
			lwsl_dht_rx_warn("%s: Announce with forbidden port %d\n", __func__, mp.port);
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
					203, "Announce_peer with forbidden port number");
			break;
		}
		if (mp.port == 1) {
			lwsl_dht_rx("%s: Announce with implied port. Using from port\n", __func__);
			if (from->sa_family == AF_INET) {
				struct sockaddr_in *temp_sin = (struct sockaddr_in*)from;
				mp.port = ntohs(temp_sin->sin_port);
			}
			else {
				struct sockaddr_in6 *temp_sin6 = (struct sockaddr_in6*)from;
				mp.port = ntohs(temp_sin6->sin6_port);
			}
		}

		storage_store(ctx, mp.info_hash, from, mp.port);

		/*
		* Note that if storage_store failed, we lie to the requestor.
		* This is to prevent them from backtracking, and hence
		* polluting the DHT.
		*/

		lws_dht_capture_announce(ctx, mp.info_hash, from, mp.port);

		lwsl_dht_rx("%s: Sending peer announced\n", __func__);
		send_peer_announced(ctx, from, fromlen, mp.tid, mp.tid_len);
		break;
	}
done:
	lws_dht_hash_destroy(&mp.id);
	lws_dht_hash_destroy(&mp.info_hash);
	lws_dht_hash_destroy(&mp.target);

	return 0;
}

