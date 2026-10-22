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

	/*
	 * Every caller looks at the byte after the digits (for ':' or 'e'):
	 * if the digits ran to the end of the buffer there is no such byte,
	 * say so rather than hand back a pointer one past the datagram.
	 */
	if (endptr)
		*endptr = i < max_len ? (char *)p + i : NULL;

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
		} else
			lwsl_notice("%s: rejecting invalid/unsupported hash type %d len %d\n",
					__func__, type, len);
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

/*
 * The "e" member of a BEP 5 error reply: a list of the numeric code and the
 * message string, "li203e24:find_node with no targete".  find_key() has
 * already checked the list is structurally complete inside the datagram, so
 * vend[-1] is its closing 'e' and both elements lie before it.  The message
 * is left pointing into the datagram.
 */
static int
parse_error(const uint8_t *buf, const uint8_t *end, struct lws_dht_mparams *mp)
{
	const uint8_t *p, *vend;
	unsigned long long n;
	size_t vlen;
	char *q;

	p = dht_bencode_find_key(buf, end, "e", &vlen);
	if (!p || vlen < 2 || *p != 'l' || p[1] != 'i')
		return -1;
	vend = p + vlen;
	p += 2;

	/* BEP 5 codes are three digits; refuse anything not shaped like one */
	n = dht_strtoull((const char *)p, lws_ptr_diff_size_t(vend, p), &q);
	if (!q || q == (char *)p || *q != 'e' || n > 999)
		return -1;
	mp->error_code = (int)n;
	p = (const uint8_t *)q + 1;

	n = dht_strtoull((const char *)p, lws_ptr_diff_size_t(vend, p), &q);
	if (!q || *q != ':')
		return -1;
	p = (const uint8_t *)q + 1;
	if (p >= vend || n > lws_ptr_diff_size_t(vend - 1, p))
		return -1;

	mp->error_msg = p;
	mp->error_msg_len = (size_t)n;

	return 0;
}

static int
parse_message(const uint8_t *buf, size_t buflen, struct lws_dht_mparams *mp)
{
	const uint8_t *p, *end = buf + buflen, *meta = NULL, *meta_end = NULL;
	size_t l;
	int message = -1;
	const uint8_t *q_ptr;

	memset(mp, 0, sizeof(*mp));
	mp->want = 0;

	if (buflen < 2 || buf[0] != 'd') {
		lwsl_notice("%s: not a bencoded dictionary", __func__);
		lwsl_hexdump_notice(buf, buflen);
		return -1;
	}

	/*
	 * A tid may use the whole of mp->tid: the notify / ack exchange uses
	 * 16-byte tids (a subscriber's random one), which must survive here
	 * for the ack to find the pending notification it answers.
	 */
	p = dht_bencode_get_string(buf, end, "t", &l);
	if (p && l > 0 && l <= sizeof(mp->tid)) {
		memcpy(mp->tid, p, l);
		mp->tid_len = l;
	} else
		mp->tid_len = 0;

	p = dht_bencode_get_string(buf, end, "y", &l);
	if (!p || l != 1) {
		lwsl_notice("%s: Missing or invalid 'y' field", __func__);
		lwsl_hexdump_notice(buf, buflen);
		return -1;
	}

	switch (*p) {
	case 'r':
		message = DHT_REPLY;
		meta = dht_bencode_find_key(buf, end, "r", &l);
		break;

	case 'q':
		q_ptr = dht_bencode_get_string(buf, end, "q", &l);
		if (!q_ptr) {
			lwsl_notice("%s: Missing 'q' field in query", __func__);
			lwsl_hexdump_notice(buf, buflen);
			return -1;
		}
		if (l == 4 && !memcmp(q_ptr, "ping", 4))
			message = DHT_PING;
		else if (l == 9 && !memcmp(q_ptr, "find_node", 9))
			message = DHT_FIND_NODE;
		else if (l == 9 && !memcmp(q_ptr, "get_peers", 9))
			message = DHT_GET_PEERS;
		else if (l == 9 && !memcmp(q_ptr, "subscribe", 9))
			message = DHT_SUBSCRIBE;
		else if (l == 17 && !memcmp(q_ptr, "subscribe_confirm", 17))
			message = DHT_SUBSCRIBE_CONFIRM;
		else if (l == 6 && !memcmp(q_ptr, "notify", 6))
			message = DHT_NOTIFY;
		else if (l == 13 && !memcmp(q_ptr, "announce_peer", 13))
			message = DHT_ANNOUNCE_PEER;
		else if (l == 4 && !memcmp(q_ptr, "data", 4))
			message = DHT_DATA;
		else {
			lwsl_notice("%s: Unknown query type: %.*s", __func__, (int)l, q_ptr);
			lwsl_hexdump_notice(buf, buflen);
			return -1;
		}

		meta = dht_bencode_find_key(buf, end, "a", &l);
		break;

	case 'e':
		/*
		 * A peer refusing a query of ours.  It carries no sender id
		 * and no a / r dict, so none of the member handling below
		 * applies to it.
		 */
		if (parse_error(buf, end, mp))
			return -1;

		return DHT_ERROR;
	default:
		return -1;
	}

	if (!meta || *meta != 'd') {
		lwsl_notice("%s: Missing or invalid 'a' or 'r' dict", __func__);
		lwsl_hexdump_notice(buf, buflen);
		return message;
	}

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

	p = dht_bencode_get_string(meta, meta_end, "sha256", &l);
	if (p && l == 32) {
		memcpy(mp->sha256, p, 32);
	}

	/* a sequencer session challenge (a reply) or the answer to one */
	p = dht_bencode_get_string(meta, meta_end, "ch", &l);
	if (p && l == sizeof(mp->ch)) {
		memcpy(mp->ch, p, sizeof(mp->ch));
		mp->ch_len = (uint8_t)l;
	}

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

	if (message == DHT_DATA || message == DHT_NOTIFY) {
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
		lwsl_debug("%s: offset key NOT FOUND in reply\n", __func__);

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

	/*
	 * The message type was determined structurally from the y / q fields
	 * at the top of this function.  An earlier version re-classified the
	 * datagram here by searching the raw bytes for fragments like "1:y1:r",
	 * which match inside attacker-chosen string values as easily as in the
	 * real fields and so could misroute a query as a reply (or vice versa).
	 */

	return message;
}

static void
lws_dht_reply_pong(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		   const struct sockaddr *from, size_t fromlen)
{
	lwsl_dht_rx("%s: Pong!\n", __func__);
#if defined(LWS_WITH_DHT_BACKEND)
	/* only a reply to a request of ours from that endpoint gets here */
	maybe_new_node(ctx, mp->id, from, fromlen, 2);
#endif
}

/*
 * Is this "sb" reply the answer to a subscribe we sent, from the node we
 * sent it to?  Each pending subscribe is answered once.  If so, \p ih is
 * set to the hash that subscribe was for.
 */

static int
lws_dht_sb_pending_take(struct lws_dht_ctx *ctx, unsigned short seq,
			const struct sockaddr *from, lws_dht_hash_t *ih)
{
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ctx->sb_pending); n++)
		if (ctx->sb_pending[n].sslen &&
		    ctx->sb_pending[n].seq == seq &&
		    ctx->sb_pending[n].sent >=
				ctx->now - LWS_DHT_PING_TIMEOUT_SECS &&
		    dht_sa_same_peer((const struct sockaddr *)
				     &ctx->sb_pending[n].ss, from)) {
			ctx->sb_pending[n].sslen = 0;
			ih->type = ctx->sb_pending[n].ih_type;
			ih->len	 = ctx->sb_pending[n].ih_len;
			memcpy(ih->id, ctx->sb_pending[n].ih, ih->len);

			return 1;
		}

	return 0;
}

static void
lws_dht_reply_nodes(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		    const struct sockaddr *from, size_t fromlen)
{
	/* the hash the request this answers was about */
	uint8_t ihbuf[sizeof(lws_dht_hash_t) + LWS_GENHASH_LARGEST];
	lws_dht_hash_t *ih = (lws_dht_hash_t *)ihbuf;
	int bound = 0;
#if defined(LWS_WITH_DHT_BACKEND)
	struct search_node *sn;
	struct search *sr = NULL;
	int introduce = 0;
#endif
	unsigned short ttid;
	size_t offset;

	ih->len = 0;

	if (tid_match(mp->tid, "sb", &ttid)) {
		/*
		 * Replies are free and unlimited, and the dnssec plugin
		 * answers a subscription token with a larger datagram to the
		 * sender: only a reply to a subscribe of ours, from where we
		 * sent it, may surface one
		 */
		bound = lws_dht_sb_pending_take(ctx, ttid, from, ih);
		if (!bound)
			lwsl_dht_rx_warn("%s: subscribe reply with no subscribe "
					 "outstanding\n", __func__);
	} else if (tid_match(mp->tid, "gp", &ttid)) {
#if defined(LWS_WITH_DHT_BACKEND)
		sr = find_search(ctx, ttid, from->sa_family);
		/*
		 * find_search() matches on the 16-bit tid alone, so bind the
		 * reply to the address we actually sent that tid to before we
		 * let it touch the search: otherwise anyone who guesses a tid
		 * can stuff our lookup with his own nodes, token and values.
		 * The reply may still teach the routing table below.
		 */
		sn = sr ? search_awaiting_reply_from(ctx, sr, from) : NULL;
		if (sr && !sn) {
			lwsl_dht_rx_warn("%s: get_peers reply from an address "
					 "with no request outstanding\n",
					 __func__);
			sr = NULL;
		}
		bound = !!sr;
#endif
	}

	lwsl_dht_rx("%s: Nodes found (%d+%d)%s\n", __func__, (int)(mp->nodes_len / LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN),
			(int)(mp->nodes6_len / LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN),
			tid_match(mp->tid, "gp", NULL) ? " for get_peers" : "");

#if defined(LWS_WITH_DHT_BACKEND)
	/*
	 * Credit the sender for replying so their pinged count resets to 0:
	 * only a reply to a request of ours from that endpoint gets here
	 */
	maybe_new_node(ctx, mp->id, from, fromlen, 2);
#endif

	if (ctx->legacy && (mp->nodes_len % LWS_DHT_NODE_INFO_LEGACY_IP4_VLEN != 0 ||
			    mp->nodes6_len % LWS_DHT_NODE_INFO_LEGACY_IP6_VLEN != 0)) {
		/*
		 * Dropped, not blacklisted: a reply's source is unverified,
		 * so blacklisting it would let a spoofer have any node he
		 * names evicted and refused (the sibling sites were fixed
		 * the same way in C-496)
		 */
		lwsl_dht_rx_warn("%s: Unexpected length for node info\n", __func__);
		return;
	}

#if defined(LWS_WITH_DHT_BACKEND)
	/*
	 * Record the reply before what it lists: while the replier still
	 * looked unanswered, a closer node from its own list could push it
	 * out of a full search, and its reply then went to the backlog, which
	 * keeps no reply or token, so it was asked again, and listed the same
	 * node again, for ever (G-211).
	 *
	 * Only the endpoint's first reply may add candidates to the search:
	 * further datagrams from it are taken for their token and values, but
	 * would otherwise let it list as many candidates as it likes (G-158),
	 * whatever id each claims (G-216).  sn is not valid after this.
	 */
	if (sr)
		introduce = search_record_reply(ctx, sr, sn, mp->id, from,
						fromlen, mp->token,
						mp->token_len);
#endif

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
#if defined(LWS_WITH_DHT_BACKEND)
				maybe_new_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), 0);
				if (introduce && sr->af == AF_INET)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin, sizeof(sin), sr, 0, NULL, 0, from);
#endif

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

#if defined(LWS_WITH_DHT_BACKEND)
				maybe_new_node(ctx, node_id, (struct sockaddr*)&sin6, sizeof(sin6), 0);
				if (introduce && sr->af == AF_INET6)
					insert_search_node(ctx, node_id, (struct sockaddr*)&sin6, sizeof(sin6), sr, 0, NULL, 0, from);
#endif

			}
			lws_dht_hash_destroy(&node_id);
		}

		offset += step;
	}

	/*
	 * Only a token in reply to a request of ours to this node is news
	 * for the app, the same as the values below.  It is reported with
	 * the hash that request was for, which is what the app must name
	 * when it uses the token.
	 */
#if defined(LWS_WITH_DHT_BACKEND)
	if (sr && sr->id->len <= LWS_GENHASH_LARGEST) {
		ih->type = sr->id->type;
		ih->len	 = sr->id->len;
		memcpy(ih->id, sr->id->id, ih->len);
	}
#endif
	if (bound && ih->len && mp->token_len > 0 && ctx->cb)
		(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_TOKEN, ih, mp->token,
			   mp->token_len, from, fromlen);

	if (mp->values_len > 0 || mp->values6_len > 0) {
		lwsl_dht_rx("%s: Got values (%d+%d)\n", __func__, (int)(mp->values_len / LWS_DHT_NODE_INFO_IP4_VLEN), (int)(mp->values6_len / LWS_DHT_NODE_INFO_IP6_VLEN));
		if (ctx->cb) {
#if defined(LWS_WITH_DHT_BACKEND)
			if (sr) {
				int j, j6;
				for (j = 0; j < (int)mp->values_len; j += LWS_DHT_NODE_INFO_IP4_VLEN)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES, sr->id, mp->values + j, LWS_DHT_NODE_INFO_IP4_VLEN, from, fromlen);
				for (j6 = 0; j6 < (int)mp->values6_len; j6 += LWS_DHT_NODE_INFO_IP6_VLEN)
					(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES6, sr->id, mp->values6 + j6, LWS_DHT_NODE_INFO_IP6_VLEN, from, fromlen);
			}
#else
			int j, j6;
			for (j = 0; j < (int)mp->values_len; j += LWS_DHT_NODE_INFO_IP4_VLEN)
				(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES, NULL, mp->values + j, LWS_DHT_NODE_INFO_IP4_VLEN, from, fromlen);
			for (j6 = 0; j6 < (int)mp->values6_len; j6 += LWS_DHT_NODE_INFO_IP6_VLEN)
				(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_VALUES6, NULL, mp->values6 + j6, LWS_DHT_NODE_INFO_IP6_VLEN, from, fromlen);
#endif
		}
	}

#if defined(LWS_WITH_DHT_BACKEND)
	if (sr)
		search_send_get_peers(ctx, sr, NULL);
#endif

}

#if defined(LWS_WITH_DHT_BACKEND)
/*
 * The search node an announce_peer reply acknowledges, or NULL if we have no
 * announce outstanding to that node at that address.
 *
 * search_step() only sends announce_peer to nodes that already answered the
 * search's get_peers, and only on a search with a port to announce; the
 * request time it stamps then is cleared again by the ack.  So the node must
 * have replied, not yet acked, have been sent the announce recently, and be
 * both the id and the endpoint we sent it to: the 16-bit tid alone goes out
 * in every get_peers of the search and proves nothing about the sender.
 */
static struct search_node *
search_announce_awaiting_ack(struct lws_dht_ctx *ctx, struct search *sr,
			     const lws_dht_hash_t *id,
			     const struct sockaddr *from)
{
	int i;

	if (!sr->port)
		return NULL;

	for (i = 0; i < sr->numnodes; i++) {
		struct search_node *n = &sr->nodes[i];

		if (!n->replied || n->acked || !n->request_time ||
		    n->request_time < ctx->now - LWS_DHT_PING_TIMEOUT_SECS)
			continue;

		if (!id_cmp(n->id, id) &&
		    dht_sa_same_peer((const struct sockaddr *)&n->ss, from))
			return n;
	}

	return NULL;
}

static void
lws_dht_reply_announce(struct lws_dht_ctx *ctx, struct lws_dht_mparams *mp,
		       const struct sockaddr *from, size_t fromlen)
{
	struct search_node *n;
	struct search *sr;
	unsigned short ttid;

	if (!tid_match(mp->tid, "ap", &ttid))
		return;

	sr = find_search(ctx, ttid, from->sa_family);
	if (!sr) {
		lwsl_dht_rx_warn("%s: Unknown announce reply!\n", __func__);
		return;
	}

	/*
	 * Like the get_peers reply, only an ack from the node we sent the
	 * announce to, at the address we sent it to, may touch the search or
	 * confirm the sender: otherwise anyone who learns the tid can mark
	 * our announcement stored without it being sent, and promote himself
	 * (or relocate a known node id to his address) to a good node without
	 * ever answering a ping.
	 */
	n = search_announce_awaiting_ack(ctx, sr, mp->id, from);
	if (!n) {
		lwsl_dht_rx_warn("%s: announce reply from a node with no "
				 "announce outstanding\n", __func__);
		return;
	}

	lwsl_dht_rx("%s: Announce peer reply!\n", __func__);

	maybe_new_node(ctx, mp->id, from, fromlen, 2);

	n->request_time	= 0;
	n->reply_time	= ctx->now;
	n->acked	= 1;
	n->pinged	= 0;

	search_send_get_peers(ctx, sr, NULL);
}
#endif

/*
 * A peer answered something we sent it with a BEP 5 error ("y":"e").  It
 * names no sender id, so there is nothing to confirm the source against, and
 * it changes nothing in our tables: it is reported to the application with
 * the address it came from, which is as unauthenticated as any datagram's.
 */
static void
lws_dht_rx_error(struct lws_dht_ctx *ctx, const struct lws_dht_mparams *mp,
		 const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_error_info ei;

	lwsl_dht_rx("%s: error reply %d '%.*s' (tid len %d)\n", __func__,
		    mp->error_code, (int)mp->error_msg_len,
		    (const char *)mp->error_msg, (int)mp->tid_len);

	if (!ctx->cb)
		return;

	memset(&ei, 0, sizeof(ei));
	ei.tid		= mp->tid;
	ei.tid_len	= mp->tid_len;
	ei.message	= (const char *)mp->error_msg;
	ei.message_len	= mp->error_msg_len;
	ei.code		= mp->error_code;

	ctx->cb(ctx->closure, LWS_DHT_EVENT_ERROR, NULL, &ei, sizeof(ei),
		from, fromlen);
}

/*
 * An ack for data one of our sequencers sent.  Acks are replies, which anyone
 * can send with any source address, and what they say retires our copy of the
 * data and proves the peer receives from us (so we retransmit to it).  So an
 * ack counts only if it echoes the random tid the sequencer for that endpoint
 * sends its chunks with, which only someone who saw our chunks knows; the
 * sequencer itself then refuses one claiming bytes we never sent.
 */

static void
dht_seq_ack(struct lws_dht_ctx *ctx, const struct lws_dht_mparams *mp,
	    const struct sockaddr *from)
{
	lws_dht_ts_t *dts = lws_dht_ts_find(ctx, from);

	if (!dts) {
		lwsl_dht_rx("%s: late ack, no sequencer for its source\n",
			    __func__);
		return;
	}

	if (lws_timingsafe_bcmp(dts->tx_tid, mp->tid, LWS_DHT_SEQ_TID_LEN)) {
		/* DIAGNOSTIC (temporary): who, it may be why we're stuck */
		lwsl_dht_rx_warn("%s: ack from %s without our sequencer's "
				 "nonce, dropped: if it repeats, the peer acks "
				 "an old session of ours\n", __func__,
				 dts->peer);
		return;
	}

	lws_dht_ts_touch(dts);

	if (mp->ch_len) {
		/*
		 * The peer does not know our session (it lost it, or we
		 * restarted) and challenges us to prove the chunks are ours:
		 * from now on they carry its challenge.  A challenge we
		 * already answer is not a reason to send anything again.
		 */
		if (dts->tx_ch_set &&
		    !memcmp(dts->tx_ch, mp->ch, sizeof(dts->tx_ch)))
			return;

		memcpy(dts->tx_ch, mp->ch, sizeof(dts->tx_ch));
		dts->tx_ch_set = 1;

		/*
		 * It receives from 0 in the session it is starting: if it
		 * restarted, what it acked is gone, and carrying on where our
		 * stream was would leave it waiting for data below that, that
		 * we will not send again
		 */
		lws_transport_sequencer_tx_rebase(dts->ts);
		lws_transport_sequencer_resend(dts->ts);

		return;
	}

	/* an ack lacking the offset leaves it at ~0, refused below */
	if (mp->offset > (uint64_t)-1 - mp->len ||
	    lws_transport_sequencer_acknowledge_sack(dts->ts,
						     mp->offset + mp->len,
						     mp->sack, mp->num_sack,
						     mp->status) >= 0)
		return;

	/*
	 * It echoed our nonce, so it received our chunks at that address, and
	 * then acked data we never sent it: it's broken or hostile, nothing
	 * we send it can be trusted to be delivered.  A refused ack touched
	 * nothing, dts is still there.
	 */
#if defined(LWS_WITH_DHT_BACKEND)
	blacklist_node(ctx, mp->id, from, dts->salen,
		       "acked data we never sent it");
#else
	dht_blacklist_endpoint(ctx, from, dts->salen,
			       "acked data we never sent it");
#endif
	lws_dht_ts_fail(dts);
}

/*
 * A data chunk: one of the peer's sequencer's, or a forgery with its source
 * address.  The receive half is bound to the peer's session, the tid its
 * chunks carry, from the first chunk it takes: anything that can feed the
 * sequencer or change the tid our acks echo is the session's.  Before this a
 * spoofer's chunk at the peer's next offset was delivered and the peer's own
 * acked unseen as a duplicate, and any datagram re-steered the tid of our
 * acks so the peer dropped them (G-141).
 *
 * A chunk with another tid is the peer restarted (a new sequencer, offsets
 * from 0) or a forgery.  It is not taken; we answer it with our challenge,
 * which a new sequencer of the peer's gets at the peer's address and sends
 * back with its chunks.  Only then is the old session replaced, and received
 * again from 0: before, the restarted peer's chunks were duplicates of the
 * old stream and acked with offsets it never sent (G-133).
 *
 * The first session is proven the same way.  Binding the receive half to
 * whatever tid came first let a blind spoofer of a peer we already had a
 * proven sequencer for (one we made to send to it, or a good node of our
 * routing table) start the session with its own tid, and have each forged
 * request answered to that peer in full: the send half's proof, the peer
 * acking what we sent, says nothing about who sent what we receive (G-204).
 * So a receive half takes nothing until a chunk carries back the challenge
 * that went to the peer's address, which costs a new transfer one round
 * trip.  A peer predating the challenge drops it as a broken ack, so it can
 * no longer start a transfer to us at all.
 *
 * A session tid is "sq" and a nonce, LWS_DHT_SEQ_TID_LEN long, the shape
 * every sender since G-096 uses.  Anything else gets no answer at all, not
 * even a challenge.  Released v5.0.0 sends its chunks with the fixed tid
 * "sqnc" and takes any 4-byte reply tid starting "sq" (or "da") as an ack,
 * one with no offset as an ack of everything: it would free its data and
 * report success for a transfer we never took (G-213).  Unanswered, it fails
 * visibly when its retries run out.  Since our challenges and acks only ever
 * echo a tid of this shape, v5.0.0 refuses every one of them (it takes only
 * 4 or 16-byte reply tids), whoever sent the chunk they answer.
 */

static void
dht_seq_data(struct lws_dht_ctx *ctx, const struct lws_dht_mparams *mp,
	     const struct sockaddr *from, size_t fromlen)
{
	struct lws_transport_sequencer *ts;
	lws_dht_ts_t *dts;

	if (mp->tid_len != LWS_DHT_SEQ_TID_LEN ||
	    !tid_match(mp->tid, "sq", NULL)) {
		lwsl_dht_rx("%s: chunk without a session tid (legacy "
			    "sender?), not answered\n", __func__);
		ctx->stats_current.rx_drops++;
		return;
	}

	/*
	 * Making a sequencer for a source we have never heard from costs
	 * ~160KB of allocation and a challenge to an unverified address: that
	 * is rate limited, and the sequencer won't repeat anything to such a
	 * source until it has acknowledged it
	 */
	ts = lws_dht_ts_rx(ctx, from, fromlen, mp->id);
	if (!ts)
		return;

	dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;

	if (!dts->rx_tid_len || dts->rx_tid_len != mp->tid_len ||
	    lws_timingsafe_bcmp(dts->rx_tid, mp->tid, (uint32_t)mp->tid_len)) {

		if (mp->ch_len != sizeof(dts->rx_ch) ||
		    lws_timingsafe_bcmp(dts->rx_ch, mp->ch,
					sizeof(dts->rx_ch))) {
			lwsl_dht_rx("%s: chunk not of a proven session of the "
				    "peer's, challenged\n", __func__);
			dht_tx_challenge(dts, mp->tid, mp->tid_len);
			return;
		}

		/*
		 * A new session from a host that has its share already: a
		 * replacement for one it has is fine, but a host can't prove
		 * sessions on any number of ports to keep the table (G-496)
		 */
		if (!dts->rx_tid_len && !lws_dht_ts_host_may_prove(dts)) {
			lwsl_dht_rx_warn("%s: its host has %d sessions "
					 "already, refused\n", __func__,
					 LWS_DHT_TS_SESSIONS_PER_HOST);
			ctx->stats_current.rx_drops++;
			return;
		}

		lwsl_dht_rx_warn("%s: %s proved a %s session, its chunk at "
				 "%llu\n", __func__, dts->peer,
				 dts->rx_tid_len ? "new" : "first",
				 (unsigned long long)mp->offset);
		if (dts->rx_tid_len)
			lws_transport_sequencer_rx_reset(ts);
		memcpy(dts->rx_tid, mp->tid, mp->tid_len);
		dts->rx_tid_len = mp->tid_len;
		/* the next session must be proven afresh */
		if (lws_get_random(ctx->vhost->context, dts->rx_ch,
				   sizeof(dts->rx_ch)) != sizeof(dts->rx_ch))
			return;
	}

	lws_dht_ts_touch(dts);
	lws_transport_sequencer_rx(ts, mp->offset, mp->data, mp->data_len);
}

int
lws_dht_process_packet(struct lws_dht_ctx *ctx, const void *buf, size_t buflen,
			const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_mparams mp;
	int message;

	memset(&mp, 0, sizeof(mp));
	mp.offset = (uint64_t)-1;

	ctx->now = (time_t)lws_now_secs();

	if (is_martian(ctx, from))
		return 0;

	if (node_blacklisted(ctx, from, fromlen)) {
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		char ads[64] = "unknown";

		lws_sa46_write_numeric_address((lws_sockaddr46 *)from, ads,
					       sizeof(ads));
		lwsl_dht_rx("%s: dropping %u bytes from blacklisted %s:%u\n",
			    __func__, (unsigned int)buflen, ads,
			    ntohs(dht_sa_port(from)));
#endif
		return 0;
	}

	message = parse_message(buf, buflen, &mp);
	if (message == DHT_ERROR) {
		lws_dht_rx_error(ctx, &mp, from, fromlen);
		goto done;
	}
	if (message < 0 || lws_dht_hash_is_zero(mp.id)) {
		ctx->stats_current.rx_drops++;
		lwsl_dht_rx_warn("%s: Unparseable message. msg=%d id_ptr=%p\n", __func__, message, mp.id);
		goto done;
	}

	if (id_cmp(mp.id, ctx->myid) == 0) {
		char ip[64] = "unknown";

		if (from->sa_family == AF_INET)
			inet_ntop(AF_INET, &((struct sockaddr_in *)from)->sin_addr, ip, sizeof(ip));
		else if (from->sa_family == AF_INET6)
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)from)->sin6_addr, ip, sizeof(ip));
		lwsl_dht_info("%s: Received message from self. from %s:%u id %02x ctx->myid %02x, ctx %p\n", __func__, ip, (unsigned int)ntohs(dht_sa_port(from)), mp.id->id[0], ctx->myid->id[0], ctx);
		goto done;
	}

	/*
	 * Rate limit requests.
	 *
	 * This used to read "message > DHT_REPLY", which was correct for the
	 * original enum where REPLY was 1 and every request sorted above it.
	 * With the lws numbering (see private-lib-misc-dht.h) that expression
	 * selects only DHT_ERROR (already dropped above) and DHT_PING, ie, it
	 * had stopped limiting anything that matters.  Enumerate the request
	 * verbs explicitly instead so renumbering cannot silently disable it
	 * again.
	 *
	 * DHT_DATA stays outside the limiter: it is one chunk of an in-progress
	 * reliable transfer rather than a standalone query, and 100/s would
	 * throttle legitimate bulk transfer.  Its cost is bounded instead by
	 * the LWS_DHT_MAX_TS cap on concurrent sequencers.
	 */
	if (message == DHT_PING || message == DHT_FIND_NODE ||
	    message == DHT_GET_PEERS || message == DHT_ANNOUNCE_PEER ||
	    message == DHT_SUBSCRIBE || message == DHT_SUBSCRIBE_CONFIRM ||
	    message == DHT_NOTIFY) {
		/* in every build: a frontend-only one still acks notify */
		if (!lws_dht_admit_request(ctx, mp.id, from)) {
			ctx->stats_current.rx_drops++;
			lwsl_dht_warn("%s: Dropping request due to rate limiting\n", __func__);
			goto done;
		}
	} else if (message == DHT_REPLY && mp.sender_ip_len) {
		/*
		 * A reply to our external-address probe, telling us what our
		 * address looks like from outside.  It counts only if it
		 * carries the random nonce we sent to that very node and comes
		 * from where we sent it, once per probe; lws_dht_ip_vote()
		 * decides what it is worth.
		 */
		lws_sockaddr46 rep;
		int j, probe = -1;

		if (mp.tid_len != LWS_DHT_IP_PROBE_TID_LEN ||
		    !tid_match(mp.tid, "ip", NULL))
			goto skip_ip_tracking;

		for (j = 0; j < ctx->ip_probe_count; j++)
			if (!ctx->ip_probes[j].answered &&
			    ctx->ip_probes[j].sslen == fromlen &&
			    dht_sa_same_peer((const struct sockaddr *)
					     &ctx->ip_probes[j].ss, from) &&
			    !lws_timingsafe_bcmp(ctx->ip_probes[j].nonce,
						 mp.tid + 2,
						 LWS_DHT_IP_PROBE_NONCE_LEN)) {
				probe = j;
				break;
			}

		if (probe < 0) {
			lwsl_dht_warn("%s: IP tracking reply matches no probe, dropped\n", __func__);
			goto skip_ip_tracking;
		}

		memset(&rep, 0, sizeof(rep));
		if (mp.sender_ip_len == 4) {
			rep.sa4.sin_family = AF_INET;
			memcpy(&rep.sa4.sin_addr, mp.sender_ip, 4);
			rep.sa4.sin_port = htons(mp.sender_port);
		} else {
#if defined(LWS_WITH_IPV6)
			rep.sa6.sin6_family = AF_INET6;
			memcpy(&rep.sa6.sin6_addr, mp.sender_ip, 16);
			rep.sa6.sin6_port = htons(mp.sender_port);
#else
			goto skip_ip_tracking;
#endif
		}

		/*
		 * A node can only see us on the family it was probed on: a v4
		 * node reporting a v6 address for us would be a vote nobody
		 * else in that family's round could have cast
		 */
		if (rep.sa4.sin_family != ctx->ip_probes[probe].ss.ss_family) {
			lwsl_dht_warn("%s: IP tracking reply family mismatch, dropped\n", __func__);
			goto skip_ip_tracking;
		}
		ctx->ip_probes[probe].answered = 1;

		lws_dht_ip_vote(ctx, from, fromlen, &rep);
skip_ip_tracking:
		;
	}

	switch(message) {
	case DHT_REPLY:
		if (mp.tid_len == 16) {
#if defined(LWS_WITH_DHT_BACKEND)
			/* bound to the subscription the tid belongs to */
			lws_dht_clear_pending_notify(ctx, mp.tid, mp.tid_len,
						     from);
#endif
			break;
		}

		/*
		 * Every other reply has to answer a request we sent, from the
		 * endpoint we sent it to, once.  Replies are free to send from
		 * any address, and what they carry (the sender's id, nodes
		 * lists) goes into our routing table: an unsolicited or forged
		 * one is dropped whole (G-119).  The transport's acks are
		 * bound to their sequencer by its nonce instead.
		 */
		if (mp.tid_len == LWS_DHT_SEQ_TID_LEN &&
		    tid_match(mp.tid, "sq", NULL)) {
			dht_seq_ack(ctx, &mp, from);
			break;
		}

		if (!dht_req_pending_take(ctx, mp.tid, mp.tid_len, from)) {
			lwsl_dht_rx_warn("%s: reply to no request of ours, "
					 "dropped\n", __func__);
			break;
		}

		if (mp.tid_len == LWS_DHT_IP_PROBE_TID_LEN &&
		    tid_match(mp.tid, "ip", NULL)) {
			/* the pong to an external-address probe */
			ctx->stats_current.rx_pong++;
			lws_dht_reply_pong(ctx, &mp, from, fromlen);
			break;
		}
		if (mp.tid_len != 4) {
			/*
			 * Not blacklisted: a reply's source is unverified, so a
			 * malformed one with a spoofed source would blacklist
			 * whoever the attacker names for us
			 */
			lwsl_dht_rx_warn("%s: Broken node truncates transaction ids\n", __func__);
			break;
		}
		if (tid_match(mp.tid, "pn", NULL) || tid_match(mp.tid, "nt", NULL)) {
			ctx->stats_current.rx_pong++;
			lws_dht_reply_pong(ctx, &mp, from, fromlen);
			break;
		}
		/* a subscribe is answered like a get_peers: nodes + token */
		if (tid_match(mp.tid, "fn", NULL) || tid_match(mp.tid, "gp", NULL) ||
		    tid_match(mp.tid, "sb", NULL)) {
			lws_dht_reply_nodes(ctx, &mp, from, fromlen);
			break;
		}
#if defined(LWS_WITH_DHT_BACKEND)
		if (tid_match(mp.tid, "ap", NULL)) {
			lws_dht_reply_announce(ctx, &mp, from, fromlen);
			break;
		}
#endif

		lwsl_dht_rx_warn("%s: Unexpected reply (tid '%.*s' len %d)\n", __func__, (int)mp.tid_len, mp.tid, (int)mp.tid_len);
		lwsl_hexdump_dht(buf, buflen);
#if defined(LWS_WITH_DHT_BACKEND)
		(void)0; /* not blacklisted: unverified source, see above */
#endif
		break;

	case DHT_PING:
		ctx->stats_current.rx_ping++;
		lwsl_dht_rx("%s: Ping (%d)!\n", __func__, (int)mp.tid_len);
#if defined(LWS_WITH_DHT_BACKEND)
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
		lwsl_dht_rx("%s: Sending pong\n", __func__);
		send_pong(ctx, from, fromlen, mp.tid, mp.tid_len);
#endif
		break;

	case DHT_FIND_NODE:
		ctx->stats_current.rx_find_node++;
		lwsl_dht_rx("%s: Find node!\n", __func__);
#if defined(LWS_WITH_DHT_BACKEND)
		/*
		 * A find_node without a target, or with one the validator
		 * refused, leaves mp.target NULL; the closest-nodes walk
		 * compares against it.  Refuse it like the sibling verbs do.
		 */
		if (!mp.target) {
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
				   203, "find_node with no target");
			goto fail;
		}
		maybe_new_node(ctx, mp.id, from, fromlen, 1);
#endif
		lwsl_dht_rx("%s: Sending closest nodes (%d)\n", __func__, mp.want);
#if defined(LWS_WITH_DHT_BACKEND)
		send_closest_nodes(ctx, from, fromlen, &mp, mp.target, from->sa_family, NULL);
#endif
		break;

	case DHT_GET_PEERS:
	case DHT_SUBSCRIBE:
		if (message == DHT_GET_PEERS)
			ctx->stats_current.rx_get_peers++;
#if defined(LWS_WITH_DHT_BACKEND)
		if (!mp.info_hash) {
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
				   203, "Get_peers/Subscribe with no info_hash");
			goto fail;
		}

		{
			struct storage *st = find_storage(ctx, mp.info_hash);

			/*
			 * The freshly derived token must actually go out in
			 * the reply: send_closest_nodes() only includes the
			 * token member when token_len is set, and without it
			 * peers can never announce on this hash, since a
			 * valid token is what authorize announce_peer.  It
			 * is only good for this info_hash.
			 */
			make_token(ctx, from, mp.info_hash, 0, mp.token);
			mp.token_len = TOKEN_SIZE;

			/* Has it? */
			if (st && st->numpeers > 0) {
				send_closest_nodes(ctx, from, fromlen,
						   &mp, mp.info_hash, from->sa_family, st);
			} else
				send_closest_nodes(ctx, from, fromlen,
						   &mp, mp.info_hash, from->sa_family, NULL);
		}
#endif
		break;

	case DHT_SUBSCRIBE_CONFIRM:
#if defined(LWS_WITH_DHT_BACKEND)
		if (!mp.info_hash) {
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
				   203, "Subscribe_confirm with no info_hash");
			goto fail;
		}

		if (!token_match(ctx, mp.token, mp.token_len, from,
				 mp.info_hash))
			goto fail;

		/* Validation passed, register the subscriber */
		{
			struct storage *st = storage_get(ctx, mp.info_hash,
							 from);
			struct subscriber *sub = NULL;
			int found = 0, from_src = 0;

			if (!st)
				goto fail;

			/*
			 * A subscriber is an endpoint: a renewed confirm from
			 * it, whatever tid it now wants its notifies under,
			 * refreshes its one entry.  Keying on (endpoint, tid)
			 * let one source take a slot per tid it made up, so
			 * with 32 datagrams an hour it held every slot of a
			 * hash and real subscribers were refused.  New
			 * endpoints also get only a small share per source,
			 * like announced peers (C-073).
			 */
			lws_start_foreach_dll(struct lws_dll2 *, d,
					      lws_dll2_get_head(&st->subscribers)) {
				sub = lws_container_of(d, struct subscriber, list);

				if (dht_sa_same_peer((const struct sockaddr *)
						     &sub->ss, from)) {
					found = 1;
					break;
				}
				if (lws_dht_same_host((const struct sockaddr *)
						     &sub->ss, from))
					from_src++;
			} lws_end_foreach_dll(d);

			if (!found) {
				if (from_src >= LWS_DHT_MAX_SUBSCRIBERS_PER_SRC) {
					lwsl_dht_rx_warn("%s: source subscriber "
							 "limit reached\n",
							 __func__);
					goto fail;
				}
				/* the scan above is O(n) per packet: cap n */
				if (lws_dll2_count(&st->subscribers) >=
						    LWS_DHT_MAX_SUBSCRIBERS) {
					lwsl_dht_rx_warn("%s: subscriber limit "
							 "reached\n", __func__);
					goto fail;
				}

				sub = lws_zalloc(sizeof(*sub), "dht subscriber");
				if (!sub) goto fail;
				memcpy(&sub->ss, from, fromlen);
				sub->sslen = fromlen;
				lws_dll2_add_head(&sub->list, &st->subscribers);
			}

			/* notifies go out under the tid it asked for last */
			memcpy(sub->tid, mp.tid, mp.tid_len);
			sub->tid_len = mp.tid_len;
			sub->expire = ctx->now + 3600; /* 1 hour TTL */
			memcpy(sub->current_sha256, mp.sha256, 32);

			/* Acknowledge */
			lws_dht_send_ack(ctx, from, fromlen, mp.tid, mp.tid_len);
		}
#endif
		break;

	case DHT_NOTIFY:
		if (!mp.info_hash) {
			lwsl_dht_rx_warn("%s: NOTIFY with no info_hash\n", __func__);
			goto done;
		}

		{
			char peer_ip[64];
			lws_sa46_write_numeric_address((lws_sockaddr46 *)from, peer_ip, sizeof(peer_ip));
			lwsl_notice("%s: Parsed NOTIFY from %s:%u. TID is %d bytes:\n", __func__, peer_ip, (unsigned int)ntohs(dht_sa_port(from)), (int)mp.tid_len);
		}
		/* Disable hexdump on rx as it is a bit noisy unless debugging, keeping structural logs: */
		/* lwsl_hexdump_notice(mp.tid, mp.tid_len); */
		/* lwsl_notice("Original NOTIFY packet (%d bytes):\n", (int)buflen); */
		/* lwsl_hexdump_notice(buf, buflen); */

		/* Acknowledge the NOTIFY so the sender marks us as delivered */
		lws_dht_send_ack(ctx, from, fromlen, mp.tid, mp.tid_len);

		if (ctx->cb) {
			(*ctx->cb)(ctx->closure, LWS_DHT_EVENT_NOTIFY, mp.info_hash, mp.data, mp.data_len, from, fromlen);
		}
		break;

	case DHT_DATA:
		if (mp.data) {
			char peer[64]; /* DIAGNOSTIC (temporary) */

			lws_dht_describe_peer(from, peer, sizeof(peer));
			/* one per chunk: debug, the sequencer says if one is stuck */
			lwsl_debug("%s: Received reliable data payload (%d bytes, offset %llu) from %s\n",
				    __func__, (int)mp.data_len,
				    (unsigned long long)mp.offset, peer);
			dht_seq_data(ctx, &mp, from, fromlen);
		}
		break;
	case DHT_ANNOUNCE_PEER:
		ctx->stats_current.rx_announce_peer++;
#if defined(LWS_WITH_DHT_BACKEND)
		if (!mp.info_hash) {
			send_error(ctx, from, fromlen, mp.tid, mp.tid_len,
				   203, "Announce_peer with no info_hash");
			goto fail;
		}

		if (!token_match(ctx, mp.token, mp.token_len, from,
				 mp.info_hash))
			goto fail;

		/* lwsl_info("%s: Announce peer\n", __func__); */

		lws_dht_capture_announce(ctx, mp.info_hash, from, mp.port ? mp.port : mp.sender_port);

		/*
		 * We have a 'values' request
		 *
		 * In theory, the node must be inserted in the routing table, but
		 * this is vulnerable to spam so we just insert the node if it's
		 * pingable.
		 */

		storage_store(ctx, mp.info_hash, from, mp.port, 0);

		/*
		 * we just drop it if we didn't add it.
		 */

		/* if we add it, we should reply */
		lws_dht_send_ack(ctx, from, fromlen, mp.tid, mp.tid_len);
#endif
		break;
	}
#if defined(LWS_WITH_DHT_BACKEND)
fail:
	/*lwsl_dht_warn("lws_dht_process_packet: fail\n");*/
#endif
done:
	lws_dht_hash_destroy(&mp.id);
	lws_dht_hash_destroy(&mp.info_hash);
	lws_dht_hash_destroy(&mp.target);

	return 0;
}
