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

static const uint8_t zeroes[20]		= {0};
static const uint8_t v4prefix[16] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

/*
 * BEP42 (DHT security extension): the first 21 bits of a node id are the
 * CRC32C of the node's masked public IP with three bits of a random byte r
 * folded in, and the last byte of the id is r.
 */

static uint32_t
dht_crc32c(const uint8_t *p, size_t len)
{
	uint32_t crc = 0xffffffffu;
	int n;

	while (len--) {
		crc ^= *p++;
		for (n = 0; n < 8; n++)
			crc = (crc >> 1) ^ (0x82f63b78u & (0u - (crc & 1u)));
	}

	return ~crc;
}

/* the BEP42 21-bit prefix for sa and r, into pre[0..2] (pre[2] bits 7..3) */
static int
dht_bep42_prefix(const struct sockaddr *sa, uint8_t r, uint8_t *pre)
{
	static const uint8_t m4[4] = { 0x03, 0x0f, 0x3f, 0xff },
			     m6[8] = { 0x01, 0x03, 0x07, 0x0f,
				       0x1f, 0x3f, 0x7f, 0xff };
	uint8_t ip[8];
	uint32_t crc;
	size_t n, len;

	switch (sa->sa_family) {
	case AF_INET:
		memcpy(ip, &((const struct sockaddr_in *)sa)->sin_addr, 4);
		for (n = 0; n < 4; n++)
			ip[n] &= m4[n];
		len = 4;
		break;
	case AF_INET6:
		memcpy(ip, &((const struct sockaddr_in6 *)sa)->sin6_addr, 8);
		for (n = 0; n < 8; n++)
			ip[n] &= m6[n];
		len = 8;
		break;
	default:
		return 1;
	}

	ip[0] |= (uint8_t)((r & 7) << 5);
	crc = dht_crc32c(ip, len);
	pre[0] = (uint8_t)(crc >> 24);
	pre[1] = (uint8_t)(crc >> 16);
	pre[2] = (uint8_t)((crc >> 8) & 0xf8);

	return 0;
}

lws_dht_hash_t *
lws_dht_bep42_id(struct lws_context *cx, const struct sockaddr *sa,
		 uint8_t rand, int type, int len)
{
	uint8_t id[64], pre[3];
	lws_dht_hash_t *h;

	if (len < 4 || len > (int)sizeof(id) || dht_bep42_prefix(sa, rand, pre))
		return NULL;

	lws_get_random(cx, id, (size_t)len);
	id[0] = pre[0];
	id[1] = pre[1];
	id[2] = (uint8_t)(pre[2] | (id[2] & 7));
	id[len - 1] = rand;

	h = lws_dht_hash_create(type, len, id);
	lws_explicit_bzero(id, sizeof(id));

	return h;
}

int
lws_dht_bep42_check(const lws_dht_hash_t *id, const struct sockaddr *sa)
{
	uint8_t pre[3];

	if (!id || id->len < 4 || dht_bep42_prefix(sa, id->id[id->len - 1], pre))
		return 0;

	return id->id[0] == pre[0] && id->id[1] == pre[1] &&
	       (id->id[2] & 0xf8) == pre[2];
}

/*
 * Our external address has just been agreed by a quorum of peers: an id we
 * made up at random is replaced by one bound to that address, so peers that
 * check BEP42 keep us.  An id the application gave us is its own business.
 * The routing table stays as it is; it is valid for any id, and peers learn
 * the new one from our next message to them.
 */
void
lws_dht_bep42_own_id(struct lws_dht_ctx *ctx, const struct sockaddr *sa)
{
	lws_dht_hash_t *h;
	uint8_t r;

	if (!ctx->id_random || !ctx->myid || lws_dht_bep42_check(ctx->myid, sa))
		return;

	lws_get_random(ctx->vhost->context, &r, 1);
	h = lws_dht_bep42_id(ctx->vhost->context, sa, r, ctx->myid->type,
			     ctx->myid->len);
	if (!h)
		return;

	lwsl_notice("%s: own id now bound to external address (BEP42)\n",
		    __func__);
	lws_dht_hash_destroy(&ctx->myid);
	ctx->myid = h;
}

void
lws_dht_capture_announce(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash,
			 const struct sockaddr *fromaddr, unsigned short prt)
{
	if (ctx->capture_announce_cb)
		ctx->capture_announce_cb(ctx, hash, fromaddr, prt);
}

/*
 * An address that is not on the public internet: loopback, RFC 1918 and
 * RFC 6598 private ranges, link-local and IPv6 ULA.  Such a peer is refused
 * unless the dht was created with allow_private_ads, and is exempt from the
 * BEP42 id check (BEP42 only binds public addresses).
 */
int
lws_dht_ads_is_private(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET: {
		const uint8_t *a = (const uint8_t *)
				&((const struct sockaddr_in *)sa)->sin_addr;

		return a[0] == 127 || a[0] == 10 ||
		       (a[0] == 172 && (a[1] & 0xf0) == 16) ||
		       (a[0] == 192 && a[1] == 168) ||
		       (a[0] == 169 && a[1] == 254) ||
		       (a[0] == 100 && (a[1] & 0xc0) == 64);
	}
	case AF_INET6: {
		const uint8_t *a = (const uint8_t *)
				&((const struct sockaddr_in6 *)sa)->sin6_addr;

		return (a[0] & 0xfe) == 0xfc ||
		       (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) ||
		       (!memcmp(a, zeroes, 15) && a[15] == 1);
	}
	default:
		return 0;
	}
}

int
is_martian(const struct lws_dht_ctx *ctx, const struct sockaddr *sa)
{
	if (lws_dht_ads_is_private(sa) && !ctx->allow_private_ads)
		return 1;

	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in*)sa;
			const uint8_t *address = (const uint8_t*)&sin->sin_addr;

			return sin->sin_port == 0 ||
				(address[0] == 0) ||
				((address[0] & 0xE0) == 0xE0);
			}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
			const uint8_t *address = (const uint8_t*)&sin6->sin6_addr;

			return sin6->sin6_port == 0 ||
				(address[0] == 0xFF) ||
				(address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
				(memcmp(address, zeroes, 15) == 0 &&
				(address[15] == 0 || address[15] == 1)) ||
				(memcmp(address, v4prefix, 12) == 0);
		}

		default:
			break;
	}

	return 0;
}


/*
 * Take a token from a bucket, refilling it first if it is empty.
 *
 * ->now is wall clock, so a backwards step (NTP, snapshot restore) can make
 * the elapsed time negative.  Test <= 0 and clamp the refill at 0: with an
 * "== 0" test a single negative refill left the counter negative forever,
 * so the limiter silently never fired again for the life of the context.
 */

static int
dht_tb_take(struct lws_dht_ctx *ctx, lws_dht_tb_t *tb, int rate, int burst)
{
	if (tb->tokens <= 0) {
		long elapsed = (long)(ctx->now - tb->time);

		if (elapsed < 0)
			elapsed = 0;

		tb->tokens = (int)MIN((long)burst, (long)rate * elapsed);
		tb->time = ctx->now;
	}

	if (tb->tokens <= 0)
		return 0;

	tb->tokens--;

	return 1;
}

/*
 * Every request costs us a reply, so requests are rate limited (C-071).  A
 * single bucket for all of them let one source, sending ~100 pings/s, take
 * every token, and we then dropped every other peer's requests, including
 * those of the nodes we actually work with.  So a request is admitted in
 * two stages:
 *
 *  - its source (dht_source_key()) has a small bucket of its own, in a
 *    fixed table recycled in LRU order, and no source gets more than that
 *    share of what follows;
 *
 *  - it then draws from one of two pools: requests from a good node of our
 *    routing table, from the endpoint we hold for it (which C-594 stops
 *    anyone else moving), use their own pool; everything else, including
 *    anything from spoofed sources, uses the general pool.  A flood can
 *    exhaust the general pool, but the nodes we already know keep being
 *    answered.
 *
 * Losing a table slot only ever gives a source a full bucket again, so
 * churning the table cannot starve anyone; the pools stay the hard cap on
 * the total.
 */

/*
 * Is `from` a good node of our routing table, at the endpoint we hold for
 * it?  Since C-594 nobody else can move that endpoint while the node is
 * alive, so this is as close as an unauthenticated DHT gets to knowing the
 * source address is genuine.
 */

int
lws_dht_peer_known(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		   const struct sockaddr *from)
{
#if defined(LWS_WITH_DHT_BACKEND)
	struct node *n;

	if (!id)
		return 0;

	n = find_node(ctx, id, from->sa_family);

	return n && node_good(ctx, n) &&
	       dht_sa_same_peer((const struct sockaddr *)&n->ss, from);
#else
	(void)ctx;
	(void)id;
	(void)from;

	return 0;
#endif
}

int
lws_dht_admit_request(struct lws_dht_ctx *ctx, const lws_dht_hash_t *id,
		      const struct sockaddr *from)
{
	lws_dht_tb_t *pool = &ctx->rl_general;
	uint8_t key[16];
	int n, victim = 0;

	if (dht_source_key(from, key))
		return 0;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ctx->rl_src); n++) {
		if (ctx->rl_src[n].af == from->sa_family &&
		    !memcmp(ctx->rl_src[n].key, key, sizeof(key)))
			break;
		/* remember a free slot, else the least recently used */
		if (ctx->rl_src[victim].af &&
		    (!ctx->rl_src[n].af ||
		     ctx->rl_src[n].last < ctx->rl_src[victim].last))
			victim = n;
	}

	if (n == (int)LWS_ARRAY_SIZE(ctx->rl_src)) {
		n = victim;
		memcpy(ctx->rl_src[n].key, key, sizeof(key));
		ctx->rl_src[n].af		= (uint8_t)from->sa_family;
		ctx->rl_src[n].tb.tokens	= LWS_DHT_RL_SRC_BURST;
		ctx->rl_src[n].tb.time		= ctx->now;
	}

	ctx->rl_src[n].last = ctx->now;

	if (!dht_tb_take(ctx, &ctx->rl_src[n].tb, LWS_DHT_RL_SRC_RATE,
			 LWS_DHT_RL_SRC_BURST))
		return 0;

	if (lws_dht_peer_known(ctx, id, from))
		pool = &ctx->rl_known;

	return dht_tb_take(ctx, pool, LWS_DHT_RL_POOL_RATE,
			   LWS_DHT_RL_POOL_BURST);
}

/*
 * args: [ch], data, id, len, offset (alphabetical)
 *
 * ch is there once the peer has challenged our session (see
 * LWS_DHT_SEQ_CH_LEN): it is how the peer knows these chunks come from
 * whoever it sent the challenge to.
 */

int
dht_tx_chunk(struct lws_transport_sequencer *ts, uint64_t offset,
	     const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	char pkt[2048];
	dht_txbuf_t t = { .buf = pkt, .size = sizeof(pkt) };

	if (dht_tx_lit(&t, "d1:ad"))
		goto fail;

	if (dts->tx_ch_set &&
	    (dht_tx_lit(&t, "2:ch") ||
	     dht_tx_str(&t, dts->tx_ch, sizeof(dts->tx_ch))))
		goto fail;

	if (dht_tx_lit(&t, "4:data") ||
	    dht_tx_str(&t, buf, len) ||
	    dht_tx_lit(&t, "2:id") ||
	    dht_tx_id(dts->ctx, &t, dts->ctx->myid) ||
	    dht_tx_lit(&t, "3:len") ||
	    dht_tx_int(&t, len) ||
	    dht_tx_lit(&t, "6:offset") ||
	    dht_tx_int(&t, offset) ||
	    dht_tx_lit(&t, "e1:q4:data1:t") ||
	    dht_tx_str(&t, dts->tx_tid, sizeof(dts->tx_tid)) ||
	    dht_tx_lit(&t, "1:y1:qe"))
		goto fail;

	return dht_send(dts->ctx, pkt, t.len, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

/*
 * reply: id, len, offset, sack (alphabetical)
 *
 * The tid is the one the peer's session sends its chunks with: that is how
 * its sequencer knows the ack comes from someone who received them.  The
 * offset is how much of the peer's stream we hold, from the receive half:
 * the send half's progress is ours, and the peer refuses an ack beyond what
 * it sent.
 */

int
dht_tx_ack(struct lws_transport_sequencer *ts, uint64_t offset, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	const lws_transport_sequencer_stats_t *stats = lws_transport_sequencer_get_stats(ts);
	char pkt[512];
	dht_txbuf_t t = { .buf = pkt, .size = sizeof(pkt) };

	if (!dts->rx_tid_len)
		return -1; /* we only ack chunks we have been sent */

	if (dht_tx_lit(&t, "d1:rd2:id") ||
	    dht_tx_id(dts->ctx, &t, dts->ctx->myid) ||
	    dht_tx_lit(&t, "3:len") ||
	    dht_tx_int(&t, 0) ||
	    dht_tx_lit(&t, "6:offset") ||
	    dht_tx_int(&t, stats->rx_offset))
		goto fail;

	{
		lws_transport_sequencer_sack_block_t blocks[4];
		size_t num_blocks, j;

		num_blocks = lws_transport_sequencer_get_sack_blocks(ts, blocks, 4);
		if (num_blocks) {
			if (dht_tx_lit(&t, "4:sackl"))
				goto fail;
			for (j = 0; j < num_blocks; j++) {
				/* d1:li<len>e1:oi<start>ee */
				if (dht_tx_lit(&t, "d1:l") ||
				    dht_tx_int(&t, blocks[j].len) ||
				    dht_tx_lit(&t, "1:o") ||
				    dht_tx_int(&t, blocks[j].start) ||
				    dht_tx_lit(&t, "e"))
					goto fail;
			}
			if (dht_tx_lit(&t, "e"))
				goto fail;
		}
	}

	if (dht_tx_lit(&t, "e1:t") ||
	    dht_tx_str(&t, dts->rx_tid, dts->rx_tid_len) ||
	    dht_tx_lit(&t, "1:y1:re"))
		goto fail;

	return dht_send(dts->ctx, pkt, t.len, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

/*
 * reply: ch, id (alphabetical)
 *
 * The answer to a chunk whose tid is not the peer's session: it echoes that
 * tid, so only the sequencer that sent the chunk takes it, and carries the
 * challenge that sequencer must send back to start a new session with us.
 * It goes to the peer's address, which a blind spoofer does not see.  With
 * no offset, it acks nothing: peers predating the challenge drop it.  The
 * tid it echoes is always a session tid, LWS_DHT_SEQ_TID_LEN long, which
 * released v5.0.0 refuses as a reply tid: chunks with any other tid are not
 * answered (dht_seq_data(), G-213).
 */

int
dht_tx_challenge(lws_dht_ts_t *dts, const uint8_t *tid, size_t tid_len)
{
	char pkt[128];
	dht_txbuf_t t = { .buf = pkt, .size = sizeof(pkt) };

	if (dht_tx_lit(&t, "d1:rd2:ch") ||
	    dht_tx_str(&t, dts->rx_ch, sizeof(dts->rx_ch)) ||
	    dht_tx_lit(&t, "2:id") ||
	    dht_tx_id(dts->ctx, &t, dts->ctx->myid) ||
	    dht_tx_lit(&t, "e1:t") ||
	    dht_tx_str(&t, tid, tid_len) ||
	    dht_tx_lit(&t, "1:y1:re"))
		return -1;

	return dht_send(dts->ctx, pkt, t.len, (struct sockaddr *)&dts->sa,
			dts->salen);
}

/*
 * A chunk the sequencer for the peer at `from` received.  Whatever the
 * handlers send from here may create or touch up to LWS_DHT_MAX_TS other
 * sequencers: dht_on_rx_data() keeps the receiving one from being recycled
 * meanwhile, and `from` is a copy, not the sequencer's own address.
 */

static int
dht_deliver(struct lws_dht_ctx *ctx, const struct sockaddr *from,
	    size_t fromlen, const uint8_t *buf, size_t len)
{
	struct lws_dht_msg msg;

	int parse_ret = lws_dht_msg_parse((const char *)buf, len, &msg);
	if (!parse_ret) {
		if (!strcmp(msg.verb, "CAP_REQ")) {
			char ack[512], json[384], peer[64];
			int n, first = 1;
			const char *last_proto = NULL;

			/* DIAGNOSTIC (temporary) */
			lws_dht_describe_peer(from, peer, sizeof(peer));
			lwsl_notice("%s: CAP_REQ from %s, answering it with "
				    "CAP_RSP\n", __func__, peer);

			/*
			 * Anyone can send this, from any source address, and
			 * the answer is bigger than the question: it is a
			 * request like any other, and costs a token.  (If the
			 * source never acknowledges the answer, the sequencer
			 * does not repeat it: see dht_ts_create().)
			 */
			if (!lws_dht_admit_request(ctx, NULL, from)) {
				ctx->stats_current.rx_drops++;
				return 0;
			}

			n = lws_snprintf(json, sizeof(json), "{\"protocols\":[");

			/* Gather protocols (dumb uniqueness since they are added consecutively by register_verbs) */
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->verb_owner)) {
				struct lws_dht_verb_list *vl = lws_container_of(d, struct lws_dht_verb_list, list);

				lwsl_debug("CAP_REQ Generator Iteration: verb=%s, protocol=%s\n",
					vl->v.name ? vl->v.name : "null",
					(vl->v.protocol && vl->v.protocol->name) ? vl->v.protocol->name : "null");

				if (vl->v.protocol && (!last_proto || strcmp(vl->v.protocol->name, last_proto) != 0)) {
					n += lws_snprintf(json + n, sizeof(json) - (size_t)n, "%s\"%s\"", first ? "" : ",", vl->v.protocol->name);
					last_proto = vl->v.protocol->name;
					first = 0;
				}
			} lws_end_foreach_dll(d);

			/* Also return the peer's perceived public IP/port */
			if (from->sa_family == AF_INET) {
				const struct sockaddr_in *sin = (const struct sockaddr_in *)from;
				char ip[64];
				inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
				lws_snprintf(json + n, sizeof(json) - (size_t)n, "],\"peer_ip\":\"%s\",\"peer_port\":%d}", ip, ntohs(sin->sin_port));
			} else {
				const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)from;
				char ip[64];
				inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
				lws_snprintf(json + n, sizeof(json) - (size_t)n, "],\"peer_ip\":\"%s\",\"peer_port\":%d}", ip, ntohs(sin6->sin6_port));
			}

			n = lws_dht_msg_gen(ack, sizeof(ack), "CAP_RSP", msg.hash, 0, (unsigned long long)strlen(json));
			if (n > 0 && (size_t)n + strlen(json) < sizeof(ack)) {
				memcpy(ack + n, json, strlen(json));
				lws_dht_send_data(ctx, from, ack, (size_t)n + strlen(json));
			}
			return 0;
		}

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ctx->verb_owner)) {
			struct lws_dht_verb_list *vl = lws_container_of(d, struct lws_dht_verb_list, list);

			if (!strcmp(vl->v.name, msg.verb)) {
				struct lws_dht_verb_dispatch_args args;
				struct lws_context *cx = ctx->vhost->context;
				int n;
				lws_fakewsi_def_plwsa(&cx->pt[ctx->wsi_v4 ?
						ctx->wsi_v4->tsi : 0]);

				if (!strcmp(msg.verb, "PUT"))
					ctx->stats_current.rx_put++;
				else if (!strcmp(msg.verb, "GET"))
					ctx->stats_current.rx_get++;

				args.ctx = ctx;
				args.msg = &msg;
				args.from = from;
				args.fromlen = fromlen;

				/*
				 * There is no connection for this callback: it
				 * gets the pt's fake wsi, prepared for this
				 * vhost and protocol, which is a whole struct
				 * lws (except on freertos), so a handler that
				 * looks past the lws_a part is not reading off
				 * the end of a stack object
				 */
				lws_fakewsi_prep_plwsa_ctx(cx);
				plwsa->vhost = ctx->vhost;
				plwsa->protocol = vl->v.protocol;

				args.out_precedence = LWS_DHT_VERB_RESULT_PROCEED;

				// lwsl_notice("DISPATCHING %s to protocol %s\n", msg.verb, vl->v.protocol->name);

				n = vl->v.protocol->callback((struct lws *)plwsa, LWS_CALLBACK_DHT_VERB_DISPATCH,
							lws_protocol_vh_priv_get(ctx->vhost, vl->v.protocol),
							&args, 0);

				if (n < 0 || args.out_precedence == LWS_DHT_VERB_RESULT_DROP_OLDER || args.out_precedence == LWS_DHT_VERB_RESULT_ERROR)
					return -1;

				if (args.out_precedence == LWS_DHT_VERB_RESULT_PASS)
					/*
					 * The plugin actively declined to handle this payload and delegated it
					 * to the next plugin in the chain. Let's continue traversing the list!
					 */
					goto pass;

				if (args.out_precedence == LWS_DHT_VERB_RESULT_PENDING_ASYNC) {
					/* The plugin will handle validation asynchronously and ACK later.
					 * We just return 0 to keep the sequencer alive but don't ACK here.
					 * The object store plugin currently manually ACKs via its own verb handler logic anyway,
					 * but this formally signals the core that the chunk was 'accepted' for now.
					 */
					return 0;
				}

				return n;

pass:
				;
			}
		} lws_end_foreach_dll(d);
	}

	if (ctx->cb)
		ctx->cb(ctx->closure, LWS_DHT_EVENT_DATA, NULL, buf, len,
			from, fromlen);

	return 0;
}

int
dht_on_rx_data(struct lws_transport_sequencer *ts, uint64_t offset,
	       const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	struct sockaddr_storage from;
	size_t fromlen = dts->salen;
	int n;

	(void)offset;

	/*
	 * The sequencer is done with this chunk, but we are not done with the
	 * sequencer: in_cb keeps dht_ts_create() from recycling it while the
	 * handlers send (G-181)
	 */
	memcpy(&from, &dts->sa, sizeof(from));

	dts->in_cb++;
	n = dht_deliver(dts->ctx, (const struct sockaddr *)&from, fromlen,
			buf, len);
	dts->in_cb--;

	return n;
}

static void
lws_dht_ts_destroy(lws_dht_ts_t *dts)
{
	lws_sul_cancel(&dts->sul_idle);
	lws_transport_sequencer_destroy(&dts->ts);
	lws_dll2_remove(&dts->list);
	lws_free(dts);
}

void
dht_on_state_change(struct lws_transport_sequencer *ts, int state, int status)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	struct sockaddr_storage peer;

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	if (state != 0) {
		char ads[64] = "unknown";

		lws_sa46_write_numeric_address((lws_sockaddr46 *)&dts->sa, ads,
					       sizeof(ads));
		lwsl_notice("%s: session with %s:%u failed (status %d)\n",
			    __func__, ads,
			    ntohs(dht_sa_port((struct sockaddr *)&dts->sa)),
			    status);
	}
#endif

	/*
	 * The callback may send, and so recycle sequencers, but not this one,
	 * which we still have to destroy if the session failed (G-181)
	 */
	if (dts->ctx->cb) {
		memcpy(&peer, &dts->sa, sizeof(peer));
		dts->in_cb++;
		dts->ctx->cb(dts->ctx->closure,
			     state == 0 ? LWS_DHT_EVENT_WRITE_COMPLETED :
					  LWS_DHT_EVENT_WRITE_FAILED,
			     NULL, (void *)(intptr_t)status, 0,
			     (struct sockaddr *)&peer, dts->salen);
		dts->in_cb--;
	}

	if (state != 0)
		lws_dht_ts_destroy(dts);
}

/*
 * Is the peer still owed something by this sequencer: data of ours it hasn't
 * acked, which a consumer is waiting to hear the fate of, or the peer's
 * proven receive session, which a blind spoofer can't make?  Then it is not
 * ours to recycle for a newcomer, see dht_ts_create().
 */

static int
dht_ts_in_use(lws_dht_ts_t *dts)
{
	const lws_transport_sequencer_stats_t *st =
				lws_transport_sequencer_get_stats(dts->ts);

	return dts->in_cb || dts->rx_tid_len || st->tx_offset > st->ack_offset;
}

/*
 * Every way a sequencer ends, other than the context going away, comes here
 * or through dht_on_state_change(): if it still held data of ours the peer
 * never acked, the consumer hears WRITE_FAILED for it, as lws-dht.h promises
 * for anything QUEUED, and a consumer waiting for WRITEABLE after BUSY isn't
 * left waiting forever.
 */

static void
dht_ts_retire(lws_dht_ts_t *dts)
{
	const lws_transport_sequencer_stats_t *st =
				lws_transport_sequencer_get_stats(dts->ts);

	if (st->tx_offset > st->ack_offset) {
		dht_on_state_change(dts->ts, 1 /* FAILED */, 0); /* destroys */
		return;
	}

	lws_dht_ts_destroy(dts);
}

static void
lws_dht_ts_idle_cb(lws_sorted_usec_list_t *sul)
{
	dht_ts_retire(lws_container_of(sul, lws_dht_ts_t, sul_idle));
}

/* the peer has made room for what lws_dht_send_data() refused it */

static void
dht_on_writeable(struct lws_transport_sequencer *ts)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	struct sockaddr_storage peer;

	if (!dts->ctx->cb)
		return;

	/* the consumer will send, and may recycle sequencers, not this one */
	memcpy(&peer, &dts->sa, sizeof(peer));
	dts->in_cb++;
	dts->ctx->cb(dts->ctx->closure, LWS_DHT_EVENT_WRITEABLE, NULL, NULL, 0,
		     (struct sockaddr *)&peer, dts->salen);
	dts->in_cb--;
}

/*
 * End the session with the peer now, eg, because we blacklisted it, rather
 * than retransmit to it until the retries run out.  Not one that is calling
 * back into the consumer: that has its caller on the stack (G-181), and will
 * fail on time anyway.
 */

void
lws_dht_ts_fail(lws_dht_ts_t *dts)
{
	if (!dts->in_cb)
		dht_on_state_change(dts->ts, 1 /* FAILED */, 0);
}

static const lws_transport_sequencer_ops_t dht_seq_ops = {
	.name			= "dht-seq",
	.tx_chunk		= dht_tx_chunk,
	.tx_ack			= dht_tx_ack,
	.on_rx_data		= dht_on_rx_data,
	.on_state_change	= dht_on_state_change,
	.on_writeable		= dht_on_writeable,
};

static const lws_retry_bo_t dht_retry_policy = {
	.retry_ms_table		= (uint32_t[]){ 25, 50, 100 },
	.retry_ms_table_count	= 3,
	.conceal_count		= 10, /* Increased from 5 to 10 */
};

/*
 * A sequencer costs ~160KB of dsh up front, and a single unsolicited (and
 * trivially spoofable) inbound 'data' datagram is enough to make one for a
 * source address we have never spoken to.  Bound how many can exist at once,
 * recycling the least-recently-used one that is not in use, so that a flood
 * churns a fixed-size table instead of growing the heap without limit; it
 * also bounds the cost of the linear lookup in lws_dht_get_ts().
 *
 * Only sequencers with nothing at stake are recycled: never one holding data
 * the peer hasn't acked, or the peer's proven session (G-496).  Otherwise
 * anyone able to forge 64 first chunks could destroy every transfer in
 * flight, and the consumer would never hear what became of its messages.
 * When all are in use, the newcomer is refused instead: an inbound chunk is
 * dropped unanswered, and lws_dht_send_data() returns LWS_DHT_SEND_REFUSED.
 * Sequencers in use end on their own, when the session fails or completes,
 * or when it has seen no traffic for 30s, and one host can only hold a few
 * proven sessions (lws_dht_ts_host_may_prove()), so it can't keep the table.
 *
 * `unproven` is set when the peer spoke first and is not a node we know at
 * that endpoint: then the sequencer sends it each chunk once and repeats
 * nothing until it has acknowledged something, so a forged source address
 * cannot turn a small request into a stream of retransmitted replies.
 */

static struct lws_transport_sequencer *
dht_ts_create(struct lws_dht_ctx *ctx, const struct sockaddr *dest,
	      size_t salen, int unproven)
{
	lws_dht_ts_t *dts;

	if (dest->sa_family != AF_INET && dest->sa_family != AF_INET6)
		return NULL;

	if ((dest->sa_family == AF_INET && salen < sizeof(struct sockaddr_in)) ||
	    (dest->sa_family == AF_INET6 && salen < sizeof(struct sockaddr_in6)))
		return NULL;

	/*
	 * A sequencer calling back into the consumer is in use too, even when
	 * it is the stalest: the callback may be what is creating this one,
	 * and the sequencer still has its caller on the stack (G-181).
	 */
	while (lws_dll2_count(&ctx->ts_owner) >= LWS_DHT_MAX_TS) {
		lws_dht_ts_t *victim = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&ctx->ts_owner)) {
			lws_dht_ts_t *c = lws_container_of(d, lws_dht_ts_t, list);

			if (!dht_ts_in_use(c)) {
				victim = c;
				break;
			}
		} lws_end_foreach_dll(d);

		if (!victim) {
			lwsl_dht_warn("%s: sequencer table full of sessions in "
				      "use, refusing one more\n", __func__);
			return NULL;
		}

		lwsl_dht_info("%s: sequencer table full, recycling an idle "
			      "one\n", __func__);
		dht_ts_retire(victim);
	}

	dts = lws_zalloc(sizeof(*dts), "dht ts");
	if (!dts)
		return NULL;

	lws_transport_sequencer_info_t tsi = {
		.cx		= ctx->vhost->context,
		.ops		= &dht_seq_ops,
		.retry_policy	= &dht_retry_policy,
		.user_data	= dts,
		.window_size	= 65536, /* 64KB - safe for broadside uploader */
		.unproven_peer	= !!unproven,
	};

	dts->ctx = ctx;
	dts->salen = salen;
	memcpy(&dts->sa, dest, salen);

	/* DIAGNOSTIC (temporary): who the sequencer's logs are about */
	lws_dht_describe_peer(dest, dts->peer, sizeof(dts->peer));
	tsi.peer = dts->peer;

	/*
	 * The nonce binds the peer's acks to this sequencer: without it, an
	 * ack is believed from anyone who can put the peer's address on a
	 * datagram, and acks retire our unsent data and prove the peer.  The
	 * challenge does the same for the peer's chunks, when they come with
	 * a tid that is not its session's.
	 */
	dts->tx_tid[0] = 's';
	dts->tx_tid[1] = 'q';
	if (lws_get_random(ctx->vhost->context, dts->tx_tid + 2,
			   LWS_DHT_SEQ_NONCE_LEN) != LWS_DHT_SEQ_NONCE_LEN ||
	    lws_get_random(ctx->vhost->context, dts->rx_ch,
			   sizeof(dts->rx_ch)) != sizeof(dts->rx_ch)) {
		lws_free(dts);
		return NULL;
	}

	dts->ts = lws_transport_sequencer_create(&tsi);

	if (!dts->ts) {
		lws_free(dts);
		return NULL;
	}

	lws_dll2_add_tail(&dts->list, &ctx->ts_owner);
	lws_sul_schedule(ctx->vhost->context, 0, &dts->sul_idle, lws_dht_ts_idle_cb, 30 * LWS_US_PER_SEC);

	return dts->ts;
}

/*
 * DIAGNOSTIC (temporary): "1.2.3.4:49100" or "[2001:db8::1]:49100", for
 * the logs
 */

void
lws_dht_describe_peer(const struct sockaddr *sa, char *buf, size_t len)
{
	char ip[48];

	if (lws_sa46_write_numeric_address((lws_sockaddr46 *)sa, ip,
					   sizeof(ip)) < 0)
		lws_strncpy(ip, "?", sizeof(ip));

	lws_snprintf(buf, len, sa->sa_family == AF_INET6 ? "[%s]:%u" :
							   "%s:%u", ip,
		     (unsigned int)ntohs(dht_sa_port(sa)));
}

/* the sequencer for the peer at sa, without counting this as its traffic */

lws_dht_ts_t *
lws_dht_ts_find(struct lws_dht_ctx *ctx, const struct sockaddr *sa)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ctx->ts_owner)) {
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);

		if (dht_sa_same_peer((const struct sockaddr *)&dts->sa, sa))
			return dts;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * May the chunk proving a session for the sequencer `dts` bind it, or does
 * its source host hold its share of proven sessions already?  A host is what
 * lws_dht_same_host() says, ie, an IPv4 address or an IPv6 /64 whatever the
 * port, as the DHT shares out everything else it limits.  Private addresses
 * are only themselves, as for search introducers: a LAN or loopback DHT has
 * many nodes behind one address.
 */

int
lws_dht_ts_host_may_prove(lws_dht_ts_t *dts)
{
	const struct sockaddr *sa = (const struct sockaddr *)&dts->sa;
	int n = 0;

	if (lws_dht_ads_is_private(sa))
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&dts->ctx->ts_owner)) {
		lws_dht_ts_t *c = lws_container_of(d, lws_dht_ts_t, list);

		if (c != dts && c->rx_tid_len &&
		    lws_dht_same_host((const struct sockaddr *)&c->sa, sa))
			n++;
	} lws_end_foreach_dll(d);

	return n < LWS_DHT_TS_SESSIONS_PER_HOST;
}

/*
 * The sequencer has seen traffic that belongs to it: what we send, or what
 * the peer sends bound to our session.  ->ts_owner is kept in least-recently
 * used order with the stalest at the head, so that the cap in
 * dht_ts_create() evicts the least interesting sequencer, and an idle one is
 * destroyed.  Traffic that fails the session checks must not keep a
 * sequencer alive, or a peer that restarted keeps its stale one forever.
 */

void
lws_dht_ts_touch(lws_dht_ts_t *dts)
{
	lws_dll2_remove(&dts->list);
	lws_dll2_add_tail(&dts->list, &dts->ctx->ts_owner);
	lws_sul_schedule(dts->ctx->vhost->context, 0, &dts->sul_idle,
			 lws_dht_ts_idle_cb, 30 * LWS_US_PER_SEC);
}

LWS_VISIBLE struct lws_transport_sequencer *
lws_dht_get_ts(struct lws_dht_ctx *ctx, const struct sockaddr *dest, size_t salen, int create)
{
	lws_dht_ts_t *dts = lws_dht_ts_find(ctx, dest);

	if (dts) {
		lws_dht_ts_touch(dts);
		return dts->ts;
	}

	if (!create)
		return NULL;

	/* we are sending to an address the caller chose */

	return dht_ts_create(ctx, dest, salen, 0);
}

/*
 * The sequencer an inbound data chunk from `from` belongs to.  Chunks for a
 * transfer already in progress stay outside the limiter, but making a
 * sequencer for a source we have no sequencer for is a request like any
 * other (C-497), in every build.  Finding one is not traffic for it until
 * the chunk is known to be of the peer's session (lws_dht_ts_touch()).
 */

struct lws_transport_sequencer *
lws_dht_ts_rx(struct lws_dht_ctx *ctx, const struct sockaddr *from,
	      size_t fromlen, const lws_dht_hash_t *id)
{
	lws_dht_ts_t *dts = lws_dht_ts_find(ctx, from);

	if (dts)
		return dts->ts;

	if (!lws_dht_admit_request(ctx, id, from)) {
		ctx->stats_current.rx_drops++;
		return NULL;
	}

	return dht_ts_create(ctx, from, fromlen,
			     !lws_dht_peer_known(ctx, id, from));
}

int
lws_callback_dht(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct lws_dht_ctx *ctx;

	switch (reason) {

	case LWS_CALLBACK_RAW_RX:
		if (!user)
			break;
		ctx = *((struct lws_dht_ctx **)user);
		if (!ctx)
			break;

		lws_dht_process_packet(ctx, in, len,
				       sa46_sockaddr(&wsi->io->udp->sa46),
				       sa46_socklen(&wsi->io->udp->sa46));
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!user)
			break;
		ctx = *((struct lws_dht_ctx **)user);
		if (ctx) {
			if (ctx->wsi_v4 == wsi)
				ctx->wsi_v4 = NULL;
			if (ctx->wsi_v6 == wsi)
				ctx->wsi_v6 = NULL;
		}
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_protocol =
	{ "lws-dht", lws_callback_dht, sizeof(struct lws_dht_ctx *), 0, 0, NULL, 0 };

static void
lws_dht_stats_periodic(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_ctx *ctx = lws_container_of(sul, struct lws_dht_ctx, sul_stats);
	uint32_t active_peers = 0;

#if defined(LWS_WITH_DHT_BACKEND)
	lws_start_foreach_dll(struct lws_dll2 *, db, lws_dll2_get_head(&ctx->buckets)) {
		struct bucket *b = lws_container_of(db, struct bucket, list);

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
			struct node *n = lws_container_of(d, struct node, list);

			if (node_good(ctx, n))
				active_peers++;
		} lws_end_foreach_dll(d);
	} lws_end_foreach_dll(db);

	lws_start_foreach_dll(struct lws_dll2 *, db6, lws_dll2_get_head(&ctx->buckets6)) {
		struct bucket *b = lws_container_of(db6, struct bucket, list);

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
			struct node *n = lws_container_of(d, struct node, list);

			if (node_good(ctx, n))
				active_peers++;
		} lws_end_foreach_dll(d);
	} lws_end_foreach_dll(db6);
#endif

	ctx->stats_current.peer_count = active_peers;

	/* Save current to history */
	ctx->stats_history[ctx->stats_history_head] = ctx->stats_current;

	/* Reset current counters (except peer_count which we just sampled) */
	memset(&ctx->stats_current, 0, sizeof(ctx->stats_current));
	ctx->stats_current.peer_count = active_peers;

	/* Advance head */
	ctx->stats_history_head = (ctx->stats_history_head + 1) % LWS_DHT_STAT_BUCKETS;

	/* Reschedule: 10 minutes */
	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul_stats,
			 lws_dht_stats_periodic, 600 * LWS_US_PER_SEC);
}

#if defined(LWS_WITH_DHT_BACKEND)
/*
 * Ask one node what our address looks like from where it is.  Each probe
 * gets its own random nonce, recorded with the node it went to: a nonce
 * shared by the round would be learnt by every probed node from its own
 * probe, and let it answer in the name of all the others.
 */

static void
lws_dht_ip_probe(struct lws_dht_ctx *ctx, const struct node *n)
{
	uint8_t tid[LWS_DHT_IP_PROBE_TID_LEN];
	int j = ctx->ip_probe_count;

	if (j >= (int)LWS_ARRAY_SIZE(ctx->ip_probes))
		return;

	ctx->ip_probes[j].ss		= n->ss;
	ctx->ip_probes[j].sslen		= n->sslen;
	ctx->ip_probes[j].answered	= 0;
	lws_get_random(ctx->vhost->context, ctx->ip_probes[j].nonce,
		       sizeof(ctx->ip_probes[j].nonce));

	tid[0] = 'i';
	tid[1] = 'p';
	memcpy(tid + 2, ctx->ip_probes[j].nonce, LWS_DHT_IP_PROBE_NONCE_LEN);

	ctx->ip_probe_count++;

	send_ping(ctx, (const struct sockaddr *)&n->ss, n->sslen, tid,
		  sizeof(tid));
}

static void
lws_dht_ip_probe_family(struct lws_dht_ctx *ctx, lws_dll2_owner_t *buckets)
{
	int sent = 0;

	lws_start_foreach_dll(struct lws_dll2 *, db, lws_dll2_get_head(buckets)) {
		struct bucket *b = lws_container_of(db, struct bucket, list);

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&b->nodes)) {
			struct node *n = lws_container_of(d, struct node, list);

			if (sent >= 8)
				return;

			if (node_good(ctx, n)) {
				lws_dht_ip_probe(ctx, n);
				sent++;
			}
		} lws_end_foreach_dll(d);
	} lws_end_foreach_dll(db);
}

static void
lws_dht_sul_ip_monitor_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_ctx *ctx = lws_container_of(sul, struct lws_dht_ctx, sul_ip_monitor);

	/*
	 * A new round forgets who we asked last time: replies to the old
	 * probes no longer match anything.
	 */
	ctx->ip_probe_count = 0;

	lws_dht_ip_probe_family(ctx, &ctx->buckets);
	lws_dht_ip_probe_family(ctx, &ctx->buckets6);

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul_ip_monitor,
			 lws_dht_sul_ip_monitor_cb, 600 * LWS_US_PER_SEC);
}

LWS_VISIBLE LWS_EXTERN void
lws_dht_test_external_ips(struct lws_dht_ctx *ctx)
{
	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul_ip_monitor,
			 lws_dht_sul_ip_monitor_cb, 1);
}
#endif

int
lws_dht_get_stats(struct lws_vhost *vh, struct lws_dht_stats *current,
		  const struct lws_dht_stats **history, int *head)
{
	struct lws_dht_ctx *ctx;

	if (!vh || !lws_dll2_get_head(&vh->dht_owner))
		return 1;

	ctx = lws_container_of(lws_dll2_get_head(&vh->dht_owner), struct lws_dht_ctx, list);

	if (current)
		*current = ctx->stats_current;
	if (history)
		*history = ctx->stats_history;
	if (head)
		*head = ctx->stats_history_head;

	return 0;
}

/*
 * A probed node's answer about our external address, already bound to its
 * probe.  It is one witness's vote: see dht-extvote.h for how votes decide.
 *
 * The witness is its host (dht_source_key(): an IPv4 address or an IPv6 /64),
 * as for every other per-peer share in the dht, so one /64 is one vote
 * however many of its addresses we probed.  The quorum is three such hosts,
 * or, in a network too small to have three, every host of the family this
 * round could probe.  ip_probes[] is what we sent, so a peer cannot deflate
 * it, and keyed by host it cannot inflate it either.
 *
 * Only a decided address is reported, and only it rebinds our node id: a
 * lone vote, however recent, never moves our BEP 42 id.
 */

void
lws_dht_ip_vote(struct lws_dht_ctx *ctx, const struct sockaddr *from,
		size_t fromlen, const lws_sockaddr46 *reported)
{
	uint8_t pk[16], pk1[16];
	lws_sockaddr46 voter, peers[8];
	struct lws_dht_consensus_info ci;
	int af = reported->sa4.sin_family, quorum = 0, j, k, ret,
	    num_peers = (int)LWS_ARRAY_SIZE(peers);
	lws_dht_extvote_t *ev;

	if (af != AF_INET && af != AF_INET6)
		return;

	/* a quorum must never decide we are somewhere unroutable */
	if (is_martian(ctx, (const struct sockaddr *)reported)) {
		lwsl_dht_warn("%s: unroutable external address reported, "
			      "ignored\n", __func__);
		return;
	}

	if (fromlen > sizeof(voter))
		return;

	memset(&voter, 0, sizeof(voter));
	memcpy(&voter, from, fromlen);

	for (j = 0; j < ctx->ip_probe_count; j++) {
		if (ctx->ip_probes[j].ss.ss_family != af ||
		    dht_source_key((const struct sockaddr *)
				   &ctx->ip_probes[j].ss, pk))
			continue;

		for (k = 0; k < j; k++)
			if (ctx->ip_probes[k].ss.ss_family == af &&
			    !dht_source_key((const struct sockaddr *)
					    &ctx->ip_probes[k].ss, pk1) &&
			    !memcmp(pk, pk1, sizeof(pk)))
				break;
		if (k == j) /* the first probe to this host */
			quorum++;
	}
	if (quorum > 3)
		quorum = 3;

	ev = &ctx->extvote[af == AF_INET6];
	ret = lws_dht_extvote_add(ev, &voter, reported, ctx->now, quorum,
				  peers, &num_peers);
	if (ret <= LWS_DHT_EXTVOTE_NO_CHANGE)
		return;

	lwsl_notice("%s: %s external address %s, %d agreeing hosts, "
		    "quorum %d\n", __func__, af == AF_INET ? "IPv4" : "IPv6",
		    ret == LWS_DHT_EXTVOTE_SHIFT ? "moved" : "decided",
		    num_peers, quorum);

	lws_dht_bep42_own_id(ctx, (const struct sockaddr *)&ev->decided);

	memset(&ci, 0, sizeof(ci));
	memcpy(&ci.ss, &ev->decided, sizeof(ev->decided));
	ci.sslen = af == AF_INET ? sizeof(struct sockaddr_in) :
				   sizeof(struct sockaddr_in6);
	ci.num_peers = num_peers;
	for (k = 0; k < num_peers; k++)
		memcpy(&ci.peer_ss[k], &peers[k], sizeof(peers[k]));

	if (ctx->cb)
		ctx->cb(ctx->closure, af == AF_INET ?
					LWS_DHT_EVENT_EXTERNAL_ADDR :
					LWS_DHT_EVENT_EXTERNAL_ADDR6,
			ret == LWS_DHT_EXTVOTE_SHIFT ? (const void *)"SHIFT" :
						       NULL,
			&ci, sizeof(ci), from, fromlen);
}

int
lws_dht_get_external_addr(struct lws_dht_ctx *ctx, struct sockaddr_storage *ss,
			  size_t *sslen)
{
	int j;

	/*
	 * The quorum decision lives where the reports are tallied, and it is
	 * not a fixed count of three: in a small network it is however many
	 * nodes there were to ask.  Report what that decided rather than
	 * re-deriving it here.
	 */

	for (j = 0; j < (int)LWS_ARRAY_SIZE(ctx->extvote); j++) {
		const lws_sockaddr46 *d = &ctx->extvote[j].decided;

		if (!d->sa4.sin_family)
			continue;

		memset(ss, 0, sizeof(*ss));
		memcpy(ss, d, sizeof(*d));
		*sslen = d->sa4.sin_family == AF_INET ?
				sizeof(struct sockaddr_in) :
				sizeof(struct sockaddr_in6);

		return 0;
	}

	return -1;
}

struct lws_dht_ctx *
lws_dht_create(const lws_dht_info_t *info)
{
	struct lws_dht_ctx *ctx;
	uint32_t r;

	if (info->vhost && lws_dll2_get_head(&info->vhost->dht_owner)) {
		return lws_container_of(lws_dll2_get_head(&info->vhost->dht_owner), struct lws_dht_ctx, list);
	}

	ctx = lws_zalloc(sizeof(*ctx), "dht ctx");
	(void)r;

	if (!ctx) {
		lwsl_err("lws_zalloc failed\n");
		return NULL;
	}

	if (!info->vhost) {
		lws_free(ctx);
		return NULL;
	}

	ctx->vhost = info->vhost;
	ctx->cb = info->cb;
	ctx->closure = info->closure;
	ctx->iface = info->iface;
	ctx->fallback_nodes_path = info->fallback_nodes_path;
	ctx->blacklist_cb = info->blacklist_cb;
	if (info->name) {
		ctx->name = lws_strdup(info->name);
		if (!ctx->name) {
			lwsl_err("lws_strdup failed\n");
			goto fail;
		}
	}
	ctx->hash_cb			= info->hash_cb;
	ctx->capture_announce_cb	= info->capture_announce_cb;
	/*
	 * The legacy 20-byte id wire encoding is only for a DHT that asks
	 * for it: lwsws's default for a "dht" block is off (lejp-conf.c),
	 * so existing deployments keep the multihash encoding they have
	 * always used
	 */
	ctx->legacy = info->legacy;
	ctx->allow_private_ads = info->allow_private_ads;
	ctx->max_hashes_per_source = info->max_hashes_per_source ?
					info->max_hashes_per_source :
					DHT_MAX_HASHES_PER_SOURCE;
	lws_dll2_owner_clear(&ctx->ts_owner);
	lws_dll2_owner_clear(&ctx->verb_owner);

	if (info->id)
		ctx->myid = lws_dht_hash_dup(info->id);
	else {
		uint8_t temp_id[20];
		lws_get_random(ctx->vhost->context, temp_id, 20);
		ctx->myid = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, temp_id);
		/* replaced by a BEP42 id once our external address is known */
		ctx->id_random = 1;
	}

	if (!ctx->myid) {
		lwsl_err("ctx->myid creation failed\n");
		goto fail;
	}

	if (info->v) {
		memcpy(ctx->my_v, "1:v4:", 5);
		memcpy(ctx->my_v + 5, info->v, 4);
		ctx->have_v = 1;
	}

	ctx->now			= (time_t)lws_now_secs();

#if defined(LWS_WITH_DHT_BACKEND)
	ctx->mybucket_grow_time		= ctx->now;
	ctx->mybucket6_grow_time	= ctx->now;
	/*
	 * Jitter must be drawn into an unsigned type: C99 % on a negative
	 * signed random gives a negative remainder, which would schedule the
	 * first maintenance pass in the past.
	 */
	ctx->confirm_nodes_time		= ctx->now + (time_t)((lws_get_random(ctx->vhost->context, &r, sizeof(r)), r) % 3);

	ctx->search_id			= (unsigned short)((lws_get_random(ctx->vhost->context, &r, sizeof(r)), r) & 0xFFFF);
	ctx->search_time		= 0;
#endif

	ctx->blacklist_secs		= info->blacklist_secs ?
					  info->blacklist_secs :
					  DHT_BLACKLIST_SECS;

	ctx->rl_known.time		= ctx->now;
	ctx->rl_known.tokens		= LWS_DHT_RL_POOL_BURST;
	ctx->rl_general.time		= ctx->now;
	ctx->rl_general.tokens		= LWS_DHT_RL_POOL_BURST;

	ctx->iface = info->iface;

#if defined(LWS_WITH_DHT_BACKEND)
	memset(ctx->secret, 0, sizeof(ctx->secret));
	if (rotate_secrets(ctx) < 0) {
		lwsl_err("rotate_secrets failed\n");
		goto fail;
	}
#endif

	if (info->port >= 0) {
		ctx->wsi_v4 = lws_create_adopt_udp(ctx->vhost, "0.0.0.0", info->port, LWS_CAUDP_BIND,
						   lws_dht_protocol.name, ctx->iface, NULL, ctx, NULL, "dht-v4");
		if (!ctx->wsi_v4) {
			lwsl_err("lws_create_adopt_udp v4 failed for port %d\n", info->port);
			goto fail;
		}
		*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v4)) = ctx;

		if (info->ipv6) {
			ctx->wsi_v6 = lws_create_adopt_udp(ctx->vhost, "::", info->port, LWS_CAUDP_BIND,
							   lws_dht_protocol.name, ctx->iface, NULL, ctx, NULL, "dht-v6");
			if (ctx->wsi_v6)
				*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v6)) = ctx;
			/* It's OK if IPv6 fails if not supported */
		}
	}

#if defined(LWS_WITH_DHT_BACKEND)
	{
		struct bucket *b = lws_zalloc(sizeof(*b), __func__);

		if (!b) {
			lwsl_err("lws_zalloc for buckets failed\n");
			goto fail;
		}
		b->af = AF_INET;
		b->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
		if (!b->first) {
			lwsl_err("ctx->buckets->first failed\n");
			lws_free(b);
			goto fail;
		}
		lws_dll2_add_tail(&b->list, &ctx->buckets);

		if (info->ipv6) {
			b = lws_zalloc(sizeof(*b), __func__);
			if (!b)
				goto fail;
			b->af = AF_INET6;
			b->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
			if (!b->first) {
				lws_free(b);
				goto fail;
			}
			lws_dll2_add_tail(&b->list, &ctx->buckets6);
		}
	}

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul,
			 lws_dht_periodic_cb, 100 * LWS_US_PER_MS);

	expire_buckets(ctx, &ctx->buckets);
	expire_buckets(ctx, &ctx->buckets6);

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul_ip_monitor,
			 lws_dht_sul_ip_monitor_cb, 5 * LWS_US_PER_SEC);
#endif

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul_stats,
			 lws_dht_stats_periodic, 600 * LWS_US_PER_SEC);

	lws_dll2_add_tail(&ctx->list, &ctx->vhost->dht_owner);

	return ctx;

fail:
	lws_dht_destroy(&ctx);
	return NULL;
}

void *
lws_dht_get_closure(struct lws_dht_ctx *ctx)
{
	if (!ctx) return NULL;
	return ctx->closure;
}

const lws_dht_hash_t *
lws_dht_get_myid(struct lws_dht_ctx *ctx)
{
	return ctx->myid;
}

void
lws_dht_destroy(struct lws_dht_ctx **pctx)
{
	struct lws_dht_ctx *ctx = *pctx;

	if (!ctx)
		return;

	if (ctx->wsi_v4) {
		*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v4)) = NULL;
		lws_set_timeout(ctx->wsi_v4, 1, LWS_TO_KILL_ASYNC);
		ctx->wsi_v4 = NULL;
	}

	if (ctx->wsi_v6) {
		*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v6)) = NULL;
		lws_set_timeout(ctx->wsi_v6, 1, LWS_TO_KILL_ASYNC);
		ctx->wsi_v6 = NULL;
	}

	lws_dll2_remove(&ctx->list);

	if (ctx->name)
		lws_free(ctx->name);

	lws_sul_cancel(&ctx->sul);
	lws_sul_cancel(&ctx->sul_stats);
	lws_sul_cancel(&ctx->sul_ip_monitor);

	lws_dht_hash_destroy(&ctx->myid);

#if defined(LWS_WITH_DHT_BACKEND)
	while (lws_dll2_get_head(&ctx->buckets) ||
	       lws_dll2_get_head(&ctx->buckets6)) {
		lws_dll2_owner_t *bo = lws_dll2_get_head(&ctx->buckets) ?
				&ctx->buckets : &ctx->buckets6;
		struct bucket *b = lws_container_of(lws_dll2_get_head(bo),
						    struct bucket, list);

		while(!lws_dll2_is_empty(&b->nodes)) {
			struct node *n = lws_container_of(lws_dll2_get_head(&b->nodes),
							  struct node, list);

			lws_dll2_remove(&n->list);
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}
		lws_dll2_remove(&b->list);
		lws_dht_hash_destroy(&b->first);
		lws_free(b);
	}

	while(!lws_dll2_is_empty(&ctx->storage)) {
		struct storage *st = lws_container_of(lws_dll2_get_head(&ctx->storage),
						      struct storage, list);

		while(!lws_dll2_is_empty(&st->subscribers)) {
			struct subscriber *sub = lws_container_of(
					lws_dll2_get_head(&st->subscribers),
					struct subscriber, list);

			lws_dll2_remove(&sub->list);
			lws_free(sub);
		}

		lws_dll2_remove(&st->list);
		lws_free(st->peers);
		lws_dht_hash_destroy(&st->id);
		lws_free(st);
	}

	while(!lws_dll2_is_empty(&ctx->searches)) {
		struct search *sr = lws_container_of(lws_dll2_get_head(&ctx->searches),
						     struct search, list);

		lws_dll2_remove(&sr->list);
		lws_dht_hash_destroy(&sr->id);
		search_free_nodes(sr);
		lws_free(sr);
	}
#endif

	lws_dll2_t *d = lws_dll2_get_head(&ctx->ts_owner);
	while (d) {
		lws_dll2_t *d1 = lws_dll2_get_next(d);
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);

		lws_sul_cancel(&dts->sul_idle);
		lws_transport_sequencer_destroy(&dts->ts);
		lws_dll2_remove(&dts->list);
		lws_free(dts);
		d = d1;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d_verb, d1_verb, lws_dll2_get_head(&ctx->verb_owner)) {
		struct lws_dht_verb_list *vl = lws_container_of(d_verb, struct lws_dht_verb_list, list);

		lws_dll2_remove(d_verb);
		lws_free(vl);
	} lws_end_foreach_dll_safe(d_verb, d1_verb);

	lws_free(ctx);
	*pctx = NULL;
}



int
lws_dht_ping_node(struct lws_dht_ctx *ctx, struct sockaddr *sa, size_t salen)
{
	uint8_t tid[4];

	lwsl_dht_info("Sending ping.\n");
	make_tid_random(ctx, tid, "pn");

	return send_ping(ctx, sa, salen, tid, 4);
}


/*
 * Say who a refused message was for and why: the consumer may well lose it
 */

static void
dht_send_dropped(const struct sockaddr *dest, size_t len, const char *why)
{
#if (_LWS_ENABLED_LOGS & LLL_WARN)
	char ads[64] = "unknown";

	lws_sa46_write_numeric_address((lws_sockaddr46 *)dest, ads, sizeof(ads));
	lwsl_dht_warn("dht: dropping %u-byte message to %s:%u: %s\n",
		      (unsigned int)len, ads, ntohs(dht_sa_port(dest)), why);
#else
	(void)dest;
	(void)len;
	(void)why;
#endif
}

static struct lws_transport_sequencer *
dht_ts_for_send(struct lws_dht_ctx *ctx, const struct sockaddr *dest,
		size_t len)
{
	struct lws_transport_sequencer *ts;
	size_t salen;

	switch (dest->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		lwsl_dht_warn("%s: dropping %u-byte message to family %d\n",
			      __func__, (unsigned int)len, dest->sa_family);
		return NULL;
	}

	/*
	 * Nothing would ever reach it, so don't queue it to be retransmitted
	 * until the session fails
	 */
	if (node_blacklisted(ctx, dest, salen)) {
		dht_send_dropped(dest, len, "peer is blacklisted");
		return NULL;
	}

	ts = lws_dht_get_ts(ctx, dest, salen, 1);
	if (!ts)
		dht_send_dropped(dest, len, "no sequencer available");

	return ts;
}

/*
 * A busy peer is the consumer's to handle, it hears when to send again: the
 * sequencer has already said why it's busy
 */

static int
dht_send_result(const struct sockaddr *dest, size_t len, int tsw)
{
	switch (tsw) {
	case LWS_TSW_QUEUED:
		return LWS_DHT_SEND_QUEUED;
	case LWS_TSW_BUSY:
		return LWS_DHT_SEND_BUSY;
	default:
		dht_send_dropped(dest, len, "the sequencer can't take it");
		return LWS_DHT_SEND_REFUSED;
	}
}

LWS_VISIBLE LWS_EXTERN int
lws_dht_send_data(struct lws_dht_ctx *ctx, const struct sockaddr *dest, const void *data, size_t len)
{
	struct lws_transport_sequencer *ts;

	if (len >= 4 && !memcmp(data, "PUT ", 4))
		ctx->stats_current.tx_put++;
	else if (len >= 4 && !memcmp(data, "GET ", 4))
		ctx->stats_current.tx_get++;

	ts = dht_ts_for_send(ctx, dest, len);
	if (!ts)
		return LWS_DHT_SEND_REFUSED;

	return dht_send_result(dest, len,
			       lws_transport_sequencer_write(ts, data, len));
}

int
lws_dht_send_data_at(struct lws_dht_ctx *ctx, const struct sockaddr *dest, uint64_t offset, const void *data, size_t len)
{
	struct lws_transport_sequencer *ts = dht_ts_for_send(ctx, dest, len);

	if (!ts)
		return LWS_DHT_SEND_REFUSED;

	return dht_send_result(dest, len,
			       lws_transport_sequencer_write_at(ts, offset,
								data, len));
}

struct lws_dll2_owner *
lws_dht_get_ts_owner(struct lws_dht_ctx *ctx)
{
	return &ctx->ts_owner;
}

int
lws_dht_msg_gen(char *out, size_t len, const char *verb, const char *hash, unsigned long long offset, unsigned long long len_val)
{
	if (!verb)
		return -1;

	return lws_snprintf(out, len, "%s %s %llu %llu ", verb, hash, offset, len_val);
}

int
lws_dht_valid_domain_name(const char *domain)
{
	size_t i, len, label = 0;

	if (!domain)
		return 0;

	len = strlen(domain);
	if (!len || len > 253)
		return 0;

	for (i = 0; i < len; i++) {
		char c = domain[i];

		if (c == '.') {
			/* empty label (".." or leading dot) or overlong */
			if (!label || label > 63)
				return 0;
			label = 0;
			continue;
		}

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_'))
			return 0;
		label++;
	}

	/*
	 * The residual label never met the c == '.' test above, so apply the
	 * same length rule to it here: an over-63 label cannot be encoded in
	 * DNS wire format at all (the length byte would alias the 0xc0
	 * compression-pointer bits), and callers rely on us for that.
	 */
	if (label > 63)
		return 0;

	/* final label may be empty only for a single trailing root dot */
	return label || domain[len - 1] == '.';
}

/*
 * The RPC-over-data wire format is four fields separated by exactly one
 * space each, optionally followed by one more space and the payload:
 *
 *   <verb> <hash> <offset> <len>[ <payload>]
 *
 * `in` points into the received datagram and is not NUL-terminated, so
 * everything here is bounded by `len` alone; lws_tokenize() is given the
 * explicit length of the four fields and never reads past it.  It must not
 * see the payload: after a token's terminating whitespace it reads on for
 * a following '=', UTF-8 checking the byte it finds, and a binary payload
 * starting with '=' or a byte that can't lead UTF-8 then failed the whole
 * message.  It extracts the fields with
 * its own integer validation, while the gap checks below insist the
 * fields were separated by exactly one space, the only shape the
 * generator emits: without them a datagram with a missing or empty field
 * would have its remaining fields silently shift left rather than be
 * rejected.
 */

int
lws_dht_msg_parse(const char *in, size_t len, struct lws_dht_msg *out)
{
	char tmp[32];
	lws_tokenize_t ts;
	const char *cur = in, *end = in + len;
	size_t i, hl;
	int sp = 0;

	if (!in || !out || len < 10)
		return -1;

	memset(out, 0, sizeof(*out));

	/* the fields end at the fourth space, if any */

	for (hl = 0; hl < len; hl++)
		if (in[hl] == ' ' && ++sp == 4)
			break;

	lws_tokenize_init(&ts, in, 0);
	ts.len = hl;

	for (i = 0; i < 4; i++) {
		size_t tl;
		lws_tokenize_elem e = lws_tokenize(&ts);

		/*
		 * The token content lives in the tokenizer's collect buffer;
		 * anchor it to the expected position in the datagram so a
		 * leading space, a double space or a non-space delimiter in
		 * place of the single separating space cannot pass.
		 */

		if ((i < 2 ? (e != LWS_TOKZE_TOKEN && e != LWS_TOKZE_INTEGER)
			   : e != LWS_TOKZE_INTEGER) ||
		    ts.token_len > (size_t)(end - cur) ||
		    memcmp(cur, ts.token, ts.token_len))
			return -1;

		tl = ts.token_len;

		switch (i) {
		case 0:
			if (tl >= sizeof(out->verb))
				return -1;
			memcpy(out->verb, cur, tl);
			out->verb[tl] = '\0';
			break;

		case 1: {
			size_t j;

			/*
			 * F-051: the hash token is composed into
			 * filesystem paths by the object-store and dnssec
			 * plugins, so it must be exactly lowercase hex
			 * (the only shape the protocol generates) and not
			 * something like "../x" or an absolute path.
			 * Reject the whole datagram otherwise.
			 */
			if (tl < 2 || tl >= sizeof(out->hash))
				return -1;

			for (j = 0; j < tl; j++) {
				char c = cur[j];
				if (!((c >= '0' && c <= '9') ||
				      (c >= 'a' && c <= 'f')))
					return -1;
			}

			memcpy(out->hash, cur, tl);
			out->hash[tl] = '\0';
			break;
		}

		case 2:
			if (tl >= sizeof(tmp))
				return -1;
			memcpy(tmp, cur, tl);
			tmp[tl] = '\0';
			out->offset = (unsigned long long)strtoull(tmp, NULL, 10);
			break;

		default:
			if (tl >= sizeof(tmp))
				return -1;
			memcpy(tmp, cur, tl);
			tmp[tl] = '\0';
			out->len = (unsigned long long)strtoull(tmp, NULL, 10);
			break;
		}

		cur += tl;

		/* the next field (or the payload) follows exactly one ' ' */

		if (i < 3) {
			if (cur >= end || *cur != ' ')
				return -1;
			cur++;
		}
	}

	/*
	 * Anything after exactly one further space is the payload; it is not
	 * validated at all here.
	 */

	if (cur < end) {
		if (*cur != ' ')
			return -1;

		if (cur + 1 < end) {
			out->payload = cur + 1;
			out->payload_len = (size_t)(end - (cur + 1));
		}
	}

	return 0;
}

int
lws_dht_notify_subscribers(struct lws_dht_ctx *ctx, const lws_dht_hash_t *hash, const uint8_t *sha256, const uint8_t *payload, size_t payload_len)
{
#if defined(LWS_WITH_DHT_BACKEND)
	struct storage *st;
	int count = 0;

	if (!ctx || !hash || !sha256)
		return -1;

	st = find_storage(ctx, hash);
	if (!st)
		return 0; /* no subscribers */

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&st->subscribers)) {
		struct subscriber *sub = lws_container_of(d, struct subscriber, list);

		/* Don't notify if the TTL expired */
		if (ctx->now <= sub->expire) {
			/* Only notify if the content actually changed from what they have */
			if (memcmp(sub->current_sha256, sha256, 32)) {
				lws_dht_send_notify(ctx, (struct sockaddr *)&sub->ss, sub->sslen, sub->tid, sub->tid_len, hash, sha256, payload, payload_len);

				/* Queue up reliable delivery retry state */
				sub->pending_notify = 1;
				sub->notify_retries = 0;
				sub->last_notify = ctx->now;
				memcpy(sub->pending_sha256, sha256, 32);

				count++;
			}
		}
	} lws_end_foreach_dll(d);

	return count;
#else
	return -1;
#endif
}

/*
 * A notify ack clears the pending notification it answers: the one sent
 * under that tid, to the endpoint the ack comes from.  The tid is the
 * subscriber's choice, not a secret, so it alone would let anyone who
 * learned it acknowledge (and so suppress) a notification it never got.
 */

void
lws_dht_clear_pending_notify(struct lws_dht_ctx *ctx, const uint8_t *tid,
			     size_t tid_len, const struct sockaddr *from)
{
#if defined(LWS_WITH_DHT_BACKEND)

	if (!ctx || !tid || tid_len != 16 || !from)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, dt, lws_dll2_get_head(&ctx->storage)) {
		struct storage *st = lws_container_of(dt, struct storage, list);

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&st->subscribers)) {
			struct subscriber *sub = lws_container_of(d, struct subscriber, list);

			if (sub->pending_notify && sub->tid_len == tid_len &&
			    !memcmp(sub->tid, tid, tid_len) &&
			    dht_sa_same_peer((const struct sockaddr *)&sub->ss,
					     from)) {
				/* ACK received! */
				sub->pending_notify = 0;
				sub->notify_retries = 0;
				/* Commit the sha256 */
				memcpy(sub->current_sha256, sub->pending_sha256, 32);
				return;
			}
		} lws_end_foreach_dll(d);
	} lws_end_foreach_dll(dt);
#endif
}

int
lws_dht_register_verbs(struct lws_dht_ctx *ctx, const char **verbs, int count, const struct lws_protocols *protocol)
{
	int i;

	for (i = 0; i < count; i++) {
		struct lws_dht_verb_list *vl = lws_zalloc(sizeof(*vl), "dht verb");

		if (!vl)
			return -1;

		vl->v.name = verbs[i];
		vl->v.protocol = protocol;
		lws_dll2_add_tail(&vl->list, &ctx->verb_owner);
	}

	return 0;
}

struct lws_dht_ctx *
lws_dht_get_by_name(struct lws_vhost *vhost, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhost->dht_owner)) {
		struct lws_dht_ctx *ctx = lws_container_of(d, struct lws_dht_ctx, list);

		if (ctx->name && !strcmp(ctx->name, name))
			return ctx;
	} lws_end_foreach_dll(d);

	return NULL;
}

void
lws_dht_destroy_all_on_vhost(struct lws_vhost *vh)
{
	while(!lws_dll2_is_empty(&vh->dht_owner)) {
		struct lws_dht_ctx *ctx = lws_container_of(lws_dll2_get_head(&vh->dht_owner),
							   struct lws_dht_ctx,
							   list);

		lws_dht_destroy(&ctx);
	}
}

LWS_VISIBLE LWS_EXTERN int
lws_dht_get_fallback_node(struct lws_context *cx, const char *custom_path, char *result, size_t result_len)
{
	lws_system_policy_t *policy;
	const char *path = "/etc/lwsws/policy";
	uint32_t random_val;
	int target_idx, current_idx = 0;

	if (custom_path)
		path = custom_path;

	if (lws_system_parse_policy(cx, path, &policy)) {
		lwsl_err("%s: Unable to parse policy %s\n", __func__, path);
		return 1;
	}

	if (!lws_dll2_count(&policy->seeds)) {
		lwsl_err("%s: No seeds in policy\n", __func__);
		lws_system_policy_free(policy);
		return 1;
	}

	lws_get_random(cx, &random_val, sizeof(random_val));
	target_idx = (int)(random_val % lws_dll2_count(&policy->seeds));

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&policy->seeds)) {
		if (current_idx++ == target_idx) {
			lws_system_seed_t *s = lws_container_of(d, lws_system_seed_t, list);
			lws_strncpy(result, s->hostname, result_len);
			lws_system_policy_free(policy);
			return 0;
		}
	} lws_end_foreach_dll(d);

	lws_system_policy_free(policy);
	return 1;
}
