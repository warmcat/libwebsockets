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

void
lws_dht_capture_announce(struct lws_dht_ctx *ctx, lws_dht_hash_t *hash,
			 const struct sockaddr *fromaddr, unsigned short prt)
{
	if (ctx->capture_announce_cb)
		ctx->capture_announce_cb(ctx, hash, fromaddr, prt);
}

int
is_martian(const struct sockaddr *sa)
{
	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in*)sa;
			const uint8_t *address = (const uint8_t*)&sin->sin_addr;

			return sin->sin_port == 0 ||
				(address[0] == 0) ||
				/* (address[0] == 127) || local loopback is okay for testing */
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



int
dht_tx_chunk(struct lws_transport_sequencer *ts, uint64_t offset,
	     const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	char pkt[2048];
	size_t i = 0;
	int rc;

	/* d1:ad4:data%d:<payload>6:offseti%llue3:leni%llue2:id%d:<id>e1:q4:data1:t2:da1:y1:qe */

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:ad4:data%d:", (int)len);
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;
	if (dht_tx_copy__advance_offset(pkt, &i, sizeof(pkt), buf, len)) goto fail;

	/* Correct alphabetical order: data (done), id, len, offset */
	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "2:id%d:", dht_tx_id_len(dts->ctx, dts->ctx->myid));
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	if (dts->ctx->legacy) {
		if (dts->ctx->myid->len >= 20) {
			if (dht_tx_copy__advance_offset(pkt, &i, sizeof(pkt), dts->ctx->myid->id, 20)) goto fail;
		} else {
			if (dht_tx_check(sizeof(pkt), i, 20)) goto fail;
			memset(pkt + i, 0, 20);
			memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
			i += 20;
		}
	} else {
		if (dht_tx_check(sizeof(pkt), i, 2 + dts->ctx->myid->len)) goto fail;
		pkt[i++] = (char)dts->ctx->myid->type;
		pkt[i++] = (char)dts->ctx->myid->len;
		memcpy(pkt + i, dts->ctx->myid->id, dts->ctx->myid->len);
		i += dts->ctx->myid->len;
	}

	if (dht_tx_check(sizeof(pkt), i, 1)) goto fail;
	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "3:leni%llue6:offseti%llue",
			 (unsigned long long)len, (unsigned long long)offset);
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e1:q4:data1:t4:sqnc1:y1:qe");
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	return dht_send(dts->ctx, pkt, i, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

int
dht_tx_ack(struct lws_transport_sequencer *ts, uint64_t offset, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	const lws_transport_sequencer_stats_t *stats = lws_transport_sequencer_get_stats(ts);
	char pkt[512];
	size_t i = 0;
	int rc;

	/* d1:rd2:id%d:<id>3:leni%llue6:offseti%lluee1:t4:sqnc1:y1:re */

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:rd2:id%d:", dht_tx_id_len(dts->ctx, dts->ctx->myid));
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	if (dht_put_id__advance_offset(dts->ctx, pkt, &i, sizeof(pkt), dts->ctx->myid)) goto fail;

	/* Correct alphabetical order: id, len, offset, sack.  Need an extra 'e' to close rd dict. */
	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "3:leni0e6:offseti%llue",
			 (unsigned long long)stats->ack_offset);
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	{
		lws_transport_sequencer_sack_block_t blocks[4];
		size_t num_blocks, j;

		num_blocks = lws_transport_sequencer_get_sack_blocks(ts, blocks, 4);
		if (num_blocks) {
			rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "4:sackl");
			if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;
			for (j = 0; j < num_blocks; j++) {
				/* d1:li...e1:oi...ee */
				rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "d1:li%llue1:oi%lluee",
						  (unsigned long long)blocks[j].len,
						  (unsigned long long)blocks[j].start);
				if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;
			}
			rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e");
			if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;
		}
	}

	rc = lws_snprintf(pkt + i, sizeof(pkt) - i, "e1:t4:sqnc1:y1:re");
	if (dht_tx_skip(&i, sizeof(pkt), (size_t)(rc))) goto fail;

	return dht_send(dts->ctx, pkt, i, (struct sockaddr *)&dts->sa, dts->salen);

fail:
	return -1;
}

int
dht_on_rx_data(struct lws_transport_sequencer *ts, uint64_t offset,
	       const uint8_t *buf, size_t len)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;
	struct lws_dht_msg msg;

	if (!lws_dht_msg_parse((const char *)buf, len, &msg)) {
		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&dts->ctx->verb_owner)) {
			struct lws_dht_verb_list *vl = lws_container_of(d, struct lws_dht_verb_list, list);

			if (!strcmp(vl->v.name, msg.verb)) {
				struct lws_dht_verb_dispatch_args args;
				struct lws_a a;
				int n;

				if (!strcmp(msg.verb, "PUT"))
					dts->ctx->stats_current.rx_put++;
				else if (!strcmp(msg.verb, "GET"))
					dts->ctx->stats_current.rx_get++;

				args.ctx = dts->ctx;
				args.msg = &msg;
				args.from = (const struct sockaddr *)&dts->sa;
				args.fromlen = dts->salen;

				/* prepare a temporary minimal wsi to associate the callback with this vhost and protocol */
				memset(&a, 0, sizeof(a));
				a.context = dts->ctx->vhost->context;
				a.vhost = dts->ctx->vhost;
				a.protocol = vl->v.protocol;

				args.out_precedence = LWS_DHT_VERB_RESULT_PROCEED;

				n = vl->v.protocol->callback((struct lws *)&a, LWS_CALLBACK_DHT_VERB_DISPATCH,
							lws_protocol_vh_priv_get(dts->ctx->vhost, vl->v.protocol),
							&args, 0);
				
				if (n < 0 || args.out_precedence == LWS_DHT_VERB_RESULT_DROP_OLDER || args.out_precedence == LWS_DHT_VERB_RESULT_ERROR)
					return -1;

				if (args.out_precedence == LWS_DHT_VERB_RESULT_PENDING_ASYNC) {
					/* The plugin will handle validation asynchronously and ACK later. 
					 * We just return 0 to keep the sequencer alive but don't ACK here.
					 * The object store plugin currently manually ACKs via its own verb handler logic anyway,
					 * but this formally signals the core that the chunk was 'accepted' for now.
					 */
					return 0;
				}

				return n;
			}
		} lws_end_foreach_dll(d);
	}

	if (dts->ctx->cb)
		dts->ctx->cb(dts->ctx->closure, LWS_DHT_EVENT_DATA,
			     NULL, buf, len, (struct sockaddr *)&dts->sa, dts->salen);

	return 0;
}

void
dht_on_state_change(struct lws_transport_sequencer *ts, int state, int status)
{
	lws_dht_ts_t *dts = (lws_dht_ts_t *)lws_transport_sequencer_get_info(ts)->user_data;

	if (!dts->ctx->cb)
		return;

	dts->ctx->cb(dts->ctx->closure,
		     state == 0 ? LWS_DHT_EVENT_WRITE_COMPLETED :
				  LWS_DHT_EVENT_WRITE_FAILED,
		     NULL, (void *)(intptr_t)status, 0,
		     (struct sockaddr *)&dts->sa, dts->salen);
}

static const lws_transport_sequencer_ops_t dht_seq_ops = {
	.name			= "dht-seq",
	.tx_chunk		= dht_tx_chunk,
	.tx_ack			= dht_tx_ack,
	.on_rx_data		= dht_on_rx_data,
	.on_state_change	= dht_on_state_change,
};

static const lws_retry_bo_t dht_retry_policy = {
	.retry_ms_table		= (uint32_t[]){ 25, 50, 100 },
	.retry_ms_table_count	= 3,
	.conceal_count		= 10, /* Increased from 5 to 10 */
};

LWS_VISIBLE struct lws_transport_sequencer *
lws_dht_get_ts(struct lws_dht_ctx *ctx, const struct sockaddr *dest, size_t salen, int create)
{
	lws_dll2_t *d = lws_dll2_get_head(&ctx->ts_owner);

	while (d) {
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);
		int match = 0;

		if (dts->sa.ss_family == dest->sa_family) {
			switch (dest->sa_family) {
			case AF_INET: {
				struct sockaddr_in *sin1 = (struct sockaddr_in *)&dts->sa;
				struct sockaddr_in *sin2 = (struct sockaddr_in *)dest;

				if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr &&
				    sin1->sin_port == sin2->sin_port)
					match = 1;
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 *sin1 = (struct sockaddr_in6 *)&dts->sa;
				struct sockaddr_in6 *sin2 = (struct sockaddr_in6 *)dest;

				if (!memcmp(&sin1->sin6_addr, &sin2->sin6_addr, 16) &&
				    sin1->sin6_port == sin2->sin6_port)
					match = 1;
				break;
			}
			}
		}

		if (match)
			return dts->ts;

		d = d->next;
	}

	if (!create)
		return NULL;

	if (dest->sa_family != AF_INET && dest->sa_family != AF_INET6)
		return NULL;

	if ((dest->sa_family == AF_INET && salen < sizeof(struct sockaddr_in)) ||
	    (dest->sa_family == AF_INET6 && salen < sizeof(struct sockaddr_in6)))
		return NULL;

	lws_dht_ts_t *dts = lws_zalloc(sizeof(*dts), "dht ts");
	if (!dts)
		return NULL;

	lws_transport_sequencer_info_t tsi = {
		.cx		= ctx->vhost->context,
		.ops		= &dht_seq_ops,
		.retry_policy	= &dht_retry_policy,
		.user_data	= dts,
		.window_size	= 65536, /* 64KB - safe for broadside uploader */
	};

	dts->ctx = ctx;
	dts->salen = salen;
	memcpy(&dts->sa, dest, salen);
	dts->ts = lws_transport_sequencer_create(&tsi);

	if (!dts->ts) {
		lws_free(dts);
		return NULL;
	}

	lws_dll2_add_tail(&dts->list, &ctx->ts_owner);

	return dts->ts;
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
				       sa46_sockaddr(&wsi->udp->sa46),
				       sa46_socklen(&wsi->udp->sa46));
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
	struct bucket *b;
	struct node *n;

	b = ctx->buckets;
	while (b) {
		n = b->nodes;
		while (n) {
			if (node_good(ctx, n))
				active_peers++;
			n = n->next;
		}
		b = b->next;
	}

	b = ctx->buckets6;
	while (b) {
		n = b->nodes;
		while (n) {
			if (node_good(ctx, n))
				active_peers++;
			n = n->next;
		}
		b = b->next;
	}
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

int
lws_dht_get_stats(struct lws_vhost *vh, struct lws_dht_stats *current,
		  const struct lws_dht_stats **history, int *head)
{
	struct lws_dht_ctx *ctx;

	if (!vh || !vh->dht_owner.head)
		return 1;

	ctx = lws_container_of(vh->dht_owner.head, struct lws_dht_ctx, list);

	if (current)
		*current = ctx->stats_current;
	if (history)
		*history = ctx->stats_history;
	if (head)
		*head = ctx->stats_history_head;

	return 0;
}

int
lws_dht_get_external_addr(struct lws_dht_ctx *ctx, struct sockaddr_storage *ss,
			  size_t *sslen)
{
	int j;

	if (!ctx->external_ads_set)
		return -1;

	for (j = 0; j < ctx->num_reported_ads; j++) {
		if (ctx->reported_ads[j].count >= 3) {
			*ss = ctx->reported_ads[j].ss;
			*sslen = ctx->reported_ads[j].sslen;

			return 0;
		}
	}

	return -1;
}

struct lws_dht_ctx *
lws_dht_create(const lws_dht_info_t *info)
{
	struct lws_dht_ctx *ctx = lws_zalloc(sizeof(*ctx), "dht ctx");
	int rc;
	(void)rc;

	if (!ctx) {
		lwsl_err("lws_zalloc failed\n");
		return NULL;
	}

	ctx->vhost			= info->vhost;
	ctx->cb				= info->cb;
	ctx->closure			= info->closure;
	ctx->legacy			= info->legacy;
	ctx->iface			= info->iface;
	if (info->name) {
		ctx->name = lws_strdup(info->name);
		if (!ctx->name) {
			lwsl_err("lws_strdup failed\n");
			goto fail;
		}
	}
	ctx->blacklist_cb		= info->blacklist_cb;
	ctx->hash_cb			= info->hash_cb;
	ctx->capture_announce_cb	= info->capture_announce_cb;
	lws_dll2_owner_clear(&ctx->ts_owner);
	lws_dll2_owner_clear(&ctx->verb_owner);

	if (info->id)
		ctx->myid = lws_dht_hash_dup(info->id);
	else {
		uint8_t temp_id[20];
		lws_get_random(ctx->vhost->context, temp_id, 20);
		ctx->myid = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, temp_id);
	}

	if (!ctx->myid) {
		lwsl_err("ctx->myid creation failed\n");
		lws_free(ctx);

		return NULL;
	}

	if (info->v) {
		memcpy(ctx->my_v, "1:v4:", 5);
		memcpy(ctx->my_v + 5, info->v, 4);
		ctx->have_v = 1;
	}

	ctx->now.tv_sec			= (time_t)lws_now_secs();

#if defined(LWS_WITH_DHT_BACKEND)
	ctx->mybucket_grow_time		= ctx->now.tv_sec;
	ctx->mybucket6_grow_time	= ctx->now.tv_sec;
	ctx->confirm_nodes_time		= ctx->now.tv_sec + ((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) % 3);

	ctx->search_id			= (unsigned short)((lws_get_random(ctx->vhost->context, &rc, sizeof(rc)), rc) & 0xFFFF);
	ctx->search_time		= 0;
#endif

	ctx->next_blacklisted		= 0;

#if defined(LWS_WITH_DHT_BACKEND)
	ctx->token_bucket_time		= ctx->now.tv_sec;
	ctx->token_bucket_tokens	= MAX_TOKEN_BUCKET_TOKENS;
#endif

	ctx->iface = info->iface;

#if defined(LWS_WITH_DHT_BACKEND)
	memset(ctx->secret, 0, sizeof(ctx->secret));
	rc = rotate_secrets(ctx);
	if (rc < 0) {
		lwsl_err("rotate_secrets failed\n");
		goto fail;
	}
#endif

	if (info->port) {
		const char *v4ads = ctx->iface;
		if (!v4ads)
			v4ads = "0.0.0.0";
		
		ctx->wsi_v4 = lws_create_adopt_udp(ctx->vhost, v4ads, info->port, LWS_CAUDP_BIND,
						   lws_dht_protocol.name, NULL, NULL, ctx, NULL, "dht-v4");
		if (!ctx->wsi_v4) {
			lwsl_err("lws_create_adopt_udp v4 failed for port %d\n", info->port);
			goto fail;
		}
		*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v4)) = ctx;

		if (info->ipv6) {
			const char *v6ads = ctx->iface;
			if (!v6ads)
				v6ads = "::";
			ctx->wsi_v6 = lws_create_adopt_udp(ctx->vhost, v6ads, info->port, LWS_CAUDP_BIND,
							   lws_dht_protocol.name, NULL, NULL, ctx, NULL, "dht-v6");
			if (ctx->wsi_v6)
				*((struct lws_dht_ctx **)lws_wsi_user(ctx->wsi_v6)) = ctx;
			/* It's OK if IPv6 fails if not supported */
		}
	}

#if defined(LWS_WITH_DHT_BACKEND)
	ctx->buckets = lws_zalloc(sizeof(struct bucket), __func__);
	if (ctx->buckets) {
		ctx->buckets->af = AF_INET;
		ctx->buckets->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
		if (!ctx->buckets->first) {
			lwsl_err("ctx->buckets->first failed\n");
			goto fail;
		}
	} else {
		lwsl_err("lws_zalloc for buckets failed\n");
		goto fail;
	}

	if (info->ipv6) {
		ctx->buckets6 = lws_zalloc(sizeof(struct bucket), __func__);
		if (ctx->buckets6) {
			ctx->buckets6->af = AF_INET6;
			ctx->buckets6->first = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, zeroes);
			if (!ctx->buckets6->first)
				goto fail;
		} else
			goto fail;
	}

	lws_sul_schedule(ctx->vhost->context, 0, &ctx->sul,
			 lws_dht_periodic_cb, 100 * LWS_US_PER_MS);

	expire_buckets(ctx, ctx->buckets);
	expire_buckets(ctx, ctx->buckets6);
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
	return ctx->closure;
}

void
lws_dht_destroy(struct lws_dht_ctx **pctx)
{
	struct lws_dht_ctx *ctx = *pctx;

	if (!ctx)
		return;

	lws_dll2_remove(&ctx->list);

	if (ctx->name)
		lws_free(ctx->name);

	lws_sul_cancel(&ctx->sul);
	lws_sul_cancel(&ctx->sul_stats);

	lws_dht_hash_destroy(&ctx->myid);

#if defined(LWS_WITH_DHT_BACKEND)
	while (ctx->buckets) {
		struct bucket *b = ctx->buckets;

		ctx->buckets = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}
		lws_dht_hash_destroy(&b->first);
		lws_free(b);
	}

	while (ctx->buckets6) {
		struct bucket *b = ctx->buckets6;

		ctx->buckets6 = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			lws_dht_hash_destroy(&n->id);
			lws_free(n);
		}
		lws_dht_hash_destroy(&b->first);
		lws_free(b);
	}

	while (ctx->storage) {
		struct storage *st = ctx->storage;

		ctx->storage = ctx->storage->next;
		lws_free(st->peers);
		lws_dht_hash_destroy(&st->id);
		lws_free(st);
	}

	while (ctx->searches) {
		struct search *sr = ctx->searches;

		ctx->searches = ctx->searches->next;
		lws_dht_hash_destroy(&sr->id);
		for (int i = 0; i < sr->numnodes; i++)
			lws_dht_hash_destroy(&sr->nodes[i].id);
		lws_free(sr);
	}
#endif

	lws_dll2_t *d = lws_dll2_get_head(&ctx->ts_owner);
	while (d) {
		lws_dll2_t *d1 = d->next;
		lws_dht_ts_t *dts = lws_container_of(d, lws_dht_ts_t, list);

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
	make_tid(tid, "pn", 0);

	return send_ping(ctx, sa, salen, tid, 4);
}


LWS_VISIBLE LWS_EXTERN int
lws_dht_send_data(struct lws_dht_ctx *ctx, const struct sockaddr *dest, const void *data, size_t len)
{
	struct lws_transport_sequencer *ts;
	size_t salen;

	if (len >= 4 && !memcmp(data, "PUT ", 4))
		ctx->stats_current.tx_put++;
	else if (len >= 4 && !memcmp(data, "GET ", 4))
		ctx->stats_current.tx_get++;

	switch (dest->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		return 1;
	}

	ts = lws_dht_get_ts(ctx, dest, salen, 1);

	if (!ts)
		return 1;

	return lws_transport_sequencer_write(ts, data, len);
}

int
lws_dht_send_data_at(struct lws_dht_ctx *ctx, const struct sockaddr *dest, uint64_t offset, const void *data, size_t len)
{
	size_t salen;
	struct lws_transport_sequencer *ts;

	switch (dest->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		return 1;
	}

	ts = lws_dht_get_ts(ctx, dest, salen, 1);

	if (!ts)
		return 1;

	return lws_transport_sequencer_write_at(ts, offset, data, len);
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
lws_dht_msg_parse(const char *in, size_t len, struct lws_dht_msg *out)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char tmp[32];
	int step = 0;

	if (!in || !out || len < 10)
		return -1;

	memset(out, 0, sizeof(*out));

	lws_tokenize_init(&ts, in, LWS_TOKENIZE_F_MINUS_NONTERM |
				   LWS_TOKENIZE_F_DOT_NONTERM |
				   LWS_TOKENIZE_F_SLASH_NONTERM);
	ts.len = len;

	do {
		e = lws_tokenize(&ts);

		if (e < 0)
			break;

		if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_INTEGER || e == LWS_TOKZE_FLOAT) {
			switch (step) {
			case 0:
				lws_tokenize_cstr(&ts, out->verb, sizeof(out->verb));
				break;
			case 1:
				lws_tokenize_cstr(&ts, out->hash, sizeof(out->hash));
				break;
			case 2:
				if (!lws_tokenize_cstr(&ts, tmp, sizeof(tmp)))
					out->offset = (unsigned long long)strtoull(tmp, NULL, 10);
				break;
			case 3:
				if (!lws_tokenize_cstr(&ts, tmp, sizeof(tmp)))
					out->len = (unsigned long long)strtoull(tmp, NULL, 10);
				
				/* Payload begins immediately after this token, skipping a space */
				if (ts.token + ts.token_len < in + len) {
					const char *pay = ts.token + ts.token_len;
					if (pay < in + len && *pay == ' ')
						pay++;
					if (pay < in + len) {
						out->payload = pay;
						out->payload_len = len - lws_ptr_diff_size_t(pay, in);
					}
				}
				return 0;
			}
			step++;
		}
	} while (e > 0);

	return -1;
}

int
lws_dht_register_verbs(struct lws_dht_ctx *ctx, const struct lws_dht_verb *verbs, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		struct lws_dht_verb_list *vl = lws_zalloc(sizeof(*vl), "dht verb");

		if (!vl)
			return -1;

		vl->v = verbs[i];
		lws_dll2_add_tail(&vl->list, &ctx->verb_owner);
	}

	return 0;
}

struct lws_dht_ctx *
lws_dht_get_by_name(struct lws_vhost *vhost, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, vhost->dht_owner.head) {
		struct lws_dht_ctx *ctx = lws_container_of(d, struct lws_dht_ctx, list);

		if (ctx->name && !strcmp(ctx->name, name))
			return ctx;
	} lws_end_foreach_dll(d);

	return NULL;
}

void
lws_dht_destroy_all_on_vhost(struct lws_vhost *vh)
{
	while (vh->dht_owner.head) {
		struct lws_dht_ctx *ctx = lws_container_of(vh->dht_owner.head,
							   struct lws_dht_ctx,
							   list);

		lws_dht_destroy(&ctx);
	}
}
