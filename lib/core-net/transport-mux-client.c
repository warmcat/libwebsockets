/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 *
 * Transport mux / demux
 */

#include <private-lib-core.h>

#if defined(STANDALONE)
struct lws_context_standalone;
#define lws_context lws_context_standalone
#endif

void
lws_transport_mux_client_request_tx(lws_transport_mux_t *tm)
{
	assert_is_tm(tm);
	tm->info.txp_cpath.ops_onw->req_write(tm->info.txp_cpath.priv_onw);
}


void
lws_transport_mux_destroy(lws_transport_mux_t **tm);

#if defined(_DEBUG)
void
lws_transport_path_client_dump(lws_txp_path_client_t *path, const char *ctx)
{
	char buf[200], *p = buf, *end = buf + sizeof(buf) - 1;
	uint32_t magic;
	int n;

	n = snprintf(p, lws_ptr_diff_size_t(end, p),
			"MUX: %p, IN: ops=%s, priv=%p",
			path->mux, path->ops_in ? path->ops_in->name : "null",
			path->priv_in);
	p = (p + n > end) ? end : p + n;
	if (path->priv_in) {
		magic = *(uint32_t *)path->priv_in;
		if (magic & 0xff000000) {
			n = snprintf(p, lws_ptr_diff_size_t(end, p), " (%c%c%c%c)",
					(int)(magic >> 24), (int)((magic >> 16) & 0xff),
					(int)((magic >> 8) & 0xff), (int)(magic & 0xff));
			p = (p + n > end) ? end : p + n;
		}
	}

	n = snprintf(p, lws_ptr_diff_size_t(end, p), ", ONW: ops=%s, priv=%p",
			path->ops_onw ? path->ops_onw->name : "null", path->priv_onw);
	p = (p + n > end) ? end : p + n;
	if (path->priv_onw) {
		magic = *(uint32_t *)path->priv_onw;
		if (magic & 0xff000000) {
			n = snprintf(p, lws_ptr_diff_size_t(end, p), " (%c%c%c%c)",
				(int)(magic >> 24), (int)((magic >> 16) & 0xff),
				(int)((magic >> 8) & 0xff), (int)(magic & 0xff));
			p = (p + n > end) ? end : p + n;
		}
	}

	*end = '\0';
	lwsl_notice("%s: %s: %s\n", __func__, ctx, buf);
}
#endif

/*
 * These are transport ops that let the mux transport encapsulate another
 * transport transparently.
 */

static int
lws_transport_mux_retry_connect(lws_txp_path_client_t *path,
				struct lws_sspc_handle *h)
{
	lws_transport_mux_ch_t *tmc;

	lwsl_user("%s\n", __func__);

	lws_transport_path_client_dump(path, __func__);

	if (path->mux->link_state != LWSTM_OPERATIONAL) {
		lwsl_user("%s: transport not operational\n", __func__);
		goto fail;
	}

	tmc = lws_transport_mux_add_channel(path->mux, (lws_transport_priv_t)h);
	if (!tmc)
		goto fail;

	lwsl_notice("%s: added channel\n", __func__);

	path->priv_onw = (lws_transport_priv_t)tmc;

	tmc->state = LWSTMC_PENDING_CREATE_CHANNEL;
	lws_dll2_add_tail(&tmc->list_pending_tx, &path->mux->pending_tx);
	lws_transport_mux_client_request_tx(path->mux);

	return 0;

fail:
	h->txp_path.ops_in->event_connect_disposition(h, 1);

	return 1;
}

static void
lws_transport_mux_ch_req_write(lws_transport_priv_t priv)
{
	lws_transport_mux_ch_t *tmc = (lws_transport_mux_ch_t *)priv;
	lws_transport_mux_t *tm;

	assert_is_tmch(tmc);
	if (!tmc->list.owner) {
		lwsl_err("%s: unlisted tmc %p\n", __func__, tmc);
		return;
	}
	tm = lws_container_of(tmc->list.owner, lws_transport_mux_t, owner);
	assert_is_tm(tm);

	lws_transport_mux_client_request_tx(tm);
	/* we want to write inside the channel, so register ch as pending */
	if (lws_dll2_is_detached(&tmc->list_pending_tx))
		lws_dll2_add_tail(&tmc->list_pending_tx, &tm->pending_tx);
}
#if 0
static void
lws_transport_mux_req_write(lws_transport_priv_t priv)
{
	lws_transport_mux_t *tm = (lws_transport_mux_t *)priv;
	assert_is_tm(tm);
	lws_transport_mux_client_request_tx(tm);
}
#endif

static int
lws_transport_mux_write(lws_transport_priv_t priv, uint8_t *buf, size_t len)
{
	lws_transport_mux_ch_t *tmc = (lws_transport_mux_ch_t *)priv;
	lws_transport_mux_t *tm = lws_container_of(tmc->list.owner,
						   lws_transport_mux_t, owner);

	assert_is_tmch(tmc);
	lwsl_user("%s: %d\n", __func__, (int)len);

	assert(len < 0xffff);

	buf[-4] = LWSSSS_LLM_MUX;
	buf[-3] = tmc->ch_idx;
	buf[-2] = (len >> 8) & 0xff;
	buf[-1] = len & 0xff;

	tm->info.txp_cpath.ops_onw->_write(tm->info.txp_cpath.priv_onw,
					   buf - 4, len + 4);

	return 0;
}
static void
lws_transport_mux_close(lws_transport_priv_t priv)
{

}
static void
lws_transport_mux_stream_up(lws_transport_priv_t priv)
{

}

/* incoming parsed channel cbs */

static int
ltm_ch_payload(lws_transport_mux_ch_t *tmc, const uint8_t *buf, size_t len)
{
	lws_ss_state_return_t r;

//	lwsl_notice("%s: len %d\n", __func__, (int)len);

	assert_is_tmch(tmc);

//	lwsl_hexdump_notice(buf, len);

	r = lws_txp_inside_sspc.event_read(tmc->priv, buf, len);
	if (r) {
		/*
		 * Basically the sspc parser rejected it as malformed... we
		 * lost something somewhere
		 *
		 */
		lwsl_notice("%s: r %d\n", __func__, r);

		return 1;
	}

//	return tm->info.txp_cpath.ops_in->event_read(tm->info.txp_cpath.priv_in,
//							buf, len);

	return 0;
}

static int
ltm_ch_opens(lws_transport_mux_ch_t *tmc, int determination)
{
	struct lws_sspc_handle *h = (struct lws_sspc_handle *)tmc->priv;

//	lws_transport_path_client_dump(&tm->info.txp_cpath, __func__);

	lwsl_sspc_err(h, "%d", determination);

       	if (lws_txp_inside_sspc.event_connect_disposition(h, determination))
        		return -1;

	return 0;
}

static int
ltm_ch_closes(lws_transport_mux_ch_t *tmc)
{
	lwsl_notice("%s\n", __func__);
	return 0;
}

static void
ltm_txp_req_write(lws_transport_mux_t *tm)
{
	lws_transport_mux_client_request_tx(tm);
}

static int
ltm_txp_can_write(lws_transport_mux_ch_t *tmc)
{
	assert_is_tmch(tmc);
	return lws_txp_inside_sspc.event_can_write(
			(struct lws_sspc_handle *)tmc->priv, 2048);
}

static const lws_txp_mux_parse_cbs_t cbs = {
	.payload		= ltm_ch_payload,
	.ch_opens		= ltm_ch_opens,
	.ch_closes		= ltm_ch_closes,
	.txp_req_write		= ltm_txp_req_write,
	.txp_can_write		= ltm_txp_can_write,
};

lws_ss_state_return_t
lws_transport_mux_event_read(lws_transport_priv_t priv,
			     const uint8_t *buf, size_t len)
{
	lws_transport_mux_t *tm = (lws_transport_mux_t *)priv;
	lws_ss_state_return_t r;

	assert_is_tm(tm);
	r = lws_transport_mux_rx_parse(tm, buf, len, &cbs);

	return r;
}

lws_ss_state_return_t
lws_transport_mux_event_can_write(struct lws_sspc_handle *h,
				  size_t metadata_limit)
{
	lwsl_notice("%s\n", __func__);
	return lws_txp_inside_sspc.event_can_write(h, metadata_limit);
}

void
lws_transport_mux_lost_coherence(lws_transport_priv_t priv)
{
	lws_transport_mux_t *tm = (lws_transport_mux_t *)priv;

	if (!tm)
		return;
	assert_is_tm(tm);

	lwsl_warn("%s: entering link LOST_SYNC\n", __func__);

	lws_transport_set_link(tm, LWSTM_TRANSPORT_DOWN);
}

lws_ss_state_return_t
lws_transport_mux_event_closed(lws_transport_priv_t priv)
{
	lws_transport_mux_ch_t *tmc = (lws_transport_mux_ch_t *)priv;
#if defined(_DEBUG)
	lws_transport_mux_t *tm = lws_container_of(tmc->list.owner,
				   lws_transport_mux_t, owner);
#endif
	assert_is_tmch(tmc);
	assert_is_tm(tm);

	if (tmc->priv) {
		lwsl_notice("%s: calling sspc event closed\n", __func__);
		lws_txp_inside_sspc.event_closed(tmc->priv);
	}

	return 0;
}

const lws_transport_client_ops_t lws_transport_mux_client_ops = {
	.name			= "txpmuxc",
 	.event_retry_connect	= lws_transport_mux_retry_connect,
 	.req_write		= lws_transport_mux_ch_req_write,
 	._write			= lws_transport_mux_write,
 	._close			= lws_transport_mux_close,
 	.event_stream_up	= lws_transport_mux_stream_up,
	.event_read		= lws_transport_mux_event_read,
	.lost_coherence		= lws_transport_mux_lost_coherence,
	.event_can_write	= lws_transport_mux_event_can_write,
	.event_closed		= lws_transport_mux_event_closed,
	.flags			= LWS_DSHFLAG_ENABLE_COALESCE |
				  LWS_DSHFLAG_ENABLE_SPLIT
};



#if defined(STANDALONE)
#undef lws_context
#endif
