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

#if defined(_DEBUG)
void
lws_transport_path_proxy_dump(lws_txp_path_proxy_t *path, const char *ctx)
{
	char buf[128], *p = buf, *end = buf + sizeof(buf) - 1;
	uint32_t magic;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			"MUX: %p, IN: ops %s, priv %p",
			path->mux, path->ops_in ? path->ops_in->name : "null",
			path->priv_in);
	if (path->priv_in) {
		magic = *(uint32_t *)path->priv_in;
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), " (%c%c%c%c)",
				(int)(magic >> 24), (int)((magic >> 16) & 0xff),
				(int)((magic >> 8) & 0xff), (int)(magic & 0xff));
	}
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ", ONW: ops %s, priv %p",
			path->ops_in ? path->ops_in->name : "null", path->priv_in);
	if (path->priv_in) {
		magic = *(uint32_t *)path->priv_in;
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), " (%c%c%c%c)",
				(int)(magic >> 24), (int)((magic >> 16) & 0xff),
				(int)((magic >> 8) & 0xff), (int)(magic & 0xff));
	}

	*end = '\0';
	lwsl_notice("%s: %s: %s\n", __func__, ctx, buf);
}
#endif


void
lws_transport_mux_proxy_request_tx(lws_transport_mux_t *tm)
{
	tm->info.txp_ppath.ops_onw->proxy_req_write(tm->info.txp_ppath.priv_onw);
}



/*
 * We're the outer, mux server creation, we should instantiate the mux and
 * onward transport
 *
 * Our transport_priv is the mux object itself.
 */

static int
lws_transport_mux_init_proxy_server(struct lws_context *cx,
			      const struct lws_transport_proxy_ops *txp_ops_inward,
			      lws_transport_priv_t txp_priv_inward,
			      lws_txp_path_proxy_t *txp_ppath,
			      const void *txp_info,
			      const char *bind, int port)
{
	lws_transport_info_t *info = (lws_transport_info_t *)txp_info;
	lws_txp_path_proxy_t txp_ppath_temp;
	lws_transport_mux_t *tm;

	lwsl_user("%s: priv_inward %p\n", __func__, txp_priv_inward);
	assert(info);
	assert(info->txp_ppath.ops_onw);

	/* let's create the mux... */

	tm = malloc(sizeof(*tm));
	if (!tm)
		return 1;

	memset(tm, 0, sizeof(*tm));
	txp_ppath->mux = tm;

#if defined(_DEBUG)
	tm->magic			= LWS_TRANSPORT_MUX_MAGIC;
#endif
	tm->cx				= cx;
	tm->info			= *info;
	tm->info.txp_ppath.ops_in	= txp_ops_inward;
	tm->info.txp_ppath.priv_in	= txp_priv_inward;
	tm->info.txp_ppath.mux		= tm;

	/* Let's see about creating the onward transport instance after...
	 * This is creating the transport-serial instance or whatever.
	 *
	 * For channels, priv is a conn.  For the proxy itself, it's NULL here.
	 */

	if (info->txp_ppath.ops_onw->init_proxy_server(cx,
						&lws_transport_mux_proxy_ops,
						(lws_transport_priv_t)tm,
						&txp_ppath_temp,
						info->onward_txp_info,
						bind, port)) {
		lwsl_err("%s: onward %s server int fail\n", __func__,
				info->txp_ppath.ops_onw->name);
		return 1;
	}

	tm->info.txp_ppath.ops_onw	= info->txp_ppath.ops_onw;
	tm->info.txp_ppath.priv_onw	= txp_ppath_temp.priv_onw;

	/* ...let's schedule a ping straight off at the mux layer */

	lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
			 sul_ping_cb, 1);

	lwsl_user("%s: OK\n", __func__);

	return 0;
}

static int
lws_transport_mux_destroy_proxy_server(struct lws_context *cx)
{
	if (!cx->txp_ppath.mux)
		return 0;

	lws_transport_mux_destroy(&cx->txp_ppath.mux);

	return 0;
}

lws_ss_state_return_t
lws_transport_mux_proxy_new_conn(struct lws_context *cx,
				 const struct lws_transport_proxy_ops *txp_ops_inward,
				 lws_transport_priv_t txp_priv_inward,
	#if defined(LWS_WITH_SYS_FAULT_INJECTION)
				         const lws_fi_ctx_t *fic,
	#endif
				struct lws_sss_proxy_conn **conn,
				lws_transport_priv_t txp_priv)
{
	return 0;
}

lws_ss_state_return_t
lws_transport_mux_proxy_close_conn(struct lws_sss_proxy_conn *conn)
{
	return 0;
}

/* incoming parsed channel cbs */

static int
ltm_ch_payload(lws_transport_mux_ch_t *tmc, const uint8_t *buf, size_t len)
{
#if defined(_DEBUG)
	lws_transport_mux_t *tm;
#endif

	assert_is_tmch(tmc);

#if defined(_DEBUG)
	tm = lws_container_of(tmc->list.owner, lws_transport_mux_t, owner);
	assert_is_tm(tm);
#endif

	lwsl_notice("%s\n", __func__);
//	lwsl_hexdump_err(buf, len);
#if defined(_DEBUG)
	lws_transport_path_proxy_dump(&tm->info.txp_ppath, __func__);
#endif

	lws_txp_inside_proxy.proxy_read(tmc->priv, buf, len);

	return 0;
}

static int
ltm_ch_opens(lws_transport_mux_ch_t *tmc, int determination)
{
	lws_transport_mux_t *tm;
	struct lws_sss_proxy_conn *conn;

	lwsl_notice("%s\n", __func__);

	assert_is_tmch(tmc);
	tm = lws_container_of(tmc->list.owner, lws_transport_mux_t, owner);
		assert_is_tm(tm);

	if (lws_txp_inside_proxy.event_new_conn(
			tm->cx, &lws_txp_inside_proxy,
			(lws_transport_priv_t)NULL,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			NULL,
#endif
			&conn,
			(lws_transport_priv_t)tmc)) {
		lwsl_err("%s: hangup from new_conn\n", __func__);
		return -1;
	}

	tmc->priv = (lws_transport_priv_t)conn;

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
//	lws_transport_mux_proxy_request_tx(tm);
	if (tm->info.txp_ppath.priv_onw)
		tm->info.txp_ppath.ops_onw->proxy_req_write(tm->info.txp_ppath.priv_onw);
}

static int
ltm_txp_can_write(lws_transport_mux_ch_t *tmc)
{
	assert_is_tmch(tmc);
	return lws_txp_inside_proxy.event_proxy_can_write(tmc->priv
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			, NULL
#endif
			);
}

static const lws_txp_mux_parse_cbs_t cbs = {
	.payload		= ltm_ch_payload ,
	.ch_opens		= ltm_ch_opens,
	.ch_closes		= ltm_ch_closes,
	.txp_req_write		= ltm_txp_req_write,
	.txp_can_write		= ltm_txp_can_write,
};

lws_ss_state_return_t
lws_transport_mux_proxy_event_proxy_can_write(
		lws_transport_priv_t priv
		//struct lws_sss_proxy_conn *conn
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
				, const lws_fi_ctx_t *fic
#endif
		)
{
	lws_transport_mux_t *tm = (lws_transport_mux_t *)priv;
	struct lws_sss_proxy_conn *conn;
	uint8_t buf[2048];
	size_t r = sizeof(buf), r1;

	assert_is_tm(tm);

	if (lws_transport_mux_pending(tm, buf, &r, &cbs)) {
		r1 = r;
		tm->info.txp_ppath.ops_onw->proxy_write(tm->info.txp_ppath.priv_onw, buf, &r);
		if (r != r1)
			assert(0);
		return 0;
	}

	conn = (struct lws_sss_proxy_conn *)tm->info.txp_ppath.priv_in;
	if (conn) {

		assert_is_conn(conn);

		tm->info.txp_ppath.ops_in->event_proxy_can_write(conn
	#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					, fic
	#endif
				);
	}

	return 0;
}

static void
lws_transport_mux_onward_bind(lws_transport_priv_t priv, struct lws_ss_handle *h)
{

}
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
static const lws_fi_ctx_t *
lws_transport_mux_fault_context(lws_transport_priv_t priv)
{
	return NULL;
}
#endif
static void
lws_transport_mux_client_up(lws_transport_priv_t priv)
{

}

static void
lws_transport_mux_proxy_req_write(lws_transport_priv_t priv)
{
	lws_transport_mux_ch_t *tmc = (lws_transport_mux_ch_t *)priv;
	lws_transport_mux_t *tm;

	assert_is_tmch(tmc);

	tm = lws_container_of(tmc->list.owner, lws_transport_mux_t, owner);
	assert_is_tm(tm);

	if (!tm->info.txp_ppath.priv_onw)
		return;

	if (lws_dll2_is_detached(&tmc->list_pending_tx))
		lws_dll2_add_tail(&tmc->list_pending_tx, &tm->pending_tx);

	tm->info.txp_ppath.ops_onw->proxy_req_write(tm->info.txp_ppath.priv_onw);
}
/**< Get the proxy to write to out on the onward (back to client) transport on this channel */
int
lws_transport_mux_proxy_write(lws_transport_priv_t priv, uint8_t *buf, size_t *len)
{
	lws_transport_mux_ch_t *tmc = (lws_transport_mux_ch_t *)priv;
	lws_transport_mux_t *tm;
	size_t olen;

	//lwsl_notice("%s\n", __func__);

	assert_is_tmch(tmc);

	tm = lws_container_of(tmc->list.owner, lws_transport_mux_t, owner);
	assert_is_tm(tm);

	assert(*len < 0xffff);

	/* use the LWS_PRE area to encapsulate the SSS inside the mux protocol */

	buf[-4] = LWSSSS_LLM_MUX;
	buf[-3] = tmc->ch_idx;
	buf[-2] = (*len >> 8) & 0xff;
	buf[-1] = *len & 0xff;

	olen = (*len) + 4;
	tm->info.txp_ppath.ops_onw->proxy_write(tm->info.txp_ppath.priv_onw,
						buf - 4, &olen);

	assert(olen == (*len) + 4);

	return 0;
}

lws_ss_state_return_t
lws_transport_mux_proxy_read(lws_transport_priv_t priv,
			     const uint8_t *buf, size_t len)
{
	lws_transport_mux_t *tm = (lws_transport_mux_t *)priv;
	lws_ss_state_return_t r;

	assert_is_tm(tm);



	r = lws_transport_mux_rx_parse(tm, buf, len, &cbs);

	return r;
}


const lws_transport_proxy_ops_t lws_transport_mux_proxy_ops = {
	.name			= "txpmuxp",
	.init_proxy_server	= lws_transport_mux_init_proxy_server,
	.destroy_proxy_server	= lws_transport_mux_destroy_proxy_server,
	.proxy_read		= lws_transport_mux_proxy_read,
 	.proxy_req_write	= lws_transport_mux_proxy_req_write,
 	.proxy_write		= lws_transport_mux_proxy_write,
	.event_onward_bind	= lws_transport_mux_onward_bind,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	.fault_context		= lws_transport_mux_fault_context,
#endif
	.event_close_conn	= lws_transport_mux_proxy_close_conn,
	.event_proxy_can_write	= lws_transport_mux_proxy_event_proxy_can_write,
	.event_new_conn		= lws_transport_mux_proxy_new_conn,
	.event_client_up	= lws_transport_mux_client_up,
	.flags			= LWS_DSHFLAG_ENABLE_COALESCE |
				  LWS_DSHFLAG_ENABLE_SPLIT
};
