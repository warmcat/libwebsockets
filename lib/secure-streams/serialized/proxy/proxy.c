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
 * When the user code is in a different process, a non-tls unix domain socket
 * proxy is used to asynchronusly transfer buffers in each direction via the
 * network stack, without explicit IPC
 *
 *     user_process{ [user code] | shim | socket-}------ lws_process{ lws }
 *
 * Lws exposes a listening unix domain socket in this case, the user processes
 * connect to it and pass just info.streamtype in an initial tx packet.  All
 * packets are prepended by a 1-byte type field when used in this mode.  See
 * lws-secure-streams.h for documentation and definitions.
 *
 * Proxying in either direction can face the situation it cannot send the onward
 * packet immediately and is subject to separating the write request from the
 * write action.  To make the best use of memory, a single preallocated buffer
 * stashes pending packets in all four directions (c->p, p->c, p->ss, ss->p).
 * This allows it to adapt to different traffic patterns without wasted areas
 * dedicated to traffic that isn't coming in a particular application.
 *
 * A shim is provided to monitor the process' unix domain socket and regenerate
 * the secure sockets api there with callbacks happening in the process thread
 * context.
 *
 * This file implements the listening unix domain socket proxy... this code is
 * only going to run on a Linux-class device with its implications about memory
 * availability.
 */

#include <private-lib-core.h>
/*
 * Proxy - onward secure-stream handler
 */

void
lws_proxy_clean_conn_ss(struct lws *wsi)
{
#if 0
	lws_ss_handle_t *h = (lws_ss_handle_t *)wsi->a.opaque_user_data;
	struct lws_sss_proxy_conn *conn = h->conn_if_sspc_onw;

	if (!wsi)
		return;

	if (conn && conn->ss)
		conn->ss->wsi = NULL;
#endif
}


void
ss_proxy_onward_link_proxy_req_writeable(lws_ss_handle_t *h_onward)
{
	ss_proxy_t *m = (ss_proxy_t *)&h_onward[1];

	if (m->conn->txp_path.priv_onw)
		m->conn->txp_path.ops_onw->proxy_req_write(m->conn->txp_path.priv_onw);
}

int
__lws_ss_proxy_bind_ss_to_conn_wsi(void *parconn, size_t dsh_size)
{
	struct lws_sss_proxy_conn *conn = (struct lws_sss_proxy_conn *)parconn;
	struct lws_context_per_thread *pt;

	if (!conn || !conn->txp_path.priv_onw || !conn->ss)
		return -1;

	pt = &conn->ss->context->pt[(int)conn->ss->tsi];

	if (lws_fi(&conn->ss->fic, "ssproxy_dsh_create_oom"))
		return -1;
	conn->dsh = lws_dsh_create(&pt->ss_dsh_owner, dsh_size,
				   (int)(conn->txp_path.ops_onw->flags | 2));
	if (!conn->dsh)
		return -1;

	conn->dsh->splitat = 1300;

	conn->txp_path.ops_onw->event_onward_bind(conn->txp_path.priv_onw,
						  conn->ss);

	return 0;
}

/*
 * event loop received something and is queueing it for the foreign side of
 * the dsh to consume later as serialized rx
 */

static int
lws_ss_serialize_rx_payload(struct lws_dsh *dsh, const uint8_t *buf,
			    size_t len, int flags, const char *rsp)
{
	lws_usec_t us = lws_now_usecs();
	uint8_t pre[128];
	int est = 19, l = 0;

	if (flags & LWSSS_FLAG_RIDESHARE) {
		/*
		 * We should have the rideshare name if we have been told it's
		 * on a non-default rideshare
		 */
		assert(rsp);
		if (!rsp)
			return 1;
		l = (int)strlen(rsp);
		est += 1 + l;
	} else
		assert(!rsp);

	// lwsl_user("%s: len %d, flags: %d\n", __func__, (int)len, flags);
	// lwsl_hexdump_info(buf, len);

	pre[0] = LWSSS_SER_RXPRE_RX_PAYLOAD;
	lws_ser_wu16be(&pre[1], (uint16_t)(len + (size_t)est - 3));
	lws_ser_wu32be(&pre[3], (uint32_t)flags);
	lws_ser_wu32be(&pre[7], 0);	/* write will compute latency here... */
	lws_ser_wu64be(&pre[11], (uint64_t)us);	/* ... and set this to the write time */

	/*
	 * If we are on a non-default rideshare, append the non-default name to
	 * the headers of the payload part, 1-byte length first
	 */

	if (flags & LWSSS_FLAG_RIDESHARE) {
		pre[19] = (uint8_t)l;
		memcpy(&pre[20], rsp, (unsigned int)l);
	}

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, (unsigned int)est, buf, len)) {
#if defined(_DEBUG)
		lws_dsh_describe(dsh, __func__);
#endif
		lwsl_err("%s: unable to alloc in dsh 1\n", __func__);

		return 1;
	}

	lwsl_notice("%s: dsh c2p %d, p2c %d\n", __func__,
		    (int)lws_dsh_get_size(dsh, KIND_C_TO_P),
		    (int)lws_dsh_get_size(dsh, KIND_SS_TO_P));

	return 0;
}

/* Onward secure streams payload interface */

lws_ss_state_return_t
lws_sss_proxy_onward_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;
	const char *rsp = NULL;
	int n;

	// lwsl_notice("%s: len %d\n", __func__, (int)len);

	/*
	 * The onward secure stream connection has received something.
	 */

	if (m->ss->rideshare != m->ss->policy && m->ss->rideshare) {
		rsp = m->ss->rideshare->streamtype;
		flags |= LWSSS_FLAG_RIDESHARE;
	}

	/*
	 * Apply SSS framing around this chunk of RX and stash it in the dsh
	 * in ss -> proxy [ -> client] direction.  This can fail...
	 */

	n = 1;
	if (m->conn->dsh && !lws_fi(&m->ss->fic, "ssproxy_dsh_rx_queue_oom"))
		n = lws_ss_serialize_rx_payload(m->conn->dsh, buf, len,
						flags, rsp);
	if (n) {
		if (m->conn->dsh) {
#if defined(_DEBUG)
			lws_dsh_describe(m->conn->dsh, __func__);
#endif
			/*
			 * We couldn't buffer this rx, eg due to OOM, let's
			 * escalate it to be a "loss of connection", which it
			 * basically is... as part of that, drop the dshes.
			 *
			 * This just affects the one stream that owns the
			 * dsh, caller should enter stream close flow and not
			 * send any further payload.
			 */

			lwsl_warn("%s: dropping SS dsh due to OOM\n", __func__);
			lws_dsh_empty(m->conn->dsh);
		}

		return LWSSSSRET_DISCONNECT_ME;
	}

	/*
	 * Manage rx flow on the SS (onward) side according to our situation
	 * in the dsh holding proxy->client serialized forwarding rx
	 */

	if (!m->conn->onward_in_flow_control && m->ss->wsi &&
	    m->ss->policy->proxy_buflen_rxflow_on_above &&
	    lws_dsh_get_size(m->conn->dsh, KIND_SS_TO_P) >=
				m->ss->policy->proxy_buflen_rxflow_on_above) {
		lwsl_ss_user(m->ss, "rxflow disabling rx (%lu / %lu, hwm %lu)",
			(unsigned long)lws_dsh_get_size(m->conn->dsh,
							KIND_SS_TO_P),
			(unsigned long)m->ss->policy->proxy_buflen,
			(unsigned long)m->ss->policy->proxy_buflen_rxflow_on_above);
		/*
		 * stop taking in rx once the onward wsi rx is above the
		 * high water mark
		 */
		lws_rx_flow_control(m->ss->wsi, 0);
		m->conn->onward_in_flow_control = 1;
	}

	if (m->conn->txp_path.priv_onw) /* if possible, request client conn write */
		m->conn->txp_path.ops_onw->proxy_req_write(m->conn->txp_path.priv_onw);

	return LWSSSSRET_OK;
}

/*
 * we are transmitting buffered payload originally from the client on to the ss
 */

lws_ss_state_return_t
lws_sss_proxy_onward_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		   size_t *len, int *flags)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;
	void *p;
	size_t si;

	if (!m->conn->ss || m->conn->state != LPCSPROX_OPERATIONAL) {
		lwsl_notice("%s: ss not ready\n", __func__);
		*len = 0;

		return LWSSSSRET_TX_DONT_SEND;
	}

	/*
	 * The onward secure stream says that we could send something to it
	 * (by putting it in buf, and setting *len and *flags)... dredge the
	 * next thing out of the dsh
	 */

	if (lws_ss_deserialize_tx_payload(m->conn->dsh, m->ss->wsi,
					  ord, buf, len, flags))
		return LWSSSSRET_TX_DONT_SEND;

	/* ... there's more we want to send? */
	if (!lws_dsh_get_head(m->conn->dsh, KIND_C_TO_P, (void **)&p, &si))
		_lws_ss_request_tx(m->conn->ss);

	if (!*len && !*flags)
		/* we don't actually want to send anything */
		return LWSSSSRET_TX_DONT_SEND;

	lwsl_info("%s: onward tx %d fl 0x%x\n", __func__, (int)*len, *flags);

	return LWSSSSRET_OK;
}

/*
 * event loop side is issuing state, serialize and put it in the dbuf for
 * the foreign side to consume later
 */

static int
lws_ss_serialize_state(struct lws_sss_proxy_conn *conn, lws_ss_constate_t state,
		       lws_ss_tx_ordinal_t ack)
{
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	const lws_fi_ctx_t *fic = conn->txp_path.ops_onw->fault_context(
						conn->txp_path.priv_onw);
#endif
	struct lws_dsh *dsh = conn->dsh;
	uint8_t pre[12];
	int n = 4;

	if (state == LWSSSCS_EVENT_WAIT_CANCELLED)
		return 0;

	lwsl_info("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

	if (!dsh) {
		/* he can't store anything further on the link */
		lwsl_notice("%s: dsh for conn was destroyed\n", __func__);
		return 0;
	}

	pre[0] = LWSSS_SER_RXPRE_CONNSTATE;
	pre[1] = 0;

	if (state > 255) {
		pre[2] = 8;
		lws_ser_wu32be(&pre[3], state);
		n = 7;
	} else {
		pre[2] = 5;
		pre[3] = (uint8_t)state;
	}

	lws_ser_wu32be(&pre[n], ack);

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, (unsigned int)n + 4, NULL, 0)
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			|| (fic && lws_fi(fic, "sspc_dsh_ss2p_oom"))
#endif
	    ) {
		lwsl_err("%s: unable to alloc in dsh 2\n", __func__);

		return 1;
	}

	return 0;
}


lws_ss_state_return_t
lws_sss_proxy_onward_state(void *userobj, void *sh, lws_ss_constate_t state,
			   lws_ss_tx_ordinal_t ack)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;
	size_t dsh_size;

	switch (state) {
	case LWSSSCS_CREATING:

		/*
		 * conn is private to -process.c, call thru to a) adjust
		 * the accepted incoming proxy link wsi tag name to be
		 * appended with the onward ss tag information now we
		 * have it, and b) allocate the dsh buffer now we
		 * can find out the policy about it for the streamtype.
		 */

		dsh_size = m->ss->policy->proxy_buflen ?
				m->ss->policy->proxy_buflen : 32768;

		lwsl_notice("%s: %s: initializing dsh max len %lu\n",
				__func__, lws_ss_tag(m->ss),
				(unsigned long)dsh_size);

		/* this includes ssproxy_dsh_create_oom fault generation */

		if (__lws_ss_proxy_bind_ss_to_conn_wsi(m->conn, dsh_size)) {

			/* failed to allocate the dsh */

			lwsl_notice("%s: dsh init failed\n", __func__);

			return LWSSSSRET_DESTROY_ME;
		}
		break;

	case LWSSSCS_DESTROYING:
		if (!m->conn)
			break;
		if (!m->conn->txp_path.priv_onw) {
			/*
			 * Our onward secure stream is closing and our client
			 * connection has already gone away... destroy the conn.
			 */
			lwsl_notice("%s: Destroying conn\n", __func__);
			lws_dsh_empty(m->conn->dsh);
			if (!m->conn->ss) {
				lws_dsh_destroy(&m->conn->dsh);
				free(m->conn);
				m->conn = NULL;
			}
			return 0;
		} else
			lwsl_info("%s: ss DESTROYING, wsi up\n", __func__);
		break;

	default:
		break;
	}
	if (!m->conn) {
		lwsl_warn("%s: dropping state due to conn not up\n", __func__);

		return LWSSSSRET_OK;
	}

	if (lws_ss_serialize_state(m->conn, state, ack))
		/*
		 * Failed to alloc state packet that we want to send in dsh,
		 * we will lose coherence and have to disconnect the link
		 */
		return LWSSSSRET_DISCONNECT_ME;

	if (state != LWSSSCS_DESTROYING &&
	    m->conn->txp_path.priv_onw) /* if possible, request client conn write */
		m->conn->txp_path.ops_onw->proxy_req_write(m->conn->txp_path.priv_onw);

	return LWSSSSRET_OK;
}

/*
 * event loop side was told about remote peer tx credit window update, serialize
 * and put it in the dbuf for the foreign side to consume later
 */

static int
lws_ss_serialize_txcr(struct lws_dsh *dsh, int txcr)
{
	uint8_t pre[7];

	lwsl_info("%s: %d\n", __func__, txcr);

	pre[0] = LWSSS_SER_RXPRE_TXCR_UPDATE;
	pre[1] = 0;
	pre[2] = 4;
	lws_ser_wu32be(&pre[3], (uint32_t)txcr);

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, 7, NULL, 0)) {
		lwsl_err("%s: unable to alloc in dsh 2\n", __func__);

		return 1;
	}

	return 0;
}

void
ss_proxy_onward_txcr(void *userobj, int bump)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;

	if (!m->conn)
		return;

	lws_ss_serialize_txcr(m->conn->dsh, bump);

	if (m->conn->txp_path.priv_onw) /* if possible, request client conn write */
		m->conn->txp_path.ops_onw->proxy_req_write(m->conn->txp_path.priv_onw);
}

/*
 * called from create_context()
 */

int
lws_ss_proxy_create(struct lws_context *cx, const char *bind, int port)
{
	assert(cx->txp_ppath.ops_onw);
	return cx->txp_ppath.ops_onw->init_proxy_server(cx,
						&lws_txp_inside_proxy,
						NULL,
						&cx->txp_ppath,
						cx->txp_ssproxy_info,
						bind, port);
}

lws_ss_state_return_t
lws_ss_proxy_destroy(struct lws_context *cx)
{
	if (!cx->txp_ppath.ops_onw)
		return 0;

	if (!cx->txp_ppath.ops_onw->destroy_proxy_server)
		return 0;
	return cx->txp_ppath.ops_onw->destroy_proxy_server(cx);
}
