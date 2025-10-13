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
 */

#include <private-lib-core.h>

/*
 * Proxy has received a new connection from a client
 */

static lws_ss_state_return_t
lws_ssproxy_txp_new_conn(struct lws_context *cx,
				const struct lws_transport_proxy_ops *txp_ops_inward,
				lws_transport_priv_t txp_priv_inward,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			       const lws_fi_ctx_t *fic,
#endif
			       struct lws_sss_proxy_conn **conn,
			       lws_transport_priv_t txp_priv)
{
	if (
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			fic &&
#endif
			lws_fi(fic, "ssproxy_client_adopt_oom"))
		*conn = NULL;
	else
		*conn = lws_zalloc(sizeof(**conn), __func__);
	if (!*conn)
		return 1;

	/* dsh is allocated when the onward ss is done */

#if defined(_DEBUG)
	(*conn)->magic			= LWS_PROXY_CONN_MAGIC;
#endif
	(*conn)->state			= LPCSPROX_WAIT_INITIAL_TX;
	(*conn)->txp_path		= cx->txp_ppath;
	(*conn)->txp_path.priv_onw	= txp_priv;

	(*conn)->txp_path.ops_in	= txp_ops_inward;
	(*conn)->txp_path.priv_in	= txp_priv_inward;
	(*conn)->cx			= cx;

	return LWSSSSRET_OK;
}

/*
 * Proxy has received a close indication from a client
 */

static lws_ss_state_return_t
lws_ssproxy_txp_close_conn(struct lws_sss_proxy_conn *conn)
{
	lws_transport_priv_t epriv;

	conn->txp_path.priv_onw = NULL;
	epriv = conn->txp_path.priv_onw;

	/*
	 * If there's an outgoing, proxied SS conn on our behalf, we
	 * have to destroy it
	 *
	 * Wsi related stuff in here is talking about the onward wsi / ss
	 * connection, it doesn't introduce any dependency on the proxy -
	 * client link transport
	 */

	if (conn->ss) {
		struct lws *cw;

		cw = conn->ss->wsi;

		/*
		 * conn->ss is the onward connection SS
		 */

		lwsl_info("%s: destroying %s, wsi %s\n",
				__func__, lws_ss_tag(conn->ss),
				lws_wsi_tag(conn->ss->wsi));

		/* sever conn relationship with onward ss about to be deleted */

		conn->ss->wsi = NULL;

		if (cw && epriv != (lws_transport_priv_t)cw) {

			/* disconnect onward SS from its wsi */

			lws_set_opaque_user_data(cw, NULL);

			/*
			 * The wsi doing the onward connection can no
			 * longer relate to the conn... otherwise when
			 * he gets callbacks he wants to bind to
			 * the ss we are about to delete
			 */
			lws_wsi_close(cw, LWS_TO_KILL_ASYNC);
		}

		/* destroy the onward ss (setting conn->ss NULL) */
		lws_ss_destroy(&conn->ss);

		/*
		 * Conn may have gone, at ss destroy handler in
		 * ssi.state for proxied ss
		 */

		return LWSSSSRET_OK;
	}

	if (conn->state == LPCSPROX_DESTROYED || !conn->ss) {
		/*
		 * There's no onward secure stream and our client
		 * connection is closing.  Destroy the conn.
		 */
		lws_dsh_destroy(&conn->dsh);
		lws_free(conn);
	} else
		lwsl_debug("%s: CLOSE; %s\n", __func__, lws_ss_tag(conn->ss));

	return LWSSSSRET_OK;
}


static lws_ss_state_return_t
lws_ssproxy_txp_rx(lws_transport_priv_t txp_priv, const uint8_t *in, size_t len)
{
	struct lws_sss_proxy_conn *conn = (struct lws_sss_proxy_conn *)txp_priv;
	lws_ss_state_return_t r;
	lws_ss_info_t ssi;

	assert_is_conn(conn);

	// lwsl_hexdump_info(in, len);

	if (conn->state == LPCSPROX_WAIT_INITIAL_TX) {
		memset(&ssi, 0, sizeof(ssi));
		ssi.user_alloc = sizeof(ss_proxy_t);
		ssi.handle_offset = offsetof(ss_proxy_t, ss);
		ssi.opaque_user_data_offset = offsetof(ss_proxy_t, conn);
		ssi.rx = lws_sss_proxy_onward_rx;
		ssi.tx = lws_sss_proxy_onward_tx;
	}
	ssi.state = lws_sss_proxy_onward_state;
	ssi.flags = 0;

	// coverity[uninit_use_in_call]
	r = lws_ss_proxy_deserialize_parse(&conn->parser, conn->cx, conn->dsh,
					   in, len, &conn->state, conn,
					   &conn->ss, &ssi);
	switch (r) {
	default:
		break;
	case LWSSSSRET_DISCONNECT_ME:
		return r;
	case LWSSSSRET_DESTROY_ME:
		if (conn->ss)
			lws_ss_destroy(&conn->ss);
		return r;
	}

	if ((conn->state == LPCSPROX_REPORTING_FAIL ||
	     conn->state == LPCSPROX_REPORTING_OK) &&
	     conn->txp_path.priv_onw)
		conn->txp_path.ops_onw->proxy_req_write(conn->txp_path.priv_onw);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
lws_ssproxy_txp_proxy_can_write(lws_transport_priv_t priv
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		, const lws_fi_ctx_t *fic
#endif
		)
{
	struct lws_sss_proxy_conn *conn = (struct lws_sss_proxy_conn *)priv;
	const lws_ss_policy_t *rsp;
	lws_ss_metadata_t *md;
	const uint8_t *cp;
	char _s[1580 + LWS_PRE], *s = _s + LWS_PRE;
	size_t si, csi;
	uint8_t *p;
	char pay;
	int n;

	assert_is_conn(conn);

	n = 0;
	pay = 0;

	*(s + 3) = 0;
	cp = (const uint8_t *)s;

	switch (conn->state) {
	case LPCSPROX_REPORTING_FAIL:
		*(s + 3) = 1;
		/* fallthru */
	case LPCSPROX_REPORTING_OK:
		*s = LWSSS_SER_RXPRE_CREATE_RESULT;
		*(s + 1) = 0;
		*(s + 2) = 1;

		n = 8;

		lws_ser_wu32be((uint8_t *)s + 4, conn->ss &&
						 conn->ss->policy ?
				conn->ss->policy->client_buflen : 0);

		/*
		 * If there's rideshare sequencing, it's added after the
		 * first 4 bytes or the create result, comma-separated
		 */

		if (conn->ss) {
			rsp = conn->ss->policy;

			while (rsp) {
				if (n != 4 && n < (int)sizeof(_s) - LWS_PRE - 2)
					*(s + (n++)) = ',';
				n += lws_snprintf(s + n, sizeof(_s) - LWS_PRE - (unsigned int)n,
						"%s", rsp->streamtype);
				rsp = lws_ss_policy_lookup(conn->cx,
					rsp->rideshare_streamtype);
			}
		}
		*(s + 2) = (char)(n - 3);
		conn->state = LPCSPROX_OPERATIONAL;
		conn->txp_path.ops_onw->event_client_up(conn->txp_path.priv_onw);
		break;

	case LPCSPROX_OPERATIONAL:

		/*
		 * returning [onward -> ] proxy]-> client
		 * rx metadata has priority 1
		 */

		md = conn->ss->metadata;
		while (md) {
			// lwsl_notice("%s: check %s: %d\n", __func__,
			// md->name, md->pending_onward);
			if (md->pending_onward) {
				size_t naml = strlen(md->name);

				// lwsl_notice("%s: proxy issuing rxmd\n", __func__);

				if (4 + naml + md->length > sizeof(_s) - LWS_PRE) {
					lwsl_err("%s: rxmdata too big\n",
							__func__);
					goto hangup;
				}
				md->pending_onward = 0;
				p = (uint8_t *)s;
				p[0] = LWSSS_SER_RXPRE_METADATA;
				lws_ser_wu16be(&p[1], (uint16_t)(1 + naml +
						      md->length));
				p[3] = (uint8_t)naml;
				memcpy(&p[4], md->name, naml);
				p += 4 + naml;
				memcpy(p, md->value__may_own_heap,
				       md->length);
				p += md->length;

				n = lws_ptr_diff(p, cp);
				goto do_write_nz;
			}

			md = md->next;
		}

		/*
		 * If we have performance data, render it in JSON
		 * and send that in LWSSS_SER_RXPRE_PERF has
		 * priority 2
		 */

#if defined(LWS_WITH_CONMON)
		if (conn->ss->conmon_json) {
			unsigned int xlen = conn->ss->conmon_len;

			if (xlen > sizeof(s) - 3)
				xlen = sizeof(s) - 3;
			cp = (uint8_t *)s;
			p = (uint8_t *)s;
			p[0] = LWSSS_SER_RXPRE_PERF;
			lws_ser_wu16be(&p[1], (uint16_t)xlen);
			memcpy(&p[3], conn->ss->conmon_json, xlen);

			lws_free_set_NULL(conn->ss->conmon_json);
			n = (int)(xlen + 3);

			pay = 0;
			goto do_write_nz;
		}
#endif
		/*
		 * if no fresh rx metadata, just pass through incoming
		 * dsh
		 */

		if (lws_dsh_get_head(conn->dsh, KIND_SS_TO_P, (void **)&p, &si))
			break;

		cp = p;
		pay = 1;
		n = (int)si;
		break;
	default:
		break;
	}
do_write_nz:
	if (!n)
		return LWSSSSRET_OK;

	if (
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	    fic &&
#endif
			lws_fi(fic, "ssproxy_client_write_fail"))
		n = -1;
	else {
		si = csi = (size_t)n;
		n = conn->txp_path.ops_onw->proxy_write(conn->txp_path.priv_onw,
						  (uint8_t *)cp, &csi);
	}

	if (n < 0) {
		lwsl_info("%s: WRITEABLE: %d\n", __func__, n);

		goto hangup;
	}

	switch (conn->state) {
	case LPCSPROX_REPORTING_FAIL:
		goto hangup;
	case LPCSPROX_OPERATIONAL:
		if (pay) {
			if (si == csi)
				lws_dsh_free((void **)&p);
			else
				lws_dsh_consume(conn->dsh, KIND_SS_TO_P, csi);

			/*
			 * Did we go below the rx flow threshold for
			 * this dsh?
			 */

			if (conn->onward_in_flow_control &&
			    conn->ss->policy->proxy_buflen_rxflow_on_above &&
			    conn->ss->wsi &&
			    lws_dsh_get_size(conn->dsh, KIND_SS_TO_P) <
			      conn->ss->policy->proxy_buflen_rxflow_off_below) {
				lwsl_user("%s: %s: rxflow enabling rx (%lu / %lu, lwm %lu)\n", __func__,
					  lws_wsi_tag(conn->ss->wsi),
					  (unsigned long)lws_dsh_get_size(conn->dsh, KIND_SS_TO_P),
					  (unsigned long)conn->ss->policy->proxy_buflen,
					  (unsigned long)conn->ss->policy->proxy_buflen_rxflow_off_below);
				/*
				 * Resume receiving taking in rx once
				 * below the low threshold
				 */
				lws_rx_flow_control(conn->ss->wsi,
						    LWS_RXFLOW_ALLOW);
				conn->onward_in_flow_control = 0;
			}
		}
		if (!lws_dsh_get_head(conn->dsh, KIND_SS_TO_P,
				     (void **)&p, &si)) {

			if (conn->txp_path.ops_onw->proxy_check_write_more &&
			    conn->txp_path.ops_onw->proxy_check_write_more(
					conn->txp_path.priv_onw)) {
				cp = p;
				pay = 1;
				n = (int)si;
				goto do_write_nz;
			}

			conn->txp_path.ops_onw->proxy_req_write(
					conn->txp_path.priv_onw);
		}
	default:
		break;
	}

	return LWSSSSRET_OK;

hangup:
	return LWSSSSRET_DISCONNECT_ME;
}

const lws_transport_proxy_ops_t lws_txp_inside_proxy = {
	.name				= "txp_inside_proxy",
	.event_new_conn			= lws_ssproxy_txp_new_conn,
	.proxy_read			= lws_ssproxy_txp_rx,
	.event_close_conn		= lws_ssproxy_txp_close_conn,
	.event_proxy_can_write		= lws_ssproxy_txp_proxy_can_write,
};

