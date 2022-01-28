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
 * These are helpers used by the transport implementation.  They contain the
 * generic sspc actions to handle events that happen at the transport.
 */

#include <private-lib-core.h>

#if defined(STANDALONE)

#define lws_context lws_context_standalone

void
lws_ser_wu16be(uint8_t *b, uint16_t u)
{
	*b++ = (uint8_t)(u >> 8);
	*b = (uint8_t)u;
}

void
lws_ser_wu32be(uint8_t *b, uint32_t u32)
{
	*b++ = (uint8_t)(u32 >> 24);
	*b++ = (uint8_t)(u32 >> 16);
	*b++ = (uint8_t)(u32 >> 8);
	*b = (uint8_t)u32;
}

void
lws_ser_wu64be(uint8_t *b, uint64_t u64)
{
	lws_ser_wu32be(b, (uint32_t)(u64 >> 32));
	lws_ser_wu32be(b + 4, (uint32_t)u64);
}

#undef lws_malloc
#define lws_malloc(a, b) malloc(a)
#undef lws_free
#define lws_free(a) free(a)

#endif

static size_t
lws_sspc_serialize_metadata(lws_sspc_handle_t *h, lws_sspc_metadata_t *md,
			    uint8_t *p, uint8_t *end)
{
	size_t n, txc;

	if (md->name[0] == '\0') {

		lwsl_sspc_info(h, "sending tx credit update %d",
				md->tx_cr_adjust);

		p[0] = LWSSS_SER_TXPRE_TXCR_UPDATE;
		lws_ser_wu16be(&p[1], 4);
		lws_ser_wu32be(&p[3], (uint32_t)md->tx_cr_adjust);

		n = 7;

	} else {

		lwsl_sspc_info(h, "sending metadata");

		p[0] = LWSSS_SER_TXPRE_METADATA;
		txc = strlen(md->name);
		n = txc + 1 + md->len;
		if (n > 0xffff)
			/* we can't serialize this metadata in 16b length */
			return 0;
		if (n > lws_ptr_diff_size_t(end, &p[4]))
			/* we don't have space for this metadata */
			return 0;
		lws_ser_wu16be(&p[1], (uint16_t)n);
		p[3] = (uint8_t)txc;
		memcpy(&p[4], md->name, (unsigned int)txc);
		memcpy(&p[4 + txc], &md[1], md->len);
		n = 4 + txc + md->len;
	}

	lws_dll2_remove(&md->list);
	lws_free(md);

	return n;
}

/*
 * An attempt to establish a link to the SS proxy has failed
 */

lws_ss_state_return_t
lws_sspc_txp_connect_disposition(lws_sspc_handle_t *h, int disposition)
{
	lws_ss_state_return_t r;
	uint64_t i;

	if (!disposition) {
		if (!h
	#if !defined(STANDALONE)
				|| lws_fi(&h->fic, "sspc_fail_on_linkup")
	#endif
		)
			return 1;

		lwsl_sspc_info(h, "CONNECTED (%s), %s", h->ssi.streamtype, h->txp_path.ops_onw->name);

		h->state = LPCSCLI_SENDING_INITIAL_TX;
		h->us_start_upstream = 0;

		h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

		return LWSSSSRET_OK;
	}

	h->txp_path.priv_onw = NULL;
	lws_sul_schedule(h->context, 0, &h->sul_retry,
			 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);

	if (!h->ssi.state)
		return LWSSSSRET_OK;

	i = (uint64_t)(lws_now_usecs() - h->us_start_upstream) / LWS_US_PER_MS;
	if (i > 0xffffffffull)
		i = 0xffffffffull;

	r = h->ssi.state(lws_sspc_to_user_object(h), NULL,
			 LWSSSCS_UPSTREAM_LINK_RETRY, (uint32_t)i);

	if (r == LWSSSSRET_DESTROY_ME)
		lws_sspc_destroy(&h);

	return LWSSSSRET_OK;
}

void
lws_sspc_sul_retry_cb(lws_sorted_usec_list_t *sul)
{
	lws_sspc_handle_t *h = lws_container_of(sul, lws_sspc_handle_t,
						sul_retry);

	if (h->txp_path.ops_onw->event_retry_connect(&h->txp_path, h))
		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);
}

/*
 * The transport connection has closed
 */

lws_ss_state_return_t
lws_sspc_txp_event_closed(lws_transport_priv_t priv)
{
	lws_sspc_handle_t *h = (lws_sspc_handle_t *)priv;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (!h) {
		lwsl_sspc_info(h, "No sspc on client proxy link close");
		return LWSSSSRET_OK;
	}

	h->parser.ps = RPAR_TYPE;

	lws_dsh_empty(h->dsh);
	h->txp_path.priv_onw = NULL;
	h->conn_req_state = LWSSSPC_ONW_NONE;
	if (h->ss_dangling_connected && h->ssi.state) {

		lwsl_sspc_notice(h, "setting _DISCONNECTED");
		h->ss_dangling_connected = 0;
		h->prev_ss_state = LWSSSCS_DISCONNECTED;
		r = h->ssi.state(ss_to_userobj(h), NULL,
					 LWSSSCS_DISCONNECTED, 0);
	}
	if (r != LWSSSSRET_DESTROY_ME)
		/*
		 * schedule a reconnect in 1s
		 */
		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);

	return r;
}

/*
 * We received rx from the proxy... caller must do destroy on DESTROY_ME
 */

lws_ss_state_return_t
lws_sspc_txp_rx_from_proxy(lws_transport_priv_t txp_priv, const uint8_t *in,
				 size_t len)
{
	lws_sspc_handle_t *h = (lws_sspc_handle_t *)txp_priv;
	void *m = (void *)((uint8_t *)(h + 1));

	assert(h);

#if !defined(STANDALONE)
	if (lws_fi(&h->fic, "sspc_fake_rxparse_disconnect_me"))
		return LWSSSSRET_DISCONNECT_ME;

	if (lws_fi(&h->fic, "sspc_fake_rxparse_destroy_me"))
		return LWSSSSRET_DESTROY_ME;
#endif

	return lws_sspc_deserialize_parse(h, in, len, (lws_ss_handle_t **)m);
}

lws_ss_state_return_t
lws_sspc_txp_tx(lws_sspc_handle_t *h, size_t metadata_limit)
{
	uint8_t *pkt = NULL, *p = NULL, *end = NULL;
	void *m = (void *)((uint8_t *)(h + 1));
	lws_ss_state_return_t r;
	uint8_t _s[64 + LWS_PRE], *s = _s + LWS_PRE, *cp = s;
	size_t txl, len;
	lws_usec_t us;
	int flags;

	/*
	 * Management of ss timeout can happen any time and doesn't
	 * depend on wsi existence or state
	 */

	if (h->pending_timeout_update) {
		cp = s;
		*s = LWSSS_SER_TXPRE_TIMEOUT_UPDATE;
		*(s + 1) = 0;
		*(s + 2) = 4;
		/*
		 *          0: use policy timeout value
		 * 0xffffffff: cancel the timeout
		 */
		lws_ser_wu32be(s + 3, h->timeout_ms);

		/* in case anything else to write */
		h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);
		h->pending_timeout_update = 0;
		txl = 7;

		goto do_write;
	}

	*(s + 1) = 0;

	/*
	 * This is the state of the link that connects us to the onward
	 * proxy
	 */
	switch (h->state) {
	case LPCSCLI_SENDING_INITIAL_TX:
		/*
		 * We are negotating the opening of a particular
		 * streamtype
		 */
		// lwsl_sspc_notice(h, "LPCSCLI_SENDING_INITIAL_TX");
		txl = strlen(h->ssi.streamtype) + 1 + 4 + 4;

		cp = s;
		*s = LWSSS_SER_TXPRE_STREAMTYPE;
		lws_ser_wu16be(s + 1, (uint16_t)txl);
		/* SSSv1: add protocol version byte (initially 1) */
		*(s + 3) = (uint8_t)LWS_SSS_CLIENT_PROTOCOL_VERSION;
#if defined(WIN32) || defined(LWS_PLAT_BAREMETAL)
		lws_ser_wu32be(s + 4, (uint32_t)0);
#else
		lws_ser_wu32be(s + 4, (uint32_t)getpid());
#endif
		lws_ser_wu32be(s + 8, (uint32_t)h->txc.peer_tx_cr_est);
		lws_strncpy((char *)(s + 12), h->ssi.streamtype,
				(sizeof(_s) - LWS_PRE) - 12);
		txl += 3;
		h->state = LPCSCLI_WAITING_CREATE_RESULT;
		goto do_write;

	case LPCSCLI_LOCAL_CONNECTED:

		// lwsl_sspc_notice(h, "LPCSCLI_LOCAL_CONNECTED");

		/*
		 * Do we need to prioritize sending any metadata
		 * changes?
		 */

		if (h->metadata_owner.count) {
			lws_sspc_metadata_t *md = lws_container_of(
				lws_dll2_get_tail(&h->metadata_owner),
				lws_sspc_metadata_t, list);
			size_t n;

			pkt = lws_malloc(metadata_limit + LWS_PRE, __func__);
			if (!pkt)
				goto hangup;
			cp = p = pkt + LWS_PRE;
			end = p + metadata_limit;

			n = lws_sspc_serialize_metadata(h, md, p, end);
			if (!n)
				goto metadata_hangup;

			txl = (size_t)n;

			lwsl_sspc_debug(h, "(local_conn) metadata");

			goto req_write_and_issue;
		}

		if (h->pending_writeable_len) {
			lwsl_sspc_debug(h, "(local_conn) PAYLOAD_LENGTH_HINT %u",
				   (unsigned int)h->writeable_len);
			cp = s;
			*s = LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT;
			lws_ser_wu16be(s + 1, 4);
			lws_ser_wu32be(s + 3, (uint32_t)h->writeable_len);
			h->pending_writeable_len = 0;
			txl = 7;
			goto req_write_and_issue;
		}

		if (h->conn_req_state >= LWSSSPC_ONW_ONGOING) {
			lwsl_sspc_info(h, "conn_req_state %d",
					h->conn_req_state);
			break;
		}

		lwsl_sspc_info(h, "(local_conn) onward connect");

		h->conn_req_state = LWSSSPC_ONW_ONGOING;

		cp = s;
		*s = LWSSS_SER_TXPRE_ONWARD_CONNECT;
		*(s + 1) = 0;
		*(s + 2) = 0;
		txl = 3;

		goto do_write;

	case LPCSCLI_OPERATIONAL:

		/*
		 *
		 * - Do we need to prioritize sending any metadata
		 *   changes?  (includes txcr updates)
		 *
		 * - Do we need to forward a hint about the payload
		 *   length?
		 */

		pkt = lws_malloc(metadata_limit + LWS_PRE, __func__);
		if (!pkt)
			goto hangup;
		cp = p = pkt + LWS_PRE;
		end = p + metadata_limit;

		if (h->metadata_owner.count) {
			lws_sspc_metadata_t *md = lws_container_of(
				lws_dll2_get_tail(&h->metadata_owner),
				lws_sspc_metadata_t, list);

			txl = lws_sspc_serialize_metadata(h, md, p, end);
			if (!txl)
				goto metadata_hangup;

			goto req_write_and_issue;
		}

		if (h->pending_writeable_len) {
			lwsl_sspc_info(h, "PAYLOAD_LENGTH_HINT %u",
				  (unsigned int)h->writeable_len);
			cp = s;
			*s = LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT;
			lws_ser_wu16be(s + 1, 4);
			lws_ser_wu32be(s + 3, (uint32_t)h->writeable_len);
			h->pending_writeable_len = 0;
			txl = 7;
			goto req_write_and_issue;
		}

		/* we can't write anything if we don't have credit */
		if (!h->ignore_txc && h->txc.tx_cr <= 0)
			lwsl_sspc_info(h, "WRITEABLE / OPERATIONAL:"
				          " lack credit (%d)",
				          (int)h->txc.tx_cr);

		len = metadata_limit - LWS_PRE - 19;
		flags = 0;
		if (!h->ssi.tx) {
			txl = 0;
			goto do_write_nz;
		}

		r = h->ssi.tx(m, h->ord++, pkt + LWS_PRE + 19, &len, &flags);
		switch (r) {
		case LWSSSSRET_TX_DONT_SEND:
			txl = 0;
			goto do_write_nz;

		case LWSSSSRET_DISCONNECT_ME:
		case LWSSSSRET_DESTROY_ME:
			lwsl_sspc_warn(h, "sspc tx DISCONNECT/DESTROY TBD");
			break;
		default:
			break;
		}

		h->txc.tx_cr = h->txc.tx_cr - (int)len;

		cp = p;
		txl = len + 19;

		us = lws_now_usecs();
		p[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
		lws_ser_wu16be(&p[1], (uint16_t)(len + 19 - 3));
		lws_ser_wu32be(&p[3], (uint32_t)flags);
		/* time spent here waiting to send this */
		lws_ser_wu32be(&p[7], (uint32_t)(us - h->us_earliest_write_req));
		/* ust that the client write happened */
		lws_ser_wu64be(&p[11], (uint64_t)us);
		h->us_earliest_write_req = 0;

		if (flags & LWSSS_FLAG_EOM)
			if (h->rsidx + 1 < (int)LWS_ARRAY_SIZE(h->rideshare_ofs) &&
			    h->rideshare_ofs[h->rsidx + 1])
				h->rsidx++;

		goto do_write;

	default:
		break;
	}

	return LWSSSSRET_OK;

req_write_and_issue:
	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

do_write_nz:
	if (!txl) {
		lws_free(pkt);

		return LWSSSSRET_OK;
	}
do_write:
	if (
#if !defined(STANDALONE)
			!lws_fi(&h->fic, "sspc_link_write_fail") &&
#endif
	    !h->txp_path.ops_onw->_write(h->txp_path.priv_onw, cp, txl)) {
		if (pkt)
			lws_free(pkt);
		return LWSSSSRET_OK;
	}

	goto hangup;

metadata_hangup:
	lwsl_sspc_err(h, "metadata too large");

hangup:
	lws_free(pkt);
	lwsl_sspc_warn(h, "hangup");

	/* hang up on the proxy link */
	return LWSSSSRET_DISCONNECT_ME;
}

void
lws_sspc_txp_lost_coherence(lws_transport_priv_t txp_priv)
{
	lws_sspc_handle_t *h = (lws_sspc_handle_t *)txp_priv;

	lwsl_sspc_warn(h, "Lost Coherence");

	h->conn_req_state = LWSSSPC_ONW_NONE;

	/* pass thru to lower layer, eg, mux */

	h->txp_path.ops_onw->lost_coherence(h->txp_path.priv_onw);
}

/*
 * The actual client transports bind to this transport ops for "inside sspc".
 * It's like this so we can transparently interpose the mux.
 *
 * Only the apis the transport needs to call on the inside need timplementing
 * for this
 */

const lws_transport_client_ops_t lws_txp_inside_sspc = {
	.name				= "txp_inside_sspc",
	.event_connect_disposition	= lws_sspc_txp_connect_disposition,
	.event_read			= lws_sspc_txp_rx_from_proxy,
	.event_can_write		= lws_sspc_txp_tx,
	.event_closed			= lws_sspc_txp_event_closed,
	.lost_coherence			= lws_sspc_txp_lost_coherence,
};
