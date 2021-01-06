/*
 * lws-minimal-secure-streams-client
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 *
 * This client does not perform any INET networking... instead it opens a unix
 * domain socket on a proxy that is listening for it, and that creates the
 * actual secure stream connection.
 *
 * We are able to use the usual secure streams api in the client process, with
 * payloads and connection state information proxied over the unix domain
 * socket and fulfilled in the proxy process.
 *
 * The public client helper pieces are built as part of lws
 */
#include <private-lib-core.h>

lws_ss_state_return_t
lws_sspc_event_helper(lws_sspc_handle_t *h, lws_ss_constate_t cs,
		      lws_ss_tx_ordinal_t flags)
{
	if (!h)
		return LWSSSSRET_OK;

	if (lws_ss_check_next_state(&h->prev_ss_state, cs))
		return LWSSSSRET_DESTROY_ME;

	if (!h->ssi.state)
		return LWSSSSRET_OK;

	return h->ssi.state((void *)((uint8_t *)&h[1]), NULL, cs, flags);
}

static void
lws_sspc_sul_retry_cb(lws_sorted_usec_list_t *sul)
{
	lws_sspc_handle_t *h = lws_container_of(sul, lws_sspc_handle_t, sul_retry);
	static struct lws_client_connect_info i;

	/*
	 * We may have started up before the system proxy, so be prepared with
	 * a sul to retry at 1Hz
	 */

	memset(&i, 0, sizeof i);
	i.context = h->context;
	if (h->context->ss_proxy_port) { /* tcp */
		i.address = h->context->ss_proxy_address;
		i.port = h->context->ss_proxy_port;
		i.iface = h->context->ss_proxy_bind;
	} else {
		if (h->context->ss_proxy_bind)
			i.address = h->context->ss_proxy_bind;
		else
#if defined(__linux__)
			i.address = "+@proxy.ss.lws";
#else
			i.address = "+/tmp/proxy.ss.lws";
#endif
	}
	i.host = i.address;
	i.origin = i.address;
	i.method = "RAW";
	i.protocol = lws_sspc_protocols[0].name;
	i.local_protocol_name = lws_sspc_protocols[0].name;
	i.path = "";
	i.pwsi = &h->cwsi;
	i.opaque_user_data = (void *)h;
	i.ssl_connection = LCCSCF_SECSTREAM_PROXY_LINK;

	lws_metrics_caliper_bind(h->cal_txn, h->context->mt_ss_cliprox_conn);

	/* this wsi is the link to the proxy */

	if (!lws_client_connect_via_info(&i)) {

		lws_metrics_caliper_report(h->cal_txn, METRES_NOGO);

		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);

		return;
	}

	lwsl_notice("%s: %s\n", __func__, h->cwsi->lc.gutag);
}

static int
lws_sspc_serialize_metadata(lws_sspc_metadata_t *md, uint8_t *p, uint8_t *end)
{
	int n, txc;

	if (md->name[0] == '\0') {

		lwsl_info("%s: sending tx credit update %d\n", __func__,
				md->tx_cr_adjust);

		p[0] = LWSSS_SER_TXPRE_TXCR_UPDATE;
		lws_ser_wu16be(&p[1], 4);
		lws_ser_wu32be(&p[3], (uint32_t)md->tx_cr_adjust);

		n = 7;

	} else {

		lwsl_info("%s: sending metadata\n", __func__);

		p[0] = LWSSS_SER_TXPRE_METADATA;
		txc = (int)strlen(md->name);
		n = txc + 1 + (int)md->len;
		if (n > 0xffff)
			/* we can't serialize this metadata in 16b length */
			return -1;
		if (n > lws_ptr_diff(end, &p[4]))
			/* we don't have space for this metadata */
			return -1;
		lws_ser_wu16be(&p[1], (uint16_t)n);
		p[3] = (uint8_t)txc;
		memcpy(&p[4], md->name, (unsigned int)txc);
		memcpy(&p[4 + txc], &md[1], md->len);
		n = 4 + txc + (int)md->len;
	}

	lws_dll2_remove(&md->list);
	lws_free(md);

	return n;
}

static int
callback_sspc_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	lws_sspc_handle_t *h = (lws_sspc_handle_t *)lws_get_opaque_user_data(wsi);
	uint8_t s[32], pkt[LWS_PRE + 2048], *p = pkt + LWS_PRE,
		*end = p + sizeof(pkt) - LWS_PRE;
	void *m = (void *)((uint8_t *)&h[1]);
	const uint8_t *cp;
	lws_usec_t us;
	int flags, n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_warn("%s: CONNECTION_ERROR\n", __func__);
		lws_metrics_caliper_report(h->cal_txn, METRES_NOGO);
		lws_set_opaque_user_data(wsi, NULL);
		h->cwsi = NULL;
		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);
		break;

        case LWS_CALLBACK_RAW_CONNECTED:
		if (!h)
			return -1;
		lwsl_info("%s: CONNECTED (%s)\n", __func__, h->ssi.streamtype);

		h->state = LPCSCLI_SENDING_INITIAL_TX;
		/*
		 * We create the dsh at the response to the initial tx, which
		 * will let us know the policy's max size for it... let's
		 * protect the connection with a promise to complete the
		 * SS serialization streamtype negotation within a short period,
		 * we will cancel this timeout when we have the proxy's ack
		 * of the streamtype serialization, eg, it exists in the proxy
		 * policy etc
		 */
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND, 3);
		lws_callback_on_writable(wsi);
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		/*
		 * our ss proxy Unix Domain socket has closed...
		 */
		lwsl_info("%s: LWS_CALLBACK_RAW_CLOSE: %s proxy conn down, sspc h %s\n",
			    __func__, lws_wsi_tag(wsi), lws_sspc_tag(h));
		if (h) {
			h->cwsi = NULL;
			/*
			 * schedule a reconnect in 1s
			 */
			lws_sul_schedule(h->context, 0, &h->sul_retry,
					 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);
		} else
			lwsl_info("%s: no sspc on client proxy link close\n", __func__);
		break;

	case LWS_CALLBACK_RAW_RX:
		/*
		 * ie, the proxy has sent us something
		 */
		lwsl_info("%s: RAW_RX: rx %d\n", __func__, (int)len);

		if (!h || !h->cwsi) {
			lwsl_info("%s: rx when client ss destroyed\n", __func__);

			return -1;
		}

		n = lws_ss_deserialize_parse(&h->parser, lws_get_context(wsi),
					     h->dsh, in, len, &h->state, h,
					     (lws_ss_handle_t **)m, &h->ssi, 1);
		switch (n) {
		case LWSSSSRET_OK:
			break;
		case LWSSSSRET_DISCONNECT_ME:
			return -1;
		case LWSSSSRET_DESTROY_ME:
			lws_set_opaque_user_data(wsi, NULL);
			lws_sspc_destroy(&h);
			return -1;
		}

		if (h->state == LPCSCLI_LOCAL_CONNECTED ||
		    h->state == LPCSCLI_ONWARD_CONNECT)
			lws_set_timeout(wsi, 0, 0);

		break;

	case LWS_CALLBACK_RAW_WRITEABLE:

		/*
		 * We can transmit something to the proxy...
		 */

		if (!h)
			break;

		lwsl_debug("%s: WRITEABLE %s, state %d\n", __func__,
			   wsi->lc.gutag, h->state);

		/*
		 * Management of ss timeout can happen any time and doesn't
		 * depend on wsi existence or state
		 */

		n = 0;
		cp = s;

		if (h->pending_timeout_update) {
			s[0] = LWSSS_SER_TXPRE_TIMEOUT_UPDATE;
			s[1] = 0;
			s[2] = 4;
			/*
			 *          0: use policy timeout value
			 * 0xffffffff: cancel the timeout
			 */
			lws_ser_wu32be(&s[3], h->timeout_ms);
			/* in case anything else to write */
			lws_callback_on_writable(h->cwsi);
			h->pending_timeout_update = 0;
			n = 7;
			goto do_write;
		}

		s[1] = 0;
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
			n = (int)strlen(h->ssi.streamtype) + 1 + 4 + 4;

			s[0] = LWSSS_SER_TXPRE_STREAMTYPE;
			lws_ser_wu16be(&s[1], (uint16_t)n);
			/* SSSv1: add protocol version byte (initially 1) */
			s[3] = (uint8_t)LWS_SSS_CLIENT_PROTOCOL_VERSION;
			lws_ser_wu32be(&s[4], (uint32_t)getpid());
			lws_ser_wu32be(&s[8], (uint32_t)h->txc.peer_tx_cr_est);
			//h->txcr_out = txc;
			lws_strncpy((char *)&s[12], h->ssi.streamtype, sizeof(s) - 12);
			n += 3;
			h->state = LPCSCLI_WAITING_CREATE_RESULT;

			break;

		case LPCSCLI_LOCAL_CONNECTED:

			// lwsl_notice("%s: LPCSCLI_LOCAL_CONNECTED\n", __func__);

			/*
			 * Do we need to prioritize sending any metadata
			 * changes?
			 */

			if (h->metadata_owner.count) {
				lws_sspc_metadata_t *md = lws_container_of(
					lws_dll2_get_tail(&h->metadata_owner),
					lws_sspc_metadata_t, list);

				cp = p;
				n = lws_sspc_serialize_metadata(md, p, end);
				if (n < 0)
					goto metadata_hangup;

				lwsl_debug("%s: (local_conn) metadata\n", __func__);

				goto req_write_and_issue;
			}

			if (h->pending_writeable_len) {
				lwsl_debug("%s: (local_conn) PAYLOAD_LENGTH_HINT %u\n",
					   __func__, (unsigned int)h->writeable_len);
				s[0] = LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT;
				lws_ser_wu16be(&s[1], 4);
				lws_ser_wu32be(&s[3], (uint32_t)h->writeable_len);
				h->pending_writeable_len = 0;
				n = 7;
				goto req_write_and_issue;
			}

			if (h->conn_req_state >= LWSSSPC_ONW_ONGOING) {
				lwsl_info("%s: conn_req_state %d\n", __func__,
						h->conn_req_state);
				break;
			}

			lwsl_info("%s: (local_conn) onward connect\n", __func__);

			h->conn_req_state = LWSSSPC_ONW_ONGOING;

			s[0] = LWSSS_SER_TXPRE_ONWARD_CONNECT;
			s[1] = 0;
			s[2] = 0;
			n = 3;
			break;

		case LPCSCLI_OPERATIONAL:

			/*
			 *
			 * - Do we need to prioritize sending any metadata
			 *   changes?  (includes txcr updates)
			 *
			 * - Do we need to forward a hint about the payload
			 *   length?
			 */

			if (h->metadata_owner.count) {
				lws_sspc_metadata_t *md = lws_container_of(
					lws_dll2_get_tail(&h->metadata_owner),
					lws_sspc_metadata_t, list);

				cp = p;
				n = lws_sspc_serialize_metadata(md, p, end);
				if (n < 0)
					goto metadata_hangup;

				goto req_write_and_issue;
			}

			if (h->pending_writeable_len) {
				lwsl_info("%s: PAYLOAD_LENGTH_HINT %u\n",
					   __func__, (unsigned int)h->writeable_len);
				s[0] = LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT;
				lws_ser_wu16be(&s[1], 4);
				lws_ser_wu32be(&s[3], (uint32_t)h->writeable_len);
				h->pending_writeable_len = 0;
				n = 7;
				goto req_write_and_issue;
			}

			/* we can't write anything if we don't have credit */
			if (!h->ignore_txc && h->txc.tx_cr <= 0) {
				lwsl_info("%s: WRITEABLE / OPERATIONAL:"
					    " lack credit (%d)\n", __func__,
					    h->txc.tx_cr);
				// break;
			}

			len = sizeof(pkt) - LWS_PRE - 19;
			flags = 0;
			if (!h->ssi.tx) {
				n = 0;
				goto do_write_nz;
			}

			n = h->ssi.tx(m, h->ord++, pkt + LWS_PRE + 19, &len,
				      &flags);
			switch (n) {
			case LWSSSSRET_TX_DONT_SEND:
				n = 0;
				goto do_write_nz;
	
			case LWSSSSRET_DISCONNECT_ME:
			case LWSSSSRET_DESTROY_ME:
				lwsl_notice("%s: sspc tx DISCONNECT/DESTROY unimplemented\n", __func__);
				break;
			default:
				break;
			}

			h->txc.tx_cr = h->txc.tx_cr - (int)len;

			cp = p;
			n = (int)(len + 19);
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

			break;
		default:
			break;
		}

do_write_nz:

		if (!n)
			break;

do_write:
		n = lws_write(wsi, (uint8_t *)cp, (unsigned int)n, LWS_WRITE_RAW);
		if (n < 0) {
			lwsl_notice("%s: WRITEABLE: %d\n", __func__, n);

			goto hangup;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

metadata_hangup:
	lwsl_err("%s: metadata too large\n", __func__);

hangup:
	lwsl_warn("hangup\n");
	/* hang up on him */
	return -1;

req_write_and_issue:
	/* in case anything else to write */
	lws_callback_on_writable(h->cwsi);
	goto do_write_nz;
}

const struct lws_protocols lws_sspc_protocols[] = {
	{
		"ssproxy-protocol",
		callback_sspc_client,
		0,
		2048, 2048, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

int
lws_sspc_create(struct lws_context *context, int tsi, const lws_ss_info_t *ssi,
	        void *opaque_user_data, lws_sspc_handle_t **ppss,
	        struct lws_sequencer *seq_owner, const char **ppayload_fmt)
{
	lws_sspc_handle_t *h;
	uint8_t *ua;
	char *p;

	/* allocate the handle (including ssi), the user alloc,
	 * and the streamname */

	h = malloc(sizeof(lws_sspc_handle_t) + ssi->user_alloc +
		   strlen(ssi->streamtype) + 1);
	if (!h)
		return 1;
	memset(h, 0, sizeof(*h));

	__lws_lc_tag(&context->lcg[LWSLCG_SSP_CLIENT], &h->lc, ssi->streamtype);

	memcpy(&h->ssi, ssi, sizeof(*ssi));
	ua = (uint8_t *)&h[1];
	memset(ua, 0, ssi->user_alloc);
	p = (char *)ua + ssi->user_alloc;
	memcpy(p, ssi->streamtype, strlen(ssi->streamtype) + 1);
	h->ssi.streamtype = (const char *)p;
	h->context = context;

	if (!ssi->manual_initial_tx_credit)
		h->txc.peer_tx_cr_est = 500000000;
	else
		h->txc.peer_tx_cr_est = ssi->manual_initial_tx_credit;

	if (!strcmp(ssi->streamtype, LWS_SMD_STREAMTYPENAME))
		h->ignore_txc = 1;

	lws_dll2_add_head(&h->client_list, &context->pt[tsi].ss_client_owner);

	/* fill in the things the real api does for the caller */

	*((void **)(ua + ssi->opaque_user_data_offset)) = opaque_user_data;
	*((void **)(ua + ssi->handle_offset)) = h;

	if (ppss)
		*ppss = h;

	/* try the actual connect */

	lws_sspc_sul_retry_cb(&h->sul_retry);

	return 0;
}

/* used on context destroy when iterating listed lws_ss on a pt */

int
lws_sspc_destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_sspc_handle_t *h = lws_container_of(d, lws_sspc_handle_t, client_list);

	lws_sspc_destroy(&h);

	return 0;
}

void
lws_sspc_rxmetadata_destroy(lws_sspc_handle_t *h)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&h->metadata_owner_rx)) {
		lws_sspc_metadata_t *md =
				lws_container_of(d, lws_sspc_metadata_t, list);

		lws_dll2_remove(&md->list);
		lws_free(md);

	} lws_end_foreach_dll_safe(d, d1);
}

void
lws_sspc_destroy(lws_sspc_handle_t **ph)
{
	lws_sspc_handle_t *h;

	lwsl_debug("%s\n", __func__);

	if (!*ph)
		return;

	h = *ph;

	if (h->destroying)
		return;

	h->destroying = 1;

	/* if this caliper is still dangling at destroy, we failed */
	lws_metrics_caliper_report(h->cal_txn, METRES_NOGO);
	if (h->ss_dangling_connected && h->ssi.state) {
		lws_sspc_event_helper(h, LWSSSCS_DISCONNECTED, 0);
		h->ss_dangling_connected = 0;
	}

	lws_sul_cancel(&h->sul_retry);
	lws_dll2_remove(&h->client_list);

	if (h->dsh)
		lws_dsh_destroy(&h->dsh);
	if (h->cwsi) {
		lws_set_opaque_user_data(h->cwsi, NULL);
		lws_wsi_close(h->cwsi, LWS_TO_KILL_ASYNC);
		h->cwsi = NULL;
	}

	/* clean out any pending metadata changes that didn't make it */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&(*ph)->metadata_owner)) {
		lws_sspc_metadata_t *md =
				lws_container_of(d, lws_sspc_metadata_t, list);

		lws_dll2_remove(&md->list);
		lws_free(md);

	} lws_end_foreach_dll_safe(d, d1);

	lws_sspc_rxmetadata_destroy(h);

	lws_sspc_event_helper(h, LWSSSCS_DESTROYING, 0);
	*ph = NULL;

	__lws_lc_untag(&h->lc);
	free(h);
}

lws_ss_state_return_t
lws_sspc_request_tx(lws_sspc_handle_t *h)
{
	if (!h || !h->cwsi)
		return LWSSSSRET_OK;

	if (!h->us_earliest_write_req)
		h->us_earliest_write_req = lws_now_usecs();

	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;

	lws_callback_on_writable(h->cwsi);

	return LWSSSSRET_OK;
}

/*
 * Currently we fulfil the writeable part locally by just enabling POLLOUT on
 * the UDS link, without serialization footprint, which is reasonable as far as
 * it goes.
 *
 * But for the ..._len() variant, the expected payload length hint we are being
 * told is something that must be serialized to the onward peer, since either
 * that guy or someone upstream of him is the guy who will compose the framing
 * with it that actually goes out.
 *
 * This information is needed at the upstream guy before we have sent any
 * payload, eg, for http POST, he has to prepare the content-length in the
 * headers, before any payload.  So we have to issue a serialization of the
 * length at this point.
 */

lws_ss_state_return_t
lws_sspc_request_tx_len(lws_sspc_handle_t *h, unsigned long len)
{
	/*
	 * for client conns, they cannot even complete creation of the handle
	 * without the onwared connection to the proxy, it's not legal to start
	 * using it until it's operation and has the onward connection (and the
	 * link has called CREATED state)
	 */

	if (!h)
		return LWSSSSRET_OK;

	lwsl_notice("%s: setting %s writeable_len %u\n", __func__, h->lc.gutag,
			(unsigned int)len);
	h->writeable_len = len;
	h->pending_writeable_len = 1;

	if (!h->us_earliest_write_req)
		h->us_earliest_write_req = lws_now_usecs();

	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;

	/*
	 * We're going to use this up with serializing h->writeable_len... that
	 * will request again.
	 */

	if (h->cwsi)
		lws_callback_on_writable(h->cwsi);

	return LWSSSSRET_OK;
}

int
lws_sspc_client_connect(lws_sspc_handle_t *h)
{
	if (!h || h->state == LPCSCLI_OPERATIONAL)
		return 0;

	assert(h->state == LPCSCLI_LOCAL_CONNECTED);
	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;
	if (h->cwsi)
		lws_callback_on_writable(h->cwsi);

	return 0;
}

struct lws_context *
lws_sspc_get_context(struct lws_sspc_handle *h)
{
	return h->context;
}

const char *
lws_sspc_rideshare(struct lws_sspc_handle *h)
{
	/*
	 * ...the serialized RX rideshare name if any...
	 */

	if (h->parser.rideshare[0]) {
		lwsl_info("%s: parser %s\n", __func__, h->parser.rideshare);
		return h->parser.rideshare;
	}

	/*
	 * The tx rideshare index
	 */

	if (h->rideshare_list[0]) {
		lwsl_info("%s: tx list %s\n", __func__,
			  &h->rideshare_list[h->rideshare_ofs[h->rsidx]]);
		return &h->rideshare_list[h->rideshare_ofs[h->rsidx]];
	}

	/*
	 * ... otherwise default to our stream type name
	 */

	lwsl_info("%s: def %s\n", __func__, h->ssi.streamtype);

	return h->ssi.streamtype;
}

static int
_lws_sspc_set_metadata(struct lws_sspc_handle *h, const char *name,
		       const void *value, size_t len, int tx_cr_adjust)
{
	lws_sspc_metadata_t *md;

	/*
	 * Are we replacing a pending metadata of the same name?  It's not
	 * efficient to do this but user code can do what it likes... let's
	 * optimize away the old one.
	 *
	 * Tx credit adjust always has name ""
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&h->metadata_owner)) {
		md = lws_container_of(d, lws_sspc_metadata_t, list);

		if (!strcmp(name, md->name)) {
			lws_dll2_remove(&md->list);
			lws_free(md);
			break;
		}

	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * We have to stash the metadata and pass it to the proxy
	 */

	md = lws_malloc(sizeof(*md) + len, "set metadata");
	if (!md) {
		lwsl_err("%s: OOM\n", __func__);

		return 1;
	}

	memset(md, 0, sizeof(*md));

	md->tx_cr_adjust = tx_cr_adjust;
	h->txc.peer_tx_cr_est += tx_cr_adjust;

	lws_strncpy(md->name, name, sizeof(md->name));
	md->len = len;
	if (len)
		memcpy(&md[1], value, len);

	lws_dll2_add_tail(&md->list, &h->metadata_owner);

	if (len) {
		lwsl_info("%s: set metadata %s\n", __func__, name);
		lwsl_hexdump_info(value, len);
	} else
		lwsl_info("%s: serializing tx cr adj %d\n", __func__,
			    (int)tx_cr_adjust);

	if (h->cwsi)
		lws_callback_on_writable(h->cwsi);

	return 0;
}

int
lws_sspc_set_metadata(struct lws_sspc_handle *h, const char *name,
		      const void *value, size_t len)
{
	return _lws_sspc_set_metadata(h, name, value, len, 0);
}

int
lws_sspc_get_metadata(struct lws_sspc_handle *h, const char *name,
		      const void **value, size_t *len)
{
	lws_sspc_metadata_t *md;

	/*
	 * client side does not have access to policy
	 * and any metadata are new to it each time,
	 * we allocate them, removing any existing with
	 * the same name first
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&h->metadata_owner_rx)) {
		md = lws_container_of(d,
			   lws_sspc_metadata_t, list);

		if (!strcmp(md->name, name)) {
			*len = md->len;
			*value = &md[1];

			return 0;
		}

	} lws_end_foreach_dll_safe(d, d1);

	return 1;
}

int
lws_sspc_add_peer_tx_credit(struct lws_sspc_handle *h, int32_t bump)
{
	lwsl_notice("%s: %d\n", __func__, bump);
	return _lws_sspc_set_metadata(h, "", NULL, 0, (int)bump);
}

int
lws_sspc_get_est_peer_tx_credit(struct lws_sspc_handle *h)
{
	return h->txc.peer_tx_cr_est;
}

void
lws_sspc_start_timeout(struct lws_sspc_handle *h, unsigned int timeout_ms)
{
	if (!h->cwsi)
		/* we can't fulfil it */
		return;
	h->timeout_ms = (uint32_t)timeout_ms;
	h->pending_timeout_update = 1;
	lws_callback_on_writable(h->cwsi);
}

void
lws_sspc_cancel_timeout(struct lws_sspc_handle *h)
{
	lws_sspc_start_timeout(h, (unsigned int)-1);
}

void *
lws_sspc_to_user_object(struct lws_sspc_handle *h)
{
	return (void *)&h[1];
}

void
lws_sspc_change_handlers(struct lws_sspc_handle *h,
	lws_ss_state_return_t (*rx)(void *userobj, const uint8_t *buf, size_t len, int flags),
	lws_ss_state_return_t (*tx)(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		  size_t *len, int *flags),
	lws_ss_state_return_t (*state)(void *userobj, void *h_src /* ss handle type */,
		     lws_ss_constate_t state, lws_ss_tx_ordinal_t ack))
{
	if (rx)
		h->ssi.rx = rx;
	if (tx)
		h->ssi.tx = tx;
	if (state)
		h->ssi.state = state;
}

const char *
lws_sspc_tag(struct lws_sspc_handle *h)
{
	if (!h)
		return "[null sspc]";
	return lws_lc_tag(&h->lc);
}
