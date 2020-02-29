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
			i.address = "+@proxy.ss.lws";
	}
	i.host = i.address;
	i.origin = i.address;
	i.method = "RAW";
	i.protocol = lws_sspc_protocols[0].name;
	i.local_protocol_name = lws_sspc_protocols[0].name;
	i.path = "";
	i.pwsi = &h->cwsi;
	i.opaque_user_data = (void *)h;

	if (!lws_client_connect_via_info(&i)) {
		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);

		return;
	}
}

static int
lws_sspc_serialize_metadata(lws_sspc_metadata_t *md, uint8_t *p)
{
	int n, txc;

	if (md->name[0] == '\0') {

		lwsl_info("%s: sending tx credit update %d\n", __func__,
				md->tx_cr_adjust);

		p[0] = LWSSS_SER_TXPRE_TXCR_UPDATE;
		lws_ser_wu16be(&p[1], 4);
		lws_ser_wu32be(&p[3], md->tx_cr_adjust);

		n = 7;

	} else {

		lwsl_info("%s: sending metadata\n", __func__);

		p[0] = LWSSS_SER_TXPRE_METADATA;
		txc = strlen(md->name);
		n = txc + 1 + md->len;
		lws_ser_wu16be(&p[1], n);
		p[3] = txc;
		memcpy(&p[4], md->name, txc);
		memcpy(&p[4 + txc], &md[1], md->len);
		n = 4 + txc + md->len;
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
	uint8_t s[32], pkt[LWS_PRE + 1400], *p = pkt + LWS_PRE;
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
		lws_set_opaque_user_data(wsi, NULL);
		h->cwsi = NULL;
		lws_sul_schedule(h->context, 0, &h->sul_retry,
				 lws_sspc_sul_retry_cb, LWS_US_PER_SEC);
		break;

        case LWS_CALLBACK_RAW_CONNECTED:
		if (!h)
			return -1;
		lwsl_info("%s: CONNECTED (%s)\n", __func__, h->ssi.streamtype);

		h->state = LPCS_SENDING_INITIAL_TX;
		h->dsh = lws_dsh_create(NULL, (LWS_PRE + LWS_SS_MTU) * 160, 1);
		if (!h->dsh)
			return -1;

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND, 3);
		lws_callback_on_writable(wsi);
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		/*
		 * our ss proxy Unix Domain socket has closed...
		 */
		lwsl_notice("%s: LWS_CALLBACK_RAW_CLOSE: proxy conn down\n", __func__);
		h->cwsi = NULL;
		//lws_sspc_destroy(&h);
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_info("%s: RAW_RX: rx %d\n", __func__, (int)len);

		if (!h || !h->cwsi) {
			lwsl_err("%s: rx with bad conn state\n", __func__);

			return -1;
		}

		if (lws_ss_deserialize_parse(&h->parser, lws_get_context(wsi),
					     h->dsh, in, len, &h->state, h,
					     (lws_ss_handle_t **)m, &h->ssi, 1))
			return -1;

		if (wsi && h->state == LPCS_LOCAL_CONNECTED)
			lws_set_timeout(wsi, 0, 0);

		break;

	case LWS_CALLBACK_RAW_WRITEABLE:

		/*
		 * We can transmit something to the proxy...
		 */

		if (!h)
			break;

		lwsl_info("%s: WRITEABLE %p: (%s) state %d\n", __func__, wsi,
				h->ssi.streamtype, h->state);

		n = 0;
		cp = s;
		s[1] = 0;
		switch (h->state) {
		case LPCS_SENDING_INITIAL_TX:
			n = strlen(h->ssi.streamtype) + 4;

			s[0] = LWSSS_SER_TXPRE_STREAMTYPE;
			lws_ser_wu16be(&s[1], n);
			lws_ser_wu32be(&s[3], h->txc.peer_tx_cr_est);
			//h->txcr_out = txc;
			lws_strncpy((char *)&s[7], h->ssi.streamtype, sizeof(s) - 7);
			n += 3;
			h->state = LPCS_WAITING_CREATE_RESULT;
			break;

		case LPCS_LOCAL_CONNECTED:
			if (!h->conn_req)
				break;

			/*
			 * Do we need to prioritize sending any metadata
			 * changes?
			 */

			if (h->metadata_owner.count) {
				lws_sspc_metadata_t *md = lws_container_of(
					lws_dll2_get_tail(&h->metadata_owner),
					lws_sspc_metadata_t, list);

				cp = p;
				n = lws_sspc_serialize_metadata(md, p);

				/* in case anything else to write */
				lws_callback_on_writable(h->cwsi);

				break;
			}


			h->conn_req = 0;
			s[0] = LWSSS_SER_TXPRE_ONWARD_CONNECT;
			s[1] = 0;
			s[2] = 0;
			n = 3;
			break;

		case LPCS_OPERATIONAL:

			/*
			 * Do we want to adjust the peer's ability to write
			 * to us?
			 */

			/*
			 * Do we need to prioritize sending any metadata
			 * changes?
			 */

			if (h->metadata_owner.count) {
				lws_sspc_metadata_t *md = lws_container_of(
					lws_dll2_get_tail(&h->metadata_owner),
					lws_sspc_metadata_t, list);

				cp = p;
				n = lws_sspc_serialize_metadata(md, p);

				/* in case anything else to write */
				lws_callback_on_writable(h->cwsi);

				break;
			}


			/* we can't write anything if we don't have credit */
			if (h->txc.tx_cr <= 0) {
				lwsl_notice("%s: WRITEABLE / OPERATIONAL:"
					    " lack credit (%d)\n", __func__,
					    h->txc.tx_cr);
				break;
			}

			len = sizeof(pkt) - LWS_PRE - 19;
			flags = 0;
			if (h->ssi.tx(m, h->ord++, pkt + LWS_PRE + 19, &len, &flags))
				break;

			h->txc.tx_cr -= len;

			cp = p;
			n = len + 19;
			us = lws_now_usecs();
			p[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
			lws_ser_wu16be(&p[1], len + 19 - 3);
			lws_ser_wu32be(&p[3], flags);
			/* time spent here waiting to send this */
			lws_ser_wu32be(&p[7], us - h->us_earliest_write_req);
			/* ust that the client write happened */
			lws_ser_wu64be(&p[11], us);
			h->us_earliest_write_req = 0;

			if (flags & LWSSS_FLAG_EOM)
				if (h->rsidx + 1 < (int)LWS_ARRAY_SIZE(h->rideshare_ofs) &&
				    h->rideshare_ofs[h->rsidx + 1])
					h->rsidx++;

			break;
		default:
			break;
		}

		if (!n)
			break;

		// lwsl_hexdump_notice(cp, n);

		n = lws_write(wsi, (uint8_t *)cp, n, LWS_WRITE_RAW);
		if (n < 0) {
			lwsl_notice("%s: WRITEABLE: %d\n", __func__, n);

			goto hangup;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

hangup:
	lwsl_warn("hangup\n");
	/* hang up on him */
	return -1;
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

	lwsl_notice("%s: streamtype %s\n", __func__, ssi->streamtype);

	/* allocate the handle (including ssi), the user alloc,
	 * and the streamname */

	h = malloc(sizeof(lws_sspc_handle_t) + ssi->user_alloc +
		   strlen(ssi->streamtype) + 1);
	memset(h, 0, sizeof(*h));
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
lws_sspc_destroy(lws_sspc_handle_t **ph)
{
	lws_sspc_handle_t *h;
	void *m;

	lwsl_debug("%s\n", __func__);

	if (!*ph)
		return;

	h = *ph;
	m = (void *)((uint8_t *)&h[1]);

	if (h->destroying)
		return;

	h->destroying = 1;

	lws_sul_schedule(h->context, 0, &h->sul_retry, NULL,
			 LWS_SET_TIMER_USEC_CANCEL);
	lws_dll2_remove(&h->client_list);

	if (h->dsh)
		lws_dsh_destroy(&h->dsh);
	if (h->cwsi) {
		struct lws *wsi = h->cwsi;
		h->cwsi = NULL;
		lws_set_timeout(wsi, 1, LWS_TO_KILL_SYNC);
	}

	/* clean out any pending metadata changes that didn't make it */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&(*ph)->metadata_owner)) {
		lws_sspc_metadata_t *md =
				lws_container_of(d, lws_sspc_metadata_t, list);

		lws_dll2_remove(&md->list);
		lws_free(md);

	} lws_end_foreach_dll_safe(d, d1);

	h->ssi.state(m, NULL, LWSSSCS_DESTROYING, 0);
	*ph = NULL;
	free(h);
}

void
lws_sspc_request_tx(lws_sspc_handle_t *h)
{
	if (!h || !h->cwsi)
		return;

	if (!h->us_earliest_write_req)
		h->us_earliest_write_req = lws_now_usecs();

	lws_callback_on_writable(h->cwsi);
}

int
lws_sspc_client_connect(lws_sspc_handle_t *h)
{
	if (!h || h->state == LPCS_OPERATIONAL)
		return 0;

	assert(h->state == LPCS_LOCAL_CONNECTED);
	h->conn_req = 1;
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
		       void *value, size_t len, int tx_cr_adjust)
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
		      void *value, size_t len)
{
	return _lws_sspc_set_metadata(h, name, value, len, 0);
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
