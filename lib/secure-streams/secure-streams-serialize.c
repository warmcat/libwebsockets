/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 * In the case Secure Streams protocol needs to pass through a buffer,
 * or a streamed connection, the protocol metadata must be serialized.  This
 * file provides internal apis to perform the serialization and deserialization
 * in and out of an lws_dsh fifo-type buffer.
 */

#include <private-lib-core.h>

typedef enum {
	RPAR_TYPE,
	RPAR_LEN_MSB,
	RPAR_LEN_LSB,

	RPAR_FLAG_B3,
	RPAR_FLAG_B2,
	RPAR_FLAG_B1,
	RPAR_FLAG_B0,

	RPAR_LATA3,
	RPAR_LATA2,
	RPAR_LATA1,
	RPAR_LATA0,

	RPAR_LATB7,
	RPAR_LATB6,
	RPAR_LATB5,
	RPAR_LATB4,
	RPAR_LATB3,
	RPAR_LATB2,
	RPAR_LATB1,
	RPAR_LATB0,

	RPAR_RIDESHARE_LEN,
	RPAR_RIDESHARE,

	RPAR_RESULT_CREATION_RIDESHARE,

	RPAR_METADATA_NAMELEN,
	RPAR_METADATA_NAME,
	RPAR_METADATA_VALUE,

	RPAR_PAYLOAD,

	RPAR_RX_TXCR_UPDATE,

	RPAR_STREAMTYPE,
	RPAR_INITTXC0,

	RPAR_TXCR0,

	RPAR_TIMEOUT0,

	RPAR_PAYLEN0,

	RPAR_RESULT_CREATION,

	RPAR_STATEINDEX,
	RPAR_ORD3,
	RPAR_ORD2,
	RPAR_ORD1,
	RPAR_ORD0,
} rx_parser_t;

#if defined(_DEBUG)
static const char *sn[] = {
	"unset",

	"LPCSPROX_WAIT_INITIAL_TX",
	"LPCSPROX_REPORTING_FAIL",
	"LPCSPROX_REPORTING_OK",
	"LPCSPROX_OPERATIONAL",
	"LPCSPROX_DESTROYED",

	"LPCSCLI_SENDING_INITIAL_TX",
	"LPCSCLI_WAITING_CREATE_RESULT",
	"LPCSCLI_LOCAL_CONNECTED",
	"LPCSCLI_ONWARD_CONNECT",
	"LPCSCLI_OPERATIONAL",
};
#endif

void
lws_ss_serialize_state_transition(lws_ss_conn_states_t *state, int new_state)
{
#if defined(_DEBUG)
	lwsl_info("%s: %s -> %s\n", __func__, sn[*state], sn[new_state]);
#endif
	*state = new_state;
}


/*
 * event loop received something and is queueing it for the foreign side of
 * the dsh to consume later as serialized rx
 */

int
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
		l = strlen(rsp);
		est += 1 + l;
	} else
		assert(!rsp);

	// lwsl_user("%s: len %d, flags: %d\n", __func__, (int)len, flags);
	// lwsl_hexdump_info(buf, len);

	pre[0] = LWSSS_SER_RXPRE_RX_PAYLOAD;
	lws_ser_wu16be(&pre[1], len + est - 3);
	lws_ser_wu32be(&pre[3], flags);
	lws_ser_wu32be(&pre[7], 0);	/* write will compute latency here... */
	lws_ser_wu64be(&pre[11], us);	/* ... and set this to the write time */

	/*
	 * If we are on a non-default rideshare, append the non-default name to
	 * the headers of the payload part, 1-byte length first
	 */

	if (flags & LWSSS_FLAG_RIDESHARE) {
		pre[19] = (uint8_t)l;
		memcpy(&pre[20], rsp, l);
	}

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, est, buf, len)) {
		lwsl_err("%s: unable to alloc in dsh 1\n", __func__);

		return 1;
	}

	return 0;
}

/*
 * event loop is consuming dsh-buffered, already-serialized tx from the
 * foreign side
 */

int
lws_ss_deserialize_tx_payload(struct lws_dsh *dsh, struct lws *wsi,
			      lws_ss_tx_ordinal_t ord, uint8_t *buf,
			      size_t *len, int *flags)
{
	uint8_t *p;
	size_t si;

	if (lws_dsh_get_head(dsh, KIND_C_TO_P, (void **)&p, &si)) {
		*len = 0;
		return 0;
	}

	/*
	 * The packet in the dsh has a proxying serialization header, process
	 * and strip it so we just forward the payload
	 */

	if (*len <= si - 23 || si < 23) {
		/*
		 * What comes out of the dsh needs to fit in the tx buffer...
		 * we have arrangements at the proxy rx of the client UDS to
		 * chop chunks larger than 1380 into seuqential lumps of 1380
		 */
		lwsl_err("%s: *len = %d, si = %d\n", __func__, (int)*len, (int)si);
		assert(0);
		return 1;
	}
	if (p[0] != LWSSS_SER_TXPRE_TX_PAYLOAD) {
		assert(0);
		return 1;
	}

	*len = lws_ser_ru16be(&p[1]) - (23 - 3);
	if (*len != si - 23) {
		/*
		 * We cannot accept any length that doesn't reflect the actual
		 * length of what came in from the dsh, either something nasty
		 * happened with truncation or we are being attacked
		 */
		assert(0);

		return 1;
	}

	memcpy(buf, p + 23, si - 23);

	*flags = lws_ser_ru32be(&p[3]);

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (wsi && wsi->a.context->detailed_latency_cb) {
		/*
		 * use the proxied latency information to compute the client
		 * and our delays, and apply to wsi.
		 *
		 * + 7 u32   us held at client before written
		 * +11 u32   us taken for transit to proxy
		 * +15 u64   ustime when proxy got packet from client
		 */
		lws_usec_t us = lws_now_usecs();

		wsi->detlat.acc_size = wsi->detlat.req_size = si - 23;
		wsi->detlat.latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] =
						lws_ser_ru32be(&p[7]);
		wsi->detlat.latencies[LAT_DUR_PROXY_CLIENT_WRITE_TO_PROXY_RX] =
						lws_ser_ru32be(&p[11]);
		wsi->detlat.latencies[LAT_DUR_PROXY_RX_TO_ONWARD_TX] =
						us - lws_ser_ru64be(&p[15]);

		wsi->detlat.latencies[LAT_DUR_USERCB] = 0;
	}
#endif

	// lwsl_user("%s: len %d, flags: %d\n", __func__, (int)*len, *flags);
	// lwsl_hexdump_info(buf, *len);

	lws_dsh_free((void **)&p);

	return 0;
}

/*
 * event loop side is issuing state, serialize and put it in the dbuf for
 * the foreign side to consume later
 */

int
lws_ss_serialize_state(struct lws_dsh *dsh, lws_ss_constate_t state,
		       lws_ss_tx_ordinal_t ack)
{
	uint8_t pre[12];
	int n = 4;

	lwsl_info("%s: %s, ord 0x%x\n", __func__, lws_ss_state_name(state),
		  (unsigned int)ack);

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

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, n + 4, NULL, 0)) {
		lwsl_err("%s: unable to alloc in dsh 2\n", __func__);

		return 1;
	}

	return 0;
}

/*
 * event loop side was told about remote peer tx credit window update, serialize
 * and put it in the dbuf for the foreign side to consume later
 */

int
lws_ss_serialize_txcr(struct lws_dsh *dsh, int txcr)
{
	uint8_t pre[7];

	lwsl_info("%s: %d\n", __func__, txcr);

	pre[0] = LWSSS_SER_RXPRE_TXCR_UPDATE;
	pre[1] = 0;
	pre[2] = 4;
	lws_ser_wu32be(&pre[3], txcr);

	if (lws_dsh_alloc_tail(dsh, KIND_SS_TO_P, pre, 7, NULL, 0)) {
		lwsl_err("%s: unable to alloc in dsh 2\n", __func__);

		return 1;
	}

	return 0;
}

/*
 * event loop side is consuming serialized data from the client via dsh, parse
 * it using a bytewise parser for the serialization header(s)...
 * it's possibly coalesced
 *
 * client: pss is pointing to the start of userdata.  We can use
 *         pss_to_sspc_h(_pss, _ssi) to convert that to a pointer to the sspc
 *         handle
 *
 * proxy: pss is pointing to &conn->ss, a pointer to the ss handle
 *
 * Returns one of
 *
 * 	LWSSSSRET_OK
 *	LWSSSSRET_DISCONNECT_ME
 *	LWSSSSRET_DESTROY_ME
 */

/* convert userdata ptr _pss to handle pointer, allowing for any layout in
 * userdata */
#define client_pss_to_sspc_h(_pss, _ssi) (*((lws_sspc_handle_t **) \
				     ((uint8_t *)_pss) + _ssi->handle_offset))
/* client pss to sspc userdata */
#define client_pss_to_userdata(_pss) ((void *)_pss)
/* proxy convert pss to ss handle */
#define proxy_pss_to_ss_h(_pss) (*_pss)

/* convert userdata ptr _pss to handle pointer, allowing for any layout in
 * userdata */
#define client_pss_to_sspc_h(_pss, _ssi) (*((lws_sspc_handle_t **) \
				     ((uint8_t *)_pss) + _ssi->handle_offset))
/* client pss to sspc userdata */
#define client_pss_to_userdata(_pss) ((void *)_pss)
/* proxy convert pss to ss handle */
#define proxy_pss_to_ss_h(_pss) (*_pss)

int
lws_ss_deserialize_parse(struct lws_ss_serialization_parser *par,
			 struct lws_context *context,
			 struct lws_dsh *dsh, const uint8_t *cp, size_t len,
			 lws_ss_conn_states_t *state, void *parconn,
			 lws_ss_handle_t **pss, lws_ss_info_t *ssi, char client)
{
	lws_ss_metadata_t *pm;
	lws_sspc_handle_t *h;
	uint8_t pre[23];
	lws_usec_t us;
	uint32_t flags;
	uint8_t *p;
	int n;

	while (len--) {
		switch (par->ps) {
		case RPAR_TYPE:
			par->type = *cp++;
			par->ps++;
			break;

		case RPAR_LEN_MSB: /* this is remaining frame length */
			par->rem = (*cp++) << 8;
			par->ps++;
			break;

		case RPAR_LEN_LSB:
			par->rem |= *cp++;
			switch (par->type) {

			/* event loop side */

			case LWSSS_SER_TXPRE_TX_PAYLOAD:
				if (client)
					goto hangup;
				if (*state != LPCSPROX_OPERATIONAL)
					goto hangup;

				par->ps = RPAR_FLAG_B3;
				break;

			case LWSSS_SER_TXPRE_DESTROYING:
				if (client)
					goto hangup;
				par->ps = RPAR_TYPE;
				lwsl_notice("%s: DESTROYING\n", __func__);
				goto hangup;

			case LWSSS_SER_TXPRE_ONWARD_CONNECT:
				if (client)
					goto hangup;
				if (*state != LPCSPROX_OPERATIONAL)
					goto hangup;
				par->ps = RPAR_TYPE;
				lwsl_notice("%s: LWSSS_SER_TXPRE_ONWARD_CONNECT\n", __func__);
				if (proxy_pss_to_ss_h(pss) &&
				    !proxy_pss_to_ss_h(pss)->wsi)
					_lws_ss_client_connect(
						proxy_pss_to_ss_h(pss), 0);
				break;

			case LWSSS_SER_TXPRE_STREAMTYPE:
				if (client)
					goto hangup;
				if (*state != LPCSPROX_WAIT_INITIAL_TX)
					goto hangup;
				if (par->rem < 4)
					goto hangup;
				par->ctr = 0;
				par->ps = RPAR_INITTXC0;
				break;

			case LWSSS_SER_TXPRE_METADATA:
				if (client)
					goto hangup;
				if (par->rem < 3)
					goto hangup;
				par->ctr = 0;
				par->ps = RPAR_METADATA_NAMELEN;
				break;

			case LWSSS_SER_TXPRE_TXCR_UPDATE:
				par->ps = RPAR_TXCR0;
				par->ctr = 0;
				break;

			case LWSSS_SER_TXPRE_TIMEOUT_UPDATE:
				if (client)
					goto hangup;
				if (par->rem != 4)
					goto hangup;
				par->ps = RPAR_TIMEOUT0;
				par->ctr = 0;
				break;

			case LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT:
				if (client)
					goto hangup;
				if (par->rem != 4)
					goto hangup;
				par->ps = RPAR_PAYLEN0;
				par->ctr = 0;
				break;

			/* client side */

			case LWSSS_SER_RXPRE_RX_PAYLOAD:
				if (!client)
					goto hangup;
				if (*state != LPCSCLI_OPERATIONAL &&
				    *state != LPCSCLI_LOCAL_CONNECTED)
					goto hangup;

				par->rideshare[0] = '\0';
				par->ps = RPAR_FLAG_B3;
				break;

			case LWSSS_SER_RXPRE_CREATE_RESULT:
				if (!client)
					goto hangup;
				if (*state != LPCSCLI_WAITING_CREATE_RESULT)
					goto hangup;

				if (par->rem < 1)
					goto hangup;

				par->ps = RPAR_RESULT_CREATION;
				break;

			case LWSSS_SER_RXPRE_CONNSTATE:
				if (!client)
					goto hangup;
				if (*state != LPCSCLI_LOCAL_CONNECTED &&
				    *state != LPCSCLI_OPERATIONAL)
					goto hangup;

				if (par->rem < 5 || par->rem > 8)
					goto hangup;

				par->ps = RPAR_STATEINDEX;
				par->ctr = 0;
				break;

			case LWSSS_SER_RXPRE_TXCR_UPDATE:
				par->ctr = 0;
				par->ps = RPAR_RX_TXCR_UPDATE;
				break;

			default:
				lwsl_notice("%s: bad type 0x%x\n", __func__,
					    par->type);
				goto hangup;
			}
			break;

			case RPAR_FLAG_B3:
			case RPAR_FLAG_B2:
			case RPAR_FLAG_B1:
			case RPAR_FLAG_B0:
				par->flags <<= 8;
				par->flags |= *cp++;
				par->ps++;
				if (!par->rem--)
					goto hangup;
				break;

			case RPAR_LATA3:
			case RPAR_LATA2:
			case RPAR_LATA1:
			case RPAR_LATA0:
				par->usd_phandling <<= 8;
				par->usd_phandling |= *cp++;
				par->ps++;
				if (!par->rem--)
					goto hangup;
				break;

			case RPAR_LATB7:
			case RPAR_LATB6:
			case RPAR_LATB5:
			case RPAR_LATB4:
			case RPAR_LATB3:
			case RPAR_LATB2:
			case RPAR_LATB1:
			case RPAR_LATB0:
				par->ust_pwait <<= 8;
				par->ust_pwait |= *cp++;
				par->ps++;
				par->frag1 = 1;
				if (!par->rem--)
					goto hangup;

				if (par->ps == RPAR_RIDESHARE_LEN &&
				    !(par->flags & LWSSS_FLAG_RIDESHARE))
					par->ps = RPAR_PAYLOAD;

				if (par->rem)
					break;

				/* fallthru - handle 0-length payload */

				if (!(par->flags & LWSSS_FLAG_RIDESHARE))
					goto payload_ff;
				goto hangup;

			/*
			 * Inbound rideshare info is provided on the RX packet
			 * itself
			 */

		case RPAR_RIDESHARE_LEN:
			par->slen = *cp++;
			par->ctr = 0;
			par->ps++;
			if (par->rem-- < par->slen)
				goto hangup;
			break;

		case RPAR_RIDESHARE:
			par->rideshare[par->ctr++] = *cp++;
			if (!par->rem--)
				goto hangup;
			if (par->ctr != par->slen)
				break;
			par->ps = RPAR_PAYLOAD;
			if (par->rem)
				break;

			/* fallthru - handle 0-length payload */

		case RPAR_PAYLOAD:
payload_ff:
			n = (int)len + 1;
			if (n > par->rem)
				n = par->rem;
			/*
			 * We get called with a serialized buffer of a size
			 * chosen by the client.  We can only create dsh entries
			 * with up to 1380 payload, to guarantee we can emit
			 * them on the onward connection atomically.
			 *
			 * If 1380 isn't enough to cover what was handed to us,
			 * we'll stop at 1380 and go around again and create
			 * more dsh entries for the rest, with their own
			 * headers.
			 */

			if (n > 1380)
				n = 1380;

			/*
			 * Since we're in the business of fragmenting client
			 * serialized payloads at 1380, we have to deal with
			 * refragmenting the SOM / EOM flags that covered the
			 * whole client serialized packet, so they apply to
			 * each dsh entry we split it into correctly
			 */

			flags = par->flags & LWSSS_FLAG_RELATED_START;
			if (par->frag1)
				/*
				 * Only set the first time we came to this
				 * state after deserialization of the header
				 */
				flags |= par->flags &
				    (LWSSS_FLAG_SOM | LWSSS_FLAG_POLL);

			if (par->rem == n)
				/*
				 * We are going to complete the advertised
				 * payload length from the client on this dsh,
				 * so give him the EOM type flags if any
				 */
				flags |= par->flags & (LWSSS_FLAG_EOM |
						LWSSS_FLAG_RELATED_END);

			par->frag1 = 0;
			us = lws_now_usecs();

			if (!client) {
				/*
				 * Proxy - we received some serialized tx from
				 * the client.
				 *
				 * The header for buffering private to the
				 * proxy is 23 bytes vs 19, so we can hold the
				 * current time when it was buffered
				 * additionally
				 */

				lwsl_info("%s: C2P RX: len %d\n", __func__,
						(int)n);

				p = pre;
				pre[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
				lws_ser_wu16be(&p[1], n + 23 - 3);
				lws_ser_wu32be(&p[3], flags);
				/* us held at client before written */
				lws_ser_wu32be(&p[7], par->usd_phandling);
				/* us taken for transit to proxy */
				lws_ser_wu32be(&p[11], us - par->ust_pwait);
				/* time used later to find proxy hold time */
				lws_ser_wu64be(&p[15], us);

				if (lws_dsh_alloc_tail(dsh, KIND_C_TO_P, pre,
						       23, cp, n)) {
					lwsl_err("%s: unable to alloc in dsh 3\n",
						 __func__);

					return LWSSSSRET_DISCONNECT_ME;
				}

				if (proxy_pss_to_ss_h(pss))
					lws_ss_request_tx(
						proxy_pss_to_ss_h(pss));
			} else {

				/*
				 * Client receives some RX from proxy
				 *
				 * Pass whatever payload we have to ss user
				 */

				lwsl_info("%s: P2C RX: len %d\n", __func__,
						(int)n);

				h = lws_container_of(par, lws_sspc_handle_t,
						     parser);
				h->txc.peer_tx_cr_est -= n;

				if (client_pss_to_sspc_h(pss, ssi))
					/* we still have an sspc handle */
					ssi->rx(client_pss_to_userdata(pss),
						(uint8_t *)cp, n, flags);

#if defined(LWS_WITH_DETAILED_LATENCY)
				if (lws_det_lat_active(context)) {
					lws_detlat_t d;

					d.type = LDLT_READ;
					d.acc_size = d.req_size = n;
					d.latencies[LAT_DUR_USERCB] =
							lws_now_usecs() - us;
					d.latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] =
							par->usd_phandling;
					d.latencies[LAT_DUR_PROXY_CLIENT_WRITE_TO_PROXY_RX] =
						us - par->ust_pwait;

					lws_det_lat_cb(context, &d);
				}
#endif
			}

			if (n) {
				cp += n;
				par->rem -= n;
				len = (len + 1) - n;
				/*
				 * if we didn't consume it all, we'll come
				 * around again and produce more dsh entries up
				 * to 1380 each until it is gone
				 */
			}
			if (!par->rem)
				par->ps = RPAR_TYPE;
			break;

		case RPAR_RX_TXCR_UPDATE:
			if (!--par->rem && par->ctr != 3)
				goto hangup;

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4)
				break;

			/*
			 * Proxy is telling us remote endpoint is allowing us
			 * par->temp32 more bytes tx credit to write to it
			 */

			h = lws_container_of(par, lws_sspc_handle_t, parser);
			h->txc.tx_cr += par->temp32;
			lwsl_info("%s: RX_PEER_TXCR: %d\n", __func__, par->temp32);
			lws_sspc_request_tx(h); /* in case something waiting */
			par->ctr = 0;
			par->ps = RPAR_TYPE;
			break;

		case RPAR_INITTXC0:
			if (!--par->rem)
				goto hangup;

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4)
				break;

			par->txcr_out = par->temp32;
			par->ctr = 0;
			par->ps = RPAR_STREAMTYPE;
			break;

		/*
		 * These are the client adjusting our / the remote peer ability
		 * to send back to him. He's sending a signed u32 BE
		 */

		case RPAR_TXCR0:

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4) {
				if (!--par->rem)
					goto hangup;
				break;
			}

			if (--par->rem)
				goto hangup;

			if (!client) {
				/*
				 * We're the proxy, being told by the client
				 * that it wants to allow more tx from the peer
				 * on the onward connection towards it.
				 */
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT)
				if (proxy_pss_to_ss_h(pss) &&
				    proxy_pss_to_ss_h(pss)->wsi) {
					lws_wsi_tx_credit(
						proxy_pss_to_ss_h(pss)->wsi,
							  LWSTXCR_PEER_TO_US,
							  par->temp32);
					lwsl_notice("%s: proxy RX_PEER_TXCR: +%d (est %d)\n",
						 __func__, par->temp32,
						 proxy_pss_to_ss_h(pss)->wsi->
							 txc.peer_tx_cr_est);
					lws_ss_request_tx(proxy_pss_to_ss_h(pss));
				} else
#endif
					lwsl_info("%s: dropping TXCR\n", __func__);
			} else {
				/*
				 * We're the client, being told by the proxy
				 * about tx credit being given to us from the
				 * remote peer, allowing the client to write to
				 * it.
				 */
				h = lws_container_of(par, lws_sspc_handle_t,
						     parser);
				h->txc.tx_cr += par->temp32;
				lwsl_info("%s: client RX_PEER_TXCR: %d\n",
							__func__, par->temp32);
				lws_sspc_request_tx(h); /* in case something waiting */
			}
			par->ps = RPAR_TYPE;
			break;

		case RPAR_TIMEOUT0:

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4) {
				if (!--par->rem)
					goto hangup;
				break;
			}

			if (--par->rem)
				goto hangup;

			/*
			 * Proxy...
			 *
			 * *pss may have gone away asynchronously inbetweentimes
			 */

			if (proxy_pss_to_ss_h(pss)) {

				if ((unsigned int)par->temp32 == 0xffffffff) {
					lwsl_notice("%s: cancel ss timeout\n",
							__func__);
					lws_ss_cancel_timeout(
						proxy_pss_to_ss_h(pss));
				} else {

					if (!par->temp32)
						par->temp32 =
						   proxy_pss_to_ss_h(pss)->
							   policy->timeout_ms;

					lwsl_notice("%s: set ss timeout for +%ums\n",
						__func__, par->temp32);

					lws_ss_start_timeout(
						proxy_pss_to_ss_h(pss),
								par->temp32);
				}
			}

			par->ps = RPAR_TYPE;
			break;

		case RPAR_PAYLEN0:
			/*
			 * It's the length from lws_ss_request_tx_len() being
			 * passed up to the proxy
			 */
			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4) {
				if (!--par->rem)
					goto hangup;
				break;
			}

			if (--par->rem)
				goto hangup;

			lwsl_notice("%s: set payload len %u\n", __func__,
				    par->temp32);

			if (proxy_pss_to_ss_h(pss))
				lws_ss_request_tx_len(proxy_pss_to_ss_h(pss),
							par->temp32);

			par->ps = RPAR_TYPE;
			break;

		case RPAR_METADATA_NAMELEN:
			if (!--par->rem)
				goto hangup;
			par->slen = *cp++;
			if (par->slen >= sizeof(par->metadata_name) - 1)
				goto hangup;
			par->ctr = 0;
			par->ps++;
			break;

		case RPAR_METADATA_NAME:
			if (!--par->rem)
				goto hangup;
			par->metadata_name[par->ctr++] = *cp++;
			if (par->ctr != par->slen)
				break;
			par->metadata_name[par->ctr] = '\0';
			par->ps = RPAR_METADATA_VALUE;

			/* only proxy side can receive these */

			if (!proxy_pss_to_ss_h(pss))
				goto hangup;

			/*
			 * This is the policy's metadata list for the given
			 * name
			 */
			pm = lws_ss_policy_metadata(proxy_pss_to_ss_h(pss)->policy,
						    par->metadata_name);
			if (!pm) {
				lwsl_err("%s: metadata %s not in proxy policy\n",
					 __func__, par->metadata_name);

				goto hangup;
			}

			par->ssmd = &proxy_pss_to_ss_h(pss)->metadata[pm->length];

			if (par->ssmd->value_on_lws_heap)
				lws_free_set_NULL(par->ssmd->value);
			par->ssmd->value_on_lws_heap = 0;

			par->ssmd->value = lws_malloc(par->rem + 1, "metadata");
			if (!par->ssmd->value) {
				lwsl_err("%s: OOM mdv\n", __func__);
				goto hangup;
			}
			par->ssmd->length = par->rem;
			/* mark it as needing cleanup */
			par->ssmd->value_on_lws_heap = 1;
			par->ctr = 0;
			break;

		case RPAR_METADATA_VALUE:
			((uint8_t *)(par->ssmd->value))[par->ctr++] = *cp++;
			if (--par->rem)
				break;

			/* we think we got all the value */
			lwsl_info("%s: RPAR_METADATA_VALUE for %s (len %d)\n",
				  __func__, par->ssmd->name,
				  (int)par->ssmd->length);
			lwsl_hexdump_info(par->ssmd->value, par->ssmd->length);
			par->ps = RPAR_TYPE;
			break;

		case RPAR_STREAMTYPE:

			/* only the proxy can get these */

			if (client)
				goto hangup;
			if (par->ctr == sizeof(par->streamtype) - 1)
				goto hangup;

			/*
			 * We can only expect to get this if we ourselves are
			 * in the state that we're waiting for it.  If it comes
			 * later it's a protocol error.
			 */

			if (*state != LPCSPROX_WAIT_INITIAL_TX)
				goto hangup;

			/*
			 * We're the proxy, creating an SS on behalf of a
			 * client
			 */

			par->streamtype[par->ctr++] = *cp++;
			if (--par->rem)
				break;

			par->ps = RPAR_TYPE;
			par->streamtype[par->ctr] = '\0';
			lwsl_notice("%s: creating proxied ss '%s', txcr %d\n",
				    __func__, par->streamtype, par->txcr_out);

			ssi->streamtype = par->streamtype;
			if (par->txcr_out) // !!!
				ssi->manual_initial_tx_credit = par->txcr_out;

			/*
			 * Even for a synthetic SS proxing action like _lws_smd,
			 * we create an actual SS in the proxy representing the
			 * connection
			 */

			ssi->flags |= LWSSSINFLAGS_PROXIED;
			if (lws_ss_create(context, 0, ssi, parconn, pss,
					  NULL, NULL)) {
				/*
				 * We're unable to create the onward secure
				 * stream he asked for... schedule a chance to
				 * inform him
				 */
				lwsl_err("%s: create '%s' fail\n",
					__func__, par->streamtype);
				*state = LPCSPROX_REPORTING_FAIL;
			} else {
				lwsl_debug("%s: create '%s' OK\n",
					__func__, par->streamtype);
				*state = LPCSPROX_REPORTING_OK;
			}

			if (*pss) {
				(*pss)->being_serialized = 1;
#if defined(LWS_WITH_SYS_SMD)
				if ((*pss)->policy != &pol_smd)
					/*
					 * In SMD case we overloaded the
					 * initial credit to be the class mask
					 */
#endif
				{
					lwsl_info("%s: Created SS initial credit %d\n",
						__func__, par->txcr_out);

					(*pss)->info.manual_initial_tx_credit = par->txcr_out;
				}
			}

			/* parent needs to schedule write on client conn */
			break;

		/* clientside states */

		case RPAR_RESULT_CREATION:
			if (*cp++) {
				lwsl_err("%s: stream creation failed\n",
					 __func__);
				goto hangup;
			}

			/*
			 * Client
			 */

			lws_ss_serialize_state_transition(state,
							  LPCSCLI_LOCAL_CONNECTED);
			h = lws_container_of(par, lws_sspc_handle_t, parser);

			/*
			 * This is telling us that the streamtype could be (and
			 * was) created at the proxy.  It's not telling us that
			 * the onward peer connection could be connected.
			 *
			 * We'll get a proxied state() coming later that informs
			 * us about the situation with that.
			 *
			 * However at this point, we should choose to inform
			 * the client that his stream was created... we will
			 * later get a proxied CREATING state from the peer
			 * but we should do it now and suppress the later one.
			 *
			 * The reason is he may set metadata in CREATING, and
			 * we will try to do writeables to sync the stream to
			 * master and ultimately bring up the onward connection now
			 * now we are in LOCAL_CONNECTED.  We need to do the
			 * CREATING now so we'll know the metadata to sync.
			 */

			h->creating_cb_done = 1;

			n = ssi->state(client_pss_to_userdata(pss),
						NULL, LWSSSCS_CREATING, 0);
			switch (n) {
			case LWSSSSRET_OK:
				break;
			case LWSSSSRET_DISCONNECT_ME:
				goto hangup;
			case LWSSSSRET_DESTROY_ME:
				return LWSSSSRET_DESTROY_ME;
			}

			if (h->cwsi)
				lws_callback_on_writable(h->cwsi);

			par->rsl_pos = 0;
			par->rsl_idx = 0;

			memset(&h->rideshare_ofs[0], 0, sizeof(h->rideshare_ofs[0]));
			h->rideshare_list[0] = '\0';
			h->rsidx = 0;

			if (!--par->rem)
				par->ps = RPAR_TYPE;
			else {
				par->ps = RPAR_RESULT_CREATION_RIDESHARE;
				if (par->rem >= sizeof(h->rideshare_list))
					goto hangup;
			}
			break;

		case RPAR_RESULT_CREATION_RIDESHARE:
			h = lws_container_of(par, lws_sspc_handle_t, parser);
			if (*cp == ',') {
				cp++;
				h->rideshare_list[par->rsl_pos++] = '\0';
				if (par->rsl_idx == LWS_ARRAY_SIZE(h->rideshare_ofs))
					goto hangup;
				h->rideshare_ofs[++par->rsl_idx] = par->rsl_pos;
			} else
				h->rideshare_list[par->rsl_pos++] = *cp++;
			if (!--par->rem)
				par->ps = RPAR_TYPE;
			break;

		case RPAR_STATEINDEX:
			par->ctr = (par->ctr << 8) | (*cp++);
			if (--par->rem == 4)
				par->ps = RPAR_ORD3;
			break;

		case RPAR_ORD3:
			par->flags = (*cp++) << 24;
			par->ps++;
			break;

		case RPAR_ORD2:
			par->flags |= (*cp++) << 16;
			par->ps++;
			break;

		case RPAR_ORD1:
			par->flags |= (*cp++) << 8;
			par->ps++;
			break;

		case RPAR_ORD0:
			par->flags |= *cp++;
			par->ps++;
			par->ps = RPAR_TYPE;

			/*
			 * Client received a proxied state change
			 */

			if (!client_pss_to_sspc_h(pss, ssi))
				/*
				 * Since we're being informed we need to have
				 * a stream to inform.  Assume whatever set this
				 * to NULL has started to close it.
				 */
				break;

			switch (par->ctr) {
			case LWSSSCS_DISCONNECTED:
			case LWSSSCS_UNREACHABLE:
			case LWSSSCS_AUTH_FAILED:
				lws_ss_serialize_state_transition(state,
						LPCSCLI_LOCAL_CONNECTED);
				client_pss_to_sspc_h(pss, ssi)->conn_req_state =
							LWSSSPC_ONW_NONE;
				break;
			case LWSSSCS_CONNECTED:
				lwsl_info("%s: CONNECTED %s\n", __func__,
					    ssi->streamtype);
				if (*state == LPCSCLI_OPERATIONAL)
					/*
					 * Don't allow to see connected more
					 * than once for one connection
					 */
					goto swallow;
				lws_ss_serialize_state_transition(state,
						LPCSCLI_OPERATIONAL);

				client_pss_to_sspc_h(pss, ssi)->conn_req_state =
						LWSSSPC_ONW_CONN;
				break;
			case LWSSSCS_TIMEOUT:
				break;
			default:
				break;
			}

			if (par->ctr < 0)
				goto hangup;

#if defined(_DEBUG)
			lwsl_info("%s: forwarding proxied state %s\n",
					__func__, lws_ss_state_name(par->ctr));
#endif

			if (par->ctr == LWSSSCS_CREATING) {
				if (h->creating_cb_done)
					/*
					 * We have told him he's CREATING when
					 * we heard we had linked up to the
					 * proxy, so suppress the remote
					 * CREATING so that he only sees it once
					 */
				break;

				h->creating_cb_done = 1;
			}

			n = ssi->state(client_pss_to_userdata(pss),
						NULL, par->ctr, par->flags);
			switch (n) {
			case LWSSSSRET_OK:
				break;
			case LWSSSSRET_DISCONNECT_ME:
				goto hangup;
			case LWSSSSRET_DESTROY_ME:
				return LWSSSSRET_DESTROY_ME;
			}

swallow:
			break;

		default:
			goto hangup;
		}
	}

	return LWSSSSRET_OK;

hangup:
	return LWSSSSRET_DISCONNECT_ME;
}
