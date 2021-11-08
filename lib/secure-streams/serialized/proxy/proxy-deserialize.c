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
 * Serialized Secure Streams deserializer for Proxy side
 */

#include <private-lib-core.h>

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

	*len = (size_t)(lws_ser_ru16be(&p[1]) - (23 - 3));
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

	*flags = (int)lws_ser_ru32be(&p[3]);

	lws_dsh_free((void **)&p);

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
lws_ss_proxy_deserialize_parse(struct lws_ss_serialization_parser *par,
			       struct lws_context *context,
			       struct lws_dsh *dsh, const uint8_t *cp,
			       size_t len, lws_ss_conn_states_t *state,
			       void *parconn, lws_ss_handle_t **pss,
			       lws_ss_info_t *ssi)
{
	lws_ss_state_return_t r;
	lws_ss_metadata_t *pm;
	uint8_t pre[23];
	uint32_t flags;
	lws_usec_t us;
	uint8_t *p;
	int n;

	while (len--) {

		switch (par->ps) {
		case RPAR_TYPE:
			par->type = *cp++;
			par->ps++;
			break;

		case RPAR_LEN_MSB: /* this is remaining frame length */
			par->rem = (uint16_t)((*cp++) << 8);
			par->ps++;
			break;

		case RPAR_LEN_LSB:
			par->rem = (uint16_t)(par->rem | *cp++);
			switch (par->type) {

			/* event loop side */

			case LWSSS_SER_TXPRE_TX_PAYLOAD:

				if (*state != LPCSPROX_OPERATIONAL)
					goto hangup;

				par->ps = RPAR_FLAG_B3;
				break;

			case LWSSS_SER_TXPRE_DESTROYING:

				par->ps = RPAR_TYPE;
				lwsl_cx_notice(context, "DESTROYING");
				goto hangup;

			case LWSSS_SER_TXPRE_ONWARD_CONNECT:


				if (*state != LPCSPROX_OPERATIONAL)
					goto hangup;

				par->ps = RPAR_TYPE;
				lwsl_cx_notice(context, "ONWARD_CONNECT");

				/*
				 * Shrug it off if we are already connecting or
				 * connected
				 */

				if (!proxy_pss_to_ss_h(pss) ||
				    proxy_pss_to_ss_h(pss)->wsi)
					break;

				/*
				 * We're going to try to do the onward connect
				 */

				if ((proxy_pss_to_ss_h(pss) &&
				     lws_fi(&proxy_pss_to_ss_h(pss)->fic,
						 "ssproxy_onward_conn_fail")) ||
				    _lws_ss_client_connect(proxy_pss_to_ss_h(pss),
							   0, parconn) ==
							   LWSSSSRET_DESTROY_ME)
					goto hangup;
				break;

			case LWSSS_SER_TXPRE_STREAMTYPE:

				if (*state != LPCSPROX_WAIT_INITIAL_TX)
					goto hangup;
				if (par->rem < 1 + 4 + 1)
					goto hangup;
				par->ps = RPAR_INIT_PROVERS;
				break;

			case LWSSS_SER_TXPRE_METADATA:

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

				if (par->rem != 4)
					goto hangup;
				par->ps = RPAR_TIMEOUT0;
				par->ctr = 0;
				break;

			case LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT:

				if (par->rem != 4)
					goto hangup;
				par->ps = RPAR_PAYLEN0;
				par->ctr = 0;
				break;

			/* client side */

			case LWSSS_SER_RXPRE_RX_PAYLOAD:
			case LWSSS_SER_RXPRE_CREATE_RESULT:
			case LWSSS_SER_RXPRE_CONNSTATE:
			case LWSSS_SER_RXPRE_METADATA:
				goto hangup;

			case LWSSS_SER_RXPRE_TXCR_UPDATE:
				par->ctr = 0;
				par->ps = RPAR_RX_TXCR_UPDATE;
				break;

			case LWSSS_SER_RXPRE_PERF:
				par->ctr = 0;
				if (!par->rem)
					goto hangup;
				par->ps = RPAR_PERF;
				break;

			default:
				lwsl_cx_notice(context, "bad type 0x%x",
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

		case RPAR_PERF:
			n = (int)len + 1;
			if (n > par->rem)
				n = par->rem;

			if (n) {
				cp += n;
				par->rem = (uint16_t)(par->rem -
						(uint16_t)(unsigned int)n);
				len = (len + 1) - (unsigned int)n;
			}
			if (!par->rem)
				par->ps = RPAR_TYPE;
			break;

		case RPAR_RIDESHARE:
			par->rideshare[par->ctr++] = (char)*cp++;
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

			{
				lws_ss_handle_t *hss;

				/*
				 * Proxy - we received some serialized tx from
				 * the client.
				 *
				 * The header for buffering private to the
				 * proxy is 23 bytes vs 19, so we can hold the
				 * current time when it was buffered
				 * additionally
				 */

				hss = proxy_pss_to_ss_h(pss);
				if (hss)
					lwsl_ss_info(hss, "C2P RX: len %d", (int)n);

				p = pre;
				pre[0] = LWSSS_SER_TXPRE_TX_PAYLOAD;
				lws_ser_wu16be(&p[1], (uint16_t)((unsigned int)n + 23 - 3));
				lws_ser_wu32be(&p[3], flags);
				/* us held at client before written */
				lws_ser_wu32be(&p[7], par->usd_phandling);
				/* us taken for transit to proxy */
				lws_ser_wu32be(&p[11], (uint32_t)(us -
						(lws_usec_t)par->ust_pwait));
				/* time used later to find proxy hold time */
				lws_ser_wu64be(&p[15], (uint64_t)us);

				if ((hss &&
				    lws_fi(&hss->fic, "ssproxy_dsh_c2p_pay_oom")) ||
				    lws_dsh_alloc_tail(dsh, KIND_C_TO_P, pre,
						       23, cp, (unsigned int)n)) {
					lwsl_ss_err(hss, "unable to alloc in dsh 3");

					return LWSSSSRET_DISCONNECT_ME;
				}

				lwsl_notice("%s: dsh c2p %d, p2c %d\n", __func__,
					    (int)lws_dsh_get_size(dsh, KIND_C_TO_P),
					    (int)lws_dsh_get_size(dsh, 1));

				if (hss)
					_lws_ss_request_tx(hss);
			}

			if (n) {
				cp += n;
				par->rem = (uint16_t)(par->rem -
						     (uint16_t)(unsigned int)n);
				len = (len + 1) - (unsigned int)n;
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
			goto hangup;

		case RPAR_INIT_PROVERS:
			/* Protocol version byte for this connection */
			par->protocol_version = *cp++;

			/*
			 * So we have to know what versions of the serialization
			 * protocol we can support at the proxy side, and
			 * reject anythng we don't know how to deal with
			 * noisily in the logs.
			 */

			if (par->protocol_version != 1) {
				lwsl_err("%s: Rejecting client with "
					 "unsupported SSv%d protocol\n",
					 __func__, par->protocol_version);

				goto hangup;
			}

			if (!--par->rem)
				goto hangup;
			par->ctr = 0;
			par->ps = RPAR_INIT_PID;
			break;


		case RPAR_INIT_PID:
			if (!--par->rem)
				goto hangup;

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4)
				break;

			par->client_pid = (uint32_t)par->temp32;
			par->ctr = 0;
			par->ps = RPAR_INITTXC0;
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
				_lws_ss_request_tx(proxy_pss_to_ss_h(pss));
			} else
#endif
				lwsl_info("%s: dropping TXCR\n", __func__);

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
						par->temp32 = (int)
						   proxy_pss_to_ss_h(pss)->
							   policy->timeout_ms;

					lwsl_notice("%s: set ss timeout for +%ums\n",
						    __func__, par->temp32);

					lws_ss_start_timeout(
						proxy_pss_to_ss_h(pss),
						     (unsigned int)par->temp32);
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

			par->ps = RPAR_TYPE;

			if (proxy_pss_to_ss_h(pss)) {
				r = lws_ss_request_tx_len(proxy_pss_to_ss_h(pss),
							(unsigned long)par->temp32);
				if (r == LWSSSSRET_DESTROY_ME)
					goto hangup;
			}
			break;

		case RPAR_METADATA_NAMELEN:
			/* both client and proxy */
			if (!--par->rem)
				goto hangup;
			par->slen = *cp++;
			if (par->slen >= sizeof(par->metadata_name) - 1)
				goto hangup;
			par->ctr = 0;
			par->ps++;
			break;

		case RPAR_METADATA_NAME:
			/* both client and proxy */
			if (!--par->rem)
				goto hangup;
			par->metadata_name[par->ctr++] = (char)*cp++;
			if (par->ctr != par->slen)
				break;
			par->metadata_name[par->ctr] = '\0';
			par->ps = RPAR_METADATA_VALUE;

			/* proxy side is receiving it */

			if (!proxy_pss_to_ss_h(pss))
				goto hangup;

			if (!proxy_pss_to_ss_h(pss)->policy) {
				lwsl_err("%s: null policy\n", __func__);
				goto hangup;
			}

			/*
			 * This is the policy's metadata list for the given
			 * name
			 */
			pm = lws_ss_policy_metadata(
					proxy_pss_to_ss_h(pss)->policy,
					par->metadata_name);
			if (!pm) {
				lwsl_err("%s: metadata %s not in proxy policy\n",
					 __func__, par->metadata_name);

				goto hangup;
			}

			par->ssmd = lws_ss_get_handle_metadata(
					proxy_pss_to_ss_h(pss),
					par->metadata_name);

			if (par->ssmd) {

				if (par->ssmd->value_on_lws_heap)
					lws_free_set_NULL(par->ssmd->value__may_own_heap);
				par->ssmd->value_on_lws_heap = 0;

				if (proxy_pss_to_ss_h(pss) &&
				    lws_fi(&proxy_pss_to_ss_h(pss)->fic, "ssproxy_rx_metadata_oom"))
					par->ssmd->value__may_own_heap = NULL;
				else
					par->ssmd->value__may_own_heap =
						lws_malloc((unsigned int)par->rem + 1, "metadata");

				if (!par->ssmd->value__may_own_heap) {
					lwsl_err("%s: OOM mdv\n", __func__);
					goto hangup;
				}
				par->ssmd->length = par->rem;
				((uint8_t *)par->ssmd->value__may_own_heap)[par->rem] = '\0';
				/* mark it as needing cleanup */
				par->ssmd->value_on_lws_heap = 1;
			}
			par->ctr = 0;
			break;

		case RPAR_METADATA_VALUE:
			/* both client and proxy */

			if (!par->ssmd) {
				/* we don't recognize the name */

				cp++;

				if (--par->rem)
					break;

				par->ps = RPAR_TYPE;
				break;
			}

			((uint8_t *)(par->ssmd->value__may_own_heap))[par->ctr++] = *cp++;

			if (--par->rem)
				break;

			/* we think we got all the value */

			lwsl_ss_info(proxy_pss_to_ss_h(pss),
				     "RPAR_METADATA_VALUE for %s (len %d)",
				     par->ssmd->name,
				     (int)par->ssmd->length);
			lwsl_hexdump_ss_info(proxy_pss_to_ss_h(pss),
					par->ssmd->value__may_own_heap,
					par->ssmd->length);

			par->ps = RPAR_TYPE;
			break;

		case RPAR_STREAMTYPE:

			/* only the proxy can get these */

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

			par->streamtype[par->ctr++] = (char)*cp++;
			if (--par->rem)
				break;

			par->ps = RPAR_TYPE;
			par->streamtype[par->ctr] = '\0';
			lwsl_info("%s: proxy ss '%s', sssv%d, txcr %d\n",
				    __func__, par->streamtype,
				    par->protocol_version, par->txcr_out);

			ssi->streamtype = par->streamtype;
			if (par->txcr_out) // !!!
				ssi->manual_initial_tx_credit = par->txcr_out;

			/*
			 * Even for a synthetic SS proxing action like _lws_smd,
			 * we create an actual SS in the proxy representing the
			 * connection
			 */

			ssi->flags |= LWSSSINFLAGS_PROXIED;
			ssi->sss_protocol_version = par->protocol_version;
			ssi->client_pid = par->client_pid;

			if (lws_ss_create(context, 0, ssi, parconn, pss,
					  NULL, NULL)) {
				/*
				 * We're unable to create the onward secure
				 * stream he asked for... schedule a chance to
				 * inform him
				 */
				lwsl_err("%s: create '%s' fail\n", __func__,
					 par->streamtype);
				*state = LPCSPROX_REPORTING_FAIL;
				break;
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
		case RPAR_RESULT_CREATION_RIDESHARE:
		case RPAR_RESULT_CREATION_DSH:
		case RPAR_STATEINDEX:
		case RPAR_ORD3:
		case RPAR_ORD2:
		case RPAR_ORD1:
		case RPAR_ORD0:
			goto hangup;

		default:
			goto hangup;
		}
	}

	return LWSSSSRET_OK;

hangup:

	lwsl_cx_notice(context, "hangup");

	return LWSSSSRET_DISCONNECT_ME;
}
