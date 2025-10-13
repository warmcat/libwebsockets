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
 * Serialized Secure Streams deserializer for Client / SSPC side
 */

#include <private-lib-core.h>

#if defined(STANDALONE)

#define lws_context lws_context_standalone

#undef lws_malloc
#define lws_malloc(a, b) malloc(a)
#undef lws_free
#define lws_free(a) free(a)
#endif

#if defined(_DEBUG) && !defined(LWS_WITH_NO_LOGS)
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

static void
lws_ss_serialize_state_transition(lws_sspc_handle_t *h,
				  lws_ss_conn_states_t *state, int new_state)
{
#if defined(_DEBUG)
	lwsl_sspc_info(h, "%s -> %s", sn[*state], sn[new_state]);
#endif
	*state = (lws_ss_conn_states_t)new_state;
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

int
lws_sspc_deserialize_parse(lws_sspc_handle_t *hh, const uint8_t *cp, size_t len,
			   lws_ss_handle_t **pss)
{
	struct lws_ss_serialization_parser *par = &hh->parser;
	lws_ss_conn_states_t *state = &hh->state;
	lws_ss_info_t *ssi = &hh->ssi;
	lws_sspc_metadata_t *md;
	lws_sspc_handle_t *h;
	uint32_t flags;
	int n, r = 0;

//	lwsl_notice("%s: len %u, par->ps %d, par->rem %d\n", __func__, (unsigned int)len, (int)par->ps, (int)par->rem);

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
			case LWSSS_SER_TXPRE_STREAMTYPE:
			case LWSSS_SER_TXPRE_DESTROYING:
			case LWSSS_SER_TXPRE_ONWARD_CONNECT:
			case LWSSS_SER_TXPRE_METADATA:
			case LWSSS_SER_TXPRE_TIMEOUT_UPDATE:
			case LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT:
				lwsl_info("RPAR_LEN_LSB\n");
				goto hangup;

			case LWSSS_SER_TXPRE_TXCR_UPDATE:
				par->ps = RPAR_TXCR0;
				par->ctr = 0;
				break;

			/* client side */

			case LWSSS_SER_RXPRE_RX_PAYLOAD:

				if (*state != LPCSCLI_OPERATIONAL &&
				    *state != LPCSCLI_LOCAL_CONNECTED) {
					lwsl_info("LWSSS_SER_RXPRE_RX_PAYLOAD\n");
					goto hangup;
				}

				par->rideshare[0] = '\0';
				par->ps = RPAR_FLAG_B3;
				break;

			case LWSSS_SER_RXPRE_CREATE_RESULT:

				if (*state != LPCSCLI_WAITING_CREATE_RESULT) {
					lwsl_info("CREATE_RESULT\n");
					goto hangup;
				}

				if (par->rem < 1) {
					lwsl_info("CREATE_RESULT 1\n");
					goto hangup;
				}

				par->ps = RPAR_RESULT_CREATION;
				break;

			case LWSSS_SER_RXPRE_CONNSTATE:

				if (*state != LPCSCLI_LOCAL_CONNECTED &&
				    *state != LPCSCLI_OPERATIONAL) {
					lwsl_info("CONNSTATE1\n");
					goto hangup;
				}

				if (par->rem < 5 || par->rem > 8) {
					lwsl_info("CONNSTATE2\n");
					goto hangup;
				}

				par->ps = RPAR_STATEINDEX;
				par->ctr = 0;
				break;

			case LWSSS_SER_RXPRE_METADATA:

				if (par->rem < 3) {
					lwsl_info("METADATA1\n");
					goto hangup;
				}
				par->ctr = 0;
				par->ps = RPAR_METADATA_NAMELEN;
				break;

			case LWSSS_SER_RXPRE_TXCR_UPDATE:
				par->ctr = 0;
				par->ps = RPAR_RX_TXCR_UPDATE;
				break;

			case LWSSS_SER_RXPRE_PERF:
				par->ctr = 0;
				if (!par->rem) {
					lwsl_info("PERF1\n");
					goto hangup;
				}
				par->ps = RPAR_PERF;
				break;

			default:
				lwsl_notice("bad type 0x%x\n", par->type);
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
				if (!par->rem--) {
					lwsl_info("RPAR_FLAG\n");
					goto hangup;
				}
				break;

			case RPAR_LATA3:
			case RPAR_LATA2:
			case RPAR_LATA1:
			case RPAR_LATA0:
				par->usd_phandling <<= 8;
				par->usd_phandling |= *cp++;
				par->ps++;
				if (!par->rem--) {
					lwsl_info("RPAR_LATA\n");
					goto hangup;
				}
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
				if (!par->rem--) {
					lwsl_info("RPAR_LATB\n");
					goto hangup;
				}

				if (par->ps == RPAR_RIDESHARE_LEN &&
				    !(par->flags & LWSSS_FLAG_RIDESHARE))
					par->ps = RPAR_PAYLOAD;

				if (par->rem)
					break;

				/* fallthru - handle 0-length payload */

				if (!(par->flags & LWSSS_FLAG_RIDESHARE))
					goto payload_ff;

				lwsl_info("RPAR_LATB1\n");
				goto hangup;

			/*
			 * Inbound rideshare info is provided on the RX packet
			 * itself
			 */

		case RPAR_RIDESHARE_LEN:
			par->slen = *cp++;
			par->ctr = 0;
			par->ps++;
			if (par->rem-- < par->slen) {
				lwsl_info("RPAR_RIDESHARE_LEN\n");
				goto hangup;
			}
			break;

		case RPAR_PERF:
			n = (int)len + 1;
			if (n > par->rem)
				n = par->rem;

			if (client_pss_to_sspc_h(pss, ssi) &&
			    ssi->rx) {
				int ret;

				/* we still have an sspc handle */
				ret = ssi->rx(client_pss_to_userdata(pss),
					(uint8_t *)cp, (unsigned int)n,
					(int)(LWSSS_FLAG_SOM | LWSSS_FLAG_EOM |
							LWSSS_FLAG_PERF_JSON));
#if !defined(STANDALONE)
				if (lws_fi(&client_pss_to_sspc_h(pss, ssi)->fic,
					   "sspc_perf_rx_fake_destroy_me"))
					ret = LWSSSSRET_DESTROY_ME;
#endif

				switch (ret) {
				case LWSSSSRET_OK:
					break;
				case LWSSSSRET_DISCONNECT_ME:
					lwsl_info("PERF_DME\n");
					goto hangup;
				case LWSSSSRET_DESTROY_ME:
					lwsl_user("%s: a\n", __func__);
					return LWSSSSRET_DESTROY_ME;
				}
			}
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
			if (!par->rem--) {
				lwsl_info("RS\n");
				goto hangup;
			}
			if (par->ctr != par->slen)
				break;
			par->ps = RPAR_PAYLOAD;
			if (par->rem)
				break;

			/* fallthru - handle 0-length payload */

		case RPAR_PAYLOAD:
payload_ff:
			n = (int)len + 1;
			assert(n >= 0);
			if (n == 0)
				break;

			if (n > par->rem)
				n = par->rem;
			if (n > 1380)
				n = 1380;

			h = lws_container_of(par, lws_sspc_handle_t, parser);

			/*
			 * If the transport is passing up little pieces, use the
			 * dsh to coalesce them to whole datagrams before giving
			 * them to the application.
			 */

			if (par->frag1 || n != par->rem) {
//				lwsl_notice("%s: coalescing %d (par->rem %d)\n",
//					__func__, n, (int)par->rem);
				r = lws_dsh_alloc_tail(h->dsh, 0, cp, (size_t)n,
						       NULL, 0);

				if (!r && n != par->rem) {
//					lwsl_notice("%s: coalesced and waiting... len %u, n %u\n", __func__, (unsigned int)len, (unsigned int)n);
					cp += n;
					h->txc.peer_tx_cr_est -= n;
					par->rem = (uint16_t)(par->rem -
							     (uint16_t)(unsigned int)n);
					len = (len + 1) - (unsigned int)n;
					assert((int)len >= 0);
					break;
				}

				/*
				 * We have to flush the dsh,
				 * or it's the last bit...
				 */

//				lwsl_notice("%s: flushing %u (par->rem %d)\n", __func__, (unsigned int)n, (int)par->rem);
			}

			/*
			 * We have to deal with refragmenting the SOM / EOM
			 * flags that covered the whole client serialized
			 * packet, so they apply to each fragment correctly
			 */

			flags = par->flags & LWSSS_FLAG_RELATED_START;
			if (par->frag1)
				/*
				 * Only set the first time we came to this
				 * state after deserialization of the header
				 */
				flags |= par->flags & (LWSSS_FLAG_SOM |
						       LWSSS_FLAG_POLL);

			if (par->rem == n)
				/*
				 * We are going to complete the advertised
				 * payload length from the client on this dsh,
				 * so give him the EOM type flags if any
				 */
				flags |= par->flags & (LWSSS_FLAG_EOM |
						       LWSSS_FLAG_RELATED_END);

			/*
			 * Client receives some RX from proxy
			 *
			 * Pass whatever payload we have to ss user.
			 */

			h->txc.peer_tx_cr_est -= n;

			// lwsl_sspc_info(h, "P2C RX: len %d", (int)n);

			if (ssi->rx && client_pss_to_sspc_h(pss, ssi)) {
				/* we still have an sspc handle */
				void *vb = NULL;
				size_t size;
				int ret;

				if (lws_dsh_get_head(h->dsh, 0, &vb, &size))
					size = 0;
				// lwsl_notice("%s: flush head says %d\n", __func__, (int)size);

				if (!size)
					/* did not go through dsh */
					ret = ssi->rx(client_pss_to_userdata(pss),
					      (uint8_t *)cp, (unsigned int)n,
					      (int)flags);
				else {
				//	lwsl_notice("%s: drainning %u\n",
				//			__func__, (int)size);

					do {
						ret = ssi->rx(client_pss_to_userdata(pss),
								(uint8_t *)vb, (unsigned int)size,
								(int)flags);
						lws_dsh_free(&vb);
						if (lws_dsh_get_head(h->dsh, 0, &vb, &size))
							size = 0;
					} while (!ret && size);

					lws_dsh_empty(h->dsh);

					if (r) {
						/*
						 * Deal with stashing the new
						 * data we couldn't fit before,
						 * now we flushed the dsh
						 */
						r = lws_dsh_alloc_tail(h->dsh, 0, cp, (size_t)n,
								       NULL, 0);
						assert(!r);
					}
				}

				par->frag1 = 0;

#if !defined(STANDALONE)
				if (client_pss_to_sspc_h(pss, ssi) &&
				    lws_fi(&client_pss_to_sspc_h(pss, ssi)->fic,
					     "sspc_rx_fake_destroy_me"))
					ret = LWSSSSRET_DESTROY_ME;
#endif

				switch (ret) {
				case LWSSSSRET_OK:
					break;
				case LWSSSSRET_DISCONNECT_ME:
					lwsl_info("PLDM\n");
					goto hangup;
				case LWSSSSRET_DESTROY_ME:
					lwsl_user("%s: b\n", __func__);
					return LWSSSSRET_DESTROY_ME;
				}
			}

			par->frag1 = 0;

			if (n) {
				cp += n;
				par->rem = (uint16_t)(par->rem -
						     (uint16_t)(unsigned int)n);
				len = (len + 1) - (unsigned int)n;
			}
			if (!par->rem)
				par->ps = RPAR_TYPE;
			break;

		case RPAR_RX_TXCR_UPDATE:
			if (!--par->rem && par->ctr != 3) {
				lwsl_info("TXCU\n");
				goto hangup;
			}

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4)
				break;

			/*
			 * Proxy is telling us remote endpoint is allowing us
			 * par->temp32 more bytes tx credit to write to it
			 */

			h = lws_container_of(par, lws_sspc_handle_t, parser);
			h->txc.tx_cr += par->temp32;
			lwsl_sspc_info(h, "RX_PEER_TXCR: %d", (int)par->temp32);
			lws_sspc_request_tx(h); /* in case something waiting */
			par->ctr = 0;
			par->ps = RPAR_TYPE;
			break;

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

			if (!--par->rem) {
				lwsl_info("PROVERS\n");
				goto hangup;
			}
			par->ctr = 0;
			par->ps = RPAR_INIT_PID;
			break;


		case RPAR_INIT_PID:
			if (!--par->rem) {
				lwsl_info("PID\n");
				goto hangup;
			}

			par->temp32 = (par->temp32 << 8) | *cp++;
			if (++par->ctr < 4)
				break;

			par->client_pid = (uint32_t)par->temp32;
			par->ctr = 0;
			par->ps = RPAR_INITTXC0;
			break;

		case RPAR_INITTXC0:
			if (!--par->rem) {
				lwsl_info("TXC0\n");
				goto hangup;
			}

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
				if (!--par->rem) {
					lwsl_info("TXCR0\n");
					goto hangup;
				}
				break;
			}

			if (--par->rem) {
				lwsl_info("TXCR0b\n");
				goto hangup;
			}

			/*
			 * We're the client, being told by the proxy
			 * about tx credit being given to us from the
			 * remote peer, allowing the client to write to
			 * it.
			 */
			h = lws_container_of(par, lws_sspc_handle_t,
					     parser);
			h->txc.tx_cr += par->temp32;
			lwsl_sspc_info(h, "client RX_PEER_TXCR: %d",
				       (int)par->temp32);
			/* in case something waiting */
			lws_sspc_request_tx(h);

			par->ps = RPAR_TYPE;
			break;

		case RPAR_PAYLEN0:
		case RPAR_TIMEOUT0:
			lwsl_info("TIMEOUT0\n");
			goto hangup;

		case RPAR_METADATA_NAMELEN:
			/* both client and proxy */
			if (!--par->rem) {
				lwsl_info("NL1\n");
				goto hangup;
			}
			par->slen = *cp++;
			if (par->slen >= sizeof(par->metadata_name) - 1) {
				lwsl_info("NL2\n");
				goto hangup;
			}
			par->ctr = 0;
			par->ps++;
			break;

		case RPAR_METADATA_NAME:
			/* both client and proxy */
			if (!--par->rem) {
				lwsl_info("MDN\n");
				goto hangup;
			}
			par->metadata_name[par->ctr++] = (char)*cp++;
			if (par->ctr != par->slen)
				break;
			par->metadata_name[par->ctr] = '\0';
			par->ps = RPAR_METADATA_VALUE;

			h = client_pss_to_sspc_h(pss, ssi);

			/*
			 * client side does not have access to policy
			 * and any metadata are new to it each time,
			 * we allocate them, removing any existing with
			 * the same name first
			 */

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					lws_dll2_get_head(
						&h->metadata_owner_rx)) {
				md = lws_container_of(d,
					   lws_sspc_metadata_t, list);

				if (!strcmp(md->name,
					    par->metadata_name)) {
					lws_dll2_remove(&md->list);
					lws_free(md);
				}

			} lws_end_foreach_dll_safe(d, d1);

			/*
			 * Create the client's rx metadata entry
			 */

#if !defined(STANDALONE)
			if (h && lws_fi(&h->fic, "sspc_rx_metadata_oom"))
				md = NULL;
			else
#endif
				md = lws_malloc(sizeof(lws_sspc_metadata_t) +
					par->rem + 1, "rxmeta");
			if (!md) {
				lwsl_err("%s: OOM\n", __func__);
				goto hangup;
			}
			if (!h)
				/* coverity */
				goto hangup;
			memset(md, 0, sizeof(lws_sspc_metadata_t));

			lws_strncpy(md->name, par->metadata_name,
					sizeof(md->name));
			md->len = par->rem;
			par->rxmetaval = (uint8_t *)&md[1];
			/*
			 * Overallocate by 1 and put a NUL just beyond
			 * the official md->len, so value can be easily
			 * dereferenced safely for NUL-terminated string
			 * apis that's the most common usage
			 */
			par->rxmetaval[md->len] = '\0';
			lws_dll2_add_tail(&md->list,
					  &h->metadata_owner_rx);
			par->ctr = 0;
			break;

		case RPAR_METADATA_VALUE:
			/* both client and proxy */

			*par->rxmetaval++ = *cp++;
			if (--par->rem)
				break;

			/* we think we got all the value */

			h = lws_container_of(par, lws_sspc_handle_t, parser);
			lwsl_sspc_notice(h, "RX METADATA %s", par->metadata_name);
			par->ps = RPAR_TYPE;
			break;

		case RPAR_STREAMTYPE:

			/* only the proxy can get these */

			lwsl_info("ST\n");
			goto hangup;

		/* clientside states */

		case RPAR_RESULT_CREATION:
			if (*cp++) {
				lwsl_err("%s: stream creation failed\n",
					 __func__);
				goto hangup;
			}

			if (--par->rem < 4) {
				lwsl_info("RC1\n");
				goto hangup;
			}

			par->ps = RPAR_RESULT_CREATION_DSH;
			par->ctr = 0;
			break;

		case RPAR_RESULT_CREATION_DSH:

			par->temp32 = (par->temp32 << 8) | (*cp++);
			if (!par->rem--) {
				lwsl_info("CDSH\n");
				goto hangup;
			}
			if (++par->ctr < 4)
				break;

			/*
			 * Client (par->temp32 == dsh alloc)
			 */

			h = lws_container_of(par, lws_sspc_handle_t, parser);

			lws_ss_serialize_state_transition(h, state,
							  LPCSCLI_LOCAL_CONNECTED);

			assert(h->txp_path.ops_onw);
			assert(h->txp_path.ops_onw->event_stream_up);
			h->txp_path.ops_onw->event_stream_up(h->txp_path.priv_onw);

			if (h->dsh)
				lws_dsh_empty(h->dsh);

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
			 * proxy and ultimately bring up the onward connection
			 * now we are in LOCAL_CONNECTED.  We need to do the
			 * CREATING now so we'll know the metadata to sync.
			 */

#if !defined(STANDALONE) && defined(LWS_WITH_SYS_METRICS)
			/*
			 * If any hanging caliper measurement, dump it, and free any tags
			 */
			lws_metrics_caliper_report_hist(h->cal_txn,
							(struct lws *)NULL);
#endif

			if (!h->creating_cb_done) {
				if (lws_ss_check_next_state_sspc(h,
						&h->prev_ss_state,
						LWSSSCS_CREATING))
					return LWSSSSRET_DESTROY_ME;

				h->prev_ss_state = (uint8_t)LWSSSCS_CREATING;
				h->creating_cb_done = 1;
			} else
				h->prev_ss_state = LWSSSCS_DISCONNECTED;

			if (ssi->state) {
				n = ssi->state(client_pss_to_userdata(pss),
					       NULL, h->prev_ss_state, 0);
				switch (n) {
				case LWSSSSRET_OK:
					break;
				case LWSSSSRET_DISCONNECT_ME:
					lwsl_info("CDSH2\n");
					goto hangup;
				case LWSSSSRET_DESTROY_ME:
					lwsl_sspc_warn(h, "d");
					return LWSSSSRET_DESTROY_ME;
				}
			}

			if (!h->dsh)
				h->dsh = lws_dsh_create(NULL,
#if defined(STANDALONE)
					2048,
#else
					(size_t)(par->temp32 ?
						 par->temp32 : 32768),
#endif
					(int)(hh->txp_path.ops_onw->flags | 1u));
			if (!h->dsh) {
				lwsl_info("CDSH3\n");
				goto hangup;
			}

			h->dsh->splitat = h->txp_path.ops_onw->dsh_splitat;

			h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

			par->rsl_pos = 0;
			par->rsl_idx = 0;

			memset(&h->rideshare_ofs[0], 0,
			       sizeof(h->rideshare_ofs[0]));
			h->rideshare_list[0] = '\0';
			h->rsidx = 0;

			/* no rideshare data is OK */
			par->ps = RPAR_TYPE;

			if (par->rem) {
				par->ps = RPAR_RESULT_CREATION_RIDESHARE;
				if (par->rem >= sizeof(h->rideshare_list)) {
					lwsl_info("CDSH4\n");
					goto hangup;
				}
			}
			break;

		case RPAR_RESULT_CREATION_RIDESHARE:
			h = lws_container_of(par, lws_sspc_handle_t, parser);
			if (*cp == ',') {
				cp++;
				h->rideshare_list[par->rsl_pos++] = '\0';
				if (par->rsl_idx == LWS_ARRAY_SIZE(h->rideshare_ofs)) {
					lwsl_info("CDSH5\n");
					goto hangup;
				}
				h->rideshare_ofs[++par->rsl_idx] = par->rsl_pos;
			} else
				h->rideshare_list[par->rsl_pos++] = (char)*cp++;
			if (!--par->rem)
				par->ps = RPAR_TYPE;
			break;

		case RPAR_STATEINDEX:
			par->ctr = (par->ctr << 8) | (*cp++);
			if (--par->rem == 4)
				par->ps = RPAR_ORD3;
			break;

		case RPAR_ORD3:
			par->flags = (uint32_t)((*cp++) << 24);
			par->ps++;
			break;

		case RPAR_ORD2:
			par->flags |= (uint32_t)((*cp++) << 16);
			par->ps++;
			break;

		case RPAR_ORD1:
			par->flags |= (uint32_t)((*cp++) << 8);
			par->ps++;
			break;

		case RPAR_ORD0:
			par->flags |= (uint32_t)(*cp++);
			par->ps++;
			par->ps = RPAR_TYPE;

			/*
			 * Client received a proxied state change
			 */

			h = client_pss_to_sspc_h(pss, ssi);
			if (!h)
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
				lws_ss_serialize_state_transition(h, state,
						LPCSCLI_LOCAL_CONNECTED);
				h->conn_req_state = LWSSSPC_ONW_NONE;
				break;

			case LWSSSCS_CONNECTED:
				lwsl_sspc_info(h, "CONNECTED %s",
							ssi->streamtype);
				if (*state == LPCSCLI_OPERATIONAL)
					/*
					 * Don't allow to see connected more
					 * than once for one connection
					 */
					goto swallow;

				lws_ss_serialize_state_transition(h, state,
							LPCSCLI_OPERATIONAL);

				h->conn_req_state = LWSSSPC_ONW_CONN;
				break;
			case LWSSSCS_TIMEOUT:
				break;
			default:
				break;
			}

#if !defined(STANDALONE) && defined(_DEBUG)
			lwsl_sspc_info(h, "forwarding proxied state %s",
					lws_ss_state_name(par->ctr));
#endif

			if (par->ctr == LWSSSCS_CREATING) {
				h = lws_container_of(par, lws_sspc_handle_t,
						     parser);
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

			if (ssi->state) {
				h = lws_container_of(par, lws_sspc_handle_t,
						     parser);
				lws_ss_constate_t cs = (lws_ss_constate_t)par->ctr;

				if (cs == LWSSSCS_CONNECTED)
					h->ss_dangling_connected = 1;
				if (cs == LWSSSCS_DISCONNECTED)
					h->ss_dangling_connected = 0;

				if (lws_ss_check_next_state_sspc(h,
							 &h->prev_ss_state, cs)) {
					lwsl_user("%s: e\n", __func__);

					return LWSSSSRET_DESTROY_ME;
				}
				if (cs < LWSSSCS_USER_BASE)
					h->prev_ss_state = (uint8_t)cs;

				h->h_in_svc = h;
				n = ssi->state(client_pss_to_userdata(pss),
					NULL, cs, par->flags);
				h->h_in_svc = NULL;
				switch (n) {
				case LWSSSSRET_OK:
					break;
				case LWSSSSRET_DISCONNECT_ME:
					lwsl_info("ORDB\n");
					goto hangup;
				case LWSSSSRET_DESTROY_ME:
					lwsl_sspc_warn(h, "f");
					return LWSSSSRET_DESTROY_ME;
				}
			}

swallow:
			break;

		default:
			goto hangup;
		}
	}

	return LWSSSSRET_OK;

hangup:

	lwsl_notice("%s: hangup\n", __func__);

	return LWSSSSRET_DISCONNECT_ME;
}
