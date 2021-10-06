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

#if defined(_DEBUG)
void
lws_assert_fourcc(uint32_t fourcc, uint32_t expected)
{
	if (fourcc == expected)
		return;

	lwsl_err("%s: fourcc mismatch, expected %c%c%c%c, saw %c%c%c%c\n",
			__func__, (int)(expected >> 24), (int)((expected >> 16) & 0xff),
			(int)((expected >> 8) & 0xff), (int)(expected & 0xff),
			(int)(fourcc >> 24), (int)((fourcc >> 16) & 0xff),
			(int)((fourcc >> 8) & 0xff), (int)(fourcc & 0xff));

	assert(0);
}
#endif
#endif

lws_transport_mux_ch_t *
lws_transport_mux_get_channel(lws_transport_mux_t *tm, lws_mux_ch_idx_t i)
{
	lws_transport_mux_ch_t *mc;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&tm->owner)) {
		mc = lws_container_of(d, lws_transport_mux_ch_t,
					list);
		if (mc->ch_idx == i)
			return mc;
	} lws_end_foreach_dll(d);

	return NULL;
}

int
lws_transport_mux_next_free(lws_transport_mux_t *tm, lws_mux_ch_idx_t *result)
{
	int n = tm->info.flags & LWSTMINFO_SERVER ? 1 : LWS_MUCH_RANGE - 1;

	if (tm->owner.count >= LWS_MUCH_RANGE - 3)
		/* too full to be safe against new muc ch selection collision */
		return 1;

	do {
		if (!(tm->_open[n >> 5] & (1u << (n & 31)))) {
			/*
			 * Additionally check if any placeholders for this
			 * channel, that did not reach open yet
			 */
			if (lws_transport_mux_get_channel(tm, (lws_mux_ch_idx_t)n))
				goto go_on;

			/*
			 * No it seems good to try it
			 */
			*result = (lws_mux_ch_idx_t)n;

			return 0;
		}
go_on:
		n += tm->info.flags & LWSTMINFO_SERVER ? 1 : -1;
	} while (n >= 0 && n < LWS_MUCH_RANGE);

	return 1;
}

void
lws_transport_set_link(lws_transport_mux_t *tm, int link_state)
{
	if (tm->link_state && !link_state) {
		lws_transport_mux_ch_t *mc;

		lwsl_user("%s: ******* transport mux link is DOWN\n", __func__);
		/* destroy any mux channels that were using the link */
		while (tm->owner.head) {
			mc = lws_container_of(tm->owner.head,
					      lws_transport_mux_ch_t, list);
			lws_transport_mux_destroy_channel(&mc);
		}
		memset(tm->_open, 0, sizeof(tm->_open));
		tm->issue_ping = 1;
		tm->awaiting_pong = 0;
		lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
				 sul_ping_cb, 2 * LWS_US_PER_SEC);
	} else if (!tm->link_state && link_state) {
		lwsl_user("%s: ******* transport mux link is UP\n", __func__);
	}
	tm->link_state = (uint8_t)link_state;
}

void
sul_ping_cb(lws_sorted_usec_list_t *sul)
{
	lws_transport_mux_t *tm = lws_container_of(sul, lws_transport_mux_t,
						   sul_ping);

	/*
	 * Some interval expired on the transport...
	 *
	 * ...because we need to send a ping now?
	 */

	if (!tm->awaiting_pong) {
		/*
		 * We start the pong timer when we decided we wanted to send
		 * it, not when we sent it, so we can catch unable to send
		 */
		lwsl_notice("%s: issuing ping\n", __func__);
		tm->issue_ping = 1;
		tm->awaiting_pong = 1;

		lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
				 sul_ping_cb, tm->info.pong_grace_us);

		if (tm->info.txp_ppath.ops_onw)
			tm->info.txp_ppath.ops_onw->proxy_req_write(
						tm->info.txp_ppath.priv_onw);
		else
			tm->info.txp_cpath.ops_onw->req_write(
						tm->info.txp_cpath.priv_onw);
		return;
	}

	/*
	 * ... hm it's because our PONG never arrived in the grace period...
	 * it means we take it that the transport is no longer passing data
	 */

	lwsl_notice("%s: no PONG came\n", __func__);
	tm->issue_ping = 1;
	tm->awaiting_pong = 0;
	lws_transport_set_link(tm, LWSTM_TRANSPORT_DOWN);
	lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
			 sul_ping_cb, 2 * LWS_US_PER_SEC);
}

#if defined(PICO_SDK_PATH) || defined(LWS_PLAT_BAREMETAL)
#if 0
struct stv {
	uint32_t tv_sec;
	uint32_t tv_usec;
};

static uint64_t
get_us_timeofday(void)
{
	struct stv tv;

	gettimeofday((struct timeval *)&tv, NULL);

	return ((uint64_t)((lws_usec_t)tv.tv_sec * LWS_US_PER_SEC) +
			  (uint64_t)tv.tv_usec);
}
#else
static uint64_t
get_us_timeofday(void)
{
	return (uint64_t)lws_now_usecs();
}
#endif
#else
static
uint64_t
get_us_timeofday(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return ((uint64_t)((lws_usec_t)tv.tv_sec * LWS_US_PER_SEC) +
			  (uint64_t)tv.tv_usec);
}
#endif

/*
 * If the mux channel wants to do something, pack together as much as will
 * fit and return nonzero to announce that the mux layer has commandeered this
 * write opportunity
 *
 * Caution, this is called by both client and proxy mux sides
 */

// !!! response timeouts

int
lws_transport_mux_pending(lws_transport_mux_t *tm, uint8_t *buf, size_t *len,
			  const lws_txp_mux_parse_cbs_t *cbs)
{
	uint8_t *p = buf, *end = buf + (*len) - 1u;
	lws_transport_mux_ch_t *mc;
	int n;

	/* pings and pongs go first */

	if (tm->issue_ping) {
		if (tm->link_state == LWSTM_TRANSPORT_DOWN) {
			lwsl_info("%s: send RESET_TRANSPORT\n", __func__);
			*p++ = LWSSSS_LLM_RESET_TRANSPORT;
		}
		lwsl_info("%s: issuing PING\n", __func__);
		*p++ = LWSSSS_LLM_PING;
		tm->us_ping_out = (uint64_t)lws_now_usecs();
		lws_ser_wu64be(p, tm->us_ping_out);
		p += 8;
		tm->issue_ping = 0;
		cbs->txp_req_write(tm);
	}

	if (lws_ptr_diff_size_t(end, p) < 18)
		goto issue;

	if (tm->issue_pong) {
		lwsl_info("%s: issuing PONG\n", __func__);
		*p++ = LWSSSS_LLM_PONG;
		lws_ser_wu64be(p, tm->us_ping_in);
		p += 8;
		lws_ser_wu64be(p, (uint64_t)lws_now_usecs());
		p += 8;
		tm->issue_pong = 0;
		cbs->txp_req_write(tm);
	}

	if (lws_ptr_diff_size_t(end, p) < 18)
		goto issue;

	if (tm->issue_pongack) {
		lwsl_info("%s: issuing PONGACK\n", __func__);
		*p++ = LWSSSS_LLM_PONGACK;
		lws_ser_wu64be(p, (uint64_t)get_us_timeofday());
		p += 8;
		tm->issue_pongack = 0;
		lws_sul_cancel(&tm->sul_ping);
		tm->awaiting_pong = 0;
		lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
				  sul_ping_cb, tm->info.ping_interval_us);

		lws_transport_set_link(tm, LWSTM_OPERATIONAL);
		cbs->txp_req_write(tm);
	}

	for (n = 0; n < LWS_MUCH_RANGE / 32; n++)
		if (tm->fin[n] && lws_ptr_diff_size_t(end, p) > 2) {
			int m;
			for (m = 0; m < 32 && lws_ptr_diff_size_t(end, p) > 2; m++)
				if (tm->fin[n] & (1u << m)) {
					lwsl_notice("%s: FIN on closed ch %d\n", __func__, (n << 5) |m);
					tm->fin[n] &= (uint32_t)~(1 << m);
					*p++ = LWSSSS_LLM_CHANNEL_NACK;
					*p++ = (uint8_t)((n << 5) | m);
					cbs->txp_req_write(tm);
				}
		}

	if (lws_ptr_diff_size_t(end, p) < 18)
		goto issue;


	if (tm->link_state == LWSTM_TRANSPORT_DOWN)
		/*
		 * We can't do anything except PING / PONG probes if the
		 * transport state is down
		 */
		goto issue;

	/* let's do any mux control packets first */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   tm->pending_tx.head) {
		mc = lws_container_of(d, lws_transport_mux_ch_t,
				      list_pending_tx);

		if (lws_ptr_diff_size_t(end, p) < 18)
			break;

		if (mc->state != LWSTMC_OPERATIONAL)
			lws_dll2_remove(&mc->list_pending_tx);

		/* he wants to write something... let's see how he is */

		switch (mc->state) {
		case LWSTMC_PENDING_CREATE_CHANNEL:
			*p++ = LWSSSS_LLM_CHANNEL_REQ;
			*p++ = mc->ch_idx;
			mc->state = LWSTMC_AWAITING_CREATE_CHANNEL_ACK;
			break;

		case LWSTMC_PENDING_CREATE_CHANNEL_ACK:
			*p++ = LWSSSS_LLM_CHANNEL_ACK;
			*p++ = mc->ch_idx;
			tm->_open[mc->ch_idx >> 5] = (uint32_t)(
					tm->_open[mc->ch_idx >> 5] |
						(1u << (mc->ch_idx & 31)));
			cbs->ch_opens(mc, 0);
			mc->state = LPCSPROX_OPERATIONAL;
			break;

		case LWSTMC_PENDING_CREATE_CHANNEL_NACK:
			*p++ = LWSSSS_LLM_CHANNEL_NACK;
			*p++ = mc->ch_idx;
			/*
			 * We're not on board with creating the proposed
			 * channel, so let's reply with that and then delete the
			 * placeholder channel we speculatively created
			 */
			cbs->ch_closes(mc);
			lws_transport_mux_destroy_channel(&mc);
			break;

		case LWSTMC_PENDING_CLOSE_CHANNEL:
			*p++ = LWSSSS_LLM_CHANNEL_CLOSE;
			*p++ = mc->ch_idx;
			mc->state = LWSTMC_AWAITING_CLOSE_CHANNEL_ACK;
			break;

		case LWSSSS_LLM_CHANNEL_CLOSE_ACK:
			/*
			 * We're telling the peer we saw and actioned his
			 * close request.  Then we can remove our side.
			 */
			*p++ = LWSSSS_LLM_CHANNEL_CLOSE;
			*p++ = mc->ch_idx;

			cbs->ch_closes(mc);
			lws_transport_mux_destroy_channel(&mc);
			break;
		}
	} lws_end_foreach_dll_safe(d, d1);

	/* if none, do the first OPERATIONAL that wants to write */

	if (buf == p) {
		//lwsl_notice("%s: looking for OPERATIONAL\n", __func__);
		lws_start_foreach_dll(struct lws_dll2 *, d, tm->pending_tx.head) {
			mc = lws_container_of(d, lws_transport_mux_ch_t,
					      list_pending_tx);

			if (mc->state == LWSTMC_OPERATIONAL) {
				lws_dll2_remove(&mc->list_pending_tx);
				// lwsl_notice("%s: passing up  event_can_write\n",
				//		__func__);

				if (cbs->txp_can_write(mc))
					return -1;

				break;
			}

		} lws_end_foreach_dll(d);
	}

	if (tm->pending_tx.head || buf != p)
		cbs->txp_req_write(tm);

issue:
	*len = lws_ptr_diff_size_t(p, buf);

	return p != buf;
}

int
lws_transport_mux_rx_parse(lws_transport_mux_t *tm,
			   const uint8_t *buf, size_t len,
			   const lws_txp_mux_parse_cbs_t *cbs)
{
	const uint8_t *end = buf + len;
	lws_transport_mux_ch_t *mc;
	size_t av;

	//lwsl_hexdump_notice(buf, len);

	while (buf < end) {
		// lwsl_user("%s: state %d\n", __func__, tm->mp_state);
		switch (tm->mp_state) {
		case LWSTMCPAR_CMD:
			tm->mp_cmd = *buf++;

			switch (tm->mp_cmd) {
			case LWSSSS_LLM_CHANNEL_REQ:
			case LWSSSS_LLM_CHANNEL_ACK:
			case LWSSSS_LLM_CHANNEL_NACK:
			case LWSSSS_LLM_CHANNEL_CLOSE:
			case LWSSSS_LLM_CHANNEL_CLOSE_ACK:
				tm->mp_state = LWSTMCPAR_CHIDX_DONE;
				break;
			case LWSSSS_LLM_MUX:
				tm->mp_state = LWSTMCPAR_CHIDX;
				break;
			case LWSSSS_LLM_PING:
			case LWSSSS_LLM_PONG:
			case LWSSSS_LLM_PONGACK:
				tm->mp_ctr = 8;
				tm->mp_state = LWSTMCPAR_T64_1;
				break;
			case LWSSSS_LLM_RESET_TRANSPORT:
				/*
				 * The other side is telling us he lost
				 * framing coherence, the transport must be
				 * reset
				 */
				lws_transport_set_link(tm, LWSTM_TRANSPORT_DOWN);
				break;
			default:
				/* uhhh... */
				lwsl_warn("%s: unknown mux cmd 0x%x\n",
						__func__, tm->mp_cmd);
				// assert(0); /* temp */
				goto fail_transport;
			}
			break;

		case LWSTMCPAR_CHIDX_DONE:
			tm->mp_idx = *buf++;
			tm->mp_state = LWSTMCPAR_CMD;
			switch (tm->mp_cmd) {
			case LWSSSS_LLM_CHANNEL_REQ:
				/*
				 * peer wants to open a specific channel, how
				 * do we feel about that?
				 */
				mc = lws_transport_mux_create_channel(tm,
								tm->mp_idx);
				if (mc) {
					/* We want to try it... */
					mc->state = LWSTMC_PENDING_CREATE_CHANNEL_ACK;
					goto ask_to_send;
				}
					/*
					 * else already pending or open for that
					 * channel, just ignore and let timeout
					 */
				break;

			case LWSSSS_LLM_CHANNEL_NACK:
			case LWSSSS_LLM_CHANNEL_ACK:
				/* peer says we can open this channel, but did
				 * we ask to open it? */
				mc = lws_transport_mux_get_channel(tm, tm->mp_idx);
				if (!mc) {
					lwsl_warn("%s: (N)ACK for open %u we don't "
						  "remember asking for\n",
						  __func__, tm->mp_idx);
					break;
				}
				if (tm->_open[tm->mp_idx >> 5] &
						1u << (tm->mp_idx & 31)) {
					lwsl_warn("%s: (N)ACK for channel "
						  "already fully open\n",
						  __func__);
					if (tm->mp_cmd == LWSSSS_LLM_CHANNEL_NACK) {
						lwsl_warn("%s: taking as FIN ch %d\n",
								__func__, tm->mp_idx);
						tm->_open[tm->mp_idx >> 5] &= (uint32_t)~(
								1 << (tm->mp_idx & 31));
						cbs->ch_closes(mc);
					}
					break;
				}

				if (tm->mp_cmd == LWSSSS_LLM_CHANNEL_ACK) {
					/* peer said 'yes' to the channel
					 * we wanted */
					tm->_open[tm->mp_idx >> 5] =
						(uint32_t)(tm->_open[tm->mp_idx >> 5] |
						(1u << (tm->mp_idx & 31)));

					lwsl_notice("%s: ch %d fully open\n",
							__func__, tm->mp_idx);

					mc->state = LWSTMC_OPERATIONAL;
					cbs->ch_opens(mc, 0);
					goto ask_to_send;
				}

				/* peer said 'no' to the channel we wanted */

				cbs->ch_opens(mc, 1);
				lws_transport_mux_destroy_channel(&mc);
				break;

			case LWSSSS_LLM_CHANNEL_CLOSE:
				mc = lws_transport_mux_get_channel(tm, tm->mp_idx);
				if (!mc) {
					lwsl_warn("%s: CLOSE for unknown ch\n",
						  __func__);
					break;
				}
				if (!(tm->_open[tm->mp_idx >> 5] &
						1u << (tm->mp_idx & 31))) {
					lwsl_warn("%s: CLOSE for channel "
						  "not fully open\n",
						  __func__);
					break;
				}
				mc->state = LWSTMC_PENDING_CLOSE_CHANNEL_ACK;
				goto ask_to_send;

			case LWSSSS_LLM_CHANNEL_CLOSE_ACK:
				/* ok... so we did ask to close that channel? */
				mc = lws_transport_mux_get_channel(tm, tm->mp_idx);
				if (!mc) {
					lwsl_warn("%s: CLOSE_ACK for unknown ch\n",
						  __func__);
					break;
				}
				if (mc->state != LWSTMC_AWAITING_CLOSE_CHANNEL_ACK) {
					lwsl_warn("%s: CLOSE_ACK on ch not waiting for it\n", __func__);
					break;
				}
				/* nothing more should come on this channel */
				lws_transport_mux_destroy_channel(&mc);
				break;
			}
			break;

		/* mux payload encapsulation */

		case LWSTMCPAR_CHIDX:
			tm->mp_idx = *buf++;
			tm->mp_state++;
			break;

		case LWSTMCPAR_PLENH:
			tm->mp_pay = (uint32_t)((*buf++) << 8);
			tm->mp_state++;
			break;

		case LWSTMCPAR_PLENL:
			tm->mp_pay |= *buf++;
			mc = lws_transport_mux_get_channel(tm, tm->mp_idx);
			if (!mc) {
				lwsl_warn("%s: DATA for unknown ch\n",
					  __func__);
				/* assertively NAK the channel */
				tm->fin[tm->mp_idx >> 5] |= 1u << (tm->mp_idx & 31);
				av = lws_ptr_diff_size_t(end, buf);
				if (av > tm->mp_pay)
					av = tm->mp_pay;
				buf += av;
				tm->mp_pay = (uint32_t)(tm->mp_pay - av);
				if (!tm->mp_pay)
					tm->mp_state = LWSTMCPAR_CMD;
				else
					tm->mp_state = LWSTMCPAR_PAY;
				goto ask_to_send;
			}
		//	lwsl_notice("%s: mux data frame len %d\n", __func__, (int)tm->mp_pay);
			assert(tm->_open[tm->mp_idx >> 5] & (1u << (tm->mp_idx & 31)));
			if (!tm->mp_pay)
				tm->mp_state = LWSTMCPAR_CMD;
			else
				tm->mp_state = LWSTMCPAR_PAY;
			break;

		case LWSTMCPAR_PAY:
			av = lws_ptr_diff_size_t(end, buf);
			if (av > tm->mp_pay)
				av = tm->mp_pay;
			mc = lws_transport_mux_get_channel(tm, tm->mp_idx);
			if (mc) {
				if (cbs->payload(mc, buf, av)) {
					/*
					 * indication of broken framing...
					 * other outcomes handled at SSPC layer
					 */

					goto fail_transport;
				}
			}
			buf += av;
			// lwsl_notice("%s: mp_pay %d -> %d\n", __func__,
			//   (int)tm->mp_pay, (int)(tm->mp_pay - av));
			tm->mp_pay -= (uint32_t)av;
			if (!tm->mp_pay)
				tm->mp_state = LWSTMCPAR_CMD;
			break;

		case LWSTMCPAR_T64_1:
			tm->mp_time = (tm->mp_time << 8) | *buf++;
			if (!--tm->mp_ctr) {
				tm->mp_ctr = 8;
				if (tm->mp_cmd == LWSSSS_LLM_PING) {
					lwsl_user("%s: got PING\n", __func__);
					tm->mp_state = LWSTMCPAR_CMD;
					tm->us_ping_in = tm->mp_time;
					tm->issue_pong = 1;
					cbs->txp_req_write(tm);
					break;
				}
				if (tm->mp_cmd == LWSSSS_LLM_PONGACK) {
					lwsl_user("%s: got PONGACK: ustime %llu\n",
							__func__,
							(unsigned long long)tm->mp_time);
					tm->us_unixtime_peer = tm->mp_time;
					tm->us_unixtime_peer_loc = (uint64_t)lws_now_usecs();
					tm->mp_state = LWSTMCPAR_CMD;
					lws_transport_set_link(tm, LWSTM_OPERATIONAL);
					lws_sul_cancel(&tm->sul_ping);
					tm->awaiting_pong = 0;
					lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
							  sul_ping_cb, tm->info.ping_interval_us);
					break;
				}

				tm->mp_state++;
			}
			break;
		case LWSTMCPAR_T64_2:
			tm->mp_time1 = (tm->mp_time1 << 8) | *buf++;
			if (--tm->mp_ctr)
					break;

			tm->mp_state = LWSTMCPAR_CMD;

			if (tm->mp_time != tm->us_ping_out) {
				lwsl_warn("%s: PONG payload mismatch 0x%llx 0x%llx\n",
					  __func__, (unsigned long long)tm->mp_time,
					  (unsigned long long)tm->us_ping_out);
				break;
			}

			lwsl_user("%s: got PONG\n", __func__);
			tm->awaiting_pong = 0;
			lws_sul_cancel(&tm->sul_ping);
			lws_sul_schedule((struct lws_context *)tm->cx, 0, &tm->sul_ping,
					  sul_ping_cb, tm->info.ping_interval_us);
			tm->issue_pongack = 1;
			cbs->txp_req_write(tm);
			break;
		}

		continue;

ask_to_send:
		if (mc && lws_dll2_is_detached(&mc->list_pending_tx))
			lws_dll2_add_tail(&mc->list_pending_tx, &tm->pending_tx);

		cbs->txp_req_write(tm);
	}

	return 0;

fail_transport:

	lws_transport_set_link(tm, LWSTM_TRANSPORT_DOWN);

	return -1;
}

lws_transport_mux_ch_t *
lws_transport_mux_create_channel(lws_transport_mux_t *tm, lws_mux_ch_idx_t i)
{
	lws_transport_mux_ch_t *mc;

	if (tm->_open[i >> 5] & (1u << (i & 31)))
		return NULL;

	if (lws_transport_mux_get_channel(tm, i))
		return NULL;

	mc = malloc(sizeof(*mc));
	if (!mc)
		return NULL;

	memset(mc, 0, sizeof(*mc));

#if defined(_DEBUG)
	mc->magic = LWS_TRANSPORT_MUXCH_MAGIC;
#endif
	mc->ch_idx = i;

	lws_dll2_add_tail(&mc->list, &tm->owner);

	return mc;
}

lws_transport_mux_ch_t *
lws_transport_mux_add_channel(lws_transport_mux_t *tm, lws_transport_priv_t priv)
{
	lws_transport_mux_ch_t *mc;
	lws_mux_ch_idx_t i;

	if (lws_transport_mux_next_free(tm, &i)) {
		lwsl_err("%s: unable to add new mux channel\n", __func__);
		return NULL;
	}

	mc = lws_transport_mux_create_channel(tm, i);
	if (mc)
		mc->priv = priv;

	return mc;
}

void
lws_transport_mux_destroy_channel(lws_transport_mux_ch_t **_mc)
{
	lws_transport_mux_ch_t *mc = *_mc;
	lws_transport_mux_t *tm = lws_container_of(mc->list.owner,
						lws_transport_mux_t, owner);

	lwsl_notice("%s: mux ch %u\n", __func__, mc->ch_idx);

	if (mc->state >= LWSTMC_PENDING_CREATE_CHANNEL_ACK)
		/* he only sets the open bit on receipt of the ACK */
		tm->_open[mc->ch_idx >> 5] &= (lws_mux_ch_idx_t)
						~(1 << (mc->ch_idx & 31));

	/*
	 * We must report channel closure... client side
	 */

	if (tm->info.txp_cpath.ops_in &&
	    tm->info.txp_cpath.ops_in->event_closed) {
		lwsl_notice("%s: calling %s event closed\n", __func__,
				tm->info.txp_cpath.ops_in->name);
		tm->info.txp_cpath.ops_in->event_closed((lws_transport_priv_t)mc);
	}

	/*
	 * We must report channel closure... proxy side
	 */

	if (tm->info.txp_ppath.ops_in &&
	    tm->info.txp_ppath.ops_in->event_close_conn) {
		lwsl_notice("%s: calling %s event_close_conn\n", __func__,
				tm->info.txp_ppath.ops_in->name);
		tm->info.txp_ppath.ops_in->event_close_conn(
				(lws_transport_priv_t)mc->priv);
	}

	lws_sul_cancel(&mc->sul);
	lws_dll2_remove(&mc->list_pending_tx);
	lws_dll2_remove(&mc->list);

	free(mc);
	*_mc = NULL;
}

lws_transport_mux_t *
lws_transport_mux_create(struct lws_context *cx, lws_transport_info_t *info,
		void *txp_handle)
{
	lws_transport_mux_t *tm = malloc(sizeof(*tm));

	if (tm) {
		memset(tm, 0, sizeof(*tm));

#if defined(_DEBUG)
		tm->magic = LWS_TRANSPORT_MUX_MAGIC;
#endif

		tm->cx		= cx;
		tm->info	= *info;
		tm->txp_handle	= txp_handle;
		tm->link_state	= LWSTM_TRANSPORT_DOWN;

		assert_is_tm(tm);

		/* let's try a ping straight off */
		if (tm->cx)
			lws_sul_schedule((struct lws_context *)tm->cx, 0,
					 &tm->sul_ping, sul_ping_cb, 1);
	}

	return tm;
}

void
lws_transport_mux_destroy(lws_transport_mux_t **tm)
{
	lws_transport_mux_ch_t *mc;

	while ((*tm)->owner.head) {
		mc = lws_container_of((*tm)->owner.head,
				      lws_transport_mux_ch_t, list);
		lws_transport_mux_destroy_channel(&mc);
	}
	free(*tm);
	*tm = NULL;
}
