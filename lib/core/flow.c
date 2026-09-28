/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * flow.c: lws_flow, a buflist a decoder consumes as the data arrives, and,
 * when the data comes from a secure stream, asks the stream's peer for more
 * as it runs low (the tx credit it grants).  It is kept apart from the
 * buflist itself (buflist.c), which both halves of the sans-IO split use,
 * because asking for credit is a secure stream's business.
 */

#include "private-lib-core.h"

lws_stateful_ret_t
lws_flow_feed(lws_flow_t *flow)
{
	if (flow->len)
		return LWS_SRET_OK;

	if (flow->blseglen)
		lws_buflist_use_segment(&flow->bl, flow->blseglen);

	flow->len = lws_buflist_next_segment_len(&flow->bl,
						 (uint8_t **)&flow->data);
	flow->blseglen = (uint32_t)flow->len;

	return flow->len ||
	       flow->state != LWSDLOFLOW_STATE_READ ? LWS_SRET_OK :
					              LWS_SRET_WANT_INPUT;
}

lws_stateful_ret_t
lws_flow_req(lws_flow_t *flow)
{
#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	int32_t est, ask;
#endif

	lws_flow_feed(flow);

	if (!flow->h || flow->state != LWSDLOFLOW_STATE_READ)
		return LWS_SRET_OK;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS)
	if (flow->window) {
		est = lws_ss_get_est_peer_tx_credit(flow->h) +
			(int)lws_buflist_total_len(&flow->bl) -
			(int)flow->blseglen + (int)flow->len;

		if (est < flow->window) {
			ask = (int32_t)(flow->window - est);
			if (ask > (flow->window / 2) || !est)
				lws_ss_add_peer_tx_credit(flow->h, ask);
		}
	}
#endif

	return flow->len ||
	       flow->state != LWSDLOFLOW_STATE_READ ? LWS_SRET_OK :
					              LWS_SRET_WANT_INPUT;
}
