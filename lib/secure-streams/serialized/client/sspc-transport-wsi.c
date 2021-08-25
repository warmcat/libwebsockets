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
 * Client SSPC where the connectivity is implemented by a wsi
 */

#include <private-lib-core.h>

static int
lws_sss_transport_wsi_cb(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	lws_sspc_handle_t *h = (lws_sspc_handle_t *)lws_get_opaque_user_data(wsi);
	size_t pktsize = wsi->a.context->max_http_header_data;
	lws_ss_state_return_t r;

	switch (reason) {

	case LWS_CALLBACK_CONNECTING:
		/*
		 * In our particular case, we want CCEs even inside the
		 * initial connect loop time
		 */
		wsi->client_suppress_CONNECTION_ERROR = 0;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_warn("%s: CCE: %s\n", __func__,
			  in ? (const char *)in : "null");
#if defined(LWS_WITH_SYS_METRICS)
		/*
		 * If any hanging caliper measurement, dump it, and free
		 * any tags
		 */
		lws_metrics_caliper_report_hist(h->cal_txn, (struct lws *)NULL);
#endif
		lws_set_opaque_user_data(wsi, NULL);
		h->txp_path.ops_in->event_connect_disposition(h, 1);
		break;

        case LWS_CALLBACK_RAW_CONNECTED:
        	lwsl_user("%s: CONNECTED\n", __func__);
        	if (h->txp_path.ops_in->event_connect_disposition(h, 0))
        		return -1;
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
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		/*
		 * our ss proxy Unix Domain socket has closed...
		 */
		lwsl_sspc_info(h, "LWS_CALLBACK_RAW_CLOSE: proxy conn down, wsi %s",
				lws_wsi_tag(wsi));

		if (h) {
			r = h->txp_path.ops_in->event_closed(h);
			h->txp_path.priv_in = NULL;
			if (r == LWSSSSRET_DESTROY_ME) {
				lws_set_opaque_user_data(wsi, NULL);
				lws_sspc_destroy(&h);
			}
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		/*
		 * ie, the proxy has sent us something
		 */

		if (!h || !h->txp_path.priv_in) {
			lwsl_info("%s: rx when client ss destroyed\n", __func__);

			return -1;
		}

		lwsl_sspc_info(h, "%s: RAW_RX: rx %d\n", __func__, (int)len);

		if (!len) {
			lwsl_sspc_notice(h, "RAW_RX: zero len");

			return -1;
		}

		r = h->txp_path.ops_in->event_read((lws_transport_priv_t)h,
						   (const uint8_t *)in, len);

		switch (r) {
		default:
			break;
		case LWSSSSRET_DISCONNECT_ME:
			lwsl_info("%s: proxlicent RX ended with DISCONNECT_ME\n",
					__func__);
			return -1;
		case LWSSSSRET_DESTROY_ME:
			lwsl_info("%s: proxlicent RX ended with DESTROY_ME\n",
					__func__);
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

		lwsl_sspc_debug(h, "WRITEABLE %s, state %d",
				wsi->lc.gutag, h->state);

		if (h->txp_path.ops_in->event_can_write(h, pktsize))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols lws_sspc_protocols[] = {
	{
		"ssproxy-protocol",
		lws_sss_transport_wsi_cb,
		0,
		2048, 2048, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/*
 * lws_sss_transport ops for wsi transport
 */

static int
lws_sss_transport_wsi_retry_connect(lws_txp_path_client_t *path, lws_sspc_handle_t *h)
{
	struct lws_client_connect_info i;

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

	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "RAW";
	i.protocol		= lws_sspc_protocols[0].name;
	i.local_protocol_name	= lws_sspc_protocols[0].name;
	i.path			= "";
	i.pwsi			= (struct lws **)&h->txp_path.priv_onw;
	i.opaque_user_data	= (void *)h;
	i.ssl_connection	= LCCSCF_SECSTREAM_PROXY_LINK;

	lws_metrics_caliper_bind(h->cal_txn, h->context->mt_ss_cliprox_conn);
#if defined(LWS_WITH_SYS_METRICS)
	lws_metrics_tag_add(&h->cal_txn.mtags_owner, "ss", h->ssi.streamtype);
#endif

	/* this wsi is the link to the proxy */

	if (!lws_client_connect_via_info(&i)) {

#if defined(LWS_WITH_SYS_METRICS)
		/*
		 * If any hanging caliper measurement, dump it, and free any tags
		 */
		lws_metrics_caliper_report_hist(h->cal_txn, (struct lws *)NULL);
#endif

		return 1; /* going to need to retry */
	}

	lwsl_sspc_notice(h, "%s", ((struct lws *)(h->txp_path.priv_onw))->lc.gutag);

	return 0; /* in progress */
}

static void
lws_sss_transport_wsi_req_write(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	if (wsi)
		lws_callback_on_writable(wsi);
}

static int
lws_sss_transport_wsi_write(lws_transport_priv_t priv, uint8_t *buf, size_t len)
{
	struct lws *wsi = (struct lws *)priv;

	if (lws_write(wsi, buf, len, LWS_WRITE_RAW) != (ssize_t)len) {
		lwsl_wsi_notice(wsi, "failed");

		return -1;
	}

	return 0;
}

static void
lws_sss_transport_wsi_close(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	if (!wsi)
		return;

	lws_set_opaque_user_data(wsi, NULL);
	lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
}

static void
lws_sss_transport_wsi_stream_up(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
}

const lws_transport_client_ops_t txp_ops_sspc_wsi = {
	.name			= "txp_sspc_wsi",
	.event_retry_connect	= lws_sss_transport_wsi_retry_connect,
	.req_write		= lws_sss_transport_wsi_req_write,
	._write			= lws_sss_transport_wsi_write,
	._close			= lws_sss_transport_wsi_close,
	.event_stream_up	= lws_sss_transport_wsi_stream_up,
	.dsh_splitat		= 1300,
};
