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
 */

#include <private-lib-core.h>

extern int
secstream_h1(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len);

static int
secstream_h2(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	int n;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		if (h->being_serialized) {
			/*
			 * We are the proxy-side SS for a remote client... we
			 * need to inform the client about the initial tx credit
			 * to write to it that the remote h2 server set up
			 */
			lwsl_info("%s: reporting initial tx cr from server %d\n",
				  __func__, wsi->txc.tx_cr);
			ss_proxy_onward_txcr((void *)&h[1], wsi->txc.tx_cr);
		}
#endif

		n = secstream_h1(wsi, reason, user, in, len);

		if (!n && (h->policy->flags & LWSSSPOLF_LONG_POLL)) {
			lwsl_notice("%s: h2 client %p entering LONG_POLL\n",
					__func__, wsi);
			lws_h2_client_stream_long_poll_rxonly(wsi);
		}
		return n;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		// lwsl_err("%s: h2 COMPLETED_CLIENT_HTTP\n", __func__);
		h->info.rx(ss_to_userobj(h), NULL, 0, LWSSS_FLAG_EOM);
		h->wsi = NULL;
		h->txn_ok = 1;
		//bad = status != 200;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_WSI_TX_CREDIT_GET:
		/*
		 * The peer has sent us additional tx credit...
		 */
		lwsl_info("%s: LWS_CALLBACK_WSI_TX_CREDIT_GET: %d\n",
			    __func__, (int32_t)len);

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		if (h->being_serialized)
			/* we are the proxy-side SS for a remote client */
			ss_proxy_onward_txcr((void *)&h[1], (int)len);
#endif
		break;

	default:
		break;
	}

	return secstream_h1(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_secstream_h2 = {
	"lws-secstream-h2",
	secstream_h2,
	0,
	0,
};

/*
 * Munge connect info according to protocol-specific considerations... this
 * usually means interpreting aux in a protocol-specific way and using the
 * pieces at connection setup time, eg, http url pieces.
 *
 * len bytes of buf can be used for things with scope until after the actual
 * connect.
 */

int
secstream_connect_munge_h2(lws_ss_handle_t *h, char *buf, size_t len,
			   struct lws_client_connect_info *i,
			   union lws_ss_contemp *ct)
{
	if (h->policy->flags & LWSSSPOLF_QUIRK_NGHTTP2_END_STREAM)
		i->ssl_connection |= LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM;

	if (h->policy->flags & LWSSSPOLF_H2_QUIRK_OVERFLOWS_TXCR)
		i->ssl_connection |= LCCSCF_H2_QUIRK_OVERFLOWS_TXCR;

	if (h->policy->flags & LWSSSPOLF_HTTP_MULTIPART)
		i->ssl_connection |= LCCSCF_HTTP_MULTIPART_MIME;

	if (h->policy->flags & LWSSSPOLF_HTTP_X_WWW_FORM_URLENCODED)
		i->ssl_connection |= LCCSCF_HTTP_X_WWW_FORM_URLENCODED;

	i->ssl_connection |= LCCSCF_PIPELINE;

	i->alpn = "h2";

	/* initial peer tx credit */

	if (h->info.manual_initial_tx_credit) {
		i->ssl_connection |= LCCSCF_H2_MANUAL_RXFLOW;
		i->manual_initial_tx_credit = h->info.manual_initial_tx_credit;
		lwsl_info("%s: initial txcr %d\n", __func__,
				i->manual_initial_tx_credit);
	}

	if (!h->policy->u.http.url)
		return 0;

	/* protocol aux is the path part */

	i->path = buf;
	lws_snprintf(buf, len, "/%s", h->policy->u.http.url);

	return 0;
}

static int
secstream_tx_credit_add_h2(lws_ss_handle_t *h, int add)
{
	lwsl_info("%s: h %p: add %d\n", __func__, h, add);
	if (h->wsi)
		return lws_h2_update_peer_txcredit(h->wsi, LWS_H2_STREAM_SID, add);

	return 0;
}

static int
secstream_tx_credit_est_h2(lws_ss_handle_t *h)
{
	if (h->wsi) {
		lwsl_info("%s: h %p: est %d\n", __func__, h,
				lws_h2_get_peer_txcredit_estimate(h->wsi));

		return lws_h2_get_peer_txcredit_estimate(h->wsi);
	}

	lwsl_info("%s: h %p: Unknown (0)\n", __func__, h);

	return 0;
}

const struct ss_pcols ss_pcol_h2 = {
	"h2",
	NULL,
	"lws-secstream-h2",
	secstream_connect_munge_h2,
	secstream_tx_credit_add_h2,
	secstream_tx_credit_est_h2
};
