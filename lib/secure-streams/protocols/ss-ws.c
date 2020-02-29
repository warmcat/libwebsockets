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

static int
secstream_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1400];
	size_t buflen;
	int f = 0, f1;

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_info("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (char *)in : "(null)");
		if (!h)
			break;
		lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		h->wsi = NULL;
		lws_ss_backoff(h);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		if (!h)
			break;
		f = lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
		if (h->wsi)
			lws_set_opaque_user_data(h->wsi, NULL);
		h->wsi = NULL;

		if (f) {
			lws_ss_destroy(&h);
			break;
		}

		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
		    !h->txn_ok && !wsi->context->being_destroyed)
			lws_ss_backoff(h);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_ss_set_timeout_us(h, LWS_SET_TIMER_USEC_CANCEL);
		lws_ss_event_helper(h, LWSSSCS_CONNECTED);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		// lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: read %d\n", (int)len);
		if (!h)
			return 0;
		if (lws_is_first_fragment(wsi))
			f |= LWSSS_FLAG_SOM;
		if (lws_is_final_fragment(wsi))
			f |= LWSSS_FLAG_EOM;
		// lws_frame_is_binary(wsi);

		h->subseq = 1;

		h->info.rx(ss_to_userobj(h), (const uint8_t *)in, len, f);

		return 0; /* don't passthru */

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (!h)
			return 0;
		// lwsl_notice("%s: ss %p: WRITEABLE\n", __func__, h);

		if (h->seqstate != SSSEQ_CONNECTED) {
			lwsl_warn("%s: seqstate %d\n", __func__, h->seqstate);
			break;
		}

		buflen = sizeof(buf) - LWS_PRE;
		if (h->info.tx(ss_to_userobj(h),  h->txord++, buf + LWS_PRE,
				&buflen, &f))
			/* don't want to send anything */
			return 0;

		f1 = lws_write_ws_flags(LWS_WRITE_BINARY,
					!!(f & LWSSS_FLAG_SOM),
					!!(f & LWSSS_FLAG_EOM));

		if (lws_write(wsi, buf + LWS_PRE, buflen, f1) != (int)buflen) {
			lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_secstream_ws = {
	"lws-secstream-ws",
	secstream_ws,
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
 *
 * For ws, protocol aux is <url path>;<ws subprotocol name>
 */

static int
secstream_connect_munge_ws(lws_ss_handle_t *h, char *buf, size_t len,
			   struct lws_client_connect_info *i,
			   union lws_ss_contemp *ct)
{
	lwsl_notice("%s\n", __func__);

	if (!h->policy->u.http.url)
		return 0;

	/* protocol aux is the path part ; ws subprotocol name */

	i->path = h->policy->u.http.url;
	lws_snprintf(buf, len, "/%s", h->policy->u.http.url);

	i->protocol = h->policy->u.http.u.ws.subprotocol;

	lwsl_notice("%s: url %s, ws subprotocol %s\n", __func__, buf, i->protocol);

	return 0;
}

const struct ss_pcols ss_pcol_ws = {
	"ws",  "http/1.1",  "lws-secstream-ws", secstream_connect_munge_ws
};
