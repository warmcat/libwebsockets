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
 * This is the glue that wires up raw-socket to Secure Streams.
 */

#include <private-lib-core.h>

int
secstream_raw(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1520], *p = &buf[LWS_PRE],
		*end = &buf[sizeof(buf) - 1];
	size_t buflen;
	int f = 0;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		assert(h);
		assert(h->policy);
		lwsl_info("%s: h: %p, %s CLIENT_CONNECTION_ERROR: %s\n", __func__,
			  h, h->policy->streamtype, in ? (char *)in : "(null)");
		lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		h->wsi = NULL;
		lws_ss_backoff(h);
		/* may have been destroyed */
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!h)
			break;
		lws_sul_cancel(&h->sul_timeout);
		lwsl_info("%s: h: %p, %s LWS_CALLBACK_CLOSED_CLIENT_HTTP\n",
			  __func__, h,
			  h->policy ? h->policy->streamtype : "no policy");
		h->wsi = NULL;
		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
		    !h->txn_ok && !wsi->a.context->being_destroyed)
			if (lws_ss_backoff(h))
				/* has been destroyed */
				break;
		/* wsi is going down anyway */
		lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_info("%s: RAW_CONNECTED\n", __func__);

		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_sul_cancel(&h->sul);
		lws_ss_event_helper(h, LWSSSCS_CONNECTED);

		lws_validity_confirmed(wsi);
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RAW_RX:
		if (!h || !h->info.rx)
			return 0;

		if (h->info.rx(ss_to_userobj(h), (const uint8_t *)in, len, 0) < 0)
			return -1;

		return 0; /* don't passthru */

	case LWS_CALLBACK_RAW_WRITEABLE:
		lwsl_info("%s: RAW_WRITEABLE\n", __func__);
		if (!h || !h->info.tx)
			return 0;

		buflen = lws_ptr_diff(end, p);
		switch(h->info.tx(ss_to_userobj(h),  h->txord++, p, &buflen, &f)) {
		case LWSSSSRET_DISCONNECT_ME:
			lwsl_debug("%s: tx handler asked to close conn\n", __func__);
			return -1; /* close connection */

		case LWSSSSRET_DESTROY_ME:
			lws_set_opaque_user_data(wsi, NULL);
			h->wsi = NULL;
			lws_ss_destroy(&h);
			return -1; /* close connection */

		case LWSSSSRET_TX_DONT_SEND:
			/* don't want to send anything */
			lwsl_debug("%s: dont want to write\n", __func__);
			return 0;
		default:
			break;
		}

		/*
		 * flags are ignored with raw, there are no protocol payload
		 * boundaries, just an arbitrarily-fragmented bytestream
		 */

		p += buflen;
		if (lws_write(wsi, buf + LWS_PRE, lws_ptr_diff(p, buf + LWS_PRE),
			 LWS_WRITE_HTTP) != (int)lws_ptr_diff(p, buf + LWS_PRE)) {
			lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

		lws_set_timeout(wsi, 0, 0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
secstream_connect_munge_raw(lws_ss_handle_t *h, char *buf, size_t len,
			   struct lws_client_connect_info *i,
			   union lws_ss_contemp *ct)
{
	i->method = "RAW";

	return 0;
}


const struct lws_protocols protocol_secstream_raw = {
	"lws-secstream-raw",
	secstream_raw,
	0,
	0,
};

const struct ss_pcols ss_pcol_raw = {
	"raw",
	"",
	"lws-secstream-raw",
	secstream_connect_munge_raw,
	NULL
};
