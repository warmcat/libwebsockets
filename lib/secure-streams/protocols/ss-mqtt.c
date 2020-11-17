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
secstream_mqtt(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	lws_mqtt_publish_param_t mqpp, *pmqpp;
	uint8_t buf[LWS_PRE + 1400];
	lws_ss_state_return_t r;
	size_t buflen;
	int f = 0;

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_info("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (char *)in : "(null)");
		if (!h)
			break;
		r = lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		h->wsi = NULL;

		if (h->u.mqtt.heap_baggage) {
			lws_free(h->u.mqtt.heap_baggage);
			h->u.mqtt.heap_baggage = NULL;
		}

		if (r == LWSSSSRET_DESTROY_ME)
			return _lws_ss_handle_state_ret(r, wsi, &h);

		r = lws_ss_backoff(h);
		if (r != LWSSSSRET_OK)
			return _lws_ss_handle_state_ret(r, wsi, &h);

		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		if (!h)
			break;
		lws_sul_cancel(&h->sul_timeout);
		r= lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
		if (h->wsi)
			lws_set_opaque_user_data(h->wsi, NULL);
		h->wsi = NULL;

		if (h->u.mqtt.heap_baggage) {
			lws_free(h->u.mqtt.heap_baggage);
			h->u.mqtt.heap_baggage = NULL;
		}

		if (r)
			return _lws_ss_handle_state_ret(r, wsi, &h);

		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
		    !h->txn_ok && !wsi->a.context->being_destroyed) {
			r = lws_ss_backoff(h);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret(r, wsi, &h);
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		/*
		 * Make sure the handle wsi points to the stream wsi not the
		 * original nwsi, in the case it was migrated
		 */
		h->wsi = wsi;
		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_sul_cancel(&h->sul);
		r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
		if (r != LWSSSSRET_OK)
			return _lws_ss_handle_state_ret(r, wsi, &h);
		if (h->policy->u.mqtt.topic)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		// lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: read %d\n", (int)len);
		if (!h || !h->info.rx)
			return 0;

		pmqpp = (lws_mqtt_publish_param_t *)in;

		f = 0;
		if (!pmqpp->payload_pos)
			f |= LWSSS_FLAG_SOM;
		if (pmqpp->payload_pos + len == pmqpp->payload_len)
			f |= LWSSS_FLAG_EOM;

		h->subseq = 1;

		r = h->info.rx(ss_to_userobj(h), (const uint8_t *)pmqpp->payload,
			   len, f);
		if (r != LWSSSSRET_OK)
			return _lws_ss_handle_state_ret(r, wsi, &h);

		return 0; /* don't passthru */

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		wsi->mqtt->done_subscribe = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_ACK:
		lws_sul_cancel(&h->sul_timeout);
		r = lws_ss_event_helper(h, LWSSSCS_QOS_ACK_REMOTE);
		if (r != LWSSSSRET_OK)
			return _lws_ss_handle_state_ret(r, wsi, &h);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
	{
		size_t used_in, used_out;
		lws_strexp_t exp;
		char expbuf[128];

		if (!h || !h->info.tx)
			return 0;
		lwsl_notice("%s: ss %p: WRITEABLE\n", __func__, h);

		if (h->seqstate != SSSEQ_CONNECTED) {
			lwsl_warn("%s: seqstate %d\n", __func__, h->seqstate);
			break;
		}

		if (h->policy->u.mqtt.subscribe &&
		    !wsi->mqtt->done_subscribe) {
			lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata, expbuf, sizeof(expbuf));

			if (lws_strexp_expand(&exp, h->policy->u.mqtt.subscribe,
					      strlen(h->policy->u.mqtt.subscribe),
					      &used_in, &used_out) != LSTRX_DONE)
				return 1;
			lwsl_notice("%s, expbuf - %s\n", __func__, expbuf);
			h->u.mqtt.sub_top.name = expbuf;

			/*
			 * The policy says to subscribe to something, and we
			 * haven't done it yet.  Do it using the pre-prepared
			 * string-substituted version of the policy string.
			 */

			lwsl_notice("%s: subscribing %s\n", __func__,
				                h->u.mqtt.sub_top.name);

			h->u.mqtt.sub_top.qos = h->policy->u.mqtt.qos;
			memset(&h->u.mqtt.sub_info, 0, sizeof(h->u.mqtt.sub_info));
			h->u.mqtt.sub_info.num_topics = 1;
			h->u.mqtt.sub_info.topic = &h->u.mqtt.sub_top;

			if (lws_mqtt_client_send_subcribe(wsi, &h->u.mqtt.sub_info)) {
				lwsl_notice("%s: unable to subscribe", __func__);
				return -1;
			}

			return 0;
		}


		buflen = sizeof(buf) - LWS_PRE;
		r = h->info.tx(ss_to_userobj(h),  h->txord++,  buf + LWS_PRE,
				  &buflen, &f);
		if (r == LWSSSSRET_TX_DONT_SEND)
			return 0;

		if (r < 0)
			return _lws_ss_handle_state_ret(r, wsi, &h);

		memset(&mqpp, 0, sizeof(mqpp));
		/* this is the string-substituted h->policy->u.mqtt.topic */
		mqpp.topic = (char *)h->u.mqtt.topic_qos.name;
		lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata, expbuf, sizeof(expbuf));

		if (lws_strexp_expand(&exp, h->policy->u.mqtt.topic,
				      strlen(h->policy->u.mqtt.topic),
				      &used_in, &used_out) != LSTRX_DONE)
			return 1;
		lwsl_notice("%s, expbuf - %s\n", __func__, expbuf);
		mqpp.topic = (char *)expbuf;

		mqpp.topic_len = strlen(mqpp.topic);
		mqpp.packet_id = h->txord - 1;
		mqpp.payload = buf + LWS_PRE;
		if (h->writeable_len)
			mqpp.payload_len = h->writeable_len;
		else
			mqpp.payload_len = buflen;

		lwsl_notice("%s: payload len %d\n", __func__,
				(int)mqpp.payload_len);

		mqpp.qos = h->policy->u.mqtt.qos;

		if (lws_mqtt_client_send_publish(wsi, &mqpp,
						 (const char *)buf + LWS_PRE, buflen,
						 f & LWSSS_FLAG_EOM)) {
			lwsl_notice("%s: failed to publish\n", __func__);

			return -1;
		}

		return 0;
	}
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_secstream_mqtt = {
	"lws-secstream-mqtt",
	secstream_mqtt,
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

enum {
	SSCMM_STRSUB_WILL_TOPIC,
	SSCMM_STRSUB_WILL_MESSAGE,
	SSCMM_STRSUB_SUBSCRIBE,
	SSCMM_STRSUB_TOPIC
};

static int
secstream_connect_munge_mqtt(lws_ss_handle_t *h, char *buf, size_t len,
			     struct lws_client_connect_info *i,
			     union lws_ss_contemp *ct)
{
	const char *sources[4] = {
		/* we're going to string-substitute these before use */
		h->policy->u.mqtt.will_topic,
		h->policy->u.mqtt.will_message,
		h->policy->u.mqtt.subscribe,
		h->policy->u.mqtt.topic
	};
	size_t used_in, olen[4] = { 0, 0, 0, 0 }, tot = 0;
	lws_strexp_t exp;
	char *ps[4];
	uint8_t *p = NULL;
	int n = -1;
	size_t blen;
	lws_system_blob_t *b = NULL;

	memset(&ct->ccp, 0, sizeof(ct->ccp));
	b = lws_system_get_blob(i->context,
				LWS_SYSBLOB_TYPE_MQTT_CLIENT_ID, 0);

	/* If LWS_SYSBLOB_TYPE_MQTT_CLIENT_ID is set */
	if (b && (blen = lws_system_blob_get_size(b))) {
		if (blen > LWS_MQTT_MAX_CIDLEN) {
			lwsl_err("%s - Client ID too long.\n",
				 __func__);
			return -1;
		}
		p = (uint8_t *)lws_zalloc(blen+1, __func__);
		n = lws_system_blob_get(b, p, &blen, 0);
		if (n) {
			ct->ccp.client_id = NULL;
		} else {
			ct->ccp.client_id = (const char *)p;
			lwsl_notice("%s - Client ID = %s\n",
				    __func__, ct->ccp.client_id);
		}
	} else {
		/* Default (Random) client ID */
		ct->ccp.client_id = NULL;
	}

	b = lws_system_get_blob(i->context,
				LWS_SYSBLOB_TYPE_MQTT_USERNAME, 0);

	/* If LWS_SYSBLOB_TYPE_MQTT_USERNAME is set */
	if (b && (blen = lws_system_blob_get_size(b))) {
		p = (uint8_t *)lws_zalloc(blen+1, __func__);
		n = lws_system_blob_get(b, p, &blen, 0);
		if (n) {
			ct->ccp.username = NULL;
		} else {
			ct->ccp.username = (const char *)p;
			lwsl_notice("%s - Username ID = %s\n",
				    __func__, ct->ccp.username);
		}
	}

	b = lws_system_get_blob(i->context,
				LWS_SYSBLOB_TYPE_MQTT_PASSWORD, 0);

	/* If LWS_SYSBLOB_TYPE_MQTT_PASSWORD is set */
	if (b && (blen = lws_system_blob_get_size(b))) {
		p = (uint8_t *)lws_zalloc(blen+1, __func__);
		n = lws_system_blob_get(b, p, &blen, 0);
		if (n) {
			ct->ccp.password = NULL;
		} else {
			ct->ccp.password = (const char *)p;
			lwsl_notice("%s - Password ID = %s\n",
				    __func__, ct->ccp.password);
		}
	}

	ct->ccp.keep_alive		= h->policy->u.mqtt.keep_alive;
	ct->ccp.clean_start		= h->policy->u.mqtt.clean_start;
	ct->ccp.will_param.qos		= h->policy->u.mqtt.will_qos;
	ct->ccp.will_param.retain	= h->policy->u.mqtt.will_retain;
	h->u.mqtt.topic_qos.qos		= h->policy->u.mqtt.qos;

	/*
	 * We're going to string-substitute several of these parameters, which
	 * have unknown, possibly large size.  And, as their usage is deferred
	 * inside the asynchronous lifetime of the MQTT connection, they need
	 * to live on the heap.
	 *
	 * Notice these allocations at h->u.mqtt.heap_baggage belong to the
	 * underlying MQTT stream lifetime, not the logical SS lifetime, and
	 * are destroyed if present at connection error or close of the
	 * underlying connection.
	 *
	 *
	 * First, compute the length of each without producing strsubst output,
	 * and keep a running total.
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(sources); n++) {
		lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata,
				NULL, (size_t)-1);
		if (lws_strexp_expand(&exp, sources[n], strlen(sources[n]),
				      &used_in, &olen[n]) != LSTRX_DONE) {
			lwsl_err("%s: failed to subsitute %s\n", __func__,
					sources[n]);
			return 1;
		}
		tot += olen[n] + 1;
	}

	/*
	 * Then, allocate enough space on the heap for the total of the
	 * substituted results
	 */

	h->u.mqtt.heap_baggage = lws_malloc(tot, __func__);
	if (!h->u.mqtt.heap_baggage)
		return 1;

	/*
	 * Finally, issue the subsitutions one after the other into the single
	 * allocated result buffer and prepare pointers into them
	 */

	p = h->u.mqtt.heap_baggage;
	for (n = 0; n < (int)LWS_ARRAY_SIZE(sources); n++) {
		lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata,
				(char *)p, (size_t)-1);
		ps[n] = (char *)p;
		if (lws_strexp_expand(&exp, sources[n], strlen(sources[n]),
				      &used_in, &olen[n]) != LSTRX_DONE)
			return 1;

		p += olen[n] + 1;
	}

	/*
	 * Point the guys who want the substituted content at the substituted
	 * strings
	 */

	ct->ccp.will_param.topic	= ps[SSCMM_STRSUB_WILL_TOPIC];
	ct->ccp.will_param.message	= ps[SSCMM_STRSUB_WILL_MESSAGE];
	h->u.mqtt.subscribe_to		= ps[SSCMM_STRSUB_SUBSCRIBE];
	h->u.mqtt.subscribe_to_len	= olen[SSCMM_STRSUB_SUBSCRIBE];
	h->u.mqtt.topic_qos.name	= ps[SSCMM_STRSUB_TOPIC];

	i->method = "MQTT";
	i->mqtt_cp = &ct->ccp;

	i->alpn = "x-amzn-mqtt-ca";

	/* share connections where possible */
	i->ssl_connection |= LCCSCF_PIPELINE;

	return 0;
}

const struct ss_pcols ss_pcol_mqtt = {
	"MQTT",
	"x-amzn-mqtt-ca", //"mqtt/3.1.1",
	&protocol_secstream_mqtt,
	secstream_connect_munge_mqtt
};
