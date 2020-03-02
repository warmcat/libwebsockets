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
	size_t buflen;
	int f = 0;

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

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
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

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		/*
		 * Make sure the handle wsi points to the stream wsi not the
		 * original nwsi, in the case it was migrated
		 */
		h->wsi = wsi;
		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_ss_set_timeout_us(h, LWS_SET_TIMER_USEC_CANCEL);
		lws_ss_event_helper(h, LWSSSCS_CONNECTED);
		if (h->policy->u.mqtt.topic)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		// lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: read %d\n", (int)len);
		if (!h)
			return 0;

		pmqpp = (lws_mqtt_publish_param_t *)in;

		f = 0;
		if (!pmqpp->payload_pos)
			f |= LWSSS_FLAG_SOM;
		if (pmqpp->payload_pos + len == pmqpp->payload_len)
			f |= LWSSS_FLAG_EOM;

		h->subseq = 1;

		h->info.rx(ss_to_userobj(h), (const uint8_t *)pmqpp->payload,
			   len, f);

		return 0; /* don't passthru */

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		wsi->mqtt->done_subscribe = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_ACK:
		lws_ss_event_helper(h, LWSSSCS_QOS_ACK_REMOTE);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (!h)
			return 0;
		lwsl_notice("%s: ss %p: WRITEABLE\n", __func__, h);

		if (h->seqstate != SSSEQ_CONNECTED) {
			lwsl_warn("%s: seqstate %d\n", __func__, h->seqstate);
			break;
		}

		if (h->policy->u.mqtt.subscribe && !wsi->mqtt->done_subscribe) {

			/*
			 * The policy says to subscribe to something, and we
			 * haven't done it yet
			 */

			lwsl_warn("%s: subscribing %s\n", __func__, h->policy->u.mqtt.subscribe);

			memset(&h->u.mqtt.sub_top, 0, sizeof(h->u.mqtt.sub_top));
			h->u.mqtt.sub_top.name = h->policy->u.mqtt.subscribe;
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
		if (h->info.tx(ss_to_userobj(h),  h->txord++, buf + LWS_PRE,
				&buflen, &f))
			/* don't want to send anything */
			return 0;

		memset(&mqpp, 0, sizeof(mqpp));
		mqpp.topic = (char *)h->policy->u.mqtt.topic;
		mqpp.topic_len = strlen(mqpp.topic);
		mqpp.packet_id = h->txord - 1;
		mqpp.payload = buf + LWS_PRE;
		if (h->writeable_len)
			mqpp.payload_len = h->writeable_len;
		else
			mqpp.payload_len = buflen;

		lwsl_notice("%s: payload len %d\n", __func__, (int)mqpp.payload_len);

		mqpp.qos = h->policy->u.mqtt.qos;

		if (lws_mqtt_client_send_publish(wsi, &mqpp,
						 (const char *)buf + LWS_PRE, buflen,
						 f & LWSSS_FLAG_EOM)) {
			lwsl_notice("%s: failed to publish\n", __func__);

			return -1;
		}

		return 0;

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

static int
secstream_connect_munge_mqtt(lws_ss_handle_t *h, char *buf, size_t len,
			     struct lws_client_connect_info *i,
			     union lws_ss_contemp *ct)
{
	memset(&ct->ccp, 0, sizeof(ct->ccp));

	ct->ccp.client_id		= "lwsMqttClient";
	ct->ccp.keep_alive		= h->policy->u.mqtt.keep_alive;
	ct->ccp.clean_start		= h->policy->u.mqtt.clean_start;
	ct->ccp.will_param.topic	= h->policy->u.mqtt.will_topic;
	ct->ccp.will_param.message	= h->policy->u.mqtt.will_message;
	ct->ccp.will_param.qos		= h->policy->u.mqtt.will_qos;
	ct->ccp.will_param.retain	= h->policy->u.mqtt.will_retain;

	lwsl_notice("%s\n", __func__);

	h->u.mqtt.topic_qos.name = h->policy->u.mqtt.subscribe;
	h->u.mqtt.topic_qos.qos = h->policy->u.mqtt.qos;

	i->method = "MQTT";
	i->mqtt_cp = &ct->ccp;

	i->alpn = "x-amzn-mqtt-ca";

	/* share connections where possible */
	i->ssl_connection |= LCCSCF_PIPELINE;

/*
	if (!h->policy->u.http.url)
		return 0;

	// protocol aux is the path part ; ws subprotocol name

	i->path = NULL;
	lws_snprintf(buf, len, "/%s", h->policy->u.mqtt.topic);

//	i->protocol = h->policy->u.mqtt.u.ws.subprotocol;

	lwsl_notice("%s: url %s, ws subprotocol %s\n", __func__, buf, i->protocol);
*/
	return 0;
}

const struct ss_pcols ss_pcol_mqtt = {
	"MQTT",
	"x-amzn-mqtt-ca", //"mqtt/3.1.1",
	"lws-secstream-mqtt",
	secstream_connect_munge_mqtt
};
