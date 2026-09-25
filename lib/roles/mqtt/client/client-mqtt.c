/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

/*
 * You can leave buf NULL, if so it will be allocated on the heap once the
 * actual length is known.  nf should be 0, it will be set at allocation time.
 *
 * Or you can ensure no allocation and use an external buffer by setting buf
 * and lim.  But buf must be in the ep context somehow, since it may have to
 * survive returns to the event loop unchanged.  Set nf to 0 in this case.
 *
 * Or you can set buf to an externally allocated buffer, in which case you may
 * set nf so it will be freed when the string is "freed".
 */

#include "private-lib-core.h"
/* #include "lws-mqtt.h" */
/* 3.1.3.1-5: MUST allow... that contain only the characters... */

static const uint8_t *code = (const uint8_t *)
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static int
lws_mqtt_generate_id(struct lws* wsi, lws_mqtt_str_t **ms, const char *client_id)
{
	struct lws_context *context = wsi->a.context;
	uint16_t ran[24]; /* 16-bit so wrap bias from %62 diluted by ~1000 */
	size_t n, len;
	uint8_t *buf;

	if (client_id)
		len = strlen(client_id);
	else
		len = LWS_MQTT_RANDOM_CIDLEN;

	/*
	 * The allocation below is sized by a uint16_t, but the copy after it
	 * uses the full size_t len; if (len + 1) wrapped we would allocate a
	 * couple of bytes and then copy the whole client id into them.
	 */
	if (len > 0xfffe) {
		lwsl_err("%s: client ID too long (%u)\n", __func__,
			 (unsigned int)len);

		return 1;
	}

	*ms = lws_mqtt_str_create((uint16_t)(len + 1));
	if (!*ms)
		return 1;

	buf = lws_mqtt_str_next(*ms, NULL);

	if (client_id) {
		lws_strnncpy((char *)buf, client_id, len, len + 1);
		lwsl_notice("%s: User space provided a client ID '%s'\n",
			    __func__, (const char *)buf);
	} else {
		lwsl_notice("%s: generating random client id\n", __func__);
		n = len * sizeof(ran[0]);
		if (lws_get_random(context, ran, n) != n) {
			lws_mqtt_str_free(ms);

			return 1;
		}

		for (n = 0; n < len; n++)
			buf[n] = code[ran[n] % 62];
		buf[len] = '\0';
	}

	if (lws_mqtt_str_advance(*ms, (uint16_t)len)) {
		lws_mqtt_str_free(ms);

		return 1;
	}

	return 0;
}

int
lws_read_mqtt(struct lws *wsi, unsigned char *buf, lws_filepos_t len)
{
	lws_mqttc_t *c = &wsi->mqtt->client;

	return _lws_mqtt_rx_parser(wsi, &c->par, buf, (size_t)len);
}

int
lws_create_client_mqtt_object(const struct lws_client_connect_info *i,
			      struct lws *wsi)
{
	lws_mqttc_t *c;
	const lws_mqtt_client_connect_param_t *cp = i->mqtt_cp;

	/* allocate the ws struct for the wsi */
	wsi->mqtt = lws_zalloc(sizeof(*wsi->mqtt), "client mqtt struct");
	if (!wsi->mqtt)
		goto oom;

	wsi->mqtt->wsi = wsi;
	c = &wsi->mqtt->client;

	if (lws_mqtt_generate_id(wsi, &c->id, cp->client_id)) {
		lwsl_err("%s: Error generating client ID\n", __func__);
		goto oom1;
	}
	lwsl_info("%s: using client id '%.*s'\n", __func__, c->id->len,
			(const char *)c->id->buf);

	if (cp->clean_start || !(cp->client_id &&
				 cp->client_id[0]))
		c->conn_flags = LMQCFT_CLEAN_START;
	if (cp->client_id_nofree)
		c->conn_flags |= LMQCFT_CLIENT_ID_NOFREE;
	if (cp->username_nofree)
		c->conn_flags |= LMQCFT_USERNAME_NOFREE;
	if (cp->password_nofree)
		c->conn_flags |= LMQCFT_PASSWORD_NOFREE;

	if (!(c->conn_flags & LMQCFT_CLIENT_ID_NOFREE))
		lws_free((void *)cp->client_id);

	c->keep_alive_secs = cp->keep_alive;
	c->qos2_state_ops = cp->qos2_state_ops;
	c->aws_iot = cp->aws_iot;

	if (cp->will_param.topic &&
	    *cp->will_param.topic) {
		c->will.topic = lws_mqtt_str_create_cstr_dup(
						cp->will_param.topic, 0);
		if (!c->will.topic)
			goto oom1;
		c->conn_flags |= LMQCFT_WILL_FLAG;
		if (cp->will_param.message) {
			c->will.message = lws_mqtt_str_create_cstr_dup(
						cp->will_param.message, 0);
			if (!c->will.message)
				goto oom2;
		}
		c->conn_flags = (uint16_t)(unsigned int)(c->conn_flags | ((cp->will_param.qos << 3) & LMQCFT_WILL_QOS_MASK));
		c->conn_flags |= (uint16_t)((!!cp->will_param.retain) * LMQCFT_WILL_RETAIN);
	}

	if (cp->username &&
	    *cp->username) {
		c->username = lws_mqtt_str_create_cstr_dup(cp->username, 0);
		if (!c->username)
			goto oom3;
		c->conn_flags |= LMQCFT_USERNAME;
		if (!(c->conn_flags & LMQCFT_USERNAME_NOFREE))
			lws_free((void *)cp->username);
		if (cp->password) {
			c->password =
				lws_mqtt_str_create_cstr_dup(cp->password, 0);
			if (!c->password)
				goto oom4;
			c->conn_flags |= LMQCFT_PASSWORD;
			if (!(c->conn_flags & LMQCFT_PASSWORD_NOFREE))
				lws_free((void *)cp->password);
		}
	}

	return 0;
oom4:
	lws_mqtt_str_free(&c->username);
oom3:
	lws_mqtt_str_free(&c->will.message);
oom2:
	lws_mqtt_str_free(&c->will.topic);
oom1:
	lws_mqtt_str_free(&c->id);

	/*
	 * We allocated wsi->mqtt, and on this path the wsi will not be
	 * transitioned into the mqtt role, so no close_role will come along
	 * later to free it... clean up after ourselves.
	 */
	lws_free_set_NULL(wsi->mqtt);
oom:
	lwsl_err("%s: OOM!\n", __func__);
	return 1;
}

/*
 * The CONNACK did not come, or said no: tell the user why, as a connection
 * failure, and close.  The parser may have replaced or removed wsi->mqtt on
 * its way out: at CONNACK the struct holding the client id is handed to the
 * new sid 1 child and we get a fresh, zeroed one instead (or, if that
 * allocation failed, none at all).  So neither wsi->mqtt nor c->id may be
 * assumed here.
 */
int
lws_mqtt_client_connack_failed(struct lws *wsi)
{
	int n;

	lws_mqttc_t *c = wsi->mqtt ? &wsi->mqtt->client : NULL;
	char msg[128];

	switch (c ? c->par.reason : LMQCP_REASON_PROTOCOL_ERROR) {
	case LMQCP_REASON_UNSUPPORTED_PROTOCOL:
		n = lws_snprintf(msg, sizeof(msg), "reason: server does not support MQTT protocol " MQTT_VER_STRING "\n");
		break;
	case LMQCP_REASON_CLIENT_ID_INVALID:
		if (c && c->id)
			n = lws_snprintf(msg, sizeof(msg), "reason: server does not accept client ID %.*s\n", c->id->len, c->id->buf);
		else
			n = lws_snprintf(msg, sizeof(msg), "reason: server does not accept client ID\n");
		break;
	case LMQCP_REASON_BAD_CREDENTIALS:
		n = lws_snprintf(msg, sizeof(msg), "reason: invalid credentials\n");
		break;
	case LMQCP_REASON_NOT_AUTHORIZED:
		n = lws_snprintf(msg, sizeof(msg), "reason: not authorized\n");
		break;
	default:
		n = lws_snprintf(msg, sizeof(msg), "reason: unknown MQTT connection failure\n");
		break;
	}

	lws_inform_client_conn_fail(wsi, (void *)msg, (size_t)n);
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, __func__);

	return LWS_RX_DIED;
}

#if defined(LWS_WITH_SOCKS5)
/*
 * sansIO rx while the socks5 leg is outstanding.  When the tunnel comes up
 * the connection goes on as a direct one does: tls first if that was asked
 * for, else the transport is up and the CONNECT is due.
 */
int
lws_mqtt_client_socks_rx(struct lws *wsi, const uint8_t *buf, size_t len)
{
	const char *cce = NULL;
	size_t used;

	switch (lws_socks5c_rx(wsi, buf, len, &cce, &used)) {
	case LW5CHS_RET_BAIL3:
		goto bail;
	case LW5CHS_RET_STARTHS:
		/*
		 * The tunnel is up: IO goes on from here as for a direct
		 * connection (tls if asked for, then our transport_up)
		 */
		if (lws_client_transport_connected(wsi))
			return LWS_RX_DIED;
		break;
	default:
		break;
	}

	/* what followed the reply is the broker's, left for the protocol */
	return (int)used;

bail:
	lwsl_wsi_info(wsi, "socks leg failed: %s", cce);
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cbail3");

	return LWS_RX_DIED;
}
#endif

