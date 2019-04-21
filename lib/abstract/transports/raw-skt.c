/*
 * libwebsockets lib/abstruct/transports/raw-skt.c
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"
#include "abstract/private.h"

typedef struct lws_atrs_priv {
	struct lws_abstract *abs;
	struct lws *wsi;
	void *user;

	lws_dll2_t same_abs_transport_list;

	uint8_t established:1;
	uint8_t connecting:1;
} lws_atrs_priv_t;

struct vhd {
	lws_dll2_owner_t owner;
};

static int
heartbeat_cb(struct lws_dll2 *d, void *user)
{
	lws_atrs_priv_t *priv = lws_container_of(d, lws_atrs_priv_t,
						 same_abs_transport_list);
	if (priv->abs->heartbeat)
		priv->abs->heartbeat(priv->user);

	return 0;
}

static int
callback_abs_client_raw_skt(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)user;
	struct vhd *vhd = (struct vhd *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					 lws_get_protocol(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd));
		if (!vhd)
			return 1;
		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 1);
		break;

	case LWS_CALLBACK_USER:
		/*
		 * This comes at 1Hz without a wsi context, so there is no
		 * valid priv.  We need to track the live abstract objects that
		 * are using our abstract protocol, and pass the heartbeat
		 * through to the ones that care.
		 */
		if (!vhd)
			break;

		lws_dll2_foreach_safe(&vhd->owner, NULL, heartbeat_cb);

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 1);
		break;

        case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_debug("LWS_CALLBACK_RAW_CONNECTED\n");
		priv->connecting = 0;
		priv->established = 1;
		if (priv->abs->accept)
			priv->abs->accept(priv->user);
                break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("CONNECTION_ERROR\n");
		if (in)
			lwsl_user("   %s\n", (const char *)in);

		/* fallthru */
	case LWS_CALLBACK_RAW_CLOSE:
		if (!user)
			break;
		lwsl_debug("LWS_CALLBACK_RAW_CLOSE\n");
		priv->established = 0;
		priv->connecting = 0;
		if (priv->abs && priv->abs->closed)
			priv->abs->closed(priv->user);
		lws_free(priv);
		lws_set_wsi_user(wsi, NULL);
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_debug("LWS_CALLBACK_RAW_RX (%d)\n", (int)len);
		return !!priv->abs->rx(priv->user, in, len);

	case LWS_CALLBACK_RAW_WRITEABLE:
		lwsl_debug("LWS_CALLBACK_RAW_WRITEABLE\n");
		priv->abs->writeable(priv->user,
				lws_get_peer_write_allowance(priv->wsi));
		break;

	case LWS_CALLBACK_RAW_SKT_BIND_PROTOCOL:
		lws_dll2_add_tail(&priv->same_abs_transport_list, &vhd->owner);
		break;

	case LWS_CALLBACK_RAW_SKT_DROP_PROTOCOL:
		lws_dll2_remove(&priv->same_abs_transport_list);
		break;

	default:
		break;
	}

	return 0;
}

const struct lws_protocols protocol_abs_client_raw_skt = {
	"lws-abs-cli-raw-skt", callback_abs_client_raw_skt,
	0, 1024, 1024, NULL, 0
};

static int
lws_atcrs_tx(lws_abs_user_t *abs_priv, uint8_t *buf, size_t len)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)abs_priv;

	if (!priv->wsi) {
		lwsl_err("%s: NULL priv->wsi\n", __func__);
		return 1;
	}

	lwsl_debug("%s: priv %p, wsi %p, ro %p\n", __func__,
			priv, priv->wsi, priv->wsi->role_ops);

	if (lws_write(priv->wsi, buf, len, LWS_WRITE_RAW) < 0)
		priv->abs->close(priv->user);

	return 0;
}

#if !defined(LWS_WITHOUT_CLIENT)
static int
lws_atcrs_client_conn(lws_abs_user_t *abs_priv, struct lws_vhost *vh,
		      const char *ip, uint16_t port, int tls_flags)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)abs_priv;
	struct lws_client_connect_info i;

	if (priv->connecting)
		return 0;

	if (priv->established) {
		lws_set_timeout(priv->wsi, PENDING_TIMEOUT_CLIENT_CONN_IDLE, 5);

		return 0;
	}

	lwsl_debug("%s: priv %p connecting to %s:%u %p\n", __func__, priv,
			ip, port, vh->context);

	memset(&i, 0, sizeof(i));

	i.path = "";
	i.vhost = vh;
	i.port = port;
	i.address = ip;
	i.method = "RAW";
	i.userdata = priv;
	i.host = i.address;
	i.pwsi = &priv->wsi;
	i.origin = i.address;
	i.context = vh->context;
	i.ssl_connection = tls_flags;
	i.local_protocol_name = "lws-abs-cli-raw-skt";

	priv->wsi = lws_client_connect_via_info(&i);
	if (!priv->wsi)
		return 1;

	priv->connecting = 1;

	return 0;
}
#endif

static int
lws_atcrs_close(lws_abs_user_t *abs_priv)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)abs_priv;
	struct lws *wsi = priv->wsi;

	if (!priv->wsi)
		return 0;

	if (!lws_raw_transaction_completed(priv->wsi))
		return 0;

	priv->wsi = NULL;
	lws_set_timeout(wsi, 1, LWS_TO_KILL_SYNC);

	/* priv is destroyed in the CLOSE callback */

	return 0;
}

static int
lws_atcrs_ask_for_writeable(lws_abs_user_t *abs_priv)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)abs_priv;

	if (!priv->wsi || !priv->established)
		return 1;

	lws_callback_on_writable(priv->wsi);

	return 0;
}

static lws_abs_user_t *
lws_atcrs_create(struct lws_abstract *abs, void *user)
{
	lws_atrs_priv_t *p = lws_zalloc(sizeof(*p), __func__);

	if (!p)
		return NULL;

	lwsl_debug("%s: created priv %p\n", __func__, p);

	p->abs = abs;
	p->user = user;

	return (lws_abs_user_t *)p;
}

static void
lws_atcrs_destroy(lws_abs_user_t **abs_priv)
{
	lws_free_set_NULL(*abs_priv);
}

static int
lws_atcrs_set_timeout(lws_abs_user_t *d, int reason, int secs)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)d;

	lws_set_timeout(priv->wsi, reason, secs);

	return 0;
}

static int
lws_atcrs_state(lws_abs_user_t *abs_priv)
{
	lws_atrs_priv_t *priv = (lws_atrs_priv_t *)abs_priv;

	if (!priv || !priv->wsi || (!priv->established && !priv->connecting))
		return 0;

	return 1;
}

lws_abstract_t lws_abstract_transport_cli_raw_skt = {
	"raw-skt",
	lws_atcrs_create,
	lws_atcrs_destroy,

	lws_atcrs_tx,
#if defined(LWS_WITHOUT_CLIENT)
	NULL,
#else
	lws_atcrs_client_conn,
#endif
	lws_atcrs_close,
	lws_atcrs_ask_for_writeable,
	lws_atcrs_set_timeout,
	lws_atcrs_state,

	/*
	 * remaining callbacks must be defined by abstract object and are
	 * called by this protocol handler
	 */

	NULL,	/* accept */
	NULL,	/* rx */
	NULL,	/* writeable */
	NULL	/* closed */
};
