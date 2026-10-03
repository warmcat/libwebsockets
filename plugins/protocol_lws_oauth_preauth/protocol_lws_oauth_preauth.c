/*
 * ws protocol handler plugin for "lws-oauth-preauth"
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This plugin provides a waiting room for devices that have not yet
 * been paired/authorized via RFC 8628 Device Flow. It allows an admin
 * to verify their physical serial number and trigger "pairing indications"
 * (like blinking LEDs) over a pre-authenticated WebSocket connection.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>

struct vhd_oauth_preauth {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws_dll2_owner devices;
	struct lws_dll2_owner listeners;
	const char *cookie_name;
	struct lws_jwk jwk;
	unsigned int max_devices;
};

struct pss_oauth_preauth {
	struct lws_dll2 list;
	struct vhd_oauth_preauth *vhd;
	struct lws *wsi;

	int is_listener;
	char serial[64];
	char name[64];
	char user_code[16];
	uint64_t expires;

	char tx_buf[512];
	size_t tx_len;
	int tx_pending;
};

static int
send_json(struct pss_oauth_preauth *pss, const char *json)
{
	if (pss->tx_pending)
		return 1;

	pss->tx_len = (size_t)lws_snprintf(pss->tx_buf + LWS_PRE, sizeof(pss->tx_buf) - LWS_PRE, "%s", json);
	pss->tx_pending = 1;
	lws_callback_on_writable(pss->wsi);
	return 0;
}

static void
broadcast_to_listeners(struct vhd_oauth_preauth *vhd, const char *json)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->listeners)) {
		struct pss_oauth_preauth *pss = lws_container_of(d, struct pss_oauth_preauth, list);
		send_json(pss, json);
	} lws_end_foreach_dll(d);
}

/*
 * Copy the string value of the top-level JSON member \p name out of the
 * len-bounded message at \p in, JSON-purified so it can be interpolated into
 * the JSON we broadcast.  Returns 1 if the member was present, else 0 with
 * \p out untouched.  Values longer than the raw bound are truncated, not
 * refused: they are display strings, and the purify step cannot cut inside
 * an escape.
 */
static int
preauth_json_str(const char *in, size_t len, const char *name, char *out,
		 size_t out_len)
{
	char raw[128];
	const char *p;
	size_t al = 0;
	int used = 0;

	p = lws_json_simple_find(in, len, name, &al);
	if (!p || !al)
		return 0;

	lws_strnncpy(raw, p, al, sizeof(raw));
	lws_json_purify(out, raw, (int)out_len, &used);

	return 1;
}

static int
callback_lws_oauth_preauth(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	struct pss_oauth_preauth *pss = (struct pss_oauth_preauth *)user;
	struct vhd_oauth_preauth *vhd = (struct vhd_oauth_preauth *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	char peerip[64];

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_oauth_preauth));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->cookie_name = "auth_session";
		vhd->max_devices = 32;

		{
			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "cookie-name"))
					vhd->cookie_name = pvo->value;
				if (!strcmp(pvo->name, "max-devices"))
					vhd->max_devices = (unsigned int)atoi(pvo->value);
				if (!strcmp(pvo->name, "jwt-jwk")) {
					if (pvo->value[0] == '{' || lws_jwk_load(&vhd->jwk, pvo->value, NULL, NULL)) {
						if (lws_jwk_import(&vhd->jwk, NULL, NULL, pvo->value, strlen(pvo->value))) {
							lwsl_err("%s: failed to load/import JWK\n", __func__);
						}
					}
				}
				pvo = pvo->next;
			}
		}
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->vhd = vhd;
		pss->wsi = wsi;
		pss->tx_pending = 0;
		pss->serial[0] = '\0';
		pss->name[0] = '\0';
		pss->user_code[0] = '\0';

		/* Determine role */
		pss->is_listener = 0;
		if (vhd->jwk.kty) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL, NULL);
			/*
			 * lws_jwt_auth_create() documents that when no
			 * presented occurrence of the cookie is live, it hands
			 * back the first that merely *verified*, so "the caller
			 * decides what an expired token means (check
			 * lws_jwt_auth_get_exp())".  Here it means nothing: a
			 * listener is the admin of the pairing waiting room and
			 * is immediately shown every pending device's user_code,
			 * which is the secret an RFC 8628 approval turns on.
			 * Require a live token, as protocol_lws_login.c and the
			 * auth server both do.
			 */
			if (ja && lws_jwt_auth_get_exp(ja) >
					  (uint64_t)lws_now_secs() &&
			    lws_jwt_auth_get_uid(ja) > 0) {
				if (lws_jwt_auth_query_grant(ja, "admin") > 0)
					pss->is_listener = 1;
			}

			if (ja)
				lws_jwt_auth_destroy(&ja);
		}

		peerip[0] = '\0';
		lws_get_peer_simple(wsi, peerip, sizeof(peerip));

		if (pss->is_listener) {
			lwsl_wsi_notice(wsi, "new oauth listener device_joined, peer: %s", peerip);
			lws_dll2_add_tail(&pss->list, &vhd->listeners);

			/* dump current waiters to the new listener */
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->devices)) {
				struct pss_oauth_preauth *dpss = lws_container_of(d, struct pss_oauth_preauth, list);
				if (dpss->serial[0]) {
					char buf[512];
					lws_snprintf(buf, sizeof(buf), "{\"event\":\"device_joined\",\"name\":\"%s\",\"serial\":\"%s\",\"user_code\":\"%s\",\"expires\":%llu}",
						dpss->name, dpss->serial, dpss->user_code, (unsigned long long)dpss->expires);
					send_json(pss, buf);
				}
			} lws_end_foreach_dll(d);
		} else {
			if (lws_dll2_count(&vhd->devices) >= vhd->max_devices) {
				lwsl_wsi_warn(wsi, "rejecting device: too many pending devices (%u)", lws_dll2_count(
					&vhd->devices));
				return -1;
			}
			lwsl_wsi_notice(wsi, "new device connected, peer: %s", peerip);
			pss->expires = lws_now_secs() + (5 * 60);
			lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, 5 * 60);
			lws_dll2_add_tail(&pss->list, &vhd->devices);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (pss->is_listener) {
			lws_dll2_remove(&pss->list);
		} else {
			if (pss->serial[0]) {
				char buf[512];
				lws_snprintf(buf, sizeof(buf), "{\"event\":\"device_left\",\"serial\":\"%s\"}", pss->serial);
				broadcast_to_listeners(vhd, buf);
			}
			lws_dll2_remove(&pss->list);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		/*
		 * Both roles speak short, single-frame JSON objects: a device
		 * announces {"name", "serial", "user_code"}, a listener sends
		 * {"cmd": "identify", "serial"}.  The ws role NUL-terminates
		 * only a non-empty slice, and with permessage-deflate a
		 * zero-length FIN arrives with in == NULL, so nothing here may
		 * look past len: fields are found with the length-bounded
		 * lws_json_simple_find() and never with strstr().  A message
		 * that does not fit one slice (rx_buffer_size) is not one of
		 * ours; the peer is dropped rather than parsed piecemeal.
		 */
		if (!in || !len)
			break;

		if (!lws_is_first_fragment(wsi) || !lws_is_final_fragment(wsi)) {
			lwsl_wsi_info(wsi, "fragmented message refused");
			return -1;
		}

		if (pss->is_listener) {
			char target_serial[64];

			if (lws_json_simple_strcmp((const char *)in, len,
						   "\"cmd\":", "identify") ||
			    !preauth_json_str((const char *)in, len, "\"serial\":",
					      target_serial,
					      sizeof(target_serial)))
				break;

			lws_start_foreach_dll(struct lws_dll2 *, d,
					      lws_dll2_get_head(&vhd->devices)) {
				struct pss_oauth_preauth *dpss =
					lws_container_of(d,
						struct pss_oauth_preauth, list);

				if (!strcmp(dpss->serial, target_serial)) {
					send_json(dpss, "{\"cmd\":\"identify\"}");
					break;
				}
			} lws_end_foreach_dll(d);
			break;
		}

		/* a device's announcement is recognised by its serial */
		if (!preauth_json_str((const char *)in, len, "\"serial\":",
				      pss->serial, sizeof(pss->serial)))
			break;

		preauth_json_str((const char *)in, len, "\"name\":", pss->name,
				 sizeof(pss->name));
		preauth_json_str((const char *)in, len, "\"user_code\":",
				 pss->user_code, sizeof(pss->user_code));

		{
			char ip[46], temp_name[256];

			ip[0] = '\0';
			lws_get_peer_simple(wsi, ip, sizeof(ip));

			if (pss->name[0])
				lws_snprintf(temp_name, sizeof(temp_name),
					     "%s (%s)", pss->name, ip);
			else
				lws_snprintf(temp_name, sizeof(temp_name),
					     "Unknown (%s)", ip);
			lws_strncpy(pss->name, temp_name, sizeof(pss->name));
		}

		if (pss->serial[0]) {
			char buf[512];

			lws_snprintf(buf, sizeof(buf),
				     "{\"event\":\"device_joined\",\"name\":\"%s\","
				     "\"serial\":\"%s\",\"user_code\":\"%s\","
				     "\"expires\":%llu}",
				     pss->name, pss->serial, pss->user_code,
				     (unsigned long long)pss->expires);
			broadcast_to_listeners(vhd, buf);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->tx_pending) {
			int m = lws_write(wsi, (uint8_t *)pss->tx_buf + LWS_PRE, pss->tx_len, LWS_WRITE_TEXT);
			if (m < 0)
				return -1;
			pss->tx_pending = 0;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_jwk_destroy(&vhd->jwk);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_OAUTH_PREAUTH \
	{ \
		"lws-oauth-preauth", \
		callback_lws_oauth_preauth, \
		sizeof(struct pss_oauth_preauth), \
		512, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_OAUTH_PREAUTH
};

LWS_VISIBLE const lws_plugin_protocol_t lws_oauth_preauth = {
	.hdr = {
		.name = "lws-oauth-preauth",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 0
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
