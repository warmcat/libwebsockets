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

struct vhd_oauth_preauth {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws_dll2_owner devices;
	struct lws_dll2_owner listeners;
	const char *cookie_name;
	struct lws_jwk jwk;
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
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->listeners.head) {
		struct pss_oauth_preauth *pss = lws_container_of(d, struct pss_oauth_preauth, list);
		send_json(pss, json);
	} lws_end_foreach_dll(d);
}

static int
callback_lws_oauth_preauth(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	struct pss_oauth_preauth *pss = (struct pss_oauth_preauth *)user;
	struct vhd_oauth_preauth *vhd = (struct vhd_oauth_preauth *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_oauth_preauth));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->cookie_name = "auth_session";

		{
			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "cookie-name"))
					vhd->cookie_name = pvo->value;
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
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
			if (ja && lws_jwt_auth_get_uid(ja) > 0) {
				pss->is_listener = 1;
			}
			if (ja)
				lws_jwt_auth_destroy(&ja);
		}

		if (pss->is_listener) {
			lwsl_notice("%s: new listener connected\n", __func__);
			lws_dll2_add_tail(&pss->list, &vhd->listeners);
			/* dump current waiters to the new listener */
			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->devices.head) {
				struct pss_oauth_preauth *dpss = lws_container_of(d, struct pss_oauth_preauth, list);
				if (dpss->serial[0]) {
					char buf[512];
					lws_snprintf(buf, sizeof(buf), "{\"event\":\"device_joined\",\"name\":\"%s\",\"serial\":\"%s\",\"user_code\":\"%s\",\"expires\":%llu}",
						dpss->name, dpss->serial, dpss->user_code, (unsigned long long)dpss->expires);
					send_json(pss, buf);
				}
			} lws_end_foreach_dll(d);
		} else {
			lwsl_notice("%s: new device connected\n", __func__);
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
	{
		const char *cp = (const char *)in;
		if (pss->is_listener) {
			/* Listeners can send {"cmd": "identify", "serial": "..."} */
			if (strstr(cp, "\"identify\"")) {
				const char *s = strstr(cp, "\"serial\":");
				if (s) {
					char target_serial[64];
					s += 9;
					while (*s == ' ' || *s == '"') s++;
					int n = 0;
					while (*s && *s != '"' && n < (int)sizeof(target_serial) - 1)
						target_serial[n++] = *s++;
					target_serial[n] = '\0';

					lws_start_foreach_dll(struct lws_dll2 *, d, vhd->devices.head) {
						struct pss_oauth_preauth *dpss = lws_container_of(d, struct pss_oauth_preauth, list);
						if (!strcmp(dpss->serial, target_serial)) {
							send_json(dpss, "{\"cmd\":\"identify\"}");
							break;
						}
					} lws_end_foreach_dll(d);
				}
			}
		} else {
			/* Devices send {"name": "...", "serial": "...", "user_code": "..."} */
			if (strstr(cp, "\"serial\":")) {
				const char *n = strstr(cp, "\"name\":");
				const char *s = strstr(cp, "\"serial\":");
				const char *u = strstr(cp, "\"user_code\":");

				char raw_name[128] = {0};
				char raw_serial[128] = {0};
				char raw_code[32] = {0};

				if (n) {
					n += 7;
					while (*n == ' ' || *n == '"') n++;
					int i = 0;
					while (*n && *n != '"' && i < (int)sizeof(raw_name) - 1)
						raw_name[i++] = *n++;
					raw_name[i] = '\0';
				}
				if (s) {
					s += 9;
					while (*s == ' ' || *s == '"') s++;
					int i = 0;
					while (*s && *s != '"' && i < (int)sizeof(raw_serial) - 1)
						raw_serial[i++] = *s++;
					raw_serial[i] = '\0';
				}
				if (u) {
					u += 12;
					while (*u == ' ' || *u == '"') u++;
					int i = 0;
					while (*u && *u != '"' && i < (int)sizeof(raw_code) - 1)
						raw_code[i++] = *u++;
					raw_code[i] = '\0';
				}

				int used = 0;
				if (raw_name[0]) lws_json_purify(pss->name, raw_name, sizeof(pss->name), &used);
				used = 0;
				if (raw_serial[0]) lws_json_purify(pss->serial, raw_serial, sizeof(pss->serial), &used);
				used = 0;
				if (raw_code[0]) lws_json_purify(pss->user_code, raw_code, sizeof(pss->user_code), &used);

				char ip[46];
				ip[0] = '\0';
				lws_get_peer_simple(wsi, ip, sizeof(ip));

				char temp_name[256];
				if (pss->name[0]) {
					lws_snprintf(temp_name, sizeof(temp_name), "%s (%s)", pss->name, ip);
				} else {
					lws_snprintf(temp_name, sizeof(temp_name), "Unknown (%s)", ip);
				}
				lws_strncpy(pss->name, temp_name, sizeof(pss->name));

				if (pss->serial[0]) {
					char buf[512];
					lws_snprintf(buf, sizeof(buf), "{\"event\":\"device_joined\",\"name\":\"%s\",\"serial\":\"%s\",\"user_code\":\"%s\",\"expires\":%llu}",
						pss->name, pss->serial, pss->user_code, (unsigned long long)pss->expires);
					broadcast_to_listeners(vhd, buf);
				}
			}
		}
		break;
	}

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->tx_pending) {
			int m = lws_write(wsi, (uint8_t *)pss->tx_buf + LWS_PRE, pss->tx_len, LWS_WRITE_TEXT);
			if (m < 0)
				return -1;
			pss->tx_pending = 0;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
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
