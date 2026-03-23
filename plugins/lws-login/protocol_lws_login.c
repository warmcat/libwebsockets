/*
 * ws protocol handler plugin for "lws login" / auth bouncer
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This plugin translates an LWS Mount Interceptor into a JWT-driven bouncer
 * depending on lws_jwt_auth. Unauthenticated connections are bounced transparently.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <stdlib.h>
#include <string.h>

struct vhd_login {
	struct lws_context *context;
	struct lws_vhost *vhost;

	/* PVO settings */
	const char *cookie_name;
	const char *service_name;
	const char *auth_server_url;
	int min_grant_level;

	struct lws_jwk jwk;
};

struct pss_login {
	struct lws_jwt_auth *ja;
};

static int
lws_login_jwt_auth_cb(struct lws_jwt_auth *ja, int state, void *user)
{
	struct lws *wsi = (struct lws *)user;

	if (state == LWS_JWT_AUTH_STATE_EXPIRED) {
		lwsl_notice("%s: Session expired naturally, killing wsi\n", __func__);
		lws_set_timeout(wsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, LWS_TO_KILL_ASYNC);
	}
	return 0;
}

static int
callback_lws_login(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct vhd_login *vhd = (struct vhd_login *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), lws_get_protocol(wsi));
	struct pss_login *pss = (struct pss_login *)user;
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
	const char *cp;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_login));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		vhd->cookie_name = "auth_session";
		vhd->service_name = "default-service";
		vhd->min_grant_level = 1;

		if (lws_pvo_get_str(in, "cookie-name", &vhd->cookie_name))
			lwsl_info("%s: default cookie-name %s\n", __func__, vhd->cookie_name);

		if (lws_pvo_get_str(in, "service-name", &vhd->service_name))
			lwsl_info("%s: default service-name %s\n", __func__, vhd->service_name);

		if (lws_pvo_get_str(in, "auth-server-url", &vhd->auth_server_url)) {
			lwsl_err("%s: auth-server-url PVO is REQUIRED\n", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "min-grant-level", &cp))
			vhd->min_grant_level = atoi(cp);

		if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
			if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
				if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
					lwsl_err("%s: failed to load/import JWK\n", __func__);
					return -1;
				}
			}
		} else {
			lwsl_err("%s: jwt-jwk PVO required\n", __func__);
			return -1;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_jwk_destroy(&vhd->jwk);
		}
		break;

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
	{
		int level = -1;
		struct lws_jwt_auth *ja;
		int is_helper = 0;
		char uri[256];

		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0) {
			if (!strcmp(uri, "/.lws-login-status") || !strcmp(uri, "/lws-login.js"))
				is_helper = 1;
		}

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);
		if (ja) {
			level = lws_jwt_auth_query_grant(ja, vhd->service_name);
			if (level >= vhd->min_grant_level) {
				lwsl_info("%s: authorized for %s\n", __func__, vhd->service_name);
				pss->ja = ja;
				if (is_helper)
					return 1;
				return 0; /* Let traffic through to the real mount */
			}
			lwsl_notice("%s: JWT valid but lacks required %s grant (has %d)\n", __func__, vhd->service_name, level);
			lws_jwt_auth_destroy(&ja);
		}

		/* Unauthorized or no session, we must intercept, routing later to LWS_CALLBACK_HTTP */
		return 1;
	}

	case LWS_CALLBACK_HTTP:
	{
		char dest[512];
		char path[256];
		char urlenc_path[512];

		path[0] = '\0';
		lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);

		if (!strcmp(path, "/lws-login.js")) {
			const char *js =
				"window.renderLwsLoginStatus = function(divId) {\n"
				"    var el = document.getElementById(divId);\n"
				"    if (!el) return;\n"
				"    fetch('/.lws-login-status').then(function(res) { return res.json(); }).then(function(data) {\n"
				"        if (data.logged_in) {\n"
				"            el.innerHTML = '<span class=\"lws-login-identity\">Logged in as <b>' + data.identity + '</b></span> | <a href=\"#\" onclick=\"document.cookie=\\'' + data.cookie_name + '=; Max-Age=0; Path=/\\'; window.location.reload();\">Logout</a>';\n"
				"        } else {\n"
				"            el.innerHTML = '<a href=\"' + data.login_url + '\">Login / Authenticate</a>';\n"
				"        }\n"
				"    });\n"
				"};\n";

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/javascript",
							(lws_filepos_t)strlen(js), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			lws_write(wsi, (unsigned char *)js, strlen(js), LWS_WRITE_HTTP_FINAL);
			return lws_http_transaction_completed(wsi);
		}

		/* Reconstruct the fully qualified absolute URI so cross-domain redirects from auth server navigate back correctly */
		char host[128];
		char fq_uri[512];

		host[0] = '\0';
		lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST);

		lws_snprintf(fq_uri, sizeof(fq_uri), "%s://%s%s",
			     lws_is_ssl(wsi) ? "https" : "http",
			     host[0] ? host : "localhost",
			     path);

		lws_urlencode(urlenc_path, fq_uri, sizeof(urlenc_path));

		lws_snprintf(dest, sizeof(dest), "%s?service_name=%s&redirect_uri=%s",
			vhd->auth_server_url, vhd->service_name, urlenc_path);

		if (!strcmp(path, "/.lws-login-status")) {
			char pl[1024];
			int len;
			if (pss && pss->ja) {
				const char *sub = lws_jwt_auth_get_sub(pss->ja);
				len = lws_snprintf(pl, sizeof(pl), "{\"logged_in\":1,\"identity\":\"%s\",\"cookie_name\":\"%s\"}",
					sub ? sub : "Unknown", vhd->cookie_name);
			} else {
				len = lws_snprintf(pl, sizeof(pl), "{\"logged_in\":0,\"login_url\":\"%s\"}", dest);
			}

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json",
							(lws_filepos_t)len, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			lws_write(wsi, (unsigned char *)pl, (size_t)len, LWS_WRITE_HTTP_FINAL);
			return lws_http_transaction_completed(wsi);
		}

		lwsl_info("%s: bouncing unauth to %s\n", __func__, dest);

		if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
				(unsigned char *)dest, (int)strlen(dest), (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

		return lws_http_transaction_completed(wsi);
	}

	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_CLOSED:
		if (pss && pss->ja) {
			lws_jwt_auth_destroy(&pss->ja);
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_LOGIN \
	{ \
		"lws_login", \
		callback_lws_login, \
		sizeof(struct pss_login), \
		1024, 0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_LOGIN
};

LWS_VISIBLE const lws_plugin_protocol_t lws_login = {
	.hdr = {
		.name = "lws login",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
