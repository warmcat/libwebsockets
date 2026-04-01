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
#include <sqlite3.h>

struct login_whitelist {
	lws_dll2_t list;
	lws_sockaddr46 sa46;
	int net_len;
};

struct vhd_login {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws_dll2_owner wl;

	/* PVO settings */
	const char *cookie_name;
	const char *service_name;
	const char *auth_server_url;
	int min_grant_level;

	char db_path[256];
	sqlite3 *db;
	char auth_domain[128];
	char cookie_domain[128];
	uint64_t jwt_validity_secs;

	struct lws_jwk jwk;
};

struct pss_login {
	struct lws_jwt_auth *ja;
	uint8_t whitelist_failed;
	char *silent_update_jwt;
};

static int
lws_login_ends_with(const char *str, const char *suffix)
{
	size_t len_str = strlen(str);
	size_t len_suffix = strlen(suffix);
	if (len_suffix > len_str) return 0;
	return !strcmp(str + len_str - len_suffix, suffix);
}

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
			lws_get_vhost(wsi), reason == LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK ? (const struct lws_protocols *)in : lws_get_protocol(wsi));
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
		lws_strncpy(vhd->auth_domain, "auth.warmcat.com", sizeof(vhd->auth_domain));
		lws_strncpy(vhd->db_path, "/var/db/lws-auth.sqlite3", sizeof(vhd->db_path));
		vhd->jwt_validity_secs = 86400;

		if (lws_pvo_get_str(in, "cookie-name", &vhd->cookie_name))
			lwsl_info("%s: default cookie-name %s\n", __func__, vhd->cookie_name);

		{
			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "whitelist")) {
					struct login_whitelist *w = malloc(sizeof(*w));
					if (!w) {
						lwsl_err("%s: OOM\n", __func__);
						return -1;
					}
					memset(w, 0, sizeof(*w));
					if (lws_parse_cidr(pvo->value, &w->sa46, &w->net_len) < 0) {
						lwsl_err("%s: invalid whitelist CIDR %s\n", __func__, pvo->value);
						free(w);
						return -1;
					}
					lws_dll2_add_tail(&w->list, &vhd->wl);
				}
				pvo = pvo->next;
			}
		}

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

		vhd->cookie_domain[0] = '\0';
		if (!lws_pvo_get_str(in, "cookie-domain", &cp))
			lws_strncpy(vhd->cookie_domain, cp, sizeof(vhd->cookie_domain));

		if (!lws_pvo_get_str(in, "auth-domain", &cp))
			lws_strncpy(vhd->auth_domain, cp, sizeof(vhd->auth_domain));

		if (!lws_pvo_get_str(in, "jwt-validity-secs", &cp))
			vhd->jwt_validity_secs = (uint64_t)atoll(cp);

		if (!lws_pvo_get_str(in, "db-path", &cp))
			lws_strncpy(vhd->db_path, cp, sizeof(vhd->db_path));

		lwsl_notice("%s: opening local database at %s\n", __func__, vhd->db_path);
		if (lws_struct_sq3_open(vhd->context, vhd->db_path, 1, &vhd->db)) {
			lwsl_warn("%s: could not open local database at %s. Dynamic grant revocation disabled.\n", __func__, vhd->db_path);
			vhd->db = NULL;
		} else {
			lwsl_notice("%s: Local database bound to %s\n", __func__, vhd->db_path);
		}


		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->wl.head) {
				struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
				lws_dll2_remove(d);
				free(w);
			} lws_end_foreach_dll_safe(d, d1);
			lws_jwk_destroy(&vhd->jwk);
			if (vhd->db)
				sqlite3_close(vhd->db);
		}
		break;

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
	{
		int level = -1;
		struct lws_jwt_auth *ja;
		char uri[256];

		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0) {
			if (lws_login_ends_with(uri, "/.lws-login-status") || lws_login_ends_with(uri, "/lws-login.js"))
				return 1;
		}

		if (!vhd) {
			lwsl_notice("%s: ALLOWING (vhd is NULL !!! protocol init failed?)\n", __func__);
			return 0;
		}

		if (vhd->wl.count) {
			char ip[64];
			lws_sockaddr46 sa46;
			int match = 0;

			lws_get_peer_simple(wsi, ip, sizeof(ip));
			if (!lws_sa46_parse_numeric_address(ip, &sa46)) {
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->wl.head) {
					struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
					if (!lws_sa46_on_net(&sa46, &w->sa46, w->net_len)) {
						match = 1;
						break;
					}
				} lws_end_foreach_dll(d);
			}

			if (!match) {
				lwsl_notice("%s: peer %s failed whitelist\n", __func__, ip);
				return 1; /* Request intercept to serve 403 */
			}
		}

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);
		if (ja) {
			lwsl_notice("%s: Valid cookie found! User authenticated.\n", __func__);
			level = lws_jwt_auth_query_grant(ja, vhd->service_name);
			if (level >= vhd->min_grant_level) {
				if (vhd->db) {
					uint32_t uid = lws_jwt_auth_get_uid(ja);
					if (uid) {
						sqlite3_stmt *stmt;
						int mismatch = 0;
						int count_db = 0;

						if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt, 1, (int)uid);
							while (sqlite3_step(stmt) == SQLITE_ROW) {
								const char *svc_name = (const char *)sqlite3_column_text(stmt, 0);
								int gl = sqlite3_column_int(stmt, 1);
								if (!svc_name) continue;

								count_db++;
								int old_gl = lws_jwt_auth_query_grant(ja, svc_name);
								if (old_gl != gl)
									mismatch = 1;
							}
							sqlite3_finalize(stmt);
						}

						if (count_db != (int)lws_jwt_auth_count_grants(ja))
							mismatch = 1;

						if (mismatch) {
							lws_jwt_auth_destroy(&ja);
							lwsl_notice("%s: Need dynamic JWT rewrite\n", __func__);
							return 1; /* Request to intercept */
						}
					}
				}

				lws_jwt_auth_destroy(&ja);
				lwsl_notice("%s: ALLOWING (User has required grant)\n", __func__);
				return 0; /* Let traffic through to the real mount */
			}
			lwsl_notice("%s: JWT valid but lacks required %s grant (has %d), INTERCEPTING\n", __func__, vhd->service_name, level);
			lws_jwt_auth_destroy(&ja);
		}

		lwsl_notice("%s: INTERCEPTING (NO VALID COOKIE FOUND)\n", __func__);
		return 1; /* Unauthorized, intercept */
	}

	case LWS_CALLBACK_HTTP:
	{
		char dest[512];
		char path[256];
		char urlenc_path[512];

		int whitelist_failed = 0;
		if (vhd->wl.count) {
			char ip[64];
			lws_sockaddr46 sa46;
			int match = 0;

			lws_get_peer_simple(wsi, ip, sizeof(ip));
			if (!lws_sa46_parse_numeric_address(ip, &sa46)) {
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->wl.head) {
					struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
					if (!lws_sa46_on_net(&sa46, &w->sa46, w->net_len)) {
						match = 1;
						break;
					}
				} lws_end_foreach_dll(d);
			}

			if (!match) whitelist_failed = 1;
		}

		if (whitelist_failed) {
			const char *err = "Page Unreachable";
			int len = (int)strlen(err);

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_FORBIDDEN, "text/plain",
							(lws_filepos_t)len, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			lws_write(wsi, (unsigned char *)err, (size_t)len, LWS_WRITE_HTTP_FINAL);
			return lws_http_transaction_completed(wsi);
		}

		if (!pss->ja)
			pss->ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);

		if (pss->ja) {
			int level = lws_jwt_auth_query_grant(pss->ja, vhd->service_name);
			if (level >= vhd->min_grant_level) {
				if (vhd->db && !pss->silent_update_jwt) {
					uint32_t uid = lws_jwt_auth_get_uid(pss->ja);
					if (uid) {
						char current_grants[512];
						char *g_p = current_grants;
						char *g_end = current_grants + sizeof(current_grants);
						sqlite3_stmt *stmt;
						int first = 1;
						int mismatch = 0;
						int count_db = 0;

						g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "\"grants\":{");

						if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt, 1, (int)uid);
							while (sqlite3_step(stmt) == SQLITE_ROW) {
								const char *svc_name = (const char *)sqlite3_column_text(stmt, 0);
								int gl = sqlite3_column_int(stmt, 1);
								if (!svc_name) continue;

								count_db++;
								int old_gl = lws_jwt_auth_query_grant(pss->ja, svc_name);
								if (old_gl != gl)
									mismatch = 1;

								if (!first)
									g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), ",");
								first = 0;
								g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "\"%s\":%d", svc_name, gl);
							}
							sqlite3_finalize(stmt);
						}
						g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "}");

						if (count_db != (int)lws_jwt_auth_count_grants(pss->ja))
							mismatch = 1;

						if (mismatch) {
							char temp[1024];
							char out[2048];
							size_t out_len = sizeof(out);
							uint64_t now = (uint64_t)time(NULL);
							uint64_t exp = now + vhd->jwt_validity_secs;
							const char *sub = lws_jwt_auth_get_sub(pss->ja);

							if (!lws_jwt_sign_compact(vhd->context, &vhd->jwk, "ES256",
													  out, &out_len, temp, sizeof(temp),
													  "{\"iss\":\"%s\",\"sub\":\"%s\",\"uid\":%u,"
													  "\"iat\":%llu,\"exp\":%llu,%s}",
													  vhd->auth_domain, sub ? sub : "Unknown", uid,
													  (unsigned long long)now, (unsigned long long)exp,
													  current_grants)) {
								pss->silent_update_jwt = strdup(out);
							}
						}
					}
				}

				if (pss->silent_update_jwt) {
					char cookie[2048], host[128], fq_uri[512];
					const char *h = NULL;

					if (vhd->cookie_domain[0]) {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
					} else {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, (unsigned long long)vhd->jwt_validity_secs);
					}

					path[0] = '\0';
					lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);

					host[0] = '\0';
					if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0)
						h = host;
#if defined(LWS_ROLE_H2)
					else if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
						h = host;
#endif
					if (!h) {
						struct lws_vhost *vh = lws_get_vhost(wsi);
						if (vh) {
							const char *vname = lws_get_vhost_name(vh);
							if (vname)
								h = vname;
						}
					}

					lws_snprintf(fq_uri, sizeof(fq_uri), "%s://%s%s",
						     lws_is_ssl(wsi) ? "https" : "http",
						     h ? h : "localhost", path);

					if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0, (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie, (int)strlen(cookie), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)fq_uri, (int)strlen(fq_uri), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;

					lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

					free(pss->silent_update_jwt);
					pss->silent_update_jwt = NULL;

					return lws_http_transaction_completed(wsi);
				}
			} else {
				lws_jwt_auth_destroy(&pss->ja);
				pss->ja = NULL;
			}
		}

		path[0] = '\0';
		lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);

		if (lws_login_ends_with(path, "/lws-login.js")) {
			const char *js =
				"window.renderLwsLoginStatus = function(divId) {\n"
				"    console.log('renderLwsLoginStatus called for ', divId);\n"
				"    var el = document.getElementById(divId);\n"
				"    if (!el) { console.log('Element not found'); return; }\n"
				"    fetch('.lws-login-status').then(function(res) { console.log('fetch status:', res.status); return res.json(); }).then(function(data) {\n"
				"        console.log('json payload: ', data);\n"
				"        if (data.logged_in) {\n"
				"            var lurl = data.auth_server_url + '/logout?redirect_uri=' + encodeURIComponent(window.location.href);\n"
				"            el.innerHTML = 'Logged in as<br><b>' + data.identity + '</b><br><a href=\"' + lurl + '\">Logout</a>';\n"
				"        } else {\n"
				"            el.innerHTML = '<a href=\"' + data.login_url + '\">Login / Authenticate</a>';\n"
				"        }\n"
				"    }).catch(function(err) {\n"
				"        console.log('lws-login auth fetch failed: ', err);\n"
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

		char host[128];
		char fq_uri[512];
		const char *h = NULL;

		host[0] = '\0';
		if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0)
			h = host;
#if defined(LWS_ROLE_H2)
		else if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
			h = host;
#endif

		if (!h) {
			struct lws_vhost *vh = lws_get_vhost(wsi);
			if (vh) {
				const char *vname = lws_get_vhost_name(vh);
				if (vname)
					h = vname;
			}
		}

		lws_snprintf(fq_uri, sizeof(fq_uri), "%s://%s%s",
			     lws_is_ssl(wsi) ? "https" : "http",
			     h ? h : "localhost",
			     path);

		lws_urlencode(urlenc_path, fq_uri, sizeof(urlenc_path));

		lws_snprintf(dest, sizeof(dest), "%s?service_name=%s&redirect_uri=%s",
			vhd->auth_server_url, vhd->service_name, urlenc_path);

		if (lws_login_ends_with(path, "/.lws-login-status")) {
			char pl[1024];
			int len;
			if (pss && pss->ja) {
				const char *sub = lws_jwt_auth_get_sub(pss->ja);
				len = lws_snprintf(pl, sizeof(pl), "{\"logged_in\":1,\"identity\":\"%s\",\"auth_server_url\":\"%s\"}",
					sub ? sub : "Unknown", vhd->auth_server_url);
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
		if (pss && pss->silent_update_jwt) {
			free(pss->silent_update_jwt);
			pss->silent_update_jwt = NULL;
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_LOGIN \
	{ \
		"lws-login", \
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
