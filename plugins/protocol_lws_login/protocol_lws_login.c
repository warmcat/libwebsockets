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

	int unauth_allow;

	struct lws_jwk jwk;
};

struct pss_login {
	struct lws_jwt_auth *ja;
	uint8_t whitelist_failed;
	char *silent_update_jwt;
	struct lws_spa *spa;
	struct lws_buflist *tx_buflist;
};

static const char * const param_names[] = {
	"token",
	"target",
};

enum enum_param_names {
	EPN_TOKEN,
	EPN_TARGET,
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

		vhd->unauth_allow = 0;
		if (!lws_pvo_get_str(in, "unauth-allow", &cp))
			vhd->unauth_allow = atoi(cp);

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
		const char *service_name;
		const struct lws_http_mount *mount;

		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0 ||
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) > 0) {
			if (lws_login_ends_with(uri, "/.lws-login-status") ||
			    lws_login_ends_with(uri, "/lws-login.js") ||
			    lws_login_ends_with(uri, "/lws-login.css") ||
			    lws_login_ends_with(uri, "/.lws-login-sso"))
				return 1;
		}

		if (!vhd) {
			lwsl_info("%s: ALLOWING (vhd is NULL !!! protocol init failed?)\n", __func__);
			return 0;
		}

		service_name = vhd->service_name;
		if (uri[0]) {
			mount = lws_find_mount(wsi, uri, (int)strlen(uri));
			if (mount) {
				if (!lws_pmo_get_str(mount, "service-name", &service_name)) {
					lwsl_info("%s: using service_name %s from target pmo\n", __func__, service_name);
				}
#if defined(LWS_WITH_JOSE)
				else if (mount->interceptor_path) {
					const struct lws_http_mount *im;
					im = lws_find_mount(wsi, mount->interceptor_path, (int)strlen(mount->interceptor_path));
					if (im && !lws_pmo_get_str(im, "service-name", &service_name))
						lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
				}
#endif
			}
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
				lwsl_info("%s: peer %s failed whitelist\n", __func__, ip);
				return 1; /* Request intercept to serve 403 */
			}
		}

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);
		if (ja) {
			lwsl_info("%s: Valid cookie found! User authenticated.\n", __func__);
			level = lws_jwt_auth_query_grant(ja, service_name);
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
							lwsl_info("%s: Need dynamic JWT rewrite\n", __func__);
							return 1; /* Request to intercept */
						}
					}
				}

				lws_jwt_auth_destroy(&ja);
				lwsl_info("%s: ALLOWING (User has required grant)\n", __func__);
				return 0; /* Let traffic through to the real mount */
			}
			lwsl_info("%s: JWT valid but lacks required %s grant (has %d), INTERCEPTING\n", __func__, service_name, level);
			lws_jwt_auth_destroy(&ja);
		}

		lwsl_info("%s: INTERCEPTING (NO VALID COOKIE FOUND)\n", __func__);

		if (vhd->unauth_allow) {
			lwsl_info("%s: ALLOWING UNAUTH (unauth-allow enabled)\n", __func__);
			return 0;
		}

		return 1; /* Unauthorized, intercept */
	}

	case LWS_CALLBACK_HTTP:
	{
		char dest[512];
		char path[256];
		char urlenc_path[512];
		const char *service_name;
		const struct lws_http_mount *mount;
		int whitelist_failed = 0;
		int n;

		if (!vhd)
			return 1;

		service_name = vhd->service_name;

		path[0] = '\0';
		n = lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);
		if (n <= 0)
			n = lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI);
		if (n > 0) {
			mount = lws_find_mount(wsi, path, n);
			if (mount) {
				if (!lws_pmo_get_str(mount, "service-name", &service_name)) {
					lwsl_info("%s: using service_name %s from target pmo\n", __func__, service_name);
				}
#if defined(LWS_WITH_JOSE)
				else if (mount->interceptor_path) {
					const struct lws_http_mount *im;
					im = lws_find_mount(wsi, mount->interceptor_path, (int)strlen(mount->interceptor_path));
					if (im && !lws_pmo_get_str(im, "service-name", &service_name))
						lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
				}
#endif
			}
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
			uint8_t *fbuf = malloc(LWS_PRE + (size_t)len);
			if (!fbuf) return -1;
			memcpy(fbuf + LWS_PRE, err, (size_t)len);
			int res = lws_buflist_append_segment(&pss->tx_buflist, fbuf, LWS_PRE + (size_t)len);
			free(fbuf);
			if (res < 0) return -1;
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) > 0) {
			if (lws_login_ends_with(path, "/.lws-login-sso"))
				return 0; /* Fall through to LWS_CALLBACK_HTTP_BODY */
		}

		if (!pss->ja)
			pss->ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);

		if (pss->ja) {
			int level = lws_jwt_auth_query_grant(pss->ja, service_name);
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
		}

		path[0] = '\0';
		lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);

		if (lws_login_ends_with(path, "/lws-login.css")) {
			const char *css =
				".lws-login-box { font-family: -apple-system, system-ui, sans-serif; padding: 16px; border-radius: 8px; background: rgba(0,0,0,0.02); border: 1px solid rgba(0,0,0,0.08); display: inline-block; font-size: 14px; line-height: 1.4; color: #333; }\n"
				"@media (prefers-color-scheme: dark) { .lws-login-box { background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); color: #888; } }\n"
				".lws-login-btn { display: inline-block; padding: 8px 16px; background: #007bff; color: white !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 13px; transition: background 0.2s; margin-top: 5px; }\n"
				".lws-login-btn:hover { background: #0056b3; }\n"
				".lws-login-err { display: inline-block; margin-top: 8px; margin-bottom: 4px; padding: 6px 10px; background: #ffebee; border-left: 3px solid #f44336; color: #c62828; font-size: 13px; font-weight: 500; }\n"
				".lws-login-link { color: #007bff; text-decoration: none; margin-right: 12px; font-weight: 500; font-size: 13px; transition: opacity 0.2s; }\n"
				".lws-login-link:hover { opacity: 0.8; }\n"
				".lws-login-logout { color: #f44336; }\n"
				".lws-login-identity { font-size: 16px; margin: 0 12px 0 0; display: inline-block; font-weight: 600; }\n"
				".lws-login-mt { margin-top: 10px; }\n"
				".lws-login-mb { margin-bottom: 8px; font-weight: 500; }\n";

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/css",
							(lws_filepos_t)strlen(css), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(css);
			uint8_t *fbuf = malloc(LWS_PRE + len);
			if (!fbuf) return -1;
			memcpy(fbuf + LWS_PRE, css, len);
			int res = lws_buflist_append_segment(&pss->tx_buflist, fbuf, LWS_PRE + len);
			free(fbuf);
			if (res < 0) return -1;
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (lws_login_ends_with(path, "/lws-login.js")) {
			const char *js =
				"window.renderLwsLoginStatus = function(divId) {\n"
				"    var el = document.getElementById(divId);\n"
				"    if (!el) return;\n"
				"    if (!document.getElementById('lws-login-css')) {\n"
				"        var link = document.createElement('link');\n"
				"        link.id = 'lws-login-css';\n"
				"        link.rel = 'stylesheet';\n"
				"        link.href = 'lws-login.css';\n"
				"        document.head.appendChild(link);\n"
				"    }\n"
				"    fetch('.lws-login-status').then(function(res) { return res.json(); }).then(function(data) {\n"
				"        var c = '<div class=\"lws-login-box\">';\n"
				"        if (data.logged_in) {\n"
				"            var lurl = data.auth_server_url + '/api/logout?redirect_uri=' + encodeURIComponent(window.location.href);\n"
				"            var admin = data.is_admin ? '<a class=\"lws-login-link\" href=\"' + data.auth_server_url + '/admin\">Admin Console</a>' : '';\n"
				"            c += '<strong class=\"lws-login-identity\">' + data.identity + '</strong><br>';\n"
				"            c += admin + ' <a class=\"lws-login-link lws-login-logout\" href=\"' + lurl + '\">Logout</a>';\n"
				"            if (!data.has_grant && !data.is_admin) {\n"
				"                 c += '<div class=\"lws-login-err\">Identity lacks required access grant for this application</div><br>';\n"
				"            }\n"
				"        } else {\n"
				"            var safe_lu = data.login_url.split('redirect_uri=')[0] + 'redirect_uri=' + encodeURIComponent(window.location.href);\n"
				"            c += '<div class=\"lws-login-mb\">Authentication Context Required</div>';\n"
				"            c += '<a class=\"lws-login-btn\" href=\"' + safe_lu + '\">Login / Authenticate &rarr;</a>';\n"
				"        }\n"
				"        el.innerHTML = c + '</div>';\n"
				"    }).catch(function(err) { console.log('lws-login fetch failed:', err); });\n"
				"};\n";

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/javascript",
							(lws_filepos_t)strlen(js), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(js);
			uint8_t *fbuf = malloc(LWS_PRE + len);
			if (!fbuf) return -1;
			memcpy(fbuf + LWS_PRE, js, len);
			int res = lws_buflist_append_segment(&pss->tx_buflist, fbuf, LWS_PRE + len);
			free(fbuf);
			if (res < 0) return -1;
			lws_callback_on_writable(wsi);
			return 0;
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
			vhd->auth_server_url, service_name, urlenc_path);

		if (lws_login_ends_with(path, "/.lws-login-status")) {
			char pl[1024];
			int len;
			if (pss && pss->ja) {
				const char *sub = lws_jwt_auth_get_sub(pss->ja);
				int is_admin = lws_jwt_auth_query_grant(pss->ja, "*") >= 1;
				int has_grant = lws_jwt_auth_query_grant(pss->ja, service_name) >= vhd->min_grant_level;
				len = lws_snprintf(pl, sizeof(pl), "{\"logged_in\":1,\"has_grant\":%d,\"identity\":\"%s\",\"auth_server_url\":\"%s\",\"login_url\":\"%s\",\"is_admin\":%d}",
					has_grant, sub ? sub : "Unknown", vhd->auth_server_url, dest, is_admin);
			} else {
				len = lws_snprintf(pl, sizeof(pl), "{\"logged_in\":0,\"login_url\":\"%s\"}", dest);
			}

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json",
							(lws_filepos_t)len, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			uint8_t *fbuf = malloc(LWS_PRE + (size_t)len);
			if (!fbuf) return -1;
			memcpy(fbuf + LWS_PRE, pl, (size_t)len);
			int res = lws_buflist_append_segment(&pss->tx_buflist, fbuf, LWS_PRE + (size_t)len);
			free(fbuf);
			if (res < 0) return -1;
			lws_callback_on_writable(wsi);
			return 0;
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

	case LWS_CALLBACK_HTTP_BODY:
	{
		char path[256];
		path[0] = '\0';
		lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI);

		if (lws_login_ends_with(path, "/.lws-login-sso")) {
			if (!pss->spa) {
				pss->spa = lws_spa_create(wsi, param_names,
							  LWS_ARRAY_SIZE(param_names),
							  2048, NULL, NULL);
				if (!pss->spa)
					return -1;
			}
			if (lws_spa_process(pss->spa, (const char *)in, (int)len)) {
				lws_spa_finalize(pss->spa);
				return -1;
			}
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	{
		char path[256];

		if (!vhd)
			return 1;

		path[0] = '\0';
		lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI);

		if (lws_login_ends_with(path, "/.lws-login-sso")) {
			if (pss->spa) {
				lws_spa_finalize(pss->spa);
				const char *token = lws_spa_get_string(pss->spa, EPN_TOKEN);
				const char *target = lws_spa_get_string(pss->spa, EPN_TARGET);

				char origin[128];
				if (token && vhd && vhd->auth_server_url && lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN) > 0) {
					if (strncmp(origin, vhd->auth_server_url, strlen(origin))) {
						lwsl_err("%s: blocking SSO CSRF from origin %s\n", __func__, origin);
						token = NULL; /* Nullify to force failure */
					}
				}

				if (token && target && vhd) {
					char temp[2048], out[2048];
					size_t out_len = sizeof(out);

					/* Ensure signature is authentic using broad algorithms. */
					if (!lws_jwt_signed_validate(vhd->context, &vhd->jwk, "ES256,ES384,ES512,RS256,RS384,RS512",
								    token, strlen(token), temp, sizeof(temp), out, &out_len)) {
						pss->silent_update_jwt = strdup(token);
					}
				}

				const char *final_target = "/";
				if (target && target[0]) {
					if (target[0] == '/' && target[1] != '/') {
						final_target = target;
					} else if (vhd->db) {
						char alt_target[512];
						int t_len = (int)strlen(target);
						lws_strncpy(alt_target, target, sizeof(alt_target));
						if (t_len > 0 && alt_target[t_len - 1] == '/')
							alt_target[t_len - 1] = '\0';
						else if (t_len < (int)sizeof(alt_target) - 2) {
							alt_target[t_len] = '/';
							alt_target[t_len + 1] = '\0';
						}
						sqlite3_stmt *stmt;
						if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM oauth_clients WHERE (',' || redirect_uris || ',') LIKE ('%,' || ? || ',%') OR (',' || redirect_uris || ',') LIKE ('%,' || ? || ',%')", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_text(stmt, 1, target, -1, SQLITE_STATIC);
							sqlite3_bind_text(stmt, 2, alt_target, -1, SQLITE_STATIC);
							if (sqlite3_step(stmt) == SQLITE_ROW) {
								final_target = target;
							} else {
								lwsl_err("%s: untrusted absolute target %s\n", __func__, target);
							}
							sqlite3_finalize(stmt);
						}
					}
				}

				if (pss->silent_update_jwt && final_target) {
					char cookie[2048];
					if (vhd->cookie_domain[0]) {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
					} else {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, (unsigned long long)vhd->jwt_validity_secs);
					}

					if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0, (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie, (int)strlen(cookie), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)final_target, (int)strlen(final_target), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
					lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

					return lws_http_transaction_completed(wsi);
				} else {
					const char *err = "Invalid SSO Token";
					int err_len = (int)strlen(err);
					if (lws_add_http_common_headers(wsi, HTTP_STATUS_FORBIDDEN, "text/plain", (lws_filepos_t)err_len, (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
					lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
					uint8_t *fbuf = malloc(LWS_PRE + (size_t)err_len);
					if (!fbuf) return -1;
					memcpy(fbuf + LWS_PRE, err, (size_t)err_len);
					int res = lws_buflist_append_segment(&pss->tx_buflist, fbuf, LWS_PRE + (size_t)err_len);
					free(fbuf);
					if (res < 0) return -1;
					lws_callback_on_writable(wsi);
					return 0;
				}
			}
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->tx_buflist)
			break;

		uint8_t *pout;
		size_t bytes = lws_buflist_next_segment_len(&pss->tx_buflist, &pout);
		if (!bytes)
			break;

		int m = lws_write(wsi, pout + LWS_PRE, (unsigned int)(bytes - LWS_PRE), LWS_WRITE_HTTP_FINAL);
		if (m < 0) return -1;

		size_t consume = (size_t)m;
		if ((size_t)m == bytes - LWS_PRE) {
			consume = bytes;
		}

		lws_buflist_use_segment(&pss->tx_buflist, consume);

		if (lws_buflist_next_segment_len(&pss->tx_buflist, &pout)) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		return lws_http_transaction_completed(wsi);

	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_CLOSED:
		if (pss && pss->tx_buflist) {
			lws_buflist_destroy_all_segments(&pss->tx_buflist);
		}
		if (pss && pss->ja) {
			lws_jwt_auth_destroy(&pss->ja);
		}
		if (pss && pss->silent_update_jwt) {
			free(pss->silent_update_jwt);
			pss->silent_update_jwt = NULL;
		}
		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
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
