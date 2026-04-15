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

#define LWS_AUTH_MAX_COOKIE_LEN 4096

struct login_whitelist {
	lws_dll2_t              list;
	lws_sockaddr46          sa46;
	int                     net_len;
};

struct vhd_login {
	struct lws_context      *context;
	struct lws_vhost        *vhost;
	struct lws_dll2_owner   wl;

	/* PVO settings */
	const char              *cookie_name;
	const char              *service_name;
	const char              *auth_server_url;
	int                     min_grant_level;

	char                    db_path[256];
	sqlite3                 *db;
	char                    auth_domain[128];
	char                    cookie_domain[128];
	uint64_t                jwt_validity_secs;

	int                     unauth_allow;

	struct lws_jwk          jwk;
	lws_dll2_owner_t        pending_refresh_list;
};

struct pss_login {
	struct lws_jwt_auth     *ja;
	uint8_t                 whitelist_failed;
	char                    *silent_update_jwt;
	struct lws_spa          *spa;
	struct lws_buflist      *tx_buflist;
};

struct pending_login_refresh {
	lws_dll2_t              list;
	lws_sorted_usec_list_t  sul;
	struct vhd_login        *vhd;

	struct lws              *wsi_server;
	struct lws              *wsi_client;

	char                    cookie_hdr[1024];

	char                    payload[1024];
	int                     payload_len;
	int                     payload_pos;

	char                    token[2048];
};

static const char * const canned_css =
        ".lws-login-box{font-family:-apple-system,system-ui,sans-serif;padding:"
        "16px;border-radius:8px;background:rgba(0,0,0,0.02);border:1px solid "
        "rgba(0,0,0,0.08);display:inline-block;font-size:14px;line-height:1.4;"
        "color:#333;}\n"
        "@media(prefers-color-scheme:dark){.lws-login-box{background:rgba(255,255,"
        "255,0.05);border-color:rgba(255,255,255,0.1);color:#888;}}\n"
        ".lws-login-btn{display:inline-block;padding:8px "
        "16px;background:#007bff;color:#fff!important;text-decoration:none;border-"
        "radius:6px;font-weight:600;font-size:13px;transition:background "
        "0.2s;margin-top:5px;}\n"
        ".lws-login-btn:hover{background:#0056b3;}\n"
        ".lws-login-err{display:inline-block;margin-top:8px;margin-bottom:4px;"
        "padding:6px 10px;background:#ffebee;border-left:3px solid "
        "#f44336;color:#c62828;font-size:13px;font-weight:500;}\n"
        ".lws-login-link{color:#007bff;text-decoration:none;margin-right:12px;font-"
        "weight:500;font-size:13px;transition:opacity 0.2s;}\n"
        ".lws-login-link:hover{opacity:0.8;}\n"
        ".lws-login-logout{color:#f44336;}\n"
        ".lws-login-identity{font-size:16px;margin:0 12px 0 "
        "0;display:inline-block;font-weight:600;}\n"
        ".lws-login-mt{margin-top:10px;}\n"
        ".lws-login-mb{margin-bottom:8px;font-weight:500;}\n";

static const char * const canned_js =
        "window.lwsLoginSilentRefresh=async function(){"
        "try{"
        "var r=await fetch('/.lws-login-refresh',{method:'POST',credentials:'include'});"
        "return r.ok;"
        "}catch(e){return false;}"
        "};"
        "window.renderLwsLoginStatus=async function(d){"
        "var e=document.getElementById(d);"
        "if(!e)return;"
        "if(!document.getElementById('lws-login-css')){"
        "var l=document.createElement('link');"
        "l.id='lws-login-css';l.rel='stylesheet';l.href='lws-login.css';"
        "document.head.appendChild(l);"
        "}"
        "try{"
        "let r=await fetch('.lws-login-status');"
        "let st=await r.json();"
        "if(!st.logged_in){"
        "if(await window.lwsLoginSilentRefresh()){"
        "r=await fetch('.lws-login-status');"
        "st=await r.json();"
        "}"
        "}"
        "var c='<div class=\"lws-login-box\">';"
        "if(st.logged_in){"
        "var u='.lws-login-logout?redirect_uri='+encodeURIComponent(window.location.href);"
        "var a=st.is_admin?'<a class=\"lws-login-link\" href=\"'+st.auth_server_url+'/api/admin\">Admin Console</a>':'';"
        "c+='<strong class=\"lws-login-identity\">'+st.identity+'</strong><br>';"
        "c+=a+' <a class=\"lws-login-link lws-login-logout\" href=\"'+u+'\">Logout</a>';"
        "if(!st.has_grant&&!st.is_admin)c+='<div class=\"lws-login-err\">login lacks grant</div><br>';"
        "if(st.exp){"
        "var n=Date.now()/1000;"
        "var m=st.exp-n;"
        "if(m>0&&m<86400){"
        "setTimeout(function(){"
        "var s=st.login_url.split('redirect_uri=')[0]+'redirect_uri='+encodeURIComponent(window.location.href);"
        "window.location.href=s;"
        "},(m-60)*1000);"
        "}"
        "}"
        "}else{"
        "var s=st.login_url.split('redirect_uri=')[0]+'redirect_uri='+encodeURIComponent(window.location.href);"
        "c+='<div class=\"lws-login-mb\">Not logged in</div>';"
        "c+='<a class=\"lws-login-btn\" href=\"'+s+'\">Login &rarr;</a>';"
        "}"
        "e.innerHTML=c+'</div>';"
        "}catch(er){console.log('lws-login fetch:',er);}"
        "};";

static void
sul_pending_refresh_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_login_refresh *ps = lws_container_of(sul,
					struct pending_login_refresh, sul);

	lwsl_info("%s: auth refresh timed out\n", __func__);
	lws_dll2_remove(&ps->list);
	free(ps);
}

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

	if (len_suffix > len_str)
		return 0;

	return !strcmp(str + len_str - len_suffix, suffix);
}

static int
callback_lws_login_client(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct pending_login_refresh *ps = (struct pending_login_refresh *)lws_wsi_user(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (*p) + len;
		char clen[16];

		if (!ps)
			break;

		lws_snprintf(clen, sizeof(clen), "%d", ps->payload_len);

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)"application/x-www-form-urlencoded",
						 33, p, end))
			return -1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
						 (unsigned char *)clen, (int)strlen(clen), p, end))
			return -1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
						 (unsigned char *)ps->cookie_hdr,
						 (int)strlen(ps->cookie_hdr), p, end))
			return -1;

		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		int n;

		if (!ps || ps->payload_pos >= ps->payload_len)
			break;

		n = lws_write(wsi, (unsigned char *)ps->payload + ps->payload_pos,
			      (size_t)(ps->payload_len - ps->payload_pos), LWS_WRITE_HTTP);
		if (n < 0)
			return -1;
		ps->payload_pos += n;

		if (ps->payload_pos < ps->payload_len)
			lws_callback_on_writable(wsi);
		else
			lws_client_http_body_pending(wsi, 0);
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		struct lws_tokenize ts;
		lws_tokenize_elem e;
		int state = 0;

		if (!ps || !in || !len)
			break;

		lws_tokenize_init(&ts, (char *)in, LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_MINUS_NONTERM);
		ts.len = len;

		while ((e = lws_tokenize(&ts)) != LWS_TOKZE_ENDED) {
			if (state == 0 && e == LWS_TOKZE_QUOTED_STRING &&
			    ts.token_len == 5 && !strncmp(ts.token, "token", 5)) {
				state = 1;
			} else if (state == 1 && e == LWS_TOKZE_DELIMITER && ts.token[0] == ':') {
				state = 2;
			} else if (state == 2 && e == LWS_TOKZE_QUOTED_STRING) {
				if (ts.token_len < sizeof(ps->token)) {
					lws_strncpy(ps->token, ts.token, ts.token_len + 1);
					lwsl_notice("%s: Extracted OAuth token natively via BFF\n", __func__);
				}
				break;
			}
		}
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: {
		if (!ps)
			break;

		if (ps->wsi_server)
			lws_callback_on_writable(ps->wsi_server);
		ps->wsi_client = NULL;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP: {
		if (!ps)
			break;
		lwsl_notice("%s: client connection closed or errored\n", __func__);
		if (ps->wsi_server && !ps->token[0]) {
			lws_callback_on_writable(ps->wsi_server);
		}
		ps->wsi_client = NULL;
		break;
	}

	default:
		break;
	}

	return 0;
}

static int
lws_login_jwt_auth_cb(struct lws_jwt_auth *ja, int state, void *user)
{
	if (state == LWS_JWT_AUTH_STATE_EXPIRED)
		lwsl_notice("%s: Session expired naturally\n", __func__);

	return 0;
}

static int
auth_verify_redirect_uri(struct vhd_login *vhd, const char *redirect_uri)
{
	sqlite3_stmt *stmt;
	int valid = 0;

	if (!redirect_uri || !redirect_uri[0])
		return 0;

	if (strstr(redirect_uri, "../") ||
	    strstr(redirect_uri, "..%2F") ||
	    strstr(redirect_uri, "..%2f"))
		return 0;

	if (sqlite3_prepare_v2(vhd->db, "SELECT redirect_uris FROM oauth_clients", -1, &stmt, NULL) == SQLITE_OK) {
		while (!valid && sqlite3_step(stmt) == SQLITE_ROW) {
			const char *uris = (const char *)sqlite3_column_text(stmt, 0);
			if (uris) {
				const char *p = uris;
				while (p && *p) {
					while (*p == ' ') p++;
					const char *comma = strchr(p, ',');
					size_t len = comma ? lws_ptr_diff_size_t(comma, p) : strlen(p);
					while (len > 0 && p[len - 1] == ' ') len--;
					while (len > 0 && p[len - 1] == '/') len--;
					if (len > 0) {
						if (!strncmp(redirect_uri, p, len)) {
							char next = redirect_uri[len];
							if (next == '\0' || next == '/' || next == '?' || next == '#') {
								valid = 1;
								break;
							}
						}
					}
					p = comma ? comma + 1 : NULL;
				}
			}
		}
		sqlite3_finalize(stmt);
	}
	return valid;
}

static int
simple_response(struct lws *wsi, struct pss_login *pss, const char *msg, const char *mime_type,
	     unsigned int code, unsigned char *start, unsigned char **p, unsigned char *end)
{
        char eb[LWS_PRE + 1024];
	int l = lws_snprintf(eb + LWS_PRE, sizeof(eb) - LWS_PRE, "%s", msg);

	if (lws_add_http_common_headers(wsi, code, mime_type, (lws_filepos_t)l, p, end))
		return -1;

        if (lws_finalize_write_http_header(wsi, start, p, end))
                return -1;

	if (lws_buflist_append_segment(&pss->tx_buflist, (unsigned char*)eb + LWS_PRE, (size_t)l) < 0)
		return -1;

	lws_callback_on_writable(wsi);

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

	switch ((int)reason) {
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

	case LWS_CALLBACK_USER + 1:
	{
		int level = -1;
		struct lws_jwt_auth *ja;
		const char *service_name;
		const struct lws_http_mount *mount;
		char uri[256];

		vhd = (struct vhd_login *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi),
				lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-login"));

		if (!vhd)
			return 1;

		service_name = vhd->service_name;
		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0 ||
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) > 0) {
			if (uri[0]) {
				mount = lws_find_mount(wsi, uri, (int)strlen(uri));
				if (mount) {
					if (!lws_pmo_get_str(mount, "service-name", &service_name)) {
						lwsl_info("%s: using service_name %s from target pmo for bypass api\n", __func__, service_name);
					}
#if defined(LWS_WITH_JOSE)
					else if (mount->interceptor_path) {
						const struct lws_http_mount *im = mount;
						while (im && im->interceptor_path) {
							im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
							if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
								lwsl_info("%s: using service_name %s from interceptor pmo for bypass api\n", __func__, service_name);
								break;
							}
						}
					}
#endif
				}
			}
		}

		if (!service_name)
			service_name = "";

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi);
		if (ja) {
			level = lws_jwt_auth_query_grant(ja, service_name);
			lws_jwt_auth_destroy(&ja);
			if (level >= vhd->min_grant_level)
				return 0; /* Authentic and authorized */
		}
		return 1; /* Unauthenticated */
	}

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
			    lws_login_ends_with(uri, "/.lws-login-sso") ||
			    lws_login_ends_with(uri, "/.lws-login-logout") ||
			    lws_login_ends_with(uri, "/.lws-login-refresh"))
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
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
							lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
							break;
						}
					}
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
		char dest[512], path[256], urlenc_path[512];
		const struct lws_http_mount *mount;
		int whitelist_failed = 0;
		const char *service_name;
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
				if (!lws_pmo_get_str(mount, "service-name", &service_name))
					lwsl_info("%s: using service_name %s from target pmo\n", __func__, service_name);

#if defined(LWS_WITH_JOSE)
				else if (mount->interceptor_path) {
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
							lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
							break;
						}
					}
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

			if (!match)
				whitelist_failed = 1;
		}

		if (whitelist_failed)
                  return simple_response(
                      wsi, pss, "Page Unreachable", "text/plain", 403,
                      (unsigned char *)buf + LWS_PRE, (unsigned char **)&p,
                      (unsigned char *)end);

                if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) > 0 &&
		    lws_login_ends_with(path, "/.lws-login-sso"))
			return 0; /* Fall through to LWS_CALLBACK_HTTP_BODY */

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

				if (vhd->cookie_domain[0])
					lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							 vhd->cookie_name, pss->silent_update_jwt, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
				else
					lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							 vhd->cookie_name, pss->silent_update_jwt, (unsigned long long)vhd->jwt_validity_secs);

				path[0] = '\0';
				if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) < 0)
					lwsl_debug("%s: URI copy failed\n", __func__);

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
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) <= 0)
			if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
				lwsl_debug("%s: URI copy failed\n", __func__);

		if (lws_login_ends_with(path, "/lws-login.css")) {
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/css",
							(lws_filepos_t)strlen(canned_css), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(canned_css);
			int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)canned_css, len);
			if (res < 0)
				return -1;
			lws_callback_on_writable(wsi);

			return 0;
		}

		if (lws_login_ends_with(path, "/lws-login.js")) {
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/javascript",
							(lws_filepos_t)strlen(canned_js), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(canned_js);
			int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)canned_js, len);
			if (res < 0)
				return -1;
			lws_callback_on_writable(wsi);

			return 0;
		}

		if (lws_login_ends_with(path, "/.lws-login-refresh")) {
			char csrf[64] = {0};
			size_t csrf_len = sizeof(csrf);
			char refresh_session[16] = {0};
			size_t refresh_session_len = sizeof(refresh_session);
			int ck_len;

			ck_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);

			if (ck_len > 0) {
				char *cookie = malloc((size_t)ck_len + 1);
				if (cookie) {
					if (lws_hdr_copy(wsi, cookie, ck_len + 1, WSI_TOKEN_HTTP_COOKIE) > 0) {
						lws_http_cookie_get(wsi, "auth_csrf", csrf, &csrf_len);
						
						/* We just need to know it exists to proceed */
						if (lws_http_cookie_get(wsi, "auth_refresh_session", refresh_session, &refresh_session_len) == 0 && csrf[0]) {
							struct pending_login_refresh *ps = malloc(sizeof(*ps));
							if (ps) {
								struct lws_client_connect_info i;
								lws_parse_uri_t *puri;

								memset(ps, 0, sizeof(*ps));
								ps->vhd = vhd;
								ps->wsi_server = wsi;
								lws_strncpy(ps->cookie_hdr, cookie, sizeof(ps->cookie_hdr));

								ps->payload_len = lws_snprintf(ps->payload, sizeof(ps->payload), "csrf_token=%s", csrf);
								ps->payload_pos = 0;

								lws_dll2_add_tail(&ps->list, &vhd->pending_refresh_list);
								lws_sul_schedule(vhd->context, 0, &ps->sul, sul_pending_refresh_cb, 5 * 60 * LWS_US_PER_SEC);

								puri = lws_parse_uri_create(vhd->auth_server_url);
								if (puri) {
									lwsl_notice("%s: Intercepted background refresh request, initiating proxy to %s/api/sso_exchange\n", __func__, vhd->auth_server_url);
									memset(&i, 0, sizeof(i));
									i.context        = vhd->context;
									i.address        = puri->host;
									i.port           = puri->port;
									i.ssl_connection = !strcmp(puri->scheme, "http") ? 0 : LCCSCF_USE_SSL;
									i.path           = "/api/sso_exchange";
									i.host           = i.address;
									i.origin         = i.address;
									i.method         = "POST";
									i.protocol       = "lws_login_client";
									i.pwsi           = &ps->wsi_client;
									i.userdata       = ps;

									lws_client_connect_via_info(&i);
									lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);
									lws_parse_uri_destroy(&puri);

									free(cookie);
									return 0; // Suspend!
								}
								free(ps);
							}
						}
					}
					free(cookie);
				}
			}
			/* Failure or no cookies, 401 Unauthorized */
			lwsl_notice("%s: Missing or malformed cookies for background refresh\n", __func__);
                        return simple_response(wsi, pss, "Missing Authorization", "text/plain",
                                            HTTP_STATUS_UNAUTHORIZED, (unsigned char *)buf + LWS_PRE,
                                            (unsigned char **)&p, (unsigned char *)end);
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

			if (pss && pss->ja) {
				const char *sub = lws_jwt_auth_get_sub(pss->ja);
				int is_admin = lws_jwt_auth_query_grant(pss->ja, "*") >= 1 ||
					       lws_jwt_auth_query_grant(pss->ja, service_name) >= 2;
				int has_grant = lws_jwt_auth_query_grant(pss->ja, service_name) >= vhd->min_grant_level;
				lws_snprintf(pl, sizeof(pl), "{\"logged_in\":1,\"exp\":%llu,\"has_grant\":%d,\"identity\":\"%s\",\"auth_server_url\":\"%s\",\"login_url\":\"%s\",\"is_admin\":%d}",
					(unsigned long long)lws_jwt_auth_get_exp(pss->ja), has_grant, sub ? sub : "Unknown", vhd->auth_server_url, dest, is_admin);
			} else
				lws_snprintf(pl, sizeof(pl), "{\"logged_in\":0,\"login_url\":\"%s\"}", dest);

                        return simple_response(wsi, pss, pl, "application/json",
                                               HTTP_STATUS_OK, (unsigned char *)buf + LWS_PRE, (unsigned char **)&p,
                                               (unsigned char *)end);
		}

		if (lws_login_ends_with(path, "/.lws-login-logout")) {
			char redirect_uri[512];
			char u[1024];
			char cookie_hdr1[256], cookie_hdr1_host[256];
			char exp[64];
			time_t t = 0;
			struct tm *tm = gmtime(&t);
			strftime(exp, sizeof(exp), "%a, %d %b %Y %H:%M:%S GMT", tm);

			redirect_uri[0] = '\0';
			if (lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", redirect_uri, sizeof(redirect_uri)) >= 0)
				lws_urldecode(redirect_uri, redirect_uri, sizeof(redirect_uri));
			if (!redirect_uri[0])
				lws_strncpy(redirect_uri, "/", sizeof(redirect_uri));

			if (vhd->cookie_domain[0])
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, vhd->cookie_domain, exp);
			else
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);

			lws_snprintf(cookie_hdr1_host, sizeof(cookie_hdr1_host), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);

			char urlenc_path[512];
			lws_urlencode(urlenc_path, redirect_uri, sizeof(urlenc_path));

			if (vhd->auth_server_url && vhd->auth_server_url[0]) {
				lws_snprintf(u, sizeof(u), "%s/api/logout?redirect_uri=%s", vhd->auth_server_url, urlenc_path);
			} else {
				/* Fallback if auth_server_url somehow missing */
				lws_strncpy(u, redirect_uri, sizeof(u));
			}

			char html[1024];
			int html_len = lws_snprintf(html, sizeof(html),
				"<html lang=\"en\"><head><meta http-equiv=\"refresh\" content=\"0; url=%s\"></head><body>Redirecting to <a href=\"%s\">%s</a></body></html>",
				u, u, u);
			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)html, (size_t)html_len) < 0) return -1;

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_SEE_OTHER, "text/html", (unsigned int)html_len, (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1, (int)strlen(cookie_hdr1), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1_host, (int)strlen(cookie_hdr1_host), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)u, (int)strlen(u), (unsigned char **)&p, (unsigned char *)end)) return 1;
			goto fin_hdrs;
		}

		lwsl_info("%s: bouncing unauth to %s\n", __func__, dest);

		char html[1024];
		int html_len = lws_snprintf(html, sizeof(html),
			"<html lang=\"en\"><head><meta http-equiv=\"refresh\" content=\"0; url=%s\"></head><body>Redirecting to <a href=\"%s\">%s</a></body></html>",
			dest, dest, dest);
		if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)html, (size_t)html_len) < 0) return -1;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_SEE_OTHER, "text/html", (unsigned int)html_len, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
				(unsigned char *)dest, (int)strlen(dest), (unsigned char **)&p, (unsigned char *)end))
			return 1;
 fin_hdrs:
		if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
		lws_callback_on_writable(wsi);
		return 0;
	}

	case LWS_CALLBACK_HTTP_BODY:
	{
		char path[256];
		path[0] = '\0';
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
			lwsl_debug("%s: URI copy failed\n", __func__);

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
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
			lwsl_debug("%s: URI copy failed\n", __func__);

		if (lws_login_ends_with(path, "/.lws-login-sso")) {
			if (pss->spa) {
				lws_spa_finalize(pss->spa);
				const char *token = lws_spa_get_string(pss->spa, EPN_TOKEN);
				const char *target = lws_spa_get_string(pss->spa, EPN_TARGET);

				char origin[128];
				if (token && vhd && vhd->auth_server_url && lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN) > 0) {
					size_t olen = strlen(origin);
					if (olen == 4 && !strcmp(origin, "null")) {
						lwsl_notice("%s: allowing null origin due to redirect bounce\n", __func__);
					} else if (strncmp(origin, vhd->auth_server_url, olen) ||
						   (vhd->auth_server_url[olen] != '\0' && vhd->auth_server_url[olen] != '/')) {
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
						if (auth_verify_redirect_uri(vhd, target)) {
							final_target = target;
						} else {
							lwsl_err("%s: untrusted absolute target %s\n", __func__, target);
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
					int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)err, (size_t)err_len);
					if (res < 0) return -1;
					lws_callback_on_writable(wsi);
					return 0;
				}
			}
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
	{
		unsigned char buf[2048 + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
		struct pending_login_refresh *ps = NULL;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_refresh_list)) {
			struct pending_login_refresh *s = lws_container_of(d, struct pending_login_refresh, list);

			if (s->wsi_server == wsi) {
				ps = s;
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (ps) {
			if (ps->token[0]) {
				char cookie[2048];
				int n;

				if (vhd->cookie_domain[0]) {
					n = lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							 vhd->cookie_name, ps->token, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
				} else {
					n = lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
							 vhd->cookie_name, ps->token, (unsigned long long)vhd->jwt_validity_secs);
				}

				if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json", 13, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie, n, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;

				lws_write(wsi, buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
				if (lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)"{\"success\":1}", 13) < 0) return -1;
				lwsl_notice("%s: Successfully issued refreshed token to browser via BFF\n", __func__);
			} else {
				if (lws_add_http_common_headers(wsi, HTTP_STATUS_UNAUTHORIZED, "application/json", 13, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
				lws_write(wsi, buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
				if (lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)"{\"success\":0}", 13) < 0) return -1;
				lwsl_notice("%s: BFF SSO Exchange denied by Server\n", __func__);
			}

			lws_sul_cancel(&ps->sul);
			lws_dll2_remove(&ps->list);
			free(ps);

			lws_callback_on_writable(wsi);

			return 0;
		}

		if (!pss || !pss->tx_buflist)
			break;

		uint8_t *pout;
		size_t bytes = lws_buflist_next_segment_len(&pss->tx_buflist, &pout);

		if (!bytes)
			break;

		size_t chunk = bytes;
		if (chunk > sizeof(buf) - LWS_PRE)
			chunk = sizeof(buf) - LWS_PRE;

		memcpy(p, pout, chunk);

		int flags = LWS_WRITE_HTTP;
		if (chunk == lws_buflist_total_len(&pss->tx_buflist))
			flags = LWS_WRITE_HTTP_FINAL;

		int m = lws_write(wsi, p, (unsigned int)chunk, (enum lws_write_protocol)flags);
		if (m < 0) return -1;

		lws_buflist_use_segment(&pss->tx_buflist, (size_t)m);

		if (lws_buflist_next_segment_len(&pss->tx_buflist, &pout)) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		return lws_http_transaction_completed(wsi);
	}

	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_CLOSED:
		if (pss && pss->tx_buflist)
			lws_buflist_destroy_all_segments(&pss->tx_buflist);

		if (pss && pss->ja)
			lws_jwt_auth_destroy(&pss->ja);

                if (pss && pss->silent_update_jwt) {
			free(pss->silent_update_jwt);
			pss->silent_update_jwt = NULL;
		}

		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}

		if (vhd) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						   lws_dll2_get_head(&vhd->pending_refresh_list)) {
				struct pending_login_refresh *s = lws_container_of(d, struct pending_login_refresh, list);

                                if (s->wsi_server == wsi) {
					s->wsi_server = NULL;
					lwsl_notice("%s: cleared dangling wsi_server from pending refresh\n", __func__);
				}
			} lws_end_foreach_dll_safe(d, d1);
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
	LWS_PLUGIN_PROTOCOL_LWS_LOGIN,
	{
		.name = "lws_login_client",
		.callback = callback_lws_login_client,
		.per_session_data_size = 0,
		.rx_buffer_size = 0,
		.id = 0,
		.user = NULL,
		.tx_packet_size = 0
	}
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
