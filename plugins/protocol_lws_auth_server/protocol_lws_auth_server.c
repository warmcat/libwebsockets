/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#endif

#include <libwebsockets.h>

#include <sqlite3.h>
#include <string.h>
#include <time.h>

#define LWS_AUTH_MAX_COOKIE_LEN 4096

static const char * const param_names[] = {
	"username",
	"password",
	"totp",
	"csrf_token",
	"client_id",
	"redirect_uri",
	"state",
	"code_challenge",
	"code_challenge_method",
	"grant_type",
	"code",
	"client_secret",
	"code_verifier",
	"service_name"
};

enum enum_param_names {
        EP_USER,
        EP_PASS,
        EP_TOTP,
        EP_CSRF,
        EP_CLIENT_ID,
        EP_REDIRECT_URI,
        EP_STATE,
        EP_CODE_CHALLENGE,
        EP_CODE_CHALLENGE_METHOD,
        EP_GRANT_TYPE,
        EP_CODE,
        EP_CLIENT_SECRET,
        EP_CODE_VERIFIER,
        EP_SERVICE_NAME,
        EP_COUNT
};

struct per_vhost_data__auth_server {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	const struct lws_protocols	*protocol;
	sqlite3				*db;
	char				db_path[256];
	char				auth_domain[128];
	char				cookie_domain[128];
	char				jwk_path[256];
	char				jwt_alg[16];
	char				cookie_name[64];
	unsigned long long		jwt_validity_secs;
	struct lws_jwk			jwk;
	int				registration_ui;
	char				email_from[128];
	char				email_subject[256];
	char				email_body[1024];
	const lws_smtp_client_ops_t	*smtp;
	lws_dll2_owner_t		ip_strikes;
	lws_dll2_owner_t		ip_bans;
	char				jwks_json[8192];
	char				ui_title[256];
	char				ui_subtitle[256];
	char				ui_new_network[256];
	char				ui_css[256];
	unsigned long long		refresh_token_validity_secs;
	unsigned int			auth_log_limit;
};

typedef struct auth_server_strike {
	lws_dll2_t			list;
	char				ip[64];
	uint64_t			last_strike;
	int				strikes;
} auth_server_strike_t;

typedef struct auth_server_ban {
	lws_dll2_t			list;
	char				ip[64];
	uint64_t			banned_until;
} auth_server_ban_t;

typedef struct lws_auth_user {
	lws_dll2_t			list;
	uint32_t			uid;
	const char			*username;
	const char			*password_hash;
	const char			*salt;
	const char			*totp_secret;
} lws_auth_user_t;

typedef struct lws_auth_service {
	lws_dll2_t			list;
	uint32_t			service_id;
	const char			*name;
} lws_auth_service_t;

typedef struct lws_auth_grant {
	lws_dll2_t			list;
	uint32_t			grant_id;
	uint32_t			uid;
	uint32_t			service_id;
	uint32_t			grant_level;
} lws_auth_grant_t;

typedef struct lws_auth_registration {
	lws_dll2_t			list;
	const char			*email;
	const char			*password_hash;
	const char			*salt;
	const char			*totp_secret;
	const char			*verify_hash;
	unsigned long long		expires;
} lws_auth_registration_t;

struct per_session_data__auth_server {
	struct lws_spa                  *spa;
	char                            requesting_url[64];
	unsigned int                    http_response_code;
	int                             totp_required;
	struct lws_buflist              *tx_buflist;
};

static const char *schema_init =

	"CREATE TABLE IF NOT EXISTS users ("
	"  uid INTEGER PRIMARY KEY AUTOINCREMENT,"
	"  username VARCHAR UNIQUE,"
	"  password_hash VARCHAR,"
	"  salt VARCHAR,"
	"  totp_secret VARCHAR"
	");"
	"CREATE TABLE IF NOT EXISTS services ("
	"  service_id INTEGER PRIMARY KEY AUTOINCREMENT,"
	"  name VARCHAR UNIQUE"
	");"
	"CREATE TABLE IF NOT EXISTS grants ("
	"  grant_id INTEGER PRIMARY KEY AUTOINCREMENT,"
	"  uid INTEGER REFERENCES users(uid),"
	"  service_id INTEGER REFERENCES services(service_id),"
	"  grant_level INTEGER,"
	"  UNIQUE(uid, service_id)"
	");"
	"CREATE TABLE IF NOT EXISTS registrations ("
	"  email TEXT UNIQUE PRIMARY KEY,"
	"  password_hash TEXT,"
	"  salt TEXT,"
	"  totp_secret TEXT,"
	"  verify_hash TEXT,"
	"  expires INTEGER"
	");"
	"CREATE TABLE IF NOT EXISTS bans ("
	"  ip TEXT UNIQUE PRIMARY KEY,"
	"  banned_until INTEGER"
	");"
	"CREATE TABLE IF NOT EXISTS oauth_clients ("
	"  client_id VARCHAR PRIMARY KEY,"
	"  client_secret_hash VARCHAR,"
	"  redirect_uris TEXT,"
	"  name VARCHAR"
	");"
	"CREATE TABLE IF NOT EXISTS oauth_codes ("
	"  code VARCHAR PRIMARY KEY,"
	"  client_id VARCHAR REFERENCES oauth_clients(client_id),"
	"  uid INTEGER REFERENCES users(uid),"
	"  redirect_uri VARCHAR,"
	"  expires INTEGER,"
	"  scope VARCHAR,"
	"  code_challenge VARCHAR,"
	"  code_challenge_method VARCHAR"
	");"
	"CREATE TABLE IF NOT EXISTS auth_sessions ("
	"  session_id VARCHAR PRIMARY KEY,"
	"  uid INTEGER REFERENCES users(uid),"
	"  expires INTEGER"
	");"
	"CREATE TABLE IF NOT EXISTS auth_log ("
	"  uid INTEGER REFERENCES users(uid),"
	"  issue_time INTEGER,"
	"  ip_address TEXT"
	");";

static int
lws_auth_totp_compute(const char *secret_b32, uint64_t t, uint32_t *code)
{
	uint8_t secret[64], t_bytes[8], hmac_result[LWS_GENHASH_LARGEST];
	struct lws_genhmac_ctx hmac_ctx;
	int secret_len, offset;
	uint32_t u;

	secret_len = lws_b32_decode_string_len(secret_b32, -1, (char *)secret, sizeof(secret));
	if (secret_len <= 0)
		return -1;

	lws_ser_wu64be(t_bytes, t);

	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, secret,
				(size_t)secret_len))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, t_bytes, 8)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);

		return -1;
	}

	if (lws_genhmac_destroy(&hmac_ctx, hmac_result))
		return -1;

	offset = hmac_result[19] & 0x0f;
	u = lws_ser_ru32be(&hmac_result[offset]) & 0x7fffffff;

	*code = u % 1000000;

	return 0;
}

static int
lws_auth_totp_verify(const char *secret_b32, uint32_t code)
{
	uint64_t t = (uint64_t)time(NULL) / 30;
	uint32_t c;
	int i;

	/* check current, previous, and next window to allow for clock drift */
	for (i = -1; i <= 1; i++)
		if (!lws_auth_totp_compute(secret_b32, (uint64_t)((int64_t)t + i), &c) &&
		    c == code)
			return 0;

	return -1;
}

static int
lws_auth_issue_jwt(struct per_vhost_data__auth_server *vhd,
                   const char *username, uint32_t uid,
                   const char *claims_json,
                   char *out, size_t *out_len)
{
	char temp[2048]; /* scratchpad for JWK/JWS generation */
	uint64_t now = (uint64_t)time(NULL);
	uint64_t exp = now + vhd->jwt_validity_secs;

	/* The format string maps directly to the JWS payload */
	int sig_ret = lws_jwt_sign_compact(vhd->context, &vhd->jwk, vhd->jwt_alg,
	                         out, out_len, temp, sizeof(temp),
	                         "{\"iss\":\"%s\",\"sub\":\"%s\",\"uid\":%u,"
	                         "\"iat\":%llu,\"exp\":%llu%s%s}",
	                         vhd->auth_domain, username, uid,
	                         (unsigned long long)now, (unsigned long long)exp,
	                         claims_json ? "," : "",
	                         claims_json ? claims_json : "");
	if (sig_ret) {
		lwsl_err("JWT sig failed (%d)\n", sig_ret);
		return sig_ret;
	}

	return 0;
}

static int
lws_auth_generate_token(struct per_vhost_data__auth_server *vhd,
                        const char *username, uint32_t uid,
                        const char *peer_ip, char *out, size_t *out_len)
{
	char claims[512];
	char *p = claims;
	char *end = claims + sizeof(claims);
	sqlite3_stmt *stmt;
	const char *query =
		"SELECT s.name, g.grant_level "
		"FROM grants g JOIN services s ON g.service_id = s.service_id "
		"WHERE g.uid = ?";
	int first = 1;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"grants\":{");

	if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_int(stmt, 1, (int)uid);
		while (sqlite3_step(stmt) == SQLITE_ROW) {
			const char *svc_name = (const char *)sqlite3_column_text(stmt, 0);
			int level = sqlite3_column_int(stmt, 1);

			if (!svc_name)
				continue;

			if (!first)
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",");
			first = 0;

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				"\"%s\":%d", svc_name, level);
		}
		sqlite3_finalize(stmt);
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "}");

	if (vhd->auth_log_limit > 0 && peer_ip && peer_ip[0]) {
		if (sqlite3_prepare_v2(vhd->db, "INSERT INTO auth_log (uid, issue_time, ip_address) VALUES (?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_int(stmt, 1, (int)uid);
			sqlite3_bind_int64(stmt, 2, (sqlite_int64)time(NULL));
			sqlite3_bind_text(stmt, 3, peer_ip, -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
		}

		if (sqlite3_prepare_v2(vhd->db, "DELETE FROM auth_log WHERE uid = ? AND rowid NOT IN (SELECT rowid FROM auth_log WHERE uid = ? ORDER BY issue_time DESC LIMIT ?)", -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_int(stmt, 1, (int)uid);
			sqlite3_bind_int(stmt, 2, (int)uid);
			sqlite3_bind_int(stmt, 3, (int)vhd->auth_log_limit);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
		}
	}

	{
		char pub64[256];
		(void)lws_b64_encode_string((const char *)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
							(int)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len, pub64, sizeof(pub64));
		lwsl_info("auth_server issue: MATHEMATICAL PROOF -> JWK path loaded from '%s', Public X-Coord length '%d', Base64 X: '%s'\n",
			vhd->jwk_path[0] ? vhd->jwk_path : "NULL!!!", (int)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len, pub64);
	}

	return lws_auth_issue_jwt(vhd, username, uid, claims, out, out_len);
}

static int
lws_auth_check_credentials(struct per_vhost_data__auth_server *vhd,
                           const char *username, const char *password,
                           uint32_t *uid)
{
	sqlite3_stmt *stmt;
	const char *query = "SELECT uid, password_hash, salt FROM users WHERE username = ?";
        const char *stored_hash, *salt;
        struct lws_genhash_ctx ctx;
        uint8_t hash[64]; /* SHA-512 outputs 64 bytes */
	char hex[129]; /* 64 * 2 + 1 */
	int match = -1;

	if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) != SQLITE_OK) {
		lwsl_err("CHECK_CREDENTIALS: DB Prepare failed!\n");
		return -1;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		lwsl_notice("CHECK_CREDENTIALS: User '%s' not found in DB\n", username);
                goto bail;
	}

	*uid = (uint32_t)sqlite3_column_int(stmt, 0);
	stored_hash = (const char *)sqlite3_column_text(stmt, 1);
	salt = (const char *)sqlite3_column_text(stmt, 2);

	// lwsl_notice("CHECK_CREDENTIALS: user='%s'\n", username);

	/* hash the input password with SHA-512 and salt */
	if (!stored_hash || !salt || lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA512)) {
		lwsl_notice("CHECK_CREDENTIALS: init failed\n");
		goto bail;
	}

	if (lws_genhash_update(&ctx, (const uint8_t *)salt, strlen(salt))) {
		lwsl_notice("CHECK_CREDENTIALS: salt update failed\n");
		goto bail;
	}

	if (lws_genhash_update(&ctx, (const uint8_t *)password, strlen(password))) {
		lwsl_notice("CHECK_CREDENTIALS: pwd update failed\n");
		goto bail;
	}

	if (lws_genhash_destroy(&ctx, hash)) {
		lwsl_notice("CHECK_CREDENTIALS: hash destroy failed\n");
		goto bail;
	}

	lws_genhash_render(LWS_GENHASH_TYPE_SHA512, hash, hex, sizeof(hex));
	// lwsl_notice("CHECK_CREDENTIALS: Calculated hex='%s' (len %d)\n", hex, (int)strlen(hex));

        if (!strcmp(stored_hash, hex)) {
		// lwsl_notice("CHECK_CREDENTIALS: MATCH OK!\n");
		match = 0;
	} else
		lwsl_notice("CHECK_CREDENTIALS: MISMATCH!\n");

bail:
	sqlite3_finalize(stmt);

	return match;
}

static void
auth_record_strike(struct per_vhost_data__auth_server *vhd, const char *ip)
{
	auth_server_strike_t *strike = NULL;
	uint64_t now = (uint64_t)time(NULL);
	int strikes = 1;

	/* Find existing strike record */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_strikes.head) {
		auth_server_strike_t *s = lws_container_of(d, auth_server_strike_t, list);
		if (!strcmp(s->ip, ip)) {
			strike = s;
			break;
		}
	} lws_end_foreach_dll_safe(d, d1);

	if (!strike) {
		if (vhd->ip_strikes.count >= 128) {
			/* LRU eviction */
			auth_server_strike_t *s = lws_container_of(vhd->ip_strikes.head, auth_server_strike_t, list);
			lws_dll2_remove(&s->list);
			free(s);
		}
		strike = malloc(sizeof(*strike));
		if (!strike) return;
		memset(strike, 0, sizeof(*strike));
		lws_strncpy(strike->ip, ip, sizeof(strike->ip));
		lws_dll2_add_tail(&strike->list, &vhd->ip_strikes);
	} else {
		/* Apply decay: if last strike was > 120s ago, reset to 1 */
		if (now - strike->last_strike > 120)
			strike->strikes = 0;
		lws_dll2_remove(&strike->list);
		lws_dll2_add_tail(&strike->list, &vhd->ip_strikes); /* move to tail (LRU) */
	}

	strike->last_strike = now;
	strike->strikes++;
	strikes = strike->strikes;

	lwsl_notice("%s: IP %s recorded strike %d\n", __func__, ip, strikes);

	if (strikes >= 5) {
		lwsl_warn("%s: Banning IP %s due to heavy abuse\n", __func__, ip);

		auth_server_ban_t *ban = malloc(sizeof(*ban));
		if (!ban) return;
		memset(ban, 0, sizeof(*ban));
		lws_strncpy(ban->ip, ip, sizeof(ban->ip));
		ban->banned_until = now + (24 * 3600); /* 24 hours */
		lws_dll2_add_tail(&ban->list, &vhd->ip_bans);

		sqlite3_stmt *stmt;
		if (sqlite3_prepare_v2(vhd->db, "INSERT OR REPLACE INTO bans (ip, banned_until) VALUES (?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
			sqlite3_bind_int64(stmt, 2, (sqlite_int64)ban->banned_until);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
		}

		/* wipe strikes so future lookups are clean */
		lws_dll2_remove(&strike->list);
		free(strike);
	}
}

static void
auth_clear_strike(struct per_vhost_data__auth_server *vhd, const char *ip)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_strikes.head) {
		auth_server_strike_t *s = lws_container_of(d, auth_server_strike_t, list);
		if (!strcmp(s->ip, ip)) {
			lws_dll2_remove(&s->list);
			free(s);
			return;
		}
	} lws_end_foreach_dll_safe(d, d1);
}

static int
auth_verify_redirect_uri(struct per_vhost_data__auth_server *vhd,
			 const char *client_id, const char *redirect_uri)
{
	sqlite3_stmt *stmt;
	int valid = 0;

	if (!redirect_uri || !redirect_uri[0])
		return 0;

	if (strstr(redirect_uri, "../") || strstr(redirect_uri, "..%2F") ||
	    strstr(redirect_uri, "..%2f"))
		return 0;

	if (client_id && client_id[0]) {
		if (sqlite3_prepare_v2(vhd->db, "SELECT redirect_uris FROM oauth_clients WHERE client_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_STATIC);
			if (sqlite3_step(stmt) == SQLITE_ROW) {
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
	} else {
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
	}
	return valid;
}

static int
send_auth_headers(struct lws *wsi, struct per_session_data__auth_server *pss, const char *content_type, const char *cookie1, const char *cookie2)
{
	uint8_t buf[2048 + LWS_PRE], *start = &buf[LWS_PRE], *p = start, *end = &buf[sizeof(buf) - 1], *pq;
	unsigned int resp_code = pss->http_response_code ? pss->http_response_code : HTTP_STATUS_OK;
        size_t amount = (size_t)lws_buflist_next_segment_len(&pss->tx_buflist, &pq);

        if (lws_add_http_common_headers(wsi, resp_code, content_type,
                                        (unsigned int)(amount ? amount - LWS_PRE: LWS_ILLEGAL_HTTP_CONTENT_LEN), &p,
                                        end)) {
                lwsl_info("send_auth_headers custom hdr err\n");

                return -1;
        }
        if (pss->totp_required &&
            lws_add_http_header_by_name(wsi, (unsigned char *)"X-Requires-TOTP:", (unsigned char *)"1", 1, &p, end)) {
                lwsl_info("send_auth_headers custom hdr err\n");

                return -1;
        }

        if (lws_add_http_header_by_name(wsi, (unsigned char *)"Cache-Control:", (unsigned char *)"no-cache, no-store, must-revalidate", 35, &p, end)) return -1;
        if (lws_add_http_header_by_name(wsi, (unsigned char *)"Pragma:", (unsigned char *)"no-cache", 8, &p, end)) return -1;
        if (lws_add_http_header_by_name(wsi, (unsigned char *)"Expires:", (unsigned char *)"0", 1, &p, end)) return -1;

	if (cookie1 && lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie1, (int)strlen(cookie1), &p, end)) {
		lwsl_info("send_auth_headers cookie1 hdr err\n");
		return -1;
	}
	if (cookie2 && lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie2, (int)strlen(cookie2), &p, end)) {
		lwsl_info("send_auth_headers cookie2 hdr err\n");
		return -1;
	}
	if (lws_finalize_write_http_header(wsi, start, &p, end)) {
		lwsl_info("send_auth_headers final hdr err\n");
		return -1;
	}

        if (pss->tx_buflist)
                lws_callback_on_writable(wsi);
        else
                return lws_http_transaction_completed(wsi);

        return 0;
}

static int
auth_check_csrf(struct lws *wsi, struct per_vhost_data__auth_server *vhd, struct per_session_data__auth_server *pss)
{
	const char *csrf_form = lws_spa_get_string(pss->spa, EP_CSRF);
	char csrf_ck[64] = {0};
	size_t csrf_len = sizeof(csrf_ck);

	lws_http_cookie_get(wsi, "auth_csrf", csrf_ck, &csrf_len);

	if (!csrf_form || !csrf_ck[0] || strcmp(csrf_ck, csrf_form)) {
		char dbg_cookie[4096] = {0};
		if (lws_hdr_copy(wsi, dbg_cookie, sizeof(dbg_cookie), WSI_TOKEN_HTTP_COOKIE) < 0)
			strncpy(dbg_cookie, "<overrun or empty>", sizeof(dbg_cookie) - 1);
		lwsl_notice("%s: CSRF validation natively failed. form='%s' cookie='%s' RAW_COOKIE='%s'\n", __func__, csrf_form ? csrf_form : "NULL", csrf_ck[0] ? csrf_ck : "NULL", dbg_cookie);
		char peer[64];
		lws_get_peer_simple(wsi, peer, sizeof(peer));
		auth_record_strike(vhd, peer);
		return -1;
	}
	return 0;
}

static int
lws_auth_api_sso_exchange(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
			  struct per_session_data__auth_server *pss)
{
	char pl[1024 + LWS_PRE];
	int len;

	if (auth_check_csrf(wsi, vhd, pss)) {
		pss->http_response_code = HTTP_STATUS_FORBIDDEN;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"CSRF validation failed\"}");
		goto send;
	}

	char cookie_hdr[2048] = {0};
	char refresh_hdr[2048] = {0};
	uint32_t uid = 0;

	const char *redirect_uri = lws_spa_get_string(pss->spa, EP_REDIRECT_URI);
	if (redirect_uri && redirect_uri[0]) {
		if (!auth_verify_redirect_uri(vhd, NULL, redirect_uri)) {
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Untrusted redirect URI\"}");
			goto send;
		}
	}

	struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
	int was_refreshed = 0;

	if (ja) {
		uid = lws_jwt_auth_get_uid(ja);
		lws_jwt_auth_destroy(&ja);
	} else if (vhd->refresh_token_validity_secs > 0) {
		char refresh_tk[128] = {0};
		size_t refresh_len = sizeof(refresh_tk);

		if (lws_http_cookie_get(wsi, "auth_refresh_session", refresh_tk, &refresh_len) == 0 && refresh_tk[0]) {
			sqlite3_stmt *stmt;
			uint64_t now = (uint64_t)time(NULL);
			if (sqlite3_prepare_v2(vhd->db, "SELECT uid, expires FROM auth_sessions WHERE session_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, refresh_tk, -1, SQLITE_TRANSIENT);
				if (sqlite3_step(stmt) == SQLITE_ROW) {
					uint64_t exp = (uint64_t)sqlite3_column_int64(stmt, 1);
					if (now < exp) {
						uid = (uint32_t)sqlite3_column_int(stmt, 0);
						was_refreshed = 1;
					}
				}
				sqlite3_finalize(stmt);
			}
		}
	}

	if (!uid) {
		pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid session\"}");
		goto send;
	}

	char username[128] = {0};
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(vhd->db, "SELECT username FROM users WHERE uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_int(stmt, 1, (int)uid);
		if (sqlite3_step(stmt) == SQLITE_ROW)
			lws_strncpy(username, (const char *)sqlite3_column_text(stmt, 0), sizeof(username));
		sqlite3_finalize(stmt);
	}

	char jwt[1024];
	size_t jwt_len = sizeof(jwt);
	char peer[64];
	lws_get_peer_simple(wsi, peer, sizeof(peer));

	if (!lws_auth_generate_token(vhd, username, uid, peer, jwt, &jwt_len)) {
		pss->http_response_code = HTTP_STATUS_OK;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"token\":\"%s\"}", jwt);
		
		if (was_refreshed && vhd->cookie_name[0]) {
			if (vhd->cookie_domain[0]) {
				lws_snprintf(cookie_hdr, sizeof(cookie_hdr),
					"%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					vhd->cookie_name, jwt, vhd->cookie_domain,
					vhd->jwt_validity_secs);
			} else {
				lws_snprintf(cookie_hdr, sizeof(cookie_hdr),
					"%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					vhd->cookie_name, jwt,
					vhd->jwt_validity_secs);
			}
		}
		goto send;
	}

	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"server_error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json", cookie_hdr[0] ? cookie_hdr : NULL, refresh_hdr[0] ? refresh_hdr : NULL);
}

static int
lws_auth_api_login(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
		   struct per_session_data__auth_server *pss)
{
	char peer[64], jwt[1024], pl[1024 + LWS_PRE];
	const char *user, *pass;
	int len, users_empty = 0;
	char cookie_hdr[2048] = {0};
	char refresh_hdr[2048] = {0};

	if (auth_check_csrf(wsi, vhd, pss)) {
		pss->http_response_code = HTTP_STATUS_FORBIDDEN;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"CSRF validation failed\"}");
		goto send;
	}

	user = lws_spa_get_string(pss->spa, EP_USER);
	pass = lws_spa_get_string(pss->spa, EP_PASS);
	const char *totp_code_str = lws_spa_get_string(pss->spa, EP_TOTP);
        sqlite3_stmt *stmt_chk, *stmt;
        size_t jwt_len = sizeof(jwt);
        char totp_secret[64] = {0};
        uint32_t uid = 0;

        lws_get_peer_simple(wsi, peer, sizeof(peer));

        if (sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1,
				   &stmt_chk, NULL) == SQLITE_OK) {
		if (sqlite3_step(stmt_chk) == SQLITE_ROW &&
			sqlite3_column_int(stmt_chk, 0) == 0) {
			users_empty = 1;
		}
		sqlite3_finalize(stmt_chk);
	}

	if (users_empty) {
		lwsl_info("login rejected (database completely empty)\n");
		auth_record_strike(vhd, peer);
		pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
                len = lws_snprintf(
                    pl + LWS_PRE, sizeof(pl) - LWS_PRE,
                    "{\"error\":\"Network uninitialized. Click 'Register here' "
                    "below to bootstrap the Administrator account.\"}");
                goto send;
        }

	if (!user || !pass) {
		lwsl_err("%s: Missing user or pass parameter\n", __func__);
		auth_record_strike(vhd, peer);
		pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Missing parameter\"}");
		goto send;
	}

	if (lws_auth_check_credentials(vhd, user, pass, &uid)) {
		lwsl_err("%s: Validation failed for user '%s'\n", __func__, user);
		lwsl_info("login bad credentials\n");
		auth_record_strike(vhd, peer);
		pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Validation failed\"}");
		goto send;
	}

	lwsl_user("%s: User '%s' validated successfully (uid %u)\n", __func__, user, uid);

	const char *query = "SELECT totp_secret FROM users WHERE uid = ?";

	if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_int(stmt, 1, (int)uid);
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			const char *stored_totp = (const char *)sqlite3_column_text(stmt, 0);
			if (stored_totp && stored_totp[0])
				lws_strncpy(totp_secret, stored_totp, sizeof(totp_secret));
		}
		sqlite3_finalize(stmt);
	}

	const char *client_id = lws_spa_get_string(pss->spa, EP_CLIENT_ID);
	const char *redirect_uri = lws_spa_get_string(pss->spa, EP_REDIRECT_URI);

	if (totp_secret[0]) {
		if (!totp_code_str || !totp_code_str[0]) {
			lwsl_info("login missing TOTP\n");
			pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
			pss->totp_required = 1;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Authenticator Code Required\"}");
			goto send;
		}

		uint32_t code = (uint32_t)atoi(totp_code_str);
		if (lws_auth_totp_verify(totp_secret, code)) {
			auth_record_strike(vhd, peer);
			lwsl_info("login bad TOTP\n");
			pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Authenticator Code\"}");
			goto send;
		}
	}

	auth_clear_strike(vhd, peer);

	/* Emulate OAuth2 whitelist logic for native SSO redirect_uri requests */
	if ((!client_id || !client_id[0]) && redirect_uri && redirect_uri[0]) {
		if (!auth_verify_redirect_uri(vhd, NULL, redirect_uri)) {
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Untrusted redirect URI\"}");
			goto send;
		}
	}

	/* If this is an OAuth2 delegate login (i.e. has client_id/redirect_uri) */
	if (client_id && client_id[0] && redirect_uri && redirect_uri[0]) {
		const char *state = lws_spa_get_string(pss->spa, EP_STATE);
		const char *code_challenge = lws_spa_get_string(pss->spa, EP_CODE_CHALLENGE);
		const char *code_challenge_method = lws_spa_get_string(pss->spa, EP_CODE_CHALLENGE_METHOD);
		int client_valid = auth_verify_redirect_uri(vhd, client_id, redirect_uri);

		if (!client_valid) {
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid client_id or redirect_uri\"}");
			goto send;
		}

		uint8_t c_rnd[32];
		char code[65];
		uint64_t now = (uint64_t)time(NULL);
		uint64_t c_expires = now + 60;
		lws_get_random(vhd->context, c_rnd, 32);
		lws_hex_from_byte_array(c_rnd, 32, code, 65);

		if (sqlite3_prepare_v2(vhd->db, "INSERT INTO oauth_codes (code, client_id, uid, redirect_uri, expires, code_challenge, code_challenge_method) VALUES (?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_STATIC);
			sqlite3_bind_int(stmt, 3, (int)uid);
			sqlite3_bind_text(stmt, 4, redirect_uri, -1, SQLITE_STATIC);
			sqlite3_bind_int64(stmt, 5, (sqlite_int64)c_expires);
			sqlite3_bind_text(stmt, 6, code_challenge ? code_challenge : "", -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 7, code_challenge_method ? code_challenge_method : "", -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
		}

		pss->http_response_code = HTTP_STATUS_OK;
		char host[128] = {0};
		lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST);
		const char *delim = strchr(redirect_uri, '?') ? "&" : "?";
		if (state && state[0])
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"redirect\":\"%s%scode=%s&state=%s&iss=https%%3A%%2F%%2F%s\"}", redirect_uri, delim, code, state, host);
		else
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"redirect\":\"%s%scode=%s&iss=https%%3A%%2F%%2F%s\"}", redirect_uri, delim, code, host);
		goto send;
	}

	/* Fallback / Native mode: generate direct JWT */
	if (!lws_auth_generate_token(vhd, user, uid, peer, jwt, &jwt_len)) {
		pss->http_response_code = HTTP_STATUS_OK;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"token\":\"%s\"}", jwt);
		if (vhd->cookie_name[0]) {
			if (vhd->cookie_domain[0]) {
				lws_snprintf(cookie_hdr, sizeof(cookie_hdr),
					"%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					vhd->cookie_name, jwt, vhd->cookie_domain,
					vhd->jwt_validity_secs);
			} else {
				lws_snprintf(cookie_hdr, sizeof(cookie_hdr),
					"%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					vhd->cookie_name, jwt,
					vhd->jwt_validity_secs);
			}
		}

		if (vhd->refresh_token_validity_secs > 0) {
			uint8_t r_rnd[32];
			char refresh_code[65];
			uint64_t r_exp = (uint64_t)time(NULL) + vhd->refresh_token_validity_secs;
			lws_get_random(vhd->context, r_rnd, 32);
			lws_hex_from_byte_array(r_rnd, 32, refresh_code, 65);
			
			if (sqlite3_prepare_v2(vhd->db, "INSERT INTO auth_sessions (session_id, uid, expires) VALUES (?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, refresh_code, -1, SQLITE_STATIC);
				sqlite3_bind_int(stmt, 2, (int)uid);
				sqlite3_bind_int64(stmt, 3, (sqlite_int64)r_exp);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}

			if (vhd->cookie_domain[0]) {
				lws_snprintf(refresh_hdr, sizeof(refresh_hdr),
					"auth_refresh_session=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					refresh_code, vhd->cookie_domain, vhd->refresh_token_validity_secs);
			} else {
				lws_snprintf(refresh_hdr, sizeof(refresh_hdr),
					"auth_refresh_session=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
					refresh_code, vhd->refresh_token_validity_secs);
			}
		}

		goto send;
        }

	lwsl_info("login token generation failed, dropping conn.\n");
	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Internal Error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json", cookie_hdr[0] ? cookie_hdr : NULL, refresh_hdr[0] ? refresh_hdr : NULL);
}

static int
lws_auth_api_token(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
		   struct per_session_data__auth_server *pss)
{
	char jwt[1024], pl[1024 + LWS_PRE];
	const char *grant_type = lws_spa_get_string(pss->spa, EP_GRANT_TYPE);
	const char *code = lws_spa_get_string(pss->spa, EP_CODE);
	const char *client_id = lws_spa_get_string(pss->spa, EP_CLIENT_ID);
	const char *redirect_uri = lws_spa_get_string(pss->spa, EP_REDIRECT_URI);
	const char *client_secret = lws_spa_get_string(pss->spa, EP_CLIENT_SECRET);
	const char *code_verifier = lws_spa_get_string(pss->spa, EP_CODE_VERIFIER);
        sqlite3_stmt *stmt;
        int len, valid_client = 0;

        if (!grant_type || strcmp(grant_type, "authorization_code")) {
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"unsupported_grant_type\"}");
		goto send;
	}

	if (!code || !client_id || !redirect_uri) {
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_request\"}");
		goto send;
	}

	if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM oauth_clients WHERE client_id = ? AND client_secret_hash = ?", -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 2, client_secret ? client_secret : "", -1, SQLITE_TRANSIENT);
		if (sqlite3_step(stmt) == SQLITE_ROW)
			valid_client = 1;
		sqlite3_finalize(stmt);
	}

	if (!valid_client) {
		pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_client\"}");
		goto send;
	}

	uint32_t uid = 0;
	char stored_challenge[128] = {0};
	char stored_method[16] = {0};

	if (sqlite3_prepare_v2(vhd->db, "SELECT uid, code_challenge, code_challenge_method FROM oauth_codes WHERE code = ? AND client_id = ? AND redirect_uri = ? AND expires > ?", -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 3, redirect_uri, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int64(stmt, 4, (sqlite_int64)time(NULL));
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			uid = (uint32_t)sqlite3_column_int(stmt, 0);
			lws_strncpy(stored_challenge, (const char *)sqlite3_column_text(stmt, 1), sizeof(stored_challenge));
			lws_strncpy(stored_method, (const char *)sqlite3_column_text(stmt, 2), sizeof(stored_method));
		}
		sqlite3_finalize(stmt);
	}

	if (!uid) {
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_grant\"}");
		goto send;
	}

	if (sqlite3_prepare_v2(vhd->db, "DELETE FROM oauth_codes WHERE code = ?", -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, code, -1, SQLITE_TRANSIENT);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}

	if (stored_challenge[0]) {
		if (!code_verifier || !code_verifier[0]) {
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_request\",\"error_description\":\"Missing code_verifier\"}");
			goto send;
		}

		if (!strcmp(stored_method, "S256")) {
			struct lws_genhash_ctx ctx;
			uint8_t hash[32];
			char b64[64];

			if (lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA256) ||
			    lws_genhash_update(&ctx, code_verifier, strlen(code_verifier)) ||
			    lws_genhash_destroy(&ctx, hash)) {
				pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
				len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"server_error\"}");
				goto send;
			}

			int n = lws_b64_encode_string((const char *)hash, 32, b64, sizeof(b64));
			if (n > 0) {
				char *q = b64;
				while (*q) {
					if (*q == '+') *q = '-';
					if (*q == '/') *q = '_';
					if (*q == '=') { *q = '\0'; break; }
					q++;
				}
			}
			if (strcmp(b64, stored_challenge)) {
				pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
				len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_grant\",\"error_description\":\"PKCE mismatch\"}");
				goto send;
			}
		} else {
			if (strcmp(code_verifier, stored_challenge)) {
				pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
				len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"invalid_grant\",\"error_description\":\"PKCE mismatch\"}");
				goto send;
			}
		}
	}

	char username[128] = {0};
	if (sqlite3_prepare_v2(vhd->db, "SELECT username FROM users WHERE uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
		sqlite3_bind_int(stmt, 1, (int)uid);
		if (sqlite3_step(stmt) == SQLITE_ROW)
			lws_strncpy(username, (const char *)sqlite3_column_text(stmt, 0), sizeof(username));
		sqlite3_finalize(stmt);
	}

	size_t jwt_len = sizeof(jwt);
	char peer[64];
	lws_get_peer_simple(wsi, peer, sizeof(peer));

	if (!lws_auth_generate_token(vhd, username, uid, peer, jwt, &jwt_len)) {
		pss->http_response_code = HTTP_STATUS_OK;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":%llu}", jwt, vhd->jwt_validity_secs);
		goto send;
	}

	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"server_error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json", NULL, NULL);
}

static int
lws_auth_api_register(struct lws *wsi, struct per_vhost_data__auth_server *vhd,

		      struct per_session_data__auth_server *pss)
{
	char pl[1024 + LWS_PRE], peer[64], auto_salt[64] = {0}, hex[129] = {0}, totp_b32[64] = {0}, verify_hash[64] = {0};
        uint8_t salt_raw[16], hash[64], totp_bytes[10], vhash_raw[16];
        sqlite3_stmt *stmt_chk, *stmt;
        struct lws_genhash_ctx ctx;
        int len, users_empty = 0;
        const char *user, *pass;

        if (sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1,
                                   &stmt_chk, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt_chk) == SQLITE_ROW &&
                sqlite3_column_int(stmt_chk, 0) == 0) {
                users_empty = 1;
            }
            sqlite3_finalize(stmt_chk);
        }

        lws_get_peer_simple(wsi, peer, sizeof(peer));

	if (users_empty) {
		/* Allow initial TOFU admin bootstrap globally across interfaces without IP restriction */
	} else {
		/* Not empty: enforce public registration policy */
		if (!vhd->registration_ui) {
			lwsl_info("reg denied (ui disabled)\n");
			pss->http_response_code = HTTP_STATUS_FORBIDDEN;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Registration Disabled\"}");
			goto send;
		}
	}

	if (auth_check_csrf(wsi, vhd, pss)) {
		pss->http_response_code = HTTP_STATUS_FORBIDDEN;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"CSRF validation failed\"}");
		goto send;
	}

	user = lws_spa_get_string(pss->spa, EP_USER);
	pass = lws_spa_get_string(pss->spa, EP_PASS);

	lwsl_user("%s: Registration requested for user: '%s'\n", __func__, user ? user : "NULL");

	if (!user || !pass) {
		lwsl_err("%s: Missing credentials in POST\n", __func__);
		lwsl_info("reg missing credentials POST\n");
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Missing Credentials\"}");
		goto send;
	}

	int user_len = (int)strlen(user);
	if (user_len < 3 || user_len > 64) {
		lwsl_info("reg invalid username length\n");
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Username length\"}");
		goto send;
	}

	for (int i = 0; i < user_len; i++) {
		char c = user[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '@' || c == '.' ||
		      c == '-' || c == '_' || c == '+')) {
			lwsl_info("reg invalid charset\n");
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Username characters\"}");
			goto send;
		}
	}

	char query_clean[128];
	lws_snprintf(query_clean, sizeof(query_clean), "DELETE FROM registrations WHERE expires < %llu", (unsigned long long)time(NULL));
	sqlite3_exec(vhd->db, query_clean, NULL, NULL, NULL);

	int exists = 0;
	if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM users WHERE username = ?", -1, &stmt_chk, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt_chk, 1, user, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(stmt_chk) == SQLITE_ROW) exists = 1;
		sqlite3_finalize(stmt_chk);
	}

	if (exists) {
		lwsl_info("reg denied: email already fully registered\n");
		auth_record_strike(vhd, peer);
		pss->http_response_code = 409;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Email already registered\"}");
		goto send;
	}

	if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM registrations WHERE email = ?", -1, &stmt_chk, NULL) == SQLITE_OK) {
		sqlite3_bind_text(stmt_chk, 1, user, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(stmt_chk) == SQLITE_ROW) exists = 1;
		sqlite3_finalize(stmt_chk);
	}

	if (exists) {
		lwsl_info("reg denied: pending verification already circulating\n");
		auth_record_strike(vhd, peer);
		pss->http_response_code = 409;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Verification pending. Check your email or wait for it to naturally expire.\"}");
		goto send;
	}

	auth_record_strike(vhd, peer); /* Throttle IP naturally to maximally 4 gen / 120s universally */

	const char *query = "INSERT OR REPLACE INTO registrations (email, password_hash, salt, totp_secret, verify_hash, expires) VALUES (?, ?, ?, ?, ?, ?)";

	lws_get_random(vhd->context, salt_raw, sizeof(salt_raw));
	lws_b32_encode_string((const char *)salt_raw, sizeof(salt_raw), auto_salt, sizeof(auto_salt));
	lws_get_random(vhd->context, totp_bytes, sizeof(totp_bytes));
	lws_b32_encode_string((const char *)totp_bytes, sizeof(totp_bytes), totp_b32, sizeof(totp_b32));
	lws_get_random(vhd->context, vhash_raw, sizeof(vhash_raw));
	lws_hex_from_byte_array(vhash_raw, sizeof(vhash_raw), verify_hash, sizeof(verify_hash));

	uint64_t expires = (uint64_t)time(NULL) + 600;

	if (!lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA512) &&
	    !lws_genhash_update(&ctx, auto_salt, strlen(auto_salt)) &&
	    !lws_genhash_update(&ctx, pass, strlen(pass)) &&
	    !lws_genhash_destroy(&ctx, hash)) {
		lws_genhash_render(LWS_GENHASH_TYPE_SHA512, hash, hex, sizeof(hex));

		if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) != SQLITE_OK)
                        goto fail;

                sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, hex, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, auto_salt, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 4, totp_b32, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 5, verify_hash, -1, SQLITE_STATIC);
                sqlite3_bind_int64(stmt, 6, (sqlite_int64)expires);
                int sr = sqlite3_step(stmt);
                sqlite3_finalize(stmt);

                if (sr != SQLITE_DONE) {
                        lwsl_err("DB insert failed: %s\n", sqlite3_errmsg(vhd->db));
                        auth_record_strike(vhd, peer);
                        pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
                        len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"User creation failed\"}");
                        goto send;
                }

                if (vhd->smtp && vhd->smtp->send_email) {
                        char url[512], mbody[1024];

                        lws_snprintf(url, sizeof(url), "https://%s/api/verify?h=%s",
                                        lws_get_vhost_name(vhd->vhost), verify_hash);
                        lws_snprintf(mbody, sizeof(mbody), vhd->email_body, url);

                        lws_smtp_email_t payload;
                        memset(&payload, 0, sizeof(payload));
                        payload.from = vhd->email_from;
                        payload.to = user;
                        payload.subject = vhd->email_subject;
                        payload.body = mbody;

                        if (vhd->smtp->send_email(vhd->context, vhd->vhost, &payload)) {
                                lwsl_err("Failed to queue verification email\n");
                                pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                                len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Email Delivery Failed\"}");

                                goto send;
                        }
                }

                pss->http_response_code = HTTP_STATUS_OK;
                len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"status\":\"Verification dispatched\"}");
                lwsl_info("reg successful, dispatched verification.\n");

                goto send;

	}
fail:
	lwsl_info("reg hash generation or DB query failed\n");
	auth_record_strike(vhd, peer);
	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Internal Error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json", NULL, NULL);
}

static int
callback_auth_server(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct per_session_data__auth_server *pss =
			(struct per_session_data__auth_server *)user;
	struct per_vhost_data__auth_server *vhd =
			(struct per_vhost_data__auth_server *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options *pvo;
        uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];
        uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
        char uri[256];

        switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__auth_server));
		if (!vhd)
			return 1;

		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

	        /* defaults */
		lws_strncpy(vhd->db_path, "/var/db/lws-auth.sqlite3", sizeof(vhd->db_path));
		lws_strncpy(vhd->auth_domain, "auth.warmcat.com", sizeof(vhd->auth_domain));
		vhd->cookie_domain[0] = '\0';
		lws_strncpy(vhd->jwk_path, "/var/db/lws-auth.jwk", sizeof(vhd->jwk_path));
		lws_strncpy(vhd->jwt_alg, "ES256", sizeof(vhd->jwt_alg));
		lws_strncpy(vhd->cookie_name, "auth_session", sizeof(vhd->cookie_name));
		lws_strncpy(vhd->ui_title, "Secure Gateway", sizeof(vhd->ui_title));
		lws_strncpy(vhd->ui_subtitle, "Authenticate your session to continue", sizeof(vhd->ui_subtitle));
		lws_strncpy(vhd->ui_new_network, "New to the network?", sizeof(vhd->ui_new_network));
		vhd->ui_css[0] = '\0';
		vhd->jwt_validity_secs = 86400; // 24 hours
		vhd->registration_ui = 0;
		vhd->auth_log_limit = 10;

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "db_path");
		if (pvo)
			lws_strncpy(vhd->db_path, pvo->value, sizeof(vhd->db_path));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "auth-domain");
		if (pvo)
			lws_strncpy(vhd->auth_domain, pvo->value, sizeof(vhd->auth_domain));

		vhd->cookie_domain[0] = '\0';
		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "cookie-domain");
		if (pvo)
			lws_strncpy(vhd->cookie_domain, pvo->value, sizeof(vhd->cookie_domain));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "jwk_path");
		if (pvo)
			lws_strncpy(vhd->jwk_path, pvo->value, sizeof(vhd->jwk_path));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "registration_ui");
		if (pvo)
			vhd->registration_ui = !strcmp(pvo->value, "1") || !strcmp(pvo->value, "true");

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "email-from");
		if (pvo)
			lws_strncpy(vhd->email_from, pvo->value, sizeof(vhd->email_from));
		else
			lws_strncpy(vhd->email_from, "noreply@warmcat.com", sizeof(vhd->email_from));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "email-subject");
		if (pvo)
			lws_strncpy(vhd->email_subject, pvo->value, sizeof(vhd->email_subject));
		else
			lws_strncpy(vhd->email_subject, "Complete your registration", sizeof(vhd->email_subject));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "email-body");
		if (pvo)
			lws_strncpy(vhd->email_body, pvo->value, sizeof(vhd->email_body));
		else
			lws_strncpy(vhd->email_body, "Please visit the following link to confirm your account securely:\r\n%s", sizeof(vhd->email_body));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "jwt_alg");
		if (pvo)
			lws_strncpy(vhd->jwt_alg, pvo->value, sizeof(vhd->jwt_alg));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "cookie-name");
		if (pvo)
			lws_strncpy(vhd->cookie_name, pvo->value, sizeof(vhd->cookie_name));

		pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "ui-title");
		if (pvo) lws_strncpy(vhd->ui_title, pvo->value, sizeof(vhd->ui_title));

		pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "ui-subtitle");
		if (pvo) lws_strncpy(vhd->ui_subtitle, pvo->value, sizeof(vhd->ui_subtitle));

		pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "ui-new-network");
		if (pvo) lws_strncpy(vhd->ui_new_network, pvo->value, sizeof(vhd->ui_new_network));

		pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "ui-css");
		if (pvo) lws_strncpy(vhd->ui_css, pvo->value, sizeof(vhd->ui_css));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "jwt-validity-secs");
		if (pvo)
			vhd->jwt_validity_secs = (unsigned long long)atoll(pvo->value);

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "refresh-validity-secs");
		if (pvo)
			vhd->refresh_token_validity_secs = (unsigned long long)atoll(pvo->value);
		else
			vhd->refresh_token_validity_secs = 0;

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "auth-log-limit");
		if (pvo)
			vhd->auth_log_limit = (unsigned int)atoi(pvo->value);

		lwsl_notice("Auth Server plugin initialized: domain '%s', db '%s', jwk '%s', alg '%s', reg_ui %d\n",
			 vhd->auth_domain, vhd->db_path, vhd->jwk_path, vhd->jwt_alg, vhd->registration_ui);

		/* load or generate JWK */
		if (lws_jwk_load(&vhd->jwk, vhd->jwk_path, NULL, NULL)) {
			lwsl_notice("Generating new EC JWK at %s\n", vhd->jwk_path);
			if (lws_jwk_generate(vhd->context, &vhd->jwk,
			                     LWS_GENCRYPTO_KTY_EC, 256, "P-256") ||
			    lws_jwk_save(&vhd->jwk, vhd->jwk_path)) {
				lwsl_vhost_err(vhd->vhost, "Auth plugin failed to generate or save JWK\n");
				return -1;
			}
		}

		/* Export public key strictly for downstream distribution */
		{
			char pub[4096];
			int plen = sizeof(pub);
			if (lws_jwk_export(&vhd->jwk, 0, pub, &plen) > 0) {
				char pub_path[300];
				FILE *f;

				lws_snprintf(pub_path, sizeof(pub_path), "%s.pub", vhd->jwk_path);
				f = fopen(pub_path, "w");
				if (f) {
					fwrite(pub, 1, strlen(pub), f);
					fclose(f);
				}

				/* Cache the JWKS JSON response natively */
				lws_snprintf(vhd->jwks_json, sizeof(vhd->jwks_json), "{\"keys\":[%s]}", pub);
			}
		}

		/* Initialize sqlite database using lws_struct */
		if (lws_struct_sq3_open(vhd->context, vhd->db_path, 1, &vhd->db)) {
			lwsl_vhost_err(vhd->vhost, "Auth plugin failed to open database\n");
			return -1; /* fail plugin init */
		}

		if (sqlite3_exec(vhd->db, schema_init, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_vhost_err(vhd->vhost, "Auth plugin schema creation failed: %s\n",
				 sqlite3_errmsg(vhd->db));
			return -1;
		}

#if !defined(WIN32)
		{
			uid_t uid = (uid_t)-1;
			gid_t gid = (gid_t)-1;

			lws_get_effective_uid_gid(vhd->context, &uid, &gid);
			if (uid != (uid_t)-1 || gid != (gid_t)-1) {
				char parent[256];
				char *last_slash;

				lws_strncpy(parent, vhd->db_path, sizeof(parent));

				if (chown(parent, uid, gid))
					lwsl_warn("Auth plugin could not chown database file '%s'\n", parent);
				else
					lwsl_notice("Auth plugin chowned database file '%s' to %d:%d\n", parent, (int)uid, (int)gid);

				last_slash = strrchr(parent, '/');
				if (last_slash && last_slash != parent) {
					*last_slash = '\0';
					if (chown(parent, uid, gid))
						lwsl_warn("Auth plugin could not chown database directory '%s'\n", parent);
					else
						lwsl_notice("Auth plugin chowned database directory '%s' to %d:%d\n", parent, (int)uid, (int)gid);
				}
			}
		}
#endif

		/* Populate persistent bans from DB */
		{
			sqlite3_stmt *stmt;
			uint64_t now = (uint64_t)time(NULL);
			if (sqlite3_prepare_v2(vhd->db, "SELECT ip, banned_until FROM bans WHERE banned_until > ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_int64(stmt, 1, (sqlite_int64)now);
				while (sqlite3_step(stmt) == SQLITE_ROW) {
					auth_server_ban_t *ban = malloc(sizeof(*ban));
					if (!ban) break;
					memset(ban, 0, sizeof(*ban));
					lws_strncpy(ban->ip, (const char *)sqlite3_column_text(stmt, 0), sizeof(ban->ip));
					ban->banned_until = (uint64_t)sqlite3_column_int64(stmt, 1);
					lws_dll2_add_tail(&ban->list, &vhd->ip_bans);
					lwsl_notice("Loaded active ban for %s\n", ban->ip);
				}
				sqlite3_finalize(stmt);
			}
			/* Sweeper for expired bans */
			if (sqlite3_prepare_v2(vhd->db, "DELETE FROM bans WHERE banned_until <= ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_int64(stmt, 1, (sqlite_int64)now);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}
			/* Sweeper for expired sessions and codes */
			if (sqlite3_prepare_v2(vhd->db, "DELETE FROM auth_sessions WHERE expires <= ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_int64(stmt, 1, (sqlite_int64)now);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}
			if (sqlite3_prepare_v2(vhd->db, "DELETE FROM oauth_codes WHERE expires <= ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_int64(stmt, 1, (sqlite_int64)now);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}
		}

		{
			const struct lws_protocols *pp = lws_vhost_name_to_protocol(vhd->vhost, "lws-smtp-client");
			if (pp) {
				vhd->smtp = (const lws_smtp_client_ops_t *)pp->user;
			}
		}

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			if (vhd->db)
				sqlite3_close(vhd->db);
			lws_jwk_destroy(&vhd->jwk);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_strikes.head) {
				auth_server_strike_t *s = lws_container_of(d, auth_server_strike_t, list);
				lws_dll2_remove(&s->list);
				free(s);
			} lws_end_foreach_dll_safe(d, d1);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_bans.head) {
				auth_server_ban_t *b = lws_container_of(d, auth_server_ban_t, list);
				lws_dll2_remove(&b->list);
				free(b);
			} lws_end_foreach_dll_safe(d, d1);
		}
		break;

	case LWS_CALLBACK_HTTP:
		lwsl_info("HTTP: path='%s'\n", in ? (const char *)in : "NULL");
		{
			char peer[64];
			lws_get_peer_simple(wsi, peer, sizeof(peer));
			uint64_t now = (uint64_t)time(NULL);

			/* Rapid ban-check */
			int is_banned = 0;
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_bans.head) {
				auth_server_ban_t *b = lws_container_of(d, auth_server_ban_t, list);
				if (!strcmp(b->ip, peer)) {
					if (now > b->banned_until) {
						/* expired, sweep it */
						lws_dll2_remove(&b->list);
						free(b);
						/* database sweep occurs below lazily, or we could explicitly: */
						sqlite3_stmt *st;
						if (sqlite3_prepare_v2(vhd->db, "DELETE FROM bans WHERE ip = ?", -1, &st, NULL) == SQLITE_OK) {
							sqlite3_bind_text(st, 1, peer, -1, SQLITE_STATIC);
							sqlite3_step(st);
							sqlite3_finalize(st);
						}
					} else {
						is_banned = 1;
					}
					break;
				}
			} lws_end_foreach_dll_safe(d, d1);

			if (is_banned) {
				lwsl_notice("%s: Banned IP %s blocked\n", __func__, peer);
				return -1;
			}
		}


		if (in && (!strcmp((const char *)in, "/admin"))) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
			if (!ja || lws_jwt_auth_query_grant(ja, "*") < 1) {
				if (ja) lws_jwt_auth_destroy(&ja);
				lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "Forbidden");
				return lws_http_transaction_completed(wsi);
			}
			lws_jwt_auth_destroy(&ja);

			const char *html_fmt = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
				"<title>Auth Server Admin</title>"
				"<link rel=\"stylesheet\" href=\"../admin.css\">"
				"%s%s%s"
				"</head><body><div class=\"container\">"
				"<div class=\"panel-header\"><h1>Admin Console</h1></div>"
				"<div class=\"tabs\">"
				"<button id=\"tabUsers\" class=\"tab-active\">User Administration</button>"
				"<button id=\"tabClients\" class=\"tab-inactive\">Grants</button>"
				"</div>"
				"<div id=\"usersView\">"
				"<table id=\"usersTable\"><thead>"
				"<tr><th>UID</th><th>Username</th><th>Active Grants</th><th>Actions</th></tr>"
				"</thead><tbody></tbody></table>"
				"</div>"
				"<div id=\"clientsView\" class=\"hidden\">"
				"<button id=\"addClientBtn\" class=\"btn-success\">+ Add Grant</button>"
				"<table id=\"clientsTable\"><thead>"
				"<tr><th>Grant ID</th><th>Display Name</th><th>Allowed Redirect URIs</th><th>Actions</th></tr>"
				"</thead><tbody></tbody></table>"
				"</div>"
				"</div>"
				"<div id=\"modal\"><div class=\"modal-content\"><h3 id=\"modalTitle\">Edit Grants</h3>"
				"<p>Enter grants as comma-separated <code>service:level</code>.</p>"
				"<div class=\"form-group\"><input type=\"text\" id=\"grantsInput\" placeholder=\"service:level\"></div>"
				"<button id=\"saveBtn\">Save</button> <button id=\"cancelBtn\" class=\"btn-muted\">Cancel</button>"
				"</div></div>"
				"<div id=\"clientModal\" class=\"modal-backdrop\">"
				"<div class=\"modal-content\">"
				"<h3 id=\"cmTitle\">Manage Grant</h3>"
				"<div class=\"form-group\"><label class=\"form-label\">Grant ID</label><input type=\"text\" id=\"cmId\" class=\"form-input\"></div>"
				"<div class=\"form-group spaced\"><label class=\"form-label\">Display Name</label><input type=\"text\" id=\"cmName\" class=\"form-input\"></div>"
				"<div class=\"form-group spaced bottom\"><label class=\"form-label\">Redirect URIs (comma delim)</label><input type=\"text\" id=\"cmRedirects\" class=\"form-input\" placeholder=\"https://...\"></div>"
				"<button id=\"cmSaveBtn\">Save</button> <button id=\"cmCancelBtn\" class=\"btn-muted\">Cancel</button>"
				"</div></div>"
				"<script src=\"../admin.js\"></script>"
				"</body></html>";

			size_t max_html_len = 4096;
			char *pl = malloc(LWS_PRE + max_html_len);
			if (!pl) return -1;
			size_t html_len = (size_t)lws_snprintf(pl + LWS_PRE, max_html_len, html_fmt,
				vhd->ui_css[0] ? "<link rel=\"stylesheet\" href=\"" : "",
				vhd->ui_css[0] ? vhd->ui_css : "",
				vhd->ui_css[0] ? "\">" : "");

			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, html_len + LWS_PRE) < 0) {
				free(pl);
				return -1;
			}
			free(pl);

			return send_auth_headers(wsi, pss, "text/html", NULL, NULL);
		}

		if (in && (!strcmp((const char *)in, "/.well-known/jwks.json") ||
				   !strcmp((const char *)in, "/jwks.json"))) {
			char buf[1024 + LWS_PRE];
			char *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
			size_t json_len = strlen(vhd->jwks_json);

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json",
							(lws_filepos_t)json_len, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_write_http_header(wsi, (unsigned char *)buf + LWS_PRE, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			char *pl = malloc(LWS_PRE + json_len + 1);
			if (pl) {
				memcpy(pl + LWS_PRE, vhd->jwks_json, json_len);
				if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, json_len + LWS_PRE) < 0) {
					free(pl);
					return -1;
				}
				free(pl);
			}

			lws_callback_on_writable(wsi);
			return 0;
		}

		if (in && (!strncmp((const char *)in, "/logout", 7))) {
			lwsl_notice("%s: Hit /logout endpoint. in=%s\n", __func__, (const char *)in);
			char redirect_uri[512] = {0};
			char buf[4096 + LWS_PRE];
			char *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;

			lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", redirect_uri, sizeof(redirect_uri));
			lws_urldecode(redirect_uri, redirect_uri, sizeof(redirect_uri));
			if (!redirect_uri[0])
				lws_strncpy(redirect_uri, "/", sizeof(redirect_uri));

			lwsl_notice("%s: Extracted redirect_uri: %s\n", __func__, redirect_uri);

			char cookie_val[LWS_AUTH_MAX_COOKIE_LEN] = {0};
			int ck_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);
			if (ck_len >= (int)sizeof(cookie_val)) {
				lwsl_err("%s: OVERRUN! HTTP cookie header length (%d) exceeds allocated buffer size (%d), auth tracking tokens may be truncated!\n", __func__, ck_len, (int)sizeof(cookie_val));
			}

			if (lws_hdr_copy(wsi, cookie_val, sizeof(cookie_val), WSI_TOKEN_HTTP_COOKIE) > 0) {
				const char *rp = strstr(cookie_val, "auth_refresh_session=");
				if (rp) {
					char refresh_tk[128] = {0};
					rp += 21;
					size_t i = 0;
					while (*rp && *rp != ';' && i < sizeof(refresh_tk) - 1)
						refresh_tk[i++] = *rp++;
					refresh_tk[i] = 0;
					if (refresh_tk[0]) {
						lwsl_notice("%s: Found auth_refresh_session in cookie, executing DB delete...\n", __func__);
						sqlite3_stmt *stmt;
						if (sqlite3_prepare_v2(vhd->db, "DELETE FROM auth_sessions WHERE session_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_text(stmt, 1, refresh_tk, -1, SQLITE_TRANSIENT);
							sqlite3_step(stmt);
							sqlite3_finalize(stmt);
							lwsl_notice("%s: DB delete complete.\n", __func__);
						} else {
							lwsl_notice("%s: DB prepare failed\n", __func__);
						}
					}
				} else {
					lwsl_notice("%s: auth_refresh_session NOT found in cookie!\n", __func__);
				}
			} else {
				lwsl_notice("%s: No cookies provided by client in /logout\n", __func__);
			}

			char cookie_hdr1[256], cookie_hdr1_host[256];
			char cookie_hdr2[256], cookie_hdr2_host[256];
			char cookie_hdr3[256], cookie_hdr3_host[256];
			char exp[64];
			time_t t = 0;
			struct tm *tm = gmtime(&t);
			strftime(exp, sizeof(exp), "%a, %d %b %Y %H:%M:%S GMT", tm);

			if (vhd->cookie_domain[0]) {
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, vhd->cookie_domain, exp);
				lws_snprintf(cookie_hdr2, sizeof(cookie_hdr2), "auth_csrf=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_domain, exp);
				lws_snprintf(cookie_hdr3, sizeof(cookie_hdr3), "auth_refresh_session=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_domain, exp);
			} else {
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);
				lws_snprintf(cookie_hdr2, sizeof(cookie_hdr2), "auth_csrf=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
				lws_snprintf(cookie_hdr3, sizeof(cookie_hdr3), "auth_refresh_session=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
			}
			lws_snprintf(cookie_hdr1_host, sizeof(cookie_hdr1_host), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);
			lws_snprintf(cookie_hdr2_host, sizeof(cookie_hdr2_host), "auth_csrf=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
			lws_snprintf(cookie_hdr3_host, sizeof(cookie_hdr3_host), "auth_refresh_session=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);

			char html[LWS_PRE + 1024];
			char urlenc_path[512];
			int html_len;

			lws_urlencode(urlenc_path, redirect_uri, sizeof(urlenc_path));

			html_len = lws_snprintf(html + LWS_PRE, sizeof(html) - LWS_PRE,
				"<html><head><meta http-equiv=\"refresh\" content=\"0; url=%s\"></head><body>Redirecting to <a href=\"%s\">%s</a></body></html>",
				urlenc_path, urlenc_path, urlenc_path);

			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)html, (size_t)html_len + LWS_PRE) < 0)
				return -1;

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_SEE_OTHER, "text/html", (unsigned int)html_len, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1, (int)strlen(cookie_hdr1), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1_host, (int)strlen(cookie_hdr1_host), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr2, (int)strlen(cookie_hdr2), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr2_host, (int)strlen(cookie_hdr2_host), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr3, (int)strlen(cookie_hdr3), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr3_host, (int)strlen(cookie_hdr3_host), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
							 (unsigned char *)redirect_uri, (int)strlen(redirect_uri),
							 (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			lwsl_notice("%s: Writing headers and requesting writable callback\n", __func__);
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (in && (!strncmp((const char *)in, "/status", 7))) {
			int users_empty = 0;
			int rc;
			sqlite3_stmt *stmt;
			if ((rc = sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1, &stmt, NULL)) == SQLITE_OK) {
				int step_rc = sqlite3_step(stmt);
				int count = -1;
				if (step_rc == SQLITE_ROW) {
					count = sqlite3_column_int(stmt, 0);
					if (count == 0)
						users_empty = 1;
				}
				lwsl_info("DB DEBUG: COUNT(*) row query: step_rc=%d (SQLITE_ROW=%d), count=%d -> users_empty=%d\n", step_rc, SQLITE_ROW, count, users_empty);
				sqlite3_finalize(stmt);
			} else {
				lwsl_err("DB DEBUG: sqlite3_prepare_v2 failed: rc=%d\n", rc);
			}

			{
			struct per_session_data__auth_server *pss =
				(struct per_session_data__auth_server *)user;

			if (pss) {
				char peer[64] = {0};
				int strikes = 0;
				lws_get_peer_simple(wsi, peer, sizeof(peer));

				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->ip_strikes.head) {
					auth_server_strike_t *s = lws_container_of(d, auth_server_strike_t, list);
					if (!strcmp(s->ip, peer)) {
						if ((uint64_t)time(NULL) - s->last_strike > 120)
							s->strikes = 0;
						strikes = s->strikes;
						break;
					}
				} lws_end_foreach_dll_safe(d, d1);

				char csrf[33] = {0};
				size_t csrf_len = sizeof(csrf);
				int has_csrf = lws_http_cookie_get(wsi, "auth_csrf", csrf, &csrf_len) == 0 && csrf[0] ? 1 : 0;

				if (!has_csrf) {
					uint8_t rnd[16];
					lws_get_random(vhd->context, rnd, 16);
					lws_hex_from_byte_array(rnd, 16, csrf, 33);
				}

				int logged_in = 0;
				int lacks_grant = 0;
				char sname[128] = {0};
				char user_email[128] = {0};
				char grants[256] = {0};
				char *gp = grants, *gend = grants + sizeof(grants);
				char logs[2048] = {0};
				lws_get_urlarg_by_name_safe(wsi, "service_name=", sname, sizeof(sname));

				char set_cookie_jwt[2048] = {0};

				if (vhd->cookie_name[0]) {
					uint32_t suid = 0;
					int was_refreshed = 0;
					struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);

					if (ja) {
						suid = lws_jwt_auth_get_uid(ja);
						lws_jwt_auth_destroy(&ja);
					} else if (vhd->refresh_token_validity_secs > 0) {
						char refresh_tk[128] = {0};
						size_t refresh_len = sizeof(refresh_tk);

						if (lws_http_cookie_get(wsi, "auth_refresh_session", refresh_tk, &refresh_len) == 0 && refresh_tk[0]) {
							sqlite3_stmt *stmt;
							uint64_t now = (uint64_t)time(NULL);
							if (sqlite3_prepare_v2(vhd->db, "SELECT uid, expires FROM auth_sessions WHERE session_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
								sqlite3_bind_text(stmt, 1, refresh_tk, -1, SQLITE_TRANSIENT);
								if (sqlite3_step(stmt) == SQLITE_ROW) {
									uint64_t exp = (uint64_t)sqlite3_column_int64(stmt, 1);
									if (now < exp) {
										suid = (uint32_t)sqlite3_column_int(stmt, 0);
										was_refreshed = 1;
									}
								}
								sqlite3_finalize(stmt);
							}
						}
					}

					if (suid) {
						logged_in = 1;
						char username[128] = {0};

						sqlite3_stmt *stmt_u;
						if (sqlite3_prepare_v2(vhd->db, "SELECT username FROM users WHERE uid = ?", -1, &stmt_u, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt_u, 1, (int)suid);
							if (sqlite3_step(stmt_u) == SQLITE_ROW) {
								lws_strncpy(username, (const char *)sqlite3_column_text(stmt_u, 0), sizeof(username));
								lws_strncpy(user_email, username, sizeof(user_email));
							}
							sqlite3_finalize(stmt_u);
						}

						if (was_refreshed) {
							char jwt[1024];
							size_t jwt_len = sizeof(jwt);
							
							if (!lws_auth_generate_token(vhd, username, suid, peer, jwt, &jwt_len)) {
								if (vhd->cookie_domain[0]) {
									lws_snprintf(set_cookie_jwt, sizeof(set_cookie_jwt),
										"%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
										vhd->cookie_name, jwt, vhd->cookie_domain,
										(unsigned long long)vhd->jwt_validity_secs);
								} else {
									lws_snprintf(set_cookie_jwt, sizeof(set_cookie_jwt),
										"%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=None; Secure",
										vhd->cookie_name, jwt,
										(unsigned long long)vhd->jwt_validity_secs);
								}
							}
						}

						/* Fetch grants for debugging output */
						int first = 1;
						if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ?", -1, &stmt_u, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt_u, 1, (int)suid);
							while (sqlite3_step(stmt_u) == SQLITE_ROW) {
								if (!first) gp += lws_snprintf(gp, lws_ptr_diff_size_t(gend, gp), ", ");
								first = 0;
								gp += lws_snprintf(gp, lws_ptr_diff_size_t(gend, gp), "\"%s\": %d",
									(const char *)sqlite3_column_text(stmt_u, 0),
									sqlite3_column_int(stmt_u, 1));
							}
							sqlite3_finalize(stmt_u);
						}

						if (sname[0]) {
							lacks_grant = 1;
							if (sqlite3_prepare_v2(vhd->db, "SELECT g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ? AND (s.name = ? OR s.name = '*');", -1, &stmt_u, NULL) == SQLITE_OK) {
								sqlite3_bind_int(stmt_u, 1, (int)suid);
								sqlite3_bind_text(stmt_u, 2, sname, -1, SQLITE_TRANSIENT);
								while (sqlite3_step(stmt_u) == SQLITE_ROW) {
									if (sqlite3_column_int(stmt_u, 0) >= 1)
										lacks_grant = 0;
								}
								sqlite3_finalize(stmt_u);
							}
						}

						char *lp = logs, *lend = logs + sizeof(logs);
						int first_log = 1;
						
						if (sqlite3_prepare_v2(vhd->db, "SELECT issue_time, ip_address FROM auth_log WHERE uid = ? ORDER BY issue_time DESC", -1, &stmt_u, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt_u, 1, (int)suid);
							while (sqlite3_step(stmt_u) == SQLITE_ROW) {
								if (!first_log) lp += lws_snprintf(lp, lws_ptr_diff_size_t(lend, lp), ", ");
								first_log = 0;
								lp += lws_snprintf(lp, lws_ptr_diff_size_t(lend, lp), "{\"time\": %lld, \"ip\": \"%s\"}",
									(long long)sqlite3_column_int64(stmt_u, 0),
									(const char *)sqlite3_column_text(stmt_u, 1));
							}
							sqlite3_finalize(stmt_u);
						}
					}
				}

				if (lws_get_urlarg_by_name_safe(wsi, "destroy=", sname, sizeof(sname)) > 0) {
					/* client wants to terminate session via async fetch */
					lwsl_info("-> TERMINATING SESSION MANUALLY! destroy URL arg present. Emitting 200 OK JSON.\n");
					logged_in = 0;
					users_empty = 0;
					lacks_grant = 0;

					char cookie_hdr1[256], cookie_hdr1_host[256], cookie_hdr2[256], cookie_hdr2_host[256], cookie_hdr3[256], cookie_hdr3_host[256];
					char exp[64];
					time_t t = 0;
					struct tm *tm = gmtime(&t);
					strftime(exp, sizeof(exp), "%a, %d %b %Y %H:%M:%S GMT", tm);

					if (vhd->cookie_domain[0]) {
						lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, vhd->cookie_domain, exp);
						lws_snprintf(cookie_hdr2, sizeof(cookie_hdr2), "auth_csrf=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_domain, exp);
						lws_snprintf(cookie_hdr3, sizeof(cookie_hdr3), "auth_refresh_session=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_domain, exp);
					} else {
						lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);
						lws_snprintf(cookie_hdr2, sizeof(cookie_hdr2), "auth_csrf=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
						lws_snprintf(cookie_hdr3, sizeof(cookie_hdr3), "auth_refresh_session=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
					}
					lws_snprintf(cookie_hdr1_host, sizeof(cookie_hdr1_host), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", vhd->cookie_name, exp);
					lws_snprintf(cookie_hdr2_host, sizeof(cookie_hdr2_host), "auth_csrf=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);
					lws_snprintf(cookie_hdr3_host, sizeof(cookie_hdr3_host), "auth_refresh_session=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=None; Secure", exp);

					char refresh_tk[128] = {0};
					size_t refresh_len = sizeof(refresh_tk);
					if (lws_http_cookie_get(wsi, "auth_refresh_session", refresh_tk, &refresh_len) == 0 && refresh_tk[0]) {
						sqlite3_stmt *stmt;
						if (sqlite3_prepare_v2(vhd->db, "DELETE FROM auth_sessions WHERE session_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_text(stmt, 1, refresh_tk, -1, SQLITE_TRANSIENT);
							sqlite3_step(stmt);
							sqlite3_finalize(stmt);
						}
					}

					pss->http_response_code = HTTP_STATUS_OK;
					char buf[2048 + LWS_PRE];
					uint8_t *start = (uint8_t *)buf + LWS_PRE, *p = start, *end = (uint8_t *)buf + sizeof(buf) - 1;

					size_t payload_len = 13; /* {"destroy":1} */

					if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json", (lws_filepos_t)payload_len, &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"Cache-Control:", (unsigned char *)"no-cache, no-store, must-revalidate", 35, &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1, (int)strlen(cookie_hdr1), &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1_host, (int)strlen(cookie_hdr1_host), &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr2, (int)strlen(cookie_hdr2), &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr2_host, (int)strlen(cookie_hdr2_host), &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr3, (int)strlen(cookie_hdr3), &p, end)) return -1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr3_host, (int)strlen(cookie_hdr3_host), &p, end)) return -1;
					if (lws_finalize_write_http_header(wsi, start, &p, end)) return -1;

					char pl[LWS_PRE + 64];
					size_t pl_len = (size_t)lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"destroy\":1}");
					if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, pl_len + LWS_PRE) < 0) return -1;

					lws_callback_on_writable(wsi);
					return 0;
				}

#if 0
				{
					char pub64[256];
					(void)lws_b64_encode_string((const char *)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
										(int)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len, pub64, sizeof(pub64));
					lwsl_notice("auth_server status: MATHEMATICAL PROOF -> JWK path loaded from '%s', Public X-Coord length '%d', Base64 X: '%s'\n",
						vhd->jwk_path[0] ? vhd->jwk_path : "NULL!!!", (int)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len, pub64);
				}
#endif

				lwsl_info("/status API endpoint returning users_empty=%d, logged_in=%d lacks_grant=%d\n", users_empty, logged_in, lacks_grant);
				pss->http_response_code = HTTP_STATUS_OK;
				char pl[4096 + LWS_PRE];
		                int len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE,
					"{\"users_empty\":%d, \"csrf_token\":\"%s\", \"logged_in\":%d, \"lacks_grant\":%d, \"email\":\"%s\", \"strikes\":%d, \"grants\":{%s}, \"logs\":[%s]}",
					users_empty, csrf, logged_in, lacks_grant, user_email, strikes, grants, logs);
				if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
					return -1;

				if (!has_csrf) {
					char cookie_hdr[128];
					lws_snprintf(cookie_hdr, sizeof(cookie_hdr), "auth_csrf=%s; Path=/; SameSite=None; HttpOnly; Secure", csrf);
					return send_auth_headers(wsi, pss, "application/json", cookie_hdr, set_cookie_jwt[0] ? set_cookie_jwt : NULL);
				}

				return send_auth_headers(wsi, pss, "application/json", set_cookie_jwt[0] ? set_cookie_jwt : NULL, NULL);
			}

                        return 0;
		}
		}

		if (in && !strncmp((const char *)in, "/manifest", 9)) {
			char pl[2048 + LWS_PRE];
			char buf[1024 + LWS_PRE];
			char *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;

			int json_len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE,
				"{\"ui_title\":\"%s\", \"ui_subtitle\":\"%s\", \"ui_new_network\":\"%s\", \"ui_css\":\"%s\"}",
				vhd->ui_title, vhd->ui_subtitle, vhd->ui_new_network, vhd->ui_css);

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json",
							(lws_filepos_t)json_len, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_write_http_header(wsi, (unsigned char *)buf + LWS_PRE, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)json_len + LWS_PRE) < 0)
				return -1;

			lws_callback_on_writable(wsi);
			return 0;
		}

		if (!strncmp((const char *)in, "/totp_svg", 9)) {
			char hbuf[128];
			if (lws_get_urlarg_by_name_safe(wsi, "h=", hbuf, sizeof(hbuf)) < 0) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing Hash");
				return lws_http_transaction_completed(wsi);
			}

			sqlite3_stmt *stmt;
			int found = 0;
			char totp[64];
			char email[128];

			if (sqlite3_prepare_v2(vhd->db, "SELECT email, totp_secret FROM registrations WHERE verify_hash = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, hbuf, -1, SQLITE_TRANSIENT);
				if (sqlite3_step(stmt) == SQLITE_ROW) {
					found = 1;
					lws_strncpy(email, (const char *)sqlite3_column_text(stmt, 0), sizeof(email));
					lws_strncpy(totp, (const char *)sqlite3_column_text(stmt, 1), sizeof(totp));
				}
				sqlite3_finalize(stmt);
			}

			if (!found) {
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "Not Found");
				return lws_http_transaction_completed(wsi);
			}

			/* Keep the registration alive so duplicate img fetches don't randomly 404 */

			size_t alloc_size = 16384 + LWS_PRE;
			uint8_t *buf = malloc(alloc_size);
			if (!buf) return -1;
			uint8_t *body_start = buf + LWS_PRE;
			uint8_t *body_end = buf + alloc_size - 1;
			uint8_t *p = body_start;

			char uri[256];
			uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];
			uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];

			lws_snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s",
				vhd->auth_domain, email, totp, vhd->auth_domain);

			qrcodegen_encodeText(uri, tempBuffer, qrcode, qrcodegen_Ecc_MEDIUM,
				qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);

			int size = qrcodegen_getSize(qrcode);
			int border = 4;

			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p),
				"<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 %d %d\" stroke=\"none\">"
				"<rect width=\"100%%\" height=\"100%%\" fill=\"#FFFFFF\"/><path d=\"",
				size + 8, size + 8);

			for (int y = 0; y < size; y++)
				for (int x = 0; x < size; x++)
					if (qrcodegen_getModule(qrcode, x, y)) {
						int run = 1;
						while (x + run < size && qrcodegen_getModule(qrcode, x + run, y))
							run++;
						int w = lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p), "M%d,%dh%dv1h-%dz ", x + border, y + border, run, run);
						if (w > 0 && (size_t)w < lws_ptr_diff_size_t(body_end, p))
							p += w;
						x += run - 1;
					}

                        p--;
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p), "\" fill=\"#000000\"/></svg>");
                        // p += lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p), "\" fill=\"#000000\"/></svg>\n\n\n");

                        size_t body_len = lws_ptr_diff_size_t(p, body_start);

			uint8_t hdr_buf[8192 + LWS_PRE];
			uint8_t *h_start = hdr_buf + LWS_PRE;
			uint8_t *h_p = h_start;
			uint8_t *h_end = hdr_buf + sizeof(hdr_buf) - 1;
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "image/svg+xml", (lws_filepos_t)body_len, &h_p, h_end)) { free(buf); return lws_http_transaction_completed(wsi); }
			if (lws_finalize_write_http_header(wsi, h_start, &h_p, h_end)) { free(buf); return lws_http_transaction_completed(wsi); }

			struct per_session_data__auth_server *pss = (struct per_session_data__auth_server *)user;
			if (pss) {
				if (lws_buflist_append_segment(&pss->tx_buflist, buf, body_len + LWS_PRE) < 0) {
					free(buf);
					return -1;
				}
				lws_callback_on_writable(wsi);
			}
			free(buf);

			if (sqlite3_prepare_v2(vhd->db, "DELETE FROM registrations WHERE verify_hash = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, hbuf, -1, SQLITE_TRANSIENT);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}

			return 0;
		}

		if (!strncmp((const char *)in, "/verify", 7)) {
			char hbuf[64];
			if (lws_get_urlarg_by_name_safe(wsi, "h=", hbuf, sizeof(hbuf)) < 0) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing Hash");
				return lws_http_transaction_completed(wsi);
			}

			sqlite3_stmt *stmt;
			int found = 0;
			uint64_t now = (uint64_t)time(NULL);
			char email[129], pass[129], salt[33], totp[65];
			lwsl_info("verify: looking for hash='%s'\n", hbuf);

			if (sqlite3_prepare_v2(vhd->db, "SELECT email, password_hash, salt, totp_secret, expires FROM registrations WHERE verify_hash = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, hbuf, -1, SQLITE_TRANSIENT);
				int s_res = sqlite3_step(stmt);
				if (s_res == SQLITE_ROW) {
					uint64_t exp = (uint64_t)sqlite3_column_int64(stmt, 4);
					if (now <= exp) {
						found = 1;
						lws_strncpy(email, (const char *)sqlite3_column_text(stmt, 0), sizeof(email));
						lws_strncpy(pass,  (const char *)sqlite3_column_text(stmt, 1), sizeof(pass));
						lws_strncpy(salt,  (const char *)sqlite3_column_text(stmt, 2), sizeof(salt));
						lws_strncpy(totp,  (const char *)sqlite3_column_text(stmt, 3), sizeof(totp));
					} else {
						lwsl_info("verify: link expired! now=%llu, exp=%llu\n", (unsigned long long)now, (unsigned long long)exp);
					}
				} else {
					lwsl_info("verify: db step failed or no row: %d %s\n", s_res, sqlite3_errmsg(vhd->db));
				}
				sqlite3_finalize(stmt);
			} else {
				lwsl_err("verify: db prepare failed: %s\n", sqlite3_errmsg(vhd->db));
			}

			if (!found) {
				char peer[64];

				lws_get_peer_simple(wsi, peer, sizeof(peer));
				auth_record_strike(vhd, peer);

				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid or Expired Link");

				return lws_http_transaction_completed(wsi);
			}

			if (sqlite3_prepare_v2(vhd->db, "INSERT INTO users (username, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 4, totp, -1, SQLITE_STATIC);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}



			int users_count = 0;
			if (sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1, &stmt, NULL) == SQLITE_OK) {
				if (sqlite3_step(stmt) == SQLITE_ROW) users_count = sqlite3_column_int(stmt, 0);
				sqlite3_finalize(stmt);
			}

			/* Always add public grant to newly minted users */
			sqlite3_exec(vhd->db, "INSERT OR IGNORE INTO services (name) VALUES ('public')", NULL, NULL, NULL);
			char public_grant_query[256];
			lws_snprintf(public_grant_query, sizeof(public_grant_query), "INSERT INTO grants (uid, service_id, grant_level) VALUES ((SELECT uid FROM users WHERE username='%s'), (SELECT service_id FROM services WHERE name='public'), 1)", email);
			sqlite3_exec(vhd->db, public_grant_query, NULL, NULL, NULL);

			if (users_count == 1) {
				sqlite3_exec(vhd->db, "INSERT OR IGNORE INTO services (service_id, name) VALUES (1, '*')", NULL, NULL, NULL);
				char grant_query[256];
				lws_snprintf(grant_query, sizeof(grant_query), "INSERT INTO grants (uid, service_id, grant_level) VALUES ((SELECT uid FROM users WHERE username='%s'), 1, 2)", email);
				sqlite3_exec(vhd->db, grant_query, NULL, NULL, NULL);
			}

			lws_snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s",
				vhd->auth_domain, email, totp, vhd->auth_domain);

			qrcodegen_encodeText(uri, tempBuffer, qrcode, qrcodegen_Ecc_MEDIUM,
				qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);

			size_t alloc_size = 16384 + LWS_PRE;  /* Plenty for verify HTML */
			uint8_t *buf = malloc(alloc_size);
			if (!buf) {
				lwsl_info("verify OOM for HTML buffer\n");
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "OOM");
				return lws_http_transaction_completed(wsi);
			}

			uint8_t *body_start = buf + LWS_PRE;
			uint8_t *body_end = buf + alloc_size - LWS_PRE - 1;
			uint8_t *p = body_start;

			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p),
				"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Account Confirmed</title>"
				"<link rel=\"stylesheet\" href=\"../auth.css\">"
				"%s%s%s"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>"
				"<body><div class=\"background-elements\"><div class=\"orb orb-1\"></div><div class=\"orb orb-2\"></div><div class=\"orb orb-3\"></div></div>"
				"<div class=\"auth-container\"><div class=\"glass-panel totp-setup-box\"><div class=\"panel-header\"><h1>Account Confirmed</h1>"
				"<p>Scan this into your Authenticator app within 5 minutes!</p>"
				"<p style=\"font-size: 0.9em; margin-top: -10px; opacity: 0.8;\">(Or tap the QR code on mobile devices)</p></div>"
				"<div class=\"qrcode-container\"><a href=\"%s\" title=\"Tap to open Authenticator App\">"
				"<img src=\"totp_svg?h=%s\" width=\"200\" height=\"200\" alt=\"TOTP Setup QR\"></a></div>"
				"<p class=\"totp-secret-text\">%s</p>"
				"<div class=\"panel-footer\"><a href=\"../\" class=\"btn-link\">Proceed to Login</a></div>"
				"</div></div></body></html>",
				vhd->ui_css[0] ? "<link rel=\"stylesheet\" href=\"" : "",
				vhd->ui_css[0] ? vhd->ui_css : "",
				vhd->ui_css[0] ? "\">" : "",
				uri, hbuf, totp);

			size_t body_len = lws_ptr_diff_size_t(p, body_start);
			if (lws_buflist_append_segment(&pss->tx_buflist, buf, body_len + LWS_PRE) < 0) {
				free(buf);
				return -1;
			}
			free(buf);

			return send_auth_headers(wsi, pss, "text/html", NULL, NULL);
		}

		if (!strncmp((const char *)in, "/authorize", 10)) {
			char client_id[128] = {0}, redirect_uri[256] = {0}, response_type[16] = {0}, state[128] = {0};
			char code_challenge[128] = {0}, code_challenge_method[16] = {0};

			if (lws_get_urlarg_by_name_safe(wsi, "client_id=", client_id, sizeof(client_id)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", redirect_uri, sizeof(redirect_uri)) < 0) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing client_id or redirect_uri");
				return lws_http_transaction_completed(wsi);
			}

			lws_get_urlarg_by_name_safe(wsi, "response_type=", response_type, sizeof(response_type));
			lws_get_urlarg_by_name_safe(wsi, "state=", state, sizeof(state));
			lws_get_urlarg_by_name_safe(wsi, "code_challenge=", code_challenge, sizeof(code_challenge));
			lws_get_urlarg_by_name_safe(wsi, "code_challenge_method=", code_challenge_method, sizeof(code_challenge_method));

			if (strcmp(response_type, "code")) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Unsupported response_type");
				return lws_http_transaction_completed(wsi);
			}

			sqlite3_stmt *stmt;
			int client_valid = auth_verify_redirect_uri(vhd, client_id, redirect_uri);

			if (!client_valid) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid client_id or redirect_uri");
				return lws_http_transaction_completed(wsi);
			}

			char cookies[LWS_AUTH_MAX_COOKIE_LEN] = {0};
			char session_id[65] = {0};
			int has_session = 0;
			uint32_t session_uid = 0;

			int ck_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);
			if (ck_len >= (int)sizeof(cookies)) {
				lwsl_err("%s: OVERRUN! HTTP cookie header length (%d) exceeds allocated buffer size (%d), auth tracking tokens may be truncated!\n", __func__, ck_len, (int)sizeof(cookies));
			}

			if (lws_hdr_copy(wsi, cookies, sizeof(cookies), WSI_TOKEN_HTTP_COOKIE) > 0) {
				const char *p = strstr(cookies, "auth_session=");
				if (p) {
					p += 13;
					size_t i = 0;
					while (*p && *p != ';' && i < sizeof(session_id) - 1)
						session_id[i++] = *p++;
					session_id[i] = 0;
					has_session = 1;
				}
			}

			if (has_session) {
				uint64_t now = (uint64_t)time(NULL);
				if (sqlite3_prepare_v2(vhd->db, "SELECT uid, expires FROM auth_sessions WHERE session_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
					sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
					if (sqlite3_step(stmt) == SQLITE_ROW) {
						session_uid = (uint32_t)sqlite3_column_int(stmt, 0);
						uint64_t exp = (uint64_t)sqlite3_column_int64(stmt, 1);
						if (now >= exp)
							session_uid = 0;
					}
					sqlite3_finalize(stmt);
				}
			}

			if (!session_uid) {
				char loc[1024];
				/* lws_urlencode is typically available, but if not we assume frontend can parse mostly raw */
				lws_snprintf(loc, sizeof(loc), "/auth?client_id=%s&redirect_uri=%s&response_type=code&state=%s&code_challenge=%s&code_challenge_method=%s",
					client_id, redirect_uri, state, code_challenge, code_challenge_method);

				uint8_t hdr_buf[8192 + LWS_PRE];
				uint8_t *h_start = hdr_buf + LWS_PRE;
				uint8_t *h_p = h_start;
				uint8_t *h_end = hdr_buf + sizeof(hdr_buf) - 1;
				if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0, &h_p, h_end)) return lws_http_transaction_completed(wsi);
				if (lws_add_http_header_by_name(wsi, (unsigned char *)"location:", (unsigned char *)loc, (int)strlen(loc), &h_p, h_end)) return lws_http_transaction_completed(wsi);
				if (lws_finalize_write_http_header(wsi, h_start, &h_p, h_end)) return lws_http_transaction_completed(wsi);
				return lws_http_transaction_completed(wsi);
			}

			uint8_t rnd[32];
			char code[65];
			lws_get_random(vhd->context, rnd, 32);
			lws_hex_from_byte_array(rnd, 32, code, 65);

			uint64_t expires = (uint64_t)time(NULL) + 60;

			if (sqlite3_prepare_v2(vhd->db, "INSERT INTO oauth_codes (code, client_id, uid, redirect_uri, expires, code_challenge, code_challenge_method) VALUES (?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_STATIC);
				sqlite3_bind_int(stmt, 3, (int)session_uid);
				sqlite3_bind_text(stmt, 4, redirect_uri, -1, SQLITE_STATIC);
				sqlite3_bind_int64(stmt, 5, (sqlite_int64)expires);
				sqlite3_bind_text(stmt, 6, code_challenge, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 7, code_challenge_method, -1, SQLITE_STATIC);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}

			char loc[1024];
			char host[128] = {0};
			lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST);
			const char *delim = strchr(redirect_uri, '?') ? "&" : "?";
			lws_snprintf(loc, sizeof(loc), "%s%scode=%s&state=%s&iss=https%%3A%%2F%%2F%s", redirect_uri, delim, code, state, host);

			uint8_t hdr_buf[8192 + LWS_PRE];
			uint8_t *h_start = hdr_buf + LWS_PRE;
			uint8_t *h_p = h_start;
			uint8_t *h_end = hdr_buf + sizeof(hdr_buf) - 1;
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0, &h_p, h_end)) return lws_http_transaction_completed(wsi);
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"location:", (unsigned char *)loc, (int)strlen(loc), &h_p, h_end)) return lws_http_transaction_completed(wsi);
			if (lws_finalize_write_http_header(wsi, h_start, &h_p, h_end)) return lws_http_transaction_completed(wsi);
			return lws_http_transaction_completed(wsi);
		}

		if (in && (strstr((const char *)in, "login") || strstr((const char *)in, "register") || strstr((const char *)in, "token") || strstr((const char *)in, "sso_exchange"))) {
			lws_strncpy(pss->requesting_url, (const char *)in, sizeof(pss->requesting_url));

			lwsl_info("%s: Processing POST to '%s'\n", __func__, pss->requesting_url);

			lws_spa_create_info_t i;
			memset(&i, 0, sizeof(i));
			i.param_names = param_names;
			i.count_params = LWS_ARRAY_SIZE(param_names);
			i.max_storage = 1024;
			pss->spa = lws_spa_create_via_info(wsi, &i);
			if (!pss->spa) {
				lwsl_err("%s: lws_spa_create_via_info failed\n", __func__);
				return -1;
			}
			lwsl_info("HTTP POST SPA successfully initialized\n");
			return 0;
		}
		lwsl_info("HTTP Request unaccounted for, breaking loop\n");
	break;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->spa) {
			if (lws_spa_process(pss->spa, in, (int)len)) {
				lwsl_info("HTTP_BODY spa_process failed\n");
				return -1;
			}
			return 0;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_info("HTTP_BODY_COMPLETION: pss->spa=%p resolving "
			  "for '%s'\n", pss->spa, pss->requesting_url);
		if (!pss->spa) {
			lwsl_err("%s: LWS_CALLBACK_HTTP_BODY_COMPLETION called but "
				 "pss->spa is NULL\n", __func__);

			break;
		}
		lws_spa_finalize(pss->spa);

		if (strstr(pss->requesting_url, "token"))
			return lws_auth_api_token(wsi, vhd, pss);
		else if (strstr(pss->requesting_url, "login"))
			return lws_auth_api_login(wsi, vhd, pss);
		else if (strstr(pss->requesting_url, "sso_exchange"))
			return lws_auth_api_sso_exchange(wsi, vhd, pss);
		else if (strstr(pss->requesting_url, "register"))
			return lws_auth_api_register(wsi, vhd, pss);

		lwsl_err("%s: Unknown requesting URL '%s'\n", __func__, pss->requesting_url);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->tx_buflist) /* nothing to write */
                        break;

                uint8_t *p;
                size_t bytes = lws_buflist_next_segment_len(&pss->tx_buflist, &p);
                if (bytes <= 0)
                        break;

                int m = lws_write(wsi, p + LWS_PRE, (unsigned int)(bytes - LWS_PRE), LWS_WRITE_HTTP_FINAL);
                if (m < 0)
                        return -1;

                size_t consume = (size_t)m;
                if ((size_t)m == bytes - LWS_PRE) {
                        consume = bytes;
                }

                lws_buflist_use_segment(&pss->tx_buflist, consume);

                if (lws_buflist_next_segment_len(&pss->tx_buflist, &p)) {
                        lws_callback_on_writable(wsi);
                        return 0;
                }

                return lws_http_transaction_completed(wsi);

	case LWS_CALLBACK_SERVER_WRITEABLE:
	{
		if (!pss->tx_buflist)
			break;

		uint8_t *txp;
		size_t txb = lws_buflist_next_segment_len(&pss->tx_buflist, &txp);

		if (txb > LWS_PRE) {
			int m = lws_write(wsi, txp + LWS_PRE, (unsigned int)(txb - LWS_PRE), LWS_WRITE_TEXT);
			if (m < 0) return -1;
			lws_buflist_use_segment(&pss->tx_buflist, txb);
		} else {
			lws_buflist_use_segment(&pss->tx_buflist, txb);
		}

		if (lws_buflist_next_segment_len(&pss->tx_buflist, &txp))
			lws_callback_on_writable(wsi);

		return 0;
	}

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
	{
		struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, NULL);
		if (!ja || lws_jwt_auth_query_grant(ja, "*") < 1) {
			if (ja) lws_jwt_auth_destroy(&ja);
			lwsl_info("WS connection rejected: missing administrative wildcard grant\n");
			return 1;
		}
		lws_jwt_auth_destroy(&ja);
		return 0;
	}

	case LWS_CALLBACK_ESTABLISHED:
		break;

	case LWS_CALLBACK_RECEIVE:
	{
		char op[32] = {0};
		int req_uid = -1;
		char new_grants[512] = {0};

		char *gp;
		if ((gp = strstr((const char *)in, "\"op\":\""))) {
			gp += 6;
			int i = 0;
			while (*gp && *gp != '"' && i < 31) op[i++] = *gp++;
		}
		if ((gp = strstr((const char *)in, "\"uid\":"))) {
			gp += 6;
			while (*gp == ' ' || *gp == '"') gp++;
			req_uid = atoi(gp);
		}
		if ((gp = strstr((const char *)in, "\"grants\":\""))) {
			gp += 10;
			int i = 0;
			while (*gp && *gp != '"' && i < 511)
				new_grants[i++] = *gp++;
		}

		char client_id[64] = {0};
		char client_name[64] = {0};
		char redirect_uris[512] = {0};

		if ((gp = strstr((const char *)in, "\"client_id\":\""))) {
			gp += 13;
			int i = 0;
			while (*gp && *gp != '"' && i < 63) client_id[i++] = *gp++;
		}
		if ((gp = strstr((const char *)in, "\"name\":\""))) {
			gp += 8;
			int i = 0;
			while (*gp && *gp != '"' && i < 63) client_name[i++] = *gp++;
		}
		if ((gp = strstr((const char *)in, "\"redirect_uris\":\""))) {
			gp += 17;
			int i = 0;
			while (*gp && *gp != '"' && i < 511) redirect_uris[i++] = *gp++;
		}
		if (!strncmp(op, "client_", 7) || !strcmp(op, "clients_list")) {
			if (!strcmp(op, "client_delete") && client_id[0]) {
				sqlite3_stmt *stmt;
				if (sqlite3_prepare_v2(vhd->db, "DELETE FROM oauth_clients WHERE client_id=?", -1, &stmt, NULL) == SQLITE_OK) {
					sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_TRANSIENT);
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);
				}
			} else if (!strcmp(op, "client_edit") && client_id[0]) {
				sqlite3_stmt *stmt;
				if (sqlite3_prepare_v2(vhd->db, "UPDATE oauth_clients SET name=?, redirect_uris=? WHERE client_id=?", -1, &stmt, NULL) == SQLITE_OK) {
					int rc;
					sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT);
					sqlite3_bind_text(stmt, 2, redirect_uris, -1, SQLITE_TRANSIENT);
					sqlite3_bind_text(stmt, 3, client_id, -1, SQLITE_TRANSIENT);
					rc = sqlite3_step(stmt);
					if (rc != SQLITE_DONE)
						lwsl_err("%s: UPDATE on cid '%s' failed with sqlite3 code %d\n", __func__, client_id, rc);
					sqlite3_finalize(stmt);
				} else {
					lwsl_err("%s: sqlite3_prepare_v2 for client_edit failed\n", __func__);
				}
			} else if (!strcmp(op, "client_create") && client_id[0]) {
				sqlite3_stmt *stmt;
				if (sqlite3_prepare_v2(vhd->db, "INSERT OR IGNORE INTO oauth_clients (client_id, name, redirect_uris, client_secret_hash) VALUES (?, ?, ?, '')", -1, &stmt, NULL) == SQLITE_OK) {
					sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_TRANSIENT);
					sqlite3_bind_text(stmt, 2, client_name, -1, SQLITE_TRANSIENT);
					sqlite3_bind_text(stmt, 3, redirect_uris, -1, SQLITE_TRANSIENT);
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);
				}
			}

			size_t alloc_sz = 16384 + LWS_PRE;
			char *b = malloc(alloc_sz);
			if (b) {
				char *o = b + LWS_PRE, *end = b + alloc_sz - 1;
				sqlite3_stmt *stmt;
				int first = 1;

				o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "{\"op\":\"clients_list_reply\",\"clients\":[");
				if (sqlite3_prepare_v2(vhd->db, "SELECT client_id, name, redirect_uris FROM oauth_clients", -1, &stmt, NULL) == SQLITE_OK) {
					while (sqlite3_step(stmt) == SQLITE_ROW) {
						const char *cid = (const char *)sqlite3_column_text(stmt, 0);
						const char *cn = (const char *)sqlite3_column_text(stmt, 1);
						const char *ru = (const char *)sqlite3_column_text(stmt, 2);
						if (!first) o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), ",");
						first = 0;
						o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "{\"client_id\":\"%s\",\"name\":\"%s\",\"redirect_uris\":\"%s\"}",
							cid ? cid : "", cn ? cn : "", ru ? ru : "");
					}
					sqlite3_finalize(stmt);
				}
				o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "]}");
				if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)b, (lws_ptr_diff_size_t(o, b))) >= 0) {
					lws_callback_on_writable(wsi);
				}
				free(b);
			}
			break;
		}

		if (!strcmp(op, "delete") && req_uid > 0) {
			int has_star = 0;
			sqlite3_stmt *s;
			if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM grants g JOIN services svc ON g.service_id = svc.service_id WHERE g.uid=? AND svc.name='*'", -1, &s, NULL) == SQLITE_OK) {
				sqlite3_bind_int(s, 1, req_uid);
				if (sqlite3_step(s) == SQLITE_ROW) has_star = 1;
				sqlite3_finalize(s);
			}
			if (!has_star) {
				char dq[256];
				sqlite3_exec(vhd->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
				lws_snprintf(dq, sizeof(dq), "DELETE FROM auth_sessions WHERE uid=%d", req_uid); sqlite3_exec(vhd->db, dq, NULL, NULL, NULL);
				lws_snprintf(dq, sizeof(dq), "DELETE FROM oauth_codes WHERE uid=%d", req_uid); sqlite3_exec(vhd->db, dq, NULL, NULL, NULL);
				lws_snprintf(dq, sizeof(dq), "DELETE FROM grants WHERE uid=%d", req_uid); sqlite3_exec(vhd->db, dq, NULL, NULL, NULL);
				lws_snprintf(dq, sizeof(dq), "DELETE FROM users WHERE uid=%d", req_uid); sqlite3_exec(vhd->db, dq, NULL, NULL, NULL);
				sqlite3_exec(vhd->db, "COMMIT;", NULL, NULL, NULL);
			}
		} else if (!strcmp(op, "edit") && req_uid > 0) {
			sqlite3_exec(vhd->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
			char eq[256];
			lws_snprintf(eq, sizeof(eq), "DELETE FROM grants WHERE uid=%d", req_uid);
			sqlite3_exec(vhd->db, eq, NULL, NULL, NULL);

			char *p2 = new_grants;
			while (*p2) {
				char *comma = strchr(p2, ',');
				if (comma) *comma = '\0';
				char *colon = strchr(p2, ':');
				if (colon) {
					*colon = '\0';
					const char *sn = p2;
					int lvl = atoi(colon + 1);

					if (sn[0] && lvl > 0) {
						sqlite3_stmt *s2;
						if (sqlite3_prepare_v2(vhd->db, "INSERT OR IGNORE INTO services (name) VALUES (?)", -1, &s2, NULL) == SQLITE_OK) {
							sqlite3_bind_text(s2, 1, sn, -1, SQLITE_TRANSIENT);
							sqlite3_step(s2);
							sqlite3_finalize(s2);
						}
						if (sqlite3_prepare_v2(vhd->db, "INSERT INTO grants (uid, service_id, grant_level) VALUES (?, (SELECT service_id FROM services WHERE name=?), ?)", -1, &s2, NULL) == SQLITE_OK) {
							sqlite3_bind_int(s2, 1, req_uid);
							sqlite3_bind_text(s2, 2, sn, -1, SQLITE_TRANSIENT);
							sqlite3_bind_int(s2, 3, lvl);
							sqlite3_step(s2);
							sqlite3_finalize(s2);
						}
					}
				}
				if (!comma) break;
				p2 = comma + 1;
			}
			sqlite3_exec(vhd->db, "COMMIT;", NULL, NULL, NULL);
		}

		size_t alloc_sz = 65536 + LWS_PRE;
		char *b = malloc(alloc_sz);
		if (b) {
			char *o = b + LWS_PRE, *end = b + alloc_sz - 1;
			sqlite3_stmt *stmt;
			int first = 1;

			o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "{\"op\":\"list_reply\",\"users\":[");

			if (sqlite3_prepare_v2(vhd->db, "SELECT uid, username FROM users", -1, &stmt, NULL) == SQLITE_OK) {
				while (sqlite3_step(stmt) == SQLITE_ROW) {
					int uid = sqlite3_column_int(stmt, 0);
					const char *un = (const char *)sqlite3_column_text(stmt, 1);

					if (!first) o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), ",");
					first = 0;

					o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "{\"uid\":%d,\"user\":\"%s\",\"grants\":{", uid, un);

					sqlite3_stmt *gstmt;
					int gfirst = 1;
					if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid=?", -1, &gstmt, NULL) == SQLITE_OK) {
						sqlite3_bind_int(gstmt, 1, uid);
						while (sqlite3_step(gstmt) == SQLITE_ROW) {
							const char *sn = (const char *)sqlite3_column_text(gstmt, 0);
							int gl = sqlite3_column_int(gstmt, 1);
							if (!gfirst) o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), ",");
							gfirst = 0;
							o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "\"%s\":%d", sn, gl);
						}
						sqlite3_finalize(gstmt);
					}
					o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "}}");
				}
				sqlite3_finalize(stmt);
			}
			o += lws_snprintf(o, lws_ptr_diff_size_t(end, o), "]}");
			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)b, (lws_ptr_diff_size_t(o, b))) < 0) {
				free(b);
				return -1;
			}
			free(b);
			lws_callback_on_writable(wsi);
		}
		break;
	}

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_info("CLOSED_HTTP wsi=%p\n", wsi);
		if (pss && pss->spa)
			lws_spa_destroy(pss->spa);
		if (pss && pss->tx_buflist)
			lws_buflist_destroy_all_segments(&pss->tx_buflist);
		break;

        default:
		break;
	}

        return lws_callback_http_dummy(wsi, reason, user, in, len);
}

#define LWS_PLUGIN_PROTOCOL_AUTH_SERVER \
	{ \
		"lws-auth-server", \
		callback_auth_server, \
		sizeof(struct per_session_data__auth_server), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_AUTH_SERVER
};

LWS_VISIBLE const lws_plugin_protocol_t lws_auth_server = {
	.hdr = {
		.name = "LWS Auth Server API",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 1000,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
