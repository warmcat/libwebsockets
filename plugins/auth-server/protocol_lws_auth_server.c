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

static const char * const param_names[] = {
	"username",
	"password",
	"totp"
};

enum enum_param_names {
        EP_USER,
        EP_PASS,
        EP_TOTP,
        EP_COUNT
};

struct per_vhost_data__auth_server {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	const struct lws_protocols	*protocol;
	sqlite3				*db;
	char				db_path[256];
	char				auth_domain[128];
	char				jwk_path[256];
	char				jwt_alg[16];
	struct lws_jwk			jwk;
	int				registration_ui;
	char				email_from[128];
	char				email_subject[256];
	char				email_body[1024];
	const lws_smtp_client_ops_t	*smtp;
	lws_dll2_owner_t		ip_strikes;
	lws_dll2_owner_t		ip_bans;
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
	char temp[1024]; /* scratchpad for JWK/JWS generation */
	uint64_t now = (uint64_t)time(NULL);
	uint64_t exp = now + (24 * 3600); /* 24 hours */

	/* The format string maps directly to the JWS payload */
	if (lws_jwt_sign_compact(vhd->context, &vhd->jwk, vhd->jwt_alg,
	                         out, out_len, temp, sizeof(temp),
	                         "{\"iss\":\"%s\",\"sub\":\"%s\",\"uid\":%u,"
	                         "\"iat\":%llu,\"exp\":%llu%s%s}",
	                         vhd->auth_domain, username, uid,
	                         (unsigned long long)now, (unsigned long long)exp,
	                         claims_json ? "," : "",
	                         claims_json ? claims_json : "")) {
		lwsl_err("JWT sig failed\n");

		return -1;
	}

	return 0;
}

static int
lws_auth_generate_token(struct per_vhost_data__auth_server *vhd,
                        const char *username, uint32_t uid,
                        char *out, size_t *out_len)
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

	if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_ROW)
                goto bail;

	*uid = (uint32_t)sqlite3_column_int(stmt, 0);
	stored_hash = (const char *)sqlite3_column_text(stmt, 1);
	salt = (const char *)sqlite3_column_text(stmt, 2);

	/* hash the input password with SHA-512 and salt */
	if (!stored_hash || !salt || lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA512))
		goto bail;

	if (!lws_genhash_update(&ctx, salt, strlen(salt)))
		goto bail;

	if (!lws_genhash_update(&ctx, password, strlen(password)))
		goto bail;

	if (!lws_genhash_destroy(&ctx, hash))
		goto bail;

	lws_genhash_render(LWS_GENHASH_TYPE_SHA512, hash, hex, sizeof(hex));

        if (!strcmp(stored_hash, hex))
		match = 0;

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

static int
send_auth_headers(struct lws *wsi, struct per_session_data__auth_server *pss, const char *content_type)
{
	uint8_t buf[2048 + LWS_PRE], *start = &buf[LWS_PRE], *p = start, *end = &buf[sizeof(buf) - 1], *pq;
	unsigned int resp_code = pss->http_response_code ? pss->http_response_code : HTTP_STATUS_OK;
        size_t amount = (size_t)lws_buflist_next_segment_len(&pss->tx_buflist, &pq);

        if (lws_add_http_common_headers(wsi, resp_code, content_type,
                                        (unsigned int)(amount ? amount - LWS_PRE: LWS_ILLEGAL_HTTP_CONTENT_LEN), &p,
                                        end)) {
                lwsl_user("[AUTH-TRX] send_auth_headers custom hdr err\n");

                return -1;
        }
        if (pss->totp_required &&
            lws_add_http_header_by_name(wsi, (unsigned char *)"X-Requires-TOTP:", (unsigned char *)"1", 1, &p, end)) {
                lwsl_user("[AUTH-TRX] send_auth_headers custom hdr err\n");

                return -1;
        }
	if (lws_finalize_write_http_header(wsi, start, &p, end)) {
		lwsl_user("[AUTH-TRX] send_auth_headers final hdr err\n");
		return -1;
	}

        if (pss->tx_buflist)
                lws_callback_on_writable(wsi);
        else
                return lws_http_transaction_completed(wsi);

        return 0;
}

static int
lws_auth_api_login(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
		   struct per_session_data__auth_server *pss)
{
	char peer[64], jwt[1024], pl[1024 + LWS_PRE];
	const char *user = lws_spa_get_string(pss->spa, EP_USER);
	const char *pass = lws_spa_get_string(pss->spa, EP_PASS);
	const char *totp_code_str = lws_spa_get_string(pss->spa, EP_TOTP);
        sqlite3_stmt *stmt_chk, *stmt;
        size_t jwt_len = sizeof(jwt);
        char totp_secret[64] = {0};
        int len, users_empty = 0;
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
		lwsl_user("[AUTH-TRX] login rejected (database completely empty)\n");
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
		lwsl_user("[AUTH-TRX] login bad credentials\n");
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

	if (totp_secret[0]) {
		if (!totp_code_str || !totp_code_str[0]) {
			lwsl_user("[AUTH-TRX] login missing TOTP\n");
			pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
			pss->totp_required = 1;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Authenticator Code Required\"}");
			goto send;
		}

		uint32_t code = (uint32_t)atoi(totp_code_str);
		if (lws_auth_totp_verify(totp_secret, code)) {
			auth_record_strike(vhd, peer);
			lwsl_user("[AUTH-TRX] login bad TOTP\n");
			pss->http_response_code = HTTP_STATUS_UNAUTHORIZED;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Authenticator Code\"}");
			goto send;
		}
	}

	if (!lws_auth_generate_token(vhd, user, uid, jwt, &jwt_len)) {
		pss->http_response_code = HTTP_STATUS_OK;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"token\":\"%s\"}", jwt);
		goto send;
        }

	lwsl_user("[AUTH-TRX] login token generation failed, dropping conn.\n");
	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Internal Error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json");
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
		if (!lws_is_local_address(peer) && !lws_is_lan_address(peer)) {
			lwsl_user("[AUTH-TRX] reg denied (admin local/lan only)\n");
			pss->http_response_code = HTTP_STATUS_SERVICE_UNAVAILABLE;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Please try again after this service has been configured by the administrator\"}");
			goto send;
		}
		/* Allow localhost/LAN admin bootstrap regardless of registration_ui */
	} else {
		/* Not empty: enforce public registration policy */
		if (!vhd->registration_ui) {
			lwsl_user("[AUTH-TRX] reg denied (ui disabled)\n");
			pss->http_response_code = HTTP_STATUS_FORBIDDEN;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Registration Disabled\"}");
			goto send;
		}
	}

	user = lws_spa_get_string(pss->spa, EP_USER);
	pass = lws_spa_get_string(pss->spa, EP_PASS);

	lwsl_user("%s: Registration requested for user: '%s'\n", __func__, user ? user : "NULL");

	if (!user || !pass) {
		lwsl_err("%s: Missing credentials in POST\n", __func__);
		lwsl_user("[AUTH-TRX] reg missing credentials POST\n");
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Missing Credentials\"}");
		goto send;
	}

	int user_len = (int)strlen(user);
	if (user_len < 3 || user_len > 64) {
		lwsl_user("[AUTH-TRX] reg invalid username length\n");
		pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
		len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Username length\"}");
		goto send;
	}

	for (int i = 0; i < user_len; i++) {
		char c = user[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '@' || c == '.' ||
		      c == '-' || c == '_' || c == '+')) {
			lwsl_user("[AUTH-TRX] reg invalid charset\n");
			pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
			len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Invalid Username characters\"}");
			goto send;
		}
	}

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
                        lwsl_err("[AUTH-TRX] DB insert failed: %s\n", sqlite3_errmsg(vhd->db));
                        auth_record_strike(vhd, peer);
                        pss->http_response_code = HTTP_STATUS_BAD_REQUEST;
                        len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"User creation failed\"}");
                        goto send;
                }

                if (vhd->smtp && vhd->smtp->send_email) {
                        char url[512], mbody[1024];

                        lws_snprintf(url, sizeof(url), "https://%s/auth/api/verify?h=%s",
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
                lwsl_user("[AUTH-TRX] reg successful, dispatched verification.\n");

                goto send;

	}
fail:
	lwsl_user("[AUTH-TRX] reg hash generation or DB query failed\n");
	auth_record_strike(vhd, peer);
	pss->http_response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
	len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"error\":\"Internal Error\"}");

send:
	if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
		return -1;

	return send_auth_headers(wsi, pss, "application/json");
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
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__auth_server));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

	        /* defaults */
		lws_strncpy(vhd->db_path, "/var/db/lws-auth.sqlite3", sizeof(vhd->db_path));
		lws_strncpy(vhd->auth_domain, "auth.warmcat.com", sizeof(vhd->auth_domain));
		lws_strncpy(vhd->jwk_path, "/var/db/lws-auth.jwk", sizeof(vhd->jwk_path));
		lws_strncpy(vhd->jwt_alg, "ES256", sizeof(vhd->jwt_alg));
		vhd->registration_ui = 0;

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "db_path");
		if (pvo)
			lws_strncpy(vhd->db_path, pvo->value, sizeof(vhd->db_path));

		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in, "auth_domain");
		if (pvo)
			lws_strncpy(vhd->auth_domain, pvo->value, sizeof(vhd->auth_domain));

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

		lwsl_notice("Auth Server plugin initialized: domain '%s', db '%s', jwk '%s', alg '%s', reg_ui %d\n",
			 vhd->auth_domain, vhd->db_path, vhd->jwk_path, vhd->jwt_alg, vhd->registration_ui);

		/* load or generate JWK */
		if (lws_jwk_load(&vhd->jwk, vhd->jwk_path, NULL, NULL)) {
			lwsl_notice("Generating new EC JWK at %s\n", vhd->jwk_path);
			if (lws_jwk_generate(vhd->context, &vhd->jwk,
			                     LWS_GENCRYPTO_KTY_EC, 256, "P-256") ||
			    lws_jwk_save(&vhd->jwk, vhd->jwk_path)) {
				lwsl_err("Auth plugin failed to generate or save JWK\n");
				return -1;
			}
		}

		/* Initialize sqlite database using lws_struct */
		if (lws_struct_sq3_open(vhd->context, vhd->db_path, 1, &vhd->db)) {
			lwsl_err("Auth plugin failed to open database\n");
			return -1; /* fail plugin init */
		}

		if (sqlite3_exec(vhd->db, schema_init, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Auth plugin schema creation failed: %s\n",
				 sqlite3_errmsg(vhd->db));
			return -1;
		}

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
		lwsl_user("[AUTH-TRX] HTTP: path='%s'\n", in ? (const char *)in : "NULL");
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

		if (in && (!strncmp((const char *)in, "/status", 7))) {
			int users_empty = 0;
			sqlite3_stmt *stmt;
			if (sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1, &stmt, NULL) == SQLITE_OK) {
				if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0)
					users_empty = 1;
				sqlite3_finalize(stmt);
			}

			struct per_session_data__auth_server *pss =
				(struct per_session_data__auth_server *)user;

			if (pss) {
				lwsl_user("[AUTH-TRX] /status API endpoint returning users_empty=%d\n", users_empty);
				pss->http_response_code = HTTP_STATUS_OK;
				char pl[1024 + LWS_PRE];
		                int len = lws_snprintf(pl + LWS_PRE, sizeof(pl) - LWS_PRE, "{\"users_empty\":%d}", users_empty);
				if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)pl, (size_t)len + LWS_PRE) < 0)
					return -1;
				return send_auth_headers(wsi, pss, "application/json");
			}

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
			char email[128], pass[129], salt[32], totp[64];

			lwsl_user("[AUTH-TRX] verify: looking for hash='%s'\n", hbuf);

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
						lwsl_user("[AUTH-TRX] verify: link expired! now=%llu, exp=%llu\n", (unsigned long long)now, (unsigned long long)exp);
					}
				} else {
					lwsl_user("[AUTH-TRX] verify: db step failed or no row: %d %s\n", s_res, sqlite3_errmsg(vhd->db));
				}
				sqlite3_finalize(stmt);
			} else {
				lwsl_err("[AUTH-TRX] verify: db prepare failed: %s\n", sqlite3_errmsg(vhd->db));
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
			if (users_count == 1) {
				sqlite3_exec(vhd->db, "INSERT OR IGNORE INTO services (service_id, name) VALUES (1, 'auth_server')", NULL, NULL, NULL);
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
				lwsl_user("[AUTH-TRX] verify OOM for HTML buffer\n");
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "OOM");
				return lws_http_transaction_completed(wsi);
			}

			uint8_t *body_start = buf + LWS_PRE;
			uint8_t *body_end = buf + alloc_size - LWS_PRE - 1;
			uint8_t *p = body_start;

			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(body_end, p),
				"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Account Confirmed</title>"
				"<link rel=\"stylesheet\" href=\"/auth/auth.css\">"
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>"
				"<body><div class=\"background-elements\"><div class=\"orb orb-1\"></div><div class=\"orb orb-2\"></div><div class=\"orb orb-3\"></div></div>"
				"<div class=\"auth-container\"><div class=\"glass-panel totp-setup-box\"><div class=\"panel-header\"><h1>Account Confirmed</h1>"
				"<p>Scan this into your Authenticator app within 5 minutes!</p></div>"
				"<div class=\"qrcode-container\"><img src=\"/auth/api/totp_svg?h=%s\" alt=\"TOTP Setup QR\"></div>"
				"<p class=\"totp-secret-text\">%s</p>"
				"<div class=\"panel-footer\"><a href=\"/auth\" class=\"btn-link\">Proceed to Login</a></div>"
				"</div></div></body></html>", hbuf, totp);

			size_t body_len = lws_ptr_diff_size_t(p, body_start);

			uint8_t hdr_buf[8192 + LWS_PRE];
			uint8_t *h_start = hdr_buf + LWS_PRE;
			uint8_t *h_p = h_start;
			uint8_t *h_end = hdr_buf + sizeof(hdr_buf) - 1;
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/html", (lws_filepos_t)body_len, &h_p, h_end)) { free(buf); return lws_http_transaction_completed(wsi); }
			if (lws_finalize_write_http_header(wsi, h_start, &h_p, h_end)) { free(buf); return lws_http_transaction_completed(wsi); }

			// Append entire body array block onto buflist queue natively!
			struct per_session_data__auth_server *pss = (struct per_session_data__auth_server *)user;
			if (pss) {
				if (lws_buflist_append_segment(&pss->tx_buflist, buf, body_len + LWS_PRE) < 0) {
					free(buf);
					return -1;
				}
				lws_callback_on_writable(wsi);
			}
			free(buf);
			return 0;
		}

		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
			lws_strncpy(pss->requesting_url,
				    (const char *)in, sizeof(pss->requesting_url));

			lwsl_user("%s: Processing POST to '%s'\n", __func__, pss->requesting_url);

			if (strstr(pss->requesting_url, "login") || strstr(pss->requesting_url, "register")) {
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
				lwsl_user("[AUTH-TRX] HTTP POST SPA successfully initialized\n");
				return 0;
			}
		}
		lwsl_user("[AUTH-TRX] HTTP Request unaccounted for, breaking loop\n");
		break;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->spa) {
			if (lws_spa_process(pss->spa, in, (int)len)) {
				lwsl_user("[AUTH-TRX] HTTP_BODY spa_process failed\n");
				return -1;
			}
			return 0;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_user("[AUTH-TRX] HTTP_BODY_COMPLETION: pss->spa=%p resolving "
			  "for '%s'\n", pss->spa, pss->requesting_url);
		if (!pss->spa) {
			lwsl_err("%s: LWS_CALLBACK_HTTP_BODY_COMPLETION called but "
				 "pss->spa is NULL\n", __func__);

			break;
		}
		lws_spa_finalize(pss->spa);

		if (strstr(pss->requesting_url, "login"))
			return lws_auth_api_login(wsi, vhd, pss);
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

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_user("[AUTH-TRX] CLOSED_HTTP wsi=%p\n", wsi);
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
		"LWS Auth Server API",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
