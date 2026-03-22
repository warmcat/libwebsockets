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

#if 0
static const lws_struct_map_t lsm_users[] = {
	LSM_UNSIGNED	(lws_auth_user_t, uid,				"uid"),
	LSM_STRING_PTR	(lws_auth_user_t, username,			"username"),
	LSM_STRING_PTR	(lws_auth_user_t, password_hash,		"password_hash"),
	LSM_STRING_PTR	(lws_auth_user_t, salt,				"salt"),
	LSM_STRING_PTR	(lws_auth_user_t, totp_secret,			"totp_secret"),
};

static const lws_struct_map_t lsm_services[] = {
	LSM_UNSIGNED	(lws_auth_service_t, service_id,		"service_id"),
	LSM_STRING_PTR	(lws_auth_service_t, name,			"name"),
};

static const lws_struct_map_t lsm_grants[] = {
	LSM_UNSIGNED	(lws_auth_grant_t, grant_id,			"grant_id"),
	LSM_UNSIGNED	(lws_auth_grant_t, uid,				"uid"),
	LSM_UNSIGNED	(lws_auth_grant_t, service_id,			"service_id"),
	LSM_UNSIGNED	(lws_auth_grant_t, grant_level,			"grant_level"),
};

static const lws_struct_map_t lsm_registrations[] = {
	LSM_STRING_PTR	(lws_auth_registration_t, email,		"email"),
	LSM_STRING_PTR	(lws_auth_registration_t, password_hash,	"password_hash"),
	LSM_STRING_PTR	(lws_auth_registration_t, salt,			"salt"),
	LSM_STRING_PTR	(lws_auth_registration_t, totp_secret,		"totp_secret"),
	LSM_STRING_PTR	(lws_auth_registration_t, verify_hash,		"verify_hash"),
	LSM_UNSIGNED	(lws_auth_registration_t, expires,		"expires"),
};

static const lws_struct_map_t lsm_bans[] = {
	LSM_STRING_PTR	(auth_server_ban_t, ip,				"ip"),
	LSM_UNSIGNED	(auth_server_ban_t, banned_until,		"banned_until"),
};

static const lws_struct_map_t lsm_schema_auth_server[] = {
	LSM_SCHEMA_DLL2	(lws_auth_user_t, list, NULL, lsm_users,	"users"),
	LSM_SCHEMA_DLL2	(lws_auth_service_t, list, NULL, lsm_services,	"services"),
	LSM_SCHEMA_DLL2	(lws_auth_grant_t, list, NULL, lsm_grants,	"grants"),
	LSM_SCHEMA_DLL2	(lws_auth_registration_t, list, NULL, lsm_registrations, "registrations"),
	LSM_SCHEMA_DLL2	(auth_server_ban_t, list, NULL, lsm_bans,	"bans"),
};
#endif

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

struct per_session_data__auth_server {
	struct		lws_spa *spa;
	char		result[8192];
	int		result_len;
	char		requesting_url[64];
};

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
		if (!lws_auth_totp_compute(secret_b32, (uint64_t)((int64_t)t + i), &c)) {
			if (c == code)
				return 0;
		}

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
        const char *stored_hash;
        const char *salt;
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
lws_auth_api_login(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
		   struct per_session_data__auth_server *pss)
{
	char peer[64];
	lws_get_peer_simple(wsi, peer, sizeof(peer));

	const char *user = lws_spa_get_string(pss->spa, EP_USER);
	const char *pass = lws_spa_get_string(pss->spa, EP_PASS);
	const char *totp_code_str = lws_spa_get_string(pss->spa, EP_TOTP);
	uint32_t uid = 0;
	char jwt[1024];
	size_t jwt_len = sizeof(jwt);

	if (!user || !pass) {
		lwsl_err("%s: Missing user or pass parameter\n", __func__);
		auth_record_strike(vhd, peer);
		lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
		return lws_http_transaction_completed(wsi);
	}

	if (lws_auth_check_credentials(vhd, user, pass, &uid)) {
		lwsl_err("%s: Validation failed for user '%s'\n", __func__, user);
		auth_record_strike(vhd, peer);
		lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
		return lws_http_transaction_completed(wsi);
	}

	lwsl_user("%s: User '%s' validated successfully (uid %u)\n", __func__, user, uid);

	sqlite3_stmt *stmt;
	const char *query = "SELECT totp_secret FROM users WHERE uid = ?";
	char totp_secret[64] = {0};

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
			uint8_t buf[1024 + LWS_PRE];
			uint8_t *start = &buf[LWS_PRE], *p = start, *end = &buf[sizeof(buf) - 1];

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_UNAUTHORIZED, "application/json", 0, &p, end))
				return -1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"x-requires-totp:", (unsigned char *)"1", 1, &p, end))
				return -1;
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return -1;

			lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
			return -1;
		}

		uint32_t code = (uint32_t)atoi(totp_code_str);
		if (lws_auth_totp_verify(totp_secret, code)) {
			auth_record_strike(vhd, peer);
			lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, "Invalid Authenticator Code.");
			return lws_http_transaction_completed(wsi);
		}
	}

	if (!lws_auth_generate_token(vhd, user, uid, jwt, &jwt_len)) {
		pss->result_len = lws_snprintf(pss->result, sizeof(pss->result), "{\"token\":\"%s\"}", jwt);
		lws_callback_on_writable(wsi);
                return 0;
        }

	lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

	return -1;
}

static int
lws_auth_api_register(struct lws *wsi, struct per_vhost_data__auth_server *vhd,
		      struct per_session_data__auth_server *pss)
{
	int users_empty = 0, is_local;
	sqlite3_stmt *stmt_chk;
        const char *user, *pass;
        char peer[64];

        if (sqlite3_prepare_v2(vhd->db, "SELECT COUNT(*) FROM users", -1,
                                   &stmt_chk, NULL) == SQLITE_OK &&
            sqlite3_step(stmt_chk) == SQLITE_ROW &&
            sqlite3_column_int(stmt_chk, 0) == 0) {
                users_empty = 1;
                sqlite3_finalize(stmt_chk);
        }

        lws_get_peer_simple(wsi, peer, sizeof(peer));
	is_local = lws_is_local_address(peer);

	if (users_empty) {
		if (!is_local) {
			lws_return_http_status(wsi, HTTP_STATUS_SERVICE_UNAVAILABLE, "Please try again after this service has been configured by the administrator");
			return lws_http_transaction_completed(wsi);
		}
		/* Allow localhost admin bootstrap regardless of registration_ui */
	} else
		/* Not empty: enforce public registration policy */
		if (!vhd->registration_ui) {
			lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "Registration Disabled");
			return lws_http_transaction_completed(wsi);
		}

	user = lws_spa_get_string(pss->spa, EP_USER);
	pass = lws_spa_get_string(pss->spa, EP_PASS);

	lwsl_user("%s: Registration requested for user: '%s'\n", __func__, user ? user : "NULL");

	if (!user || !pass) {
		lwsl_err("%s: Missing credentials in POST\n", __func__);
		lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing Credentials");
		return lws_http_transaction_completed(wsi);
	}

	int user_len = (int)strlen(user);
	if (user_len < 3 || user_len > 64) {
		lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid Username length");
		return lws_http_transaction_completed(wsi);
	}

	for (int i = 0; i < user_len; i++) {
		char c = user[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '@' || c == '.' ||
		      c == '-' || c == '_' || c == '+')) {
			lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid Username characters");
			return lws_http_transaction_completed(wsi);
		}
	}

	sqlite3_stmt *stmt;
	const char *query = "INSERT OR REPLACE INTO registrations (email, password_hash, salt, totp_secret, verify_hash, expires) VALUES (?, ?, ?, ?, ?, ?)";
	struct lws_genhash_ctx ctx;
	uint8_t hash[64];
	char hex[129];

	uint8_t salt_raw[16];
	char auto_salt[32];
	lws_get_random(vhd->context, salt_raw, sizeof(salt_raw));
	lws_b32_encode_string((const char *)salt_raw, sizeof(salt_raw), auto_salt, sizeof(auto_salt));

	uint8_t totp_bytes[10];
	char totp_b32[20];
	lws_get_random(vhd->context, totp_bytes, sizeof(totp_bytes));
	lws_b32_encode_string((const char *)totp_bytes, sizeof(totp_bytes), totp_b32, sizeof(totp_b32));

	uint8_t vhash_raw[16];
	char verify_hash[33];
	lws_get_random(vhd->context, vhash_raw, sizeof(vhash_raw));
	lws_hex_from_byte_array(vhash_raw, sizeof(vhash_raw), verify_hash, sizeof(verify_hash));

	uint64_t expires = (uint64_t)time(NULL) + 600;

	if (!lws_genhash_init(&ctx, LWS_GENHASH_TYPE_SHA512) &&
	    !lws_genhash_update(&ctx, auto_salt, strlen(auto_salt)) &&
	    !lws_genhash_update(&ctx, pass, strlen(pass)) &&
	    !lws_genhash_destroy(&ctx, hash)) {
		lws_genhash_render(LWS_GENHASH_TYPE_SHA512, hash, hex, sizeof(hex));

		if (sqlite3_prepare_v2(vhd->db, query, -1, &stmt, NULL) == SQLITE_OK) {
			sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, hex, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, auto_salt, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 4, totp_b32, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 5, verify_hash, -1, SQLITE_STATIC);
                        sqlite3_bind_int64(stmt, 6, (sqlite_int64)expires);
                        if (sqlite3_step(stmt) == SQLITE_DONE) {

				if (vhd->smtp && vhd->smtp->send_email) {
					char url[512];
					lws_snprintf(url, sizeof(url), "https://%s/auth/api/verify?h=%s", vhd->auth_domain, verify_hash);
					vhd->smtp->send_email(vhd->context, vhd->vhost, user, url);
				}

				pss->result_len = lws_snprintf(pss->result, sizeof(pss->result), "{\"status\":\"Please check your email\"}");
				lws_callback_on_writable(wsi);
			} else {
				auth_record_strike(vhd, peer);
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "User creation failed");
				sqlite3_finalize(stmt);
				return lws_http_transaction_completed(wsi);
			}
			sqlite3_finalize(stmt);
			return 0;
		}
	}
	auth_record_strike(vhd, peer);
	lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
	return lws_http_transaction_completed(wsi);
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

		if (!strncmp((const char *)in, "/verify", 7) || !strncmp((const char *)in, "verify", 6)) {
			char hbuf[64];
			if (!lws_get_urlarg_by_name(wsi, "h=", hbuf, sizeof(hbuf))) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing Hash");
				return lws_http_transaction_completed(wsi);
			}

			sqlite3_stmt *stmt;
			int found = 0;
			uint64_t now = (uint64_t)time(NULL);
			char email[128], pass[129], salt[32], totp[64];

			if (sqlite3_prepare_v2(vhd->db, "SELECT email, password_hash, salt, totp_secret, expires FROM registrations WHERE verify_hash = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, hbuf, -1, SQLITE_STATIC);
				if (sqlite3_step(stmt) == SQLITE_ROW) {
					uint64_t exp = (uint64_t)sqlite3_column_int64(stmt, 4);
					if (now <= exp) {
						found = 1;
						lws_strncpy(email, (const char *)sqlite3_column_text(stmt, 0), sizeof(email));
						lws_strncpy(pass, (const char *)sqlite3_column_text(stmt, 1), sizeof(pass));
						lws_strncpy(salt, (const char *)sqlite3_column_text(stmt, 2), sizeof(salt));
						lws_strncpy(totp, (const char *)sqlite3_column_text(stmt, 3), sizeof(totp));
					}
				}
				sqlite3_finalize(stmt);
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

			if (sqlite3_prepare_v2(vhd->db, "DELETE FROM registrations WHERE email = ?", -1, &stmt, NULL) == SQLITE_OK) {
				sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
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

			char uri[256];
			uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
			uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];

			lws_snprintf(uri, sizeof(uri), "otpauth://totp/%s:%s?secret=%s&issuer=%s",
				vhd->auth_domain, email, totp, vhd->auth_domain);

			qrcodegen_encodeText(uri, tempBuffer, qrcode, qrcodegen_Ecc_MEDIUM,
				qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);

			size_t alloc_size = 65536 + LWS_PRE;
			uint8_t *buf = malloc(alloc_size);
			if (!buf) {
				lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "OOM");
				return lws_http_transaction_completed(wsi);
			}
			uint8_t *start = &buf[LWS_PRE], *p = start, *end = &buf[alloc_size - 1];

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/html", 0, &p, end)) { free(buf); return lws_http_transaction_completed(wsi); }
			if (lws_finalize_write_http_header(wsi, start, &p, end)) { free(buf); return lws_http_transaction_completed(wsi); }
			lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_HEADERS);

			p = start;
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				"<html><body style='font-family:sans-serif;text-align:center;background:#1e293b;color:white;padding:50px;'>"
				"<h2>Account Confirmed</h2><p>Please scan this into your Authenticator app within 5 minutes!</p>"
				"<div style='background:white;padding:20px;display:inline-block;border-radius:10px;margin:20px;'><svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 %d %d\" stroke=\"none\"><rect width=\"100%%\" height=\"100%%\" fill=\"#FFFFFF\"/><path d=\"",
				qrcodegen_getSize(qrcode) + 8, qrcodegen_getSize(qrcode) + 8);

			int size = qrcodegen_getSize(qrcode);
			int border = 4;
			for (int y = 0; y < size; y++) {
				for (int x = 0; x < size; x++) {
					if (qrcodegen_getModule(qrcode, x, y)) {
						int run = 1;
						while (x + run < size && qrcodegen_getModule(qrcode, x + run, y))
							run++;
						int w = lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "M%d,%dh%dv1h-%dz ", x + border, y + border, run, run);
						if (w > 0 && (size_t)w < lws_ptr_diff_size_t(end, p))
							p += w;
						x += run - 1;
					}
				}
			}

			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "\" fill=\"#000000\"/></svg></div>"
				"<p style='font-family:monospace;letter-spacing:2px;'>%s</p>"
				"<p><a href='/' style='color:#a855f7;'>Proceed to Login</a></p></body></html>", totp);

			lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_FINAL);
			free(buf);
			return lws_http_transaction_completed(wsi);
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
				return 0;
			}
		}
		break;

	case LWS_CALLBACK_HTTP_BODY:
		if (pss->spa) {
			if (lws_spa_process(pss->spa, in, (int)len))
				return -1;
			return 0;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!pss->spa) {
			lwsl_err("%s: LWS_CALLBACK_HTTP_BODY_COMPLETION called but pss->spa is NULL\n", __func__);
			break;
		}
		lws_spa_finalize(pss->spa);

		lwsl_user("%s: HTTP_BODY_COMPLETION for '%s'\n", __func__, pss->requesting_url);

		if (strstr(pss->requesting_url, "login"))
			return lws_auth_api_login(wsi, vhd, pss);
		else if (strstr(pss->requesting_url, "register"))
			return lws_auth_api_register(wsi, vhd, pss);

		lwsl_err("%s: Unknown requesting URL '%s'\n", __func__, pss->requesting_url);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (pss->result_len > 0) {
			uint8_t buf[2048 + LWS_PRE];
			uint8_t *start = &buf[LWS_PRE], *p = start,
				*end = &buf[sizeof(buf) - 1];

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"application/json", (unsigned int)pss->result_len,
					&p, end))
				return lws_http_transaction_completed(wsi);
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return lws_http_transaction_completed(wsi);
			lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
			lws_write(wsi, (uint8_t *)pss->result, (unsigned int)pss->result_len, LWS_WRITE_HTTP_FINAL);
			pss->result_len = 0;
			return lws_http_transaction_completed(wsi);
		}
		break;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && pss->spa)
			lws_spa_destroy(pss->spa);
		break;

        default:
		break;
	}

	return 0;
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
		"lws_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif
