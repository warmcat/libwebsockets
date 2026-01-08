/*
 * lws-minimal-http-server-jwt
 *
 * Copyright (C) 2025 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal http server that handles JWT-based authentication.
 * It uses an SQLite3 database for user credentials and a JWK file for signing.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sqlite3.h>

#define LOGIN_COOKIE_NAME "minimal_jwt"

/*
 * We will create a "users" table in a local sqlite3 file
 */
static const char * const sql_create_users =
"CREATE TABLE IF NOT EXISTS users ("
" id INTEGER PRIMARY KEY AUTOINCREMENT,"
" username TEXT NOT NULL UNIQUE,"
" password TEXT NOT NULL"
");";

static const char * const sql_init_admin =
"INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password');";

/*
 * Per-vhost private data
 */
struct vhd {
	struct lws_context	*context;
	struct lws_vhost	*vhost;

	sqlite3			*pdb;
	const char		*sqlite3_path;

	/* JWT configuration */
	const char		*jwt_issuer;
	const char		*jwt_audience;
	char			jwt_auth_alg[16];
	struct lws_jwk		jwt_jwk_auth;
};

/*
 * Per-session private data
 */
struct pss {
	struct vhd		*vhd;
	struct lws_spa		*spa;

	char			authorized;
	char			auth_user[32];
	uint64_t		expiry_unix_time;

	unsigned int		login_form:1;
	unsigned int		spa_failed:1;
};

static int interrupted;

/*
 * POST form parameter names
 */
static const char * const param_names[] = {
	"username",
	"password",
	"success_redir",
};

enum enum_param_names {
	EPN_USERNAME,
	EPN_PASSWORD,
	EPN_SUCCESS_REDIR,
};

/*
 * Helper to check DB for credentials
 */
static int
check_credentials(struct vhd *vhd, const char *username, const char *password)
{
	sqlite3_stmt *stmt;
	int rc;
	int valid = 0;

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT 1 FROM users WHERE username = ? AND password = ?", -1, &stmt, NULL) != SQLITE_OK) {
		lwsl_err("%s: prepare failed: %s\n", __func__, sqlite3_errmsg(vhd->pdb));
		return 0;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW)
		valid = 1;

	sqlite3_finalize(stmt);
	return valid;
}

static int
file_upload_cb(void *data, const char *name, const char *filename,
		char *buf, int len, enum lws_spa_fileupload_states state)
{
	return 0;
}

static int
callback_jwt(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_get_protocol(wsi));
	struct pss *pss = (struct pss *)user;
	struct lws_jwt_sign_set_cookie ck;
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];
	size_t cml;
	int n;
	const char *cp;

	switch (reason) {
		case LWS_CALLBACK_PROTOCOL_INIT:
			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					lws_get_protocol(wsi),
					sizeof(struct vhd));
			if (!vhd)
				return -1;

			vhd->context = lws_get_context(wsi);
			vhd->vhost = lws_get_vhost(wsi);

			/* Get configuration from PVOs */
			if (lws_pvo_get_str(in, "database", &vhd->sqlite3_path)) {
				lwsl_err("%s: database pvo required\n", __func__);
				return -1;
			}

			/* Open DB */
			if (sqlite3_open(vhd->sqlite3_path, &vhd->pdb) != SQLITE_OK) {
				lwsl_err("%s: Unable to open db %s: %s\n",
						__func__, vhd->sqlite3_path, sqlite3_errmsg(vhd->pdb));
				return -1;
			}

			/* Initialize DB */
			char *err_msg = NULL;
			if (sqlite3_exec(vhd->pdb, sql_create_users, NULL, NULL, &err_msg) != SQLITE_OK) {
				lwsl_err("%s: DB init failed: %s\n", __func__, err_msg);
				sqlite3_free(err_msg);
				return -1;
			}
			if (sqlite3_exec(vhd->pdb, sql_init_admin, NULL, NULL, &err_msg) != SQLITE_OK) {
				lwsl_err("%s: DB init admin failed: %s\n", __func__, err_msg);
				sqlite3_free(err_msg);
				return -1;
			}

			/* JWT config */
			if (lws_pvo_get_str(in, "jwt-iss", &vhd->jwt_issuer)) return -1;
			if (lws_pvo_get_str(in, "jwt-aud", &vhd->jwt_audience)) return -1;
			if (lws_pvo_get_str(in, "jwt-auth-alg", &cp)) return -1;
			lws_strncpy(vhd->jwt_auth_alg, cp, sizeof(vhd->jwt_auth_alg));

			if (lws_pvo_get_str(in, "jwt-auth-jwk-path", &cp)) return -1;

			/* Load JWK */
			{
				int fd = open(cp, LWS_O_RDONLY);
				if (fd < 0) {
					lwsl_err("Cannot open JWK %s\n", cp);
					return -1;
				}
				int r = (int)read(fd, buf, sizeof(buf));
				close(fd);
				if (r < 0 || lws_jwk_import(&vhd->jwt_jwk_auth, NULL, NULL, (const char *)buf, (size_t)r)) {
					lwsl_err("Failed to parse JWK\n");
					return -1;
				}
			}

			lwsl_user("JWT Auth init complete. DB: %s\n", vhd->sqlite3_path);
			break;

		case LWS_CALLBACK_PROTOCOL_DESTROY:
			if (vhd) {
				if (vhd->pdb) sqlite3_close(vhd->pdb);
				lws_jwk_destroy(&vhd->jwt_jwk_auth);
			}
			break;

		case LWS_CALLBACK_HTTP:
			if (!vhd)
				return -1;

			pss->authorized = 0;

			/* 
			 * Check for JWT cookie 
			 */
			memset(&ck, 0, sizeof(ck));
			ck.jwk		= &vhd->jwt_jwk_auth;
			ck.alg		= vhd->jwt_auth_alg;
			ck.iss		= vhd->jwt_issuer;
			ck.aud		= vhd->jwt_audience;
			ck.cookie_name	= LOGIN_COOKIE_NAME;

			cml = sizeof(buf);

			/* Validate JWT */
			if (!lws_jwt_get_http_cookie_validate_jwt(wsi, &ck, (char *)buf, &cml)) {
				lwsl_notice("%s: cookie validate returned OK, %.*s\n", __func__, (int)(ck.extra_json ? ck.extra_json_len : 0), ck.extra_json);
				if (ck.extra_json &&
				    !lws_json_simple_strcmp(ck.extra_json, ck.extra_json_len, "\"authorized\":", "1")) {
					pss->authorized = 1;
					pss->expiry_unix_time = ck.expiry_unix_time;
					lws_strncpy(pss->auth_user, ck.sub, sizeof(pss->auth_user));
					lwsl_notice("Authorized user: %s\n", pss->auth_user);
				}
			}

			/* Check URL path */
			const char *url_path = (const char *)in;

			puts(url_path);

			if (!strcmp(url_path, "/login")) {
				pss->login_form = 1;
				lwsl_notice("%s: return 0 on /login\n", __func__);
				return 0;
			}

			if (!strcmp(url_path, "/logout")) {
				/* Clear cookie and redirect */
				char cookie_clr[256];
				n = lws_snprintf(cookie_clr, sizeof(cookie_clr),
						"%s=deleted; HttpOnly; SameSite=Strict; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", LOGIN_COOKIE_NAME);

				if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, &p, end)) return 1;
				if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE, 
							(unsigned char *)cookie_clr, n, &p, end)) return 1;

				const char *redir = "/";
				/* Get redirect from form if present, but for now simple */
				if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, 
							(unsigned char *)redir, (int)strlen(redir), &p, end)) return 1;

				if (lws_finalize_write_http_header(wsi, start, &p, end)) return 1;

				return 0;
			}

			if (!strcmp(url_path, "/api/secret")) {
				if (!pss->authorized) {
					lwsl_notice("%s: HTTP: /api/secret when not authorized\n", __func__);
					if (lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL))
						return -1;
					break;
				}

				lwsl_notice("%s: returning the secret\n", __func__);

				/* Return secret JSON */
				p = start;
				n = lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), 
						"{\"secret\": \"The eagle flies at midnight\", \"user\": \"%s\", \"expiry\": %llu}", 
						pss->auth_user, (unsigned long long)pss->expiry_unix_time);
				p += n;

				if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
					return 1;
				if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, 
							(unsigned char *)"application/json", 16, &p, end))
					return 1;
				if (lws_add_http_header_content_length(wsi, (lws_filepos_t)n, &p, end))
					return 1;
				if (lws_finalize_write_http_header(wsi, start, &p, end))
					return 1;

				lws_write(wsi, start, (size_t)n, LWS_WRITE_HTTP_FINAL);
				return 0;
			}

			break; /* Continue to serve static files */

		case LWS_CALLBACK_HTTP_BODY:
			lwsl_notice("%s: HTTP_BODY: login_form %d\n", __func__, pss->login_form);
			if (!pss->login_form)
				break;

			if (!pss->spa) {
				pss->spa = lws_spa_create(wsi, param_names,
							LWS_ARRAY_SIZE(param_names),
							1024, file_upload_cb, pss);
				if (!pss->spa)
					return -1;
			}

			lwsl_hexdump_notice(in, len);

			if (lws_spa_process(pss->spa, in, (int)len))
				pss->spa_failed = 1;

			break;

		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
			lwsl_notice("%s: HTTP_BODY_COMPLETION: login_form %d\n", __func__, pss->login_form);

			if (pss->login_form) {
				const char *user, *pass, *redir;

				if (pss->spa)
					lws_spa_finalize(pss->spa);

				if (pss->spa_failed) {
					lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
					goto spa_cleanup;
				}

				user = lws_spa_get_string(pss->spa, EPN_USERNAME);
				pass = lws_spa_get_string(pss->spa, EPN_PASSWORD);
				redir = lws_spa_get_string(pss->spa, EPN_SUCCESS_REDIR);
				if (!redir)
					redir = "/";

				if (user && pass && check_credentials(vhd, user, pass)) {
					/* Login Success - Generate JWT */
					memset(&ck, 0, sizeof(ck));
					lws_strncpy(ck.sub, user, sizeof(ck.sub));
					ck.jwk			= &vhd->jwt_jwk_auth;
					ck.alg			= vhd->jwt_auth_alg;
					ck.iss			= vhd->jwt_issuer;
					ck.aud			= vhd->jwt_audience;
					ck.cookie_name		= LOGIN_COOKIE_NAME;
					ck.extra_json		= "\"authorized\": 1";
					ck.expiry_unix_time	= 3600; /* 1 hour */

					if (lws_add_http_header_status(wsi, 301, &p, end)) return 1;

					if (lws_jwt_sign_token_set_http_cookie(wsi, &ck, &p, end)) {
						lwsl_err("JWT sign failed\n");
						if (lws_return_http_status(wsi,
							HTTP_STATUS_INTERNAL_SERVER_ERROR,
							"JWT Signing Failure"))
							return 1;
						return 0;
					}

					if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
								(unsigned char *)redir, (int)strlen(redir), &p, end))
						return 1;

					if (lws_finalize_write_http_header(wsi, start, &p, end))
						return 1;

					lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_FINAL);
				} else {
					/* Login Failed */
					lwsl_notice("Login failed for %s\n", user ? user : "null");
					lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
				}

spa_cleanup:
				if (pss->spa) {
					lws_spa_destroy(pss->spa);
					pss->spa = NULL;
				}
				return 0;
			}
			break;

		default:
			break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{ "http", callback_jwt, sizeof(struct pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Mount definitions
 */
static const struct lws_http_mount mount = {
	.mountpoint			= "/",
	.origin				= "./mount-origin",
	.def				= "index.html",
	.origin_protocol		= LWSMPRO_FILE,
	.mountpoint_len			= 1,
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct lws_protocol_vhost_options pvo_jwk, pvo_alg, pvo_aud, pvo_iss, pvo_db, pvo_proto;
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;

	signal(SIGINT, sigint_handler);
	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS minimal http server JWT | visit http://localhost:7681\n");

	info.port = 7681;
	info.mounts = &mount;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	/*
	 * Prepare PVOs (Per-Vhost Options)
	 * These act like configuration values passed to the protocol init
	 */

	/* Linked list of options */
	pvo_jwk.next = NULL;
	pvo_jwk.name = "jwt-auth-jwk-path";
	pvo_jwk.value = "./private.jwk";

	pvo_alg.next = &pvo_jwk;
	pvo_alg.name = "jwt-auth-alg";
	pvo_alg.value = "HS512";

	pvo_aud.next = &pvo_alg;
	pvo_aud.name = "jwt-aud";
	pvo_aud.value = "minimal-jwt-example";

	pvo_iss.next = &pvo_aud;
	pvo_iss.name = "jwt-iss";
	pvo_iss.value = "minimal-jwt-server";

	pvo_db.next = &pvo_iss;
	pvo_db.name = "database";
	pvo_db.value = "./users.sqlite3";

	/* Attach options to the "http" protocol */
	pvo_proto.next = NULL;
	pvo_proto.name = "http";
	pvo_proto.value = ""; /* protocol name matches this */
	pvo_proto.options = &pvo_db;

	info.pvo = &pvo_proto;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
