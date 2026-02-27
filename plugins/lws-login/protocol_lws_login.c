/*
 * ws protocol handler plugin for "lws login"
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This plugin provides SQLite3-based authentication as a mount-based interceptor.
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

struct lws_login_user {
	char username[32];
	char password[64];
};

static const lws_struct_map_t lsm_user[] = {
	LSM_CARRAY(struct lws_login_user, username, "username"),
	LSM_CARRAY(struct lws_login_user, password, "password"),
};

static const lws_struct_map_t lsm_schema[] = {
	LSM_SCHEMA(struct lws_login_user, NULL, lsm_user, "users"),
};

struct vhd_login {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const char *db_path;
	const char *asset_dir;
	sqlite3 *pdb;

	/* Captcha/JWT config inherited or explicitly set */
	const char *jwt_issuer;
	const char *jwt_audience;
	const char *cookie_name;
	struct lws_jwk jwk;
	char jwt_alg[32];
	int jwt_expiry;
};

struct pss_login {
	struct lws_spa *spa;
	char username[32];
	char password[64];
	uint8_t login_attempted:1;
};

static const char * const param_names[] = {
	"username",
	"password",
};

enum enum_param_names {
	EPN_USERNAME,
	EPN_PASSWORD,
};

static int
lws_login_verify_credentials(struct vhd_login *vhd, const char *user, const char *pass)
{
	lws_dll2_owner_t owner;
	struct lws_login_user *u;
	char filter[128];
	struct lwsac *ac = NULL;
	int n = -1;

	lws_dll2_owner_clear(&owner);
	lws_snprintf(filter, sizeof(filter), "username = '%s'", user);

	if (lws_struct_sq3_deserialize(vhd->pdb, filter, NULL, lsm_schema, &owner, &ac, 0, 1)) {
		lwsl_err("%s: db query failed\n", __func__);
		return -1;
	}

	u = (struct lws_login_user *)lws_dll2_get_head(&owner);
	if (u && !strcmp(u->password, pass))
		n = 0;

	lwsac_free(&ac);

	return n;
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
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_login));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->jwt_expiry = 3600;
		vhd->cookie_name = "lws_login_jwt";
		vhd->jwt_issuer = "lws";
		vhd->jwt_audience = "lws";
		lws_strncpy(vhd->jwt_alg, "HS256", sizeof(vhd->jwt_alg));

		if (lws_pvo_get_str(in, "db-path", &vhd->db_path)) {
			lwsl_vhost_err(lws_get_vhost(wsi), "%s: db-path PVO required\n", __func__);
			return -1;
		}

		if (lws_struct_sq3_open(vhd->context, vhd->db_path, 1, &vhd->pdb)) {
			lwsl_err("%s: failed to open db %s\n", __func__, vhd->db_path);
			return -1;
		}

		if (lws_struct_sq3_create_table(vhd->pdb, lsm_schema)) {
			lwsl_err("%s: failed to create table\n", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "asset-dir", &vhd->asset_dir))
			if (!strncmp(vhd->asset_dir, "file://", 7))
				vhd->asset_dir += 7;

		lws_pvo_get_str(in, "jwt-issuer", &vhd->jwt_issuer);
		lws_pvo_get_str(in, "jwt-audience", &vhd->jwt_audience);
		lws_pvo_get_str(in, "cookie-name", &vhd->cookie_name);
		if (!lws_pvo_get_str(in, "jwt-alg", &cp))
			lws_strncpy(vhd->jwt_alg, cp, sizeof(vhd->jwt_alg));
		if (!lws_pvo_get_str(in, "jwt-expiry", &cp))
			vhd->jwt_expiry = atoi(cp);

		if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
			if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
				if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
					lwsl_err("%s: failed to load/import JWK\n", __func__);
					return -1;
				}
			}
		} else {
			lwsl_vhost_err(lws_get_vhost(wsi), "%s: jwt-jwk PVO required\n", __func__);
			return -1;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_struct_sq3_close(&vhd->pdb);
			lws_jwk_destroy(&vhd->jwk);
		}
		break;

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
		return lws_interceptor_check(wsi, lws_get_protocol(wsi));

	case LWS_CALLBACK_HTTP:
		/* Serves the login page assets */
		{
			char path[512];
			const char *uri = (const char *)in;
			const char *ctype = "text/html";

			if (!uri[0] || !strcmp(uri, "/"))
				uri = "index.html";

			lws_snprintf(path, sizeof(path), "%s/%s",
				     vhd->asset_dir ? vhd->asset_dir : ".", uri);

			ctype = lws_get_mimetype(path, NULL);
			if (!ctype)
				ctype = "text/html";

			if (lws_serve_http_file(wsi, path, ctype, NULL, 0))
				return 1;
		}
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					LWS_ARRAY_SIZE(param_names), 1024,
					NULL, NULL);
			if (!pss->spa)
				return -1;
		}

		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lws_spa_finalize(pss->spa);
		lws_strncpy(pss->username, lws_spa_get_string(pss->spa, EPN_USERNAME), sizeof(pss->username));
		lws_strncpy(pss->password, lws_spa_get_string(pss->spa, EPN_PASSWORD), sizeof(pss->password));
		pss->login_attempted = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->login_attempted)
			break;

		if (!lws_login_verify_credentials(vhd, pss->username, pss->password)) {
			/* Success! Issue cookie and redirect back */
			/* We can't easily call lws_captcha_issue_cookie because it's vhd-specific
			 * and expects vhd_captcha. We'll have to manually do it or
			 * make it more generic. For now, let's assume we can use it if we
			 * fake the VHD or if we just implement the signing here.
			 */
			struct lws_jwt_sign_set_cookie ck;

			memset(&ck, 0, sizeof(ck));
			ck.alg = vhd->jwt_alg;
			ck.iss = vhd->jwt_issuer;
			ck.aud = vhd->jwt_audience;
			ck.jwk = &vhd->jwk;
			lws_strncpy(ck.sub, pss->username, sizeof(ck.sub));
			ck.cookie_name = vhd->cookie_name;
			ck.expiry_unix_time = (unsigned long)vhd->jwt_expiry;

			if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			/* Redirect to where we came from, or just / if unknown */
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)"/", 1, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			if (lws_jwt_sign_token_set_http_cookie(wsi, &ck, (uint8_t **)&p, (uint8_t *)end))
				return 1;

			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;

			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
			return lws_http_transaction_completed(wsi);
		} else {
			/* Failure - redirect back with error */
			if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)"/?error=Invalid+credentials", 27, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
			return lws_http_transaction_completed(wsi);
		}
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (pss->spa) {
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
		"lws login",
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
