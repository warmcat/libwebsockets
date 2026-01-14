/*
 * ws protocol handler plugin for "lws captcha ratelimit"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * These test plugins are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * This plugin serves as an example of how to implement a captcha diversion.
 * Please refer to READMEs/README-captcha.md for configuration details.
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
#include <stdlib.h>

#if !defined (LWS_PLUGIN_STATIC)
extern const struct lws_protocols captcha_ratelimit_protocols[];
#endif

struct pss_captcha {
	lws_sorted_usec_list_t sul;
	struct lws *wsi;
};

struct vhd_captcha {
	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws_jwk jwk;
	const char *cookie_name;
	const char *jwt_issuer;
	const char *jwt_audience;
	char jwt_alg[32];
	int jwt_expiry;
};

static void
ratelimit_cb(lws_sorted_usec_list_t *sul)
{
	struct pss_captcha *pss = lws_container_of(sul, struct pss_captcha, sul);
	struct vhd_captcha *vhd = (struct vhd_captcha *)
			lws_protocol_vh_priv_get(lws_get_vhost(pss->wsi),
						 lws_get_protocol(pss->wsi));
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE,
	     *end = buf + sizeof(buf) - 1;
	struct lws_jwt_sign_set_cookie ck;
	char ip[64], uri[256];
	int n;

	/*
	 * We waited 5s. Now we issue the JWT cookie and redirect.
	 */

	lws_get_peer_simple(pss->wsi, ip, sizeof(ip));

	memset(&ck, 0, sizeof(ck));
	ck.alg = vhd->jwt_alg;
	ck.iss = vhd->jwt_issuer;
	ck.aud = vhd->jwt_audience;
	ck.jwk = &vhd->jwk;
	lws_strncpy(ck.sub, ip, sizeof(ck.sub));
	ck.expiry_unix_time = (unsigned long)lws_now_secs() + (unsigned long)vhd->jwt_expiry;
	ck.cookie_name = vhd->cookie_name;

	if (lws_jwt_sign_token_set_http_cookie(pss->wsi, &ck, (uint8_t **)&p, (uint8_t *)end)) {
		lwsl_err("%s: failed to sign JWT\n", __func__);
		return;
	}

	if (lws_add_http_header_status(pss->wsi, HTTP_STATUS_FOUND, (unsigned char **)&p, (unsigned char *)end))
		return;

	/* Redirect back to the same URL (reloading it) */
	n = lws_hdr_copy(pss->wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);
	if (n > 0) {
		if (lws_add_http_header_by_token(pss->wsi,
						 WSI_TOKEN_HTTP_LOCATION,
						 (unsigned char *)uri,
						 n, (unsigned char **)&p, (unsigned char *)end))
			return;
	}

	if (lws_finalize_http_header(pss->wsi, (unsigned char **)&p, (unsigned char *)end))
		return;

	lws_write(pss->wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE),
		  LWS_WRITE_HTTP_HEADERS);

	if (lws_http_transaction_completed(pss->wsi))
		return;
}

static int
callback_captcha_ratelimit(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	struct pss_captcha *pss = (struct pss_captcha *)user;
	struct vhd_captcha *vhd = (struct vhd_captcha *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	struct lws_jwt_sign_set_cookie ck;
	char buf[LWS_PRE + 2048], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
	const char *cp;
	char ip[64];
	size_t s;
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct vhd_captcha));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->cookie_name = "lws_captcha_jwt";
		vhd->jwt_expiry = 600; /* 10 mins */
		vhd->jwt_issuer = "lws";
		vhd->jwt_audience = "lws";
		lws_strncpy(vhd->jwt_alg, "HS256", sizeof(vhd->jwt_alg));

		if (lws_pvo_get_str(in, "jwt-issuer", &vhd->jwt_issuer))
			lwsl_info("Using default jwt-issuer\n");
		if (lws_pvo_get_str(in, "jwt-audience", &vhd->jwt_audience))
			lwsl_info("Using default jwt-audience\n");
		if (lws_pvo_get_str(in, "jwt-alg", &cp))
			lws_strncpy(vhd->jwt_alg, cp, sizeof(vhd->jwt_alg));

		s = 600;
		if (!lws_pvo_get_str(in, "jwt-expiry", &cp))
			vhd->jwt_expiry = atoi(cp);

		if (!lws_pvo_get_str(in, "cookie-name", &cp))
			vhd->cookie_name = cp;

		/* We expect a JWK for signing to be passed in pvo "jwt-jwk" */
		/* For simplicity, we load it from a file path if provided */

		if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
			/* treat as a file path */
			if (lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
				lwsl_err("%s: failed to load JWK from %s\n", __func__, cp);
				return -1;
			}
		} else {
			lwsl_err("%s: jwt-jwk PVO required\n", __func__);
			return -1;
		}

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_jwk_destroy(&vhd->jwk);
		break;

	case LWS_CALLBACK_HTTP_CAPTCHA_CHECK:
#if !defined (LWS_PLUGIN_STATIC)
		/*
		 * When called from the diversion logic, wsi->protocol is the
		 * original protocol (e.g., http), not this one. We must use
		 * this protocol's definition to find our VHD.
		 */
		vhd = (struct vhd_captcha *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 &captcha_ratelimit_protocols[0]);
#endif
		if (!vhd)
			return 1;

		/*
		 * Check if the user has a valid cookie.
		 * Return 0 if valid, 1 if not.
		 */
		memset(&ck, 0, sizeof(ck));
		ck.alg = vhd->jwt_alg;
		ck.iss = vhd->jwt_issuer;
		ck.aud = vhd->jwt_audience;
		ck.jwk = &vhd->jwk;
		ck.cookie_name = vhd->cookie_name;

		s = sizeof(buf);
		/* reuse buf for validation result */
		if (lws_jwt_get_http_cookie_validate_jwt(wsi, &ck, buf, &s)) {
			lwsl_info("%s: cookie missing or invalid\n", __func__);
			return 1;
		}

		/* Check IP match */
		lws_get_peer_simple(wsi, ip, sizeof(ip));
		if (strcmp(ck.sub, ip)) {
			lwsl_notice("%s: IP mismatch %s vs %s\n", __func__, ck.sub, ip);
			return 1;
		}

		/* Valid */
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lws_sul_cancel(&pss->sul);
		break;

	case LWS_CALLBACK_HTTP:
		{
			char uri[256];
			int len = lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);

			if (len > 0) {
				if (lws_strstr_wildcard(uri, sizeof(uri), "captcha.css", 0)) {
					lws_serve_http_file(wsi, "plugins/captcha-assets/captcha.css", "text/css", NULL, 0);
					return 1;
				}
				if (lws_strstr_wildcard(uri, sizeof(uri), "captcha.js", 0)) {
					lws_serve_http_file(wsi, "plugins/captcha-assets/captcha.js", "application/javascript", NULL, 0);
					return 1;
				}
			}
		}

		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
			/*
			 * User clicked the button.
			 * Wait 5 seconds, then issue cookie.
			 */
			pss->wsi = wsi;
			lws_sul_schedule(vhd->context, 0, &pss->sul, ratelimit_cb, 5 * LWS_US_PER_SEC);
			return 0;
		}

		/* Serve the captcha page */
		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)"text/html", 9, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		n = lws_snprintf(buf + LWS_PRE + 1024, sizeof(buf) - LWS_PRE - 1024, /* buffer for body */
			"<html><head>"
			"<link rel=\"stylesheet\" href=\"captcha.css\">"
			"<script src=\"captcha.js\"></script>"
			"</head><body>"
			"<div class=\"captcha-modal\">"
			"<h1>Are you human?</h1>"
			"<form method=\"POST\" action=\"\" onsubmit=\"return startCaptcha()\">"
			"<input type=\"submit\" id=\"captcha-btn\" value=\"I am human (wait 5s)\">"
			"<div id=\"countdown\"></div>"
			"</form>"
			"</div>"
			"</body></html>");

		if (lws_add_http_header_content_length(wsi, (lws_filepos_t)n, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		/* Write headers */
		if (lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
			return 1;

		/* Write body */
		if (lws_write(wsi, (unsigned char *)buf + LWS_PRE + 1024, (size_t)n, LWS_WRITE_HTTP_FINAL) < 0)
			return 1;

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_CAPTCHA_RATELIMIT \
	{ \
		"lws_captcha_ratelimit", \
		callback_captcha_ratelimit, \
		sizeof(struct pss_captcha), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols captcha_ratelimit_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_CAPTCHA_RATELIMIT
};

LWS_VISIBLE const lws_plugin_protocol_t lws_captcha_ratelimit = {
	.hdr = {
		"lws captcha ratelimit",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = captcha_ratelimit_protocols,
	.count_protocols = LWS_ARRAY_SIZE(captcha_ratelimit_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
