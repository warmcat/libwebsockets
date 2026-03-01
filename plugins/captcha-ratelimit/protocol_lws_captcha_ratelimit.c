/*
 * ws protocol handler plugin for "lws captcha ratelimit"
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This is the simplest possible captcha, which only needs the user
 * to click a button, which appears a fixed time after the page
 * opens and delays a fixed time subsequently.
 *
 * The captchas are controlled by pvo for the vhost, for this one
 * the example pvos look like
 *
 *    "lws_captcha_ratelimit": {
 *        "status": "ok",
 *        "jwt-jwk": 		  "{\"k\":\"...\",\"kty\":\"oct\"}",
 *        "jwt-issuer":           "lws-test",
 *        "jwt-audience":         "lws-test",
 *        "jwt-alg":              "HS256",
 *        "jwt-expiry":           600,
 *        "cookie-name":          "lws_captcha_jws",
 *        "asset-dir":            "file://_lws_ddir_/libwebsockets-test-server/captcha-ratelimit/captcha-assets",
 *        "pre-delay-ms":         5000,
 *        "post-delay-ms":        3000
 *    }
 *
 * The "jwt-jwk" member (truncated here) is a JWK you can create with
 *
 *    $ lws-crypto-jwk -t OCT
 *
 * You need to escape any quotes inside the key with a backslash.
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

static const struct lws_interceptor_ops ratelimit_ops = {
	.name = "ratelimit",
};

static int
callback_captcha_ratelimit(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	return lws_callback_interceptor(wsi, reason, user, in, len, &ratelimit_ops);
}

#define LWS_PLUGIN_PROTOCOL_LWS_CAPTCHA_RATELIMIT                                  \
{										   \
	"lws_captcha_ratelimit",                                                   \
	callback_captcha_ratelimit,                                                \
	1024, /* pss size */                                                       \
	1024,                                                                      \
	0,                                                                         \
	NULL,                                                                      \
	0									   \
}

#if !defined(LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols captcha_ratelimit_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_CAPTCHA_RATELIMIT};

LWS_VISIBLE const lws_plugin_protocol_t lws_captcha_ratelimit = {
	.hdr = {
		.name = "lws captcha ratelimit",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = captcha_ratelimit_protocols,
	.count_protocols = LWS_ARRAY_SIZE(captcha_ratelimit_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
