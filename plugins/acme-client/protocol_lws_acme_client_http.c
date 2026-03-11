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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
#include "lws-acme-client.h"

struct vhd_acme_http {
	const struct lws_protocols *core_protocol;
	const struct lws_acme_core_ops *core_ops;
	struct per_vhost_data__lws_acme_client *core_vhd;

	struct lws_context *context;
	struct lws_vhost *temp_vhost;
	struct lws_context_creation_info ci;
	struct lws_http_mount mount;
	char mountpoint[256];
	char key_auth[1024];

	struct lws_vhost *vhost;
};

static int
callback_chall_http01(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len)
{
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	struct vhd_acme_http *ah = lws_vhost_user(vhost);
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_wsi_notice(wsi, "CA connection received, key_auth %s",
			    ah->key_auth);

		if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end)) {
			lwsl_wsi_warn(wsi, "add status failed");
			return -1;
		}

		if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(unsigned char *)"text/plain", 10,
					&p, end)) {
			lwsl_wsi_warn(wsi, "add content_type failed");
			return -1;
		}

		n = (int)strlen(ah->key_auth);
		if (lws_add_http_header_content_length(wsi, (lws_filepos_t)n, &p, end)) {
			lwsl_wsi_warn(wsi, "add content_length failed");
			return -1;
		}

		if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
					(unsigned char *)"attachment", 10,
					&p, end)) {
			lwsl_wsi_warn(wsi, "add content_dispo failed");
			return -1;
		}

		if (lws_finalize_write_http_header(wsi, start, &p, end)) {
			lwsl_wsi_warn(wsi, "finalize http header failed");
			return -1;
		}

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "%s", ah->key_auth);
		if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_HTTP_FINAL) != lws_ptr_diff(p, start)) {
			lwsl_wsi_err(wsi, "_write content failed");
			return -1;
		}

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols chall_http01_protocols[] = {
	{ "http", callback_chall_http01, 0, 0, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static int
challenge_start_http(struct lws_vhost *vh, void *priv, const char *token,
		     const char *key_auth, const char *domain)
{
	struct vhd_acme_http *ah = (struct vhd_acme_http *)priv;

	lws_snprintf(ah->mountpoint, sizeof(ah->mountpoint),
			"/.well-known/acme-challenge/%s", token);
	lws_strncpy(ah->key_auth, key_auth, sizeof(ah->key_auth));

	memset(&ah->mount, 0, sizeof(ah->mount));
	ah->mount.protocol = "http";
	ah->mount.mountpoint = ah->mountpoint;
	ah->mount.mountpoint_len = (unsigned char)strlen(ah->mountpoint);
	ah->mount.origin_protocol = LWSMPRO_CALLBACK;

	memset(&ah->ci, 0, sizeof(ah->ci));
	ah->ci.mounts = &ah->mount;
	ah->ci.port = 80;
	ah->ci.protocols = chall_http01_protocols;
	ah->ci.user = ah;
	ah->ci.vhost_name = "acme-http01-temp";

	ah->temp_vhost = lws_create_vhost(ah->context, &ah->ci);
	if (!ah->temp_vhost) {
		lwsl_vhost_err(vh, "failed to create http-01 challenge vhost");
		return 1;
	}

	/* Signal the core that we're ready */
	if (ah->core_ops && ah->core_ops->notify_challenge_ready)
		ah->core_ops->notify_challenge_ready(ah->core_vhd);

	return 0;
}

static void
challenge_cleanup_http(struct lws_vhost *vh, void *priv)
{
	struct vhd_acme_http *ah = (struct vhd_acme_http *)priv;

	if (ah->temp_vhost) {
		lws_vhost_destroy(ah->temp_vhost);
		ah->temp_vhost = NULL;
	}
}

static const struct lws_acme_challenge_ops acme_http_ops = {
	.challenge_start = challenge_start_http,
	.challenge_poll = NULL,
	.challenge_cleanup = challenge_cleanup_http,
};

static int
callback_lws_acme_client_http(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len)
{
	struct vhd_acme_http *ah =
			(struct vhd_acme_http *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	struct lws_vhost *vh = lws_get_vhost(wsi);

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		ah = lws_protocol_vh_priv_zalloc(vh, lws_get_protocol(wsi),
						 sizeof(struct vhd_acme_http));
		if (!ah)
			return -1;

		ah->context = lws_get_context(wsi);
		ah->vhost = vh;
		ah->core_protocol = lws_vhost_name_to_protocol(vh, "lws-acme-client-core");
		if (!ah->core_protocol || !ah->core_protocol->user) {
			lwsl_vhost_err(vh, "lws-acme-client-core protocol not found or no ops exported");
			return -1;
		}

		ah->core_ops = (const struct lws_acme_core_ops *)ah->core_protocol->user;

		if (ah->core_ops && ah->core_ops->init_vhost) {
			ah->core_vhd = ah->core_ops->init_vhost(lws_get_context(wsi), vh,
					(const struct lws_protocol_vhost_options *)in,
					&acme_http_ops, ah);
			if (!ah->core_vhd) {
				lwsl_vhost_err(vh, "core init failed");
				return -1;
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (ah && ah->core_ops && ah->core_ops->destroy_vhost) {
			ah->core_ops->destroy_vhost(ah->core_vhd);
		}
		challenge_cleanup_http(vh, ah);
		break;

	case LWS_CALLBACK_VHOST_CERT_AGING:
		if (ah && ah->core_ops && ah->core_ops->cert_aging) {
			return ah->core_ops->cert_aging(ah->core_vhd,
				(const struct lws_acme_cert_aging_args *)in);
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT_HTTP \
	{ \
		"lws-acme-client-http", \
		callback_lws_acme_client_http, \
		sizeof(struct vhd_acme_http), \
		0, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_acme_client_http_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT_HTTP
};

LWS_VISIBLE const lws_plugin_protocol_t lws_acme_client_http = {
	.hdr = {
		.name = "acme client http",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_acme_client_http_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_acme_client_http_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
