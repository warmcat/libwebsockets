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

struct vhd_acme_dns {
	const struct lws_protocols *core_protocol;
	const struct lws_acme_core_ops *core_ops;
	struct per_vhost_data__lws_acme_client *core_vhd;

	struct lws_vhost *vhost;
	const char *update_script;
};

static int
challenge_start_dns(struct lws_vhost *vh, void *priv, const char *token,
		     const char *key_auth, const char *domain)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)priv;
	char cmd[512];
	int n;

	if (!ad->update_script) {
		lwsl_vhost_err(vh, "dns-01 challenge requires 'update-script' pvo");
		return 1;
	}

	/* Use a custom script to inject the DNS record. */
	/* We pass domain and key_auth so the script can set _acme-challenge.<domain> IN TXT "<key_auth>" */
	
	lws_snprintf(cmd, sizeof(cmd), "%s \"%s\" \"%s\"", ad->update_script, domain, key_auth);
	
	lwsl_vhost_info(vh, "Executing dns-01 solver script: %s", cmd);
	
	n = system(cmd);
	if (n) {
		lwsl_vhost_err(vh, "dns-01 script failed: %d", n);
		return 1;
	}

	/* Signal the core that we're ready */
	if (ad->core_ops && ad->core_ops->notify_challenge_ready)
		ad->core_ops->notify_challenge_ready(ad->core_vhd);

	return 0;
}

static void
challenge_cleanup_dns(struct lws_vhost *vh, void *priv)
{
	/* The DNS record can be cleaned up later via cron or by passing a "cleanup" arg to the script */
}

static const struct lws_acme_challenge_ops acme_dns_ops = {
	.challenge_start = challenge_start_dns,
	.challenge_poll = NULL,
	.challenge_cleanup = challenge_cleanup_dns,
};

static int
callback_lws_acme_client_dns(struct lws *wsi, enum lws_callback_reasons reason,
			      void *user, void *in, size_t len)
{
	struct vhd_acme_dns *ad =
			(struct vhd_acme_dns *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options *pvo =
			(const struct lws_protocol_vhost_options *)in;
	struct lws_vhost *vh = lws_get_vhost(wsi);

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		ad = lws_protocol_vh_priv_zalloc(vh, lws_get_protocol(wsi),
						 sizeof(struct vhd_acme_dns));
		if (!ad)
			return -1;

		ad->vhost = vh;
		
		/* Grab the update script configuration from pvos */
		while (pvo) {
			if (!strcmp(pvo->name, "update-script"))
				ad->update_script = pvo->value;
			pvo = pvo->next;
		}

		ad->core_protocol = lws_vhost_name_to_protocol(vh, "lws-acme-client-core");
		if (!ad->core_protocol || !ad->core_protocol->user) {
			lwsl_vhost_err(vh, "lws-acme-client-core protocol not found or no ops exported");
			return -1;
		}

		ad->core_ops = (const struct lws_acme_core_ops *)ad->core_protocol->user;

		if (ad->core_ops && ad->core_ops->init_vhost) {
			ad->core_vhd = ad->core_ops->init_vhost(lws_get_context(wsi), vh,
					(const struct lws_protocol_vhost_options *)in,
					&acme_dns_ops, ad);
			if (!ad->core_vhd) {
				lwsl_vhost_err(vh, "core init failed");
				return -1;
			}
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (ad && ad->core_ops && ad->core_ops->destroy_vhost) {
			ad->core_ops->destroy_vhost(ad->core_vhd);
		}
		challenge_cleanup_dns(vh, ad);
		break;

	case LWS_CALLBACK_VHOST_CERT_AGING:
		if (ad && ad->core_ops && ad->core_ops->cert_aging) {
			return ad->core_ops->cert_aging(ad->core_vhd,
				(const struct lws_acme_cert_aging_args *)in);
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT_DNS \
	{ \
		"lws-acme-client-dns", \
		callback_lws_acme_client_dns, \
		sizeof(struct vhd_acme_dns), \
		0, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_acme_client_dns_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT_DNS
};

LWS_VISIBLE const lws_plugin_protocol_t lws_acme_client_dns = {
	.hdr = {
		.name = "acme client dns",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_acme_client_dns_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_acme_client_dns_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
