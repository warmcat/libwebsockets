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
#include <fcntl.h>

#include "lws-acme-client.h"
#include <errno.h>

struct vhd_acme_dns {
	const struct lws_protocols *core_protocol;
	const struct lws_acme_core_ops *core_ops;
	struct per_vhost_data__lws_acme_client *core_vhd;

	struct lws_context *context;
	struct lws_vhost *vhost;
	char *base_dir;
	char active_domain[256];
	lws_sorted_usec_list_t sul_delay;
};

static void
sul_dns_ready_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_acme_dns *ad = lws_container_of(sul, struct vhd_acme_dns, sul_delay);
	if (ad->core_ops && ad->core_ops->notify_challenge_ready && ad->core_vhd) {
		lwsl_vhost_info(ad->vhost, "dns-01 5s propagation complete, notifying Let's Encrypt");
		ad->core_ops->notify_challenge_ready(ad->core_vhd);
	}
}

static int
challenge_start_dns(struct lws_vhost *vh, void *priv, const char *token,
		     const char *key_auth, const char *domain)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)priv;
	char path[512], zone_path[512];
	int fd;
	size_t n;

	if (!ad->base_dir) {
		lwsl_vhost_err(vh, "dns-01 challenge requires 'base-dir' pvo");
		return 1;
	}

	lws_strncpy(ad->active_domain, domain, sizeof(ad->active_domain));

	lws_snprintf(path, sizeof(path), "%s/domains/%s/dns/%s.zone.acme", ad->base_dir, domain, domain);

	fd = open(path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (fd < 0) {
		lwsl_vhost_err(vh, "failed to create acme zone file %s", path);
		return 1;
	}

	uint8_t digest[32];
	struct lws_genhash_ctx hash_ctx;
	char b64[128];
	int b64_len;

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hash_ctx, (const uint8_t *)key_auth, strlen(key_auth)) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lwsl_vhost_err(vh, "failed to compute SHA-256 digest of key_auth");
		close(fd);
		return 1;
	}

	b64_len = lws_jws_base64_enc((const char *)digest, 32, b64, sizeof(b64));
	if (b64_len < 0) {
		lwsl_vhost_err(vh, "failed to base64url encode digest");
		close(fd);
		return 1;
	}

	char line[512];
	n = (size_t)lws_snprintf(line, sizeof(line),
		"_acme-challenge\t1\tIN\tTXT\t\"%s\"\n"
		"%s.\t1\tIN\tCAA\t0 issue \"letsencrypt.org\"\n", b64, domain);
	if (write(fd, line, n) != (ssize_t)n) {
		close(fd);
		lwsl_vhost_err(vh, "failed writing to acme zone file %s", path);
		return 1;
	}
	close(fd);

	/* Remove the signed zone file to force the monitor to resign with the acme TXT */
	lws_snprintf(zone_path, sizeof(zone_path), "%s/domains/%s/dns/%s.zone.signed", ad->base_dir, domain, domain);
	if (unlink(zone_path) < 0 && errno != ENOENT) {
		lwsl_user("%s: CRITICAL ERROR - unlink failed on %s! (errno %d)\n", __func__, zone_path, errno);
	} else {
		lwsl_user("%s: Successfully unlinked %s to force resign\n", __func__, zone_path);
	}

	/* Wake up the non-recursive inotify watcher reliably by creating and unlinking a file in the watched directory */
	char domain_dir[512];
	lws_snprintf(domain_dir, sizeof(domain_dir), "%s/domains/.acme_trigger_%s", ad->base_dir, domain);
	int trigger_fd = open(domain_dir, LWS_O_CREAT | LWS_O_WRONLY, 0600);
	if (trigger_fd >= 0) close(trigger_fd);
	unlink(domain_dir);

	lwsl_user("Created dns-01 local acme temp zone addon: %s, waiting 20s for DHT propagation...\n", path);
	lws_sul_schedule(ad->context, 0, &ad->sul_delay, sul_dns_ready_cb, 20 * LWS_US_PER_SEC);

	return 0;
}

static void
challenge_cleanup_dns(struct lws_vhost *vh, void *priv)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)priv;
	char path[512], zone_path[512];

	if (ad->base_dir && ad->active_domain[0]) {
		lws_snprintf(path, sizeof(path), "%s/domains/%s/dns/%s.zone.acme", ad->base_dir, ad->active_domain, ad->active_domain);
		unlink(path);

		/* Remove the signed zone file to force the monitor to resign without the acme TXT */
		lws_snprintf(zone_path, sizeof(zone_path), "%s/domains/%s/dns/%s.zone.signed", ad->base_dir, ad->active_domain, ad->active_domain);
		if (unlink(zone_path) < 0 && errno != ENOENT) {
			lwsl_user("%s: CRITICAL ERROR - cleanup unlink failed on %s! (errno %d)\n", __func__, zone_path, errno);
		} else {
			lwsl_user("%s: Successfully unlinked %s to force resign\n", __func__, zone_path);
		}

		/* Wake up the non-recursive inotify watcher reliably by creating and unlinking a file in the watched directory */
		char domain_dir[512];
		lws_snprintf(domain_dir, sizeof(domain_dir), "%s/domains/.acme_trigger_cleanup_%s", ad->base_dir, ad->active_domain);
		int trigger_fd = open(domain_dir, O_CREAT | O_WRONLY, 0600);
		if (trigger_fd >= 0) close(trigger_fd);
		unlink(domain_dir);

		lwsl_vhost_info(vh, "Cleaned up dns-01 local acme temp zone addon: %s", path);
		ad->active_domain[0] = '\0';
	}
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
	struct lws_vhost *vh = lws_get_vhost(wsi);

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		lwsl_notice("acme_dns: PROTOCOL_INIT called (in=%p, ad=%p)\n", in, ad);
		if (ad || !in) {
			lwsl_notice("acme_dns: ignoring INIT (ad=%p, in=%p)\n", ad, in);
			return 0;
		}

		/*
		 * Don't run ACME certificate acquisition inside the root-monitor
		 * spawned process to avoid duplicated challenges.
		 */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-dht-dnssec-monitor-root"))
			return 0;

		ad = lws_protocol_vh_priv_zalloc(vh, lws_get_protocol(wsi),
						 sizeof(struct vhd_acme_dns));
		if (!ad)
			return -1;

		ad->vhost = vh;
		ad->context = lws_get_context(wsi);

		{
			lws_system_policy_t *policy;
			if (lws_system_parse_policy(lws_get_context(wsi), "/etc/lwsws/policy", &policy)) {
				lwsl_vhost_notice(vh, "acme dns: couldn't parse policy, plugin disabled.");
				return -1;
			}
			ad->base_dir = strdup(policy->dns_base_dir);
			lws_system_policy_free(policy);
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
		if (ad) {
			lws_sul_cancel(&ad->sul_delay);
		}
		if (ad && ad->core_ops && ad->core_ops->destroy_vhost) {
			ad->core_ops->destroy_vhost(ad->core_vhd);
		}
		if (ad) {
			challenge_cleanup_dns(vh, ad);
			if (ad->base_dir)
				free(ad->base_dir);
		}
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
