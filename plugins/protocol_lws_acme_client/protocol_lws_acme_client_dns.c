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

#include "private-acme-client.h"
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

struct vhd_acme_dns {
	const struct lws_protocols *core_protocol;
	const struct lws_acme_core_ops *core_ops;
	struct per_vhost_data__lws_acme_client *core_vhd;

	struct lws_context *context;
	struct lws_vhost *vhost;
	char *base_dir;
	char active_domain[256];
	lws_sorted_usec_list_t sul_delay;
	time_t saved;		/* when we handed over the challenge TXT */
	lws_usec_t deadline;	/* for the zone with it to be signed */
	char txt[64];		/* the challenge TXT value */
#if defined(LWS_WITH_SYS_ASYNC_DNS) && defined(LWS_WITH_AUTHORITATIVE_DNS)
	struct acme_dns_wait *wait;
	struct acme_dns_ns ns[ACME_DNS_MAX_NS];
	struct acme_dns_server servers[ACME_DNS_WAIT_MAX_SERVERS];
	int nns;
	int nservers;
	int resolving;		/* NS names we are still looking up */
#endif
};

/*
 * The root process merges the challenge TXT into the domain's zone and signs
 * it, and lwsws publishes the signed zone to the DHT as soon as it sees the
 * new .jws.  Only once the zone's authoritative servers are serving it is it
 * worth asking the ACME server to look for it: a resolver on its way that
 * asks too soon may cache that there is no such record.  Signing can be held
 * up, eg, until the external addresses are known, so rather than hoping it
 * happened, watch for it; and then ask the zone's name servers directly
 * until they all serve the TXT (see acme-dns-wait.c).
 */

/* how often to look for the zone with the challenge being signed */
#define ACME_DNS_POLL_US	(1 * LWS_US_PER_SEC)
/* how long signing it may take before we give up this attempt */
#define ACME_DNS_SIGN_US	(180 * LWS_US_PER_SEC)
/*
 * how long after signing we wait if we can't ask the name servers (no NS in
 * the zone, or none of them could be looked up)
 */
#define ACME_DNS_SPREAD_US	(20 * LWS_US_PER_SEC)
/* how long the name servers may take to serve it, and how often we ask */
#define ACME_DNS_SERVE_US	(180 * LWS_US_PER_SEC)
#define ACME_DNS_SERVE_POLL_US	(2 * LWS_US_PER_SEC)

static void
acme_dns_ready(struct vhd_acme_dns *ad)
{
	if (ad->core_ops && ad->core_ops->notify_challenge_ready && ad->core_vhd) {
		lwsl_vhost_notice(ad->vhost, "dns-01: challenge zone published, "
				  "asking the ACME server to check it");
		ad->core_ops->notify_challenge_ready(ad->core_vhd);
	}
}

static void
sul_dns_ready_cb(lws_sorted_usec_list_t *sul)
{
	acme_dns_ready(lws_container_of(sul, struct vhd_acme_dns, sul_delay));
}

#if defined(LWS_WITH_SYS_ASYNC_DNS) && defined(LWS_WITH_AUTHORITATIVE_DNS)

static void
acme_dns_served_cb(void *opaque, int ok, const char *why)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)opaque;

	ad->wait = NULL; /* it is freed when we return */

	if (ok) {
		lwsl_vhost_notice(ad->vhost, "dns-01: every name server of %s "
				  "serves the challenge", ad->active_domain);
		acme_dns_ready(ad);
		return;
	}

	lwsl_vhost_err(ad->vhost, "dns-01: %s", why);

	if (ad->core_ops && ad->core_ops->challenge_failed && ad->core_vhd)
		ad->core_ops->challenge_failed(ad->core_vhd, why);
}

/* we know every address we are going to: ask them */

static void
acme_dns_ask_servers(struct vhd_acme_dns *ad)
{
	char qname[300];

	lws_snprintf(qname, sizeof(qname), "_acme-challenge.%s",
		     ad->active_domain);

	if (ad->nservers)
		ad->wait = acme_dns_wait_start(ad->context, qname, ad->txt,
					       ad->servers, ad->nservers,
					       ACME_DNS_SERVE_US,
					       ACME_DNS_SERVE_POLL_US,
					       acme_dns_served_cb, ad);
	if (ad->wait) {
		lwsl_vhost_notice(ad->vhost, "dns-01: asking %d addresses of "
				  "%d name servers for the challenge",
				  ad->nservers, ad->nns);
		return;
	}

	lwsl_vhost_warn(ad->vhost, "dns-01: can't ask the name servers of "
			"%s, allowing %ds instead", ad->active_domain,
			(int)(ACME_DNS_SPREAD_US / LWS_US_PER_SEC));
	lws_sul_schedule(ad->context, 0, &ad->sul_delay, sul_dns_ready_cb,
			 ACME_DNS_SPREAD_US);
}

static void
acme_dns_add_server(struct vhd_acme_dns *ad, const char *ns,
		    const lws_sockaddr46 *sa46)
{
	struct acme_dns_server *s;

	if (ad->nservers == (int)LWS_ARRAY_SIZE(ad->servers))
		return;

	s = &ad->servers[ad->nservers++];
	memset(s, 0, sizeof(*s));
	lws_strncpy(s->ns, ns, sizeof(s->ns));
	s->sa46 = *sa46;
	sa46_sockport(&s->sa46, htons(53));
}

static struct lws *
acme_dns_ns_resolved_cb(struct lws *wsi, const char *ads,
			const struct addrinfo *result, int n, void *opaque)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)opaque;
	const struct addrinfo *ai;
	lws_sockaddr46 sa46;

	for (ai = result; ads && ai; ai = ai->ai_next) {
		memset(&sa46, 0, sizeof(sa46));
		if (ai->ai_family == AF_INET &&
		    ai->ai_addrlen >= sizeof(struct sockaddr_in))
			memcpy(&sa46.sa4, ai->ai_addr, sizeof(sa46.sa4));
#if defined(LWS_WITH_IPV6)
		else if (ai->ai_family == AF_INET6 &&
			 ai->ai_addrlen >= sizeof(struct sockaddr_in6))
			memcpy(&sa46.sa6, ai->ai_addr, sizeof(sa46.sa6));
#endif
		else
			continue;
		acme_dns_add_server(ad, ads, &sa46);
	}

	if (!result)
		lwsl_vhost_warn(ad->vhost, "dns-01: can't look up a name "
				"server of %s", ad->active_domain);
	else
		lws_async_dns_freeaddrinfo(&result);

	if (!--ad->resolving)
		acme_dns_ask_servers(ad);

	return NULL;
}

/* find the zone's name servers and their addresses */

static void
acme_dns_find_servers(struct vhd_acme_dns *ad)
{
	char path[1024], *buf = NULL;
	struct stat st;
	int fd, n, m;

	ad->nns = ad->nservers = 0;

	lws_snprintf(path, sizeof(path), "%s/domains/%s/%s.zone.signed",
		     ad->base_dir, ad->active_domain, ad->active_domain);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (!fstat(fd, &st) && st.st_size > 0 &&
		    st.st_size < 1024 * 1024) {
			buf = malloc((size_t)st.st_size + 1);
			if (buf && read(fd, buf, LWS_POSIX_LENGTH_CAST(st.st_size)) !=
							(ssize_t)st.st_size) {
				free(buf);
				buf = NULL;
			}
		}
		close(fd);
	}

	if (buf) {
		buf[st.st_size] = '\0';
		ad->nns = acme_dns_zone_ns(buf, (size_t)st.st_size,
					   ad->active_domain, ad->ns,
					   (int)LWS_ARRAY_SIZE(ad->ns));
		free(buf);
	}
	if (ad->nns <= 0) {
		ad->nns = 0;
		acme_dns_ask_servers(ad);
		return;
	}

	/*
	 * One count stands for us until every lookup is started, since a
	 * cached one calls back before lws_async_dns_query() returns
	 */
	ad->resolving = 1;

	for (n = 0; n < ad->nns; n++) {
		if (ad->ns[n].glue_count) {
			for (m = 0; m < ad->ns[n].glue_count; m++)
				acme_dns_add_server(ad, ad->ns[n].host,
						    &ad->ns[n].glue[m]);
			continue;
		}

		/* it calls back exactly once, even when it fails */
		ad->resolving++;
		lws_async_dns_query(ad->context, 0, ad->ns[n].host,
				    LWS_ADNS_RECORD_A, acme_dns_ns_resolved_cb,
				    NULL, ad, NULL);
	}

	if (!--ad->resolving)
		acme_dns_ask_servers(ad);
}

#endif

static void
sul_dns_signed_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_acme_dns *ad = lws_container_of(sul, struct vhd_acme_dns, sul_delay);
	char path[1024];
	struct stat st;

	lws_snprintf(path, sizeof(path), "%s/domains/%s/%s.zone.signed.jws",
		     ad->base_dir, ad->active_domain, ad->active_domain);

	if (!stat(path, &st) && st.st_mtime >= ad->saved) {
#if defined(LWS_WITH_SYS_ASYNC_DNS) && defined(LWS_WITH_AUTHORITATIVE_DNS)
		lwsl_vhost_notice(ad->vhost, "dns-01: zone with the challenge "
				  "signed, waiting for its name servers");
		acme_dns_find_servers(ad);
#else
		lwsl_vhost_notice(ad->vhost, "dns-01: zone with the challenge "
				  "signed, allowing %ds for the DHT",
				  (int)(ACME_DNS_SPREAD_US / LWS_US_PER_SEC));
		lws_sul_schedule(ad->context, 0, &ad->sul_delay,
				 sul_dns_ready_cb, ACME_DNS_SPREAD_US);
#endif
		return;
	}

	if (lws_now_usecs() < ad->deadline) {
		lws_sul_schedule(ad->context, 0, &ad->sul_delay,
				 sul_dns_signed_cb, ACME_DNS_POLL_US);
		return;
	}

	lwsl_vhost_err(ad->vhost, "dns-01: %s was not signed with the "
		       "challenge in %ds", ad->active_domain,
		       (int)(ACME_DNS_SIGN_US / LWS_US_PER_SEC));

	if (ad->core_ops && ad->core_ops->challenge_failed && ad->core_vhd)
		ad->core_ops->challenge_failed(ad->core_vhd,
				"zone with the dns-01 challenge was not signed");
}

static int
challenge_start_dns(struct lws_vhost *vh, void *priv, const char *token,
		     const char *key_auth, const char *domain)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)priv;
	uint8_t digest[32];
	struct lws_genhash_ctx hash_ctx;
	char b64[128];
	int b64_len;
	size_t n;

	if (!ad->base_dir) {
		lwsl_vhost_err(vh, "dns-01 challenge requires 'base-dir' pvo");
		return 1;
	}

	lws_strncpy(ad->active_domain, domain, sizeof(ad->active_domain));

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hash_ctx, (const uint8_t *)key_auth, strlen(key_auth)) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lwsl_vhost_err(vh, "failed to compute SHA-256 digest of key_auth");
		return 1;
	}

	b64_len = lws_jws_base64_enc((const char *)digest, 32, b64, sizeof(b64));
	if (b64_len < 0 || (size_t)b64_len >= sizeof(ad->txt)) {
		lwsl_vhost_err(vh, "failed to base64url encode digest");
		return 1;
	}
	lws_strncpy(ad->txt, b64, sizeof(ad->txt));

	char line[512];
	n = (size_t)lws_snprintf(line, sizeof(line),
		"_acme-challenge\t1\tIN\tTXT\t\"%s\"\n"
		"%s.\t1\tIN\tCAA\t0 issue \"letsencrypt.org\"\n", b64, domain);

	if (ad->core_ops && ad->core_ops->acme_ipc_save_payload) {
		int r = ad->core_ops->acme_ipc_save_payload(ad->core_vhd, "save_dns_challenge", domain, "none", line, n);
		if (r) {
			lwsl_vhost_err(vh, "failed writing to acme zone file via footprint IPC");
			return 1;
		}
	} else {
		lwsl_vhost_err(vh, "core_ops->acme_ipc_save_payload missing!");
		return 1;
	}

	/*
	 * The root daemon's IPC handler has the zone signed again with the
	 * TXT in, watch for that
	 */
	ad->saved = (time_t)lws_now_secs();
	ad->deadline = lws_now_usecs() + ACME_DNS_SIGN_US;

	lwsl_vhost_notice(vh, "dns-01: challenge for %s handed over, waiting "
			  "for the zone with it to be signed", domain);
	lws_sul_schedule(ad->context, 0, &ad->sul_delay, sul_dns_signed_cb,
			 ACME_DNS_POLL_US);

	return 0;
}

static void
challenge_cleanup_dns(struct lws_vhost *vh, void *priv)
{
	struct vhd_acme_dns *ad = (struct vhd_acme_dns *)priv;

	/* the attempt is over, whether or not we were still waiting */
	lws_sul_cancel(&ad->sul_delay);
#if defined(LWS_WITH_SYS_ASYNC_DNS) && defined(LWS_WITH_AUTHORITATIVE_DNS)
	acme_dns_wait_destroy(&ad->wait);
	lws_async_dns_cancel_by_opaque(ad->context, ad);
	ad->resolving = 0;
#endif

	if (ad->base_dir && ad->active_domain[0]) {
		if (ad->core_ops && ad->core_ops->acme_ipc_save_payload) {
			ad->core_ops->acme_ipc_save_payload(ad->core_vhd, "cleanup_dns_challenge", ad->active_domain, "none", "", 0);
		}
		lwsl_vhost_info(vh, "Cleaned up dns-01 local acme temp zone addon via IPC");
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
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		if (ad || !in)
			return 0;

		/* ACME now runs globally in the root-monitor */

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
