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

#if !defined(__LWS_DHT_DNSSEC_H__)
#define __LWS_DHT_DNSSEC_H__

struct lws_context;

struct lws_dht_dnssec_keygen_args {
	const char *domain;
	const char *workdir;
	const char *type;   /* e.g. "EC" or "RSA" */
	const char *curve;
	int bits;
};

struct lws_dht_dnssec_dsfromkey_args {
	const char *domain;
	const char *workdir;
	const char *hash;   /* E.g., "SHA256" */
};

struct lws_dht_dnssec_signzone_args {
	const char *domain;
	const char *workdir;
	const char *certs_dir;
	uint32_t sign_validity_duration;
	char ipv4[64];
	char ipv6[64];
};

struct lws_dht_dnssec_importnsd_args {
	const char *domain;
	const char *key1_prefix;
	const char *key2_prefix; /* optional if only importing 1 key */
};

/*
 * The status a zone fetch completes with
 */
enum lws_dht_dnssec_fetch_status {
	LWS_DHT_DNSSEC_FETCH_ABORTED	= -2, /* refused or dropped unfinished,
					       * eg, vhost destroyed: no result
					       * and nothing more will come */
	LWS_DHT_DNSSEC_FETCH_INVALID	= -1, /* what came failed validation */
	LWS_DHT_DNSSEC_FETCH_TIMEOUT	= 0,  /* nobody answered in time */
	LWS_DHT_DNSSEC_FETCH_OK		= 1,  /* the zone is in DHT storage */
};

/*
 * status is one of enum lws_dht_dnssec_fetch_status
 */
typedef void (*lws_dht_dnssec_fetch_cb_t)(void *opaque, const char *domain, int status);

/*
 * Ownership of opaque: a fetch_zone() call that is not a cancel calls cb
 * exactly once with opaque, whatever happens to the fetch, so cb is the one
 * place that needs to release it.  That may happen before fetch_zone()
 * returns: when the zone is already in storage (FETCH_OK), and when the
 * fetch is refused (FETCH_ABORTED, and fetch_zone() returns nonzero).
 *
 * A request with the same domain, cb and opaque as one still pending is
 * merged into it, and cb is called once for both.
 *
 * A cancel (is_cancel = 1) drops the pending requests for that domain and
 * opaque without calling their cb: opaque is the caller's again.  A cancel
 * with domain NULL drops every pending request with that opaque, so a caller
 * going away can take back everything it handed out at once.  A cancel must
 * not be made from inside cb.
 */
struct lws_dht_dnssec_fetch_zone_args {
	struct lws_vhost *vhost;
	const char *domain;
	const char *cache_dir;
	lws_dht_dnssec_fetch_cb_t cb;
	void *opaque;
	int is_cancel; /* If 1, cancel an ongoing fetch for this domain/opaque
			* pair, or for every domain with opaque if domain is
			* NULL */
	int force_network; /* If 1, bypass local cache and query network directly */
};

struct lws_dht_dnssec_ops {
	int (*keygen)(struct lws_context *context, struct lws_dht_dnssec_keygen_args *args);
	int (*dsfromkey)(struct lws_context *context, struct lws_dht_dnssec_dsfromkey_args *args);
	int (*signzone)(struct lws_context *context, struct lws_dht_dnssec_signzone_args *args);
	int (*importnsd)(struct lws_context *context, struct lws_dht_dnssec_importnsd_args *args);
	int (*bump_zone_serial)(struct lws_context *context, const char *zone_filepath);

	int (*add_temp_zone)(struct lws_context *context, const char *domain, const char *zone_str, int ttl_secs);
	int (*publish_jws)(struct lws_vhost *vhost, const char *jws_filepath);
	int (*fetch_zone)(struct lws_context *cx,
			struct lws_dht_dnssec_fetch_zone_args *args);

	/*
	 * Tell DHT plugin to actively subscribe to the network for changes
	 * to this domain using LWS_DHT_EVENT_NOTIFY pub/sub.
	 */
	int (*subscribe_zone)(struct lws_vhost *vhost, const char *domain);

	/*
	 * Actively repair an outdated peer we encountered by firing a targeted
	 * EVENT_NOTIFY packet at them containing the fresh SOA Serial.
	 */
	int (*notify_peer_outdated)(struct lws_vhost *vhost, const char *domain,
				    const lws_sockaddr46 *sa46_peer, uint64_t newer_soa_serial);

	void (*register_auth_cb)(struct lws_vhost *vh, void (*cb)(void *opaque, const char *domain, const char *payload_path), void *opaque);
};


#endif
