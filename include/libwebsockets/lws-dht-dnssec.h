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
	uint32_t sign_validity_duration;
};

struct lws_dht_dnssec_importnsd_args {
	const char *domain;
	const char *key1_prefix;
	const char *key2_prefix; /* optional if only importing 1 key */
};

typedef void (*lws_dht_dnssec_fetch_cb_t)(void *opaque, const char *domain, int status);

struct lws_dht_dnssec_fetch_zone_args {
	struct lws_vhost *vhost;
	const char *domain;
	const char *cache_dir;
	lws_dht_dnssec_fetch_cb_t cb;
	void *opaque;
	int is_cancel; /* If 1, cancel an ongoing fetch for this domain/opaque pair */
};

struct lws_dht_dnssec_ops {
	int (*keygen)(struct lws_context *context, struct lws_dht_dnssec_keygen_args *args);
	int (*dsfromkey)(struct lws_context *context, struct lws_dht_dnssec_dsfromkey_args *args);
	int (*signzone)(struct lws_context *context, struct lws_dht_dnssec_signzone_args *args);
	int (*importnsd)(struct lws_context *context, struct lws_dht_dnssec_importnsd_args *args);

	int (*add_temp_zone)(struct lws_context *context, const char *domain, const char *zone_str, int ttl_secs);
	int (*publish_jws)(struct lws_context *context, const char *jws_filepath);
	int (*fetch_zone)(struct lws_context *context, struct lws_dht_dnssec_fetch_zone_args *args);

	void (*register_auth_cb)(struct lws_vhost *vh, void (*cb)(void *opaque, const char *domain, const char *payload_path), void *opaque);
};


#endif
