/*
 * libwebsockets ACME client plugin
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

#if !defined(__LWS_ACME_CLIENT_H__)
#define __LWS_ACME_CLIENT_H__

#include <libwebsockets.h>

struct lws_vhost;
struct lws_context;
struct lws_protocol_vhost_options;
struct lws_acme_cert_aging_args;

typedef enum {
    LWS_ACME_CHALLENGE_TYPE_HTTP_01,
    LWS_ACME_CHALLENGE_TYPE_DNS_01,
} lws_acme_challenge_type;

struct lws_acme_cert_config_acme {
	const char *country;
	const char *state;
	const char *locality;
	const char *organization;
	const char *directory_url;
};

struct lws_acme_cert_config {
    lws_dll2_t list;

    const char *pvop[LWS_TLS_TOTAL_COUNT];

    lws_acme_challenge_type challenge_type;

    /* Top level JSON parsed fields */
	const char *common_name;
	const char *email;
	const char *challenge_type_str;
	const char *profile;
	struct lws_acme_cert_config_acme *acme;
};

struct lws_acme_challenge_ops {
	int (*challenge_start)(struct lws_vhost *vhost, void *challenge_priv,
			       const char *token, const char *key_auth,
			       const char *domain);
	int (*challenge_poll)(struct lws_vhost *vhost, void *challenge_priv);
	void (*challenge_cleanup)(struct lws_vhost *vhost, void *challenge_priv);
};

struct lws_acme_core_ops {
	struct per_vhost_data__lws_acme_client *
	(*init_vhost)(struct lws_context *context, struct lws_vhost *vhost, const struct lws_protocol_vhost_options *pvo,
		      const struct lws_acme_challenge_ops *ops, void *challenge_priv);

	int
	(*cert_aging)(struct per_vhost_data__lws_acme_client *vhd,
		      const struct lws_acme_cert_aging_args *caa);

	void
	(*destroy_vhost)(struct per_vhost_data__lws_acme_client *vhd);

	void
	(*notify_challenge_ready)(struct per_vhost_data__lws_acme_client *vhd);

	void
	(*trigger_resign)(struct per_vhost_data__lws_acme_client *vhd);
};

#endif
