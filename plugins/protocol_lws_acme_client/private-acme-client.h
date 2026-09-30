/*
 * libwebsockets ACME client protocol plugin
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 *
 *  This implementation follows draft 7 of the IETF standard, and falls back
 *  to whatever differences exist for Boulder's tls-sni-01 challenge.
 *  tls-sni-02 is also supported.
 */

/*
 * Private to the ACME client plugin, and to api-test-acme-json, which
 * checks its parsing of the ACME server's JSON (see acme-json.c) against
 * canned responses
 */

#if !defined(__LWS_PRIVATE_ACME_CLIENT_H__)
#define __LWS_PRIVATE_ACME_CLIENT_H__

#include "lws-acme-client.h"

typedef enum {
	ACME_STATE_DIRECTORY,	/* get the directory JSON using GET + parse */
	ACME_STATE_NEW_NONCE,	/* get the replay nonce */
	ACME_STATE_NEW_ACCOUNT,	/* register a new RSA key + email combo */
	ACME_STATE_NEW_ORDER,	/* start the process to request a cert */
	ACME_STATE_AUTHZ,	/* */
	ACME_STATE_START_CHALL, /* notify server ready for one challenge */
	ACME_STATE_POLLING,	/* he should be trying our challenge */
	ACME_STATE_POLLING_CSR, /* sent CSR, checking result */
	ACME_STATE_DOWNLOAD_CERT,

	ACME_STATE_FINISHED
} lws_acme_state;

/*
 * The root daemon answers each request on the IPC stream with one JSON line,
 * {"req":"<the request's name>","status":"ok"|"error",...}\n, but a read can
 * carry several lines or part of one, and it also sends every client lines
 * that answer nothing we asked (eg, "cert_status").  A refusal before it
 * knew what we asked for (eg, authentication failed) has no "req".
 */

typedef enum {
	ACME_IPC_LINE_UNRELATED,	/* not an answer to a request of ours */
	ACME_IPC_LINE_SAVE,		/* answers one of our save-type requests */
	ACME_IPC_LINE_VALIDITY,		/* answers get_cert_validity */
	ACME_IPC_LINE_REFUSED,		/* refuses a request of ours, unknown which */
} acme_ipc_line_t;

struct acme_ipc_reply {
	acme_ipc_line_t		type;
	int			days_left;	/* VALIDITY */
	int			total_days;	/* VALIDITY */
	unsigned int		ok:1;		/* "status":"ok" */
	unsigned int		stores_cert:1;	/* SAVE of the cert or its key */
};

/* reassembles the daemon's lines across reads */
struct acme_ipc_rx {
	char			buf[2048];
	size_t			len;	/* sizeof(buf): overlong line, dropped */
};

typedef int (*acme_ipc_line_cb_t)(void *opaque, const char *line, size_t len);

struct acme_connection {
	char buf[4096];
	char replay_nonce[64];
	char chall_token[64];
	char chall_type[16];	/* the challenge authz picked, eg, "dns-01" */
	char challenge_uri[256];
	char detail[64];
	char status[16];
	char key_auth[256];
	char urls[6][256]; /* directory contents */
	char active_url[256];
	char authz_url[256];
	char order_url[256];
	char finalize_url[256];
	char cert_url[256];
	char acct_id[256];
	char *kid;
	lws_acme_state state;
	struct lws_client_connect_info i;
	struct lejp_ctx jctx;
	struct lws_vhost *vhost;

	struct lws *cwsi;

	const char *real_vh_name;
	const char *real_vh_iface;

	char *alloc_privkey_pem;

	char *dest;
	int pos;
	int len;
	int resp;
	int cpos;

	int real_vh_port;
	int goes_around;

	size_t len_privkey_pem;

	unsigned int yes;
	unsigned int use:1;
	unsigned int is_sni_02:1;
	unsigned int saves_awaited:1;	/* cert fetched, waiting on IPC saves */
	unsigned int save_refused:1;	/* the daemon refused to store cert / key */
};

struct per_vhost_data__lws_acme_client {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	const struct lws_acme_challenge_ops *ops;
	void *challenge_priv;

	/*
	 * the vhd is allocated for every vhost using the plugin.
	 * But ac is only allocated when we are doing the server auth.
	 */
	struct acme_connection *ac;

	struct lws_jwk jwk;
	char *dns_base_dir;

	/*
	 * State owned by the temporary http-01 challenge vhost.
	 *
	 * lws_vhost_destroy() is asynchronous while wsi are still bound, so the
	 * temp vhost (and the mount matching that walks its mount list) can
	 * outlive the acquisition that created it.  Everything the temp vhost
	 * points at must therefore live here in the vhd, which lasts as long as
	 * the parent vhost, and not in the ac we free at the end of each
	 * attempt
	 */
	struct lws_context_creation_info chall_ci;
	struct lws_http_mount chall_mount;
	char chall_mountpoint[256];
	char chall_key_auth[256];

	lws_dll2_owner_t cert_configs;
    struct lws_acme_cert_config *active_cert;
    lws_sorted_usec_list_t sul_aging;
    lws_sorted_usec_list_t sul_acquisition;
    lws_sorted_usec_list_t sul_watchdog;
    lws_usec_t last_acme_failure;
    /*
     * LE allows 5 duplicate certs / 7 days: repeated acquisition attempts
     * for an unchanged cert must back off exponentially or we can be
     * locked out of ordering for the rest of the week
     */
    int acme_fail_count;
    lws_usec_t acme_retry_not_before;

	int count_live_pss;
	char *dest;
	int pos;
	int len;
	#if !defined(LWS_WITH_ESP32)
	/* removed persistent fd_updated_cert/key handles since they are opened dynamically per cert */
	/* we allocate memory here because we drop root too early */
#endif
	const char *uds_path;
	const char *ipc_uds_path;	/* what vhd->ipc connects to */
	struct lws_async_ipc *ipc;
	struct acme_ipc_rx ipc_rx;
	/* reply timeout, and the deferred handling of an IPC failure */
	lws_sorted_usec_list_t sul_ipc;
	/*
	 * Save-type requests on the current IPC connection still waiting for
	 * their answer line.  An aging validity request is outstanding while
	 * aging_current_cert is set.  Both go when the connection does.
	 */
	int ipc_pending_saves;
	char ipc_failing;

	struct lws_dll2 *aging_current_cert;
	int aging_is_production;
	char aging_global_email[128];
	char aging_global_profile[128];
	struct lws_acme_cert_aging_args aging_caa;
#if defined(LWS_WITH_SYS_SMD)
	struct lws_smd_peer *smd_peer;
#endif
};

/*
 * Parsers for the ACME server's JSON responses, see acme-json.c.  The
 * directory and authz parsers take the vhd as their lejp user, the order
 * and challenge ones the acme_connection
 */

/* indexes into acme_jdir_tok[], and so into acme_connection.urls[] */
enum enum_jdir_tok {
	JAD_KEY_CHANGE_URL,
	JAD_TOS_URL,
	JAD_NEW_ACCOUNT_URL,
	JAD_NEW_NONCE_URL,
	JAD_NEW_ORDER_URL,
	JAD_REVOKE_CERT_URL,
};

extern const char * const acme_jdir_tok[6];
extern const char * const acme_jorder_tok[7];
extern const char * const acme_jauthz_tok[9];
extern const char * const acme_jchac_tok[5];

signed char
acme_cb_dir(struct lejp_ctx *ctx, char reason);
signed char
acme_cb_order(struct lejp_ctx *ctx, char reason);
signed char
acme_cb_authz(struct lejp_ctx *ctx, char reason);
signed char
acme_cb_chac(struct lejp_ctx *ctx, char reason);

/*
 * Feed bytes read from the root daemon's IPC stream: cb is called with each
 * complete line, NUL-terminated, without its '\n'.  Stops and returns 1 if
 * cb returns nonzero, else returns 0.
 */
int
acme_ipc_rx(struct acme_ipc_rx *rx, const char *in, size_t len,
	    acme_ipc_line_cb_t cb, void *opaque);

void
acme_ipc_classify(const char *line, size_t len, struct acme_ipc_reply *r);

#endif
