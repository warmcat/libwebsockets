/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

#ifndef _WIN32
/* this is needed for Travis CI */
#include <dirent.h>
#endif

#define ESC_INSTALL_DATADIR "_lws_ddir_"

static const char * const paths_global[] = {
	"global.uid",
	"global.gid",
	"global.username",
	"global.groupname",
	"global.count-threads",
	"global.count-async-threads",
	"global.init-ssl",
	"global.server-string",
	"global.plugin-dir",
	"global.ws-pingpong-secs", /* deprecated */
	"global.timeout-secs",
	"global.reject-service-keywords[].*",
	"global.reject-service-keywords[]",
	"global.default-alpn",
	"global.ip-limit-ah",
	"global.ip-limit-wsi",
	"global.rlimit-nofile",
	"global.cpd-bypass",
	"global.quic-pad-crypto",
	"global.allow-early-data",
	"global.quic-only-latest",
	"global.quic-early-key-update",
};

enum lejp_global_paths {
	LEJPGP_UID,
	LEJPGP_GID,
	LEJPGP_USERNAME,
	LEJPGP_GROUPNAME,
	LEJPGP_COUNT_THREADS,
	LEJPGP_COUNT_ASYNC_THREADS,
	LWJPGP_INIT_SSL,
	LEJPGP_SERVER_STRING,
	LEJPGP_PLUGIN_DIR,
	LWJPGP_PINGPONG_SECS,
	LWJPGP_TIMEOUT_SECS,
	LWJPGP_REJECT_SERVICE_KEYWORDS_NAME,
	LWJPGP_REJECT_SERVICE_KEYWORDS,
	LWJPGP_DEFAULT_ALPN,
	LWJPGP_IP_LIMIT_AH,
	LWJPGP_IP_LIMIT_WSI,
	LWJPGP_FD_LIMIT_PT,
	LEJPGP_CPD_BYPASS,
	LEJPGP_QUIC_PAD_CRYPTO,
	LEJPGP_ALLOW_EARLY_DATA,
	LEJPGP_QUIC_ONLY_LATEST,
	LEJPGP_QUIC_EARLY_KEY_UPDATE,
};

static const char * const paths_vhosts[] = {
	"vhosts[]",
	"vhosts[].name",
	"vhosts[].port",
	"vhosts[].interface",
	"vhosts[].unix-socket",
	"vhosts[].unix-socket-perms",
	"vhosts[].sts",
	"vhosts[].host-ssl-key",
	"vhosts[].host-ssl-cert",
	"vhosts[].host-ssl-ca",
	"vhosts[].access-log",
	"vhosts[].mounts[].mountpoint",
	"vhosts[].mounts[].origin",
	"vhosts[].mounts[].protocol",
	"vhosts[].mounts[].default",
	"vhosts[].mounts[].auth-mask",
	"vhosts[].mounts[].cgi-timeout",
	"vhosts[].mounts[].cgi-env[].*",
	"vhosts[].mounts[].cgi-env[]",
	"vhosts[].mounts[].cache-max-age",
	"vhosts[].mounts[].cache-reuse",
	"vhosts[].mounts[].cache-revalidate",
	"vhosts[].mounts[].cache-no",
	"vhosts[].mounts[].exact-match",
	"vhosts[].mounts[].append-path",
	"vhosts[].mounts[].no-ws-upgrades",
	"vhosts[].mounts[].basic-auth",
	"vhosts[].mounts[].cache-intermediaries",
	"vhosts[].mounts[].extra-mimetypes.*",
	"vhosts[].mounts[].extra-mimetypes",
	"vhosts[].mounts[].interpret.*",
	"vhosts[].mounts[].interpret",
	"vhosts[].mounts[].cgi-chroot",
	"vhosts[].mounts[].cgi-chdir",
	"vhosts[].mounts[].headers[].*",
	"vhosts[].mounts[].headers[]",
	"vhosts[].mounts[].keepalive-timeout",
#if defined(LWS_WITH_JOSE)
	"vhosts[].mounts[].interceptor-path",
#endif
	"vhosts[].mounts[]",
	/* Nested generic paths handled dynamically in LEJPVP_PROTOCOL_NAME_OPT */
	"vhosts[].ws-protocols[].*.*",
	"vhosts[].ws-protocols[].*",
	"vhosts[].ws-protocols[]",
	"vhosts[].keepalive_timeout",
	"vhosts[].enable-client-ssl",
	"vhosts[].ciphers",
	"vhosts[].ecdh-curve",
	"vhosts[].noipv6",
	"vhosts[].ipv6only",
	"vhosts[].ssl-option-set",
	"vhosts[].ssl-option-clear",
	"vhosts[].mounts[].pmo[].*",
	"vhosts[].mounts[].pmo[]",
	"vhosts[].headers[].*",
	"vhosts[].headers[]",
	"vhosts[].client-ssl-key",
	"vhosts[].client-ssl-cert",
	"vhosts[].client-ssl-ca",
	"vhosts[].client-ssl-ciphers",
	"vhosts[].onlyraw",
	"vhosts[].client-cert-required",
	"vhosts[].ignore-missing-cert",
	"vhosts[].error-document-404",
	"vhosts[].alpn",
	"vhosts[].fo-listen-queue",
	"vhosts[].ssl-client-option-set",
	"vhosts[].ssl-client-option-clear",
	"vhosts[].tls13-ciphers",
	"vhosts[].client-tls13-ciphers",
	"vhosts[].client-ecdh-curve",
	"vhosts[].strict-host-check",

	"vhosts[].listen-accept-role",
	"vhosts[].listen-accept-protocol",
	"vhosts[].apply-listen-accept", /* deprecates "onlyraw" */
	"vhosts[].fallback-listen-accept",
	"vhosts[].allow-non-tls",
	"vhosts[].redirect-http",
	"vhosts[].allow-http-on-https",

	"vhosts[].disable-no-protocol-ws-upgrades",
	"vhosts[].h2-half-closed-long-poll",
#if defined(LWS_WITH_DHT)
	"vhosts[].dht[].v",
	"vhosts[].dht[].name",
	"vhosts[].dht[].port",
	"vhosts[].dht[].ipv6",
	"vhosts[].dht[].hash",
	"vhosts[].dht[]",
#endif
	"vhosts[].quic-mtu",
	"vhosts[].quic-preferred-addresses",
};

enum lejp_vhost_paths {
	LEJPVP,
	LEJPVP_NAME,
	LEJPVP_PORT,
	LEJPVP_INTERFACE,
	LEJPVP_UNIXSKT,
	LEJPVP_UNIXSKT_PERMS,
	LEJPVP_STS,
	LEJPVP_HOST_SSL_KEY,
	LEJPVP_HOST_SSL_CERT,
	LEJPVP_HOST_SSL_CA,
	LEJPVP_ACCESS_LOG,
	LEJPVP_MOUNTPOINT,
	LEJPVP_ORIGIN,
	LEJPVP_MOUNT_PROTOCOL,
	LEJPVP_DEFAULT,
	LEJPVP_DEFAULT_AUTH_MASK,
	LEJPVP_CGI_TIMEOUT,
	LEJPVP_CGI_ENV,
	LEJPVP_CGI_ENV_base,
	LEJPVP_MOUNT_CACHE_MAX_AGE,
	LEJPVP_MOUNT_CACHE_REUSE,
	LEJPVP_MOUNT_CACHE_REVALIDATE,
	LEJPVP_MOUNT_CACHE_NO,
	LEJPVP_MOUNT_EXACT_MATCH,
	LEJPVP_MOUNT_APPEND_PATH,
	LEJPVP_MOUNT_NO_WS_UPGRADES,
	LEJPVP_MOUNT_BASIC_AUTH,
	LEJPVP_MOUNT_CACHE_INTERMEDIARIES,
	LEJPVP_MOUNT_EXTRA_MIMETYPES,
	LEJPVP_MOUNT_EXTRA_MIMETYPES_base,
	LEJPVP_MOUNT_INTERPRET,
	LEJPVP_MOUNT_INTERPRET_base,
	LEJPVP_CGI_CHROOT,
	LEJPVP_CGI_CHDIR,
	LEJPVP_MOUNTPOINT_HEADERS_NAME,
	LEJPVP_MOUNTPOINT_HEADERS,
	LEJPVP_MOUNTPOINT_KEEPALIVE_TIMEOUT,
#if defined(LWS_WITH_JOSE)
	LEJPVP_MOUNT_INTERCEPTOR_PATH,
#endif

	LEJPVP_MOUNTS,

	/* Nested generic enum slots removed */
	LEJPVP_PROTOCOL_NAME_OPT,
	LEJPVP_PROTOCOL_NAME,
	LEJPVP_PROTOCOL,
	LEJPVP_KEEPALIVE_TIMEOUT,
	LEJPVP_ENABLE_CLIENT_SSL,
	LEJPVP_CIPHERS,
	LEJPVP_ECDH_CURVE,
	LEJPVP_NOIPV6,
	LEJPVP_IPV6ONLY,
	LEJPVP_SSL_OPTION_SET,
	LEJPVP_SSL_OPTION_CLEAR,
	LEJPVP_PMO,
	LEJPVP_PM_baseO,
	LEJPVP_HEADERS_NAME,
	LEJPVP_HEADERS,
	LEJPVP_CLIENT_SSL_KEY,
	LEJPVP_CLIENT_SSL_CERT,
	LEJPVP_CLIENT_SSL_CA,
	LEJPVP_CLIENT_CIPHERS,
	LEJPVP_FLAG_ONLYRAW,
	LEJPVP_FLAG_CLIENT_CERT_REQUIRED,
	LEJPVP_IGNORE_MISSING_CERT,
	LEJPVP_ERROR_DOCUMENT_404,
	LEJPVP_ALPN,
	LWJPVP_FO_LISTEN_QUEUE,
	LEJPVP_SSL_CLIENT_OPTION_SET,
	LEJPVP_SSL_CLIENT_OPTION_CLEAR,
	LEJPVP_TLS13_CIPHERS,
	LEJPVP_CLIENT_TLS13_CIPHERS,
	LEJPVP_CLIENT_ECDH_CURVE,
	LEJPVP_FLAG_STRICT_HOST_CHECK,

	LEJPVP_LISTEN_ACCEPT_ROLE,
	LEJPVP_LISTEN_ACCEPT_PROTOCOL,
	LEJPVP_FLAG_APPLY_LISTEN_ACCEPT,
	LEJPVP_FLAG_FALLBACK_LISTEN_ACCEPT,
	LEJPVP_FLAG_ALLOW_NON_TLS,
	LEJPVP_FLAG_REDIRECT_HTTP,
	LEJPVP_FLAG_ALLOW_HTTP_ON_HTTPS,

	LEJPVP_FLAG_DISABLE_NO_PROTOCOL_WS_UPGRADES,
	LEJPVP_FLAG_H2_HALF_CLOSED_LONG_POLL,
#if defined(LWS_WITH_DHT)
	LEJPVP_DHT_V,
	LEJPVP_DHT_NAME,
	LEJPVP_DHT_PORT,
	LEJPVP_DHT_IPV6,
	LEJPVP_DHT_HASH,
	LEJPVP_DHT,
#endif
	LEJPVP_QUIC_MTU,
	LEJPVP_QUIC_PREFERRED_ADDRESSES,
};

#define MAX_PLUGIN_DIRS 10

struct jpargs {
	struct lws_context_creation_info *info;
	struct lws_context *context;
	const struct lws_protocols *protocols;
	const struct lws_protocols **pprotocols;
	const struct lws_extension *extensions;
	char *p, *end, valid;
	struct lws_http_mount *head, *last;

	struct lws_protocol_vhost_options *pvo;
	struct lws_protocol_vhost_options *pvo_em;
	struct lws_protocol_vhost_options *pvo_int;

	struct lws_protocol_vhost_options *pvo_mp;

	struct lws_http_mount m;
	const char **plugin_dirs;
	int count_plugin_dirs;

	unsigned int reject_ws_with_no_protocol:1;
	unsigned int enable_client_ssl:1;
	unsigned int fresh_mount:1;
	unsigned int any_vhosts:1;
	unsigned int chunk:1;

	struct lwsac *ac;
       void *user;

#if defined(LWS_WITH_DHT)
	struct lws_dht_info dht;
	struct jpargs_dht_list {
		struct jpargs_dht_list *next;
		struct lws_dht_info info;
	} *dht_head, *dht_last;
	uint8_t dht_active;
#endif
};

/*
 * Everything the config callbacks parse out of the JSON, both structs and
 * their strings, lives in one fixed-size "config strings" arena provided by
 * the caller.  a->end is exclusive, ie, the last byte of the underlying
 * allocation is deliberately never used.  All arena allocation goes through
 * these checked helpers, so a->p <= a->end always holds.
 */

/* will "need" bytes at "at" fit in what's left of the arena? */
static int
lwsws_room(struct jpargs *a, char *at, size_t need)
{
	return at <= a->end && (size_t)(a->end - at) >= need;
}

/*
 * Bump-allocate len bytes at 16-byte alignment.  Returns the allocation
 * start and advances a->p past it, or NULL if the request can't be
 * satisfied, in which case the caller must fail the parse
 */
static void *
lwsws_alloc(struct jpargs *a, size_t len)
{
	char *p = a->p;

	if ((lws_intptr_t)p & 15)
		p += 16 - ((lws_intptr_t)p & 15);

	if (!lwsws_room(a, p, len))
		return NULL;

	a->p = p + len;
	a->chunk = 0;

	return p;
}

/*
 * The arena is exhausted, or no wildcard name is available where one is
 * required.  Fail the parse naming the config path that ran out, so the
 * operator can act on it.
 *
 * The callback contract is checked differently by lejp depending on the
 * reason: -1 is the only return that is treated as failure for all of them
 */
static signed char
lwsws_exhausted(struct lejp_ctx *ctx)
{
	lwsl_err("config strings arena exhausted at %s\n", ctx->path);

	return -1;
}

/*
 * Copy the wildcard name from the matched path into the arena, laid out as
 * name + term + '\0'.  Returns the name pointer with a->p left just past
 * the '\0' ready for the associated value string, or NULL if it can't be
 * done
 */
static char *
lwsws_name(struct jpargs *a, struct lejp_ctx *ctx, char term)
{
	char wild[LEJP_MAX_PATH];
	char *name;
	int n;

	/* the wildcard can only be as long as the path it is taken from */
	n = lejp_get_wildcard(ctx, 0, wild, (int)sizeof(wild));
	if (n < 1)
		return NULL;

	name = lwsws_alloc(a, (size_t)n + 1);
	if (!name)
		return NULL;

	memcpy(name, wild, (size_t)n - 1);
	name[n - 1] = term;
	name[n] = '\0';

	return name;
}

/*
 * How many arena bytes does it take to store string s, with any install
 * datadir escapes expanded?  Not counting the terminating NUL
 */
static size_t
lwsws_string_len(const char *s)
{
	const char *e;
	size_t esc = strlen(ESC_INSTALL_DATADIR), total = 0;

	while ((e = strstr(s, ESC_INSTALL_DATADIR)) != NULL) {
		total += (size_t)(e - s) + strlen(LWS_INSTALL_DATADIR);
		s = e + esc;
	}

	return total + strlen(s);
}

static int
arg_to_bool(const char *s)
{
	static const char * const on[] = { "on", "yes", "true" };
	int n = atoi(s);

	if (n)
		return 1;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(on); n++)
		if (!strcasecmp(s, on[n]))
			return 1;

	return 0;
}

static void
set_reset_flag(uint64_t *p, const char *state, uint64_t flag)
{
	if (arg_to_bool(state))
		*p |= flag;
	else
		*p &= ~(flag);
}

static signed char
lejp_globals_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;
	struct lws_protocol_vhost_options *rej;
	char *p;

	if (reason == LEJPCB_VAL_STR_START ||
	    reason == LEJPCB_VAL_STR_CHUNK ||
	    reason == LEJPCB_VAL_STR_END)
		if (lejp_string_unify_part(ctx, &a->ac, reason))
			return 1;

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	/* this catches, eg, global.reject-service-keywords[].xxx */
	if (reason == LEJPCB_VAL_STR_END &&
	    ctx->path_match == LWJPGP_REJECT_SERVICE_KEYWORDS_NAME + 1) {
		rej = lwsws_alloc(a, sizeof(*rej));
		if (!rej)
			return lwsws_exhausted(ctx);

		rej->name = lwsws_name(a, ctx, '\0');
		if (!rej->name)
			return lwsws_exhausted(ctx);

		rej->next = a->info->reject_service_keywords;
		a->info->reject_service_keywords = rej;
		// lwsl_notice("  adding rej %s=%s\n", rej->name, ctx->buf);
		rej->value = a->p;
		rej->options = NULL;
		goto dostring;
	}

	switch (ctx->path_match - 1) {
	case LEJPGP_UID:
		a->info->uid = (unsigned int)atoi(ctx->buf);
		return 0;
	case LEJPGP_GID:
		a->info->gid = (unsigned int)atoi(ctx->buf);
		return 0;
	case LEJPGP_USERNAME:
		a->info->username = a->p;
		break;
	case LEJPGP_GROUPNAME:
		a->info->groupname = a->p;
		break;
	case LEJPGP_COUNT_THREADS:
		a->info->count_threads = (unsigned int)atoi(ctx->buf);
		return 0;
	case LEJPGP_COUNT_ASYNC_THREADS:
#if defined(LWS_WITH_ASYNC_QUEUE)
		a->info->count_async_threads = (uint8_t)atoi(ctx->buf);
#endif
		return 0;
	case LWJPGP_INIT_SSL:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
		return 0;
	case LEJPGP_CPD_BYPASS:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_CPD_BYPASS;
		return 0;
	case LEJPGP_QUIC_PAD_CRYPTO:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_QUIC_PAD_CRYPTO;
		return 0;
	case LEJPGP_ALLOW_EARLY_DATA:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_ALLOW_EARLY_DATA;
		return 0;
	case LEJPGP_QUIC_ONLY_LATEST:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_QUIC_LATEST_VERSION;
		return 0;
	case LEJPGP_QUIC_EARLY_KEY_UPDATE:
		if (arg_to_bool(ctx->buf))
			a->info->options |= LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE;
		return 0;
	case LEJPGP_SERVER_STRING:
#if defined(LWS_WITH_SERVER)
		a->info->server_string = a->p;
#endif
		break;
	case LEJPGP_PLUGIN_DIR:
		if (a->count_plugin_dirs == MAX_PLUGIN_DIRS - 1) {
			lwsl_err("Too many plugin dirs\n");
			return -1;
		}
		a->plugin_dirs[a->count_plugin_dirs++] = a->p;
		break;

	case LWJPGP_PINGPONG_SECS: /* deprecated */
		return 0;

	case LWJPGP_TIMEOUT_SECS:
		a->info->timeout_secs = (unsigned int)atoi(ctx->buf);
		return 0;

#if defined(LWS_WITH_TLS)
	case LWJPGP_DEFAULT_ALPN:
		a->info->alpn = a->p;
		break;
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	case LWJPGP_IP_LIMIT_AH:
		a->info->ip_limit_ah = (uint16_t)atoi(ctx->buf);
		return 0;

	case LWJPGP_IP_LIMIT_WSI:
		a->info->ip_limit_wsi = (uint16_t)atoi(ctx->buf);
		return 0;
#endif

	case LWJPGP_FD_LIMIT_PT:
		a->info->rlimit_nofile = atoi(ctx->buf);
		return 0;

	default:
		return 0;
	}

dostring:
	/*
	 * The value string may have arrived in multiple chunks with any
	 * ${define} substitutions applied; only act on it as a whole at the
	 * string end
	 */
	if (reason == LEJPCB_VAL_STR_CHUNK) {
		a->chunk = 1;
		return 0;
	}

	if (reason == LEJPCB_VAL_STR_END) {
		if (lejp_string_unify(ctx, &a->ac))
			return lwsws_exhausted(ctx);
		p = ctx->su.fp;
	} else
		p = ctx->buf;

	a->chunk = 0;

	if (!lwsws_room(a, a->p, strlen(p) + 1))
		return lwsws_exhausted(ctx);

	a->p += lws_snprintf(a->p, lws_ptr_diff_size_t(a->end, a->p), "%s", p);
	*(a->p)++ = '\0';

	return 0;
}

static signed char
lejp_vhosts_cb(struct lejp_ctx *ctx, char reason)
{
	struct jpargs *a = (struct jpargs *)ctx->user;
	struct lws_protocol_vhost_options *mp_cgienv, *headers;
	struct lws_http_mount *m;
	char *p, *p1;
	int n;

	if (reason == LEJPCB_VAL_STR_START ||
	    reason == LEJPCB_VAL_STR_CHUNK ||
	    reason == LEJPCB_VAL_STR_END)
		if (lejp_string_unify_part(ctx, &a->ac, reason))
			return 1;

#if 0
	lwsl_notice(" %d: %s (%d)\n", reason, ctx->path, ctx->path_match);
	for (n = 0; n < ctx->wildcount; n++)
		lwsl_notice("    %d\n", ctx->wild[n]);
#endif

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == LEJPVP + 1) {
		uint64_t i[4];
#if defined(LWS_WITH_SERVER)
		const char *ss;
#endif

		/* set the defaults for this vhost */
		a->reject_ws_with_no_protocol = 0;
		a->valid = 1;
		a->head = NULL;
		a->last = NULL;

		i[0] = a->info->count_threads;
		i[1] = a->info->options & (
			LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME |
			LWS_SERVER_OPTION_LIBUV |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_UV_NO_SIGSEGV_SIGFPE_SPIN |
			LWS_SERVER_OPTION_LIBEVENT |
			LWS_SERVER_OPTION_QUIC_PAD_CRYPTO |
			LWS_SERVER_OPTION_ALLOW_EARLY_DATA |
			LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE |
			LWS_SERVER_OPTION_LIBEV
				);
#if defined(LWS_WITH_SERVER)
		ss = a->info->server_string;
#endif
		i[3] = a->info->timeout_secs;

		memset(a->info, 0, sizeof(*a->info));

		a->info->count_threads = (unsigned int)i[0];
		a->info->options = i[1];
#if defined(LWS_WITH_SERVER)
		a->info->server_string = ss;
#endif
		a->info->timeout_secs = (unsigned int)i[3];

		a->info->protocols = a->protocols;
		a->info->pprotocols = a->pprotocols;
#if defined(LWS_ROLE_WS)
		a->info->extensions = a->extensions;
#endif
               a->info->user = a->user;
#if defined(LWS_WITH_TLS)
#if defined(LWS_WITH_CLIENT)
#if defined(LWS_WITH_GNUTLS)
		a->info->client_ssl_cipher_list = "NORMAL";
#else
		a->info->client_ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
			"ECDHE-RSA-AES256-GCM-SHA384:"
			"DHE-RSA-AES256-GCM-SHA384:"
			"ECDHE-RSA-AES256-SHA384:"
			"HIGH:!aNULL:!eNULL:!EXPORT:"
			"!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
			"!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
			"!DHE-RSA-AES128-SHA256:"
			"!AES128-GCM-SHA256:"
			"!AES128-SHA256:"
			"!DHE-RSA-AES256-SHA256:"
			"!AES256-GCM-SHA384:"
			"!AES256-SHA256";
#endif
#endif
#if defined(LWS_WITH_SERVER)
#if defined(LWS_WITH_GNUTLS)
		a->info->ssl_cipher_list = "NORMAL";
#else
		a->info->ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
				       "ECDHE-RSA-AES256-GCM-SHA384:"
				       "DHE-RSA-AES256-GCM-SHA384:"
				       "ECDHE-RSA-AES256-SHA384:"
				       "HIGH:!aNULL:!eNULL:!EXPORT:"
				       "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
				       "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
				       "!DHE-RSA-AES128-SHA256:"
                                       "!ECDHE-RSA-AES128-GCM-SHA256:"
				       "!AES128-GCM-SHA256:"
				       "!AES128-SHA256:"
				       "!DHE-RSA-AES256-SHA256:"
				       "!AES256-GCM-SHA384:"
                                       "!AES256-SHA256:"
                                       "!CAMELLIA128:!CAMELLIA256";
#endif
#endif
#endif
		a->info->keepalive_timeout = 5;
	}

#if defined(LWS_WITH_DHT)
	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match == LEJPVP_DHT + 1) {
		a->dht_active = 1;
		memset(&a->dht, 0, sizeof(a->dht));
		a->dht.port = 7682;
		a->dht.legacy = 1;
	}
#endif

	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match == LEJPVP_MOUNTS + 1) {
		a->fresh_mount = 1;
		memset(&a->m, 0, sizeof(a->m));
	}

	/* this catches, eg, vhosts[].ws-protocols[].xxx-protocol */
	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match == LEJPVP_PROTOCOL_NAME + 1) {
		a->pvo = lwsws_alloc(a, sizeof(*a->pvo));
		if (!a->pvo)
			return lwsws_exhausted(ctx);

		a->pvo->name = lwsws_name(a, ctx, '\0');
		if (!a->pvo->name)
			return lwsws_exhausted(ctx);

		/* ie, enable this protocol, no options yet */
		a->pvo->next = a->info->pvo;
		a->info->pvo = a->pvo;
		lwsl_info("  adding protocol %s\n", a->pvo->name);
		a->pvo->value = a->p;
		a->pvo->options = NULL;
		goto dostring;
	}

	/* this catches, eg, vhosts[].headers[].xxx */
	if ((reason == LEJPCB_VAL_STR_END || reason == LEJPCB_VAL_STR_CHUNK) &&
	    ctx->path_match == LEJPVP_HEADERS_NAME + 1) {

		if (!a->chunk) {
			headers = lwsws_alloc(a, sizeof(*headers));
			if (!headers)
				return lwsws_exhausted(ctx);

			headers->name = lwsws_name(a, ctx, ':');
			if (!headers->name)
				return lwsws_exhausted(ctx);

			/* ie, add this header */
			headers->next = a->info->headers;
			a->info->headers = headers;

			lwsl_notice("  adding header %s=%s\n", headers->name,
				    ctx->buf);
			headers->value = a->p;
			headers->options = NULL;
		}
		a->chunk = reason == LEJPCB_VAL_STR_CHUNK;
		goto dostring;
	}

	/* this catches, eg, vhosts[].mount[].headers[].xxx */
	if ((reason == LEJPCB_VAL_STR_END || reason == LEJPCB_VAL_STR_CHUNK) &&
	    ctx->path_match == LEJPVP_MOUNTPOINT_HEADERS_NAME + 1) {

		if (!a->chunk) {
			headers = lwsws_alloc(a, sizeof(*headers));
			if (!headers)
				return lwsws_exhausted(ctx);

			headers->name = lwsws_name(a, ctx, ':');
			if (!headers->name)
				return lwsws_exhausted(ctx);

			/* ie, add this header */
			/* linked-list of pvos start held in a->pvo_mp */
			headers->next = a->pvo_mp;
			a->pvo_mp = headers;

			lwsl_notice("  adding header %s=%s\n", headers->name,
				    ctx->buf);
			headers->value = a->p;
			headers->options = NULL;
		}
		a->chunk = reason == LEJPCB_VAL_STR_CHUNK;
		goto dostring;
	}


	if (reason == LEJPCB_OBJECT_END &&
	    (ctx->path_match == LEJPVP + 1 || !ctx->path[0]) &&
	    a->valid) {

		struct lws_vhost *vhost;

		//lwsl_notice("%s\n", ctx->path);
		if (!a->info->port &&
		    !(a->info->options & LWS_SERVER_OPTION_UNIX_SOCK)) {
			lwsl_err("Port required (eg, 443)\n");
			return 1;
		}
		a->valid = 0;
		a->info->mounts = a->head;

		vhost = lws_create_vhost(a->context, a->info);
		if (!vhost) {
			lwsl_err("Failed to create vhost %s\n",
				 a->info->vhost_name);
			return 1;
		}
		a->any_vhosts = 1;

		if (a->reject_ws_with_no_protocol) {
			a->reject_ws_with_no_protocol = 0;

			vhost->default_protocol_index = 255;
		}

#if defined(LWS_WITH_TLS) && defined(LWS_WITH_CLIENT)
		if (a->enable_client_ssl) {
			const char *cert_filepath =
					a->info->client_ssl_cert_filepath;
			const char *private_key_filepath =
				       a->info->client_ssl_private_key_filepath;
			const char *ca_filepath =
					a->info->client_ssl_ca_filepath;
			const char *cipher_list =
					a->info->client_ssl_cipher_list;

			memset(a->info, 0, sizeof(*a->info));
			a->info->client_ssl_cert_filepath = cert_filepath;
			a->info->client_ssl_private_key_filepath =
							private_key_filepath;
			a->info->client_ssl_ca_filepath = ca_filepath;
			a->info->client_ssl_cipher_list = cipher_list;
			a->info->options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			lws_init_vhost_client_ssl(a->info, vhost);
		}
#endif

#if defined(LWS_WITH_DHT)
		{
			struct jpargs_dht_list *d = a->dht_head;
			while (d) {
				d->info.vhost = vhost;
				if (!lws_dht_create(&d->info))
					lwsl_err("Failed to create DHT\n");
				d = d->next;
			}
			a->dht_head = a->dht_last = NULL;
		}
#endif

		return 0;
	}

#if defined(LWS_WITH_DHT)
	if (reason == LEJPCB_OBJECT_END &&
	    ctx->path_match == LEJPVP_DHT + 1) {
		struct jpargs_dht_list *d;

		if (!a->dht_active)
			return 0;

		d = lwsws_alloc(a, sizeof(*d));
		if (!d)
			return lwsws_exhausted(ctx);

		d->info = a->dht;
		d->next = NULL;

		if (a->dht_last)
			a->dht_last->next = d;
		else
			a->dht_head = d;

		a->dht_last = d;
		a->dht_active = 0;
	}
#endif

	if (reason == LEJPCB_OBJECT_END &&
	    ctx->path_match == LEJPVP_MOUNTS + 1) {
		static const char * const mount_protocols[] = {
			"http://",
			"https://",
			"file://",
			"cgi://",
			">http://",
			">https://",
			"callback://",
			"gzip://",
		};

		if (!a->fresh_mount)
			return 0;

		if (!a->m.mountpoint || !a->m.origin) {
			lwsl_err("mountpoint and origin required\n");
			return 1;
		}
		lwsl_debug("adding mount %s\n", a->m.mountpoint);
		m = lwsws_alloc(a, sizeof(*m));
		if (!m)
			return lwsws_exhausted(ctx);

		memcpy(m, &a->m, sizeof(*m));
		if (a->last)
			a->last->mount_next = m;

		for (n = 0; n < (int)LWS_ARRAY_SIZE(mount_protocols); n++)
			if (!strncmp(a->m.origin, mount_protocols[n],
			     strlen(mount_protocols[n]))) {
				lwsl_info("----%s\n", a->m.origin);
				m->origin_protocol = (uint8_t)(unsigned int)n;
				m->origin = a->m.origin +
					    strlen(mount_protocols[n]);
				break;
			}

		if (n == (int)LWS_ARRAY_SIZE(mount_protocols)) {
			lwsl_err("unsupported protocol:// %s\n", a->m.origin);
			return 1;
		}

		/* attach the tree of mountpoint headers, if any */
		m->headers = a->pvo_mp;
		a->pvo_mp = NULL;

		if (!a->head)
			a->head = m;

		a->last = m;
		a->fresh_mount = 0;
	}

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
#if defined(LWS_WITH_DHT)
	case LEJPVP_DHT_V:
		a->dht.v = a->p;
		break;
	case LEJPVP_DHT_NAME:
		a->dht.name = a->p;
		break;
	case LEJPVP_DHT_PORT:
		a->dht.port = atoi(ctx->buf);
		return 0;
	case LEJPVP_DHT_IPV6:
		a->dht.ipv6 = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_DHT_HASH:
		if (!strcmp(ctx->buf, "sha1")) {
			a->dht.aux = LWS_DHT_HASH_TYPE_SHA1;
			a->dht.legacy = 0;
		} else if (!strcmp(ctx->buf, "sha256")) {
			a->dht.aux = LWS_DHT_HASH_TYPE_SHA256;
			a->dht.legacy = 0;
		} else if (!strcmp(ctx->buf, "sha512")) {
			a->dht.aux = LWS_DHT_HASH_TYPE_SHA512;
			a->dht.legacy = 0;
		} else if (!strcmp(ctx->buf, "blake3")) {
			a->dht.aux = LWS_DHT_HASH_TYPE_BLAKE3;
			a->dht.legacy = 0;
		}
		return 0;
#endif
	case LEJPVP_NAME:
		a->info->vhost_name = a->p;
		break;
	case LEJPVP_PORT:
		a->info->port = atoi(ctx->buf);
		return 0;
	case LEJPVP_INTERFACE:
		a->info->iface = a->p;
		break;
	case LEJPVP_UNIXSKT:
		if (arg_to_bool(ctx->buf))
			a->info->options |= (uint64_t)LWS_SERVER_OPTION_UNIX_SOCK;
		else
			a->info->options &= (uint64_t)~(LWS_SERVER_OPTION_UNIX_SOCK);
		return 0;
	case LEJPVP_UNIXSKT_PERMS:
		a->info->unix_socket_perms = a->p;
		break;
	case LEJPVP_STS:
		if (arg_to_bool(ctx->buf))
			a->info->options |= (uint64_t)LWS_SERVER_OPTION_STS;
		else
			a->info->options &= (uint64_t)~(LWS_SERVER_OPTION_STS);
		return 0;
#if defined(LWS_WITH_TLS)
	case LEJPVP_HOST_SSL_KEY:
		a->info->ssl_private_key_filepath = a->p;
		break;
	case LEJPVP_HOST_SSL_CERT:
		a->info->ssl_cert_filepath = a->p;
		break;
	case LEJPVP_HOST_SSL_CA:
		a->info->ssl_ca_filepath = a->p;
		break;
#endif
	case LEJPVP_ACCESS_LOG:
		a->info->log_filepath = a->p;
		break;
	case LEJPVP_MOUNTPOINT:
		a->m.mountpoint = a->p;
		a->m.mountpoint_len = (unsigned char)strlen(ctx->buf);
		break;
	case LEJPVP_ORIGIN:
		if (!strncmp(ctx->buf, "callback://", 11))
			a->m.protocol = a->p + 11;

		if (!a->m.origin)
			a->m.origin = a->p;
		break;
	case LEJPVP_DEFAULT:
		a->m.def = a->p;
		break;
	case LEJPVP_DEFAULT_AUTH_MASK:
		a->m.auth_mask = (unsigned int)atoi(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_CACHE_MAX_AGE:
		a->m.cache_max_age = atoi(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_CACHE_REUSE:
		a->m.cache_reusable = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_CACHE_REVALIDATE:
		a->m.cache_revalidate = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_CACHE_NO:
		a->m.cache_no = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_EXACT_MATCH:
		a->m.exact_match = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_APPEND_PATH:
		a->m.append_path = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_NO_WS_UPGRADES:
		a->m.no_ws_upgrades = !!arg_to_bool(ctx->buf);
		return 0;
	case LEJPVP_MOUNT_CACHE_INTERMEDIARIES:
		a->m.cache_intermediaries = !!arg_to_bool(ctx->buf);;
		return 0;
	case LEJPVP_MOUNT_BASIC_AUTH:
#if defined(LWS_WITH_HTTP_BASIC_AUTH)
		a->m.basic_auth_login_file = a->p;
#endif
		break;
	case LEJPVP_CGI_TIMEOUT:
		a->m.cgi_timeout = atoi(ctx->buf);
		return 0;
	case LWJPVP_FO_LISTEN_QUEUE:
		a->info->fo_listen_queue = atoi(ctx->buf);
		return 0;
	case LEJPVP_KEEPALIVE_TIMEOUT:
		a->info->keepalive_timeout = atoi(ctx->buf);
		return 0;
	case LEJPVP_MOUNTPOINT_KEEPALIVE_TIMEOUT:
		a->m.keepalive_timeout = (unsigned int)atoi(ctx->buf);
		return 0;
#if defined(LWS_WITH_JOSE)
	case LEJPVP_MOUNT_INTERCEPTOR_PATH:
		a->m.interceptor_path = a->p;
		break;
#endif
#if defined(LWS_WITH_TLS)
#if defined(LWS_WITH_CLIENT)
	case LEJPVP_CLIENT_CIPHERS:
		a->info->client_ssl_cipher_list = a->p;
		break;
	case LEJPVP_CLIENT_TLS13_CIPHERS:
		a->info->client_tls_1_3_plus_cipher_list = a->p;
		break;
	case LEJPVP_CLIENT_ECDH_CURVE:
		a->info->client_ecdh_curve = a->p;
		break;
#endif

	case LEJPVP_CIPHERS:
		a->info->ssl_cipher_list = a->p;
		break;
	case LEJPVP_TLS13_CIPHERS:
		a->info->tls1_3_plus_cipher_list = a->p;
		break;
	case LEJPVP_ECDH_CURVE:
		a->info->ecdh_curve = a->p;
		break;
#endif
	case LEJPVP_PMO:
	case LEJPVP_CGI_ENV:
		if (a->chunk)
			goto dostring;

		mp_cgienv = lwsws_alloc(a, sizeof(*mp_cgienv));
		if (!mp_cgienv)
			return lwsws_exhausted(ctx);

		mp_cgienv->name = lwsws_name(a, ctx, '\0');
		if (!mp_cgienv->name)
			return lwsws_exhausted(ctx);

		mp_cgienv->next = a->m.cgienv;
		a->m.cgienv = mp_cgienv;
		mp_cgienv->value = a->p;
		mp_cgienv->options = NULL;
		//lwsl_notice("    adding pmo / cgi-env '%s' = '%s'\n",
		//		mp_cgienv->name, mp_cgienv->value);
		goto dostring;

	case LEJPVP_PROTOCOL_NAME_OPT:
	{
		struct lws_protocol_vhost_options *pvo_parent = a->pvo;
		struct lws_protocol_vhost_options *pvo_cur;
		int wild1 = ctx->wild[1];
		int lvl_start = 1;
		int lvl, start, len, next_p;
		char key_buf[128];

		if (a->chunk)
			goto dostring;

		/* Find the largest stack level that is <= wild1 */
		for (lvl = 1; lvl < ctx->sp; lvl++) {
			int p = (unsigned char)ctx->st[lvl].p;
			if (p <= wild1) {
				lvl_start = lvl;
			} else {
				break;
			}
		}

		/* Iterate through the stack to build the PVO tree */
		for (lvl = lvl_start; lvl < ctx->sp; lvl++) {
			start = (unsigned char)ctx->st[lvl].p;
			next_p = (lvl + 1 < ctx->sp) ? (unsigned char)ctx->st[lvl+1].p : (int)strlen(ctx->path);

			if (next_p <= start)
				continue; /* Skip empty or invalid levels (e.g. string value level) */

			if (ctx->path[start] == '.')
				start++;

			if (next_p <= start)
				continue;

			len = next_p - start;
			if (ctx->path[next_p - 1] == '.')
				len--; /* Exclude the trailing dot */

			if (len <= 0)
				continue;

			if (len >= (int)sizeof(key_buf))
				len = sizeof(key_buf) - 1;

			memcpy(key_buf, &ctx->path[start], (size_t)len);
			key_buf[len] = '\0';

			/* Find or create the PVO at this level */
			pvo_cur = (struct lws_protocol_vhost_options *)pvo_parent->options;
			while (pvo_cur && strcmp(pvo_cur->name, key_buf)) {
				pvo_cur = (struct lws_protocol_vhost_options *)pvo_cur->next;
			}

			if (!pvo_cur) {
				size_t kl = strlen(key_buf) + 1;
				char *nm;

				pvo_cur = lwsws_alloc(a, sizeof(*pvo_cur));
				if (!pvo_cur)
					return lwsws_exhausted(ctx);

				/* the pvo member is const; copy via a
				 * writable handle */
				nm = lwsws_alloc(a, kl);
				if (!nm)
					return lwsws_exhausted(ctx);
				memcpy(nm, key_buf, kl);
				pvo_cur->name = nm;

				pvo_cur->value = NULL;
				pvo_cur->options = NULL;

				/* Link into parent's options */
				pvo_cur->next = pvo_parent->options;
				pvo_parent->options = pvo_cur;
			}

			pvo_parent = pvo_cur;
		}

		/* The last created PVO is the leaf node. Value goes here via dostring */
		if (pvo_parent)
			pvo_parent->value = a->p;

		goto dostring;
	}

	case LEJPVP_MOUNT_EXTRA_MIMETYPES:
		if (a->chunk)
			goto dostring;

		a->pvo_em = lwsws_alloc(a, sizeof(*a->pvo_em));
		if (!a->pvo_em)
			return lwsws_exhausted(ctx);

		a->pvo_em->name = lwsws_name(a, ctx, '\0');
		if (!a->pvo_em->name)
			return lwsws_exhausted(ctx);

		/* ie, enable this protocol, no options yet */
		a->pvo_em->next = a->m.extra_mimetypes;
		a->m.extra_mimetypes = a->pvo_em;
		lwsl_notice("  + extra-mimetypes %s -> %s\n", a->pvo_em->name,
			    ctx->buf);
		a->pvo_em->value = a->p;
		a->pvo_em->options = NULL;
		goto dostring;

	case LEJPVP_MOUNT_INTERPRET:
		if (a->chunk)
			goto dostring;

		a->pvo_int = lwsws_alloc(a, sizeof(*a->pvo_int));
		if (!a->pvo_int)
			return lwsws_exhausted(ctx);

		a->pvo_int->name = lwsws_name(a, ctx, '\0');
		if (!a->pvo_int->name)
			return lwsws_exhausted(ctx);

		/* ie, enable this protocol, no options yet */
		a->pvo_int->next = a->m.interpret;
		a->m.interpret = a->pvo_int;
		lwsl_notice("  adding interpret %s -> %s\n", a->pvo_int->name,
			    ctx->buf);
		a->pvo_int->value = a->p;
		a->pvo_int->options = NULL;
		goto dostring;

	case LEJPVP_CGI_CHROOT:
		a->m.cgi_chroot_path = a->p;
		break;

	case LEJPVP_CGI_CHDIR:
		a->m.cgi_wd = a->p;
		break;

	case LEJPVP_ENABLE_CLIENT_SSL:
		a->enable_client_ssl = !!arg_to_bool(ctx->buf);
		return 0;
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_CLIENT)
	case LEJPVP_CLIENT_SSL_KEY:
		a->info->client_ssl_private_key_filepath = a->p;
		break;
	case LEJPVP_CLIENT_SSL_CERT:
		a->info->client_ssl_cert_filepath = a->p;
		break;
	case LEJPVP_CLIENT_SSL_CA:
		a->info->client_ssl_ca_filepath = a->p;
		break;
#endif

	case LEJPVP_NOIPV6:
		set_reset_flag(&a->info->options, ctx->buf,
			       LWS_SERVER_OPTION_DISABLE_IPV6);
		return 0;

	case LEJPVP_FLAG_ONLYRAW:
		set_reset_flag(&a->info->options, ctx->buf,
			    LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG);
		return 0;

	case LEJPVP_IPV6ONLY:
		a->info->options |= LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY;
		set_reset_flag(&a->info->options, ctx->buf,
			       LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
		return 0;

	case LEJPVP_FLAG_CLIENT_CERT_REQUIRED:
		if (arg_to_bool(ctx->buf))
			a->info->options |=
			    LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
		return 0;

	case LEJPVP_IGNORE_MISSING_CERT:
		set_reset_flag(&a->info->options, ctx->buf,
				LWS_SERVER_OPTION_IGNORE_MISSING_CERT);
		return 0;

	case LEJPVP_FLAG_STRICT_HOST_CHECK:
		set_reset_flag(&a->info->options, ctx->buf,
			LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK);
		return 0;

	case LEJPVP_ERROR_DOCUMENT_404:
		a->info->error_document_404 = a->p;
		break;

#if defined(LWS_WITH_TLS)
	case LEJPVP_SSL_OPTION_SET:
		a->info->ssl_options_set |= atol(ctx->buf);
		return 0;
	case LEJPVP_SSL_OPTION_CLEAR:
		a->info->ssl_options_clear |= atol(ctx->buf);
		return 0;

#if defined(LWS_WITH_CLIENT)
	case LEJPVP_SSL_CLIENT_OPTION_SET:
		a->info->ssl_client_options_set |= atol(ctx->buf);
		return 0;
	case LEJPVP_SSL_CLIENT_OPTION_CLEAR:
		a->info->ssl_client_options_clear |= atol(ctx->buf);
		return 0;
#endif

	case LEJPVP_ALPN:
		a->info->alpn = a->p;
		break;
	case LEJPVP_QUIC_MTU:
		a->info->quic_mtu = (uint32_t)atoi(ctx->buf);
		return 0;
	case LEJPVP_QUIC_PREFERRED_ADDRESSES:
		a->info->quic_preferred_addresses = a->p;
		lwsl_notice("Parsed quic-preferred-addresses: %s\n", a->p);
		break;
#endif

	case LEJPVP_LISTEN_ACCEPT_ROLE:
		a->info->listen_accept_role = a->p;
		break;
	case LEJPVP_LISTEN_ACCEPT_PROTOCOL:
		a->info->listen_accept_protocol = a->p;
		break;

	case LEJPVP_FLAG_APPLY_LISTEN_ACCEPT:
		set_reset_flag(&a->info->options, ctx->buf,
			LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG);
		return 0;
	case LEJPVP_FLAG_FALLBACK_LISTEN_ACCEPT:
		lwsl_notice("vh %s: LEJPVP_FLAG_FALLBACK_LISTEN_ACCEPT: %s\n",
			    a->info->vhost_name, ctx->buf);
		set_reset_flag(&a->info->options, ctx->buf,
		      LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG);
		return 0;
	case LEJPVP_FLAG_ALLOW_NON_TLS:
		set_reset_flag(&a->info->options, ctx->buf,
			       LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT);
		return 0;
	case LEJPVP_FLAG_REDIRECT_HTTP:
		set_reset_flag(&a->info->options, ctx->buf,
			       LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS);
		return 0;
	case LEJPVP_FLAG_ALLOW_HTTP_ON_HTTPS:
		set_reset_flag(&a->info->options, ctx->buf,
			       LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER);
		return 0;

	case LEJPVP_FLAG_DISABLE_NO_PROTOCOL_WS_UPGRADES:
		a->reject_ws_with_no_protocol = 1;
		return 0;

	case LEJPVP_FLAG_H2_HALF_CLOSED_LONG_POLL:
		set_reset_flag(&a->info->options, ctx->buf,
				LWS_SERVER_OPTION_VH_H2_HALF_CLOSED_LONG_POLL);
		return 0;

	default:
		return 0;
	}

dostring:
	if (reason == LEJPCB_VAL_STR_CHUNK) {
		a->chunk = 1;
		return 0;
	}

	if (reason == LEJPCB_VAL_STR_END) {
		lejp_string_unify(ctx, &a->ac);
		p = ctx->su.fp;
	} else
		p = ctx->buf;

	a->chunk = 0;

	if (!p)
		return 0;

	if (reason != LEJPCB_VAL_STR_END)
		p[LEJP_STRING_CHUNK] = '\0';

	/* the whole value string, with any datadir escapes expanded, has to
	 * fit in what's left of the arena or the parse fails loudly... this
	 * also stops a->p from ever being able to advance past a->end and
	 * turning the bounded copies below into unbounded ones
	 */

	if (!lwsws_room(a, a->p, lwsws_string_len(p) + 1))
		return lwsws_exhausted(ctx);

	p1 = (char *)strstr(p, ESC_INSTALL_DATADIR);
	if (p1) {
		n = lws_ptr_diff(p1, p);
		lws_strncpy(a->p, p, (unsigned int)n + 1u);
		a->p += n;
		a->p += lws_snprintf(a->p, lws_ptr_diff_size_t(a->end, a->p), "%s",
				     LWS_INSTALL_DATADIR);
		p += n + (int)strlen(ESC_INSTALL_DATADIR);
	}

	a->p += lws_snprintf(a->p, lws_ptr_diff_size_t(a->end, a->p), "%s", p);
	if (reason == LEJPCB_VAL_STR_END)
		*(a->p)++ = '\0';

	return 0;
}

/*
 * Scoped substitution preprocessing
 *
 * Pairs whose name starts with '=', like
 *
 *   "=PKI_ROOT": "/var/dnssec"
 *
 * are consumed here as scoped preprocessor defines and concealed from the
 * user callback.  String values have any ${NAME} sequences expanded from
 * the defines visible at that point, before the user callback sees them,
 *
 *   "pki-root": "${PKI_ROOT}/zone-master.key"
 *
 * A define is visible from where it is defined until the close of the JSON
 * object it was defined in; defines from enclosing objects stay visible and
 * may be shadowed by redefinition in an inner object.  The symbols defined
 * at each object nesting level live in a per-scope lwsac listed on a
 * per-scope dll2 owner, so closing the object just unpicks the owner and
 * destroys the lwsac.  Each config file is parsed with a fresh set of
 * defines, ie, root scope means "the rest of this file".
 *
 * lws_strexp is inherently incremental, so the substitution is applied to
 * the lejp string chunks as they are produced: the substituted result is
 * re-chunked into ctx->buf and passed on to the user callback using the
 * same chunking rules lejp itself uses.
 */

#define LEJP_CONF_SCOPE_DEPTH	16	/* tracked object nesting levels */
#define LEJP_CONF_NAME_MAX	31	/* matches lws_strexp name limit */
#define LEJP_CONF_EXP_BUF	512	/* strexp output scratch */
#define LEJP_CONF_LWSAC_CHUNK	512

struct lejp_conf_symbol {
	lws_dll2_t	list;		/* on the defining scope's owner */
	char		*value;		/* fully-substituted value, in scope ac */
	char		name[];		/* define name without the '=', in ac */
};

struct lejp_conf_scope {
	struct lwsac		*ac;	/* storage for symbols defined here */
	lws_dll2_owner_t	owner;	/* lejp_conf_symbol list on ac */
};

struct lejp_conf_subs {
	/* where preprocessed callbacks are forwarded */
	lejp_callback		 cb;
	void			 *user;

	struct lejp_conf_scope	 scopes[LEJP_CONF_SCOPE_DEPTH];
	int			 depth;		/* innermost scope is depth - 1 */
	int			 untracked;	/* object nesting beyond the
						 * tracked scope stack */

	/* substitution session for the string value being parsed */
	lws_strexp_t		 exp;
	char			 out[LEJP_CONF_EXP_BUF];

	/* "=name" pair whose value we are consuming */
	char			 pending_name[LEJP_CONF_NAME_MAX + 1];
	char			*pending_val;	/* substituted value assembly */
	size_t			 pending_len;
	size_t			 pending_alloc;

	unsigned char		 pending:1;
};

static signed char
lejp_conf_forward(struct lejp_conf_subs *subs, struct lejp_ctx *ctx,
		  char reason)
{
	signed char n;
	void *u = ctx->user;

	ctx->user = subs->user;
	n = subs->cb(ctx, reason);
	ctx->user = u;

	return n;
}

/* destroy everything related to defines, used at scope end and parse end */

static void
lejp_conf_subs_reset(struct lejp_conf_subs *subs)
{
	while (subs->depth > 0) {
		struct lejp_conf_scope *s = &subs->scopes[--subs->depth];

		lwsac_free(&s->ac);
		memset(s, 0, sizeof(*s));
	}
	subs->untracked = 0;

	if (subs->pending_val)
		lws_free(subs->pending_val);
	subs->pending_val = NULL;
	subs->pending_len = 0;
	subs->pending_alloc = 0;
	subs->pending = 0;
}

/*
 * Innermost scope first, and newest definition first within a scope, so
 * inner and later defines shadow outer and earlier ones
 */
static struct lejp_conf_symbol *
lejp_conf_sym_find(struct lejp_conf_subs *subs, const char *name)
{
	lws_dll2_t *d;
	int lvl;

	for (lvl = subs->depth; lvl > 0; lvl--)
		for (d = lws_dll2_get_tail(&subs->scopes[lvl - 1].owner); d;
		     d = lws_dll2_get_prev(d)) {
			struct lejp_conf_symbol *sym =
				lws_container_of(d, struct lejp_conf_symbol,
						 list);

			if (!strcmp(sym->name, name))
				return sym;
		}

	return NULL;
}

/* lws_strexp resolver: copy the symbol value out, resuming after FILLED_OUT */

static int
lejp_conf_sym_expand(void *priv, const char *name, char *out, size_t *pos,
		     size_t olen, size_t *exp_ofs)
{
	struct lejp_conf_subs *subs = (struct lejp_conf_subs *)priv;
	struct lejp_conf_symbol *sym = lejp_conf_sym_find(subs, name);
	size_t total, rem;

	if (!sym) {
		lwsl_err("%s: unknown conf symbol '${%s}'\n", __func__, name);

		return LSTRX_FATAL_NAME_UNKNOWN;
	}

	/* continue from where we left off last time */
	total = strlen(sym->value);
	rem = total - *exp_ofs;

	if (out) {
		const char *v = sym->value + *exp_ofs;

		/* leave the last byte for the NUL expand() adds itself */
		while (rem && *pos < olen - 1) {
			out[(*pos)++] = *v++;
			rem--;
		}
	}

	*exp_ofs = total - rem;

	return rem ? LSTRX_FILLED_OUT : LSTRX_DONE;
}

static int
lejp_conf_pending_append(struct lejp_conf_subs *subs, const char *in,
			 size_t len)
{
	size_t need = subs->pending_len + len + 1, alloc;
	char *np;

	if (need > subs->pending_alloc) {
		alloc = subs->pending_alloc ? subs->pending_alloc : 128;
		while (alloc < need)
			alloc <<= 1;

		np = lws_realloc(subs->pending_val, alloc, "lejp-conf-defval");
		if (!np)
			return -1;

		subs->pending_val = np;
		subs->pending_alloc = alloc;
	}

	memcpy(subs->pending_val + subs->pending_len, in, len);
	subs->pending_len += len;
	subs->pending_val[subs->pending_len] = '\0';

	return 0;
}

/* the define's string value completed: create its symbol in current scope */

static signed char
lejp_conf_define_complete(struct lejp_conf_subs *subs, struct lejp_ctx *ctx)
{
	struct lejp_conf_scope *s = &subs->scopes[subs->depth - 1];
	struct lejp_conf_symbol *sym;
	size_t nl = strlen(subs->pending_name);
	char *v;

	sym = lwsac_use_zero(&s->ac, sizeof(*sym) + nl + 1,
			     LEJP_CONF_LWSAC_CHUNK);
	v = lwsac_use(&s->ac, subs->pending_len + 1, LEJP_CONF_LWSAC_CHUNK);
	if (!sym || !v) {
		lwsl_err("%s: line %u: OOM creating define '%s'\n", __func__,
			 ctx->line, subs->pending_name);

		return -1;
	}

	memcpy(sym->name, subs->pending_name, nl + 1);
	sym->value = v;
	memcpy(v, subs->pending_val, subs->pending_len);
	v[subs->pending_len] = '\0';

	lws_dll2_add_tail(&sym->list, &s->owner);

	subs->pending = 0;
	subs->pending_len = 0;

	return 0;
}

/*
 * Substitute lejp's current string chunk in ctx->buf / ctx->npos.  If we
 * are consuming a define, the result is accumulated as the define value,
 * otherwise it is re-chunked into ctx->buf and passed on to the user
 * callback.  The final piece of the final chunk is passed on using the
 * reason we got, so the user callback sees the string end exactly once, and
 * never sees a chunk piece larger than lejp's own.
 */
static signed char
lejp_conf_str_chunk(struct lejp_conf_subs *subs, struct lejp_ctx *ctx,
		    char reason)
{
	char insp[LEJP_STRING_CHUNK];
	const char *in = insp;
	size_t in_len = ctx->npos, used_in, used_out;
	int n, final;
	signed char ret;

	/*
	 * The re-chunked output goes into ctx->buf, so the input needs its
	 * own copy for when the out buffer fills mid-chunk and we continue
	 * from where we left off
	 */
	assert(in_len <= sizeof(insp));
	memcpy(insp, ctx->buf, in_len);

	do {
		n = lws_strexp_expand(&subs->exp, in, in_len, &used_in,
				      &used_out);
		if (n < 0) {
			lwsl_err("%s: line %u: substitution failed\n",
				 __func__, ctx->line);

			return -1;
		}

		final = (n == LSTRX_DONE && reason == LEJPCB_VAL_STR_END);

		if (subs->pending) {
			if (lejp_conf_pending_append(subs, subs->out, used_out))
				return -1;

			if (final && lejp_conf_define_complete(subs, ctx))
				return -1;
		} else {
			size_t ofs = 0;

			/* an empty, non-final piece needs nothing passing on */
			if (!used_out && !final)
				goto filled;

			for (;;) {
				size_t m = used_out - ofs;

				if (m > LEJP_STRING_CHUNK)
					m = LEJP_STRING_CHUNK;

				memcpy(ctx->buf, subs->out + ofs, m);
				ctx->npos = (uint8_t)m;
				ctx->buf[m] = '\0';

				ret = lejp_conf_forward(subs, ctx,
						(final && ofs + m == used_out) ?
							reason :
							LEJPCB_VAL_STR_CHUNK);
				if (ret)
					return ret;

				ofs += m;
				if (ofs == used_out)
					break;
			}
		}
filled:
		/*
		 * used_out counts from the last out buffer reset, so it
		 * must be reset after every emit, not only when it filled
		 */
		lws_strexp_reset_out(&subs->exp, subs->out,
				     sizeof(subs->out));
		if (n == LSTRX_FILLED_OUT) {
			in += used_in;
			in_len -= used_in;
		}
	} while (n == LSTRX_FILLED_OUT);

	return 0;
}

/* lejp callback performing the scoped define preprocessing */

static signed char
lejp_conf_preproc_cb(struct lejp_ctx *ctx, char reason)
{
	struct lejp_conf_subs *subs = (struct lejp_conf_subs *)ctx->user;
	unsigned char nm_ofs;
	char *nm;
	size_t nl;

	if (subs->pending) {
		/* the define's value must be a string, and stays concealed */
		switch (reason) {
		case LEJPCB_VAL_STR_START:
			lws_strexp_init(&subs->exp, subs, lejp_conf_sym_expand,
					subs->out, sizeof(subs->out));
			return 0;
		case LEJPCB_VAL_STR_CHUNK:
		case LEJPCB_VAL_STR_END:
			return lejp_conf_str_chunk(subs, ctx, reason);
		case LEJPCB_FAILED:
		case LEJPCB_DESTRUCTED:
			lejp_conf_subs_reset(subs);
			return lejp_conf_forward(subs, ctx, reason);
		default:
			lwsl_err("%s: line %u: define '%s': value must be a "
				 "string\n", __func__, ctx->line,
				 subs->pending_name);
			return -1;
		}
	}

	switch (reason) {
	case LEJPCB_CONSTRUCTED:
	case LEJPCB_DESTRUCTED:
	case LEJPCB_FAILED:
		/* defines only live for a single parse */
		lejp_conf_subs_reset(subs);
		break;

	case LEJPCB_OBJECT_START:
		if (subs->depth == LEJP_CONF_SCOPE_DEPTH) {
			/* objects nested deeper than we track scopes for */
			subs->untracked++;
			break;
		}
		memset(&subs->scopes[subs->depth], 0,
		       sizeof(subs->scopes[0]));
		subs->depth++;
		break;

	case LEJPCB_OBJECT_END:
		if (subs->untracked)
			subs->untracked--;
		else
			if (subs->depth) {
				struct lejp_conf_scope *s =
					&subs->scopes[--subs->depth];

				lwsac_free(&s->ac);
				memset(s, 0, sizeof(*s));
			}
		break;

	case LEJPCB_PAIR_NAME:
		/* the new pair name is at the end of ctx->path[] */
		nm_ofs = (unsigned char)ctx->st[ctx->sp].p;
		nm = &ctx->path[nm_ofs];
		nl = (size_t)(ctx->pst[ctx->pst_sp].ppos - nm_ofs);

		if (*nm != '=')
			break;

		if (subs->untracked || !subs->depth) {
			lwsl_err("%s: line %u: define nested too deeply\n",
				 __func__, ctx->line);
			return -1;
		}

		nm++;
		nl--;

		if (!nl || nl > LEJP_CONF_NAME_MAX ||
		    strspn(nm, "abcdefghijklmnopqrstuvwxyz"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != nl) {
			lwsl_err("%s: line %u: invalid define name\n",
				 __func__, ctx->line);
			return -1;
		}

		memcpy(subs->pending_name, nm, nl);
		subs->pending_name[nl] = '\0';
		subs->pending = 1;

		return 0;	/* concealed from the user callback */

	case LEJPCB_VAL_STR_START:
		lws_strexp_init(&subs->exp, subs, lejp_conf_sym_expand,
				subs->out, sizeof(subs->out));
		break;

	case LEJPCB_VAL_STR_CHUNK:
	case LEJPCB_VAL_STR_END:
		return lejp_conf_str_chunk(subs, ctx, reason);

	default:
		break;
	}

	return lejp_conf_forward(subs, ctx, reason);
}

/*
 * returns 0 = OK, 1 = can't open, 2 = parsing error
 */

static int
lwsws_get_config(void *user, const char *f, const char * const *paths,
		 int count_paths, lejp_callback cb)
{
	unsigned char buf[128];
	struct lejp_ctx ctx;
	struct lejp_conf_subs subs;
	int n, m = 0, fd;

	memset(&ctx, 0, sizeof(ctx));
	memset(&subs, 0, sizeof(subs));
	subs.cb = cb;
	subs.user = user;

	fd = lws_open(f, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", f);
		return 2;
	}
	lwsl_info("%s: %s\n", __func__, f);
	lejp_construct(&ctx, lejp_conf_preproc_cb, &subs, paths,
		       (uint8_t)(unsigned int)count_paths);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (!n)
			break;
		// write(2, buf, (size_t)n);
		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);
	n = (int32_t)ctx.line;
	lejp_destruct(&ctx);

	if (m < 0) {
		lwsl_err("%s(%u): parsing error %d: %s\n", f, n, m,
			 lejp_error_to_string(m));
		return 2;
	}

	return 0;
}

struct lws_dir_args {
	void *user;
	const char * const *paths;
	int count_paths;
	lejp_callback cb;
};

static int
lwsws_get_config_d_cb(const char *dirpath, void *user,
		      struct lws_dir_entry *lde)
{
	struct lws_dir_args *da = (struct lws_dir_args *)user;
	char path[256];

	if (lde->type != LDOT_FILE && lde->type != LDOT_UNKNOWN /* ZFS */)
		return 0;

	lws_snprintf(path, sizeof(path) - 1, "%s/%s", dirpath, lde->name);

	return lwsws_get_config(da->user, path, da->paths,
				da->count_paths, da->cb);
}

int
lwsws_get_config_globals(struct lws_context_creation_info *info, const char *d,
			 char **cs, int *len)
{
	struct lws_dir_args da;
	struct jpargs a;
#if defined(LWS_WITH_PLUGINS)
	const char * const *old = info->plugin_dirs;
#endif
	char dd[128];

	memset(&a, 0, sizeof(a));

	a.info = info;
	a.p = *cs;
	a.end = (a.p + *len) - 1;
	a.valid = 0;

	a.plugin_dirs = lwsws_alloc(&a, MAX_PLUGIN_DIRS * sizeof(void *)); /* writeable version */
	if (!a.plugin_dirs) {
		lwsl_err("config strings arena too small\n");
		return 1;
	}
#if defined(LWS_WITH_PLUGINS)
	info->plugin_dirs = (void *)a.plugin_dirs;
#endif

#if defined(LWS_WITH_PLUGINS)
	/* copy any default paths */

	while (old && *old) {
		a.plugin_dirs[a.count_plugin_dirs++] = *old;
		old++;
	}
#endif

	lws_snprintf(dd, sizeof(dd) - 1, "%s/conf", d);
	if (lwsws_get_config(&a, dd, paths_global,
			     LWS_ARRAY_SIZE(paths_global), lejp_globals_cb) > 1)
		return 1;
	lws_snprintf(dd, sizeof(dd) - 1, "%s/conf.d", d);

	da.user = &a;
	da.paths = paths_global;
	da.count_paths = LWS_ARRAY_SIZE(paths_global),
	da.cb = lejp_globals_cb;

	/*
	 * lws_dir() returns 0 if our callback asked to stop, which it does
	 * by returning nonzero when a conf.d file could not be parsed
	 */
	if (!lws_dir(dd, &da, lwsws_get_config_d_cb))
		return 1;

	a.plugin_dirs[a.count_plugin_dirs] = NULL;

	lwsac_free(&a.ac);

	*cs = a.p;
	*len = lws_ptr_diff(a.end, a.p);

	return 0;
}

#if 0
typedef struct lws_retry_bo {
        const uint32_t  *retry_ms_table;           /* base delay in ms */
        uint16_t        retry_ms_table_count;      /* entries in table */
        uint16_t        conceal_count;             /* max retries to conceal */
        uint16_t        secs_since_valid_ping;     /* idle before PING issued */
        uint16_t        secs_since_valid_hangup;   /* idle before hangup conn */
        uint8_t         jitter_percent;         /* % additional random jitter */
} lws_retry_bo_t;
#endif

static const uint32_t rmst[] = { 1000, 2000, 5000, 10000, 30000 };

static const lws_retry_bo_t rebo = {
	.retry_ms_table			= rmst,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(rmst),
	.conceal_count			= 2,
	.secs_since_valid_ping		= 15,
	.secs_since_valid_hangup	= 20,
	.jitter_percent			= 25,
};

int
lwsws_get_config_vhosts(struct lws_context *context,
			struct lws_context_creation_info *info, const char *d,
			char **cs, int *len)
{
	struct lws_dir_args da;
	struct jpargs a;
	char dd[128];

	if (lws_cmdline_option_cx(context, "--lws-dht-dnssec-monitor-root") ||
	    lws_cmdline_option_cx(context, "--lws-stub")) {
		struct lws_context_creation_info i;

		lwsl_notice("%s: stub/monitor process: skipping vhost parsing\n", __func__);
		memset(&i, 0, sizeof(i));
		i.vhost_name = "stub-dummy";
		i.port = CONTEXT_PORT_NO_LISTEN;
		i.options = info->options | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT | LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
		i.protocols = info->protocols;
		i.pprotocols = info->pprotocols;
#if defined(LWS_ROLE_WS)
		i.extensions = info->extensions;
#endif
		struct lws_vhost *vh = lws_create_vhost(context, &i);
		if (!vh)
			return 1;

		lws_context_init_ssl_library(context, &i);
		lws_init_vhost_client_ssl(&i, vh);

		return 0;
	}

	memset(&a, 0, sizeof(a));

	a.info = info;
	if (!a.info->retry_and_idle_policy)
		a.info->retry_and_idle_policy = &rebo;
	a.p = *cs;
	a.end = a.p + *len;
	a.valid = 0;
	a.context = context;
	a.protocols = info->protocols;
       a.user = info->user;
	a.pprotocols = info->pprotocols;
#if defined(LWS_ROLE_WS)
	a.extensions = info->extensions;
#endif

	lws_snprintf(dd, sizeof(dd) - 1, "%s/conf", d);
	if (lwsws_get_config(&a, dd, paths_vhosts,
			     LWS_ARRAY_SIZE(paths_vhosts), lejp_vhosts_cb) > 1)
		return 1;
	lws_snprintf(dd, sizeof(dd) - 1, "%s/conf.d", d);

	da.user = &a;
	da.paths = paths_vhosts;
	da.count_paths = LWS_ARRAY_SIZE(paths_vhosts),
	da.cb = lejp_vhosts_cb;

	/* as in lwsws_get_config_globals(), lws_dir() 0 means a file failed */
	if (!lws_dir(dd, &da, lwsws_get_config_d_cb))
		return 1;

	*cs = a.p;
	*len = lws_ptr_diff(a.end, a.p);

	lwsac_free(&a.ac);

	if (!a.any_vhosts) {
		lwsl_err("Need at least one vhost\n");
		return 1;
	}

//	lws_finalize_startup(context, __func__);

	return 0;
}
