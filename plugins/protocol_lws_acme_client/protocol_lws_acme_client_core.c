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

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include "../../lib/tls/private-lib-tls.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <sys/stat.h>
#include <fcntl.h>
#include "lws-acme-client.h"

#if !defined(WIN32)
#include <sys/socket.h>
#include <sys/un.h>

typedef enum {
	ACME_STATE_DIRECTORY,	/* get the directory JSON using GET + parse */
	ACME_STATE_NEW_NONCE,	/* get the replay nonce */
	ACME_STATE_NEW_ACCOUNT,	/* register a new RSA key + email combo */
	ACME_STATE_NEW_ORDER,	/* start the process to request a cert */
	ACME_STATE_AUTHZ,	/* */
	ACME_STATE_START_CHALL, /* notify server ready for one challenge */
	ACME_STATE_POLLING,	/* he should be trying our challenge */
	ACME_STATE_POLLING_CSR,	/* sent CSR, checking result */
	ACME_STATE_DOWNLOAD_CERT,

	ACME_STATE_FINISHED
} lws_acme_state;

struct acme_connection {
	char buf[4096];
	char replay_nonce[64];
	char chall_token[64];
	char challenge_uri[256];
	char detail[64];
	char status[16];
	char key_auth[256];
	char http01_mountpoint[256];
	struct lws_http_mount mount;
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
	struct lws_context_creation_info ci;
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
	struct lws_genrsa_ctx rsactx;
	char *dns_base_dir;

	lws_dll2_owner_t cert_configs;
    struct lws_acme_cert_config *active_cert;
    lws_sorted_usec_list_t sul_aging;
    lws_sorted_usec_list_t sul_acquisition;
    lws_usec_t last_acme_failure;

	int count_live_pss;
	char *dest;
	int pos;
	int len;
	#if !defined(LWS_WITH_ESP32)
	/* removed persistent fd_updated_cert/key handles since they are opened dynamically per cert */
	/* we allocate memory here because we drop root too early */
#endif
	const char *uds_path;
};

/*
 * Maps for nested JSON parsing
 */
static const lws_struct_map_t map_acme_acme_obj[] = {
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, country, "country"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, state, "state"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, locality, "locality"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, organization, "organization"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, directory_url, "directory-url"),
};

static const lws_struct_map_t map_acme_cert_config[] = {
	LSM_STRING_PTR(struct lws_acme_cert_config, common_name, "common-name"),
	LSM_STRING_PTR(struct lws_acme_cert_config, challenge_type_str, "challenge-type"),
	LSM_STRING_PTR(struct lws_acme_cert_config, email, "email"),
	LSM_CHILD_PTR(struct lws_acme_cert_config, acme, struct lws_acme_cert_config_acme, NULL, map_acme_acme_obj, "acme"),
};

static const lws_struct_map_t map_acme_cert_config_root[] = {
	LSM_SCHEMA(struct lws_acme_cert_config, NULL, map_acme_cert_config, "lws-acme-client-config"),
};

static int
acme_ipc_save_payload(struct per_vhost_data__lws_acme_client *vhd, const char *req, const char *domain, const char *filename, const char *payload, size_t payload_len)
{
	const char *uds_path = vhd->uds_path;
	if (!uds_path) uds_path = lws_cmdline_option_cx(vhd->context, "--uds-path");
	if (!uds_path) uds_path = "/var/run/lws-dnssec-monitor.sock";

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		lwsl_err("IPC socket() failed: %d\n", errno);
		return 1;
	}
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, uds_path, sizeof(addr.sun_path) - 1);
	int retries = 200;
	int last_errno = 0;

	while (retries--) {
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
			goto connected;

		last_errno = errno;
		if (errno == ECONNREFUSED || errno == ENOENT) {
			usleep(100000); /* 100ms */
			continue;
		}

		lwsl_err("IPC connect() to %s failed: %d\n", uds_path, errno);
		close(fd);
		return 1;
	}
	lwsl_err("IPC connect() to %s failed after retries for %s (%s): %d\n",
		 uds_path, domain, filename, last_errno);
	close(fd);
	return 1;

connected:
	;

	char header[3072];
	char jwt[2048] = {0};

	/* Sign the payload with the proxy 64-byte secret preamble */
#if defined(LWS_WITH_JOSE)
	lws_system_blob_t *b = lws_system_get_blob(vhd->context, LWS_SYSBLOB_TYPE_EXT_AUTH1, 0);
	if (b) {
		size_t hex_len = lws_system_blob_get_size(b);
		if (hex_len > 0) {
			char hex[129];
			char temp[2048];
			size_t jwt_len = sizeof(jwt);
			struct lws_jwk jwk;
			if (hex_len >= sizeof(hex)) hex_len = sizeof(hex) - 1;
			lws_system_blob_get(b, (uint8_t *)hex, &hex_len, 0);
			hex[hex_len] = '\0';
			memset(&jwk, 0, sizeof(jwk));
			jwk.kty = LWS_GENCRYPTO_KTY_OCT;
			jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].len = 64;
			jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf = malloc(64);
			lws_hex_to_byte_array(hex, jwk.e[LWS_GENCRYPTO_OCT_KEYEL_K].buf, 64);

			uint64_t now = (uint64_t)lws_now_usecs() / LWS_US_PER_SEC;
			lws_jwt_sign_compact(vhd->context, &jwk, "HS256", jwt, &jwt_len, temp, sizeof(temp),
			    "{\"iss\":\"acme-ipc\",\"aud\":\"dnssec-monitor\",\"iat\":%llu,\"exp\":%llu}",
			    (unsigned long long)now, (unsigned long long)now + 300);

			lws_jwk_destroy(&jwk);
		}
	}
#endif

	int hlen = lws_snprintf(header, sizeof(header), "{\"req\":\"%s\",\"jwt\":\"%s\",\"domain\":\"%s\",\"subdomain\":\"%s\",\"zone\":\"", req, jwt, domain, filename);
	write(fd, header, (size_t)hlen);

	for (size_t i = 0; i < payload_len; i++) {
        char c = payload[i];
        if (c == '\n') { write(fd, "\\n", 2); }
        else if (c == '\r') { write(fd, "\\r", 2); }
        else if (c == '"') { write(fd, "\\\"", 2); }
        else if (c == '\\') { write(fd, "\\\\", 2); }
        else { write(fd, &c, 1); }
    }
	write(fd, "\"}\n", 3);

	char resp[256];
	ssize_t n = read(fd, resp, sizeof(resp) - 1);
	close(fd);

	if (n > 0) {
		resp[n] = '\0';
		if (strstr(resp, "\"status\":\"error\"")) {
			lwsl_err("IPC server returned error: %s\n", resp);
			return 1;
		}
	} else {
		lwsl_err("IPC server failed to respond or returned empty\n");
		return 1;
	}

	return 0;
}
#else
static int
acme_ipc_save_payload(struct per_vhost_data__lws_acme_client *vhd, const char *req, const char *domain, const char *filename, const char *payload, size_t payload_len)
{
	return 1;
}
#endif

static int
callback_chall_http01(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len)
{
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	struct acme_connection *ac = lws_vhost_user(vhost);
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_wsi_notice(wsi, "CA connection received, key_auth %s",
			    ac->key_auth);

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

		n = (int)strlen(ac->key_auth);
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
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "%s", ac->key_auth);
		// lwsl_notice("%s: len %d\n", __func__, lws_ptr_diff(p, start));
		if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_HTTP_FINAL) != lws_ptr_diff(p, start)) {
			lwsl_wsi_err(wsi, "_write content failed");
			return 1;
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
jws_create_packet(struct lws_jwe *jwe, const char *payload, size_t len,
		  const char *nonce, const char *url, const char *kid,
		  char *out, size_t out_len, struct lws_context *context)
{
	char *buf, *start, *p, *end, *p1, *end1;
	struct lws_jws jws;
	int n, m;

	lws_jws_init(&jws, &jwe->jwk, context);

	/*
	 * This buffer is local to the function, the actual output is prepared
	 * into out.  Only the plaintext protected header
	 * (which contains the public key, 512 bytes for 4096b) goes in
	 * here temporarily.
	 */
	n = LWS_PRE + 2048;
	buf = malloc((unsigned int)n);
	if (!buf) {
		lwsl_warn("%s: malloc %d failed\n", __func__, n);
		return -1;
	}

	p = start = buf + LWS_PRE;
	end = buf + n - LWS_PRE - 1;

	/*
	 * temporary JWS protected header plaintext
	 */
	if (!jwe->jose.alg || !jwe->jose.alg->alg)
		goto bail;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"alg\":\"RS256\"");
	if (kid)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",\"kid\":\"%s\"", kid);
	else {
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",\"jwk\":");
		m = lws_ptr_diff(end, p);
		n = lws_jwk_export(&jwe->jwk, 0, p, &m);
		if (n < 0) {
			lwsl_notice("failed to export jwk\n");
			goto bail;
		}
		p += n;
	}
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",\"url\":\"%s\"", url);
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",\"nonce\":\"%s\"}", nonce);

	/*
	 * prepare the signed outer JSON with all the parts in
	 */
	p1 = out;
	end1 = out + out_len - 1;

	p1 += lws_snprintf(p1, lws_ptr_diff_size_t(end1, p1), "{\"protected\":\"");
	jws.map_b64.buf[LJWS_JOSE] = p1;
	n = lws_jws_base64_enc(start, lws_ptr_diff_size_t(p, start), p1, lws_ptr_diff_size_t(end1, p1));
	if (n < 0) {
		lwsl_notice("%s: failed to encode protected\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_JOSE] = (uint32_t)n;
	p1 += n;

	p1 += lws_snprintf(p1, lws_ptr_diff_size_t(end1, p1), "\",\"payload\":\"");
	jws.map_b64.buf[LJWS_PYLD] = p1;
	n = lws_jws_base64_enc(payload, len, p1, lws_ptr_diff_size_t(end1, p1));
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_PYLD] = (uint32_t)n;
	p1 += n;

	p1 += lws_snprintf(p1, lws_ptr_diff_size_t(end1, p1), "\",\"signature\":\"");

	/*
	 * taking the b64 protected header and the b64 payload, sign them
	 * and place the signature into the packet
	 */
	n = lws_jws_sign_from_b64(&jwe->jose, &jws, p1, lws_ptr_diff_size_t(end1, p1));
	if (n < 0) {
		lwsl_notice("sig gen failed\n");

		goto bail;
	}
	jws.map_b64.buf[LJWS_SIG] = p1;
	jws.map_b64.len[LJWS_SIG] = (uint32_t)n;

	p1 += n;
	p1 += lws_snprintf(p1, lws_ptr_diff_size_t(end1, p1), "\"}");

	free(buf);

	return lws_ptr_diff(p1, out);

bail:
	lws_jws_destroy(&jws);
	free(buf);

	return -1;
}

static int
callback_acme_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len);

#define LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT \
{ \
	"lws-acme-client-core", \
	callback_acme_client, \
	0, \
	512, \
	0, (void *)&acme_core_ops, 0 \
}

/* directory JSON parsing */

static const char * const jdir_tok[] = {
	"keyChange",
	"meta.termsOfService",
	"newAccount",
	"newNonce",
	"newOrder",
	"revokeCert",
};

enum enum_jdir_tok {
	JAD_KEY_CHANGE_URL,
	JAD_TOS_URL,
	JAD_NEW_ACCOUNT_URL,
	JAD_NEW_NONCE_URL,
	JAD_NEW_ORDER_URL,
	JAD_REVOKE_CERT_URL,
};

static signed char
cb_dir(struct lejp_ctx *ctx, char reason)
{
	struct per_vhost_data__lws_acme_client *s =
		(struct per_vhost_data__lws_acme_client *)ctx->user;

	if (reason == LEJPCB_VAL_STR_START && ctx->path_match) {
		s->pos = 0;
		s->len = sizeof(s->ac->urls[0]) - 1;
		s->dest = s->ac->urls[ctx->path_match - 1];
		return 0;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (s->pos + ctx->npos > s->len) {
		lwsl_notice("url too long\n");
		return -1;
	}

	memcpy(s->dest + s->pos, ctx->buf, ctx->npos);
	s->pos += ctx->npos;
	s->dest[s->pos] = '\0';

	return 0;
}


/* order JSON parsing */

static const char * const jorder_tok[] = {
	"status",
	"expires",
	"identifiers[].type",
	"identifiers[].value",
	"authorizations",
	"finalize",
	"certificate"
};

enum enum_jorder_tok {
	JAO_STATUS,
	JAO_EXPIRES,
	JAO_IDENTIFIERS_TYPE,
	JAO_IDENTIFIERS_VALUE,
	JAO_AUTHORIZATIONS,
	JAO_FINALIZE,
	JAO_CERT
};

static signed char
cb_order(struct lejp_ctx *ctx, char reason)
{
	struct acme_connection *s = (struct acme_connection *)ctx->user;

	if (reason == LEJPCB_CONSTRUCTED)
		s->authz_url[0] = '\0';

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JAO_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JAO_EXPIRES:
		break;
	case JAO_IDENTIFIERS_TYPE:
		break;
	case JAO_IDENTIFIERS_VALUE:
		break;
	case JAO_AUTHORIZATIONS:
		lws_snprintf(s->authz_url, sizeof(s->authz_url), "%s",
			     ctx->buf);
		break;
	case JAO_FINALIZE:
		lws_snprintf(s->finalize_url, sizeof(s->finalize_url), "%s",
				ctx->buf);
		break;
	case JAO_CERT:
		lws_snprintf(s->cert_url, sizeof(s->cert_url), "%s", ctx->buf);
		break;
	}

	return 0;
}

/* authz JSON parsing */

static const char * const jauthz_tok[] = {
	"identifier.type",
	"identifier.value",
	"status",
	"expires",
	"challenges[].type",
	"challenges[].status",
	"challenges[].url",
	"challenges[].token",
	"detail"
};

enum enum_jauthz_tok {
	JAAZ_ID_TYPE,
	JAAZ_ID_VALUE,
	JAAZ_STATUS,
	JAAZ_EXPIRES,
	JAAZ_CHALLENGES_TYPE,
	JAAZ_CHALLENGES_STATUS,
	JAAZ_CHALLENGES_URL,
	JAAZ_CHALLENGES_TOKEN,
	JAAZ_DETAIL,
};

static signed char
cb_authz(struct lejp_ctx *ctx, char reason)
{
	struct per_vhost_data__lws_acme_client *vhd = (struct per_vhost_data__lws_acme_client *)ctx->user;
	struct acme_connection *s = vhd->ac;

	if (reason == LEJPCB_CONSTRUCTED) {
		s->yes = 0;
		s->use = 0;
		s->chall_token[0] = '\0';
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JAAZ_ID_TYPE:
		break;
	case JAAZ_ID_VALUE:
		break;
	case JAAZ_STATUS:
		break;
	case JAAZ_EXPIRES:
		break;
	case JAAZ_DETAIL:
		lws_snprintf(s->detail, sizeof(s->detail), "%s", ctx->buf);
		break;
	case JAAZ_CHALLENGES_TYPE:
		lwsl_notice("JAAZ_CHALLENGES_TYPE: %s\n", ctx->buf);
		lws_acme_challenge_type expected_challenge = vhd->active_cert ? vhd->active_cert->challenge_type : LWS_ACME_CHALLENGE_TYPE_HTTP_01;
		s->use = !strcmp(ctx->buf, expected_challenge == LWS_ACME_CHALLENGE_TYPE_DNS_01 ? "dns-01" : "http-01");
		break;
	case JAAZ_CHALLENGES_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JAAZ_CHALLENGES_URL:
		lwsl_notice("JAAZ_CHALLENGES_URL: %s %d\n", ctx->buf, s->use);
		if (s->use) {
			lws_strncpy(s->challenge_uri, ctx->buf,
				    sizeof(s->challenge_uri));
			s->yes = s->yes | 2;
		}
		break;
	case JAAZ_CHALLENGES_TOKEN:
		lwsl_notice("JAAZ_CHALLENGES_TOKEN: %s %d\n", ctx->buf, s->use);
		if (s->use) {
			lws_strncpy(s->chall_token, ctx->buf,
				    sizeof(s->chall_token));
			s->yes = s->yes | 1;
		}
		break;
	}

	return 0;
}

/* challenge accepted JSON parsing */

static const char * const jchac_tok[] = {
	"type",
	"status",
	"uri",
	"token",
	"error.detail"
};

enum enum_jchac_tok {
	JCAC_TYPE,
	JCAC_STATUS,
	JCAC_URI,
	JCAC_TOKEN,
	JCAC_DETAIL,
};

static signed char
cb_chac(struct lejp_ctx *ctx, char reason)
{
	struct acme_connection *s = (struct acme_connection *)ctx->user;

	if (reason == LEJPCB_CONSTRUCTED) {
		s->yes = 0;
		s->use = 0;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JCAC_TYPE:
		if (strcmp(ctx->buf, "http-01"))
			return 1;
		break;
	case JCAC_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JCAC_URI:
		s->yes = s->yes | 2;
		break;
	case JCAC_TOKEN:
		lws_strncpy(s->chall_token, ctx->buf, sizeof(s->chall_token));
		s->yes = s->yes | 1;
		break;
	case JCAC_DETAIL:
		lws_snprintf(s->detail, sizeof(s->detail), "%s", ctx->buf);
		break;
	}

	return 0;
}

static int
lws_acme_report_status(struct lws_vhost *v, int state, const char *json)
{
	lws_callback_vhost_protocols_vhost(v, LWS_CALLBACK_VHOST_CERT_UPDATE,
					   (void *)json, (unsigned int)state);

	return 0;
}

/*
 * Notice: trashes i and url
 */
static struct lws *
lws_acme_client_connect(struct lws_context *context, struct lws_vhost *vh,
		struct lws **pwsi, struct lws_client_connect_info *i,
		char *url, const char *method)
{
	const char *p;
	char path[200];
	lws_parse_uri_t *puri;
	struct lws *wsi;

	memset(i, 0, sizeof(*i));
	i->port = 443;
	puri = lws_parse_uri_create(url);
	if (!puri) {
		lwsl_err("unable to parse uri %s\n", url);

		return NULL;
	}

	i->address = puri->host;
	i->port = puri->port;
	p = puri->path;

	/* add back the leading / on path */
	if (p[0] != '/') {
		path[0] = '/';
		lws_strncpy(path + 1, p, sizeof(path) - 1);
		i->path = path;
	} else
		i->path = p;

	i->context = context;
	i->vhost = vh;
	i->ssl_connection = LCCSCF_USE_SSL;
	i->host = i->address;
	i->origin = i->address;
	i->method = method;
	i->pwsi = pwsi;
	i->protocol = "lws-acme-client-core";

	wsi = lws_client_connect_via_info(i);
	if (!wsi) {
		lws_snprintf(path, sizeof(path) - 1,
			     "Unable to connect to %s", url);
		lwsl_notice("%s: %s\n", __func__, path);
		lws_acme_report_status(vh, LWS_CUS_FAILED, path);
	} else {
        lwsl_vhost_notice(vh, "ACME Network Call Initiated: %s %s [wsi=%p]", method, url, wsi);
    }

	if (puri)
		lws_parse_uri_destroy(&puri);

	return wsi;
}

static void
lws_acme_finished(struct per_vhost_data__lws_acme_client *vhd)
{
	lwsl_notice("%s\n", __func__);
    lws_sul_cancel(&vhd->sul_aging);

	if (vhd->ac) {
		if (vhd->ac->vhost)
			lws_vhost_destroy(vhd->ac->vhost);
		if (vhd->ac->alloc_privkey_pem)
			free(vhd->ac->alloc_privkey_pem);
		free(vhd->ac);
	}

	lws_genrsa_destroy(&vhd->rsactx);
	lws_jwk_destroy(&vhd->jwk);

	if (vhd->dns_base_dir) {
		free(vhd->dns_base_dir);
		vhd->dns_base_dir = NULL;
	}

	vhd->ac = NULL;
#if defined(LWS_WITH_ESP32)
	lws_esp32.acme = 0; /* enable scanning */
#endif
}


static int
lws_acme_load_create_auth_keys(struct per_vhost_data__lws_acme_client *vhd,
		int bits)
{
	int n;

	if (!lws_jwk_load(&vhd->jwk, vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH],
				NULL, NULL))
		return 0;

	vhd->jwk.kty = LWS_GENCRYPTO_KTY_RSA;

	lwsl_notice("Generating ACME %d-bit keypair... "
			"will take a little while\n", bits);
	n = lws_genrsa_new_keypair(vhd->context, &vhd->rsactx, LGRSAM_PKCS1_1_5,
			vhd->jwk.e, bits);
	if (n) {
		lwsl_vhost_warn(vhd->vhost, "failed to create keypair");
		return 1;
	}

	lwsl_notice("...keypair generated\n");

	if (lws_jwk_save(&vhd->jwk, vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH])) {
        lwsl_vhost_notice(vhd->vhost, "falling back to ACME footprint IPC to save %s", vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH]);
        char tmp_path[256];
        lws_snprintf(tmp_path, sizeof(tmp_path), "/tmp/lws-acme-auth-%d.jwk", getpid());
        if (!lws_jwk_save(&vhd->jwk, tmp_path)) {
            int fd = open(tmp_path, O_RDONLY);
            int success = 0;
            if (fd >= 0) {
                struct stat st;
                if (!fstat(fd, &st) && st.st_size > 0) {
                    char *buf = malloc((size_t)st.st_size);
                    if (buf && read(fd, buf, (size_t)st.st_size) == st.st_size) {
                        const char *fp = vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH];
                        const char *fn = strrchr(fp, '/');
                        if (fn) fn++; else fn = fp;
                        int r = acme_ipc_save_payload(vhd,
                            "save_auth_key",
                            vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] ? vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] : vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME],
                            fn,
                            buf, (size_t)st.st_size);
                        if (!r) success = 1;
                    }
                    if (buf) free(buf);
                }
                close(fd);
            }
            unlink(tmp_path);
            if (!success) {
                lwsl_vhost_warn(vhd->vhost, "unable to save %s via footprint IPC",
                        vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH]);
                vhd->last_acme_failure = lws_now_usecs();
                return 1;
            }
        } else {
            lwsl_vhost_warn(vhd->vhost, "unable to save %s",
                    vhd->active_cert->pvop[LWS_TLS_SET_AUTH_PATH]);
            vhd->last_acme_failure = lws_now_usecs();
            return 1;
        }
	}

	return 0;
}

static int
lws_acme_start_acquisition(struct per_vhost_data__lws_acme_client *vhd,
		struct lws_vhost *v);

static void
lws_acme_start_acquisition_cb(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__lws_acme_client *vhd = lws_container_of(sul,
			struct per_vhost_data__lws_acme_client, sul_acquisition);

	lws_acme_start_acquisition(vhd, vhd->vhost);
}

static int
lws_acme_start_acquisition(struct per_vhost_data__lws_acme_client *vhd,
		struct lws_vhost *v)
{
	char buf[128];

	/* ...and we were given enough info to do the update? */

	if (!vhd->active_cert || !vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME])
		return -1;

	if (vhd->ac) {
		lwsl_vhost_notice(vhd->vhost, "acme: acquisition already in progress, ignoring trigger");
		return 0;
	}

	if (vhd->last_acme_failure &&
	    lws_now_usecs() - vhd->last_acme_failure < 60 * LWS_US_PER_SEC) {
		lwsl_vhost_notice(vhd->vhost, "acme: recent failure, cooling down");
		return 0;
	}

	/*
	 * ...well... we should try to do something about it then...
	 */
	lwsl_vhost_notice(vhd->vhost, "ACME cert needs creating / updating:  "
			"vhost %s", lws_get_vhost_name(vhd->vhost));

	vhd->ac = malloc(sizeof(*vhd->ac));
	memset(vhd->ac, 0, sizeof(*vhd->ac));

	/*
	 * So if we don't have it, the first job is get the directory.
	 *
	 * If we already have the directory, jump straight into trying
	 * to register our key.
	 *
	 * We always try to register the keys... if it's not the first
	 * time, we will get a JSON body in the (legal, nonfatal)
	 * response like this
	 *
	 * {
	 *   "type": "urn:acme:error:malformed",
	 *   "detail": "Registration key is already in use",
	 *   "status": 409
	 * }
	 */
	if (!vhd->ac->urls[0][0]) {
		vhd->ac->state = ACME_STATE_DIRECTORY;
		lws_snprintf(buf, sizeof(buf) - 1, "%s",
				vhd->active_cert->pvop[LWS_TLS_SET_DIR_URL]);
	} else {
		vhd->ac->state = ACME_STATE_NEW_ACCOUNT;
		lws_snprintf(buf, sizeof(buf) - 1, "%s",
				vhd->ac->urls[JAD_NEW_ACCOUNT_URL]);
	}

	vhd->ac->real_vh_port = lws_get_vhost_port(vhd->vhost);
	vhd->ac->real_vh_name = lws_get_vhost_name(vhd->vhost);
	vhd->ac->real_vh_iface = lws_get_vhost_iface(vhd->vhost);

	lws_acme_report_status(vhd->vhost, LWS_CUS_STARTING, NULL);

	lws_acme_report_status(vhd->vhost, LWS_CUS_CREATE_KEYS,
			"Generating auth keys, please wait");
	if (lws_acme_load_create_auth_keys(vhd, 2048))
		goto bail;
	lws_acme_report_status(vhd->vhost, LWS_CUS_CREATE_KEYS,
			"Auth keys created");

	if (lws_acme_client_connect(vhd->context, vhd->vhost,
				&vhd->ac->cwsi, &vhd->ac->i, buf, "GET"))
		return 0;

bail:
	free(vhd->ac);
	vhd->ac = NULL;

	return 1;
}

struct acme_scan_ctx {
	struct per_vhost_data__lws_acme_client *vhd;
	char domain[256];
};

static int
lws_acme_scan_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
    struct acme_scan_ctx *scan_ctx = (struct acme_scan_ctx *)user;
    struct per_vhost_data__lws_acme_client *vhd = scan_ctx->vhd;
    struct lws_struct_args args;
    char path[256];
    int fd, n;

    if (lde->type != LDOT_FILE)
        return 0;

    size_t n_len = strlen(lde->name);
    if (n_len < 5 || strcmp(&lde->name[n_len - 5], ".json"))
        return 0;

    lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

    fd = lws_open(path, O_RDONLY);
    if (fd < 0) {
        lwsl_vhost_err(vhd->vhost, "acme: couldn't open %s", path);
        return 0;
    }

    memset(&args, 0, sizeof(args));
    args.map_st[0] = map_acme_cert_config_root;
    args.map_entries_st[0] = LWS_ARRAY_SIZE(map_acme_cert_config_root);
    args.ac_block_size = 512;

    struct lejp_ctx ctx;

    lws_struct_json_init_parse(&ctx, NULL, &args);

    struct lws_acme_cert_config *cfg = NULL;

    while (1) {
        char buf[256];
        n = (int)read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;

        int m = lejp_parse(&ctx, (uint8_t *)buf, n);
        if (m < 0 && m != LEJP_CONTINUE) {
            lwsl_vhost_err(vhd->vhost, "acme: json parse failed: %s %d", path, m);
            goto done;
        }
    }

    cfg = (struct lws_acme_cert_config *)args.dest;
    if (cfg) {
		char common_name_s[128];
		char dir_path[256];
		char *q = common_name_s;
		const char *p;
		size_t len;

        cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME] = cfg->common_name;
        cfg->pvop[LWS_TLS_REQ_ELEMENT_EMAIL] = cfg->email;
        if (cfg->acme) {
            cfg->pvop[LWS_TLS_REQ_ELEMENT_COUNTRY] = cfg->acme->country;
            cfg->pvop[LWS_TLS_REQ_ELEMENT_STATE] = cfg->acme->state;
            cfg->pvop[LWS_TLS_REQ_ELEMENT_LOCALITY] = cfg->acme->locality;
            cfg->pvop[LWS_TLS_REQ_ELEMENT_ORGANIZATION] = cfg->acme->organization;
            cfg->pvop[LWS_TLS_SET_DIR_URL] = cfg->acme->directory_url;
        }

		if (cfg->common_name) {
			p = cfg->common_name;
			while (*p && q < &common_name_s[sizeof(common_name_s) - 1]) {
				if (isalnum(*p) || *p == '.' || *p == '-')
					*q++ = *p;
				else
					*q++ = '_';
				p++;
			}
			*q = '\0';

			char *certs_dir = dir_path;
			const char *env_dir = (cfg->acme && cfg->acme->directory_url && strstr(cfg->acme->directory_url, "staging")) ? "staging" : "production";
			lws_snprintf(certs_dir, sizeof(dir_path), "%s/domains/%s/certs", vhd->dns_base_dir, scan_ctx->domain);
#if !defined(WIN32) && !defined(LWS_WITH_ESP32)
			mkdir(certs_dir, 0700);
#endif
			lws_snprintf(certs_dir, sizeof(dir_path), "%s/domains/%s/certs/%s", vhd->dns_base_dir, scan_ctx->domain, env_dir);
#if !defined(WIN32) && !defined(LWS_WITH_ESP32)
			mkdir(certs_dir, 0700);
#endif
			lws_snprintf(certs_dir, sizeof(dir_path), "%s/domains/%s/certs/%s/crt", vhd->dns_base_dir, scan_ctx->domain, env_dir);
#if !defined(WIN32) && !defined(LWS_WITH_ESP32)
			mkdir(certs_dir, 0700);
#endif
			lws_snprintf(certs_dir, sizeof(dir_path), "%s/domains/%s/certs/%s/key", vhd->dns_base_dir, scan_ctx->domain, env_dir);
#if !defined(WIN32) && !defined(LWS_WITH_ESP32)
			mkdir(certs_dir, 0700);
#endif

			len = strlen(vhd->dns_base_dir) + strlen(scan_ctx->domain) + strlen(common_name_s) + 128;

			char *cert_path = (char *)malloc(len);
			char *key_path = (char *)malloc(len);
			char *auth_path = (char *)malloc(len);

			if (cert_path && key_path && auth_path) {
				lws_snprintf(cert_path, len, "%s/domains/%s/certs/%s/crt/%s-latest.crt", vhd->dns_base_dir, scan_ctx->domain, env_dir, common_name_s);
				lws_snprintf(key_path, len, "%s/domains/%s/certs/%s/key/%s-latest.key", vhd->dns_base_dir, scan_ctx->domain, env_dir, common_name_s);
				lws_snprintf(auth_path, len, "%s/domains/%s/%s-auth.jwk", vhd->dns_base_dir, scan_ctx->domain, common_name_s);

				cfg->pvop[LWS_TLS_SET_CERT_PATH] = cert_path;
				cfg->pvop[LWS_TLS_SET_KEY_PATH] = key_path;
				cfg->pvop[LWS_TLS_SET_AUTH_PATH] = auth_path;
			}
		}

        /* Determine challenge type based on challenge-type string */
        cfg->challenge_type = LWS_ACME_CHALLENGE_TYPE_HTTP_01; /* Default */
        if (cfg->challenge_type_str && !strcmp(cfg->challenge_type_str, "dns-01"))
            cfg->challenge_type = LWS_ACME_CHALLENGE_TYPE_DNS_01;

        lws_dll2_clear(&cfg->list);
        lws_dll2_add_tail(&cfg->list, &vhd->cert_configs);
        lwsl_vhost_notice(vhd->vhost, "acme: loaded cert %s",
            cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME] ?
            cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME] : "unknown");
    }

done:
    close(fd);
    lejp_destruct(&ctx);
    return 0;
}

static int
lws_acme_scan_domains_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct per_vhost_data__lws_acme_client *vhd = (struct per_vhost_data__lws_acme_client *)user;
	struct acme_scan_ctx scan_ctx;
	struct lws_dir_info info;
	char path[512];

	if (lde->type != LDOT_DIR)
		return 0;

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	scan_ctx.vhd = vhd;
	lws_strncpy(scan_ctx.domain, lde->name, sizeof(scan_ctx.domain));

	lws_snprintf(path, sizeof(path), "%s/domains/%s/conf.d", vhd->dns_base_dir, lde->name);

	lwsl_notice("acme: Scanning domain config dir %s\n", path);

	memset(&info, 0, sizeof(info));
	info.dirpath = path;
	info.user = &scan_ctx;
	info.cb = lws_acme_scan_dir_cb;
	lws_dir_via_info(&info);

	return 0;
}

LWS_VISIBLE int
lws_acme_core_cert_aging(struct per_vhost_data__lws_acme_client *vhd,
			 const struct lws_acme_cert_aging_args *caa);

static void
lws_acme_timer_cb(lws_sorted_usec_list_t *sul)
{
    struct per_vhost_data__lws_acme_client *vhd =
        lws_container_of(sul, struct per_vhost_data__lws_acme_client, sul_aging);

    lws_acme_core_cert_aging(vhd, NULL);
    lws_sul_schedule(vhd->context, 0, &vhd->sul_aging, lws_acme_timer_cb, 3600 * LWS_US_PER_SEC);
}

static int
callback_acme_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct per_vhost_data__lws_acme_client *vhd =
		(struct per_vhost_data__lws_acme_client *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_get_protocol(wsi));
	char buf[LWS_PRE + 2536], *start = buf + LWS_PRE, *p = start,
		 *end = buf + sizeof(buf) - 1, digest[32], *failreason = NULL;
	struct lws_acme_cert_aging_args *caa;
	struct acme_connection *ac = NULL;
	unsigned char **pp, *pend;
	const char *content_type;
	struct lws_jwe jwe;
	struct lws *cwsi;
	int n, m;

	if (vhd)
		ac = vhd->ac;

	lws_jwe_init(&jwe, lws_get_context(wsi));

	switch ((int)reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		/* ACME now runs globally in the root-monitor */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-dht-dnssec-monitor-root"))
			return 0;

		if (!vhd) {
			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					lws_get_protocol(wsi),
					sizeof(struct per_vhost_data__lws_acme_client));
			if (!vhd)
				return -1;
			vhd->context = lws_get_context(wsi);
			vhd->protocol = lws_get_protocol(wsi);
			vhd->vhost = lws_get_vhost(wsi);
		}

		if (vhd->dns_base_dir) {
			lwsl_notice("acme_core: Already fully initialized\n");
			return 0;
		}

        lws_dll2_owner_clear(&vhd->cert_configs);
		{
			lws_system_policy_t *policy;
			if (lws_system_parse_policy(vhd->context, "/etc/lwsws/policy", &policy)) {
				lwsl_err("acme: couldn't parse global policy. Plugin disabled.\n");
				return -1;
			}
			vhd->dns_base_dir = strdup(policy->dns_base_dir);
			lws_system_policy_free(policy);

			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "uds-path"))
					vhd->uds_path = pvo->value;
				pvo = pvo->next;
			}
		}

        {
            struct lws_dir_info info;
            char path[512];
            int ret;
            memset(&info, 0, sizeof(info));
            lws_snprintf(path, sizeof(path), "%s/domains", vhd->dns_base_dir);
            lwsl_notice("acme: ACME PLUGIN INIT! Scanning base domains dir %s\n", path);
            info.dirpath = path;
            info.user = vhd;
            info.cb = lws_acme_scan_domains_cb;
            ret = lws_dir_via_info(&info);
            if (ret)
                lwsl_err("acme: Failed to scan domains dir %s (err %d)\n", path, ret);
            else
                lwsl_notice("acme: Found %d cert configs in base dir\n", (int)vhd->cert_configs.count);
        }

        /* Start polling domain cert lifetimes */
        lws_sul_schedule(vhd->context, 0, &vhd->sul_aging, lws_acme_timer_cb, 5 * LWS_US_PER_SEC);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_acme_finished(vhd);
		break;

	case LWS_CALLBACK_VHOST_CERT_AGING:
		if (!vhd)
			break;

		caa = (struct lws_acme_cert_aging_args *)in;
		/*
		 * Somebody is telling us about a cert some vhost is using.
		 *
		 * First see if the cert is getting close enough to expiry that
		 * we *want* to do something about it.
		 */
		if ((int)(ssize_t)len > 14)
			break;

		/*
		 * ...is this a vhost we were configured on?
		 */
		if (vhd->vhost != caa->vh)
			return 1;

		if (!vhd->active_cert)
			return 1; /* For now, just operate on the single active certificate during aging */

		for (n = 0; n < LWS_TLS_TOTAL_COUNT; n++)
			if (caa->element_overrides[n])
				vhd->active_cert->pvop[n] = caa->element_overrides[n];

		lwsl_notice("scheduling acme acquisition on %s: %s\n",
				lws_get_vhost_name(caa->vh),
				vhd->active_cert->pvop[LWS_TLS_SET_DIR_URL]);

		lws_sul_schedule(lws_get_context(wsi), 0, &vhd->sul_acquisition,
				 lws_acme_start_acquisition_cb, 100 * LWS_US_PER_MS);
		break;

	/*
	 * Client
	 */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!ac)
			break;

		ac->resp = (int)lws_http_client_http_response(wsi);
        lwsl_vhost_notice(vhd->vhost, "ACME Received Response: [wsi=%p] HTTP %d (State %d)", wsi, ac->resp, ac->state);

		/* we get a new nonce each time */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_REPLAY_NONCE) &&
				lws_hdr_copy(wsi, ac->replay_nonce,
					sizeof(ac->replay_nonce),
					WSI_TOKEN_REPLAY_NONCE) < 0) {
			lwsl_vhost_warn(vhd->vhost, "nonce too large");

			goto failed;
		}

		switch (ac->state) {
		case ACME_STATE_DIRECTORY:
			lejp_construct(&ac->jctx, cb_dir, vhd, jdir_tok,
					LWS_ARRAY_SIZE(jdir_tok));
			break;

		case ACME_STATE_NEW_NONCE:
			/*
			 *  we try to register our keys next.
			 *  It's OK if it ends up they're already registered,
			 *  this eliminates any gaps where we stored the key
			 *  but registration did not complete for some reason...
			 */
			ac->state = ACME_STATE_NEW_ACCOUNT;
			lws_acme_report_status(vhd->vhost, LWS_CUS_REG, NULL);

			strcpy(buf, ac->urls[JAD_NEW_ACCOUNT_URL]);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
					&ac->cwsi, &ac->i, buf, "POST");
			if (!cwsi) {
				lwsl_vhost_warn(vhd->vhost, "failed to connect to acme");
				goto failed;
			}

			return -1;

		case ACME_STATE_NEW_ACCOUNT:
			if (ac->resp >= 400) {
				lwsl_vhost_warn(vhd->vhost, "new-account failed with HTTP %d! We will keep connection open to read the JSON error body.", ac->resp);
				/* Do not goto failed here, so we can read the JSON body explaining why! */
			} else if (!lws_hdr_total_length(wsi,
						  WSI_TOKEN_HTTP_LOCATION)) {
				lwsl_vhost_warn(vhd->vhost, "no Location, HTTP %d", ac->resp);
				goto failed;
			}

			if (lws_hdr_copy(wsi, ac->acct_id, sizeof(ac->acct_id),
					 WSI_TOKEN_HTTP_LOCATION) < 0) {
				lwsl_vhost_warn(vhd->vhost, "Location too large");
				goto failed;
			}

			ac->kid = ac->acct_id;

			lwsl_vhost_notice(vhd->vhost, "Location: %s", ac->acct_id);
			break;

		case ACME_STATE_NEW_ORDER:
			if (lws_hdr_copy(wsi, ac->order_url,
					 sizeof(ac->order_url),
					 WSI_TOKEN_HTTP_LOCATION) < 0) {
				lwsl_vhost_warn(vhd->vhost, "missing cert location");

				goto failed;
			}

			lejp_construct(&ac->jctx, cb_order, ac, jorder_tok,
					LWS_ARRAY_SIZE(jorder_tok));
			break;

		case ACME_STATE_AUTHZ:
			lejp_construct(&ac->jctx, cb_authz, vhd, jauthz_tok,
					LWS_ARRAY_SIZE(jauthz_tok));
			break;

		case ACME_STATE_START_CHALL:
			lejp_construct(&ac->jctx, cb_chac, ac, jchac_tok,
					LWS_ARRAY_SIZE(jchac_tok));
			break;

		case ACME_STATE_POLLING:
		case ACME_STATE_POLLING_CSR:
			lejp_construct(&ac->jctx, cb_order, ac, jorder_tok,
					LWS_ARRAY_SIZE(jorder_tok));
			break;

		case ACME_STATE_DOWNLOAD_CERT:
			ac->cpos = 0;
			break;

		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!ac)
			break;

		switch (ac->state) {
		case ACME_STATE_DIRECTORY:
		case ACME_STATE_NEW_NONCE:
			break;

		case ACME_STATE_NEW_ACCOUNT:
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{"
				"\"termsOfServiceAgreed\":true"
				",\"contact\": [\"mailto:%s\"]}",
				vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_EMAIL]);

			lws_strncpy(ac->active_url, ac->urls[JAD_NEW_ACCOUNT_URL], sizeof(ac->active_url));
pkt_add_hdrs:
			if (lws_gencrypto_jwe_alg_to_definition("RSA1_5",
						&jwe.jose.alg)) {
				ac->len = 0;
				lwsl_notice("%s: no RSA1_5\n", __func__);
				goto failed;
			}
			jwe.jwk = vhd->jwk;

			ac->len = jws_create_packet(&jwe,
					start, lws_ptr_diff_size_t(p, start),
					ac->replay_nonce,
					ac->active_url,
					ac->kid,
					&ac->buf[LWS_PRE],
					sizeof(ac->buf) - LWS_PRE,
					lws_get_context(wsi));
			if (ac->len < 0) {
				ac->len = 0;
				lwsl_notice("jws_create_packet failed\n");
				goto failed;
			}
			ac->buf[LWS_PRE + ac->len] = '\0';
			lwsl_vhost_notice(vhd->vhost, "ACME POST payload to %s:\n%s", ac->active_url, &ac->buf[LWS_PRE]);


			pp = (unsigned char **)in;
			pend = (*pp) + len;

			ac->pos = 0;
			content_type = "application/jose+json";

			if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_TYPE,
						(uint8_t *)content_type, 21, pp,
						pend)) {
				lwsl_vhost_warn(vhd->vhost, "could not add content type");
				goto failed;
			}

			n = sprintf(buf, "%d", ac->len);
			if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_LENGTH,
						(uint8_t *)buf, n, pp, pend)) {
				lwsl_vhost_warn(vhd->vhost, "could not add content length");
				goto failed;
			}

			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
			break;

		case ACME_STATE_NEW_ORDER:
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					"{"
					"\"identifiers\":[{"
					"\"type\":\"dns\","
					"\"value\":\"%s\""
					"}]"
					"}",
			vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME]);

			lws_strncpy(ac->active_url, ac->urls[JAD_NEW_ORDER_URL], sizeof(ac->active_url));
			goto pkt_add_hdrs;

		case ACME_STATE_AUTHZ:
			lws_strncpy(ac->active_url, ac->authz_url, sizeof(ac->active_url));
			goto pkt_add_hdrs;

		case ACME_STATE_START_CHALL:
			p = start;
			end = &buf[sizeof(buf) - 1];

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{}");
			lws_strncpy(ac->active_url, ac->challenge_uri, sizeof(ac->active_url));
			goto pkt_add_hdrs;

		case ACME_STATE_POLLING:
			lws_strncpy(ac->active_url, ac->order_url, sizeof(ac->active_url));
			goto pkt_add_hdrs;

		case ACME_STATE_POLLING_CSR:
			if (ac->goes_around) {
				lws_strncpy(ac->active_url, ac->order_url, sizeof(ac->active_url));
				goto pkt_add_hdrs;
			}
			lwsl_vhost_notice(vhd->vhost, "Generating ACME CSR... may take a little while");
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"csr\":\"");
			n = lws_tls_acme_sni_csr_create_ecdsa(vhd->context,
					&vhd->active_cert->pvop[0],
					(uint8_t *)p, lws_ptr_diff_size_t(end, p),
					&ac->alloc_privkey_pem,
					&ac->len_privkey_pem);
			if (n < 0) {
				lwsl_vhost_warn(vhd->vhost, "CSR generation failed");
				goto failed;
			}
			p += n;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"}");
			lws_strncpy(ac->active_url, ac->finalize_url, sizeof(ac->active_url));
			goto pkt_add_hdrs;

		case ACME_STATE_DOWNLOAD_CERT:
			lws_strncpy(ac->active_url, ac->cert_url, sizeof(ac->active_url));
			goto pkt_add_hdrs;
			break;

		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:

		if (!ac)
			break;

		if (ac->pos == ac->len)
			break;

		ac->buf[LWS_PRE + ac->len] = '\0';
		if (lws_write(wsi, (uint8_t *)ac->buf + LWS_PRE,
					(size_t)ac->len, LWS_WRITE_HTTP_FINAL) < 0)
			return -1;

		ac->pos = ac->len;
		lws_client_http_body_pending(wsi, 0);
		break;

	/* chunked content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!ac)
			return -1;

		switch (ac->state) {
		case ACME_STATE_POLLING_CSR:
		case ACME_STATE_POLLING:
		case ACME_STATE_START_CHALL:
		case ACME_STATE_AUTHZ:
		case ACME_STATE_NEW_ORDER:
		case ACME_STATE_DIRECTORY:

			lwsl_notice("ACME JSON: %.*s\n", (int)len, (const char *)in);
			m = lejp_parse(&ac->jctx, (uint8_t *)in, (int)len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_notice("lejp parse failed %d\n", m);
				goto failed;
			}
			break;

		case ACME_STATE_NEW_ACCOUNT:
			if (ac->resp >= 400) {
				/* Print the error body directly so we can see why Let's Encrypt rejected the request */
				char errbuf[2048];
				size_t copylen = len < sizeof(errbuf) - 1 ? len : sizeof(errbuf) - 1;
				memcpy(errbuf, in, copylen);
				errbuf[copylen] = '\0';
				lwsl_vhost_warn(vhd->vhost, "Let's Encrypt Error Body: %s", errbuf);
			}
			break;

		case ACME_STATE_DOWNLOAD_CERT:
			/*
			 * It should be the DER cert...
			 * ACME 2.0 can send certs chain with 3 certs, store only first bytes
			 */
			if ((unsigned int)ac->cpos + len > sizeof(ac->buf))
				len = sizeof(ac->buf) - (unsigned int)ac->cpos;

			if (len) {
				memcpy(&ac->buf[ac->cpos], in, len);
				ac->cpos += (int)len;
			}
			break;
		default:
			break;
		}
		break;

	/* unchunked content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (!ac)
			return -1;

		switch (ac->state) {
		default:
			{
				char buffer[2048 + LWS_PRE];
				char *px = buffer + LWS_PRE;
				int lenx = sizeof(buffer) - LWS_PRE;

				if (lws_http_client_read(wsi, &px, &lenx) < 0)
					return -1;
			}
			break;
		}
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:

		if (!ac)
			return -1;

		switch (ac->state) {
		case ACME_STATE_DIRECTORY:
			lejp_destruct(&ac->jctx);

			/* check dir validity */

			for (n = 0; n < 6; n++)
				lwsl_notice("   %d: %s\n", n, ac->urls[n]);

			ac->state = ACME_STATE_NEW_NONCE;

			strcpy(buf, ac->urls[JAD_NEW_NONCE_URL]);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
					&ac->cwsi, &ac->i, buf,
					"GET");
			if (!cwsi) {
				lwsl_notice("%s: failed to connect to acme\n",
						__func__);
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_NEW_ACCOUNT:
			if ((ac->resp >= 200 && ac->resp < 299) ||
			    ac->resp == 409) {
				/*
				 * Our account already existed, or exists now.
				 *
				 */
				ac->state = ACME_STATE_NEW_ORDER;

				strcpy(buf, ac->urls[JAD_NEW_ORDER_URL]);
				cwsi = lws_acme_client_connect(vhd->context,
						vhd->vhost, &ac->cwsi,
						&ac->i, buf, "POST");
				if (!cwsi)
					lwsl_notice("%s: failed to connect\n",
							__func__);

				/* close the completed client connection */
				return -1;
			} else {
				lwsl_notice("newAccount replied %d\n",
						ac->resp);
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_NEW_ORDER:
			lejp_destruct(&ac->jctx);
			if (!ac->authz_url[0]) {
				lwsl_notice("no authz\n");
				goto failed;
			}

			/*
			 * Move on to requesting a cert auth.
			 */
			ac->state = ACME_STATE_AUTHZ;
			lws_acme_report_status(vhd->vhost, LWS_CUS_AUTH,
					NULL);

			strcpy(buf, ac->authz_url);
			cwsi = lws_acme_client_connect(vhd->context,
					vhd->vhost, &ac->cwsi,
					&ac->i, buf, "POST");
			if (!cwsi)
				lwsl_notice("%s: failed to connect\n", __func__);

			return -1; /* close the completed client connection */

		case ACME_STATE_AUTHZ:
			lejp_destruct(&ac->jctx);
			if (ac->resp / 100 == 4) {
				lws_snprintf(buf, sizeof(buf),
						"Auth failed: %s", ac->detail);
				failreason = buf;
				lwsl_vhost_warn(vhd->vhost, "auth failed");
				goto failed;
			}
			lwsl_vhost_info(vhd->vhost, "chall: %s (%d)\n", ac->chall_token, ac->resp);
			if (!ac->chall_token[0]) {
				lwsl_vhost_warn(vhd->vhost, "no challenge");
				goto failed;
			}

			ac->state = ACME_STATE_START_CHALL;
			lws_acme_report_status(vhd->vhost, LWS_CUS_CHALLENGE,
					NULL);

			memset(&ac->ci, 0, sizeof(ac->ci));

			/* compute the key authorization */

			p = ac->key_auth;
			end = p + sizeof(ac->key_auth) - 1;

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s.", ac->chall_token);
			lws_jwk_rfc7638_fingerprint(&vhd->jwk, digest);
			n = lws_jws_base64_enc(digest, 32, p, lws_ptr_diff_size_t(end, p));
			if (n < 0)
				goto failed;

			lwsl_vhost_notice(vhd->vhost, "key_auth: '%s'", ac->key_auth);

			int is_dns = vhd->active_cert && vhd->active_cert->challenge_type == LWS_ACME_CHALLENGE_TYPE_DNS_01;

			if (is_dns) {
				if (!vhd->ops || !vhd->ops->challenge_start) {
					lwsl_vhost_err(vhd->vhost, "dns-01 ops not provided");
					goto failed;
				}

				n = vhd->ops->challenge_start(vhd->vhost, vhd->challenge_priv,
					ac->chall_token, ac->key_auth,
				    vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME]);

				if (n) {
					lwsl_vhost_err(vhd->vhost, "dns-01 challenge start failed");
					goto failed;
				}
				return -1; /* dns-01 is asynchronous, it will reconnect Let's Encrypt after the propagation delay! */
			} else {
				lws_snprintf(ac->http01_mountpoint,
						sizeof(ac->http01_mountpoint),
						"/.well-known/acme-challenge/%s",
						ac->chall_token);

				memset(&ac->mount, 0, sizeof (struct lws_http_mount));
				ac->mount.protocol = "http";
				ac->mount.mountpoint = ac->http01_mountpoint;
				ac->mount.mountpoint_len = (unsigned char)
					strlen(ac->http01_mountpoint);
				ac->mount.origin_protocol = LWSMPRO_CALLBACK;

				ac->ci.mounts = &ac->mount;

				/* listen on the same port as the vhost that triggered us */
				ac->ci.port = 80;

				/* make ourselves protocols[0] for the new vhost */
				ac->ci.protocols = chall_http01_protocols;

				/*
				 * vhost .user points to the ac associated with the
				 * temporary vhost
				 */
				ac->ci.user = ac;

				ac->vhost = lws_create_vhost(lws_get_context(wsi),
						&ac->ci);
				if (!ac->vhost)
					goto failed;
			}

			lwsl_vhost_notice(vhd->vhost, "challenge_uri %s", ac->challenge_uri);

			/*
			 * The challenge-specific vhost is up... let the ACME
			 * server know we are ready to roll...
			 */
			ac->goes_around = 0;
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i,
						       ac->challenge_uri,
						       "POST");
			if (!cwsi) {
				lwsl_vhost_warn(vhd->vhost, "Connect failed");
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_START_CHALL:
			lwsl_vhost_notice(vhd->vhost, "COMPLETED start chall: %s",
				          ac->challenge_uri);
poll_again:
			ac->state = ACME_STATE_POLLING;
			lws_acme_report_status(vhd->vhost, LWS_CUS_CHALLENGE,
					       NULL);

			if (ac->goes_around++ == 200) {
				lwsl_notice("%s: too many chall retries\n",
						__func__);

				goto failed;
			}

			strcpy(buf, ac->order_url);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "POST");
			if (!cwsi) {
				lwsl_vhost_warn(vhd->vhost, "failed to connect to acme");

				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_POLLING:

			if (ac->resp == 202 && strcmp(ac->status, "invalid") &&
					       strcmp(ac->status, "valid"))
				goto poll_again;

			if (!strcmp(ac->status, "pending"))
				goto poll_again;

			if (!strcmp(ac->status, "invalid")) {
				lwsl_vhost_warn(vhd->vhost, "Challenge failed");
				lws_snprintf(buf, sizeof(buf),
						"Challenge Invalid: %s",
						ac->detail);
				failreason = buf;
				goto failed;
			}

			lwsl_vhost_notice(vhd->vhost, "ACME challenge passed");

			if (vhd->ops && vhd->ops->challenge_cleanup)
				vhd->ops->challenge_cleanup(vhd->vhost, vhd->challenge_priv);

			/*
			 * The challenge was validated... so delete the
			 * temp vhost now its job is done
			 */
			if (ac->vhost)
				lws_vhost_destroy(ac->vhost);
			ac->vhost = NULL;

			/*
			 * now our JWK is accepted as authorized to make
			 * requests for the domain, next move is create the
			 * CSR signed with the JWK, and send it to the ACME
			 * server to request the actual certs.
			 */
			ac->state = ACME_STATE_POLLING_CSR;
			lws_acme_report_status(vhd->vhost, LWS_CUS_REQ, NULL);
			ac->goes_around = 0;

			strcpy(buf, ac->finalize_url);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "POST");
			if (!cwsi) {
				lwsl_vhost_warn(vhd->vhost, "Failed to connect to acme");

				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_POLLING_CSR:
			if (ac->resp < 200 || ac->resp > 202) {
				lwsl_notice("CSR poll failed on resp %d\n",
						ac->resp);
				goto failed;
			}

			if (ac->resp != 200 || ac->cert_url[0] == '\0') {
				if (ac->goes_around++ == 200) {
					lwsl_vhost_warn(vhd->vhost, "Too many retries");

					goto failed;
				}
				strcpy(buf, ac->order_url);
				cwsi = lws_acme_client_connect(vhd->context,
						vhd->vhost,
						&ac->cwsi, &ac->i, buf,
						"POST");
				if (!cwsi) {
					lwsl_vhost_warn(vhd->vhost,
						"Failed to connect to acme");

					goto failed;
				}
				/* close the completed client connection */
				return -1;
			}

			ac->state = ACME_STATE_DOWNLOAD_CERT;

			strcpy(buf, ac->cert_url);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "POST");
			if (!cwsi) {
				lwsl_vhost_warn(vhd->vhost, "Failed to connect to acme");

				goto failed;
			}
			return -1;

		case ACME_STATE_DOWNLOAD_CERT:

			if (ac->resp != 200) {
				lwsl_vhost_warn(vhd->vhost, "Download cert failed on resp %d",
					    ac->resp);
				goto failed;
			}
			lwsl_vhost_notice(vhd->vhost, "The cert was sent..");

			lws_acme_report_status(vhd->vhost, LWS_CUS_ISSUE, NULL);

			/*
			 * That means we have the issued cert in
			 * ac->buf, length in ac->cpos; and the key in
			 * ac->alloc_privkey_pem, length in
			 * ac->len_privkey_pem.
			 * ACME 2.0 can send certs chain with 3 certs, we need save only first
			 */
			{
				char cert_ts[256], key_ts[256], full_ts[256];
				const char *cert_latest = vhd->active_cert->pvop[LWS_TLS_SET_CERT_PATH];
				const char *key_latest = vhd->active_cert->pvop[LWS_TLS_SET_KEY_PATH];
				char full_latest[256];
				char timebuf[64];
				time_t t;
				struct tm *tm;
				int fd_cert = -1, fd_key = -1, fd_full = -1;
				char *p;
				int cpos_fullchain = ac->cpos;

				char *end_cert = strstr(ac->buf, "END CERTIFICATE-----");

				if (end_cert) {
					ac->cpos = (int)(lws_ptr_diff_size_t(end_cert, ac->buf) + sizeof("END CERTIFICATE-----") - 1);
				} else {
					ac->cpos = 0;
					lwsl_vhost_err(vhd->vhost, "Unable to find ACME cert!");
					goto failed;
				}

				time(&t);
				tm = localtime(&t);
				strftime(timebuf, sizeof(timebuf), "%Y%m%d-%H%M%S", tm);

				lws_strncpy(cert_ts, cert_latest, sizeof(cert_ts));
				p = strstr(cert_ts, "-latest.crt");
				if (p)
					lws_snprintf(p, sizeof(cert_ts) - (size_t)(p - cert_ts), "-%s.crt", timebuf);

				lws_strncpy(full_latest, cert_latest, sizeof(full_latest));
				p = strstr(full_latest, "-latest.crt");
				if (p)
					lws_snprintf(p, sizeof(full_latest) - (size_t)(p - full_latest), "-latest-fullchain.crt");

				lws_strncpy(full_ts, full_latest, sizeof(full_ts));
				p = strstr(full_ts, "-latest-fullchain.crt");
				if (p)
					lws_snprintf(p, sizeof(full_ts) - (size_t)(p - full_ts), "-%s-fullchain.crt", timebuf);

				lws_strncpy(key_ts, key_latest, sizeof(key_ts));
				p = strstr(key_ts, "-latest.key");
				if (p)
					lws_snprintf(p, sizeof(key_ts) - (size_t)(p - key_ts), "-%s.key", timebuf);

#if !defined(LWS_WITH_ESP32)
				fd_cert = lws_open(cert_ts, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC
#ifdef WIN32
					| O_BINARY
#endif
					, 0600);
				if (fd_cert < 0) {
					lwsl_vhost_notice(vhd->vhost, "falling back to IPC footprint to save %s", cert_ts);
					const char *fn = strrchr(cert_ts, '/');
					if (fn) fn++; else fn = cert_ts;
					int r = acme_ipc_save_payload(vhd, "save_cert", vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] ? vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] : vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME], fn, ac->buf, (size_t)ac->cpos);
					if (r) {
						lwsl_vhost_err(vhd->vhost, "unable to create cert file %s", cert_ts);
						goto failed;
					}
				} else {
					n = lws_plat_write_cert(vhd->vhost, 0, fd_cert, ac->buf, (size_t)ac->cpos);
					close(fd_cert);
					if (n) {
						lwsl_vhost_err(vhd->vhost, "unable to write ACME cert!");
						goto failed;
					}
				}

				fd_key = lws_open(key_ts, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC
#ifdef WIN32
					| O_BINARY
#endif
					, 0600);
				if (fd_key < 0) {
					lwsl_vhost_notice(vhd->vhost, "falling back to IPC footprint to save %s", key_ts);
					const char *fn = strrchr(key_ts, '/');
					if (fn) fn++; else fn = key_ts;
					int r = acme_ipc_save_payload(vhd, "save_key", vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] ? vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] : vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME], fn, ac->alloc_privkey_pem, ac->len_privkey_pem);
					if (r) {
						lwsl_vhost_err(vhd->vhost, "unable to create key file %s", key_ts);
						goto failed;
					}
				} else {
					n = lws_plat_write_cert(vhd->vhost, 1, fd_key, ac->alloc_privkey_pem, ac->len_privkey_pem);
					close(fd_key);
					if (n) {
						lwsl_vhost_err(vhd->vhost, "unable to write ACME key!");
						goto failed;
					}
				}

				fd_full = lws_open(full_ts, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC
#ifdef WIN32
					| O_BINARY
#endif
					, 0600);
				if (fd_full < 0) {
					lwsl_vhost_notice(vhd->vhost, "falling back to IPC footprint to save %s", full_ts);
					const char *fn = strrchr(full_ts, '/');
					if (fn) fn++; else fn = full_ts;
					int r = acme_ipc_save_payload(vhd, "save_cert", vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] ? vhd->active_cert->pvop[LWS_TLS_SET_ROOT_DOMAIN] : vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME], fn, ac->buf, (size_t)cpos_fullchain);
					if (r) {
						lwsl_vhost_err(vhd->vhost, "unable to create fullchain file %s", full_ts);
					}
				} else {
					n = lws_plat_write_cert(vhd->vhost, 0, fd_full, ac->buf, (size_t)cpos_fullchain);
					close(fd_full);
					if (n) {
						lwsl_vhost_err(vhd->vhost, "unable to write ACME fullchain cert!");
					}
				}

				/* Symlink update */
				unlink(cert_latest);
				unlink(full_latest);
#if !defined(WIN32)
				symlink(strrchr(cert_ts, '/') ? strrchr(cert_ts, '/') + 1 : cert_ts, cert_latest);
				symlink(strrchr(full_ts, '/') ? strrchr(full_ts, '/') + 1 : full_ts, full_latest);
#endif

				unlink(key_latest);
#if !defined(WIN32)
				symlink(strrchr(key_ts, '/') ? strrchr(key_ts, '/') + 1 : key_ts, key_latest);
#endif

				lwsl_vhost_notice(vhd->vhost, "Updated certs written for %s "
						"to %s and %s",
					vhd->active_cert->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME],
					cert_ts,
					key_ts);
#else
				n = lws_plat_write_cert(vhd->vhost, 0, 0, ac->buf, (size_t)ac->cpos);
				if (n) {
					lwsl_vhost_err(vhd->vhost, "unable to write ACME cert!");
					goto failed;
				}

				n = lws_plat_write_cert(vhd->vhost, 1, 0, ac->alloc_privkey_pem, ac->len_privkey_pem);
				if (n) {
					lwsl_vhost_err(vhd->vhost, "unable to write ACME key!");
					goto failed;
				}
				lwsl_vhost_notice(vhd->vhost, "Updated certs written securely via NVS.");
#endif
			}

			/* notify lws there was a cert update */

			if (lws_tls_cert_updated(vhd->context,
					vhd->active_cert->pvop[LWS_TLS_SET_CERT_PATH],
					vhd->active_cert->pvop[LWS_TLS_SET_KEY_PATH],
						ac->buf, (size_t)ac->cpos,
						ac->alloc_privkey_pem,
						ac->len_privkey_pem)) {
				lwsl_vhost_warn(vhd->vhost, "problem setting certs");
			}

			lws_acme_finished(vhd);
			lws_acme_report_status(vhd->vhost,
					LWS_CUS_SUCCESS, NULL);

			return -1;

		default:
			break;
		}
		break;

	case LWS_CALLBACK_USER + 0xac33:
		if (!vhd)
			break;
		cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
				&ac->cwsi, &ac->i,
				ac->challenge_uri,
				"GET");
		if (!cwsi) {
			lwsl_vhost_warn(vhd->vhost, "Failed to connect");
			goto failed;
		}
		break;

	default:
		break;
	}

	return 0;

failed:
	if (vhd->ops && vhd->ops->challenge_cleanup)
		vhd->ops->challenge_cleanup(vhd->vhost, vhd->challenge_priv);

	lwsl_vhost_warn(vhd->vhost, "Failed out");
	lws_acme_report_status(vhd->vhost, LWS_CUS_FAILED, failreason);
	lws_acme_finished(vhd);

	return -1;
}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE struct per_vhost_data__lws_acme_client *
lws_acme_core_init_vhost(struct lws_context *context, struct lws_vhost *vh,
			 const struct lws_protocol_vhost_options *pvo,
			 const struct lws_acme_challenge_ops *ops, void *priv)
{
	struct per_vhost_data__lws_acme_client *vhd;

	vhd = (struct per_vhost_data__lws_acme_client *)
	      lws_protocol_vh_priv_get(vh, lws_vhost_name_to_protocol(vh, "lws-acme-client-core"));

	if (!vhd) {
		vhd = lws_protocol_vh_priv_zalloc(vh,
				lws_vhost_name_to_protocol(vh, "lws-acme-client-core"),
				sizeof(struct per_vhost_data__lws_acme_client));
		if (!vhd)
			return NULL;

		vhd->context = context;
		vhd->protocol = lws_vhost_name_to_protocol(vh, "lws-acme-client-core");
		vhd->vhost = vh;
	}

	vhd->ops = ops;
	vhd->challenge_priv = priv;

	return vhd;
}

LWS_VISIBLE void
lws_acme_core_destroy_vhost(struct per_vhost_data__lws_acme_client *vhd)
{
	/* lws_dll2 list cleanup happens in the overarching protocol destroy loop */
	if (vhd)
		lws_acme_finished(vhd);
}

LWS_VISIBLE int
lws_acme_core_cert_aging(struct per_vhost_data__lws_acme_client *vhd,
			 const struct lws_acme_cert_aging_args *caa)
{
	int n, days_left, total_days;
    struct lws_acme_cert_config *cfg;

	if (!vhd || !vhd->cert_configs.head)
		return 0;

    /* If we are already doing an ACME check, busy. Try again later */
    if (vhd->ac)
        return 0;

    lws_start_foreach_dll(struct lws_dll2 *, d, vhd->cert_configs.head) {
        cfg = lws_container_of(d, struct lws_acme_cert_config, list);

        if (!cfg->pvop[LWS_TLS_SET_CERT_PATH] || !cfg->pvop[LWS_TLS_SET_KEY_PATH])
            goto next_cert;

        /* Check if cert needs renewing based on 25% remaining validity */
        if (!lws_tls_cert_get_x509_remaining(vhd->context,
                                         cfg->pvop[LWS_TLS_SET_CERT_PATH],
                                         &days_left, &total_days)) {
             lwsl_vhost_notice(vhd->vhost, "acme: cert %s: %d days left, total %d",
                cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME], days_left, total_days);

             if (total_days && days_left > (total_days / 4))
                 goto next_cert; /* Still active! */
        }

        /* Activate this cert and configure it for acquisition! */
        vhd->active_cert = cfg;
        for (n = 0; n < LWS_TLS_TOTAL_COUNT; n++) {
            if (caa && caa->element_overrides[n])
                vhd->active_cert->pvop[n] = caa->element_overrides[n];
        }

        lwsl_notice("scheduling acme acquisition on %s (cert: %s): %s\n",
                lws_get_vhost_name(vhd->vhost),
                cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME],
                vhd->active_cert->pvop[LWS_TLS_SET_DIR_URL]);

        lws_sul_schedule(vhd->context, 0, &vhd->sul_acquisition,
                         lws_acme_start_acquisition_cb, 100 * LWS_US_PER_MS);
        return 0; /* Wait for this cert to finish before kicking off the next! */

next_cert:
		;
    } lws_end_foreach_dll(d);

	return 0;
}

LWS_VISIBLE void
lws_acme_core_notify_challenge_ready(struct per_vhost_data__lws_acme_client *vhd)
{
    struct acme_connection *ac = vhd->ac;
    if (!ac) return;
    ac->goes_around = 0;
    struct lws *cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
                           &ac->cwsi, &ac->i,
                           ac->challenge_uri,
                           "POST");
    if (!cwsi) {
        lwsl_vhost_warn(vhd->vhost, "Connect failed");
        // goto failed; // Not easy to jump to failed here, let poll timeout handle it
    }
}

LWS_VISIBLE void
lws_acme_core_destroy_vhost(struct per_vhost_data__lws_acme_client *vhd);

LWS_VISIBLE int
lws_acme_core_cert_aging(struct per_vhost_data__lws_acme_client *vhd,
			 const struct lws_acme_cert_aging_args *caa);

LWS_VISIBLE void
lws_acme_core_notify_challenge_ready(struct per_vhost_data__lws_acme_client *vhd);

static const struct lws_acme_core_ops acme_core_ops = {
	.init_vhost = lws_acme_core_init_vhost,
	.destroy_vhost = lws_acme_core_destroy_vhost,
	.cert_aging = lws_acme_core_cert_aging,
	.notify_challenge_ready = lws_acme_core_notify_challenge_ready
};

LWS_VISIBLE const struct lws_protocols lws_acme_client_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_acme_client_core = {
	.hdr = {
		.name = "acme client core",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_acme_client_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_acme_client_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
