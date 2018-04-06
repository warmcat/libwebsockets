/*
 * libwebsockets ACME client protocol plugin
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *
 *  Acme is in a big messy transition at the moment from a homebrewed api
 *  to an IETF one.  The old repo for the homebrew api (they currently
 *  implement) is marked up as deprecated and "not accurate[ly] reflect[ing]"
 *  what they implement, but the IETF standard, currently at v7 is not yet
 *  implemented at let's encrypt (ETA Jan 2018).
 *
 *  This implementation follows draft 7 of the IETF standard, and falls back
 *  to whatever differences exist for Boulder's tls-sni-01 challenge.  The
 *  tls-sni-02 support is there but nothing to test it against at the time of
 *  writing (Nov 1 2017).
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>
#include <stdlib.h>

typedef enum {
	ACME_STATE_DIRECTORY,	 /* get the directory JSON using GET + parse */
	ACME_STATE_NEW_REG,	 /* register a new RSA key + email combo */
	ACME_STATE_NEW_AUTH,	 /* start the process to request a cert */
	ACME_STATE_ACCEPT_CHALL, /* notify server ready for one challenge */
	ACME_STATE_POLLING,	 /* he should be trying our challenge */
	ACME_STATE_POLLING_CSR,	 /* sent CSR, checking result */

	ACME_STATE_FINISHED
} lws_acme_state;

struct acme_connection {
	char buf[4096];
	char replay_nonce[64];
	char chall_token[64];
	char challenge_uri[256];
	char detail[64];
	char status[16];
	char san_a[100];
	char san_b[100];
	char urls[6][100]; /* directory contents */
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

	unsigned int yes:2;
	unsigned int use:1;
	unsigned int is_sni_02:1;
};

struct per_vhost_data__lws_acme_client {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	/*
	 * the vhd is allocated for every vhost using the plugin.
	 * But ac is only allocated when we are doing the server auth.
	 */
	struct acme_connection *ac;

	struct lws_jwk jwk;
	struct lws_genrsa_ctx rsactx;

	char *pvo_data;
	char *pvop[LWS_TLS_TOTAL_COUNT];
	const char *pvop_active[LWS_TLS_TOTAL_COUNT];
	int count_live_pss;
	char *dest;
	int pos;
	int len;

	int fd_updated_cert; /* these are opened while we have root... */
	int fd_updated_key; /* ...if nonempty next startup will replace old */
};

static int
callback_acme_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len);

#define LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT \
	{ \
		"lws-acme-client", \
		callback_acme_client, \
		0, \
		512, \
		0, NULL, 0 \
	}

static const struct lws_protocols acme_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT,
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/* directory JSON parsing */

static const char * const jdir_tok[] = {
	"key-change",
	"meta.terms-of-service",
	"new-authz",
	"new-cert",
	"new-reg",
	"revoke-cert",
};
enum enum_jhdr_tok {
	JAD_KEY_CHANGE_URL,
	JAD_TOS_URL,
	JAD_NEW_AUTHZ_URL,
	JAD_NEW_CERT_URL,
	JAD_NEW_REG_URL,
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

/* authz JSON parsing */

static const char * const jauthz_tok[] = {
	"identifier.type",
	"identifier.value",
	"status",
	"expires",
	"challenges[].type",
	"challenges[].status",
	"challenges[].uri",
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
	JAAZ_CHALLENGES_URI,
	JAAZ_CHALLENGES_TOKEN,
	JAAZ_DETAIL,
};
static signed char
cb_authz(struct lejp_ctx *ctx, char reason)
{
	struct acme_connection *s = (struct acme_connection *)ctx->user;

	if (reason == LEJPCB_CONSTRUCTED) {
		s->yes = 0;
		s->use = 0;
		s->chall_token[0] = '\0';
		s->is_sni_02 = 0;
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
		if (s->is_sni_02)
			break;
		s->use = !strcmp(ctx->buf, "tls-sni-01") ||
			 !strcmp(ctx->buf, "tls-sni-02");
		s->is_sni_02 = !strcmp(ctx->buf, "tls-sni-02");
		break;
	case JAAZ_CHALLENGES_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JAAZ_CHALLENGES_URI:
		if (s->use) {
			lws_strncpy(s->challenge_uri, ctx->buf,
				sizeof(s->challenge_uri));
			s->yes |= 2;
		}
		break;
	case JAAZ_CHALLENGES_TOKEN:
		lwsl_notice("JAAZ_CHALLENGES_TOKEN: %s %d\n", ctx->buf, s->use);
		if (s->use) {
			lws_strncpy(s->chall_token, ctx->buf,
				sizeof(s->chall_token));
			s->yes |= 1;
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
		if (strcmp(ctx->buf, "tls-sni-01") &&
		    strcmp(ctx->buf, "tls-sni-02"))
			return 1;
		break;
	case JCAC_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JCAC_URI:
		s->yes |= 2;
		break;
	case JCAC_TOKEN:
		lws_strncpy(s->chall_token, ctx->buf,
				sizeof(s->chall_token));
		s->yes |= 1;
		break;
	case JCAC_DETAIL:
		lws_snprintf(s->detail, sizeof(s->detail), "%s", ctx->buf);
		break;
	}

	return 0;
}

/* https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md
 *
 * 7.1:
 *
 * Boulder does not implement the new-order resource.
 * Instead of new-order Boulder implements the new-cert resource that is
 * defined in draft-ietf-acme-02 Section 6.5.
 *
 * Boulder also doesn't implement the new-nonce endpoint.
 *
 * Boulder implements the new-account resource only under the new-reg key.
 *
 * Boulder implements Link: rel="next" headers from new-reg to new-authz, and
 * new-authz to new-cert, as specified in draft-02, but these links are not
 * provided in the latest draft, and clients should use URLs from the directory
 * instead.
 *
 * Boulder does not provide the "index" link relation pointing at the
 * directory URL.
 *
 * (ie, just use new-cert instead of new-order, use the directory for links)
 */

static int
lws_acme_report_status(struct lws_vhost *v, int state, const char *json)
{
	lws_callback_vhost_protocols_vhost(v, LWS_CALLBACK_VHOST_CERT_UPDATE,
					   (void *)json, state);

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
	const char *prot, *p;
	char path[200], _url[256];
	struct lws *wsi;

	memset(i, 0, sizeof(*i));
	i->port = 443;
	lws_strncpy(_url, url, sizeof(_url));
	if (lws_parse_uri(_url, &prot, &i->address, &i->port, &p)) {
		lwsl_err("unable to parse uri %s\n", url);

		return NULL;
	}

	/* add back the leading / on path */
	path[0] = '/';
	lws_strncpy(path + 1, p, sizeof(path) - 1);
	i->path = path;
	i->context = context;
	i->vhost = vh;
	i->ssl_connection = 1;
	i->host = i->address;
	i->origin = i->address;
	i->method = method;
	i->pwsi = pwsi;
	i->protocol = "lws-acme-client";

	wsi = lws_client_connect_via_info(i);
	if (!wsi) {
		lws_snprintf(path, sizeof(path) - 1,
			     "Unable to connect to %s", url);
		lwsl_notice("%s: %s\n", __func__, path);
		lws_acme_report_status(vh, LWS_CUS_FAILED, path);
	}

	return wsi;
}

static void
lws_acme_finished(struct per_vhost_data__lws_acme_client *vhd)
{
	lwsl_debug("%s\n", __func__);

	if (vhd->ac) {
		if (vhd->ac->vhost)
			lws_vhost_destroy(vhd->ac->vhost);
		if (vhd->ac->alloc_privkey_pem)
			free(vhd->ac->alloc_privkey_pem);
		free(vhd->ac);
	}

	lws_genrsa_destroy(&vhd->rsactx);
	lws_jwk_destroy(&vhd->jwk);

	vhd->ac = NULL;
#if defined(LWS_WITH_ESP32)
	lws_esp32.acme = 0; /* enable scanning */
#endif
}

static const char * const pvo_names[] = {
	"country",
	"state",
	"locality",
	"organization",
	"common-name",
	"email",
	"directory-url",
	"auth-path",
	"cert-path",
	"key-path",
};

static int
lws_acme_load_create_auth_keys(struct per_vhost_data__lws_acme_client *vhd,
			       int bits)
{
	int n;

	if (!lws_jwk_load(&vhd->jwk, vhd->pvop[LWS_TLS_SET_AUTH_PATH]))
		return 0;

	strcpy(vhd->jwk.keytype, "RSA");
	lwsl_notice("Generating ACME %d-bit keypair... "
		    "will take a little while\n", bits);
	n = lws_genrsa_new_keypair(vhd->context, &vhd->rsactx, &vhd->jwk.el,
				   bits);
	if (n) {
		lwsl_notice("failed to create keypair\n");

		return 1;
	}

	lwsl_notice("...keypair generated\n");

	if (lws_jwk_save(&vhd->jwk,
		    vhd->pvop[LWS_TLS_SET_AUTH_PATH])) {
		lwsl_notice("unable to save %s\n",
		      vhd->pvop[LWS_TLS_SET_AUTH_PATH]);

		return 1;
	}

	return 0;
}

static int
lws_acme_start_acquisition(struct per_vhost_data__lws_acme_client *vhd,
			   struct lws_vhost *v)
{
	char buf[128];

	/* ...and we were given enough info to do the update? */

	if (!vhd->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME])
		return -1;

	/*
	 * ...well... we should try to do something about it then...
	 */
	lwsl_notice("%s: ACME cert needs creating / updating:  "
		    "vhost %s\n", __func__, lws_get_vhost_name(vhd->vhost));

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
			     vhd->pvop_active[LWS_TLS_SET_DIR_URL]);
	} else {
		vhd->ac->state = ACME_STATE_NEW_REG;
		lws_snprintf(buf, sizeof(buf) - 1, "%s",
			     vhd->ac->urls[JAD_NEW_REG_URL]);
	}

	vhd->ac->real_vh_port = lws_get_vhost_port(vhd->vhost);
	vhd->ac->real_vh_name = lws_get_vhost_name(vhd->vhost);
	vhd->ac->real_vh_iface = lws_get_vhost_iface(vhd->vhost);

	lws_acme_report_status(vhd->vhost, LWS_CUS_STARTING, NULL);

#if defined(LWS_WITH_ESP32)
	lws_acme_report_status(vhd->vhost, LWS_CUS_CREATE_KEYS,
			       "Generating keys, please wait");
	if (lws_acme_load_create_auth_keys(vhd, 2048))
		goto bail;
	lws_acme_report_status(vhd->vhost, LWS_CUS_CREATE_KEYS,
			       "Auth keys created");
#endif

	if (lws_acme_client_connect(vhd->context, vhd->vhost,
				    &vhd->ac->cwsi, &vhd->ac->i, buf, "GET"))
		return 0;

#if defined(LWS_WITH_ESP32)
bail:
#endif
	free(vhd->ac);
	vhd->ac = NULL;

	return 1;
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
	unsigned char **pp, *pend;
	const char *content_type;
	const struct lws_protocol_vhost_options *pvo;
	struct lws_acme_cert_aging_args *caa;
	struct acme_connection *ac = NULL;
	struct lws_genhash_ctx hctx;
	struct lws *cwsi;
	int n, m;

	if (vhd)
		ac = vhd->ac;

	switch ((int)reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_acme_client));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		/* compute how much we need to hold all the pvo payloads */
		m = 0;
		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			m += strlen(pvo->value) + 1;
			pvo = pvo->next;
		}
		p = vhd->pvo_data = malloc(m);
		if (!p)
			return -1;

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			start = p;
			n = strlen(pvo->value) + 1;
			memcpy(start, pvo->value, n);
			p += n;

			for (m = 0; m < (int)ARRAY_SIZE(pvo_names); m++)
				if (!strcmp(pvo->name, pvo_names[m]))
					vhd->pvop[m] = start;

			pvo = pvo->next;
		}

		n = 0;
		for (m = 0; m < (int)ARRAY_SIZE(pvo_names); m++)
			if (!vhd->pvop[m] && m >= LWS_TLS_REQ_ELEMENT_COMMON_NAME) {
				lwsl_notice("%s: require pvo '%s'\n", __func__,
						pvo_names[m]);
				n |= 1;
			} else
				if (vhd->pvop[m])
					lwsl_info("  %s: %s\n", pvo_names[m],
							vhd->pvop[m]);
		if (n) {
			free(vhd->pvo_data);
			vhd->pvo_data = NULL;

			return -1;
		}

#if !defined(LWS_WITH_ESP32)
		/*
		 * load (or create) the registration keypair while we
		 * still have root
		 */
		if (lws_acme_load_create_auth_keys(vhd, 4096))
			return 1;

		/*
		 * in case we do an update, open the update files while we
		 * still have root
		 */
		lws_snprintf(buf, sizeof(buf) - 1, "%s.upd",
			     vhd->pvop[LWS_TLS_SET_CERT_PATH]);
		vhd->fd_updated_cert = open(buf, LWS_O_WRONLY | LWS_O_CREAT |
						 LWS_O_TRUNC, 0600);
		if (vhd->fd_updated_cert < 0) {
			lwsl_err("unable to create update cert file %s\n", buf);
			return -1;
		}
		lws_snprintf(buf, sizeof(buf) - 1, "%s.upd",
			     vhd->pvop[LWS_TLS_SET_KEY_PATH]);
		vhd->fd_updated_key = open(buf, LWS_O_WRONLY | LWS_O_CREAT |
						LWS_O_TRUNC, 0600);
		if (vhd->fd_updated_key < 0) {
			lwsl_err("unable to create update key file %s\n", buf);
			return -1;
		}
#endif
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->pvo_data) {
			free(vhd->pvo_data);
			vhd->pvo_data = NULL;
		}
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

		for (n = 0; n < (int)ARRAY_SIZE(vhd->pvop);n++)
			if (caa->element_overrides[n])
				vhd->pvop_active[n] = caa->element_overrides[n];
			else
				vhd->pvop_active[n] = vhd->pvop[n];

		lwsl_notice("starting acme acquisition on %s: %s\n",
				lws_get_vhost_name(caa->vh), vhd->pvop_active[LWS_TLS_SET_DIR_URL]);

		lws_acme_start_acquisition(vhd, caa->vh);
		break;

	/*
	 * Client
	 */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("%s: CLIENT_ESTABLISHED\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: CLIENT_CONNECTION_ERROR: %p\n", __func__, wsi);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_notice("%s: CLOSED_CLIENT_HTTP: %p\n", __func__, wsi);
		break;

	case LWS_CALLBACK_CLOSED:
		lwsl_notice("%s: CLOSED: %p\n", __func__, wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_notice("lws_http_client_http_response %d\n",
			    lws_http_client_http_response(wsi));
		if (!ac)
			break;
		ac->resp = lws_http_client_http_response(wsi);
		/* we get a new nonce each time */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_REPLAY_NONCE) &&
		    lws_hdr_copy(wsi, ac->replay_nonce,
				 sizeof(ac->replay_nonce),
				 WSI_TOKEN_REPLAY_NONCE) < 0) {
			lwsl_notice("%s: nonce too large\n", __func__);

			goto failed;
		}

		switch (ac->state) {
		case ACME_STATE_DIRECTORY:
			lejp_construct(&ac->jctx, cb_dir, vhd, jdir_tok,
				       ARRAY_SIZE(jdir_tok));
			break;
		case ACME_STATE_NEW_REG:
			break;
		case ACME_STATE_NEW_AUTH:
			lejp_construct(&ac->jctx, cb_authz, ac, jauthz_tok,
				       ARRAY_SIZE(jauthz_tok));
			break;

		case ACME_STATE_POLLING:
		case ACME_STATE_ACCEPT_CHALL:
			lejp_construct(&ac->jctx, cb_chac, ac, jchac_tok,
				       ARRAY_SIZE(jchac_tok));
			break;

		case ACME_STATE_POLLING_CSR:
			ac->cpos = 0;
			if (ac->resp != 201)
				break;
			/*
			 * He acknowledges he will create the cert...
			 * get the URL to GET it from in the Location
			 * header.
			 */
			if (lws_hdr_copy(wsi, ac->challenge_uri,
					 sizeof(ac->challenge_uri),
					 WSI_TOKEN_HTTP_LOCATION) < 0) {
				lwsl_notice("%s: missing cert location:\n",
					    __func__);

				goto failed;
			}

			lwsl_notice("told to fetch cert from %s\n",
					ac->challenge_uri);
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
			break;
		case ACME_STATE_NEW_REG:
			p += lws_snprintf(p, end - p, "{"
					  "\"resource\":\"new-reg\","
					  "\"contact\":["
					  "\"mailto:%s\""
					  "],\"agreement\":\"%s\""
					  "}",
					  vhd->pvop_active[LWS_TLS_REQ_ELEMENT_EMAIL],
					  ac->urls[JAD_TOS_URL]);

			puts(start);
pkt_add_hdrs:
			ac->len = lws_jws_create_packet(&vhd->jwk,
							start, p - start,
							ac->replay_nonce,
							&ac->buf[LWS_PRE],
							sizeof(ac->buf) -
								 LWS_PRE);
			if (ac->len < 0) {
				ac->len = 0;
				lwsl_notice("lws_jws_create_packet failed\n");
				goto failed;
			}

			pp = (unsigned char **)in;
			pend = (*pp) + len;

			ac->pos = 0;
			content_type =         "application/jose+json";
			if (ac->state == ACME_STATE_POLLING_CSR)
				content_type = "application/pkix-cert";

			if (lws_add_http_header_by_token(wsi,
				    WSI_TOKEN_HTTP_CONTENT_TYPE,
					(uint8_t *)content_type, 21, pp, pend)) {
				lwsl_notice("could not add content type\n");
				goto failed;
			}

			n = sprintf(buf, "%d", ac->len);
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(uint8_t *)buf, n, pp, pend)) {
				lwsl_notice("could not add content length\n");
				goto failed;
			}

			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
			lwsl_notice("prepare to send ACME_STATE_NEW_REG\n");
			break;
		case ACME_STATE_NEW_AUTH:
			p += lws_snprintf(p, end - p,
					"{"
					 "\"resource\":\"new-authz\","
					 "\"identifier\":{"
					  "\"type\":\"http-01\","
					  "\"value\":\"%s\""
					 "}"
					"}", vhd->pvop_active[LWS_TLS_REQ_ELEMENT_COMMON_NAME]);
			goto pkt_add_hdrs;

		case ACME_STATE_ACCEPT_CHALL:
			/*
			 * Several of the challenges in this document makes use
			 * of a key authorization string.  A key authorization
			 * expresses a domain holder's authorization for a
			 * specified key to satisfy a specified challenge, by
			 * concatenating the token for the challenge with a key
			 * fingerprint, separated by a "." character:
			 *
			 * key-authz = token || '.' ||
			 * 	       base64(JWK_Thumbprint(accountKey))
			 *
			 * The "JWK_Thumbprint" step indicates the computation
			 * specified in [RFC7638], using the SHA-256 digest.  As
			 * specified in the individual challenges below, the
			 * token for a challenge is a JSON string comprised
			 * entirely of characters in the base64 alphabet.
			 * The "||" operator indicates concatenation of strings.
			 *
			 *    keyAuthorization (required, string):  The key
			 *  authorization for this challenge.  This value MUST
			 *  match the token from the challenge and the client's
			 *  account key.
			 *
			 * draft acme-01 tls-sni-01:
			 *
			 *    {
			 *         "keyAuthorization": "evaGxfADs...62jcerQ",
			 *    }   (Signed as JWS)
			 *
			 * draft acme-07 tls-sni-02:
			 *
			 * POST /acme/authz/1234/1
			 * Host: example.com
			 * Content-Type: application/jose+json
			 *
			 * {
			 *  "protected": base64url({
			 *    "alg": "ES256",
			 *    "kid": "https://example.com/acme/acct/1",
			 *    "nonce": "JHb54aT_KTXBWQOzGYkt9A",
			 *    "url": "https://example.com/acme/authz/1234/1"
			 *  }),
			 *  "payload": base64url({
			 *     "keyAuthorization": "evaGxfADs...62jcerQ"
			 *  }),
			 * "signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
			 * }
			 *
			 * On receiving a response, the server MUST verify that
			 * the key authorization in the response matches the
			 * "token" value in the challenge and the client's
			 * account key.  If they do not match, then the server
			 * MUST return an HTTP error in response to the POST
			 * request in which the client sent the challenge.
			 */

			lws_jwk_rfc7638_fingerprint(&vhd->jwk, digest);
			p = start;
			end = &buf[sizeof(buf) - 1];

			p += lws_snprintf(p, end - p,
					  "{\"resource\":\"challenge\","
					  "\"type\":\"tls-sni-0%d\","
					  "\"keyAuthorization\":\"%s.",
					  1 + ac->is_sni_02,
					  ac->chall_token);
			n = lws_jws_base64_enc(digest, 32, p, end - p);
			if (n < 0)
				goto failed;
			p += n;
			p += lws_snprintf(p, end - p, "\"}");
			puts(start);
			goto pkt_add_hdrs;

		case ACME_STATE_POLLING:
			break;

		case ACME_STATE_POLLING_CSR:
			/*
			 * "To obtain a certificate for the domain, the agent
			 * constructs a PKCS#10 Certificate Signing Request that
			 * asks the Let’s Encrypt CA to issue a certificate for
			 * example.com with a specified public key. As usual,
			 * the CSR includes a signature by the private key
			 * corresponding to the public key in the CSR. The agent
			 * also signs the whole CSR with the authorized
			 * key for example.com so that the Let’s Encrypt CA
			 * knows it’s authorized."
			 *
			 * IOW we must create a new RSA keypair which will be
			 * the cert public + private key, and put the public
			 * key in the CSR.  The CSR, just for transport, is also
			 * signed with our JWK, showing that as the owner of the
			 * authorized JWK, the request should be allowed.
			 *
			 * The cert comes back with our public key in it showing
			 * that the owner of the matching private key (we
			 * created that keypair) is the owner of the cert.
			 *
			 * We feed the CSR the elements we want in the cert,
			 * like the CN etc, and it gives us the b64URL-encoded
			 * CSR and the PEM-encoded (public +)private key in
			 * memory buffers.
			 */
			if (ac->goes_around)
				break;

			p += lws_snprintf(p, end - p,
					  "{\"resource\":\"new-cert\","
					  "\"csr\":\"");
			n = lws_tls_acme_sni_csr_create(vhd->context,
							&vhd->pvop_active[0],
							(uint8_t *)p, end - p,
							&ac->alloc_privkey_pem,
							&ac->len_privkey_pem);
			if (n < 0) {
				lwsl_notice("CSR generation failed\n");
				goto failed;
			}
			p += n;
			p += lws_snprintf(p, end - p, "\"}");
			puts(start);
			goto pkt_add_hdrs;

		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		lwsl_notice("LWS_CALLBACK_CLIENT_HTTP_WRITEABLE\n");
		if (!ac)
			break;
		if (ac->pos == ac->len)
			break;

		ac->buf[LWS_PRE + ac->len] = '\0';
		if (lws_write(wsi, (uint8_t *)ac->buf + LWS_PRE,
			      ac->len, LWS_WRITE_HTTP_FINAL) < 0)
			return -1;
		lwsl_notice("wrote %d\n", ac->len);
		ac->pos = ac->len;
		lws_client_http_body_pending(wsi, 0);
		break;

	/* chunked content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!ac)
			return -1;
		switch (ac->state) {
		case ACME_STATE_POLLING:
		case ACME_STATE_ACCEPT_CHALL:
		case ACME_STATE_NEW_AUTH:
		case ACME_STATE_DIRECTORY:
			((char *)in)[len] = '\0';
			puts(in);
			m = (int)(signed char)lejp_parse(&ac->jctx,
							 (uint8_t *)in, len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_notice("lejp parse failed %d\n", m);
				goto failed;
			}
			break;
		case ACME_STATE_NEW_REG:
			((char *)in)[len] = '\0';
			puts(in);
			break;
		case ACME_STATE_POLLING_CSR:
			/* it should be the DER cert! */
			if (ac->cpos + len > sizeof(ac->buf)) {
				lwsl_notice("Incoming cert is too large!\n");
				goto failed;
			}
			memcpy(&ac->buf[ac->cpos], in, len);
			ac->cpos += len;
			break;
		default:
			break;
		}
		break;

	/* unchunked content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		lwsl_notice("%s: LWS_CALLBACK_RECEIVE_CLIENT_HTTP\n", __func__);
		{
			char buffer[2048 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_notice("%s: COMPLETED_CLIENT_HTTP\n", __func__);

		if (!ac)
			return -1;
		switch (ac->state) {
		case ACME_STATE_DIRECTORY:
			lejp_destruct(&ac->jctx);

			/* check dir validity */

			for (n = 0; n < 6; n++)
				lwsl_notice("   %d: %s\n", n, ac->urls[n]);

			/*
			 * So... having the directory now... we try to
			 * register our keys next.  It's OK if it ends up
			 * they're already registered... this eliminates any
			 * gaps where we stored the key but registration did
			 * not complete for some reason...
			 */
			ac->state = ACME_STATE_NEW_REG;
			lws_acme_report_status(vhd->vhost, LWS_CUS_REG, NULL);

			strcpy(buf, ac->urls[JAD_NEW_REG_URL]);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "POST");
			if (!cwsi) {
				lwsl_notice("%s: failed to connect to acme\n",
					    __func__);
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_NEW_REG:
			if ((ac->resp >= 200 && ac->resp < 299) ||
			     ac->resp == 409) {
				/*
				 * Our account already existed, or exists now.
				 *
				 * Move on to requesting a cert auth.
				 */
				ac->state = ACME_STATE_NEW_AUTH;
				lws_acme_report_status(vhd->vhost, LWS_CUS_AUTH,
							NULL);

				strcpy(buf, ac->urls[JAD_NEW_AUTHZ_URL]);
				cwsi = lws_acme_client_connect(vhd->context,
							vhd->vhost, &ac->cwsi,
							&ac->i, buf, "POST");
				if (!cwsi)
					lwsl_notice("%s: failed to connect\n",
						    __func__);
				return -1; /* close the completed client connection */
			} else {
				lwsl_notice("new-reg replied %d\n", ac->resp);
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_NEW_AUTH:
			lejp_destruct(&ac->jctx);
			if (ac->resp / 100 == 4) {
				lws_snprintf(buf, sizeof(buf),
					     "Auth failed: %s", ac->detail);
				failreason = buf;
				lwsl_notice("auth failed\n");
				goto failed;
			}
			lwsl_notice("chall: %s (%d)\n", ac->chall_token, ac->resp);
			if (!ac->chall_token[0]) {
				lwsl_notice("no challenge\n");
				goto failed;
			}


			ac->state = ACME_STATE_ACCEPT_CHALL;
			lws_acme_report_status(vhd->vhost, LWS_CUS_CHALLENGE,
						NULL);

			/* tls-sni-01 ... what a mess.
			 * The stuff in
			 * https://tools.ietf.org/html/
			 * 		draft-ietf-acme-acme-01#section-7.3
			 * "requires" n but it's missing from let's encrypt
			 * tls-sni-01 challenge.  The go docs say that they just
			 * implement one hashing round regardless
			 * https://godoc.org/golang.org/x/crypto/acme
			 *
			 * The go way is what is actually implemented today by
			 * letsencrypt
			 *
			 * "A client responds to this challenge by constructing
			 * a key authorization from the "token" value provided
			 * in the challenge and the client's account key.  The
			 * client first computes the SHA-256 digest Z0 of the
			 * UTF8-encoded key authorization, and encodes Z0 in
			 * UTF-8 lower-case hexadecimal form."
			 */

			/* tls-sni-02
			 *
			 * SAN A MUST be constructed as follows: compute the
			 * SHA-256 digest of the UTF-8-encoded challenge token
			 * and encode it in lowercase hexadecimal form.  The
			 * dNSName is "x.y.token.acme.invalid", where x
			 * is the first half of the hexadecimal representation
			 * and y is the second half.
			 */

			memset(&ac->ci, 0, sizeof(ac->ci));

			/* first compute the key authorization */

			lws_jwk_rfc7638_fingerprint(&vhd->jwk, digest);
			p = start;
			end = &buf[sizeof(buf) - 1];

			p += lws_snprintf(p, end - p, "%s.", ac->chall_token);
			n = lws_jws_base64_enc(digest, 32, p, end - p);
			if (n < 0)
				goto failed;
			p += n;

			if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256))
				return -1;

			if (lws_genhash_update(&hctx, (uint8_t *)start,
						lws_ptr_diff(p, start))) {
				lws_genhash_destroy(&hctx, NULL);

				return -1;
			}
			if (lws_genhash_destroy(&hctx, digest))
				return -1;

			p = buf;
			for (n = 0; n < 32; n++) {
				p += lws_snprintf(p, end - p, "%02x",
						  digest[n] & 0xff);
				if (n == (32 / 2) - 1)
					p = buf + 64;
			}

			p = ac->san_a;
			if (ac->is_sni_02) {
				lws_snprintf(p, sizeof(ac->san_a),
					     "%s.%s.token.acme.invalid",
					     buf, buf + 64);

				/*
				 * SAN B MUST be constructed as follows: compute
				 * the SHA-256 digest of the UTF-8 encoded key
				 * authorization and encode it in lowercase
				 * hexadecimal form.  The dNSName is
				 * "x.y.ka.acme.invalid" where x is the first
				 * half of the hexadecimal representation and y
				 * is the second half.
				 */
				lws_jwk_rfc7638_fingerprint(&vhd->jwk,
							    (char *)digest);

				p = buf;
				for (n = 0; n < 32; n++) {
					p += lws_snprintf(p, end - p, "%02x",
							  digest[n] & 0xff);
					if (n == (32 / 2) - 1)
						p = buf + 64;
				}

				p = ac->san_b;
				lws_snprintf(p, sizeof(ac->san_b),
					     "%s.%s.ka.acme.invalid",
					     buf, buf + 64);
			} else {
				lws_snprintf(p, sizeof(ac->san_a),
				     "%s.%s.acme.invalid", buf, buf + 64);
				ac->san_b[0] = '\0';
			}

			lwsl_notice("san_a: '%s'\n", ac->san_a);
			lwsl_notice("san_b: '%s'\n", ac->san_b);

			/*
			 * tls-sni-01:
			 *
			 * The client then configures the TLS server at the
			 * domain such that when a handshake is initiated with
			 * the Server Name Indication extension set to
			 * "<Zi[0:32]>.<Zi[32:64]>.acme.invalid", the
			 * corresponding generated certificate is presented.
			 *
			 * tls-sni-02:
			 *
			 *  The client MUST ensure that the certificate is
			 *  served to TLS connections specifying a Server Name
			 *  Indication (SNI) value of SAN A.
			 */
			ac->ci.vhost_name = ac->san_a;

			/*
			 * we bind to exact iface of real vhost, so we can
			 * share the listen socket by SNI
			 */
			ac->ci.iface = ac->real_vh_iface;

			/* listen on the same port as the vhost that triggered
			 * us */
			ac->ci.port = ac->real_vh_port;
			/* Skip filling in any x509 info into the ssl_ctx.
			 * It will be done at the callback
			 * LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS
			 * in this callback handler (below)
			 */
			ac->ci.options = LWS_SERVER_OPTION_CREATE_VHOST_SSL_CTX |
					 LWS_SERVER_OPTION_SKIP_PROTOCOL_INIT |
					 LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			/* make ourselves protocols[0] for the new vhost */
			ac->ci.protocols = acme_protocols;
			/*
			 * vhost .user points to the ac associated with the
			 * temporary vhost
			 */
			ac->ci.user = ac;

			ac->vhost = lws_create_vhost(lws_get_context(wsi),
						     &ac->ci);
			if (!ac->vhost)
				goto failed;

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
				lwsl_notice("%s: failed to connect\n",
					    __func__);
				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_ACCEPT_CHALL:
			/*
			 * he returned something like this (which we parsed)
			 *
			 * {
			 *   "type": "tls-sni-01",
			 *   "status": "pending",
			 *   "uri": "https://acme-staging.api.letsencrypt.org/
			 *   		acme/challenge/xCt7bT3FaxoIQU3Qry87t5h
			 *   		uKDcC-L-0ERcD5DLAZts/71100507",
			 *   "token": "j2Vs-vLI_dsza4A35SFHIU03aIe2PzFRijbqCY
			 *   		dIVeE",
			 *   "keyAuthorization": "j2Vs-vLI_dsza4A35SFHIU03aIe2
			 *   		PzFRijbqCYdIVeE.nmOtdFd8Jikn6K8NnYYmT5
			 *   		vCM_PwSDT8nLdOYoFXhRU"
			 * }
			 *
			 */
			lwsl_notice("%s: COMPLETED accept chall: %s\n",
					__func__, ac->challenge_uri);
poll_again:
			ac->state = ACME_STATE_POLLING;
			lws_acme_report_status(vhd->vhost, LWS_CUS_CHALLENGE, NULL);

			if (ac->goes_around++ == 20) {
				lwsl_notice("%s: too many chall retries\n",
					    __func__);

				goto failed;
			}

			lws_timed_callback_vh_protocol(vhd->vhost, vhd->protocol,
					LWS_CALLBACK_USER + 0xac33, ac->goes_around == 1 ? 10 : 2);
			return -1; /* close the completed client connection */

		case ACME_STATE_POLLING:

			if (ac->resp == 202 &&
			    strcmp(ac->status, "invalid") &&
			    strcmp(ac->status, "valid")) {
				lwsl_notice("status: %s\n", ac->status);
				goto poll_again;
			}

			if (!strcmp(ac->status, "invalid")) {
				lwsl_notice("%s: polling failed\n", __func__);
				lws_snprintf(buf, sizeof(buf),
					     "Challenge Invalid: %s", ac->detail);
				failreason = buf;
				goto failed;
			}

			lwsl_notice("Challenge passed\n");

			/*
			 * The challenge was validated... so delete the
			 * temp SNI vhost now its job is done
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

			strcpy(buf, ac->urls[JAD_NEW_CERT_URL]);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "POST");
			if (!cwsi) {
				lwsl_notice("%s: failed to connect to acme\n",
					    __func__);

				goto failed;
			}
			return -1; /* close the completed client connection */

		case ACME_STATE_POLLING_CSR:
			/*
			 * (after POSTing the CSR)...
			 *
			 * If the CA decides to issue a certificate, then the
			 * server creates a new certificate resource and
			 * returns a URI for it in the Location header field
			 * of a 201 (Created) response.
			 *
			 * HTTP/1.1 201 Created
			 * Location: https://example.com/acme/cert/asdf
			 *
			 * If the certificate is available at the time of the
			 * response, it is provided in the body of the response.
			 * If the CA has not yet issued the certificate, the
			 * body of this response will be empty.  The client
			 * should then send a GET request to the certificate URI
			 * to poll for the certificate.  As long as the
			 * certificate is unavailable, the server MUST provide a
			 * 202 (Accepted) response and include a Retry-After
			 * header to indicate when the server believes the
			 * certificate will be issued.
			 */
			if (ac->resp < 200 || ac->resp > 202) {
				lwsl_notice("CSR poll failed on resp %d\n",
					    ac->resp);
				goto failed;
			}

			if (ac->resp == 200) {
				char *pp;
				int max;

				lwsl_notice("The cert was sent..\n");

				lws_acme_report_status(vhd->vhost,
						LWS_CUS_ISSUE, NULL);

				/*
				 * That means we have the issued cert DER in
				 * ac->buf, length in ac->cpos; and the key in
				 * ac->alloc_privkey_pem, length in
				 * ac->len_privkey_pem.
				 *
				 * We write out a PEM copy of the cert, and a
				 * PEM copy of the private key, using the
				 * write-only fds we opened while we still
				 * had root.
				 *
				 * Estimate the size of the PEM version of the
				 * cert and allocate a temp buffer for it.
				 *
				 * This is a bit complicated because first we
				 * drop the b64url version into the buffer at
				 * +384, then we add the header at 0 and move
				 * lines of it back + '\n' to make PEM.
				 *
				 * This avoids the need for two fullsize
				 * allocations.
				 */

				max = (ac->cpos * 4) / 3 + 16 + 384;

				start = p = malloc(max);
				if (!p)
					goto failed;

				n = lws_b64_encode_string(ac->buf, ac->cpos,
							  start + 384, max - 384);
				if (n < 0) {
					free(start);
					goto failed;
				}

				pp = start + 384;
				p += lws_snprintf(start, 64, "%s",
						"-----BEGIN CERTIFICATE-----\n");

				while (n) {
					m = 65;
					if (n < m)
						m = n;
					memcpy(p, pp, m);
					n -= m;
					p += m;
					pp += m;
					if (n)
						*p++ = '\n';
				}
				p += lws_snprintf(p,
						  max - lws_ptr_diff(p, start),
						  "%s",
						  "\n-----END CERTIFICATE-----\n");

				n = lws_plat_write_cert(vhd->vhost, 0,
						vhd->fd_updated_cert, start,
						lws_ptr_diff(p, start));
				free(start);
				if (n) {
					lwsl_err("unable to write ACME cert! %d\n", n);
					goto failed;
				}
				/*
				 * don't close it... we may update the certs
				 * again
				 */

				if (lws_plat_write_cert(vhd->vhost, 1,
							vhd->fd_updated_key,
							ac->alloc_privkey_pem,
							ac->len_privkey_pem)) {
					lwsl_err("unable to write ACME key!\n");
					goto failed;
				}

				/*
				 * we have written the persistent copies
				 */

				lwsl_notice("%s: Updated certs written for %s "
					    "to %s.upd and %s.upd\n", __func__,
					    vhd->pvop_active[LWS_TLS_REQ_ELEMENT_COMMON_NAME],
					    vhd->pvop_active[LWS_TLS_SET_CERT_PATH],
					    vhd->pvop_active[LWS_TLS_SET_KEY_PATH]);

				/* notify lws there was a cert update */

				if (lws_tls_cert_updated(vhd->context,
					vhd->pvop_active[LWS_TLS_SET_CERT_PATH],
					vhd->pvop_active[LWS_TLS_SET_KEY_PATH],
					ac->buf, ac->cpos,
					ac->alloc_privkey_pem,
					ac->len_privkey_pem)) {
					lwsl_notice("problem setting certs\n");
				}

				lws_acme_finished(vhd);
				lws_acme_report_status(vhd->vhost,
							LWS_CUS_SUCCESS, NULL);

				return 0;
			}

			lws_acme_report_status(vhd->vhost, LWS_CUS_CONFIRM, NULL);

			/* he is preparing the cert, go again with a GET */

			if (ac->goes_around++ == 30) {
				lwsl_notice("%s: too many retries\n",
					    __func__);

				goto failed;
			}

			strcpy(buf, ac->challenge_uri);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &ac->cwsi, &ac->i, buf,
						       "GET");
			if (!cwsi) {
				lwsl_notice("%s: failed to connect to acme\n",
					    __func__);

				goto failed;
			}
			return -1; /* close the completed client connection */

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
				lwsl_notice("%s: failed to connect\n", __func__);
				goto failed;
			}
			break;

	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
		/*
		 * This goes to vhost->protocols[0], but for our temp certs
		 * vhost we created, we have arranged that to be our protocol,
		 * so the callback will come here.
		 *
		 * When we created the temp vhost, we set its pvo to point
		 * to the ac associated with the temp vhost.
		 */
		lwsl_debug("LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS\n");
		ac = (struct acme_connection *)lws_get_vhost_user(
							(struct lws_vhost *)in);

		lws_acme_report_status((struct lws_vhost *)in,
				        LWS_CUS_CREATE_REQ,
				        "creating challenge cert");

		if (lws_tls_acme_sni_cert_create((struct lws_vhost *)in,
						 ac->san_a, ac->san_b)) {
			lwsl_err("%s: creating the sni test cert failed\n", __func__);

			return -1;
		}
		break;

	default:
		break;
	}

	return 0;

failed:
	lwsl_err("%s: failed out\n", __func__);
	lws_acme_report_status(vhd->vhost, LWS_CUS_FAILED, failreason);
	lws_acme_finished(vhd);

	return -1;
}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_acme_client(struct lws_context *context,
			      struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_acme_client(struct lws_context *context)
{
	return 0;
}

#endif
