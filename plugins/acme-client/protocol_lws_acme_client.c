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
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>
#include <stdlib.h>

typedef enum {
	WALK_NONE,
	WALK_INITIAL,
	WALK_LIST,
	WALK_FINAL
} e_walk;

struct acme_provider {
	char urls[6][200];
	char replay_nonce[64];
};

typedef enum {
	ACME_STATE_DIRECTORY,	/* get the directory JSON using GET + parse */
	ACME_STATE_NEW_REG,	/* register a new RSA key + email combo */
	ACME_STATE_NEW_AUTH,	/* start the process to request a cert */

	ACME_STATE_FINISHED
} lws_acme_state;

struct per_session_data__lws_acme_client {
	struct per_session_data__lws_acme_client *next;

	struct lws *wsi;
	char user_agent[128];

	e_walk walk;
	struct per_session_data__lws_acme_client *walk_next;
	unsigned char subsequent:1;
	unsigned char changed_partway:1;
};

struct per_vhost_data__lws_acme_client {
	struct per_session_data__lws_acme_client *live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	int count_live_pss;

	char directory_url[128];
	char config_dir[64];

	lws_acme_state state;
	struct lws_client_connect_info i;
	struct acme_provider ap;
	struct lejp_ctx jctx;
	struct lws *cwsi;
	struct lws_jwk jwk;

	char *dest;
	int pos;
	int len;
	int resp;

	struct lws_genrsa_ctx rsactx;

	char buf[4096];
	char challenge_token[64];

	unsigned int yes:1;
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
		s->len = sizeof(s->ap.urls[0]) - 1;
		s->dest = s->ap.urls[ctx->path_match - 1];

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
};
static signed char
cb_authz(struct lejp_ctx *ctx, char reason)
{
	struct per_vhost_data__lws_acme_client *s =
			(struct per_vhost_data__lws_acme_client *)ctx->user;

	if (reason == LEJPCB_VAL_STR_START && ctx->path_match) {
		s->pos = 0;
		s->len = sizeof(s->ap.urls[0]) - 1;

		return 0;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JAAZ_ID_TYPE:
		s->yes = 0;
		s->challenge_token[0] = '\0';
		break;
	case JAAZ_ID_VALUE:
		break;
	case JAAZ_STATUS:
		break;
	case JAAZ_EXPIRES:
		break;
	case JAAZ_CHALLENGES_TYPE:
		s->yes = !strcmp(ctx->buf, "http-01");
		break;
	case JAAZ_CHALLENGES_STATUS:
		break;
	case JAAZ_CHALLENGES_URI:
		break;
	case JAAZ_CHALLENGES_TOKEN:
		if (s->yes)
			strncpy(s->challenge_token, ctx->buf,
				sizeof(s->challenge_token) - 1);
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


/*
 * trashes i and url
 */
static struct lws *
lws_acme_client_connect(struct lws_context *context, struct lws_vhost *vh,
			struct lws **pwsi, struct lws_client_connect_info *i,
			char *url, const char *method)
{
	const char *prot, *p;
	char path[200];

	memset(i, 0, sizeof(*i));
	i->port = 443;
	if (lws_parse_uri(url, &prot, &i->address, &i->port, &p)) {
		lwsl_err("unable to parse uri %s\n", url);

		return NULL;
	}

	/* add back the leading / on path */
	path[0] = '/';
	strncpy(path + 1, p, sizeof(path) - 2);
	path[sizeof(path) - 1] = '\0';
	i->path = path;
	i->context = context;
	i->vhost = vh;
	i->ssl_connection = 1;
	i->host = i->address;
	i->origin = i->address;
	i->method = method;
	i->pwsi = pwsi;
	i->protocol = "lws-acme-client";

	return lws_client_connect_via_info(i);
}

static void
lws_acme_finished(struct per_vhost_data__lws_acme_client *vhd)
{
	lwsl_notice("finishing up jws stuff\n");
	lws_genrsa_destroy(&vhd->rsactx);
	lws_jwk_destroy(&vhd->jwk);
	vhd->state = ACME_STATE_FINISHED;
}

/*
 * We support two separate connection types here:
 *
 *  - client connection results
 *
 *  - websocket connection to make the admin user's info live
 */
int
callback_acme_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	struct per_session_data__lws_acme_client *pss1, *pss2, *pss =
			(struct per_session_data__lws_acme_client *)user;
	struct per_vhost_data__lws_acme_client *vhd =
			(struct per_vhost_data__lws_acme_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	char buf[LWS_PRE + 384], ip[24], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf) - 1;
	unsigned char **pp = (unsigned char **)in, *pend = in + len;
	const struct lws_protocol_vhost_options *pvo;
	struct lws *cwsi;
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_acme_client));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "config-dir"))
				strncpy(vhd->config_dir, pvo->value,
					sizeof(vhd->config_dir) - 1);
			if (!strcmp(pvo->name, "directory-url"))
				strncpy(vhd->directory_url, pvo->value,
					sizeof(vhd->directory_url) - 1);

			pvo = pvo->next;
		}

		if (!vhd->config_dir[0] || !vhd->directory_url[0]) {
			lwsl_notice("%s: pvo \"config-dir\", "
				    "\"directory-url\" required\n",
				    __func__);

			return -1;
		}

		/*
		 * so we need a private key... load it from config if it
		 * exists, or create it
		 */

		sprintf(buf, "%s/rsa-private-keys.jwk", vhd->config_dir);

		if (lws_jwk_load(&vhd->jwk, buf)) {
			strcpy(vhd->jwk.keytype, "RSA");
			n = lws_genrsa_new_keypair(lws_get_context(wsi),
						   &vhd->rsactx,
						   &vhd->jwk.el, 4096);
			if (n) {
				lwsl_notice("failed to create keypair\n");

				return 1;
			}

			if (lws_jwk_save(&vhd->jwk, buf)) {
				lwsl_notice("unable to save %s\n", buf);

				return 1;
			}

			/*
			 * We always try to register the keys... if it's not
			 * the first time, we will get a JSON body in the
			 * (legal, nonfatal) response like this
			 *
			 * {
			 *   "type": "urn:acme:error:malformed",
			 *   "detail": "Registration key is already in use",
			 *   "status": 409
			 * }
			 */
		}

		/*
		 * ... either way the first job is get the directory ...
		 */

		vhd->state = ACME_STATE_DIRECTORY;

		strcpy(buf, vhd->directory_url);
		cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
					       &vhd->cwsi, &vhd->i, buf,
					       "GET");
		if (!cwsi)
			lwsl_notice("%s: acme connect failed\n", __func__);

		break;

	/*
	 * Client
	 */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("%s: CLIENT_ESTABLISHED\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: CLIENT_CONNECTION_ERROR\n", __func__);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		lwsl_notice("%s: CLOSED_CLIENT_HTTP\n", __func__);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_notice("lws_http_client_http_response %d\n",
				lws_http_client_http_response(wsi));
		vhd->resp = lws_http_client_http_response(wsi);
		/* we get a new nonce each time */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_REPLAY_NONCE) &&
		    lws_hdr_copy(wsi, vhd->ap.replay_nonce,
				 sizeof(vhd->ap.replay_nonce),
				 WSI_TOKEN_REPLAY_NONCE) < 0) {
			lwsl_notice("%s: nonce too large\n", __func__);

			return -1;
		}

		switch (vhd->state) {
		case ACME_STATE_DIRECTORY:
			lejp_construct(&vhd->jctx, cb_dir, vhd, jdir_tok,
				       ARRAY_SIZE(jdir_tok));
			break;
		case ACME_STATE_NEW_REG:
			break;
		case ACME_STATE_NEW_AUTH:
			lejp_construct(&vhd->jctx, cb_authz, vhd, jauthz_tok,
				       ARRAY_SIZE(jauthz_tok));
			break;
		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		switch (vhd->state) {

		case ACME_STATE_DIRECTORY:
			break;
		case ACME_STATE_NEW_REG:
			p += lws_snprintf(p, end - p, "{"
					"\"resource\":\"new-reg\","
					"\"contact\":["
					 "\"mailto:andy@warmcat.com\""
					"],\"agreement\":\"%s\""
					"}", vhd->ap.urls[JAD_TOS_URL]);
pkt_add_hdrs:
			vhd->len = lws_jws_create_packet(&vhd->jwk,
							 start, p - start,
							 vhd->ap.replay_nonce,
							 &vhd->buf[LWS_PRE],
							 sizeof(vhd->buf) -
								 LWS_PRE);
			if (vhd->len < 0) {
				vhd->len = 0;
				lwsl_notice("lws_jws_create_packet failed\n");
				return -1;
			}
			vhd->pos = 0;

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(uint8_t *)"application/jose+json",
					21, pp, pend))
				return -1;

			n = sprintf(buf, "%d", vhd->len);
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(uint8_t *)buf, n, pp, pend))
				return -1;

			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
			break;
		case ACME_STATE_NEW_AUTH:
			p += lws_snprintf(p, end - p,
					"{"
					 "\"resource\":\"new-authz\","
					 "\"identifier\":{"
					  "\"type\":\"http-01\","
					  "\"value\":\"home.warmcat.com\""
					 "}"
					"}");
			goto pkt_add_hdrs;
		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		lwsl_notice("LWS_CALLBACK_CLIENT_HTTP_WRITEABLE\n");
		if (vhd->pos != vhd->len) {
			vhd->buf[LWS_PRE + vhd->len] = '\0';
			if (lws_write(wsi, (uint8_t *)vhd->buf + LWS_PRE,
				      vhd->len, LWS_WRITE_HTTP_FINAL) < 0)
				return -1;
			lwsl_notice("wrote %d\n", vhd->len);
			vhd->pos = vhd->len;
			lws_client_http_body_pending(wsi, 0);
		}
		break;

	/* chunked content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		switch (vhd->state) {
		case ACME_STATE_NEW_AUTH:
		case ACME_STATE_DIRECTORY:
			m = (int)(signed char)lejp_parse(&vhd->jctx,
							 (uint8_t *)in, len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_notice("lejp parse failed %d\n", m);
				return -1;
			}
			break;
		case ACME_STATE_NEW_REG:
			((char *)in)[len] = '\0';
			puts(in);
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

		switch (vhd->state) {
		case ACME_STATE_DIRECTORY:
			lejp_destruct(&vhd->jctx);

			/* check dir validity */

			for (n = 0; n < 6; n++)
				lwsl_notice("   %d: %s\n", n, vhd->ap.urls[n]);

			/*
			 * So... having the directory now... we try to
			 * register our keys next.  It's OK if it ends up
			 * they're already registered... this eliminates any
			 * gaps where we stored the key but registration did
			 * not complete for some reason...
			 */
			vhd->state = ACME_STATE_NEW_REG;

			strcpy(buf, vhd->ap.urls[JAD_NEW_REG_URL]);
			cwsi = lws_acme_client_connect(vhd->context, vhd->vhost,
						       &vhd->cwsi, &vhd->i, buf,
						       "POST");
			if (!cwsi)
				lwsl_notice("%s: failed to connect to acme\n",
					    __func__);
			break;

		case ACME_STATE_NEW_REG:
			if ((vhd->resp >= 200 && vhd->resp < 299) ||
			     vhd->resp == 409) {
				/*
				 * Our account already existed, or exists now.
				 *
				 * Move on to requesting a cert auth.
				 */
				vhd->state = ACME_STATE_NEW_AUTH;

				strcpy(buf, vhd->ap.urls[JAD_NEW_AUTHZ_URL]);
				cwsi = lws_acme_client_connect(vhd->context,
							vhd->vhost, &vhd->cwsi,
							&vhd->i, buf, "POST");
				if (!cwsi)
					lwsl_notice("%s: failed to connect\n",
						    __func__);
				break;
			} else {
				lwsl_notice("new-reg replied %d\n", vhd->resp);
				lws_acme_finished(vhd);
			}
			break;

		case ACME_STATE_NEW_AUTH:
			lejp_destruct(&vhd->jctx);
			lwsl_notice("chall: %s\n", vhd->challenge_token);
			p = vhd->buf;
			end = &vhd->buf[sizeof(vhd->buf) - 1];
			p += lws_snprintf(p, end - p, "%s.",
					vhd->challenge_token);
			n = lws_jws_sign_from_b64(NULL, 0, vhd->challenge_token,
						  strlen(vhd->challenge_token),
						  p, end - p,
						  LWS_GENHASH_TYPE_SHA256,
						  &vhd->jwk);
			if (n < 0) {
				lwsl_notice("signing the chall failed\n");
				return -1;
			}
			p += n;
			vhd->len = lws_ptr_diff(p, vhd->buf);
			vhd->pos = 0;

			puts(vhd->buf);

			lws_acme_finished(vhd);
//			lws_callback_on_writable(wsi);
			break;
		default:
			break;
		}

		break;

	/*
	 * Websockets
	 */

	case LWS_CALLBACK_ESTABLISHED:

		/*
		 * This shows how to stage sending a single ws message in
		 * multiple fragments.  In this case, it lets us trade off
		 * memory needed to make the data vs time to send it.
		 */

		vhd->count_live_pss++;
		pss->next = vhd->live_pss_list;
		vhd->live_pss_list = pss;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		switch (pss->walk) {
		case WALK_INITIAL:
			n = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;;
			p += lws_snprintf(p, end - p,
				      "{ \"version\":\"%s\","
				      " \"hostname\":\"%s\","
				      " \"wsi\":\"%d\", \"conns\":[",
				      lws_get_library_version(),
				      lws_canonical_hostname(vhd->context),
				      vhd->count_live_pss);
			pss->walk = WALK_LIST;
			pss->walk_next = vhd->live_pss_list;
			break;
		case WALK_LIST:
			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			if (!pss->walk_next)
				goto walk_final;

			if (pss->subsequent)
				*p++ = ',';
			pss->subsequent = 1;

			m = 0;
			pss2 = vhd->live_pss_list;
			while (pss2) {
				if (pss2 == pss->walk_next) {
					m = 1;
					break;
				}
				pss2 = pss2->next;
			}
			if (!m) {
				/* our next guy went away */
				pss->walk = WALK_FINAL;
				pss->changed_partway = 1;
				break;
			}

			strcpy(ip, "unknown");
			lws_get_peer_simple(pss->walk_next->wsi, ip,
					    sizeof(ip));
			p += lws_snprintf(p, end - p,
					"{\"peer\":\"%s\",\"time\":\"%ld\","
					"\"ua\":\"%s\"}",
					ip, (long)0,
					pss->walk_next->user_agent);
			pss->walk_next = pss->walk_next->next;
			if (!pss->walk_next)
				pss->walk = WALK_FINAL;
			break;
		case WALK_FINAL:
walk_final:
			n = LWS_WRITE_CONTINUATION;
			p += sprintf(p, "]}");
			if (pss->changed_partway) {
				pss->subsequent = 0;
				pss->walk_next = vhd->live_pss_list;
				pss->walk = WALK_INITIAL;
			} else
				pss->walk = WALK_NONE;
			break;
		default:
			return 0;
		}

		m = lws_write(wsi, (unsigned char *)start, p - start, n);
		if (m < 0) {
			lwsl_err("ERROR %d writing to di socket\n", m);
			return -1;
		}

		if (pss->walk != WALK_NONE)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("pmd test: RX len %d\n", (int)len);
		puts(in);
		break;

	case LWS_CALLBACK_CLOSED:
		pss1 = vhd->live_pss_list;
		pss2 = NULL;

		while (pss1) {
			if (pss1 == pss) {
				if (pss2)
					pss2->next = pss->next;
				else
					vhd->live_pss_list = pss->next;
				break;
			}

			pss2 = pss1;
			pss1 = pss1->next;
		}
//		trigger_resend(vhd);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_ACME_CLIENT \
	{ \
		"lws-acme-client", \
		callback_acme_client, \
		sizeof(struct per_session_data__lws_acme_client), \
		512, \
		0, NULL, 0 \
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
