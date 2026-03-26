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

#include <libwebsockets.h>
#include <libwebsockets/lws-genhash.h>
#include <string.h>
#include <stdlib.h>

struct vhd_oauth2_client {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const char *remote_auth_url;
	const char *client_id;
	const char *cookie_name;

	lws_dll2_owner_t pending_auth_list;
};

/*
 * This is the pending authorization state tracking object.
 * We store this dynamically while the user completes the login remotely.
 */
struct pending_auth_state {
	lws_dll2_t list;
	lws_sorted_usec_list_t sul;
	struct vhd_oauth2_client *vhd;

	struct lws *wsi_server;
	struct lws *wsi_client;

	char state[48];
	char code_verifier[64];
	char redirect_uri[256];
	char code[256];
	char token[2048];

	char payload[1024];
	int payload_len;
	int payload_pos;
};

static void
sul_pending_auth_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_auth_state *ps = lws_container_of(sul,
					struct pending_auth_state, sul);

	lwsl_info("%s: auth state %s timed out\\n", __func__, ps->state);
	lws_dll2_remove(&ps->list);
	free(ps);
}

static int
callback_lws_oauth2_client(struct lws *wsi, enum lws_callback_reasons reason,
			   void *user, void *in, size_t len)
{
	struct vhd_oauth2_client *vhd = (struct vhd_oauth2_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_oauth2_client));
		if (!vhd)
			return 1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->cookie_name = "auth_session";

		if (in) {
			const struct lws_protocol_vhost_options *pvo =
				(const struct lws_protocol_vhost_options *)in;

			while (pvo) {
				if (!strcmp(pvo->name, "remote-auth-url"))
					vhd->remote_auth_url = pvo->value;
				if (!strcmp(pvo->name, "client-id"))
					vhd->client_id = pvo->value;
				if (!strcmp(pvo->name, "cookie-name"))
					vhd->cookie_name = pvo->value;
				pvo = pvo->next;
			}
		}

		if (!vhd->remote_auth_url || !vhd->client_id) {
			lwsl_err("%s: lws-oauth2-client requires remote-auth-url and client-id\n", __func__);
			return 1;
		}

		lwsl_notice("%s: initialized oauth2 client using auth=%s\n", __func__, vhd->remote_auth_url);
		break;

	case LWS_CALLBACK_HTTP: {
		char uri[256];

		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) < 0)
			break;

		if (!strcmp(uri, "/oauth/login")) {
			struct pending_auth_state *ps;
			uint8_t rand_bytes[32];
			uint8_t hash[32];
			char code_challenge[64];
			char sname[128] = {0};
			char loc[1024];
			struct lws_genhash_ctx hctx;
			unsigned char buf[1024], *p = buf, *end = buf + sizeof(buf) - 1;
			int loc_len;

			ps = malloc(sizeof(*ps));
			if (!ps)
				return 1;
			memset(ps, 0, sizeof(*ps));
			ps->vhd = vhd;

			if (lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", ps->redirect_uri, sizeof(ps->redirect_uri)) < 0) {
				lws_strncpy(ps->redirect_uri, "/", sizeof(ps->redirect_uri));
			}

			lws_get_urlarg_by_name_safe(wsi, "service_name=", sname, sizeof(sname));

			lws_get_random(vhd->context, rand_bytes, 16);
			lws_b64_encode_string_url((const char *)rand_bytes, 16, ps->state, sizeof(ps->state));

			lws_get_random(vhd->context, rand_bytes, 32);
			lws_b64_encode_string_url((const char *)rand_bytes, 32, ps->code_verifier, sizeof(ps->code_verifier));

			if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256) ||
			    lws_genhash_update(&hctx, ps->code_verifier, strlen(ps->code_verifier)) ||
			    lws_genhash_destroy(&hctx, hash)) {
				free(ps);
				return -1;
			}
			lws_b64_encode_string_url((const char *)hash, 32, code_challenge, sizeof(code_challenge));

			lws_dll2_add_tail(&ps->list, &vhd->pending_auth_list);
			lws_sul_schedule(vhd->context, 0, &ps->sul, sul_pending_auth_cb, 5 * 60 * LWS_US_PER_SEC);

			loc_len = lws_snprintf(loc, sizeof(loc), "%s/api/authorize?client_id=%s&redirect_uri=%%2Foauth%%2Fcallback&state=%s&code_challenge=%s&code_challenge_method=S256&response_type=code%s%s",
				vhd->remote_auth_url, vhd->client_id, ps->state, code_challenge,
				sname[0] ? "&service_name=" : "", sname);

			if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end)) return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, loc_len, &p, end)) return 1;
			if (lws_finalize_http_header(wsi, &p, end)) return 1;

			lws_write(wsi, buf, (size_t)lws_ptr_diff(p, buf), LWS_WRITE_HTTP_HEADERS);
			return lws_http_transaction_completed(wsi);
		}

		if (!strcmp(uri, "/oauth/callback")) {
			char state_in[48];
			char code_in[256];
			struct pending_auth_state *ps = NULL;

			if (lws_get_urlarg_by_name_safe(wsi, "state=", state_in, sizeof(state_in)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "code=", code_in, sizeof(code_in)) < 0) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing state or code");
				return lws_http_transaction_completed(wsi);
			}

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						   lws_dll2_get_head(&vhd->pending_auth_list)) {
				struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
				if (!strcmp(s->state, state_in)) {
					ps = s;
					break;
				}
			} lws_end_foreach_dll_safe(d, d1);

			if (!ps) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid or expired state");
				return lws_http_transaction_completed(wsi);
			}

			// We found it! Suspend timeout
			lws_sul_cancel(&ps->sul);

			lws_strncpy(ps->code, code_in, sizeof(ps->code));
			ps->wsi_server = wsi;

			// Suspend the server WSI and kick off the token fetch
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);

			ps->payload_len = lws_snprintf(ps->payload, sizeof(ps->payload),
				"grant_type=authorization_code&client_id=%s&redirect_uri=%%2Foauth%%2Fcallback&code=%s&code_verifier=%s",
				vhd->client_id, ps->code, ps->code_verifier);
			ps->payload_pos = 0;

			{
				struct lws_client_connect_info i;
				char auth_url[256];
				const char *prot, *ads, *path;
				int port = 443;

				lws_strncpy(auth_url, vhd->remote_auth_url, sizeof(auth_url));
				if (lws_parse_uri(auth_url, &prot, &ads, &port, &path)) {
					lwsl_err("Failed to parse remote-auth-url\n");
					lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Invalid config");
					return lws_http_transaction_completed(wsi);
				}

				memset(&i, 0, sizeof(i));
				i.context = vhd->context;
				i.address = ads;
				i.port = port;
				i.ssl_connection = !strcmp(prot, "http") ? 0 : LCCSCF_USE_SSL;
				i.path = "/api/token";
				i.host = i.address;
				i.origin = i.address;
				i.method = "POST";
				i.protocol = "lws-oauth2-client";
				i.pwsi = &ps->wsi_client;
				i.userdata = ps;

				lws_client_connect_via_info(&i);
			}

			return 0; // suspend without writing any header yet
		}
		break;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE: {
		struct pending_auth_state *ps = NULL;
		char loc[512];
		char cookie[2048];
		unsigned char buf[1024 + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
		int n;

		// Find if this WSI belongs to a pending auth state that just finished
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
			if (s->wsi_server == wsi && s->token[0]) {
				ps = s;
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (!ps)
			break;

		// Found the finished state!
		n = lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=3600; SameSite=Lax",
				 vhd->cookie_name, ps->token);

		lws_strncpy(loc, ps->redirect_uri, sizeof(loc));

		// Unlink and free it, we don't need it anymore
		lws_dll2_remove(&ps->list);
		free(ps);

		// Issue the cookie and the 302
		if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end)) return 1;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, (int)strlen(loc), &p, end)) return 1;
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE, (unsigned char *)cookie, n, &p, end)) return 1;
		if (lws_finalize_http_header(wsi, &p, end)) return 1;

		lws_write(wsi, buf + LWS_PRE, (size_t)lws_ptr_diff(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
		return lws_http_transaction_completed(wsi);
	}

	case LWS_CALLBACK_CLOSED_HTTP: {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
			if (s->wsi_server == wsi) {
				s->wsi_server = NULL;
			}
		} lws_end_foreach_dll_safe(d, d1);
		break;
	}

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (unsigned char *)in + len - 1;

		if (!ps)
			break;

		*p += lws_snprintf((char *)*p, (size_t)lws_ptr_diff(end, *p),
				   "Content-Type: application/x-www-form-urlencoded\x0d\x0a"
				   "Content-Length: %d\x0d\x0a", ps->payload_len);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		int n;

		if (!ps || ps->payload_pos >= ps->payload_len)
			break;

		n = lws_write(wsi, (unsigned char *)ps->payload + ps->payload_pos,
			      (size_t)(ps->payload_len - ps->payload_pos), LWS_WRITE_HTTP);
		if (n < 0)
			return -1;
		ps->payload_pos += n;

		if (ps->payload_pos < ps->payload_len)
			lws_callback_on_writable(wsi);
		else
			lws_client_http_body_pending(wsi, 0);
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		char *tok;

		if (!ps || !in || !len)
			break;

		// Extremely naive JSON extraction of "access_token"
		// A robust implementation would use lejp or lws_tokenize
		tok = strstr((const char *)in, "\"access_token\"");
		if (tok) {
			tok = strchr(tok, ':');
			if (tok) {
				tok = strchr(tok, '"');
				if (tok) {
					char *end = strchr(tok + 1, '"');
					if (end) {
						size_t tlen = lws_ptr_diff_size_t(end, tok + 1);
						if (tlen < sizeof(ps->token)) {
							lws_strncpy(ps->token, tok + 1, tlen + 1);
							lwsl_notice("%s: Extracted OAuth token successfully\n", __func__);
						}
					}
				}
			}
		}
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);

		if (!ps)
			break;

		if (ps->wsi_server)
			lws_callback_on_writable(ps->wsi_server);
		ps->wsi_client = NULL;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);

		if (!ps)
			break;

		lwsl_notice("%s: client connection closed or errored\n", __func__);

		if (ps->wsi_server && !ps->token[0]) {
			// Failed, resume server to throw 500
			lws_callback_on_writable(ps->wsi_server);
		}
		ps->wsi_client = NULL;
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY: {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *ps = lws_container_of(d, struct pending_auth_state, list);
			lws_sul_cancel(&ps->sul);
			lws_dll2_remove(&ps->list);
			free(ps);
		} lws_end_foreach_dll_safe(d, d1);
		break;
	}

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-oauth2-client",
		callback_lws_oauth2_client,
		0,
		0,
		0, NULL, 0
	}
};

LWS_VISIBLE const lws_plugin_protocol_t lws_oauth2_client = {
	.hdr = {
		"OAuth2 Client",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols)
};
