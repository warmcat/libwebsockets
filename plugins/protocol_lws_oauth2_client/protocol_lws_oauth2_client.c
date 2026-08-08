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
	unsigned long cookie_max_age_secs;	/* fallback Max-Age when no expires_in is available */

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

	struct lejp_ctx jctx;
	const char *fatal_error;

	/* If /api/token returns an error JSON (no access_token), capture the
	 * error / error_description strings so the bail log shows the actual
	 * auth-server rejection instead of a generic "Failed to obtain access
	 * token". */
	char token_error[64];
	char token_error_desc[128];

	char state[48];
	char code_verifier[64];
	char redirect_uri[256];
	/* The absolute OAuth callback URL (https://<app-host>/oauth/callback) we
	 * send to the auth server as redirect_uri at /oauth/login and /api/token.
	 * Derived from the incoming request's scheme://host so it is correct for
	 * cross-domain apps (a relative /oauth/callback would be followed on the
	 * auth server's host, landing on the wrong origin).  Distinct from
	 * redirect_uri above, which is the app page the user returns to. */
	char oauth_redirect_uri[256];
	char code[256];
	char token[LWS_SSO_MAX_COOKIE];
	int token_len;
	unsigned long expires_in_secs;	/* seconds, from the token response; 0 = unknown */

	/*
	 * Long-term refresh token + its lifetime, from the token response.  We set
	 * these as the auth_refresh_session cookie on the app host at /oauth/callback
	 * so lws-login's silent renewal (background + cold-load) has something to
	 * renew with.  Empty when the auth server has refresh disabled.
	 */
	char refresh_token[128];
	int refresh_token_len;
	unsigned long refresh_expires_in_secs;

	char csrf[33];			/* random CSRF token issued with the session,
						 * used by lws-login's renewal BFF for its
						 * double-submit check */

	char payload[1024];
	int payload_len;
	int payload_pos;
};

static const char * const lejp_paths[] = {
	"access_token",
	"expires_in",
	"refresh_token",
	"refresh_expires_in",
	"error",
	"error_description"
};

static signed char
oauth_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pending_auth_state *ps = (struct pending_auth_state *)ctx->user;

	/*
	 * String values arrive as LEJPCB_VAL_STR_CHUNK (possibly several
	 * times for a long value) then LEJPCB_VAL_STR_END; numeric values as
	 * LEJPCB_VAL_NUM_INT/FLOAT.  All of these have the LEJP_FLAG_CB_IS_VALUE
	 * bit set.  The previous "reason != LEJP_FLAG_CB_IS_VALUE" test never
	 * matched any real value (the full reason is eg VAL_STR_END = 0x40|13),
	 * so access_token / expires_in / refresh_token / error were never
	 * captured and the flow always bailed with "Failed to obtain access
	 * token".  Bit-test the flag, like every other LEJP consumer in tree
	 * (jws.c, jose.c, jwe.c, jose_key.c).
	 */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE))
		return 0;

	switch (ctx->path_match) {
	case 1: /* access_token */
		if (ps->token_len + ctx->npos >= LWS_SSO_MAX_COOKIE - 1) {
			ps->fatal_error = "JWT in cookie is truncated";
			return -1;
		}
		memcpy(ps->token + ps->token_len, ctx->buf, ctx->npos);
		ps->token_len += ctx->npos;
		ps->token[ps->token_len] = '\0';
		break;

	case 2: /* expires_in: capture so the cookie Max-Age matches the token lifetime */
		if (ctx->npos) {
			char tmp[24];
			size_t i, copy = ctx->npos < sizeof(tmp) - 1 ?
					   ctx->npos : sizeof(tmp) - 1;
			memcpy(tmp, ctx->buf, copy);
			tmp[copy] = '\0';
			/* only trust it if it's pure digits */
			for (i = 0; i < copy; i++)
				if (tmp[i] < '0' || tmp[i] > '9')
					return 0;
			ps->expires_in_secs = (unsigned long)atoll(tmp);
		}
		break;

	case 3: /* refresh_token: long-term code for auth_refresh_session cookie.
		 * LEJP may deliver the value in multiple chunks; accumulate the
		 * same way access_token does (raw memcpy + running length). */
		if (ps->refresh_token_len + ctx->npos >=
						(int)sizeof(ps->refresh_token) - 1) {
			ps->fatal_error = "refresh token truncated";
			return -1;
		}
		memcpy(ps->refresh_token + ps->refresh_token_len,
		       ctx->buf, ctx->npos);
		ps->refresh_token_len += ctx->npos;
		ps->refresh_token[ps->refresh_token_len] = '\0';
		break;

	case 4: /* refresh_expires_in: lifetime of the refresh token, seconds */
		if (ctx->npos) {
			char tmp[24];
			size_t i, copy = ctx->npos < sizeof(tmp) - 1 ?
					   ctx->npos : sizeof(tmp) - 1;
			memcpy(tmp, ctx->buf, copy);
			tmp[copy] = '\0';
			for (i = 0; i < copy; i++)
				if (tmp[i] < '0' || tmp[i] > '9')
					return 0;
			ps->refresh_expires_in_secs = (unsigned long)atoll(tmp);
		}
		break;

	case 5: /* error: OAuth2 error code from /api/token (eg invalid_grant) */
		if (ctx->npos) {
			size_t copy = ctx->npos < sizeof(ps->token_error) - 1 ?
					   ctx->npos : sizeof(ps->token_error) - 1;
			memcpy(ps->token_error, ctx->buf, copy);
			ps->token_error[copy] = '\0';
		}
		break;

	case 6: /* error_description: human-readable detail from /api/token */
		if (ctx->npos) {
			size_t copy = ctx->npos < sizeof(ps->token_error_desc) - 1 ?
					   ctx->npos : sizeof(ps->token_error_desc) - 1;
			memcpy(ps->token_error_desc, ctx->buf, copy);
			ps->token_error_desc[copy] = '\0';
		}
		break;
	}

	return 0;
}

/*
 * ps is shared between two wsis: the incoming /oauth/callback server wsi
 * (ps->wsi_server) and the outgoing /api/token client wsi (ps->wsi_client,
 * which carries ps as its externally-allocated user_space).  Either leg may
 * finish first; freeing ps while the other leg still references it is a
 * use-after-free (the allocator may reuse or zero the block, so the surviving
 * leg sees garbage -- eg payload_len silently becoming 0).
 *
 * Each leg clears its own back-pointer and calls here; ps is only torn down
 * once BOTH legs are done.  The TIMEOUT_PENDING sul is also cancelled so a
 * late 5min timeout cannot free ps under a still-live wsi either.
 */
static void
pending_auth_release(struct pending_auth_state *ps)
{
	if (!ps)
		return;

	if (ps->wsi_server || ps->wsi_client)
		return;

	lws_sul_cancel(&ps->sul);
	lws_dll2_remove(&ps->list);
	lejp_destruct(&ps->jctx);
	free(ps);
}

static void
sul_pending_auth_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_auth_state *ps = lws_container_of(sul,
					struct pending_auth_state, sul);

	lwsl_notice("%s: pending auth state %s timed out (server=%p, "
		    "client=%p)\n", __func__, ps->state,
		    (void *)ps->wsi_server, (void *)ps->wsi_client);

	/*
	 * The 5min validity of the auth code elapsed.  Close any still-live
	 * wsis; their close callbacks clear the matching back-pointer and
	 * call pending_auth_release(), so ps is freed only after both legs
	 * are gone -- never while a wsi still references it (which was a
	 * use-after-free in the old "free ps here unconditionally" code).
	 */
	if (ps->wsi_server)
		lws_wsi_close(ps->wsi_server, LWS_TO_KILL_ASYNC);
	if (ps->wsi_client)
		lws_wsi_close(ps->wsi_client, LWS_TO_KILL_ASYNC);

	/*
	 * If both legs already finished, no close callback will fire, so
	 * release here.  Otherwise the close callbacks do it.
	 */
	pending_auth_release(ps);
}

/*
 * Decide the cookie Max-Age to write.  Prefer the lifetime the auth server
 * actually returned for this token; fall back to the operator-configured
 * default; final fallback is the historical 1h so we never silently write a
 * session cookie with no expiry.
 */
static unsigned long
cookie_max_age(struct vhd_oauth2_client *vhd, unsigned long expires_in_secs)
{
	if (expires_in_secs)
		return expires_in_secs;
	if (vhd->cookie_max_age_secs)
		return vhd->cookie_max_age_secs;
	return 3600;
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
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		if (!in)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_oauth2_client));
		if (!vhd)
			return 1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->cookie_name = "auth_session";

		{
			const struct lws_protocol_vhost_options *pvo =
				(const struct lws_protocol_vhost_options *)in;

			while (pvo) {
				if (!strcmp(pvo->name, "remote-auth-url"))
					vhd->remote_auth_url = pvo->value;
				if (!strcmp(pvo->name, "client-id"))
					vhd->client_id = pvo->value;
				if (!strcmp(pvo->name, "cookie-name"))
					vhd->cookie_name = pvo->value;
				if (!strcmp(pvo->name, "cookie-max-age-secs") &&
				    pvo->value && pvo->value[0])
					vhd->cookie_max_age_secs =
						(unsigned long)atoll(pvo->value);
				pvo = pvo->next;
			}
		}

			if (!vhd->remote_auth_url || !vhd->client_id) {
				lwsl_vhost_err(vhd->vhost, "%s: lws-oauth2-client requires remote-auth-url and client-id\n", __func__);
				return 1;
			}

			lwsl_vhost_notice(vhd->vhost, "%s: initialized oauth2 client using auth=%s\n",
					  __func__, vhd->remote_auth_url);
			break;

	case LWS_CALLBACK_HTTP: {
		char uri[256];
		size_t ulen;

		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) < 0 &&
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) < 0)
			break;

		lwsl_wsi_notice(wsi, "oauth2-client HTTP dispatch: uri='%s'", uri);

		/*
		 * Tolerate a single trailing slash on our routes so callers that
		 * build the Login URL as "<entry>/" + "?..." (eg lws-login's dest
		 * construction at protocol_lws_login.c, which appends "/" when
		 * auth-server-url doesn't end with one) still hit /oauth/login
		 * rather than falling through unhandled.
		 */
		ulen = strlen(uri);
		if (ulen > 1 && uri[ulen - 1] == '/') {
			uri[ulen - 1] = '\0';
			/* a bare "/" normalizes to "" -- restore it so the root
			 * case isn't mishandled; our routes all start with /oauth */
			if (uri[0] == '\0')
				uri[0] = '/', uri[1] = '\0';
		}

		if (!strcmp(uri, "/oauth/login")) {
			struct pending_auth_state *ps;
			uint8_t rand_bytes[32];
			uint8_t hash[32];
			char code_challenge[64];
			char sname[128] = {0};
			char loc[1024];
			struct lws_genhash_ctx hctx;
			/* Sized to absorb the vhost's default header block (CSP,
			 * permissions-policy, HSTS, etc -- can be ~1KB on hosts
			 * like libwebsockets.org) that lws_add_http_header_status
			 * auto-appends, plus the Location: header and headroom.
			 * A 1KB buffer ran out and the 302 silently failed there. */
			unsigned char buf[LWS_SSO_MAX_COOKIE + 512 + LWS_PRE], *p = buf + LWS_PRE,
					*end = buf + sizeof(buf) - 1;

			ps = malloc(sizeof(*ps));
			if (!ps)
				return 1;
			memset(ps, 0, sizeof(*ps));
			ps->vhd = vhd;

			if (lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", ps->redirect_uri, sizeof(ps->redirect_uri)) < 0) {
				lws_strncpy(ps->redirect_uri, "/", sizeof(ps->redirect_uri));
			} else {
				/*
				 * Open Redirect defense: the post-login redirect
				 * target MUST be a relative local path.  Callers (eg
				 * lws-login) may pass a fully-qualified same-origin
				 * URL like "https://libwebsockets.org/sai"; if the
				 * host matches the request's host, accept it by
				 * reducing it to its path.  Anything else (absolute
				 * URL on a different host, protocol-relative
				 * "//evil.com", etc) is reset to "/".
				 */
				if (!strncmp(ps->redirect_uri, "http://", 7) ||
				    !strncmp(ps->redirect_uri, "https://", 8)) {
					char reqhost[160], urghost[160];
					const char *hp, *pp;
					size_t hlen;
					int scheme_off = ps->redirect_uri[4] == ':' ? 7 : 8;
					int got = 0;

					hp = ps->redirect_uri + scheme_off;
					pp = strchr(hp, '/');
					hlen = pp ? (size_t)(pp - hp) : strlen(hp);
					if (hlen >= sizeof(urghost))
						hlen = sizeof(urghost) - 1;
					memcpy(urghost, hp, hlen);
					urghost[hlen] = '\0';

					/* request host: Host header, else h2/h3 :authority */
					reqhost[0] = '\0';
					if (lws_hdr_copy(wsi, reqhost, sizeof(reqhost),
						 WSI_TOKEN_HOST) > 0
#if defined(LWS_ROLE_H2)
					    || lws_hdr_copy(wsi, reqhost,
						 sizeof(reqhost),
						 WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0
#endif
					    )
						got = 1;

					if (got && !strcmp(reqhost, urghost)) {
						/* same-origin: keep just the path */
						lws_strncpy(ps->redirect_uri,
							    pp ? pp : "/",
							    sizeof(ps->redirect_uri));
					} else
						lws_strncpy(ps->redirect_uri, "/",
							    sizeof(ps->redirect_uri));
				}
				/* still enforce: relative, and not protocol-relative */
				if (ps->redirect_uri[0] != '/' ||
				    ps->redirect_uri[1] == '/')
					lws_strncpy(ps->redirect_uri, "/",
						    sizeof(ps->redirect_uri));
			}

			if (lws_get_urlarg_by_name_safe(wsi, "service_name=", sname, sizeof(sname)) < 0)
				lwsl_debug("%s: no service_name bound\n", __func__);

			lws_get_random(vhd->context, rand_bytes, 16);
			lws_b64_encode_string_url((const char *)rand_bytes, 16, ps->state, sizeof(ps->state));

			lws_get_random(vhd->context, rand_bytes, 32);
			lws_b64_encode_string_url((const char *)rand_bytes, 32, ps->code_verifier, sizeof(ps->code_verifier));

			/*
			 * Issue our own CSRF token with the session; the silent-refresh
			 * BFF double-submit-checks it against the form field.  We mint it
			 * here (not at refresh time) so it has the session's lifetime and
			 * is present from the very first request the app makes.
			 */
			{
				uint8_t rnd[16];
				lws_get_random(vhd->context, rnd, sizeof(rnd));
				lws_hex_from_byte_array(rnd, sizeof(rnd),
							ps->csrf, sizeof(ps->csrf));
			}

			if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256) ||
			    lws_genhash_update(&hctx, ps->code_verifier, strlen(ps->code_verifier)) ||
			    lws_genhash_destroy(&hctx, hash)) {
				lwsl_wsi_notice(wsi, "/oauth/login: genhash failed");
				free(ps);
				return -1;
			}
			lws_b64_encode_string_url((const char *)hash, 32, code_challenge, sizeof(code_challenge));

			/*
			 * Build the absolute OAuth callback URL for this app origin.
			 * The auth server echoes redirect_uri verbatim into the browser
			 * navigation after authorize, so a relative /oauth/callback would
			 * be followed on the auth server's host -- landing on the wrong
			 * origin.  Derive scheme://host the same way lws-login's
			 * silent-update path does: Host/:authority header for host,
			 * x-forwarded-proto or lws_is_ssl() for scheme.
			 */
			{
				char host[128];
				const char *h = NULL;
				host[0] = '\0';
				if (lws_hdr_copy(wsi, host, sizeof(host),
						 WSI_TOKEN_HOST) > 0)
					h = host;
#if defined(LWS_ROLE_H2)
				else if (lws_hdr_copy(wsi, host, sizeof(host),
						WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
					h = host;
#endif
				if (!h) {
					struct lws_vhost *vh = lws_get_vhost(wsi);
					if (vh) {
						const char *vn = lws_get_vhost_name(vh);
						if (vn)
							h = vn;
					}
				}

				{
					const char *scheme = "http";
#if defined(LWS_WITH_CUSTOM_HEADERS)
					char proto[16] = "";
					if (lws_hdr_custom_copy(wsi, proto, sizeof(proto),
							"x-forwarded-proto:", 18) > 0) {
						if (!strcasecmp(proto, "https"))
							scheme = "https";
					} else
#endif
					if (lws_is_ssl(lws_get_network_wsi(wsi)))
						scheme = "https";

					lws_snprintf(ps->oauth_redirect_uri,
						sizeof(ps->oauth_redirect_uri),
						"%s://%s/oauth/callback",
						scheme, h ? h : "localhost");
				}
			}

			lws_dll2_add_tail(&ps->list, &vhd->pending_auth_list);
			lws_sul_schedule(vhd->context, 0, &ps->sul, sul_pending_auth_cb, 5 * 60 * LWS_US_PER_SEC);

			{
				char enc_uri[512];
				lws_urlencode(enc_uri, ps->oauth_redirect_uri,
					      sizeof(enc_uri));
				lws_snprintf(loc, sizeof(loc),
					"%s/api/authorize?client_id=%s&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256&response_type=code%s%s",
					vhd->remote_auth_url, vhd->client_id,
					enc_uri, ps->state, code_challenge,
					sname[0] ? "&service_name=" : "", sname);
			}

			if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end)) {
				lwsl_wsi_notice(wsi, "/oauth/login: add_status failed");
				return 1;
			}
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, (int)strlen(loc), &p, end)) {
				lwsl_wsi_notice(wsi, "/oauth/login: add_location failed (loc len %d, room %d)",
						(int)strlen(loc), (int)lws_ptr_diff(end, p));
				return 1;
			}
			if (lws_finalize_http_header(wsi, &p, end)) {
				lwsl_wsi_notice(wsi, "/oauth/login: finalize failed");
				return 1;
			}

			lwsl_wsi_notice(wsi, "/oauth/login: writing 302 -> %s", loc);

			/* headers-only 302: under h2 the HEADERS frame must carry
			 * END_STREAM or the stream hangs open waiting for a body
			 * that never comes (browser sees 0 bytes / no response). */
			lws_write(wsi, buf + LWS_PRE, (size_t)lws_ptr_diff(p, buf + LWS_PRE),
				  LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
			return lws_http_transaction_completed(wsi);
		}

		if (!strcmp(uri, "/oauth/callback")) {
			char state_in[48];
			char code_in[256];
			char iss_in[256];
			struct pending_auth_state *ps = NULL;

			// lwsl_wsi_notice(wsi, "/oauth/callback: handler entry");

			if (lws_get_urlarg_by_name_safe(wsi, "state=", state_in, sizeof(state_in)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "code=", code_in, sizeof(code_in)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "iss=", iss_in, sizeof(iss_in)) < 0) {
				lwsl_wsi_notice(wsi, "/oauth/callback: exit 1");
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing state, code, or iss");
				return lws_http_transaction_completed(wsi);
			}

			lws_urldecode(iss_in, iss_in, sizeof(iss_in));
			if (strlen(iss_in) != strlen(vhd->remote_auth_url) || strcmp(iss_in, vhd->remote_auth_url)) {
				lwsl_wsi_notice(wsi, "/oauth/callback: mix-up defense "
						"blocked: iss='%s' != remote-auth-url "
						"'%s'", iss_in,
						vhd->remote_auth_url ?
							vhd->remote_auth_url :
							"(null)");
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid issuer parameter");
				return lws_http_transaction_completed(wsi);
			}

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						   lws_dll2_get_head(&vhd->pending_auth_list)) {
				struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
				if (strlen(s->state) == strlen(state_in) && !lws_timingsafe_bcmp(s->state, state_in, (uint32_t)strlen(s->state))) {
					ps = s;
					break;
				}
			} lws_end_foreach_dll_safe(d, d1);

			if (!ps) {
				lwsl_wsi_notice(wsi, "/oauth/callback: invalid / expired state");

				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Invalid or expired state");
				return lws_http_transaction_completed(wsi);
			}

			// We found it! Suspend timeout
			lws_sul_cancel(&ps->sul);

			lws_strncpy(ps->code, code_in, sizeof(ps->code));
			ps->wsi_server = wsi;

			// Suspend the server WSI and kick off the token fetch
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);

			lejp_construct(&ps->jctx, oauth_lejp_cb, ps, lejp_paths, LWS_ARRAY_SIZE(lejp_paths));

			{
				/* Must byte-match the redirect_uri sent to /api/authorize
				 * (the auth server compares it against oauth_codes). */
				char enc_uri[512];
				lws_urlencode(enc_uri, ps->oauth_redirect_uri,
					      sizeof(enc_uri));
				ps->payload_len = lws_snprintf(ps->payload,
					sizeof(ps->payload),
					"grant_type=authorization_code&client_id=%s&redirect_uri=%s&code=%s&code_verifier=%s",
					vhd->client_id, enc_uri, ps->code,
					ps->code_verifier);
			}
			ps->payload_pos = 0;

			{
				struct lws_client_connect_info i;
				lws_parse_uri_t *puri;

				puri = lws_parse_uri_create(vhd->remote_auth_url);
				if (!puri) {
					lwsl_wsi_warn(wsi, "Failed to parse remote-auth-url\n");
					lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Invalid config");
					return lws_http_transaction_completed(wsi);
				}

			memset(&i, 0, sizeof(i));
			i.context		= vhd->context;
                       /*
                        * Bind the outgoing /api/token client connection to the
                        * SAME vhost the incoming /oauth/callback request was
                        * served on.  lws routes CLIENT_* callbacks through
                        * wsi->a.protocol->callback, and the protocol is resolved
                        * by name ONLY from the bound vhost's protocols[] array
                        * (lws_vhost_name_to_protocol in connect.c PHASE 5).
                        *
                        * If we leave i.vhost NULL, lws falls back to the
                        * "default" / vhost_list head vhost, which does NOT have
                        * "lws-oauth2-client" enabled; the lookup returns NULL,
                        * the wsi is left on protocols[0] of the wrong vhost, and
                        * LWS_CALLBACK_COMPLETED_CLIENT_HTTP / CLIENT_CONNECTION_ERROR
                        * are delivered to the wrong callback.  Our plugin never
                        * sees them, so lws_callback_on_writable(ps->wsi_server)
                        * is never called and the server wsi hangs forever --
                        * the browser sees "no response, no timeout" on
                        * /oauth/callback.
                        */
			i.vhost			= vhd->vhost;

			i.address		= puri->host;
			i.port			= puri->port;
			i.ssl_connection	= !strcmp(puri->scheme, "http") ? 0 : LCCSCF_USE_SSL;
			i.path			= "/api/token";
			i.host			= i.address;
			i.origin		= i.address;
			i.method		= "POST";
			i.protocol		= "lws-oauth2-client";
			i.pwsi			= &ps->wsi_client;
			i.userdata		= ps;

			if (!lws_client_connect_via_info(&i)) {
				/*
				 * The async /api/token client connection could
				 * not even be created: no client wsi exists, so no
				 * CLIENT_CONNECTION_ERROR / COMPLETED_CLIENT_HTTP
				 * callback will ever fire to resume us.  Without
				 * this, the server wsi would hang suspended forever
				 * (the browser sees "no response, no timeout").  Drop
				 * the pending state and fail the request now.
				 */
				lwsl_wsi_notice(wsi, "/oauth/callback: failed to "
						"connect to %s for /api/token",
						vhd->remote_auth_url ?
							vhd->remote_auth_url :
							"(null)");
				/*
				 * No client wsi was created, so the server leg is
				 * the only owner; clear wsi_server and release.
				 */
				ps->wsi_server = NULL;
				ps->wsi_client = NULL;
				pending_auth_release(ps);
				lws_return_http_status(wsi,
					HTTP_STATUS_BAD_GATEWAY,
					"Unable to reach auth server");
				return lws_http_transaction_completed(wsi);
			}
			lwsl_wsi_notice(wsi, "/oauth/callback: client connect started");

			lws_parse_uri_destroy(&puri);
		}

		return 0; // suspend without writing any header yet
		}
		break;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE: {
		struct pending_auth_state *ps = NULL;
		char loc[512];
		char cookie[LWS_SSO_MAX_COOKIE];
		unsigned char buf[LWS_SSO_MAX_COOKIE + 512 + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;

		// Find if this WSI belongs to a pending auth state that just finished
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
			if (s->wsi_server == wsi) {
				ps = s;
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (!ps)
			break;

		if (ps->fatal_error || !ps->token[0]) {
			/*
			 * If /api/token returned an OAuth2 error JSON, surface
			 * the actual error code + description so the cause is
			 * visible (eg invalid_grant / PKCE mismatch / invalid_client)
			 * instead of a generic "Failed to obtain access token".
			 */
			if (!ps->fatal_error && (ps->token_error[0] ||
						 ps->token_error_desc[0]))
				lwsl_wsi_notice(wsi, "/api/token rejected: error='%s' "
					    "desc='%s'\n",
					    ps->token_error[0] ?
						    ps->token_error : "(none)",
					    ps->token_error_desc[0] ?
						    ps->token_error_desc : "(none)");
			lwsl_wsi_notice(wsi, "bailing with fatal error: %s",
				    ps->fatal_error ? ps->fatal_error : "Failed to obtain access token");
			lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
					       ps->fatal_error ? ps->fatal_error : "Failed to obtain access token");
			/*
			 * The server leg is done.  Don't free ps outright: the
			 * outgoing /api/token client wsi may still hold ps as its
			 * user_space and fire callbacks on it -- freeing here is a
			 * use-after-free.  Detach the server's back-pointer and let
			 * pending_auth_release() tear ps down only when the client
			 * leg is also done.
			 */
			ps->wsi_server = NULL;
			pending_auth_release(ps);
			return lws_http_transaction_completed(wsi);
		}

		// Found the finished state!
		lws_snprintf(cookie, sizeof(cookie),
			 "%s=%s; Path=/; Max-Age=%lu; SameSite=Lax; Secure; HttpOnly",
			 vhd->cookie_name, ps->token,
			 cookie_max_age(vhd, ps->expires_in_secs));

		lws_strncpy(loc, ps->redirect_uri, sizeof(loc));

		// capture the csrf (and refresh token, if the server issued one)
		// before we drop ps; emitted as extra set-cookies below, alongside
		// auth_session.
		{
			char csrf_cookie[80];
			char refresh_cookie[160];
			int cl, rl = 0;
			/*
			 * auth_csrf guards silent renewal (the double-submit
			 * check on the side-channel POST), so it must outlive the
			 * short-lived auth_session JWT it was minted alongside --
			 * otherwise renewal can never run once that JWT expires
			 * (eg a suspended tablet waking after the JWT, but not the
			 * long-term refresh session, has lapsed).  Give it the
			 * refresh lifetime when we have a refresh token; fall back
			 * to the JWT lifetime for non-refreshable sessions.
			 */
			unsigned long csrf_ma =
				ps->refresh_token[0] && ps->refresh_expires_in_secs
					? ps->refresh_expires_in_secs
					: cookie_max_age(vhd, ps->expires_in_secs);
			lws_snprintf(csrf_cookie, sizeof(csrf_cookie),
				     "auth_csrf=%s; Path=/; Max-Age=%lu; "
				     "SameSite=Lax; Secure; HttpOnly",
				     ps->csrf, csrf_ma);
			cl = (int)strlen(csrf_cookie);

			/*
			 * If the auth server minted a long-term refresh token, set
			 * it as auth_refresh_session on this (app) host.  lws-login's
			 * silent renewal then has a cookie to renew with, scoped to
			 * the same host as auth_session/auth_csrf.  Same lifetime
			 * model as those: prefer the server-reported refresh
			 * lifetime, fall back to the configured cookie-max-age-secs,
			 * finally the session-cookie default.
			 */
			if (ps->refresh_token[0]) {
				unsigned long ma = ps->refresh_expires_in_secs;
				if (!ma)
					ma = cookie_max_age(vhd, 0);
				rl = lws_snprintf(refresh_cookie,
						  sizeof(refresh_cookie),
						  "auth_refresh_session=%s; "
						  "Path=/; Max-Age=%lu; "
						  "SameSite=Lax; Secure; HttpOnly",
						  ps->refresh_token, ma);
			}

			lwsl_wsi_notice(wsi, "/oauth/callback: issuing %s cookie "
				"(Max-Age %lus) + auth_csrf (Max-Age %lus)%s",
				vhd->cookie_name,
				cookie_max_age(vhd, ps->expires_in_secs),
				csrf_ma,
				rl ? " + auth_refresh_session"
				   : " [NO refresh token from auth server -> "
				     "silent renewal will not work]");

			// Issue the cookies and the 302
			if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end) ||
			    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, (int)strlen(loc), &p, end) ||
			    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE, (unsigned char *)cookie, (int)strlen(cookie), &p, end) ||
			    lws_add_http_header_by_name(wsi, (const uint8_t *)"set-cookie:", (const uint8_t *)csrf_cookie, cl, &p, end) ||
			    (rl && lws_add_http_header_by_name(wsi, (const uint8_t *)"set-cookie:", (const uint8_t *)refresh_cookie, rl, &p, end)) ||
			    lws_finalize_http_header(wsi, &p, end))
				return 1;
		}

		/*
		 * Server leg is done (302 + cookies written).  As with the bail
		 * path, don't free ps outright if the /api/token client wsi is
		 * still alive -- it still references ps as its user_space.
		 */
		ps->wsi_server = NULL;
		pending_auth_release(ps);

		/* headers-only 302 (set-cookies + Location): under h2 the HEADERS
		 * frame must carry END_STREAM or the stream hangs open. */
		lws_write(wsi, buf + LWS_PRE, (size_t)lws_ptr_diff(p, buf + LWS_PRE),
			  LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
		return lws_http_transaction_completed(wsi);
	}

	case LWS_CALLBACK_CLOSED_HTTP: {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *s = lws_container_of(d, struct pending_auth_state, list);
			if (s->wsi_server == wsi) {
				/* The /oauth/callback server wsi closed (eg the
				 * browser gave up).  Detach the server leg; ps is
				 * released if the client leg is also done. */
				s->wsi_server = NULL;
				pending_auth_release(s);
			}
		} lws_end_foreach_dll_safe(d, d1);
		break;
	}

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		/*
		 * Per the documented contract (lws-callbacks.h): `in` is a
		 * pointer to the producer's write-cursor variable (so *p is the
		 * current write position in the header scratch buffer), and `len`
		 * is the number of bytes remaining from *p to the end of that
		 * buffer (exclusive, already discounted by 12 for the CRLF CRLF
		 * terminator lws appends after we return).
		 */
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (*p) + len;
		char cl[16];

		if (!ps)
			break;

		/*
		 * Append the POST headers through the lws API, not by raw
		 * lws_snprintf into the buffer: the APPEND scratch buffer holds
		 * H1 text on h1 but HPACK on h2, so writing "Content-Type:..."
		 * as plain text would inject raw header bytes into the h2 HPACK
		 * block.  lws_add_http_header_by_token emits the correct bytes
		 * for whichever role we are.
		 */
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"application/x-www-form-urlencoded",
				33, p, end))
			return 1;

		lws_snprintf(cl, sizeof(cl), "%d", ps->payload_len);
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(unsigned char *)cl, (int)strlen(cl), p, end))
			return 1;

		/*
		 * Arm the POST body write: the canonical pattern (see
		 * minimal-http-client-post / test-client.c) of setting body-pending
		 * and requesting WRITEABLE after appending Content-Type/Length.
		 */
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		size_t chunk;
		int n;

		if (!ps || ps->payload_pos >= ps->payload_len)
			break;

		chunk = (size_t)(ps->payload_len - ps->payload_pos);

		/*
		 * On the final body chunk, pair lws_client_http_body_pending(,0)
		 * with LWS_WRITE_HTTP_FINAL.  As minimal-http-client-post notes,
		 * this is "necessary to support H2, it means we will write no
		 * more on this stream" -- it puts END_STREAM on the last DATA
		 * frame so the server knows the request body is complete.
		 */
		lws_client_http_body_pending(wsi, 0);

		n = lws_write(wsi, (unsigned char *)ps->payload + ps->payload_pos,
			      chunk, LWS_WRITE_HTTP_FINAL);
		if (n < 0)
			return -1;
		ps->payload_pos += n;

		if (ps->payload_pos < ps->payload_len)
			lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);
		int m;

		if (!ps || !in || !len)
			break;

		m = lejp_parse(&ps->jctx, (const unsigned char *)in, (int)len);
		if (m < 0 && m != LEJP_CONTINUE) {
			if (!ps->fatal_error)
				ps->fatal_error = "Token JSON parsing failed";
		}
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);

		if (!ps)
			break;

		if (ps->wsi_server)
			lws_callback_on_writable(ps->wsi_server);
		/* The client leg is done; release ps if the server leg already
		 * finished too. */
		ps->wsi_client = NULL;
		pending_auth_release(ps);
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP: {
		struct pending_auth_state *ps = (struct pending_auth_state *)lws_wsi_user(wsi);

		if (!ps)
			break;

		/*
		 * CLIENT_CONNECTION_ERROR delivers a human-readable reason in
		 * (in, len); CLOSED_CLIENT_HTTP has in == NULL.  Logging the
		 * reason is the difference between guessing why the /api/token
		 * fetch failed and knowing -- lws sets cce strings like
		 * "bio_create failed", "error sending h2 preface",
		 * "first service failed", "Timed out waiting server reply",
		 * or a TLS error from the handshake.
		 */
		if (reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR && in && len)
			lwsl_wsi_notice(wsi, "%s: /api/token client connection "
					"failed: %.*s", __func__,
					(int)len, (const char *)in);
		else
			lwsl_wsi_notice(wsi, "%s: /api/token client connection "
					"closed", __func__);

		if (ps->wsi_server && !ps->token[0]) {
			// Failed, resume server to throw 500
			lws_callback_on_writable(ps->wsi_server);
		}
		/* The client leg is gone; release ps if the server leg already
		 * finished too (otherwise the server's later teardown will). */
		ps->wsi_client = NULL;
		pending_auth_release(ps);
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY: {
		if (!vhd)
			break;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_auth_list)) {
			struct pending_auth_state *ps = lws_container_of(d, struct pending_auth_state, list);
			lws_sul_cancel(&ps->sul);
			lejp_destruct(&ps->jctx);
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
		.name = "OAuth2 Client",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 0,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols)
};
