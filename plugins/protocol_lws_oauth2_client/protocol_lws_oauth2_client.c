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
	const char *auth_server_url;		/* side-channel base URL for /api/sso_exchange;
						 * defaults to remote_auth_url */
	const char *client_id;
	const char *cookie_name;
	unsigned long cookie_max_age_secs;	/* fallback Max-Age when no expires_in is available */

	lws_dll2_owner_t pending_auth_list;
	lws_dll2_owner_t pending_refresh_list;
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

	char state[48];
	char code_verifier[64];
	char redirect_uri[256];
	char code[256];
	char token[LWS_SSO_MAX_COOKIE];
	int token_len;
	unsigned long expires_in_secs;	/* seconds, from the token response; 0 = unknown */

	char csrf[33];			/* random CSRF token issued with the session,
					 * used by the silent-refresh BFF for its
					 * double-submit check */

	char payload[1024];
	int payload_len;
	int payload_pos;
};

/*
 * Outstanding silent-refresh state.  Created when the browser hits the
 * /.lws-oauth-refresh BFF endpoint; freed when the side-channel POST to the
 * auth server completes (or times out).
 */
struct pending_refresh_state {
	lws_dll2_t list;
	lws_sorted_usec_list_t sul;
	struct vhd_oauth2_client *vhd;

	struct lws *wsi_server;
	struct lws *wsi_client;

	struct lejp_ctx jctx;
	const char *fatal_error;

	/* forwarded browser Cookie header, for /api/sso_exchange */
	char cookie_hdr[1024];

	char payload[512];
	int payload_len;
	int payload_pos;

	char token[LWS_SSO_MAX_COOKIE];
	int token_len;
};

static const char * const lejp_paths[] = {
	"access_token",
	"expires_in"
};

static signed char
oauth_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pending_auth_state *ps = (struct pending_auth_state *)ctx->user;

	if (reason != LEJP_FLAG_CB_IS_VALUE)
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
	}

	return 0;
}

static const char * const refresh_lejp_paths[] = {
	"token",
	"error"
};

static signed char
refresh_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pending_refresh_state *ps =
			(struct pending_refresh_state *)ctx->user;

	if (reason != LEJP_FLAG_CB_IS_VALUE)
		return 0;

	switch (ctx->path_match) {
	case 1: /* token */
		if (ps->token_len + ctx->npos >= LWS_SSO_MAX_COOKIE - 1) {
			ps->fatal_error = "JWT in refresh response is truncated";
			return -1;
		}
		memcpy(ps->token + ps->token_len, ctx->buf, ctx->npos);
		ps->token_len += ctx->npos;
		ps->token[ps->token_len] = '\0';
		break;

	case 2: /* error */
		if (!ps->fatal_error)
			ps->fatal_error = "Refresh rejected by auth server";
		break;
	}

	return 0;
}

static void
sul_pending_auth_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_auth_state *ps = lws_container_of(sul,
					struct pending_auth_state, sul);

	lwsl_info("%s: auth state %s timed out\\n", __func__, ps->state);
	lws_dll2_remove(&ps->list);
	lejp_destruct(&ps->jctx);
	free(ps);
}

static void
sul_pending_refresh_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_refresh_state *ps = lws_container_of(sul,
					struct pending_refresh_state, sul);

	/*
	 * Mirrors the login plugin: the 5min timeout is a leak backstop, far
	 * longer than any legitimate sso_exchange round-trip.  The browser wsi
	 * has its own PENDING_TIMEOUT_HTTP_CONTENT (30s) that will produce the
	 * 401 if we never complete; we don't wake it from here, because freeing
	 * ps here means the WRITEABLE lookup must not find it.
	 */
	lwsl_info("%s: refresh state timed out\n", __func__);
	lws_dll2_remove(&ps->list);
	lejp_destruct(&ps->jctx);
	free(ps);
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

/*
 * Client-side auto-renewal helper, served at /oauth/refresh.js.
 *
 * Strategy: the plugin doesn't locally validate the JWT (it has no JWK), so it
 * cannot read exp from the cookie itself.  Instead we renew on a fixed cadence
 * derived from the configured cookie lifetime (renew at ~75% of lifetime, i.e.
 * comfortably before expiry but not so often we hammer the auth server), and
 * also immediately whenever the tab regains focus -- covering the common case
 * of a user returning to a long-idle tab whose cookie is about to lapse.
 *
 * On a hard failure (401 from the BFF, meaning the long-term login cookie is
 * genuinely gone server-side) we stop retrying and leave it to the application
 * to render its own logged-out UX.  Network errors and 5xx do NOT count as
 * logged-out: we back off and try again, because the long-term login cookie
 * may still be perfectly valid server-side and only the network blip stopped
 * us.  This is the key behavioural fix: transient errors no longer flicker the
 * UI to "logged out".
 *
 * CSP note: this is served as a plain external .js (no inline script), matching
 * the project's strict-CSP requirement.  It is stored as a C string literal
 * like the login plugin does.
 *
 * The %lu below is filled with cookie_max_age_secs at serve time (0 -> default
 * 1800s cadence), so the operator's configured cookie lifetime drives renewal.
 */
static const char refresh_js[] =
"/* lws-oauth2-client silent refresh; served from /oauth/refresh.js */\n"
"(function(){\n"
"if(window.__lwsOauthRefresh)return;window.__lwsOauthRefresh=1;\n"
"var LIFE=%lu;                  /* cookie lifetime in seconds, from server */\n"
"var inflight=0,dead=0,armed=null;\n"
"/* renew at ~75%% of lifetime, clamped to [60s, 1h]; default 25min. */\n"
"var cadence=Math.min(3600,Math.max(60,Math.round((LIFE||1800)*0.75)))*1000;\n"
"function sched(ms){if(armed)clearTimeout(armed);armed=setTimeout(tick,ms);}\n"
"async function renew(){\n"
"if(inflight||dead)return null;inflight=1;\n"
"try{var r=await fetch('/oauth/refresh',{method:'POST',credentials:'include'});\n"
"inflight=0;\n"
"if(r.status===401){dead=1;return false;} /* hard fail: long-term login gone */\n"
"if(!r.ok)return null;               /* transient: keep session, retry */\n"
"return true;}catch(e){inflight=0;return null;}}\n"
"async function tick(){\n"
"if(dead)return;\n"
"var ok=await renew();\n"
"if(ok===true){sched(cadence);return;}\n"
"if(ok===false){return;}             /* dead: stop */\n"
"sched(30000);                       /* transient fail: retry in 30s */\n"
"}\n"
"/* also renew immediately when the tab becomes visible again */\n"
"document.addEventListener('visibilitychange',function(){\n"
"if(!document.hidden&&!dead&&!inflight)tick();});\n"
"if(document.readyState==='loading')\n"
"document.addEventListener('DOMContentLoaded',tick);else tick();\n"
"})();\n";

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
				if (!strcmp(pvo->name, "auth-server-url"))
					vhd->auth_server_url = pvo->value;
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

			/*
			 * The side channel for silent renewal targets /api/sso_exchange on
			 * the auth server.  By default that is the same place we redirect
			 * the browser to (remote-auth-url), but the operator may split them
			 * eg. when browser-facing and server-to-server URLs differ.
			 */
			if (!vhd->auth_server_url)
				vhd->auth_server_url = vhd->remote_auth_url;

			lwsl_vhost_notice(vhd->vhost, "%s: initialized oauth2 client using auth=%s (side-channel via %s)\n",
					  __func__, vhd->remote_auth_url,
					  vhd->auth_server_url);
			break;

	case LWS_CALLBACK_HTTP: {
		char uri[256];

		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) < 0 &&
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) < 0)
			break;

		if (!strcmp(uri, "/oauth/login")) {
			struct pending_auth_state *ps;
			uint8_t rand_bytes[32];
			uint8_t hash[32];
			char code_challenge[64];
			char sname[128] = {0};
			char loc[1024];
			struct lws_genhash_ctx hctx;
			unsigned char buf[1024 + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;

			ps = malloc(sizeof(*ps));
			if (!ps)
				return 1;
			memset(ps, 0, sizeof(*ps));
			ps->vhd = vhd;

			if (lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", ps->redirect_uri, sizeof(ps->redirect_uri)) < 0) {
				lws_strncpy(ps->redirect_uri, "/", sizeof(ps->redirect_uri));
			} else {
				/* Prevent Open Redirect by enforcing relative local paths */
				if (ps->redirect_uri[0] != '/' || ps->redirect_uri[1] == '/')
					lws_strncpy(ps->redirect_uri, "/", sizeof(ps->redirect_uri));
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
				free(ps);
				return -1;
			}
			lws_b64_encode_string_url((const char *)hash, 32, code_challenge, sizeof(code_challenge));

			lws_dll2_add_tail(&ps->list, &vhd->pending_auth_list);
			lws_sul_schedule(vhd->context, 0, &ps->sul, sul_pending_auth_cb, 5 * 60 * LWS_US_PER_SEC);

			lws_snprintf(loc, sizeof(loc), "%s/api/authorize?client_id=%s&redirect_uri=%%2Foauth%%2Fcallback&state=%s&code_challenge=%s&code_challenge_method=S256&response_type=code%s%s",
				vhd->remote_auth_url, vhd->client_id, ps->state, code_challenge,
				sname[0] ? "&service_name=" : "", sname);

			if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end)) return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, (int)strlen(loc), &p, end)) return 1;
			if (lws_finalize_http_header(wsi, &p, end)) return 1;

			lws_write(wsi, buf + LWS_PRE, (size_t)lws_ptr_diff(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			return lws_http_transaction_completed(wsi);
		}

		if (!strcmp(uri, "/oauth/callback")) {
			char state_in[48];
			char code_in[256];
			char iss_in[256];
			struct pending_auth_state *ps = NULL;

			if (lws_get_urlarg_by_name_safe(wsi, "state=", state_in, sizeof(state_in)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "code=", code_in, sizeof(code_in)) < 0 ||
			    lws_get_urlarg_by_name_safe(wsi, "iss=", iss_in, sizeof(iss_in)) < 0) {
				lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, "Missing state, code, or iss");
				return lws_http_transaction_completed(wsi);
			}

			lws_urldecode(iss_in, iss_in, sizeof(iss_in));
			if (strlen(iss_in) != strlen(vhd->remote_auth_url) || strcmp(iss_in, vhd->remote_auth_url)) {
				lwsl_err("%s: Mix-up defense blocked callback for unknown iss %s\\n", __func__, iss_in);
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

			ps->payload_len = lws_snprintf(ps->payload, sizeof(ps->payload),
				"grant_type=authorization_code&client_id=%s&redirect_uri=%%2Foauth%%2Fcallback&code=%s&code_verifier=%s",
				vhd->client_id, ps->code, ps->code_verifier);
			ps->payload_pos = 0;

			{
				struct lws_client_connect_info i;
				lws_parse_uri_t *puri;

				puri = lws_parse_uri_create(vhd->remote_auth_url);
				if (!puri) {
					lwsl_err("Failed to parse remote-auth-url\n");
					lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Invalid config");
					return lws_http_transaction_completed(wsi);
				}

				memset(&i, 0, sizeof(i));
				i.context = vhd->context;
				i.address = puri->host;
				i.port = puri->port;
				i.ssl_connection = !strcmp(puri->scheme, "http") ? 0 : LCCSCF_USE_SSL;
				i.path = "/api/token";
				i.host = i.address;
				i.origin = i.address;
				i.method = "POST";
				i.protocol = "lws-oauth2-client";
				i.pwsi = &ps->wsi_client;
				i.userdata = ps;

				lws_client_connect_via_info(&i);
				lws_parse_uri_destroy(&puri);
			}

			return 0; // suspend without writing any header yet
		}

		/*
		 * Silent-renewal client helper.  Served as an external .js so it
		 * complies with the strict CSP.  The app includes it with
		 * <script src="/oauth/refresh.js"></script> and it self-arrows.
		 */
		if (!strcmp(uri, "/oauth/refresh.js")) {
			char js[sizeof(refresh_js) + 32];
			int n = lws_snprintf(js, sizeof(js), refresh_js,
					     (unsigned long)vhd->cookie_max_age_secs);
			unsigned char buf[256 + LWS_PRE], *p = buf + LWS_PRE,
					*end = buf + sizeof(buf) - 1;

			if (lws_add_http_common_headers(wsi,
					HTTP_STATUS_OK,
					"application/javascript; charset=utf-8",
					(lws_filepos_t)(unsigned long)n, &p, end))
				return 1;
			/* defeat cross-origin script inclusion */
			if (lws_add_http_header_by_name(wsi,
					(const uint8_t *)"cross-origin-resource-policy:",
					(const uint8_t *)"same-origin", 11, &p, end))
				return 1;
			if (lws_finalize_http_header(wsi, &p, end))
				return 1;
			if (lws_write(wsi, buf + LWS_PRE,
				      (size_t)lws_ptr_diff(p, buf + LWS_PRE),
				      LWS_WRITE_HTTP_HEADERS) < 0)
				return 1;
			if (lws_write(wsi, (unsigned char *)js, (size_t)n,
				      LWS_WRITE_HTTP_FINAL) < 0)
				return 1;
			return lws_http_transaction_completed(wsi);
		}

		/*
		 * Silent-renewal BFF endpoint.  The browser POSTs here with its
		 * cookies (credentials:'include'); we forward the Cookie header to
		 * the auth server's /api/sso_exchange side channel.  If the long-term
		 * auth_refresh_session cookie is still valid there, the server re-mints
		 * a fresh short-lived auth_session JWT and we transparently re-issue
		 * the cookie here -- the user never sees a logged-out state.
		 *
		 * Returns 200 + new cookie on success, 401 on hard failure (long-term
		 * login gone -- this is the only case the JS treats as "logged out"),
		 * 5xx/network on transient failure (JS retries, keeps last session).
		 */
		if (!strcmp(uri, "/oauth/refresh")) {
			char csrf[64] = { 0 }, refresh_tk[128] = { 0 };
			size_t csrf_len = sizeof(csrf);
			size_t refresh_len = sizeof(refresh_tk);
			int ck_len = lws_hdr_total_length(wsi,
							WSI_TOKEN_HTTP_COOKIE);

			if (ck_len <= 0 ||
			    lws_http_cookie_get(wsi, "auth_refresh_session",
						refresh_tk, &refresh_len) ||
			    !refresh_tk[0] ||
			    lws_http_cookie_get(wsi, "auth_csrf",
						csrf, &csrf_len) ||
			    !csrf[0]) {
				/* no long-term login cookie present -> hard fail */
				lwsl_notice("%s: refresh requested without "
					    "auth_refresh_session/auth_csrf "
					    "cookies\n", __func__);
				return lws_return_http_status(wsi,
						HTTP_STATUS_UNAUTHORIZED,
						"Missing Authorization");
			}

			struct pending_refresh_state *ps = malloc(sizeof(*ps));
			if (!ps)
				return 1;
			memset(ps, 0, sizeof(*ps));
			ps->vhd = vhd;
			ps->wsi_server = wsi;

			/* forward the full browser cookie jar to the side channel */
			if (lws_hdr_copy(wsi, ps->cookie_hdr,
					 sizeof(ps->cookie_hdr),
					 WSI_TOKEN_HTTP_COOKIE) < 0) {
				free(ps);
				return lws_return_http_status(wsi,
						HTTP_STATUS_UNAUTHORIZED,
						"Missing Authorization");
			}

			ps->payload_len = lws_snprintf(ps->payload,
					sizeof(ps->payload), "csrf_token=%s",
					csrf);
			ps->payload_pos = 0;

			lejp_construct(&ps->jctx, refresh_lejp_cb, ps,
				       refresh_lejp_paths,
				       LWS_ARRAY_SIZE(refresh_lejp_paths));

			lws_dll2_add_tail(&ps->list, &vhd->pending_refresh_list);
			lws_sul_schedule(vhd->context, 0, &ps->sul,
					 sul_pending_refresh_cb,
					 5 * 60 * LWS_US_PER_SEC);

			lws_parse_uri_t *puri =
					lws_parse_uri_create(vhd->auth_server_url);
			if (!puri) {
				lws_sul_cancel(&ps->sul);
				lws_dll2_remove(&ps->list);
				lejp_destruct(&ps->jctx);
				free(ps);
				return lws_return_http_status(wsi,
						HTTP_STATUS_UNAUTHORIZED,
						"Missing Authorization");
			}

			struct lws_client_connect_info i;
			memset(&i, 0, sizeof(i));
			i.context        = vhd->context;
			i.address        = puri->host;
			i.port           = puri->port;
			i.ssl_connection = !strcmp(puri->scheme, "http") ?
						0 : LCCSCF_USE_SSL;
			i.path           = "/api/sso_exchange";
			i.host           = i.address;
			i.origin         = i.address;
			i.method         = "POST";
			i.protocol       = "lws-oauth2-client-refresh";
			i.pwsi           = &ps->wsi_client;
			i.userdata       = ps;

			lwsl_notice("%s: silent renew via %s/api/sso_exchange\n",
				    __func__, vhd->auth_server_url);
			lws_client_connect_via_info(&i);
			lws_parse_uri_destroy(&puri);
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);

			return 0; /* suspend; WRITEABLE finalizes the response */
		}
		break;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE: {
		struct pending_auth_state *ps = NULL;
		struct pending_refresh_state *rs = NULL;
		char loc[512];
		char cookie[LWS_SSO_MAX_COOKIE];
		unsigned char buf[LWS_SSO_MAX_COOKIE + 512 + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;

		// Find if this WSI belongs to a pending refresh that just finished
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_refresh_list)) {
			struct pending_refresh_state *s = lws_container_of(d,
						struct pending_refresh_state, list);
			if (s->wsi_server == wsi) {
				rs = s;
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (rs) {
			/*
			 * Silent renewal completion.  On success we re-issue the
			 * short-lived auth_session cookie with a fresh token; the
			 * browser cookie is replaced transparently and the user
			 * never sees a state change.  On any failure we return 401
			 * so the client JS flips to its logged-out UX.
			 */
			int ok = (rs->token[0] && !rs->fatal_error);

			if (ok) {
				int n = lws_snprintf(cookie, sizeof(cookie),
					 "%s=%s; Path=/; Max-Age=%lu; "
					 "SameSite=Lax; Secure; HttpOnly",
					 vhd->cookie_name, rs->token,
					 cookie_max_age(vhd, 0));

				if (lws_add_http_common_headers(wsi,
						HTTP_STATUS_OK,
						"application/json",
						(lws_filepos_t)13L, &p, end) ||
				    lws_add_http_header_by_name(wsi,
						(const uint8_t *)"set-cookie:",
						(const uint8_t *)cookie, n,
						&p, end) ||
				    lws_finalize_http_header(wsi, &p, end)) {
					ok = 0;
				} else {
					unsigned char body[] = "{\"success\":1}";
					lws_write(wsi, buf + LWS_PRE,
					      (size_t)lws_ptr_diff(p, buf + LWS_PRE),
					      LWS_WRITE_HTTP_HEADERS);
					lws_write(wsi, body, sizeof(body) - 1,
						  LWS_WRITE_HTTP_FINAL);
					lwsl_notice("%s: silent renew issued "
						    "fresh cookie\n", __func__);
				}
			}

			if (!ok)
				lws_return_http_status(wsi,
					HTTP_STATUS_UNAUTHORIZED,
					"Session renewal failed");

			lws_sul_cancel(&rs->sul);
			lws_dll2_remove(&rs->list);
			lejp_destruct(&rs->jctx);
			free(rs);
			return lws_http_transaction_completed(wsi);
		}

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
			lwsl_notice("%s: bailing with fatal error: %s\n", __func__,
				    ps->fatal_error ? ps->fatal_error : "Failed to obtain access token");
			lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
					       ps->fatal_error ? ps->fatal_error : "Failed to obtain access token");
			lws_dll2_remove(&ps->list);
			lejp_destruct(&ps->jctx);
			free(ps);
			return lws_http_transaction_completed(wsi);
		}

		// Found the finished state!
		lws_snprintf(cookie, sizeof(cookie),
			 "%s=%s; Path=/; Max-Age=%lu; SameSite=Lax; Secure; HttpOnly",
			 vhd->cookie_name, ps->token,
			 cookie_max_age(vhd, ps->expires_in_secs));

		lws_strncpy(loc, ps->redirect_uri, sizeof(loc));

		// capture the csrf before we drop ps; emitted as a second set-cookie
		// below, alongside auth_session
		{
			char csrf_cookie[80];
			int cl;
			lws_snprintf(csrf_cookie, sizeof(csrf_cookie),
				     "auth_csrf=%s; Path=/; Max-Age=%lu; "
				     "SameSite=Lax; Secure; HttpOnly",
				     ps->csrf,
				     cookie_max_age(vhd, ps->expires_in_secs));
			cl = (int)strlen(csrf_cookie);

			// Issue the cookies and the 302
			if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end) ||
			    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)loc, (int)strlen(loc), &p, end) ||
			    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SET_COOKIE, (unsigned char *)cookie, (int)strlen(cookie), &p, end) ||
			    lws_add_http_header_by_name(wsi, (const uint8_t *)"set-cookie:", (const uint8_t *)csrf_cookie, cl, &p, end) ||
			    lws_finalize_http_header(wsi, &p, end))
				return 1;
		}

		// Unlink and free it, we don't need it anymore
		lws_dll2_remove(&ps->list);
		lejp_destruct(&ps->jctx);
		free(ps);

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
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_refresh_list)) {
			struct pending_refresh_state *s = lws_container_of(d,
						struct pending_refresh_state, list);
			if (s->wsi_server == wsi)
				s->wsi_server = NULL;
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

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_refresh_list)) {
			struct pending_refresh_state *rs = lws_container_of(d,
						struct pending_refresh_state, list);
			lws_sul_cancel(&rs->sul);
			lejp_destruct(&rs->jctx);
			lws_dll2_remove(&rs->list);
			free(rs);
		} lws_end_foreach_dll_safe(d, d1);
		break;
	}

	default:
		break;
	}

	return 0;
}

/*
 * Side-channel client callback for silent renewal.  This is a separate
 * protocol ("lws-oauth2-client-refresh") so its userdata is unambiguously a
 * pending_refresh_state, never a pending_auth_state -- mirroring how the login
 * plugin splits its main vs lws_login_client protocols.  It only does the
 * outbound POST of csrf_token to /api/sso_exchange and parses the {"token":...}
 * reply into ps->token; the browser-facing response is finalized in the main
 * callback's LWS_CALLBACK_HTTP_WRITEABLE when ps->wsi_server is woken.
 */
static int
callback_lws_oauth2_refresh_client(struct lws *wsi,
				   enum lws_callback_reasons reason,
				   void *user, void *in, size_t len)
{
	struct pending_refresh_state *ps =
			(struct pending_refresh_state *)lws_wsi_user(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (unsigned char *)in + len - 1;
		char clen[16];

		if (!ps)
			break;

		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"application/x-www-form-urlencoded",
				33, p, end))
			return -1;

		/* forward the browser's cookies to the side channel */
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
				(unsigned char *)ps->cookie_hdr,
				(int)strlen(ps->cookie_hdr), p, end))
			return -1;

		lws_snprintf(clen, sizeof(clen), "%d", ps->payload_len);
		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(unsigned char *)clen, (int)strlen(clen), p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		int n;

		if (!ps || ps->payload_pos >= ps->payload_len)
			break;

		n = lws_write(wsi,
			      (unsigned char *)ps->payload + ps->payload_pos,
			      (size_t)(ps->payload_len - ps->payload_pos),
			      LWS_WRITE_HTTP);
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
		int m;

		if (!ps || !in || !len)
			break;

		m = lejp_parse(&ps->jctx, (const unsigned char *)in, (int)len);
		if (m < 0 && m != LEJP_CONTINUE) {
			if (!ps->fatal_error)
				ps->fatal_error = "Refresh JSON parsing failed";
		}
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!ps)
			break;
		if (ps->wsi_server)
			lws_callback_on_writable(ps->wsi_server);
		ps->wsi_client = NULL;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!ps)
			break;
		lwsl_notice("%s: refresh client connection %s\n", __func__,
			    reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR ?
			    "errored" : "closed");
		if (ps->wsi_server && !ps->token[0])
			lws_callback_on_writable(ps->wsi_server);
		ps->wsi_client = NULL;
		break;

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
	}, {
		"lws-oauth2-client-refresh",
		callback_lws_oauth2_refresh_client,
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
