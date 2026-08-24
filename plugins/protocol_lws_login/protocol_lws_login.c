/*
 * ws protocol handler plugin for "lws login" / auth bouncer
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This plugin translates an LWS Mount Interceptor into a JWT-driven bouncer
 * depending on lws_jwt_auth. Unauthenticated connections are bounced transparently.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define LWS_AUTH_MAX_COOKIE_LEN LWS_SSO_MAX_COOKIE

struct login_whitelist {
	lws_dll2_t              list;
	lws_sockaddr46          sa46;
	int                     net_len;
};

struct vhd_login {
	struct lws_context      *context;
	struct lws_vhost        *vhost;
	struct lws_dll2_owner   wl;

	/* PVO settings */
	const char              *cookie_name;
	const char              *service_name;
	const char              *auth_server_url;
	const char              *unauth_protocols;
	int                     min_grant_level;

	char                    db_path[256];
	sqlite3                 *db;
	char                    auth_domain[128];
	char                    cookie_domain[128];
	uint64_t                jwt_validity_secs;
	uint64_t                csrf_max_age_secs;	/* auth_csrf cookie lifetime
							 * minted/renewed by this bouncer;
							 * default 30d. Decoupled from
							 * jwt_validity_secs because the
							 * csrf cookie must outlive the
							 * short JWT to guard renewal. */

	int                     unauth_allow;

	struct lws_jwk          jwk;
	lws_dll2_owner_t        pending_refresh_list;
};

struct pss_login {
	struct lws_jwt_auth     *ja;
	uint8_t                 whitelist_failed;
	char                    *silent_update_jwt;
	struct lws_spa          *spa;
	struct lws_buflist      *tx_buflist;
	size_t                  tx_remaining; /* body bytes not yet written, so the
					       * FINAL write can be identified
					       * correctly (see WRITEABLE) */
};

/*
 * Renewal completion mode.  Both the background BFF (POST .lws-login-refresh from
 * the page's widget JS) and the cold-load bouncer path run the exact same
 * /api/sso_exchange side channel; they differ only in what we do with the result.
 */
#define LWS_LOGIN_REFRESH_BFF      0 /* 200+set-cookie on success, 401 on dead */
#define LWS_LOGIN_REFRESH_COLDLOAD 1 /* 302-to-self with new cookie, else 303 to auth */

/*
 * COLDLOAD renewal has to send the browser back to the exact URL it asked
 * for, query string included: app pages deep-link through the query (eg
 * sai's ?project=X&branch=Y&event=Z&task=<uuid>), so losing it lands the
 * freshly re-logged-in user on a shortened, unusable URL.  Sized with
 * headroom over any realistic deep link.
 */
#define LWS_LOGIN_MAX_URI 512

struct pending_login_refresh {
	lws_dll2_t              list;
	lws_sorted_usec_list_t  sul;
	struct vhd_login        *vhd;

	struct lws              *wsi_server;
	struct lws              *wsi_client;

	/*
	 * The browser's Cookie header we forward verbatim to the auth server.
	 * Real jars carry several cookies plus parallel host-only / Domain=
	 * duplicates of the auth ones, so this needs LWS_SSO_MAX_COOKIE (4096):
	 * at 1024 a large jar truncated silently, and the truncated tail could
	 * contain exactly the auth_refresh_session the exchange needs.
	 */
	char                    cookie_hdr[LWS_SSO_MAX_COOKIE];

	/*
	 * POST body for the renewal exchange.  The body proper starts
	 * LWS_PRE bytes into payload[]: lws_write() composes the h2/h3 DATA
	 * frame header into the bytes immediately BEFORE the pointer it is
	 * given, so a body buffer without LWS_PRE headroom gets scribbled
	 * into (for h1 nothing is prepended, which is how this used to get
	 * away with it).
	 */
	char                    payload[LWS_PRE + 1024];
	int                     payload_len;
	int                     payload_pos;

	char                    token[2048];

	/*
	 * What the auth server actually said, so the browser-leg completion
	 * log can state the real denial reason instead of an anonymous
	 * "denied by Server": the HTTP status, the JSON "error" member of the
	 * response body, and -- when the side channel died before any
	 * response -- the client connection error string.
	 */
	unsigned                resp_status;
	char                    resp_error[96];
	char                    conn_error[160];

	/* COLDLOAD: the original request URI (path + query), so the success
	 * self-redirect lands the browser back on the protected URL it
	 * asked for. */
	char                    orig_path[LWS_LOGIN_MAX_URI];
	/* COLDLOAD: the pre-built auth-form URL (with service_name + redirect_uri),
	 * used only on renewal failure to land the user on the login form. */
	char                    authform_url[512];
	int                     mode; /* LWS_LOGIN_REFRESH_* */
};

static const char * const canned_css =
        ".lws-login-box{position:relative;font-family:-apple-system,system-ui,sans-serif;padding:"
        "16px;border-radius:8px;background:rgba(0,0,0,0.02);border:1px solid "
        "rgba(0,0,0,0.08);display:inline-block;font-size:14px;line-height:1.4;"
        "color:#333;}\n"
        "@media(prefers-color-scheme:dark){.lws-login-box{background:rgba(255,255,"
        "255,0.05);border-color:rgba(255,255,255,0.1);color:#888;}}\n"
        ".lws-login-btn{display:inline-block;padding:8px "
        "16px;background:#007bff;color:#fff!important;text-decoration:none;border-"
        "radius:6px;font-weight:600;font-size:13px;transition:background "
        "0.2s;margin-top:5px;}\n"
        ".lws-login-btn:hover{background:#0056b3;}\n"
        ".lws-login-err{display:inline-block;margin-top:8px;margin-bottom:4px;"
        "padding:6px 10px;background:#ffebee;border-left:3px solid "
        "#f44336;color:#c62828;font-size:13px;font-weight:500;}\n"
        ".lws-login-link{color:#007bff;text-decoration:none;margin-right:12px;font-"
        "weight:500;font-size:13px;transition:opacity 0.2s;}\n"
        ".lws-login-link:hover{opacity:0.8;}\n"
        ".lws-login-logout{color:#f44336;}\n"
        ".lws-login-identity{font-size:16px;margin:0 12px 0 "
        "0;display:inline-block;font-weight:600;}\n"
        ".lws-login-mt{margin-top:10px;}\n"
        ".lws-login-mb{margin-bottom:8px;font-weight:500;}\n"
        ".lws-preauth-banner{position:relative;margin-top:10px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.2);padding:12px;border-radius:8px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 4px 12px rgba(0,0,0,0.15);}"
        ".lws-preauth-info{display:flex;flex-direction:column;}"
        ".lws-preauth-title{font-weight:600;font-size:14px;margin-bottom:4px;}"
        ".lws-preauth-desc{font-size:12px;color:#aaa;}"
        ".lws-preauth-link{background:#28a745;color:#fff!important;text-decoration:none;padding:6px 12px;border-radius:4px;font-weight:600;font-size:13px;transition:background 0.2s;display:flex;align-items:center;gap:8px;}"
        ".lws-preauth-link:hover{background:#218838;}"
        ".pie-timer{width:20px;height:20px;transform:rotate(-90deg);border-radius:50%;}"
        ".pie-timer circle{fill:none;stroke:#fff;stroke-width:10;stroke-dasharray:31.4;transition:stroke-dashoffset 1s linear;}"
        ".lws-login-refgirl{position:absolute;bottom:0px;right:-10px;height:120px;opacity:0.8;pointer-events:none;z-index:1;}"
        ".lws-preauth-widget{display:none;position:absolute;top:0;left:100%;margin-left:15px;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:8px;max-height:200px;overflow-y:auto;background:#2b2d31;box-shadow:0 8px 16px rgba(0,0,0,0.3);z-index:1000;min-width:280px;}"
        ".lws-preauth-widget.active{display:block;}"
        ".lws-login-avatar-admin{color:#007bff;margin-right:6px;display:inline-block;vertical-align:middle;}"
        ".lws-login-avatar-user{color:#333;margin-right:6px;display:inline-block;vertical-align:middle;}"
        "@media(prefers-color-scheme:dark){.lws-login-avatar-user{color:#888;}}";

static const char * const canned_js =
        /* lwsLoginSilentRefresh: attempt a side-channel renewal via the BFF.
         * Returns a tri-state so callers can distinguish a hard failure (the
         * long-term login session is genuinely gone -> the auth server returns
         * 401) from a transient failure (network blip, 5xx, captive-portal
         * re-establishing on a freshly-woken device).  Only the hard failure
         * should escalate to the login page; transient failures are
         * retry-worthy because the long-term session may still be valid. */
        "window.lwsLoginSilentRefresh=async function(){"
        "try{"
        "var r=await fetch('.lws-login-refresh',{method:'POST',credentials:'include'});"
        "if(r.status===401)return 'dead';"
        "return r.ok?'ok':'transient';"
        "}catch(e){return 'transient';}"
        "};"
        /* lwsLoginEscalate: give up on silent renewal and send the user to the
         * auth server login page, preserving the current location for the
         * post-login redirect.  Idempotent via a guard flag so multiple
         * concurrent 'dead' results only navigate once. */
        "window.lwsLoginEscalate=function(login_url){"
        "if(window.__lwsLoginEscalated)return;"
        "window.__lwsLoginEscalated=1;"
        "var s=login_url.split('redirect_uri=')[0]+'redirect_uri='+encodeURIComponent(window.location.href);"
        "window.location.href=s;"
        "};"
        /* lwsLoginEsc: HTML-escape for the innerHTML render boundary.  Every
         * dynamic string composed into the widget's markup passes through
         * this (or, for URL query values like device_code,
         * encodeURIComponent).  Not all producers are trusted here: the
         * preauth widget renders device-provided name / user_code that
         * arrived over an UNauthenticated websocket, so the rule is that
         * dynamic data can inject text, never markup. */
        "window.lwsLoginEsc=function(s){var m={'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'};"
        "return String(s).replace(/[&<>\"']/g,function(c){return m[c];});};"
        "window.renderLwsLoginStatus=async function(d){"
        "window.__lwsLoginDiv=d;"
        "var e=document.getElementById(d);"
        "if(!e)return;"
        "if(window.__lwsLoginInflight)return;"
        "window.__lwsLoginInflight=1;"
        "if(!document.getElementById('lws-login-css')){"
        "var l=document.createElement('link');"
        "l.id='lws-login-css';l.rel='stylesheet';l.href='lws-login.css';"
        "document.head.appendChild(l);"
        "}"
        "try{"
        "let r=await fetch('.lws-login-status');"
        "let st=await r.json();"
        "if(!st.logged_in){"
        "var sr=await window.lwsLoginSilentRefresh();"
        "if(sr==='ok'){"
        "r=await fetch('.lws-login-status');"
        "st=await r.json();"
        "}else if(sr==='dead'){"
        /* long-term login gone.  If this mount allows anonymous access
         * (unauth_allow), do NOT bounce to the auth server -- the user can
         * legitimately use the page unauthenticated, and escalating them
         * (especially a user whose JWT simply expired but who lacks the grant)
         * traps them on the auth server's denial page.  Just render the
         * anonymous state; they can click Login themselves if they want. */
        "if(!st.unauth_allow){"
        "window.__lwsLoginInflight=0;"
        "window.lwsLoginEscalate(st.login_url);"
        "return;"
        "}"
        "}"
        "}"
        "var c='<div class=\"lws-login-box\">';"
        "if(st.server_now){"
        "var skew=Math.abs(st.server_now-(Date.now()/1000));"
        "if(skew>300){"
        "c+='<div class=\"lws-login-err\">Warning: Device clock off by '+Math.round(skew/60)+' mins</div><br>';"
        "c+='<img src=\"'+window.lwsLoginEsc(st.auth_server_url)+'/refgirl-time.png\" class=\"lws-login-refgirl\">';"
        "}"
        "}"
        "if(st.logged_in){"
        "window.lwsLoginRetry=0;"
        "var u='.lws-login-logout?redirect_uri='+encodeURIComponent(window.location.href);"
        "var a=st.is_admin?'<a class=\"lws-login-link\" href=\"'+window.lwsLoginEsc(st.auth_server_url)+'/api/admin\">Admin Console</a>':'';"
        "var av='<svg viewBox=\"0 0 24 24\" width=\"16\" height=\"16\" stroke=\"currentColor\" stroke-width=\"2\" fill=\"none\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2\"></path><circle cx=\"12\" cy=\"7\" r=\"4\"></circle></svg>';"
        "var gl=st.is_admin?255:(st.grant_level||0);"
        "var ac=gl>=2?'lws-login-avatar-admin':'lws-login-avatar-user';"
        "c+='<span class=\"'+ac+'\">'+av+'</span>';"
        "c+='<strong class=\"lws-login-identity\">'+window.lwsLoginEsc(st.identity)+'</strong><br>';"
        "c+=a+' <a class=\"lws-login-link lws-login-logout\" href=\"'+window.lwsLoginEsc(u)+'\">Logout</a>';"
        "if(!st.has_grant&&!st.is_admin)c+='<div class=\"lws-login-err\">login lacks grant</div><br>';"
        "if(st.exp){"
        "var n=st.server_now?st.server_now:(Date.now()/1000);"
        "var m=st.exp-n;"
        /* Schedule a silent refresh before expiry.  The upper bound must be
         * larger than any realistic cookie lifetime, otherwise long-lived
         * sessions (eg the 24h default jwt-validity-secs) never schedule a
         * refresh and the status div goes stale until a manual page reload.
         * 30d (2592000s) is well past any sensible session token lifetime
         * while still guarding against nonsensical multi-year exp values. */
        "if(m>0&&m<2592000){"
        "setTimeout(async function(){"
        "var sr=await window.lwsLoginSilentRefresh();"
        /* On a successful renewal, re-render to pick up the fresh exp.  On any
         * failure ('dead' or 'transient'), do NOT escalate or immediately
         * re-render: we are still rendering a LOGGED-IN box and the JWT is
         * (or was very recently) valid.  Escalating a logged-in user -- eg
         * one who merely lacks the grant on an unauth-allow mount, or whose
         * refresh cookie simply expired -- traps them on the auth server's
         * denial page.  Instead let the JWT ride out: the expiry timer below
         * fires at actual expiry, re-fetches status, and only then (if the
         * session is genuinely dead) does the not-logged-in branch escalate. */
        "if(sr==='ok')window.renderLwsLoginStatus(d);"
        "},(m>60?m-60:0)*1000);"
        /* Safety net: at actual expiry, re-render regardless.  If the JWT has
         * expired and refresh never succeeded, this transitions cleanly to the
         * not-logged-in branch (which decides escalation) rather than leaving
         * a stale logged-in box. */
        "setTimeout(function(){window.renderLwsLoginStatus(d);},(m+1)*1000);"
        "}"
        "}"
        "}else{"
        "var s=st.login_url.split('redirect_uri=')[0]+'redirect_uri='+encodeURIComponent(window.location.href);"
        "c+='<div class=\"lws-login-mb\">Not logged in</div>';"
        "c+='<a class=\"lws-login-btn\" href=\"'+window.lwsLoginEsc(s)+'\">Login &rarr;</a>';"
        /* We reach here only when silent refresh returned 'transient' (a hard
         * 'dead' already escalated out of the function above).  Back off and
         * retry; if the long-term session is actually dead, the next
         * renderLwsLoginStatus will get 'dead' from the silent-refresh attempt
         * in the not-logged-in branch and escalate then. */
        "let iv=[1,2,5,10,30,60,300,600,1200,3600];let rt=window.lwsLoginRetry||0;let d_s=iv[rt]||3600;window.lwsLoginRetry=rt+1;"
        "setTimeout(function(){window.renderLwsLoginStatus(d);},d_s*1000);"
        "}"
        "var pc=document.getElementById('lws-preauth-container');"
        "e.innerHTML=c+'</div>';"
        "if(st.logged_in){"
        "if(!pc){pc=document.createElement('div');pc.id='lws-preauth-container';pc.className='lws-preauth-widget';}"
        "e.style.position='relative';e.appendChild(pc);"
        "if(!window.lwsPreauthWS){"
        "var asu=st.auth_server_url || st.login_url.split('/login')[0];"
        "var u=asu.replace('https','wss').replace('http','ws');"
        "var ws=new WebSocket(u,'lws-oauth-preauth');"
        "window.lwsPreauthWS=ws;"
        "var devs={};"
        "function draw(){"
        "var h='';var now=Date.now()/1000;"
        "for(var k in devs){"
        "var d=devs[k];var left=d.expires-now;if(left<=0){delete devs[k];continue;}"
        "var pct=left/300.0;var dash=(1-pct)*31.4;"
        "h+='<div class=\"lws-preauth-banner\"><div class=\"lws-preauth-info\">';"
        "h+='<span class=\"lws-preauth-title\">New Device: '+window.lwsLoginEsc(d.name)+'</span>';"
        "h+='<span class=\"lws-preauth-desc\">Requires authorization</span></div>';"
        "h+='<a class=\"lws-preauth-link\" href=\"'+window.lwsLoginEsc(st.auth_server_url)+'/?device_code='+encodeURIComponent(d.user_code)+'\" target=\"_blank\">';"
        "h+='<svg class=\"pie-timer\" viewBox=\"0 0 10 10\"><circle cx=\"5\" cy=\"5\" r=\"5\" stroke-dashoffset=\"'+dash+'\"></circle></svg>';"
        "h+='Authorize</a></div>';"
        "}"
        "pc.innerHTML=h;"
        "if(Object.keys(devs).length>0){pc.classList.add('active');setTimeout(draw,1000);}else{pc.classList.remove('active');}"
        "}"
        "ws.onmessage=function(e){"
        "var m=JSON.parse(e.data);"
        "if(m.event==='device_joined'){devs[m.serial]=m;draw();}"
        "else if(m.event==='device_left'){delete devs[m.serial];draw();}"
        "};"
        "}"
        "}"
        "window.__lwsLoginInflight=0;"
        "}catch(er){"
        "console.log('lws-login fetch:',er);"
        "window.__lwsLoginInflight=0;"
        "let iv=[1,2,5,10,30,60,300,600,1200,3600];let rt=window.lwsLoginRetry||0;let d_s=iv[rt]||3600;window.lwsLoginRetry=rt+1;"
        "setTimeout(function(){window.renderLwsLoginStatus(d);},d_s*1000);"
        "}"
        "};"
        /* Wake trigger: when the device/tab wakes (eg an Android tablet that
         * slept through its renewal slot), fire a status check on visibility
         * change or bfcache restore so the not-logged-in -> silent-refresh ->
         * escalate flow runs without needing a manual page interaction.
         * Debounced to 1s to coalesce rapid visibility flips, and skipped if a
         * check is already in flight or we've already escalated to login. */
        "window.__lwsLoginWake=function(){"
        "if(window.__lwsLoginEscalated||window.__lwsLoginInflight)return;"
        "if(!window.__lwsLoginDiv)return;"
        "if(window.__lwsLoginWakeTimer)return;"
        "window.__lwsLoginWakeTimer=setTimeout(function(){"
        "window.__lwsLoginWakeTimer=null;"
        "if(!window.__lwsLoginEscalated&&!window.__lwsLoginInflight)"
        "window.renderLwsLoginStatus(window.__lwsLoginDiv);"
        "},1000);"
        "};"
        "document.addEventListener('visibilitychange',function(){"
        "if(!document.hidden)window.__lwsLoginWake();});"
        "window.addEventListener('pageshow',function(ev){"
        /* ev.persisted===true => restored from bfcache (a frozen tab reactivated,
         * eg after the device slept) -> worth a wake check.  A fresh load
         * (persisted===false) already runs its own initial render. */
        "if(ev.persisted)window.__lwsLoginWake();});";

/*
 * Tear down ps wherever we decided its life is over (server response done,
 * refresh timed out, creation unwinding).  The side-channel client wsi, if
 * still alive, has ps as its user_space: clear that and close it off before
 * freeing ps, or its later callbacks (RECEIVE_CLIENT_HTTP_READ, COMPLETED,
 * CLOSED, CCE) would dereference freed ps.  Mirrors pending_auth_release()
 * in protocol_lws_oauth2_client.c.
 */
static void
pending_login_release(struct pending_login_refresh *ps)
{
	if (!ps)
		return;

	if (ps->wsi_client) {
		lws_set_wsi_user(ps->wsi_client, NULL);
		lws_wsi_close(ps->wsi_client, LWS_TO_KILL_ASYNC);
		ps->wsi_client = NULL;
	}

	lws_sul_cancel(&ps->sul);
	lws_dll2_remove(&ps->list);
	free(ps);
}

static void
sul_pending_refresh_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_login_refresh *ps = lws_container_of(sul,
					struct pending_login_refresh, sul);

	/*
	 * Log against the suspended browser leg where possible, so the timeout
	 * is attributable to the peer that is waiting on it.
	 */
	lwsl_wsi_info(ps->wsi_server, "auth refresh timed out");
	/*
	 * The renewal exchange is taking too long: drop it and free ps via the
	 * common path, which first detaches and closes the still-live client
	 * leg (freeing directly here left the client wsi's user_space
	 * dangling).
	 */
	pending_login_release(ps);
}

/*
 * Kick off a silent side-channel renewal against the auth server's
 * /api/sso_exchange, forwarding the browser's full cookie jar (so the server
 * sees auth_refresh_session + auth_csrf exactly as it would for a direct call).
 *
 * Used by both:
 *  - the background BFF (.lws-login-refresh, mode=BFF), and
 *  - the cold-load bouncer path (mode=COLDLOAD), which tries renewal before
 *    bouncing the user to the login form.
 *
 * The browser wsi is suspended (we return without finalising headers); the
 * side-channel client (callback_lws_login_client) parses {"token":...} into
 * ps->token, and COMPLETED_CLIENT_HTTP wakes wsi_server, whose WRITEABLE
 * completes the response according to ps->mode.
 *
 * Returns 1 if the renewal was kicked off (caller must stop processing and
 * suspend), 0 if it could not start (no valid auth_refresh_session / auth_csrf
 * present, or the auth-server URL won't parse) -- in the 0 case the caller
 * proceeds with its existing fallback (303 to login form, or BFF 401).
 *
 * `ck_len` is lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE).  `cookie` is the
 * caller-owned copy of that header (we lws_strncpy it into ps).  `orig_path` is
 * NULL for BFF mode.  `authform_url` is the pre-built login-form URL to land on
 * if a COLDLOAD renewal fails (NULL for BFF mode).
 */
/*
 * Mint a fresh auth_csrf value (32 hex chars + NUL) into out[33].  Used at
 * renewal success to rotate the csrf cookie so its lifetime resets every
 * renewal rather than dying on the original login's fixed schedule (which is
 * what causes the background-timer redirect flash once it lapses).  Pure
 * double-submit: the server stores nothing about csrf, so re-minting here
 * needs no server-side change -- the next renewal reads the new cookie value
 * and submits it as the matching csrf_token= form field.
 */
static void
lws_login_mint_csrf(struct vhd_login *vhd, char *out)
{
	uint8_t rnd[16];
	lws_get_random(vhd->context, rnd, sizeof(rnd));
	lws_hex_from_byte_array(rnd, sizeof(rnd), out, 33);
}

/*
 * Worst-case auth_csrf Set-Cookie string: "auth_csrf=" (10) + 32 hex chars
 * + "; Path=/; Domain=" (17) + cookie_domain (<= 127, vhd cap) + "; Max-Age="
 * (10) + u64 decimal (<= 20) + "; SameSite=Lax; Secure; HttpOnly" (32).
 * 256 covers it with headroom.  Callers MUST size their buffers with this:
 * at one point the BFF rotation used a 96-byte buffer, and the 30d default
 * Max-Age (2592000) alone grows the string to 100 bytes -- the truncated
 * string embedded its NUL into the response headers (over h1 the client
 * parser rejected it; over h2 the rotated cookie never reached the browser
 * at all, so renewals never refreshed the csrf sidecar's lifetime and it
 * died on the original login's schedule).
 */
#define LWS_LOGIN_CSRF_COOKIE_SZ 256

/*
 * Format an auth_csrf Set-Cookie string into out (caller buffer,
 * LWS_LOGIN_CSRF_COOKIE_SZ bytes) using vhd's csrf_max_age_secs, and return
 * its length.  Same shape/scoping as the auth_session cookie: HttpOnly;
 * Secure; SameSite=Lax; optional Domain=.
 *
 * Returns strlen(out) rather than the lws_snprintf() would-be length, so a
 * truncated result can never cause a caller to copy the NUL terminator out
 * of the buffer and into a header.
 */
static int
lws_login_build_csrf_cookie(struct vhd_login *vhd, const char *csrf, char *out,
			    size_t out_len)
{
	if (vhd->cookie_domain[0])
		lws_snprintf(out, out_len,
			"auth_csrf=%s; Path=/; Domain=%s; Max-Age=%llu; "
			"SameSite=Lax; Secure; HttpOnly",
			csrf, vhd->cookie_domain,
			(unsigned long long)vhd->csrf_max_age_secs);
	else
		lws_snprintf(out, out_len,
			"auth_csrf=%s; Path=/; Max-Age=%llu; SameSite=Lax; Secure; HttpOnly",
			csrf, (unsigned long long)vhd->csrf_max_age_secs);

	return (int)strlen(out);
}

static int
lws_login_kick_refresh(struct vhd_login *vhd, struct lws *wsi, const char *cookie,
		       const char *csrf, int mode, const char *orig_path,
		       const char *authform_url)
{
	struct pending_login_refresh *ps;
	struct lws_client_connect_info i;
	lws_parse_uri_t *puri;

	/*
	 * The side channel binds to THIS vhost and resolves its protocol by
	 * name, so lws_login_client must be enabled on the same vhost the
	 * interceptor runs on.  If it is not, lws silently binds the wsi to
	 * the vhost's protocols[0] while still attaching ps as its user data:
	 * every client callback (including the CLIENT_CONNECTION_ERROR when
	 * the wsi is later freed) is then misrouted, ps->wsi_client dangles,
	 * and pending_login_release() writes into freed memory.  Refuse to
	 * start the exchange at all instead.
	 */
	if (!lws_vhost_name_to_protocol(vhd->vhost, "lws_login_client")) {
		lwsl_wsi_err(wsi, "%s: vhost %s does not have the "
			     "lws_login_client protocol enabled: refusing to "
			     "start the renewal side channel (enable it in "
			     "this vhost's ws-protocols)",
			     __func__, lws_get_vhost_name(vhd->vhost));
		return 0;
	}

	ps = malloc(sizeof(*ps));
	if (!ps)
		return 0;
	memset(ps, 0, sizeof(*ps));
	ps->vhd = vhd;
	ps->wsi_server = wsi;
	ps->mode = mode;
	lws_strncpy(ps->cookie_hdr, cookie, sizeof(ps->cookie_hdr));
	if (orig_path)
		lws_strncpy(ps->orig_path, orig_path, sizeof(ps->orig_path));
	if (authform_url)
		lws_strncpy(ps->authform_url, authform_url,
			    sizeof(ps->authform_url));

	ps->payload_len = lws_snprintf(ps->payload + LWS_PRE,
				       sizeof(ps->payload) - LWS_PRE,
				       "csrf_token=%s", csrf);
	ps->payload_pos = 0;

	lws_dll2_add_tail(&ps->list, &vhd->pending_refresh_list);
	lws_sul_schedule(vhd->context, 0, &ps->sul, sul_pending_refresh_cb,
			 5 * 60 * LWS_US_PER_SEC);

	puri = lws_parse_uri_create(vhd->auth_server_url);
	if (!puri) {
		pending_login_release(ps);
		return 0;
	}

	lwsl_wsi_notice(wsi, "initiating silent renewal via "
			"%s/api/sso_exchange (%s)", vhd->auth_server_url,
			mode == LWS_LOGIN_REFRESH_COLDLOAD ? "cold-load" : "bff");

	memset(&i, 0, sizeof(i));
	i.context        = vhd->context;
	/*
	 * Bind the outbound client connection to the SAME vhost the lws-login
	 * protocol is mounted on: lws resolves the named protocol
	 * (lws_login_client) only from the bound vhost's protocols[] array,
	 * and without i.vhost it falls back to _ss_default (which doesn't have
	 * lws_login_client enabled), misrouting every CLIENT_* callback.  This
	 * is the same bug class that stalled lws-oauth2-client's /api/token
	 * fetch -- the vhost must be set explicitly.
	 */
	i.vhost          = vhd->vhost;
	i.address        = puri->host;
	i.port           = puri->port;
	i.ssl_connection = !strcmp(puri->scheme, "http") ? 0 : LCCSCF_USE_SSL;
	i.path           = "/api/sso_exchange";
	i.host           = i.address;
	i.origin         = i.address;
	i.method         = "POST";
	i.protocol       = "lws_login_client";
	i.pwsi           = &ps->wsi_client;
	i.userdata       = ps;

	if (!lws_client_connect_via_info(&i)) {
		/*
		 * The side channel could not even start (lws NULLs *pwsi on
		 * synchronous failure).  Unwind ps now rather than leaving
		 * the suspended browser leg to time out against a pending
		 * exchange that will never complete.
		 */
		pending_login_release(ps);
		lws_parse_uri_destroy(&puri);

		return 0;
	}

	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);
	lws_parse_uri_destroy(&puri);

	return 1;
}

/*
 * Kick a side-channel renewal when the browser's jar has the
 * auth_refresh_session cookie but not its auth_csrf sidecar.  That state is
 * reachable without anything being wrong server-side: the two cookies are
 * minted by different flows (the delegate /oauth/callback pairs them, but a
 * native login on the auth server's own host plants an unpaired Domain-scoped
 * refresh cookie, and browser-side eviction or a device sleeping past the
 * csrf cookie's expiry can age the sidecar out first).  Treating it as a hard
 * denial made the login widget classify a live session as dead and navigate
 * the whole page to the auth form.
 *
 * The auth server's csrf check on /api/sso_exchange is a double-submit
 * comparison between the csrf_token= form field and the auth_csrf cookie in
 * the forwarded jar -- both of which this side channel itself produces.  So
 * when the jar lacks auth_csrf, mint a fresh value and inject the matching
 * pair into the exchange: a browser without access to the HttpOnly cookies
 * cannot reach this code, and a cross-site form POST cannot carry the
 * SameSite=Lax auth_refresh_session, so the browser-side csrf cookie was not
 * adding protection the refresh cookie does not already provide.  If the
 * refresh session is genuinely invalid the auth server still 401s the
 * exchange and the caller sees exactly the outcome it saw before.
 *
 * On exchange success the BFF / cold-load completion paths rotate a fresh
 * auth_csrf cookie into the browser jar themselves, healing the underlying
 * state.
 *
 * The minted cookie is prepended to the forwarded jar so that even if a very
 * large jar has to be truncated into ps->cookie_hdr, the pair we are about to
 * double-submit survives intact.
 */
static int
lws_login_kick_refresh_selfheal(struct vhd_login *vhd, struct lws *wsi,
				const char *cookie, int mode,
				const char *orig_path, const char *authform_url)
{
	char minted[33];
	size_t alen = strlen(cookie) + sizeof(minted) + 16;
	char *jar;
	int kicked;

	jar = malloc(alen);
	if (!jar)
		return 0;

	lws_login_mint_csrf(vhd, minted);
	lws_snprintf(jar, alen, "auth_csrf=%s; %s", minted, cookie);

	kicked = lws_login_kick_refresh(vhd, wsi, jar, minted, mode,
					orig_path, authform_url);
	free(jar);

	return kicked;
}

/*
 * Serve the protected page to the browser by re-issuing the JWT cookie and
 * 302-ing back to the same URL the browser originally asked for.  Used by:
 *  - the grant-mismatch "silent update" path (logged in, but grants changed),
 *    and
 *  - the cold-load renewal success path (was logged-out, just re-minted the
 *    JWT server-side).
 *
 * In both cases the effect from the browser's POV is identical: the request
 * completes as if it had been authenticated all along -- no navigation away,
 * no flash of any other page.  `path` is the request's GET/POST URI.
 *
 * On any header-build failure returns non-zero so the caller can surface an
 * error; on success the response is fully written and the transaction is
 * completed, returning 0.
 */
static int
lws_login_serve_self_redirect_with_cookie(struct lws *wsi, struct pss_login *pss,
					  struct vhd_login *vhd,
					  const char *token, const char *path,
					  unsigned char *buf, unsigned char **pp,
					  unsigned char *end,
					  const char *extra_set_cookie)
{
	/* path can be a full path + query (LWS_LOGIN_MAX_URI); add room for
	 * scheme://host so composing the absolute Location cannot truncate */
	char cookie[LWS_SSO_MAX_COOKIE], host[128],
	      fq_uri[LWS_LOGIN_MAX_URI + 192];
	unsigned char *p = *pp;
	const char *h = NULL;

	if (vhd->cookie_domain[0])
		lws_snprintf(cookie, sizeof(cookie),
			 "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
			 vhd->cookie_name, token, vhd->cookie_domain,
			 (unsigned long long)vhd->jwt_validity_secs);
	else
		lws_snprintf(cookie, sizeof(cookie),
			 "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
			 vhd->cookie_name, token,
			 (unsigned long long)vhd->jwt_validity_secs);

	host[0] = '\0';
	if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0)
		h = host;
#if defined(LWS_ROLE_H2)
	else if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
		h = host;
#endif
	if (!h) {
		struct lws_vhost *vh = lws_get_vhost(wsi);
		if (vh) {
			const char *vname = lws_get_vhost_name(vh);
			if (vname)
				h = vname;
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
		if (lws_is_ssl(lws_get_network_wsi(wsi))) {
			scheme = "https";
		}

		lws_snprintf(fq_uri, sizeof(fq_uri), "%s://%s%s", scheme,
			     h ? h : "localhost", path);
	}

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0,
					&p, end))
		return 1;
	if (lws_add_http_header_by_name(wsi, (const uint8_t *)"set-cookie:",
					(const uint8_t *)cookie,
					(int)strlen(cookie), &p, end))
		return 1;
	if (extra_set_cookie &&
	    lws_add_http_header_by_name(wsi, (const uint8_t *)"set-cookie:",
					(const uint8_t *)extra_set_cookie,
					(int)strlen(extra_set_cookie), &p, end))
		return 1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
					 (const uint8_t *)fq_uri,
					 (int)strlen(fq_uri), &p, end))
		return 1;
	if (lws_finalize_http_header(wsi, &p, end))
		return 1;

	lws_write(wsi, (unsigned char *)buf + LWS_PRE,
		  (size_t)lws_ptr_diff(p, buf + LWS_PRE),
		  LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

	*pp = p;
	(void)pss;
	return 0;
}

static const char * const param_names[] = {
	"token",
	"target",
};

enum enum_param_names {
	EPN_TOKEN,
	EPN_TARGET,
};

static int
lws_login_ends_with(const char *str, const char *suffix)
{
	size_t len_str = strlen(str);
	size_t len_suffix = strlen(suffix);

	if (len_suffix > len_str)
		return 0;

	return !strcmp(str + len_str - len_suffix, suffix);
}

/*
 * Reconstruct the full request URI (path + query string) into dest.
 *
 * lws seals WSI_TOKEN_GET_URI at the '?': the args live on in the
 * WSI_TOKEN_HTTP_URI_ARGS fragment chain, one "name=value" fragment per
 * query parameter.  Walking the fragments (like the CGI env code) recovers
 * the URL the browser asked for, so re-login redirects can round-trip deep
 * links like "/sai/?project=X&branch=Y&task=<uuid>" instead of landing on
 * the bare path.
 *
 * The fragments have already been percent-decoded by the URI parser, so
 * each is re-encoded on the way out: joining the decoded forms directly
 * would let a value that contained an encoded '&' or '=' (say
 * task=a%26b) re-emerge as a query STRUCTURE change (task=a&b).  If the
 * joined URI would not fit, the query is dropped rather than silently
 * truncated mid-parameter.
 */
static void
lws_login_copy_uri_with_args(struct lws *wsi, const char *path, char *dest,
			     size_t len)
{
	char arg[256], enc[768];
	size_t ol;
	int m = 0;

	lws_strncpy(dest, path, len);
	ol = strlen(dest);

	while (ol < len - 1) {
		int al = lws_hdr_copy_fragment(wsi, arg, (int)sizeof(arg),
					       WSI_TOKEN_HTTP_URI_ARGS, m);
		int n;

		if (al <= 0)
			break;

		lws_urlencode(enc, arg, (int)sizeof(enc));
		n = lws_snprintf(dest + ol, len - ol, "%s%s",
				 m ? "&" : "?", enc);
		if (n < 0 || ol + (size_t)n >= len) {
			lwsl_wsi_notice(wsi, "%s: uri + query too long, "
					 "dropping query", __func__);
			dest[ol] = '\0';
			break;
		}
		ol += (size_t)n;
		m++;
	}
}

static int
callback_lws_login_client(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct pending_login_refresh *ps = (struct pending_login_refresh *)lws_wsi_user(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in;
		unsigned char *end = (*p) + len;
		char clen[16];

		if (!ps)
			break;

		lws_snprintf(clen, sizeof(clen), "%d", ps->payload_len);

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)"application/x-www-form-urlencoded",
						 33, p, end))
			return -1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH,
						 (unsigned char *)clen, (int)strlen(clen), p, end))
			return -1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
						 (unsigned char *)ps->cookie_hdr,
						 (int)strlen(ps->cookie_hdr), p, end))
			return -1;

		/*
		 * Arm the POST body write -- same canonical pattern as
		 * minimal-http-client-post and lws-oauth2-client: set body-pending
		 * and request WRITEABLE after appending the headers.  On h2 this
		 * is required (no h1-style auto-arm fallback).
		 */
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);

		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE: {
		size_t chunk;
		int n;

		if (!ps || ps->payload_pos >= ps->payload_len)
			break;

		chunk = (size_t)(ps->payload_len - ps->payload_pos);

		/*
		 * Final body chunk: pair lws_client_http_body_pending(,0) with
		 * LWS_WRITE_HTTP_FINAL so h2 puts END_STREAM on the last DATA
		 * frame and the server knows the request body is complete.
		 */
		lws_client_http_body_pending(wsi, 0);
		n = lws_write(wsi,
			      (unsigned char *)ps->payload + LWS_PRE +
			      ps->payload_pos,
			      chunk, LWS_WRITE_HTTP_FINAL);
		if (n < 0)
			return -1;
		ps->payload_pos += n;

		if (ps->payload_pos < ps->payload_len)
			lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buffer[4096];
		char *px = buffer + LWS_PRE;
		int plen = (int)sizeof(buffer) - LWS_PRE;

		if (!ps)
			break;

		/*
		 * For h1, response body delivery requires the callback to
		 * drain it itself (h2 delivers RECEIVE_CLIENT_HTTP_READ
		 * directly from its mux polling) -- the canonical pattern
		 * from minimal-http-client(-post) and lws-oauth2-client.
		 * Without this, over h1 the /api/sso_exchange response was
		 * never read: the suspended browser leg hung until its
		 * timeout.
		 */
		if (lws_http_client_read(wsi, &px, &plen) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!ps)
			break;
		/*
		 * Capture the auth server's actual verdict so the browser-leg
		 * completion can log WHY the renewal was denied (401 Invalid
		 * session vs 403 CSRF vs 5xx) instead of an anonymous "denied".
		 */
		ps->resp_status = lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		struct lws_tokenize ts;
		lws_tokenize_elem e;
		int state = 0, estate = 0;

		if (!ps || !in || !len)
			break;

		lws_tokenize_init(&ts, (char *)in, LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_MINUS_NONTERM);
		ts.len = len;

		while ((e = lws_tokenize(&ts)) != LWS_TOKZE_ENDED) {
			if (state == 0 && e == LWS_TOKZE_QUOTED_STRING &&
			    ts.token_len == 5 && !strncmp(ts.token, "token", 5)) {
				state = 1;
			} else if (state == 1 && e == LWS_TOKZE_DELIMITER && ts.token[0] == ':') {
				state = 2;
			} else if (state == 2 && e == LWS_TOKZE_QUOTED_STRING) {
				if (ts.token_len < sizeof(ps->token)) {
					lws_strncpy(ps->token, ts.token, ts.token_len + 1);
					lwsl_wsi_notice(wsi, "Extracted OAuth token natively via BFF");
				}
				break;
			} else if (estate == 0 && e == LWS_TOKZE_QUOTED_STRING &&
				   ts.token_len == 5 &&
				   !strncmp(ts.token, "error", 5)) {
				estate = 1;
			} else if (estate == 1 && e == LWS_TOKZE_DELIMITER &&
				   ts.token[0] == ':') {
				estate = 2;
			} else if (estate == 2 && e == LWS_TOKZE_QUOTED_STRING) {
				/* denial reason, eg {"error":"Invalid session"}:
				 * capture once for the browser-leg log */
				size_t c = (size_t)ts.token_len;

				if (c >= sizeof(ps->resp_error))
					c = sizeof(ps->resp_error) - 1;
				if (!ps->resp_error[0]) {
					memcpy(ps->resp_error, ts.token, c);
					ps->resp_error[c] = '\0';
				}
				estate = 3;
			}
		}
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: {
		if (!ps)
			break;

		if (ps->wsi_server)
			lws_callback_on_writable(ps->wsi_server);
		/* detach us from the wsi: CLOSED can still fire after this */
		lws_set_wsi_user(wsi, NULL);
		ps->wsi_client = NULL;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!ps)
			break;
		/*
		 * in carries the human-readable connection failure: keep it
		 * for the browser-leg denial log, since "denied" with no
		 * response at all is usually this (unreachable auth server,
		 * TLS problem, IP ban on the auth server side...).
		 */
		lws_snprintf(ps->conn_error, sizeof(ps->conn_error), "%s",
			     in ? (const char *)in : "unknown");
		lwsl_wsi_notice(wsi, "renewal side channel failed: %s",
				ps->conn_error);
		if (ps->wsi_server && !ps->token[0]) {
			lws_callback_on_writable(ps->wsi_server);
		}
		lws_set_wsi_user(wsi, NULL);
		ps->wsi_client = NULL;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP: {
		if (!ps)
			break;
		lwsl_wsi_info(wsi, "renewal side channel closed");
		if (ps->wsi_server && !ps->token[0]) {
			lws_callback_on_writable(ps->wsi_server);
		}
		lws_set_wsi_user(wsi, NULL);
		ps->wsi_client = NULL;
		break;
	}

	default:
		break;
	}

	return 0;
}

static int
lws_login_jwt_auth_cb(struct lws_jwt_auth *ja, int state, void *user)
{
	if (state == LWS_JWT_AUTH_STATE_EXPIRED)
		lwsl_notice("%s: Session expired naturally\n", __func__);

	return 0;
}

static int
auth_verify_redirect_uri(struct vhd_login *vhd, const char *redirect_uri)
{
	sqlite3_stmt *stmt;
	int valid = 0;

	if (!redirect_uri || !redirect_uri[0])
		return 0;

	if ((char *)strstr(redirect_uri, "../") ||
	    (char *)strstr(redirect_uri, "..%2F") ||
	    (char *)strstr(redirect_uri, "..%2f"))
		return 0;

	if (sqlite3_prepare_v2(vhd->db, "SELECT redirect_uris FROM oauth_clients", -1, &stmt, NULL) == SQLITE_OK) {
		while (!valid && sqlite3_step(stmt) == SQLITE_ROW) {
			const char *uris = (const char *)sqlite3_column_text(stmt, 0);
			if (uris) {
				const char *p = uris;
				while (p && *p) {
					while (*p == ' ' || *p == '\r' || *p == '\n') p++;
					const char *comma = strchr(p, ',');
					size_t len = comma ? lws_ptr_diff_size_t(comma, p) : strlen(p);
					while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\r' || p[len - 1] == '\n')) len--;
					while (len > 0 && p[len - 1] == '/') len--;
					if (len > 0) {
						if (!strncasecmp(redirect_uri, p, len)) {
							char next = redirect_uri[len];
							if (next == '\0' || next == '/' || next == '?' || next == '#') {
								valid = 1;
								break;
							}
						}
					}
					p = comma ? comma + 1 : NULL;
				}
			}
		}
		sqlite3_finalize(stmt);
	}
	return valid;
}

static int
simple_response(struct lws *wsi, struct pss_login *pss, const char *msg, const char *mime_type,
	     unsigned int code, unsigned char *start, unsigned char **p, unsigned char *end)
{
        char eb[LWS_PRE + 1024];
	int l = lws_snprintf(eb + LWS_PRE, sizeof(eb) - LWS_PRE, "%s", msg);

	if (lws_add_http_common_headers(wsi, code, mime_type, (lws_filepos_t)l, p, end))
		return -1;

	if (lws_add_http_header_by_name(wsi, (unsigned char *)"cache-control:", (unsigned char *)"no-cache, no-store, must-revalidate", 35, p, end))
		return -1;

        if (lws_finalize_write_http_header(wsi, start, p, end))
                return -1;

	if (lws_buflist_append_segment(&pss->tx_buflist, (unsigned char*)eb + LWS_PRE, (size_t)l) < 0)
		return -1;
	pss->tx_remaining = (size_t)l;

	lws_callback_on_writable(wsi);

	return 0;
}

/*
 * A "global admin" is solely the holder of the "*" wildcard grant -- the
 * established "god" grant, the TOFU bootstrap account that can manage every
 * user and account on the system.  This is the ONLY grant that unlocks the
 * central auth-server Admin Console (/api/admin, which itself gates on the
 * literal "*") and is the ONLY thing that should drive the "Admin Console"
 * link in the status widget and x-lws-login-admin:1 for backends.
 *
 * A named, app-scoped grant at level >= 2 (eg lws-sai:2) makes the user an
 * admin of *that one app*; it must NOT be reported as a global admin here,
 * or the user gets shown an Admin Console link they cannot actually open.
 * The app-local admin level is carried separately by x-lws-login-grant-level
 * / "grant_level", so backends and the widget can apply their own threshold
 * (eg the avatar badge at grant_level >= 2).
 */
static int
lws_login_is_global_admin(struct lws_jwt_auth *ja)
{
	return lws_jwt_auth_query_grant(ja, "*") >= 1;
}

/*
 * Reduce the verified grants for this request to a single \ref
 * lws_login_state, the role injected as x-lws-login-state for the backend.
 *
 * The "*" wildcard is checked FIRST, so a global admin (god) is always
 * LWS_LOGIN_STATE_GLOBAL_ADMIN regardless of any named grant on the token
 * (any "*" level >= 1 qualifies, per lws_login_is_global_admin).  Below that,
 * the named grant level for this mount decides USER vs APP_ADMIN, and a valid
 * JWT with no usable grant here is NO_GRANT.  |level| may be -1 when no
 * service grant (and no "*") was found.  A NULL ja (no/invalid JWT, only
 * reachable on an unauth-allow mount) yields ANON.
 */
static enum lws_login_state
lws_login_state_from_grants(struct lws_jwt_auth *ja, int level)
{
	if (lws_login_is_global_admin(ja))
		return LWS_LOGIN_STATE_GLOBAL_ADMIN;
	if (level >= 2)
		return LWS_LOGIN_STATE_APP_ADMIN;
	if (level >= 1)
		return LWS_LOGIN_STATE_USER;
	if (ja)
		return LWS_LOGIN_STATE_NO_GRANT;
	return LWS_LOGIN_STATE_ANON;
}

/*
 * Stamp the cooked login state onto the browser-side wsi as "extra onward
 * headers" so the proxy (HTTP or WS) forwards them to the backend app.  The
 * app then reads x-lws-login-state (the authoritative summary role) with no
 * JWT/grant logic of its own.
 *
 *   x-lws-login-state:        stringified lws_login_state (authoritative)
 *   x-lws-login-admin:        1 iff state == GLOBAL_ADMIN (back-compat)
 *   x-lws-login-grant-level:  raw integer grant level used for this mount
 *   x-lws-login-sub:          subject identity ("" if anonymous)
 *
 * x-lws-login-admin is derived from |state| so it stays consistent with
 * x-lws-login-state by construction; a backend that wants "admin of my own
 * app" should instead check `state >= LWS_LOGIN_STATE_APP_ADMIN` or read
 * x-lws-login-grant-level.
 *
 * Mirrors lib/roles/http/server/interceptor.c lws_interceptor_inject_header:
 * anti-spoof any client-supplied copy first (lws_http_zap_header), then append
 * "Name: value\r\n" lines to wsi->http.extra_onward_headers.  The backend
 * trusts these because only the interceptor (which holds the JWK) can set
 * them -- a browser cannot elevate itself, its x-lws-login-* is zapped here.
 *
 * sub/level may be NULL/-1 for the anonymous (unauth-allow) case; we still
 * inject the headers (with x-lws-login-state:0 / x-lws-login-admin:0) so the
 * backend sees an explicit "anonymous" rather than ambiguous absence.
 */
static void
lws_login_inject_state(struct lws *wsi, const char *sub, int level,
		       enum lws_login_state state)
{
	char buf[32];

	/* anti-spoof any client-supplied copy first, then stamp trusted value */
	lws_http_zap_header(wsi, LWS_LOGIN_HDR_STATE);
	lws_http_zap_header(wsi, LWS_LOGIN_HDR_ADMIN);
	lws_http_zap_header(wsi, LWS_LOGIN_HDR_GRANT_LEVEL);
	lws_http_zap_header(wsi, LWS_LOGIN_HDR_SUB);

	lws_snprintf(buf, sizeof(buf), "%d", (int)state);
	lws_http_add_onward_header(wsi, LWS_LOGIN_HDR_STATE, buf);

	lws_http_add_onward_header(wsi, LWS_LOGIN_HDR_ADMIN,
				   state == LWS_LOGIN_STATE_GLOBAL_ADMIN
					   ? "1" : "0");

	lws_snprintf(buf, sizeof(buf), "%d", level);
	lws_http_add_onward_header(wsi, LWS_LOGIN_HDR_GRANT_LEVEL, buf);

	lws_http_add_onward_header(wsi, LWS_LOGIN_HDR_SUB, sub ? sub : "");
}

static int
callback_lws_login(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct vhd_login *vhd = (struct vhd_login *)lws_protocol_vh_priv_get(
			lws_get_vhost(wsi), reason == LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK ? (const struct lws_protocols *)in : lws_get_protocol(wsi));
	struct pss_login *pss = (struct pss_login *)user;
	char buf[LWS_PRE + LWS_SSO_MAX_COOKIE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
	const char *cp;

	switch ((int)reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		if (!in)
			return 0;
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct vhd_login));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		vhd->cookie_name = "auth_session";
		vhd->service_name = "default-service";
		vhd->min_grant_level = 1;
		lws_strncpy(vhd->auth_domain, "auth.warmcat.com", sizeof(vhd->auth_domain));
		lws_strncpy(vhd->db_path, "/var/db/lws-auth.sqlite3", sizeof(vhd->db_path));
		vhd->jwt_validity_secs = 86400;
		vhd->csrf_max_age_secs = 30 * 24 * 3600; /* 30d: csrf must outlive JWT */

		if (lws_pvo_get_str(in, "cookie-name", &vhd->cookie_name))
			lwsl_info("%s: default cookie-name %s\n", __func__, vhd->cookie_name);

		{
			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			while (pvo) {
				if (!strcmp(pvo->name, "whitelist")) {
					struct login_whitelist *w = malloc(sizeof(*w));
					if (!w) {
						lwsl_err("%s: OOM\n", __func__);
						return -1;
					}
					memset(w, 0, sizeof(*w));
					if (lws_parse_cidr(pvo->value, &w->sa46, &w->net_len) < 0) {
						lwsl_err("%s: invalid whitelist CIDR %s\n", __func__, pvo->value);
						free(w);
						return -1;
					}
					lws_dll2_add_tail(&w->list, &vhd->wl);
				}
				pvo = pvo->next;
			}
		}

		if (lws_pvo_get_str(in, "service-name", &vhd->service_name))
			lwsl_info("%s: default service-name %s\n", __func__, vhd->service_name);

		if (lws_pvo_get_str(in, "auth-server-url", &vhd->auth_server_url)) {
			lwsl_err("%s: auth-server-url PVO is REQUIRED\n", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "min-grant-level", &cp))
			vhd->min_grant_level = atoi(cp);

		if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
			if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
				if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
					lwsl_err("%s: failed to load/import JWK\n", __func__);
					return -1;
				}
			}
		} else {
			lwsl_err("%s: jwt-jwk PVO required\n", __func__);
			return -1;
		}

		vhd->cookie_domain[0] = '\0';
		if (!lws_pvo_get_str(in, "cookie-domain", &cp))
			lws_strncpy(vhd->cookie_domain, cp, sizeof(vhd->cookie_domain));

		if (!lws_pvo_get_str(in, "auth-domain", &cp))
			lws_strncpy(vhd->auth_domain, cp, sizeof(vhd->auth_domain));

		if (!lws_pvo_get_str(in, "jwt-validity-secs", &cp))
			vhd->jwt_validity_secs = (uint64_t)atoll(cp);

		if (!lws_pvo_get_str(in, "csrf-max-age-secs", &cp))
			vhd->csrf_max_age_secs = (uint64_t)atoll(cp);

		vhd->unauth_allow = 0;
		if (!lws_pvo_get_str(in, "unauth-allow", &cp))
			vhd->unauth_allow = atoi(cp);

		if (!lws_pvo_get_str(in, "unauth-protocols", &vhd->unauth_protocols))
			lwsl_notice("%s: unauth-protocols: %s\n", __func__, vhd->unauth_protocols);

		if (!lws_pvo_get_str(in, "db-path", &cp))
			lws_strncpy(vhd->db_path, cp, sizeof(vhd->db_path));

		if (lws_struct_sq3_open(vhd->context, vhd->db_path, 1, &vhd->db)) {
			lwsl_err("%s: could not open local database at %s. Dynamic grant revocation disabled.\n", __func__, vhd->db_path);
			vhd->db = NULL;
		}


		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->wl.head) {
				struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
				lws_dll2_remove(d);
				free(w);
			} lws_end_foreach_dll_safe(d, d1);
			lws_jwk_destroy(&vhd->jwk);
			if (vhd->db)
				sqlite3_close(vhd->db);
		}
		break;

	case LWS_CALLBACK_USER + 1:
	{
		int level = -1;
		struct lws_jwt_auth *ja;
		const char *service_name;
		const struct lws_http_mount *mount;
		char uri[256];

		vhd = (struct vhd_login *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi),
				lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-login"));

		if (!vhd)
			return 1;

		service_name = vhd->service_name;
		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0 ||
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) > 0) {
			if (uri[0]) {
				mount = lws_find_mount(wsi, uri, (int)strlen(uri));
				if (mount) {
					if (!lws_pmo_get_str(mount, "service-name", &service_name)) {
						lwsl_info("%s: using service_name %s from target pmo for bypass api\n", __func__, service_name);
					}
#if defined(LWS_WITH_JOSE)
					else if (mount->interceptor_path) {
						const struct lws_http_mount *im = mount;
						while (im && im->interceptor_path) {
							im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
							if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
								lwsl_info("%s: using service_name %s from interceptor pmo for bypass api\n", __func__, service_name);
								break;
							}
						}
					}
#endif
				}
			}
		}

		if (!service_name)
			service_name = "";

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi, NULL);
		if (ja) {
			int epoch_ok = 1;
			if (vhd->db) {
				uint32_t uid = lws_jwt_auth_get_uid(ja);
				if (uid) {
					sqlite3_stmt *stmt;
					if (sqlite3_prepare_v2(vhd->db, "SELECT session_epoch FROM users WHERE uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
						sqlite3_bind_int(stmt, 1, (int)uid);
						if (sqlite3_step(stmt) == SQLITE_ROW) {
							uint32_t db_epoch = (uint32_t)sqlite3_column_int(stmt, 0);
							if (db_epoch != lws_jwt_auth_get_sec(ja))
								epoch_ok = 0;
						}
						sqlite3_finalize(stmt);
					}
				}
			}
			level = lws_jwt_auth_query_grant(ja, service_name);
			lws_jwt_auth_destroy(&ja);
			if (epoch_ok && level >= vhd->min_grant_level)
				return 0; /* Authentic and authorized */
		}
		return 1; /* Unauthenticated */
	}

	case LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK:
	{
		int level = -1;
		struct lws_jwt_auth *ja;
		char uri[256];
		const char *service_name;
		const struct lws_http_mount *mount;

		uri[0] = '\0';
		if (lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI) > 0 ||
		    lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI) > 0) {
			if (lws_login_ends_with(uri, "/.lws-login-status") ||
			    lws_login_ends_with(uri, "/lws-login.js") ||
			    lws_login_ends_with(uri, "/lws-login.css") ||
			    lws_login_ends_with(uri, "/.lws-login-sso") ||
			    lws_login_ends_with(uri, "/.lws-login-logout") ||
			    lws_login_ends_with(uri, "/.lws-login-refresh"))
				return 1;
		}

		if (!vhd) {
			lwsl_err("%s: DENYING (vhd is NULL !!! protocol init failed or unconfigured)\n", __func__);
			return 1;
		}

		if (vhd->unauth_protocols) {
			char ws_prot[256];
			if (lws_hdr_copy(wsi, ws_prot, sizeof(ws_prot), WSI_TOKEN_PROTOCOL) > 0) {
				/* simplistic match, sufficient for our usecase but could be tokenized */
				if ((char *)strstr(vhd->unauth_protocols, ws_prot)) {
					lwsl_notice("%s: bypassing interceptor for unauth protocol '%s'\n", __func__, ws_prot);
					return 0;
				}
			}
		}

		service_name = vhd->service_name;
		int unauth_allow = vhd->unauth_allow;
		if (uri[0]) {
			mount = lws_find_mount(wsi, uri, (int)strlen(uri));
			if (mount) {
				const char *pmo_val;
				int target_sn = !lws_pmo_get_str(mount, "service-name", &service_name);
				int target_ua = !lws_pmo_get_str(mount, "unauth-allow", &pmo_val);

				if (target_sn)
					lwsl_info("%s: using service_name %s from target pmo\n", __func__, service_name);
				if (target_ua) {
					unauth_allow = atoi(pmo_val);
					lwsl_info("%s: using unauth_allow %d from target pmo\n", __func__, unauth_allow);
				}

#if defined(LWS_WITH_JOSE)
				if (!target_sn && mount->interceptor_path) {
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
							lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
							break;
						}
					}
				}
				if (!target_ua && mount->interceptor_path) {
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "unauth-allow", &pmo_val)) {
							unauth_allow = atoi(pmo_val);
							lwsl_info("%s: using unauth_allow %d from interceptor pmo\n", __func__, unauth_allow);
							break;
						}
					}
				}
#endif
			}
		}

		if (vhd->wl.count) {
			char ip[64];
			lws_sockaddr46 sa46;
			int match = 0;

			lws_get_peer_simple(wsi, ip, sizeof(ip));
			if (!lws_sa46_parse_numeric_address(ip, &sa46)) {
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->wl.head) {
					struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
					if (!lws_sa46_on_net(&sa46, &w->sa46, w->net_len)) {
						match = 1;
						break;
					}
				} lws_end_foreach_dll(d);
			}

			if (!match) {
				lwsl_info("%s: peer %s failed whitelist\n", __func__, ip);
				return 1; /* Request intercept to serve 403 */
			}
		}

		ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi, NULL);
		if (ja) {
			const char *did = lws_jwt_auth_get_did(ja);
			if (did && vhd->db) {
				sqlite3_stmt *stmt;
				int found_device = 0;
				if (sqlite3_prepare_v2(vhd->db, "SELECT 1 FROM devices WHERE device_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
					sqlite3_bind_text(stmt, 1, did, -1, SQLITE_STATIC);
					if (sqlite3_step(stmt) == SQLITE_ROW)
						found_device = 1;
					sqlite3_finalize(stmt);
				}
				if (!found_device) {
					lwsl_notice("%s: Device %s rejected (not found in DB %s), rejecting JWT\n", __func__, did, vhd->db_path);
					lws_jwt_auth_destroy(&ja);
					return 1; /* Request to intercept */
				}
			}

			lwsl_info("%s: Valid cookie found! User authenticated.\n", __func__);
			level = lws_jwt_auth_query_grant(ja, service_name);
			if (level >= vhd->min_grant_level) {
				if (vhd->db) {
					uint32_t uid = lws_jwt_auth_get_uid(ja);
					if (uid) {
						sqlite3_stmt *stmt;
						int mismatch = 0;
						int count_db = 0;

						if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt, 1, (int)uid);
							while (sqlite3_step(stmt) == SQLITE_ROW) {
								const char *svc_name = (const char *)sqlite3_column_text(stmt, 0);
								int gl = sqlite3_column_int(stmt, 1);
								if (!svc_name) continue;

								count_db++;
								int old_gl = lws_jwt_auth_query_grant(ja, svc_name);
								if (old_gl != gl)
									mismatch = 1;
							}
							sqlite3_finalize(stmt);
						}

						if (sqlite3_prepare_v2(vhd->db, "SELECT session_epoch FROM users WHERE uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt, 1, (int)uid);
							if (sqlite3_step(stmt) == SQLITE_ROW) {
								uint32_t db_epoch = (uint32_t)sqlite3_column_int(stmt, 0);
								if (db_epoch != lws_jwt_auth_get_sec(ja)) {
									lwsl_info("%s: session epoch mismatch! DB=%u JWT=%u\n", __func__, db_epoch, lws_jwt_auth_get_sec(ja));
									mismatch = 1;
								}
							}
							sqlite3_finalize(stmt);
						}

						if (count_db != (int)lws_jwt_auth_count_grants(ja))
							mismatch = 1;

						if (mismatch) {
							lws_jwt_auth_destroy(&ja);
							lwsl_info("%s: Need dynamic JWT rewrite\n", __func__);
							return 1; /* Request to intercept */
					}
				}
			}

			{
				/* capture login state before destroying ja, and
				 * stamp it for the proxy to forward to backend.
				 * The single lws_login_state encodes the role
				 * (anon/user/app-admin/global-admin); the bouncer
				 * no longer leaks a separate is_admin boolean.
				 *
				 * lws_jwt_auth_get_sub() points into the ja
				 * allocation itself, so it must be copied out
				 * before ja is destroyed: the value is consumed
				 * synchronously here, a stack copy is enough.
				 * Sized to match ja's internal sub[]. */
				char sub[128];
				const char *s;
				enum lws_login_state state =
					lws_login_state_from_grants(ja, level);

				s = lws_jwt_auth_get_sub(ja);
				sub[0] = '\0';
				if (s)
					lws_strncpy(sub, s, sizeof(sub));

				lws_jwt_auth_destroy(&ja);

				lws_login_inject_state(wsi, sub, level, state);
			}
			lwsl_info("%s: ALLOWING (User has required grant)\n", __func__);
			return 0; /* Let traffic through to the real mount */
		}
		lwsl_info("%s: JWT valid but lacks required %s grant (has %d), INTERCEPTING\n", __func__, service_name, level);
		lws_jwt_auth_destroy(&ja);
	}

	lwsl_info("%s: INTERCEPTING (NO VALID COOKIE FOUND)\n", __func__);

	if (unauth_allow) {
		/* anonymous: explicit ANON state for the backend */
		lws_login_inject_state(wsi, NULL, -1, LWS_LOGIN_STATE_ANON);
		lwsl_info("%s: ALLOWING UNAUTH (unauth-allow enabled)\n", __func__);
		return 0;
	}

	return 1; /* Unauthorized, intercept */
}

	case LWS_CALLBACK_HTTP:
	{
		char dest[512], path[256], urlenc_path[512];
		const struct lws_http_mount *mount;
		int whitelist_failed = 0;
		const char *service_name;
		const char *pmo_val;
		int unauth_allow = vhd->unauth_allow;
		int n;

		if (!vhd)
			return 1;

		service_name = vhd->service_name;

		path[0] = '\0';
		n = lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI);
		if (n <= 0)
			n = lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI);

		if (n > 0) {
			mount = lws_find_mount(wsi, path, n);
			if (mount) {
				int target_sn = !lws_pmo_get_str(mount, "service-name", &service_name);
				int target_ua = !lws_pmo_get_str(mount, "unauth-allow", &pmo_val);

				if (target_sn)
					lwsl_info("%s: using service_name %s from target pmo\n", __func__, service_name);
				if (target_ua) {
					unauth_allow = atoi(pmo_val);
					lwsl_info("%s: using unauth_allow %d from target pmo\n", __func__, unauth_allow);
				}

#if defined(LWS_WITH_JOSE)
				if (!target_sn && mount->interceptor_path) {
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "service-name", &service_name)) {
							lwsl_info("%s: using service_name %s from interceptor pmo\n", __func__, service_name);
							break;
						}
					}
				}
				if (!target_ua && mount->interceptor_path) {
					const struct lws_http_mount *im = mount;
					while (im && im->interceptor_path) {
						im = lws_find_mount(wsi, im->interceptor_path, (int)strlen(im->interceptor_path));
						if (im && !lws_pmo_get_str(im, "unauth-allow", &pmo_val)) {
							unauth_allow = atoi(pmo_val);
							lwsl_info("%s: using unauth_allow %d from interceptor pmo\n", __func__, unauth_allow);
							break;
						}
					}
				}
#endif
			}
		}

		if (vhd->wl.count) {
			char ip[64];
			lws_sockaddr46 sa46;
			int match = 0;

			lws_get_peer_simple(wsi, ip, sizeof(ip));
			if (!lws_sa46_parse_numeric_address(ip, &sa46)) {
				lws_start_foreach_dll(struct lws_dll2 *, d, vhd->wl.head) {
					struct login_whitelist *w = lws_container_of(d, struct login_whitelist, list);
					if (!lws_sa46_on_net(&sa46, &w->sa46, w->net_len)) {
						match = 1;
						break;
					}
				} lws_end_foreach_dll(d);
			}

			if (!match)
				whitelist_failed = 1;
		}

		if (whitelist_failed)
                  return simple_response(
                      wsi, pss, "Page Unreachable", "text/plain", 403,
                      (unsigned char *)buf + LWS_PRE, (unsigned char **)&p,
                      (unsigned char *)end);

                if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) > 0 &&
		    lws_login_ends_with(path, "/.lws-login-sso"))
			return 0; /* Fall through to LWS_CALLBACK_HTTP_BODY */

		if (!pss->ja)
			pss->ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, lws_login_jwt_auth_cb, wsi, NULL);

		if (pss->ja) {
			uint64_t exp = lws_jwt_auth_get_exp(pss->ja);
			if (exp && exp < (uint64_t)lws_now_secs()) {
				lwsl_info("%s: JWT expired (exp %llu, now %llu)\n", __func__, (unsigned long long)exp, (unsigned long long)lws_now_secs());
				lws_jwt_auth_destroy(&pss->ja);
			}
		}

		if (pss->ja) {
			int level = lws_jwt_auth_query_grant(pss->ja, service_name);
			if (level >= vhd->min_grant_level) {
				if (vhd->db && !pss->silent_update_jwt) {
					uint32_t uid = lws_jwt_auth_get_uid(pss->ja);
					if (uid) {
						char current_grants[512];
						char *g_p = current_grants;
						char *g_end = current_grants + sizeof(current_grants);
						sqlite3_stmt *stmt;
						int first = 1;
						int mismatch = 0;
						int count_db = 0;

						g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "\"grants\":{");

						if (sqlite3_prepare_v2(vhd->db, "SELECT s.name, g.grant_level FROM grants g JOIN services s ON g.service_id = s.service_id WHERE g.uid = ?", -1, &stmt, NULL) == SQLITE_OK) {
							sqlite3_bind_int(stmt, 1, (int)uid);
							while (sqlite3_step(stmt) == SQLITE_ROW) {
								const char *svc_name = (const char *)sqlite3_column_text(stmt, 0);
								int gl = sqlite3_column_int(stmt, 1);
								if (!svc_name) continue;

								count_db++;
								int old_gl = lws_jwt_auth_query_grant(pss->ja, svc_name);
								if (old_gl != gl)
									mismatch = 1;

								if (!first)
									g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), ",");
								first = 0;
								g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "\"%s\":%d", svc_name, gl);
							}
							sqlite3_finalize(stmt);
						}
						g_p += lws_snprintf(g_p, lws_ptr_diff_size_t(g_end, g_p), "}");

						if (count_db != (int)lws_jwt_auth_count_grants(pss->ja))
							mismatch = 1;

						if (mismatch) {
							char temp[1024];
							char out[2048];
							size_t out_len = sizeof(out);
							uint64_t now = (uint64_t)time(NULL);
							uint64_t exp = now + vhd->jwt_validity_secs;
							const char *sub = lws_jwt_auth_get_sub(pss->ja);

							if (!lws_jwt_sign_compact(vhd->context, &vhd->jwk, "ES256",
													  out, &out_len, temp, sizeof(temp),
													  "{\"iss\":\"%s\",\"sub\":\"%s\",\"uid\":%u,"
													  "\"iat\":%llu,\"exp\":%llu,%s}",
													  vhd->auth_domain, sub ? sub : "Unknown", uid,
													  (unsigned long long)now, (unsigned long long)exp,
													  current_grants)) {
								pss->silent_update_jwt = strdup(out);
							}
						}
					}
				}
			}

			if (pss->silent_update_jwt) {
				path[0] = '\0';
				if (lws_hdr_copy(wsi, path, sizeof(path),
						 WSI_TOKEN_GET_URI) < 0)
					lwsl_debug("%s: URI copy failed\n", __func__);

				if (!lws_login_serve_self_redirect_with_cookie(
						wsi, pss, vhd, pss->silent_update_jwt,
						path, (unsigned char *)buf,
						(unsigned char **)&p,
						(unsigned char *)end, NULL)) {
					free(pss->silent_update_jwt);
					pss->silent_update_jwt = NULL;
					return lws_http_transaction_completed(wsi);
				}
				/* header build failed */
				return 1;
			}
		}

		path[0] = '\0';
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) <= 0)
			if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
				lwsl_debug("%s: URI copy failed\n", __func__);

		if (lws_login_ends_with(path, "/lws-login.css")) {
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/css",
							(lws_filepos_t)strlen(canned_css), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(canned_css);
			int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)canned_css, len);
			if (res < 0)
				return -1;
			pss->tx_remaining = len;
			lws_callback_on_writable(wsi);

			return 0;
		}

		if (lws_login_ends_with(path, "/lws-login.js")) {
			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/javascript",
							(lws_filepos_t)strlen(canned_js), (unsigned char **)&p, (unsigned char *)end))
				return 1;
			if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
				return 1;
			lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
			size_t len = strlen(canned_js);
			int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)canned_js, len);
			if (res < 0)
				return -1;
			pss->tx_remaining = len;
			lws_callback_on_writable(wsi);

			return 0;
		}

		if (lws_login_ends_with(path, "/.lws-login-refresh")) {
			char csrf[64] = {0};
			size_t csrf_len = sizeof(csrf);
			char refresh_session[128] = {0};
			size_t refresh_session_len = sizeof(refresh_session);
			int ck_len;

			ck_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);

			if (ck_len > 0) {
				char *cookie = malloc((size_t)ck_len + 1);
				if (cookie) {
					int kicked = 0;
					if (lws_hdr_copy(wsi, cookie, ck_len + 1,
							 WSI_TOKEN_HTTP_COOKIE) > 0) {
						int got_csrf = lws_http_cookie_get(
								wsi, "auth_csrf",
								csrf, &csrf_len) == 0
								&& csrf[0];
						int got_refresh = lws_http_cookie_get(
								wsi, "auth_refresh_session",
								refresh_session,
								&refresh_session_len) == 0
								&& refresh_session[0];
						if (got_csrf && got_refresh)
							kicked = lws_login_kick_refresh(
									vhd, wsi,
									cookie, csrf,
									LWS_LOGIN_REFRESH_BFF,
									NULL, NULL);
						else if (got_refresh) {
							/*
							 * Refresh session present but its csrf
							 * sidecar is gone: self-heal instead of
							 * denying, or the widget classifies a live
							 * session as dead and trashes the page.
							 * Log the raw jar: recurrences on devices
							 * we cannot inspect are otherwise
							 * undiagnosable.
							 */
							lwsl_wsi_notice(wsi,
								"background refresh self-heal: "
								"auth_csrf cookie missing but "
								"auth_refresh_session present, "
								"minting side-channel csrf pair "
								"(jar: '%s')", cookie);
							kicked = lws_login_kick_refresh_selfheal(
									vhd, wsi, cookie,
									LWS_LOGIN_REFRESH_BFF,
									NULL, NULL);
						} else if (got_csrf)
							lwsl_wsi_notice(wsi,
								"background refresh denied: "
								"auth_refresh_session cookie "
								"missing (not logged in via "
								"refreshable session) "
								"(jar: '%s')", cookie);
						else
							lwsl_wsi_notice(wsi,
								"background refresh denied: no "
								"auth_csrf and no "
								"auth_refresh_session "
								"(jar: '%s')", cookie);
					} else {
						lwsl_wsi_notice(wsi,
							"background refresh denied: "
							"malformed Cookie header");
					}
					free(cookie);
					if (kicked)
						return 0; /* suspend */
				}
			} else {
				/*
				 * No Cookie header at all: normal for an
				 * anonymous visitor whose page widget just fired
				 * a renewal probe.  Info, not notice.
				 */
				lwsl_wsi_info(wsi, "background refresh with no "
					      "Cookie header (anonymous visitor)");
			}
			/* Failure or no cookies, 401 Unauthorized */
                        return simple_response(wsi, pss, "Missing Authorization", "text/plain",
                                            HTTP_STATUS_UNAUTHORIZED, (unsigned char *)buf + LWS_PRE,
                                            (unsigned char **)&p, (unsigned char *)end);
		}

		char host[128];
		char fq_uri[512];
		const char *h = NULL;

		host[0] = '\0';
		if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0)
			h = host;
#if defined(LWS_ROLE_H2)
		else if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
			h = host;
#endif

		if (!h) {
			struct lws_vhost *vh = lws_get_vhost(wsi);
			if (vh) {
				const char *vname = lws_get_vhost_name(vh);
				if (vname)
					h = vname;
			}
		}

		{
			const char *scheme = "http";
#if defined(LWS_WITH_CUSTOM_HEADERS)
			char proto[16] = "";

			if (lws_hdr_custom_copy(wsi, proto, sizeof(proto), "x-forwarded-proto:", 18) > 0) {
				if (!strcasecmp(proto, "https"))
					scheme = "https";
			} else
#endif
			if (lws_is_ssl(lws_get_network_wsi(wsi))) {
				scheme = "https";
			}

			lws_snprintf(fq_uri, sizeof(fq_uri), "%s://%s%s",
				     scheme,
				     h ? h : "localhost",
				     path);
		}

		lws_urlencode(urlenc_path, fq_uri, sizeof(urlenc_path));

		size_t asu_len = strlen(vhd->auth_server_url);
		lws_snprintf(dest, sizeof(dest), "%s%s?service_name=%s&redirect_uri=%s",
			vhd->auth_server_url,
			(asu_len > 0 && vhd->auth_server_url[asu_len - 1] == '/') ? "" : "/",
			service_name, urlenc_path);

		if (lws_login_ends_with(path, "/.lws-login-status")) {
			char pl[1024];

			if (pss && pss->ja) {
				const char *sub = lws_jwt_auth_get_sub(pss->ja);
				int level = lws_jwt_auth_query_grant(pss->ja, service_name);
				/*
				 * Compute the single lws_login_state for this
				 * request (same mapping as the backend header
				 * injection) and derive the JSON booleans from
				 * it so they can't drift apart.  is_admin means
				 * a GLOBAL system admin only (the "*" wildcard),
				 * the one thing that unlocks the auth-server
				 * Admin Console and the "Admin Console" link in
				 * the widget; an app-scoped level >= 2 is an
				 * APP_ADMIN, reflected by login_state and
				 * grant_level but not is_admin.
				 */
				enum lws_login_state state =
					lws_login_state_from_grants(pss->ja, level);
				int is_admin = state == LWS_LOGIN_STATE_GLOBAL_ADMIN;
				int has_grant = state >= LWS_LOGIN_STATE_USER;
				lws_snprintf(pl, sizeof(pl), "{\"logged_in\":1,\"server_now\":%llu,\"exp\":%llu,\"has_grant\":%d,\"grant_level\":%d,\"login_state\":%d,\"identity\":\"%s\",\"auth_server_url\":\"%s\",\"login_url\":\"%s\",\"is_admin\":%d,\"unauth_allow\":%d}",
					(unsigned long long)lws_now_secs(), (unsigned long long)lws_jwt_auth_get_exp(pss->ja), has_grant, level, (int)state, sub ? sub : "Unknown", vhd->auth_server_url ? vhd->auth_server_url : "", dest, is_admin, unauth_allow);
			} else
				lws_snprintf(pl, sizeof(pl), "{\"logged_in\":0,\"login_state\":%d,\"server_now\":%llu,\"auth_server_url\":\"%s\",\"login_url\":\"%s\",\"unauth_allow\":%d}", (int)LWS_LOGIN_STATE_ANON, (unsigned long long)lws_now_secs(), vhd->auth_server_url ? vhd->auth_server_url : "", dest, unauth_allow);

                        return simple_response(wsi, pss, pl, "application/json",
                                               HTTP_STATUS_OK, (unsigned char *)buf + LWS_PRE, (unsigned char **)&p,
                                               (unsigned char *)end);
		}

		if (lws_login_ends_with(path, "/.lws-login-logout")) {
			char redirect_uri[512];
			char u[1024];
			char cookie_hdr1[256], cookie_hdr1_host[256];
			char exp[64];
			time_t t = 0;
#if defined(WIN32) || defined(_WIN32)
			struct tm tmp;
			struct tm *tm = gmtime_s(&tmp, &t) == 0 ? &tmp : NULL;
#else
			struct tm tmp;
			struct tm *tm = gmtime_r(&t, &tmp);
#endif
			if (tm)
				strftime(exp, sizeof(exp), "%a, %d %b %Y %H:%M:%S GMT", tm);
			else
				exp[0] = '\0';

			redirect_uri[0] = '\0';
			if (lws_get_urlarg_by_name_safe(wsi, "redirect_uri=", redirect_uri, sizeof(redirect_uri)) >= 0)
				lws_urldecode(redirect_uri, redirect_uri, sizeof(redirect_uri));
			if (!redirect_uri[0])
				lws_strncpy(redirect_uri, "/", sizeof(redirect_uri));

			if (vhd->cookie_domain[0])
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Domain=%s; Expires=%s; Max-Age=0; HttpOnly; SameSite=Lax; Secure", vhd->cookie_name, vhd->cookie_domain, exp);
			else
				lws_snprintf(cookie_hdr1, sizeof(cookie_hdr1), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=Lax; Secure", vhd->cookie_name, exp);

			lws_snprintf(cookie_hdr1_host, sizeof(cookie_hdr1_host), "%s=; Path=/; Expires=%s; Max-Age=0; HttpOnly; SameSite=Lax; Secure", vhd->cookie_name, exp);

			char urlenc_path[512];
			lws_urlencode(urlenc_path, redirect_uri, sizeof(urlenc_path));

			if (vhd->auth_server_url && vhd->auth_server_url[0]) {
				lws_snprintf(u, sizeof(u), "%s/api/logout?redirect_uri=%s", vhd->auth_server_url, urlenc_path);
			} else {
				/* Fallback if auth_server_url somehow missing */
				lws_strncpy(u, redirect_uri, sizeof(u));
			}

			char html[1024];
			int html_len = lws_snprintf(html, sizeof(html),
				"<html lang=\"en\"><head><meta http-equiv=\"refresh\" content=\"0; url=%s\"></head><body>Redirecting to <a href=\"%s\">%s</a></body></html>",
				u, u, u);
			if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)html, (size_t)html_len) < 0) return -1;
			pss->tx_remaining = (size_t)html_len;

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_SEE_OTHER, "text/html", (unsigned int)html_len, (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1, (int)strlen(cookie_hdr1), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie_hdr1_host, (int)strlen(cookie_hdr1_host), (unsigned char **)&p, (unsigned char *)end)) return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)u, (int)strlen(u), (unsigned char **)&p, (unsigned char *)end)) return 1;
			goto fin_hdrs;
		}

		/*
		 * If unauth-allow is set on this mount, let the request fall
		 * through to the real mount content instead of bouncing to the
		 * auth server.  This applies both to anonymous visitors and to
		 * logged-in users who simply lack the required grant: the login
		 * widget (.lws-login-status) reports their actual state so the
		 * app can show itself with no admin rights, rather than trapping
		 * them on an auth-server "you lack the grant" page they cannot
		 * escape.  (CONFIRM_REQ_OK already let them through; this keeps
		 * the HTTP path consistent with that decision.)
		 */
		if (unauth_allow) {
			lwsl_info("%s: ALLOWING unauth-allow fall-through\n",
				  __func__);
			return 0;
		}

		lwsl_info("%s: bouncing unauth to %s\n", __func__, dest);

		/*
		 * Cold-load silent renewal: this is a genuine page request whose JWT
		 * is missing/expired, but the browser may still carry the long-term
		 * auth_refresh_session + auth_csrf cookies.  Before bouncing the
		 * user's main document to the auth server login form (which would
		 * lose in-page state and flash a login page for nothing), try a
		 * server-side renewal through the same /api/sso_exchange side channel
		 * the background BFF uses.  On success we re-mint the JWT cookie and
		 * 302 back to this same URL -- the page just loads, no navigation.
		 * Only on a hard failure (long-term session genuinely gone) do we
		 * fall through to the 303 below, landing the user on the form to
		 * actually log in again.  Cookieless requests skip the hop entirely.
		 */
			{
				int ck_len2 = lws_hdr_total_length(wsi,
							WSI_TOKEN_HTTP_COOKIE);
				if (ck_len2 > 0) {
					char csrf2[64] = {0};
					size_t csrf2_len = sizeof(csrf2);
					char refresh2[128] = {0};
					size_t refresh2_len = sizeof(refresh2);
					int got_csrf2 = lws_http_cookie_get(wsi,
							"auth_csrf", csrf2,
							&csrf2_len) == 0 && csrf2[0];
					int got_refresh2 =
						lws_http_cookie_get(wsi,
							"auth_refresh_session",
							refresh2,
							&refresh2_len) == 0 &&
							refresh2[0];

					if (got_refresh2) {
						char *cookie2 = malloc((size_t)ck_len2 + 1);
						if (cookie2) {
							char orig_uri[LWS_LOGIN_MAX_URI];
							int kicked;
							/* the self-redirect target must
							 * include the query string, or
							 * the user's deep link comes
							 * back shortened */
							lws_login_copy_uri_with_args(
									wsi, path,
									orig_uri,
									sizeof(orig_uri));
							if (lws_hdr_copy(wsi, cookie2,
									 ck_len2 + 1,
									 WSI_TOKEN_HTTP_COOKIE) > 0) {
								if (got_csrf2)
									kicked = lws_login_kick_refresh(
										vhd, wsi, cookie2,
										csrf2,
										LWS_LOGIN_REFRESH_COLDLOAD,
										orig_uri, dest);
								else {
									/* csrf sidecar missing:
									 * self-heal rather than
									 * bounce (see
									 * ..._selfheal comment) */
									lwsl_wsi_notice(wsi,
										"cold-load renewal self-heal: "
										"auth_csrf cookie missing but "
										"auth_refresh_session present, "
										"minting side-channel csrf pair "
										"(jar: '%s')", cookie2);
									kicked = lws_login_kick_refresh_selfheal(
											vhd, wsi, cookie2,
											LWS_LOGIN_REFRESH_COLDLOAD,
											orig_uri, dest);
								}
							}
							else
								kicked = 0;
							free(cookie2);
							if (kicked)
								return 0; /* suspend */
						}
					}
				}
			}

		char html[1024];
		int html_len = lws_snprintf(html, sizeof(html),
			"<html lang=\"en\"><head><meta http-equiv=\"refresh\" content=\"0; url=%s\"></head><body>Redirecting to <a href=\"%s\">%s</a></body></html>",
			dest, dest, dest);
		if (lws_buflist_append_segment(&pss->tx_buflist, (uint8_t *)html, (size_t)html_len) < 0) return -1;
		pss->tx_remaining = (size_t)html_len;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_SEE_OTHER, "text/html", (unsigned int)html_len, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
				(unsigned char *)dest, (int)strlen(dest), (unsigned char **)&p, (unsigned char *)end))
			return 1;
 fin_hdrs:
		if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end))
			return 1;

		lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
		lws_callback_on_writable(wsi);
		return 0;
	}

	case LWS_CALLBACK_HTTP_BODY:
	{
		char path[256];
		path[0] = '\0';
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
			lwsl_debug("%s: URI copy failed\n", __func__);

		if (lws_login_ends_with(path, "/.lws-login-sso")) {
			if (!pss->spa) {
				pss->spa = lws_spa_create(wsi, param_names,
							  LWS_ARRAY_SIZE(param_names),
							  LWS_SSO_MAX_COOKIE, NULL, NULL);
				if (!pss->spa)
					return -1;
			}
			if (lws_spa_process(pss->spa, (const char *)in, (int)len)) {
				lws_spa_finalize(pss->spa);
				return -1;
			}
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	{
		char path[256];

		if (!vhd)
			return 1;

		path[0] = '\0';
		if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_POST_URI) < 0)
			lwsl_debug("%s: URI copy failed\n", __func__);

		if (lws_login_ends_with(path, "/.lws-login-sso")) {
			if (pss->spa) {
				lws_spa_finalize(pss->spa);
				const char *token = lws_spa_get_string(pss->spa, EPN_TOKEN);
				const char *target = lws_spa_get_string(pss->spa, EPN_TARGET);

				char origin[128], referer[256];
				const char *chk_url = NULL;
				int has_origin = lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN) > 0;
				int has_referer = lws_hdr_copy(wsi, referer, sizeof(referer), WSI_TOKEN_HTTP_REFERER) > 0;

				if (has_origin && strcmp(origin, "null")) {
					chk_url = origin;
				} else if (has_referer) {
					chk_url = referer;
				}

				/*
				 * A presented token gets planted as the
				 * browser's session cookie, so it must come
				 * with positive proof it originated at the
				 * configured auth server: an Origin (non-"null",
				 * sandboxed iframes send "null") or a Referer
				 * matching auth-server-url's scheme+host+port.
				 * Fail closed on every path where a positive
				 * match cannot be made.  A cross-site form POST
				 * suppressing both headers used to skip the
				 * check entirely and plant its token: login
				 * CSRF.  The legit flow, the auth server's
				 * auto-submitting form POST, always carries one
				 * of the two.
				 */
				if (token && vhd) {
					lws_parse_uri_t *puri_auth = NULL, *puri_chk = NULL;

					if (!vhd->auth_server_url) {
						lwsl_err("%s: blocking SSO token: no auth-server-url to check origin against\n",
							 __func__);
						token = NULL;
					} else if (!chk_url) {
						lwsl_err("%s: blocking SSO token: no origin/referer to check against %s (login CSRF?)\n",
							 __func__, vhd->auth_server_url);
						token = NULL;
					} else {
						puri_auth = lws_parse_uri_create(vhd->auth_server_url);
						puri_chk = lws_parse_uri_create(chk_url);

						if (!puri_auth || !puri_chk ||
						    strcmp(puri_auth->scheme, puri_chk->scheme) ||
						    strcasecmp(puri_auth->host, puri_chk->host) ||
						    puri_auth->port != puri_chk->port) {
							lwsl_err("%s: blocking SSO CSRF from origin/referer %s (expected %s)\n",
								 __func__, chk_url, vhd->auth_server_url);
							token = NULL;
						} else {
							lwsl_notice("%s: allowing SSO request matching auth server origin %s\n",
								    __func__, chk_url);
						}
					}

					if (puri_auth)
						lws_parse_uri_destroy(&puri_auth);
					if (puri_chk)
						lws_parse_uri_destroy(&puri_chk);
				}

				if (token && target && vhd) {
					char temp[2048], out[2048];
					size_t out_len = sizeof(out);

					/* Ensure signature is authentic using broad algorithms. */
					if (!lws_jwt_signed_validate(vhd->context, &vhd->jwk, "ES256,ES384,ES512,RS256,RS384,RS512",
								    token, strlen(token), temp, sizeof(temp), out, &out_len)) {
						pss->silent_update_jwt = strdup(token);
					}
				}

				const char *final_target = "/";
				if (target && target[0]) {
					if (target[0] == '/' && target[1] != '/') {
						final_target = target;
					} else {
						lws_parse_uri_t *puri_tgt = lws_parse_uri_create(target);
						if (puri_tgt) {
							char host[128] = "";
							const char *h = NULL;
							if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0)
								h = host;
#if defined(LWS_ROLE_H2)
							else if (lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
								h = host;
#endif
							if (!h) {
								struct lws_vhost *vh = lws_get_vhost(wsi);
								if (vh) h = lws_get_vhost_name(vh);
							}
							if (h && !strcasecmp(puri_tgt->host, h)) {
								final_target = target;
							} else if (vhd->db) {
								if (auth_verify_redirect_uri(vhd, target)) {
									final_target = target;
								} else {
									lwsl_err("%s: untrusted absolute target %s\n", __func__, target);
								}
							}
							lws_parse_uri_destroy(&puri_tgt);
						}
					}
				}

				if (pss->silent_update_jwt && final_target) {
					char cookie[LWS_SSO_MAX_COOKIE];
					if (vhd->cookie_domain[0]) {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
					} else {
						lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
							     vhd->cookie_name, pss->silent_update_jwt, (unsigned long long)vhd->jwt_validity_secs);
					}

					if (lws_add_http_common_headers(wsi, HTTP_STATUS_FOUND, "text/html", 0, (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie, (int)strlen(cookie), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)final_target, (int)strlen(final_target), (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
					lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);

					return lws_http_transaction_completed(wsi);
				} else {
					const char *err = "Invalid SSO Token";
					int err_len = (int)strlen(err);
					if (lws_add_http_common_headers(wsi, HTTP_STATUS_FORBIDDEN, "text/plain", (lws_filepos_t)err_len, (unsigned char **)&p, (unsigned char *)end)) return 1;
					if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
					lws_write(wsi, (unsigned char *)buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
					int res = lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)err, (size_t)err_len);
					if (res < 0) return -1;
					pss->tx_remaining = (size_t)err_len;
					lws_callback_on_writable(wsi);
					return 0;
				}
			}
		}
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
	{
		unsigned char buf[LWS_SSO_MAX_COOKIE + LWS_PRE], *p = buf + LWS_PRE, *end = buf + sizeof(buf) - 1;
		struct pending_login_refresh *ps = NULL;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vhd->pending_refresh_list)) {
			struct pending_login_refresh *s = lws_container_of(d, struct pending_login_refresh, list);

			if (s->wsi_server == wsi) {
				ps = s;
				break;
			}
		} lws_end_foreach_dll_safe(d, d1);

		if (ps) {
			if (ps->mode == LWS_LOGIN_REFRESH_COLDLOAD) {
				/*
				 * Cold-load renewal completion.  On success we
				 * re-mint the JWT cookie and 302 back to the URL
				 * the browser originally asked for -- the page
				 * just loads, no navigation, no flash.  On failure
				 * (long-term session genuinely gone) we issue the
				 * 303 to the auth server login form we pre-built,
				 * landing the user where they can actually log in.
				 */
				if (ps->token[0]) {
					/*
					 * Rotate auth_csrf alongside the re-minted
					 * JWT, same rationale as the BFF path: the
					 * csrf cookie must reset its lifetime every
					 * renewal or it dies on the original login's
					 * schedule and the next renewal fails.
					 */
					char new_csrf[33];
					char csrf_cookie[LWS_LOGIN_CSRF_COOKIE_SZ];

					lws_login_mint_csrf(vhd, new_csrf);
					lws_login_build_csrf_cookie(vhd, new_csrf,
								 csrf_cookie,
								 sizeof(csrf_cookie));
					if (!lws_login_serve_self_redirect_with_cookie(
							wsi, pss, vhd, ps->token,
							ps->orig_path, buf, &p, end,
							csrf_cookie)) {
						lwsl_wsi_notice(wsi, "cold-load "
							"renewal ok, re-served %s",
							ps->orig_path);
						pending_login_release(ps);
						return lws_http_transaction_completed(wsi);
					}
					/* header build failed */
					pending_login_release(ps);
					return 1;
				}

				/* failure: 303 to the auth form */
				if (ps->authform_url[0]) {
					char html[1024];
					int html_len;

					if (ps->resp_status)
						lwsl_wsi_notice(wsi, "cold-load "
							"renewal denied: auth server "
							"answered HTTP %u '%s', "
							"bouncing to auth form",
							ps->resp_status,
							ps->resp_error[0] ?
								ps->resp_error :
								"(no error detail)");
					else
						lwsl_wsi_notice(wsi, "cold-load "
							"renewal denied: no auth "
							"server response (%s), "
							"bouncing to auth form",
							ps->conn_error[0] ?
								ps->conn_error :
								"connection failed");
					html_len = lws_snprintf(html,
						sizeof(html),
						"<html lang=\"en\"><head>"
						"<meta http-equiv=\"refresh\" "
						"content=\"0; url=%s\"></head>"
						"<body>Redirecting to <a "
						"href=\"%s\">%s</a></body></html>",
						ps->authform_url,
						ps->authform_url,
						ps->authform_url);
					if (lws_buflist_append_segment(
							&pss->tx_buflist,
							(uint8_t *)html,
							(size_t)html_len) < 0) {
						pending_login_release(ps);
						return -1;
					}
					pss->tx_remaining = (size_t)html_len;

					if (lws_add_http_common_headers(wsi,
							HTTP_STATUS_SEE_OTHER,
							"text/html",
							(unsigned int)html_len,
							(unsigned char **)&p,
							(unsigned char *)end) ||
					    lws_add_http_header_by_token(wsi,
							WSI_TOKEN_HTTP_LOCATION,
							(unsigned char *)
								ps->authform_url,
							(int)strlen(ps->authform_url),
							(unsigned char **)&p,
							(unsigned char *)end)) {
						pending_login_release(ps);
						return 1;
					}
					if (lws_finalize_http_header(wsi,
							(unsigned char **)&p,
							(unsigned char *)end)) {
						pending_login_release(ps);
						return 1;
					}
					lws_write(wsi,
						  (unsigned char *)buf + LWS_PRE,
						  lws_ptr_diff_size_t(p, buf + LWS_PRE),
						  LWS_WRITE_HTTP_HEADERS);
					pending_login_release(ps);
					lws_callback_on_writable(wsi);
					return 0;
				}
				/* no authform URL stashed (defensive): serve a 401 */
				lwsl_wsi_notice(wsi, "cold-load renewal failed "
					"with no authform URL");
				if (lws_add_http_common_headers(wsi,
						HTTP_STATUS_UNAUTHORIZED,
						"application/json", 13,
						(unsigned char **)&p,
						(unsigned char *)end) ||
				    lws_finalize_http_header(wsi,
						(unsigned char **)&p,
						(unsigned char *)end)) {
					pending_login_release(ps);
					return 1;
				}
				lws_write(wsi, (unsigned char *)buf + LWS_PRE,
					  lws_ptr_diff_size_t(p, buf + LWS_PRE),
					  LWS_WRITE_HTTP_HEADERS);
				pending_login_release(ps);
				lws_callback_on_writable(wsi);
				return 0;
			} else if (ps->token[0]) {
				char cookie[LWS_SSO_MAX_COOKIE];
				char csrf_cookie[LWS_LOGIN_CSRF_COOKIE_SZ];
				char new_csrf[33];
				int n, cn;

				if (vhd->cookie_domain[0]) {
					lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Domain=%s; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
							 vhd->cookie_name, ps->token, vhd->cookie_domain, (unsigned long long)vhd->jwt_validity_secs);
				} else {
					lws_snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; Max-Age=%llu; HttpOnly; SameSite=Lax; Secure",
							 vhd->cookie_name, ps->token, (unsigned long long)vhd->jwt_validity_secs);
				}
				/* strlen, not the snprintf return: it answers the
				 * truncated size, which would plant the string's
				 * NUL inside the header */
				n = (int)strlen(cookie);

				/*
				 * Rotate auth_csrf on every successful renewal so its
				 * lifetime resets with the session instead of dying on
				 * the original login's fixed schedule (which is what
				 * makes the widget escalate to a redirect flash once it
				 * lapses).  The next renewal reads this new value and
				 * submits it as the matching csrf_token= form field.
				 */
				lws_login_mint_csrf(vhd, new_csrf);
				cn = lws_login_build_csrf_cookie(vhd, new_csrf,
								 csrf_cookie,
								 sizeof(csrf_cookie));

				if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "application/json", 13, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)cookie, n, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_add_http_header_by_name(wsi, (unsigned char *)"set-cookie:", (unsigned char *)csrf_cookie, cn, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;

				lws_write(wsi, buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
				if (lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)"{\"success\":1}", 13) < 0) return -1;
				pss->tx_remaining = 13;
				lwsl_wsi_notice(wsi, "Successfully issued refreshed token to browser via BFF");
			} else {
				if (lws_add_http_common_headers(wsi, HTTP_STATUS_UNAUTHORIZED, "application/json", 13, (unsigned char **)&p, (unsigned char *)end)) return 1;
				if (lws_finalize_http_header(wsi, (unsigned char **)&p, (unsigned char *)end)) return 1;
				lws_write(wsi, buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
				if (lws_buflist_append_segment(&pss->tx_buflist, (const uint8_t *)"{\"success\":0}", 13) < 0) return -1;
				pss->tx_remaining = 13;
				/*
				 * No token came back.  Say WHY, using what the
				 * side channel captured: the auth server's HTTP
				 * status + JSON error member when it answered,
				 * or the connection failure when it never did.
				 */
				if (ps->resp_status)
					lwsl_wsi_notice(wsi,
						"BFF renewal denied: auth "
						"server answered HTTP %u '%s'",
						ps->resp_status,
						ps->resp_error[0] ?
							ps->resp_error :
							"(no error detail)");
				else
					lwsl_wsi_notice(wsi,
						"BFF renewal denied: no "
						"auth server response (%s)",
						ps->conn_error[0] ?
							ps->conn_error :
							"connection failed");
			}

			pending_login_release(ps);

			lws_callback_on_writable(wsi);

			return 0;
		}

		if (!pss || !pss->tx_buflist)
			break;

		uint8_t *pout;
		size_t bytes = lws_buflist_next_segment_len(&pss->tx_buflist, &pout);

		if (!bytes)
			break;

		/*
		 * We must set LWS_WRITE_HTTP_FINAL on the write that sends the last
		 * bytes of the body, so that under HTTP/2 the END_STREAM flag lands on
		 * the final DATA frame.  Comparing chunk to lws_buflist_total_len() is
		 * wrong once a segment is partly consumed: total_len() sums each
		 * segment's original len without subtracting pos, so the second chunk
		 * of a body larger than the write buffer never compares equal, FINAL
		 * is never set, and browsers report NS_ERROR_NET_PARTIAL_TRANSFER.
		 * struct lws_buflist is opaque to plugins, so we track the remaining
		 * body length in pss->tx_remaining and mark FINAL when this chunk
		 * brings it to zero.
		 */
		size_t chunk = bytes;
		if (chunk > sizeof(buf) - LWS_PRE)
			chunk = sizeof(buf) - LWS_PRE;

		memcpy(p, pout, chunk);

		int flags = (chunk >= pss->tx_remaining) ?
				LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;

		int m = lws_write(wsi, p, (unsigned int)chunk, (enum lws_write_protocol)flags);
		if (m < 0) return -1;

		pss->tx_remaining -= (size_t)m;
		lws_buflist_use_segment(&pss->tx_buflist, (size_t)m);

		if (lws_buflist_next_segment_len(&pss->tx_buflist, &pout)) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		return lws_http_transaction_completed(wsi);
	}

		case LWS_CALLBACK_CLOSED_HTTP:
		case LWS_CALLBACK_CLOSED:
			if (pss && pss->tx_buflist) {
				lws_buflist_destroy_all_segments(&pss->tx_buflist);
				pss->tx_remaining = 0;
			}

		if (pss && pss->ja)
			lws_jwt_auth_destroy(&pss->ja);

                if (pss && pss->silent_update_jwt) {
			free(pss->silent_update_jwt);
			pss->silent_update_jwt = NULL;
		}

		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}

		if (vhd) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
						   lws_dll2_get_head(&vhd->pending_refresh_list)) {
				struct pending_login_refresh *s = lws_container_of(d, struct pending_login_refresh, list);

                                if (s->wsi_server == wsi) {
					s->wsi_server = NULL;
					lwsl_wsi_notice(wsi, "cleared dangling "
						"wsi_server from pending refresh");
				}
			} lws_end_foreach_dll_safe(d, d1);
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_LOGIN \
	{ \
		"lws-login", \
		callback_lws_login, \
		sizeof(struct pss_login), \
		1024, 0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_LOGIN,
	{
		.name = "lws_login_client",
		.callback = callback_lws_login_client,
		.per_session_data_size = 0,
		.rx_buffer_size = 0,
		.id = 0,
		.user = NULL,
		.tx_packet_size = 0
	}
};

LWS_VISIBLE const lws_plugin_protocol_t lws_login = {
	.hdr = {
		.name = "lws login",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
