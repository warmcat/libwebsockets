# lws-login / JWT Auth Bouncer

## Introduction

The `lws-login` plugin is a mount-based interceptor handler that securely guards pages by explicitly requiring a verified JSON Web Token (JWT) session.

Instead of maintaining its own database, it acts as a lightweight, proactive **bouncer**, completely reliant on the core `lws_jwt_auth` helper API. Unauthenticated requests—or requests with a valid JWT but lacking the required `grants` privileges—are swiftly intercepted and redirected via HTTP 302 to a central Auth Server portal matching the configured PVOs. Once a user procures a valid session cookie from the Auth Server, the bouncer transparently allows traffic to pass through to the underlying application mount.

Furthermore, `lws-login` natively maintains an `lws_sorted_usec_list` (SUL) expiration timer tracking the exact token `exp` boundary. Even if a WebSocket successfully upgrades over the protected mount, the connection will be gracefully terminated the exact moment the active authorization token naturally expires!

## WebSocket Upgrades

When a mount is protected by an `interceptor-path` (such as `lws-login`), **both standard HTTP requests and `wss://` WebSocket upgrade requests are subjected to the exact same cryptographic JWT validation.**

If an unauthorized client (such as a headless script like `-camshow` or a browser without a valid session cookie) attempts to negotiate a WebSocket connection against a protected mount, the connection is proactively intercepted and immediately rejected with an `HTTP 401 Unauthorized` status during the HTTP phase of the handshake, cleanly dropping the socket.

However, for headless IoT clients that strictly cannot redirect to a login page, we provide the `unauth-protocols` bypass to allow them into a pre-authentication "waiting room". See [Headless Device Authorization](#headless-device-authorization) below.


## Per-Vhost Options (PVOs)

This plugin handles several PVO options to control the redirection routing and the properties of the required JWT session cookie:

| PVO Name | Description |
|---|---|
| `auth-server-url` | **Required.** The base URI of the central auth server portal to redirect unauthenticated users to (e.g. `https://auth.warmcat.com/login`). |
| `jwt-jwk` | **Required.** Either a JSON Web Key string or the path to a file containing a JSON Web Key, used to establish signing criteria for verifying the token signature. Must match the public key the central server uses to sign tokens. |
| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. Defaults to `"auth_session"`. Limited to 1..63 characters: the protocol refuses to initialize with a longer name, since the composed `Set-Cookie` buffers are sized for that cap (a cookie that could not be composed whole would otherwise have to be silently truncated or fail the response). |
| `service-name` | The explicitly required grant category strictly checked against the JWT privileges array. Defaults to `"default-service"`. *Note: Any authenticated user holding a wildcard (`*`) assignment in their JWT grants array will automatically bypass this constraint, acting as an administrator for any requested service.* **This option responds to BOTH a PVO definition (applying globally to the vhost) and can be dynamically overridden by a Per-Mount Option (PMO) definition of the same name.** |
| `min-grant-level` | The strict integer threshold allowing passage for the given service name within the token. Defaults to `1`. |
| `cookie-domain` | The optional specific domain name the auth cookie should be scoped to stringently (e.g. `warmcat.com`). If unspecified, defaults to omitting the domain from the cookie. |
| `auth-domain` | The issuer domain namespace string injected as `iss` when generating tokens. Defaults to `auth.warmcat.com`. |
| `jwt-validity-secs` | Integer representing the time-to-live for a dynamically migrated cookie. Defaults to `86400` (24 hours). |
| `db-path` | Absolute filepath to the shared sqlite3 permissions database (used to instantly verify and rewrite valid cookies suffering from revoked grants). Defaults to `/var/db/lws-auth.sqlite3`. |
| `whitelist` | Optional array of CIDR netblock strings (e.g. `10.0.0.0/8`, `192.168.1.0/24`). If any are provided, the connecting peer must match at least one explicitly or they will uniformly receive a `403 Forbidden` bypass, regardless of login state. |
| `unauth-allow` | If set to `1`, unauthenticated connections are **not** actively bounced via a 302 redirect. Traffic is instead permitted through to the underlying application mount unhindered. This enables scenarios where an underlying mount might conditionally render public views while relying securely on `/.lws-login-status` responses to dictate authenticated view logic without hard-failing unauthenticated guests. |
| `unauth-protocols` | Optional comma-separated list of `Sec-WebSocket-Protocol` names (e.g., `lws-oauth-preauth`) that are permitted to bypass the JWT requirement during the upgrade phase. This allows unauthenticated headless devices to negotiate specific protocols to complete RFC 8628 Device Flow pairing. |

**Where does the JWK come from?**
The central `auth-server` plugin automatically generates an Elliptic Curve (EC P-256) keypair upon its first startup and saves it to its configured `jwk_path` (e.g., `/var/db/lws-auth.jwk`). To configure the `jwt-jwk` PVO for this bouncer mount, you simply take the contents of that generated file.

Because the JWT validator only strictly requires the public key components to verify the signature, you can either:
1. Provide the exact literal JSON string from the Auth Server's generated JWK file.
2. Read the literal string dynamically into the PVO when configuring your mount from your application.

*(Note: While passing the full keypair including the private key into the bouncer works, it is best practice to strip the private component `d` from the JSON if the bouncer is operating on an entirely different physical server).*

## Headless Device Authorization (RFC 8628)

When building embedded devices without a screen or UI (such as IP cameras or IoT sensors), they inherently lack the ability to follow HTTP 302 redirects to a login page or process interactive OAuth flows.

To securely onboard these devices to a protected mount without opening security holes, you can utilize the `lws-oauth-preauth` protocol in conjunction with the `unauth-protocols` PVO bypass.

1. **The Bypass**: By defining `"unauth-protocols": "lws-oauth-preauth"` in your `lws-login` configuration, the interceptor will unconditionally allow incoming WebSocket connections that specifically request the `lws-oauth-preauth` subprotocol, even if they lack a valid JWT.
2. **The Waiting Room**: The `lws-oauth-preauth` plugin provides a secure "waiting room". Unauthenticated devices can connect and broadcast their unique hardware serial numbers and pairing codes.
3. **Admin Verification**: Authenticated administrators (who connect with a valid JWT) can join this same protocol to observe pending devices. Crucially, admins can issue specific commands (like `{"cmd": "identify"}`) that the server securely routes to the target device to trigger physical "pairing indications" (e.g., blinking an LED). This ensures the admin visually verifies the physical hardware before explicitly granting it authorization via the Auth Server, effectively preventing remote phishing attacks.

The admin side of this flow runs in the authenticated page: the canned `lws-login.js` widget renders each pending device's self-reported `name` / `user_code` — strings that arrived over the **unauthenticated** device connection — into the page's DOM. The widget's render boundary therefore HTML-escapes every dynamic string it composes into markup via `window.lwsLoginEsc()` (and `encodeURIComponent()`s the `device_code` query value), so device-provided data can inject text into the approval list but never markup or script. The fence is asserted against the actually-served `lws-login.js` by the `widget-js-fence` scenario of `api-test-lws-login-bff`; if you extend the widget, keep the rule that no dynamic string reaches an `innerHTML` composition unescaped.

## Cross-Domain SSO Architecture

If `cookie-domain` sharing fails because the target application operates on an entirely distinct apex domain (e.g., `auth.warmcat.com` logging into `libwebsockets.org`), the system natively utilizes high-performance auto-submitting POSTs.
When the auth portal completes authorization and identifies a foreign target domain, it dynamically preserves the original target's path sequence and constructs a transient `<form method="POST" action="https://[foreign-domain]/[target/path]/.lws-login-sso">` containing the encrypted JWT securely inside the POST body. This explicitly scopes the interception back to the specific internal mount processing the request rather than discarding internal hierarchies.
`lws-login` intercepts all localized `/.lws-login-sso` boundaries dynamically, digests the incoming POST securely, verifies the tokens using `lws_spa`, provisions a newly scoped localized top-level cookie, and redirects cleanly back to the ultimate target securely.

The SSO boundary is closed against login CSRF: a submitted token is only honored when the request carries positive proof it originated at the configured auth server — an `Origin` header (or, for user agents that do not send one on form POSTs, a `Referer`) whose scheme, host and port match `auth-server-url`. A token arriving with neither header matchable — for example a cross-site form POST from a sandboxed iframe combined with a no-referrer policy, which suppresses both — is rejected with `403` and nothing is planted. The legitimate flow (the auth server's auto-submitting form POST) always carries one of the two headers identifying the auth server.

If a visiting client lacks the required `cookie-name`, or their validated token does not meet the `<service-name>:<min-grant-level>` threshold (and they do not hold a `*` administrative wildcard), the plugin calculates the `redirect_uri` based on the exact path they were attempting to reach.

It intercepts the connection and issues a standard `HTTP 302 Found` bouncing them dynamically to:
`%auth-server-url%?service_name=%service-name%&redirect_uri=%url_encoded_path%`

The central Auth Server portal will parse these parameters. If the user is unauthenticated, they will be prompted to log in. However, if the user successfully authenticates but strictly lacks the necessary `%service-name%` privilege assignment, the central Auth Server will cleanly deny them with an `Access Denied` status to prevent endless redirect looping between the two nodes!

## Injected Backend Headers

When a request is allowed through to the backend app mounted behind the bouncer, `lws-login` stamps the cooked, trusted authentication result onto the request as `x-lws-login-*` headers (anti-spoofed via `lws_http_zap_header()` first, so a browser cannot elevate itself). The backend reads these with no JWT or grant logic of its own. They are only trustworthy when the request actually transited the bouncer's proxy path; a backend reachable directly must not rely on them.

| Header | Value | Meaning |
|---|---|---|
| `x-lws-login-state` | stringified `enum lws_login_state` (see `lws-http.h`) | **Authoritative summary role.** Prefer this. |
| `x-lws-login-grant-level` | integer | Raw grant level the bouncer used to decide the role for this mount (e.g. `2`). Finer detail than the state. |
| `x-lws-login-sub` | string | Verified subject identity (empty when anonymous). |
| `x-lws-login-admin` | `0` or `1` | Back-compat: `1` exactly when `state == LWS_LOGIN_STATE_GLOBAL_ADMIN`. |

The `lws_login_state` values are ordered by privilege:

| Value | Name | Meaning |
|---|---|---|
| `0` | `LWS_LOGIN_STATE_ANON` | No valid JWT (only observable on mounts with `unauth-allow=1`). |
| `1` | `LWS_LOGIN_STATE_NO_GRANT` | Valid JWT, but no grant (and no `*`) for this service. |
| `2` | `LWS_LOGIN_STATE_USER` | Holds this service's grant at level `>= 1` but `< 2`, no `*`. |
| `3` | `LWS_LOGIN_STATE_APP_ADMIN` | Holds this service's grant at level `>= 2`, no `*`: **admin of this app only**, not a system-wide admin. |
| `4` | `LWS_LOGIN_STATE_GLOBAL_ADMIN` | Holds the `*` wildcard grant (the TOFU "god" account): admin of the whole system. Any `*` level `>= 1` qualifies. |

Because the values are ordered, a backend can write `state >= LWS_LOGIN_STATE_APP_ADMIN` for "any kind of admin" and `state == LWS_LOGIN_STATE_GLOBAL_ADMIN` for "system-wide only". **Do not conflate `APP_ADMIN` with `GLOBAL_ADMIN`**: an app admin can administer only the app behind this mount, whereas a global admin can administer every user and account on the system (including from the central auth-server Admin Console at `/api/admin`, which itself gates on the literal `*` grant).

## Example JSON Configuration (`lwsws`)

You can enable this bouncing natively via a standard JSON layout without compiling custom C code. This example protects a local dashboard physically sitting at `/var/www/dashboard`, demanding that connecting users hold at least a `level 2` clearance for `dashboard-service` before `lws-login` lets traffic pass.

```json
{
  "vhosts": [{
    "name": "protected.example.com",
    "port": 443,
    "mounts": [{
      "mountpoint": "/dashboard",
      "origin": "file:///var/www/dashboard",
      "default": "index.html",
      "pmo": [{
        "service-name": "dashboard-service"
      }]
    }],
    "ws-protocols": [{
      "lws-login": {
        "status": "ok",
        "auth-server-url": "https://auth.warmcat.com/login",
        "jwt-jwk": "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}",
        "cookie-name": "auth_session",
        "min-grant-level": "2",
        "unauth-allow": "0"
      }
    },
    {
      "lws_login_client": {
        "status": "ok"
      }
    }]
  }]
}
```

**The `lws_login_client` entry is required on the same vhost as `lws-login`.**  The
silent-renewal side channel is an ordinary lws client connection bound to the
interceptor's own vhost, and its callbacks are routed by protocol name.  Without
it, lws binds the side channel to the vhost's first protocol and misroutes every
client callback, so the renewal never works and the exchange bookkeeping can
dereference a freed wsi; the plugin detects this at runtime and refuses to start
the exchange with an obvious error in the log instead.

Notice that the `pmo` *(Per-Mount Option)* strictly binds the `dashboard-service` name to the `/dashboard` mount, cleanly overriding any default global values the protocol was initialized with.

## Background Token Renewal (Silent Auth)

For Single Page Apps (such as `deaddrop` or `sai`), when the JWT naturally expires, the server will correctly and instantly drop the WebSocket connection. You can seamlessly renew this session in the background without needing to forcefully redirect the user's browser, provided they still possess a valid `auth_refresh_session` cookie from the central authority.

To leverage this, ensure your HTML includes the dynamically generated helper script:
```html
<script src="lws-login.js"></script>
```

Then, you can hook the `window.lwsLoginSilentRefresh` helper directly into your WebSocket `onclose` retry handler:

```javascript
ws.onclose = async function() {
    console.log("Connection lost, attempting silent renewal...");

    // If the helper is available, silently ask the local lws-login backend
    // to proxy an sso_exchange to the authority and issue a fresh cookie
    if (typeof window.lwsLoginSilentRefresh === 'function') {
        await window.lwsLoginSilentRefresh();
    }

    // Attempt standard reconnect now that the auth_session cookie is refreshed
    connect_ws();
};
```

This functions by initiating an invisible HTTP `POST` to the localized `/.lws-login-refresh` endpoint. The `lws-login` C-plugin intercepts this, securely acts as a Backend-For-Frontend (BFF) proxy using Libwebsockets' asynchronous non-blocking client API, fetches the new token directly from the Auth Server, and sets your browser's new `auth_session` cookie. Because all of this occurs entirely over backend TLS interfaces, your frontend Javascript never directly touches or exposes the Cross-Site Request Forgery (CSRF) tokens or OAuth codes!

The same renewal side channel is also used for **cold-load silent renewal**: when a browser holding a valid `auth_refresh_session` cookie requests a protected page whose JWT has lapsed, the bouncer renews server-side and answers with a `302` back to the exact URL that was asked for — **query string included** — so app deep links (eg `sai`'s `?project=…&task=…`) survive re-login intact instead of landing the user on a shortened, unusable URL.

### CSRF sidecar self-heal

The renewal double-submit on the auth server compares the `csrf_token=` form
field against the `auth_csrf` cookie in the browser's forwarded jar — both of
which the side channel itself produces.  If the browser's jar has a valid
`auth_refresh_session` but its `auth_csrf` sidecar has been lost or expired
(they can be minted by different flows with different scopes and birthdays —
eg a native login on the auth server's own host plants an unpaired
`Domain=`-scoped refresh cookie), the BFF and the cold-load renewal simply
mint a fresh matching pair for the exchange instead of denying it.  A browser
without access to the `HttpOnly` cookies cannot reach that code, and a
cross-site form POST cannot carry the `SameSite=Lax` `auth_refresh_session`,
so the browser-side csrf cookie was not adding protection the refresh cookie
does not already provide.  On exchange success the response rotates a fresh
`auth_csrf` cookie into the browser jar, healing the underlying state; if the
refresh session is genuinely invalid the auth server still 401s and the
widget escalates as before.  Without this, a live session whose sidecar died
was classified as dead and the user's whole page was navigated to the auth
form — trashing eg an in-progress HLS playback for a split-second re-login
round trip.  These self-heal events (and any remaining denials) are logged
with the raw cookie jar at `notice`, since the affected devices usually
cannot be inspected.

### Denial observability

When an exchange is refused, both ends now say exactly why, attributed to the
wsi (so the peer is identifiable against interleaved bot traffic): the
completion log on the app side states the auth server's actual answer —
`BFF renewal denied: auth server answered HTTP 401 'Invalid session'` — or the
client-connection failure string when there was no response at all.  On the
auth server, `/api/sso_exchange` denial logs account for every presented
credential: which of `auth_session` / `auth_refresh_session` was absent, and
what happened to each same-named refresh value (`2 value(s) presented: 1
expired, 1 not in db, 0 live` — browsers legitimately hold several
`auth_refresh_session` values at once, ordered oldest-first, so resolution
walks them all rather than trusting the first).  CSRF double-submit failures
log which half was missing and the lengths, never the values themselves.
