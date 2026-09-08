# lws-auth-server

This is a lightweight authentication server implemented as a libwebsockets protocol plugin (`protocol_lws_auth_server`).
It acts as a central identity provider and issues time-limited JWTs to outsource authentication from other services.

## Features

- **SQLite Backend**: Centrally stores identity information (using `lws_struct`).
- **Flexible Metadata**: Maps decoupled user identities to services and specific grant levels.
- **Base32 & TOTP**: Integrated HMAC-SHA1 to natively verify 6-digit authenticator codes.
- **OAuth2 Authorization Code Grant**: Natively supports full stateful OAuth2 flows, including `/authorize` endpoints, short-lived session cookies, PKCE validation (SHA-256 base64url), and `/token` exchange for JWT emission.
- **JWT Issuance**: Built-in `lws_jose` and `lws-genjwt` to issue cryptographically signed JWTs.
- **Double Submit Cookie CSRF**: Natively protects the SPA API endpoints via a stateless `csrf_token` form payload and transparent `HttpOnly` validation pairing.
- **Autonomous IP Rate Limiting**: Employs an internal LRU cache to natively track authentication strikes, issuing global 24-hour network bans dynamically to throttle arbitrary SMTP execution scripts or registration bot floods.
- **Single-Use Verification Pipeline**: Ephemeral registration hashes operate as one-time read tokens: the first `/verify` visit is the one that creates the `users` row, and a replay of the link fails the same way an invalid one does (so the TOTP secret is shown once, and exactly one set of backup codes is ever minted).  The QR graphic fetch (`/totp_svg`) then reaps the record.
- **Decoupled SMTP Templating**: Administratively definable PVO overlays (`email-subject`, `email-body`) instantly decouple arbitrary verification alerts natively.
- **Mobile Authenticator Deep-Linking**: Implicitly wraps the generated TOTP vector graphic explicitly into a tappable `otpauth://` deep-link anchor to seamlessly trigger iOS/Android 2FA applications organically.
- **Refresh Token Support**: Supports stateful OAuth2 refresh tokens for silent session renewal, with configurable token lifetimes.  This is optional and disabled by default.

## Configuration (PVOs)

The plugin can be enabled on any vhost. Its behavior is customized using Per-Vhost Options (PVOs).

| PVO Name | Description | Example |
| --- | --- | --- |
| `db_path` | Required: The absolute path to the SQLite3 database file. If the file is missing or empty, the plugin will automatically create it and initialize the schema. | `/var/db/lws-auth.sqlite3` |
| `auth-domain` | Required: The authorizing domain context for this instance. It binds identities conceptually as `name@domain`, avoiding arbitrary collisions if tokens are exported. | `auth.warmcat.com` |
| `cookie-domain` | Optional: The specific domain name the auth cookie should be scoped to (e.g. `warmcat.com`). If unspecified, defaults to omitting the domain from the cookie. | `warmcat.com` |
| `jwk_path` | Required: Absolute path to the JSON Web Key (JWK) for JWT signing. If missing, an EC P-256 key is generated and saved here automatically. | `/var/db/lws-auth.jwk` |
| `jwt_alg` | Optional: The JWS signing algorithm to use for issued tokens. Defaults to `ES256`. | `RS256` |
| `cookie-name` | Optional: Name of the HTTP cookie that the server should natively emit containing the JWT payload upon successful non-OAuth2 login. Empty by default (no cookie). | `auth_token` |
| `jwt-validity-secs` | Optional: Time-to-live for the signed JWT in seconds. Defaults to `86400` (24 hours). | `3600` |
| `refresh-validity-secs` | Optional: Duration in seconds to issue stateful, database-backed refresh sessions. If set `> 0`, transparent silent renewals are natively permitted. Defaults to `0` (stateless). | `2592000` |
| `auth-log-limit` | Optional: Maximum number of recent authentication IP audit logs to retain per-identity in the database. Set to `0` to completely disable logging. Defaults to `10`. | `10` |
| `registration_ui` | Optional. If `1` or `true`, exposes public web UI endpoints. Useful for general signups. Defaults to `0` or false. | `true` |
| `email-from` | Optional: The sender email address for outgoing SMTP verification emails. Defaults to `noreply@warmcat.com`. | `noreply@example.com` |
| `email-subject` | Optional: The subject line for the verification email. Defaults to `Complete your registration`. | `Please confirm your ExampleApp account` |
| `email-body` | Optional: The template string for the email body. It must include exactly one `%s` token which will be dynamically replaced by the confirmation URL. | `Click here:\n\n%s` |
| `ui-title` | Optional: Overrides the default string array "Authentication Server" natively displayed on front-end portals. | `Internal SSO Portal` |
| `ui-subtitle` | Optional: Overrides the default "Give your credentials to continue" messaging. | `Strictly authorized personnel only` |
| `ui-new-network` | Optional: Overrides the "New to the network?" prompt for registration links. | `Access Required?` |
| `ui-css` | Optional: Explicit path mapping to serve bespoke UI customization CSS. When defined alongside `LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE`, the system gracefully expands the underlying `style-src` CSP to permit local stylesheet injections safely. | `/admin.css` |

## Example JSON Configuration

You can enable this plugin on a vhost without writing any C code at all by supplying a standard JSON configuration to `lwsws` or any LWS server parsing `lejp-conf`.

This example mounts the front-end UI at `/` (the assets dir with `index.html` as the default) and configures the `lws-auth-server` protocol with its required PVOs.  Note the UI must live at the root of the auth vhost: `/api/authorize` redirects anonymous inbound OAuth2 logins to `/?client_id=...` (with the OAuth2 params preserved in the query for `auth.js` to replay after login), the same URL shape `lws-login`'s `login_url` convention uses.

```json
{
  "vhosts": [{
    "name": "auth.warmcat.com",
    "port": 443,
    "mounts": [{
      "mountpoint": "/api",
      "origin": "callback://lws-auth-server"
    }, {
      "mountpoint": "/",
      "origin": "file://_lws_ddir_/libwebsockets-test-server/auth",
      "default": "index.html",
      "headers": [{
        "Content-Security-Policy": "default-src 'none'; img-src 'self' data: ; script-src 'self'; font-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://libwebsockets.org;"
      }]
    }],
    "ws-protocols": [{
      "lws-smtp-client": {
        "status": "ok",
        "smtp-host": "127.0.0.1",
        "smtp-port": "25",
        "smtp-tls": "none"
      },
      "lws-auth-server": {
        "status": "ok",
        "db_path": "/var/db/lws-auth.sqlite3",
        "auth-domain": "auth.warmcat.com",
        "jwk_path": "/var/db/lws-auth.jwk",
        "jwt_alg": "ES256",
        "jwt-validity-secs": "900",
        "refresh-validity-secs": "2592000",
        "auth-log-limit": "10",
        "registration_ui": "1",
        "email-from": "admin@auth.warmcat.com",
        "email-subject": "Welcome! Please verify",
        "email-body": "Hello,\n\nPlease verify your account by clicking the following link:\n\n%s\n\nThanks!"
      }
    }]
  }]
}
```

## Initial Admin Configuration

By default, the `registration_ui` option is disabled (`false` or `0`) to prevent public sign-ups in purely administrative environments.

However, if the `users` table in your SQLite database is completely empty, the system will temporarily permit registration of your initial administrative user through the normal web UI. **This bootstrap is intentionally not restricted to any source IP** — once the database is empty, registration is accepted from any interface so that the very first account can be created. (Restrict it at the network layer if you need to.)

The bootstrap registration uses the same code path as ordinary registration: the credentials are staged in the `registrations` table and a verification link is emailed to the address given. **Email delivery must be working** (see the `lws-smtp-client` PVOs above) for the TOFU administrator to receive and click that link; if no SMTP relay is reachable the link never arrives and the account is never promoted into `users`. In other words: TOFU bootstrap depends on the SMTP client plugin being co-mounted and correctly configured, exactly like every other email-verifying flow.

### The TOFU "God" Grant
The very first user promoted into an empty `users` table (i.e. the one whose verification link is consumed first) is automatically provisioned with a literal `*` wildcard grant. This specialized grant establishes total, unrestricted administrative rights (or "god mode") across all applications verifying against this system.

### Web Administration Dashboard
Users holding the `*` wildcard grant can gain access to the built-in JSON Web UI natively mounted at `/admin` **(Note: This path is relative to wherever you mounted the `callback://lws-auth-server` endpoint for the API itself, e.g. `https://auth.warmcat.com/api/admin` or `https://auth.warmcat.com/auth/api/admin`)**! This dashboard utilizes a bi-directional WebSocket backend to allow you to easily edit user grants, list accounts, or purge identities without manually writing raw SQL queries.  *(Note: For security reasons, the underlying system intrinsically prohibits anyone from deleting identities holding the `*` wildcard through the `/admin` UI to prevent irreversible lockout scenarios).*

### Complete Server Wipe Recovery
If you catastrophically lose access to the single TOFU administrator account or severely corrupt the grants table to the point of a hard lockout, you can safely trigger a pristine reboot. Stop the server, delete the SQLite `db_path` file entirely (and optionally, the `jwk_path` to forcibly rotate all deployed cryptographic signatures downstream), and restart `libwebsockets`. A brand-new database schema will be generated, and the TOFU bootstrap registration will be accepted again from any interface — provided email delivery is functional so you can complete the verification step.

## Database Schema

The plugin maintains several core tables natively initialized within SQLite:
1. `users`: Stores core credentials (`uid`, `username`, `password_hash`, `totp_secret`).
2. `services` & `grants`: Inventory of consuming endpoints/services and join tables that give a `uid` a specific `grant_level` for a given `service_id`.
3. `oauth_clients`: Stores registered OAuth2 consumers (`client_id`, `client_secret_hash`, `redirect_uris`, `name`).
4. `oauth_codes`: Tracks ephemeral authorization codes during the OAuth2 exchange, including structural PKCE challenges (`code`, `client_id`, `uid`, `redirect_uri`, `expires`, `code_challenge`, `code_challenge_method`).
5. `auth_sessions`: Maintains short-lived stateless HttpOnly cookies allowing transparent redirect resolutions (`session_id`, `uid`, `expires`).
6. `devices`: One row per paired device-flow credential (`device_id`, `uid`, `name`, `created`); deleting a row revokes that device's token.

`users.session_epoch` and `users.totp_last` are added automatically by `ALTER TABLE` when an older database is opened.

## Front-end Assets

We serve a strict CSP-compliant UI from `./assets` mapped into this plugin.
There are no inline `<script>` blocks, no inline event handlers and no inline
`style=` attributes anywhere in it, so `script-src 'self'; style-src 'self'`
(no `'unsafe-inline'`) holds.

Two directives in the example policy above are coupled to how this plugin
works, and are worth understanding before you copy it:

- **`form-action` must list every `lws-login` app origin.**  SSO completion is
  by design a *cross-origin* form POST from this vhost to
  `https://<app>/.lws-login-sso` carrying the session JWT in the body, and
  `form-action` is exactly the directive that restricts where a form may be
  submitted.  Under a bare `form-action 'self'` — which is what the built-in
  `LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE` policy
  emits — the browser refuses that submission, and it does so silently as far
  as the page is concerned: `form.submit()` returns normally.  `auth.js`
  listens for the `securitypolicyviolation` event and shows an error rather
  than leaving a dead login page, but the login still cannot complete.  Add
  each app's origin (`https://app.example.com`) to `form-action` on this
  vhost.  Do **not** answer this with `form-action *` or by dropping the
  `headers` block: that also drops `script-src 'self'`, which is the
  containment the admin and login DOM relies on.
- **`connect-src 'self'` is deliberate.**  `ws:` / `wss:` in a source list are
  *scheme* sources: they match every host, so they would let any injected
  script open a WebSocket to an arbitrary origin and stream the admin
  console's user list, grants and CSRF token out.  The assets do not need
  them — `auth.js` fetches same-origin paths and `admin.js` builds its socket
  from `window.location.host`, and a same-origin `ws://`/`wss://` URL already
  matches `'self'`.  Only widen this if your own pages talk to a third-party
  WebSocket endpoint.

## Security notes for operators

### Put the CSP on the API mount too

The example above attaches `Content-Security-Policy` to the `/` file mount
only.  The plugin *also* serves HTML of its own from the
`callback://lws-auth-server` mount — `/api/admin`, `/api/device` and the
`/api/verify` confirmation page — and those get no CSP at all unless you add a
`headers` block to that mount as well.  Do that: it is defence in depth behind
the plugin's own output escaping.

### The CSRF double submit

Every state-changing endpoint (`/api/login`, `/api/register`,
`/api/forgot_password`, `/api/reset_password`, `/api/device_approve`,
`/api/sso_exchange`, `POST /api/logout`) requires a `csrf_token` form field
matching the `auth_csrf` cookie, compared with `lws_timingsafe_bcmp()`.

That cookie is `HttpOnly`, so the page cannot read it back out of
`document.cookie`: the server hands the token to the page separately, in the
`/api/status` JSON for `index.html`, and in a `data-csrf` attribute on the
button for the `/api/device` page.  If you write your own front end, take the
token from one of those and never from `document.cookie` — and do not make the
cookie readable to fix it, since that is what the double submit is proving.

A presented `auth_csrf` cookie is only adopted if it has the exact
32-lowercase-hex shape the server is the only setter of; anything else is
replaced with a fresh token, so a cookie planted by a sibling host cannot
reach the JSON or the HTML attribute the token is composed into.

### Session revocation

Every issued JWT carries the user's `session_epoch` as the `sec` claim, and
every session resolution in the plugin rejects a token whose `sec` no longer
matches the `users` row.  So `UPDATE users SET session_epoch = session_epoch+1`
(which `/api/reset_password` does) immediately invalidates every outstanding
JWT for that user, as well as their `auth_sessions` refresh rows.

Device-flow tokens are long-lived (ten years) but are now also checked against
the `devices` table on every use: `DELETE FROM devices WHERE device_id = ...`
revokes one device without touching the user's other sessions.  There is no
admin UI for that yet — do it with `sqlite3` on `db_path`.

### Rate limiting is keyed on the transport peer address

Strikes, bans and the `auth_log` rows all use the *socket* peer.  Behind a
reverse proxy that is the proxy, not the user, which means:

- a proxy on the same host presents a local address, and local addresses are
  deliberately never struck (they are our own in-process API clients), so the
  login/registration throttles become no-ops; and
- a proxy on another host means one abusive client's fifth failure bans the
  proxy address, ie every user, for 24 hours.

**Terminate TLS and serve this vhost directly**, or restrict it at the network
layer.  Consuming a forwarded client address safely needs a trusted-proxy
configuration this plugin does not have yet.

### Password policy

Registration and password reset both require at least 8 characters.  That is a
floor, not a policy — put a real one in front of it if you need one.

### Known gaps

- `/api/logout` still accepts a `GET`, which mutates server-side session state
  with no CSRF token, so a third-party page can force a logout by navigating
  the victim at it (the session cookies are `SameSite=Lax`, which a top-level
  navigation carries; a subresource `GET` does not).  The effect is a nuisance
  denial of service against one user, not privilege escalation.  The `GET`
  form is kept because `lws-login` links a top-level navigation at it to log
  the user out of the app and the auth server together.  The session teardown
  the UI itself uses is now `POST /api/logout` with the `auth_csrf`
  double-submit (`assets/auth.js`), and the CSRF-free `GET
  /api/status?destroy=` it used to call has been removed.
- `/api/register` answers `409` distinguishably for an already-registered
  address and for one with a verification pending, which enumerates accounts.
  Collapsing them to a single always-`200` "if the address is free you will
  receive a verification email" answer is the real fix and changes the
  registration UX.
- The 100000-round PBKDF2 runs inline on the event loop thread.  The limiter is
  now applied before it, but it still belongs on the threadpool.
