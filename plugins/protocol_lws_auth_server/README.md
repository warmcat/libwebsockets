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
- **Single-Use Verification Pipeline**: Ephemeral registration hashes operate as one-time tokens.  A GET of the mailed `/api/verify` link only shows a page asking to confirm, since mail gateways and link scanners fetch every link in a message before the user does; the page's POST (with the `auth_csrf` double submit) is what creates the `users` row, and a replay fails the same way an invalid link does (so the TOTP secret is shown once, and exactly one set of backup codes is ever minted).  The QR graphic (`/totp_svg`) is served only for an unexpired registration that has been confirmed, and that fetch then reaps the record.
- **Decoupled SMTP Templating**: Administratively definable PVO overlays (`email-subject`, `email-body`) instantly decouple arbitrary verification alerts natively.
- **Mobile Authenticator Deep-Linking**: Implicitly wraps the generated TOTP vector graphic explicitly into a tappable `otpauth://` deep-link anchor to seamlessly trigger iOS/Android 2FA applications organically.
- **Refresh Token Support**: Supports stateful OAuth2 refresh tokens for silent session renewal, with configurable token lifetimes.  This is optional and disabled by default.

## Configuration (PVOs)

The plugin can be enabled on any vhost. Its behavior is customized using Per-Vhost Options (PVOs).

If the plugin is not set up on a vhost, because the vhost names it with no
options at all (`"lws-auth-server": {}`) or because its init failed (eg, the
key at `jwk_path` could not be generated or saved, or the database at
`db_path` could not be opened or given its schema; the reason is logged at
startup), a `callback://lws-auth-server` mount on that vhost answers every
request with `503` and its admin WebSocket upgrade is refused.

| PVO Name | Description | Example |
| --- | --- | --- |
| `db_path` | Required: The absolute path to the SQLite3 database file. If the file is missing or empty, the plugin will automatically create it and initialize the schema. | `/var/db/lws-auth.sqlite3` |
| `auth-domain` | Required: The authorizing domain context for this instance. It binds identities conceptually as `name@domain`, avoiding arbitrary collisions if tokens are exported. | `auth.warmcat.com` |
| `cookie-domain` | Optional: The specific domain name the auth cookie should be scoped to (e.g. `warmcat.com`). If unspecified, defaults to omitting the domain from the cookie. | `warmcat.com` |
| `jwk_path` | Required: Absolute path to the JSON Web Key (JWK) for JWT signing. If missing, an EC P-256 key is generated and saved here automatically. | `/var/db/lws-auth.jwk` |
| `jwt_alg` | Optional: The JWS signing algorithm to use for issued tokens. Defaults to `ES256`. An `HS*` alg needs a symmetric (`oct`) key at `jwk_path`; that key is the signing secret, so it is not published in `/.well-known/jwks.json` (which then serves an empty key set) and validators must be given it out of band.  Versions before that change wrote an `oct` key, secret included, to `<jwk_path>.pub` and served it as the JWKS: if one is still next to the key (the plugin warns at init), treat the key as disclosed, replace it and delete the `.pub`. | `RS256` |
| `cookie-name` | Optional: Name of the HTTP cookie that the server should natively emit containing the JWT payload upon successful non-OAuth2 login. Empty by default (no cookie). | `auth_token` |
| `jwt-validity-secs` | Optional: Time-to-live for the signed JWT in seconds. Defaults to `86400` (24 hours). | `3600` |
| `refresh-validity-secs` | Optional: Duration in seconds to issue stateful, database-backed refresh sessions. If set `> 0`, transparent silent renewals are natively permitted. Defaults to `0` (stateless). | `2592000` |
| `auth-log-limit` | Optional: Maximum number of recent authentication IP audit logs to retain per-identity in the database. Set to `0` to completely disable logging. Defaults to `10`. | `10` |
| `kdf-per-sec` | Optional: how many password hashes (100000 rounds of PBKDF2-SHA512, run on the event loop thread) unauthenticated logins and registrations may cause per second in total, with up to two seconds' worth in a burst.  Beyond it they are answered `503` "Too many attempts" until the budget refills, so a flood cannot stall the server.  Defaults to `8`. | `8` |
| `registration_ui` | Optional. If `1` or `true`, exposes public web UI endpoints. Useful for general signups. Defaults to `0` or false. | `true` |
| `email-from` | Optional: The sender email address for outgoing SMTP verification emails. Defaults to `noreply@warmcat.com`. | `noreply@example.com` |
| `email-subject` | Optional: The subject line for the verification email. Defaults to `Complete your registration`. | `Please confirm your ExampleApp account` |
| `email-body` | Optional: The template string for the email body. It must include exactly one `%s` token which will be dynamically replaced by the confirmation URL. | `Click here:\n\n%s` |
| `trusted-proxies` | Optional: comma-separated addresses of reverse proxies whose `X-Forwarded-For` is believed.  When the socket peer is one of them, the strikes, bans and audit rows are keyed on the last address in `X-Forwarded-For` (the one that proxy appended), which must be numeric; from any other peer the header is ignored.  Empty by default: the socket peer is the client. | `127.0.0.1,::1` |
| `feed-secret` | Optional: enables the auth feed (see [The auth feed](#the-auth-feed)), and is the secret its subscribers must present: 32 to 128 printable characters, or, if it starts with `/`, the path of a file holding them.  Without it, the feed refuses every subscriber. | `/etc/lwsws/auth-feed.secret` |
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
        "email-body": "Hello,\n\nPlease verify your account by clicking the following link:\n\n%s\n\nThanks!",
        "feed-secret": "/etc/lwsws/auth-feed.secret"
      },
      "lws-auth-feed": {
        "status": "ok"
      }
    }]
  }]
}
```

## The auth feed

`lws-login`, the bouncer guarding the other vhosts, needs to know when a token that verifies no longer stands: the account's session epoch moved, a device was revoked, the grants changed.  Rather than reading this plugin's database, which ties it to this host, it subscribes to the `lws-auth-feed` ws protocol this plugin also provides (see `../protocol_lws_login/protocol_lws_login.md`).

Enable it by listing `lws-auth-feed` in the vhost's `ws-protocols` beside `lws-auth-server`, and giving `lws-auth-server` a `feed-secret`.  A subscriber connects with the `lws-auth-feed` subprotocol and `Authorization: Bearer <feed-secret>`; anything else is refused, and logged with its address.

Each subscriber is sent a snapshot, one JSON message, when it connects, and again whenever it would change.  It holds every account's uid and session epoch, every grant, every device token not revoked, every oauth client's `redirect_uris`, and the public half of the signing key (a symmetric key has none, and is left out).  The schema is in `plugins/lws-auth-feed.h`, shared with `lws-login`.

Once a second, the plugin looks at whether the database changed, by its own writes or by another connection's (`PRAGMA data_version`), eg an admin with the `sqlite3` shell.  If it did, it builds a snapshot and sends it only if it differs from the last one, so the many writes that don't touch it, like logins and the audit log, send nothing.  So a revocation reaches every `lws-login` within about a second.

The snapshot carries every account's uid and grants, so keep `feed-secret` as secret as the database: anyone with it can read them.  It carries no password hashes, TOTP secrets, emails or session ids.

## Initial Admin Configuration

By default, the `registration_ui` option is disabled (`false` or `0`) to prevent public sign-ups in purely administrative environments.

However, if the `users` table in your SQLite database is completely empty, the system will temporarily permit registration of your initial administrative user through the normal web UI. **This bootstrap is intentionally not restricted to any source IP** — once the database is empty, registration is accepted from any interface so that the very first account can be created. (Restrict it at the network layer if you need to.)

The bootstrap registration uses the same code path as ordinary registration: the credentials are staged in the `registrations` table and a verification link is emailed to the address given. **Email delivery must be working** (see the `lws-smtp-client` PVOs above) for the TOFU administrator to receive and click that link; if no SMTP relay is reachable the link never arrives and the account is never promoted into `users`. In other words: TOFU bootstrap depends on the vhost's SMTP client reaching a relay, exactly like every other email-verifying flow.

Mail goes out through the vhost's own lws SMTP client (`lws_smtpc_vhost()`, see `READMEs/README.smtp-client.md`), which the `lws-smtp-client` PVOs configure; with none it uses a plaintext relay on `127.0.0.1:25`.  How each mail went, including any the relay refused, is logged by it.

The verification and recovery links this mail carries are bearer secrets for the account, so a remote relay should be reached with `"smtp-tls": "implicit"` or `"starttls"`, when its certificate is checked against `smtp-host` (or `smtp-tls-host`, if the certificate is for a different name than the relay is reached by).  `"smtp-tls-skip-hostname-check": "1"` turns the name check off and is only for a relay on a path nothing else can get onto.

### The TOFU "God" Grant
The very first user promoted into an empty `users` table (i.e. the one whose verification link is consumed first) is automatically provisioned with a literal `*` wildcard grant. This specialized grant establishes total, unrestricted administrative rights (or "god mode") across all applications verifying against this system.

### Web Administration Dashboard
Users holding the `*` wildcard grant can gain access to the built-in JSON Web UI natively mounted at `/admin` **(Note: This path is relative to wherever you mounted the `callback://lws-auth-server` endpoint for the API itself, e.g. `https://auth.warmcat.com/api/admin` or `https://auth.warmcat.com/auth/api/admin`)**! This dashboard utilizes a bi-directional WebSocket backend to allow you to easily edit user grants, list accounts, or purge identities without manually writing raw SQL queries.  *(Note: For security reasons, the underlying system intrinsically prohibits anyone from deleting identities holding the `*` wildcard through the `/admin` UI to prevent irreversible lockout scenarios).*

The dashboard's WebSocket is only accepted from a page on the auth vhost's own
origin (its `Origin` must be `https://` plus the host the request was sent
to), since `SameSite=Lax` does not stop a page on a same-site host (a sibling
subdomain, or the apps on the parent domain) from sending the session cookie
with an upgrade.  It is authorised by the session at the upgrade, and that
session is checked again before every operation, before every message it
sends and every 10s while idle: once the session has expired or been revoked
(a password reset, the account deleted), or the account no longer holds `*`
in the grants table, the socket is closed with status 1008 and the page
reloads.

Editing an account's grants moves that account's session epoch on, so the
tokens it holds, which carry the old grants in their `grants` claim, stop
being accepted at once rather than when they expire; with refresh sessions
enabled the next renewal mints one with the grants as edited, otherwise the
user logs in again.  This includes editing your own account from the
dashboard, which ends your own session.

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
`/api/sso_exchange`, `POST /api/logout`, `POST /api/verify`) requires a `csrf_token` form field
matching the `__Host-auth_csrf` cookie, compared with `lws_timingsafe_bcmp()`.

The `__Host-` prefix matters: a browser only accepts a cookie of that name
when it is `Secure`, `Path=/` and has no `Domain`, so only this host can set
it.  A bare-named cookie could be planted by any host under the same
registrable domain (`Domain=<parent>`, with a longer `Path` so it is sent
first), and the double submit then only proved the attacker knew the value
they planted.  The bare `auth_csrf` is no longer read, only cleared at logout.

The double submit is backed by an Origin check on every `/api/` POST
(`lws_http_origin_check()`): a POST whose `Origin` is not this vhost's own
`https://<host>` (or `http://<host>` when the vhost is not itself doing the
TLS) is refused with `403` before anything else happens.  `SameSite=Lax` does
not stop a same-site sibling page from posting with the session cookie, but
the browser names that page in `Origin`.  A POST with no `Origin` at all is
accepted, since browsers always send one on a POST: those come from
server-side clients such as `lws-login`'s renewal or `lws-oauth2-client`'s
`/api/token`, which carry no ambient browser credential.  Behind a reverse
proxy, the proxy must pass the browser's `Host` through unchanged for this to
match.

That cookie is `HttpOnly`, so the page cannot read it back out of
`document.cookie`: the server hands the token to the page separately, in the
`/api/status` JSON for `index.html`, and in a `data-csrf` attribute on the
button for the `/api/device` page.  If you write your own front end, take the
token from one of those and never from `document.cookie` — and do not make the
cookie readable to fix it, since that is what the double submit is proving.

A presented csrf cookie is only adopted if it has the exact
32-lowercase-hex shape the server is the only setter of; anything else is
replaced with a fresh token, so a value the server did not mint cannot reach
the JSON or the HTML attribute the token is composed into.

### Token purpose

Every session and device JWT the server issues carries `"pur":"sso"`
(`LWS_JWT_AUTH_PURPOSE_SSO`), and the server and the in-tree relying parties
(lws-login, deaddrop, hls, oauth-preauth, the dnssec monitor) accept only
tokens carrying it, via `lws_jwt_auth_create_via_info()`.  So another kind of
token signed with the same key, eg an interceptor's visit cookie, is never
taken for a session.  Tokens issued before the claim was added are refused:
users log in again, and device tokens have to be issued again.  A key shared
with other token minters is only safe while each of them signs its own
purpose; see `READMEs/README.jwt.md`.

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

Either reaches the `lws-login` bouncers on other vhosts through the auth feed
within about a second.

### What one account can make the server store

Every `/api/authorize` by a logged-in user (and every delegate login) issues
an `oauth_codes` row living 60 s, and every `/api/token` and login mints an
`auth_sessions` refresh row living `refresh-validity-secs`.  However many an
account asks for, it keeps at most 16 codes and 64 refresh sessions: its
expired rows are reaped first, and then issuing one more evicts its oldest
(the soonest to expire).  So the newest always works; what gives way is the
code of a login abandoned a while ago, or the refresh session of the device
that logged in longest ago, which then has to log in again.  The reaping and
the insert of one request are one transaction, so one commit.

Expired rows of every table that has them (`oauth_codes`, `auth_sessions`,
`device_codes`, `password_recovery`, `registrations`) are also swept every
30 s, at most 256 rows per table a pass (a pass that finds more comes back a
second later), and all of them at startup.

### Rate limiting is keyed on the client address

Strikes, bans and the `auth_log` rows use the socket peer, unless the peer is
one of the `trusted-proxies`, in which case they use the client address that
proxy appended to `X-Forwarded-For`.  Behind a reverse proxy you must list it
there, or the proxy is the client as far as the limiter is concerned:

- a proxy on the same host presents a local address, and local addresses are
  deliberately never struck (they are our own in-process API clients), so the
  login/registration throttles become no-ops; and
- a proxy on another host means one abusive client's fifth failure bans the
  proxy address, ie every user, for 24 hours.

Only the last `X-Forwarded-For` entry is used, since the trusted proxy wrote
it; earlier entries came from the client or hops you do not trust, and their
length does not matter.  A proxy that is not listed gets no say, so a forged
header from an ordinary client changes nothing.

When a trusted proxy forwards a request, the forwarded address is the only
answer: if the last entry is not a numeric address, the request is refused
with `400` rather than being keyed on the proxy itself, which would let the
client either escape the limits (a local proxy's address is never struck) or
get the proxy, and so every user, banned.  A request from a trusted proxy
with no `X-Forwarded-For` at all is taken to be from the proxy's host itself,
as the in-process API clients are.

Strikes and bans are kept per host, not per address: an IPv4 address, but an
IPv6 client's whole /64, since one host commands all of it and could
otherwise start again with no strikes from a fresh address every attempt.
Audit rows still record the full address.

Failures are also counted per account: after eight wrong passwords,
authenticator codes or backup codes for one account (one forgiven every
120 s, like the address strikes) its logins are refused with `503` until
they decay, whatever addresses they come from.  That is a nuisance an
attacker can inflict on a known account name; it is the price of a guessing
campaign spread over many addresses no longer getting a free run.  Names
that are not accounts are counted the same way, so the brake engaging does
not tell anyone which names exist, but separately: failures for made-up
names cannot crowd a real account's count out of memory.

Every login that makes the server hash a password and does not end in a
completed login costs its host a strike: a wrong password or code, but also a
right password sent without the authenticator code (the first step of a
second factor login), or one with a redirect that is refused.  A completed
login forgives the strikes of the account that logged in, but not those of
its host, which only decay: otherwise a host holding any one account could
clear its own brake between guesses at others, or spend the whole hashing
budget below at no cost to itself.

The first step of a second factor login, the right password without the
code, holds its strike aside instead of on the host: it is dropped when the
second step completes the login from the same host within 120 s, and lands
on the host, like any other strike, only if none does.  So people logging in
with a second factor from one host or /64, even at the same moment, neither
brake nor ban it among themselves.  A host repeating first steps without
completing them is struck as before: a repeat for the same account lands the
held strike and strikes for itself (one completed login gives one of those
back), and a host holds at most three strikes aside at a time, first steps
for more accounts striking it at once.

Behind all of that, the password hashing unauthenticated requests can cause
is budgeted as a whole (`kdf-per-sec`), so however the requests are spread
across hosts and names, they cannot keep the event loop busy hashing.

### Password policy

Registration and password reset both require at least 8 characters.  That is a
floor, not a policy — put a real one in front of it if you need one.

### Known gaps

- `/logout` still accepts a `GET`, kept because `lws-login` links a top-level
  navigation at it to log the user out of the app and the auth server
  together.  A cross-site navigation or embedding of it is refused with `403`
  on the browser's `Sec-Fetch-Site` (same-site, same-origin and typed-in
  navigations go through), so a third-party page can no longer force a
  logout from any browser that sends the header (all current ones); a browser
  too old to send it is taken at its word.  The session teardown the UI
  itself uses is `POST /api/logout` with the csrf double-submit
  (`assets/auth.js`).
- `/api/register` answers `200` "if the address is free, a verification email
  has been sent" whether the address is free, registered or pending, so it no
  longer enumerates accounts; a registered or pending address still costs a
  strike.
- The 100000-round PBKDF2 runs inline on the event loop thread.  The limiter is
  applied before it, per host, per account and in total (`kdf-per-sec`), but
  it still belongs on the threadpool, with the login response completed from
  the worker.
- The admin WebSocket accepts `{"op":"device_revoke","uid":N,"client_id":"<device_id>"}`
  to revoke one device token; the admin page does not offer it yet.
