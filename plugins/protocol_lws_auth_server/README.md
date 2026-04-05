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
- **Single-Use Verification Pipeline**: Ephemeral registration hashes securely operate as absolute one-time read tokens for extracting the generated TOTP graphics (`/totp_svg`), passively reaping unused records natively.
- **Decoupled SMTP Templating**: Administratively definable PVO overlays (`email-subject`, `email-body`) instantly decouple arbitrary verification alerts natively.
- **Mobile Authenticator Deep-Linking**: Implicitly wraps the generated TOTP vector graphic explicitly into a tappable `otpauth://` deep-link anchor to seamlessly trigger iOS/Android 2FA applications organically.
- **Refresh Token Support**: Supports stateful OAuth2 refresh tokens for silent session renewal, with configurable token lifetimes.  This is optional and disabled by default.

## Configuration (PVOs)

The plugin can be enabled on any vhost. Its behavior is customized using Per-Vhost Options (PVOs).

| PVO Name | Description | Example |
| --- | --- | --- |
| `db_path` | Required: The absolute path to the SQLite3 database file. If the file is missing or empty, the plugin will automatically create it and initialize the schema. | `/var/db/lws-auth.sqlite3` |
| `auth_domain` | Required: The authorizing domain context for this instance. It binds identities conceptually as `name@domain`, avoiding arbitrary collisions if tokens are exported. | `auth.warmcat.com` |
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

This example mounts the front-end UI at `/auth` and configures the `lws-auth-server` protocol with its required PVOs:

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
        "Content-Security-Policy": "default-src 'none'; img-src 'self' data: ; script-src 'self'; font-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://libwebsockets.org;"
      }]
    }],
    "ws-protocols": [{
      "lws-smtp-client": {
        "status": "ok"
      },
      "lws-auth-server": {
        "status": "ok",
        "db_path": "/var/db/lws-auth.sqlite3",
        "auth_domain": "auth.warmcat.com",
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

However, if the `users` table in your SQLite database is completely empty, the system will temporarily permit registration of your initial administrative user through the normal web UI **if and only if** you are connecting from localhost (`127.0.0.1`, `::1`, or `localhost`) or an unroutable private LAN address (e.g. `10.x.x.x`, `192.168.x.x`).

### The TOFU "God" Grant
The very first user created via this localhost bootstrap method is automatically provisioned with a literal `*` wildcard grant. This specialized grant establishes total, unrestricted administrative rights (or "god mode") across all applications verifying against this system.

### Web Administration Dashboard
Users holding the `*` wildcard grant can gain access to the built-in JSON Web UI natively mounted at `/admin` **(Note: This path is relative to wherever you mounted the `callback://lws-auth-server` endpoint for the API itself, e.g. `https://auth.warmcat.com/api/admin` or `https://auth.warmcat.com/auth/api/admin`)**! This dashboard utilizes a bi-directional WebSocket backend to allow you to easily edit user grants, list accounts, or purge identities without manually writing raw SQL queries.  *(Note: For security reasons, the underlying system intrinsically prohibits anyone from deleting identities holding the `*` wildcard through the `/admin` UI to prevent irreversible lockout scenarios).*

### Complete Server Wipe Recovery
If you catastrophically lose access to the single TOFU administrator account or severely corrupt the grants table to the point of a hard lockout, you can safely trigger a pristine reboot. Stop the server, delete the SQLite `db_path` file entirely (and optionally, the `jwk_path` to forcibly rotate all deployed cryptographic signatures downstream), and restart `libwebsockets`. A brand-new database schema will be generated, and the TOFU bootstrap portal will re-open for your IP natively.

## Database Schema

The plugin maintains several core tables natively initialized within SQLite:
1. `users`: Stores core credentials (`uid`, `username`, `password_hash`, `totp_secret`).
2. `services` & `grants`: Inventory of consuming endpoints/services and join tables that give a `uid` a specific `grant_level` for a given `service_id`.
3. `oauth_clients`: Stores registered OAuth2 consumers (`client_id`, `client_secret_hash`, `redirect_uris`, `name`).
4. `oauth_codes`: Tracks ephemeral authorization codes during the OAuth2 exchange, including structural PKCE challenges (`code`, `client_id`, `uid`, `redirect_uri`, `expires`, `code_challenge`, `code_challenge_method`).
5. `auth_sessions`: Maintains short-lived stateless HttpOnly cookies allowing transparent redirect resolutions (`session_id`, `uid`, `expires`).

## Front-end Assets

We serve a strict CSP-compliant UI from `./assets` mapped into this plugin.
