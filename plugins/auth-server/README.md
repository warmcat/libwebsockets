# lws-auth-server

This is a lightweight authentication server implemented as a libwebsockets protocol plugin (`protocol_lws_auth_server`).
It acts as a central identity provider and issues time-limited JWTs to outsource authentication from other services.

## Features

- **SQLite Backend**: Centrally stores identity information (using `lws_struct`).
- **Flexible Metadata**: Maps decoupled user identities to services and specific grant levels.
- **Base32 & TOTP**: Integrated HMAC-SHA1 to natively verify 6-digit authenticator codes.
- **JWT Issuance**: Built-in `lws_jose` and `lws-genjwt` to issue cryptographically signed JWTs.

## Configuration (PVOs)

The plugin can be enabled on any vhost. Its behavior is customized using Per-Vhost Options (PVOs).

| PVO Name | Description | Example |
| --- | --- | --- |
| `db_path` | Required: The absolute path to the SQLite3 database file. If the file is missing or empty, the plugin will automatically create it and initialize the schema. | `/var/db/lws-auth.sqlite3` |
| `auth_domain` | Required: The authorizing domain context for this instance. It binds identities conceptually as `name@domain`, avoiding arbitrary collisions if tokens are exported. | `auth.warmcat.com` |
| `jwk_path` | Required: Absolute path to the JSON Web Key (JWK) for JWT signing. If missing, an EC P-256 key is generated and saved here automatically. | `/var/db/lws-auth.jwk` |
| `jwt_alg` | Optional: The JWS signing algorithm to use for issued tokens. Defaults to `ES256`. | `RS256` |
| `registration_ui` | Optional. If `1` or `true`, exposes public web UI endpoints. Useful for general signups. Defaults to `0` or false. | `true` |
| `email-from` | Optional: The sender email address for outgoing SMTP verification emails. Defaults to `noreply@warmcat.com`. | `noreply@example.com` |
| `email-subject` | Optional: The subject line for the verification email. Defaults to `Complete your registration`. | `Please confirm your ExampleApp account` |
| `email-body` | Optional: The template string for the email body. It must include exactly one `%s` token which will be dynamically replaced by the confirmation URL. | `Click here:\n\n%s` |

## Example JSON Configuration

You can enable this plugin on a vhost without writing any C code at all by supplying a standard JSON configuration to `lwsws` or any LWS server parsing `lejp-conf`.

This example mounts the front-end UI at `/auth` and configures the `lws-auth-server` protocol with its required PVOs:

```json
{
  "vhosts": [{
    "name": "auth.warmcat.com",
    "port": 443,
    "mounts": [{
      "mountpoint": "/auth/api",
      "origin": "callback://lws-auth-server"
    }, {
      "mountpoint": "/auth",
      "origin": "file:///usr/local/share/libwebsockets-test-server/auth",
      "default": "index.html"
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

The first user created via this localhost bootstrap method is automatically granted full admin privileges (`grant_level` 2) for the `auth_server` service.

## Database Schema

The plugin maintains three main tables:
1. `users`: Stores core credentials (`uid`, `username`, `password_hash`, `totp_secret`).
2. `services`: An inventory of consuming endpoints/services (`service_id`, `name`).
3. `grants`: A join table that gives `uid` a specific `grant_level` for a given `service_id`.

## Front-end Assets

We serve a strict CSP-compliant UI from `./assets` mapped into this plugin.
