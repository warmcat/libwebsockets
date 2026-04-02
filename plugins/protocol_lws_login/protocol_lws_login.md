# lws-login / JWT Auth Bouncer

## Introduction

The `lws-login` plugin is a mount-based interceptor handler that securely guards pages by explicitly requiring a verified JSON Web Token (JWT) session.

Instead of maintaining its own database, it acts as a lightweight, proactive **bouncer**, completely reliant on the core `lws_jwt_auth` helper API. Unauthenticated requests—or requests with a valid JWT but lacking the required `grants` privileges—are swiftly intercepted and redirected via HTTP 302 to a central Auth Server portal matching the configured PVOs. Once a user procures a valid session cookie from the Auth Server, the bouncer transparently allows traffic to pass through to the underlying application mount.

Furthermore, `lws-login` natively maintains an `lws_sorted_usec_list` (SUL) expiration timer tracking the exact token `exp` boundary. Even if a WebSocket successfully upgrades over the protected mount, the connection will be gracefully terminated the exact moment the active authorization token naturally expires!

## Per-Vhost Options (PVOs)

This plugin handles several PVO options to control the redirection routing and the properties of the required JWT session cookie:

| PVO Name | Description |
|---|---|
| `auth-server-url` | **Required.** The base URI of the central auth server portal to redirect unauthenticated users to (e.g. `https://auth.warmcat.com/login`). |
| `jwt-jwk` | **Required.** Either a JSON Web Key string or the path to a file containing a JSON Web Key, used to establish signing criteria for verifying the token signature. Must match the public key the central server uses to sign tokens. |
| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. Defaults to `"auth_session"`. |
| `service-name` | The explicitly required grant category strictly checked against the JWT privileges array. Defaults to `"default-service"`. *Note: Any authenticated user holding a wildcard (`*`) assignment in their JWT grants array will automatically bypass this constraint, acting as an administrator for any requested service.* **This option responds to BOTH a PVO definition (applying globally to the vhost) and can be dynamically overridden by a Per-Mount Option (PMO) definition of the same name.** |
| `min-grant-level` | The strict integer threshold allowing passage for the given service name within the token. Defaults to `1`. |
| `cookie-domain` | The optional specific domain name the auth cookie should be scoped to stringently (e.g. `warmcat.com`). If unspecified, defaults to omitting the domain from the cookie. |
| `auth-domain` | The issuer domain namespace string injected as `iss` when generating tokens. Defaults to `auth.warmcat.com`. |
| `jwt-validity-secs` | Integer representing the time-to-live for a dynamically migrated cookie. Defaults to `86400` (24 hours). |
| `db-path` | Absolute filepath to the shared sqlite3 permissions database (used to instantly verify and rewrite valid cookies suffering from revoked grants). Defaults to `/var/db/lws-auth.sqlite3`. |
| `whitelist` | Optional array of CIDR netblock strings (e.g. `10.0.0.0/8`, `192.168.1.0/24`). If any are provided, the connecting peer must match at least one explicitly or they will uniformly receive a `403 Forbidden` bypass, regardless of login state. |
| `unauth-allow` | If set to `1`, unauthenticated connections are **not** actively bounced via a 302 redirect. Traffic is instead permitted through to the underlying application mount unhindered. This enables scenarios where an underlying mount might conditionally render public views while relying securely on `/.lws-login-status` responses to dictate authenticated view logic without hard-failing unauthenticated guests. |

**Where does the JWK come from?**
The central `auth-server` plugin automatically generates an Elliptic Curve (EC P-256) keypair upon its first startup and saves it to its configured `jwk_path` (e.g., `/var/db/lws-auth.jwk`). To configure the `jwt-jwk` PVO for this bouncer mount, you simply take the contents of that generated file.

Because the JWT validator only strictly requires the public key components to verify the signature, you can either:
1. Provide the exact literal JSON string from the Auth Server's generated JWK file.
2. Read the literal string dynamically into the PVO when configuring your mount from your application.

*(Note: While passing the full keypair including the private key into the bouncer works, it is best practice to strip the private component `d` from the JSON if the bouncer is operating on an entirely different physical server).*

| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. Defaults to `"auth_session"`. |
| `service-name` | The explicitly required grant category strictly checked against the JWT privileges array. Defaults to `"default-service"`. *Note: Any authenticated user holding a wildcard (`*`) assignment in their JWT grants array will automatically bypass this constraint, acting as an administrator for any requested service.* **This option responds to BOTH a PVO definition (applying globally to the vhost) and can be dynamically overridden by a Per-Mount Option (PMO) definition of the same name.** |
| `min-grant-level` | The strict integer threshold allowing passage for the given service name within the token. Defaults to `1`. |
| `cookie-domain` | The optional specific domain name the auth cookie should be scoped to stringently (e.g. `warmcat.com`). If unspecified, defaults to omitting the domain from the cookie. |
| `auth-domain` | The issuer domain namespace string injected as `iss` when generating tokens. Defaults to `auth.warmcat.com`. |
| `jwt-validity-secs` | Integer representing the time-to-live for a dynamically migrated cookie. Defaults to `86400` (24 hours). |
| `db-path` | Absolute filepath to the shared sqlite3 permissions database (used to instantly verify and rewrite valid cookies suffering from revoked grants). Defaults to `/var/db/lws-auth.sqlite3`. |
| `whitelist` | Optional array of CIDR netblock strings (e.g. `10.0.0.0/8`, `192.168.1.0/24`). If any are provided, the connecting peer must match at least one explicitly or they will uniformly receive a `403 Forbidden` bypass, regardless of login state. |

## Cross-Domain SSO Architecture

If `cookie-domain` sharing fails because the target application operates on an entirely distinct apex domain (e.g., `auth.warmcat.com` logging into `libwebsockets.org`), the system natively utilizes high-performance auto-submitting POSTs.
When the auth portal completes authorization and identifies a foreign target domain, it dynamically preserves the original target's path sequence and constructs a transient `<form method="POST" action="https://[foreign-domain]/[target/path]/.lws-login-sso">` containing the encrypted JWT securely inside the POST body. This explicitly scopes the interception back to the specific internal mount processing the request rather than discarding internal hierarchies.
`lws-login` intercepts all localized `/.lws-login-sso` boundaries dynamically, digests the incoming POST securely, verifies the tokens using `lws_spa`, provisions a newly scoped localized top-level cookie, and redirects cleanly back to the ultimate target securely.

If a visiting client lacks the required `cookie-name`, or their validated token does not meet the `<service-name>:<min-grant-level>` threshold (and they do not hold a `*` administrative wildcard), the plugin calculates the `redirect_uri` based on the exact path they were attempting to reach.

It intercepts the connection and issues a standard `HTTP 302 Found` bouncing them dynamically to:
`%auth-server-url%?service_name=%service-name%&redirect_uri=%url_encoded_path%`

The central Auth Server portal will parse these parameters. If the user is unauthenticated, they will be prompted to log in. However, if the user successfully authenticates but strictly lacks the necessary `%service-name%` privilege assignment, the central Auth Server will cleanly deny them with an `Access Denied` status to prevent endless redirect looping between the two nodes!

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
    }]
  }]
}
```

Notice that the `pmo` *(Per-Mount Option)* strictly binds the `dashboard-service` name to the `/dashboard` mount, cleanly overriding any default global values the protocol was initialized with.
