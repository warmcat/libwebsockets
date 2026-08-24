# lws-oauth2-client

## Introduction

The `lws-oauth2-client` plugin is an entirely standalone protocol handler that seamlessly integrates the **OAuth2 Authorization Code Grant** (with PKCE) into any libwebsockets-based server.

Instead of writing custom OAuth2 tracking and exchanging logic, a relying application can simply redirect unauthenticated users to this plugin's mount. The plugin will handle state generation, the redirect to the central Authority's `/api/authorize`, intercept the callback, securely exchange the code for a JWT via `/api/token`, issue the token as a cookie, and finally return the user to their original destination!

Because this plugin isolates the OAuth2 handshake from the application logic, it works perfectly alongside `lws-login`.

## Mount Pattern

This plugin intercepts requests to:

- `/oauth/login` — Starts the login process (redirect to the Authority).
- `/oauth/callback` — The callback URI registered with your OAuth server.

You can mount this plugin statically in your JSON config or conditionally load
it at runtime.

## Per-Vhost Options (PVOs)

This plugin handles the following PVO options:

| PVO Name | Description |
|---|---|
| `remote-auth-url` | **Required.** The base URI of the central auth server (e.g. `https://auth.warmcat.com`). The plugin will target `/api/authorize` and `/api/token` under this root. |
| `client-id` | **Required.** The globally unique identifier assigned to this client application by the Auth Server. |
| `cookie-name` | Custom name emitted for holding the session token upon successful callback. Defaults to `"auth_session"`. Limited to 1..63 characters: the protocol refuses to initialize with a longer name, since the composed `Set-Cookie` buffers are sized for that cap (a cookie that could not be composed whole would otherwise have to be silently truncated or fail the login). |
| `cookie-domain` | Optional `Domain=` attribute for the `auth_session` / `auth_csrf` / `auth_refresh_session` cookies minted at `/oauth/callback`. Set it to the same value as `lws-login`'s `cookie-domain` on the same deployment: otherwise the two plugins mint parallel host-only and `Domain=`-scoped cookies with different birthdays, and the `auth_csrf` sidecar can end up expiring on a different schedule from the `auth_refresh_session` it belongs with. Omit entirely (do not set it on just one of the plugins) to keep all cookies host-only. |
| `cookie-max-age-secs` | Fallback `Max-Age` for the session cookie, in seconds. Defaults to `3600` (1h) for backwards compatibility, but the actual `expires_in` returned by `/api/token` is used in preference when present. Raise this (or the server's `jwt-validity-secs`) to lengthen the session. |

## Keeping the session alive (token renewal)

This plugin handles only the **initial** OAuth/PKCE handshake: redirecting to
the Authority, exchanging the code for a JWT, and dropping the short-lived
`auth_session` (plus a matching `auth_csrf`) cookie.

Ongoing **token renewal** — re-minting that short-lived cookie from the
Authority's long-term `auth_refresh_session` cookie before it expires, without
bouncing the user's main document to a login page — is handled by
**`lws-login`**, the JWT bouncer mounted in front of your protected pages. See
the `lws-login` README: it performs renewal both in the background (via its
widget JS) and on a cold page load (server-side, before any redirect to the
login form), so a valid session stays alive transparently and only a genuinely
expired long-term login ever reaches the auth form.

## How to use alongside `lws-login`

If you are using `lws-login` as a JWT bouncer to protect an application endpoint, simply point its `auth-server-url` PVO to the `/oauth/login` route of this plugin!

```json
  "ws-protocols": [{
    "lws-oauth2-client": {
       "remote-auth-url": "https://auth.warmcat.com",
       "client-id": "monitor",
       "cookie-name": "auth_session",
       "cookie-max-age-secs": "1800"
    }
  }, {
    "lws-login": {
       "jwt-jwk": "{...}",
       "auth-server-url": "/oauth/login",
       "service-name": "monitor",
       "cookie-name": "auth_session"
    }
  }]
```

Upon attempting to access the protected URI, the `lws-login` plugin will natively bounce them to `/oauth/login?service_name=monitor&redirect_uri=...`. The OAuth client will take over, process the handshake securely via the backend, drop the local cookie, and automatically return the user to the protected URI. `lws-login` will see the new cookie and allow passage.

Thereafter, `lws-login` keeps the session alive on its own — both in the
background (its widget JS) and when a page is loaded with an already-expired
short-lived cookie but a still-valid long-term login (it re-mints the cookie
server-side before ever redirecting to the login form). No additional include or
configuration on this plugin is required for renewal; see the `lws-login` README
for the renewal requirements (notably `refresh-validity-secs > 0` on the auth
server, so the long-term cookie is issued at login time).

**Grant Forwarding**: Any `service_name=XYZ` URL parameter provided to `/oauth/login` (which is automatically appended by `lws-login` via its `service-name` PVO) will be seamlessly forwarded up the chain to the remote Authority node. This allows the backend `auth.warmcat.com` server to strictly cryptographically enforce user UI-blocking and privileges _before_ rendering the login screen or issuing an OAuth code back to your local client!
