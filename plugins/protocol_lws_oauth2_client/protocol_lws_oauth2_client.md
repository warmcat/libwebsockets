# lws-oauth2-client

## Introduction

The `lws-oauth2-client` plugin is an entirely standalone protocol handler that seamlessly integrates the **OAuth2 Authorization Code Grant** (with PKCE) into any libwebsockets-based server.

Instead of writing custom OAuth2 tracking and exchanging logic, a relying application can simply redirect unauthenticated users to this plugin's mount. The plugin will handle state generation, the redirect to the central Authority's `/api/authorize`, intercept the callback, securely exchange the code for a JWT via `/api/token`, issue the token as a cookie, and finally return the user to their original destination!

Because this plugin isolates the OAuth2 handshake from the application logic, it works perfectly alongside `lws-login`.

## Mount Pattern

This plugin intercepts requests to:

- `/oauth/login` — Starts the login process (redirect to the Authority).
- `/oauth/callback` — The callback URI registered with your OAuth server.
- `/oauth/refresh` — **Silent-renewal BFF endpoint** (POST). Proxies to the
  Authority's `/api/sso_exchange` to transparently re-issue a fresh short-lived
  `auth_session` cookie before the current one expires, backed by the long-term
  `auth_refresh_session` cookie. See [Silent renewal](#silent-renewal) below.
- `/oauth/refresh.js` — The companion client-side JS that drives the renewal
  cadence. Include it once per protected page.

You can mount this plugin statically in your JSON config or conditionally load
it at runtime.

## Per-Vhost Options (PVOs)

This plugin handles the following PVO options:

| PVO Name | Description |
|---|---|
| `remote-auth-url` | **Required.** The base URI of the central auth server (e.g. `https://auth.warmcat.com`). The plugin will target `/api/authorize` and `/api/token` under this root. |
| `client-id` | **Required.** The globally unique identifier assigned to this client application by the Auth Server. |
| `cookie-name` | Custom name emitted for holding the session token upon successful callback. Defaults to `"auth_session"`. |
| `cookie-max-age-secs` | Fallback `Max-Age` for the session cookie, in seconds. Defaults to `3600` (1h) for backwards compatibility, but the actual `expires_in` returned by `/api/token` is used in preference when present. Raise this (or the server's `jwt-validity-secs`) to lengthen the session. |
| `auth-server-url` | Base URL used for the silent-renewal side channel (`/api/sso_exchange`). Defaults to `remote-auth-url`. Set this separately when the browser-facing Authority URL and the server-to-server URL differ (e.g. internal vs. public hostnames). |

## Silent renewal

Without silent renewal, the `auth_session` cookie expires (by default after one
hour) and the application appears "logged out" to the user until they click
through the full OAuth flow again. With the auth server's
`refresh-validity-secs` > 0, it also issues a long-term `auth_refresh_session`
cookie (typically days to weeks) backed by its `auth_sessions` table. This
plugin uses that long-term cookie to renew the short-lived one in the background:

1. The browser includes `/oauth/refresh.js` on protected pages.
2. That JS POSTs to `/oauth/refresh` on a cadence (~75% of the cookie lifetime,
   and immediately on tab refocus), sending `credentials: 'include'`.
3. The plugin forwards the browser's cookies to the Authority's
   `/api/sso_exchange`. If the long-term `auth_refresh_session` is still valid,
   the server mints a fresh short-lived JWT and the plugin re-issues the
   `auth_session` cookie transparently — the user never sees a state change.
4. Only on a hard failure (the server reports the long-term login is gone,
   returned as HTTP 401) does the JS stop retrying and leave it to the
   application to render its own logged-out UX. **Network errors and transient
   5xx do not log the user out** — the JS backs off and retries, because the
   long-term cookie may still be valid server-side.

> **Requirements for silent renewal to function:** the auth server must be built
> with `refresh-validity-secs` > 0 (see the `lws-auth-server` README), so that
> the `auth_refresh_session` cookie is actually issued at login time. Without
> it, `/oauth/refresh` will (correctly) return 401 and renewal is a no-op.

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

To enable silent renewal, include the helper script once on each protected page
(inside the page that also carries the `lws-login` status widget, or any
top-level app shell):

```html
<script src="/oauth/refresh.js"></script>
```

The script self-initialises and self-schedules; it is a no-op if already loaded,
so it is safe to include on every page. It complies with the strict CSP (it is a
plain external script with no inline code).

**Grant Forwarding**: Any `service_name=XYZ` URL parameter provided to `/oauth/login` (which is automatically appended by `lws-login` via its `service-name` PVO) will be seamlessly forwarded up the chain to the remote Authority node. This allows the backend `auth.warmcat.com` server to strictly cryptographically enforce user UI-blocking and privileges _before_ rendering the login screen or issuing an OAuth code back to your local client!
