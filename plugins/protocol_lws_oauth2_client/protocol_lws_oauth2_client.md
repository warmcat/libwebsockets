# lws-oauth2-client

## Introduction

The `lws-oauth2-client` plugin is an entirely standalone protocol handler that seamlessly integrates the **OAuth2 Authorization Code Grant** (with PKCE) into any libwebsockets-based server.

Instead of writing custom OAuth2 tracking and exchanging logic, a relying application can simply redirect unauthenticated users to this plugin's mount. The plugin will handle state generation, the redirect to the central Authority's `/api/authorize`, intercept the callback, securely exchange the code for a JWT via `/api/token`, issue the token as a cookie, and finally return the user to their original destination!

Because this plugin isolates the OAuth2 handshake from the application logic, it works perfectly alongside `lws-login`.

## Mount Pattern

This plugin only requires intercepting requests to:
- `/oauth/login` (Starts the login process)
- `/oauth/callback` (The callback URI registered with your OAuth server)

You can mount this plugin statically in your JSON config or conditionally load it at runtime.

## Per-Vhost Options (PVOs)

This plugin handles the following PVO options:

| PVO Name | Description |
|---|---|
| `remote-auth-url` | **Required.** The base URI of the central auth server (e.g. `https://auth.warmcat.com`). The plugin will target `/api/authorize` and `/api/token` under this root. |
| `client-id` | **Required.** The globally unique identifier assigned to this client application by the Auth Server. |
| `cookie-name` | Custom name emitted for holding the session token upon successful callback. Defaults to `"auth_session"`. |

## How to use alongside `lws-login`

If you are using `lws-login` as a JWT bouncer to protect an application endpoint, simply point its `auth-server-url` PVO to the `/oauth/login` route of this plugin!

```json
  "ws-protocols": [{
    "lws-oauth2-client": {
       "remote-auth-url": "https://auth.warmcat.com",
       "client-id": "monitor",
       "cookie-name": "auth_session"
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

**Grant Forwarding**: Any `service_name=XYZ` URL parameter provided to `/oauth/login` (which is automatically appended by `lws-login` via its `service-name` PVO) will be seamlessly forwarded up the chain to the remote Authority node. This allows the backend `auth.warmcat.com` server to strictly cryptographically enforce user UI-blocking and privileges _before_ rendering the login screen or issuing an OAuth code back to your local client!
