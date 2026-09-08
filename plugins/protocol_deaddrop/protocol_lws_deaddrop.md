# lws-deaddrop

## Introduction

The `lws-deaddrop` plugin implements an authenticated file upload server feature (a "deaddrop") over WebSocket and HTTP POST. Authorized users can securely upload files using multipart/form-data. The server also monitors the configured upload directory (using `inotify` on Linux platforms) to present an active browser listing of shared files between authenticated users directly over a WebSockets portal connection.

## Per-Vhost Options (PVOs)

This plugin accepts the following configuring Per-Vhost Options (PVOs):

| PVO Name | Description |
|---|---|
| `upload-dir` | **Required.** An absolute file path pointing to the directory where uploaded files should be stored by the server. |
| `max-size` | Optional integer expressing the maximum permitted file upload size in bytes. Any file POSTs over this size will be aborted with an HTTP 413 "Payload Too Large". Defaults to `20971520` (20MB). |
| `cookie-name` | Optional string defining the authentication session cookie name to clear during a logout hook in the UI. Defaults to `auth_session`. |
| `jwt-jwk` | Optional JSON string or absolute path to a file containing a JSON Web Key (JWK) for JWT token validation. When provided, the plugin will natively read the value from the cookie set by `cookie-name`, validate it against the JWK, and use the JWT `"sub"` subject field as the authenticated identity. Recommended when used securely behind an `lws-login` interceptor mount. |
| `basic-auth` | Optional path to an lws basic-auth password file.  lws itself checks it at the ws upgrade and rewrites the `Authorization` header to the validated username.  The plugin only believes an `Authorization` header identity when this PVO is present: without it, nothing has validated the header and any peer could simply name itself. |
| `allow-anonymous` | Optional; set to anything except `off` or `0` to let unauthenticated peers open the ws connection.  By default the ws upgrade is refused unless the peer authenticated (valid, unexpired JWT session cookie, or basic auth as above), because the ws channel serves the whole file listing and the IP of every connected user, and (unlike the mounts) it never passes through an `lws-login` bouncer. |
| `origin-allow` | Optional comma-separated list of complete origins (eg, `https://a.example.com,https://b.example.com:8443`) that are accepted on the ws upgrade and the upload POST in addition to the origin the vhost is reached at. |
| `require-origin` | Optional; set to anything except `off` or `0` to also refuse requests that carry no `Origin` header at all.  See "Origin / CSRF policy" below. |

## Origin / CSRF policy

Both entry points the plugin owns are authenticated by an ambient credential
(the JWT session cookie, or basic auth) and neither is covered by the
same-origin policy by itself: the WebSocket handshake is exempt from it, and a
`multipart/form-data` POST is a CORS "simple request" that is sent without a
preflight.  Without an `Origin` check, any page the victim visits while logged
in could open the ws as the victim (receiving the entire file listing and every
connected user's IP address), delete the victim's files, and upload files
attributed to the victim.

So `Origin`, when present, must match either

 - the origin this vhost is being reached at, ie, the request's `Host` (h1) or
   `:authority` (h2/h3) with the scheme, or

 - one of the origins listed in the `origin-allow` PVO.

Anything else, including the literal `null` an opaque/sandboxed document sends,
is refused: the ws upgrade is rejected and the upload POST is answered 403.

When lws is not itself terminating tls, it cannot distinguish an `http`
deployment from an `https` one behind a tls-terminating proxy, so in that case
its own host is accepted over either scheme.  Pin it exactly with
`origin-allow` if that matters for your deployment.

A request carrying **no** `Origin` header is allowed by default.  Browsers
always send `Origin` on a WebSocket handshake and on any POST, so its absence
identifies a non-browser client (curl, a script, another service), and it is
only the browser that a hostile page can aim at the server with the victim's
cookie attached.  Refusing those unconditionally would break scripted use of
the drop without closing an attack, so it is left to the deployment: set
`require-origin` on a vhost that only ever serves browsers.
