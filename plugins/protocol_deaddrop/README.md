# Deaddrop: File upload and sharing plugin

## Building the plugin

Just configure lws with `cmake .. -DLWS_WITH_PLUGINS=1` and build lws as normal.

## Configurable settings

|pvo name|value meaning|
|---|---|
|upload-dir|A writeable directory where uploaded files will go.  It must exist when the vhost is created, when it is resolved (relative to the current directory, through any symlinks) once for good|
|max-size|Maximum individual file size in bytes|
|jwt-jwk|Path to the JSON Web Key (JWK) used to verify JWT signatures.  Only the lws auth server's session tokens, which carry `"pur":"sso"`, are accepted|
|cookie-name|Optional: Name of the HTTP cookie that the server should expect the JWT payload in. Defaults to `auth_session`|
|basic-auth|Optional: path to an lws basic-auth password file, that lws checks the ws upgrade against.  If this is set, a user lws's own basic auth accepted for the request is a deaddrop user: from this file on the ws, and from the mount's own basic auth login file on the `upload` and `get` mounts.  The `Authorization` header itself is never believed, so a mount without basic auth has no basic auth user|
|allow-anonymous|Optional: set to other than `off` / `0` to allow unauthenticated ws connections.  By default they are refused|
|origin-allow|Optional: comma-separated list of extra origins (eg, `https://a.example.com,https://b.example.com`) accepted on the ws upgrade and the upload POST, in addition to the vhost's own origin|
|require-origin|Optional: set to other than `off` / `0` to also refuse requests that carry no `Origin` header at all, ie, non-browser clients|

### CSRF / Origin policy

The ws upgrade and the upload POST are both authenticated by an ambient
credential (the session cookie, or basic auth), and neither is protected by
the same-origin policy on its own: a ws handshake is exempt from it, and a
`multipart/form-data` POST is a CORS "simple request".  So the plugin checks
the `Origin` header on both, and refuses it unless it matches the origin the
vhost is being reached at (`Host` / `:authority`) or an entry in
`origin-allow`.  A sandboxed document's literal `Origin: null` never matches.

If lws is not itself terminating tls (ie, it is behind a tls-terminating
proxy) it cannot tell an `http` deployment from an `https` one, so in that
case the vhost's own host is accepted over either scheme.  Use `origin-allow`
to pin it exactly.

A request with *no* `Origin` at all is allowed by default: browsers always
send one on a ws upgrade and on any POST, so its absence means a non-browser
client (curl, a script), which is not something a hostile page can aim at the
server with the victim's cookie attached.  A vhost that only ever serves
browsers should set `require-origin` to close that off too.

## Required mounts

To use deaddrop meaningfully, all the mounts and the ws protocol must be
protected by JWT authentication.  Note the ws upgrade never passes through
mounts, so the `lws-login` bouncer cannot protect it: the plugin itself
refuses the upgrade for a peer with no valid, unexpired session.  And to use JWT securely, the connection must
be protected from snooping by tls.

1) Set the `jwt-jwk` pvo to require valid signatures on WebSocket connections as described above.

2) Protect your basic fileserving mount by the same JWT bouncer (`lws-login`)... this is
   used to serve index.html, the css etc.

3) Add a callback mount into "lws-deaddrop" protocol at "upload"... so if your
   URL for deaddrop is "/tools/share", this would be at "/tools/share/upload".
   It must also be protected by the JWT bouncer.

4) Add a second callback mount into "lws-deaddrop" at "get"... continuing the
   example above, it would be "/tools/share/get".  The plugin serves the
   uploaded files from there itself (see "Downloads" below), so do not serve
   "upload-dir" with a file mount.  It must also be protected by the JWT
   bouncer.

## Downloads

deaddrop never delivers anything renderable: it moves text where there is no
clipboard, and binary files.  Every download from the "get" mount is sent
whatever its extension as

 - `Content-Type: application/octet-stream`
 - `Content-Disposition: attachment` with a safe filename (the uploaded name
   without the owner prefix)
 - `X-Content-Type-Options: nosniff`
 - `Content-Security-Policy: sandbox; default-src 'none'`

so a shared `.html`, `.svg` or `.js` can never run as active content on the
deaddrop origin, as whoever opens its link.  Downloads need an authenticated
user (as uploads do), unless the vhost set `allow-anonymous`.

## Using with C

See ./minimal-examples/http-server/minimal-example-http-server-deaddrop for
how to use the plugin directly with C.

## Using with lwsws / lejp-conf

As a plugin, you can configure the mounts and pvos per-vhost easily in JSON.

All the snippets here

The mountpoints would look something like this (added to vhost/mounts)

```
	{
         "mountpoint": "/tools/share",
         "origin": "file:///var/www/deaddrop",
         "default": "index.html"
        }, {
         "mountpoint": "/tools/share/upload",
         "origin": "callback://lws-deaddrop"
        }, {
         "mountpoint": "/tools/share/get",
         "origin": "callback://lws-deaddrop"
	}
```

This enables the plugin on the vhost, configures the pvos, and makes
the wss serving also depend on having a valid JWT session.

```
         "ws-protocols": [{
                  "lws-deaddrop": {
                  "status": "ok",
                  "upload-dir": "/var/cache/deaddrop-uploads",
                  "max-size": "52428800",
                  "jwt-jwk": "/var/db/lws-auth.jwk",
                  "cookie-name": "auth_session"
                }
          }],
```
