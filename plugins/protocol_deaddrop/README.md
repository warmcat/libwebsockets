# Deaddrop: File upload and sharing plugin

## Building the plugin

Just configure lws with `cmake .. -DLWS_WITH_PLUGINS=1` and build lws as normal.

## Configurable settings

|pvo name|value meaning|
|---|---|
|upload-dir|A writeable directory where uploaded files will go|
|max-size|Maximum individual file size in bytes|
|jwt-jwk|Path to the JSON Web Key (JWK) used to verify JWT signatures|
|cookie-name|Optional: Name of the HTTP cookie that the server should expect the JWT payload in. Defaults to `auth_session`|

## Required mounts

To use deaddrop meaningfully, all the mounts and the ws protocol must be
protected by JWT authentication.  And to use JWT securely, the connection must
be protected from snooping by tls.

1) Set the `jwt-jwk` pvo to require valid signatures on WebSocket connections as described above.

2) Protect your basic fileserving mount by the same JWT bouncer (`lws-login`)... this is
   used to serve index.html, the css etc.

3) Add a callback mount into "lws-deaddrop" protocol at "upload"... so if your
   URL for deaddrop is "/tools/share", this would be at "/tools/share/upload".
   It must also be protected by the JWT bouncer.

4) Add a fileserving mount at the url "get" (continuing the example above, it
   would be "/tools/share/get" whose origin matches the "upload-dir" pvo
   value you selected.  This mount needs any additional mimtype mappings since
   it's where the uploaded files are shared from.

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
         "origin": "file:///var/cache/deaddrop-uploads",

	 "extra-mimetypes": {
		".bin": "application/octet-stream",
		".ttf": "application/x-font-truetype",
		".otf": "application/font-sfnt",
		".zip": "application/zip",
		".webm": "video/webm",
		".romfs": "application/octet-stream",
		".pdf": "application/pdf",
		".odt": "application/vnd.oasis.opendocument.text",
		".tgz": "application/x-gzip",
		".tar.gz": "application/x-gzip"
	  }
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
