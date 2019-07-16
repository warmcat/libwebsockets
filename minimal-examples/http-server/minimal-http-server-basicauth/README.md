# lws minimal http server basic auth

This demonstrates how to protect a mount using a password
file outside of the mount itself.

Although it's called 'basic auth' it supports both basic auth and
RFC7616 MD5 digest auth depending on `LWS_WITH_HTTP_AUTH_BASIC` or
`LWS_WITH_HTTP_AUTH_DIGEST`.

The demo has two mounts, a normal one at / and one protected
by basic auth at /secret.

For Basic Auth (`LWS_WITH_HTTP_AUTH_BASIC`) the file at ./ba-passwords contains
valid user:password combinations directly.  For Digest Auth (`LWS_WITH_HTTP_AUTH_DIGEST`)
the file at ./digest-passwords contains valid user:md5 combinations.  The hash
is computed by `echo -n "user:lwsauthtest@localhost:password" | md5sum`

## Discovering the authenticated user

After a successful authentication, the `WSI_TOKEN_HTTP_AUTHORIZATION` token
contains the authenticated username.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-basic-auth
[2018/04/19 08:40:05:1333] USER: LWS minimal http server basic auth | visit http://localhost:7681
[2018/04/19 08:40:05:1333] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 off
```

Visit http://localhost:7681, and follow the link there to the secret area.

Give your browser "user" and "password" as the credentials.

