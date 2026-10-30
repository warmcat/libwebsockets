# lws minimal http server digest auth

Demonstrates protecting a mount with HTTP Digest Auth using an
htdigest-format password file.

The demo has two mounts: a normal one at `/` and one protected by
Digest Auth at `/secret`.

The file `./da-passwords` contains valid credentials in htdigest format:

```
username:realm:HA1hex
```

where `HA1hex` is the lowercase hex MD5 digest of `"username:realm:password"`.

The supplied file has `user:lwsws:f919cc9b...` which corresponds to
username `user`, realm `lwsws`, password `password`.

You can manage the file with the standard `htdigest` tool:

```
htdigest -c ./da-passwords lwsws user
```

## Discovering the authenticated user

After successful authentication, the `WSI_TOKEN_HTTP_AUTHORIZATION` token
contains the authenticated username, matching the Basic Auth convention.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-digestauth
[...] USER: LWS minimal http server digest auth | visit http://localhost:7681
```

Visit `http://localhost:7681`, follow the link to `/secret`, and enter
`user` / `password` when the browser prompts.

You can also test with `curl`:

```
$ curl --digest -u user:password http://localhost:7681/secret/index.html
```
