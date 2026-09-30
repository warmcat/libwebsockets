# lws api test http basic auth

A file mount protected by a basic auth login file, over every http transport
the build has: h1, h2 with prior knowledge, h2 over tls and h3.  lws is both
ends, in one process.

`/` is a public file mount on `./docroot`, and `/private` a file mount on
`./docroot/private`, inside it, behind the login file.

|request|expected|
|---|---|
|`/private/index.html`, no `Authorization:`|401, with a `WWW-Authenticate: Basic realm=...` challenge|
|`/private/index.html`, credentials the login file does not list|401, with the challenge|
|`/private/index.html`, credentials the login file lists|200, the private file|
|`/index.html`|200, the public file|
|`/PRIVATE/index.html`, `/Private/index.html`, `/private./index.html`, `/private%20/index.html`, no credentials|anything but the private file|

The last row is for filesystems that find a file by more names than its own:
case folds on windows and macOS, and windows drops the dots and spaces a name
ends with.  Those URIs miss `/private` and go to `/`, where lws refuses to
serve a file that is `/private`'s (403).  Elsewhere there is no such file
(404).

The login file is `./basic-auth.txt`, one `user:password` per line, and the
files are in `./docroot`, so run it with the test directory as the cwd.

## running it

```
$ ./lws-api-test-http-basic-auth -p 7681 --h2c-port 7682 --tls-port 7683 --h3-port 7684
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|Port for the h1 server vhost (default 7681)
--h2c-port <port>|Port for the h2 prior-knowledge server vhost (default 7682)
--tls-port <port>|Port for the h2 over tls server vhost (default 7683)
--h3-port <port>|UDP port for the h3 server vhost (default 7684)
--server <address>|Address the client connects to (default 127.0.0.1)
