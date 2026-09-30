# lws api test http basic auth

A mount protected by a basic auth login file, over every http transport the
build has: h1, h2 with prior knowledge, h2 over tls and h3.  lws is both
ends, in one process.

|request|expected|
|---|---|
|no `Authorization:`|401, with a `WWW-Authenticate: Basic realm=...` challenge|
|credentials the login file does not list|401, with the challenge|
|credentials the login file lists|200, served by the mount's protocol|

The login file is `./basic-auth.txt`, one `user:password` per line, so run it
with the test directory as the cwd.

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
