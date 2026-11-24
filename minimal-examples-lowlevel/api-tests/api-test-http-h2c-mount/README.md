# lws api test http h2c mount

A mount with `no_ws_upgrades` is passed over for a websocket upgrade, so that
the upgrade lands in a mount that serves it.  An h1 request that upgrades to
h2c is not a websocket upgrade: it is an http request, served on h2 stream 1,
and it must land in the mount its path does, meeting that mount's gates, as it
would without the upgrade.

The server has a public file mount at `/`, and inside its origin the origin of
a file mount at `/private`, behind a basic auth login file, and with
`no_ws_upgrades`.  If the h2c request were not given to `/private`, `/` would
serve the private file from its own origin, without asking for any
credentials.  A raw client in the same process makes the requests:

 - `/private/index.html`, as plain h1 without credentials: 401
 - the same, upgrading to h2c: 401, and the upgrade is not done
 - the same, upgrading to h2c, with credentials: the private file, on stream
   1, so h2c works here and the files are where we think
 - `/index.html`, upgrading to h2c: the public file, on stream 1

The files and the login file are made in the cwd, named with the process id,
and removed afterwards.

```
$ ./lws-api-test-http-h2c-mount
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--server <address>|Address of the test server (default 127.0.0.1)
