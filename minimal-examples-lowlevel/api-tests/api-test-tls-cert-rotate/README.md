# lws api test tls cert rotate

A tls server vhost has its certificate renewed while it is serving, the way a
renewal does it: the cert and key files the vhost was created with are
rewritten, and `lws_tls_cert_updated()` is told the paths.  lws is both ends:
after each step a new client connection must be served, under the certificate
the step expects.

|step|what happens|served under|
|---|---|---|
|initial cert|vhost as created|localhost|
|rotated|files rewritten with a second cert + key|wronghost.example.com|
|rotation without a key keeps the cert|new cert written, key file still empty, so the load fails|wronghost.example.com|
|rotated back|first cert + key written again|localhost|

A failed rotation must leave the vhost on the tls ctx it had, and each
rotation must give the vhost a ctx of its own for the new cert, so the old one
is retired without disturbing what the vhost serves.

The live files `tls-cert-rotate-live.cert` / `.key` are written in the
working directory (ctest runs it in the build dir); the certs copied into them
come from `--certs <dir>`.  Both certs are self-signed test certs.

## build

```
 $ cmake . && make
```

## usage

|Option|Meaning|
|---|---|
|-p <port>|tls server port (default 7681)|
|--server <addr>|address the client connects to (default 127.0.0.1)|
|--certs <dir>|where the test certs are (default .)|

```
 $ ./lws-api-test-tls-cert-rotate --certs <this dir>
[2026/09/30 18:00:00:0000] U: LWS API selftest: tls server cert rotation
[2026/09/30 18:00:00:0000] U: --- initial cert: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotated: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotation without a key keeps the cert: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotated back: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- all steps passed ---
[2026/09/30 18:00:00:0000] U: Completed: PASS
```
