# lws api test tls cert rotate

A tls server vhost has its certificate renewed while it is serving, the way a
renewal does it: the cert and key files the vhost was created with are
rewritten, and `lws_tls_cert_updated()` is told the paths.  lws is both ends:
after each step a new client connection must be served, under the certificate
the step expects.

|step|client names|what happens|served under|
|---|---|---|---|
|initial cert|srv|vhost as created|localhost|
|rotated|srv|files rewritten with a second cert + key|wronghost.example.com|
|rotated, the other vhost by SNI|localhost|nothing, the client checks the cert is for the name|localhost|
|rotation without a key keeps the cert|srv|new cert written, key file still empty, so the load fails|wronghost.example.com|
|rotated back|srv|first cert + key written again|localhost|

A failed rotation must leave the vhost on the tls ctx it had, and each
rotation must give the vhost a ctx of its own for the new cert, so the old one
is retired without disturbing what the vhost serves.

A second vhost, `localhost`, shares the listener with a cert of its own (the
first cert), which is never renewed.  The renewed ctx must keep everything the
first one did, including the SNI callback: while `srv` is on the renewed cert,
a client naming `localhost` must still be shown the `localhost` vhost's cert.
That client checks the cert it is shown is for the name it dialled, so a
listener that lost its SNI, and shows it `srv`'s renewed cert, fails the step.
The other steps skip that check, since `srv` is shown with both certs in turn.

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
[2026/09/30 18:00:00:0000] U: --- rotated, the other vhost by SNI: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotation without a key keeps the cert: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotated back: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- all steps passed ---
[2026/09/30 18:00:00:0000] U: Completed: PASS
```
