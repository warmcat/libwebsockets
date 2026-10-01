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
|the other vhost by SNI keeps its own alpn|localhost|the client offers h2 and http/1.1, `localhost` only has http/1.1: it must not get h2 from `srv`'s list|localhost|
|rotation without a key keeps the cert|srv|new cert written, key file still empty, so the load fails|wronghost.example.com|
|renewed on disk, lws not told|srv|first cert + key written alongside and the live paths moved onto them, `lws_tls_cert_updated()` not called: the client reconnects until the vhost has noticed|localhost|
|rotated back|srv|first cert + key written again|localhost|
|renewed on disk, held back for the grace period|graced|second cert + key renewed on disk, the client connects 3s later, inside the vhost's 6s grace|localhost|
|renewed on disk, served after the grace period|graced|nothing, the client reconnects until the grace has passed and the vhost moved on|wronghost.example.com|
|rebound off srv, which goes while it holds srv's ctx|127.0.0.1, no SNI|Host: moves it to the `127.0.0.1` vhost; while it waits for the answer, srv's cert is renewed and srv destroyed|localhost|

The two "renewed on disk" kinds of step are renewals nobody tells lws about,
the way an acme client in another process, the cert distribution client or
certbot renew: a vhost whose cert and key are files watches them, and moves
onto new ones by itself.  The live paths are moved onto the new files with a
symlink, as those renewers do (on Windows the files are rewritten in place
instead).  The `graced` vhost, on a listener of its own so its steps don't
depend on SNI, has a 6s `tls_cert_grace_secs`: a renewal must not be served
until that long after it was written, then it must be.  Without
`LWS_WITH_DIR` a renewal is only seen hourly, so these steps are skipped.

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

The `localhost` vhost has only http/1.1 in its alpn, while `srv`, whose
listener it shares, also has h2.  A client that names `localhost` in SNI and
offers h2 must get the alpn of the vhost it named, http/1.1, not `srv`'s h2.
mbedtls servers take the alpn list from the listener's config whatever SNI
picks, so this step is skipped there (and with bearssl, schannel and
openhitls, which are not known to do better).

The last step checks a connection may outlive the vhost whose tls ctx it
handshaked under.  A third vhost on the listener is named `127.0.0.1`, and a
client dials that address, so it sends no SNI and the handshake is under
`srv`'s ctx, but its `Host:` header moves the connection to the third vhost.
While the server holds its answer back, it renews `srv`'s cert, which retires
the ctx the connection is using, and destroys `srv`, which has nothing bound to
it any more and goes at once.  The connection is then answered and closed: the
retired ctx must only be freed then, with its last user (a ctx freed with the
vhost is a use after free, which an ASan build shows).  An ipv6-only build
skips this step.

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
|--port-graced <port>|the graced vhost's tls server port (default 7682)|
|--server <addr>|address the client connects to (default 127.0.0.1)|
|--certs <dir>|where the test certs are (default .)|

```
 $ ./lws-api-test-tls-cert-rotate --certs <this dir>
[2026/09/30 18:00:00:0000] U: LWS API selftest: tls server cert rotation
[2026/09/30 18:00:00:0000] U: --- initial cert: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotated: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotated, the other vhost by SNI: served under 'localhost': PASS ---
[2026/09/30 18:00:00:0000] U: --- rotation without a key keeps the cert: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:05:0000] U: --- renewed on disk, lws not told: served under 'localhost': PASS ---
[2026/09/30 18:00:05:0000] U: --- rotated back: served under 'localhost': PASS ---
[2026/09/30 18:00:08:0000] U: --- renewed on disk, held back for the grace period: served under 'localhost': PASS ---
[2026/09/30 18:00:11:0000] U: --- renewed on disk, served after the grace period: served under 'wronghost.example.com': PASS ---
[2026/09/30 18:00:11:0000] U: drop_srv_cb: srv renewed, destroying it
[2026/09/30 18:00:11:0000] U: --- rebound off srv, which goes while it holds srv's ctx: served under 'localhost': PASS ---
[2026/09/30 18:00:11:0000] U: --- all steps passed ---
[2026/09/30 18:00:11:0000] U: Completed: PASS
```
