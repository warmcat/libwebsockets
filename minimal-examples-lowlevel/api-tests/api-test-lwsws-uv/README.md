# api-test-lwsws-uv

An end-to-end ctest that runs **lwsws itself** -- on libuv, with its protocol
plugins `dlopen`ed out of the build tree and its vhosts and mounts described by
a generated JSON config -- and drives it with small C clients, the way the
maintainer's production server is actually deployed.

The other ctests in the tree run the poll loop, in-process, with no plugins and
no mounts.  That leaves whole classes of production defect untested: the
interceptor flows, h1 pipelining across a file transfer, and the QUIC/TCP
connect race under libuv.

## What the fixture is

`st_lwsws_uv` / `ki_lwsws_uv` start and stop `lwsws` through
`scripts/ctest-background.sh`, which appends `-d1039`; that is what makes lwsws
install its crash handler, so a `SIGSEGV` in the worker prints a backtrace into
the fixture log (`/tmp/ctest-background-lwsws.lwsws_uv.*`).  The kill test
prints that log.

CMake generates the config from `conf.in` and `conf.d/apitest.json.in` with
`configure_file(... @ONLY)`, so the ports (from `lws_get_free_ports()`), the
build tree's plugin dir, the generated test certs and the mount origins are all
build-tree paths.  lwsws is started with `-n` so only this build tree's `lib/`
is scanned for plugins, and `-c <generated config dir>`.

No `uid` / `gid` are configured: lws only calls `setuid()` / `setgid()` when
they are set (`lws_plat_drop_app_privileges()`, `lib/plat/unix/unix-caps.c`),
so lwsws does not need root and runs as whoever ctest runs as.

Two vhosts share the ctest host name:

| vhost | what |
|---|---|
| `:PORT` tls | `"alpn": "h3,h2,http/1.1"`, which is also what makes lws bind a QUIC UDP listener on the same port number (`server.c`, `check_quic:`), so h1, h2 and h3 are all reachable at one host:port like warmcat.com |
| `:PORT+1` cleartext | the h1 pipelining target, and the origin the tls vhost's `/proxy` mount proxies back to |

Mounts on the tls vhost:

| mountpoint | origin | why |
|---|---|---|
| `/files` | `file://` a generated dir | one small file and one generated 4MB file |
| `/gated` | `file://` | protected by `"interceptor-path": "/captcha"` |
| `/captcha` | `callback://lws_captcha_ratelimit` | the interceptor, with a very short `pre-delay-ms` / `post-delay-ms` |
| `/ws` | `callback://lws-status` | ws protocol mount |
| `/proxy` | `http://127.0.0.1:PORT+1/` | proxies back into this same lwsws |
| `/deaddrop`, `/deaddrop/upload`, `/deaddrop/get` | assets / `callback://lws-deaddrop` / upload dir | |

`keepalive_timeout` is 5s and the global `timeout-secs` is 10s, so the idle
close paths are reached inside a 60s test.

### Plugins

Loaded: `lws_captcha_ratelimit`, `lws-status`, `lws-mirror-protocol`,
`lws-deaddrop` (with `upload-dir` in the build tree and `allow-anonymous`, so it
needs no external service).

Not loaded: `lws-dht-dnssec-monitor`.  It needs `LWS_WITH_AUTHORITATIVE_DNS`,
`LWS_WITH_SYS_ASYNC_DNS_DNSSEC`, `LWS_WITH_SPAWN` and `LWS_WITH_SYS_WHOIS`, and
even then it spawns a privileged helper over a unix socket, publishes into a
DHT and talks to an ACME CA -- external services and credentials a ctest must
not depend on.  `lws-login` is not loaded either: its plugin only builds with
`LWS_WITH_STRUCT_SQLITE3`, and `api-test-lws-login-bff` already covers it.

## The cases

Each is a `-t <case>` of one client binary.  `--evlib uv` puts the *client* on
libuv too; the option is parsed by this test itself so it does not depend on
any library cmdline support.

### `captcha` / `captcha-h2` -- the interceptor handshake (C-468)

1. `GET /gated/` with no cookies -> 200, the challenge page, and the
   `lws_interceptor_v` visit cookie.
2. `GET /captcha/captcha.js` with no cookies -> 200, the interceptor's own
   asset (what the challenge page's `<script>` fetches).
3. `POST /gated/` with the visit cookie -> 303, the pass cookie, and
   `Location: /gated/?lws_interceptor_ok=1`.
   **This is C-468**: the challenge form posts to the gated url itself
   (`captcha-assets/captcha.js` sets `form.action = window.location.pathname`).
   Treating that as "not the form's POST" answered every submission with a 303
   back to the challenge, which is the infinite captcha loop warmcat.com hit
   and `6b004539e` reverted.
4. `GET /gated/?lws_interceptor_ok=1` with the pass cookie -> 303 to `/gated/`.
5. `GET /gated/` with the pass cookie -> 200 and the real gated content.

Each step gets its own client context: lws remembers the negotiated ALPN and
the advertised Alt-Svc h3 endpoint per context, so a second request on one
context would silently be upgraded to h3 whatever role the case asked for.

`captcha-h2` is also the regression test for **C-474**, which it found: step 3
failed with status 0 and it was not the interceptor's fault.  The lws **h2
client** sent the body from `CLIENT_HTTP_WRITEABLE` with zero stream credit
(the lws server opens the stream window at 0 and grows it by `WINDOW_UPDATE`
once it has the `HEADERS`), and the `WINDOW_UPDATE` that then arrived re-armed
the writeable callback on the now half-closed stream; this test's callback,
like any user's, wrote the body again, the server answered `GOAWAY`
(`STREAM_CLOSED`) and the response was lost with the connection.  The stock
`lws-minimal-http-client-post` (multipart, h2) hit the same thing
intermittently.  Fixed in `ops-h2.c`: no body callback without credit, no
writeable callback and no write at all on a stream after its `END_STREAM`.

The interceptor binds its cookies to the peer's IP (the JWT `sub` claim), so
these cases pin the client to one address family -- `localhost` resolves to
both, and lws is free to pick either per connect.

### `pipeline` -- h1 keepalive across a transfer (C-460)

On one raw keepalive connection to the cleartext listener:

1. a `GET` for the 4MB file and a `GET` for the small file written in **one**
   write, both responses drained and byte-checked;
2. the same pair again, but with the second request deliberately arriving as
   its own POLLIN *during* the big response -- the client stops reading so the
   server is still inside `lws_serve_http_file_fragment()` when it lands.  That
   is the shape the reverted C-460 release broke: the mid-transaction POLLIN
   re-attached an ah, cleared `hdr_parsing_completed`, and
   `lws_http_transaction_completed()` then silently no-opped;
3. one more ordinary transaction on the same connection, proving it really did
   come back to keepalive;
4. going quiet, and requiring the server to idle-close it (so the keepalive
   timeout was re-armed at all).

### `proxy`

A request through `/proxy`, whose origin is this lwsws's own cleartext
listener, so the onward request headers are really composed and consumed,
compared against the same file fetched from the origin directly.

### `h3race` -- the QUIC/TCP race under libuv (C-473)

An h3 client with the TCP fallback **enabled**, so the happy-eyeballs racer
really starts (the log line to look for is `TCP connected, waiting for QUIC
grace`).  QUIC wins on loopback and the TCP racer is parked.  The client then
stays alive 16s -- past the server's idle close of that unused TCP connection.
Before `5c8543f55` the ALPN migration copied and zeroed the evlib private block
before the racer teardown ran, so the racer's libuv poll watcher outlived the
wsi it pointed at and the peer's idle close was the POLLIN that dereferenced
freed memory.  The client must survive and still serve a further h3 request.

Run on libuv (where it crashed) and on the poll loop as a control.

Not covered as a case, but found while writing this: an **h3 client POST with a
request body** is worse still -- lwsws answers it with a QUIC
`CONNECTION_CLOSE`, error `0x6` `FINAL_SIZE_ERROR`, on the request STREAM frame
(type `0x0f`), ie, the client put two conflicting FINs on the request stream.
Reproduce with
`lws-minimal-http-client-post --h3 -l https://localhost:<tls port>/gated/`,
which fails differently again ("CLIENT_CONNECTION_ERROR: no ads" out of its
`CLIENT_HTTP_WRITEABLE`).  There is no h3 POST ctest anywhere in the tree.

### `quicabort` -- context destroy during the QUIC handshake (C-471)

A QUIC client is brought up and its whole context destroyed at 1, 3, 8, 20, 50
and 120ms -- `lws_context_destroy()` sends the `CONNECTION_CLOSE` -- spanning
"during the handshake" and "just after it".  lwsws must then still answer
ordinary h1 requests on both listeners.

## Running it

```
$ cmake --build <build tree> -j8
$ cd <build tree> && ctest -R lwsws-uv -j1 --output-on-failure
```

The fixture tests are pulled in automatically by `FIXTURES_REQUIRED`.  Never
run two ctest trees at once: the cleanup script kills background servers by
binary name.

## A libuv note

`stop_loop()` in `main.c` leaves the loop with `uv_stop()` and destroys the
context afterwards, from outside the service, rather than calling
`lws_context_destroy()` from the callback that decided to stop.  That is not
style: `lws_context_destroy()` from inside a callback only sets
`pt->destroy_self` and defers (`lib/core/context.c`, "if
(pt->inside_lws_service) ... deferred_pt = 1"), and under libuv the only place
that flag is ever acted on is `lws_io_cb()`
(`lib/event-libs/libuv/libuv.c:153`) -- the next time an fd in the loop has an
event.  When the last connection has just gone away there is no such event, and
`uv_run()` never returns: the process hangs forever.  Poking
`lws_cancel_service()` afterwards does not rescue it (the resulting `lws_io_cb`
is itself inside the service, so the re-entered destroy defers again).
