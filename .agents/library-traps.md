# Library rules and recurring bug classes

These are rules about lws internals that are not obvious from any one
file, and classes of bug that have recurred.  The state machine and
sansIO design is documented properly in
`READMEs/README.wsi-state-machines.md`, `READMEs/README.sans-io-split.md`
and `READMEs/README.sans-io-port.md`; read those before changing either.

## Bug classes worth hunting for

 - **Staged failures.**  A fatal condition detected synchronously but
   enforced asynchronously, with success returned meanwhile.  The h2
   parser's GOAWAY used to queue the frame and return 0 ("carry on"), so
   parsing continued on a connection already judged fatal; connection-
   scoped hpack state then drove per-stream header storage out of bounds.
   Every individual check was correct; the defect was the contract
   between files.  When reviewing, ask "what does the caller do with
   this verdict?", and look for connection-scoped parser state driving
   per-stream storage.  Hunt by driver / inner-parser pairs, and compare
   h1 / h2 / h3 sibling guards.
 - **Eating the tx half.**  `lws_is_flowcontrolled()` is about rx only.  A
   role's handle_POLLIN that early-returns on it before looking at revents
   also suppresses POLLOUT, which wedges anything whose only way forward
   is the writeable.
 - **Iterator invalidation by rotation.**  Fair-share child walks that do
   remove + add_tail of the serviced child under
   `lws_start_foreach_dll_safe` can loop forever (the cached next points
   back).  Bound such walks by the child count at pass start.
 - **Synchronous completion.**  Paths that are usually asynchronous can
   complete inside the call: a TLS client handshake step (resumed TLS 1.3
   on loopback), or an async DNS cache hit, or an NXDOMAIN from the
   blocking resolver (connect2.c / connect3.c), making
   `lws_client_connect_via_info()` deliver the CCE before it returns NULL.
   (Async dns caches an NXDOMAIN but never serves an A/AAAA lookup from
   it, so a test cannot get an in-call CCE that way.)  Every plugin caller needs the guard (G-043).
   `lws_create_adopt_udp()` likewise delivers RAW_CLOSE inside the call
   when the UDP connect() of a numeric address fails (adopt.c), so state
   its callback can already reach must not be used after it (G-067).
   `*i->pwsi` is only stored after the client bind (io/client/connect.c),
   so a CCE handler that identifies its connection by `wsi == *pwsi` does
   not recognise one delivered inside the connect call.
   Callers that touch state after the call (or free it in the CCE
   handler) break.  The pattern used: an `in_connect` flag that the CCE
   handler checks, deferring to the connect caller.
 - **Per-level budgets that multiply.**  A work or depth budget reset
   inside each nested construct bounds one level but not the total: k
   levels of a 4096-step budget is 4096^k.  lhp's `:is()` / `:where()` /
   `:not()` selector budget and calc() `var()` expansion had this shape
   (G-080, G-082).  Bound total work per document / request, not per level.
 - **Resolving untrusted URLs.**  `lws_http_rel_to_url()` copies an
   absolute `file://` URL whatever the base's scheme, and SS opens any
   `file://` endpoint, so a remote document can name local files (G-088).
   Callers resolving untrusted URLs need their own scheme policy.
 - **Per-host limits on IPv6.**  One IPv6 host commands a whole /64.  In
   the DHT, `dht_source_key()` (dht.c) is the per-host key used by
   admission, the bucket cap and BEP 42; anything counting distinct peers
   (votes, quorums, rate limits) must key on it, not on the full address
   (G-094).
 - **Heuristics driven by unauthenticated input.**  A counter or state
   change moved by packets that never authenticated is an attacker's
   lever: QUIC's consecutive-decrypt-failure close and key-phase probe
   counters (ops-quic.c) let an injector kill a connection (G-104).  Only
   authenticated packets may change connection state.  Likewise a DHT
   routing-table entry may only change on proof from the endpoint itself
   (its reply to a request we sent there), never because it was named in
   a nodes list or sent one unsolicited datagram (G-119).  DHT replies are
   now only taken against `req_pending`, so a new request sender must go
   through `dht_send_request()` or its replies are dropped.
 - **Jumps past initialisers.**  A `goto` (or `switch` case) that jumps
   past `char buf[N] = {0};` skips the initialiser: the buffer is
   indeterminate at the label.  -Wall -Wextra are silent; gcc's
   -Wjump-misses-init finds it (C only: g++ rejects it under -Werror,
   clang accepts and ignores it).  Declare everything a label's path uses
   before the first jump (G-105 sent stack to the peer as Set-Cookie).
 - **Two parsers deciding identity.**  When a signed payload is checked by
   one parser and consumed by another, they must agree on what it is.
   dht-dnssec bound a zone to its first `$ORIGIN` while auth-dns installs
   it under its last one, so a zone signed for one domain was served as
   another (G-117).  The consumer must re-derive the identity with the
   parser that will serve it and compare.
 - **Fixed quorums.**  Any consensus threshold written as a fixed count
   of peers is wrong for small deployments.  Derive it from what the
   routing table can actually supply.
 - **ANY-from state rows hide bugs.**  Prefer explicit source states in
   the state tables.
 - **Before filing "unbounded buflist"**: every `lws_buflist` refuses to
   grow past `LWS_BUFLIST_OOM_LIMIT` (2MB, `lws_buflist_check_room()`),
   so check the append's failure handling instead (G-076, disputed).

## HTTP

 - **Header (ah) lifetime.**  User code may read request headers in
   `LWS_CALLBACK_HTTP` and, for a request with a body, through
   `LWS_CALLBACK_HTTP_BODY` to `LWS_CALLBACK_HTTP_BODY_COMPLETION`; after
   that they are not guaranteed.  h2 / h3 streams release the ah after
   `LWS_CALLBACK_HTTP` for a bodyless request, or after
   `HTTP_BODY_COMPLETION` (lws_http_ah_release_after_dispatch(), server.c);
   h1 currently holds it to transaction completion, but that is not
   promised.  Library code must not read the ah after
   dispatch: snapshot what it needs onto the wsi.  Never gate body
   delivery, or a check on the body's state ("body already complete",
   "more than content-length"), on `wsi->http.ah` being present: the
   check silently stops applying once the ah goes (G-016), and on h3 a
   trailers HEADERS block attaches a fresh ah (G-022).  Test any new ah reader
   against an h2 stream in HTTP_WRITEABLE.
 - Deliver `LWS_CALLBACK_HTTP_BODY_COMPLETION` only through
   `lws_http_body_completion()`, which latches `wsi->http.rx_body_done`
   so completion happens at most once per request on every role (G-016,
   G-022).  Calling the protocol callback directly reopens that bug.
 - `WSI_TOKEN_HTTP_COLON_AUTHORITY` exists only in builds with h2 or h3
   (or `LWS_HTTP_HEADERS_ALL`): library code reading it needs that guard
   or the h1-only build breaks.
 - async-dns caps every reply at 1500 bytes, TCP included
   (`LWS_ADNS_MAX_PAYLOAD`).  That cap is currently the only bound on
   DNSSEC verification work per response (G-113): raising it needs a
   verification budget at the same time.
 - A prior-knowledge h2 network connection holds a pool ah for its whole
   life (attached at connect, detached at destroy), so every h2
   connection costs one ah before any stream.  Contexts with SS ConMon
   also run a captive-portal check whose client takes one: tests that
   size the ah pool need `LWS_SERVER_OPTION_CPD_BYPASS`.
 - On h3, a header block started with `lws_add_http_header_status()`
   must be finalized (`lws_finalize_write_http_header()` /
   `lws_finalize_http_header()`) before it is written: the QPACK prefix is
   only filled in then, and `LWS_WRITE_HTTP_HEADERS_CONTINUATION` is not
   framed on h3 (qpack.c, ops-h3.c; G-101).
 - **`lws_hdr_extant()`** reads `frags[n].flags & 2`, not just whether a
   fragment index is set.  Anything creating ah fragments itself must set
   the flag, or the header reads as absent (or as the ah's previous
   user's).
 - **Body framing (RFC 9112 6.3).**  An h1 request with neither
   Content-Length nor Transfer-Encoding has no body.  The lws client sends
   a body with no Content-Length as chunked.  The h1 server accepts only a
   lone `chunked` transfer coding.
 - Whatever follows the headers in the same read is stashed on the
   buflist *before* `lws_http_action()`, because `pt->serv_buf` is reused
   by status / file / redirect responses.
 - **Ranges / multipart**: delimiters are built from the same format
   macros for both the bytes sent and the Content-Length sizing, so the
   two cannot drift.  Keep it that way.  A response whose last range ends
   short of EOF must still be the final write (END_STREAM on h2 / h3).
 - **Proxy mounts** (`LWSMPRO_HTTP`): the vhost must use the default http
   protocol, or one whose callback defers to `lws_callback_http_dummy()`,
   which carries the proxy's header relay.  The onward request is composed
   from the decoded URI, so it must be re-encoded.  A file mount falls
   through to the mount protocol's `LWS_CALLBACK_HTTP` when the file is
   missing.
 - **SSE** connections sit in an established state that looks like idle
   keepalive to the h1 rx policy; `wsi->http_carries_sse` keeps the idle
   timeout and response watchdog off them.
 - Any transfer must renew its timeout per piece sent.
 - A request joining a kept-warm h2 / h3 connection gets
   `LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP` at the join with status 0,
   before any response.  This is a known open design question; tests
   skip a status-0 established.
 - Non-pipelining h1 clients default to keeping the connection warm for 5s
   even after sending `connection: close`.

## Writeable and POLLOUT

 - WRITEABLE can arrive unrequested (h3 stream writes re-arm the writer;
   h2 WINDOW_UPDATE on stream 0 wakes every child).  Code that parks a wsi
   waiting on a side channel must track completion itself.
 - `lws_has_buffered_out()` counts in-flight (sent, unacked) data as well
   as unsent; `lws_has_unsent_buffered_out()` counts only pending tx.
   Close-flush and deferred completion want the first; "may I write"
   decisions want the second.  Using the first on QUIC streams serialises
   to one fragment per round trip.
 - A server QUIC netconn shares the listen UDP socket and is not in the
   fds table, so `lws_change_pollfd()` on it is a silent no-op.  POLLOUT
   requested by any child during a pass latches
   `io.leave_pollout_active`, overriding a DROP; a child that re-arms while
   it cannot progress spins the loop on the always-writable UDP socket.
 - On a server, every QUIC connection that completed its handshake has a
   bidi stream child from the ALPN migration onwards
   (`rops_alpn_negotiated_quic()`: the old wsi becomes stream 0 under the
   new netconn), whether or not the peer ever opens a stream.  "Idle" or
   "has requests" decided by counting bidi children is therefore always
   "busy" after the handshake.
 - A failed `lws_write()` marks the socket unusable and leaves closing it
   to the caller, and `lws_callback_on_writable()` refuses an unusable
   wsi.  A protocol that keeps such a wsi (a long-lived UDP socket, say)
   waits forever for writeables it will never get.

## TLS

 - Never close the fd a TLS object was created with as if it were still
   the wsi's socket: QUIC client TLS is created lazily, and racer
   promotion or socket swaps reuse fd numbers.
 - The TLS close stage must not close over unread rx: send close_notify
   (SHUT_WR), then read and discard until FIN, as for plaintext.
   Otherwise the kernel aborts the connection and drops the tail of what
   was flushed just before.
 - All ALPN handling happens once, in `lws_ssl_client_connect2()`, after
   the peer is confirmed; backends don't do it.
 - Running vhosts pick up renewed certs without restart: vhosts watch
   their cert files and swap the TLS ctx (old one retired by refcount).
   Grace period is `info->tls_cert_grace_secs`.

## Client connect

 - `lws_client_stash_to_headers()` keeps `wsi->stash` until close in
   every build (it used to free it early with SOCKS5).  Read the address
   with
   `lws_wsi_client_stash_item(wsi, CIS_ADDRESS, _WSI_TOKEN_CLIENT_PEER_ADDRESS)`.
 - Whether credentials may follow a client redirect is decided only by
   `lws_client_redirect_creds_ok()` (https with strict verification, same
   host or a subdomain, or an SS policy `redirect_credentials_to` entry).
   New credential-bearing paths must go through it (G-027).
 - Happy-eyeballs racers for a QUIC-first attempt are TCP.  Client job
   drivers that advance on COMPLETED must ignore a previous job's late
   CLOSED: after an h3 → h2 fallback, the h2 stream's CLOSED arrives a
   service pass after its COMPLETED.
 - An h2 client request moves to a new stream wsi at the SETTINGS
   migration (http2.c, `h2n->swsi`), so per-request state kept on the
   client wsi must be copied there explicitly.  `client_no_follow_redirect`
   is; the redirect counter was not, and reset to 0 on every redirect that
   needed a new connection (G-026).  h1 and h3 keep the request on the
   same wsi.

## State machines

 - Attribute bits in the wsi state word must survive
   `lws_role_transition()`, which rewrites the whole word.
 - Bools that some resets clear and some don't are a hazard; prefer state.
 - The halves are called "sansIO" and "IO" (not "core", which means
   `lib/core`).  Transmit is a pull: IO asks the role for bytes; app data
   from `lws_write()` is the one push, framed in place in `LWS_PRE`.
 - A no-socket harness must never call `lws_service()`: it enters the real
   poll() and blocks until the next sul.
 - Renaming member accesses across the tree: never include `plugins/`
   (they can't see `struct lws`), and audit directories no local build
   compiles (`plat/windows`, freertos, optee, ...) before committing.
 - ws has two writeable paths, h1 (`rops_handle_POLLOUT_ws()`) and the mux
   one ws over h2 / h3 uses (`lws_ws_mux_child_pollout()`), and two rx
   parsers, server (`server-ws.c` / `ops-ws.c`) and client
   (`client-parser-ws.c`).  The client handshake offer is composed twice
   too (h1 in `client-ws.c`, h2 / h3 in `http2.c`), with the accept checks
   in a third place.  Fixes have repeatedly landed in only one of each set
   (G-036, G-040, G-041, G-042, G-044): check the twins.
 - At MQTT CONNACK the whole `wsi->mqtt` struct, including per-connection
   client settings (`client.qos2_state_ops`, `id`, `aws_iot`), moves to
   the sid 1 child and the network wsi gets a fresh zeroed one
   (`mqtt.c`, after `w->mqtt = wsi->mqtt`).  Parser code reading
   `wsi->mqtt->client.*` on the network wsi after CONNACK sees nothing
   (G-037).

## Secure Streams

 - An SS handle sees `LWSSSCS_CREATING` exactly once; user code does
   one-time init there.  In sspc, a `DISCONNECT_ME` from any proxied state
   drops the whole proxy link, unlike direct SS.
 - `lws_ss_set_metadata()` binds by reference: don't pass stack buffers.
   The value must outlive every reconnect, not just the first connect;
   use `lws_ss_alloc_set_metadata()` for anything the caller owns (G-143,
   seen by ASan only on the retry path).
 - SS flow windows (`manual_initial_tx_credit`,
   `lws_ss_add_peer_tx_credit()`) only act on protocols with `tx_cr_add`,
   ie, h2.  On h1 nothing holds the peer back (G-144).
 - The builtin `__default` streamtype is TLS-only and ignores `http://`
   endpoints ("ignoring non-tls scheme"); in-process plain-http tests
   need their own `pss_policies_json` (see api-test-lhp-doc-cache).
 - Server `LWSSSCS_SERVER_UPGRADE` goes to the accepted stream: CREATING,
   CONNECTING, SERVER_UPGRADE, CONNECTED.
 - A body-carrying SS method with a tx callback but no known length is
   sent chunked on h1.

## lejp

 - Since 2021, element paths of a scalar array `x` are `x[]`, which never
   match a reflex spelled `x`.  When adding a scalar-array key to a lejp
   token list, add the `key[]` reflex too.  Otherwise a later
   trailing-wildcard reflex (`s[].*`) silently hijacks elements 2..n.
 - A catch-all like `"s[].*"` matches every deeper path.  Every nested key
   needs its bare `"s[].*.<key>"` entry too.
 - A trailing `*` eats everything including dots: put `"x.*.*"` before
   `"x.*"`.
 - '#' comments are opt-in (`LEJP_FLAG_FEAT_COMMENTS`).  Out-of-tree users
   parsing hand-edited JSON need to set it after `lejp_construct()`.
 - Callbacks must not return positive values for things that aren't
   errors: positive returns at value end abort the parse.
 - Scheme / keyword tables indexed by position drift from their enums; use
   `{prefix, ENUM}` pairs.

## Plugins and stubs

 - In a privileged stub, when one request type hardens its file access
   (private-dir fd checks, O_NOFOLLOW, regular-file and size checks),
   check every other request type in the same stub: they usually still
   open paths directly (G-098, cert-dist client `get_hash`).

 - `PROTOCOL_INIT` comes once per vhost instantiating the protocol, so it
   is wrong for once-per-process work.  Use `lws_plugin_protocol_t`
   `.init` / `.deinit` (called once per context).
 - Composing a plugin (`LWS_PLUGIN_STATIC`, listed in `info->plugins`) is
   legitimate; lws then drops a builtin or dlopened plugin of the same
   name.  Composed plugins' protocols go on vhosts via `info.pprotocols`.
   `_BUILTIN` plus composed gives two copies with separate statics.
 - A test-built protocol plugin (`libprotocol_<base>.so`) needs
   `target_compile_definitions(... LWS_BUILDING_SHARED)`, or
   `-fvisibility=hidden` hides its export.
 - Stubs don't take pvos.  Spawned stub children get cwd `/` and no
   environment, so relative plugin dirs don't work in them.
 - `PROTOCOL_DESTROY` is not delivered to protocols a plugins-build vhost
   never instantiated: core protocols injected into every vhost tear down
   their per-vhost state in vhost destroy instead.
 - Logic in plugins with no end-to-end test (eg ACME) goes in a separate
   testable file (`acme-json.c`) that an api-test compiles in.
