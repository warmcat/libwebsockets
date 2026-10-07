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
   on loopback), or an async DNS cache hit making
   `lws_client_connect_via_info()` deliver the CCE before it returns.
   Callers that touch state after the call (or free it in the CCE
   handler) break.  The pattern used: an `in_connect` flag that the CCE
   handler checks, deferring to the connect caller.
 - **Fixed quorums.**  Any consensus threshold written as a fixed count
   of peers is wrong for small deployments.  Derive it from what the
   routing table can actually supply.
 - **ANY-from state rows hide bugs.**  Prefer explicit source states in
   the state tables.

## HTTP

 - **Header (ah) lifetime.**  User code may read request headers in
   `LWS_CALLBACK_HTTP` and, for a request with a body, through
   `LWS_CALLBACK_HTTP_BODY` to `LWS_CALLBACK_HTTP_BODY_COMPLETION`; after
   that they are not guaranteed.  h2 / h3 streams release the ah right
   after dispatch; h1 currently holds it to transaction completion, but
   that is not promised.  Library code must not read the ah after
   dispatch: snapshot what it needs onto the wsi.  Never gate body
   delivery on `wsi->http.ah` being present.  Test any new ah reader
   against an h2 stream in HTTP_WRITEABLE.
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

 - `lws_client_stash_to_headers()` frees `wsi->stash` early in
   `LWS_WITH_SOCKS5` builds, and keeps it until close otherwise.  Sai's
   distro / coverage configs imply SOCKS5; little else does.  Any
   `if (wsi->stash ...)` guard is a feature that is off in distro
   packages.  Read the address with
   `lws_wsi_client_stash_item(wsi, CIS_ADDRESS, _WSI_TOKEN_CLIENT_PEER_ADDRESS)`.
 - Happy-eyeballs racers for a QUIC-first attempt are TCP.  Client job
   drivers that advance on COMPLETED must ignore a previous job's late
   CLOSED: after an h3 → h2 fallback, the h2 stream's CLOSED arrives a
   service pass after its COMPLETED.

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

## Secure Streams

 - An SS handle sees `LWSSSCS_CREATING` exactly once; user code does
   one-time init there.  In sspc, a `DISCONNECT_ME` from any proxied state
   drops the whole proxy link, unlike direct SS.
 - `lws_ss_set_metadata()` binds by reference: don't pass stack buffers.
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
