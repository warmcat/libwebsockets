# Library rules and recurring bug classes

These are rules about lws internals that are not obvious from any one
file, and classes of bug that have recurred.  The state machine and
sansIO design is documented properly in
`READMEs/README.wsi-state-machines.md`, `READMEs/README.sans-io-split.md`
and `READMEs/README.sans-io-port.md`; read those before changing either.

## Bug classes worth hunting for

 - **FreeRTOS builds force `LWS_MAX_SMP 1`, so `lws_pt_lock()` and
   `lws_context_lock()` compile to nothing there.**  esp-idf event
   handlers, the timer daemon and ISRs run outside the lws thread and
   must hand work to it (SMD, `lws_cancel_service()`), never touch lws
   state directly (G-475, G-478).

 - **A fix to one backend's helper rarely reaches its siblings.**  The
   C-314 `lws_x509_create_cert()` double-free fix went into mbedtls only
   and stayed open on openssl and gnutls for months (G-403).  When fixing
   or verifying a TLS / gencrypto backend function, grep the same
   function in every backend under lib/tls/.

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
 - **DNS name encoders trust their input.**  In the auth-dns signer a
   passing NSEC3 pre-pass does not cover every owner (NSEC3 owners are
   added afterwards with one more label), so every `name_to_wire()`
   failure must be checked where it is called (G-162); name syntax
   (labels 1..63, total <= 255, no empty labels) is validated nowhere in
   the zone parser.  The async-dns query encoder is bounded only by
   `DNS_MAX` in `lws_async_dns_query()` (G-161): raising it needs real
   checks in `lws_async_dns_writeable()`.
 - **`lws_auth_dns_verify_zone()` is a self-consistency check, not
   authentication** (G-163): it trusts DNSKEYs in the zone text itself.
 - **Varint-length encoders:** bounding a whole field up front with
   "len + length + small slack" is wrong once both length varints go
   multi-byte; bound each piece just before writing it (G-154, hpack).

## Addresses and PROXY v2

 - **Two identities behind PROXY v2:** `lws_get_peer_simple()`,
   `lws_io_peer_address()` and `lws_get_peer_addresses()` return the
   forwarded client (the effective entry of the peer stack,
   `pstack_count > 1`, `lws_peer_effective()`, since G-199 P1
   8ad13a51f / ae12f5f60); anything calling `getpeername()` directly gets
   the proxy.  Each stack entry has a credibility level (HEARSAY <
   VOUCHED < ROUTABLE < CRYPTO); per-client policy must not key on
   HEARSAY, see security-audit/reports/peer-address-stack.md.  Since
   500f08eab `lws_io_peer_policy()` decides: an effective entry at VOUCHED
   or better is believed; otherwise `lws_get_peer_host_key()` returns
   `LWS_HOST_KEY_UNPROVEN` and peer limits count it in one context-wide
   unproven pseudo-peer (`.unproven_limit_wsi`).  QUIC entries rise to
   ROUTABLE / CRYPTO as QUIC proves them (1a9eb394b).  Peer limits key on the named client since
   G-196 (a trusted proxy's connection counts against nobody until its
   header arrives).  New per-client
   policy must use the helpers, and anything evaluated at adopt runs
   before the PROXY header has been read.
 - **The h1 role attaches an ah at adoption, before pre-accept:** anything
   that changes `wsi->peer` later must detach and re-attach the ah, or
   `lws_peer_track_ah_detach()` asserts (G-196).  The ah wait list takes
   POLLIN off on every refused attach, and pre-accept leaves an ah waiter
   deaf (G-209); POLLIN returns when the ah is granted.
 - **Numeric hosts vs libc:** `lws_parse_numeric_address()` is
   inet_pton-strict since G-197, but glibc `getaddrinfo()` still resolves
   inet_aton forms (`012.0.0.1` as 10.0.0.1, `10.1`, `167772161`,
   `0xa.0.0.1`).  `lws_host_is_ambiguous_numeric()` detects those, and the
   client resolve paths refuse them; use it before trusting any filter
   decision on a host string the platform will resolve.  The client
   connect refuses them in `lws_client_connect_2_dnsreq_MAY_CLOSE_WSI()`
   before the proxy decision, so SOCKS5 / HTTP CONNECT are covered (G-212).

## HTTP

 - **A ws upgrade never passes `lws_http_action_gates()`.**  On h1, h2
   and h3 it only gets the interceptor chain, and a proxied upgrade
   leaves from `lws_process_ws_upgrade()` before any auth or filter
   callback (G-489).  Any new mount gate needs a ws twin.
 - **An h1 wsi carries per-request state across keep-alive
   transactions**: anything set per request must be cleared in
   `lws_http_transaction_completed()` (`interpreting`, `cache_*` were not:
   G-493).  h2/h3 streams get fresh wsis, so a fix tested only there
   misses this.
 - **qpack decoder:** the only bound on a peer-chosen dynamic index is the
   late `insert_count` / `used_entries` check; Required Insert Count and
   Base are not validated (G-191).  Any new path resolving a dynamic
   reference must go through `lws_qpack_get_dynamic_entry()`.
 - **h2/h3 trailers never reach the request headers:**
   `lws_h2_hpack_no_store()` gates every hpack store once the stream has
   left `LRS_HEADERS`, and h3 drops trailer fields after validating them.
 - **JWT cookies are interchangeable across purposes.**
   `lws_jwt_get_http_cookie_validate_jwt()` checks signature, iss, aud,
   nbf, exp and sub only; the client chooses the cookie name.  Two cookies
   signed with one jwk for different purposes need a claim that tells
   them apart (G-171, interceptor visit vs pass).  The library now has
   `purpose` in `struct lws_jwt_sign_set_cookie`, written as a `"pur"`
   claim and required by `lws_jwt_get_http_cookie_validate_jwt()` (a NULL
   purpose refuses tokens that carry one).  Session tokens too, since
   G-188: `lws_jwt_auth_create_via_info()` can require iss / aud /
   purpose, `lws_jwt_auth_create()` refuses tokens carrying `pur`, and the
   auth server's tokens carry `"pur":"sso"` (`LWS_JWT_AUTH_PURPOSE_SSO`):
   tests minting session tokens for lws-login or the auth server must
   include it.  `lws_json_simple_find()` ignores JSON
   structure, so a claim stays unforgeable only because the signer
   purifies sub and refuses `"pur":` elsewhere: a new free-text claim in
   `jwt_sign_cookie_value()` needs the same treatment.
 - **A Location built from `WSI_TOKEN_*_URI` needs a backslash check:**
   the URI parser decodes `%5C` to `\` and keeps it while collapsing `//`,
   and browsers follow `/\host` as `//host` (G-173).
 - **HEAD bodies:** since G-190 the role write paths drop a HEAD answer's
   body bytes and keep END_STREAM / FIN, so handlers need no HEAD check
   of their own; a HEAD's headers still match the GET's (including any
   coding).
 - **The control-byte check on outgoing headers**
   (`lws_hdr_add_value_bad()`) lives only in the role-agnostic
   `lws_add_http_header_by_name()` / `_by_token()` wrappers.  Code calling
   `lws_add_http2_*` / `lws_add_http3_*` directly, or composing with
   `lws_snprintf()` (the h1 client request line), gets no check (G-156).
 - **Per-host keys in plugins:** `lws_get_peer_simple()` resolves h2/h3
   stream wsis to the connection's real peer (the QUIC netconn address on
   h3) and honours PROXY v2.
 - **`content_length_explicitly_zero` is the per-request "no body" signal**
   on every role, except h3 FIN-without-CL, which ends through
   `lws_h3_rx_fin_server()` and the body path.
   `lws_return_http_status()` never applies stream compression.
 - **h2 server dispatch is deferred to the writeable walk:** every HEADERS
   in one read is decoded, each taking an ah, before any is dispatched.
   Per-connection ah accounting must exclude streams the peer has
   finished (END_STREAM / half-closed remote; h3 `qs->fin_received`), as
   `lws_mux_ah_cap_reached()` does (G-028 2a, cap
   `max_http_header_pool_per_mux`, default 8).
 - **Request bodies have a minimum rate on every role** since G-028 2b
   (`http_body_min_rate` 500 B/s after `http_body_grace_secs` 20s): a test
   trickling a body slower than that past 20s must raise the grace or use
   `LWS_HTTP_BODY_MIN_RATE_NONE`.
 - **h3 has no destroy_role:** per-stream state that h1/h2 free in
   destroy_role (eg, the stream compressor) must be freed in
   `rops_close_kill_connection_h3()`.
 - **Snapshots taken at dispatch (G-151 stage 1):** Content-Type
   (`wsi->http.content_type`, used by lws_spa), Range, gzip-acceptable,
   stream coding (validated in the gate, so h3 too), basic-auth user
   (`lws_http_basic_auth_user()`), method_post, expect_continue.  New code
   must use these, not the ah, after LWS_CALLBACK_HTTP.
 - **`rx_policy()` runs only on POLLIN / POLLOUT revents** (io/service.c),
   so an h1 ah re-attach after a release happens at the next poll event,
   not every service pass.  Pipeline depth in
   `lws_http_transaction_completed()` is counted only on the branch that
   still has the ah (G-151 stage 0 notes).
 - **A cgi takes no BODY / BODY_COMPLETION callbacks**: its body ends via
   `lws_cgi_stdin_body_end()`.  `lws_get_child()` is true for a cgi wsi
   (the stdwsis are its children), so the proxy branches in
   `lws_callback_http_dummy()` trigger for cgi too.
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
 - A backend refuses an unsafe mTLS vhost config in
   `lws_tls_server_client_cert_verify_config()`, called from
   `lws_tls_server_vhost_ctx_setup()` at creation and at cert rotation,
   not in `certs_load`: look there before filing a missing refusal.
 - **openssl client SSL_CTXs are shared** between client vhosts whose
   creation parameters hash the same, so a per-vhost trust change after
   creation (`lws_tls_client_vhost_extra_cert_mem()`) reaches every vhost
   sharing it (G-392).

## Raw connections

 - **CONNECT needs a CONNECT mount** (`LWSMPRO_CONNECT`,
   `"origin": "connect://<protocol>"`, mountpoint = `host:port`) since
   G-002; anything else gets 405.  A raw connection has a validity timer
   only where lws started one (today, a CONNECT mount): there
   `lws_validity_confirmed()` restarts it via
   `_lws_validity_raw_keepalive()`, elsewhere it does nothing.  Raw has no
   ping of its own, so the protocol must confirm more often than the
   hangup time (default 50s).  A rebind (SNI, Host:, :authority) moves a
   server wsi's inherited `retry_policy` to the new vhost's and re-arms a
   running validity timer (G-222).

## WebSocket rx

 - **A RECEIVE is not a message, and its UTF-8 may be partial.**  ws rx
   UTF-8 validation (default for TEXT) only insists on a complete
   sequence at the end of the final fragment: a non-final fragment, or a
   chunk of a frame bigger than the rx buffer, can end mid-character
   (ops-ws.c).  A protocol that stores or relays each RECEIVE as a whole
   message must reassemble (`lws_is_final_fragment()`) or validate it
   itself with `lws_check_utf8()` before echoing it as TEXT (G-379).
   BINARY frames are never UTF-8 validated: relaying one as TEXT without
   checking `lws_frame_is_binary()` breaks every receiver (G-450).
 - A server's ws RECEIVE is capped by one read, `pt_serv_buf_size -
   LWS_PRE` (4096 by default, 8192 in lwsws), not by the protocol's
   `rx_buffer_size`: anything bigger always arrives in pieces
   (io/service.c).  A protocol that refuses pieces caps its messages there.

## Logging secrets

 - Header values go through `lws_http_hdr_log_value()` (credential
   headers, urlargs and unknown names: length only; paths lose the
   query) and paths through `lws_http_log_path()` since G-350 / G-351.
   New log sites must use them; never hexdump key, PEM, cookie, token or
   metadata buffers at any level (G-345, G-349).

 - Secret buffers (keys, DER, PEM, session tickets, ECDH secrets) are
   wiped before free in every TLS backend since G-349 (24e8da514 openssl,
   45ce40b50 gnutls, f60d12dad mbedtls, 5c59cdb13 bearssl, ce6ca0b17
   schannel, b94714bff openhitls); the last four were not compiled here,
   only in Sai.
 - `private-lib-tls.h` and the backend headers are included early in
   `private-lib-core.h`, before `lws_free` / `lws_free_set_NULL` are
   defined: a static inline in a TLS backend header can't use them, put
   such helpers in a .c file.

## QUIC io state

 - When a QUIC connection moves to a new wsi on ALPN negotiation (h3,
   lws-quic), only what `lws_io_udp_transfer_socket()` copies explicitly
   moves: any new per-connection io state (peer stack, relay port, relay
   proof...) must be added there too (G-359, 7e91787ff).
 - An event lib without `migrate_wsi` gets its per-wsi data `memcpy`d to
   the new wsi.  Any evlib whose per-wsi data names its wsi, or is
   registered with the loop by address, must implement it (uloop does
   not: G-471).
 - **QUIC passthrough relay state (`cx->pt_qflows`, `pt_qpending`,
   `pt_relayed`, `vh->passthrough_qwsi`) is context-wide and unlocked**:
   listener threads, the relay wsi's tsi and the pt-0 sweep all touch it,
   so it is only safe with one service thread until G-482 is fixed.

## Accept gating

 - Only TCP listen sockets (`role_ops_listen`) are ever paused; QUIC and
   passthrough relay UDP sockets carry established flows and never are
   (G-361, eac559ac5).  `lws_accept_listener_open()` is the single
   decision for both the TLS restriction gate and the fds-full pause.
   A server QUIC connection takes its TLS slot only at address validation
   (io op `tls_quic_admit`, `LWS_IO_OPS_ABI_VERSION` 4): spoofed Initials
   never consume slots.

## Vhost selection

 - Host / :authority / SNI / passthrough vhost selection is scoped to the
   accepting listener since G-329 (36126a218): `lws_select_vhost*()` take
   the accepting vhost and only consider `lws_vhost_shares_listener()`
   vhosts.  `lws_vhost_bind_wsi()` returns nonzero when it refuses a move
   (a connection bound to a protocol the new vhost lacks, G-330): every
   caller must act on it (drop, 421, reject).
 - An h3 vhost with `iface` had no quic listener before 65b2f2a40 (the
   quic listener did SO_BINDTODEVICE unconditionally: "unable to create
   INET socket 19"); now only with `.bind_iface`, like tcp.
 - A raw TLS client (method "RAW" with `LCCSCF_USE_SSL`) gets
   RAW_CONNECTED after the handshake, SNI from `i.host`; delaying the
   request from a sul lets a test destroy a vhost in between
   (api-test-vhost-listener-scope proto-moved).

## Lists

 - `lws_start_foreach_dll_safe` survives removal of the current entry
   only.  Removing the cached next inside the body trips the dll2
   generation guard: an assert abort in builds with asserts (Debug, or
   CMake build type None), a log and restart from the head with NDEBUG.
   A "UAF from a stale _safe next" is really an assert DoS / revisit
   (G-312, api-test-h2-parked-rx).  Walks whose body can free arbitrary
   members move the list to a local owner and take from its head.

## Client connect

 - **A restart is a second connect for vhost choice.**  Redirects, auth
   retries, QUIC->TCP and address fallback go through
   `lws_client_transport_rebind()` (close.c), not connect.c: a rule like
   "JIT trust only when the app gave no `i.vhost`" enforced only at
   connect is bypassed by a 302 (G-407).

 - **`i.pwsi` is not cleared when the client wsi closes**: it is written
   at connect and NULLed only on a connect failure.  Track closure by
   the wsi's final callback on its own protocol, not by watching `*pwsi`:
   since G-298 (ccd5e26a0) every client wsi gets exactly one
   CLIENT_CONNECTION_ERROR (never connected) or CLOSED, including during
   context destroy.  `LWS_CALLBACK_WSI_DESTROY` only goes to
   protocols[0].  A wsi's timers are cancelled after its vhost unbind
   (1af9d316b), so PROTOCOL_DESTROY arming one on a dying wsi is safe.
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

 - **`__default`'s endpoint is `${endpoint}`, and an app setting it to a
   `file://` url is a designed use** (lhp/dlo, 39 api-test-lhp-dlo tests).
   A rule treating any substituted endpoint as untrusted breaks it; trust
   has to follow where the metadata came from (G-372).
 - An SS rx callback can get `len == 0` with a NULL `buf` at EOM; a
   `memcpy` from it is a bare SIGTRAP under UBSan (nonnull).
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
 - **lws_dsh flags reshape records:** with `LWS_DSHFLAG_ENABLE_COALESCE`,
   `lws_dsh_alloc_tail()` appends onto the existing tail object; with
   `ENABLE_SPLIT` and `splitat` it cuts a record into several objects and
   only the first carries the header.  Flags are per kind since
   2acd3aa4c: give a record-structured kind
   `lws_dsh_set_kind_flags(dsh, kind, 0)` (G-186); `lws_dsh_empty()` keeps
   them.  A pointer from `lws_dsh_get_head()` has no LWS_PRE headroom
   (the object header sits right before it), so never pass one to a
   transport `_write` / `proxy_write`: copy behind `LWS_PRE` first, as
   `lws_ssproxy_stage_dsh_head()` does.  Transports under the mux get
   `LWS_PRE - 4` (G-203).
 - **Peer credential checks are one-sided by design:** C-630 checks client
   peer ids on the proxy side; the sspc client only logs the proxy's
   uid/gid and does not require it to match (maintainer, G-185).  Any
   local user can squat an abstract UDS name: where the proxy's identity
   matters, use a filesystem-path UDS.
 - **The SS tcp proxy listens on loopback by default** (G-187): with
   `ss_proxy_port` and no `ss_proxy_bind` it binds 127.0.0.1 (::1 with no
   IPv4), and any bind that is not a numeric loopback address (including
   interface names like "lo") is refused unless
   `.ss_proxy_tcp_allow_remote` is set.  The tcp link has no client
   authentication.
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
 - **Without `LEJP_FLAG_FEAT_STRICT_KEY_CHARS` a key containing '.' can
   match a deeper member pattern** while the enclosing object was never
   opened (SS policy, lejp-conf: G-395, G-399).  lwsws can't set the
   flag (it needs keys like `".zip"`), so callbacks that write to a
   "current object" must check it exists (and is the right depth).
   At PAIR_NAME `ctx->sp` is the depth of the object holding the key
   (document 0, array 1, element 2); a string value adds one.  A middle
   `*` in a match pattern stops at `.` or `[`.  `path_match` is not
   cleared when nothing matches, so a stale match can survive into the
   next key (policy-json.c checks depth for this, G-395).

## lws_struct

 - **A struct parsed from peer JSON is not validated.**  String members
   the peer omits stay NULL, integers go through atoi() with no range or
   sign check, and malformed nesting can build a different tree from the
   document (G-437, G-440, G-441, G-442).  Consumers NULL-check every
   string member and range-check integers themselves.

## DHT transport sequencer

 - **Two paths destroy a sequencer without `on_state_change`**: the
   oldest-used eviction in `dht_ts_create()` and the idle-out.  Consumers
   get no WRITE_FAILED for queued data there (G-496), so any promise to
   consumers about sequencer lifetime has to cover them.  A dht-dnssec
   zone fetch fans out to up to 65 sequencers against the 64-entry table,
   so it evicts every other transfer (G-508).

 - **Session model (G-133 / G-141):** a receive half binds to the tid of
   the first chunk it takes; only that tid feeds it and our acks echo it.
   A chunk with another tid gets a `"ch"` challenge, and only a chunk
   echoing `ch` replaces the session (reset to offset 0).  Look up with
   `lws_dht_ts_find()` (no refresh) and call `lws_dht_ts_touch()` only
   after the session or nonce check, or stale sequencers stay alive.
 - `stats.ack_offset` belongs to the send half, `stats.rx_offset` to the
   receive half (G-140).
 - **Sequencer callback contract** (G-181): `on_rx_data` and
   `on_state_change` are called last and may destroy the sequencer;
   `tx_chunk` and `tx_ack` must not.  In the DHT, `lws_dht_ts_t.in_cb`
   keeps a sequencer that is calling back from being recycled by the LRU
   cap in `dht_ts_create()`; new code calling back into a consumer from a
   sequencer must set it, and pass a copy of the peer address, never
   `&dts->sa`.
 - **`peer_proven` is about the send half only.**  Every receive session,
   first or replacement, binds only to a chunk echoing the `"ch"`
   challenge (G-204); "known good node at that endpoint" proves the
   routing entry, not that a datagram came from that node.  Hand-driven
   raw test peers must answer the challenge on their first chunk: copy the
   8 bytes after `d1:rd2:ch8:` and resend with `2:ch8:<ch>` ahead of
   `4:data` (`sr_challenge()` in api-test-dht-seq-reentry,
   `q_queue_chunk()` in api-test-dht-krpc).
 - **Only 10-byte "sq" + nonce tids are answered** (G-213): a chunk with
   any other tid (v5.0.0's fixed `sqnc`, forgeries) gets no reply, since
   v5.0.0 read a challenge as an ack of offset 0 that reset its
   retry count (endless retransmit).  Note `parse_message()` zeroes `mp`,
   so a missing offset parses as 0, not ~0, whatever the caller preset
   (G-217).  Hand-driven raw test
   peers must use "sq" + 8 bytes as their session tid or they are ignored.
 - **Search policy (G-158 / G-211 / G-216):** a get_peers reply is
   recorded through `search_record_reply()`, for the entry asked at that
   endpoint whatever id it claims; an endpoint introduces once per search;
   the replier is recorded before its
   nodes list; only the 8 closest replied candidates are protected; the
   backlog keeps failure counts; failed endpoints are remembered per
   search; a search ends `LWS_DHT_SEARCH_MAX_SECS` (300s) after it starts.
 - **Unproven peers** get their first chunk plus at most
   `LWS_TS_UNPROVEN_TX_ALLOWANCE` (1536) bytes beyond what they sent us
   until they ack; the rest is held and flushed on proof (G-182).
 - **`find_node()` matches by id only:** any `find_node(id)` then
   `mark_as_pinged()` must also check the node's endpoint is the one the
   request went to (G-179).

## Plugins and stubs

 - **dht-dnssec `fetch_zone`:** the fetch cb is called while the request
   is still listed, so cancelling from inside cb is a use-after-free; a
   cancel with domain NULL drops every request with that opaque (G-220).
   auth-dns with dht-dnssec only works on the same vhost:
   `get_dnssec_vhd()` resolves to the caller's own vhost.  `is_fail`
   in the fetch args fails an opaque's requests with one
   `LWS_DHT_DNSSEC_FETCH_TIMEOUT` cb each; auth-dns uses it when the last
   query waiting on a domain times out (G-224).  The stand-in
   lws-dht-dnssec protocol in api-test-auth-dns-zonedir can take fetches
   that never answer, to test auth-dns fetch handling without a DHT.
 - **dht-dnssec fetches open only for an RSP from a host the GET went to**
   (G-153): tests that hand-make a `lws_dht_dnssec_fetch_req` must record
   the responder with `dht_dnssec_fetch_req_send()`.
 - **vhost destroy order:** every instantiated protocol's PROTOCOL_DESTROY
   runs before any per-vhost data is freed (lib/io/vhost.c), so a
   protocol's destroy may still use another protocol's per-vhost data on
   the same vhost.
 - **lws-login renewal objects** (`pending_login_refresh`) are bounded per
   vhd and per host, released when their browser leg closes, and at
   PROTOCOL_DESTROY (G-166, G-167).  A new path that parks a browser wsi
   on a side channel must do the same.  Renewals start only for an
   `auth_refresh_session` of exactly 64 hex characters, so test fixtures
   expecting one must use that shape.
 - **lws-login uses the page URL itself as redirect_uri** and posts the
   token to `<page path>/.lws-login-sso`; changing redirect_uri matching
   in the auth server changes lws-login's contract too (G-112).
 - **auth-server 2FA in tests:** a TOTP code is good for one login per
   30 s, so back-to-back two-step logins in a test use backup codes (the
   lwsws-oauth "limits" scenario does).  Step 1 of a two-step login
   strikes the host; a completed step 2 from the same host and account
   within 120 s gives exactly that strike back (G-223).
 - **lws-login's cookies (`auth_session`, `auth_csrf`) are unprefixed and
   usually Domain-scoped**, so siblings can write them: shape-check values
   read from them before re-emitting them anywhere (G-168).
 - In a privileged stub, when one request type hardens its file access
   (private-dir fd checks, O_NOFOLLOW, regular-file and size checks),
   check every other request type in the same stub: they usually still
   open paths directly (G-098, cert-dist client `get_hash`).

 - The interceptor's cookies carry a `__Host-` prefix even over plain
   http and must be sent back under that name (B56, api-test-captcha-login).
 - Seen by B56: a plugin protocol's init (and its vhd) happened after the
   first service turn, not at `lws_create_vhost()`; a test that needs the
   vhd must service once first.
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
 - `lwsac_unreference()` only frees (and NULLs the caller's pointer)
   when the lwsac is detached and the count reaches 0; otherwise the
   caller's pointer is left set.  Clear your own copy after unreferencing
   or a later use is a use-after-free (seen under ASan in B42's deaddrop
   work).
 - `lws_serve_http_file()` takes its extra headers already encoded with
   `lws_add_http_header_by_name()` on the same wsi; that works on h2 too.
   A `callback://` mount gets the GET with the URL part after the
   mountpoint as `in`.
 - deaddrop serves downloads itself from a `callback://lws-deaddrop`
   `get` mount (G-282), never as a file mount: deployments using a file
   mount on the upload dir must change it.
 - A test that drives plugin internals with a `struct vhd` of its own
   (eg on the stack) must run that plugin's PROTOCOL_DESTROY teardown
   itself on every exit, or LSan fails it on allocations the plugin
   frees in real use (G-226, api-test-dnssec-monitor-inventory).
 - Logic in plugins with no end-to-end test (eg ACME) goes in a separate
   testable file (`acme-json.c`) that an api-test compiles in.
