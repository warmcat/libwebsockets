# wsi state machines

## The problem this solves

A `struct lws` (wsi) has one state word, `wsistate`, and for most of the
life of the library its dynamic part was a single flat enum, `LRS_*`, with
36 values.  Reading the transition trace from the whole ctest suite showed
that those 36 values are really the states of four independent machines that
happen to share one slot:

|machine|what it tracks|
|---|---|
|transport|getting a socket to the peer: dns, connect, proxy / socks, the tls handshake or accept|
|carrier|the protocol handshake on top of the socket: h1 first request and reply, h2 preface and settings, mqtt connack, the h1 server's upgrade decision|
|transaction|the http request / response cycle and its body and file phases, or "established" for roles that have no transactions|
|close|the polite ws close, draining buffered tx, the staged tcp shutdown, dead|

Because one slot can only hold one value, whenever two of these were active
at once (a ws connection in the middle of a close handshake, a client being
retargeted by a redirect, an h1 server holding a completed transaction while
the next request's headers arrive) the second machine's state was carried in
a per-wsi bool.  Those bools were the real hazard: some resets cleared them
and some did not, and each reader had to know which bools qualified which
state.  Of 203 distinct edges observed in ctest, 99 crossed from one machine
into another.

The machines now each own their own bits of the word, are set only through
their own setters, and are listed in per-machine transition tables that a
debug build asserts against.  This document is the specification of those
machines.  The tables in `lib/core-net/wsi-state.c` are authoritative; this
describes what they mean.

## The state word

```
 31 30   24 23    20 19    16 15 14  12 11 10   9    8   7      0
 [u][role ][carrier][transp] [cs][close][-][c][nest][pocb][ state ]
```

|bits|holds|read with|set with|
|---|---|---|---|
|0-9|the live state: the transaction machine's `LRS_` value with its `LWSIFS_POCB` / `LWSIFS_NOT_EST` qualifiers|`lwsi_state_live()`|`lws_wsi_event()`|
|10|`LWSIFS_TXN_COMPLETING`: the transaction was completed while a partial write was outstanding|`lwsi_txn_completing()`|`lwsi_set_txn_completing()`|
|12-14|close machine, `enum lws_close_phase` `LCS_*`|`lwsi_close()`|`lws_wsi_event()`, a row to a close phase|
|15|`LWSIFS_CLOSE_STARTED`: `__lws_close_free_wsi()` has been entered|||
|16-19|transport machine, `enum lws_transport_phase` `LTS_*`|`lwsi_transport()`|`lws_wsi_event()`, a row to a transport phase|
|20-23|carrier machine, `enum lws_carrier_phase` `LCR_*`|`lwsi_carrier()`|`lws_wsi_event()` routes handshake states here|
|24-29|role flags: client / server side, h2 encapsulation|`lwsi_role_*()`|`lws_wsi_event()`, a row that names a side|
|30|`LWSIFS_SKT_UNUSABLE`: the socket is known dead, take the abortive close path|`lwsi_skt_unusable()`|`lwsi_set_skt_unusable()`|

`lwsi_state()` still returns a single `LRS_` value for the many readers that
only need to know "what is this connection doing right now": it reports the
close machine if one is set, else the transport machine, else the carrier
handshake if one is in progress, else the live state.  That precedence is
what the old flat enum was approximating.  `lwsi_state_live()` reads the
live bits underneath a close, so what the connection was doing when it
started to close stays visible.

Bits 10 and 30 are attributes of the live state rather than machines:
they survive a live-state change, and `lws_role_transition()` carries them
across a role change, except that a restart to `LRS_UNCONNECTED` (redirect,
auth retry, h3 to tcp fallback) drops them, since the new connection has its
own socket and its own transaction.

## Transport machine

Client side, in order:

```
UNCONNECTED -> WAITING_DNS -> WAITING_CONNECT -> [proxy] -> [WAITING_SSL] -> (carrier)
```

where `[proxy]` is `WAITING_PROXY_REPLY` for an http CONNECT proxy, or
`WAITING_SOCKS_GREETING_REPLY -> [WAITING_SOCKS_AUTH_REPLY ->]
WAITING_SOCKS_CONNECT_REPLY` for socks5.  `WAITING_SSL -> WAITING_CONNECT`
is a retry on another address or transport, the quic to tcp fallback.  `WAITING_DNS ->
UNCONNECTED` is the dns retry.

Server side, for a tls listener: `SSL_INIT -> SSL_ACK_PENDING` (accept in
progress, may bounce through `AWAITING_SSL_ACCEPT` when the accept is on an
async worker) and then the first carrier or transaction state.

Two terminal sub-phases report as `UNCONNECTED` to `lwsi_state()` but are
distinct in the bits:

- `LTS_FAILED`: the connect was reported failed to the user
  (`lws_inform_client_conn_fail()`); the close must not report it again.
  It can be entered from any phase, including from an established
  connection when a happy-eyeballs leader passes on its powers.
- `LTS_RESTARTING`: `lws_client_reset()` is retargeting the wsi; it has no
  live state until the pickup's `lws_role_transition(UNCONNECTED)`.  Only a
  client can be in it, and no live state may be set while it is.

The transport phase ends implicitly: setting any live or carrier state
clears the transport bits.

## Carrier machine

|role|phases|
|---|---|
|h1 client|`H1C_ISSUE_HANDSHAKE` (before tls) -> `H1C_ISSUE_HANDSHAKE2` (sending the first request) -> `WAITING_SERVER_REPLY` (first response headers)|
|h2 client|`H2_AWAIT_PREFACE` -> `H2_WAITING_TO_SEND_HEADERS` (per stream) -> `WAITING_SERVER_REPLY`|
|h2 server|`H2_AWAIT_PREFACE` -> `H2_AWAIT_SETTINGS`|
|h3 client|`H2_WAITING_TO_SEND_HEADERS` -> `WAITING_SERVER_REPLY`|
|h1 server|`H1_UPGRADE`: an Upgrade: header was seen, deciding between ws, h2c and refusing|
|mqtt client|`MQTTC_IDLE` -> `MQTTC_AWAIT_CONNACK`|

The carrier is `LCR_ESTABLISHED` from the first transaction state onward.
Carrier and transaction are sequential, not stacked, and the same `LRS_`
names are reused per transaction: an h1 client re-enters
`H1C_ISSUE_HANDSHAKE2` and `WAITING_SERVER_REPLY` for each pipelined request.
A handshake-named state is routed into the carrier bits only while the
carrier is not yet established; afterwards it is a per-transaction phase in
the live bits.  So "is this client still waiting for its first
response" is `lwsi_carrier() == LCR_WAITING_SERVER_REPLY`, while "is a
response pending" is `lwsi_hdrs_pending()`.

## Transaction machine

### h1 server

```
HEADERS ---(request parsed)---> ESTABLISHED ---> DOING_TRANSACTION
   ^                              |    |    \--> ISSUING_FILE <-> AWAITING_FILE_READ
   |                              |    \-------> BODY --> DISCARD_BODY
   |                              v                 |         |
   +-------------- TXN_COMPLETED <------------------+---------+
```

- `HEADERS`: idle between requests, or reading one.  A server is in
  `HEADERS` from accept until it has a request to act on.
- `ESTABLISHED`: acting on a parsed request; the user callback is being
  driven.  It also carries `H1_UPGRADE` out to the carrier when the request
  asked for one.
- `DOING_TRANSACTION`: a mount action (cgi, proxy, file) is in progress.
- `BODY` / `DISCARD_BODY`: a request body is being delivered, or drained
  because the user finished before reading it.
- `ISSUING_FILE` / `AWAITING_FILE_READ`: a file is being served, the latter
  while an async read is out on a worker.
- `TXN_COMPLETED`: `lws_http_transaction_completed()` ran; hold here until
  the connection is writable and buffered tx has drained, then back to
  `HEADERS` for keep-alive or close.  The `+completing` attribute records a
  completion that arrived while a partial write was still outstanding.

### h2 and h3 server streams

A stream is born `HEADERS`.  From there `DEFERRING_ACTION` (headers complete,
the action is deferred to POLLOUT and any body is stashed) or straight to
`DOING_TRANSACTION`; `DEFERRING_ACTION -> ESTABLISHED` when it runs.  The
same `BODY`, `ISSUING_FILE` and `AWAITING_FILE_READ` phases apply.  A mux
stream has no `TXN_COMPLETED`: completion closes the stream.  The h2 network
connection itself sits in `ESTABLISHED` after settings, as does an h3
server's own unidirectional control streams.

### h1 client

```
(carrier) --> ESTABLISHED --> IDLING
                 |   ^          |
                 |   +-- WAITING_SERVER_REPLY <-- ISSUE_HTTP_BODY <-- H1C_ISSUE_HANDSHAKE2
                 +---------------^
```

- `ESTABLISHED`: response headers received, the response body is being
  delivered.
- `ISSUE_HTTP_BODY`: request headers sent, the user is supplying a body.
- `WAITING_SERVER_REPLY`: a request is out, response headers pending.  A
  1xx interim response rewinds to here.
- `IDLING`: keep-alive, nothing in flight; the connection is kept warm for
  the `keep_warm_secs` of the request that last used it, and a new request
  to the same endpoint in that time is handed the connection (it re-enters
  `H1C_ISSUE_HANDSHAKE2` from the pipeline queue).  Nothing turns up: the
  keep-warm timeout closes it in good order.

### h2 and h3 client streams

A stream is born in `H2_WAITING_TO_SEND_HEADERS`, sends its headers
(`ISSUE_HTTP_BODY` if it has a body) and waits in `WAITING_SERVER_REPLY`;
the response headers bring it to `ESTABLISHED` and `BODY`.  The network
connection is `ESTABLISHED` from the moment its own first request moves to
the sid-1 child (it carries streams only from then on), goes `IDLING` when
its last stream closes with nothing queued (`LAST_STREAM_CLOSED`) and is
revived to `ESTABLISHED` when a new one joins (`CONN_REUSED`), so on every
client `ESTABLISHED` means a response is in flight and `IDLING` means
nothing is.  While `IDLING` the connection is kept warm for the
`keep_warm_secs` of the request that last used it, with its tcp + tls
already up for a new request to the same endpoint; the peer's PINGs and
WINDOW_UPDATEs do not extend that, only a new stream (which drops the
timeout) does.  Nothing joins: the keep-warm timeout closes it in good
order.

### Other roles

raw sockets, raw files, pipes, dbus, mqtt and quic have no transactions:
they enter `ESTABLISHED` when usable and stay there.  For a raw client the
adoption callback has been delivered exactly when `lwsi_carrier()` is
`LCR_ESTABLISHED`.

## Close machine

The close machine runs on top of the others without disturbing them.

```
                +--> WAITING_TO_SEND_CLOSE --> AWAITING_CLOSE_ACK --+
(ws, we close)  |                                                   |
                |                                                   v
(ws, peer closed) --> RETURNED_CLOSE --> FLUSHING_BEFORE_CLOSE --> [SHUTDOWN] --> DEAD_SOCKET --> USER_TOLD
                                             ^
(anything else) -----------------------------+
```

- `WAITING_TO_SEND_CLOSE`: we initiated a ws close and have a CLOSE frame
  to send (initiator only, on every side and carrier).
- `AWAITING_CLOSE_ACK`: our CLOSE was sent, waiting for the peer's.
- `RETURNED_CLOSE`: the peer's CLOSE arrived first; we answer it as a PONG
  would be, then close.  One encoding on both sides.
- `FLUSHING_BEFORE_CLOSE`: drain buffered tx, then close.  Entered from any
  state by `lws_close_free_wsi()` when a partial is outstanding, or from
  outside by `lws_raw_transaction_completed()` on a raw socket.
- `SHUTDOWN`: server side only, tcp half-close sent, waiting for the peer's
  FIN so the close is not seen as abortive; never on a raw socket or without
  a socket.
- `DEAD_SOCKET`: out of the fd table, being freed.  `USER_TOLD` is the same
  state after the user's CLOSED callback ran.

Invariants the checker enforces: an unusable socket never enters
`WAITING_TO_SEND_CLOSE`, `RETURNED_CLOSE`, `AWAITING_CLOSE_ACK` or
`SHUTDOWN`; `RETURNED_CLOSE` only on a ws role; `SHUTDOWN` only on a server
wsi with a socket.

## Role changes

A role or side change is an event like any other: the row names the role
and side that follow, or takes them from the site (the ops argument of
`lws_wsi_event_role()` for adoption, the client bind and a restart, which
are the site's to choose), from the mux parent (a fresh child is its
parent's), or from a wsi the site says the new one is like
(`lws_wsi_event_x()`, for our own h3 control streams and a wsi taking over
a quic connection).  So the h1 to h2 / ws upgrades, quic to h3 at ALPN, the
client's sid-1 migration, a stream let onto its connection, webtransport,
raw, and the restart to `UNCONNECTED` on redirect or fallback all read as
`ev=NAME` on a `role_transition` edge in the trace.  The only role write
without an event is a wsi's birth, where the creator hands in the ops.

Underneath, `lws_wsi_role_transition_ev()` rewrites the whole word: side
flags, a transport or carrier state into its bits over an `UNCONNECTED`
live state, or a live state with the carrier marked established.

## Build options

|option|effect|
|---|---|
|`LWS_WITH_STATE_TRACE`|append each distinct `(role, state) -> (role, state)` edge the process performs, once, to `$LWS_STATE_TRACE_FILE` (stderr if unset), as `LRS h1/S:HEADERS -> h1/S:ESTABLISHED set_state <wsi tag>`.  Attributes show as `+completing`, `+unusable`, `+failed`, `+restarting`, `+told`.|
|`LWS_WITH_STATE_CHECK`|look every edge up: a live-state edge must be one the event table produces, a phase or role change must carry an event's name (the engine made it from a row) or be a birth; `abort()` on one that is not, or that breaks an invariant, logging `unlisted wsi state edge ...` or `invariant broken on wsi state edge ...`; an event with no row aborts too|

Both are off by default and change nothing about what any transition does.
To regenerate the observed edge set, build with the trace on and run

```
LWS_STATE_TRACE_FILE=/tmp/edges.txt ctest
```

then `sort -u` the file.  The event table in `wsi-state.c` is the
transition function itself; its rows were derived from the observed edge
set over the ctest suite and the fuzz seed corpus plus the statically
present edges nothing reaches.  A new edge is either an omission in the
table or a bug at the site.

## Events

The sites of the carrier and transaction machines do not name the state
they want; they report what happened with `lws_wsi_event(wsi, LWS_WSIEV_*)`
and the event table in `wsi-state.c` says what state that lands in, by
role, side and current state.  The same event lands in different states by
role (request headers complete is `H1_UPGRADE` on an h1 server and
`DEFERRING_ACTION` on a mux stream), and a site does not choose.  The
site-local facts that used to pick the state (is a body pending, was an
upgrade asked for) are distinct events instead, so the information is in
the word rather than in a bool beside it.  An event with no row is a bug
at the site: the state is left alone, an error is logged, and
`LWS_WITH_STATE_CHECK` aborts.  The trace shows the event on each edge as
`ev=NAME`.  Nothing else writes any of the four machines, a role or a
side: there is no setter for them outside `wsi-state.c`, only the events,
and a wsi's birth.

The transport and close machines are driven the same way: a row whose
target is a transport or close phase (`XT()` / `XC()` in the table) sets
that machine's bits, over whatever the others were doing.  Their events
read as what happened on the wire or in the close flow: `DNS_START`,
`CONNECT_START`, `TLS_START`, `TLS_ACCEPT_PENDING`, `CONN_FAILED`,
`RETARGET`; `WS_CLOSE_INITIATED`, `WS_CLOSE_SENT`, `WS_PEER_CLOSE`,
`CLOSE_FLUSH`, `CLOSE_STAGED`, `SOCKET_GONE`, `USER_TOLD`.

The events, with the states they lead to:

|event|h1 server|h2 / h3 server stream|h1 client|h2 / h3 client stream|
|---|---|---|---|---|
|request headers complete, no upgrade|`ESTABLISHED`|`DEFERRING_ACTION` or `DOING_TRANSACTION`|||
|request headers complete, upgrade asked|`H1_UPGRADE`||||
|action deferred now runs||`ESTABLISHED`|||
|action started|`DOING_TRANSACTION`|`DOING_TRANSACTION`|||
|file serving started|`ISSUING_FILE`|`ISSUING_FILE`|||
|file read handed to a worker / returned|`AWAITING_FILE_READ` / `ISSUING_FILE`|same|||
|file sent|`ESTABLISHED`|`ESTABLISHED`|||
|body starts|`BODY`|`BODY`||`BODY`|
|user finished before the body|`DISCARD_BODY`||||
|transaction completed|`TXN_COMPLETED`|(stream closes)|`IDLING`, or `H1C_ISSUE_HANDSHAKE2` with a pipelined next||
|writable after completion, tx drained|`HEADERS`||||
|request headers sent, body pending|||`ISSUE_HTTP_BODY`|`ISSUE_HTTP_BODY`|
|request headers sent, no body|||`WAITING_SERVER_REPLY`|`WAITING_SERVER_REPLY`|
|request body sent|||`WAITING_SERVER_REPLY`|`WAITING_SERVER_REPLY`|
|response headers complete|||`ESTABLISHED` (role may change to ws)|`ESTABLISHED` (or ws encapsulated)|
|1xx interim response|||`WAITING_SERVER_REPLY`||
|auth challenge, retrying|||`H1C_ISSUE_HANDSHAKE2`||
|stream opened by the peer||`HEADERS`|||
|stream let onto its connection||||`H2_WAITING_TO_SEND_HEADERS`|
|last stream closed, nothing queued (connection)||||`IDLING`|
|idle connection gets a new stream (connection)||||`ESTABLISHED`|

`ESTABLISHED` means one thing on each side: on a server, acting on a
parsed request; on a client, a response in flight.
