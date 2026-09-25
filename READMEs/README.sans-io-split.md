# The sans-IO split

lws is being divided into two halves with one narrow interface between
them.  This document is the rule for deciding which half a piece of code
belongs to, the interface, and the directories.  It is written so that a
reader, human or otherwise, can place any function in a few seconds.

## The two halves

**sansIO**: decides what bytes mean and what bytes to send next.  Parsers,
framers, the protocol state machines (`README.wsi-state-machines.md`), the
role ops, flow control, mux stream scheduling, the proxy and socks
handshakes, hpack and qpack, the quic packet and frame layer.

**IO**: moves bytes and time.  Sockets, file descriptors, poll flags, the
fd table, event-loop integration, the TLS record layer, UDP datagram
send and receive, DNS lookups, connect and happy eyeballs, the clock.

The test: **if it were deleted, would the bytes on the wire or the state
transitions change for a given input?**  Yes: sansIO.  No, only *when* or
*how* the same bytes get moved: IO.

Corollary, as a grep: sansIO code never names a socket or fd
(`desc.sockfd`, `send(`, `recv(`, `sendto(`), a poll flag (`LWS_POLLIN`),
a TLS library object (`SSL_`, `gnutls_`, `mbedtls_`), or an event-loop
handle (`uv_`, `ev_`, `event_base`), and never reads or writes the
transport itself (`lws_ssl_capable_read(`, `lws_buflist_aware_read(`): the
rx pump and the tx path do that.  IO code never parses or composes a
protocol byte.  The `pollfd` a role's `handle_POLLIN` is handed today is
the IO-to-sansIO entry in its current spelling, not a violation.

## The interface

The sansIO half is driven entirely by these calls from IO, and asks IO for
things only through these requests.  Nothing else crosses.

| direction | call | today's C |
|---|---|---|
| IO -> sansIO | **rx(bytes) -> consumed**: bytes arrived, take what you can; an empty rx is the peer closing | the `rx` role op, fed by `lws_rx_pump()` from every role's `handle_POLLIN`; the app's pull of a response body, `lws_http_client_read()`, is the same read at the app's pace into the app's buffer, feeding `lws_h1_client_body_rx()` |
| IO -> sansIO | **rx_dgram(bytes, peer, ecn) -> ok**: the datagram spelling of rx: one datagram arrived from this peer with these ECN bits; it is taken whole, nothing is parked | the `rx_dgram` role op, fed by `lws_rx_pump_dgram()`; quic |
| IO -> sansIO | **tx(buf, max) -> n, more**: the transport can take bytes: fill the caller's buffer with the next ones to send, from wherever you got to last time, and say whether more remain | `lws_write()` composing into the `LWS_PRE` headroom then `lws_issue_raw()`; role `handle_POLLOUT`.  Converted: the status page (`lws_http_status_page_send_pending()`), file serving (`lws_http_file_tx()` producing, `lws_serve_http_file_fragment()` in IO driving) |
| IO -> sansIO | **deadline()**: the deadline you set has passed | `sul` callbacks, `lws_sul_wsitimeout_cb` |
| IO -> sansIO | **transport(up / failed / gone)** | `client_transport_up` op, `LWS_WSIEV_TRANSPORT_UP`, `CONN_FAILED`, `SOCKET_GONE` |
| sansIO -> IO | **want_write()**: call tx when the transport can take bytes | `lws_callback_on_writable()`; `lws_service_wsi_as_writable()` is the same request served now |
| sansIO -> IO | **deadline(us) / no deadline** | `lws_set_timeout()`, `lws_sul_schedule()` |
| sansIO -> IO | **want_read(on / off)**: stop feeding me rx, or resume | `lws_rx_flow_control()` |
| sansIO -> IO | **close(reason)** | `lws_close_free_wsi()`, `LWS_WSIEV_CLOSE_FLUSH` |

Four in (rx has a datagram spelling for quic), four out.  A sansIO part that needs anything else from IO is a
sansIO part with IO in it.

**Sending is a pull.**  IO owns the buffer and calls tx when the transport
can take bytes; sansIO emits as much as fits and keeps, in its own state,
where it got to, so the next tx continues from there.  Something that must
go out as several frames (an h2 response's HEADERS then its DATA, a
status page, a redirect) is a small state machine over those frames, not
two writes in a row hoping the second fits, and not a heap copy of the
remainder waiting on a buflist.  IO's partial-send buffering exists only
for the transport's own short writes, never as a place for sansIO to park
what it could not send.  Where the whole thing fits one call, one call;
the state machine is for what may not, above all quic, whose packets are
sized to a dynamic MTU.

**A content source's tx.**  File serving is the shape every tx of a
source follows:

    n = tx(wsi, buf, max, &p, &flags, &last)

IO owns `buf` (the pt serv_buf behind its `LWS_PRE` headroom) and says how
much of it, `max`, may be used.  sansIO fills it with the payload of the
next `lws_write()` and returns:

| return | meaning |
|---|---|
| n > 0 | n bytes at `p` in `buf`; `flags` says how the role frames them; `last` says they end the response |
| 0 | nothing more: the source is finished |
| `LWS_TX_WAIT` | nothing now, and sansIO has asked want_write for when there is (its read went to a worker thread, its tx credit is spent) |
| `LWS_TX_FAIL` | the source failed and has cleaned up; IO closes |

sansIO's position advances by what it produced: once produced, bytes are
IO's, and IO's partial-send buffer holds what the transport does not take
at once.  sansIO applies its own clamps inside `max`, from what the peer
told it (h2 max frame size, tx credit, a Range budget) and what its own
framing needs (a chunk header's room, a transform's growth); IO never
knows why n is less than max.  The driver is IO's: while the transport can
take more, tx then write; when tx says the source is finished and nothing
of it is left buffered, tell sansIO the response completed.

The file system is a content source, not the transport: reading the file,
and handing that read to a worker thread, are the source's business and
stay on the sansIO side of this line.

## The headers

The public api is tiered the same way, as three meta-headers under
`include/libwebsockets/` that `libwebsockets.h` includes in order:

| meta-header | holds | rule |
|---|---|---|
| `lws-core.h` | the substrate both halves stand on: dll2, buflist, lwsac, logging, time as data, parsers, decoders, utilities | names nothing outside the process's memory |
| `lws-sansio.h` | the protocol half as an application sees it: the callbacks, the write flags, the http, ws, h2, h3, mqtt vocabulary | IO's objects appear only through pointers; the meta-header forward-declares their tags |
| `lws-io.h` | the transport half: context and vhost creation, adopt, connect, service, tls library objects, dns, event loops, platform devices | everything that names something outside the process |

Applications keep including `libwebsockets.h` and see no change.  Someone
porting the protocols, or embedding the sansIO half alone, reads
`lws-core.h` and `lws-sansio.h` and has the whole of what they carry.
Components are placed by the rule, not by their history; where a header
mixes the two (`lws-client.h` has both the connect request, IO's, and the
client's protocol calls) it sits with its predominant half and is noted for
splitting.  `lws-callbacks.h` is sansIO's and carries a few IO reasons (the
poll fd and lock ones): one C enum cannot live in two headers, so they stay
there, marked.

The private headers are tiered the same way, by the file that defines each
prototype: `lib/core-net/IO/private-lib-io.h` holds the IO half's (defined
under `lib/core-net/IO`, `lib/plat`, `lib/tls`, `lib/event-libs`,
`lib/drivers`, the async dns), and `private-lib-core.h` includes it unless
`LWS_SANSIO_CHECK` is defined.  `scripts/sans-io-check.sh <build-dir>`
compiles every sansIO source that way, from the build's
`compile_commands.json`, so each place sansIO code calls into IO fails to
compile and names its line; it prints the callees by frequency and the
totals.  That list is the remaining work on the rx and tx plumbing, and
the compiler keeps it, not a grep.  (The tls private prototypes are not yet
hidden: they share a header with the tls structs that `struct lws` embeds
by value, which the struct split resolves.)

**The four requests sansIO makes of IO** (want_write, deadline, want_read,
close) are calls into IO today, spelled `lws_callback_on_writable()`,
`lws_set_timeout()` / `lws_sul_schedule()`, `lws_rx_flow_control()` and
`lws_close_free_wsi()`.  Those names stay, as sansIO's api: what the tiering
adds is that at the bottom of each, where the request reaches the transport,
it goes through one struct of four function pointers, `lws_io_ops_t`, that
IO fills in for the normal build and an embedder of the sansIO half fills in
for theirs.  A port that returns its requests as polled outputs, the way a
Rust sans-IO crate does, implements the same four.  The struct is the seam;
the rest of the two halves never see each other.

Time is an input: sansIO is told the deadline passed, it never reads the
clock to decide anything.  Reading the clock for a log line or a metric
is tolerated in sansIO until the split is done.

## What goes where in the tree

The directories are the halves.  Placement by directory is the whole rule.

| directory | half | notes |
|---|---|---|
| `lib/roles/*` | sansIO | every role: state machine, parser, framer, scheduler |
| `lib/core-net/wsi.c`, `wsi-state.c`, `close.c`, `state.c`, `vhost.c`, `socks5-client.c`, `dummy-callback.c` | sansIO | the wsi state, the event table, connection lifecycle decisions, the socks handshake |
| `lib/core-net/client/connect4.c` proxy CONNECT composition | sansIO | it composes protocol bytes |
| `lib/core-net/IO/`: `output.c`, `pollfd.c`, `service.c`, `adopt.c`, `network.c`, `route.c`, `wsi-timeout.c`, `sorted-usec-list.c` | IO | moving bytes, fds, poll, timers |
| `lib/core-net/IO/client/`: `connect.c`, `connect2.c`, `connect3.c` | IO | dns, connect, happy eyeballs |
| `lib/tls/*` record layer: `lws_ssl_capable_read/write`, bio, session cache, handshake driving | IO | sansIO sees plaintext |
| `lib/roles/quic` packet and frame layer, `lib/roles/h3`, qpack | sansIO | quic is a sansIO part with a datagram interface instead of a stream one |
| `lib/roles/quic` `sendto` for version negotiation, retry and path migration | IO | the last place a role touches the socket, to be moved behind tx |
| `lib/plat/*`, `lib/event-libs/*` | IO | |
| `lib/core/*`, `lib/misc/*`, `lib/system/*` | neither | context, logging, utilities: shared by both halves, used by both |

Where a file has both today (`connect4.c`, `ops-quic.c`), the split is
inside the file until it is moved; the decision rule still says which half
each function is in.

## Rules from now on

1. New code goes on the side the test puts it.  A change that adds a
   socket, poll or TLS-library reference under `lib/roles` or the sansIO
   files above is wrong, whatever else it does.
2. The eight interface calls are the only way across.  Adding a ninth is a
   design change, not a convenience.
3. The state trace (`LWS_STATE_TRACE_FILE`) is the oracle: a split step is
   done when the gate's edge set is unchanged.
4. `scripts/sans-io-lint.sh` greps the sansIO directories for the forbidden
   identifiers and compares the total with `scripts/sans-io-lint.baseline`.
   More than the baseline fails; a step that brings it down re-baselines
   with `--update`.  The count only goes down.

## Staging

1. Finish the boundary violations that already exist: the socks and proxy
   legs writing to the fd, connect completion special cases living in
   `connect4.c` instead of the roles (both done: `c9ca0d2f5` and the
   `client_transport_up` op).
2. Land the lint with today's count as its baseline (done: 273 by the
   first measure; 213 once it counted transport reads and stopped counting
   the handler's pollfd).
3. Move the IO files of `lib/core-net` into `lib/core-net/IO/`, no code
   change, so the directory says what the file is (done).
4. Convert one role's rx to take bytes instead of reading them (h1 or ws),
   with the trace unchanged.  This is the pattern for the rest (done:
   `lws_rx_pump()` feeds the `rx` op of h1 both sides, raw-skt, raw-proxy,
   mqtt, h2 and ws; `lws_rx_pump_dgram()` feeds quic's `rx_dgram`, doing
   the recvmsg and the ECN control message itself; the socks5 and http
   CONNECT legs of a client's transport, and the idle wait of a kept-warm
   h1 connection, are states of the client rx.  The app's pull of a
   response body, `lws_http_client_read()`, is IO too: it reads as much as
   fits the app's buffer and feeds the body rx, so nothing is queued for a
   body the app has not asked for and the transport's window is the
   backpressure.  No role reads its transport any more).
5. h2, then h3 over the quic datagram layer, then the remaining roles.
6. Tier the public headers into `lws-core.h`, `lws-sansio.h`, `lws-io.h`
   (done), then the private ones, with the sansIO-only compile check
   (done: `private-lib-io.h`, `scripts/sans-io-check.sh`; first inventory
   82 calls into IO from sansIO sources, 42 callees, `lws_issue_raw` and
   `lws_rx_pump` from the roles' own handlers among them).
7. The four requests through `lws_io_ops_t` (done: `lws-io-ops.h`,
   `lws_io_ops_default` in IO/pollfd.c, `lws_context_creation_info.io_ops`).
8. When every role is converted, the IO half is a replaceable component,
   and the sansIO half is what a port translates.
