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
protocol byte.  No sansIO role has a `handle_POLLIN` any more: only the transport
adapter roles, which are IO, see a `pollfd`.

## The interface

The sansIO half is driven entirely by these calls from IO, and asks IO for
things only through these requests.  Nothing else crosses.

| direction | call | today's C |
|---|---|---|
| IO -> sansIO | **rx(bytes) -> consumed**: bytes arrived, take what you can; an empty rx is the peer closing | the `rx` role op, fed by `lws_rx_pump()` from IO's rx stage under the role's `rx_policy`; after the pass's reading the role's `rx_done` acts on what it holds; the app's pull of a response body, `lws_http_client_read()`, is the same read at the app's pace into the app's buffer, feeding `lws_h1_client_body_rx()` |
| IO -> sansIO | **rx_dgram(bytes, peer, ecn) -> ok**: the datagram spelling of rx: one datagram arrived from this peer with these ECN bits; it is taken whole, nothing is parked | the `rx_dgram` role op, fed by `lws_rx_pump_dgram()`; quic.  A role with this op rides a datagram transport: IO gives a client one when the role binds, reports ECN and marks what it sends ECT(0), and takes a bound one as a listener |
| IO -> sansIO | **tx(buf, max) -> n, more**: the transport can take bytes: fill the caller's buffer with the next ones to send, from wherever you got to last time, and say whether more remain | The app's data is the push form: its writeable callback is IO's pull, and `lws_write()` frames what it hands in place, in the `LWS_PRE` headroom, and gives it to IO with `lws_io_tx_push()`, uncopied; so do the proxy legs' one-shot messages (socks, http CONNECT) and a mux stream continuing its partial (`lws_io_tx_push(w, NULL, 0)`).  Everything else is pulled.  Converted: the status page (`lws_http_status_page_send_pending()`), file serving (`lws_http_file_tx()` producing, `lws_serve_http_file_fragment()` in IO driving), and, through the `tx` and `tx_sent` role ops that IO's `lws_tx_pump()` pulls at the start of the transport owner's POLLOUT pass, before its `handle_POLLOUT`: h2's protocol packets (`lws_h2_pps_tx()`, then `lws_h2_pps_done()` once written; the client preface and the 101 answering an h2c upgrade are protocol packets too, so they go in order ahead of the SETTINGS), and quic's packets (the datagram spelling, where each piece is a datagram with its destination: `lws_quic_packet_tx()` produces into IO's buffer sized to the path MTU and `lws_quic_packet_sent()` hears how the send went.  A listener's connections share its socket, so its tx is its own queued replies (version negotiation, retry) and then each connection that asked to write, in turn) |
| IO -> sansIO | **deadline()**: the deadline you set has passed | `sul` callbacks, `lws_sul_wsitimeout_cb` |
| IO -> sansIO | **transport(up(peer) / failed / gone)** | `client_transport_up(wsi, peer)` op, `LWS_WSIEV_TRANSPORT_UP`, `CONN_FAILED`, `SOCKET_GONE` |
| sansIO -> IO | **want_write()**: call tx when the transport can take bytes | `lws_callback_on_writable()`; `lws_service_wsi_as_writable()` is the same request served now, and `lws_io_tx_now()` its datagram tx alone (a closing quic connection's CONNECTION_CLOSE) |
| sansIO -> IO | **deadline(us) / no deadline** | `lws_set_timeout()`, `lws_sul_schedule()` |
| sansIO -> IO | **want_read(on / off)**: stop feeding me rx, or resume | `lws_rx_flow_control()` |
| sansIO -> IO | **close(reason)** | `lws_close_free_wsi()`, `LWS_WSIEV_CLOSE_FLUSH`; at the transport the request has phases, `lws_io_ops_t.close(wsi, phase)`: quiesce (nothing of the transport's may act on the wsi; it answers whether the wsi was still waiting for its socket, when its close callback is owed), unwatch (no longer polled or offered buffered rx; a restart, a file closing, and every close once its shutdown and staging are decided), shutdown, stage (keep it until the peer has finished), release |
| sansIO -> IO | **transport(start / made / failed)**: the client's request is ready, so its transport may start; a transport the role makes inside its own protocol is up, so it won any race for the connection; or it failed before it was up | `lws_client_transport_start()`: a client that waited for its header table has it, IO starts dns and the connect; `lws_client_transport_established()`: quic's handshake is done, IO drops the tcp connects racing it, their timers and the h3 grace; `lws_client_transport_failed()`: quic's never completed, IO retargets the connection to the next dns result or to tcp if it can.  The socks and CONNECT legs' tunnel coming up is `lws_client_transport_connected()`, after which IO still has the tls to do |
| sansIO -> IO | **path(commit / new socket, peer)**: a datagram connection's peer moved, or it wants a new local port to reach it | `lws_io_path()`, `lws_io_ops_t.path`: quic's connection migration and preferred address (RFC 9000 9); IO aims or replaces the socket and reports the committed peer |
| sansIO -> IO | **created(wsi)**: a connection object was made | `lws_io_ops_t.created`: IO sets up its half of the object, with no transport yet; the close's release is its end |
| sansIO -> IO | **transfer(from, to)**: the connection goes on as another object | `lws_io_transfer()`, `lws_io_ops_t.transfer`: quic's connection leaving the wsi that dialled it for its own network wsi, a kept-warm connection joining the wsi queued on it; IO moves the socket, its poll place, its watcher and the tls session |

Four in (rx has a datagram spelling for quic), eight out.  The last four
out are about the transport and its object rather than the bytes: a client
decides when its transport may start, a protocol that makes its own
transport (quic) decides when it is up or has failed and where its peer is,
and sansIO decides which of its objects a connection is.  A sansIO part that
needs anything else from IO is a sansIO part with IO in it.

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

Where what follows the bytes depends on their having gone, the shape has
a third step: h2's SETTINGS ack starts the first response, whose bytes
must follow the ack's, and quic's frames are in flight only once the
datagram was taken, else they go back to pending under the same packet
number.  So: produce into IO's buffer, IO writes, then the producer is
told (`lws_h2_pps_done()`, `lws_quic_packet_sent()`).  quic is the case
the README warned of: its buffer is the path MTU, which moves, so the
producer clamps every packet to what it is handed and keeps no copy.

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
prototype: `lib/io/private-lib-io.h` holds the IO half's (defined
under `lib/io`, `lib/plat`, `lib/tls`, `lib/event-libs`,
`lib/drivers`, the async dns), and `private-lib-core.h` includes it unless
`LWS_SANSIO_CHECK` is defined.  sansIO's requests of IO are spelled in
`lib/sansio/private-lib-sansio-seam.h`: for the sansIO sources it defines
each as a static inline call through the context's `lws_io_ops_t`, keeping
the name the request always had (`lws_io_tx_push()`,
`lws_client_transport_start()`, `lws_tls_session_ptr()`, ...) or, where
IO's implementation is public api, an `lws_io_...()` name
(`lws_io_peer_address()` for `lws_get_peer_simple()`,
`lws_io_tx_file()` for `lws_serve_http_file_fragment()`); every other
source sees IO's own functions of those names, whose prototypes are in
`private-lib-io.h`, and they are what `lws_io_ops_default` points to.  So
the seam is the interface, and what the check reports is
exactly the calls that are not it.  `scripts/sans-io-check.sh <build-dir>`
compiles every sansIO source that way, from the build's
`compile_commands.json`, so each place sansIO code calls into IO past the
seam fails to compile and names its line; it prints the callees by the
number of files calling them, and the totals (the compiler reports a
callee once per file, so the count is of file-and-callee pairs, and
clearing one site can reveal the next in the same file).  That list is
the remaining work on the rx and tx plumbing, and the compiler keeps it,
not a grep.  The same check is part of every build: every source under
`lib/sansio` is a sansIO source (`lib/sansio/CMakeLists.txt` collects what
its directory added as `SOURCES_SANSIO`), and `lib/CMakeLists.txt` gives
those sources `LWS_SANSIO_CHECK` and an implicit declaration as an error
(`-Werror=implicit-function-declaration`, `/we4013` on MSVC) as source
properties, so the ordinary library targets compile them blind to IO and
a call past the seam fails the build at its line.  The script stays as
the inventory: it lists every such call at once, where the build stops at
the first.  (The tls private prototypes are not yet
hidden: they share a header with the tls structs that `struct lws` embeds
by value, which the struct split resolves.)  What the compile cannot see,
a call to an IO function declared in a header both halves include,
`scripts/sans-io-link-check.sh <build-dir>` finds in the built objects:
every symbol the sansIO objects reference that only an IO object defines
and that is neither public api nor in the seam, with the files using it.

**The four requests sansIO makes of IO** (want_write, deadline, want_read,
close) are spelled `lws_callback_on_writable()`, `lws_set_timeout()` /
`lws_sul_schedule()`, `lws_rx_flow_control()` and `lws_close_free_wsi()`.
Those names stay, as sansIO's api: at the bottom of each, where the request
reaches the transport, it goes through one struct of function pointers,
`lws_io_ops_t`, that IO fills in for the normal build and an embedder of the
sansIO half fills in for theirs.  The deadline is the exception that proves
the shape: the timer lists are neither half's (below), sansIO schedules into
them, and IO hears a new earliest deadline through the `deadline` op.  The
rest of sansIO's requests go through the same struct: see "The contract".
A port that returns its requests as polled outputs, the way a Rust sans-IO
crate does, implements the same.  The struct is the seam; the rest of the
two halves never see each other.

## The contract

What a port of the sansIO half implements, or an embedder of it supplies,
is `lws_io_ops_t` (`include/libwebsockets/lws-io-ops.h`, every member
documented there) and two platform functions.  IO's implementation of each
member is named beside it; a member marked optional may be NULL where the
embedder carries nothing that needs it.

| theme | member | the request | IO's implementation |
|---|---|---|---|
| loop | `want_write` | call my tx when the transport can take bytes | `lws_io_want_write_pollfd()` |
| loop | `want_read` | feed / stop feeding my rx | `lws_io_want_read_pollfd()` |
| loop | `deadline` (optional) | the earliest deadline on a thread moved | NULL: the built-in loops ask each turn |
| loop | `close` | the close, by phase: quiesce, unwatch, shutdown, stage, release | `lws_io_close_pollfd()` |
| object | `path` (optional) | a datagram connection's peer moved, or wants a new socket | `lws_io_path_dgram()` |
| object | `created` (optional) | a connection object was made | `lws_io_adjunct_init()` |
| object | `transfer` | the connection goes on as another object | `lws_io_transfer_pollfd()` |
| transport | `transport_start` | a client's request is ready: start its transport | `lws_client_transport_start()` |
| transport | `transport_connected` | the socks / CONNECT tunnel is up | `lws_client_transport_connected()` |
| transport | `transport_established` | quic made its transport, it won the race | `lws_client_transport_established()` |
| transport | `transport_failed` (optional) | quic's transport failed: retarget if possible | `lws_client_transport_failed()` |
| transport | `transport_rebind` (optional) | a restarted client may belong on a jit-trust vhost | `lws_client_transport_rebind()` |
| transport | `client_connect` (optional) | a new client connection, a proxied transaction's onward leg | `lws_client_connect_via_info()` |
| transport | `peer_address` (optional) | the peer's address as text | `lws_get_peer_simple()` |
| tls | `tls_session` (optional) | the library's session object | `lws_tls_session_ptr()` |
| tls | `tls_hs_ca_id` (optional) | which CA verified the peer | `lws_tls_wsi_hs_ca_id()` |
| tls | `tls_peer_cert_info` (optional) | the peer certificate's information | `lws_tls_peer_cert_info()` |
| tls | `tls_quic_session` | make quic's session | `lws_tls_quic_session()` |
| tls | `tls_quic_handshake` | feed quic's CRYPTO bytes to the handshake | `lws_tls_quic_advance_handshake()` |
| tls | `tls_quic_set_tp`, `tls_quic_get_tp` | quic's transport parameters | `lws_tls_quic_set/get_transport_parameters()` |
| tls | `tls_confirm_peer_cert` | is the server's certificate acceptable | `lws_tls_client_confirm_peer_cert()` |
| tls | `tls_quic_aead`, `tls_quic_alert`, `tls_quic_alpn` | what quic's handshake settled | `lws_tls_quic_aead_type()`, `_alert()`, `_alpn()` |
| tx | `tx_push` | take these framed bytes now (the push) | `lws_io_tx_push()` |
| tx | `tx_now` (optional) | pull a datagram connection's tx now | `lws_io_tx_now()` |
| tx | `tx_choked` | would the transport block a write now | `lws_plat_tx_choked()` |
| tx | `tx_file` (optional) | drive a served file into the transport | `lws_serve_http_file_fragment()` |
| service | `service_writable` | want_write served now | `lws_service_wsi_as_writable()` |
| service | `service_now` | rx served now | `lws_io_service_now()` |
| service | `wake` | come round the loop soon | `lws_cancel_service_pt()` |
| rx | `http_client_read` (optional) | the app pulls its response body | `lws_http_client_read()` |
| vhost | `vhost_destroy` | a going vhost's last connection went | `__lws_vhost_destroy2()` |
| vhost | `vhost_jit_grace` (optional) | a jit-trust vhost's last connection went | `lws_tls_jit_trust_vh_start_grace()` |
| cgi | `cgi_start`, `cgi_stdout_tx`, `cgi_stdin_write`, `cgi_stdin_body_end`, `cgi_stderr_read`, `cgi_remove_and_kill`, `cgi_release` | an http transaction's child process | `lws_cgi_via_info()`, `lws_cgi_write_split_stdout_headers()`, `lws_cgi_stdin_write()`, ... |

The tls members exist in a build with tls, the cgi ones in a build with
cgi, since the types they name do.  The platform functions are injected
dependencies rather than requests: `lws_now_usecs()`, the clock, and
`lws_get_random()`, the random source.  A port passes them in; everything
else sansIO links with is the substrate neither half owns (`lib/core`,
`lib/misc`, the neither-half files of `lib/core-net`, the generic crypto),
which a port translates along with it.

How the calls sansIO made into IO were placed, when the contract was
written down (2026-09-28): the timer lists and a connection's timeouts
(`__lws_sul_insert()`, `lws_sul_cancel()`, `lws_sul_schedule()`,
`lws_set_timeout()`), the address text helpers (`lws_sa46_*`) and the
freeing of a conmon record are neither half's and moved to
`lib/core-net`; `lws_write()` and the sansIO part of
`lws_send_pipe_choked()` were sansIO code in IO's files and moved to
`lib/sansio/output.c`; the app apis that call every connection of a
protocol walk IO's fd table and moved to `lib/io/pollfd.c`; everything
else became the members above.

**Who calls rx.**  The end state of the rx side is that IO's service reads
and calls rx itself, and no role has a `handle_POLLIN` of its own.  What
a role knows is *how* it can be read in its current state: an h2 stream
takes parked bytes only, ws bounds a pass by its own budget, h1 parks
while it serves a file, a raw socket reads even with rx parked, and
during the transport phases of a client the bytes are not the role's at
all.  That knowledge is one small op, `rx_policy(wsi, &flags, &max)`,
answering for this pass: pump once, pump while there is more (tls holds
decrypted bytes, or a parked remainder), hold (do not read now), or "the
role reads on its own terms" (an h1 client whose body the app pulls).
IO's service asks it, does the reading it was told to, then tells the
role the pass's reading is done through `rx_done(wsi)`, where the role
acts on what it now holds: an h1 client interprets the response headers
it completed, or tells the app there is body to pull; a role that parked
rx re-arms its reading once the parked bytes are gone.  The pass's
POLLOUT goes to IO's dispatcher, in the states that take a writeable or
where the policy insisted, and is cleared otherwise; the dispatcher's own
priorities (a partial send, a compression partial, a cgi step) come before
the role's `handle_POLLOUT` op.  Fairness between a socket's POLLIN and
POLLOUT is IO's, kept in the service.  That is the whole of a sansIO
role's service interface: `rx_policy`, `rx` (or `rx_dgram`), `rx_done`,
`handle_POLLOUT`, and `client_transport_up`; no sansIO role has a
`handle_POLLIN`, only the transport adapter roles, which are IO, keep one.

Time is an input: sansIO is told the deadline passed, it never reads the
clock to decide anything.  Reading the clock for a log line or a metric
is tolerated in sansIO until the split is done.

## The object

`struct lws` is the connection as sansIO knows it: the state word, the
role, the parsers' state, the buflists, the timers, the mux position.  IO
has its own things to remember about the same connection, which sansIO
never reads: the socket, its place in the fd table, the poll bookkeeping,
the event-library handle, what kind of socket it is.  Those live in
`struct lws_io_adjunct`, which `struct lws` holds by pointer, `wsi->io`,
and nothing under `lib/sansio` names a member of it.

The adjunct is allocated with the wsi, after it, so a connection is still
one allocation: the wsi's constructor asks for `sizeof(struct lws)` plus
the context's `wsi_io_size` (the adjunct, and the event library's per-wsi
block after it), and IO's `created` op places the adjunct there and sets
it up (no socket, no place in the poll set), with a pointer back to its
wsi for what reaches the wsi from one of IO's own list nodes or timers.
A wsi made up for a callback that has none (the protocol init and destroy
callbacks, a vhost's callbacks, the h3 dummy) points at the context's
`fake_io`, an adjunct with no transport.

The compile check enforces it: under `LWS_SANSIO_CHECK` the adjunct's type
is incomplete, so a sansIO file that reads `wsi->io->desc.sockfd` does not
compile, the same way a call into IO does not, and `struct lws` has the
same layout whichever half compiles it.  A port keeps the two objects
apart the same way (in Rust the IO side owns its adjunct and holds the
sansIO connection by value or handle).

What goes in the adjunct is decided by the same test as a function: if
sansIO's decisions do not depend on it, it is IO's.  The socket identity
went first (`desc`, `position_in_fds_table`, the POLLOUT bookkeeping
bits, `evlib_wsi`, the socket-kind flags).  The connection's addresses,
address family, udp state, the parallel-connect racers, peer limits and
the async workers follow, then the datagram socket's peer state.  The
tls session is IO's: the record layer, the handshake, the library's
objects live in the adjunct, and quic's crypto asks the session what it
needs (the negotiated AEAD, the alert, the alpn) through `lws_tls_quic_*`
queries.  sansIO keeps what it asked for (`use_ssl`, the connection's
LCCSCF_ flags, which the roles decide by) and what the handshake settled
that it acts on (`alpn`, whether the session was reused), which IO sets
before it says the transport is up.

## What goes where in the tree

The directories are the halves.  Placement by directory is the whole rule:
`lib/sansio` is the sansIO half and `lib/io` the IO half, and the build
(`SOURCES_SANSIO`), the checks and the lint take the half from the
directory.

| directory | half | notes |
|---|---|---|
| `lib/sansio/*` | sansIO | every role that speaks a wire protocol (`h1`, `h2`, `h3`, `http`, `ws`, `wt`, `quic`, `mqtt`, `raw-skt`, `raw-proxy`): state machine, parser, framer, scheduler; `private-lib-sansio.h`, the role ops and the wsi state; `private-lib-sansio-seam.h`, the seam |
| `lib/sansio/wsi.c`, `wsi-state.c`, `close.c`, `state.c`, `vhost.c`, `output.c`, `socks5-client.c`, `dummy-callback.c` | sansIO | the wsi state, the event table, connection lifecycle decisions, the vhost's protocols and roles, the app's write (`lws_write()`, `lws_send_pipe_choked()`), the socks handshake |
| `lib/sansio/client-connect4.c` | sansIO | a client's step once its socket is connected (`lws_client_connect_4_established()`): it composes the http proxy CONNECT, runs the socks greeting, queues a pipelined connection behind its leader, and otherwise asks IO for the transport |
| `lib/io/`: `output.c`, `pollfd.c`, `service.c`, `adopt.c`, `network.c`, `route.c`, `sorted-usec-list.c`, `vhost.c` | IO | moving bytes, fds, poll; running the timers that are due; a vhost's creation and destruction (its listen sockets, tls contexts, dns) |
| `lib/io/client/`: `connect.c`, `connect2.c`, `connect3.c`, `transport.c`, `sort-dns.c`, `conmon.c` | IO | dns, connect, happy eyeballs; address selection for connect (RFC 6724 sorting of the resolved addresses); the connection-monitoring report of what the transport did |
| `lib/tls/*` record layer: `lws_ssl_capable_read/write`, bio, session cache, handshake driving | IO | sansIO sees plaintext |
| `lib/sansio/quic` packet and frame layer, `lib/sansio/h3`, qpack | sansIO | quic is a sansIO part with a datagram interface instead of a stream one |
| `lib/io/listen`, `netlink`, `pipe`, `raw-file`, `dbus`, `cgi` | IO | transport adapters wearing the role interface: they accept sockets, read pipes, fds and the kernel's routing; nothing on the wire is theirs |
| `lib/plat/*`, `lib/event-libs/*` | IO | |
| `lib/core/*`, `lib/misc/*`, `lib/system/*` | neither | context, logging, utilities: shared by both halves, used by both |
| `lib/core-net/roles.c`, `async-queue.c`, `client/client.c`, `address.c`, `sorted-usec-list.c`, `wsi-timeout.c`, the generic crypto in `lib/tls` (`lws-gen*`) | neither | the role registry both halves dispatch through (sansIO roles and IO's adapters), the worker pool, the client's proxy settings, header stash and the freeing of a conmon record that both halves call, addresses as text and as data (`lws_sa46_*`, `lws_parse_numeric_address()`, cidr, mac), the timer lists both halves schedule into and a connection's timeouts on them (a new earliest deadline is announced to IO through the `deadline` op), crypto primitives |
| `lib/io/lejp-conf.c` | IO | lwsws' config: it makes the vhosts and mounts it describes |

Of the files that had both, `connect4.c` is whole in sansIO as
`client-connect4.c`: the port the socket connected to (the proxy's, when
there is one) is IO's record, made when IO chooses where to connect, and
nothing of IO is left in it.  The checks and the lint find nothing of IO
in `quic/ops-quic.c` either.  What the lint still counts is
`quic/crypto-quic.c` calling gnutls directly for quic's packet
protection AEAD and its alert mapping.  Where a file has both, the split
is inside the file until it is moved; the decision rule still says which
half each function is in.

## Rules from now on

1. New code goes on the side the test puts it.  A change that adds a
   socket, poll or TLS-library reference under `lib/sansio` is wrong,
   whatever else it does.
2. The interface calls are the only way across.  Adding one is a design
   change, not a convenience.
3. The state trace (`LWS_STATE_TRACE_FILE`) is the oracle: a split step is
   done when the gate's edge set is unchanged.
4. `scripts/sans-io-lint.sh` greps `lib/sansio` for the forbidden
   identifiers and compares the total with `scripts/sans-io-lint.baseline`.
   More than the baseline fails; a step that brings it down re-baselines
   with `--update`.  The count only goes down.

## The scratch buffer

`pt->serv_buf` is one buffer per service thread that IO piles into so that
nothing has to allocate: the rx pump reads into it behind `LWS_PRE`, and the
tx pulls (quic packets, h2 pps, file fragments, the h1 proxy body relay)
produce into it.  Directly above it, the same size, is `pt->compose_buf`,
where the composers (`lws_serve_http_file()`, `lws_return_http_status()`,
the ws and mqtt handshakes and packets, the client requests, socks5 and
proxy CONNECT) build their bytes.  `lws_http_redirect()` and the
`lws_add_http_header_...()` helpers write into whatever buffer the caller
passes them, so they are the caller's business.

The composers get their own half because they cannot know what else is
live when they run: user code calls them from callbacks the parsers deliver
in the middle of a read, while the read's unparsed tail is still in
serv_buf (a POST answered from `LWS_CALLBACK_HTTP_BODY_COMPLETION` with a
pipelined request, later h2 frames or the rest of a quic datagram behind
it; an mqtt publish from `LWS_CALLBACK_MQTT_CLIENT_RX` with the broker's
next packets behind it, or echoing the very payload it was handed).  The
tx pulls run from POLLOUT, never inside a read, so they can share serv_buf
with the rx pump.  Both halves are one allocation after the context,
`2 x pt_serv_buf_size` per thread, so `pt_serv_buf_size` keeps meaning the
most any one user of either half may use.

Both halves are only sound while whoever is using a range of them is the
only user of that range, and only inside one service pass: the next pass,
for any socket on the thread, reuses them.  Ownership can be fragmented:
while a read's unparsed tail is still live at the top, the pump's claim on
the part below it that the parser has already consumed is given back.

The rules:

1. A read's bytes belong to the rx pump until the role's `rx` returns.  A
   role that has parsed or parked everything up to a point gives the
   prefix back (`lws_servbuf_trim()`), and one that has parked the rest of
   the read on its buflist, as the h1 server does before it acts on a
   request, gives all of it back (`lws_servbuf_release_containing()`).
   User code must not run while unparsed bytes it could compose over are
   still in the buffer: park them first.
2. A composer composes in compose_buf, never serv_buf, and owns what it
   composes into from its first byte until the write that consumes it
   returns.  It hands the buffer over explicitly when it delegates to
   another composer without having composed anything (the file server's
   404 and 416).
3. Nothing holds any of it across a service pass boundary.

`LWS_WITH_SERVBUF_CHECK` (Debug only, off by default, alongside
`LWS_WITH_STATE_CHECK`) makes these checkable: each user claims its range
with a name (`lws_servbuf_claim()`) into a small per-thread table covering
both halves (so either one overrunning into the other is seen too), a claim
overlapping a live one aborts naming both, a claim still live when
`_lws_service_fd_tsi()` is entered aborts naming it.  Every serv_buf user
in the library is instrumented; pointers that turn out not to be in
serv_buf (a buflist segment) are ignored, so the same calls cover the
parked paths.  Without the option the calls compile to nothing.

The tracking itself is not IO's or sansIO's: it is the core `lws_region`
api (`include/libwebsockets/lws-region.h`), which tracks claims on any
caller-provided buffer in a caller-provided slot table.  The pt holds one
`lws_region_t` over serv_buf and compose_buf together, set up with
`LWS_REGION_F_ABORT` when the context allocates them, and the `lws_servbuf_...()` spellings are macros in
`private-lib-core-net.h` over the pt's region, visible to both halves, so
neither side reaches across the seam to use it.  A release is by the
handle the claim returned, which carries the slot's generation, so a
stale release after the claim was already handed on by
`lws_servbuf_release_containing()` leaves whoever reused the slot alone.
One user is not claimed on purpose: the tls fallback peek
(`recv(MSG_PEEK)` on a fresh connection in the accept path, nothing else
can be live).

## Staging

1. Finish the boundary violations that already exist: the socks and proxy
   legs writing to the fd, connect completion special cases living in
   `connect4.c` instead of the roles (both done: `c9ca0d2f5` and the
   `client_transport_up` op).
2. Land the lint with today's count as its baseline (done: 273 by the
   first measure; 213 once it counted transport reads and stopped counting
   the handler's pollfd).
3. Move the IO files of `lib/core-net` into `lib/core-net/IO/`, no code
   change, so the directory says what the file is (done; then both halves
   became directories, `lib/sansio` and `lib/io`, the roles going to the
   half each is in).
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
5. h2, then h3 over the quic datagram layer, then the remaining roles
   (done for rx: every role's bytes come through rx / rx_dgram).  Then
   the roles' handlers stop reading: `rx_policy` and IO's rx stage
   (done: every role answers it, IO's `lws_rx_stage()` reads for the
   poll and for the ripe-rxflow pass alike, and keeps the fairness
   between POLLIN and POLLOUT).  The pass's POLLOUT is IO's dispatcher's
   (done: every role's writeable is its `handle_POLLOUT` op).  A client's
   dns, connect and tls passes are IO's client transport machine
   (done: `lib/io/client/transport.c`; the role hears the transport is up
   through its `client_transport_up` op and starts its protocol; the socks
   and CONNECT legs stay the role's rx and tell IO when the tunnel is up
   with `lws_client_transport_connected()`).
6. Tier the public headers into `lws-core.h`, `lws-sansio.h`, `lws-io.h`
   (done), then the private ones, with the sansIO-only compile check
   (done: `private-lib-io.h`, `scripts/sans-io-check.sh`; first inventory
   82 calls into IO from sansIO sources, 42 callees; 48 and 25 once the
   adapter roles were classed as IO and the sansIO functions that lived in
   IO files moved home.  What is left is IO code in sansIO files, the
   POLLOUT clears, the pump calls from the roles' own handlers, and
   `lws_issue_raw`, now `lws_io_tx_push()`, as today's spelling of tx).
7. The four requests through `lws_io_ops_t` (done: `lws-io-ops.h`,
   `lws_io_ops_default` in `lib/io/pollfd.c`, `lws_context_creation_info.io_ops`).
   Then quic's datagram socket, the largest group left in the check: its
   path is a request (`path`), a connection moving to another wsi is one
   (`transfer`, shared with the keep-warm join), the handshake ending the
   race with the tcp fallback is `lws_client_transport_established()`, and
   what IO already knew (the peer it connected to, that a datagram role
   wants a udp socket, ECN and its listeners) is IO's to act on or to pass
   in (done: the check fell from 19 lines to 7).  Then quic's tx is a
   pull: IO drives the loop that sends its packets and asks quic for each
   (done: quic names nothing of IO's any more; 6 lines left, none quic's).
   Then the stream roles (done: h2's protocol packets are pulled, the
   client preface and the h2c 101 among them; what stays a push is named
   for it, `lws_io_tx_push()`: the app's lws_write() data, framed in place
   uncopied, the proxy legs' one-shot messages, a mux stream's partial).
   Then the last of the check's lines (done: 0): the close's quiesce
   answers whether the close callback is owed, the pt pipe leaves the loop
   at the quiesce, a raw file and every close stop watching the transport
   through the unwatch phase, the object's IO half is set up through
   `created`, and a client's quic fallback and its start after waiting for
   a header table are `lws_client_transport_failed()` and
   `lws_client_transport_start()`.  The check only sees calls to what is
   declared for IO alone; an IO function also declared in a header both
   halves see (`lws_addrinfo_clean()` was one) is invisible to it.  The
   link-level check (`scripts/sans-io-link-check.sh`) found 20 of those
   (done: 0): the close's remaining transport steps are its phases; what
   sansIO asks of the tls session is in the seam, quic's session is made
   by one request, and an SNI bind records its CA on the tls side; the
   locked deadline and a destroyed vhost's last unbind are seam requests;
   the role registry is neither half's; lwsws' config loader is IO's; and
   the h1 client's request headers go out through the push, which also
   keeps what a short write left (they were lost before).  The check sees
   only what a build compiles: with the optional features on (cgi, the
   access log, jit trust) 8 more (done: 0): a cgi is a child process IO
   runs for an http transaction, asked through the seam to take its
   request body, end its stdin, be killed and released; a cgi stdio pipe
   is known by a role property (`child_stdio`) rather than by naming the
   cgi role; the access log asks IO for the peer as text; a restarted
   client's jit-trust vhost and a jit-trust vhost's grace are IO's.
8. Split the object: IO's fields of `struct lws` move into the
   `lws_io_adjunct` (see "The object"), the check making it opaque to
   sansIO (done: the socket identity first; then the adjunct is held by
   pointer, allocated after the wsi, its type incomplete to sansIO, so
   both halves compile the same `struct lws`; then the members only IO
   used, found by counting each member's uses in the two halves).
9. A byte-level harness: a connection whose transport is the test's
   (`lws_set_transport()` for a server connection, the `transport` of
   `lws_client_connect_info` for a client one, under the tls record layer
   and at the datagram edge), driving an h1 transaction and a ws exchange
   with no socket under them and no poll(): the test is the loop, and
   hears lws's requests of the transport through a wrapped
   `lws_io_ops_default` (done: `api-test-sansio`, both halves; a client
   with a transport skips dns and connect and starts on it as connected,
   `lws_client_connect_transport()`).  Then the sansIO half compiled
   alone (done as a compile: every build compiles what is under
   `lib/sansio` blind to IO, above, and fails on a call into IO past the
   seam; with the link-level check, the objects need nothing private of
   IO's; and with the struct split both halves compile the same
   `struct lws`, so the library the byte-level harness runs against is
   the one whose sansIO objects were compiled that way).  These are the
   test of "technically complete"; the static checks above are
   inferences until they pass.
10. When every role is converted, the IO half is a replaceable component,
   and the sansIO half is what a port translates.

## Open before it is done

An outside review (2026-09-27) of whether the split is ready to rely on
in C, and to be the source of a Rust port, listed these.  Each is worked
on and marked done here, like the staging above.

### Before relying on it in C

1. CI.  Nothing guarded the split unless a CI configuration turned its
   checks on (done: the compile check is part of every build, on every
   platform and configuration CI builds; the sai configuration `sansio`,
   on one Linux gcc builder with the optional features that reach across
   the split on, also runs `scripts/sans-io-link-check.sh`;
   `scripts/sans-io-check.sh` is not run there, since the build fails on
   the same calls).
2. The harness covers only h1 and ws (six cases).  It needs h2, h3
   through the datagram edge (`recv_dgram` / `send_dgram` in the
   transport ops), mqtt, and a case under tls.
3. Behaviour left over from the split:
   - a quic frame in flight counts as buffered output, so an h3 file
     response goes one fragment per round trip, and the loop spins after
     the client vanishes;
   - mux streams on the parked-rx list: they have no fd, so the forced
     service pass they cause may not be able to reach them (unverified);
   - the keep-warm join's status at ESTABLISHED (parked).

### Before it is the port's source

4. tx is a push where the app's data is concerned: `lws_write()` reaches
   `lws_io_tx_push()` from sansIO (15 files, about 60 call sites), and
   the roles compose into the pt's buffers directly.  A sans-IO port has
   to hand bytes out, so the app's data becomes a pull like the rest,
   with `lws_write()` kept as the app's api on top of it.
5. Time is not an input: sansIO reads the clock about 56 times, about 23
   of them decisions (quic congestion control, loss detection, pacing),
   and timer callbacks get no "now".  The pass's timestamp is to be
   passed into the rx, tx and deadline entry points.
6. What IO reads of the object is wide: about 85 members of `struct lws`,
   1674 uses.  Most are config reads through the vhost and context, but
   the cgi adapter reaches into the http role's state 132 times, and IO
   reads the stash, the alpn, the user space and the tls wish directly.
   IO wants an explicit accessor set, and cgi its own state.
7. Locks and the fd table: sansIO takes the pt, context and vhost locks
   about 38 times, and walks IO's fd table to enumerate connections in
   three places in wsi.c.  A port has neither.  (The fd table walks are
   done: they were app apis over every connection of a protocol, and
   moved to IO.  The locks are not.)
8. The interface is about twenty calls, not the four requests above:
   the transport machine's five, seven tls session queries, the cgi's
   four and the served-now variants.  "The interface" is to state the
   real contract, since that is what a port implements (done: every
   request is an `lws_io_ops_t` member, "The contract" above lists them,
   and the sansIO objects take nothing else of IO's but the clock and the
   random source).
