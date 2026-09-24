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
(`desc.sockfd`, `send(`, `recv(`, `sendto(`), a poll flag (`pollfd`,
`revents`, `LWS_POLLIN`), a TLS library object (`SSL_`, `gnutls_`,
`mbedtls_`), or an event-loop handle (`uv_`, `ev_`, `event_base`).  IO
code never parses or composes a protocol byte.

## The interface

The sansIO half is driven entirely by these calls from IO, and asks IO for
things only through these requests.  Nothing else crosses.

| direction | call | today's C |
|---|---|---|
| IO -> sansIO | **rx(bytes)**: bytes arrived, consume them | role `handle_POLLIN` (which today reads the socket itself; the split hands it the bytes) |
| IO -> sansIO | **tx(buf, max) -> n, more**: the transport can take bytes: fill the caller's buffer with the next ones to send, from wherever you got to last time, and say whether more remain | `lws_write()` composing into the `LWS_PRE` headroom then `lws_issue_raw()`; role `handle_POLLOUT` |
| IO -> sansIO | **deadline()**: the deadline you set has passed | `sul` callbacks, `lws_sul_wsitimeout_cb` |
| IO -> sansIO | **transport(up / failed / gone)** | `client_transport_up` op, `LWS_WSIEV_TRANSPORT_UP`, `CONN_FAILED`, `SOCKET_GONE` |
| sansIO -> IO | **want_write()**: call tx when the transport can take bytes | `lws_callback_on_writable()`; `lws_service_wsi_as_writable()` is the same request served now |
| sansIO -> IO | **deadline(us) / no deadline** | `lws_set_timeout()`, `lws_sul_schedule()` |
| sansIO -> IO | **close(reason)** | `lws_close_free_wsi()`, `LWS_WSIEV_CLOSE_FLUSH` |

Four in, three out.  A sansIO part that needs anything else from IO is a
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
| `lib/roles/quic` `sendto`/`recvfrom` | IO | the one place a role touches the socket, to be moved behind tx/rx |
| `lib/plat/*`, `lib/event-libs/*` | IO | |
| `lib/core/*`, `lib/misc/*`, `lib/system/*` | neither | context, logging, utilities: shared by both halves, used by both |

Where a file has both today (`connect4.c`, `ops-quic.c`), the split is
inside the file until it is moved; the decision rule still says which half
each function is in.

## Rules from now on

1. New code goes on the side the test puts it.  A change that adds a
   socket, poll or TLS-library reference under `lib/roles` or the sansIO
   files above is wrong, whatever else it does.
2. The seven interface calls are the only way across.  Adding an eighth is a
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
2. Land the lint with today's count as its baseline (done: 273).
3. Move the IO files of `lib/core-net` into `lib/core-net/IO/`, no code
   change, so the directory says what the file is (done).
4. Convert one role's rx to take bytes instead of reading them (h1 or ws),
   with the trace unchanged.  This is the pattern for the rest.
5. h2, then h3 over the quic datagram layer, then the remaining roles.
6. When every role is converted, the IO half is a replaceable component,
   and the sansIO half is what a port translates.
