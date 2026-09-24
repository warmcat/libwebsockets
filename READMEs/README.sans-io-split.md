# The sans-IO split

lws is being divided into two halves with one narrow interface between
them.  This document is the rule for deciding which half a piece of code
belongs to, the interface, and the directories.  It is written so that a
reader, human or otherwise, can place any function in a few seconds.

## The two halves

**core**: decides what bytes mean and what bytes to send next.  Parsers,
framers, the protocol state machines (`README.wsi-state-machines.md`), the
role ops, flow control, mux stream scheduling, the proxy and socks
handshakes, hpack and qpack, the quic packet and frame layer.

**io**: moves bytes and time.  Sockets, file descriptors, poll flags, the
fd table, event-loop integration, the TLS record layer, UDP datagram
send and receive, DNS lookups, connect and happy eyeballs, the clock.

The test: **if it were deleted, would the bytes on the wire or the state
transitions change for a given input?**  Yes: core.  No, only *when* or
*how* the same bytes get moved: io.

Corollary, as a grep: core code never names a socket or fd
(`desc.sockfd`, `send(`, `recv(`, `sendto(`), a poll flag (`pollfd`,
`revents`, `LWS_POLLIN`), a TLS library object (`SSL_`, `gnutls_`,
`mbedtls_`), or an event-loop handle (`uv_`, `ev_`, `event_base`).  io
code never parses or composes a protocol byte.

## The interface

The core is driven entirely by these calls, and drives io entirely by these
requests.  Nothing else crosses.

| direction | call | today's C |
|---|---|---|
| io -> core | **rx(bytes)**: bytes arrived, consume them | role `handle_POLLIN` (which today reads the socket itself; the split hands it the bytes) |
| io -> core | **writable()**: the out buffer drained, you may produce | role `handle_POLLOUT`, `perform_user_POLLOUT` |
| io -> core | **deadline()**: the deadline you set has passed | `sul` callbacks, `lws_sul_wsitimeout_cb` |
| io -> core | **transport(up / failed / gone)** | `LWS_WSIEV_TRANSPORT_UP`, `CONN_FAILED`, `SOCKET_GONE` |
| core -> io | **tx(bytes)**: queue these to send | `lws_issue_raw()` appending to `buflist_out` |
| core -> io | **want_write()**: call me back when drained | `lws_callback_on_writable()` |
| core -> io | **deadline(us) / no deadline** | `lws_set_timeout()`, `lws_sul_schedule()` |
| core -> io | **close(reason)** | `lws_close_free_wsi()`, `LWS_WSIEV_CLOSE_FLUSH` |

Four in, four out.  A core that needs anything else from io is a core that
has io in it.

Time is an input: the core is told the deadline passed, it never reads the
clock to decide anything.  Reading the clock for a timestamp in a log or a
metric is io's business too, but is tolerated in core until the split is
done.

## What goes where in the tree

The directories are the halves.  Placement by directory is the whole rule.

| directory | half | notes |
|---|---|---|
| `lib/roles/*` | core | every role: state machine, parser, framer, scheduler |
| `lib/core-net/wsi.c`, `wsi-state.c`, `close.c`, `state.c`, `vhost.c`, `socks5-client.c`, `dummy-callback.c` | core | the wsi state, the event table, connection lifecycle decisions, the socks handshake |
| `lib/core-net/client/connect4.c` proxy CONNECT composition | core | it composes protocol bytes |
| `lib/core-net/output.c`, `pollfd.c`, `service.c`, `adopt.c`, `network.c`, `route.c`, `wsi-timeout.c`, `sorted-usec-list.c` | io | moving bytes, fds, poll, timers |
| `lib/core-net/client/connect.c`, `connect2.c`, `connect3.c` | io | dns, connect, happy eyeballs |
| `lib/tls/*` record layer: `lws_ssl_capable_read/write`, bio, session cache, handshake driving | io | the core sees plaintext |
| `lib/roles/quic` packet and frame layer, `lib/roles/h3`, qpack | core | quic is a core with a datagram interface instead of a stream one |
| `lib/roles/quic` `sendto`/`recvfrom` | io | the one place a role touches the socket, to be moved behind tx/rx |
| `lib/plat/*`, `lib/event-libs/*` | io | |
| `lib/core/*`, `lib/misc/*`, `lib/system/*` | neither | context, logging, utilities: shared by both halves, used by both |

Where a file has both today (`connect4.c`, `ops-quic.c`), the split is
inside the file until it is moved; the decision rule still says which half
each function is in.

## Rules from now on

1. New code goes on the side the test puts it.  A change that adds a
   socket, poll or TLS-library reference under `lib/roles` or the core
   files above is wrong, whatever else it does.
2. The eight interface calls are the only way across.  Adding a ninth is a
   design change, not a convenience.
3. The state trace (`LWS_STATE_TRACE_FILE`) is the oracle: a split step is
   done when the gate's edge set is unchanged.
4. `scripts/sans-io-lint.sh` greps the core directories for the forbidden
   identifiers.  It reports the count; the count only goes down.

## Staging

1. Finish the boundary violations that already exist: the socks and proxy
   legs writing to the fd (done), connect completion special cases living
   in `connect4.c` instead of the roles.
2. Land the lint with today's count as its baseline.
3. Move the io files of `lib/core-net` into `lib/core-net/io/`, no code
   change, so the directory says what the file is.
4. Convert one role's rx to take bytes instead of reading them (h1 or ws),
   with the trace unchanged.  This is the pattern for the rest.
5. h2, then h3 over the quic datagram core, then the remaining roles.
6. When every role is converted, the io half is a replaceable component,
   and the core half is what a port translates.
