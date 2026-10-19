# lws-api-test-peer-stack-quic

Checks the peer address stack (`lws_peer_walk()` and friends, in
`lws-network-helper.h`) of QUIC connections.  A QUIC connection's peer is
first only the source address of a datagram, which anyone can write, so its
entry starts as HEARSAY and is raised as QUIC proves more about it:
ROUTABLE once the address is validated (RFC 9000 8.1: a packet from it
protected by the Handshake keys, a Retry token bound to it, or a
PATH_RESPONSE from it), CRYPTO once the handshake is done on that validated
path.

An h3 server and client run in one process.

 - **levels**: the client's connection is HEARSAY while it dials, and CRYPTO
   once its handshake is done; while it is hearsay, `lws_get_peer_host_key()`
   gives `LWS_HOST_KEY_UNPROVEN` for it.  The server sees the client as one
   SOCKET entry at CRYPTO when the request arrives, keyed as its own host, so
   its logs and access log show the client by its bare address, as for a TCP
   connection, not with a hearsay port and cred.

 - **migration**: the client reaches the server through a little udp "NAT"
   in the test, which, once the first half of a slow response has arrived,
   moves its side to a new port, as a NAT rebinding does.  When the server
   has validated the new path and moved the connection onto it (RFC 9000 9),
   its peer entry is the NAT's new port at ROUTABLE: a new path starts again
   from hearsay and is raised by its own validation, it does not keep the
   CRYPTO the handshake proved about the old path.

 - **split**: the NAT sends the client's first Initial from one port, and
   every later long header packet, its Handshake packets among them, from
   another, whose answers it drops, as a client with two sockets or a NAT
   rebinding during the handshake would.  The Handshake keys prove the
   address the server's Initial went to (RFC 9000 8.1), not the source a
   Handshake packet claims, so the server sees the client on the first port
   at CRYPTO, keyed as its own host: it is not left unproven for its life,
   counted against no host's `ip_limit_wsi`.

 - **access log** (with `LWS_WITH_ACCESS_LOG`): the levels phase's request
   is logged with just the client's address as its host field.

With `LWS_WITH_PEER_LIMITS`, the unproven budget, in a second context (so
nothing of the phases above still counts), with `ip_limit_wsi` and
`unproven_limit_wsi` both 1, and `pl_notify_cb` counting refusals: those for
a host name its address, those for the unproven budget none.  Each client has
a client vhost of its own, so none joins another's connection.

 - **hold**: a client's request is held unanswered by the server: its
   validated connection stays up, counted against 127.0.0.1.

 - **host**: another client is let in while its address is unproven, since it
   counts in the unproven budget, but refused when QUIC validates its address
   and it moves to 127.0.0.1's budget, which is full.

 - **unproven**: the test sends a lone QUIC Initial from a raw udp socket,
   which never validates its address.  It is let in, so the held connection
   does not count in the unproven budget any more; it fills it, so the next
   client's Initial is refused for the unproven budget (with no address
   named), though its host's budget would not have mattered yet.

 - **release**: the server answers the held request, and the held client gets
   it: a full unproven budget does not affect validated connections.

## Commandline

| option | meaning |
|--------|---------|
| `-p PORT` | the server's h3 port |
| `--cert FILE`, `--key FILE` | the server's certificate and key |
| `--access-log FILE` | the server's access log, emptied first, checked at the end |

## Run

```
$ ctest -R api-test-peer-stack-quic
```
