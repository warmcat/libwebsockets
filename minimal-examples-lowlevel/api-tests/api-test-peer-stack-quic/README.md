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
   once its handshake is done.  The server sees the client as one SOCKET
   entry at CRYPTO when the request arrives, so its logs and access log show
   the client by its bare address, as for a TCP connection, not with a
   hearsay port and cred.

 - **migration**: the client reaches the server through a little udp "NAT"
   in the test, which, once the first half of a slow response has arrived,
   moves its side to a new port, as a NAT rebinding does.  When the server
   has validated the new path and moved the connection onto it (RFC 9000 9),
   its peer entry is the NAT's new port at ROUTABLE: a new path starts again
   from hearsay and is raised by its own validation, it does not keep the
   CRYPTO the handshake proved about the old path.

 - **access log** (with `LWS_WITH_ACCESS_LOG`): the levels phase's request
   is logged with just the client's address as its host field.

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
