# lws minimal quic client server

This example runs a QUIC server on a UDP listener and, unless told otherwise,
a QUIC client in the same process that connects to it.  Both sides open a
stream and send each other 128KB, and the test passes when each side has
received all of it, in order.

Each byte sent is a function of its stream offset, so the receiver checks the
data arrived in order, with nothing lost or repeated, as well as that it all
arrived.

## build

```
 $ cmake . && make
```

## usage

|Option|Meaning|
|---|---|
|-p <port>|Port the server listens on, and the client connects to (default 7681)|
|--server <address>|Server address the client connects to (default 127.0.0.1)|
|-s|Server only: no client, and the server does not send data unprompted|
|-u <url>|Connect the client to the server at this url instead of running one here|
|--relay <port>|The client connects through a relay on this port, see below|
|--stray|With `--relay`, the relay also sends the client stray packets of another connection, see below|
|--outage <ms>|With `--relay`, after the client's first Initial the relay loses all but the client's Initial packets for this long, see below|
|--early-1rtt|With `--relay`, the relay sends the client's first 1-RTT packet ahead of its Finished, see below|
|--forwarder|With `--relay`, the relay also sends the server copies of the client's small packets from an address that never answers, see below|
|--write-size <n>|Bytes sent per `lws_write()`, 1 to 1024 (default 1024)|
|--cubic|Use the CUBIC congestion controller instead of the default NewReno, see below|

```
 $ ./lws-minimal-quic-client-server
```

## the reordering relay

With `--relay <port>`, the client connects to a UDP relay in the same process
instead of to the server.  The relay passes datagrams on in each direction,
but holds up to four at a time and sends each batch on last first, so both
sides receive the handshake's CRYPTO data and the stream data out of order,
and have to hold what arrives early until the gap in front of it fills.  A
datagram arriving while its direction's batch is full is dropped, which QUIC
recovers from like any other loss.

The relay needs the server address to be numeric, eg

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --write-size 100
```

Small `--write-size` values make each packet carry many small STREAM frames.

With `--stray` as well, the relay also sends the client, ahead of the first
and every eighth batch it passes on to it, a long header packet of some other
QUIC connection: connection IDs that are not the client's, alternately in
QUIC v2 and v1, and a payload nobody has keys for.  Stray packets like this
are an ordinary network event.  The first one arrives before the server's
first Initial, during the handshake, and the rest after it; the client must
drop all of them without any of them changing its connection (RFC 9000 7.2:
the server's connection ID is taken only from its first Initial that
authenticates, and RFC 9368: the version only from a packet that
authenticates), and the transfer must complete.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --stray
```

With `--outage <ms>` as well, once the relay has passed on the client's first
Initial, for that long it loses everything the client sends except its Initial
packets, as a run of corrupted packets would: packets after the Initial ones
in a datagram are blanked to padding, and a datagram with no Initial packet
at the front is dropped.  The server hears the client acknowledge its
Initial, so it has a round trip time measurement, but never gets the client's
Finished.  It must keep probing and keep the half-open connection within its
handshake deadline, so that the handshake completes and the transfer goes
ahead once the client's retransmissions get through again.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --outage 2000
```

With `--early-1rtt` instead, the relay passes datagrams on as they come,
except that after the client's first Initial it holds the client's Handshake
packets, with its Finished in them, until the client's first 1-RTT datagram,
with the start of its stream data, has gone on ahead of them.  So the server
gets that 1-RTT packet before its handshake has completed, as it can when the
network reorders them.  It must not process it then (RFC 9001 5.7), but it can
hold it until its handshake completes.  For a second after, the relay loses the
client's other 1-RTT datagrams, so nothing the client sends again can stand in
for the early one: by the end of that second, the server must have the start
of the stream.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --early-1rtt
```

With `--forwarder` instead, the relay also has a second socket, and sends the
server a copy of each of the client's small 1-RTT datagrams, eg, its ACKs, from
there, ahead of the original, as an off-path attacker who can see the client's
packets might.  The copy is new and authentic to the server, so it looks like
the client moved (RFC 9000 9.3), and the server probes the new address with a
PATH_CHALLENGE that is never answered.  The server must stay on the path it
validated, so the transfer completes, and once probing the forwarder's address
failed, not keep probing it for every packet that comes from it.  With a small
`--write-size`, the client sends plenty of small packets; the test fails if the
server sent the forwarder more than its one probe would, about 14 datagrams
here, where probing again for every copy sends around 80.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --forwarder --write-size 64
```

## congestion controller

lws uses NewReno (`lws_cc_ops_newreno`) unless `lws_context_creation_info`
`.quic_cc_ops` names another controller.  With `--cubic` both the server and
the client in this process use `lws_cc_ops_cubic` instead, so the transfer, and
through the relay the loss recovery, exercise that controller's accounting:

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --write-size 100 --cubic
```

## Retry

With `LWS_QUIC_FORCE_RETRY` set in the environment, the lws QUIC server answers
every Initial that has no token with a Retry, and only accepts the client's
next Initial carrying the token (RFC 9000 8.1.2).  The client checks the
server's transport parameters repeat the connection IDs of that exchange
(RFC 9000 7.3).

```
 $ LWS_QUIC_FORCE_RETRY=1 ./lws-minimal-quic-client-server
```
