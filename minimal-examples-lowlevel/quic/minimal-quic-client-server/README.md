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
|--pmtu <bytes>|With `--relay`, the relay loses datagrams bigger than this, 1200 to 2048, and checks both sides found the biggest size they can send, see below|
|--delay-spike|With `--pmtu`, when each side starts probing, the relay holds what it sends for 500ms, see below|
|--blackhole|With `--relay`, once each side sends bigger packets than an IP MTU of 1280 carries, the relay loses them all, see below|
|--write-size <n>|Bytes sent per `lws_write()`, 1 to 1024 (default 1024)|
|--spread <ms>|The client spreads its writes over this long, 0 to 30000 (default 0, as fast as it can), see below|
|--cubic|Use the CUBIC congestion controller instead of the default NewReno, see below|

```
 $ ./lws-minimal-quic-client-server
```

## spreading the client's writes

With `--spread <ms>`, the client doesn't write as fast as it can, but spreads
its 128KB evenly over that long, so the connection and its stream carry data
for that long.  The server reaps a connection that is idle, by default 5s after
its handshake if it has no streams, and must not take one whose stream is still
busy for idle.

```
 $ ./lws-minimal-quic-client-server --spread 8000
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
validated, so the transfer completes.  A probe sends its PATH_CHALLENGE again
no more than once a PTO, and gives up after three (RFC 9000 8.2.1, 8.2.4),
however fast the client's packets come; once it failed, the server must not
probe the forwarder's address again for 1s, doubling each time it fails again.

With a small `--write-size`, the client sends plenty of small packets, and
with `--spread` they keep coming for long enough to see the server probe, fail
and wait several times.  Over the time the server sent the forwarder anything,
the test allows it 3 datagrams for each probe it could have started backing
off like that, and one more probe.  A server that sends the challenge again
each time it's lost, ie, as fast as the client's packets are acked, sends
dozens more; one that probes again at once after failing sends about twice as
many.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --forwarder --write-size 64 --spread 12000
```

With `--pmtu <bytes>` instead, the relay passes datagrams on as they come, but
loses any bigger than that, as a path with a smaller MTU would.  Once its
handshake completed, each side looks for the biggest datagrams the path
carries (DPLPMTUD, RFC 9000 14.3): lws sends probes, each a PING padded out
to the size it probes, in packets of their own, so the search goes on whether
the side has anything else to send or not, and the peer acks every probe.  It
probes an IP MTU of 1380, then up in steps of 100 to 1500, or less if the
peer's `max_udp_payload_size` is smaller, as datagrams 48 bytes smaller, for
the IPv6 and UDP headers.  A probe that is lost is sent again, but after it
lost three probes of a size, it settles on the size it has, and tries that
size again 10 minutes later.  Lost probes are not sent again by loss
recovery, nor count as congestion (RFC 9000 14.4).

By the end of the transfer, the biggest datagram each side sent must be the
biggest of those sizes the path carries, and it must not have lost more than
three datagrams that were too big for it.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --pmtu 1400
```

With `--delay-spike` as well, the path's delay spikes just as each side
starts probing: from the first probe, the relay holds everything that side
sends for 500ms, then sends it all on in order.  By then the side gave its
probes up for lost, and may have settled on 1280, but when their acks come
after all, the path carries their size, and it must search on from there.
The same checks as `--pmtu` apply.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --pmtu 1500 --delay-spike
```

With `--blackhole` instead, the path's MTU falls under the connection.  The
relay passes datagrams on as they come, until it has passed ten in a
direction that are bigger than an IP MTU of 1280 carries, 1232 bytes; from
then on it loses every datagram bigger than that in that direction, without
telling anyone, as a path whose MTU fell to 1280 would.  Loss recovery alone
never gets through: what was lost goes again in packets just as big.

So each side watches for packets bigger than 1232 being lost (RFC 8899 4.3):
once three were lost with none sent after them getting through, it goes back
to 1280 at once, and sends a probe of 1232 bytes to confirm small packets
still get through.  It can't wait for that before going back: the other side
acks the probe in what it sends next, which is big, and lost too.  Once the
probe gets through, the side searches again from 1280, and settles there when
its probes of 1380 are lost; it tries 1380 again 10 minutes later.  If a big
packet sent before going back is acked after all, it was ordinary loss, and
the side goes back to the size it had.  The transfer must complete, and each
side must have sent big packets into the black hole, or nothing was tested.

```
 $ ./lws-minimal-quic-client-server --server 127.0.0.1 -p 7681 --relay 7682 --blackhole
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
