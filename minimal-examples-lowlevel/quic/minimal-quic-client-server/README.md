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
