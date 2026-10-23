# lws minimal http Server Side Events + ringbuffer

This demonstates serving both normal content and
content over Server Side Events, where all clients
see the same data via a ringbuffer.

Two separate threads generate content into the
ringbuffer at random intervals.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-sse
[2018/04/20 06:09:56:9974] USER: LWS minimal http Server-Side Events + ring | visit http://localhost:7681
[2018/04/20 06:09:57:0148] NOTICE: Creating Vhost 'default' port 7681, 2 protocols, IPv6 off
```

Visit http://localhost:7681, which connects back to the server using SSE
and displays the incoming data.  Connecting from multiple browsers shows
the same content from the server ringbuffer.


## Threads

The ringbuffer and the list of connected SSE clients are shared between the
lws service thread and the two content threads, so:

 - only the lws service thread touches connections with lws apis; the only
   lws api the content threads call is `lws_cancel_service()`, to wake it.

 - `lock_ring` covers the ringbuffer, each client's tail in it, and the
   membership of the client list, on both sides: the content threads insert
   under it, and the service thread adds and removes clients, takes its copy
   of a message, consumes it and frees what everybody has been sent under it.

 - nothing calls into lws while holding `lock_ring`, so it can't get mixed
   up with lws' own locks: the copy of the message is written after
   unlocking.
