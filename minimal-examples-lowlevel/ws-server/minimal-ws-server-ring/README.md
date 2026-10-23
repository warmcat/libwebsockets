# lws minimal ws server (lws_ring)

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-ws-server
[2018/03/04 09:30:02:7986] USER: LWS minimal ws server (lws_ring) | visit http://localhost:7681
[2018/03/04 09:30:02:7986] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 on
```

Visit http://localhost:7681 on multiple browser windows

Text you type in any browser window is sent to all of them.

Each message is passed on whole, as the type (TEXT or BINARY) it was sent as,
however it was fragmented on the way.  Messages up to 4096 bytes are passed
on: a client sending a bigger one is closed with 1009 (Message Too Big), and
a client sending a TEXT message that isn't valid UTF-8 is closed with 1007,
and nothing of either is passed on.

A ringbuffer holds up to 8 lines of text.

A message is freed from the ringbuffer once it has been sent to everybody.
This also demonstrates what to do about clients that send faster than the
others can be sent to, and clients that stop reading:

 - when the ringbuffer is full, the server stops reading from every client
   (`lws_rx_flow_control()`) until it is half empty again, so senders are
   slowed to the pace of the slowest receiver and no message is lost.  (A ws
   connection carried on an h2 stream can't be paused like that, since h2
   flow controls it instead: a message from it that finds the ringbuffer full
   is dropped.)

 - a client is closed when the oldest message it hasn't been sent yet has
   been waiting for it for 5s, so one that stops reading can't hold everybody
   else up for longer than that.  A client that keeps up is always being sent
   fresh messages and is never closed, however much anybody sends, and a
   slower one that reads steadily just slows the senders down.  Only a client
   too slow to take the ringbuffer's 8 messages in 5s while somebody is
   sending is closed.
