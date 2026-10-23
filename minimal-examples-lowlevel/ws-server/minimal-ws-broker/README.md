# lws minimal ws broker

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-ws-broker
[2018/03/15 12:23:12:1559] USER: LWS minimal ws broker | visit http://localhost:7681
[2018/03/15 12:23:12:1560] NOTICE: Creating Vhost 'default' port 7681, 2 protocols, IPv6 off
```

Visit http://localhost:7681 on multiple browser windows

The page opens a subscribe mode ws connection back to the broker,
and a publisher mode ws connection back to the broker.

The textarea shows the data from the subscription connection.

If you type text is in the text box and press send, the text
is passed to the broker on the publisher ws connection and
sent to all subscribers.

A ws connection made to the URL `/publisher` is a publisher, and one made to
any other URL a subscriber.  That works for ws connections carried on an h2
stream too, if you serve the broker over h2: their URL comes in an extended
CONNECT, not a GET, which `lws_http_get_uri_and_method()` takes care of.

Each message is passed on whole, as the type (TEXT or BINARY) it was sent as,
however it was fragmented on the way.  Messages up to 4096 bytes are passed
on: a client sending a bigger one is closed with 1009 (Message Too Big), and
a client sending a TEXT message that isn't valid UTF-8 is closed with 1007,
and nothing of either is passed on.

A ringbuffer holds up to 8 messages, and only frees a message once every
subscriber has been sent it.  This also demonstrates what to do about
publishers that send faster than the subscribers can be sent to, and
subscribers that can't keep up:

 - when the ringbuffer is full, the broker stops reading from every publisher
   (`lws_rx_flow_control()`) until it is half empty again, so publishers are
   slowed to the pace of the slowest subscriber and no message is lost.  (A
   ws connection carried on an h2 stream can't be paused like that, since h2
   flow controls it instead: a message from it that finds the ringbuffer full
   is dropped.)

 - a subscriber is closed when the oldest message it hasn't been sent yet has
   been waiting for it for 5s, so one that stops reading can't hold everybody
   up for longer than that.  A subscriber that keeps up is always being sent
   fresh messages and is never closed, however much the publishers send, and
   a slower one that reads steadily just slows the publishers down.  Only a
   subscriber too slow to take the ringbuffer's 8 messages in 5s while the
   publishers are busy is closed.

 - what is published while there are no subscribers is ignored, and when the
   last subscriber goes (eg, closed for not reading), whatever was still
   waiting for it is dropped.  So publishers the broker stopped reading from
   because the ringbuffer was full are read from again, rather than waiting
   for somebody to subscribe, and the next subscriber is only sent what is
   published after it joined.
