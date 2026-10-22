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

Each message is passed on whole, as the type (TEXT or BINARY) it was sent as,
however it was fragmented on the way.  Messages up to 4096 bytes are passed
on: a client sending a bigger one is closed with 1009 (Message Too Big), and
a client sending a TEXT message that isn't valid UTF-8 is closed with 1007,
and nothing of either is passed on.

The ringbuffer only frees a message once every subscriber has been sent it,
and drops new messages while it is full.  So that one subscriber that stops
reading can't get every new message dropped for everybody else, a subscriber
that has had messages waiting for it for 5s without catching up is closed.
