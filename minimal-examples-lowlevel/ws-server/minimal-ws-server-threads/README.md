# lws minimal ws server (threads)

## build

```
 $ cmake . && make
```

Pthreads is required on your system.

## usage

```
 $ ./lws-minimal-ws-server-threads
[2018/03/13 13:09:52:2208] USER: LWS minimal ws server + threads | visit http://localhost:7681
[2018/03/13 13:09:52:2365] NOTICE: Creating Vhost 'default' port 7681, 2 protocols, IPv6 off
```

Visit http://localhost:7681 on multiple browser windows

Two asynchronous threads generate strings and add them to a ringbuffer,
signalling lws to send new entries to all the browser windows.

This demonstrates how to safely manage asynchronously generated content
and hook it up to the lws service thread.

The ringbuffer only frees a message once every connection has been sent it,
and the spam threads skip a message while it is full.  So that one client
that stops reading can't get every new message skipped for everybody else, a
client is closed when the oldest message it hasn't been sent yet has been
waiting for it for 5s.  A client that keeps up is never closed: each time
it can be written to, it is sent everything waiting for it that the
connection will take.

While nobody is connected the spam threads add nothing, and whatever was
still in the ringbuffer when the last client went is dropped, so a client
that connects later isn't sent stale messages from before it connected.
