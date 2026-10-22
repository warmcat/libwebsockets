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
and drops new messages while it is full.  So that one client that stops
reading can't get every new message dropped for everybody else, a client
that has had messages waiting for it for 5s without catching up is closed.
