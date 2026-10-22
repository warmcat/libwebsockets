# lws minimal ws server

## build

```
 $ cmake . && make
```

## Commandline Options

Option|Meaning
---|---
-d|Set logging verbosity
-s|Serve using TLS selfsigned cert (ie, connect to it with https://...)
-h|Strict Host: header checking against vhost name (localhost) and port
-v|Connection validity use 3s / 10s instead of default 5m / 5m10s

## usage

```
 $ ./lws-minimal-ws-server
[2018/03/04 09:30:02:7986] USER: LWS minimal ws server | visit http://localhost:7681
[2018/03/04 09:30:02:7986] NOTICE: Creating Vhost 'default' port 7681, 1 protocols, IPv6 on
```

Visit http://localhost:7681 on multiple browser windows

Text you type in any browser window is sent to all of them.

Each message is passed on whole, as the type (TEXT or BINARY) it was sent as,
however it was fragmented on the way.  Messages up to 4096 bytes are passed
on: a client sending a bigger one is closed with 1009 (Message Too Big), and
a client sending a TEXT message that isn't valid UTF-8 is closed with 1007,
and nothing of either is passed on.

For simplicity of this example, only one line of text is cached at the server.
