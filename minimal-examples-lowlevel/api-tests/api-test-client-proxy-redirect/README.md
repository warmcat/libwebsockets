# lws api test client proxy redirect

An lws http client going through an http CONNECT proxy, or a SOCKS5 proxy
(when lws is built with `-DLWS_WITH_SOCKS5=1`), follows its origin's
redirects to the origin, never to the proxy:

 - a relative `Location: /echo` is on the origin the client asked for, by
   the name it asked for it by, on the origin's port
 - an absolute `Location` naming the origin on another port goes to that
   port, through the proxy

Raw clients go through the same proxies too: a raw-skt client, plaintext and
over tls, and (when lws is built with `-DLWS_ROLE_RAW_PROXY=1`) a client of
the raw-proxy role.  Their origin is a raw server in the same process that
speaks first, with a banner, as smtp does.  A raw-skt client must be told
`RAW_CONNECTED`, over tls when it asked for it, before it is given any rx, and
every byte a raw client is given must be the origin's, never the proxy's
reply.  The client answers the banner and must get the origin's answer back.

The origin is two lws server vhosts in the same process, on two ports.  Each
answers `/echo` with the port it listens on and the `Host:` it was asked for,
and the client checks both.  The client names the origin `localhost` while the
proxy is `127.0.0.1`, so a request retargeted at the proxy's address arrives
with the wrong `Host:`, and one retargeted at the proxy's port never reaches
the origin.

ctest runs it against `../api-test-ws-close/proxy-fixture.py`, which is an
http CONNECT and a SOCKS5 proxy on one port, with the raw origin's tls using
`../api-test-ws-close/localhost-100y.cert` and `.key`.

```
$ python3 ../api-test-ws-close/proxy-fixture.py --port 7692 &
$ ./lws-api-test-client-proxy-redirect -p 7690 --port2 7691 --proxy 127.0.0.1:7692 \
	--cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|The origin's first port (default 7690)
--port2 <port>|The origin's second port, the redirect target (default 7691)
--port-raw <port>|The raw origin's port (default 7693)
--port-raw-tls <port>|The raw origin's tls port (default 7694)
--cert <path>|The raw origin's tls certificate (default `localhost-100y.cert`)
--key <path>|The raw origin's tls key (default `localhost-100y.key`)
--proxy <host:port>|The http CONNECT / SOCKS5 proxy (required)
