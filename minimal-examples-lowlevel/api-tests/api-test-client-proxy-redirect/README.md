# lws api test client proxy redirect

An lws http client going through an http CONNECT proxy, or a SOCKS5 proxy
(when lws is built with `-DLWS_WITH_SOCKS5=1`), follows its origin's
redirects to the origin, never to the proxy:

 - a relative `Location: /echo` is on the origin the client asked for, by
   the name it asked for it by, on the origin's port
 - an absolute `Location` naming the origin on another port goes to that
   port, through the proxy

The origin is two lws server vhosts in the same process, on two ports.  Each
answers `/echo` with the port it listens on and the `Host:` it was asked for,
and the client checks both.  The client names the origin `localhost` while the
proxy is `127.0.0.1`, so a request retargeted at the proxy's address arrives
with the wrong `Host:`, and one retargeted at the proxy's port never reaches
the origin.

ctest runs it against `../api-test-ws-close/proxy-fixture.py`, which is an
http CONNECT and a SOCKS5 proxy on one port.

```
$ python3 ../api-test-ws-close/proxy-fixture.py --port 7692 &
$ ./lws-api-test-client-proxy-redirect -p 7690 --port2 7691 --proxy 127.0.0.1:7692
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|The origin's first port (default 7690)
--port2 <port>|The origin's second port, the redirect target (default 7691)
--proxy <host:port>|The http CONNECT / SOCKS5 proxy (required)
