# lws-api-test-udp-unreachable

A connected UDP socket whose datagram draws an ICMP port unreachable is told of
it by the kernel as a bare `POLLERR`, level-triggered until something takes the
error from the socket.  The service loop must take it and fail the wsi's next
read with it, so the wsi hears `LWS_CALLBACK_RAW_CLOSE` promptly.  Before that
the error was never consumed: the service thread spun on `poll()` until the
next send, and the wsi heard nothing.

The test makes two UDP wsi to a loopback port nothing listens on (an ephemeral
port the kernel just handed out and took back), each sends one datagram, and
both must close within 3 seconds:

|wsi|made by|covers|
|---|---|---|
|client|`lws_create_adopt_udp()`|the connect-wait phase, where the client transport reads the socket error as a failed connect|
|adopted|a socket the test created and connected itself, given to `lws_adopt_descriptor_vhost()`|a wsi past any connect phase, where the error was never taken before and the loop spun|

Linux only: it is the only platform whose `poll()` reports the datagram error
this way, and where lws `connect()`s the socket (Apple does not), which the
error delivery needs.

## Run

```
$ ctest -R api-test-udp-unreachable
```
