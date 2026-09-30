# lws-api-test-transport-mux

Exercises the SS transport mux framing layer on its own: the test feeds mux
commands into `lws_transport_mux_rx_parse()` as the peer would, checks what
`lws_transport_mux_pending()` wants to send back, and stands in for whatever
owns the channels on our side (sspc on a client, the SS proxy) with a
recording set of `lws_txp_mux_parse_cbs_t` callbacks.  No transport, sspc
or proxy is involved.

It checks that

- a channel the peer asks for, and then ACKs himself before we answer, is not
  opened by his ACK; on the client role, which has nothing to bind it to, it
  is refused with a NACK and never passed up to be written on
- a channel the peer asks for and then NACKs (a FIN) is withdrawn, nothing
  is sent for it
- on the proxy role, a channel the peer asks for is bound and ACKed, and a
  later ACK from him for it changes nothing
- our own channel is requested with CHANNEL_REQ, the peer's ACK opens it and
  DATA on it reaches the owner
- when the owner of a channel is given a write opportunity and says the
  channel must close, the mux closes that channel with a FIN and nothing is
  sent from the caller's buffer for that write opportunity
- when the owner of a channel can't go on with DATA that came on it, the mux
  closes just that channel with a FIN, and the link stays up

## Build

The mux apis are for custom transports, which link the static library, so
the test needs `LWS_WITH_SECURE_STREAMS_PROXY_API` and the static library
(`LWS_WITH_STATIC`, the default).  It is registered with ctest as
`api-test-transport-mux`.

## Run

```
$ ctest -R api-test-transport-mux
```
