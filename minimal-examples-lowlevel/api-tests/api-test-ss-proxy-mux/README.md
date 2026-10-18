# lws-api-test-ss-proxy-mux

Exercises an SS proxy whose clients reach it over the transport mux, the way
the serial-link proxy in `minimal-examples/ssproxy/ssproxy-custom-transport-uart`
does, in one process.

The proxy is created with `info.txp_ops_ssproxy = &lws_transport_mux_proxy_ops`,
and under the mux, where that example has its serial port, there is a "link"
transport implemented in the test.  What the proxy writes on the link is
parsed by the test as the mux client would, and what the test sends is given
to the mux's `proxy_read()` as if it had come in on the link.  The test speaks
the mux protocol (answering PING, asking for a channel) and, inside the
channel, the serialized SS protocol, the way an sspc client at the other end
of the link would.

The client's stream is fulfilled by a local sink registered in the process.
Once the proxy has created it, the client sends, all in one read of the link:

|payload|why|
|---|---|
|1400 bytes|more than the proxy's 1380-byte chunk, so it is queued as a 1380-byte and a 20-byte chunk, the first bigger than the mux's 1300-byte dsh split size|
|10 bytes, then 20 bytes|queued back to back behind it, before the sink can take anything|

The sink must receive exactly the 1430 bytes that were sent, in order.  The
proxy queues each chunk of client tx as one dsh object with its own header,
so the queue must not coalesce or split them as the mux's flags would.

Every write the proxy makes on the link has its headroom checked too: a
transport's `proxy_write()` may use `LWS_PRE` bytes behind the buffer it is
given, and a transport under the mux, which takes 4 of them for its header,
may use `LWS_PRE - 4`.  The link transport fills all of that with a pattern,
as a transport framing writes for its link might, so a write made from a
buffer that does not really have it (eg, straight out of a dsh object, whose
header is right behind the payload) corrupts that header or trips ASan.

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT` and a JSON policy
build (not `LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY`).  It is registered
with ctest as `api-test-ss-proxy-mux`.

## Run

```
$ ctest -R api-test-ss-proxy-mux
```

or run `lws-api-test-ss-proxy-mux` directly; it takes the usual builtin
switches, eg `-d1151` for more logging.
