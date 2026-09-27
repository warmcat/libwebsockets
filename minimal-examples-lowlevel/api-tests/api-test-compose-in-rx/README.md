# lws-api-test-compose-in-rx

The composers, eg `lws_return_http_status()` and
`lws_mqtt_client_send_publish()`, can be called from a callback that a
parser delivers partway through a read, while the rest of that read is
still waiting to be parsed.  What they compose must not land on it.  They
build in the per-thread `pt->compose_buf`, and the rx pump reads into
`pt->serv_buf` below it (see "The scratch buffer" in
READMEs/README.sans-io-split.md).

In each leg, one read carries the bytes that trigger the callback and more
protocol behind them.  The callback composes, and the leg checks that the
bytes behind still arrive intact:

 - **h1**: a raw client sends a POST head, pauses, then sends its 8-byte
   body with a pipelined `GET /ok` right behind it in one write.  The server
   answers the POST from `LWS_CALLBACK_HTTP_BODY_COMPLETION` with
   `lws_return_http_status()`.  Both requests must get their own 200.

 - **h2** (cleartext, prior knowledge, when built with h2): a raw client
   opens stream 1 with a POST head, pauses, then sends stream 1's DATA with
   END_STREAM and stream 3's `GET /ok` HEADERS in one write.  Stream 1 is
   answered from `HTTP_BODY_COMPLETION` the same way.  Both streams must
   get a 200 and END_STREAM, with no GOAWAY or RST_STREAM.  The leg also
   covers a stream answered by a status page from `HTTP_BODY_COMPLETION`:
   its page body must still be sent when the stream closes.

 - **mqtt** (when built with mqtt): a fake broker on a raw vhost answers the
   SUBSCRIBE with the SUBACK and two PUBLISHes in one write.  The client
   echoes the first PUBLISH from `LWS_CALLBACK_MQTT_CLIENT_RX`, publishing
   straight from the payload pointer it was handed.  The broker must get the
   echo intact, and the client must still get the second PUBLISH intact.

The raw clients control what shares a write: the request head goes first,
and the rest follows in one write 200ms later, after the server has read
the head on its own.

## Usage

```
 $ lws-api-test-compose-in-rx -p 7681 --h2-port 7682 --mqtt-port 7683
[2026/09/27 08:12:23:3244] U: LWS API selftest: composing from inside rx
[2026/09/27 08:12:23:3298] U: mqtt: OK
[2026/09/27 08:12:23:5294] U: h1: OK
[2026/09/27 08:12:23:5315] U: h2: OK
[2026/09/27 08:12:23:5441] U: Completed: OK
```

|Option|Meaning|
|---|---|
|-p <port>|h1 server port (default 7681)|
|--h2-port <port>|h2 server port (default 7682)|
|--mqtt-port <port>|fake mqtt broker port (default 7683)|

## Exit

0 if every leg passes.  Nonzero if any leg fails, or if the legs have not
all finished within 10s.
