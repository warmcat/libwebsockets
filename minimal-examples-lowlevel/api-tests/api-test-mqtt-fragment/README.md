# lws-api-test-mqtt-fragment

Fence for the mqtt client's rx parser being restartable at any byte.  What one
read hands the parser is whatever the network delivered, so any field of any
packet may be split across reads, and a field longer than one read (a
`PUBLISH` topic may be up to 64KB) can only ever arrive split.  The parser used
to need each `PUBLISH` topic, and every 2-byte packet id, whole in one read,
and closed the connection, with all its streams, when one straddled a read.

The test runs a fake in-process MQTT broker on an `LWS_SERVER_OPTION_ONLY_RAW`
vhost and connects the real lws mqtt client to it over loopback.  The broker
sends everything except the long topic one byte per write, a millisecond
apart, so every field of every packet it sends straddles a read.  Each step
waits for the client's exact reply, byte for byte, before the next.

|broker sends|client must|
|---|---|
|`CONNACK`, then `SUBACK` for the client's `SUBSCRIBE` to `lws/frag/#`|become established and subscribed|
|QoS1 `PUBLISH` 0x0101 on `lws/frag/a`|deliver it, `PUBACK` 0x0101|
|QoS2 `PUBLISH` 0x0102 on `lws/frag/b`, then its `PUBREL`|deliver it, `PUBREC` 0x0102, then `PUBCOMP` 0x0102|
|QoS1 `PUBLISH` 0x0103 whose topic is 6000 bytes, more than one read brings, in one write|deliver it with the whole topic, `PUBACK` 0x0103|
|`PUBREC`, then `PUBCOMP`, for the client's own QoS2 `PUBLISH`|send `PUBREL` with its id|
|`UNSUBACK` for the client's `UNSUBSCRIBE`|report the unsubscribe|
|`SUBACK` for the client's `SUBSCRIBE` to exactly `lws/frag/a`, then a `PUBLISH` whose topic is `lws/frag/a`, a NUL and `x`|close the connection without delivering it: the topic would otherwise be cut at the NUL and match the exact subscription [MQTT-1.5.4-2]|

Apart from the last step, a failure to parse closes the connection, which
fails the test; so does a step that doesn't complete within 20s.

ctest passes `-p <port>` with a free port.

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1
-DLWS_ROLE_MQTT=1`.
