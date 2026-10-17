# lws-api-test-mqtt-inflight

Fence for the operations an mqtt client stream has awaiting the broker's ack.

A stream tracks one such operation, a QoS1 or QoS2 `PUBLISH` waiting for its
`PUBACK` or `PUBREC`, or a `SUBSCRIBE` or `UNSUBSCRIBE` waiting for its `SUBACK`
or `UNSUBACK`, by a single packet id, and `LWS_CALLBACK_MQTT_ACK` doesn't say
which operation it is about.  So a stream has one at a time, and acks no stream
claims any more must be dealt with on the connection, not close it.

Two streams share one connection to an in-process fake broker on an
`LWS_SERVER_OPTION_ONLY_RAW` vhost, which answers each `PUBLISH` according to its
payload.  The steps run in order on the one connection:

|step|what happens|what must happen|
|---|---|---|
|busy|stream a publishes at QoS1, and while that awaits its `PUBACK`, tries another QoS1 `PUBLISH` and a `SUBSCRIBE`|both are refused, nothing goes out for them; after the `PUBACK`, the second `PUBLISH` goes|
|qos2 back to back|a publishes at QoS2 and, at its `MQTT_ACK` (the `PUBREC`), at QoS2 again; the broker sends the first one's `PUBCOMP` only after the second `PUBLISH`|the second `PUBLISH` goes, the late `PUBCOMP` is ignored|
|resend|the broker withholds the `PUBACK` for a's QoS1 `PUBLISH` until lws' 3s timeout gives a `MQTT_RESEND`; meanwhile stream b joins and takes the connection's next packet id; then the broker acks the resend twice|the resend has dup set and the packet id the `PUBLISH` first went with, and the second `PUBACK` is ignored|
|gone|b publishes at QoS2 and closes; then the broker sends its `PUBREC`|the connection still answers with a `PUBREL`, releasing the id, ignores the `PUBCOMP` that follows, and a goes on|

The test fails if either stream closes before the end, or the broker sees more
than one connection.

 - A second operation used to silently take over the stream's packet id, so
   when the first one's ack came, no stream claimed it.

 - Any ack no stream claimed, from that, from a QoS2 `PUBCOMP` arriving after
   the stream published again, or from a stream that had closed, was taken
   for a protocol error and closed the connection, with every stream on it.

 - A resend took the connection's latest packet id, which another stream
   could have taken meanwhile, rather than the one it first went with.

## Usage

```
 $ lws-api-test-mqtt-inflight -p 17684
[2026/10/17 12:00:00:0000] U: LWS API selftest: MQTT client operations in flight
...
[2026/10/17 12:00:00:0000] U: Completed: OK
```

## Exit

0 on success, nonzero if any step fails or the test times out.
