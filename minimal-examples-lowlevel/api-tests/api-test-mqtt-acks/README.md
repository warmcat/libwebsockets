# lws-api-test-mqtt-acks

Fence for the acks the mqtt client owes the broker (issue #3680): every
`PUBACK`, `PUBREC`, `PUBREL` and `PUBCOMP` must go out, promptly, quoting the
packet id of what it answers, in the order those packets arrived
[MQTT-4.6.0-2, -3, -4].

The test runs a fake in-process MQTT broker on an `LWS_SERVER_OPTION_ONLY_RAW`
vhost and connects the real lws mqtt client to it over loopback.  Once the
client has subscribed, the broker plays a series of rounds at it.  Most send
several packets in one write, so they arrive in one read.  Each round waits for
exactly the right acks, byte for byte and in order, before the next starts, and
has 3s to get them: the client's keepalive is 60s, so an ack that only leaves
with the next `PINGREQ` fails the round.

|round|broker sends|client must reply|
|---|---|---|
|qos1 burst|two QoS1 `PUBLISH`, ids 0x0101, 0x0102, while the client has nothing to write|`PUBACK` 0x0101, `PUBACK` 0x0102|
|qos2 burst|two QoS2 `PUBLISH`, ids 0x0201, 0x0202|`PUBREC` 0x0201, `PUBREC` 0x0202|
|pubrel burst|their two `PUBREL`|`PUBCOMP` 0x0201, `PUBCOMP` 0x0202|
|our qos2|the client publishes at QoS2; the broker answers with its `PUBREC` and, in the same write, a `PUBREL` 0x0303 of its own|`PUBREL` with the client's own id, then `PUBCOMP` 0x0303|
|late ack|the client sends the first half of a chunked QoS0 `PUBLISH`, the broker sends a QoS1 `PUBLISH` 0x0501, then the client finishes its `PUBLISH`|`PUBACK` 0x0501, after the whole `PUBLISH` and not inside it|
|held|the client sends the first half of a chunked QoS0 `PUBLISH`, the broker sends 100 QoS1 `PUBLISH` from 0x3000, and the client finishes its `PUBLISH` 500ms later, from a timer|all 100 `PUBACK`, in order, after the whole `PUBLISH`; fewer than 100 deliveries before it was finished|
|flood|100 QoS1 `PUBLISH` in one write, several times more than lws holds acks for at once|all 100 `PUBACK`, in order|

 - Each ack used to be one flag per type plus one packet id shared by all of
   them.  A `PUBACK` was only written when some stream on the connection also
   wanted to write, back-to-back packets overwrote each other's id so only the
   last was acked, and our `PUBREL` quoted whatever id the last packet that
   carried one had, eg, the broker's own `PUBREL`.

 - An ack that came due while one of our `PUBLISH` was going out in chunks
   could not be written until it finished, and then waited for something else
   to write.

 - The flood checks the queue's limit: when it is full the client must stop
   parsing at a packet boundary, hold its rx and carry on once its acks have
   been written, without losing or reordering any of them.

 - The held round fills the queue while the acks can't be written at all,
   because the client is in the middle of a `PUBLISH`.  Rx stays held until
   the `PUBLISH` is finished, which is why lws_mqtt_client_send_publish()
   says finishing one sent in parts must not wait for anything received on
   the same connection: the client here finishes from a timer.  (The late ack
   round finishes on the broker's `PUBLISH`, which is safe only because a
   single ack can't fill the queue.)

## Usage

```
 $ lws-api-test-mqtt-acks -p 17683
[2026/10/17 12:00:00:0000] U: LWS API selftest: MQTT client acks
...
[2026/10/17 12:00:00:0000] U: Completed: OK
```

## Exit

0 on success, nonzero if any round fails or times out.
