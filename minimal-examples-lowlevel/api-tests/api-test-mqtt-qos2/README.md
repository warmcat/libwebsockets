# lws-api-test-mqtt-qos2

Fence for the mqtt client's side of inbound QoS2 (issue #3672).

The test runs a fake in-process MQTT broker on an `LWS_SERVER_OPTION_ONLY_RAW`
vhost and connects the real lws mqtt client to it over loopback.  On
`LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED` the client restores one QoS2 packet id
with `lws_mqtt_client_qos2_rx_add()`, as an application persisting QoS2 state
across connections would, then subscribes to one topic at QoS2.

The broker then walks the client through a lock-stepped script, moving on
only when the client's reply to the last step is exactly right:

|step|broker sends|client must reply|deliveries|QOS2_RX_COMPLETE|
|---|---|---|---|---|
|publish|`PUBLISH` QoS2 id 0x1234|`PUBREC` `50 02 12 34`|1|0|
|publish dup|same, DUP=1|`PUBREC` `50 02 12 34`|1|0|
|pubrel|`PUBREL` id 0x1234|`PUBCOMP` `70 02 12 34`|1|1|
|publish again|`PUBLISH` QoS2 id 0x1234, a new message|`PUBREC`|2|1|
|pubrel again|`PUBREL` id 0x1234|`PUBCOMP`|2|2|
|publish restored|`PUBLISH` DUP=1 id 0x0777|`PUBREC` `50 02 07 77`|2|2|
|pubrel restored|`PUBREL` id 0x0777|`PUBCOMP` `70 02 07 77`|2|3|

 - `PUBREC` and `PUBCOMP` must have fixed header flags 0 [MQTT-3.5.1, 3.7.1];
   only `PUBREL` carries 0x2.  A compliant broker closes a client that gets
   this wrong, so inbound QoS2 never completed against one.

 - The DUP resend and the restored id must not be delivered a second time,
   and each `PUBREL` must find its id and release it.  The rx id list entries
   were once allocated without being zeroed, so their list linkage started as
   heap junk and they could fail to join the list: duplicates were delivered
   again, the `PUBREL` found nothing and the entry leaked.  ctest runs the
   test with glibc's `MALLOC_PERTURB_` so the junk is there without ASan too.

## Usage

```
 $ lws-api-test-mqtt-qos2 -p 17682
[2026/10/03 12:00:00:0000] U: LWS API selftest: MQTT client QoS2 rx
...
[2026/10/03 12:00:00:0000] U: Completed: OK
```

## Exit

0 on success, nonzero if any step fails or the exchange times out.
