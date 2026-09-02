# lws-api-test-mqtt-unsub

Fence for the mqtt subscribe / unsubscribe topic-count contract,
`LWS_MQTT_MAX_TOPICS` (F-058).

The test runs a fake in-process MQTT broker on an `LWS_SERVER_OPTION_ONLY_RAW`
vhost and connects the real lws mqtt client to it over loopback, so the
established-state tx composition paths are the ones exercised.

After a genuine one-topic subscribe / SUBACK, the fence legs are:

 - an unsubscribe with `LWS_MQTT_MAX_TOPICS + 1` topics (the first one real)
   must be refused with a nonzero return and exactly one loud `lwsl_err`,
   before any subscription refcount is touched or any packet composed;
 - an unsubscribe with zero topics must be refused the same way;
 - a subscribe with `LWS_MQTT_MAX_TOPICS + 1` topics must be refused the
   same way (the subscribe-side twin of the same guard);
 - the boundary leg: a `LWS_MQTT_MAX_TOPICS`-topic unsubscribe (first topic
   real) is the widest legal call and must still work end-to-end, producing
   a real UNSUBSCRIBE / UNSUBACK exchange and `LWS_CALLBACK_MQTT_UNSUBSCRIBED`.

## Usage

```
 $ lws-api-test-mqtt-unsub -p 17681
[2026/09/02 12:00:00:0000] U: callback_mqtt: MQTT_CLIENT_ESTABLISHED
...
Completed: OK
```

## Exit

0 on success, nonzero if any leg fails or the exchange times out.
