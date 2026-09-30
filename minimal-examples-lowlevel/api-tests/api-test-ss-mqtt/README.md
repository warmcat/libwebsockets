# lws-api-test-ss-mqtt

Secure Streams over mqtt, against a small mqtt 3.1.1 broker running in the same
process on a raw vhost.  It checks what an application may do from its stream
callbacks when streams share one mqtt connection: each stream must hear its
states once and in order, be destroyed once, and nothing may use a stream after
it was destroyed (run it in an ASan build to see that).

The broker answers CONNECT, SUBSCRIBE, UNSUBSCRIBE and PINGREQ, and sends a
PUBLISH back at QoS0 to the connection it came from if that connection
subscribed to its topic.  It counts the SUBSCRIBEs it sees, so a leg can tell
whether a subscribe really went to the broker.

|leg|what the streams do|what must happen|
|---|---|---|
|qos0 ack destroy|a QoS0 stream sends one message and returns `LWSSSSRET_DESTROY_ME` from `LWSSSCS_QOS_ACK_REMOTE`|the ack lws makes up for QoS0 (there is no PUBACK) comes once, after the send, no `LWSSSCS_QOS_NACK_REMOTE`, destroyed once|
|local subscribed destroy|a second stream subscribes to the topic the first already holds on the shared connection, and returns `LWSSSSRET_DESTROY_ME` from `LWSSSCS_CONNECTED`|no SUBSCRIBE goes to the broker for it, it is told it is subscribed (and so connected) once, destroyed once|

## Switches

|Option|Meaning|
|---|---|
|-p <port>|Port for the in-process test broker (default 1883)|
|--server <address>|Address the streams connect to (default localhost)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-ss-mqtt
```

```
[2026/09/30 17:53:03:3809] U: --- leg qos0 ack destroy ---
...
[2026/09/30 17:53:03:3823] U: leg qos0 ack destroy: OK
[2026/09/30 17:53:03:3823] U: --- leg local subscribed destroy ---
...
[2026/09/30 17:53:03:3824] U: leg local subscribed destroy: OK
[2026/09/30 17:53:03:3858] U: Completed: PASS
```

## Exit

0 if every leg passed, otherwise nonzero.
