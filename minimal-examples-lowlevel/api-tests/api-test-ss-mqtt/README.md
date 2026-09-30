# lws-api-test-ss-mqtt

Secure Streams over mqtt, against a small mqtt 3.1.1 broker running in the same
process on a raw vhost.  It checks what an application may do from its stream
callbacks when streams share one mqtt connection, including destroying another
stream on it while lws is walking the connection's streams to tell each of them
something: each stream must hear its states once and in order, be destroyed
once, and nothing may use a stream after it was destroyed (run it in an ASan
build to see that).

The broker answers CONNECT, SUBSCRIBE, UNSUBSCRIBE and PINGREQ, and sends a
PUBLISH back at QoS0 to the connection it came from if that connection
subscribed to its topic.  It counts the SUBSCRIBEs it sees, so a leg can tell
whether a subscribe really went to the broker.

|leg|what the streams do|what must happen|
|---|---|---|
|queue destroy|three streams start together: the first makes the connection, the other two queue on it; the first queued one to be adopted destroys the other from `LWSSSCS_CONNECTED`|the destroyed one is never connected and destroyed once, adoption of the queue carries on without it|
|qos0 ack destroy|a QoS0 stream sends one message and returns `LWSSSSRET_DESTROY_ME` from `LWSSSCS_QOS_ACK_REMOTE`|the ack lws makes up for QoS0 (there is no PUBACK) comes once, after the send, no `LWSSSCS_QOS_NACK_REMOTE`, destroyed once|
|local subscribed destroy|a second stream subscribes to the topic the first already holds on the shared connection, and returns `LWSSSSRET_DESTROY_ME` from `LWSSSCS_CONNECTED`|no SUBSCRIBE goes to the broker for it, it is told it is subscribed (and so connected) once, destroyed once|
|rx destroys sibling|two streams subscribed to one topic on the shared connection; the second publishes to it and the broker sends it back; whichever hears it first destroys the other from its rx callback|the message is heard once, by the survivor, the other is destroyed once|
|tx destroys sibling|two streams on the shared connection both ask to write in the same pass; whichever is asked first destroys the other from its tx callback|the other is destroyed once and not asked to write|

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
[2026/09/30 18:06:54:4280] U: --- leg queue destroy ---
...
[2026/09/30 18:06:54:4285] U: leg queue destroy: OK
...
[2026/09/30 18:06:54:4296] U: leg rx destroys sibling: OK
[2026/09/30 18:06:54:4296] U: --- leg tx destroys sibling ---
...
[2026/09/30 18:06:54:4299] U: leg tx destroys sibling: OK
[2026/09/30 18:06:54:4370] U: Completed: PASS
```

## Exit

0 if every leg passed, otherwise nonzero.
