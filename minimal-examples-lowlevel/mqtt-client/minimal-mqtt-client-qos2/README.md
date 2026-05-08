# lws-minimal-mqtt-client-qos2

This is a minimal example demonstrating MQTT QoS 2 functionality with deduplication and session restoration capabilities.

The client connects to a local Mosquitto broker, subscribes to a topic (`test/topic0`), and publishes a QoS 2 message to that same topic. It tracks the `packet_id` of unacknowledged QoS 2 receives using the operations API.

## Build

```bash
$ cmake . && make
```

## Usage

This example requires a local `mosquitto` broker to run against.

### 1. Standard Testing
Run the client normally to see the full QoS 2 handshake without any interruptions:

```bash
$ ./lws-minimal-mqtt-client-qos2
```

The client will successfully connect, subscribe, publish a message, receive it, and log the payload, followed by the normal completion.

### 2. Fault Injection Mode (Session Resumption)
Run the client with the `-f` flag to simulate a dropped connection during the QoS 2 handshake:

```bash
$ ./lws-minimal-mqtt-client-qos2 -f
```

**Sequence of Events:**
1. The client receives the QoS 2 `PUBLISH` from the broker.
2. The custom `my_rx_add` callback fires, saving the unacknowledged `packet_id` to the simulated state store.
3. The client immediately drops its connection (forceful simulation).
4. The built-in retry policy triggers a reconnection.
5. On connection establishment, the client injects the stashed `packet_id` back into the library using `lws_mqtt_client_qos2_rx_add`.
6. Mosquitto resends the `PUBLISH` with `DUP=1`.
7. `libwebsockets` recognizes the duplicate, drops the payload to maintain the *Exactly-Once* guarantee, and seamlessly resumes the handshake (`PUBREC` -> `PUBREL` -> `PUBCOMP`).

## Commandline Options

- `-d <log level>`: Set the logging level (e.g., `-d 1039`)
- `-s`: Use TLS / HTTPS
- `-f`: Simulate connection drop for testing QoS 2 restoration
