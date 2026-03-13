# lws-minimal-raw-dht-zone-client

This example demonstrates how to utilize the `protocol_lws_dht_dnssec.c` libwebsockets plugin to participate in the Libwebsockets Distributed Hash Table (DHT) as a zone client.

Specifically, it illustrates uploading and downloading verified domain zonefiles (JWS `.payload`s).

## Validating Online Distributions Offline

When a valid DNSSEC `.zone` payload buffer is distributed across the raw UDP connection pool via the JSON Web Signature wrapping, a local offline node fetches it and cryptographically unwraps it against the upstream Registrar's live DNSKEY queries. The signature, signed directly by the downstream server's internal domain `.key` structure, establishes a root of trust entirely bypassing the CA model!

When `lws-minimal-raw-dht-zone-client` attempts to `--put` or download implicitly via `--domain`, the DHT plugin validates the JSON Web Signature internally. Upon success, this client exposes the storage directory outputs showing exactly where the unwrapped `.zone` buffer extracts to securely.

## Command Line Options

| Parameter | Purpose | Notes |
|---|---|---|
| `-s <path>` | Sets the path to the internal storage directory for caches and unwrapped keys. | Defaults to `./dht-store` |
| `-p <port>` | The UDP socket port to bind the DHT protocol engine to on the local machine. | Defaults to `5000` |
| `--domain <hostname>` | Triggers a download sequence of that specific registered Domain. | Acts as an alias for `--get` if `--put` is absent. |
| `--put <file_path>` | Points the engine to actively chunk, sign, wrap, and distribute a payload object to the network. | |
| `--target-ip <ip>` | Explicitly sets the bootstrapping UDP network node target. | If omitted, defaults to pulling a random node from `libwebsockets-dht-nodes.txt` installed at `${LWS_INSTALL_DATADIR}/libwebsockets` (or overridden by the `dht-fallback-nodes` PVO). |
| `--target-port <port>`| Selects the target node port. | Usually dynamically read from the nodes list if the IP is omitted. |

## Examples

### Downloading a verified Domain Payload

To bootstrap against the random list and resolve the zone for a specific domain:
```bash
$ ./lws-minimal-raw-dht-zone-client --domain dnssec.to -p 5005
```

### Uploading a Locally Signed JWS

Assuming a successfully authorized `.jws` buffer path:
```bash
$ ./lws-minimal-raw-dht-zone-client --put /etc/dht/my-domain.jws -p 5005
```
