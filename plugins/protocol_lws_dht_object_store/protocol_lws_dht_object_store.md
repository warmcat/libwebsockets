# lws-dht-object-store Plugin

This plugin implements an advanced libwebsockets DHT (Distributed Hash Table) object storage node. It allows chunked transfer of mutable and immutable objects across the decentralized network, enabling full payload synchronization using cryptographic hashing and optional JWK signatures for authentication.

## Building

This plugin requires `LWS_WITH_DHT=1`, `LWS_WITH_DHT_BACKEND=1`, `LWS_WITH_JOSE=1` (for JWK and JSON processing) and `LWS_WITH_PLUGINS=1`.

## Using with lwsws

You can deploy the plugin using the `lwsws` JSON configuration format within a vhost.

```json
{
  "vhosts": [{
      "name": "dht-backend",
      "port": "-1",
      "ws-protocols": [{
          "lws-dht-object-store": {
              "status": "ok",
              "dht-port": "49100",
              "dht-storage-path": "/var/lib/lwsws/dht-store",
              "dht-jwk": "/var/lib/lwsws/dht.jwk"
          }
      }]
  }]
}
```

### Protocol Vhost Options (PVOs)

| Option | Optional | Description |
|-----------|-----------|-------------|
| `dht-storage-path` | **Required** | The filesystem directory path where the DHT node will persist received objects and state |
| `dht-port` | Yes | The UDP port the DHT node will listen on (default: `49100`) |
| `dht-iface` | Yes | The specific network interface to bind the DHT socket (default: binds to all available) |
| `dht-fallback-nodes` | Yes | The filesystem path to the fallback nodes list text file (default: `${LWS_INSTALL_DATADIR}/libwebsockets/libwebsockets-dht-nodes.txt`) |
| `target-ip` | Yes | Defines an initial anchor/bootstrap peer IP address |
| `target-port` | Yes | Defines an initial anchor/bootstrap peer UDP port |
| `dht-jwk` | Yes | Path to a `.jwk` file containing the node's cryptographic identity |
| `put-file` | Yes | Automatically inject a local file into the DHT during startup (used via CLI) |
| `get-hash` | Yes | Automatically query a hash and download it from the network during startup |
| `bulk` | Yes | Enables bulk testing mode for throughput checks |
| `gen-manifest` | Yes | Automatically generate and print an initial manifest object layout |
| `dht-policy-allow` | Yes | Provide a hash or rule string representing peers/objects to allow |
| `dht-policy-deny` | Yes | Provide a hash or rule string representing peers/objects to deny |
| `receiver` | Yes | Flags the node specifically as an active sink capable of receiving chunks |
