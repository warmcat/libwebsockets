# lws-dht-store Plugin

This plugin implements a lightweight, basic libwebsockets DHT (Distributed Hash Table) integration protocol node. It serves as an introductory or baseline example of binding the `lws_dht` API into a plugin structure to handle elementary network hashing queries and responses.

## Building

This plugin requires `LWS_WITH_DHT=1`, `LWS_WITH_DHT_BACKEND=1`, and `LWS_WITH_PLUGINS=1`.

## Using with lwsws

You can deploy the plugin using the `lwsws` JSON configuration format within a vhost by attaching the `lws_dht_store` protocol.

```json
{
  "vhosts": [{
      "name": "dht-store-backend",
      "port": "-1",
      "ws-protocols": [{
          "lws_dht_store": {
              "status": "ok",
              "dht-storage-path": "/var/lib/lwsws/dht-store",
              "dht-port": "49100"
          }
      }]
  }]
}
```

### Protocol Vhost Options (PVOs)

| Option | Optional | Description |
|-----------|-----------|-------------|
| `dht-storage-path` | **Required** | The filesystem directory path where the node should operate its logical data store |
| `dht-port` | Yes | The UDP port the underlying DHT node will establish on (default: `5000`) |
| `dht-iface` | Yes | The specific network interface to bind the DHT socket (default: binds to all available if undefined) |
| `dht-fallback-nodes` | Yes | The filesystem path to the fallback nodes list text file (default: `${LWS_INSTALL_DATADIR}/libwebsockets/libwebsockets-dht-nodes.txt`) |
| `dht-echo` | Yes | Set to `"1"` to enable the `ECHO ` loopback diagnostic (default: disabled) |

### `dht-echo`

The node can reply to an unmatched DHT data payload beginning `ECHO ` by
sending the remainder back to the source address.  That is a debugging aid
only: DHT data is accepted from any source with no return-routability check, so
with it enabled a peer that spoofs a victim's source address can have the node
emit arbitrary bytes at the victim, attributable to the node's operator.  It is
therefore disabled unless `dht-echo` is explicitly set to `"1"`, and it should
not be enabled on a node reachable from an untrusted network.
