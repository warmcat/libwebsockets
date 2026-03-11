# lws-dht-store Plugin

This plugin implements a lightweight, basic libwebsockets DHT (Distributed Hash Table) integration protocol node. It serves as an introductory or baseline example of binding the `lws_dht` API into a plugin structure to handle elementary network hashing queries and responses.

## Building

This plugin requires `LWS_WITH_DHT=1` and `LWS_WITH_PLUGINS=1`.

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
