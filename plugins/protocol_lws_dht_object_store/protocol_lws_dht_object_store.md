# lws-dht-object-store Plugin

This plugin implements a libwebsockets DHT (Distributed Hash Table) object storage node. It allows chunked transfer of content-addressed objects across the decentralized network: an object's key is the SHA-256 hex of its content, and the node verifies that before it will store or serve it.

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
| `dht-allow-private` | No | `"1"` admits peers on private, loopback or link-local addresses (a LAN deployment, or local testing); by default only public addresses are kept |
| `dht-iface` | Yes | The specific network interface to bind the DHT socket (default: binds to all available) |
| `dht-fallback-nodes` | Yes | The filesystem path to the fallback nodes list text file (default: `${LWS_INSTALL_DATADIR}/libwebsockets/libwebsockets-dht-nodes.txt`) |
| `target-ip` | Yes | Defines an initial anchor/bootstrap peer IP address |
| `target-port` | Yes | Defines an initial anchor/bootstrap peer UDP port |
| `dht-jwk` | Yes | Path to a `.jwk` file containing the node's cryptographic identity |
| `put-file` | Yes | Automatically inject a local file into the DHT during startup (used via CLI) |
| `get-hash` | Yes | Automatically query a hash and download it from the network during startup |
| `bulk` | Yes | Enables bulk testing mode for throughput checks |
| `gen-manifest` | Yes | Automatically generate and print an initial manifest object layout |
| `dht-policy-allow` | Yes | Comma-separated list of lowercase-hex object key prefixes that may be stored or served (default: all) |
| `dht-policy-deny` | Yes | Comma-separated list of lowercase-hex object key prefixes that may never be stored or served (checked first, wins) |
| `dht-max-object-size` | Yes | Largest object, in bytes, that will be accepted (default and hard ceiling: 16MiB) |
| `dht-store-quota` | Yes | Total bytes that may be committed to the store while the node is up (default: 256MiB) |
| `receiver` | Yes | Flags the node specifically as an active sink capable of receiving chunks |
| `dht-test-handshake` | Yes | Places the node in testing mode for synthetic handshake validation |

`completion-cb` / `completion-cb-arg` are **not** configuration options: they
carry a C function pointer and its closure from an application that builds the
pvo list programmatically, and are only consulted when one of the client / test
modes above (`put-file`, `get-hash`, `bulk`, `gen-manifest`, `receiver`,
`dht-test-handshake`) was also asked for.  From an lwsws JSON config a pvo
value is a pointer into the parsed config text, so setting them there would
mean calling into a data buffer... do not put them in a config file.

## What the node does and does not trust

DHT datagrams are accepted from any source address with no return-routability
check, so everything below is applied to unauthenticated, attacker-chosen
input:

 - **PUT / RSP.**  The declared object length must be at most
   `dht-max-object-size`, and the store will not commit more than
   `dht-store-quota` bytes in total, counting what the transfers in flight
   declared.  At most 16 transfers may be in flight at once, and at most 4 of
   them from one source host (an IPv4 address or an IPv6 /64, as the DHT
   counts hosts).  A transfer is discarded after 30s without progress, or
   once it falls more than 30s behind an average of 1KiB/s, however it keeps
   sending, releasing its fd, digest context and partial file: so a peer
   trickling a few bytes at a time cannot hold a slot for long.  Chunks must
   arrive strictly in order, so a
   peer cannot seek to an arbitrary 64-bit offset.  Content is written to a
   `.<key>.part` file created with `O_EXCL | O_NOFOLLOW` in a `0700` store
   directory, and is `rename()`d onto `<key>` only once its SHA-256 equals the
   key it was offered under.  Content that does not hash to its own
   content-address is therefore never stored and never served.  A transfer
   also belongs to the address that opened it, since object keys are public
   and in-flight transfers are otherwise found by key alone.
 - **RSP** is additionally only accepted against a GET this node actually sent
   and has not yet timed out.  An unsolicited RSP is dropped.
 - **GET** honours `dht-policy-allow` / `dht-policy-deny`, opens with
   `O_NOFOLLOW`, and is rate-capped (32 responses per second per node) because
   the reply is much larger than the request and the source address may be
   spoofed.

There is still no peer authentication: `dht-jwk` currently only establishes the
node's own identity, and PUT is not signature-checked.  The DHT transport only
delivers a PUT or RSP from a source address that answered its challenge, so the
in-flight slots are accounted per source host; but the GET response budget is
per-node, since a GET needs no reply from its claimed source, and one peer can
consume what another wanted.  A peer with many hosts (eg, many IPv6 /64s) can
still occupy the in-flight slots, if it keeps each of them moving at the
minimum rate.
Do not expose a node storing anything sensitive to an untrusted network.
