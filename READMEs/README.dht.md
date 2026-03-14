# Libwebsockets Distributed Hash Table (DHT)

Libwebsockets provides an implementation of a Kademlia-based Distributed Hash Table (DHT) compatible with the BitTorrent DHT network. It is useful for decentralized node discovery, configuration fetching, and peer-to-peer metadata storage without relying on centralized infrastructure.

## CMake Build Options

The DHT functionality is physically split into client and backend blocks to allow resource-constrained devices to participate as clients without maintaining full routing tables and storage on the device.

*   `LWS_WITH_DHT`: Enables the DHT frontend and client API. This provides the core functionality to manage a DHT node ID (`dht-id.c`), serialize and parse base DHT protocol messages (`dht-bencode.c`), and manage networking and queries (`dht-tx.c`, `dht.c`).
*   `LWS_WITH_DHT_BACKEND`: Enables the full DHT backend. This includes managing buckets, maintaining the complex routing table, coordinating decentralized searches, maintaining in-memory storage, and automatically responding to incoming RPCs like `ping`, `find_node`, `get_peers`, and `announce_peer`. This is automatically enabled by default when `LWS_WITH_DHT` is enabled, but can be forced off with `-DLWS_WITH_DHT_BACKEND=0`.

## Configuration Options (`lws_dht_info_t`)

To interact with the DHT, you must declare and configure an instance of `lws_dht_info` and pass it to `lws_dht_create()`, which allocates the active `lws_dht_ctx` tracking structural state.

```c
struct lws_dht_info {
	struct lws_context *ctx;    // the overarching lws_context
	const char *vhost;          // the vhost name to bind to
	const char *interface_name; // the network interface for the socket
	int port;                   // the port to bind to (0 = random)
	uint8_t *myid;              // 20-byte persistent node ID (or NULL for random)
	lws_dht_cb_t *cb;           // callback function for DHT events
	void *closure;              // opaque user pointer passed back in the callback
	int capture_announce_cb;    // non-zero to trigger callbacks on announce_peer
};
```

When building exclusively as a client (`LWS_WITH_DHT_BACKEND=0`), certain hidden structural attributes used exclusively for routing tables and storage coordination inside `lws_dht_ctx` will be omitted from the build to minimize memory footprint.

## APIs

*   `lws_dht_create(const struct lws_dht_info *info)`: Allocates and initializes the overarching DHT context.
*   `lws_dht_destroy(struct lws_dht_ctx **ctx)`: Destroys the active DHT object and frees its allocations.

A typical DHT client needs to formulate queries and dispatch them:
*   `lws_dht_send_ping(...) `: Transmits a minimal standard `ping` query to confirm a node is active.
*   `lws_dht_send_find_node(...)`: Requests closest nodes to a specified target ID from an external peer.
*   `lws_dht_send_get_peers(...)`: Queries peers holding specific metadata/values matching an `info_hash`.
*   `lws_dht_send_announce_peer(...)`: Announces to peers that your node is currently serving a resource corresponding to an `info_hash`.
*   `lws_dht_send_subscribe(...)`: Initiates a long-poll request to be notified when a value at a given `info_hash` is modified or deleted.
*   `lws_dht_send_subscribe_confirm(...)`: Formulates a valid challenge-response to complete a subscription utilizing a generated security token securely fetched from the target.
*   `lws_dht_send_ack(...)`: Dispatches an empty `DHT_REPLY` back to a sender matching a 16-byte tracking cookie, commonly used to acknowledge asynchronous notification updates.

## Handling Events and Verb Handlers

Libwebsockets allows deep interception of typical DHT lifecycles using structured external callbacks (`lws_dht_cb_t`). This provides custom logic for arbitrary events like resolving your consensus external IP, processing peer payloads, or implementing plugin-provided features.

You can easily handle payloads by placing your logic inside an LWS protocol handler or a standalone plugin.
To intercept incoming announcements explicitly:
1. Ensure your build enabled `LWS_WITH_DHT_BACKEND=1` alongside `LWS_WITH_DHT=1`.
2. Configure `capture_announce_cb` to `1` in the `lws_dht_info` passed to creation.
3. Define a matching function according to the `lws_dht_cb_t` signatute.
4. Execute custom logic on respective payload codes like `LWS_DHT_EVENT_ANNOUNCE` and `LWS_DHT_EVENT_EXTERNAL_ADDR`.

```c
static int
my_dht_callback(void *closure, int event, const uint8_t *id,
		const uint8_t *values, size_t values_len,
		const struct sockaddr *from, size_t fromlen)
{
	switch (event) {
	case LWS_DHT_EVENT_ANNOUNCE:
		// Triggered every time a peer announces they hold a resource
		break;
	case LWS_DHT_EVENT_VALUES:
		// Process newly received IPv4 storage values from a get_peers request
		break;
	case LWS_DHT_EVENT_VALUES6:
		// Process newly received IPv6 storage values from a get_peers request
		break;
	case LWS_DHT_EVENT_EXTERNAL_ADDR:
		// Update localized behavior when consensus external apparent address is found
		break;
	}
	return 0;
}
```
