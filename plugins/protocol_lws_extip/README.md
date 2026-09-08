# `protocol_lws_extip` Plugin

This plugin implements a very lightweight UDP-based IP detection mechanism that's cheap to operate even for millions of clients. It operates cleanly from behind NAT environments, allowing clients to be notified within 60s of their external IP changing. To protect against UDP reflection/amplification attacks, it uses a zero-state HMAC-SHA256 cookie validation mechanism that requires an attacker to own the IP it's attacking from in order to receive a valid cookie.

## Build requirements

 - LWS_WITH_UDP=1
 - LWS_WITH_EXTIP=1
 - LWS_WITH_SYS_ASYNC_DNS=1

## Operation

1. **Client** resolves the server hostname via `lws_async_dns` for both A (IPv4) and AAAA (IPv6) records, detecting them them entirely independently over separate UDP sockets.
2. **Client** requests an IPv4/IPv6 cookie (`R`).
3. **Server** issues a `C<raw 32-byte cookie>`. The cookie is a stateless HMAC-SHA256 signature of the client's current IP and port. 
4. **Client** pings periodically (`P<raw 32-byte cookie>`).
5. **Server** validates the cookie against the incoming IP address. If it matches, the Server replies with an `O<raw 32-byte cookie>` (OK heartbeat).
6. If the NAT drops and the Client changes IPs, the ping arrives from a new IP. The HMAC fails to validate against the new IP. The Server instantly replies with `I<New IP>` denoting an IP change.
7. The Client clears its cookie, emits an `report_external_ip_cb` system state event with `status=1` containing the newly verified IP, and loops back to step 1.
8. If the Client does not receive an `O` or `I` for 3 consecutive pings (90 seconds) on a specific family socket, it declares that IP route offline and emits `report_external_ip_cb` with `status=2` and an empty `sa46` structure.

## Per-Vhost Options (PVOs)

The plugin can operate as a server or a client on a per-vhost basis. Both modes can be enabled simultaneously if acting as a peer.

### Server Mode PVOs

To enable the server:
- `"listen-port"`: Set the UDP port to listen on. Presence of this option implicitly enables the server.

### Client Mode PVOs

To enable the client:
- `"connect"`: **(Mandatory for client)** The address and port of the server to ping, formatted as `address:port`. Presence of this option implicitly enables the client.

## Integration

When the client detects an IP change, it invokes the global `lws_system_ops_t` callback `report_external_ip_cb(..., LWS_EXTIP_SRC_EXTIP, ...)` to distribute the event down to your application layers or external modules like DHT routing.

## lwsws Config Example

To configure the plugin to run as a server using the `lwsws` JSON convention, you can add it to your vhost's `ws-protocols` section.

```json
{
  "vhosts": [
    {
      "name": "myvhost",
      "port": 443,
      "ws-protocols": [
        {
          "protocol-lws-extip": {
            "status": "ok",
            "listen-port": "49200"
          }
        }
      ]
    }
  ]
}
```

## Security notes

- The client sockets are bound rather than connected, so the kernel delivers
  datagrams from any source to them.  The client therefore checks that the
  source address *and* port of a `C` / `O` / `I` datagram match the server
  address it resolved and sent its request to, and drops anything else.  Since
  these replies set the process-wide notion of the node's external IP (and the
  SMD `ext-ips` broadcast derived from it), without that check any host able to
  reach the bound port - including an off-path spoofer - could set it.
- The client also pairs each reply with the request it actually made: it only
  sends `R` when it has no cookie and `P` when it has one, so a `C` is only
  honoured while no cookie is held, and an `O` or `I` only while one is.  An
  unsolicited reply cannot drive a state transition.
- An `I` (or the address trailing a `C`) that does not parse as a numeric
  address is dropped rather than reported: reporting the zeroed result would
  be taken as "offline" and would clear the address we do have.
- The server compares the ping cookie with `lws_timingsafe_bcmp()`.
- The server still answers an `R` from an unvalidated source (it must, to
  bootstrap the cookie), so it is technically a UDP reflector; the reply is
  only around 1.5x - 2x the size of the request, and everything after the
  bootstrap requires a cookie the sender can only obtain at its own address.
  Do not expose the server port to the internet without a packet-rate limit in
  front of it if that gain matters to you.
