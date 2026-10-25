# `protocol_lws_extip_router` Plugin

The router already knows the addresses a host behind it is reachable on from
outside, since they are configured on its outward interfaces: typically the
IPv4 address on its ppp link and the IPv6 prefix on its LAN interface.  This
plugin lets the router tell the hosts behind it, in a reply signed with the
router's key over a nonce the host chose, so the host can trust it and know
it's current.

What the host learns is reported to the context as `LWS_EXTIP_SRC_ROUTER`.
The context keeps every source's view separately, and ranks the router above
the extip server (`LWS_EXTIP_SRC_EXTIP`, see `protocol_lws_extip`) and the
DHT consensus (`LWS_EXTIP_SRC_DHT`).  While the router is answering, its
addresses are the ones broadcast in the `ext-ips` SMD message; if it stops
answering, the next best source's view takes over.

## Build requirements

 - LWS_WITH_EXTIP=1
 - LWS_WITH_JOSE=1
 - a unix-type platform (interface addresses come from `getifaddrs()`)

## Operation

1. The host makes a fresh random nonce and asks
   `GET <router-url>?nonce=<nonce>`.
2. The router reads the addresses on its configured interfaces and replies
   with a compact JWS (`application/jose`), signed ES256 with its private
   key, of

   ```
   {"pur":"lws-extip-router","nonce":"<nonce>",
    "v4":["192.0.2.1"],"v6":["2001:db8:1:2::/64"]}
   ```

   `v4` lists the IPv4 addresses on `v4-iface`.  `v6` lists the distinct
   prefixes of the IPv6 addresses on `v6-iface`, leaving out link-local ones
   and, on Linux, ones that are deprecated, tentative or failed DAD.
3. The host takes the reply only if it is signed by the router's key, and
   it's the answer to the nonce it just sent; otherwise it may be a replay
   of an old answer.
4. The host reports the first IPv4 address as its external IPv4 address.
   IPv6 is not NATed, so the router's prefix is not our address: the host
   reports its own address inside the prefix, leaving out link-local ones
   and, on Linux, temporary (RFC 8981), deprecated and tentative ones.  If it
   has none, and `v6-suffix` is set, it reports the prefix with the suffix
   filling the bits after it.
5. It asks again every `interval-secs`.  After 3 queries in a row fail
   (no reply, refused signature, wrong nonce...), it withdraws what it
   reported, so the next best source takes over.

## Per-Vhost Options (PVOs)

A vhost is either the router, or a client of one.

### Router mode

The plugin answers on a mount whose origin is `callback://lws-extip-router`.

PVO|Meaning
---|---
`jwk-private`|**Mandatory**, selects router mode: path to the router's EC P-256 private JWK
`v4-iface`|Interface whose IPv4 addresses we report, eg `ppp0`
`v6-iface`|Interface whose IPv6 prefixes we report, eg `enp2s0`

At least one of `v4-iface` or `v6-iface` is needed.

### Client mode

PVO|Meaning
---|---
`router-url`|**Mandatory**, selects client mode: `http://` or `https://` URL of the router's mount
`jwk-public`|**Mandatory**: path to the router's EC P-256 public JWK
`interval-secs`|How often to ask, default 60
`v6-suffix`|Optional, eg `::5`: if we have no address of our own in the router's prefix, report the prefix with this filling the rest

## Keys

Make the router's keypair with `lws-crypto-jwk` (from
`minimal-examples-lowlevel/crypto/minimal-crypto-jwk`):

```
$ lws-crypto-jwk -t EC -v P-256 --key-ops "sign verify" --public router.pub.jwk > router.jwk
```

`router.jwk` contains the private key: keep it on the router only, readable
only by the lwsws user.  Copy `router.pub.jwk` to the hosts.

## lwsws config examples

On the router, eg with the external IPv4 on `ppp0` and the IPv6 /64 on the
LAN side, `enp2s0`, listening only on the LAN interface:

```json
{
  "vhosts": [{
    "name": "extip-router",
    "port": "7690",
    "interface": "enp2s0",
    "mounts": [{
      "mountpoint": "/extip",
      "origin": "callback://lws-extip-router"
    }],
    "ws-protocols": [{
      "lws-extip-router": {
        "status": "ok",
        "jwk-private": "/etc/lwsws/router.jwk",
        "v4-iface": "ppp0",
        "v6-iface": "enp2s0"
      }
    }]
  }]
}
```

On a host behind it:

```json
{
  "vhosts": [{
    "name": "extip-client",
    "port": "-1",
    "ws-protocols": [{
      "lws-extip-router": {
        "status": "ok",
        "router-url": "http://192.168.1.1:7690/extip",
        "jwk-public": "/etc/lwsws/router.pub.jwk"
      }
    }]
  }]
}
```

## Security notes

- The reply is trusted because of its signature, not because of the
  transport: plain http on the LAN is fine, and anyone able to tamper with
  it can only make the host refuse it.  The JOSE alg is fixed to ES256, and
  the keys are checked to be EC at startup.
- The nonce is 33 random bytes per query, and only a reply over the nonce of
  the query in flight is taken, so an old reply can't be replayed later
  (eg, to push an address the router no longer has).
- The signed payload carries `"pur":"lws-extip-router"`, so a JWS made with
  the same key for some other purpose can't be passed off as a reply.
- Every query makes the router sign something, so don't expose the router's
  vhost beyond the LAN: listen only on the LAN interface (`interface`) as above.
- The router reports exactly what is on the interfaces it was told to use;
  it doesn't judge whether it's a public address.
- Outside Linux the plugin can't see IPv6 address flags, so it can't skip
  temporary or deprecated addresses there.
