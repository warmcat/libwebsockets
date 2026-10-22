# lws-dht-dnssec Plugin

This plugin extends the core libwebsockets Distributed Hash Table (DHT) framework to provide a secure, decentralized storage layer specifically designed for DNSSEC zone files.

It works by intercepting DHT `PUT` requests, requiring client-side JSON Web Signatures (JWS) enclosing the zone files, which the plugin subsequently validates asynchronously against the authoritative Domain Name System (DNS) `DS` records.

## Features
- Validates the signatures on uploaded payload against the public keys verified by DNS `DS`.
- Stores payloads securely with an automatic domain-hashed derivation (`lws-dnssec-dht-<domain>`).
- Supports the protocol-level version precedence mechanics resolving replacing states.
- Re-uses LWS JSON Object Signing and Encryption (`lws-jose`) routines and asynchronous DNS resolution natively.

## Active Change Notifications
The plugin actively utilizes the `SUBSCRIBE`, `SUBSCRIBE_CONFIRM` and `NOTIFY` DHT verbs to monitor the zone files it serves for changes:
- Whenever a fetch of a zone it serves completes, whether the zone was new or one it already had, the plugin issues a `SUBSCRIBE` to the DHT node that answered it, which holds the zone.
- So each zone it serves is fetched once the DHT is up, even when a copy is in its storage from before a restart: the copy is served meanwhile, and may be older than the network's.
- That node answers with a token, which the plugin returns in a `SUBSCRIBE_CONFIRM` for that zone's hash.  A token for any other hash is not confirmed.
- The holder forgets a subscriber after an hour, so subscriptions are renewed every 20 minutes.
- When the holder accepts a new version of the zone, it sends a `NOTIFY` carrying the new serial and the domain to its subscribers, retrying until they acknowledge it.  The plugin acknowledges it and fetches the zone.
- A zone is fetched for `NOTIFY`s at most once a minute, except that a newer serial from the holder it subscribed with (or from a `NOTIFY` sender that passed the cookie exchange) is fetched at once, at most every 5 seconds.  A `NOTIFY` inside that minute is not dropped: one fetch when the minute ends covers it.  Subscribing to the zone again inside the minute is deferred the same way.

## Zone Fetches
When a node needs a zone it does not hold (auth-dns asked for it, or a `NOTIFY` said there is a newer one), it sends `GET <zone hash>` and takes the zone from the first asked node whose `RSP` arrives; `RSP`s from any node that was not asked are refused.
- Every node asked takes one of the DHT's 64 transport sequencers until it acknowledges, and uploads, other fetches and serial queries need them too, so a fetch asks at most 8 routing table nodes at a time (`LWS_DHT_DNSSEC_FETCH_FANOUT`), good ones and half from each address family first, plus the bootstrap target if one is configured.
- If nobody has answered, each of its 3 retries, 15s apart, asks the next 8 nodes it has not asked yet, and the target again.  Once a node answers, nobody more is asked.
- A node the DHT has no sequencer for at the moment (`LWS_DHT_SEND_REFUSED` or `LWS_DHT_SEND_BUSY`) is not counted as asked: it is asked again in an early round 4s later, at most 4 times per fetch.  An early round only asks as many nodes as its full round could not, so a fetch asks at most 8 nodes and the target per 15s, and never more hosts than it can remember having asked.
- A fetch of a zone with the same completion and opaque as one in progress joins it, and sends nothing more.
- auth-dns starts a fetch for a DNS query only if its zone is not already being fetched, and at most 4 at once, then one per 2s, for each source host, and 32 at once, then one per 250ms, in all; a query over that is answered `REFUSED`, since DNS queries can come from forged sources.

## Zone Serial Queries
To see a new version of a zone spread across the DHT, eg, in the dnssec monitor's domain page, the `query_serials` op asks every node in the routing table which serial of a zone it holds:
- The plugin sends each node `SOA_REQ <zone hash> 0 0` followed by an 8-byte nonce, random per query.
- A node answers `SOA_RSP <zone hash> <serial> <1 if it holds the zone, else 0>` followed by the same nonce.  Only an answer from a node that was asked, carrying that query's nonce, is taken.
- The caller hears each node's answer as it comes, and of the nodes that didn't answer within `LWS_DHT_DNSSEC_SERIAL_QUERY_SECS` (5s): a node older than these verbs never answers.  Its own copy is reported too, and then the end of the query.
- One query runs per caller (opaque) at a time, and at most 16 at once.  Each asks at most 24 nodes, half from each address family first: every node asked takes one of the DHT's 64 transport sequencers, which zone transfers need too.

## Zonefile Security Validation
To prevent abuse from malicious peers or compromised routing, the plugin enforces strict boundaries on incoming zonefiles before they are committed to the local cache:
1. **Size Limits**: `PUT` and `GET` chunk sequences have a hard limit of 128KB (`131072` bytes). Payloads exceeding this size are aggressively dropped, preventing disk and memory exhaustion attacks.
2. **Syntax Parsing checks**: Following JWS signature unwrapping, the plugin actively parses the payload using `lws_auth_dns_parse_zone_buf`. This guarantees the incoming file is a syntactically correct DNS zonefile.
3. **Signed and in date**: the JWS carries no time, and the key it is signed with (the KSK the domain's DS names) lives for years, so every version of a zone its owner ever published would verify forever.  The zone's own RRSIGs carry when it was signed and for how long, under the JWS signature, so a zone is refused unless it has an RRSIG over its apex SOA and every RRSIG in it is inside its validity period now, give or take `LWS_AUTH_DNS_RRSIG_SKEW_SECS` (300s) of clock skew.  A zone without RRSIGs is refused: `lws-crypto-dnssec signzone` and the dnssec monitor always sign, and auth-dns, which serves the zone, applies the same check before installing it.  The stored copy is dropped, and no longer served or handed to auth-dns, when its earliest RRSIG expires, so the publisher has to re-sign and republish before then (signatures are good for 30 days by default).
4. **Replay Protection**: To stop attackers from replaying older, but validly signed zonefiles, a version is refused if its `SOA` serial is older (RFC 1982 order) than the copy in the cache, or if its serial or signing time (the inception of its SOA RRSIG) is older than the newest version of the zone the node ever took.  That high-water mark is kept in `<storage>/<h0h1>/<h2h3>/<hash>.hwm`, next to the zone, and outlives its payload, so a node whose copy expired or was swept is not rolled back either.  The mark is removed a week after the RRSIGs of the version it records expired, when any older version has expired too.  It is written to `<hash>.hwm.tmp`, synced and renamed into place.  A mark that exists but can't be opened or read, or is not exactly 20 bytes, fails closed: every version of the zone is refused, and the mark is neither replaced nor swept, until the operator removes it (the node logs it as an error).  A node that never had the zone takes the first version that is signed and in date; it learns of newer ones through its subscription to the holder.  A publisher putting the version a node already holds is acknowledged as for a new one, so it does not count it a failure and publish it again; nothing is stored or announced.
## CMake Configuration
To enable the underlying requirements so out-of-the-box DHT plugins and the `lws-dht-dnssec` node work, your `libwebsockets` CMake build requires the following options:

```cmake
-DLWS_WITH_DHT=1
-DLWS_WITH_DHT_BACKEND=1
-DLWS_WITH_JOSE=1
-DLWS_WITH_SYS_ASYNC_DNS=1
-DLWS_WITH_GENCRYPTO=1
-DLWS_WITH_SYS_ASYNC_DNS_DNSSEC=1
-DLWS_ROLE_RAW_FILE=1
-DLWS_WITH_PLUGINS=1
```

## Per-vhost Options
The plugin operates under the standard `lws` plugin model using per-vhost options (pvos) to configure its behaviors. The available options include:

The plugin runs once per process: give the `dht-*` pvos to one vhost only,
normally the one serving auth-dns.  If another vhost has a `dht-port` too, no
second instance is started there, since both would share the DHT port and the
kernel would split the PUTs between them; an error names the vhost already
running it.  auth-dns or other users of the plugin's ops on any vhost reach
the one running instance.


| Option Name      | Description                                                                                                                                              | Default Value           |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|
| `storage`        | The directory on the filesystem where validated DHT fragments (zone files) should be written to and served from.                                         | `/tmp/lws-dht-store`    |
| `jwk`            | Path to a JSON Web Key (JWK) representing the trusted node key for secure communication/authorization. If it isn't found, one is automatically generated.| `dht.jwk`               |
| `allow` / `deny` | Optional filesystem paths to list specific rules/access lists based on public keys or identifiers, restricting who can access or modify DHT records.     | `NULL`                  |
| `test_handshake` | Boolean flag (`1` or `0`) to place the node in testing mode, generating synthetic responses to trace handshake mechanics during development.             | `0`                     |
| `cli_receiver`   | Boolean flag (`1` or `0`) intended for the `minimal-raw-dht-zone-client` CLI application to tell the plugin context it is acting as an active receiver.  | `0`                     |
| `dht-iface` | The network interface the DHT node should bind to. | `NULL` |
| `dht-port` | The port the DHT node should bind to. | `NULL` |
| `dht-allow-private` | `"1"` admits peers on private, loopback or link-local addresses (a LAN deployment, or local testing); by default only public addresses are kept. | `"0"` |
| `dht-fallback-nodes` | Comma-separated list of fallback bootstrapping nodes (e.g. `1.2.3.4:443,5.6.7.8:443`). | `NULL` |
| `dht-jwk` | Path to the JSON Web Key (JWK) used specifically for DHT participation authentication. | `NULL` |
| `dht-storage-path` | Path indicating where DHT data objects should be persisted locally. | `NULL` |
| `dht-policy-allow` / `dht-policy-deny` | Path to access control list files allowing or denying peers from participating in the local DHT node based on public keys. | `NULL` |
| `dht-test-handshake` | Places the DHT network layer into handshake testing mode. | `0` |
| `get-domain` | Instructs the CLI or node to perform an active DHT `GET` query for a specific target domain. | `NULL` |
| `get-hash` | Instructs the CLI or node to perform an active DHT `GET` query for a specific content hash. | `NULL` |
| `put-file` | Instructs the CLI to perform a DHT `PUT` operation storing a local file into the network. | `NULL` |
| `gen-manifest` | Path to generate a manifest file indicating the state of DHT operations. | `NULL` |
| `bulk` | Boolean flag (`1` or `0`) to enable bulk data transfer modes. | `0` |
| `target-port` | The target port to connect to when bootstrapping or joining a node (CLI usage). | `0` |
| `completion-cb` / `completion-cb-arg` | Callback configurations used by programmatic C API invocations, usually ignored via configuration files. | `NULL` |

## Example Client Usage
When using the accompanying `minimal-raw-dht-zone-client`, the CLI dynamically injects these PVOs on instantiation. For example, to sign your local file and instruct the context to forward it with the domain context:

```bash
./lws-minimal-raw-dht-zone-client \
    --domain example.com \
    --jwk my-domain.jwk \
    --target-ip 127.0.0.1 \
    --put /tmp/zone.txt
```

## Dynamic Zonefile Substitutions
During the `signzone` process, the system supports dynamic string substitutions evaluated on a line-by-line basis. If a requested substitution variable resolves to an empty blank string or the underlying requirements (like absent IP parameters or missing certificates) aren't met, the engine gracefully skips and entirely drops the invoking line from the final signed zone. This allows creating robust generic records that adapt securely to the runtime node capacity.

The following substitution keys are provided:
- `${EXTIP4}`: Injects the dynamically detected external IPv4 address of the node generating the re-sign.
- `${EXTIP6}`: Injects the dynamically detected external IPv6 address of the node generating the re-sign.
- `${DANE0}`: Generates a DANE TLSA SHA-256 signature string for the *current* active TLS certificate. The parser natively identities the target `<domain>` context from the front of the corresponding record line (such as `_443._tcp.warmcat.com. IN TLSA ...`) and accesses `/var/dnssec/domains/<domain>/tls/<domain>.crt` to actively compute the `3 1 1 <hash>` DANE data.
- `${DANE1}`: Acts identically to `DANE0`, however signs the *previous* archived certificate by checking `/var/dnssec/domains/<domain>/tls/<domain>.crt.1`.

### Substitution Examples
If an operator authors the following raw zone file config:
```text
example.com.      IN A     ${EXTIP4}
example.com.      IN AAAA  ${EXTIP6}
_443._tcp.example.com. IN TLSA ${DANE0}
_443._tcp.example.com. IN TLSA ${DANE1}
```

Upon `signzone`:
- If the node **lacks an external IPv6 address**, the entire `example.com. IN AAAA ${EXTIP6}` line will be seamlessly excluded from the resulting signed zone.
- The `${DANE0}` key evaluates `_443._tcp.example.com.` and automatically locates `/var/dnssec/domains/example.com/tls/example.com.crt`. It hashes the embedded SPKI, returning `3 1 1 e3b0c4429...`.
- If no archived certificate (`example.com.crt.1`) exists, the second TLSA line containing `${DANE1}` will drop itself natively.

## `lws-crypto-dnssec` Utility
Libwebsockets provides the `<build-dir>/bin/lws-crypto-dnssec` standalone utility that interfaces dynamically using the `lws-dht-dnssec` plugin.

To manage keys and signatures efficiently, the utility relies entirely on the `<domain>` to implicitly determine corresponding JSON Web Key (JWK) paths:

### Key Generation Configuration
Keys generated are RSA `RSASHA256` (DNSSEC Type 8) by default if `--type RSA` is requested. Generating both a KSK and ZSK at once:
```bash
./lws-crypto-dnssec keygen --type RSA --bits 1024 example.com
# Outputs: example.com.ksk.key, example.com.ksk.private.jwk, example.com.zsk.key, and example.com.zsk.private.jwk
```

### NSD Key Import (`importnsd`)
To migrate preexisting domains utilizing keys from standard BIND utilities without rotating them, you can ingest the raw configuration files natively:
```bash
./lws-crypto-dnssec importnsd example.com Kexample.com.+013+12345 Kexample.com.+013+67890
# Parses the .private and .key parameters implicitly based on the DNSKEY flags.
# Outputs: example.com.ksk.key, example.com.ksk.private.jwk, example.com.dnssec.txt, etc.
```

### Delegation Signer Record (DS) Extract
You can grab the Base64 DS fingerprint required for your domain's registrar directly from the `.key` public component:
```bash
./lws-crypto-dnssec dsfromkey example.com
# Derives from naturally existing example.com.ksk.key within the path
```

### Zonefile Signature Wrap
After validating your configurations inside `example.com.zone`, it can rapidly wrap it in the required signature headers by locating your `.private.jwk` elements:
```bash
./lws-crypto-dnssec signzone example.com
# Generates example.com.zone.signed and example.com.zone.signed.jws
```
