# lws-dht-dnssec Plugin

This plugin extends the core libwebsockets Distributed Hash Table (DHT) framework to provide a secure, decentralized storage layer specifically designed for DNSSEC zone files.

It works by intercepting DHT `PUT` requests, requiring client-side JSON Web Signatures (JWS) enclosing the zone files, which the plugin subsequently validates asynchronously against the authoritative Domain Name System (DNS) `DS` records.

## Features
- Validates the signatures on uploaded payload against the public keys verified by DNS `DS`.
- Stores payloads securely with an automatic domain-hashed derivation (`lws-dnssec-dht-<domain>`).
- Supports the protocol-level version precedence mechanics resolving replacing states.
- Re-uses LWS JSON Object Signing and Encryption (`lws-jose`) routines and asynchronous DNS resolution natively.

## Active Change Notifications
The plugin actively utilizes the `SUBSCRIBE`, `SUBSCRIBE_CONFIRM` and `NOTIFY` DHT verbs to monitor downloaded zone files for changes:
- When a zone is successfully downloaded and validated, the plugin automatically issues a `SUBSCRIBE` request to the original DHT node.
- The subscription is finalized with a cryptographically secure `SUBSCRIBE_CONFIRM` challenge containing a local ID and the current payload's SHA256 hash.
- If the authoritative DNS node updates the zone file, it will broadcast a `NOTIFY` to all active long-poll subscribers. The plugin will instantly acknowledge the notification (via `lws_dht_send_ack`) and re-fetch the updated zone asynchronously.

## Zonefile Security Validation
To prevent abuse from malicious peers or compromised routing, the plugin enforces strict boundaries on incoming zonefiles before they are committed to the local cache:
1. **Size Limits**: `PUT` and `GET` chunk sequences have a hard limit of 128KB (`131072` bytes). Payloads exceeding this size are aggressively dropped, preventing disk and memory exhaustion attacks.
2. **Syntax Parsing checks**: Following JWS signature unwrapping, the plugin actively parses the payload using `lws_auth_dns_parse_zone_buf`. This guarantees the incoming file is a syntactically correct DNS zonefile.
3. **SOA Serial Replay Protection**: To stop attackers from replaying older, but validly signed zonefiles, the plugin extracts the `SOA` serial number from the parsed zone and mandates that it be sequentially newer than any existing copy of the zonefile in the cache.
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

| Option Name      | Description                                                                                                                                              | Default Value           |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|
| `storage`        | The directory on the filesystem where validated DHT fragments (zone files) should be written to and served from.                                         | `/tmp/lws-dht-store`    |
| `jwk`            | Path to a JSON Web Key (JWK) representing the trusted node key for secure communication/authorization. If it isn't found, one is automatically generated.| `dht.jwk`               |
| `allow` / `deny` | Optional filesystem paths to list specific rules/access lists based on public keys or identifiers, restricting who can access or modify DHT records.     | `NULL`                  |
| `test_handshake` | Boolean flag (`1` or `0`) to place the node in testing mode, generating synthetic responses to trace handshake mechanics during development.             | `0`                     |
| `cli_receiver`   | Boolean flag (`1` or `0`) intended for the `minimal-raw-dht-zone-client` CLI application to tell the plugin context it is acting as an active receiver.  | `0`                     |
| `dht-iface` | The network interface the DHT node should bind to. | `NULL` |
| `dht-port` | The port the DHT node should bind to. | `NULL` |
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
