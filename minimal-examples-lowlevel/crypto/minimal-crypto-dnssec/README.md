# lws-crypto-dnssec

This standalone utility dynamically calls into the `lws-dht-dnssec` plugin to generate compliant Domain Name System Security Extensions (DNSSEC) cryptography keys intuitively, relying on the `<domain>` to format matching files automatically.

## Building

It requires `libwebsockets` built utilizing:
```cmake
-DLWS_WITH_DHT_BACKEND=1
-DLWS_WITH_GENCRYPTO=1
-DLWS_WITH_JOSE=1
-DLWS_WITH_PLUGINS=1
```

## Key Generation (`keygen`)

Generates cryptographically secure Key Signing Key (KSK) and Zone Signing Key (ZSK) pairs simultaneously, natively leveraging `lws_gencrypto`.

Usage: `lws-crypto-dnssec keygen [--type <RSA|EC>] [--bits <size>] [--curve <curve>] <domain>`

- **`--type`**: Generates keys natively compatible with DNSSEC mapping:
  - `RSA` (maps to Algorithm 8: RSASHA256)
  - `EC` (maps to Algorithm 13: ECDSAP256SHA256, default algorithm for curve P-256)
- **`--bits`**: Specifies the bitlength for RSA algorithms (e.g., 1024, 2048).

### File Outputs
Keys are automatically written following the target `<domain>`:
- `<domain>.<ksk|zsk>.private.jwk`: The private key exported as a JSON Web Key.
- `<domain>.<ksk|zsk>.key`: The public `DNSKEY` formatted directly for inclusion within standard BIND zone files.

## Importing NSD Keys (`importnsd`)

Allows importing an existing domain from standard BIND/NSD setups by ingesting existing `.private` and `.key` files into standard JWK format.

Usage: `lws-crypto-dnssec importnsd <domain> <key1-prefix> [key2-prefix]`

- Parses BIND file payloads (e.g. `Kexample.com.+013+12345.private` and `.key`)
- Detects whether keys are `KSK` or `ZSK` implicitly based on DNSKEY parameters (flags 256 or 257)
- Yields the same output files as `keygen`:
  - `<domain>.<ksk|zsk>.private.jwk`
  - `<domain>.<ksk|zsk>.key`
- Also computes your standard DNSSEC summary and DS keys mimicking `dsfromkey`, saving it as `<domain>.dnssec.txt`.

## Delegation Signer Generation (`dsfromkey`)

Constructs a `DS` (Delegation Signer) record fingerprint to establish the chain of trust with the parent registrar.

Usage: `lws-crypto-dnssec dsfromkey [--hash <hash>] <domain>`

- Assumes the existence of your generated `<domain>.ksk.key` path recursively.
- Prints the parsed base64 fingerprint logic.

## Zone Signing (`signzone`)

Verifies and cryptographically signs a raw zone file, incorporating both your KSK and ZSK signatures using `lws_jose`.

Usage: `lws-crypto-dnssec signzone [--duration <hours>] <domain>`

- Iterates and parses `<domain>.zone` (The user-provided mock base-zone).
- Automatically bumps the SOA serial number using the `YYYYMMDDnn` format natively.
- Locates `<domain>.ksk.private.jwk` and `<domain>.zsk.private.jwk`.
- Emits `<domain>.zone.signed` containing all initial `A`, `NS`, `SOA` records and appending the newly compiled `DNSKEY` and `RRSIG` combinations.
- Outputs `<domain>.zone.signed.jws` representing the completed JSON Web Signature payload securely ingestible into the DHT network.
