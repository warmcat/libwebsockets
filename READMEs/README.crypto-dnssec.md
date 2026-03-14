## lws-crypto-dnssec

`lws-crypto-dnssec` is a native utility provided by libwebsockets for handling DNSSEC cryptographic operations, allowing you to generate keys, create Delegation Signer (DS) records, and securely sign authoritative DNS zone files natively without relying on heavy external tools like BIND or NSD utilities.

It produces standard, RFC-compliant outputs: `.key` files (RFC 4034 DNSKEY format), `.zone` files containing canonical RRSIG and NSEC3 chains, and outer JSON Web Signatures (JWS) for deployment to the `lws` DHT.

### Build Requirements
To build this utility, you must enable the following CMake options when configuring libwebsockets:
- `LWS_WITH_JOSE=1`
- `LWS_WITH_GENCRYPTO=1`
- `LWS_WITH_SYS_ASYNC_DNS_DNSSEC=1`
- `LWS_WITH_AUTHORITATIVE_DNS=1`

You can enable these individually, or if your build script enables them recursively, ensure they are ultimately selected. Once configured, build using `make`.

### Step 1: Create an Unsigned DNS Zone File

Start by creating a standard, unsigned text DNS zone file for your domain. You do not need to manually add `DNSKEY`, `NSEC3`, `NSEC3PARAM`, or `RRSIG` records—the signing utility will automatically generate and inject these for you.

Create a file named `mydomain.zone`:

```zone
$ORIGIN mydomain.com.
$TTL 86400

@ IN SOA ns1.mydomain.com. admin.mydomain.com. (
    2026030801 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; nxdomain ttl
)

@ IN NS ns1.mydomain.com.
@ IN NS ns2.mydomain.com.

ns1 IN A 192.168.1.1
ns2 IN A 192.168.1.2
www IN A 192.168.1.100
```

### Step 2: Generate the Cryptographic Keys

DNSSEC requires a pair of keys: a Key Signing Key (KSK) and a Zone Signing Key (ZSK).

**1. Generate the Key Signing Key (KSK):**
The KSK signs the `DNSKEY` record itself. It is the root of trust for your zone.

```bash
lws-crypto-dnssec keygen --ksk --curve P-384 mydomain.com
```
This generates two files:
- `mydomain.com.ksk.private.jwk` (Your secret private key in JWK format)
- `mydomain.com.ksk.key` (The public DNSKEY record text representation)

**2. Generate the Zone Signing Key (ZSK):**
The ZSK signs all the other operational records in your zone (A, AAAA, MX, etc.).

```bash
lws-crypto-dnssec keygen --curve P-384 mydomain.com
```
This generates:
- `mydomain.com.zsk.private.jwk`
- `mydomain.com.zsk.key`

*Note: You can specify other curves such as `P-384` or `P-521` using the `--curve` argument.*

### Step 2.5: Importing Existing NSD/BIND Keys (Optional)

If you are migrating an existing domain from standard BIND or NSD setups, you can import your existing DNSSEC keys directly into the `lws` JWK format without generating new ones.

The `importnsd` command takes your domain and the file prefixes of your existing `.private` and `.key` files (usually named like `Kmydomain.com.+013+12345`).

```bash
lws-crypto-dnssec importnsd mydomain.com Kmydomain.com.+013+12345 Kmydomain.com.+013+67890
```

The utility automatically parses the `DNSKEY` flags (256 for ZSK, 257 for KSK) to assign the correct roles, extracts the cryptographic parameters, and exports standard `mydomain.com.ksk.private.jwk` and `mydomain.com.zsk.private.jwk` files. It also generates a `mydomain.com.dnssec.txt` summarizing your DS records.

### Step 3: Extract DS Information for the Registrar

To establish the chain of trust, the parent zone (e.g., the `.com` registry) must publish a Delegation Signer (DS) record containing a cryptographic hash of your public KSK.

You can extract this DS digest from your public KSK using the `dsfromkey` command:

```bash
lws-crypto-dnssec dsfromkey --hash SHA256 mydomain.com.ksk.key
```
*Output Example:*
```text
mydomain.com. IN DS 5167 13 2 49c0a71...
```
You will provide the Keytag (`5167`), Algorithm (`13`), Digest Type (`2` for SHA-256), and the resulting hex Digest to your domain registrar.

*(Alternatively, the `signzone` command in the next step will conveniently print out this exact DS information to the console during signing).*

### Step 4: Sign the Zone File

Now, you will take the unsigned zone file, process it with your keys, and generate both the DNSSEC-signed `.zone` file and an outer JWS wrapper.

```bash
lws-crypto-dnssec signzone \
    --ksk mydomain.com.ksk.private.jwk \
    --zsk mydomain.com.zsk.private.jwk \
    --duration 2592000 \
    mydomain.zone mydomain.zone.signed mydomain.zone.signed.jws
```

**What happens during this step:**
1. **Canonicalization**: The tool normalizes the input records.
2. **NSEC3 Chains**: It calculates iterations of hashed owner names to prevent zone walking, injecting `NSEC3` and `NSEC3PARAM` records.
3. **DNSKEY Injection**: Your public KSK and ZSK are converted from JWK to wire format and injected as `DNSKEY` records at the zone apex.
4. **Inner DNSSEC Signatures**: It hashes the normalized RRsets and signs them with your ZSK. The apex `DNSKEY` record is signed with your KSK. These signatures are injected as `RRSIG` records.
5. **Outer JWS Signature**: Finally, the completely assembled, canonical text zone is wrapped inside a JSON Web Signature (JWS) to ensure transport integrity when deploying it to external sources like the libwebsockets DHT framework.

**Outputs:**
- `mydomain.zone.signed`: The standard, DNSSEC-signed authoritative zone text ready for a traditional nameserver.
- `mydomain.zone.signed.jws`: The JWS-signed JSON document containing the entire zone, mathematically verifiable using your zone keys.
