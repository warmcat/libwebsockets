# lws-acme-client

## Introduction

The `lws-acme-client` plugin suite implements an ACME client designed for interacting with Certificate Authorities (like Let's Encrypt). It supports both `http-01` and `dns-01` challenges natively.

Recently, the plugin was refactored to support **centralized multi-certificate management**. Instead of only managing a single certificate for the vhost it is attached to, it can now manage an arbitrary number of certificates dynamically. It reads certificate configurations from JSON files located in a specified configuration directory (`conf.d`), deploys them, and monitors them for renewal.

The ACME logic is modularized into three separate protocol plugins:
- `lws-acme-client-core`: The backend state machine orchestrating the ACME process with the Certificate Authority.
- `lws-acme-client-http`: The frontend plugin for `http-01` challenges.
- `lws-acme-client-dns`: The frontend plugin for `dns-01` challenges.

## Per-Vhost Options (PVOs)

The `lws-acme-client` suite automatically reads the system global policy `/etc/lwsws/policy` during initialization to determine the `dns_base_dir`. You do not need to configure any PVOs for `conf-dir` or `root-dir`.

## Certificate JSON Configuration

Each certificate you want to manage should have its own `.json` file. These files must be placed within the domain-specific configuration directory: `$dns_base_dir/domains/<domain-name>/conf.d/`.

For example, config for `example.com` and its subdomains goes in `$dns_base_dir/domains/example.com/conf.d/`.

| JSON Key | Description |
|---|---|
| `common-name` | CSR Subject: The primary domain being certified (e.g. `example.com`). **Required** to start acquisition. |
| `challenge-type` | The ACME challenge to use: either `"http-01"` or `"dns-01"`. Defaults to `"http-01"`. |
| `email` | Registration email for ACME account (used for expiry notifications by the CA). |
| `profile` | ACME certificate profile to request in the newOrder, e.g. `"classic"` (90-day) or `"shortlived"` (~6-day). If unset, the global `profile` from `acme_config.json` applies; if that is also unset, the CA's default profile is used. |
| `acme` | A nested JSON object containing ACME-specific properties for this certificate. |

### The `acme` sub-object properties

| JSON Key | Description |
|---|---|
| `country` | CSR Subject: 2-letter Country code. |
| `state` | CSR Subject: State or Province name. |
| `locality` | CSR Subject: Locality or geographic name. |
| `organization` | CSR Subject: Organization name. |
| `directory-url` | The initial ACME CA directory URL (e.g., Let's Encrypt staging or production URL). |

*Note: The plugin automatically writes the Let's Encrypt `_acme-challenge` TXT record into `$dns_base_dir/domains/<domain-name>/dns/<domain-name>.zone.acme`. The `lws-dht-dnssec-monitor` automatically detects this drop-in file, securely merges it, and signs the updated payload.*

### Dynamic Path Generation

The plugin dynamically generates paths for your authentication keys, certificates, and private keys within the domain's standardized directory structure based on the `dns_base_dir`. You do **not** specify `auth-path`, `cert-path`, or `key-path` in the JSON.

* **Format:** `$dns_base_dir/domains/<domain-name>/certs/{crt,key}/<common-name>-[latest|date].[crt|key]`

The plugin creates versioned files with timestamps and maintains a `-latest` symlink pointing to the most recently generated file for easy references by the web server (e.g., `$dns_base_dir/domains/<domain-name>/certs/crt/<common-name>-latest.crt`).

## Example `lwsws` JSON Configuration

Here is an example of configuring `lwsws` to enable the ACME client plugin on a secure vhost.

```json
{
  "vhosts": [
    {
      "name": "dnssec-management",
      "port": "443",
      "host-ssl": "1",
      "ws-protocols": [
        {
          "lws-dht-dnssec": {
            "status": "ok",
             "dht-storage-path": "/var/lib/lws-dht"
          }
        },
        {
          "lws-dht-dnssec-monitor": {
            "status": "ok",
            "uds-path": "/var/run/dnssec.sock"
          }
        },
        {
          "lws-acme-client-core": {
            "status": "ok"
          }
        },
        {
          "lws-acme-client-dns": {
            "status": "ok"
          }
        }
      ]
    }
  ]
}
```

*Note: The acquisition sequence triggers automatically when `lws-acme-client-core` receives the `LWS_CALLBACK_VHOST_CERT_AGING` event on startup or when the certificate gets close to expiration. There is no manual trigger command required.*

### Forcing a reissue

Certificates are evaluated at startup and hourly after that, and renewed once
a quarter or less of their validity is left.  To reissue a certificate
before then, eg, to move it to a different `profile` straight away, send on
SMD class `LWSSMDCL_CERTS`

```json
{"acme":"force-reissue","domain":"example.com","common-name":"www.example.com"}
```

`domain` is the directory under `$dns_base_dir/domains/` the certificate's
config was loaded from, and `common-name` its config's `common-name`.  That
certificate is then reissued at its next evaluation however much validity it
has left, and the evaluation is brought forward to now (or the next one, if an
evaluation or acquisition is already running).  The backoff after failed
acquisitions still applies.  The `lws-dht-dnssec-monitor` UI sends this from
the "Force reissue" button on each row of its TLS certificates table.

## How a dns-01 challenge is put in place

The DNS plugin hands the challenge TXT to the `lws-dht-dnssec-monitor` root
process over IPC, which merges it into the domain's zone and signs it again;
lwsws then publishes the new signed zone to the DHT, where the domain's
authoritative servers pick it up.  The plugin watches for the zone's
`.zone.signed.jws` being rewritten after it handed the TXT over.  If the zone
is not signed within 3 minutes (eg, it uses `${EXTIP4}` / `${EXTIP6}` and the
external addresses are not known yet), the attempt fails without the ACME
server being asked, so it doesn't count as a failed validation, and the usual
backoff applies.

Once it is signed, the plugin asks the zone's name servers (its apex `NS`
records, at the addresses the zone gives them or that they resolve to)
directly, every 2s, for `_acme-challenge.<domain>` TXT, and only asks the ACME
server to validate when every one of them serves the challenge: a resolver
asking too soon could cache that there is no such record.  A name server
counts when one of its addresses answers with the challenge and none answers
without it; an address that doesn't answer at all, eg, over IPv6 from a host
with no IPv6 route, is ignored.  If they don't all serve it within 3 minutes,
the attempt fails the same way, and the log names the ones that didn't.  If
the zone has no usable `NS` records, or none of them can be looked up, the
plugin falls back to allowing 20s after signing.

## Example Certificate JSON Configurations (`$dns_base_dir/domains/<domain-name>/conf.d/*.json`)

### Example: DNS-01 Challenge

Place this file in your domain's config directory (e.g., `/etc/dnssec/domains/example.com/conf.d/example.com.json`):

```json
{
  "common-name": "example.com",
  "challenge-type": "dns-01",
  "email": "admin@example.com",
  "acme": {
    "country": "GB",
    "state": "London",
    "locality": "London",
    "organization": "My Organization",
    "directory-url": "https://acme-staging-v02.api.letsencrypt.org/directory"
  }
}
```

### Example: HTTP-01 Challenge

Place this file for another domain (e.g., `/etc/dnssec/domains/my-other-domain.com/conf.d/my-other-domain.com.json`):

```json
{
  "common-name": "my-other-domain.com",
  "challenge-type": "http-01",
  "email": "admin@my-other-domain.com",
  "acme": {
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "Another Organization",
    "directory-url": "https://acme-staging-v02.api.letsencrypt.org/directory"
  }
}
```

## Global settings (`$dns_base_dir/acme_config.json`)

The `lws-dht-dnssec-monitor` Global Settings form persists its settings into `$dns_base_dir/acme_config.json`; the ACME client re-reads this file before each acquisition round and applies it to every configured certificate.

| JSON Key | Description |
|---|---|
| `enabled` | Global ACME kill-switch: when `false`, no acquisitions are attempted. |
| `production` | Selects the Let's Encrypt production or staging directory URL for all certs, and which `certs/` subdirectory keys and certs are stored under. |
| `email` | Registration email applied to all certs, overriding any per-cert `email`. |
| `profile` | ACME certificate profile (e.g. `"shortlived"` for ~6-day certs, `"classic"` for 90-day) applied to all certs, overriding any per-cert `profile`. If neither is set, the CA's default profile is used. |

