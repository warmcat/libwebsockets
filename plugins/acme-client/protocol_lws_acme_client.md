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
