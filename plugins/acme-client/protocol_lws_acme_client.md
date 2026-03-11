# lws-acme-client

## Introduction

The `lws-acme-client` plugin suite implements an ACME client designed for interacting with Certificate Authorities (like Let's Encrypt). It supports both `http-01` and `dns-01` challenges natively.

Recently, the plugin was refactored to support **centralized multi-certificate management**. Instead of only managing a single certificate for the vhost it is attached to, it can now manage an arbitrary number of certificates dynamically. It reads certificate configurations from JSON files located in a specified configuration directory (`conf.d`), deploys them, and monitors them for renewal.

The ACME logic is modularized into three separate protocol plugins:
- `lws-acme-client-core`: The backend state machine orchestrating the ACME process with the Certificate Authority.
- `lws-acme-client-http`: The frontend plugin for `http-01` challenges.
- `lws-acme-client-dns`: The frontend plugin for `dns-01` challenges.

## Per-Vhost Options (PVOs)

To enable the plugin, attach it to a vhost and provide the core configuration PVOs. The plugin requires the following PVOs on the vhost:

| PVO Name | Description |
|---|---|
| `conf-dir` | Absolute path to the directory containing JSON configuration files for each managed certificate (e.g., `/etc/lws-certs/conf.d`). Files must end in `.json`. |
| `root-dir` | Absolute path to the directory where the certificates and keys will be stored (e.g., `/etc/lws-certs`). If omitted, defaults to `/etc/lws-certs`. |

## Certificate JSON Configuration

Each certificate you want to manage should have its own `.json` file in the `conf-dir`. The JSON files map directly to the configuration options for that certificate.

| JSON Key | Description |
|---|---|
| `common-name` | CSR Subject: The primary domain being certified (e.g. `example.com`). **Required** to start acquisition. |
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
| `update_script` | **(dns-01 only)** The script executed to add/remove the TXT challenge record. |

*Note: If `update_script` is present in the JSON configuration, the plugin will automatically use the `dns-01` challenge. Otherwise, it will default to `http-01`.*

### Dynamic Path Generation

The plugin dynamically generates paths for your authentication keys, certificates, and private keys. You do **not** specify `auth-path`, `cert-path`, or `key-path` in the JSON.
Instead, they are generated using the `root-dir` (from the vhost PVOs) and the `common-name` from your JSON configuration:

* **Format:** `${root-dir}/${common-name}/${common-name}-${datetime}.[jwk|crt|key]`

The plugin creates versioned files with timestamps and maintains a `-latest` symlink pointing to the most recently generated file for easy references by the web server (e.g., `${root-dir}/${common-name}/${common-name}-latest.crt`).

## Example `lwsws` JSON Configuration

Here is an example of configuring `lwsws` to enable the ACME client plugin on a secure vhost.

```json
{
  "vhosts": [
    {
      "name": "acme-manager",
      "port": "443",
      "host-ssl": "1",
      "ws-protocols": [
        {
          "lws-acme-client-dns": {
            "conf-dir": "/etc/lws-certs/conf.d",
            "root-dir": "/etc/lws-certs"
          }
        }
      ]
    }
  ]
}
```

## Example Certificate JSON Configurations (`conf.d/*.json`)

### Example: DNS-01 Challenge

Place this file in your `conf-dir` (e.g., `/etc/lws-certs/conf.d/example.com.json`):

```json
{
  "common-name": "example.com",
  "email": "admin@example.com",
  "acme": {
    "country": "GB",
    "state": "London",
    "locality": "London",
    "organization": "My Organization",
    "directory-url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "update_script": "/etc/lws-certs/update-dns.sh"
  }
}
```

### Example: HTTP-01 Challenge

Place this file in your `conf-dir` (e.g., `/etc/lws-certs/conf.d/my-other-domain.com.json`):

```json
{
  "common-name": "my-other-domain.com",
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
