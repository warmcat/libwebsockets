# lws-dht-dnssec-monitor

## Introduction

The `lws-dht-dnssec-monitor` plugin automates the tracking, signing, and uploading of authoritative DNS zones utilizing the core capabilities provided by `lws-dht-dnssec`. Instead of configuring and running tools manually for every zone, this plugin operates as a background monitor that:
1. Scans a centralized JSON configuration directory (`<base-dir>/domains`) to discover which domains it manages.
2. Checks for missing ZSK or KSK DNSSEC keys and automatically generates them if they don't exist.
3. Compares the modification timestamps of unsigned zone files against their signed counterparts to detect upstream zone edits.
4. Securely merges any active temporary ACME zones (via `dns-01`) into the main zone payload before authoritative signing.
5. Automatically signs (or re-signs) the zone if the upstream `.zone` file is newer than the `.signed` file.
6. Automatically publishes the resulting JWS payloads directly into the libwebsockets DHT for propagation.

This monitor is designed specifically to work in tandem with the [lws-acme-client](../acme-client/protocol_lws_acme_client.md) using the centralized multi-certificate management flow, allowing your LAN servers to handle thousands of domains securely.

### Web UI
The plugin includes a set of HTML/JS/CSS assets for a modern, Web-based management UI that interfaces securely with the backend JSON WS proxy using stateless `lws_jwt_auth` API verification.

These UI assets do not contain any inline scripts or styles, ensuring they are strictly Content-Security-Policy (CSP) compliant. The `assets/` directory must be manually mounted by the administrator in the `lwsws` JSON configuration if Web UI management is desired. To prevent unauthenticated users from even loading the UI files, configure the mount to use the `lws-login` interceptor protocol, requiring the `domain-admin` service grant (which aligns identically with the WebSocket backend verification).

## Prerequisite: lws-dht-dnssec

This plugin is a high-level orchestrator; it relies on `protocol_lws_dht_dnssec` being loaded into the application (via `LWS_WITH_DHT` / `LWS_WITH_AUTHORITATIVE_DNS`). Ensure that the `lws-dht-dnssec` plugin is initialized prior to this monitor (which defaults to a later initialization priority).

## Per-Vhost Options (PVOs)

To enable the plugin, attach it to your configuration and provide the following PVOs:

| PVO Name | Description | Default |
|---|---|---|
| `uds-path` | Absolute path for the Unix Domain Socket where the root process will listen for proxy UI commands. | `/var/run/lws-dnssec-monitor.sock` |
| `exe-path` | Path to the Libwebsockets host application (e.g. `lwsws`) used to spawn the root process variant. | `/usr/local/bin/lwsws` |
| `uid` | User ID to drop privileges to in the spawned process (if standard POSIX). | `0` (do not drop) |
| `gid` | Group ID to drop privileges to in the spawned process (if standard POSIX). | `0` (do not drop) |
| `signature-duration` | The duration in seconds for which the newly generated DNSSEC signatures should remain valid. | 31536000 (1 year) |
| `jwk_path` | Absolute path to the JSON Web Key (JWK) for JWT verification in the web UI. | `NULL` |
| `cookie-name` | Name of the HTTP cookie that the monitor should check for JWT sessions. | `auth_session` |

## Domain JSON Configuration (`$dns_base_dir/domains`)

This plugin shares the exact same JSON format parsed by the [lws-acme-client](../acme-client/protocol_lws_acme_client.md). For every `<domain>` directory inside `$dns_base_dir/domains`:

1. The monitor looks for `$dns_base_dir/domains/<domain>/conf.d/<domain>.json` and extracts `common-name`. It can also extract custom generator keys like `"key-type"` (e.g. `RSA` or `EC`), `"key-curve"` (e.g. `P-256` or `P-384`), and `"key-bits"` (e.g. `4096`).
2. It looks inside `$dns_base_dir/domains/<domain>/` for the respective `<domain>.zone` base file.
3. It validates whether `${common-name}.zsk.private.jwk` and `${common-name}.ksk.private.jwk` exist inside that directory. If missing, they are automatically generated honoring the provided JSON key type configuration (defaulting to EC `P-256`).

You do **not** need to declare separate configuration files for ACME vs DNSSEC. A single `example.com.json` specifying `"common-name": "example.com"` is sufficient for both plugins to target the domain effectively.

## Example `lwsws` JSON Configuration

Here is an example configuring `lwsws` to enable the monitor alongside the DHT infrastructure:

```json
{
  "vhosts": [
    {
      "name": "dnssec-management",
      "port": "443",
      "ws-protocols": [
        {
          "lws-dht-dnssec": {
             "dht-storage-path": "/var/lib/lws-dht"
          }
        },
        {
          "lws-login": {
            "status": "ok",
            "auth-server-url": "https://auth.warmcat.com/login",
            "jwt-jwk": "/var/db/lws-auth.jwk",
            "service-name": "domain-admin"
          }
        },
        {
          "lws-dht-dnssec-monitor": {
            "uds-path": "/var/lib/lws-certs/dnssec.sock",
            "uid": "1000",
            "gid": "1000",
            "signature-duration": "2592000"
          }
        }
      ],
      "mounts": [
        {
          "protocol": "lws-dht-dnssec-monitor",
          "mountpoint": "/dnssec-monitor",
          "origin": "file://_lws_ddir_/libwebsockets-test-server/lws-dht-dnssec-monitor/assets",
          "default": "index.html",
          "interceptor-path": "/lws-login"

          "extra-mimetypes": {
             ".css": "text/css"
          },
          "headers": [
            {
               "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';"
            }
          ]
        },
        {
          "mountpoint": "/lws-login",
          "origin": "callback://lws-login",
          "protocol": "lws-login"
        }
      ]
    }
  ]
}
```

## Directory Structure Expectations

Based on the global `/etc/lwsws/policy` `dns_base_dir` usage (e.g. `/var/lib/lws-certs`), assuming a domain `example.com`, the plugin expects the directory structure to be populated like this:

```
/var/lib/lws-certs/domains/
└── example.com/
    ├── conf.d/
    │   └── example.com.json            <-- Your JSON configuration here
    ├── example.com.zone            <-- The raw unsigned DNS zone file
    ├── example.com.signed          <-- (Generated automatically)
    ├── example.com.jws             <-- (Generated automatically)
    ├── example.com.zsk.private.jwk <-- (Generated automatically if missing)
    └── example.com.ksk.private.jwk <-- (Generated automatically if missing)
```

If you edit `example.com.zone`, the monitor will automatically detect the timestamp mismatch during its next periodic scan (every 5 minutes) and re-sign the zone, replacing the `.signed` and `.jws` outputs.
