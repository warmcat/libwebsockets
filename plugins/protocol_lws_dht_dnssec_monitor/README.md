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

## Prerequisite: lws-dht-dnssec

This plugin is a high-level orchestrator; it relies on `protocol_lws_dht_dnssec` being loaded into the application (via `LWS_WITH_DHT` / `LWS_WITH_AUTHORITATIVE_DNS`). Ensure that the `lws-dht-dnssec` plugin is initialized prior to this monitor (which defaults to a later initialization priority).

## Per-Vhost Options (PVOs)

To enable the plugin, attach it to your configuration and provide the following PVOs:

| PVO Name | Description | Default |
|---|---|---|
| `base-dir` | Absolute path to the central state directory where domain configurations and zones are stored. (e.g. `/var/lib/lws-certs`) | **Required** |
| `uds-path` | Absolute path for the Unix Domain Socket where the root process will listen for proxy UI commands. | `/var/run/lws-dnssec-monitor.sock` |
| `exe-path` | Path to the Libwebsockets host application (e.g. `lwsws`) used to spawn the root process variant. | `/usr/local/bin/lwsws` |
| `uid` | User ID to drop privileges to in the spawned process (if standard POSIX). | `0` (do not drop) |
| `gid` | Group ID to drop privileges to in the spawned process (if standard POSIX). | `0` (do not drop) |
| `signature-duration` | The duration in seconds for which the newly generated DNSSEC signatures should remain valid. | 31536000 (1 year) |

## Domain JSON Configuration (`<base-dir>/domains`)

This plugin shares the exact same JSON format parsed by the [lws-acme-client](../acme-client/protocol_lws_acme_client.md). For every `.json` file inside `<base-dir>/domains`:

1. The monitor extracts `common-name`.
2. It looks inside `<base-dir>/domains/${common-name}/dns/` for the respective `${common-name}.zone` base file.
3. It validates whether `${common-name}.zsk.private.jwk` and `${common-name}.ksk.private.jwk` exist inside that directory.

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
          "lws-dht-dnssec-monitor": {
            "base-dir": "/var/lib/lws-certs",
            "uds-path": "/var/lib/lws-certs/dnssec.sock",
            "uid": "1000",
            "gid": "1000",
            "signature-duration": "2592000"
          }
        }
      ]
    }
  ]
}
```

## Directory Structure Expectations

Based on the `<base-dir>` usage, assuming a domain `example.com`, the plugin expects the directory structure to be populated like this:

```
/var/lib/lws-certs/domains/
├── example.com.json                <-- Your JSON configuration here
└── example.com/
    └── dns/
        ├── example.com.zone            <-- The raw unsigned DNS zone file
        ├── example.com.signed          <-- (Generated automatically)
        ├── example.com.jws             <-- (Generated automatically)
        ├── example.com.zsk.private.jwk <-- (Generated automatically if missing)
        └── example.com.ksk.private.jwk <-- (Generated automatically if missing)
```

If you edit `example.com.zone`, the monitor will automatically detect the timestamp mismatch during its next periodic scan (every 5 minutes) and re-sign the zone, replacing the `.signed` and `.jws` outputs.
