# lws-dht-dnssec-monitor

## Introduction

The `lws-dht-dnssec-monitor` plugin automates the tracking, signing, and uploading of authoritative DNS zones utilizing the core capabilities provided by `lws-dht-dnssec`.

Instead of configuring and running tools manually for every zone, this plugin operates as a background monitor that:
1. Scans a centralized JSON configuration directory (`conf-dir`) to discover which domains it manages.
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
| `conf-dir` | Absolute path to the directory containing JSON configuration files for each managed domain (e.g., `/etc/lws-certs/conf.d`). Files must end in `.json`. | **Required** |
| `zone-dir` | Absolute path to the directory where the base `.zone` files and generated cryptographic keys (`.jwk`, `.key`) are stored. | **Required** |
| `signature-duration` | The duration in seconds for which the newly generated DNSSEC signatures should remain valid. | 31536000 (1 year) |

## Domain JSON Configuration (`conf.d`)

This plugin shares the exact same JSON format parsed by the [lws-acme-client](../acme-client/protocol_lws_acme_client.md). For every `.json` file inside the `conf-dir`:

1. The monitor extracts `common-name`.
2. It looks inside `${zone-dir}/${common-name}/` for the respective `${common-name}.zone` base file.
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
            "conf-dir": "/etc/lws-certs/conf.d",
            "zone-dir": "/var/lib/dns-zones",
            "signature-duration": "2592000"
          }
        }
      ]
    }
  ]
}
```

## Directory Structure Expectations

Based on the `conf-dir` JSON files, assuming a domain `example.com`, the plugin expects the `zone-dir` to be populated like this:

```
/var/lib/dns-zones/
└── example.com/
    ├── example.com.zone            <-- The raw unsigned DNS zone file
    ├── example.com.signed          <-- (Generated automatically)
    ├── example.com.jws             <-- (Generated automatically)
    ├── example.com.zsk.private.jwk <-- (Generated automatically if missing)
    └── example.com.ksk.private.jwk <-- (Generated automatically if missing)
```

If you edit `example.com.zone`, the monitor will automatically detect the timestamp mismatch during its next periodic scan (every 5 minutes) and re-sign the zone, replacing the `.signed` and `.jws` outputs.
