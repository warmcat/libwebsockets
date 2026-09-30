# lws-dht-dnssec-monitor

## Introduction

The `lws-dht-dnssec-monitor` plugin automates the tracking, signing, and uploading of authoritative DNS zones utilizing the core capabilities provided by `lws-dht-dnssec`. Instead of configuring and running tools manually for every zone, this plugin operates as a background monitor that:
1. Scans a centralized JSON configuration directory (`<base-dir>/domains`) to discover which domains it manages.
2. Checks for missing ZSK or KSK DNSSEC keys and automatically generates them if they don't exist.
3. Compares the modification timestamps of unsigned zone files against their signed counterparts to detect upstream zone edits.
4. Securely merges any active temporary ACME zones (via `dns-01`) into the main zone payload before authoritative signing.
5. Automatically signs (or re-signs) the zone if the upstream `.zone` file is newer than the `.signed` file, or if the DHT-detected external addresses its `${EXTIP4}` / `${EXTIP6}` records resolve to have changed (see below).
6. Automatically publishes the resulting JWS payloads directly into the libwebsockets DHT for propagation.

This monitor is designed specifically to work in tandem with the [lws-acme-client](../acme-client/protocol_lws_acme_client.md) using the centralized multi-certificate management flow, allowing your LAN servers to handle thousands of domains securely.

### Web UI
The plugin includes a set of HTML/JS/CSS assets for a modern, Web-based management UI that interfaces securely with the backend JSON WS proxy using stateless `lws_jwt_auth` API verification.

These UI assets do not contain any inline scripts or styles, ensuring they are strictly Content-Security-Policy (CSP) compliant. The `assets/` directory must be manually mounted by the administrator in the `lwsws` JSON configuration if Web UI management is desired. To prevent unauthenticated users from even loading the UI files, configure the mount to use the `lws-login` interceptor protocol, requiring the `domain-admin` service grant (which aligns identically with the WebSocket backend verification).

#### Force cert reissue

Each row of the TLS tab's "Cross-Domain TLS Certificates" table ends with a
"Force reissue" button, which has the ACME client reissue that row's
certificate now, however much validity it has left, for example to move it
onto a newly chosen certificate profile at once rather than at the next
renewal.  The buttons are only enabled while the "ACME Enabled" checkbox of the
certificate's toplevel domain is set.  The ACME client runs in the lwsws
process rather than the root process, so the proxy answers this request itself,
checking the row's FQDN lies inside its domain and sending
`{"acme":"force-reissue","domain":"...","common-name":"..."}` on SMD class
`LWSSMDCL_CERTS`.  The usual backoff after failed acquisitions still applies,
and Let's Encrypt allows only 5 identical certificates per week.

#### Registrar DS record

For the domain's DNSSEC chain to reach the root, the parent zone must publish
a DS record for the domain's KSK, which you give your registrar.  The domain's
header's Registrar row shows the DS fields registrars ask for, each with a
Copy button: the key tag, algorithm, digest type and digest.  The root process
computes them from the KSK with `lws_auth_dns_key_records()`, the same way the
signer does when it logs the DS.  They are all public.

#### Registry WHOIS

Each domain's header shows the registry's expiry date, the nameservers the
registry delegates to, and whether the registry says the delegation is
DNSSEC-signed, from `<base-dir>/domains/<domain>/whois.json`.  Whois servers
are untrusted, so the lwsws process does the queries, not the root process:
about 20s after startup, and then every 10 minutes, it looks for a domain whose
`whois.json` is missing or more than a day old, and queries the registry
(found through whois.iana.org), one domain at a time.  A domain is not queried
again within an hour, whatever the result.  The results go to the root process
over the UDS IPC as canonical JSON in an authenticated `update_whois` request,
and the root process validates them again before writing `whois.json`.

#### Server IP Inventory

The Domains tab also carries a Server IP Inventory table below the domain list. It lists unique network interfaces rather than DNS names: a name binding both an A and an AAAA record is evidence that those two addresses live on the same interface of one server, so addresses are grouped into interfaces by the names that bind them together, and every name pointing at any of an interface's addresses is listed once as evidence on that row instead of once per name. Each name links into the zonefile editor for the zonefile(s) it was found in, and carries any LOC record written for it.

Records written against the DHT-detected dynamic addresses (`${EXTIP4}` / `${EXTIP6}`) resolve to the currently detected external addresses, which the UI already learns from the `ext-ips` distribution and passes with the inventory request, with the configured IPv6 suffix applied exactly as the zonefile editor previews `${EXTIP6}`. Until an address is detected, the records still group together on the `${EXTIP4}` / `${EXTIP6}` macro text.

A world map between the domain list and the inventory places one abstract server icon per interface. Interfaces with a LOC record are placed at its exact coordinates; the others are estimated at the centroid of their address's country, resolved through dbip-country CSVs that the monitor's root process downloads monthly from [sapics/ip-location-db](https://github.com/sapics/ip-location-db) into `<base-dir>/geo` (and re-downloads when older than 30 days). Scrolling and dragging pan the map, pinching (or ctrl+scroll, or the corner +/- buttons) zooms it, and clicking a marker opens the zonefile editor of its first name. The map outline is vendored Natural Earth 1:110m land TopoJSON (`assets/land-110m.json`, public domain via the world-atlas packaging); the projection is a few lines of Web Mercator in `monitor.js` with no third-party JavaScript.

Each address tracks what kinds of names point at it. If an address is only referred to by NS records (delegation glue), it is marked "NS only", since it may not be your infrastructure; if the same address is also bound to host names in the same or another zonefile, the more specific records indicate the nameserver is your infrastructure.

The table is served from an ephemeral sqlite3 cache (`<base-dir>/ip-inventory.sqlite3`) holding a row for every record parsed from every zonefile. The cache is regenerated by rescanning only zonefiles whose mtime or size changed since they were last scanned, so the table stays cheap even with a large number of zonefiles. This requires lws to be built with `-DLWS_WITH_SQLITE3=1`; without it, the inventory answers an explicit "built without sqlite3 support" error and the rest of the UI is unaffected.

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
    ├── example.com.zone.signed.extip <-- (Generated for zones using ${EXTIP4} / ${EXTIP6})
    ├── whois.json                  <-- (Registry whois, refreshed daily)
    ├── example.com.jws             <-- (Generated automatically)
    ├── example.com.zsk.private.jwk <-- (Generated automatically if missing)
    └── example.com.ksk.private.jwk <-- (Generated automatically if missing)
```

A domain created from the UI starts with an empty `example.com.zone`.  When
the zone is empty, the editor fills in a starter zone to edit (an SOA, two
nameservers, and example `@` records on the documentation addresses), but
nothing is written, and so signed and published, until you save it.  Creating
a domain that already exists leaves its zone and configuration alone.

If you edit `example.com.zone`, the monitor will automatically detect the timestamp mismatch during its next periodic scan (every 5 minutes) and re-sign the zone, replacing the `.signed` and `.jws` outputs.

## Dynamic external addresses

Zonefile records can use `${EXTIP4}` / `${EXTIP6}` for the host's external addresses, as detected by the DHT. The DHT runs in the unprivileged lwsws process, while zones are signed by the spawned root monitor process; lwsws forwards every change of the detected addresses to the root process over the root process' stdin pipe, which is otherwise only used to hand it the IPC auth token at spawn.

`${EXTIP6}` has the IPv6 suffix set in the UI applied, as the zonefile editor previews it: the suffix is one hex group that replaces the last 16 bits of the detected address. With no suffix set, the address is used as the DHT detected it.

After signing a zone that uses either macro, the monitor records the values it signed with in `<domain>.zone.signed.extip`. Whenever the detected addresses or the suffix change, including after a restart, only zones whose record differs are re-signed and so republished. A zone using the macros is not signed at all until at least one external address is known, since that would publish it without those records; if only one family has been detected, the other waits up to a minute to appear before the zone is signed without it (the `${EXTIP6}` lines are then dropped, as the signer documents).
