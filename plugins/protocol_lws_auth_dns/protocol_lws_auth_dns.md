# lws auth dns plugin

## Introduction

The `protocol_lws_auth_dns` plugin provides an authoritative DNS server implementation for `libwebsockets` using the existing DNSSEC and `auth-dns` library components. This plugin allows an application to serve parsed DNS `.zone` files over both UDP and TCP.

When the plugin is initialized on a vhost with the `raw-skt` role and the `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG` option, it listens on the configured port (typically 53, determined by the `port` setting of the encompassing vhost configuration) and handles incoming raw payloads passing as DNS queries.

The plugin scans the specified directory for `.zone` files, parses them into memory using `lws_auth_dns_parse_zone_buf`, and matches incoming `QNAME`, `QTYPE`, and `QCLASS`. If a query requests a record that is known (present in the loaded zones), it formulates a valid `NOERROR` DNS protocol response incorporating the authoritative records. If the domain name is entirely unknown, the server responds immediately with `REFUSED` according to authoritative namserver conventions, fulfilling resolvers that query it.

## Scalability and Caching

To efficiently serve high volumes of requests without ballooning memory usage, the `lws-auth-dns` plugin employs a bounded, in-memory LRU (Least Recently Used) cache for loaded DNS zones. When integrated with the `lws-dht-dnssec` plugin for resolving unknown zones dynamically over the DHT, the plugin relies natively on the DHT's hashed storage for long-term disk cache, only pulling currently active zones into memory.

Memory cleanup is robust and self-sustaining:
- **LRU Eviction**: Bounded limit managed by the `cache-max-zones` PVO (defaults to 1000). When exceeded, the oldest unused zones are smoothly removed from memory.
- **Time/Logic Eviction**: A periodic timer continuously checks zone expiry. Zones logically expiring due to their SOA `TTL` or their DNSSEC `RRSIG` validity dates are actively purged from memory.

## Negative Answers and NSEC3

When a query with the DNSSEC `DO` bit set does not match a record in a served
zone, the authority section carries the zone `SOA` and, per RFC 5155 §7.2, only
the NSEC3 RRs that actually deny the name:

 - the NSEC3 matching the *closest encloser*,
 - the NSEC3 *covering* the next closer name, and
 - the NSEC3 *covering* the wildcard at the closest encloser,

deduplicated (one NSEC3 often covers two of these), each followed by its
`RRSIG`.  For a `NODATA` answer — the name exists but the type does not — only
the NSEC3 matching the queried name is returned.  Anything more would hand
every querier NSEC3 hashes it did not ask about, ie, offline zone walking,
which is the thing NSEC3 exists to prevent.

The owner hashes are recomputed per query from the zone's `NSEC3PARAM`, so
zones whose iteration count exceeds 150 (RFC 5155 §A.1's useful maximum; RFC
9276 deprecates anything above 0) are not proved at all rather than allowed to
spend the event loop thread's time.  Zones signed with a hash algorithm other
than SHA-1, or with no NSEC3 records, likewise get an `SOA`-only authority
section.  If the proof does not fit in the querier's advertised EDNS0 buffer
the `TC` bit is set rather than a partial (and therefore useless) proof
emitted.

Note there is no response rate limiting (RRL/SLIP) or DNS cookie (RFC 7873)
support in the plugin yet, so a DNSSEC negative answer remains a usable UDP
amplification vector towards a spoofed source; front the service with a
rate limiter if it is exposed.

## Per-vhost Options (PVO)

The plugin behavior is controlled by providing the following Per-Vhost Options (PVOs) when initializing the vhost:

| PVO Name   | Description |
| ---------- | ----------- |
| `zone-dir` | **Required.** Specifies the absolute or relative directory path containing the `.zone` authoritative DNS files to parse and serve. The plugin will scan this directory once during vhost initialization and load valid DNS zone files matching the `*.zone` extension. If this PVO is missing, the protocol refuses to start — there is no default (an earlier default of shared `/tmp/lws-auth-dns` allowed any local user to inject authoritative zones and was removed for security reasons). |
| `cache-max-zones` | Optional. Limits the maximum number of authoritative zones to keep in the active memory LRU cache. Defaults to 1000. When reached, older (less recently queried) zones are evicted and freed from memory. |
| `dht-max-pending` | Optional. Limits the number of pending network DNS queries (UDP and TCP) queued per vhost waiting for a DHT fetch to resolve. This counts *distinct domains*; there are additional fixed limits of 16 distinct domains and 64 queries per source address, and 1024 pending queries in total. Defaults to 128. When any limit is reached, entirely new queries requiring a DHT fetch are immediately rejected with a `REFUSED` response to prevent memory exhaustion DoS attacks. |
| `dnsbl` | Optional. A comma-separated list of DNSBL domains (e.g. `zen.spamhaus.org,test.local`). When provided, the plugin performs asynchronous validation of both the queried domain and the target IPs against all configured DNSBL servers before returning the authoritative DNS response. Positive responses (drops) are cached for 5 minutes. |

The DNSBL lookups are deduplicated by queried name while they are in flight
(a repeat of a name whose lookups have not completed is dropped rather than
issuing a second set of up to 16 targets × 16 DNSBLs outbound queries), and at
most 256 queries may be suspended on DNSBL lookups at a time; beyond that
further queries are answered `REFUSED`.

## Zone Directory Trust Policy

Because everything loaded from the zone dir is served as **authoritative** data, and expired / evicted zone entries are unlinked from it, the directory's contents must be exclusively controlled by the account the service runs as.  At initialization the plugin fails closed (refuses to start) unless the `zone-dir`:

 - exists and is a real directory (not a symlink to one),
 - is owned by the service's effective uid, and
 - is not group- or world-writable.

Individual zone files are additionally only admitted from the scan when they

 - are named in the decorated `<origin>_<ttl-expiry>_<sig-expiry>_<serial>.zone`
   shape the plugin itself labels its cache entries with, with the origin part
   a presentation-format DNS name (labels of `[A-Za-z0-9-]`, no underscores,
   since `_` separates the decorator fields),
 - are regular files owned by the service's effective uid and not symlinks, and
 - are not group- or world-writable.

Files that do not meet these conditions are ignored with a notice in the log; deploy provisioning tools should create the directory mode `0755` (or stricter) and zone files mode `0644` (or stricter) owned by the service account.

## Logging

A DNS label may contain any octet, including newlines and terminal escapes, so
every wire-derived name is passed through `lws_json_purify()` before it reaches
a log line.  Per-query lines are at `info` level, so an unauthenticated peer
cannot drive the operator's log volume at the default `notice` level.

## Example `lwsws` Configuration

The following is an example of how to enable and configure the plugin on a vhost using `lwsws` JSON configuration (note that the vhost itself defines the listening port, typically port 53 for DNS):

```json
{
	"vhosts": [{
		"name": "auth-dns-vhost",
		"port": 53,
		"ciphers": "",
		"listen-accept-role": "raw-skt",
		"listen-accept-protocol": "lws-auth-dns",
		"ws-protocols": [{
			"protocol-lws-auth-dns": {
				"status": "ok",
				"zone-dir": "/etc/lws-auth-dns/zones",
				"cache-max-zones": "1000",
				"dht-max-pending": "16",
				"dnsbl": "zen.spamhaus.org,test.local"
			}
		}]
	}]
}
```
