# lws auth dns plugin

## Introduction

The `protocol_lws_auth_dns` plugin provides an authoritative DNS server implementation for `libwebsockets` using the existing DNSSEC and `auth-dns` library components. This plugin allows an application to serve parsed DNS `.zone` files over both UDP and TCP.

When the plugin is initialized on a vhost with the `raw-skt` role and the `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG` option, it listens on the configured port (typically 53, determined by the `port` setting of the encompassing vhost configuration) and handles incoming raw payloads passing as DNS queries.

The plugin scans the specified directory for `.zone` files, parses them into memory using `lws_auth_dns_parse_zone_buf`, and matches incoming `QNAME`, `QTYPE`, and `QCLASS`. If a query requests a record that is known (present in the loaded zones), it formulates a valid `NOERROR` DNS protocol response incorporating the authoritative records. If the domain name is entirely unknown, the server responds immediately with `REFUSED` according to authoritative namserver conventions, fulfilling resolvers that query it.

## Per-vhost Options (PVO)

The plugin behavior is controlled by providing the following Per-Vhost Options (PVOs) when initializing the vhost:

| PVO Name   | Description |
| ---------- | ----------- |
| `zone-dir` | Optional if `dht-zone-dir` is provided. Specifies the absolute or relative directory path containing the `.zone` authoritative DNS files to parse and serve. The plugin will scan this directory once during vhost initialization and load valid DNS zone files matching the `*.zone` extension. |
| `dht-zone-dir` | Optional. Specifies a directory to cache securely fetched DHT zone files. If a DNS query does not match an existing zone, and this PVO is active alongside the `lws-dht-dnssec` plugin, the `lws-auth-dns` plugin will pause processing the query, dynamically lookup and validate the corresponding JWS-signed zonefile via the DHT, cache it here, load it into memory, and resume processing the suspended DNS queries. |
| `dht-max-pending` | Optional. Limits the number of pending network DNS queries (UDP and TCP) queued per vhost waiting for a DHT fetch to resolve. Defaults to 16. When the limit is reached, entirely new queries requiring a DHT fetch are immediately rejected with a `REFUSED` response to prevent memory exhaustion DoS attacks. |

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
				"dht-zone-dir": "/tmp/lws-dht-zones",
				"dht-max-pending": "16"
			}
		}]
	}]
}
```
