# lws auth dns plugin

## Introduction

The `protocol_lws_auth_dns` plugin provides an authoritative DNS server implementation for `libwebsockets` using the existing DNSSEC and `auth-dns` library components. This plugin allows an application to serve parsed DNS `.zone` files over both UDP and TCP.

When the plugin is initialized on a vhost with the `raw-skt` role and the `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG` option, it listens on the configured port (typically 53 or 5353) and handles incoming raw payloads passing as DNS queries.

The plugin scans the specified directory for `.zone` files, parses them into memory using `lws_auth_dns_parse_zone_buf`, and matches incoming `QNAME`, `QTYPE`, and `QCLASS`. If a query requests a record that is known (present in the loaded zones), it formulates a valid `NOERROR` DNS protocol response incorporating the authoritative records. If the domain name is entirely unknown, the server responds immediately with `REFUSED` according to authoritative namserver conventions, fulfilling resolvers that query it.

## Per-vhost Options (PVO)

The plugin behavior is controlled by providing the following Protocol Virtual Objects (PVOs) when initializing the vhost:

| PVO Name   | Description |
| ---------- | ----------- |
| `zone-dir` | Mandatory. Specifies the absolute or relative directory path containing the `.zone` authoritative DNS files to parse and serve. The plugin will scan this directory once during vhost initialization and load valid DNS zone files matching the `*.zone` extension. |
