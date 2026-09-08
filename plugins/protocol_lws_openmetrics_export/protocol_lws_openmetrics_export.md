# lws-openmetrics-export

## Introduction

The `lws-openmetrics-export` plugin provides functionality for serving system and active metrics in the OpenMetrics format, compatible with Prometheus scrapers. The plugin exports several internal protocol handlers:
1. `lws-openmetrics` - Direct HTTP listener where a scraper can natively scrape metrics out.
2. `lws-openmetrics-prox-agg` - Metrics proxy server logic local to the scraper.
3. `lws-openmetrics-prox-server` - Metrics proxy server logic handling remotely connected instances.
4. `lws-openmetrics-prox-client` - Client process connecting back to the remote proxy server to expose its internal metrics payload outwardly to the scraper securely.

## Per-Vhost Options (PVOs)

Depending on which of the four plugin protocols a Virtual Host mounts, the following PVOs are parsed during initialization (`LWS_CALLBACK_PROTOCOL_INIT`):

| PVO Name | Protocol Scope | Description |
|---|---|---|
| `proxy-side-bind-name` | `lws-openmetrics-prox-agg`<br>`lws-openmetrics-prox-server` | String name used to correctly bind the aggregator component side to its pairing server counterpart. Required to establish the routing proxy inside `lws`. |
| `ws-server-uri` | `lws-openmetrics-prox-client` | String URI representing where the remote client should establish its outgoing connection proxy. Required. |
| `metrics-proxy-path` | `lws-openmetrics-prox-client` | String path specifying how the client instance will be referenced on the proxy host aggregator side. Required. |
| `ba-secret` | `lws-openmetrics-prox-client` | String Basic Access secret used by the client for handshaking onto the proxied metrics ring server. Required. |

## Proxy-side limits

`lws-openmetrics-prox-server` applies two limits to joining ws clients:

 - the greet (the client's `metrics-proxy-path`) must be non-empty and must not
   already be in use by another joined client, since the path is the client's
   whole identity at the proxy and a duplicate would let either client answer -
   and so forge - the other's scrape.

 - a single metrics dump from one client is capped at 1MB; a client that
   exceeds it, or that never sends the final fragment of an unbounded message,
   is disconnected.

## Label sets

A histogram bucket name arrives here as an already-composed OpenMetrics label
set and is emitted between the `{` and `}` of its metric line.  Some of the
values in it come from the network (for instance the host of a connection that
followed a redirect), so before emitting it the exporter neutralises anything
structural in it - braces, backslashes, control characters, and quotes that are
not opening or closing a value.  That keeps the emitted document well-formed
whatever a bucket name contains.

It cannot, however, tell a label a peer smuggled into a value from one the
producer meant to emit; only the code composing the label set knows where a
value ends, so escaping within values has to happen there.

Neither `lws-openmetrics` nor the proxy protocols authenticate in-plugin; that
is left to the mount / vhost configuration.  Since the exported document
includes the hostname, `argv[0]` and connection-failure histograms (which
include peer addresses), an unauthenticated mount is an information disclosure.
