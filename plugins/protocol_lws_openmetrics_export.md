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
