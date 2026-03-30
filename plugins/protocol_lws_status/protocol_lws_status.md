# lws-status-protocol

## Introduction

The `lws-status-protocol` is a simple plugin designed for monitoring the server's status and connections. When established, it reports JSON-encoded information containing server hostname, LWS library version, the number of currently active connections grouped under the vhost, and basic telemetry like peer IPs and corresponding HTTP User-Agent strings. The plugin will push out updates sequentially as new clients connect or disconnect.

## Per-Vhost Options (PVOs)

This plugin currently does not parse or require any Per-Vhost Options (PVOs). It automatically monitors connections active on the virtual host it is associated with.
