# lws-status-protocol

## Introduction

The `lws-status-protocol` is a simple plugin designed for monitoring the server's status and connections. When established, it reports JSON-encoded information containing server hostname, LWS library version, the number of currently active connections grouped under the vhost, and basic telemetry like peer IPs and corresponding HTTP User-Agent strings. The plugin will push out updates sequentially as new clients connect or disconnect.

This is by design a demonstration: every viewer, without any authentication, sees the IP address and User-Agent of every connection to the protocol on the vhost.  Don't enable it on a vhost where that is not acceptable.

The User-Agent is the peer's to choose.  If it is not valid UTF-8, its non-ASCII bytes are replaced with `?`, and it is JSON-escaped and, if its escaped form is longer than 383 bytes, cut short at a character boundary, so that the JSON sent to other viewers is always valid UTF-8 and complete.

## Per-Vhost Options (PVOs)

This plugin currently does not parse or require any Per-Vhost Options (PVOs). It automatically monitors connections active on the virtual host it is associated with.
