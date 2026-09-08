# lws-mirror-protocol

## Introduction

The `lws-mirror-protocol` plugin is aWebSocket protocol handler that demonstrates pub/sub or broadcast-like behavior. Devices or clients connecting to the same mirror instance will see all messages sent by any participants mirrored across all connected clients on that instance. Different mirror instances can be joined by adding a URL argument `?mirror=xxx`.

The instance name is the only thing separating one mirror instance from another, so it must be storable whole: names longer than 29 characters are refused with the connection closed, rather than stored truncated and matched against in full (which would let a prefix of somebody else's long name join his instance).

## Per-Vhost Options (PVOs)

This plugin currently does not accept any Per-Vhost Options (PVOs) for configuration. All mirror logic operates based on runtime connections and internal instance states.
