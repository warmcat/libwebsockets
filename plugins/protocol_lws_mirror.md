# lws-mirror-protocol

## Introduction

The `lws-mirror-protocol` plugin is aWebSocket protocol handler that demonstrates pub/sub or broadcast-like behavior. Devices or clients connecting to the same mirror instance will see all messages sent by any participants mirrored across all connected clients on that instance. Different mirror instances can be joined by adding a URL argument `?mirror=xxx`.

## Per-Vhost Options (PVOs)

This plugin currently does not accept any Per-Vhost Options (PVOs) for configuration. All mirror logic operates based on runtime connections and internal instance states.
