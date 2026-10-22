# dumb-increment-protocol

## Introduction

The `dumb-increment-protocol` plugin is a simple WebSocket protocol handler designed primarily for testing and demonstration purposes. It demonstrates a basic incrementing number generation that is sent over a WebSocket connection using a periodic timer. It also responds to specific text commands like `"reset\n"` (to reset the counter) and `"closeme\n"` (to request connection closure).

Each connection has its own 50ms timer, which asks for a write on that connection only, so each connection receives one number every 50ms however many connections there are.

## Per-Vhost Options (PVOs)

This plugin can be configured via the following PVOs:

| PVO Name | Description |
|---|---|
| `options` | An integer value treated as a bitfield. If bit 0 is set (e.g., value `1`), the periodic timer used to send incrementing numbers is disabled out of the box, stopping the automated broadcast of numbers. |
