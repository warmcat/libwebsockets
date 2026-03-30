# protocol-lws-raw-test

## Introduction

The `protocol-lws-raw-test` plugin demonstrates the `libwebsockets` capabilities for adopting and handling RAW File Descriptors (FIFOs) and RAW Socket Descriptors (such as a generic TCP socket connection rather than an HTTP/WS protocol). It acts as a basic echo endpoint to echo whatever is piped into the server's connected sockets or into the provided local filesystem FIFO pipe.

## Per-Vhost Options (PVOs)

This plugin accepts the following configuring Per-Vhost Options (PVOs):

| PVO Name | Description |
|---|---|
| `fifo-path` | **Required.** An absolute file path pointing to where the server should create and open a FIFO pipe used for Raw File Descriptor interaction. |
| `raw` | LWS Native Flag: Setting this to `"1"` marks the protocol as being configured for generalized raw socket connections, ignoring standard HTTP upgrade checks. |
