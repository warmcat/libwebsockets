# client-loopback-test

## Introduction

The `client-loopback-test` is a plugin facilitating testing of WebSocket client functionality. It acts over HTTP to initiate a looped-back WebSocket client connection using `lws_client_connect_via_info` directly pointing to its own WebSocket protocol handler. The URL mount is typically set to `/c`, giving callers a way to make subsequent `ws://` or `wss://` URI loopback connection attempts.

## Per-Vhost Options (PVOs)

This plugin evaluates URL queries instead of instantiation-time Per-Vhost Options (PVOs). There are no PVOs defined for this plugin.
