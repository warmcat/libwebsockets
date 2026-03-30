# raw-proxy

## Introduction

The `raw-proxy` plugin behaves as an active raw-socket proxy capable of port-forwarding traffic from incoming connections directly to a specified onward destination socket natively throughout the libwebsockets event loop without bridging. It implements a non-blocking `LWS_CALLBACK_RAW_PROXY_...` flow to correctly buffer transmission arrays natively across the incoming and outgoing legs cleanly.

## Per-Vhost Options (PVOs)

This plugin requires one Per-Vhost Option (PVO) at instantiation to define the routing destination:

| PVO Name | Description |
|---|---|
| `onward` | **Required.** String encoding specifying the proxy loop destination. The required format is either `ipv4:IP_ADDR[:PORT]` or `ipv6:IP_ADDR`. |
