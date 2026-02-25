# WebRTC Video Conferencing Mixer Plugin (`lws-webrtc-mixer`)

This protocol implements a WebRTC video conferencing mixer. It works in conjunction with the core WebRTC protocol (`protocol_lws_webrtc`) to provide a multi-participant conferencing experience by compositing video streams and mixing audio on the server side into a single stream for each participant.

## Relationship to `protocol_lws_webrtc`

The WebRTC mixer plugin relies heavily on `protocol_lws_webrtc`. While `protocol_lws_webrtc` handles the low-level SDP signaling, ICE candidate gathering, and fundamental RTP/RTCP transport, the `lws-webrtc-mixer` protocol handles the high-level logic of mixing multiple WebRTC streams together. The `lws-webrtc` protocol must be loaded alongside `lws-webrtc-mixer` to function properly.

## Asset and Sound Installation

The user interface for the WebRTC mixer (HTML, CSS, JS) and the associated sound effects (WAV files) are located in the `assets/` and `sounds/` subdirectories of the plugin. 

When the project is installed (e.g., via `make install`), these assets are typically installed into the global shared data directory under `libwebsockets-test-server/lws-webrtc-mixer`.

These assets are made available to clients by defining a standard lws mount in your `lwsws` configuration that points to this directory.

## Per-Vhost Options (PVOs)

The WebRTC plugins support the following Per-Vhost Options (PVOs) to configure their behavior:

| Plugin | PVO Name | Description | Example |
|---|---|---|---|
| `lws-webrtc` | `external-ip` | The external IPv4 address of the server used for ICE candidates. This is required for clients outside the local network to establish WebRTC connections. | `"10.199.0.10"` |
| `lws-webrtc` | `udp-port` | The UDP port used for the WebRTC transport. | `"1234"` |
| `lws-webrtc` | `lws-webrtc-ops` | Handled internally via code to provide the operational struct linking the core WebRTC protocol to higher-level protocols. | - |

*(Note: The `lws-webrtc-mixer` and `lws-webrtc-udp` plugins currently do not require specific PVOs of their own, but expect the base `lws-webrtc` plugin to be configured).*

## Example `lwsws` Configuration Fragment

The following is an example configuration fragment for `lwsws` that enables the required WebRTC protocols and mounts the mixer assets:

```json
"ws-protocols": [{
                        "lws-webrtc": {
                                "status": "ok",
                                "external-ip": "10.199.0.10"
                        },
                        "lws-webrtc-udp": {
                                "status": "ok"
                        },
                        "lws-webrtc-mixer": {
                                "status": "ok"
                        }
}],
"mounts": [{
                }, {
                        "mountpoint":   "/mixer",
                        "origin":       "file://_lws_ddir_/libwebsockets-test-server/lws-webrtc-mixer",
                        "default": "index.html",
                        "headers": [{
                                "content-security-policy": "default-src 'none'; img-src 'self' data: https://scan.coverity.com https://bestpractices.coreinfrastructure.org https://img.shields.io ; script-src 'self' 'unsafe-inline'; media-src 'unsafe-inline'; font-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss://libwebsockets.org:443; frame-ancestors 'none'; base-uri 'none'; form-action 'self';",
                                "permissions-policy": "geolocation=(),microphone=(self),camera=(self),display-capture=(),document-domain=(),execution-while-not-rendered=(),execution-while-out-of-viewport=(),identity-credentials-get=(),local-fonts=(),payment=(),serial=(),usb=(),speaker-selection=()"
                        }],
                        "keepalive-timeout": "999"
                }
]}
```
