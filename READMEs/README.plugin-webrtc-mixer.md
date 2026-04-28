# WebRTC Video Conferencing Mixer Plugin (`lws-webrtc-mixer`)

This protocol implements a WebRTC video conferencing mixer. It works in conjunction with the core WebRTC protocol (`protocol_lws_webrtc`) to provide a multi-participant conferencing experience by compositing video streams and mixing audio on the server side into a single stream for each participant.

## Relationship to `protocol_lws_webrtc`

The WebRTC mixer plugin relies heavily on `protocol_lws_webrtc`. While `protocol_lws_webrtc` handles the low-level SDP signaling, ICE candidate gathering, and fundamental RTP/RTCP transport, the `lws-webrtc-mixer` protocol handles the high-level logic of mixing multiple WebRTC streams together. The `lws-webrtc` protocol must be loaded alongside `lws-webrtc-mixer` to function properly.

## GStreamer Video Composition

Video decoding, composition, and encoding (H.264/AV1) are handled entirely by GStreamer. This enables hardware-accelerated media pipelines that drastically reduce CPU usage and memory footprint compared to software-based transcoding.

### Build Requirements
To compile the mixer plugin, you must enable `LWS_WITH_WEBRTC_MIXER=ON` in CMake and install the GStreamer development headers:
- **Debian/Ubuntu**: `sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev`
- **Fedora/RHEL**: `sudo dnf install gstreamer1-devel gstreamer1-plugins-base-devel`

### Runtime Requirements
At runtime, GStreamer relies on platform-specific plugins to utilize hardware acceleration for compositing and encoding. Ensure you have the appropriate GStreamer packages installed for your system.

* **Intel (VAAPI)**: Requires the VAAPI plugins.
  - Debian/Ubuntu: `sudo apt install gstreamer1.0-vaapi intel-media-va-driver-non-free`
  - *Example PVO*: `"vaapicompositor name=comp ! queue ! vaapih264enc byte-stream=true config-interval=1 ! appsink name=outsink sync=false"`

* **Rockchip (MPP)**: Requires Rockchip MPP plugins.
  - *Example PVO*: `"mppcompositor name=comp ! queue ! mpph264enc byte-stream=true config-interval=1 ! appsink name=outsink sync=false"`

* **Software Fallback**: If no hardware acceleration is available, standard plugins are used.
  - Debian/Ubuntu: `sudo apt install gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly`
  - *Example PVO*: `"compositor name=comp background=black ! videoconvert ! videoscale ! video/x-raw,width=1280,height=720,framerate=25/1,format=I420 ! x264enc tune=zerolatency speed-preset=ultrafast ! h264parse config-interval=1 ! video/x-h264,stream-format=byte-stream,alignment=au ! appsink name=outsink sync=false async=false"`

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
| `lws-webrtc-mixer` | `gstreamer-pipeline` | The GStreamer pipeline string used to compose and encode the video. The pipeline *must* include a compositor element named `comp` and an appsink named `outsink` (or `outsink_h264` / `outsink_av1`). **IMPORTANT**: To ensure WebRTC compatibility and support for clients joining mid-session, your encoder should be configured for Annex-B (`byte-stream=true`) and periodic keyframe headers (`config-interval=1`). | `"vaapicompositor name=comp ! vaapih264enc byte-stream=true config-interval=1 ! appsink name=outsink sync=false"` |

*(Note: The `lws-webrtc-udp` plugin currently does not require specific PVOs of its own, but expects the base `lws-webrtc` plugin to be configured).*

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
                                "status": "ok",
                                "gstreamer-pipeline": "compositor name=comp background=black ! videoconvert ! videoscale ! video/x-raw,width=1280,height=720,framerate=25/1,format=I420 ! x264enc tune=zerolatency speed-preset=ultrafast ! h264parse config-interval=1 ! video/x-h264,stream-format=byte-stream,alignment=au ! appsink name=outsink sync=false async=false"
                        }
}],
"mounts": [{
                }, {
                        "mountpoint":   "/mixer",
                        "origin":       "file://_lws_ddir_/libwebsockets-test-server/lws-webrtc-mixer",
                        "default": "index.html",
                        "headers": [{
                                "content-security-policy": "default-src 'none'; img-src 'self' data: https://scan.coverity.com ; script-src 'self' 'unsafe-inline'; media-src 'unsafe-inline'; font-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss://libwebsockets.org:443; frame-ancestors 'none'; base-uri 'none'; form-action 'self';",
                                "permissions-policy": "geolocation=(),microphone=(self),camera=(self),display-capture=(),document-domain=(),execution-while-not-rendered=(),execution-while-out-of-viewport=(),identity-credentials-get=(),local-fonts=(),payment=(),serial=(),usb=(),speaker-selection=()"
                        }],
                        "keepalive-timeout": "999"
                }
]}
```
