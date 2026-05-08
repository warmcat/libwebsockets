# lws-webrtc

This plugin implements a shared WebRTC signaling and media transport layer within libwebsockets. It handles the WebSocket signaling, DTLS (Datagram Transport Layer Security) negotiation, SRTP (Secure Real-time Transport Protocol) keying, and RTP packetization for both audio and video streams.

## Features

- **Signaling**: Parses and generates SDP (Session Description Protocol) offer/answer exchanges over a secure WebSocket connection.
- **ICE Handling**: Processes STUN (Session Traversal Utilities for NAT) binding requests to establish connectivity without full ICE-agent complexity (acts as an ICE-lite server).
- **Security**: Sets up DTLS handshakes and extracts SRTP keys to encrypt outgoing RTP media flows.
- **Media Delivery**: Provides a C API (`lws_webrtc_send_video`, `lws_webrtc_send_audio`) to inject raw H.264/AV1 NAL units and Opus frames into the WebRTC session.
- **Packetization**: Automatically fragments H.264/AV1 bitstreams and wraps them in RTP packets suitable for browsers.
- **Feedback**: Receives and processes RTCP (RTP Control Protocol) feedback, particularly NACKs and PLIs (Picture Loss Indications), to maintain stream health.

## Usage

This protocol is usually utilized as an underlying infrastructure plugin for higher-level media handlers (like `protocol_lws_rtc_camera` or `protocol_lws_webrtc_mixer`), which feed the raw media frames into `lws_webrtc`.

It provides operations via `lws_vhost_name_to_protocol(vh, "lws-webrtc")->user`, exposing functions like:
- `lws_webrtc_send_video()`
- `lws_webrtc_send_audio()`
- `lws_webrtc_send_text()`
- Session iteration and telemetry functions.

When a client connects to the `lws-webrtc` WebSocket endpoint, the server responds with an SDP offer containing the supported codecs (H.264, AV1, Opus) and negotiates the WebRTC UDP data path transparently.
