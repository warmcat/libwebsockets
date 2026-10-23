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

## Vhost options

|pvo|default|meaning|
|---|---|---|
|`external-ip`|none|the address offered in our ICE candidates, and the self-signed certificate's SAN|
|`udp-port`|7682|the UDP port media and DTLS use|
|`max-sessions`|64|how many server ws sessions the vhost holds at once, 1 - 65535|
|`max-sessions-per-host`|16|how many of those may come from one peer host (an IPv4 address or an IPv6 /64, see `lws_get_peer_host_key()`), 1 - 65535|

## Sessions are capped

Anyone who can open the ws can have a session, and each one holds a media
object, a DTLS context once it makes an offer, and, once media flows to it,
a tx pacer thread.  So past `max-sessions` overall, or `max-sessions-per-host`
from one host, the ws upgrade is refused (in
`LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION`, and again at `ESTABLISHED` for
anything that came between).  Client sessions, the ones we make, are not
counted.  The protocols built on this one (the mixer, rtc_camera) pass these
callbacks through, so the caps apply to them too: set the pvos on the
`lws-webrtc` protocol of their vhost.

A session's tx pacer, and its thread (with a 128KB stack, see
`lws_txp_create()`), is only made when the first media packet is sent to the
peer, so sessions that never get as far as media cost no thread.  If the
thread can't be made, packets are sent unpaced.

The log of a session's setup that the mixer's `request_debug_log` returns is
only allocated when something is logged, holds at most 8KB, and is dropped
once the DTLS handshake completes.
