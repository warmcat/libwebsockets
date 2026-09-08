# lws-webrtc-mixer

A server-side SFU/MCU: it receives each peer's depacketised audio and video
from the `lws-webrtc` plugin, decodes and composites them with GStreamer, and
sends a single mixed stream back to every participant.

## Vhost options

|pvo|default|meaning|
|---|---|---|
|`gstreamer-pipeline`|a 720p `compositor` -> `x264enc` -> `appsink` chain|the room's encode pipeline; it must contain an element named `comp` and an `appsink` named `outsink` or `outsink_h264`|
|`max-rooms`|8|how many rooms this vhost will create|

## Rooms

The room is chosen by the `?room=` URI query arg on the signalling ws
connection, eg `wss://example.com/?room=lobby`; with no arg, or an
unacceptable one, the peer lands in `default`.  Room names are restricted to
`[A-Za-z0-9_.-]` and 31 characters.

A room owns a GStreamer encode pipeline and is not destroyed until the vhost
goes away, because the media worker thread holds pointers to it (see
"Threading" below).  Since an unauthenticated peer chooses the name, the
number of rooms a vhost will create is capped by `max-rooms`; connections
that would need a new room past the cap are refused.

## Threading

The plugin runs the lws event loop thread and one detached media worker
thread over the same objects.  The ownership rule is written out in full at
`struct mixer_media_session` in `mixer-media.h` and must be respected by any
change here.  In short:

 - `struct mixer_media_session` is the only object shared between the
   threads.  It is refcounted, one reference per thread, and its
   cross-thread fields are marked `[mutex]`.

 - `struct participant`, the room's participant/chat/sound lists and
   `vhd->rooms` belong to the lws thread.  The worker never dereferences a
   participant; what it needs (the display name and stats line) is
   snapshotted into the session.

 - the GStreamer pipelines, `vhd->sessions`, `vhd->w_rooms` and the layout
   context belong to the worker.  The worker renders the layout to JSON and
   publishes the string under `room->mutex_layout`; the lws thread only ever
   copies that finished string out to broadcast it.

 - a session leaves `vhd->sessions` only on the worker thread, either from
   the `MSG_REMOVE_SESSION` the lws thread posts when the participant goes
   away, or --- if that control ring was full --- from the `orphaned` flag,
   which the worker reaps on its next tick.

## Authorization

**The signalling protocol here is unauthenticated.** Anyone who can open the
`lws-webrtc-mixer` ws protocol on the vhost can enter a room.  If that is not
what you want, gate the vhost itself (eg, with `lws-login` / a JWT cookie
mount) --- nothing in this plugin does it for you.

Within a room, the plugin does enforce the following:

 - Each participant gets an opaque, server-assigned id (`uN`).  Everything
   addressed at another participant --- `set_control`, `request_caps` --- is
   addressed by that id, which appears as `id` in the `client_list` message.
   The display name a participant chooses for itself is cosmetic and is not
   used for routing, so copying somebody else's name achieves nothing.

 - The **controller** of a room is the first participant to arrive (and, when
   it leaves, whoever is then at the head of the room).  Only the controller,
   or a participant addressing itself, may:

     - drive a participant's camera/microphone device settings with
       `set_control`
     - read a participant's enumerated device capabilities with
       `request_caps`, or receive them in the proactive
       `remote_capabilities` push

 - `chat` is only accepted from a participant that has sent `join`, since it
   enters the room's history and is replayed to everyone who joins later.

 - `request_caps` is rate limited to one per second per participant, the
   stored capability blob is capped at 2KB, and no more text is queued to a
   peer whose tx backlog is already over 256KB.

A capability blob is bytes we received from a peer and never parsed, so it is
relayed as an escaped JSON *string* in the `payload` member, which the client
parses separately.  Do not "simplify" that back into splicing the raw blob in
as JSON: a peer could then close the enclosing object and append its own
top-level keys, ie, forge any server message --- including a WebRTC `answer`
or ICE `candidate` --- to every other peer in the room.

## ICE servers (browser assets)

`assets/main.js` creates its `RTCPeerConnection` with **no** ICE servers by
default.  A STUN or TURN server is a third party that learns the visitor's
public IP address and NAT mapping on every page load that reaches `join()`, so
which one (if any) to use is deployment policy and is not hard coded here.
For a mixer that the browsers can reach directly --- the usual case, since the
mixer is the only peer --- host candidates are all that is needed.

To configure one, set `data-ice-servers` on the `<script>` tag in
`assets/index.html` that loads `main.js` (its `id` must stay `mixerScript`) to
a JSON array of `RTCIceServer` dictionaries:

```html
<script id="mixerScript" src="main.js"
	data-ice-servers='[{"urls":"stun:stun.example.com:19302"}]'></script>
```

An empty or unparseable value means no ICE servers.

## Known gaps

 - The server does not rate limit `chat`.  A joined participant is bounded
   only by `al <= 1024` per message and by the 20-entry room history, so N
   messages in still means N broadcasts out to every joined peer.  The client
   now caps what it keeps in the DOM, but the broadcast amplification is a
   server-side concern: `chat` should carry a per-participant token bucket
   (say a handful per second, with a small burst) beside the existing length
   check, in the same place `request_caps` is already rate limited.

 - The `layout` message is one shared broadcast string whose regions are
   identified only by the participant's cosmetic display name.  A client
   therefore cannot reliably tell which region is its own, and only accepts a
   name match when exactly one region carries its name.  Tagging each region
   with the opaque participant id would let the client identify its own tile
   authoritatively.
