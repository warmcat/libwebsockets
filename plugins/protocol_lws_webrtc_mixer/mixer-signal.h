/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Peer signalling messages the mixer relays to another participant.  These
 * do not depend on GStreamer, so api-test-webrtc-mixer-signal can run them.
 */

#if !defined(__LWS_MIXER_SIGNAL_H__)
#define __LWS_MIXER_SIGNAL_H__

#include <stdint.h>
#include <stddef.h>

/* participant ids are server-assigned, "u<n>" */
#define MIXER_SIGNAL_ID_MAX		24

enum mixer_control_kind {
	MIXER_CONTROL_VIDEO,
	MIXER_CONTROL_AUDIO,
};

/*
 * Everything a set_control from a peer is allowed to carry:
 *
 * {"type":"set_control","target":"<id>","kind":"video"|"audio",
 *  "id":<control id>,"val":<value>}
 *
 * The control id is a v4l2 / ALSA control id, an unsigned 32-bit integer,
 * sent as a JSON number or as a string of decimal digits (the browser keeps
 * them as strings); the value is a signed 32-bit integer.
 */
struct mixer_set_control {
	char				target[MIXER_SIGNAL_ID_MAX];
	enum mixer_control_kind		kind;
	uint32_t			id;
	int32_t				val;
};

/*
 * Parse a peer's set_control message strictly.  The whole of `in` must be
 * one flat JSON object holding each member above exactly once and nothing
 * else.  Returns 0 and fills `sc`, or -1 if the message is not exactly that.
 *
 * The message must never be relayed as received: the mixer picks the type
 * from the first "type" in the bytes, but a browser's JSON.parse() keeps the
 * last of duplicate keys, so a relayed message can be a set_control to us
 * and any other server message to its target.
 */
int
mixer_set_control_parse(const char *in, size_t len,
			struct mixer_set_control *sc);

/*
 * Compose the set_control the mixer sends to the target, from what
 * mixer_set_control_parse() accepted and the sender's server-assigned id.
 * Returns the length of the message in `buf`, or -1 if it did not fit.
 */
int
mixer_set_control_compose(char *buf, size_t len, const char *from,
			  const struct mixer_set_control *sc);

#endif
