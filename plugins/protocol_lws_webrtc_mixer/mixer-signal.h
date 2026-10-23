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
 * Peer signalling messages the mixer relays to another participant, and the
 * checks and composition helpers for peer text it echoes to the room.  These
 * do not depend on GStreamer, so api-test-webrtc-mixer-signal can run them.
 */

#if !defined(__LWS_MIXER_SIGNAL_H__)
#define __LWS_MIXER_SIGNAL_H__

#include <libwebsockets.h>
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

/*
 * Is this peer-supplied text fit to store and send on to browsers?  It must
 * be valid, complete UTF-8 with no NUL: the mixer echoes it in ws TEXT
 * frames, and a browser fails the connection on invalid UTF-8 in one.
 */
int
mixer_text_ok(const char *s, size_t len);

/*
 * Is a peer's capabilities message fit to keep?  The mixer stores the
 * message verbatim and relays it in ws TEXT frames to each participant that
 * may control its sender, then again each time one of those joins, so it
 * must be one whole message (the caller drops the pieces of a fragmented
 * one), no bigger than `max`, hold a "controls" member and pass
 * mixer_text_ok().  Returns 0 and sets
 * *is_audio from its "kind" member, or -1 if it may not be kept.
 */
int
mixer_caps_ok(const char *in, size_t len, size_t max, int *is_audio);

/*
 * Copy a JSON string value that lws_json_simple_find() returned into a
 * bounded destination.  Returns 0 only if a non-empty value that fits and
 * passes mixer_text_ok() was copied and NUL-terminated.
 */
int
mixer_json_str(char *dest, size_t dest_len, const char *v, size_t al);

/*
 * Add one complete element `ent` of `ent_len` bytes to a JSON array being
 * composed at *p, preceded by a comma if *count is nonzero, but only if it
 * fits leaving `reserve` bytes free before `end` for closing the message.
 * Returns 0 and advances *p and *count if it was added, or -1 having written
 * nothing; it does not NUL-terminate.  So a message that runs out of room
 * ends after its last whole element and can still be closed, instead of
 * being cut partway through one (possibly inside a UTF-8 sequence).
 */
int
mixer_json_list_add(char **p, const char *end, size_t reserve, int *count,
		    const char *ent, size_t ent_len);

/*
 * A participant's grant level, when nothing authenticated it, or its
 * account holds no grant for the mixer's service
 */
#define MIXER_GRANT_NONE		(-1)

/*
 * May a participant with grant level `p_level` drive the camera and
 * microphone controls of one with `tp_level`, or read its device
 * capabilities?  `self` is nonzero when they are the same participant.
 *
 * Rights in a room come only from the authenticated account's grant level
 * for the mixer's service, IRC-owner style: a participant holding at least
 * `control_level` controls the room, but not a participant whose level is
 * higher than its own.  Nobody else may aim these at anybody but itself.
 * With no grant level configured (`control_level` MIXER_GRANT_NONE), or no
 * authenticated participants, a room has no controller at all.
 *
 * Returns nonzero if it may.
 */
int
mixer_may_control_levels(int self, int p_level, int tp_level,
			 int control_level);

/*
 * Spacing for something we do on behalf of peers that we must not do more
 * often than every `interval` however often they ask for it: rebroadcasting
 * the client_list to the room, forcing a keyframe from the room's encoder,
 * relaying a participant's chat.  Each of those used to be done once per
 * tiny message from any peer, multiplying its traffic by the room size.
 */
struct mixer_gate {
	lws_usec_t			last;	/* when we last did it, 0: never */
	lws_usec_t			interval;
};

/*
 * Returns 0 if it may be done at `now`, else how many us until it may be.
 * It doesn't record anything: call mixer_gate_mark() when you do it.
 */
lws_usec_t
mixer_gate_wait(const struct mixer_gate *g, lws_usec_t now);

static LWS_INLINE void
mixer_gate_mark(struct mixer_gate *g, lws_usec_t now)
{
	g->last = now;
}

#endif
