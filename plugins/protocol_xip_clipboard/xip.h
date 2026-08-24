/*
 * xip - cross-machine clipboard sync over libwebsockets
 *
 * Shared constants and wire-protocol definitions used by both the
 * lws protocol plugin (relay) and the client binary.
 *
 * Wire protocol v1 (one JSON object per ws TEXT message):
 *
 *   C -> S  {"t":"hello","proto":1,"token":"<hex>","name":"box"}
 *   S -> C  {"t":"welcome","id":7,"hash":"<16hex>"}     (hash optional)
 *   C -> S  {"t":"fetch"}
 *   C -> S  {"t":"clip","mime":"text/plain;charset=utf-8",
 *            "hash":"<16hex>","seq":12,"i":0,"n":3,"d":"<base64 chunk>"}
 *   S -> C  same "clip" frames, relayed to every other authenticated client
 *   S -> C  {"t":"error","reason":"auth|too-large|bad-chunk"}
 *   C -> S  {"t":"bye"}
 *
 * Payloads travel base64-encoded inside ws TEXT frames so no invalid UTF-8
 * can ever hit the websocket layer.  Chunks carry up to XIP_CHUNK_RAW bytes
 * of raw payload each.
 */

#ifndef XIP_COMMON_H
#define XIP_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XIP_PROTO_VERSION	1
#define XIP_WS_PROTOCOL		"xip"		/* ws subprotocol name */
#define XIP_RAW_PROTOCOL	"xip-raw"	/* adopted watch fds */

#define XIP_DEFAULT_PORT	9750

#define XIP_CHUNK_RAW		(48u * 1024u)	/* raw payload per chunk */
/* worst-case ws frame: b64 expansion + JSON envelope */
#define XIP_FRAME_MAX		((size_t)XIP_CHUNK_RAW / 3u * 4u + 512u)

#define XIP_MAX_BYTES_DEFAULT	(4u * 1024u * 1024u)

#define XIP_TOKEN_MAX		128
#define XIP_NAME_MAX		48
#define XIP_MIME_MAX		64
#define XIP_HASH_HEX		17		/* 16 hex digits + NUL */
#define XIP_PATH_MAX		96		/* ws URL path = group key */

#define XIP_RS			0x1e		/* record separator framing */

#define XIP_MIME_TEXT_UTF8	"text/plain;charset=utf-8"

enum xip_msg_type {
	XIP_MSG_NONE = 0,
	XIP_MSG_HELLO,
	XIP_MSG_WELCOME,
	XIP_MSG_FETCH,
	XIP_MSG_CLIP,
	XIP_MSG_ERROR,
	XIP_MSG_BYE,
};

/* parsed wire message; strings always NUL-terminated */
struct xip_msg {
	enum xip_msg_type	type;
	unsigned int		proto;
	unsigned int		id;		/* welcome: session id */
	unsigned int		seq, i, n;	/* clip chunking */
	int			have_hash;
	char			token[XIP_TOKEN_MAX + 1];
	char			name[XIP_NAME_MAX + 1];
	char			mime[XIP_MIME_MAX + 1];
	char			hash[XIP_HASH_HEX];
	char			reason[64];
	uint8_t		       *data;		/* decoded 'd' (may be NULL) */
	size_t			data_len;
};

enum xip_mode {
	XIP_MODE_CONNECT = 0,
	XIP_MODE_PUSH,
	XIP_MODE_PULL,
};

#ifdef __cplusplus
}
#endif

#endif
