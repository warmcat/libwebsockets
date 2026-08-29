#ifndef XIP_PROTO_H
#define XIP_PROTO_H

#include <stddef.h>

#include <libwebsockets.h>	/* struct lejp_ctx in parser state */

#include "xip.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- message builders (return length, or -1 if cap too small) ---- */

int xip_build_hello(char *buf, size_t cap, const char *token, const char *name);
int xip_build_welcome(char *buf, size_t cap, unsigned id, const char *hash_or_null);
int xip_build_fetch(char *buf, size_t cap);
int xip_build_bye(char *buf, size_t cap);
int xip_build_error(char *buf, size_t cap, const char *reason);
/* the clip envelope up to the opening quote of the "d" payload */
int xip_build_clip_head(char *buf, size_t cap, const char *mime,
			const char *hash, unsigned seq, unsigned i,
			unsigned n);
int xip_build_clip(char *buf, size_t cap, const char *mime, const char *hash,
		   unsigned seq, unsigned i, unsigned n,
		   const char *b64, size_t b64len);

/* JSON string escaping of s into buf; returns added length or -1 */
int xip_json_escape(char *buf, size_t cap, const char *s);

/* ---- streaming parser (one JSON object per ws message) ---- */

struct xip_parser {
	struct lejp_ctx	lejp;
	struct xip_msg	msg;
	char		field[24];
	char	       *acc;		/* whole-string accumulator for "d" */
	size_t		acc_len, acc_cap;
	int		acc_active;
	int		complete;
	int		failed;
};

void xip_parser_init(struct xip_parser *p);
/* frees any allocations and readies for the next message */
void xip_parser_reset(struct xip_parser *p);

/* returns 1 = message complete (p->msg valid), 0 = need more, -1 = error */
int  xip_parser_feed(struct xip_parser *p, const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
