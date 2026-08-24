#ifndef XIP_CHUNK_H
#define XIP_CHUNK_H

#include <stddef.h>

#include "proto.h"
#include "xip.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- sender side: split payload into ready-to-send clip frames ---- */

struct xip_chunker {
	const uint8_t *data;
	size_t		len, off;
	unsigned	seq, n, next_i;
	char		mime[XIP_MIME_MAX + 1];
	char		hash[XIP_HASH_HEX];
};

/* returns 0 ok, -1 on bad args */
int xip_chunker_init(struct xip_chunker *c, const uint8_t *data, size_t len,
		     const char *mime, unsigned seq);

/* 1 = produced a frame (buf, *outlen), 0 = done, -1 = error */
int xip_chunker_next(struct xip_chunker *c, char *buf, size_t cap,
		     size_t *outlen);

/* ---- receiver side: reassemble chunked clips ---- */

struct xip_reasm {
	uint8_t       *data;			/* reassembled payload */
	size_t		len, cap;
	unsigned	seq, n, expect_i;
	char		mime[XIP_MIME_MAX + 1];
	char		hash[XIP_HASH_HEX];
	int		active;
};

/*
 * returns 1 = complete (r->data/r->len/mime/hash valid), 0 = need more
 * chunks, -1 = protocol violation / oversize (reasm resets itself).
 */
int xip_reasm_add(struct xip_reasm *r, const struct xip_msg *m,
		  size_t max_bytes);

/* drop any partial state (keeps allocated capacity) */
void xip_reasm_reset(struct xip_reasm *r);
void xip_reasm_destroy(struct xip_reasm *r);

#ifdef __cplusplus
}
#endif

#endif
