#include <libwebsockets.h>

#include <stdlib.h>
#include <string.h>

#include "chunk.h"
#include "hash.h"

int
xip_chunker_init(struct xip_chunker *c, const uint8_t *data, size_t len,
		 const char *mime, unsigned seq)
{
	if (!data || !mime)
		return -1;

	memset(c, 0, sizeof(*c));
	c->data = data;
	c->len = len;
	c->seq = seq;
	c->n = (unsigned)((len + XIP_CHUNK_RAW - 1) / XIP_CHUNK_RAW);
	if (!c->n)
		c->n = 1;			/* empty clip = one empty chunk */
	c->next_i = 0;

	lws_strncpy(c->mime, mime, sizeof(c->mime));
	xip_hash_hex(data, len, c->hash);

	return 0;
}

int
xip_chunker_next(struct xip_chunker *c, char *buf, size_t cap, size_t *outlen)
{
	size_t piece, prefix;
	int n;

	if (c->next_i >= c->n)
		return 0;

	piece = c->len - c->off;
	if (piece > XIP_CHUNK_RAW)
		piece = XIP_CHUNK_RAW;

	n = xip_build_clip_head(buf, cap, c->mime, c->hash,
				c->seq, c->next_i, c->n);
	if (n < 0)
		return -1;
	prefix = (size_t)n;

	/*
	 * Provable bound before encoding: b64 of `piece` bytes is at most
	 * 4 * ceil(piece / 3); +4 covers closing quote, brace, NUL and the
	 * encoder's own NUL.  Keeps the write into buf evidently in-cap.
	 */
	{
		size_t b64max = (piece + 2) / 3 * 4;

		if (prefix + b64max + 4 > cap)
			return -1;
	}

	/* base64-encode straight into the frame */
	n = lws_b64_encode_string((const char *)c->data + c->off, (int)piece,
				  buf + prefix, (int)(cap - prefix - 2));
	if (n < 0)
		return -1;

	if (prefix + (size_t)n + 3 > cap)
		return -1;
	buf[prefix + (size_t)n] = '"';
	buf[prefix + (size_t)n + 1] = '}';
	buf[prefix + (size_t)n + 2] = '\0';
	*outlen = prefix + (size_t)n + 2;

	c->off += piece;
	c->next_i++;

	return 1;
}

/* ------------------------------------------------------------------ */

int
xip_reasm_add(struct xip_reasm *r, const struct xip_msg *m, size_t max_bytes)
{
	if (m->type != XIP_MSG_CLIP)
		return -1;


	if (!r->active) {
		if (m->i != 0 || m->n == 0 || m->n > 4096)
			return -1;
		/* keep r->data/r->cap (spare capacity), reset the rest */
		r->seq = m->seq;
		r->n = m->n;
		r->expect_i = 0;
		r->len = 0;
		lws_strncpy(r->mime, m->mime, sizeof(r->mime));
		lws_strncpy(r->hash, m->hash, sizeof(r->hash));
		r->active = 1;
	}

	if (m->seq != r->seq || m->n != r->n || m->i != r->expect_i ||
	    strcmp(m->hash, r->hash) || strcmp(m->mime, r->mime)) {
		xip_reasm_reset(r);
		return -1;
	}

	if (r->len + m->data_len > max_bytes) {
		xip_reasm_reset(r);
		return -1;
	}

	if (m->data_len) {
		if (r->len + m->data_len > r->cap) {
			size_t nc = r->cap ? r->cap : 2 * XIP_CHUNK_RAW;
			uint8_t *nb;

			while (nc < r->len + m->data_len)
				nc *= 2;
			nb = (uint8_t *)realloc(r->data, nc);
			if (!nb) {
				xip_reasm_reset(r);
				return -1;
			}
			r->data = nb;
			r->cap = nc;
		}
		memcpy(r->data + r->len, m->data, m->data_len);
		r->len += m->data_len;
	}

	r->expect_i++;

	if (r->expect_i == r->n) {
		char hex[XIP_HASH_HEX];

		xip_hash_hex(r->data, r->len, hex);
		if (strcmp(hex, r->hash)) {	/* integrity check */
			xip_reasm_reset(r);
			return -1;
		}
		r->active = 0;

		return 1;
	}

	return 0;
}

void
xip_reasm_reset(struct xip_reasm *r)
{
	r->active = 0;
	r->len = 0;
	r->expect_i = 0;
}

void
xip_reasm_destroy(struct xip_reasm *r)
{
	free(r->data);
	memset(r, 0, sizeof(*r));
}
