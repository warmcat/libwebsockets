/*
 * Copyright (c) 2009-2011 by Juliusz Chroboczek
 * Minor changes (c) 2018 Gwiz <gwiz2009@gmail.com>
 *   Added handler for implied port & hook for dhtdigg
 * Copyright (c) 2026 Andy Green <andy@warmcat.com>
 *   Adaptation for lws, cleaning, modernization
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "private-lib-misc-dht.h"

int
lws_dht_hash_validate(int type, int len)
{
	switch (type) {
	case LWS_DHT_HASH_TYPE_SHA1:
		return len == 20;
	case LWS_DHT_HASH_TYPE_SHA256:
		return len == 32;
	case LWS_DHT_HASH_TYPE_SHA512:
		return len == 64;
	case LWS_DHT_HASH_TYPE_BLAKE3:
		return len == 32;
	}

	return 0;
}

LWS_VISIBLE lws_dht_hash_t *
lws_dht_hash_create(int type, int len, const uint8_t *data)
{
	lws_dht_hash_t *h;

	if (!lws_dht_hash_validate(type, len)) {
		lwsl_dht_warn("%s: invalid hash type %d len %d\n", __func__, type, len);

		return NULL;
	}

	h = lws_malloc(sizeof(*h) + (size_t)len, __func__);
	if (!h)
		return NULL;

	h->type = (uint8_t)type;
	h->len = (uint8_t)len;
	if (data)
		memcpy(h->id, data, (size_t)len);
	else
		memset(h->id, 0, (size_t)len);

	return h;
}

int
lws_dht_hash_copy(lws_dht_hash_t *dest, const lws_dht_hash_t *src)
{
	if (dest->len < src->len)
		return -1;

	dest->type = src->type;
	memcpy(dest->id, src->id, (size_t)src->len);

	return 0;
}

LWS_VISIBLE void
lws_dht_hash_destroy(lws_dht_hash_t **p)
{
	if (!*p)
		return;
	lws_free(*p);
	*p = NULL;
}

int
lws_dht_hash_is_zero(const lws_dht_hash_t *h)
{
	int i;

	if (!h)
		return 1;

	for (i = 0; i < h->len; i++)
		if (h->id[i])
			return 0;

	return 1;
}

lws_dht_hash_t *
lws_dht_hash_dup(const lws_dht_hash_t *src)
{
	return lws_dht_hash_create(src->type, src->len, src->id);
}

int
lws_dht_hash_cmp(const lws_dht_hash_t *a, const lws_dht_hash_t *b)
{
	if (a->type != b->type)
		return a->type - b->type;
	if (a->len != b->len)
		return a->len - b->len;

	return memcmp(a->id, b->id, a->len);
}

static void
dht_default_hash(void *hash_return, int hash_size,
		 const void *v1, int len1,
		 const void *v2, int len2,
		 const void *v3, int len3)
{
	uint8_t *h = hash_return;
	const uint8_t *p;
	int i;

	memset(h, 0, (size_t)hash_size);

	p = v1;
	for (i = 0; i < len1; i++)
		h[i % hash_size] ^= p[i];
	p = v2;
	for (i = 0; i < len2; i++)
		h[i % hash_size] ^= p[i];
	p = v3;
	for (i = 0; i < len3; i++)
		h[i % hash_size] ^= p[i];
}

void
lws_dht_hash(struct lws_dht_ctx *ctx, void *hash_return, int hash_size,
	     const void *v1, int len1,
	     const void *v2, int len2,
	     const void *v3, int len3)
{
	if (ctx->hash_cb) {
		ctx->hash_cb(hash_return, hash_size, v1, len1, v2, len2, v3, len3);
		return;
	}

	dht_default_hash(hash_return, hash_size, v1, len1, v2, len2, v3, len3);
}

int
id_cmp(const lws_dht_hash_t *restrict id1, const lws_dht_hash_t *restrict id2)
{
	/* Memcmp is guaranteed to perform an unsigned comparison. */
	return lws_dht_hash_cmp(id1, id2);
}

int
xorcmp(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2,
		const lws_dht_hash_t *ref)
{
	int i;
	int len = ref->len;

	for (i = 0; i < len; i++) {
		uint8_t v1 = (i < id1->len) ? id1->id[i] : 0;
		uint8_t v2 = (i < id2->len) ? id2->id[i] : 0;
		uint8_t vr = (i < ref->len) ? ref->id[i] : 0;
		uint8_t x1 = v1 ^ vr;
		uint8_t x2 = v2 ^ vr;

		if (x1 != x2)
			return x1 < x2 ? -1 : 1;
	}

	return 0;
}

int
lowbit(const lws_dht_hash_t *id)
{
	int i, j;
	for (i = (int)id->len - 1; i >= 0; i--)
		if (id->id[i] != 0)
			break;

	if (i < 0)
		return -1;

	for (j = 7; j >= 0; j--)
		if ((id->id[i] & (0x80 >> j)) != 0)
			break;

	return 8 * i + j;
}

/* Find how many bits two ids have in common. */
int
common_bits(const lws_dht_hash_t *id1, const lws_dht_hash_t *id2)
{
	int i, j;
	uint8_t xor;
	int len = MIN(id1->len, id2->len);

	for (i = 0; i < len; i++) {
		if (id1->id[i] != id2->id[i])
			break;
	}

	if (i == len)
		return len * 8;

	xor = id1->id[i] ^ id2->id[i];

	j = 0;
	while ((xor & 0x80) == 0) {
		xor = (uint8_t)(xor << 1);
		j++;
	}

	return 8 * i + j;
}

