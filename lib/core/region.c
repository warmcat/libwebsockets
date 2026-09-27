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
 * lws_region: who holds which range of a shared scratch buffer.  See
 * include/libwebsockets/lws-region.h.
 */

#include "private-lib-core.h"

/*
 * A handle is the slot index in the low 8 bits and the slot's generation
 * above it, so a release by a stale handle, of a claim that was already
 * given up and whose slot has been reused since, finds the generation moved
 * on and leaves the new claim alone.
 */
#define LWS_REGION_GEN_MASK		0x7fff

static int
lws_region_violation(const lws_region_t *r, int e)
{
	if (r->flags & LWS_REGION_F_ABORT)
		abort();

	return e;
}

static int
lws_region_inside(const lws_region_t *r, const uint8_t *p)
{
	return p >= r->base && p <= r->base + r->len;
}

static lws_region_claim_t *
lws_region_find(lws_region_t *r, const uint8_t *p)
{
	size_t n;

	for (n = 0; n < r->count_claims; n++)
		if (r->claims[n].s && p >= r->claims[n].s &&
		    p <= r->claims[n].e)
			return &r->claims[n];

	return NULL;
}

int
lws_region_init(lws_region_t *r, const char *name, const void *base,
		size_t len, lws_region_claim_t *claims, size_t count_claims,
		unsigned int flags)
{
	if (!count_claims || count_claims > 255)
		return -1;

	memset(claims, 0, sizeof(*claims) * count_claims);

	r->name		= name;
	r->base		= (const uint8_t *)base;
	r->len		= len;
	r->claims	= claims;
	r->count_claims	= (uint8_t)count_claims;
	r->flags	= (uint8_t)flags;

	return 0;
}

int
lws_region_claim(lws_region_t *r, const void *_p, size_t len, const char *who)
{
	const uint8_t *p = (const uint8_t *)_p, *e;
	lws_region_claim_t *c;
	size_t n;

	if (!lws_region_inside(r, p))
		return LWS_REGION_NOT_TRACKED;

	/* compare lengths, so an oversize len can't wrap the end pointer */
	if (len > (size_t)((r->base + r->len) - p)) {
		lwsl_err("%s: %s: %s claims past the end (%llu at +%llu)\n",
			 __func__, r->name, who, (unsigned long long)len,
			 (unsigned long long)(p - r->base));

		return lws_region_violation(r, LWS_REGION_E_OVERRUN);
	}
	e = p + len;

	for (n = 0; n < r->count_claims; n++) {
		c = &r->claims[n];

		if (c->s && p < c->e && e > c->s) {
			lwsl_err("%s: %s: %s claims +%llu..+%llu while %s "
				 "holds +%llu..+%llu\n", __func__, r->name, who,
				 (unsigned long long)(p - r->base),
				 (unsigned long long)(e - r->base), c->who,
				 (unsigned long long)(c->s - r->base),
				 (unsigned long long)(c->e - r->base));

			return lws_region_violation(r, LWS_REGION_E_OVERLAP);
		}
	}

	for (n = 0; n < r->count_claims; n++) {
		c = &r->claims[n];

		if (c->s)
			continue;

		c->s	= p;
		c->e	= e;
		c->who	= who;
		c->gen	= (uint16_t)((c->gen + 1) & LWS_REGION_GEN_MASK);

		return (int)(((unsigned int)c->gen << 8) | (unsigned int)n);
	}

	lwsl_err("%s: %s: %s: no free claim slot\n", __func__, r->name, who);

	return lws_region_violation(r, LWS_REGION_E_FULL);
}

void
lws_region_release(lws_region_t *r, int handle)
{
	lws_region_claim_t *c;
	unsigned int slot;

	if (handle < 0)
		return;

	slot = (unsigned int)handle & 0xff;
	if (slot >= r->count_claims)
		return;

	c = &r->claims[slot];
	if (c->gen == (((unsigned int)handle >> 8) & LWS_REGION_GEN_MASK))
		c->s = NULL;
}

void
lws_region_release_containing(lws_region_t *r, const void *p)
{
	lws_region_claim_t *c = lws_region_find(r, (const uint8_t *)p);

	if (c)
		c->s = NULL;
}

void
lws_region_trim(lws_region_t *r, const void *_p)
{
	const uint8_t *p = (const uint8_t *)_p;
	lws_region_claim_t *c = lws_region_find(r, p);

	if (!c)
		return;

	if (p >= c->e)
		c->s = NULL; /* nothing left of it */
	else
		c->s = p;
}

int
lws_region_idle(const lws_region_t *r, const char *where)
{
	size_t n;

	(void)where; /* only for logging */

	for (n = 0; n < r->count_claims; n++)
		if (r->claims[n].s) {
			lwsl_err("%s: %s: %s still holds +%llu..+%llu at %s\n",
				 __func__, r->name, r->claims[n].who,
				 (unsigned long long)(r->claims[n].s - r->base),
				 (unsigned long long)(r->claims[n].e - r->base),
				 where);

			return lws_region_violation(r, -1);
		}

	return 0;
}
