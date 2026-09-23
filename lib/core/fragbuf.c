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
 * lws_fragbuf: a large buffer that does not insist on being contiguous
 */

#include "private-lib-core.h"

/*
 * The control block is one allocation: the header, then the unit table, then
 * the run table, then the list of allocation bases we have to free.
 *
 *   u[n]   points at unit n
 *   run[n] is how many units from n on are physically contiguous with it, so
 *          lws_fragbuf_at() can answer "and how much can you have in one go"
 *          without walking
 */

struct lws_fragbuf {
	size_t		units;
	size_t		unit_size;
	unsigned int	allocs;

	uint8_t		**u;
	uint16_t	*run;
	uint8_t		**base;
};

void
lws_fragbuf_destroy(lws_fragbuf_t **pfb)
{
	lws_fragbuf_t *fb = *pfb;
	unsigned int n;

	if (!fb)
		return;

	for (n = 0; n < fb->allocs; n++)
		lws_free(fb->base[n]);

	lws_free(fb);
	*pfb = NULL;
}

lws_fragbuf_t *
lws_fragbuf_create_cap(size_t units, size_t unit_size, size_t cap)
{
	size_t remaining = units, done = 0, hdr;
	lws_fragbuf_t *fb;
	uint8_t *p;

	if (!units || !unit_size || units > 0xffff)
		return NULL;

	/*
	 * Sized for the worst case of one allocation per unit... it is three
	 * small tables next to each other, and even a 448-row surface only
	 * spends a few KB on them to be able to exist at all
	 */

	hdr = sizeof(*fb) + (units * (sizeof(uint8_t *) * 2 + sizeof(uint16_t)));

	fb = lws_zalloc(hdr, __func__);
	if (!fb)
		return NULL;

	p = (uint8_t *)&fb[1];
	fb->u = (uint8_t **)p;
	p += units * sizeof(uint8_t *);
	fb->base = (uint8_t **)p;
	p += units * sizeof(uint8_t *);
	fb->run = (uint16_t *)p;

	fb->units = units;
	fb->unit_size = unit_size;

	/*
	 * Ask for the whole thing first: if the heap can do it, we end up with
	 * exactly the single allocation the caller would have made himself,
	 * and the unit table is then just a contiguous walk.
	 *
	 * Only when that fails do we start halving what we ask for, taking
	 * the largest piece the heap will still give us each time.  That is
	 * the invitation to fit in what fragmentation has left, rather than
	 * failing outright while there is plenty free in total.
	 */

	while (remaining) {
		size_t take = cap && cap < remaining ? cap : remaining;
		uint8_t *q = NULL;
		size_t n;

		while (take) {
			q = lws_malloc(take * unit_size, __func__);
			if (q)
				break;

			take /= 2;
		}

		if (!q) {
			lws_fragbuf_destroy(&fb);

			return NULL;
		}

		fb->base[fb->allocs++] = q;

		for (n = 0; n < take; n++) {
			fb->u[done + n] = q + (n * unit_size);
			fb->run[done + n] = (uint16_t)(take - n);
		}

		done += take;
		remaining -= take;
	}

	if (fb->allocs != 1)
		lwsl_info("%s: %u units of %u took %u pieces\n", __func__,
			  (unsigned int)units, (unsigned int)unit_size,
			  fb->allocs);

	return fb;
}

lws_fragbuf_t *
lws_fragbuf_create(size_t units, size_t unit_size)
{
	return lws_fragbuf_create_cap(units, unit_size, 0);
}

uint8_t *
lws_fragbuf_unit(const lws_fragbuf_t *fb, size_t unit)
{
	if (unit >= fb->units)
		return NULL;

	return fb->u[unit];
}

uint8_t *
lws_fragbuf_at(const lws_fragbuf_t *fb, size_t ofs, size_t *avail)
{
	size_t unit = ofs / fb->unit_size, io = ofs % fb->unit_size;

	if (unit >= fb->units) {
		*avail = 0;

		return NULL;
	}

	*avail = (size_t)(fb->run[unit] * fb->unit_size) - io;

	return fb->u[unit] + io;
}

unsigned int
lws_fragbuf_pieces(const lws_fragbuf_t *fb)
{
	return fb->allocs;
}
