/*
 * LWS PNG -- derived from uPNG -- derived from LodePNG version 20100808
 * Stateful, linewise PNG decode requiring ~36KB fixed heap
 *
 * Copyright (c) 2005-2010 Lode Vandevenne (LodePNG)
 * Copyright (c) 2010 Sean Middleditch (uPNG)
 * Copyright (c) 2021 Andy Green <andy@warmcat.com> (Stateful, incremental)
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.

 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must not
 *      claim that you wrote the original software. If you use this software
 *      in a product, an acknowledgment in the product documentation would be
 *	appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must not be
 *	misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *	distribution.
 *
 *  AG: The above notice is the ZLIB license, libpng also uses it.
 *
 * This version was rewritten from the upng project's fork of lodepng and
 * adapted to be a stateful stream parser.  This rewrite retains the ZLIB
 * license of the source material for simplicity.
 *
 * That allows it to use a fixed 32KB ringbuffer to hold decodes, and
 * incrementally decode chunks into it as we want output lines that are not yet
 * present there.  The input png nor the output bitmap need to be all in one
 * place at one time.
 */

#include <private-lib-core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

typedef enum upng_color {
	LWS_UPNG_LUM		= 0,
	LWS_UPNG_RGB		= 2,
	LWS_UPNG_LUMA		= 4,
	LWS_UPNG_RGBA		= 6
} upng_color;

struct upng_unfline {
	uint8_t			*recon;
	const uint8_t		*scanline;
	const uint8_t		*precon;
	uint8_t			filterType;
	unsigned int		bypp;
	unsigned int		bypl;

	const uint8_t		*in;
	uint8_t			*lines;
	unsigned int		bpp;

	unsigned int		y;
	unsigned long		diff;
	unsigned long		ibp;
	unsigned long		sp;

	char			padded;
	char			alt;
};

typedef enum {
	UOF_MAGIC,
	UOF_SKIP,
	UOF_TYPE4,
	UOF_WIDTH4,
	UOF_HEIGHT4,
	UOF_CDEPTH,
	UOF_CTYPE,
	UOF_ONLY_ZERO3,
	UOF_SKIP4,

	UOF_CHUNK_LEN,
	UOF_CHUNK_TYPE,
	UOF_INSIDE,

	UOF_SKIP_CHUNK_LEN,
} upng_outer_framing_t;



struct lws_upng_t {
	struct upng_unfline	u;
	inflator_ctx_t		inf;

	unsigned int		width;
	unsigned int		height;

	upng_color		color_type;
	unsigned int		color_depth;
	lws_upng_format_t	format;

	const uint8_t		*chunk;

	int			sctr;
	uint32_t		acc;

	uint32_t		chunklen;
	uint32_t		ctype;

	upng_outer_framing_t	of;

	uint8_t			no_more_input;
	char			hold_at_metadata;
};

static lws_stateful_ret_t
lws_upng_decode(lws_upng_t *upng, const uint8_t **buf, size_t *size);

static int
paeth(int a, int b, int c)
{
	int p = a + b - c;
	int pa = p > a ? p - a : a - p;
	int pb = p > b ? p - b : b - p;
	int pc = p > c ? p - c : c - p;

	if (pa <= pb && pa <= pc)
		return a;

	if (pb <= pc)
		return b;

	return c;
}

static lws_stateful_ret_t
unfilter_scanline(lws_upng_t *u)
{
	struct upng_unfline *uf = &u->u;
	unsigned long i;

	switch (uf->filterType) {
	case 0: /* None */
		for (i = 0; i < uf->bypl; i++)
			uf->recon[i] = u->inf.out[(uf->sp + i) %
			                            u->inf.info_size];
		break;
	case 1: /* Sub */
		for (i = 0; i <  uf->bypp; i++)
			uf->recon[i] = u->inf.out[(uf->sp + i) %
			                            u->inf.info_size];

		for (i = uf->bypp; i < uf->bypl; i++)
			uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
			                            u->inf.info_size] +
				uf->recon[i - uf->bypp]);
		break;
	case 2: /* Up */
		if (uf->y)
			for (i = 0; i < uf->bypl; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				            u->inf.info_size] + uf->precon[i]);
		else
			for (i = 0; i < uf->bypl; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				                          u->inf.info_size]);
		break;
	case 3: /* Average */
		if (uf->y) {
			for (i = 0; i < uf->bypp; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				        u->inf.info_size] + uf->precon[i] / 2);
			for (i = uf->bypp; i < uf->bypl; i++)
				uf->recon[i] = (uint8_t)
					(u->inf.out[(uf->sp + i) %
					            u->inf.info_size] +
					((uf->recon[i - uf->bypp] +
							uf->precon[i]) / 2));
		} else {
			for (i = 0; i < uf->bypp; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				                         u->inf.info_size]);
			for (i = uf->bypp; i < uf->bypl; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				                         u->inf.info_size] +
					uf->recon[i - uf->bypp] / 2);
		}
		break;
	case 4: /* Paeth */
		if (uf->y) {
			for (i = 0; i < uf->bypp; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				                          u->inf.info_size] +
					paeth(0, uf->precon[i], 0));
			for (i = uf->bypp; i < uf->bypl; i++)
				uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
				                          u->inf.info_size] +
					paeth(uf->recon[i - uf->bypp],
							uf->precon[i],
							uf->precon[i - uf->bypp]));
			break;
		}

		for (i = 0; i < uf->bypp; i++)
			uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
			                            u->inf.info_size]);
		for (i = uf->bypp; i < uf->bypl; i++)
			uf->recon[i] = (uint8_t)(u->inf.out[(uf->sp + i) %
			                                u->inf.info_size] +
				paeth(uf->recon[i - uf->bypp], 0, 0));
		break;
	default:
		lwsl_err("%s: line start is broken %d\n", __func__,
				uf->filterType);
		return LWS_SRET_FATAL + 12;
	}

	u->inf.consumed_linear += uf->bypl;

	return LWS_SRET_OK;
}

lws_stateful_ret_t
lws_upng_emit_next_line(lws_upng_t *u, const uint8_t **ppix,
		    const uint8_t **pos, size_t *size, char hold_at_metadata)
{
	struct upng_unfline	*uf = &u->u;
	unsigned long		obp;
	lws_stateful_ret_t	ret = LWS_SRET_OK;

	*ppix = NULL;

	u->hold_at_metadata = hold_at_metadata;

	if (u->height && uf->y >= u->height)
		goto out;

	/*
	 * The decoder emits into the 32KB window ringbuffer, if we don't
	 * already have at least one line's worth of output in there, we'll
	 * have to do more inflation
	 */

	if (u->inf.outpos_linear - u->inf.consumed_linear < uf->bypl + 1) {
		ret = lws_upng_decode(u, pos, size);
		if ((!*size && ret == LWS_SRET_WANT_INPUT) ||
		    (ret & (LWS_SRET_FATAL | LWS_SRET_YIELD)) ||
		    !u->inf.outpos_linear)
			return ret;

		assert(u->inf.info_size);
		assert(uf->bypl + 1);
	}

	if (u->inf.outpos_linear - u->inf.consumed_linear < uf->bypl + 1)
		return ret;

	obp		= uf->alt ? uf->bypl : 0;
	uf->precon	= uf->alt ? uf->lines : uf->lines + uf->bypl;
	uf->recon	= &uf->lines[obp];
	*ppix		= uf->recon;
	uf->filterType	= uf->in[(u->inf.consumed_linear++) % u->inf.info_size];
	uf->sp		= u->inf.consumed_linear % u->inf.info_size;

	if (unfilter_scanline(u) != LWS_SRET_OK) {
		ret = LWS_SRET_FATAL + 13;

		goto out;
	}

	if (uf->padded) {
		unsigned long x;

		for (x = 0; x < (unsigned long)u->width * (unsigned long)uf->bpp; x++) {
			uint8_t bit = (uint8_t)((uf->in[(uf->ibp) >> 3] >>
						(7 - ((uf->ibp) & 7))) & 1);
			uf->ibp++;

			if (!bit)
				uf->lines[obp >> 3] &=
					(uint8_t)(~(1 << (7 - (obp & 7))));
			else
				uf->lines[obp >> 3] = (uint8_t)(uf->lines[obp >> 3] |
						(uint8_t)(1 << (7 - (obp & 7))));

			obp++;
		}

		uf->ibp += uf->diff;
	}

out:
	uf->alt ^= 1;
	uf->y++;

	return ret;
}

static lws_upng_format_t
determine_format(lws_upng_t* upng) {
	switch (upng->color_type) {
	case LWS_UPNG_LUM:
		switch (upng->color_depth) {
		case 1:
			return LWS_UPNG_LUMINANCE1;
		case 2:
			return LWS_UPNG_LUMINANCE2;
		case 4:
			return LWS_UPNG_LUMINANCE4;
		case 8:
			return LWS_UPNG_LUMINANCE8;
		default:
			return LWS_UPNG_BADFORMAT;
		}
	case LWS_UPNG_RGB:
		switch (upng->color_depth) {
		case 8:
			return LWS_UPNG_RGB8;
		case 16:
			return LWS_UPNG_RGB16;
		default:
			return LWS_UPNG_BADFORMAT;
		}
	case LWS_UPNG_LUMA:
		switch (upng->color_depth) {
		case 1:
			return LWS_UPNG_LUMINANCE_ALPHA1;
		case 2:
			return LWS_UPNG_LUMINANCE_ALPHA2;
		case 4:
			return LWS_UPNG_LUMINANCE_ALPHA4;
		case 8:
			return LWS_UPNG_LUMINANCE_ALPHA8;
		default:
			return LWS_UPNG_BADFORMAT;
		}
	case LWS_UPNG_RGBA:
		switch (upng->color_depth) {
		case 8:
			return LWS_UPNG_RGBA8;
		case 16:
			return LWS_UPNG_RGBA16;
		default:
			return LWS_UPNG_BADFORMAT;
		}
	default:
		return LWS_UPNG_BADFORMAT;
	}
}

static const uint8_t magic[] = { 137, 80, 78, 71, 13, 10, 26, 10 };

static lws_stateful_ret_t
lws_upng_decode(lws_upng_t* u, const uint8_t **_pos, size_t *_size)
{
	const uint8_t *pos = _pos ? *_pos : NULL, *end = pos + *_size;
	lws_stateful_ret_t r = LWS_SRET_FATAL + 60;
	size_t m;

	if (u->of == UOF_INSIDE && !u->inf.in) {
		u->inf.inpos = 0;
		u->inf.in = pos;
		u->inf.bp = 0;
		m = lws_ptr_diff_size_t(end, pos);
		if (m > u->chunklen)
			m = u->chunklen;
		u->inf.inlen = m;
	}

	while (!u->no_more_input &&
	       ((u->of == UOF_INSIDE && _pos == NULL) || pos < end)) {
		switch (u->of) {
		case UOF_MAGIC:
			if (*pos++ != magic[u->sctr++])
				return LWS_SRET_FATAL + 17;
			if (u->sctr == sizeof(magic)) {
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_SKIP:
			pos++;
			if (++u->sctr == 4) {
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_TYPE4:
			u->acc = (u->acc << 8) | *pos++;
			if (++u->sctr == 4) {
				if (u->acc != LWS_FOURCC('I','H','D','R'))
					return LWS_SRET_FATAL + 18;
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_WIDTH4:
			u->acc = (u->acc << 8) | *pos++;
			if (++u->sctr == 4) {
				u->width = u->acc;
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_HEIGHT4:
			u->acc = (u->acc << 8) | *pos++;
			if (++u->sctr == 4) {
				u->height = u->acc;
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_CDEPTH:
			u->color_depth =*pos++;
			u->of++;
			break;

		case UOF_CTYPE:
			u->color_type = *pos++;
			//lwsl_notice("w %d, h %d, depth %d, type %d\n",
			//		u->width, u->height,
			//		u->color_depth, u->color_type);
			u->format = determine_format(u);
			if (u->format == LWS_UPNG_BADFORMAT)
				return LWS_SRET_FATAL + 19;
			u->of++;
			break;

		case UOF_ONLY_ZERO3:
			if (*pos++)
				return LWS_SRET_FATAL + 20;
			if (++u->sctr == 3) {
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_SKIP4:
			pos++;
			if (++u->sctr != 4)
				break;

			/* takes us to +33 */

			memset(&u->inf, 0, sizeof(u->inf));

			/* 32KB gz sliding window */
			u->inf.info_size = 32768 + 512;
			u->u.bpp	 = lws_upng_get_bpp(u);
			if (!u->u.bpp)
				return LWS_SRET_FATAL + 14;

			u->u.y		= 0;
			u->u.ibp	= 0;
			u->u.bypp	= (u->u.bpp + 7) / 8;
			u->inf.bypl = u->u.bypl	= u->width * u->u.bypp;

			u->inf.outlen	= u->inf.info_size;
			u->inf.outpos	= 0;
			u->inf.state	= UPNS_ID_BL_GB_DONE;
			u->inf.upng	= u;

			u->u.alt	= 0; /* which of the two lines to write to */
			u->u.padded	= u->u.bpp < 8 &&
					  u->width * u->u.bpp !=
					  ((u->width * u->u.bpp + 7) / 8) * 8;
			u->u.diff	= (((u->width * u->u.bpp + 7) / 8) * 8) -
						(u->width * u->u.bpp);

			u->of++;
			u->sctr = 0;
			break;

		case UOF_CHUNK_LEN:
			if (!u->inf.out) {
				size_t ims = (u->u.bypl * 2) + u->inf.info_size;

				if (u->hold_at_metadata)
					return LWS_SRET_AWAIT_RETRY;

				u->inf.out = (uint8_t *)lws_malloc(ims, __func__);
				if (!u->inf.out) {
					lwsl_notice("%s: inf malloc %u OOM\n",
						__func__, (unsigned int)ims);

					return LWS_SRET_YIELD;
				}
				u->u.lines = u->inf.out + u->inf.info_size;
				u->u.in		= u->inf.out;
			}
			u->chunklen = (u->chunklen << 8) | *pos++;
			if (++u->sctr == 4) {
				u->of++;
				u->sctr = 0;
			}
			break;

		case UOF_CHUNK_TYPE:
			u->ctype = (u->ctype << 8) | *pos++;
			if (++u->sctr != 4)
				break;
			u->sctr = 0;
			if (u->ctype == LWS_FOURCC('I','E','N','D')) {
				u->no_more_input = 1;
				break;
			}
			if (u->ctype != LWS_FOURCC('I','D','A','T')) {
				if (!(u->ctype & (32 << 24)))
					/* says it is critical... */
					 return LWS_SRET_FATAL + 27;

				u->chunklen += 4; /* chunk-end CRC */

				/* noncritical, skip */
				u->of = UOF_SKIP_CHUNK_LEN;
				break;
			}

			if (u->chunklen < 2)
				return LWS_SRET_FATAL + 31;

			/* it's a usable IDAT */

			if (!u->inf.subsequent)
				u->inf.inpos = 2;
			else
				u->inf.inpos = 0;

			m = lws_ptr_diff_size_t(end, pos);
			if (m > u->chunklen)
				m = u->chunklen;

			u->inf.in = pos;
			u->inf.inlen = m;
			u->inf.bp = 0;
			u->of++;
			break;

		case UOF_INSIDE:
			if (!u->inf.subsequent) {

				switch (u->sctr) {
				case 0:
					u->acc = (uint32_t)((*pos++) << 8);
					u->sctr++;
					continue;

				case 1:
					u->acc |= *pos++;

					if (u->acc % 31)
						return LWS_SRET_FATAL + 31;

					if (((u->acc >> 8) & 15) != 8 ||
					    ((u->acc >> 12) & 15) > 7)
						return LWS_SRET_FATAL + 31;

					if ((u->acc >> 5) & 1)
						return LWS_SRET_FATAL + 31;

					u->inf.subsequent = 1;
					break;
				}
			}

			r = _lws_upng_inflate_data(&u->inf);
			switch (r) {

			case LWS_SRET_WANT_INPUT:

				/* indicate no existing to drain */
				u->inf.in = NULL;

				pos += u->inf.inlen - u->inf.inpos;
				u->chunklen = u->chunklen -
						(unsigned int)(u->inf.inlen);

				if (!u->chunklen) {
					u->chunklen = 4; /* skip the 32-bit CRC */

					u->of = UOF_SKIP_CHUNK_LEN;
					break;
				}
				if (pos != end) {
					u->inf.inpos = 0;
					u->inf.in = pos;
					m = lws_ptr_diff_size_t(end, pos);
					if (m > u->chunklen)
						m = u->chunklen;
					u->inf.inlen = m;
					continue;
				}
				goto bail;
			default:
				goto bail;
			}
			break;

		case UOF_SKIP_CHUNK_LEN:
			pos++;
			if (!--u->chunklen) {
				u->of = UOF_CHUNK_LEN;
				u->sctr = 0;
				break;
			}
			break;
		}
	}

	r = LWS_SRET_OK;
	if (!u->no_more_input)
		r = LWS_SRET_WANT_INPUT;

bail:
	*_pos = pos;
	*_size = lws_ptr_diff_size_t(end, pos);

	return r;
}

lws_upng_t *
lws_upng_new(void)
{
	lws_upng_t* upng;

	upng = (lws_upng_t*)lws_zalloc(sizeof(lws_upng_t), __func__);
	if (upng == NULL)
		return NULL;

	upng->color_type = LWS_UPNG_RGBA;
	upng->color_depth = 8;
	upng->format = LWS_UPNG_RGBA8;

	upng->of = UOF_MAGIC;
	upng->sctr = 0;

	upng->inf.upng = upng;

	return upng;
}

void
lws_upng_free(lws_upng_t** upng)
{
	if ((*upng)->inf.out)
		lws_free_set_NULL((*upng)->inf.out);

	lws_free_set_NULL(*upng);
}


unsigned int
lws_upng_get_width(const lws_upng_t* upng)
{
	return upng->width;
}

unsigned int
lws_upng_get_height(const lws_upng_t* upng)
{
	return upng->height;
}

unsigned int
lws_upng_get_bpp(const lws_upng_t* upng)
{
	return lws_upng_get_bitdepth(upng) *
			lws_upng_get_components(upng);
}

unsigned int
lws_upng_get_components(const lws_upng_t* upng)
{
	switch (upng->color_type) {
	case LWS_UPNG_LUM:
		return 1;
	case LWS_UPNG_RGB:
		return 3;
	case LWS_UPNG_LUMA:
		return 2;
	case LWS_UPNG_RGBA:
		return 4;
	default:
		return 0;
	}
}

unsigned int
lws_upng_get_bitdepth(const lws_upng_t* upng)
{
	return upng->color_depth;
}

unsigned int
lws_upng_get_pixelsize(const lws_upng_t* upng)
{
	unsigned bits = lws_upng_get_bitdepth(upng) *
				lws_upng_get_components(upng);

	bits += bits % 8;

	return bits;
}

lws_upng_format_t
lws_upng_get_format(const lws_upng_t *upng)
{
	return upng->format;
}
