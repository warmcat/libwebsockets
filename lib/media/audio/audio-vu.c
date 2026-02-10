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
 */

#include <libwebsockets.h>

#include "private-lib-core.h"
#include <math.h>

int
lws_media_audio_calc_energy(const lws_audio_vu_info_t *info,
			    const int16_t *pcm, size_t len_samples, int *result)
{
	int64_t sum = 0;
	int count = 0;
	int32_t avg = 0;
	uint64_t energy = 0;
	size_t i;
	size_t stride = (size_t)(info->sample_stride > 0 ? info->sample_stride : 1);

	if (!pcm || !result)
		return 1;

	/* 1. Calculate Average (DC Offset) */
	for (i = 0; i < len_samples; i += stride) {
		sum += (int64_t)pcm[i];
		count++;
	}

	if (count > 0)
		avg = (int32_t)(sum / count);

	/* 2. Calculate Energy (Sum of abs diff from avg) */
	for (i = 0; i < len_samples; i += stride) {
		int32_t val = (int32_t)pcm[i] - avg;
		if (val < 0)
			val = -val;
		energy += (uint64_t)val;
	}

	/* 3. Apply Squelch and Logarithmic Scaling */
	if (energy > info->squelch_level) {
		double db_min = log10(info->squelch_level);
		double db_max = log10(info->max_energy);
		double db_cur = log10((double)energy);

		if (db_max > db_min) {
			*result = (int)(((db_cur - db_min) / (db_max - db_min)) * 100.0);
		} else {
			*result = 0;
		}
	} else
		*result = 0;

	if (*result > 100)
		*result = 100;
	if (*result < 0)
		*result = 0;

	return 0;
}
