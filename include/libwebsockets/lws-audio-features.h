/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2024 Andy Green <andy@warmcat.com>
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

#ifndef _LWS_AUDIO_FEATURES_H
#define _LWS_AUDIO_FEATURES_H

typedef struct lws_audio_vu_info {
    double squelch_level; /* energy below this is reported as 0 */
    double max_energy;    /* max expected energy for log scaling */
    int sample_stride;    /* step size for sampling (e.g. 48) */
} lws_audio_vu_info_t;

/**
 * lws_media_audio_calc_energy() - Calculate audio energy level (0-100)
 *
 * \param info: pointer to lws_audio_vu_info_t containing config
 * \param pcm: pointer to signed 16-bit PCM samples
 * \param len_samples: number of samples in pcm buffer
 * \param result: pointer to integer to hold the result (0-100)
 *
 * Returns 0 on success, or non-zero on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_media_audio_calc_energy(const lws_audio_vu_info_t *info,
                            const int16_t *pcm, size_t len_samples, int *result);

#endif
