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
 * Adaptive Performance Tracking API
 */

#ifndef _LWS_ADAPT_H
#define _LWS_ADAPT_H

struct lws_adapt;

/**
 * lws_adapt_create() - Create an adaptive performance tracking context
 *
 * \param num_levels: The number of discrete capability levels (0=Best, num_levels-1=Safest)
 * \param ewma_halflife_short_us: Half-life decay for short-term reaction (e.g. 5 seconds)
 * \param ewma_halflife_long_us: Half-life decay for long-term recovery (e.g. 60 seconds)
 *
 * Returns an opaque tracking object. Level 0 is considered the highest quality
 * but most-demanding state. Level N is the safest fallback.
 */
LWS_VISIBLE LWS_EXTERN struct lws_adapt *
lws_adapt_create(int num_levels, uint32_t ewma_halflife_short_us,
		 uint32_t ewma_halflife_long_us);

/**
 * lws_adapt_destroy() - Destroy the adaptation tracking context
 *
 * \param padapt: Pointer to the adapt context pointer.
 */
LWS_VISIBLE LWS_EXTERN void
lws_adapt_destroy(struct lws_adapt **padapt);

/**
 * lws_adapt_report() - Report success or failure of the current capability cycle
 *
 * \param adapt: The adaptation context
 * \param success: 0 if the system failed to meet constraints (lag, frame drop), 1 if it met them
 * \param us: Current timestamp in microseconds (e.g. from lws_now_usecs())
 *
 * Records a data point. The underlying EWMAs will decay older points based on
 * the elapsed time since the previous report.
 */
LWS_VISIBLE LWS_EXTERN void
lws_adapt_report(struct lws_adapt *adapt, int success, lws_usec_t us);

/**
 * lws_adapt_get_level() - Query the recommended capability tier
 *
 * \param adapt: The adaptation context
 *
 * Returns the currently recommended level integer (0 ... num_levels-1).
 * If the short-term EWMA falls below a drop threshold, it immediately degrades
 * the recommended internal level. If both the short-term and long-term EWMAs
 * for the lower level are highly stable and the exponential backoff from any
 * previous failure has expired, it recommends an upgrade.
 */
LWS_VISIBLE LWS_EXTERN int
lws_adapt_get_level(struct lws_adapt *adapt);

#endif
