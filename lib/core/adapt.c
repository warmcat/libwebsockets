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

#include "private-lib-core.h"

struct lws_adapt_level {
	uint32_t ewma_short; /* 0-10000 (0 = Total Fail, 10000 = Total Success) */
	uint32_t ewma_long;  /* 0-10000 */
	lws_usec_t last_update;
};

struct lws_adapt {
	int active_level;
	int num_levels;

	uint32_t hl_short_us;
	uint32_t hl_long_us;

	lws_usec_t last_downgrade_us;
	uint32_t backoff_multiplier;

	struct lws_adapt_level *levels;
};

/* 10000 represents 1.0 (100% success rate) */
#define LWS_ADAPT_MAX_SCORE 10000
#define LWS_ADAPT_DOWNGRADE_THRESHOLD 8500 /* If short-term drops below 85% success */
#define LWS_ADAPT_UPGRADE_THRESHOLD 9800   /* If BOTH short & long are >98% success */
#define LWS_ADAPT_BASE_BACKOFF_US (30ll * LWS_US_PER_SEC) /* Base 30s wait before retry */

static uint32_t
ewma_update(uint32_t current_score, int success, lws_usec_t elapsed_us, uint32_t halflife_us)
{
	if (halflife_us == 0)
		return success ? LWS_ADAPT_MAX_SCORE : 0;

	/* Rough decay. Alpha = 1.0 - exp(-(elapsed/halflife) * ln(2)) */
	/* For speed on embedded without math.h: simple linear approx for small elapsed */

	/* Prevent massive underflows if system sleeps */
	if (elapsed_us > halflife_us * 5)
		elapsed_us = halflife_us * 5;

	/* Bounding alpha between 0 and 100000 (corresponding to 0.0 - 1.0 multiplier ratio) */
	uint64_t alpha = ((uint64_t)elapsed_us * 100000ull) / halflife_us;
	if (alpha > 100000) alpha = 100000;

	uint32_t target_score = success ? LWS_ADAPT_MAX_SCORE : 0;

	/* score = current * (1 - alpha) + target * alpha */
	uint32_t new_score = (uint32_t)(((uint64_t)current_score * (100000ll - alpha) +
					 (uint64_t)target_score * alpha) / 100000ll);
	return new_score;
}

struct lws_adapt *
lws_adapt_create(int num_levels, uint32_t ewma_halflife_short_us,
		 uint32_t ewma_halflife_long_us)
{
	struct lws_adapt *a;

	if (num_levels < 1)
		return NULL;

	a = lws_zalloc(sizeof(*a), "lws_adapt");
	if (!a)
		return NULL;

	a->levels = lws_zalloc(sizeof(struct lws_adapt_level) * (unsigned int)num_levels, "lws_adapt_lvls");
	if (!a->levels) {
		lws_free(a);
		return NULL;
	}

	a->num_levels = num_levels;
	a->hl_short_us = ewma_halflife_short_us;
	a->hl_long_us = ewma_halflife_long_us;
	a->active_level = 0; /* Assume best level initially */
	a->backoff_multiplier = 1;

	lws_usec_t now = lws_now_usecs();
	for (int i = 0; i < num_levels; i++) {
		a->levels[i].ewma_short = LWS_ADAPT_MAX_SCORE;
		a->levels[i].ewma_long = LWS_ADAPT_MAX_SCORE;
		a->levels[i].last_update = now;
	}

	return a;
}

void
lws_adapt_destroy(struct lws_adapt **padapt)
{
	if (!padapt || !*padapt)
		return;

	if ((*padapt)->levels)
		lws_free((*padapt)->levels);

	lws_free(*padapt);
	*padapt = NULL;
}

void
lws_adapt_report(struct lws_adapt *a, int success, lws_usec_t us)
{
	if (!a || a->active_level < 0 || a->active_level >= a->num_levels)
		return;

	struct lws_adapt_level *l = &a->levels[a->active_level];

	/* Handle initial state or crazy jumps backwards */
	if (l->last_update == 0 || us < l->last_update) {
		l->last_update = us;
		return;
	}

	lws_usec_t elapsed_us = us - l->last_update;
	l->last_update = us;

	l->ewma_short = ewma_update(l->ewma_short, success, elapsed_us, a->hl_short_us);
	l->ewma_long = ewma_update(l->ewma_long, success, elapsed_us, a->hl_long_us);

	/* Check for immediate downgrade flag within report cycle */
	if (l->ewma_short < LWS_ADAPT_DOWNGRADE_THRESHOLD && a->active_level < a->num_levels - 1) {
		lwsl_notice("%s: Downgrading level %d -> %d (Score: %u/%u)\n",
			__func__, a->active_level, a->active_level + 1,
			(unsigned int)l->ewma_short, (unsigned int)LWS_ADAPT_MAX_SCORE);

		a->active_level++;
		a->last_downgrade_us = us;
		a->backoff_multiplier *= 3; /* Exponentially harsher backoff for upgrades */

		/* Give the *new* level a brief immunity grace period by pre-filling its queue */
		a->levels[a->active_level].ewma_short = LWS_ADAPT_MAX_SCORE;
		a->levels[a->active_level].last_update = us;
		return;
	}

	/* Slowly forgive past failures if we've been running safely at the best level for a long time */
	if (a->active_level == 0 && a->backoff_multiplier > 1) {
		/* If we've survived 4x the last backoff duration without downgrading, reduce the multiplier */
		lws_usec_t forgiveness_period = LWS_ADAPT_BASE_BACKOFF_US * (lws_usec_t)a->backoff_multiplier * 4;
		if (us > a->last_downgrade_us + forgiveness_period) {
			a->backoff_multiplier /= 3;
			if (a->backoff_multiplier < 1)
				a->backoff_multiplier = 1;
			a->last_downgrade_us = us; /* Reset the clock for the next forgiveness tier */
			lwsl_notice("%s: Sustained stability! Reducing backoff multiplier to %u\n", __func__, (unsigned int)a->backoff_multiplier);
		}
	}
}

int
lws_adapt_get_level(struct lws_adapt *a)
{
	if (!a) return 0;

	/* Can we upgrade? */
	if (a->active_level > 0) {
		struct lws_adapt_level *l = &a->levels[a->active_level];
		lws_usec_t now = lws_now_usecs();

		/* 1. Ensure current degraded level is performing near-flawlessly */
		if (l->ewma_short > LWS_ADAPT_UPGRADE_THRESHOLD &&
		    l->ewma_long > LWS_ADAPT_UPGRADE_THRESHOLD) {

			/* 2. Enforce exponential backoff timer from last failure */
			lws_usec_t backoff_required = LWS_ADAPT_BASE_BACKOFF_US * (lws_usec_t)a->backoff_multiplier;

			if (now > a->last_downgrade_us + backoff_required) {
				lwsl_notice("%s: Upgrading level %d -> %d (Stable for %u us)\n",
					__func__, a->active_level, a->active_level - 1,
					(unsigned int)(now - a->last_downgrade_us));

				a->active_level--;
				a->last_downgrade_us = now; /* So we measure forgiveness from the moment of success */

				/* Pre-fill the upgraded level with optimistic score */
				a->levels[a->active_level].ewma_short = LWS_ADAPT_MAX_SCORE;
				a->levels[a->active_level].last_update = now;
			}
		} else {
			/* If the lower tier is struggling, reset our upgrade dreams and backoff */
			if (l->ewma_short < LWS_ADAPT_DOWNGRADE_THRESHOLD) {
				a->last_downgrade_us = now;
			}
		}
	}

	return a->active_level;
}
