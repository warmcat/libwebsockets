/*
 * Generic LED controller ops
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 * This is like an abstract class for leds, a real implementation provides
 * functions for the ops that use the underlying, eg, OS gpio arrangements.
 */

#if !defined(__LWS_LED_H__)
#define __LWS_LED_H__

/* 0 is always OFF, for gpio, anything else is ON */
typedef uint16_t lws_led_intensity_t;
typedef uint16_t lws_led_seq_phase_t;
#define LWS_LED_MAX_INTENSITY		(0xffff)
#define LWS_LED_FRAME_RATE		20
#define LWS_LED_FUNC_PHASE		1024

struct lws_led_state; /* opaque */

typedef lws_led_intensity_t (*lws_led_lookup_t)(int idx);

typedef struct lws_led_sequence_def_t {
	lws_led_lookup_t	func;
	lws_led_seq_phase_t	ledphase_offset;
	int			ledphase_total;
	int			ms_full_phase; /* to compute rate */
} lws_led_sequence_def_t;

/* this should always be first in the subclassed implementation types */

typedef struct lws_led_ops {
	void (*intensity)(const struct lws_led_ops *lo, int index,
			  lws_led_intensity_t inten);
	int (*lookup)(const struct lws_led_ops *lo, const char *name);
	struct lws_led_state * (*create)(const struct lws_led_ops *led_ops);
	void (*destroy)(struct lws_led_state *);
} lws_led_ops_t;

typedef struct lws_led_gpio_map {
	const char			*name;
	_lws_plat_gpio_t		gpio;
	uint8_t				active_level;
} lws_led_gpio_map_t;

typedef struct lws_led_gpio_controller {
	const lws_led_ops_t		led_ops;

	const lws_gpio_ops_t		*gpio_ops;
	const lws_led_gpio_map_t	*led_map;
	uint8_t				count_leds;
} lws_led_gpio_controller_t;

/* ops */

LWS_VISIBLE LWS_EXTERN struct lws_led_state *
lws_led_gpio_create(const lws_led_ops_t *led_ops);

LWS_VISIBLE LWS_EXTERN void
lws_led_gpio_destroy(struct lws_led_state *lcs);

LWS_VISIBLE LWS_EXTERN void
lws_led_gpio_intensity(const struct lws_led_ops *lo, int index, lws_led_intensity_t inten);

LWS_VISIBLE LWS_EXTERN int
lws_led_gpio_lookup(const struct lws_led_ops *lo, const char *name);

#define lws_led_gpio_ops \
	{ \
		.create		= lws_led_gpio_create, \
		.destroy	= lws_led_gpio_destroy, \
		.intensity	= lws_led_gpio_intensity, \
		.lookup		= lws_led_gpio_lookup, \
	}

#endif

