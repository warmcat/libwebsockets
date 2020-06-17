/*
 * Generic GPIO led
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
 */
#include "private-lib-core.h"

typedef struct lws_led_state
{
#if defined(LWS_PLAT_FREERTOS)
	TimerHandle_t				timer;
#endif
	lws_led_gpio_controller_t		*controller;
} lws_led_state_t;

#if defined(LWS_PLAT_FREERTOS)
static void
lws_led_timer_cb(TimerHandle_t th)
{
//	lws_led_state_t *lcs = pvTimerGetTimerID(th);
}
#endif

struct lws_led_state *
lws_led_gpio_create(const lws_led_ops_t *led_ops)
{
	lws_led_state_t *lcs = lws_zalloc(sizeof(lws_led_state_t), __func__);
	lws_led_gpio_controller_t *lgc = (lws_led_gpio_controller_t *)led_ops;
	int n;

	if (!lcs)
		return NULL;

	lcs->controller = lgc;

#if defined(LWS_PLAT_FREERTOS)
	lcs->timer = xTimerCreate("leds", 1, 0, lcs,
				  (TimerCallbackFunction_t)lws_led_timer_cb);
#endif

	for (n = 0; n < lgc->count_leds; n++) {
		lgc->gpio_ops->mode(lgc->led_map[n].gpio, LWSGGPIO_FL_WRITE);
		lgc->gpio_ops->set(lgc->led_map[n].gpio,
				   !lgc->led_map[n].active_level);
	}

	return lcs;
}

void
lws_led_gpio_destroy(struct lws_led_state *lcs)
{
#if defined(LWS_PLAT_FREERTOS)
        xTimerDelete(&lcs->timer, 0);
#endif
	lws_free(lcs);
}

void
lws_led_gpio_intensity(const struct lws_led_ops *lo, int idx, lws_led_intensity_t inten)
{
	const lws_led_gpio_controller_t *lgc = (lws_led_gpio_controller_t *)lo;
	const lws_led_gpio_map_t *map = &lgc->led_map[idx];

	lgc->gpio_ops->set(map->gpio, (!!map->active_level) ^ !inten);

//	ledc_set_duty(LEDC_HIGH_SPEED_MODE, LEDC_CHANNEL_0, inten);
//	ledc_update_duty(LEDC_HIGH_SPEED_MODE, LEDC_CHANNEL_0);
}


int
lws_led_gpio_lookup(const struct lws_led_ops *lo, const char *name)
{
	const lws_led_gpio_controller_t *lgc = (lws_led_gpio_controller_t *)lo;
	int n;

	for (n = 0; n < lgc->count_leds; n++)
		if (!strcmp(name, lgc->led_map[n].name))
			return n;

	return -1;
}

static const lws_led_intensity_t sineq16[] = {
        0x0000, 0x0191, 0x031e, 0x04a4, 0x061e, 0x0789, 0x08e2, 0x0a24,
        0x0b4e, 0x0c5c, 0x0d4b, 0x0e1a, 0x0ec6, 0x0f4d, 0x0faf, 0x0fea,
};

static lws_led_intensity_t sine_lu(int n)
{
        switch ((n >> 4) & 3) {
        case 1:
                return 4096 + sineq16[n & 15];
        case 2:
                return 4096 + sineq16[15 - (n & 15)];
        case 3:
                return 4096 - sineq16[n & 15];
        default:
                return  4096 - sineq16[15 - (n & 15)];
        }
}

/* useful for sine led fade patterns */

lws_led_intensity_t lws_led_func_sine(int n)
{
        /*
         * 2: quadrant
         * 4: table entry in quadrant
         * 4: interp (LSB)
         *
         * total 10 bits / 1024 steps per cycle
	 *
	 * +   0: 0
	 * + 256: 4096
	 * + 512: 8192
	 * + 768: 4096
	 * +1023: 0
         */

        return (sine_lu(n >> 4) * (15 - (n & 15)) +
                sine_lu((n >> 4) + 1) * (n & 15)) / 15;
}

const lws_led_sequence_def_t lws_ledseq_sine_wipe = {
		.func			= lws_led_func_sine,
		.ledphase_offset	= 0, /* already at 0 amp at 0 phase */
		.ledphase_total		= 512, /* 180 degree phase ./^ */
		.ms_full_phase		= 1000, /* ie, 500ms for 180 degree */
};

