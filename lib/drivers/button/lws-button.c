/*
 * Generic GPIO / irq buttons
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

#if defined(LWS_PLAT_FREERTOS)
#include <freertos/timers.h>
#endif

/*
 * This is the opaque, allocated, non-const, dynamic footprint of the
 * button controller
 */

typedef struct lws_button_state {
#if defined(LWS_PLAT_FREERTOS)
	TimerHandle_t				timer;
#endif
	const lws_button_controller_t		*controller;
	struct lws_context			*ctx;
	lws_button_idx_t			enable_bitmap;
	lws_button_idx_t			state_bitmap;
} lws_button_state_t;

/*
 * This is the bottom-half scheduled via a timer set in the ISR.  From here
 * we are allowed to hold mutexes etc.  We are coming here because any button
 * interrupt arrived, we have to try to figure out which events have happened.
 */

#if defined(LWS_PLAT_FREERTOS)
static void
lws_button_bh(TimerHandle_t th)
{
	lws_button_state_t *bcs = pvTimerGetTimerID(th);

	lws_smd_msg_printf(bcs->ctx, LWSSMDCL_INTERACTION,
			   "{\"btn\":\"%s/%s\", \"s\":\"click\"}",
			   bcs->controller->smd_bc_name,
			   bcs->controller->button_map[0].smd_interaction_name);

#if 0
	if (lws_esp32.button_is_down)
		gpio_set_intr_type(GPIO_SW, GPIO_INTR_POSEDGE);
	else
		gpio_set_intr_type(GPIO_SW, GPIO_INTR_NEGEDGE);

	lws_esp32.button_is_down = gpio_get_level(GPIO_SW);

	lws_esp32_button(lws_esp32.button_is_down);
#endif
}
#endif

struct lws_button_state *
lws_button_controller_create(struct lws_context *ctx,
			     const lws_button_controller_t *controller)
{
	lws_button_state_t *bcs = lws_zalloc(sizeof(lws_button_state_t), __func__);

	if (!bcs)
		return NULL;

	bcs->controller = controller;
	bcs->ctx = ctx;

#if defined(LWS_PLAT_FREERTOS)
        bcs->timer = xTimerCreate("bcst", 1, 0, bcs,
                          (TimerCallbackFunction_t)lws_button_bh);
#endif

	return bcs;
}

void
lws_button_controller_destroy(struct lws_button_state *bcs)
{
	/* disable them all */
	lws_button_enable(bcs, 0, 0);

#if defined(LWS_PLAT_FREERTOS)
        xTimerDelete(&bcs->timer, 0);
#endif

	lws_free(bcs);
}

/*
 * This is happening in interrupt context, we have to schedule a bottom half to
 * do the foreground lws_smd queueing, using, eg, a platform timer.
 *
 * All the buttons point here and use one timer per button controller.  An
 * interrupt here means, "something happened to one or more buttons"
 */

void
lws_button_irq_cb_t(void *arg)
{
#if defined(LWS_PLAT_FREERTOS)
	lws_button_state_t *bcs = (lws_button_state_t *)arg;

	xTimerStart(bcs->timer, 0);
#endif
}

lws_button_idx_t
lws_button_get_bit(struct lws_button_state *bcs, const char *name)
{
	const lws_button_controller_t *bc = bcs->controller;
	int n;

	for (n = 0; n < bc->count_buttons; n++)
		if (!strcmp(name, bc->button_map[n].smd_interaction_name))
			return 1 << n;

	return 0; /* not found */
}

void
lws_button_enable(lws_button_state_t *bcs,
		  lws_button_idx_t _reset, lws_button_idx_t _set)
{
	lws_button_idx_t u = (bcs->enable_bitmap & (~_reset)) | _set;
	const lws_button_controller_t *bc = bcs->controller;
	int n;

	for (n = 0; n < bcs->controller->count_buttons; n++) {
		if (!(bcs->enable_bitmap & (1 << n)) && (u & (1 << n))) {
			/* set as input with pullup or pulldown appropriately */
			bc->gpio_ops->mode(bc->button_map[n].gpio,
				LWSGGPIO_FL_READ |
				((bc->active_state_bitmap & (1 << n)) ?
				LWSGGPIO_FL_PULLDOWN : LWSGGPIO_FL_PULLUP));
			/* this one is becoming enabled */
			bc->gpio_ops->irq_mode(bc->button_map[n].gpio,
					bc->active_state_bitmap & (1 << n) ?
						LWSGGPIO_IRQ_RISING :
							LWSGGPIO_IRQ_FALLING,
						lws_button_irq_cb_t, bcs);
		}
		if ((bcs->enable_bitmap & (1 << n)) && !(u & (1 << n)))
			/* this one is becoming disabled */
			bc->gpio_ops->irq_mode(bc->button_map[n].gpio,
						LWSGGPIO_IRQ_NONE, NULL, NULL);
	}

	bcs->enable_bitmap = u;
}
