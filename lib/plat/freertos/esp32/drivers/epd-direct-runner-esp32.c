/*
 * lws directly-driven EPD runner, a FreeRTOS task pinned to a core
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
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
 * See include/libwebsockets/lws-esp32-epd-direct.h
 *
 * The task calls lws_display_epd_direct_service() and waits as long as it
 * says, or for a kick from the event loop side.  It calls nothing else in
 * lws.  Waits shorter than a tick are spun, since the core is ours.
 */

#include <libwebsockets.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/idf_additions.h>
#include <esp_rom_sys.h>

/*
 * If we haven't blocked for this long, sleep a tick so the core's idle task
 * can run, eg, to feed the task watchdog
 */
#define EPDD_RUNNER_BUSY_US	(100 * LWS_US_PER_MS)

static const lws_epd_direct_esp32_runner_t *
to_er(const lws_epd_direct_runner_t *r)
{
	return lws_container_of(r, lws_epd_direct_esp32_runner_t, runner);
}

static void
runner_task(void *arg)
{
	const lws_epd_direct_esp32_runner_t *er =
				(const lws_epd_direct_esp32_runner_t *)arg;
	lws_epd_direct_esp32_runner_state_t *st = er->state;
	lws_usec_t us, busy_since = lws_now_usecs(), tick_us =
				(lws_usec_t)portTICK_PERIOD_MS * LWS_US_PER_MS;
	TickType_t ticks;

	for (;;) {
		us = lws_display_epd_direct_service(st->lds);
		if (us == LWS_EPDD_SVC_STOP)
			break;

		if (us >= 0 && us < tick_us) {
			if (lws_now_usecs() - busy_since < EPDD_RUNNER_BUSY_US) {
				if (us)
					esp_rom_delay_us((uint32_t)us);
				continue;
			}
			/* we've had the core long enough, let it idle */
			us = tick_us;
		}

		ticks = us == LWS_EPDD_SVC_IDLE ? portMAX_DELAY :
			(TickType_t)((us + tick_us - 1) / tick_us);
		ulTaskNotifyTake(pdTRUE, ticks);
		busy_since = lws_now_usecs();
	}

	/*
	 * stop() deletes us once it sees we ended, so it can keep notifying
	 * us until then without the task going away under it
	 */
	st->ended = 1;
	for (;;)
		vTaskSuspend(NULL);
}

int
lws_epd_direct_esp32_runner_start(const lws_epd_direct_runner_t *r,
				  lws_display_state_t *lds)
{
	const lws_epd_direct_esp32_runner_t *er = to_er(r);
	lws_epd_direct_esp32_runner_state_t *st = er->state;
	TaskHandle_t t;

	memset(st, 0, sizeof(*st));
	st->lds = lds;

	if (xTaskCreatePinnedToCore(runner_task, "epdd", er->stack_size,
				    (void *)er, er->priority, &t,
				    er->core) != pdPASS)
		return 1;

	st->task = t;

	return 0;
}

void
lws_epd_direct_esp32_runner_kick(const lws_epd_direct_runner_t *r)
{
	lws_epd_direct_esp32_runner_state_t *st = to_er(r)->state;

	if (st->task)
		xTaskNotifyGive((TaskHandle_t)st->task);
}

void
lws_epd_direct_esp32_runner_stop(const lws_epd_direct_runner_t *r)
{
	lws_epd_direct_esp32_runner_state_t *st = to_er(r)->state;

	if (!st->task)
		return;

	/* the service says stop, once it's unpowered the panel */

	while (!st->ended) {
		xTaskNotifyGive((TaskHandle_t)st->task);
		vTaskDelay(1);
	}

	vTaskDelete((TaskHandle_t)st->task);
	st->task = NULL;
}
