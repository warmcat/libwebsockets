/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 * lws_ota platform implementation for esp-idf
 *
 * The whole platform OTA implementation runs in its own task context, which
 * is created in ota_start() and ends after doing ABORT or FINALIZE.  Async
 * completions are passed back to the main code by lws_cancel_service().
 *
 * The task uses the lws_ota_t (eg, g->buf while writing it to flash) until it
 * ends.  lws doesn't free it before taking the ABORT or FINALIZE completion,
 * except when it is destroyed from outside (eg, context destroy): then it
 * calls lws_plat_ota_detach(), which waits for the task to end.
 */

#include "private-lib-core.h"
#include "esp_ota_ops.h"

extern lws_settings_instance_t *si;

/*
 * Our platform-specific single OTA process object, it knows the esp-idf OTA
 * handle too after ota_start succeeds.
 */

typedef struct {
	lws_ota_t			*g;

	esp_ota_handle_t		ota; /* opaque platform ota handle */
	TaskHandle_t			th;
	SemaphoreHandle_t		sem; /* given by the task as it ends */
	const esp_partition_t		*ep;
	volatile uint8_t		detached;
	uint8_t				begun; /* pop.ota is valid */
} _lws_ota_process_t;

static _lws_ota_process_t pop;

static void
ota_task_completed(lws_ota_t *g)
{
	if (pop.detached)
		/* lws is waiting in lws_plat_ota_detach() and wants no
		 * completions now, the task ending is what it waits for */
		return;

	g->async_completed = 1;
	lws_cancel_service(g->cx);
}

static void
ota_task(void *_g)
{
	lws_ota_t *g = (lws_ota_t *)_g;
	esp_err_t e;
	uint32_t no;

	while (1) {

		xTaskNotifyWaitIndexed(0, 0, ULONG_MAX, &no, portMAX_DELAY);

		/* something to do */

		g->async_r = LWSOTARET_ONGOING;

		switch (no) {

		case LWS_OTA_ASYNC_START:
			pop.ep = esp_ota_get_next_update_partition(NULL);

			g->async_r = LWSOTARET_NOSLOT;

			/*
			 * With only one OTA partition, the next one is the one
			 * we are running from, and esp_ota_begin() can only
			 * fail with ESP_ERR_OTA_PARTITION_CONFLICT
			 */

			if (!pop.ep || pop.ep == esp_ota_get_running_partition()) {
				lwsl_err("%s: no OTA partition to update into, "
					 "the partition table needs two\n",
					 __func__);
				ota_task_completed(g);
				break;
			}

			if (g->expected_size > pop.ep->size) {
				lwsl_err("%s: image %u bigger than partition "
					 "%s (%u)\n", __func__,
					 (unsigned int)g->expected_size,
					 pop.ep->label,
					 (unsigned int)pop.ep->size);
				ota_task_completed(g);
				break;
			}

			e = esp_ota_begin(pop.ep, g->expected_size, &pop.ota);
			if (e == ESP_OK) {
				pop.begun = 1;
				g->async_r = LWSOTARET_OK;
			} else {
				g->async_r = LWSOTARET_FAILED;
				lwsl_err("%s: esp_ota_begin: %s\n", __func__,
					 esp_err_to_name(e));
			}

			ota_task_completed(g);
			break;

		case LWS_OTA_ASYNC_WRITE:
			/*
			 * g->flow has compressed data we can use when we
			 * need it
			 */

			g->async_r = LWSOTARET_FAILED;
			e = esp_ota_write(pop.ota, g->buf, g->buf_len);
			if (e == ESP_OK)
				g->async_r = LWSOTARET_OK;
			else
				lwsl_cx_err(g->cx, "esp_ota_write: %s",
					    esp_err_to_name(e));

			ota_task_completed(g);
			break;

		case LWS_OTA_ASYNC_ABORT:
		case LWS_OTA_ASYNC_FINALIZE:

			g->async_r = LWSOTARET_FAILED;
			if (no == LWS_OTA_ASYNC_ABORT) {
				/*
				 * If START failed, there is no platform
				 * update to abort, only the task to end
				 */
				e = ESP_OK;
				if (pop.begun) {
					e = esp_ota_abort(pop.ota);
					if (e != ESP_OK)
						lwsl_cx_err(g->cx,
							"esp_ota_abort: %s",
							esp_err_to_name(e));
				}
			} else {
				e = esp_ota_end(pop.ota);
				if (e != ESP_OK)
					lwsl_cx_err(g->cx, "esp_ota_end: %s",
						    esp_err_to_name(e));
				if (e == ESP_OK) {
					/*
					 * Mark that we want to boot into the
					 * updated firmware that we just
					 * installed
					 */

					e = esp_ota_set_boot_partition(pop.ep);
					if (e != ESP_OK)
						lwsl_cx_err(g->cx,
							"esp_ota_set_boot_partition: %s",
							esp_err_to_name(e));
				}
				if (e == ESP_OK) {
					struct timeval tv;

					/*
					 * Set the latest fw unixtime to the new
					 * guy.  Set the time we updated.
					 */

					lws_settings_plat_printf(si,
						"ota.fw_unixtime", "%llu",
						(unsigned long long)g->unixtime);

					if (!gettimeofday(&tv, NULL))
						lws_settings_plat_printf(si,
							"ota.upd_unixtime", "%llu",
							(unsigned long long)tv.tv_sec);
				}
			}
			pop.begun = 0;
			if (e == ESP_OK)
				g->async_r = LWSOTARET_OK;

			/*
			 * Once lws sees this completion, it may free g at
			 * any time: we must not touch g after it
			 */
			ota_task_completed(g);

			/* if lws_plat_ota_detach() is waiting, it can go on */
			xSemaphoreGive(pop.sem);
			vTaskDelete(NULL);

			return;
		}
	}
}

/*
 * lws only queues an op when none is in flight, and nothing after ABORT or
 * FINALIZE, so the task is alive and waiting whenever this is called
 */

void
lws_plat_ota_queue(lws_ota_t *g, lws_ota_async_t a)
{
	if (!pop.th || pop.g != g) {
		lwsl_err("%s: no ota task for %p\n", __func__, (void *)g);
		return;
	}

	g->async_last = a;
	xTaskNotify(pop.th, a, eSetValueWithOverwrite);
}

int
lws_plat_ota_start(lws_ota_t *g)
{
	/*
	 * The last task, if any, gives the semaphore as it ends (unless
	 * lws_plat_ota_detach() already took it)
	 */
	if (pop.g && xSemaphoreTake(pop.sem, 0) != pdTRUE) {
		lwsl_err("%s: ota task still active\n", __func__);
		return 1;
	}

	if (pop.sem)
		vSemaphoreDelete(pop.sem);
	pop.sem = NULL;
	pop.g = NULL;
	pop.th = NULL;
	pop.detached = 0;
	pop.begun = 0;

	pop.sem = xSemaphoreCreateBinary();
	if (!pop.sem)
		return 1;

	if (xTaskCreate(ota_task, "ota", 3072, g, tskIDLE_PRIORITY,
			&pop.th) != pdPASS) {
		pop.th = NULL;
		return 1;
	}

	pop.g = g;
	g->op = (lws_ota_process_t)&pop;

	lws_plat_ota_queue(g, LWS_OTA_ASYNC_START);

	return 0;
}

/*
 * lws is about to free g, eg because the context is being destroyed, while
 * our task may still be using it.  Make the task abort and end, and wait for
 * that, so g outlives everything the task does with it.
 */

void
lws_plat_ota_detach(lws_ota_t *g)
{
	if (pop.g != g)
		return;

	pop.detached = 1;

	/*
	 * Only lws (on this thread) queues ABORT or FINALIZE, and the task only
	 * ends after one of those.  If neither was queued, the task is still
	 * alive (perhaps busy with a write, it sees the notification after)
	 * and needs telling.  If one was, the task is ending or has ended and
	 * given the semaphore, and must not be notified.
	 */

	if (g->async_last != LWS_OTA_ASYNC_ABORT &&
	    g->async_last != LWS_OTA_ASYNC_FINALIZE)
		lws_plat_ota_queue(g, LWS_OTA_ASYNC_ABORT);

	/*
	 * Flash ops can take a while, but we must not let g be freed under
	 * the task, so wait however long it takes
	 */
	xSemaphoreTake(pop.sem, portMAX_DELAY);

	pop.th = NULL;
	pop.g = NULL;
	g->op = NULL;
}

int
lws_plat_ota_report_current(lws_ota_t *g, int bad)
{
	if (bad)
		esp_ota_mark_app_invalid_rollback_and_reboot();
	else
		esp_ota_mark_app_valid_cancel_rollback();

	return LWSOTARET_OK;
}

int
lws_plat_ota_get_last_fw_unixtime(uint64_t *fw_unixtime)
{
	uint8_t buf[20];
	size_t l = sizeof(buf);

	if (lws_settings_plat_get(si, "ota.fw_unixtime", buf, &l)) {
		lwsl_notice("%s: not in settings\n", __func__);
		return 1;
	}

	*fw_unixtime = atoll((const char *)buf);

	return 0;
}
