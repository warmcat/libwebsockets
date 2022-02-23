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
 * is created in ota_start() and taken down in ota_finalize().  Async
 * completions are passed back to the main code by lws_cancel_service().
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
	SemaphoreHandle_t		sem;
	const esp_partition_t		*ep;
} _lws_ota_process_t;

static _lws_ota_process_t pop;

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

			if (pop.ep) {
				e = esp_ota_begin(pop.ep, g->expected_size,
						  &pop.ota);
				if (e == ESP_OK)
					g->async_r = LWSOTARET_OK;
				else
					printf("esp_ota_begin: %d\n", (int)e);
			} else
				lwsl_err("%s: no next update part\n", __func__);

			g->async_completed = 1;
			lws_cancel_service(g->cx);
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
				lwsl_cx_err(g->cx, "esp_ota_write: %d", (int)e);

			g->async_completed = 1;
			lws_cancel_service(g->cx);
			break;

		case LWS_OTA_ASYNC_ABORT:
		case LWS_OTA_ASYNC_FINALIZE:

			g->async_r = LWSOTARET_FAILED;
			if (no == LWS_OTA_ASYNC_ABORT)
				e = esp_ota_abort(pop.ota);
			else {
				e = esp_ota_end(pop.ota);
				if (e == ESP_OK) {
					struct timeval tv;

					/*
					 * Mark that we want to boot into the
					 * updated firmware that we just
					 * installed
					 */

					e = esp_ota_set_boot_partition(pop.ep);

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
			if (e == ESP_OK)
				g->async_r = LWSOTARET_OK;
			else
				lwsl_cx_err(g->cx, "esp_ota_end: %d", (int)e);

			g->async_completed = 1;
			lws_cancel_service(g->cx);

			pop.th = NULL;
			vTaskDelete(0);

			return;
		}
	}
}

void
lws_plat_ota_queue(lws_ota_t *g, lws_ota_async_t a)
{
	g->async_last = a;
	xTaskNotify(pop.th, a, eSetValueWithOverwrite);
}

int
lws_plat_ota_start(lws_ota_t *g)
{
	g->op = (lws_ota_process_t)&pop;

	xTaskCreate(ota_task, "ota", 3072, g, tskIDLE_PRIORITY, &pop.th);
	if (!pop.th)
		return 1;

	lws_plat_ota_queue(g, LWS_OTA_ASYNC_START);

	return 0;
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
