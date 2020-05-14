/*
 * lws-minimal-esp32
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Based on espressif Public Domain sample
 */

#define LWIP_PROVIDE_ERRNO 1
#define _ESP_PLATFORM_ERRNO_H_

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"
#include <nvs_flash.h>
#include <esp_netif.h>

#include <libwebsockets.h>

lws_sorted_usec_list_t sul;
int interrupted;

static void
sul_cb(lws_sorted_usec_list_t *sul)
{
	interrupted = 1;
}

void 
app_main(void)
{
	wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
	struct lws_context_creation_info info;
	struct lws_context *context;
	esp_chip_info_t chip_info;
	int n = 0;

	lws_set_log_level(15, NULL);
        nvs_flash_init();
	esp_netif_init();

	n = esp_wifi_init(&wic);
	if (n) {
		lwsl_err("%s: wifi init fail: %d\n", __func__, n);
		goto spin;
	}

	memset(&info, 0, sizeof(info));

	lwsl_notice("LWS minimal build test\n");

	esp_chip_info(&chip_info);
	lwsl_notice("chip: %s (%d CPU cores) WiFi%s%s\n",
		   CONFIG_IDF_TARGET, chip_info.cores,
		   (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
		   (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

	lwsl_notice("silicon revision %d\n", chip_info.revision);

	lwsl_notice("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

	lwsl_notice("Free heap: %d\n", esp_get_free_heap_size());

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return;
	}

	/*
	 * We just exit the event loop after 3s
	 */

	lws_sul_schedule(context, 0, &sul, sul_cb, 3 * LWS_USEC_PER_SEC);

	while (n >= 0 && !interrupted) {
		n = lws_service(context, 0);
		taskYIELD();
	}

	lws_context_destroy(context);

	lwsl_notice("Completed: PASS\n");
//	fflush(stdout);
//	esp_restart();

spin:
	vTaskDelay(10);
	taskYIELD();
	goto spin;
}

