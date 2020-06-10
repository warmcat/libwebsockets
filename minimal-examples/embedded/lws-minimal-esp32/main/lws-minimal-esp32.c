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
#include <driver/gpio.h>

#include <libwebsockets.h>

struct lws_context *context;
lws_sorted_usec_list_t sul;
lws_display_state_t lds;
int interrupted;

static void
esp32_i2c_delay(void)
{
	ets_delay_us(1);
}

static const lws_bb_i2c_t li2c = {
	.bb_ops			= lws_bb_i2c_ops,
	.scl			= GPIO_NUM_15,
	.sda			= GPIO_NUM_4,
	.gpio			= &lws_gpio_plat,
	.delay			= esp32_i2c_delay
};

static const lws_display_ssd1306_t disp = {
	.disp = {
		lws_display_ssd1306_ops,
		.w	= 128,
		.h	= 64
	},
	.i2c		= (lws_i2c_ops_t *)&li2c,
	.gpio		= &lws_gpio_plat,
	.reset_gpio	= GPIO_NUM_16,
	.i2c7_address	= SSD1306_I2C7_ADS1
};

static const uint8_t img[] = {
#include "../banded-img.h"
};

static void
sul_cb(lws_sorted_usec_list_t *sul)
{
	//interrupted = 1;
	lwsl_notice("Completed: PASS\n");
}

void 
app_main(void)
{
	wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
	struct lws_context_creation_info info;
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

	lwsl_notice("LWS test for Heltec WB32 ESP32 board\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return;
	}

	/*
	 * Show the lws logo on the display
	 */

	lws_display_state_init(&lds, context, 10000, 20000, 200, 10, &disp.disp);
	lws_display_state_active(&lds);
	disp.disp.blit(lds.disp, img, 0, 0, 128, 64);

	/*
	 * We say the test succeeded if we survive 3s around the event loop
	 */

	lws_sul_schedule(context, 0, &sul, sul_cb, 3 * LWS_USEC_PER_SEC);

	while (n >= 0 && !interrupted) {
		n = lws_service(context, 0);
		taskYIELD();
	}

	lws_context_destroy(context);

//	fflush(stdout);
//	esp_restart();

spin:
	vTaskDelay(10);
	taskYIELD();
	goto spin;
}
