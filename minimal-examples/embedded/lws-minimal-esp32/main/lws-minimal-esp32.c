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
struct lws_led_state *lls;
lws_display_state_t lds;
int interrupted;

/*
 * Hook up bitbang i2c, display driver and display
 */

static void
esp32_i2c_delay(void)
{
	ets_delay_us(1);
}

static const lws_bb_i2c_t li2c = {
	.bb_ops				= lws_bb_i2c_ops,
	.scl				= GPIO_NUM_15,
	.sda				= GPIO_NUM_4,
	.gpio				= &lws_gpio_plat,
	.delay				= esp32_i2c_delay
};

static const lws_display_ssd1306_t disp = {
	.disp = {
		lws_display_ssd1306_ops,
		.w			= 128,
		.h			= 64
	},
	.i2c				= (lws_i2c_ops_t *)&li2c,
	.gpio				= &lws_gpio_plat,
	.reset_gpio			= GPIO_NUM_16,
	.i2c7_address			= SSD1306_I2C7_ADS1
};

/*
 * Button controller
 */

static const lws_button_map_t bcm[] = {
	{
		.gpio			= GPIO_NUM_0,
		.smd_interaction_name	= "user"
	},
};

static const lws_button_controller_t bc = {
	.smd_bc_name			= "bc",
	.gpio_ops			= &lws_gpio_plat,
	.button_map			= &bcm[0],
	.active_state_bitmap		= 0,
	.count_buttons			= LWS_ARRAY_SIZE(bcm),
};

/*
 * pwm controller
 */

static const lws_pwm_map_t pwm_map[] = {
	{ .gpio = GPIO_NUM_25, .index = 0 }
};

static const lws_pwm_ops_t pwm_ops = {
	lws_pwm_plat_ops,
	.pwm_map			= &pwm_map[0],
	.count_pwm_map			= LWS_ARRAY_SIZE(pwm_map)
};

/*
 * led controller
 */

static const lws_led_gpio_map_t lgm[] = {
	{
		.name			= "alert",
		.gpio			= GPIO_NUM_25,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 1,
	},
};

static const lws_led_gpio_controller_t lgc = {
	.led_ops			= lws_led_gpio_ops,
	.gpio_ops			= &lws_gpio_plat,
	.led_map			= &lgm[0],
	.count_leds			= LWS_ARRAY_SIZE(lgm)
};

static const uint8_t img[] = {
#include "../banded-img.h"
};

static uint8_t flip;

static const lws_led_sequence_def_t *seqs[] = {
	&lws_pwmseq_static_on,
	&lws_pwmseq_static_off,
	&lws_pwmseq_sine_endless_slow,
	&lws_pwmseq_sine_endless_fast,
};

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{

	if (!lws_json_simple_strcmp(buf, len, "\"src\":", "bc/user")) {
		if (!lws_json_simple_strcmp(buf, len, "\"event\":", "click")) {
			lws_led_transition(lls, "alert", seqs[flip & 3],
					   &lws_pwmseq_linear_wipe);
			flip++;
		}
	}

	lwsl_hexdump_notice(buf, len);

	/*
	 * Any kind of user interaction brings the display back up and resets
	 * the dimming and blanking timers
	 */
	lws_display_state_active(&lds);

	return 0;
}

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
	struct lws_button_state *bcs;
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
	info.early_smd_cb = smd_cb;
	info.early_smd_class_filter = LWSSMDCL_INTERACTION;
	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return;
	}

	lls = lgc.led_ops.create(&lgc.led_ops);
	if (!lls) {
		lwsl_err("%s: could not create led\n", __func__);
		goto spin;
	}

	/* pwm init must go after the led controller init */

	pwm_ops.init(&pwm_ops);
	lgc.led_ops.intensity(&lgc.led_ops, "alert", 0);
//	lws_led_transition(lls, 0, &lws_pwmseq_sine_endless, NULL);

	bcs = lws_button_controller_create(context, &bc);
	if (!bcs) {
		lwsl_err("%s: could not create buttons\n", __func__);
		goto spin;
	}

	/*
	 * Show the lws logo on the display
	 */

	lws_display_state_init(&lds, context, 10000, 20000, 200, 10, &disp.disp);
	lws_display_state_active(&lds);
	disp.disp.blit(lds.disp, img, 0, 0, 128, 64);

	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));
	lgc.led_ops.intensity(&lgc.led_ops, "alert", 0);

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
