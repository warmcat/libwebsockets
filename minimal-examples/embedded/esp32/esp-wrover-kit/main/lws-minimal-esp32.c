/*
 * lws-minimal-esp32
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Configured for ESP32 WROVER KIT
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

static const uint8_t logo[] = {
#include "cat-565.h"
};

/*
 * Button controller
 *
 * On the WROVER KIT, it's a bit overloaded... the two buttons are reset and
 * gpio0, gpio is also used for one of the RGB LEDs channels control so it's not
 * really usable as a general user button.
 *
 * Instead we use GPIO 14 (available on J1) for a button with the other side
 * of the switch connected to 0V.
 */

static const lws_button_map_t bcm[] = {
	{
		.gpio			= GPIO_NUM_14,
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
	{ .gpio = GPIO_NUM_2, .index = 0, .active_level = 1 },
	{ .gpio = GPIO_NUM_0, .index = 1, .active_level = 1 },
	{ .gpio = GPIO_NUM_4, .index = 2, .active_level = 1 },
	{ .gpio = GPIO_NUM_5, .index = 3, .active_level = 0 }
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
		.name			= "red",
		.gpio			= GPIO_NUM_2,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 1,
	},
	{
		.name			= "green",
		.gpio			= GPIO_NUM_0,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 1,
	},
	{
		.name			= "blue",
		.gpio			= GPIO_NUM_4,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 1,
	},
	{
		.name			= "backlight",
		.gpio			= GPIO_NUM_5,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 0,
		/*
		 * The wrover kit uses a 2 NPN in series to drive the backlight
		 * which means if the GPIO provides no current, the backlight is
		 * full-on.  This causes a white flash during boot... they mark
		 * the first stage with "Modify In ESP-WROVER-KIT!" on the
		 * schematics but on Kit v4.1, it's still like that.
		 */
	},
};

static const lws_led_gpio_controller_t lgc = {
	.led_ops			= lws_led_gpio_ops,
	.gpio_ops			= &lws_gpio_plat,
	.led_map			= &lgm[0],
	.count_leds			= LWS_ARRAY_SIZE(lgm)
};

/*
 * Bitbang SPI configuration for display
 */

static const lws_bb_spi_t lbspi = {
		.bb_ops = {
			lws_bb_spi_ops,
			.bus_mode = LWS_SPI_BUSMODE_CLK_IDLE_LOW_SAMP_RISING
		},
		.gpio		= &lws_gpio_plat,
		.clk		= GPIO_NUM_19,
		.ncs		= { GPIO_NUM_22 },
		.ncmd		= { GPIO_NUM_21 },
		.mosi		= GPIO_NUM_23,
		.miso		= GPIO_NUM_25,
		.flags		= LWSBBSPI_FLAG_USE_NCS0 |
				  LWSBBSPI_FLAG_USE_NCMD0
};

/*
 * SPI display
 */

static const lws_display_ili9341_t disp = {
	.disp = {
		lws_display_ili9341_ops,
		.bl_pwm_ops		= &pwm_ops,
		.bl_active		= &lws_pwmseq_static_on,
		.bl_dim			= &lws_pwmseq_static_half,
		.bl_transition		= &lws_pwmseq_linear_wipe,
		.bl_index		= 3,
		.w			= 320,
		.h			= 240,
		.latency_wake_ms	= 150,
	},
	.spi				= (lws_spi_ops_t *)&lbspi,
	.gpio				= &lws_gpio_plat,
	.reset_gpio			= GPIO_NUM_18,
	.spi_index			= 0
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
			lws_led_transition(lls, "blue", seqs[flip & 3],
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
	/* In CI, we use sai-expect to look for this string for success */
	lwsl_notice("Completed: PASS\n");
}

void 
app_main(void)
{
	wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
	struct lws_context_creation_info info;
	struct lws_button_state *bcs;
	int n = 0;

	lws_set_log_level(1024 | 15, NULL);
        nvs_flash_init();
	esp_netif_init();

	n = esp_wifi_init(&wic);
	if (n) {
		lwsl_err("%s: wifi init fail: %d\n", __func__, n);
		goto spin;
	}

	memset(&info, 0, sizeof(info));

	lwsl_notice("LWS test for Espressif ESP32 WROVER KIT\n");

	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.early_smd_cb = smd_cb;
	info.early_smd_class_filter = LWSSMDCL_INTERACTION;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return;
	}

	/* bring up the led controller */

	lls = lgc.led_ops.create(&lgc.led_ops);
	if (!lls) {
		lwsl_err("%s: could not create led\n", __func__);
		goto spin;
	}

	/* pwm init must go after the led controller init */

	pwm_ops.init(&pwm_ops);

	/* ... and the button controller */

	bcs = lws_button_controller_create(context, &bc);
	if (!bcs) {
		lwsl_err("%s: could not create buttons\n", __func__);
		goto spin;
	}

	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));

	/* ... bring up spi bb and the display */

	lbspi.bb_ops.init(&lbspi.bb_ops);
	lws_display_state_init(&lds, context, 30000, 10000, lls, &disp.disp);

	/* put the cat picture up there and enable the backlight */

	disp.disp.blit(lds.disp, logo, 0, 0, 320, 240);
	lws_display_state_active(&lds);

	/*
	 * Make the RGB LED do something using sequenced PWM... pressing the
	 * GPIO14 button with single-presses advances the blue channel between
	 * different sequences
	 */

	lws_sul_schedule(context, 0, &sul, sul_cb, 3 * LWS_USEC_PER_SEC);
	lws_led_transition(lls, "blue", &lws_pwmseq_sine_endless_fast,
					   &lws_pwmseq_linear_wipe);
	lws_led_transition(lls, "green", &lws_pwmseq_sine_endless_slow,
					   &lws_pwmseq_linear_wipe);
	lws_led_transition(lls, "red", &lws_pwmseq_sine_endless_slow,
					   &lws_pwmseq_linear_wipe);

	/*
	 * We say the test succeeded if we survive 3s around the event loop
	 */

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
