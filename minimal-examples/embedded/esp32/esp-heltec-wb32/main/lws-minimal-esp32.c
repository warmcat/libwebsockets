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

#include <driver/gpio.h>

#include <libwebsockets.h>

struct lws_context *context;
lws_sorted_usec_list_t sul;
struct lws_led_state *lls;
lws_display_state_t lds;
lws_netdev_instance_wifi_t *wnd;
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
	{ .gpio = GPIO_NUM_25, .index = 0, .active_level = 1 }
};

static const lws_pwm_ops_t pwm_ops = {
	lws_pwm_plat_ops,
	.pwm_map			= &pwm_map[0],
	.count_pwm_map			= LWS_ARRAY_SIZE(pwm_map)
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

static const lws_netdev_ops_t wifi_ops = {
	lws_netdev_wifi_plat_ops
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
	struct lws_context_creation_info info;
	struct lws_button_state *bcs;
	int n = 0;

	lws_set_log_level(15, NULL);

        lws_netdev_plat_init();
        lws_netdev_plat_wifi_init();

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

	/* create the wifi network device and configure it */

	wnd = (lws_netdev_instance_wifi_t *)
			wifi_ops.create(context, &wifi_ops, "wl0", NULL);
	if (!wnd) {
		lwsl_err("%s: failed to create wifi object\n", __func__);
		goto spin;
	}

	strcpy(wnd->sta.creds.ssid, "xxx");
	strcpy(wnd->sta.creds.passphrase, "yyy");
	wnd->flags |= LNDIW_MODE_STA;

	if (wifi_ops.configure(&wnd->inst, NULL)) {
		lwsl_err("%s: failed to configure wifi object\n", __func__);
		goto spin;
	}
	wifi_ops.up(&wnd->inst);

	lls = lgc.led_ops.create(&lgc.led_ops);
	if (!lls) {
		lwsl_err("%s: could not create led\n", __func__);
		goto spin;
	}

	/* pwm init must go after the led controller init */

	pwm_ops.init(&pwm_ops);

	bcs = lws_button_controller_create(context, &bc);
	if (!bcs) {
		lwsl_err("%s: could not create buttons\n", __func__);
		goto spin;
	}

	/*
	 * Show the lws logo on the display
	 */

	lws_display_state_init(&lds, context, 10000, 20000, lls, &disp.disp);
	disp.disp.blit(lds.disp, img, 0, 0, 128, 64);
	lws_display_state_active(&lds);

	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));
	lws_led_transition(lls, "alert", &lws_pwmseq_static_off,
			   &lws_pwmseq_static_on);

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
