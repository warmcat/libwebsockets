/*
 * devices for Waveshare ESP32-S3-Touch-LCD-1.28
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A 240px round GC9A01A LCD on SPI, with a CST816S touch panel over it on
 * i2c.  Touching a link on the displayed page follows it.
 */

#include "../../main.h"

struct lws_led_state *lls;
lws_display_state_t lds;
struct lws_button_state *bcs;
lws_netdev_instance_wifi_t *wnd;
lws_settings_instance_t *si;

const char *carousel_urls[] = {
        "https://slashdot.org",
        "https://libwebsockets.org/lhp-tests/t4.html",
        "https://libwebsockets.org/lhp-tests/t7.html",
        "https://libwebsockets.org/lhp-tests/t1.html",
        "https://libwebsockets.org/lhp-tests/t2.html",
        NULL
};

static const uint8_t fira_c_r_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular10.mcufont.h"
};
static const uint8_t fira_c_r_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};
static const uint8_t fira_c_r_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular14.mcufont.h"
};
static const uint8_t fira_c_r_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_r_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular20.mcufont.h"
};
static const uint8_t fira_c_r_24[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular24.mcufont.h"
};
static const uint8_t fira_c_b_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold10.mcufont.h"
};
static const uint8_t fira_c_b_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold12.mcufont.h"
};
static const uint8_t fira_c_b_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold14.mcufont.h"
};
static const uint8_t fira_c_b_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold16.mcufont.h"
};
static const uint8_t fira_c_b_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold20.mcufont.h"
};
static const uint8_t fira_c_b_24[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold24.mcufont.h"
};

/*
 * Button controller
 *
 * The only button is BOOT on GPIO0, which is an ordinary input once we are
 * running
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
 * pwm controller, the only thing on it is the backlight
 */

static const lws_pwm_map_t pwm_map[] = {
        { .gpio = GPIO_NUM_2, .index = 0, .active_level = 1 },
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
                .name                   = "backlight",
                .gpio                   = GPIO_NUM_2,
                .pwm_ops                = &pwm_ops, /* managed by pwm */
                .active_level           = 1,
	},
};

static const lws_led_gpio_controller_t lgc = {
	.led_ops			= lws_led_gpio_ops,
	.gpio_ops			= &lws_gpio_plat,
	.led_map			= &lgm[0],
	.count_leds			= LWS_ARRAY_SIZE(lgm)
};

/*
 * SPI for the display
 */

static const lws_bb_spi_t lbspi = {
		.bb_ops = {
			lws_esp32_spi_ops,
			/*
			 * Write-only (SPI_DEVICE_NO_DUMMY), so it can go this
			 * fast through the GPIO matrix, and the flex to the
			 * panel is only a couple of cm
			 */
			.spi_clk_hz = 80000000,
			.bus_mode = LWS_SPI_BUSMODE_CLK_IDLE_LOW_SAMP_RISING
		},
		.gpio		= &lws_gpio_plat,
		.clk		= GPIO_NUM_10,
		.ncs		= { GPIO_NUM_9 },
		.ncmd		= { GPIO_NUM_8 },
		.mosi		= GPIO_NUM_11,
		.miso		= GPIO_NUM_12,

		.unit		= 1, /* SPI2_HOST */

		.flags		= LWSBBSPI_FLAG_USE_NCS0 |
				  LWSBBSPI_FLAG_USE_NCMD0
};

/*
 * SPI display
 */

const lws_display_gc9a01a_t disp = {
	.disp = {
		lws_display_gc9a01a_ops,
		.bl_pwm_ops             = &pwm_ops,
		.bl_active              = &lws_pwmseq_static_on,
		.bl_dim                 = &lws_pwmseq_static_half,
		.bl_transition          = &lws_pwmseq_linear_wipe,
		.bl_index               = 0,

		.ic = {
			.wh_px = { { 240,0 },      { 240,0 } },
			.wh_mm = { { 32,40000000 },  { 32,40000000 } },
			.type	= LWSSURF_565,
			/* the panel is round: its corners can't be seen */
			.round	= 1,
			/* it can be sent a band of lines on their own */
			.band	= 1,
		},
		.name			= "Waveshare 1.28in 240x240 round LCD",
		.latency_wake_ms	= 150,
	},
	.cb				= display_completion_cb,
	.spi				= (lws_spi_ops_t *)&lbspi,
	.gpio				= &lws_gpio_plat,
	.reset_gpio			= GPIO_NUM_14,
	.spi_index			= 0
};

/*
 * i2c for the touch panel, bitbanged
 */

static void
esp32_i2c_delay(void)
{
        volatile int n = 0;

        while (n < 2)
                n++;
}

static const lws_bb_i2c_t li2c = {
	.bb_ops				= lws_bb_i2c_ops,
	.scl				= GPIO_NUM_7,
	.sda				= GPIO_NUM_6,
	.gpio				= &lws_gpio_plat,
	.delay				= esp32_i2c_delay
};

/*
 * The touch panel reports in the LCD's own pixels, the same way up
 */

static const lws_touch_cst816s_t touch = {
	.touch = {
		lws_touch_cst816s_ops,
		.gpio			= &lws_gpio_plat,
		.name			= "ts",
		.wh_native		= { 240, 240 },
		.wh_px			= { 240, 240 },
		.irq_gpio		= GPIO_NUM_5,
		.irq_edge		= LWSGGPIO_IRQ_FALLING,
	},
	.i2c				= &li2c.bb_ops,
	.reset_gpio			= GPIO_NUM_13,
	.has_reset_gpio			= 1,
};

/*
 * Settings stored in platform nv
 */

static const lws_settings_ops_t sett = {
	lws_settings_ops_plat
};

/*
 * Wifi
 */

static const lws_netdev_ops_t wifi_ops = {
	lws_netdev_wifi_plat_ops
};

int
init_plat_devices(struct lws_context *cx)
{
	lws_netdevs_t *netdevs = lws_netdevs_from_ctx(cx);

	/* held soon after starting, the button forgets the wifi credentials */
	plat_reset_button = "user";

	si = lws_settings_init(&sett, (void *)"nvs");
	if (!si) {
		lwsl_err("%s: failed to create settings instance\n", __func__);
		return 1;
	}
	netdevs->si = si;

	lws_font_register(cx, fira_c_r_10, sizeof(fira_c_r_10));
	lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12));
	lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_font_register(cx, fira_c_r_24, sizeof(fira_c_r_24));
	lws_font_register(cx, fira_c_b_10, sizeof(fira_c_b_10));
	lws_font_register(cx, fira_c_b_12, sizeof(fira_c_b_12));
	lws_font_register(cx, fira_c_b_14, sizeof(fira_c_b_14));
	lws_font_register(cx, fira_c_b_16, sizeof(fira_c_b_16));
	lws_font_register(cx, fira_c_b_20, sizeof(fira_c_b_20));
	lws_font_register(cx, fira_c_b_24, sizeof(fira_c_b_24));

	/* create the wifi network device and configure it */

	wnd = (lws_netdev_instance_wifi_t *)
				wifi_ops.create(cx, &wifi_ops, "wl0", NULL);
	if (!wnd) {
		lwsl_err("%s: failed to create wifi object\n", __func__);
		return 1;
	}

	wnd->flags |= LNDIW_MODE_STA;

	if (wifi_ops.configure(&wnd->inst, NULL)) {
		lwsl_err("%s: failed to configure wifi object\n", __func__);
		return 1;
	}

	wifi_ops.up(&wnd->inst);

	/* bring up the led controller */

	lls = lgc.led_ops.create(&lgc.led_ops);
	if (!lls) {
		lwsl_err("%s: could not create led\n", __func__);
		return 1;
	}

	/* pwm init must go after the led controller init */

	pwm_ops.init(&pwm_ops);

	/* ... and the button controller */

	bcs = lws_button_controller_create(cx, &bc);
	if (!bcs) {
		lwsl_err("%s: could not create buttons\n", __func__);
		return 1;
	}

	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));

	/* ... bring up spi and the display */

	lbspi.bb_ops.init(&lbspi.bb_ops);
	lws_display_state_init(&lds, cx, 60000, 40000, lls, &disp.disp);

	/* ... and i2c and the touch panel over it */

	li2c.bb_ops.init(&li2c.bb_ops);
	tcs = lws_touch_create(cx, &touch.touch);
	if (!tcs) {
		lwsl_err("%s: could not create touch\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * Undoes init_plat_devices(), in reverse, while the context still exists:
 * the context doesn't own these and can't free them itself
 */

void
deinit_plat_devices(struct lws_context *cx)
{
	lws_touch_destroy(&tcs);

	lws_button_controller_destroy(bcs);
	bcs = NULL;

	lgc.led_ops.destroy(lls);
	lls = NULL;

	wifi_ops.destroy((struct lws_netdev_instance **)&wnd);

	lws_netdevs_from_ctx(cx)->si = NULL;
	lws_settings_deinit(&si);
}

void
show_demo_phase(int phase)
{
	(void)phase;
}
