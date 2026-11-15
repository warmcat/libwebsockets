/*
 * devices for LilyGo T-Display S3 Long
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A 180 x 640 LCD on an AXS15231B controller, on quad SPI, with a CST3530
 * touch controller over it on i2c.  The display and touch controller share
 * one reset line, GPIO16, which the display driver pulses.  Touching a link
 * on the displayed page follows it.
 *
 * The i2c bus also has the board's SY6970 battery charger on it, at 0x6a,
 * which isn't used here.
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
 * The only button we can use is BOOT on GPIO0, which is an ordinary input
 * once we are running.  The other one LilyGo's pin list gives, GPIO21, is
 * the display's third QSPI data line.
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
 * pwm controller, the only thing on it is the backlight, GPIO1 is the
 * enable of its LED driver
 */

static const lws_pwm_map_t pwm_map[] = {
        { .gpio = GPIO_NUM_1, .index = 0, .active_level = 1 },
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
                .gpio                   = GPIO_NUM_1,
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
 * Quad SPI for the display: the pixels go on four data lines.  There's no
 * D/C line, the controller is told what is coming in the header of each
 * transaction.  LilyGo found it corrupted at 40MHz.
 */

static const lws_bb_spi_t lbspi = {
		.bb_ops = {
			lws_esp32_spi_ops,
			.spi_clk_hz = 32000000,
			.bus_mode = LWS_SPI_BUSMODE_CLK_IDLE_LOW_SAMP_RISING
		},
		.gpio		= &lws_gpio_plat,
		.clk		= GPIO_NUM_17,
		.ncs		= { GPIO_NUM_12 },
		.mosi		= GPIO_NUM_13,	/* D0 */
		.miso		= GPIO_NUM_18,	/* D1 */
		.d2		= GPIO_NUM_21,
		.d3		= GPIO_NUM_14,

		.unit		= 1, /* SPI2_HOST */

		.flags		= LWSBBSPI_FLAG_USE_NCS0,
		.quad		= 1,
};

/*
 * QSPI display
 */

const lws_display_axs15231b_t disp = {
	.disp = {
		lws_display_axs15231b_ops,
		.bl_pwm_ops             = &pwm_ops,
		.bl_active              = &lws_pwmseq_static_on,
		.bl_dim                 = &lws_pwmseq_static_half,
		.bl_transition          = &lws_pwmseq_linear_wipe,
		.bl_index               = 0,

		.ic = {
			/* the panel's own portrait way up, it can't rotate */
			.wh_px = { { 180,0 },      { 640,0 } },
			/* 3.4in diagonal */
			.wh_mm = { { 23,38000000 },  { 83,14000000 } },
			.type	= LWSSURF_565,
		},
		.name			= "LilyGo T-Display S3 Long 180x640 LCD",
		.latency_wake_ms	= 150,
	},
	.cb				= display_completion_cb,
	.spi				= (lws_spi_ops_t *)&lbspi,
	.gpio				= &lws_gpio_plat,
	.reset_gpio			= GPIO_NUM_16,
	.spi_index			= 0
};

/*
 * i2c for the touch panel, bitbanged on GPIO15 (SDA) and GPIO10 (SCL)
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
	.scl				= GPIO_NUM_10,
	.sda				= GPIO_NUM_15,
	.gpio				= &lws_gpio_plat,
	.delay				= esp32_i2c_delay
};

/*
 * The touch panel reports in the LCD's own pixels, the same way up.  Its
 * reset is the display's, which the display driver releases 130ms after it
 * is initialized: the driver's default settle time looks for it after that,
 * and it's retried for a while if it isn't answering yet.
 */

static const lws_touch_cst3530_t touch = {
	.touch = {
		lws_touch_cst3530_ops,
		.gpio			= &lws_gpio_plat,
		.name			= "ts",
		.wh_native		= { 180, 640 },
		.wh_px			= { 180, 640 },
		.irq_gpio		= GPIO_NUM_11,
		.irq_edge		= LWSGGPIO_IRQ_FALLING,
	},
	.i2c				= &li2c.bb_ops,
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

	/* ... bring up spi and the display, which resets the touch too */

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
