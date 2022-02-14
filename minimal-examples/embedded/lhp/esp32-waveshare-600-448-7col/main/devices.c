/*
 * devices for ESP32 Waveshare board + 600 x 448 7-colour ACEP EPD display
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include "../../main.h"

struct lws_led_state *lls;
lws_display_state_t lds;
struct lws_button_state *bcs;
lws_netdev_instance_wifi_t *wnd;
lws_settings_instance_t *si;

const char *carousel_urls[] = {
        "https://libwebsockets.org/lhp-tests/t4.html",
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
static const uint8_t fira_c_r_32[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular32.mcufont.h"
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

static const uint8_t splash_jpg[] = {
#include "splash-600-448.jpg.h"
};
static const lws_dlo_filesystem_t fs_splash = {
	.name			= "splash.jpg",
	.data			= &splash_jpg,
	.len			= sizeof(splash_jpg)
};

static const lws_button_map_t bcm[] = {
	{
		.gpio			= GPIO_NUM_0,  /* "BOOT" button */
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
//			lws_bb_spi_ops,
			lws_esp32_spi_ops,
			.spi_clk_hz = 16000000,
			.bus_mode = LWS_SPI_BUSMODE_CLK_IDLE_LOW_SAMP_RISING
		},
		.gpio		= &lws_gpio_plat,
		.clk		= GPIO_NUM_13,
		.ncs		= { GPIO_NUM_15 },
		.ncmd		= { GPIO_NUM_27 },
		.mosi		= GPIO_NUM_14,
		.miso		= GPIO_NUM_16,

		.unit		= 1,

		.flags		= LWSBBSPI_FLAG_USE_NCS0 |
				  LWSBBSPI_FLAG_USE_NCMD0
};

/*
 * SPI 7-colour Electrophoretic Display
 */

static const lws_display_colour_t palette[] = {
        PALETTE_RGBY(0, 0, 0),                  /* black */
        PALETTE_RGBY(255, 255, 255),            /* white */
        PALETTE_RGBY(0, 255, 0),                /* green */
        PALETTE_RGBY(0, 0, 255),                /* blue */
        PALETTE_RGBY(255, 0, 0),                /* red */
        PALETTE_RGBY(255, 255, 0),              /* yellow */
        PALETTE_RGBY(255, 127, 0),              /* orange */
};

const lws_display_spd1656_spi_t disp = {
        .disp = {
                lws_display_spd1656_ops,
                .ic = {
                        .wh_px = { { 600,0 },       { 448,0 } },
                        .wh_mm = { { 114,5000000 }, {  82,5000000 } },
                        .palette                = palette,
                        .palette_depth          = LWS_ARRAY_SIZE(palette),
                        .type                   = LWSSURF_PALETTE,
                },
                .name                   = "EPD: 600x448 7-colour",
                .latency_wake_ms        = 50,
        },
        .cb                             = display_completion_cb,
        .spi                            = (lws_spi_ops_t *)&lbspi,
        .gpio                           = &lws_gpio_plat,
        .reset_gpio                     = GPIO_NUM_26,
        .busy_gpio                      = GPIO_NUM_25,
        .spi_index                      = 0,
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

	si = lws_settings_init(&sett, (void *)"nvs");
	if (!si) {
		lwsl_err("%s: failed to create settings instance\n", __func__);
		return 1;
	}
	netdevs->si = si;

#if 0
	/*
	 * This is a temp hack to bootstrap the settings to contain the test
	 * AP ssid and passphrase for one time, so the settings can be stored
	 * while there's no UI atm
	 */
	{
		lws_wifi_creds_t creds;

		memset(&creds, 0, sizeof(creds));

		lws_strncpy(creds.ssid, "xx", sizeof(creds.ssid));
		lws_strncpy(creds.passphrase, "xxx", sizeof(creds.passphrase));
		lws_dll2_add_tail(&creds.list, &netdevs->owner_creds);

		if (lws_netdev_credentials_settings_set(netdevs)) {
			lwsl_err("%s: failed to write bootstrap creds\n",
					__func__);
			return 1;
		}
	}
#endif

	lws_font_register(cx, fira_c_r_10, sizeof(fira_c_r_10));
	lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12));
	lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_font_register(cx, fira_c_r_24, sizeof(fira_c_r_24));
	lws_font_register(cx, fira_c_r_32, sizeof(fira_c_r_32));
	lws_font_register(cx, fira_c_b_10, sizeof(fira_c_b_10));
	lws_font_register(cx, fira_c_b_12, sizeof(fira_c_b_12));
	lws_font_register(cx, fira_c_b_14, sizeof(fira_c_b_14));
	lws_font_register(cx, fira_c_b_16, sizeof(fira_c_b_16));
	lws_font_register(cx, fira_c_b_20, sizeof(fira_c_b_20));
	lws_font_register(cx, fira_c_b_24, sizeof(fira_c_b_24));

	lws_dlo_file_register(cx, &fs_splash);


//	if (lws_netdev_instance_wifi_settings_get(si, "netdev.wl0", &niw, &ac)) {
//		lwsl_err("%s: unable to fetch wl0 settings\n", __func__);
//		return 1;
//	}

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

	/* ... bring up spi bb and the display */

	lbspi.bb_ops.init(&lbspi.bb_ops);
	lws_display_state_init(&lds, cx, 30000, 10000, NULL, &disp.disp);

	lws_led_transition(lls, "red", &lws_pwmseq_static_off,
				       &lws_pwmseq_linear_wipe);

	return 0;
}

void
show_demo_phase(int phase)
{
	switch (phase) {
	case LWS_LHPCD_PHASE_IDLE:
		lws_led_transition(lls, "red", &lws_pwmseq_static_off,
				   &lws_pwmseq_linear_wipe);
		break;
	case LWS_LHPCD_PHASE_FETCHING:
		lws_led_transition(lls, "red", &lws_pwmseq_sine_endless_slow,
				   &lws_pwmseq_linear_wipe);
		break;
	case LWS_LHPCD_PHASE_RENDERING:
		lws_led_transition(lls, "red", &lws_pwmseq_static_on,
				   &lws_pwmseq_linear_wipe);
		break;
	}
}
