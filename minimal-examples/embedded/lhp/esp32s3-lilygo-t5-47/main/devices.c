/*
 * devices for LilyGo T5 4.7" e-paper, ESP32-S3
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A 960 x 540 E Ink ED047TC1 panel with no controller of its own: we drive its
 * source and gate drivers directly, with lws-epd-direct.h.
 *
 * There are three ways the panel signals can be routed, chosen by
 * T547_ROUTING:
 *
 *  - T547_ROUTING_V23: the LilyGo board, V2.3.  XLE, SPV, XOE, MODE1, the
 *    panel supply enables and the board's power hold are on a 74HCT4094
 *    shift register.
 *
 *  - T547_ROUTING_V24: the LilyGo board, V2.4.  As V2.3, except XLE and SPV
 *    have their own gpios.
 *
 *  - T547_ROUTING_WATCH: no panel at all, but a Waveshare
 *    ESP32-S3-Touch-LCD-1.28 (ESP32-S3R2, 2MB quad PSRAM), with the signals
 *    on gpios it doesn't use, so the timing and the driver can be checked on
 *    a scope before the LilyGo boards are to hand.  The signals worth
 *    watching are on its 12-pin GPIO_OUT header.  It's laid out like V2.4.
 *
 * The watch routing is the default for now.  The real boards need
 * sdkconfig changed for their 8MB octal PSRAM, see the README.
 */

#include "../../main.h"

#define T547_ROUTING_WATCH	0
#define T547_ROUTING_V23	1
#define T547_ROUTING_V24	2

#if !defined(T547_ROUTING)
#define T547_ROUTING		T547_ROUTING_WATCH
#endif

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
 * The LilyGo board's user button is on GPIO21 (its GPIO0 BOOT button is
 * the shift register strobe once we are running).  On the watch, GPIO21 is
 * D0, and its button is BOOT on GPIO0.
 */

static const lws_button_map_t bcm[] = {
	{
#if T547_ROUTING == T547_ROUTING_WATCH
		.gpio			= GPIO_NUM_0,
#else
		.gpio			= GPIO_NUM_21,
#endif
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
 * The panel supplies
 *
 * RAIL0 enables the LT1945 boost converter, which makes the gate driver's
 * +22V VGH and -20V VGL, and what the +-15V source driver supplies are
 * regulated from.  RAIL1 then switches on VNEG (-15V), and RAIL2 VPOS
 * (+15V); VCOM comes from VPOS through a trimmer and an op-amp.  The ED047TC1
 * datasheet wants VNEG, then at least 1ms later VPOS, then VCOM 100us after,
 * and the other way around to power off, with VGL going last, once VNEG and
 * VPOS have discharged.
 */

static const lws_epd_direct_esp32_step_t power_on[] = {
	{ LWS_EPDD_CTL_RAIL0, 1, 1000 },
	{ LWS_EPDD_CTL_RAIL1, 1, 1000 },
	{ LWS_EPDD_CTL_RAIL2, 1, 200 },
}, power_off[] = {
	{ LWS_EPDD_CTL_RAIL2, 0, 100 },
	{ LWS_EPDD_CTL_RAIL1, 0, 10000 },
	{ LWS_EPDD_CTL_RAIL0, 0, 0 },
};

/*
 * The 74HCT4094 outputs on the LilyGo boards.  QP7 is the end of the shift
 * register the first bit shifted in reaches.
 *
 *	QP0	XLE (V2.3)	QP4	SPV (V2.3), active low
 *	QP1	LT1945 SHDN	QP5	board power hold, keep high
 *	QP2	VPOS enable	QP6	MODE1
 *	QP3	VNEG enable	QP7	XOE
 */

#define SR(_n)		{ LWS_EPDD_CTLSRC_SR, _n, 0, 0 }
#define SR_LOW(_n)	{ LWS_EPDD_CTLSRC_SR, _n, 1, 0 }
#define SR_HOLD(_n)	{ LWS_EPDD_CTLSRC_SR, _n, 0, 1 }
#define GPIO(_n)	{ LWS_EPDD_CTLSRC_GPIO, _n, 0, 0 }
#define GPIO_LOW(_n)	{ LWS_EPDD_CTLSRC_GPIO, _n, 1, 0 }

static lws_epd_direct_esp32_state_t epd_state;

/*
 * The passes run on a task of their own on the second core, so they aren't
 * held up by anything else, eg, rendering the next page on the first core
 */

static lws_epd_direct_esp32_runner_state_t epd_runner_state;

static const lws_epd_direct_esp32_runner_t epd_runner = {
	.runner = {
		lws_epd_direct_esp32_runner_ops,
	},
	.state				= &epd_runner_state,
	.stack_size			= 4096,
	.core				= 1,
	.priority			= 10,
};

static const lws_epd_direct_esp32_t epd_bus = {
	.bus = {
		lws_epd_direct_esp32_ops,
	},
	.panel				= &lws_epd_direct_panel_ed047tc1,
	.state				= &epd_state,
	.power_on			= power_on,
	.power_on_count			= LWS_ARRAY_SIZE(power_on),
	.power_off			= power_off,
	.power_off_count		= LWS_ARRAY_SIZE(power_off),
	/*
	 * The ED047TC1 takes XCL up to 60MHz, 20MHz is its typical.  It's
	 * an exact division of the S3 LCD peripheral's 160MHz clock.
	 */
	.xcl_hz				= 20000000,
	.sr_first_out			= 7,

#if T547_ROUTING == T547_ROUTING_WATCH

	/*
	 * Watch: the clocks, start pulses, XLE, D0 and the shift register
	 * strobe are on the GPIO_OUT header, for a scope.  The rest are on
	 * pads the watch leaves unconnected.  It has no shift register, so
	 * those outputs aren't seen, but the strobe shows when it's written.
	 *
	 *	header	signal		suggested scope channel
	 *	GPIO15	XCL / CKH	1
	 *	GPIO16	XSTL / STH	2
	 *	GPIO17	CKV		3
	 *	GPIO18	XLE		4
	 *	GPIO21	D0
	 *	GPIO33	4094 STR
	 */

	.data_gpio			= { 21, 36, 37, 38, 39, 40, 41, 42 },
	.xcl_gpio			= 15,
	.sth_gpio			= 16,
	.ckv_gpio			= 17,
	.sr_data_gpio			= 34,
	.sr_clk_gpio			= 35,
	.sr_str_gpio			= 33,
	.ctl = {
		[LWS_EPDD_CTL_LE]	= GPIO(18),
		[LWS_EPDD_CTL_STV]	= GPIO_LOW(47),
		[LWS_EPDD_CTL_OE]	= SR(7),
		[LWS_EPDD_CTL_MODE]	= SR(6),
		[LWS_EPDD_CTL_RAIL0]	= SR_LOW(1),
		[LWS_EPDD_CTL_RAIL1]	= SR(3),
		[LWS_EPDD_CTL_RAIL2]	= SR(2),
		[LWS_EPDD_CTL_AUX]	= SR_HOLD(5),
	},

#else

	/* LilyGo T5 4.7" S3, V2.3 and V2.4 */

	.data_gpio			= { 8, 1, 2, 3, 4, 5, 6, 7 },
	.xcl_gpio			= 41,
	.sth_gpio			= 40,
	.ckv_gpio			= 38,
	.sr_data_gpio			= 13,
	.sr_clk_gpio			= 12,
	.sr_str_gpio			= 0,
	.ctl = {
#if T547_ROUTING == T547_ROUTING_V24
		[LWS_EPDD_CTL_LE]	= GPIO(48),
		[LWS_EPDD_CTL_STV]	= GPIO_LOW(45),
#else
		[LWS_EPDD_CTL_LE]	= SR(0),
		[LWS_EPDD_CTL_STV]	= SR_LOW(4),
#endif
		[LWS_EPDD_CTL_OE]	= SR(7),
		[LWS_EPDD_CTL_MODE]	= SR(6),
		[LWS_EPDD_CTL_RAIL0]	= SR_LOW(1),
		[LWS_EPDD_CTL_RAIL1]	= SR(3),
		[LWS_EPDD_CTL_RAIL2]	= SR(2),
		[LWS_EPDD_CTL_AUX]	= SR_HOLD(5),
	},

#endif
};

/*
 * Black and white waveforms.  These are a first guess, to be found on the
 * panel: about 0.3s of drive for a transition, and clearing by pushing every
 * pixel black and white twice.
 */

#define B LWS_EPDD_BLACK
#define W LWS_EPDD_WHITE

static const uint8_t wf_to_black[] = {
	B, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B, B,
}, wf_to_white[] = {
	W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W, W,
}, wf_clear[] = {
	B, B, B, B, B, B, B, B, B, B, W, W, W, W, W, W, W, W, W, W,
	B, B, B, B, B, B, B, B, B, B, W, W, W, W, W, W, W, W, W, W,
};

static const lws_epd_direct_waveform_bw_t wf_bw = {
	.to_black			= wf_to_black,
	.to_black_len			= LWS_ARRAY_SIZE(wf_to_black),
	.to_white			= wf_to_white,
	.to_white_len			= LWS_ARRAY_SIZE(wf_to_white),
	.clear				= wf_clear,
	.clear_len			= LWS_ARRAY_SIZE(wf_clear),
	/* at least the source driver output settling time */
	.row_drive_us			= 20,
};

static const lws_display_colour_t palette[] = {
	PALETTE_RGBY(0, 0, 0),
	PALETTE_RGBY(255, 255, 255),
};

static const lws_display_epd_direct_t disp = {
	.disp = {
		lws_display_epd_direct_ops,
		.ic = {
			.wh_px = { { 960,0 },		{ 540,0 } },
			.wh_mm = { { 103,68000000 },	{ 58,32000000 } },
			.palette		= palette,
			.palette_depth		= LWS_ARRAY_SIZE(palette),
			.type			= LWSSURF_PALETTE,
			.greyscale		= 1, /* line buffer is Y */
		},
		.name			= "ED047TC1 960x540 direct",
		.latency_wake_ms	= 0,
		.latency_update_ms	= 600,
	},
	.panel				= &lws_epd_direct_panel_ed047tc1,
	.wf_bw				= &wf_bw,
	.bus				= &epd_bus.bus,
	.runner				= &epd_runner.runner,
	.cb				= display_completion_cb,
	.full_refresh_every		= 20,
	.power_off_idle_ms		= 1000,
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

	/* the button controller */

	bcs = lws_button_controller_create(cx, &bc);
	if (!bcs) {
		lwsl_err("%s: could not create buttons\n", __func__);
		return 1;
	}

	lws_button_enable(bcs, 0, lws_button_get_bit(bcs, "user"));

	/*
	 * ... and the display.  It clears the panel, and tells us it's ready
	 * when that's done.  There's no backlight.
	 */

	lws_display_state_init(&lds, cx, 30000, 10000, NULL, &disp.disp);
	if (!lds.priv) {
		lwsl_err("%s: could not create display\n", __func__);
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
	lws_display_epd_direct_destroy(&lds);

	lws_button_controller_destroy(bcs);
	bcs = NULL;

	wifi_ops.destroy((struct lws_netdev_instance **)&wnd);

	lws_netdevs_from_ctx(cx)->si = NULL;
	lws_settings_deinit(&si);
}

void
show_demo_phase(int phase)
{
	(void)phase;
}
