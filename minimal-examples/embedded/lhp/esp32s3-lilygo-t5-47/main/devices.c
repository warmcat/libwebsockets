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
 * There are two ways the panel signals can be routed, chosen by
 * T547_ROUTING:
 *
 *  - T547_ROUTING_LILYGO: the LilyGo T5 4.7" S3 board (V2.4 is the current
 *    one).  XLE, SPV, XOE, MODE1, the panel supply enables and the scan
 *    direction are on a 74HCT4094 shift register, as LilyGo's own code for
 *    the board has them.
 *
 *  - T547_ROUTING_WATCH: no panel at all, but a Waveshare
 *    ESP32-S3-Touch-LCD-1.28 (ESP32-S3R2, 2MB quad PSRAM), with the signals
 *    on gpios it doesn't use, so the timing and the driver can be checked on
 *    a scope without a panel.  The signals worth watching are on its
 *    12-pin GPIO_OUT header.  XLE and SPV are on gpios of their own, so
 *    they can be seen on the scope.
 *
 * The LilyGo board is the default.  sdkconfig is for its 8MB octal PSRAM;
 * the watch routing needs it changed for the watch's 2MB quad PSRAM, see
 * the README.
 *
 * On the LilyGo boards, there's a GT911 touch panel over the display, on
 * an i2c bus it shares with a PCF8563 rtc and its backup battery.  The
 * watch's gpios for that are used for the panel signals, and its own touch
 * panel is something else, so the watch routing has no touch or rtc.
 */

#include "../../main.h"
#include "freertos/semphr.h"

#define T547_ROUTING_WATCH	0
#define T547_ROUTING_LILYGO	1

#if !defined(T547_ROUTING)
#define T547_ROUTING		T547_ROUTING_LILYGO
#endif

/*
 * 1 replaces what lhp draws with a fixed pattern, to check what goes out on
 * the panel bus with a scope.  See "Scope test pattern" in the README.
 */
#if !defined(T547_SCOPE_PATTERN)
#define T547_SCOPE_PATTERN	0
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
 * On V2.4, PWR_EN, on the 4094's QP5, switches the 3.3V the panel side runs
 * from.  With it, the LT1945 boost converter makes the gate driver's +22V
 * VGH and -20V VGL, and the +-15V source driver supplies are regulated from
 * those; VCOM comes from +15V through a trimmer and an op-amp.  So they all
 * come and go together: we give them 20ms to come up.  The 4094 outputs
 * the board was designed with for sequencing them, QP1 - QP3, aren't
 * connected on V2.4.
 */

static const lws_epd_direct_esp32_step_t power_on[] = {
	{ LWS_EPDD_CTL_RAIL0, 1, 20000 },
}, power_off[] = {
	{ LWS_EPDD_CTL_RAIL0, 0, 0 },
};

/*
 * The 74HCT4094 outputs on the LilyGo board.  QP7 is the end of the shift
 * register the first bit shifted in reaches.
 *
 *	QP0	XLE		QP4	SPV, active low
 *	QP1	NC		QP5	PWR_EN, the panel supplies
 *	QP2	NC		QP6	MODE1
 *	QP3	NC		QP7	XOE
 */

#define SR(_n)		{ LWS_EPDD_CTLSRC_SR, _n, 0, 0 }
#define SR_LOW(_n)	{ LWS_EPDD_CTLSRC_SR, _n, 1, 0 }
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
	 * The ED047TC1 takes XCL up to 60MHz, 20MHz is its typical.  10MHz
	 * is what LilyGo's own code uses, and what's been seen to work on the
	 * board.  It's an exact division of the S3 LCD peripheral's 160MHz
	 * clock.
	 */
	.xcl_hz				= 10000000,
	.sr_first_out			= 7,
	/*
	 * LilyGo's own code writes the 4094 with gpio_set_level() calls,
	 * a few hundred ns apart: it's not known yet how much faster the
	 * board's 4094 can be clocked
	 */
	.sr_edge_ns			= 300,
	.frame_lead_ckv			= 2,

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
		[LWS_EPDD_CTL_RAIL0]	= SR(5),
	},

#else

	/* LilyGo T5 4.7" S3; GPIO45 and GPIO48 aren't connected on V2.4 */

	.data_gpio			= { 8, 1, 2, 3, 4, 5, 6, 7 },
	.xcl_gpio			= 41,
	.sth_gpio			= 40,
	.ckv_gpio			= 38,
	.sr_data_gpio			= 13,
	.sr_clk_gpio			= 12,
	.sr_str_gpio			= 0,
	.ctl = {
		[LWS_EPDD_CTL_LE]	= SR(0),
		[LWS_EPDD_CTL_STV]	= SR_LOW(4),
		[LWS_EPDD_CTL_OE]	= SR(7),
		[LWS_EPDD_CTL_MODE]	= SR(6),
		[LWS_EPDD_CTL_RAIL0]	= SR(5),
	},

#endif
};

/*
 * Black and white waveforms, giving each pixel about as much drive as
 * LilyGo's own code for this board does.
 *
 * It darkens white to black with 15 passes of 2 - 30us, about 102us in all,
 * and lightens black to white with 15 passes of 0.8 - 30us, about 55us.
 * Here, those are 5 and 3 passes of 20us, since every pass of an update must
 * drive for the same time.
 *
 * Its clear is 4 times 4 passes black then 4 white, of 50us each, and so is
 * ours.
 */

#define B LWS_EPDD_BLACK
#define W LWS_EPDD_WHITE

static const uint8_t wf_to_black[] = {
	B, B, B, B, B,
}, wf_to_white[] = {
	W, W, W,
}, wf_clear[] = {
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
	B, B, B, B, W, W, W, W,
};

static const lws_epd_direct_waveform_bw_t wf_bw = {
	.to_black			= wf_to_black,
	.to_black_len			= LWS_ARRAY_SIZE(wf_to_black),
	.to_white			= wf_to_white,
	.to_white_len			= LWS_ARRAY_SIZE(wf_to_white),
	.clear				= wf_clear,
	.clear_len			= LWS_ARRAY_SIZE(wf_clear),
	/* at least the source driver output settling time */
	.drive_ns			= 20000,
	.clear_drive_ns			= 50000,
};

static const lws_display_colour_t palette[] = {
	PALETTE_RGBY(0, 0, 0),
	PALETTE_RGBY(255, 255, 255),
};

#if T547_SCOPE_PATTERN

/*
 * Whatever lhp draws, the lines we pass on are black marks on white, on
 * rows 100 - 111 only.  A mark is four pixels, so one bus byte of black
 * drive codes, 0x55, in a row of 240.  Each row has marks at bytes 0 and
 * 239.  Rows 100 - 107 also have one at byte 16, 32 ... 128, different on
 * each row, and rows 108 - 111 are all the same, with one at byte 200.
 */

#define SP_ROW_FIRST	100
#define SP_ROWS_STAIR	8
#define SP_ROWS_SAME	4

static int
scope_pattern_blit(lws_display_state_t *lds, const uint8_t *src,
		   lws_box_t *box, lws_dll2_owner_t *ids)
{
	static uint8_t line[960];
	int y = box->y.whole, k = y - SP_ROW_FIRST, byte;

	if (box->h.whole != 1)
		/* not a line: the start or end of an update */
		return lws_display_epd_direct_blit(lds, src, box, ids);

	memset(line, 0xff, sizeof(line));

	if (k >= 0 && k < SP_ROWS_STAIR + SP_ROWS_SAME) {
		byte = k < SP_ROWS_STAIR ? 16 * (k + 1) : 200;

		memset(line, 0, 4);
		memset(line + 4 * byte, 0, 4);
		memset(line + sizeof(line) - 4, 0, 4);
	}

	return lws_display_epd_direct_blit(lds, line, box, ids);
}

#endif

static const lws_display_epd_direct_t disp = {
	.disp = {
#if T547_SCOPE_PATTERN
		.init			= lws_display_epd_direct_init,
		.blit			= scope_pattern_blit,
		.power			= lws_display_epd_direct_power,
		.clear			= lws_display_epd_direct_clear,
		.bistable		= 1,
#else
		lws_display_epd_direct_ops,
#endif
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
		/*
		 * An update only drives the pixels that change, in about
		 * 60ms, and the next can start before it ends: something
		 * animated, eg, the update spinner, can be moved on often
		 */
		.anim_hz		= 18,
	},
	.panel				= &lws_epd_direct_panel_ed047tc1,
	.wf_bw				= &wf_bw,
	.bus				= &epd_bus.bus,
	.runner				= &epd_runner.runner,
	.cb				= display_completion_cb,
	.full_refresh_every		= 20,
	.power_off_idle_ms		= 1000,
};

#if T547_ROUTING != T547_ROUTING_WATCH

/*
 * i2c for the touch panel and the rtc, bitbanged on GPIO18 (SDA) and GPIO17
 * (SCL)
 */

static void
esp32_i2c_delay(void)
{
	volatile int n = 0;

	while (n < 2)
		n++;
}

/*
 * The touch panel is read from an OS timer, and the rtc from the lws event
 * loop, so each transaction holds the bus, so they don't interleave
 */

static StaticSemaphore_t i2c_mutex_mem;
static SemaphoreHandle_t i2c_mutex;

static int
esp32_i2c_lock(const lws_i2c_ops_t *ctx)
{
	return xSemaphoreTake(i2c_mutex, portMAX_DELAY) != pdTRUE;
}

static void
esp32_i2c_unlock(const lws_i2c_ops_t *ctx)
{
	xSemaphoreGive(i2c_mutex);
}

static const lws_bb_i2c_t li2c = {
	.bb_ops				= lws_bb_i2c_ops_locked(esp32_i2c_lock,
							esp32_i2c_unlock),
	.scl				= GPIO_NUM_17,
	.sda				= GPIO_NUM_18,
	.gpio				= &lws_gpio_plat,
	.delay				= esp32_i2c_delay
};

/*
 * The GT911 touch panel, its INT on GPIO47 and its reset not connected.
 * It reports the panel as portrait, 540 x 960, so its coordinates are
 * swapped and y inverted onto the landscape display, following LilyGo's
 * example code.  At init it logs the resolution and orientation it says it
 * has, and its i2c address, which the driver probes for.
 */

static const lws_touch_gt911_t touch = {
	.touch = {
		lws_touch_gt911_ops,
		.gpio			= &lws_gpio_plat,
		.name			= "ts",
		.wh_native		= { 540, 960 },
		.wh_px			= { 960, 540 },
		.irq_gpio		= GPIO_NUM_47,
		.irq_edge		= LWSGGPIO_IRQ_FALLING,
		.flags			= LWSTOUCH_FL_SWAP_XY |
					  LWSTOUCH_FL_INVERT_Y,
	},
	.i2c				= &li2c.bb_ops,
};

/*
 * The PCF8563 rtc, with its backup battery, on the same bus.  Its INT isn't
 * used.  If it has a time it believes, we know the time at boot from it, and
 * ntp only sets it right in the background.
 */

static const lws_rtc_pcf8563_t rtc = {
	.rtc = {
		lws_rtc_pcf8563_ops,
		.name			= "pcf8563",
	},
	.i2c				= &li2c.bb_ops,
};

#endif

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

#if T547_ROUTING != T547_ROUTING_WATCH
	/* ... and i2c and the touch panel over it */

	i2c_mutex = xSemaphoreCreateMutexStatic(&i2c_mutex_mem);
	li2c.bb_ops.init(&li2c.bb_ops);
	tcs = lws_touch_create(cx, &touch.touch);
	if (!tcs) {
		lwsl_err("%s: could not create touch\n", __func__);
		return 1;
	}

	/* ... and the rtc, which is only a loss if it's not there */
	if (lws_rtc_attach(cx, &rtc.rtc))
		lwsl_warn("%s: no rtc\n", __func__);
#endif

	return 0;
}

/*
 * Undoes init_plat_devices(), in reverse, while the context still exists:
 * the context doesn't own these and can't free them itself
 */

void
deinit_plat_devices(struct lws_context *cx)
{
	lws_rtc_detach(cx);
	lws_touch_destroy(&tcs);
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
