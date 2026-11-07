/*
 * lws directly-driven EPD transport for esp32
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * See include/libwebsockets/lws-esp32-epd-direct.h
 *
 * A row goes like this:
 *
 *  - row_load(): the i80 bus DMAs the row's codes into the source drivers,
 *    clocked by XCL, with XSTL (the bus D/C line) low while it does
 *
 *  - row_drive(): when the DMA is done, and the previous row's gate pulse has
 *    finished, pulse XLE to latch the codes onto the source driver outputs,
 *    then start an RMT pulse on CKV to hold the gate on for the row for the
 *    drive time.  It returns without waiting for the pulse, so the next row
 *    can be encoded and sent while this one is driven.
 *
 * so rows overlap, the next row being sent while the previous one is driven.
 */

#include <libwebsockets.h>

#include <soc/soc_caps.h>
#include <driver/gpio.h>
#include <esp_heap_caps.h>
#include <esp_rom_sys.h>
#include <esp_attr.h>

#if SOC_LCD_I80_SUPPORTED && SOC_RMT_SUPPORTED

#include <esp_lcd_io_i80.h>
#include <esp_lcd_panel_io.h>
#include <driver/rmt_tx.h>
#include <driver/rmt_encoder.h>

/* RMT resolution: 0.1us ticks */
#define EPDD_RMT_HZ		10000000
#define EPDD_TICKS_PER_US	(EPDD_RMT_HZ / 1000000)

static const lws_epd_direct_esp32_t *
to_ee(const lws_epd_direct_bus_ops_t *bus)
{
	return lws_container_of(bus, lws_epd_direct_esp32_t, bus);
}

/*
 * Write the shift register shadow out.  Its outputs change together when it's
 * strobed at the end.
 */

static void
sr_write(const lws_epd_direct_esp32_t *ee)
{
	int n, out;

	gpio_set_level(ee->sr_str_gpio, 0);

	for (n = 0; n < 8; n++) {
		out = ee->sr_first_out ? 7 - n : n;

		gpio_set_level(ee->sr_clk_gpio, 0);
		gpio_set_level(ee->sr_data_gpio,
			       (uint32_t)((ee->state->sr >> out) & 1));
		gpio_set_level(ee->sr_clk_gpio, 1);
	}

	gpio_set_level(ee->sr_clk_gpio, 0);
	gpio_set_level(ee->sr_str_gpio, 1);
	gpio_set_level(ee->sr_str_gpio, 0);
}

static void
ctl_set(const lws_epd_direct_esp32_t *ee, int ctl, int assert)
{
	const lws_epd_direct_esp32_ctl_t *c = &ee->ctl[ctl];
	int level = (!!assert) ^ (!!c->active_low);

	switch (c->src) {
	case LWS_EPDD_CTLSRC_GPIO:
		gpio_set_level(c->index, (uint32_t)level);
		break;

	case LWS_EPDD_CTLSRC_SR:
		if (level)
			ee->state->sr = (uint8_t)(ee->state->sr |
						  (1u << c->index));
		else
			ee->state->sr = (uint8_t)(ee->state->sr &
						  ~(1u << c->index));
		sr_write(ee);
		break;

	default:
		break;
	}
}

static int
gpio_out(int gpio, int level)
{
	gpio_config_t gc;

	if (gpio < 0)
		return 0;

	memset(&gc, 0, sizeof(gc));
	gc.pin_bit_mask = 1ull << gpio;
	gc.mode = GPIO_MODE_OUTPUT;

	if (gpio_config(&gc) != ESP_OK)
		return 1;

	gpio_set_level(gpio, (uint32_t)level);

	return 0;
}

static bool IRAM_ATTR
trans_done_cb(esp_lcd_panel_io_handle_t io, esp_lcd_panel_io_event_data_t *ed,
	      void *user_ctx)
{
	lws_epd_direct_esp32_state_t *st = (lws_epd_direct_esp32_state_t *)user_ctx;

	st->dma_busy = 0;

	return false;
}

static void
ckv_wait(const lws_epd_direct_esp32_t *ee)
{
	lws_epd_direct_esp32_state_t *st = ee->state;

	if (st->rmt_busy) {
		rmt_tx_wait_all_done((rmt_channel_handle_t)st->rmt, -1);
		st->rmt_busy = 0;
	}
}

/*
 * Start a CKV pulse, high for high_ticks then low for at least low_ticks, and
 * don't wait for it
 */

static void
ckv_pulse(const lws_epd_direct_esp32_t *ee, uint32_t high_ticks,
	  uint32_t low_ticks)
{
	lws_epd_direct_esp32_state_t *st = ee->state;
	rmt_transmit_config_t tc;

	ckv_wait(ee);

	if (!high_ticks)
		high_ticks = 1;
	if (high_ticks > 0x7fff)
		high_ticks = 0x7fff;
	if (!low_ticks)
		low_ticks = 1;
	if (low_ticks > 0x7fff)
		low_ticks = 0x7fff;

	/*
	 * An rmt_symbol_word_t: duration0 in b0 - b14, level0 in b15, then
	 * duration1 and level1 the same in the upper 16 bits
	 */
	st->ckv_sym = high_ticks | (1u << 15) | (low_ticks << 16);

	memset(&tc, 0, sizeof(tc));
	if (rmt_transmit((rmt_channel_handle_t)st->rmt,
			 (rmt_encoder_handle_t)st->rmt_enc, &st->ckv_sym,
			 sizeof(st->ckv_sym), &tc) == ESP_OK)
		st->rmt_busy = 1;
}

/*
 * The shortest gate clock pulse the panel allows, as high and low ticks
 */

static void
ckv_min(const lws_epd_direct_esp32_t *ee, uint32_t *hi, uint32_t *lo)
{
	const lws_epd_direct_panel_t *p = ee->panel;
	uint32_t period = p->ckv_max_hz ? (EPDD_RMT_HZ + p->ckv_max_hz - 1) /
					   p->ckv_max_hz : 1;

	*hi = ((uint32_t)p->ckv_min_high_ns * EPDD_TICKS_PER_US + 999) / 1000;
	*lo = ((uint32_t)p->ckv_min_low_ns * EPDD_TICKS_PER_US + 999) / 1000;

	if (*hi + *lo < period) {
		*hi = period / 2;
		*lo = period - *hi;
	}
}

void *
lws_epd_direct_esp32_alloc_dma(const lws_epd_direct_bus_ops_t *bus,
			       size_t size)
{
	return heap_caps_malloc(size, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL |
				      MALLOC_CAP_8BIT);
}

void
lws_epd_direct_esp32_free_dma(const lws_epd_direct_bus_ops_t *bus, void **p)
{
	if (*p) {
		heap_caps_free(*p);
		*p = NULL;
	}
}

void
lws_epd_direct_esp32_deinit(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;

	if (st->rmt) {
		ckv_wait(ee);
		rmt_disable((rmt_channel_handle_t)st->rmt);
		rmt_del_channel((rmt_channel_handle_t)st->rmt);
		st->rmt = NULL;
	}
	if (st->rmt_enc) {
		rmt_del_encoder((rmt_encoder_handle_t)st->rmt_enc);
		st->rmt_enc = NULL;
	}
	if (st->io) {
		while (st->dma_busy)
			;
		esp_lcd_panel_io_del((esp_lcd_panel_io_handle_t)st->io);
		st->io = NULL;
	}
	if (st->i80_bus) {
		esp_lcd_del_i80_bus((esp_lcd_i80_bus_handle_t)st->i80_bus);
		st->i80_bus = NULL;
	}

	st->ready = 0;
}

int
lws_epd_direct_esp32_init(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;
	esp_lcd_panel_io_i80_config_t ioc;
	esp_lcd_i80_bus_config_t bc;
	rmt_tx_channel_config_t rc;
	rmt_copy_encoder_config_t ec;
	esp_lcd_i80_bus_handle_t i80;
	esp_lcd_panel_io_handle_t io;
	rmt_channel_handle_t rmt;
	rmt_encoder_handle_t enc;
	int n, uses_sr = 0;

	if (!st || !ee->panel || ee->xcl_hz > ee->panel->xcl_max_hz) {
		lwsl_err("%s: no state, or data clock too fast for panel\n",
			 __func__);
		return 1;
	}

	memset(st, 0, sizeof(*st));

	/* the control lines start deasserted, unless the board says */

	for (n = 0; n < LWS_EPDD_CTL_COUNT; n++) {
		const lws_epd_direct_esp32_ctl_t *c = &ee->ctl[n];
		int level = (!!c->init_asserted) ^ (!!c->active_low);

		if (c->src == LWS_EPDD_CTLSRC_SR) {
			if (c->index > 7) {
				lwsl_err("%s: bad sr output\n", __func__);
				return 1;
			}
			uses_sr = 1;
			if (level)
				st->sr = (uint8_t)(st->sr | (1u << c->index));
		}

		if (c->src == LWS_EPDD_CTLSRC_GPIO && gpio_out(c->index, level))
			goto bail_gpio;
	}

	if (uses_sr) {
		if (ee->sr_data_gpio < 0 || ee->sr_clk_gpio < 0 ||
		    ee->sr_str_gpio < 0) {
			lwsl_err("%s: shift register gpios missing\n",
				 __func__);
			return 1;
		}
		if (gpio_out(ee->sr_data_gpio, 0) ||
		    gpio_out(ee->sr_clk_gpio, 0) ||
		    gpio_out(ee->sr_str_gpio, 0))
			goto bail_gpio;
		sr_write(ee);
	}

	/* the source driver bus */

	memset(&bc, 0, sizeof(bc));
	bc.dc_gpio_num = ee->sth_gpio;
	bc.wr_gpio_num = ee->xcl_gpio;
	bc.clk_src = LCD_CLK_SRC_DEFAULT;
	for (n = 0; n < 8; n++)
		bc.data_gpio_nums[n] = ee->data_gpio[n];
	bc.bus_width = 8;
	bc.max_transfer_bytes = ee->panel->source_px / 4u + bus->row_tail_bytes;

	if (esp_lcd_new_i80_bus(&bc, &i80) != ESP_OK) {
		lwsl_err("%s: i80 bus creation failed\n", __func__);
		return 1;
	}
	st->i80_bus = i80;

	memset(&ioc, 0, sizeof(ioc));
	ioc.cs_gpio_num = -1;
	ioc.pclk_hz = ee->xcl_hz;
	ioc.trans_queue_depth = 2;
	ioc.on_color_trans_done = trans_done_cb;
	ioc.user_ctx = st;
	ioc.lcd_cmd_bits = 8;
	ioc.lcd_param_bits = 8;
	/* XSTL is low while a row is sent, otherwise high */
	ioc.dc_levels.dc_idle_level = 1;
	ioc.dc_levels.dc_cmd_level = 1;
	ioc.dc_levels.dc_dummy_level = 1;
	ioc.dc_levels.dc_data_level = 0;

	if (esp_lcd_new_panel_io_i80(i80, &ioc, &io) != ESP_OK) {
		lwsl_err("%s: i80 io creation failed\n", __func__);
		goto bail;
	}
	st->io = io;

	/* the gate driver clock */

	memset(&rc, 0, sizeof(rc));
	rc.gpio_num = ee->ckv_gpio;
	rc.clk_src = RMT_CLK_SRC_DEFAULT;
	rc.resolution_hz = EPDD_RMT_HZ;
	rc.mem_block_symbols = SOC_RMT_MEM_WORDS_PER_CHANNEL;
	rc.trans_queue_depth = 2;

	if (rmt_new_tx_channel(&rc, &rmt) != ESP_OK) {
		lwsl_err("%s: rmt channel creation failed\n", __func__);
		goto bail;
	}
	st->rmt = rmt;

	memset(&ec, 0, sizeof(ec));
	if (rmt_new_copy_encoder(&ec, &enc) != ESP_OK ||
	    rmt_enable(rmt) != ESP_OK) {
		lwsl_err("%s: rmt encoder failed\n", __func__);
		goto bail;
	}
	st->rmt_enc = enc;

	st->ready = 1;

	lwsl_notice("%s: data clock %uHz\n", __func__,
		    (unsigned int)ee->xcl_hz);

	return 0;

bail_gpio:
	lwsl_err("%s: gpio config failed\n", __func__);

	return 1;

bail:
	lws_epd_direct_esp32_deinit(bus);

	return 1;
}

int
lws_epd_direct_esp32_power(const lws_epd_direct_bus_ops_t *bus, int on)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	const lws_epd_direct_esp32_step_t *s = on ? ee->power_on : ee->power_off;
	uint8_t n, count = on ? ee->power_on_count : ee->power_off_count;

	if (!ee->state->ready)
		return 1;

	if (!on) {
		/* nothing may be driven while the supplies go */
		ckv_wait(ee);
		ctl_set(ee, LWS_EPDD_CTL_OE, 0);
		ctl_set(ee, LWS_EPDD_CTL_MODE, 0);
	}

	for (n = 0; n < count; n++) {
		if (s[n].ctl >= LWS_EPDD_CTL_COUNT)
			return 1;
		ctl_set(ee, s[n].ctl, s[n].assert);
		if (s[n].delay_us)
			esp_rom_delay_us(s[n].delay_us);
	}

	return 0;
}

void
lws_epd_direct_esp32_frame_start(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	uint32_t hi, lo;
	uint8_t n;

	ckv_min(ee, &hi, &lo);

	/*
	 * The gate driver takes the start pulse on a CKV edge, then each CKV
	 * moves it on a row
	 */

	ctl_set(ee, LWS_EPDD_CTL_MODE, 1);
	ctl_set(ee, LWS_EPDD_CTL_STV, 1);
	ckv_pulse(ee, hi, lo);
	ckv_wait(ee);
	ctl_set(ee, LWS_EPDD_CTL_STV, 0);

	for (n = 0; n < ee->frame_lead_ckv; n++)
		ckv_pulse(ee, hi, lo);

	ckv_wait(ee);
	ctl_set(ee, LWS_EPDD_CTL_OE, 1);
}

void
lws_epd_direct_esp32_row_load(const lws_epd_direct_bus_ops_t *bus,
			      const uint8_t *data, size_t len)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;

	while (st->dma_busy)
		;

	st->dma_busy = 1;
	if (esp_lcd_panel_io_tx_color((esp_lcd_panel_io_handle_t)st->io, -1,
				      data, len) != ESP_OK) {
		st->dma_busy = 0;
		lwsl_err("%s: tx failed\n", __func__);
	}
}

void
lws_epd_direct_esp32_row_drive(const lws_epd_direct_bus_ops_t *bus,
			       uint32_t drive_us)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	uint32_t hi, lo;

	while (ee->state->dma_busy)
		;

	/* the previous row's gate pulse must end before we latch this one */

	ckv_wait(ee);

	ctl_set(ee, LWS_EPDD_CTL_LE, 1);
	esp_rom_delay_us(1);
	ctl_set(ee, LWS_EPDD_CTL_LE, 0);

	ckv_min(ee, &hi, &lo);
	ckv_pulse(ee, drive_us * EPDD_TICKS_PER_US, lo);
}

void
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	uint32_t hi, lo;

	ckv_min(ee, &hi, &lo);
	ckv_pulse(ee, hi, lo);
}

void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);

	ckv_wait(ee);
	ctl_set(ee, LWS_EPDD_CTL_OE, 0);
	ctl_set(ee, LWS_EPDD_CTL_MODE, 0);
}

#else

/* this chip has no i80 LCD peripheral or no RMT */

int
lws_epd_direct_esp32_init(const lws_epd_direct_bus_ops_t *bus)
{
	lwsl_err("%s: not supported on this chip\n", __func__);

	return 1;
}

void
lws_epd_direct_esp32_deinit(const lws_epd_direct_bus_ops_t *bus) { }

int
lws_epd_direct_esp32_power(const lws_epd_direct_bus_ops_t *bus, int on)
{
	return 1;
}

void *
lws_epd_direct_esp32_alloc_dma(const lws_epd_direct_bus_ops_t *bus,
			       size_t size)
{
	return NULL;
}

void
lws_epd_direct_esp32_free_dma(const lws_epd_direct_bus_ops_t *bus, void **p) { }

void
lws_epd_direct_esp32_frame_start(const lws_epd_direct_bus_ops_t *bus) { }

void
lws_epd_direct_esp32_row_load(const lws_epd_direct_bus_ops_t *bus,
			      const uint8_t *data, size_t len) { }

void
lws_epd_direct_esp32_row_drive(const lws_epd_direct_bus_ops_t *bus,
			       uint32_t drive_us) { }

void
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus) { }

void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus) { }

#endif
