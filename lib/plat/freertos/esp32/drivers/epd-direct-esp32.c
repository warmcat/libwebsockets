/*
 * lws directly-driven EPD transport for the ESP32-S3
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
 *  - row_load(): GDMA feeds the row's codes to LCD_CAM, which clocks them into
 *    the source drivers on XCL, with XSTL (its D/C line) low while it does
 *
 *  - row_drive(): when the row has been sent, and the previous row's gate
 *    pulse has ended, pulse XLE to latch the codes onto the source driver
 *    outputs, then start an RMT pulse on CKV to hold the gate on for the row
 *    for the drive time.  It returns without waiting for the pulse, so the
 *    next row can be encoded and sent while this one is driven.
 *
 * so rows overlap, the next row being sent while the previous one is driven.
 *
 * The bus ops are called by whatever runs the passes, normally a task of its
 * own on the second core, and they wait by spinning on the peripherals'
 * status bits and the cpu cycle count, since the waits are a few us at most.
 * Nothing here takes an interrupt.  The IDF drivers' per-transfer apis cost
 * more than sending a row does, so LCD_CAM, its GDMA channel and the RMT
 * channel are driven through the hal and private headers: the IDF drivers are
 * only used to set things up.
 */

#include <libwebsockets.h>

#include <sdkconfig.h>
#include <soc/soc_caps.h>
#include <driver/gpio.h>
#include <esp_heap_caps.h>
#include <esp_rom_sys.h>

/*
 * It knows the ESP32-S3's LCD_CAM and RMT registers.  Other chips with an
 * LCD_CAM i80 bus lay out their RMT registers differently.
 */
#if defined(CONFIG_IDF_TARGET_ESP32S3)

#include <esp_attr.h>
#include <esp_cpu.h>
#include <esp_clk_tree.h>
#include <esp_rom_gpio.h>
#include <esp_private/esp_clk_tree_common.h>
#include <esp_private/periph_ctrl.h>
#include <esp_private/gpio.h>
#include <esp_private/gdma.h>
#include <esp_private/gdma_link.h>
#include <esp_private/rmt.h>
#include <driver/rmt_tx.h>
#include <hal/lcd_ll.h>
#include <hal/lcd_periph.h>
#include <hal/rmt_ll.h>
#include <hal/gpio_ll.h>
#include <soc/gpio_struct.h>
#include <soc/rmt_struct.h>

/* RMT resolution: 0.1us ticks */
#define EPDD_RMT_HZ		10000000
#define EPDD_TICKS_PER_US	(EPDD_RMT_HZ / 1000000)

/* LCD_CAM's clock is divided by this before the pixel clock divider */
#define EPDD_LCD_GROUP_DIV	2

/*
 * How long LCD_CAM's FIFO is given to fill from DMA before it starts sending.
 * It's hidden inside the previous row's gate pulse.
 */
#define EPDD_PREFILL_NS		1000

/* SPV before the CKV edge it's taken on: the datasheet wants 100ns */
#define EPDD_SPV_SETUP_NS	200

/* shortest time between edges we make on the shift register's lines */
#define EPDD_SR_EDGE_NS		50

/*
 * The RMT channels' symbol memory, from the chip's linker script.  The RMT
 * driver gives us the channel, we write the one pulse it sends ourselves.
 */
extern volatile uint32_t RMTMEM[];

/*
 * What runs for each row is in IRAM: from flash, through a cache the other
 * core is also using, a miss costs us more than the gaps we're trying to keep
 * between the panel signals.  Its timings are worked out at init, so it
 * doesn't divide, or look at the panel description, per row.
 */

static inline lcd_cam_dev_t *
lcd_dev(void)
{
	return LCD_LL_GET_HW(0);
}

static inline const lws_epd_direct_esp32_t *
to_ee(const lws_epd_direct_bus_ops_t *bus)
{
	return lws_container_of(bus, lws_epd_direct_esp32_t, bus);
}

static uint32_t
ns_to_cyc(const lws_epd_direct_esp32_state_t *st, uint32_t ns)
{
	return (uint32_t)(((uint64_t)ns * st->cyc_per_us + 999) / 1000);
}

static void IRAM_ATTR
spin_cyc(uint32_t cyc)
{
	uint32_t t0 = esp_cpu_get_cycle_count();

	while (esp_cpu_get_cycle_count() - t0 < cyc)
		;
}

static void
spin_ns(const lws_epd_direct_esp32_state_t *st, uint32_t ns)
{
	spin_cyc(ns_to_cyc(st, ns));
}

static void IRAM_ATTR
pin_set(int gpio, int level)
{
	gpio_ll_set_level(&GPIO, (uint32_t)gpio, (uint32_t)level);
}

/*
 * Write the shift register shadow out.  Its outputs change together when it's
 * strobed at the end.
 */

static void IRAM_ATTR
sr_write(const lws_epd_direct_esp32_t *ee)
{
	lws_epd_direct_esp32_state_t *st = ee->state;
	int n, out;

	pin_set(ee->sr_str_gpio, 0);

	for (n = 0; n < 8; n++) {
		out = ee->sr_first_out ? 7 - n : n;

		pin_set(ee->sr_clk_gpio, 0);
		pin_set(ee->sr_data_gpio, (st->sr >> out) & 1);
		spin_cyc(st->sr_edge_cyc);
		pin_set(ee->sr_clk_gpio, 1);
		spin_cyc(st->sr_edge_cyc);
	}

	pin_set(ee->sr_clk_gpio, 0);
	pin_set(ee->sr_str_gpio, 1);
	spin_cyc(st->sr_edge_cyc);
	pin_set(ee->sr_str_gpio, 0);
}

static void IRAM_ATTR
ctl_set(const lws_epd_direct_esp32_t *ee, int ctl, int assert)
{
	const lws_epd_direct_esp32_ctl_t *c = &ee->ctl[ctl];
	lws_epd_direct_esp32_state_t *st = ee->state;
	int level = (!!assert) ^ (!!c->active_low);

	switch (c->src) {
	case LWS_EPDD_CTLSRC_GPIO:
		pin_set(c->index, level);
		break;

	case LWS_EPDD_CTLSRC_SR:
		if (level)
			st->sr = (uint8_t)(st->sr | (1u << c->index));
		else
			st->sr = (uint8_t)(st->sr & ~(1u << c->index));
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

/* wait for the gate pulse in flight, if any, including its low time */

static void IRAM_ATTR
ckv_wait(lws_epd_direct_esp32_state_t *st)
{
	uint32_t done = RMT_LL_EVENT_TX_DONE(st->rmt_ch);

	if (!st->ckv_busy)
		return;

	while (!(rmt_ll_tx_get_interrupt_status_raw(&RMT,
					(uint32_t)st->rmt_ch) & done))
		;

	rmt_ll_clear_interrupt_status(&RMT, done);
	st->ckv_busy = 0;
}

/*
 * An RMT symbol: duration0 in b0 - b14, level0 in b15, then duration1 and
 * level1 the same in the upper 16 bits.  Ours is high, then low.
 */

static uint32_t IRAM_ATTR
ckv_sym(uint32_t high_ticks, uint32_t low_ticks)
{
	if (!high_ticks)
		high_ticks = 1;
	if (high_ticks > 0x7fff)
		high_ticks = 0x7fff;
	if (!low_ticks)
		low_ticks = 1;
	if (low_ticks > 0x7fff)
		low_ticks = 0x7fff;

	return high_ticks | (1u << 15) | (low_ticks << 16);
}

/*
 * Get the idle channel ready to send sym, so starting it is then a single
 * register write.  The symbol after ours, zero, ends it.
 */

static void IRAM_ATTR
ckv_arm(lws_epd_direct_esp32_state_t *st, uint32_t sym)
{
	if (st->ckv_sym != sym) {
		st->ckv_mem[0] = sym;
		st->ckv_sym = sym;
	}

	RMT.chnconf0[st->rmt_ch].val = st->ckv_conf_rewind;
}

static void IRAM_ATTR
ckv_go(lws_epd_direct_esp32_state_t *st)
{
	RMT.chnconf0[st->rmt_ch].val = st->ckv_conf_go;
	st->ckv_busy = 1;
}

/* start a gate pulse, after the one in flight */

static void IRAM_ATTR
ckv_pulse(lws_epd_direct_esp32_state_t *st, uint32_t sym)
{
	ckv_wait(st);
	ckv_arm(st, sym);
	ckv_go(st);
}

/*
 * A gate pulse high for high_ticks, low for no longer than the panel needs
 * between pulses
 */

static uint32_t IRAM_ATTR
ckv_drive_sym(const lws_epd_direct_esp32_state_t *st, uint32_t high_ticks)
{
	uint32_t lo = st->ckv_low;

	if (high_ticks + lo < st->ckv_period)
		lo = st->ckv_period - high_ticks;

	return ckv_sym(high_ticks, lo);
}

/*
 * Work out what the gate pulses need in RMT ticks: the shortest pulse the
 * panel allows, and the least low time and period for any pulse
 */

static void
ckv_timing(const lws_epd_direct_esp32_t *ee)
{
	const lws_epd_direct_panel_t *p = ee->panel;
	lws_epd_direct_esp32_state_t *st = ee->state;
	uint32_t period = p->ckv_max_hz ? (EPDD_RMT_HZ + p->ckv_max_hz - 1) /
					   p->ckv_max_hz : 2,
		 hi = ((uint32_t)p->ckv_min_high_ns * EPDD_TICKS_PER_US + 999) /
									1000,
		 lo = ((uint32_t)p->ckv_min_low_ns * EPDD_TICKS_PER_US + 999) /
									1000;

	if (!hi)
		hi = 1;
	if (!lo)
		lo = 1;
	if (period > 0x7fff)
		period = 0x7fff;

	st->ckv_low = (uint16_t)lo;
	st->ckv_period = (uint16_t)period;

	if (hi + lo < period) {
		hi = period / 2;
		lo = period - hi;
	}

	st->ckv_min_hi = (uint16_t)hi;
	st->ckv_min_lo = (uint16_t)lo;
}

/* wait for the row being sent, if any, to have been sent */

static void IRAM_ATTR
lcd_wait(lws_epd_direct_esp32_state_t *st)
{
	lcd_cam_dev_t *dev = lcd_dev();

	if (!st->lcd_busy)
		return;

	while (!(dev->lc_dma_int_raw.val & LCD_LL_EVENT_TRANS_DONE))
		;

	lcd_ll_clear_interrupt_status(dev, LCD_LL_EVENT_TRANS_DONE);
	st->lcd_busy = 0;
}

/*
 * The DMA descriptor list for a row buffer.  We are only given a few row
 * buffers, over and over, so each gets a list made once, that the DMA doesn't
 * change, and is restarted for each row.
 */

static uintptr_t
link_mount(lws_epd_direct_esp32_state_t *st, const uint8_t *data, size_t len)
{
	gdma_buffer_mount_config_t mc;
	int n = st->link_next;

	st->link_next = (uint8_t)((n + 1) % LWS_EPDD_ESP32_LINKS);
	st->link_buf[n] = NULL;

	memset(&mc, 0, sizeof(mc));
	mc.buffer = (void *)data;
	mc.length = len;
	mc.flags.mark_eof = 1;
	mc.flags.mark_final = GDMA_FINAL_LINK_TO_NULL;

	if (gdma_link_mount_buffers((gdma_link_list_handle_t)st->link[n], 0,
				    &mc, 1, NULL) != ESP_OK)
		return 0;

	st->link_buf[n] = data;
	st->link_head[n] = gdma_link_get_head_addr(
					(gdma_link_list_handle_t)st->link[n]);

	return st->link_head[n];
}

static inline uintptr_t
link_for(lws_epd_direct_esp32_state_t *st, const uint8_t *data, size_t len)
{
	int n;

	for (n = 0; n < LWS_EPDD_ESP32_LINKS; n++)
		if (st->link_buf[n] == data)
			return st->link_head[n];

	return link_mount(st, data, len);
}

void *
lws_epd_direct_esp32_alloc_dma(const lws_epd_direct_bus_ops_t *bus,
			       size_t size)
{
	(void)bus;

	return heap_caps_aligned_alloc(4, size, MALLOC_CAP_DMA |
					MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

void
lws_epd_direct_esp32_free_dma(const lws_epd_direct_bus_ops_t *bus, void **p)
{
	(void)bus;

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
	lcd_cam_dev_t *dev = lcd_dev();
	int n;

	if (st->rmt) {
		ckv_wait(st);
		rmt_disable((rmt_channel_handle_t)st->rmt);
		rmt_del_channel((rmt_channel_handle_t)st->rmt);
		st->rmt = NULL;
	}

	if (st->dma) {
		lcd_wait(st);
		gdma_disconnect((gdma_channel_handle_t)st->dma);
		gdma_del_channel((gdma_channel_handle_t)st->dma);
		st->dma = NULL;
	}

	for (n = 0; n < LWS_EPDD_ESP32_LINKS; n++)
		if (st->link[n]) {
			gdma_del_link_list((gdma_link_list_handle_t)st->link[n]);
			st->link[n] = NULL;
		}

	if (st->lcd_acquired) {
		PERIPH_RCC_ATOMIC() {
			lcd_ll_enable_clock(dev, false);
		}
		PERIPH_RCC_RELEASE_ATOMIC(soc_lcd_i80_signals[0].module, ref) {
			if (!ref)
				lcd_ll_enable_bus_clock(0, false);
		}
		esp_clk_tree_enable_src((soc_module_clk_t)LCD_CLK_SRC_DEFAULT,
					false);
		st->lcd_acquired = 0;
	}

	st->ready = 0;
}

/* LCD_CAM as an 8-bit i80 bus, sending only data phases */

static int
lcd_init(const lws_epd_direct_esp32_t *ee)
{
	lws_epd_direct_esp32_state_t *st = ee->state;
	const soc_lcd_i80_signal_desc_t *sig = &soc_lcd_i80_signals[0];
	lcd_cam_dev_t *dev = lcd_dev();
	uint32_t src_hz = 0, res, pre;
	int n;

	if (esp_clk_tree_enable_src((soc_module_clk_t)LCD_CLK_SRC_DEFAULT,
				    true) != ESP_OK ||
	    esp_clk_tree_src_get_freq_hz((soc_module_clk_t)LCD_CLK_SRC_DEFAULT,
				ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED,
				&src_hz) != ESP_OK || !src_hz)
		return 1;

	/* the pixel clock divider is an integer, so round to not be faster */

	res = src_hz / EPDD_LCD_GROUP_DIV;
	pre = (res + ee->xcl_hz - 1) / ee->xcl_hz;
	if (!pre || pre > LCD_LL_PCLK_DIV_MAX)
		return 1;
	st->xcl_hz = res / pre;

	PERIPH_RCC_ACQUIRE_ATOMIC(sig->module, ref) {
		if (!ref) {
			lcd_ll_enable_bus_clock(0, true);
			lcd_ll_reset_register(0);
		}
	}
	st->lcd_acquired = 1;

	PERIPH_RCC_ATOMIC() {
		lcd_ll_enable_clock(dev, true);
		lcd_ll_select_clk_src(dev, LCD_CLK_SRC_DEFAULT);
		lcd_ll_set_group_clock_coeff(dev, EPDD_LCD_GROUP_DIV, 0, 0);
	}

	lcd_ll_reset(dev);
	lcd_ll_fifo_reset(dev);

	/* we look at the raw status, nothing goes to the cpu */
	PERIPH_RCC_ATOMIC() {
		lcd_ll_enable_interrupt(dev, LCD_LL_EVENT_I80, false);
	}
	lcd_ll_clear_interrupt_status(dev, UINT32_MAX);

	lcd_ll_enable_rgb_mode(dev, false);
	lcd_ll_enable_color_convert(dev, false);
	lcd_ll_set_dma_read_stride(dev, 8);
	lcd_ll_set_swizzle_mode(dev, LCD_LL_SWIZZLE_AB2BA);
	lcd_ll_enable_swizzle(dev, false);
	lcd_ll_reverse_dma_data_bit_order(dev, false);
	/* how much is sent is set by the DMA */
	lcd_ll_enable_output_always_on(dev, true);
	lcd_ll_set_data_wire_width(dev, 8);

	lcd_ll_set_pixel_clock_prescale(dev, pre);
	/* XCL idles high, data changes on its falling edge */
	lcd_ll_set_clock_idle_level(dev, true);
	lcd_ll_set_pixel_clock_edge(dev, false);
	/* XSTL is low while a row is sent, otherwise high */
	lcd_ll_set_dc_level(dev, true, true, true, false);
	lcd_ll_set_phase_cycles(dev, 0, 0, 1);
	lcd_ll_set_blank_cycles(dev, 1, 1);

	/* the pins */

	for (n = 0; n < 8; n++) {
		gpio_func_sel((gpio_num_t)ee->data_gpio[n], PIN_FUNC_GPIO);
		esp_rom_gpio_connect_out_signal((uint32_t)ee->data_gpio[n],
				(uint32_t)sig->data_sigs[n], false, false);
	}
	gpio_func_sel((gpio_num_t)ee->sth_gpio, PIN_FUNC_GPIO);
	esp_rom_gpio_connect_out_signal((uint32_t)ee->sth_gpio,
					(uint32_t)sig->dc_sig, false, false);
	gpio_func_sel((gpio_num_t)ee->xcl_gpio, PIN_FUNC_GPIO);
	esp_rom_gpio_connect_out_signal((uint32_t)ee->xcl_gpio,
					(uint32_t)sig->wr_sig, false, false);

	return 0;
}

/* a GDMA channel feeding LCD_CAM, and a reusable list for each row buffer */

static int
dma_init(lws_epd_direct_esp32_state_t *st)
{
	gdma_channel_alloc_config_t ac;
	gdma_strategy_config_t sc;
	gdma_transfer_config_t tc;
	gdma_link_list_config_t lc;
	gdma_channel_handle_t ch;
	gdma_link_list_handle_t ll;
	int n;

	memset(&ac, 0, sizeof(ac));
	if (gdma_new_ahb_channel(&ac, &ch, NULL) != ESP_OK)
		return 1;
	st->dma = ch;

	if (gdma_connect(ch, GDMA_MAKE_TRIGGER(GDMA_TRIG_PERIPH_LCD, 0)) !=
								ESP_OK)
		return 1;

	/*
	 * The DMA doesn't take ownership of, or write back, the descriptors,
	 * so a list can be started again without being made again
	 */

	memset(&sc, 0, sizeof(sc));
	sc.owner_check = false;
	sc.auto_update_desc = false;
	memset(&tc, 0, sizeof(tc));
	/* rows are small and sent at 20MB/s at most: no burst, no alignment */
	tc.max_data_burst_size = 0;
	if (gdma_apply_strategy(ch, &sc) != ESP_OK ||
	    gdma_config_transfer(ch, &tc) != ESP_OK)
		return 1;

	memset(&lc, 0, sizeof(lc));
	lc.num_items = 1;
	lc.item_alignment = 4;
	lc.flags.check_owner = 0;

	for (n = 0; n < LWS_EPDD_ESP32_LINKS; n++) {
		if (gdma_new_link_list(&lc, &ll) != ESP_OK)
			return 1;
		st->link[n] = ll;
	}

	return 0;
}

/* an RMT channel for CKV, that we only start and look at the end of */

static int
rmt_init(const lws_epd_direct_esp32_t *ee)
{
	lws_epd_direct_esp32_state_t *st = ee->state;
	rmt_tx_channel_config_t rc;
	rmt_channel_handle_t rmt;
	rmt_chnconf0_reg_t conf;
	int id;

	memset(&rc, 0, sizeof(rc));
	rc.gpio_num = ee->ckv_gpio;
	rc.clk_src = RMT_CLK_SRC_DEFAULT;
	rc.resolution_hz = EPDD_RMT_HZ;
	rc.mem_block_symbols = SOC_RMT_MEM_WORDS_PER_CHANNEL;
	rc.trans_queue_depth = 1;

	if (rmt_new_tx_channel(&rc, &rmt) != ESP_OK)
		return 1;
	st->rmt = rmt;

	/*
	 * We never call rmt_transmit(), so the driver never enables the
	 * channel's interrupts: we start it and see it end ourselves
	 */

	if (rmt_enable(rmt) != ESP_OK || rmt_get_channel_id(rmt, &id) != ESP_OK)
		return 1;

	st->rmt_ch = id;
	st->ckv_mem = &RMTMEM[(size_t)id * SOC_RMT_MEM_WORDS_PER_CHANNEL];

	/* our symbol goes in word 0, this one after it ends the pulse */
	st->ckv_mem[1] = 0;
	st->ckv_sym = 0;
	rmt_ll_clear_interrupt_status(&RMT, RMT_LL_EVENT_TX_DONE(id));

	/*
	 * The driver has configured the channel, and nothing else changes it
	 * while we have it, so starting it is that config with the bits that
	 * rewind it, or start it, set.  They clear themselves.
	 */

	conf.val = RMT.chnconf0[id].val;
	conf.tx_start_chn = 0;
	conf.mem_rd_rst_chn = 0;
	conf.apb_mem_rst_chn = 0;
	conf.conf_update_chn = 0;

	conf.mem_rd_rst_chn = 1;
	st->ckv_conf_rewind = conf.val;
	conf.mem_rd_rst_chn = 0;
	conf.conf_update_chn = 1;
	conf.tx_start_chn = 1;
	st->ckv_conf_go = conf.val;

	return 0;
}

int
lws_epd_direct_esp32_init(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;
	int n, uses_sr = 0;

	if (!st || !ee->panel || !ee->xcl_hz ||
	    ee->xcl_hz > ee->panel->xcl_max_hz) {
		lwsl_err("%s: no state, or data clock too fast for panel\n",
			 __func__);
		return 1;
	}

	memset(st, 0, sizeof(*st));
	st->cyc_per_us = esp_rom_get_cpu_ticks_per_us();
	st->sr_edge_cyc = ns_to_cyc(st, EPDD_SR_EDGE_NS);

	/* XLE is pulsed every row, if it's on a gpio we go straight to it */
	st->le_gpio = -1;
	if (ee->ctl[LWS_EPDD_CTL_LE].src == LWS_EPDD_CTLSRC_GPIO) {
		st->le_gpio = ee->ctl[LWS_EPDD_CTL_LE].index;
		st->le_level = (uint8_t)!ee->ctl[LWS_EPDD_CTL_LE].active_low;
	}

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

	if (lcd_init(ee)) {
		lwsl_err("%s: LCD_CAM setup failed\n", __func__);
		goto bail;
	}
	if (dma_init(st)) {
		lwsl_err("%s: GDMA setup failed\n", __func__);
		goto bail;
	}
	if (rmt_init(ee)) {
		lwsl_err("%s: RMT setup failed\n", __func__);
		goto bail;
	}

	/* the waits each row needs, in cpu cycles */

	st->le_delay_cyc = ns_to_cyc(st, (uint32_t)
			(((uint64_t)ee->panel->le_min_delay_xcl_x2 *
			  500000000ull + st->xcl_hz - 1) / st->xcl_hz));
	st->le_width_cyc = ns_to_cyc(st, ee->panel->le_min_width_ns);
	st->le_off_cyc = ns_to_cyc(st, ee->panel->le_min_off_ns);
	st->prefill_cyc = ns_to_cyc(st, EPDD_PREFILL_NS);
	ckv_timing(ee);

	st->ready = 1;

	lwsl_notice("%s: data clock %uHz\n", __func__,
		    (unsigned int)st->xcl_hz);

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
	lws_epd_direct_esp32_state_t *st = ee->state;
	const lws_epd_direct_esp32_step_t *s = on ? ee->power_on : ee->power_off;
	uint8_t n, count = on ? ee->power_on_count : ee->power_off_count;

	if (!st->ready)
		return 1;

	if (!on) {
		/* nothing may be driven while the supplies go */
		ckv_wait(st);
		lcd_wait(st);
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
	lws_epd_direct_esp32_state_t *st = ee->state;
	uint32_t sym = ckv_sym(st->ckv_min_hi, st->ckv_min_lo);
	uint8_t n;

	ckv_wait(st);

	/*
	 * The gate driver takes the start pulse on a CKV rising edge, then each
	 * CKV moves it on a row.  SPV has to be set up 100ns before the edge,
	 * and go away at least 100ns after it, but before CKV falls.
	 */

	ctl_set(ee, LWS_EPDD_CTL_MODE, 1);
	ctl_set(ee, LWS_EPDD_CTL_STV, 1);
	spin_ns(st, EPDD_SPV_SETUP_NS);
	ckv_pulse(st, sym);
	spin_ns(st, ((uint32_t)st->ckv_min_hi * 1000u / EPDD_TICKS_PER_US) / 2);
	ctl_set(ee, LWS_EPDD_CTL_STV, 0);

	for (n = 0; n < ee->frame_lead_ckv; n++)
		ckv_pulse(st, sym);

	ckv_wait(st);
	ctl_set(ee, LWS_EPDD_CTL_OE, 1);
}

void IRAM_ATTR
lws_epd_direct_esp32_row_load(const lws_epd_direct_bus_ops_t *bus,
			      const uint8_t *data, size_t len)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;
	lcd_cam_dev_t *dev = lcd_dev();
	uintptr_t head;

	lcd_wait(st);

	head = link_for(st, data, len);
	if (!head)
		return;

	lcd_ll_reset(dev);
	lcd_ll_fifo_reset(dev);
	gdma_start((gdma_channel_handle_t)st->dma, (intptr_t)head);
	/* let the DMA get something into the FIFO before it's sent from */
	spin_cyc(st->prefill_cyc);
	lcd_ll_start(dev);
	st->lcd_busy = 1;
}

void IRAM_ATTR
lws_epd_direct_esp32_row_drive(const lws_epd_direct_bus_ops_t *bus,
			       uint32_t drive_ns)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);
	lws_epd_direct_esp32_state_t *st = ee->state;
	uint32_t sym = ckv_drive_sym(st, (drive_ns * EPDD_TICKS_PER_US + 999) /
									1000);

	lcd_wait(st);
	/* XLE follows the last XCL by le_min_delay_xcl_x2 half cycles */
	spin_cyc(st->le_delay_cyc);

	/*
	 * The previous row's gate pulse must end before we latch this one.
	 * Then the gate pulse for this row is made ready, so it can follow
	 * XLE as closely as possible.
	 */
	ckv_wait(st);
	ckv_arm(st, sym);

	if (st->le_gpio >= 0) {
		pin_set(st->le_gpio, st->le_level);
		spin_cyc(st->le_width_cyc);
		pin_set(st->le_gpio, !st->le_level);
	} else {
		ctl_set(ee, LWS_EPDD_CTL_LE, 1);
		spin_cyc(st->le_width_cyc);
		ctl_set(ee, LWS_EPDD_CTL_LE, 0);
	}

	ckv_go(st);

	/* the next row's data mustn't start too soon after XLE */
	spin_cyc(st->le_off_cyc);
}

void IRAM_ATTR
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus)
{
	lws_epd_direct_esp32_state_t *st = to_ee(bus)->state;

	ckv_pulse(st, ckv_sym(st->ckv_min_hi, st->ckv_min_lo));
}

void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus)
{
	const lws_epd_direct_esp32_t *ee = to_ee(bus);

	ckv_wait(ee->state);
	ctl_set(ee, LWS_EPDD_CTL_OE, 0);
	ctl_set(ee, LWS_EPDD_CTL_MODE, 0);
}

#else

/* not an ESP32-S3 */

int
lws_epd_direct_esp32_init(const lws_epd_direct_bus_ops_t *bus)
{
	lwsl_err("%s: not supported on this chip\n", __func__);

	return 1;
}

void
lws_epd_direct_esp32_deinit(const lws_epd_direct_bus_ops_t *bus)
{
	/* init refused the bus on this chip: nothing to do */
}

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
lws_epd_direct_esp32_free_dma(const lws_epd_direct_bus_ops_t *bus, void **p)
{
	/* init refused the bus on this chip: nothing to do */
}

void
lws_epd_direct_esp32_frame_start(const lws_epd_direct_bus_ops_t *bus)
{
	/* init refused the bus on this chip: nothing to do */
}

void
lws_epd_direct_esp32_row_load(const lws_epd_direct_bus_ops_t *bus,
			      const uint8_t *data, size_t len)
{
	/* init refused the bus on this chip: nothing to do */
}

void
lws_epd_direct_esp32_row_drive(const lws_epd_direct_bus_ops_t *bus,
			       uint32_t drive_ns)
{
	/* init refused the bus on this chip: nothing to do */
}

void
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus)
{
	/* init refused the bus on this chip: nothing to do */
}

void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus)
{
	/* init refused the bus on this chip: nothing to do */
}

#endif
