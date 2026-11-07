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
 * The lws_epd_direct_bus_ops_t transport on the ESP32-S3, and a runner that
 * runs the passes on a FreeRTOS task of their own, eg, on the second core.
 *
 * The source driver data bus and its clock (XCL / CKH) are the LCD_CAM i80
 * data lines and WR, its start pulse (XSTL / STH) is the i80 D/C line, low
 * while a row is sent, and the gate driver clock (CKV) pulses come from an RMT
 * channel, so the gate can be held on for a row while the next one is being
 * sent.  Each row costs a few register writes rather than calls into the IDF
 * drivers, so it drives LCD_CAM, its GDMA channel and the RMT channel through
 * the IDF's hal and private headers.  It was written against esp-idf v6.1.
 *
 * The other control lines and the panel supplies may each be on a gpio, or on
 * an output of a 74HC(T)4094 / 595 type shift register, since boards are short
 * of gpios.  The shift register is written by bitbanging three gpios.
 */

#if !defined(__LWS_ESP32_EPD_DIRECT_H__)
#define __LWS_ESP32_EPD_DIRECT_H__

/*
 * The panel control lines and supply enables other than the data bus, its
 * clocks and the start pulses on the bus
 */

enum {
	LWS_EPDD_CTL_LE,	/* source driver latch (XLE) */
	LWS_EPDD_CTL_OE,	/* source driver output enable (XOE) */
	LWS_EPDD_CTL_MODE,	/* gate driver output mode (MODE1) */
	LWS_EPDD_CTL_STV,	/* gate driver start pulse (SPV / STV) */
	LWS_EPDD_CTL_RAIL0,	/* panel supply enables, as the board has */
	LWS_EPDD_CTL_RAIL1,	/* them: the power sequences say which is */
	LWS_EPDD_CTL_RAIL2,	/* which */
	LWS_EPDD_CTL_RAIL3,
	LWS_EPDD_CTL_AUX,	/* something else on the shift register the
				 * board needs held, see .init_asserted */

	LWS_EPDD_CTL_COUNT
};

enum {
	LWS_EPDD_CTLSRC_NONE,	/* the board doesn't have this line */
	LWS_EPDD_CTLSRC_GPIO,	/* .index is a gpio */
	LWS_EPDD_CTLSRC_SR,	/* .index is a shift register output, 0 - 7 */
};

typedef struct lws_epd_direct_esp32_ctl {
	uint8_t			src;
	/**< LWS_EPDD_CTLSRC_ */
	uint8_t			index;
	/**< the gpio, or the shift register output */
	uint8_t			active_low;
	/**< the line is asserted by driving it low */
	uint8_t			init_asserted;
	/**< it's asserted from init, rather than deasserted, eg, a board
	 * power hold that shares the shift register */
} lws_epd_direct_esp32_ctl_t;

/*
 * A step of sequencing the panel supplies: assert or deassert a line, then
 * wait at least delay_us before the next step
 */

typedef struct lws_epd_direct_esp32_step {
	uint8_t			ctl;
	/**< LWS_EPDD_CTL_ */
	uint8_t			assert;
	/**< 1 to assert it, 0 to deassert it */
	uint32_t		delay_us;
} lws_epd_direct_esp32_step_t;

/*
 * What the transport keeps while it's running.  The board provides one per
 * panel, it's opaque.
 */

#define LWS_EPDD_ESP32_LINKS	3

typedef struct lws_epd_direct_esp32_state {
	void			*dma;
	/**< the GDMA channel feeding LCD_CAM */
	void			*link[LWS_EPDD_ESP32_LINKS];
	/**< a DMA descriptor list for each row buffer we've been given */
	const uint8_t		*link_buf[LWS_EPDD_ESP32_LINKS];
	/**< the row buffer each one is for */
	void			*rmt;
	/**< the RMT channel for CKV */
	uintptr_t		link_head[LWS_EPDD_ESP32_LINKS];
	/**< the DMA address of each descriptor list */
	volatile uint32_t	*ckv_mem;
	/**< the RMT channel's symbol memory */
	uint32_t		ckv_sym;
	/**< the RMT symbol in the channel's memory */
	uint32_t		ckv_conf_rewind;
	/**< RMT channel config register value that rewinds it */
	uint32_t		ckv_conf_go;
	/**< RMT channel config register value that starts it */
	uint32_t		cyc_per_us;
	/**< cpu cycles per us, for the short waits */
	uint32_t		le_delay_cyc;
	/**< cpu cycles from the end of the data to XLE */
	uint32_t		le_width_cyc;
	/**< cpu cycles XLE is asserted for */
	uint32_t		le_off_cyc;
	/**< cpu cycles from XLE to the next data */
	uint32_t		prefill_cyc;
	/**< cpu cycles DMA is given to start filling the bus FIFO */
	uint32_t		sr_edge_cyc;
	/**< cpu cycles between shift register edges */
	uint32_t		xcl_hz;
	/**< the data clock we actually got */
	uint16_t		ckv_min_hi;
	/**< RMT ticks high, for the shortest CKV pulse */
	uint16_t		ckv_min_lo;
	/**< RMT ticks low, for the shortest CKV pulse */
	uint16_t		ckv_low;
	/**< the least RMT ticks low after any CKV pulse */
	uint16_t		ckv_period;
	/**< the least RMT ticks for a whole CKV pulse */
	int			rmt_ch;
	int			le_gpio;
	/**< XLE's gpio if it's on one, else -1 */
	uint8_t			le_level;
	/**< the level XLE's gpio is at when asserted */
	uint8_t			link_next;
	/**< which link to reuse for a row buffer we haven't seen */
	uint8_t			sr;
	/**< what the shift register outputs are */
	uint8_t			ckv_busy;
	/**< a CKV pulse was started and we haven't seen it end */
	uint8_t			lcd_busy;
	/**< a row was started on the bus and we haven't seen it end */
	uint8_t			lcd_acquired;
	uint8_t			ready;
} lws_epd_direct_esp32_state_t;

typedef struct lws_epd_direct_esp32 {
	lws_epd_direct_bus_ops_t	bus;
	/**< use lws_epd_direct_esp32_ops to set the ops */
	const lws_epd_direct_panel_t	*panel;
	/**< for the timing limits */
	lws_epd_direct_esp32_state_t	*state;

	const lws_epd_direct_esp32_step_t *power_on;
	const lws_epd_direct_esp32_step_t *power_off;

	uint32_t			xcl_hz;
	/**< the source driver data clock, at most the panel's xcl_max_hz */

	int8_t				data_gpio[8];
	/**< the gpio for each bus bit, D0 first */
	int8_t				xcl_gpio;
	/**< source driver data clock, XCL / CKH */
	int8_t				sth_gpio;
	/**< source driver start pulse, XSTL / STH */
	int8_t				ckv_gpio;
	/**< gate driver clock, CKV */
	int8_t				sr_data_gpio;
	int8_t				sr_clk_gpio;
	int8_t				sr_str_gpio;
	/**< the shift register's serial data, clock and strobe, or -1 if
	 * nothing is on a shift register */

	lws_epd_direct_esp32_ctl_t	ctl[LWS_EPDD_CTL_COUNT];

	uint8_t				power_on_count;
	uint8_t				power_off_count;
	uint8_t				sr_first_out;
	/**< the shift register output the first bit shifted in ends up on,
	 * eg, 7 for a 4094 with QP7 the far end */
	uint8_t				frame_lead_ckv;
	/**< extra gate clocks after the start pulse before the first row */
} lws_epd_direct_esp32_t;

LWS_VISIBLE LWS_EXTERN int
lws_epd_direct_esp32_init(const lws_epd_direct_bus_ops_t *bus);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_deinit(const lws_epd_direct_bus_ops_t *bus);
LWS_VISIBLE LWS_EXTERN int
lws_epd_direct_esp32_power(const lws_epd_direct_bus_ops_t *bus, int on);
LWS_VISIBLE LWS_EXTERN void *
lws_epd_direct_esp32_alloc_dma(const lws_epd_direct_bus_ops_t *bus,
			       size_t size);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_free_dma(const lws_epd_direct_bus_ops_t *bus, void **p);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_frame_start(const lws_epd_direct_bus_ops_t *bus);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_row_load(const lws_epd_direct_bus_ops_t *bus,
			      const uint8_t *data, size_t len);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_row_drive(const lws_epd_direct_bus_ops_t *bus,
			       uint32_t drive_ns);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus);

/*
 * Runs the passes on a FreeRTOS task pinned to a core.  It doesn't hog the
 * core: if it has been busy for a while, it sleeps a tick so the core's idle
 * task can run.
 */

typedef struct lws_epd_direct_esp32_runner_state {
	void			*task;
	lws_display_state_t	*lds;
	volatile uint8_t	ended;
} lws_epd_direct_esp32_runner_state_t;

typedef struct lws_epd_direct_esp32_runner {
	lws_epd_direct_runner_t	runner;
	/**< use lws_epd_direct_esp32_runner_ops to set the ops */
	lws_epd_direct_esp32_runner_state_t *state;
	uint32_t		stack_size;
	/**< bytes of stack for the task */
	uint8_t			core;
	/**< the core to run it on */
	uint8_t			priority;
	/**< its FreeRTOS priority */
} lws_epd_direct_esp32_runner_t;

LWS_VISIBLE LWS_EXTERN int
lws_epd_direct_esp32_runner_start(const lws_epd_direct_runner_t *r,
				  lws_display_state_t *lds);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_runner_kick(const lws_epd_direct_runner_t *r);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_runner_stop(const lws_epd_direct_runner_t *r);

#define lws_epd_direct_esp32_runner_ops \
	.start		= lws_epd_direct_esp32_runner_start, \
	.kick		= lws_epd_direct_esp32_runner_kick, \
	.stop		= lws_epd_direct_esp32_runner_stop

#define lws_epd_direct_esp32_ops \
	.init		= lws_epd_direct_esp32_init, \
	.deinit		= lws_epd_direct_esp32_deinit, \
	.power		= lws_epd_direct_esp32_power, \
	.alloc_dma	= lws_epd_direct_esp32_alloc_dma, \
	.free_dma	= lws_epd_direct_esp32_free_dma, \
	.frame_start	= lws_epd_direct_esp32_frame_start, \
	.row_load	= lws_epd_direct_esp32_row_load, \
	.row_drive	= lws_epd_direct_esp32_row_drive, \
	.row_skip	= lws_epd_direct_esp32_row_skip, \
	.frame_end	= lws_epd_direct_esp32_frame_end

#endif
