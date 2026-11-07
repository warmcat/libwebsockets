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
 * The lws_epd_direct_bus_ops_t transport on esp32 chips with the i80 LCD
 * peripheral, eg, the ESP32-S3.  The source driver data bus and its clock
 * (XCL / CKH) are the i80 bus data lines and WR, its start pulse (XSTL / STH)
 * is the i80 D/C line, low while a row is sent, and the gate driver clock
 * (CKV) pulses come from an RMT channel, so the gate can be held on for a row
 * while the next one is being sent.
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

typedef struct lws_epd_direct_esp32_state {
	void			*i80_bus;
	void			*io;
	void			*rmt;
	void			*rmt_enc;
	volatile int		dma_busy;
	uint32_t		ckv_sym;
	/**< the RMT symbol for the gate clock pulse being sent */
	uint8_t			sr;
	/**< what the shift register outputs are */
	uint8_t			rmt_busy;
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
			       uint32_t drive_us);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_row_skip(const lws_epd_direct_bus_ops_t *bus);
LWS_VISIBLE LWS_EXTERN void
lws_epd_direct_esp32_frame_end(const lws_epd_direct_bus_ops_t *bus);

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
