/*
 * lws abstract display implementation for SSD1675B on SPI
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
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
 * Based on datasheet
 *
 *   https://cdn-learn.adafruit.com/assets/assets/000/092/748/original/SSD1675_0.pdf
 *
 * This chip takes a planar approach with two distinct framebuffers for b0 and
 * b1 of the red levels.  But the panel is B&W so we ignore red.
 *
 * Notice this 2.13" B&W panel needs POSITION B on the Waveshare ESP32
 * prototype board DIP switch.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {
	SSD1675B_CMD_DRIVER_OUT_CTRL				= 0x01,
	SSD1675B_CMD_GATE_DRIVEV_CTRL				= 0x03,
	SSD1675B_CMD_SOURCE_DRIVEV_CTRL				= 0x04,
	SSD1675B_CMD_DEEP_SLEEP					= 0x10,
	SSD1675B_CMD_DATA_ENTRY_MODE				= 0x11,
	SSD1675B_CMD_SW_RESET					= 0x12,
	SSD1675B_CMD_MAIN_ACTIVATION				= 0x20,
	SSD1675B_CMD_DISPLAY_UPDATE_CTRL			= 0x22,
	SSD1675B_CMD_WRITE_BW_SRAM				= 0x24,
	SSD1675B_CMD_WRITE_RED_SRAM				= 0x26,
	SSD1675B_CMD_VCOM_VOLTAGE				= 0x2C,
	SSD1675B_CMD_LUT					= 0x32,
	SSD1675B_CMD_WRITE_DISPLAY_OPTIONS			= 0x37,
	SSD1675B_CMD_DUMMY_LINE					= 0x3A,
	SSD1675B_CMD_GATE_TIME					= 0x3B,
	SSD1675B_CMD_BORDER_WAVEFORM				= 0x3C,
	SSD1675B_CMD_SET_RAM_X					= 0x44,
	SSD1675B_CMD_SET_RAM_Y					= 0x45,
	SSD1675B_CMD_SET_COUNT_X				= 0x4e,
	SSD1675B_CMD_SET_COUNT_Y				= 0x4f,
	SSD1675B_CMD_SET_ANALOG_BLOCK_CTRL			= 0x74,
	SSD1675B_CMD_SET_DIGITAL_BLOCK_CTRL			= 0x7e,
};

typedef enum {
	LWSDISPST_IDLE,
	LWSDISPST_INIT1,
	LWSDISPST_INIT2,
	LWSDISPST_INIT3,
	LWSDISPST_INIT4,
	LWSDISPST_WRITE1,
	LWSDISPST_WRITE2,
	LWSDISPST_WRITE3,
	LWSDISPST_WRITE4,
	LWSDISPST_WRITE5,

	LWSDISPRET_ASYNC			= 1
} lws_display_update_state_t;

//static
const uint8_t ssd1675b_init1_full[] = {
	0,	SSD1675B_CMD_SW_RESET,
	/* wait idle */
}, ssd1675b_init1_part[] = {
	1,	SSD1675B_CMD_VCOM_VOLTAGE,		0x26,
	/* wait idle */
}, ssd1675b_init2_full[] = {
	1, 	SSD1675B_CMD_SET_ANALOG_BLOCK_CTRL,	0x54,
	1,	SSD1675B_CMD_SET_DIGITAL_BLOCK_CTRL,	0x3b,
	3,	SSD1675B_CMD_DRIVER_OUT_CTRL,		0xf9, 0x00, 0x00,
	1,	SSD1675B_CMD_DATA_ENTRY_MODE,		0x03,
	2,	SSD1675B_CMD_SET_RAM_X,			0x00, 0x0f,
	4,	SSD1675B_CMD_SET_RAM_Y,			0x00, 0x00, 0xf9, 0x00,
	1,	SSD1675B_CMD_BORDER_WAVEFORM,		0x03,
	1,	SSD1675B_CMD_VCOM_VOLTAGE,		0x55,
	1,	SSD1675B_CMD_GATE_DRIVEV_CTRL,		0x15,
	3,	SSD1675B_CMD_SOURCE_DRIVEV_CTRL,	0x41, 0xa8, 0x32,
	1,	SSD1675B_CMD_DUMMY_LINE,		0x30,
	1,	SSD1675B_CMD_GATE_TIME,			0x0a,
	70,	SSD1675B_CMD_LUT,
		0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,   //LUT0: BB:  VS 0 ~7
		0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,   //LUT1: BW:  VS 0 ~7
		0x80, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00,   //LUT2: WB:  VS 0 ~7
		0x10, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00,   //LUT3: WW:  VS 0 ~7
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT4: VCOM:VS 0 ~7

		0x03, 0x03, 0x00, 0x00, 0x02,               // TP0 A~D RP0
		0x09, 0x09, 0x00, 0x00, 0x02,               // TP1 A~D RP1
		0x03, 0x03, 0x00, 0x00, 0x02,               // TP2 A~D RP2
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP3 A~D RP3
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP4 A~D RP4
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP5 A~D RP5
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP6 A~D RP6
	1,	SSD1675B_CMD_SET_COUNT_X,		0x00,
	2,	SSD1675B_CMD_SET_COUNT_Y,		0x00, 0x00,
}, ssd1675b_init2_part[] = {
	70,	SSD1675B_CMD_LUT,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT0: BB:  VS 0 ~7
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT1: BW:  VS 0 ~7
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT2: WB:  VS 0 ~7
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT3: WW:  VS 0 ~7
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   //LUT4: VCOM:VS 0 ~7

		0x0A, 0x00, 0x00, 0x00, 0x00,               // TP0 A~D RP0
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP1 A~D RP1
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP2 A~D RP2
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP3 A~D RP3
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP4 A~D RP4
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP5 A~D RP5
		0x00, 0x00, 0x00, 0x00, 0x00,               // TP6 A~D RP6

	7,	SSD1675B_CMD_WRITE_DISPLAY_OPTIONS,	0x00, 0x00, 0x00, 0x00,
							0x40, 0x00, 0x00,
	1,	SSD1675B_CMD_DISPLAY_UPDATE_CTRL,	0xc0,
	0,	SSD1675B_CMD_MAIN_ACTIVATION,
	/* wait idle */
}, ssd1675b_init3_part[] = {
	1,	SSD1675B_CMD_BORDER_WAVEFORM,		0x01
}, ssd1675b_off[] = {
	1,	SSD1675B_CMD_DEEP_SLEEP,		0x01
}, ssd1675b_wp1[] = {
	0,	SSD1675B_CMD_WRITE_BW_SRAM,
}, ssd1675b_wp2[] = {
	0,	SSD1675B_CMD_WRITE_RED_SRAM,
}, ssd1675b_complete_full[] = {
	1,	SSD1675B_CMD_DISPLAY_UPDATE_CTRL,	0xc7,
	0,	SSD1675B_CMD_MAIN_ACTIVATION
};

typedef struct lws_display_ssd1675b_spi_state {
	struct lws_display_state		*lds;

	uint8_t					*planebuf;

	uint32_t				*line[2];
	lws_surface_error_t			*u[2];

	lws_sorted_usec_list_t			sul;

	size_t					pb_len;
	size_t					pb_pos;

	int					state;
	int					budget;
} lws_display_ssd1675b_spi_state_t;

#define lds_to_disp(_lds) (const lws_display_ssd1675b_spi_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_ssd1675b_spi_state_t *)_lds->priv;

/*
 * The lws greyscale line composition buffer is width x Y bytes linearly.
 *
 * For SSD1675B, this is processed into a private buffer layout in priv->line
 * that is sent over SPI to the chip, the format is both packed and planar: the
 * first half is packed width x 1bpp "B&W" bits, and the second half is packed
 * width x "red" bits.  We only support B&W atm.
 */

/* MSB plane is in first half of priv linebuf */

#define pack_native_pixel(_line, _x, _c) \
		{ *_line = (*_line & ~(1 << (((_x ^ 7) & 31)))) | \
				(_c << (((_x ^ 7) & 31))); \
		  if ((_x & 31) == 31) \
			  _line++; }

static void
async_cb(lws_sorted_usec_list_t *sul);

#define BUSY_TIMEOUT_BUDGET 160

static int
check_busy(lws_display_ssd1675b_spi_state_t *priv, int level)
{
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(priv->lds);

	if (ea->gpio->read(ea->busy_gpio) == level)
		return 0; /* good */

	if (!--priv->budget) {
		lwsl_err("%s: timeout waiting idle %d\n", __func__, level);
		return -1; /* timeout */
	}
	lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
			 LWS_US_PER_MS * 50);

	return 1; /* keeping on trying */
}

static int
spi_issue_table(struct lws_display_state *lds, const uint8_t *table, size_t len)
{
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(lds);
	lws_spi_desc_t desc;
	size_t pos = 0;

	memset(&desc, 0, sizeof(desc));
	desc.count_cmd = 1;

	while (pos < len) {
		desc.count_write = table[pos++];
		desc.src = &table[pos++];
		desc.data = &table[pos];
		pos += desc.count_write;

		ea->spi->queue(ea->spi, &desc);
	}

	return 0;
}

static void
async_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_ssd1675b_spi_state_t *priv = lws_container_of(sul,
					lws_display_ssd1675b_spi_state_t, sul);
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(priv->lds);

	switch (priv->state) {

	case LWSDISPST_INIT1:
		/* take reset low for a short time */
		ea->gpio->set(ea->reset_gpio, 0);
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT2:
		/* park reset high again and then wait a bit */
		ea->gpio->set(ea->reset_gpio, 1);
		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 20);
		break;

	case LWSDISPST_INIT3:
		if (check_busy(priv, 0))
			return;

		spi_issue_table(priv->lds, ssd1675b_init1_full,
				LWS_ARRAY_SIZE(ssd1675b_init1_full));

		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT4:
		if (check_busy(priv, 0))
			return;

		priv->state = LWSDISPST_IDLE;
		spi_issue_table(priv->lds, ssd1675b_init2_full,
				LWS_ARRAY_SIZE(ssd1675b_init2_full));

		if (ea->cb)
			ea->cb(priv->lds, 1);
		break;

	case LWSDISPST_WRITE1:

		/*
		 * Finalize the write of the planes, LUT set then REFRESH
		 */

		spi_issue_table(priv->lds, ssd1675b_complete_full,
				LWS_ARRAY_SIZE(ssd1675b_complete_full));
		priv->budget = BUSY_TIMEOUT_BUDGET;
		priv->state++;

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 50);
		break;

	case LWSDISPST_WRITE2:
		if (check_busy(priv, 0))
			return;

		if (ea->spi->free_dma)
			ea->spi->free_dma(ea->spi,
					    (void **)&priv->line[0]);
		else
			lws_free_set_NULL(priv->line[0]);
		lws_free_set_NULL(priv->u[0]);

		/* fully completed the blit */

		priv->state = LWSDISPST_IDLE;
		if (ea->cb)
			ea->cb(priv->lds, 2);
		break;

	default:
		break;
	}
}

int
lws_display_ssd1675b_spi_init(struct lws_display_state *lds)
{
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(lds);
	lws_display_ssd1675b_spi_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;

	ea->gpio->mode(ea->busy_gpio, LWSGGPIO_FL_READ | LWSGGPIO_FL_PULLUP);

	ea->gpio->mode(ea->reset_gpio, LWSGGPIO_FL_WRITE | LWSGGPIO_FL_PULLUP);

	ea->gpio->set(ea->reset_gpio, 1);
	priv->state = LWSDISPST_INIT1;
	lws_sul_schedule(lds->ctx, 0, &priv->sul, async_cb,
			 LWS_US_PER_MS * 200);

	return 0;
}

/* no backlight */

int
lws_display_ssd1675b_spi_brightness(const struct lws_display *disp, uint8_t b)
{
	return 0;
}

int
lws_display_ssd1675b_spi_blit(struct lws_display_state *lds, const uint8_t *src,
			     lws_box_t *box)
{
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(lds);
	lws_display_ssd1675b_spi_state_t *priv = lds_to_priv(lds);
	lws_greyscale_error_t *gedl_this, *gedl_next;
	const lws_surface_info_t *ic = &ea->disp.ic;
	int plane_line_bytes = (ic->wh_px[0].whole + 7) / 8;
	lws_colour_error_t *edl_this, *edl_next;
	const uint8_t *pc = src;
	lws_display_colour_t c;
	lws_spi_desc_t desc;
	uint32_t *lo;
	int n, m;

	if (priv->state) {
		lwsl_warn("%s: ignoring as busy\n", __func__);
		return 1; /* busy */
	}

	if (!priv->line[0]) {
		/*
		 * We have to allocate the packed line and error diffusion
		 * buffers
		 */
		if (ea->spi->alloc_dma)
			priv->line[0] = ea->spi->alloc_dma(ea->spi, (plane_line_bytes + 4) * 2);
		else
			priv->line[0] = lws_zalloc((plane_line_bytes + 4) * 2, __func__);

		if (!priv->line[0]) {
			lwsl_err("%s: OOM\n", __func__);
			priv->state = LWSDISPST_IDLE;

			return 1;
		}

		priv->line[1] = (uint32_t *)(((uint8_t *)priv->line[0]) + plane_line_bytes + 4);

		if (lws_display_alloc_diffusion(ic, priv->u)) {
			if (ea->spi->free_dma)
				ea->spi->free_dma(ea->spi,
						    (void **)&priv->line[0]);
			else
				lws_free_set_NULL(priv->line[0]);
			lwsl_err("%s: OOM\n", __func__);
			priv->state = LWSDISPST_IDLE;
			return 1;
		}
	}

	lo = priv->line[box->y.whole & 1];

	switch (box->h.whole) {
	case 0: /* update needs to be finalized */

		priv->state = LWSDISPST_WRITE1;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 2);
		break;

	case 1:  /* single line = issue line */

		edl_this = (lws_colour_error_t *)priv->u[(box->y.whole & 1) ^ 1];
		edl_next = (lws_colour_error_t *)priv->u[box->y.whole & 1];
		gedl_this = (lws_greyscale_error_t *)edl_this;
		gedl_next = (lws_greyscale_error_t *)edl_next;

		if (!pc) {
			for (n = 0; n < ic->wh_px[0].whole; n++)
				pack_native_pixel(lo, n, 1 /* white */);
			goto go;
		}

		if (ic->greyscale) {
			gedl_next[ic->wh_px[0].whole - 1].rgb[0] = 0;

			for (n = 0; n < plane_line_bytes * 8; n++) {
				c = (pc[0] << 16) | (pc[0] << 8) | pc[0];

				m = lws_display_palettize_grey(ic, ic->palette,
						   ic->palette_depth, c, &gedl_this[n]);
				pack_native_pixel(lo, n, (uint8_t)m);

				dist_err_floyd_steinberg_grey(n, ic->wh_px[0].whole,
							      gedl_this, gedl_next);
				if (n < ic->wh_px[0].whole)
					pc++;
			}
		} else {
			edl_next[ic->wh_px[0].whole - 1].rgb[0] = 0;
			edl_next[ic->wh_px[0].whole - 1].rgb[1] = 0;
			edl_next[ic->wh_px[0].whole - 1].rgb[2] = 0;

			for (n = 0; n < plane_line_bytes * 8; n++) {
				c = (pc[2] << 16) | (pc[1] << 8) | pc[0];

				m = lws_display_palettize_col(ic, ic->palette,
						   ic->palette_depth, c, &edl_this[n]);
				pack_native_pixel(lo, n, (uint8_t)m);

				dist_err_floyd_steinberg_col(n, ic->wh_px[0].whole,
							     edl_this, edl_next);

				if (n < ic->wh_px[0].whole)
					pc += 3;
			}
		}
go:
		memset(&desc, 0, sizeof(desc));
		if (!box->y.whole)
			spi_issue_table(priv->lds, ssd1675b_wp1,
					LWS_ARRAY_SIZE(ssd1675b_wp1));

		desc.data = (uint8_t *)priv->line[box->y.whole & 1];
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;
		desc.count_write = plane_line_bytes;
		ea->spi->queue(ea->spi, &desc);

		return 0;

	default: /* starting update */
		break;
	}

	return 0;
}

int
lws_display_ssd1675b_spi_power(lws_display_state_t *lds, int state)
{
	const lws_display_ssd1675b_spi_t *ea = lds_to_disp(lds);

	if (!state) {
		spi_issue_table(lds, ssd1675b_off, LWS_ARRAY_SIZE(ssd1675b_off));

		if (ea->gpio)
			ea->gpio->set(ea->reset_gpio, 0);

		return 0;
	}

	return 0;
}
