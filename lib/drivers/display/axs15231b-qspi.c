/*
 * lws abstract display implementation for AXS15231B on quad SPI
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
 *
 * Over quad SPI, everything sent to the controller under one nCS starts with
 * an 8-bit opcode and a 24-bit address, both on one line.  The opcode says
 * what follows, and the address holds the DCS command in its middle byte:
 *
 *  - 0x02: a register write, its data on one line
 *  - 0x32: pixels, on all four lines, 0x2c (RAMWR) to start writing the
 *          window, 0x3c (RAMWRC) to carry on from where the last ended
 *
 * nCS goes up after each line of pixels, so each line after the first is sent
 * as a RAMWRC.  The pixels are RGB565, most significant byte first.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {
	AXS15231B_QSPI_OP_REG					= 0x02,
	AXS15231B_QSPI_OP_PIXELS				= 0x32,

	AXS15231B_SLPIN						= 0x10,
	AXS15231B_SLPOUT					= 0x11,
	AXS15231B_DISPOFF					= 0x28,
	AXS15231B_DISPON					= 0x29,
	AXS15231B_CASET						= 0x2a,
	AXS15231B_RASET						= 0x2b,
	AXS15231B_RAMWR						= 0x2c,
	AXS15231B_RAMWRC					= 0x3c,
};

/* the times reset is held and then given to come up, from LilyGo's driver */
#define AXS15231B_RESET_ASSERT_MS		130
#define AXS15231B_RESET_SETTLE_MS		300

/*
 * The controller is set up from its OTP defaults, so coming up is just
 * waking it, with how long to leave it after each step
 */

static const struct {
	uint8_t		cmd;
	uint8_t		ms;
} axs15231b_init[] = {
	{ AXS15231B_DISPOFF,	 20 },
	{ AXS15231B_SLPIN,	120 },
	{ AXS15231B_SLPOUT,	200 },
	{ AXS15231B_DISPON,	 20 },
};

typedef enum {
	LWSDISPST_IDLE,
	LWSDISPST_RESET_ASSERT,
	LWSDISPST_RESET_RELEASE,
	LWSDISPST_INIT,
} lws_display_update_state_t;

typedef struct lws_display_axs15231b_qspi_state {
	struct lws_display_state		*lds;

	uint32_t				*line[2];
	lws_surface_error_t			*u[2];

	lws_sorted_usec_list_t			sul;
	int					state;
	uint8_t					init_step;
	uint8_t					ramwr_sent; /* the window
						* opened by the last blit box
						* has had its first line */
} lws_display_axs15231b_qspi_state_t;

#define lds_to_disp(_lds) (const lws_display_axs15231b_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_axs15231b_qspi_state_t *)_lds->priv;

#define pack_native_pixel(_line, _x, _c) { \
		if (!(_x & 1)) \
			*_line = htons(_c); \
		else \
			{ *_line = (*_line) | ((uint32_t)htons(_c) << 16); _line++; } }

static int
axs15231b_queue(const lws_display_axs15231b_t *disp, uint8_t op, uint8_t cmd,
		const uint8_t *data, size_t len, uint8_t flags)
{
	const uint8_t hdr[4] = { op, 0, cmd, 0 };
	lws_spi_desc_t desc;

	memset(&desc, 0, sizeof(desc));
	desc.src		= hdr; /* taken into the transaction at queue */
	desc.count_cmd		= sizeof(hdr);
	desc.data		= data;
	desc.count_write	= (uint16_t)len;
	desc.channel		= disp->spi_index;
	desc.flags		= flags;

	return disp->spi->queue(disp->spi, &desc);
}

static int
axs15231b_reg(const lws_display_axs15231b_t *disp, uint8_t cmd,
	      const uint8_t *data, size_t len)
{
	/* the data is copied into a DMA bounce buffer as it's queued */

	return axs15231b_queue(disp, AXS15231B_QSPI_OP_REG, cmd, data, len, 0);
}

static int
axs15231b_window_edge(const lws_display_axs15231b_t *disp, uint8_t cmd,
		      int start, int end)
{
	uint8_t b[4] = {
		(uint8_t)(start >> 8), (uint8_t)start,
		(uint8_t)(end >> 8), (uint8_t)end
	};

	return axs15231b_reg(disp, cmd, b, sizeof(b));
}

static void
spi_drain(const lws_display_axs15231b_t *disp)
{
	if (disp->spi->in_flight)
		while (disp->spi->in_flight(disp->spi))
			;
}

static void
async_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_axs15231b_qspi_state_t *priv = lws_container_of(sul,
			lws_display_axs15231b_qspi_state_t, sul);
	const lws_display_axs15231b_t *disp = lds_to_disp(priv->lds);

	switch (priv->state) {
	case LWSDISPST_RESET_ASSERT:
		if (disp->gpio)
			disp->gpio->set(disp->reset_gpio, 0);
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 AXS15231B_RESET_ASSERT_MS * LWS_US_PER_MS);
		break;

	case LWSDISPST_RESET_RELEASE:
		if (disp->gpio)
			disp->gpio->set(disp->reset_gpio, 1);
		priv->state++;
		priv->init_step = 0;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 AXS15231B_RESET_SETTLE_MS * LWS_US_PER_MS);
		break;

	case LWSDISPST_INIT:
		if (priv->init_step < LWS_ARRAY_SIZE(axs15231b_init)) {
			axs15231b_reg(disp, axs15231b_init[priv->init_step].cmd,
				      NULL, 0);
			lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
					 async_cb, LWS_US_PER_MS *
				axs15231b_init[priv->init_step++].ms);
			break;
		}

		spi_drain(disp);

		priv->state = LWSDISPST_IDLE;
		if (disp->cb)
			disp->cb(priv->lds, 1);
		break;

	default:
		break;
	}
}

int
lws_display_axs15231b_qspi_init(lws_display_state_t *lds)
{
	const lws_display_axs15231b_t *disp = lds_to_disp(lds);
	lws_display_axs15231b_qspi_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;

	/* hardware nRESET, starting from released */

	if (disp->gpio) {
		disp->gpio->mode(disp->reset_gpio, LWSGGPIO_FL_WRITE |
						   LWSGGPIO_FL_PULLUP);
		disp->gpio->set(disp->reset_gpio, 1);
	}

	priv->state = LWSDISPST_RESET_ASSERT;
	lws_sul_schedule(lds->ctx, 0, &priv->sul, async_cb, 1);

	return 0;
}

int
lws_display_axs15231b_qspi_blit(lws_display_state_t *lds, const uint8_t *src,
				lws_box_t *box, lws_dll2_owner_t *ids)
{
	lws_display_axs15231b_qspi_state_t *priv = lds_to_priv(lds);
	const lws_display_axs15231b_t *disp = lds_to_disp(lds);
	const lws_surface_info_t *ic = &lds->disp->ic;
	lws_greyscale_error_t *gedl_this, *gedl_next;
	lws_colour_error_t *edl_this, *edl_next;
	int bytes_pl = ic->wh_px[0].whole * 2;
	/*
	 * pack_native_pixel() does a whole 32-bit store for each even pixel,
	 * so for an odd width, the line buffers are strided to a whole u32
	 */
	int stride_pl = (bytes_pl + 3) & ~3;
	const uint8_t *pc = src;
	lws_display_colour_t c;
	uint32_t *lo;
	int n, m;

	if (!priv->line[0]) {
		if (disp->spi->alloc_dma)
			priv->line[0] = disp->spi->alloc_dma(disp->spi,
							(size_t)stride_pl * 2);
		else
			priv->line[0] = lws_malloc((size_t)stride_pl * 2,
						   __func__);

		if (!priv->line[0]) {
			lwsl_err("%s: failed to alloc %u\n", __func__,
				 (unsigned int)stride_pl * 2);
			return 1;
		}

		priv->line[1] = (uint32_t *)((uint8_t *)priv->line[0] +
								stride_pl);

		if (lws_display_alloc_diffusion(ic, priv->u)) {
			if (disp->spi->free_dma)
				disp->spi->free_dma(disp->spi,
						    (void **)&priv->line[0]);
			else
				lws_free_set_NULL(priv->line[0]);

			lwsl_err("%s: OOM\n", __func__);
			return 1;
		}
	}

	if (box->h.whole > 1) {
		/* open the window the lines that follow will fill */

		axs15231b_window_edge(disp, AXS15231B_CASET, box->x.whole,
				      box->x.whole + box->w.whole - 1);
		axs15231b_window_edge(disp, AXS15231B_RASET, box->y.whole,
				      box->y.whole + box->h.whole - 1);
		priv->ramwr_sent = 0;

		return 0;
	}

	if (box->h.whole) {
		lo = priv->line[box->y.whole & 1];

		/*
		 * The line before last went out of the buffer we are about
		 * to fill: wait until only the last line is still in flight
		 */
		if (disp->spi->in_flight)
			while (disp->spi->in_flight(disp->spi) > 1)
				;

		edl_this = (lws_colour_error_t *)priv->u[(box->y.whole & 1) ^ 1];
		edl_next = (lws_colour_error_t *)priv->u[box->y.whole & 1];
		gedl_this = (lws_greyscale_error_t *)edl_this;
		gedl_next = (lws_greyscale_error_t *)edl_next;

		if (!pc) {
			for (n = 0; n < ic->wh_px[0].whole; n++)
				pack_native_pixel(lo, n, 0xffff);
			goto go;
		}

		if (ic->greyscale)
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				c = (lws_display_colour_t)((pc[0] << 16) |
						(pc[0] << 8) | pc[0]);

				m = lws_display_palettize_grey(ic, ic->palette,
					   ic->palette_depth, c, &gedl_this[n]);
				pack_native_pixel(lo, n, (uint16_t)m);

				dist_err_floyd_steinberg_grey(n,
						ic->wh_px[0].whole,
						gedl_this, gedl_next);
				pc++;
			}
		else if (ic->type == LWSSURF_565)
			/* there's no palette to choose from, or error to diffuse */
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				/* htons() may be a macro using it twice */
				uint16_t px = lws_display_565(
					(lws_display_colour_t)((pc[2] << 16) |
							(pc[1] << 8) | pc[0]));

				pack_native_pixel(lo, n, px);
				pc += 3;
			}
		else
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				c = (lws_display_colour_t)((pc[2] << 16) |
						(pc[1] << 8) | pc[0]);

				m = lws_display_palettize_col(ic, ic->palette,
					    ic->palette_depth, c, &edl_this[n]);
				pack_native_pixel(lo, n, (uint16_t)m);

				dist_err_floyd_steinberg_col(n,
						ic->wh_px[0].whole,
						edl_this, edl_next);

				pc += 3;
			}

go:
		if (axs15231b_queue(disp, AXS15231B_QSPI_OP_PIXELS,
				    priv->ramwr_sent ? AXS15231B_RAMWRC :
						       AXS15231B_RAMWR,
				    (const uint8_t *)priv->line[box->y.whole & 1],
				    (size_t)bytes_pl,
				    LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED |
				    LWS_SPI_FLAG_DATA_QUAD))
			lwsl_err("%s: failed to queue\n", __func__);

		priv->ramwr_sent = 1;

		return 0;
	}

	/* a zero-height blit ends the update */

	spi_drain(disp);

	if (disp->spi->free_dma)
		disp->spi->free_dma(disp->spi, (void **)&priv->line[0]);
	else
		lws_free_set_NULL(priv->line[0]);

	lws_free_set_NULL(priv->u[0]);

	if (disp->cb)
		disp->cb(priv->lds, 2);

	return 0;
}

int
lws_display_axs15231b_qspi_power(lws_display_state_t *lds, int state)
{
	const lws_display_axs15231b_t *disp = lds_to_disp(lds);

	return axs15231b_reg(disp, state ? AXS15231B_SLPOUT : AXS15231B_SLPIN,
			     NULL, 0);
}
