/*
 * lws abstract display implementation for gc9a01a on spi
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * This is somewhat complicated by the platform SPI may a) need special
 * allocation for the display driver-private packed line buffers, and b) the
 * allocated memory may have 32-bit alignment and access requirements.
 *
 * The allocation is handled by having ops members in the SPI driver ops struct,
 * the alignment has to be observed in the display driver.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {

	GC9A01A_NOP						= 0x00,
	GC9A01A_SWRESET						= 0x01,
	GC9A01A_RDDID						= 0x04,
	GC9A01A_RDDST						= 0x09,

	GC9A01A_SLPIN						= 0x10,
	GC9A01A_SLPOUT						= 0x11,
	GC9A01A_PTLON						= 0x12,
	GC9A01A_NORON						= 0x13,

	GC9A01A_INVOFF						= 0x20,
	GC9A01A_INVON						= 0x21,
	GC9A01A_DISPOFF						= 0x28,
	GC9A01A_DISPON						= 0x29,
	GC9A01A_CASET						= 0x2a,
	GC9A01A_PASET						= 0x2b,
	GC9A01A_RAMWR						= 0x2c,
	GC9A01A_RAMRD						= 0x2e,

	GC9A01A_PTLAR						= 0x30,
	GC9A01A_VSCRDEF						= 0x33,
	GC9A01A_TEOFF						= 0x34,
	GC9A01A_TEON						= 0x35,
	GC9A01A_MADCTL						= 0x36,
	GC9A01A_VSCRSADD					= 0x37,
	GC9A01A_PIXFMT						= 0x3a,
};

typedef enum {
	LWSDISPST_IDLE,
	LWSDISPST_INIT1,
	LWSDISPST_INIT2,
	LWSDISPST_INIT3,
	LWSDISPST_INIT4,
	LWSDISPST_INIT5,

	LWSDISPRET_ASYNC			= 1
} lws_display_update_state_t;

typedef struct lws_display_gc9a01a_spi_state {
	struct lws_display_state		*lds;

	uint32_t				*line[2];
	lws_surface_error_t			*u[2];

	lws_sorted_usec_list_t			sul;
	int					state;
} lws_display_gc9a01a_spi_state_t;

#define lds_to_disp(_lds) (const lws_display_gc9a01a_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_gc9a01a_spi_state_t *)_lds->priv;

#define pack_native_pixel(_line, _x, _c) { \
		if (!(_x & 1)) \
			*_line = htons(_c); \
		else \
			{ *_line = (*_line) | (htons(_c) << 16); _line++; } }

static const uint8_t gc9a01a_240x240_init[] = {
	 2, 0xEF, 0xEB, 0x14,
	 1, 0xFE,
	 1, 0xEF,
	 2, 0xEB, 0x14,
	 2, 0x84, 0x40,
	 2, 0x85, 0xFF,
	 2, 0x86, 0xFF,
	 2, 0x87, 0xFF,
	 2, 0x88, 0x0A,
	 2, 0x89, 0x21,
	 2, 0x8A, 0x00,
	 2, 0x8B, 0x80,
	 2, 0x8C, 0x01,
	 2, 0x8D, 0x01,
	 2, 0x8E, 0xFF,
	 2, 0x8F, 0xFF,
	 3, 0xB6, 0x00, 0x20,
	 2, 0x3A, 0x05, /* 16-bit RGB565 */
	 5, 0x90, 0x08, 0x08, 0x08, 0x08,
	 2, 0xBD, 0x06,
	 2, 0xBC, 0x00,
	 4, 0xFF, 0x60, 0x01, 0x04,
	 2, 0xC3, 0x13,
	 2, 0xC4, 0x13,
	 2, 0xC9, 0x22,
	 2, 0xBE, 0x11,
	 3, 0xE1, 0x10, 0x0E,
	 4, 0xDF, 0x21, 0x0C, 0x02,
	 7, 0xF0, 0x45, 0x09, 0x08, 0x08, 0x26, 0x2A,
	 7, 0xF1, 0x43, 0x70, 0x72, 0x36, 0x37, 0x6F,
	 7, 0xF2, 0x45, 0x09, 0x08, 0x08, 0x26, 0x2A,
	 7, 0xF3, 0x43, 0x70, 0x72, 0x36, 0x37, 0x6F,
	 3, 0xED, 0x1B, 0x0B,
	 2, 0xAE, 0x77,
	 2, 0xCD, 0x63,
	10, 0x70, 0x07, 0x07, 0x04, 0x0E, 0x0F, 0x09, 0x07, 0x08, 0x03,
	 2, 0xE8, 0x34,
	13, 0x62, 0x18, 0x0D, 0x71, 0xED, 0x70, 0x70, 0x18, 0x0F, 0x71, 0xEF, 0x70, 0x70,
	13, 0x63, 0x18, 0x11, 0x71, 0xF1, 0x70, 0x70, 0x18, 0x13, 0x71, 0xF3, 0x70, 0x70,
	 8, 0x64, 0x28, 0x29, 0xF1, 0x01, 0xF1, 0x00, 0x07,
	11, 0x66, 0x3C, 0x00, 0xCD, 0x67, 0x45, 0x45, 0x10, 0x00, 0x00, 0x00,
	11, 0x67, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x01, 0x54, 0x10, 0x32, 0x98,
	 8, 0x74, 0x10, 0x85, 0x80, 0x00, 0x00, 0x4E, 0x00,
	 3, 0x98, 0x3E, 0x07,
	 1, 0x35,
	 1, 0x21,
	 0, GC9A01A_SLPOUT
}, gc9a01a_240x240_dispon[] = {
	0, GC9A01A_DISPON
}, gc9a01a_240x240_sleep_in[] = {
	0, GC9A01A_SLPIN
}, gc9a01a_240x240_sleep_out[] = {
	0, GC9A01A_SLPOUT
};

static void
async_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_gc9a01a_spi_state_t *priv = lws_container_of(sul,
			lws_display_gc9a01a_spi_state_t, sul);
	const lws_display_gc9a01a_t *disp = lds_to_disp(priv->lds);

	switch (priv->state) {
	case LWSDISPST_INIT1:
		if (disp->gpio)
			disp->gpio->set(disp->reset_gpio, 0);
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT2:
		if (disp->gpio)
			disp->gpio->set(disp->reset_gpio, 1);
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 120);
		break;

	case LWSDISPST_INIT3:
		lws_spi_table_issue(disp->spi, 0, gc9a01a_240x240_init,
				    LWS_ARRAY_SIZE(gc9a01a_240x240_init));
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 120);
		break;

	case LWSDISPST_INIT4:
		lws_spi_table_issue(disp->spi, 0, gc9a01a_240x240_dispon,
				    LWS_ARRAY_SIZE(gc9a01a_240x240_dispon));
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 20);
		break;

	case LWSDISPST_INIT5:
		if (disp->spi->in_flight)
			while (disp->spi->in_flight(disp->spi))
				;

		priv->state = LWSDISPST_IDLE;
		if (disp->cb)
			disp->cb(priv->lds, 1);
		break;

	default:
		break;
	}
}

int
lws_display_gc9a01a_spi_init(lws_display_state_t *lds)
{
	const lws_display_gc9a01a_t *disp = lds_to_disp(lds);
	lws_display_gc9a01a_spi_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;

	/* hardware nRESET */

	if (disp->gpio)
		disp->gpio->mode(disp->reset_gpio, LWSGGPIO_FL_WRITE |
					           LWSGGPIO_FL_PULLUP);

	priv->state = LWSDISPST_INIT1;
	lws_sul_schedule(lds->ctx, 0, &priv->sul, async_cb, 1);

	return 0;
}

/* backlight handled by PWM */

int
lws_display_gc9a01a_spi_brightness(lws_display_state_t *lds, uint8_t b)
{
	return 0;
}

int
lws_display_gc9a01a_spi_blit(lws_display_state_t *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids)
{
	lws_display_gc9a01a_spi_state_t *priv = lds_to_priv(lds);
	const lws_display_gc9a01a_t *disp = lds_to_disp(lds);
	const lws_surface_info_t *ic = &lds->disp->ic;
	lws_greyscale_error_t *gedl_this, *gedl_next;
	lws_colour_error_t *edl_this, *edl_next;
	int bytes_pl = ic->wh_px[0].whole * 2;
	static DMA_ATTR uint32_t buf[5];
	lws_display_list_coord_t h, y;
	lws_display_colour_t c;
	lws_spi_desc_t desc;
	const uint8_t *pc;
	uint32_t *lo;
	int n, m;

	if (!priv->line[0]) {
		if (disp->spi->alloc_dma)
			priv->line[0] = disp->spi->alloc_dma(disp->spi,
							     bytes_pl * 2);
		else
			priv->line[0] = lws_malloc(bytes_pl * 2, __func__);

		if (!priv->line[0]) {
			lwsl_err("%s: failed to alloc %u\n", __func__,
					(unsigned int)bytes_pl * 2);
			return 1;
		}

		priv->line[1] = (uint32_t *)((uint8_t *)priv->line[0] + bytes_pl);

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

	pc = src;
	lo = priv->line[box->y.whole & 1];

	memset(&desc, 0, sizeof(desc));
	desc.count_cmd = 1;
	desc.src = (uint8_t *)&buf[4];

	/*
	 * Blit a line at a time
	 */

	h = box->h.whole;
	y = box->y.whole;

	if (h > 1) {

		buf[4] = GC9A01A_CASET;
		desc.data = (uint8_t *)&buf[0];
		desc.flags = 0;
		buf[0] = (((box->x.whole + box->w.whole - 1) & 0xff) << 24) | (((box->x.whole + box->w.whole - 1) >> 8) << 16) | ((box->x.whole & 0xff) << 8) | (box->x.whole >> 8);
		desc.count_write = 4;
		disp->spi->queue(disp->spi, &desc);

		buf[4] = GC9A01A_PASET;
		buf[0] = (((box->y.whole + box->h.whole - 1) & 0xff) << 24) | (((box->y.whole + box->h.whole - 1) >> 8) << 16) | ((box->y.whole & 0xff) << 8) | (box->y.whole >> 8);
		disp->spi->queue(disp->spi, &desc);

		buf[4] = GC9A01A_RAMWR;
		/* priv->line is already allocated for DMA */
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED | LWS_SPI_FLAG_DATA_CONTINUE;
		desc.count_write = 0;
		disp->spi->queue(disp->spi, &desc);

		return 0;
	}

	if (h) {

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
				c = (pc[0] << 16) | (pc[0] << 8) | pc[0];

				m = lws_display_palettize_grey(ic, ic->palette,
					   ic->palette_depth, c, &gedl_this[n]);
				pack_native_pixel(lo, n, m);

				dist_err_floyd_steinberg_grey(n, ic->wh_px[0].whole,
							      gedl_this, gedl_next);
				pc++;
			}
		else
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				c = (pc[2] << 16) | (pc[1] << 8) | pc[0];

				m = lws_display_palettize_col(ic, ic->palette,
					    ic->palette_depth, c, &edl_this[n]);
				pack_native_pixel(lo, n, m);

				dist_err_floyd_steinberg_col(n, ic->wh_px[0].whole,
							     edl_this, edl_next);

				pc += 3;
			}

go:
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;
		if (y + 1 != ic->wh_px[1].whole)
			desc.flags |= LWS_SPI_FLAG_DATA_CONTINUE;

		desc.data = (uint8_t *)priv->line[box->y.whole & 1];
		desc.count_write = bytes_pl;
		desc.count_cmd = 0;

		if (disp->spi->queue(disp->spi, &desc)) {
			lwsl_err("%s: failed to queue\n", __func__);
		}

		src += bytes_pl;
		y++;

		return 0;
	}

	if (!box->h.whole) {

		if (disp->spi->in_flight)
			while (disp->spi->in_flight(disp->spi))
				;

		if (disp->spi->free_dma)
			disp->spi->free_dma(disp->spi, (void **)&priv->line[0]);
		else
			lws_free_set_NULL(priv->line[0]);

		lws_free_set_NULL(priv->u[0]);

		if (disp->cb)
			disp->cb(priv->lds, 2);
	}

	return 0;
}

int
lws_display_gc9a01a_spi_power(lws_display_state_t *lds, int state)
{
	const lws_display_gc9a01a_t *disp = lds_to_disp(lds);

	if (state)
		lws_spi_table_issue(disp->spi, 0, gc9a01a_240x240_sleep_out,
				    LWS_ARRAY_SIZE(gc9a01a_240x240_sleep_out));
	else
		lws_spi_table_issue(disp->spi, 0, gc9a01a_240x240_sleep_in,
				    LWS_ARRAY_SIZE(gc9a01a_240x240_sleep_in));

	/* we're not going to do anything useful for 5ms after this */

	return 0;
}
