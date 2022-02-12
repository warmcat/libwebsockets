/*
 * lws abstract display implementation for ili9341 on spi
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

	ILI9341_NOP						= 0x00,
	ILI9341_SWRESET						= 0x01,
	ILI9341_RDDID						= 0x04,
	ILI9341_RDDST						= 0x09,

	ILI9341_SLPIN						= 0x10,
	ILI9341_SLPOUT						= 0x11,
	ILI9341_PTLON						= 0x12,
	ILI9341_NORON						= 0x13,

	ILI9341_RDMODE						= 0x0a,
	ILI9341_RDMADCTL					= 0x0b,
	ILI9341_RDPIXFMT					= 0x0c,
	ILI9341_RDIMGFMT					= 0x0d,
	ILI9341_RDSELFDIAG					= 0x0f,

	ILI9341_INVOFF						= 0x20,
	ILI9341_INVON						= 0x21,
	ILI9341_GAMMASET					= 0x26,
	ILI9341_DISPOFF						= 0x28,
	ILI9341_DISPON						= 0x29,
	ILI9341_CASET						= 0x2a,
	ILI9341_PASET						= 0x2b,
	ILI9341_RAMWR						= 0x2c,
	ILI9341_RAMRD						= 0x2e,

	ILI9341_PTLAR						= 0x30,
	ILI9341_VSCRDEF						= 0x33,
	ILI9341_MADCTL						= 0x36,
	ILI9341_VSCRSADD					= 0x37,
	ILI9341_PIXFMT						= 0x3a,

	ILI9341_FRMCTR1						= 0xb1,
	ILI9341_FRMCTR2						= 0xb2,
	ILI9341_FRMCTR3						= 0xb3,
	ILI9341_INVCTR						= 0xb4,
	ILI9341_DFUNCTR						= 0xb6,

	ILI9341_PWCTR1						= 0xc0,
	ILI9341_PWCTR2						= 0xc1,
	ILI9341_PWCTR3						= 0xc2,
	ILI9341_PWCTR4						= 0xc3,
	ILI9341_PWCTR5						= 0xc4,
	ILI9341_VMCTR1						= 0xc5,
	ILI9341_VMCTR2						= 0xc7,
	ILI9341_FACPUMPRAT					= 0xcb,
	ILI9341_FACPWCTRB					= 0xcf,

	ILI9341_RDID1						= 0xda,
	ILI9341_RDID2						= 0xdb,
	ILI9341_RDID3						= 0xdc,
	ILI9341_RDID4						= 0xdd,

	ILI9341_GMCTRP1						= 0xe0,
	ILI9341_GMCTRN1						= 0xe1,
	ILI9341_FACPWCTRA					= 0xe8,
	ILI9341_FACPWCTR1					= 0xea,
	ILI9341_FACDRTIMCTRA					= 0xed,

	ILI9341_FACSETGAMMACRV					= 0xf2,
	ILI9341_FACDRTIMCTR					= 0xf7,
};

typedef struct lws_display_ili9341_spi_state {
	struct lws_display_state		*lds;

	uint32_t				*line[2];
	lws_surface_error_t			*u[2];

	lws_sorted_usec_list_t			sul;
} lws_display_ili9341_spi_state_t;

#define lds_to_disp(_lds) (const lws_display_ili9341_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_ili9341_spi_state_t *)_lds->priv;

#define pack_native_pixel(_line, _x, _c) { \
		if (!(_x & 1)) \
			*_line = htons(_c); \
		else \
			{ *_line = (*_line) | (htons(_c) << 16); _line++; } }

static const uint8_t ili9341_320x240_init[] = {
	/*
	 * This provides 70Hz 320x240 at RGB565, we assume im[3:0] is 1110
	 * which is 4-bit SPI
	 */

	 3, ILI9341_FACPWCTRB,	    0x00, 0x83, 0x30,
	 4, ILI9341_FACDRTIMCTRA,   0x64, 0x03, 0x12, 0x81,
	 3, ILI9341_FACPWCTRA,	    0x85, 0x01, 0x79,
	 5, ILI9341_FACPUMPRAT,	    0x39, 0x2c, 0x00, 0x34, 0x02,
	 1, ILI9341_FACDRTIMCTR,    0x20,
	 2, ILI9341_FACPWCTR1,	    0x00, 0x00,

	 1, ILI9341_PWCTR1,	    0x26,
	 1, ILI9341_PWCTR2,	    0x11,
	 2, ILI9341_VMCTR1,	    0x35, 0x3e,
	 1, ILI9341_VMCTR2,	    0xbe,
	 1, ILI9341_MADCTL,	    0x28,
	 1, ILI9341_VSCRSADD,	    0x00,
	 1, ILI9341_PIXFMT,	    0x55,
	 2, ILI9341_FRMCTR1,	    0x00, 0x1b,
	 1, ILI9341_FACSETGAMMACRV, 0x00,
	 1, ILI9341_GAMMASET,	    0x01,
	15, ILI9341_GMCTRP1,	    0x0f, 0x31, 0x2b, 0x0c, 0x0e, 0x08, 0x4e,
				    0xf1, 0x37, 0x07, 0x10, 0x03, 0x0e, 0x09,
				    0x00,
	15, ILI9341_GMCTRN1,	    0x00, 0x0e, 0x14, 0x03, 0x11, 0x07, 0x31,
				    0xc1, 0x48, 0x08, 0x0f, 0x0c, 0x31, 0x36,
				    0x0f,
	4, ILI9341_DFUNCTR,	    0x0a, 0x82, 0x27, 0x00,
	0, ILI9341_SLPOUT
}, ili9341_320x240_dispon[] = {
	0, ILI9341_DISPON
}, ili9341_320x240_sleep_in[] = {
	0, ILI9341_SLPIN
}, ili9341_320x240_sleep_out[] = {
	0, ILI9341_SLPOUT
};

int
lws_display_ili9341_spi_init(lws_display_state_t *lds)
{
	const lws_display_ili9341_t *disp = lds_to_disp(lds);
	lws_display_ili9341_spi_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;

	/* hardware nRESET */

	if (disp->gpio) {
		disp->gpio->mode(disp->reset_gpio, LWSGGPIO_FL_WRITE |
					           LWSGGPIO_FL_PULLUP);
		disp->gpio->set(disp->reset_gpio, 0);

		lws_msleep(1);
		disp->gpio->set(disp->reset_gpio, 1);
		lws_msleep(1);
	}

	lws_spi_table_issue(disp->spi, 0, ili9341_320x240_init,
			    LWS_ARRAY_SIZE(ili9341_320x240_init));

	lws_msleep(5);

	lws_spi_table_issue(disp->spi, 0, ili9341_320x240_dispon,
			    LWS_ARRAY_SIZE(ili9341_320x240_dispon));

	if (disp->spi->in_flight)
		while (disp->spi->in_flight(disp->spi))
			;

	if (disp->cb)
		disp->cb(priv->lds, 1);

	return 0;
}

/* backlight handled by PWM */

int
lws_display_ili9341_spi_brightness(lws_display_state_t *lds, uint8_t b)
{
	return 0;
}

int
lws_display_ili9341_spi_blit(lws_display_state_t *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids)
{
	lws_display_ili9341_spi_state_t *priv = lds_to_priv(lds);
	const lws_display_ili9341_t *disp = lds_to_disp(lds);
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

		buf[4] = ILI9341_CASET;
		desc.data = (uint8_t *)&buf[0];
		desc.flags = 0;
		buf[0] = ((box->w.whole & 0xff) << 24) | ((box->w.whole >> 8) << 16) | (box->x.whole) | (box->x.whole);
		desc.count_write = 4;
		disp->spi->queue(disp->spi, &desc);

		buf[4] = ILI9341_PASET;
//		buf[0] = (((y + 1) & 0xff) << 24) | (((y + 1) >> 8) << 16) | ((y & 0xff) << 8) | (y >> 8);
		buf[0] = (((box->h.whole) & 0xff) << 24) | (((box->h.whole) >> 8) << 16) | ((y & 0xff) << 8) | (y >> 8);
		disp->spi->queue(disp->spi, &desc);

		buf[4] = ILI9341_RAMWR;
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
lws_display_ili9341_spi_power(lws_display_state_t *lds, int state)
{
	const lws_display_ili9341_t *disp = lds_to_disp(lds);

	if (state)
		lws_spi_table_issue(disp->spi, 0, ili9341_320x240_sleep_out,
				    LWS_ARRAY_SIZE(ili9341_320x240_sleep_out));
	else
		lws_spi_table_issue(disp->spi, 0, ili9341_320x240_sleep_in,
				    LWS_ARRAY_SIZE(ili9341_320x240_sleep_in));

	/* we're not going to do anything useful for 5ms after this */

	return 0;
}
