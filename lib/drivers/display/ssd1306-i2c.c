/*
 * lws abstract display implementation for ssd1306 on i2c
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
 *
 * The OLED display is composed of 128 x 8 bytes, where the bytes contain 8
 * columnar pixels in a single row.  We can handle it by buffering 8 lines and
 * then issuing it as 128 linear bytes.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {
	SSD1306_SETLOWCOLUMN		= 0x00,
	SSD1306_SETHIGHCOLUMN		= 0x10,

	SSD1306_MEMORYMODE		= 0x20,
	SSD1306_COLUMNADDR		= 0x21,
	SSD1306_PAGEADDR		= 0x22,
	SSD1306_DEACTIVATE_SCROLL	= 0x2e,

	SSD1306_SETSTARTLINE		= 0x40,

	SSD1306_SETCONTRAST		= 0x81,
	SSD1306_CHARGEPUMP		= 0x8d,

	SSD1306_SEGREMAP		= 0xa0,
	SSD1306_SETSEGMENTREMAP		= 0xa1,
	SSD1306_DISPLAYALLON_RESUME	= 0xa4,
	SSD1306_DISPLAYALLON		= 0xa5,
	SSD1306_NORMALDISPLAY		= 0xa6,
	SSD1306_INVERTDISPLAY		= 0xa7,
	SSD1306_SETMULTIPLEX		= 0xa8,
	SSD1306_DISPLAYOFF	 	= 0xae,
	SSD1306_DISPLAYON		= 0xaf,

	SSD1306_COMSCANINC		= 0xc0,
	SSD1306_COMSCANDEC		= 0xc8,

	SSD1306_SETDISPLAYOFFSET	= 0xd3,
	SSD1306_SETDISPLAYCLOCKDIV	= 0xd5,
	SSD1306_SETPRECHARGE		= 0xd9,
	SSD1306_SETCOMPINS		= 0xda,
	SSD1306_SETVCOMDESELECT		= 0xdb,

	SSD1306_NOP			= 0xe3,
};

static uint8_t ssd1306_128x64_init[] = {
	SSD1306_DISPLAYOFF,
	SSD1306_SETDISPLAYCLOCKDIV,		0xf0,
	SSD1306_SETMULTIPLEX,			64 - 1,
	SSD1306_SETDISPLAYOFFSET,		0,
	SSD1306_CHARGEPUMP,			0x14,
	SSD1306_MEMORYMODE,			0,
	SSD1306_SEGREMAP | (0 << 0),
	SSD1306_COMSCANDEC,
	SSD1306_SETCOMPINS,			(1 << 4) | 0x02,
	SSD1306_SETCONTRAST,			0x7f,
	SSD1306_SETPRECHARGE,			(0xf << 4) | (1 << 0),
	SSD1306_SETVCOMDESELECT,		(4 << 4),
	SSD1306_DEACTIVATE_SCROLL,
	SSD1306_DISPLAYALLON_RESUME,
	SSD1306_NORMALDISPLAY,
	//SSD1306_DISPLAYON
};

typedef struct lws_display_ssd1306_i2c_state_t {
	struct lws_display_state		*lds;

	uint8_t					*line8;
	lws_surface_error_t			*u[2];

	lws_sorted_usec_list_t			sul;
} lws_display_ssd1306_i2c_state_t;

#define lds_to_disp(_lds) (const lws_display_ssd1306_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_ssd1306_i2c_state_t *)_lds->priv;

int
lws_display_ssd1306_i2c_init(lws_display_state_t *lds)
{
	const lws_display_ssd1306_t *si = lds_to_disp(lds);
	lws_display_ssd1306_i2c_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;

	si->i2c->init(si->i2c);

	if (si->gpio) {
		si->gpio->mode(si->reset_gpio, LWSGGPIO_FL_WRITE |
					       LWSGGPIO_FL_PULLUP);
		si->gpio->set(si->reset_gpio, 0);
		lws_msleep(1);
		si->gpio->set(si->reset_gpio, 1);
		lws_msleep(1);
	}

	if (lws_i2c_command_list(si->i2c, si->i2c7_address,
				 ssd1306_128x64_init,
				 LWS_ARRAY_SIZE(ssd1306_128x64_init))) {
		lwsl_err("%s: fail\n", __func__);
		return 1;
	}

	if (si->cb)
		si->cb(lds, 1);

	return 0;
}

int
lws_display_ssd1306_i2c_contrast(lws_display_state_t *lds, uint8_t b)
{
	const lws_display_ssd1306_t *si = lds_to_disp(lds);
	uint8_t ba[2];

	ba[0] = SSD1306_SETCONTRAST;
	ba[1] = b;

	return lws_i2c_command_list(si->i2c, si->i2c7_address,
				    ba, LWS_ARRAY_SIZE(ba));
}

int
lws_display_ssd1306_i2c_blit(lws_display_state_t *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids)
{
	lws_display_ssd1306_i2c_state_t *priv = lds_to_priv(lds);
	const lws_display_ssd1306_t *si = lds_to_disp(lds);
	const lws_surface_info_t *ic = &lds->disp->ic;
	lws_greyscale_error_t *gedl_this, *gedl_next;
	int bytes_pl = (ic->wh_px[0].whole + 7) / 8;
	lws_display_list_coord_t y = box->y.whole;
	const uint8_t *pc = src;
	lws_display_colour_t c;
	uint8_t ba[6], *lo;
	int n, m;

	/*
	 * The display is arranged in 128x8 bands, with one byte containing
	 * the 8 vertical pixels of the band.
	 */

	if (!priv->line8) {
		priv->line8 = lws_malloc(bytes_pl * 8, __func__);
		if (!priv->line8)
			return 1;

		if (lws_display_alloc_diffusion(ic, priv->u)) {
			lws_free_set_NULL(priv->line8);

			lwsl_err("%s: OOM\n", __func__);
			return 1;
		}
	}

	lo = priv->line8;

	switch (box->h.whole) {
	default: /* start */
		break;

	case 0: /* end */
		lws_free_set_NULL(priv->line8);
		lws_free_set_NULL(priv->u[0]);

		lwsl_err("%s: End of raster\n", __func__);

		ba[0] = SSD1306_NORMALDISPLAY;
		ba[1] = SSD1306_DISPLAYON;
		if (lws_i2c_command_list(si->i2c, si->i2c7_address, ba, 2)) {
			lwsl_err("%s: fail\n", __func__);
			return 1;
		}

		if (si->cb)
			si->cb(priv->lds, 2);
		break;

	case 1: /* per line */

		gedl_this = (lws_greyscale_error_t *)priv->u[(box->y.whole & 1) ^ 1];
		gedl_next = (lws_greyscale_error_t *)priv->u[box->y.whole & 1];

		for (n = ic->wh_px[0].whole - 1; n >= 0; n--) {
			c = (pc[0] << 16) | (pc[0] << 8) | pc[0];

			m = lws_display_palettize_grey(ic, ic->palette,
					   ic->palette_depth, c, &gedl_this[n]);
			if (m)
				lo[n] = (lo[n] | (1 << (y & 7)));
			else
				lo[n] = (lo[n] & ~(1 << (y & 7)));

			dist_err_floyd_steinberg_grey(n, ic->wh_px[0].whole,
						      gedl_this, gedl_next);
			pc++;
		}

		if ((y & 7) != 7)
			break;

		ba[0] = SSD1306_COLUMNADDR;
		ba[1] = box->x.whole;
		ba[2] = box->x.whole + box->w.whole - 1;

		if (lws_i2c_command_list(si->i2c, si->i2c7_address,
					 ba, 3)) {
			lwsl_err("%s: fail\n", __func__);
			return 1;
		}

		ba[0] = SSD1306_PAGEADDR;
		ba[1] = y / 8;
		ba[2] = ba[1] + ((ic->wh_px[0].whole) / 8) - 1;

		if (lws_i2c_command_list(si->i2c, si->i2c7_address,
					 ba, 3)) {
			lwsl_err("%s: fail\n", __func__);
			return 1;
		}


		lws_bb_i2c_start(si->i2c);
		lws_bb_i2c_write(si->i2c, si->i2c7_address << 1);
		lws_bb_i2c_write(si->i2c, SSD1306_SETSTARTLINE | y);

		for (m = 0; m < box->w.whole; m++)
			lws_bb_i2c_write(si->i2c, priv->line8[m]);

		lws_bb_i2c_stop(si->i2c);
		break;
	}

	return 0;
}

int
lws_display_ssd1306_i2c_power(lws_display_state_t *lds, int state)
{
#if 0
	const lws_display_ssd1306_t *si = (const lws_display_ssd1306_t *)lds->disp;

	if (!state)
		return lws_i2c_command(si->i2c, si->i2c7_address,
				       SSD1306_DISPLAYOFF | !!state);

	return lws_display_ssd1306_i2c_init(lds);
#endif

	return 0;
}
