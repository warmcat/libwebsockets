/*
 * lws abstract display implementation for Epd 7-colour ACEP SPD1656 on spi
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
 *   https://www.waveshare.com/w/upload/b/bf/SPD1656_1.1.pdf
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {
	SPD1656_CMD_PSR			= 0x00,
	SPD1656_CMD_PWR			= 0x01,
	SPD1656_CMD_POF			= 0x02,
	SPD1656_CMD_PFS			= 0x03,
	SPD1656_CMD_PON			= 0x04,
	SPD1656_CMD_BTST		= 0x06,
	SPD1656_CMD_DSLP		= 0x07,
	SPD1656_CMD_DTM1		= 0x10,
	SPD1656_CMD_DSP			= 0x11,
	SPD1656_CMD_DRF			= 0x12,
	SPD1656_CMD_PLL			= 0x30,
	SPD1656_CMD_TSE			= 0x41,
	SPD1656_CMD_CDI			= 0x50,
	SPD1656_CMD_TCON		= 0x60,
	SPD1656_CMD_TRES		= 0x61,
	SPD1656_CMD_PWS			= 0xe3,
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

static const uint8_t spd1656_init1[] = {
	2,	SPD1656_CMD_PSR,		0xef, 0x08,
	4,	SPD1656_CMD_PWR,		0x37, 0x00, 0x23, 0x23,
	1,	SPD1656_CMD_PFS,		0x00,
	3,	SPD1656_CMD_BTST,		0xc7, 0xc7, 0x1d,
	1,	SPD1656_CMD_PLL,		0x39,
	1,	SPD1656_CMD_TSE,		0x00,
	1,	SPD1656_CMD_CDI,		0x37,
	1,	SPD1656_CMD_TCON,		0x22,
}, spd1656_init2[] = {
	4, 	SPD1656_CMD_TRES,		0, 0, 0, 0, /* filled in */
	1,	SPD1656_CMD_PWS,		0xaa,
}, spd1656_init3[] = {
	1,	SPD1656_CMD_CDI,		0x37,
}, spd1656_off[] = {
	1,	SPD1656_CMD_DSLP,		0xa5,
}, spd1656_write1[] = {
	4, 	SPD1656_CMD_TRES,		0, 0, 0, 0, /* filled in */
}, spd1656_write1a[] = {
	0,	SPD1656_CMD_DTM1
	/* ... frame data ... */
}, spd1656_write2[] = {
	0,	SPD1656_CMD_PON,
}, spd1656_write3[] = {
	0,	SPD1656_CMD_DRF,
}, spd1656_write4[] = {
	0,	SPD1656_CMD_POF,
};

typedef struct lws_display_spd1656_spi_state {
	struct lws_display_state		*lds;
	uint32_t				*line[2];
	lws_surface_error_t			*u[2];
	lws_sorted_usec_list_t			sul;
	int					state;
	int					budget;
} lws_display_spd1656_spi_state_t;

#define lds_to_disp(_lds) (const lws_display_spd1656_spi_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_spd1656_spi_state_t *)_lds->priv;

#define pack_native_pixel(_line, _x, _c) \
		{ *_line = (*_line & ~(0xf << (((_x ^ 1) & 7) * 4))) | \
				(_c << (((_x ^ 1) & 7) * 4)); \
		  if ((_x & 7) == 7) \
			  _line++; }

static void
async_cb(lws_sorted_usec_list_t *sul);

#define BUSY_TIMEOUT_BUDGET 60

static int
check_busy(lws_display_spd1656_spi_state_t *priv, int level)
{
	const lws_display_spd1656_spi_t *ea = lds_to_disp(priv->lds);

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

static void
async_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_spd1656_spi_state_t *priv = lws_container_of(sul,
			lws_display_spd1656_spi_state_t, sul);
	const lws_display_spd1656_spi_t *ea = lds_to_disp(priv->lds);
	uint8_t buf[32];
	//int budget = 5;

	switch (priv->state) {

	case LWSDISPST_INIT1:
		/* take reset low for a short time */
		ea->gpio->set(ea->reset_gpio, 0);
		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 2);
		break;

	case LWSDISPST_INIT2:
		/* park reset high again and then wait a bit */
		ea->gpio->set(ea->reset_gpio, 1);
		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT3:
		if (check_busy(priv, 1))
			return;

		lws_spi_table_issue(ea->spi, 0, spd1656_init1,
				    LWS_ARRAY_SIZE(spd1656_init1));

		if (ea->spi->in_flight)
			while (ea->spi->in_flight(ea->spi))
				;

		memcpy(buf, spd1656_init2, LWS_ARRAY_SIZE(spd1656_init2));

		/* width and height filled in from display struct */

		buf[2] = (ea->disp.ic.wh_px[0].whole >> 8) & 0xff;
		buf[3] = ea->disp.ic.wh_px[0].whole & 0xff;
		buf[4] = (ea->disp.ic.wh_px[1].whole >> 8) & 0xff;
		buf[5] = ea->disp.ic.wh_px[1].whole & 0xff;

		lws_spi_table_issue(ea->spi, 0, buf,
				    LWS_ARRAY_SIZE(spd1656_init2));

		if (ea->spi->in_flight)
			while (ea->spi->in_flight(ea->spi))
				;

		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT4:
		priv->state = LWSDISPST_IDLE;
		lws_spi_table_issue(ea->spi, 0, spd1656_init3,
				    LWS_ARRAY_SIZE(spd1656_init3));

		if (ea->spi->in_flight)
			while (ea->spi->in_flight(ea->spi))
				;

		if (ea->cb)
			ea->cb(priv->lds, 1);
		break;


	case LWSDISPST_WRITE1:

		/* rendered and sent the whole frame of pixel data */

		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;

		lws_spi_table_issue(ea->spi, 0, spd1656_write2,
				   LWS_ARRAY_SIZE(spd1656_write2));

		/* fallthru */

	case LWSDISPST_WRITE2:
		if (check_busy(priv, 1))
			return;

		priv->state++;
		priv->budget = 20000 / 50;

		lws_spi_table_issue(ea->spi, 0, spd1656_write3,
				    LWS_ARRAY_SIZE(spd1656_write3));

		/*
		 * this is going to start the refresh, it may wait in check_busy
		 * for serveral seconds while it does the sequence on the panel
		 */

		/* fallthru */

	case LWSDISPST_WRITE3:
		if (check_busy(priv, 1))
			return;

		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;
		lws_spi_table_issue(ea->spi, 0, spd1656_write4,
				    LWS_ARRAY_SIZE(spd1656_write4));

		/* fallthru */

	case LWSDISPST_WRITE4:
		if (check_busy(priv, 1))
			return;

		priv->state++;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 200);
		break;

	case LWSDISPST_WRITE5:

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
lws_display_spd1656_spi_init(struct lws_display_state *lds)
{
	const lws_display_spd1656_spi_t *ea = lds_to_disp(lds);
	lws_display_spd1656_spi_state_t *priv;

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
lws_display_spd1656_spi_brightness(const struct lws_display *disp, uint8_t b)
{
	return 0;
}

int
lws_display_spd1656_spi_blit(struct lws_display_state *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids)
{
	lws_display_spd1656_spi_state_t *priv = lds_to_priv(lds);
	const lws_display_spd1656_spi_t *ea = lds_to_disp(lds);
	lws_greyscale_error_t *gedl_this, *gedl_next;
	const lws_surface_info_t *ic = &ea->disp.ic;
	lws_colour_error_t *edl_this, *edl_next;
	size_t bytes_pl = ic->wh_px[0].whole / 2;
	const uint8_t *pc = src;
	lws_display_colour_t c;
	lws_spi_desc_t desc;
	uint8_t temp[10];
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
			priv->line[0] = ea->spi->alloc_dma(ea->spi, bytes_pl * 2);
		else
			priv->line[0] = lws_zalloc(bytes_pl * 2, __func__);

		if (!priv->line[0]) {
			lwsl_err("%s: OOM\n", __func__);
			priv->state = LWSDISPST_IDLE;
			return 1;
		}

		priv->line[1] = (uint32_t *)(((uint8_t *)priv->line[0]) + bytes_pl);

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

	// lwsl_notice("%s: switch %d\n", __func__, box->h.whole);

	switch (box->h.whole) {
	case 0: /* update is finished */
		priv->state = LWSDISPST_WRITE1;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb, 1);
		if (ea->spi->free_dma)
			ea->spi->free_dma(ea->spi,
					    (void **)&priv->line[0]);
		else
			lws_free_set_NULL(priv->line[0]);
		lws_free_set_NULL(priv->u[0]);
		return 0;

	case 1: /* single line = issue line */
		edl_this = (lws_colour_error_t *)priv->u[(box->y.whole & 1) ^ 1];
		edl_next = (lws_colour_error_t *)priv->u[box->y.whole & 1];
		gedl_this = (lws_greyscale_error_t *)edl_this;
		gedl_next = (lws_greyscale_error_t *)edl_next;

		memset(&desc, 0, sizeof(desc));

		if (!pc) {
			for (n = 0; n < ic->wh_px[0].whole; n++)
				pack_native_pixel(lo, n, 1 /* white */);
			goto go;
		}

		if (ic->greyscale)
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				c = (pc[0] << 16) | (pc[0] << 8) | pc[0];

				m = lws_display_palettize_grey(ic, ic->palette,
						   ic->palette_depth, c, &gedl_this[n]);
				pack_native_pixel(lo, n, (uint8_t)m);

				dist_err_floyd_steinberg_grey(n, ic->wh_px[0].whole,
							      gedl_this, gedl_next);
				pc++;
			}
		else
			for (n = 0; n < ic->wh_px[0].whole; n++) {
				c = (pc[2] << 16) | (pc[1] << 8) | pc[0];

				m = lws_display_palettize_col(ic, ic->palette,
						   ic->palette_depth, c, &edl_this[n]);
				pack_native_pixel(lo, n, (uint8_t)m);

				dist_err_floyd_steinberg_col(n, ic->wh_px[0].whole,
							     edl_this, edl_next);

				pc += 3;
			}

go:
		/* priv->line is already allocated for DMA */
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;
		desc.flags |= box->y.whole + 1 != ic->wh_px[1].whole ?
				LWS_SPI_FLAG_DATA_CONTINUE : 0;
		desc.data = (uint8_t *)priv->line[box->y.whole & 1];
		desc.count_write = ic->wh_px[0].whole / 2;
		ea->spi->queue(ea->spi, &desc);

		return 0;

	default:
		/* Start whole page update... no partial updates on this controller,
		 * box must be whole display */

		lwsl_notice("%s: start update\n", __func__);
		memcpy(temp, spd1656_write1, LWS_ARRAY_SIZE(spd1656_write1));

		/* width and height filled in from display struct */

		temp[2] = (lds->disp->ic.wh_px[0].whole >> 8) & 0xff;
		temp[3] = lds->disp->ic.wh_px[0].whole & 0xff;
		temp[4] = (lds->disp->ic.wh_px[1].whole >> 8) & 0xff;
		temp[5] = lds->disp->ic.wh_px[1].whole & 0xff;

		lws_spi_table_issue(ea->spi, 0, temp,
				    LWS_ARRAY_SIZE(spd1656_write1));

		lws_spi_table_issue(ea->spi, LWS_SPI_FLAG_DATA_CONTINUE,
				spd1656_write1a, LWS_ARRAY_SIZE(spd1656_write1a));

		return 0;
	}
}

int
lws_display_spd1656_spi_power(lws_display_state_t *lds, int state)
{
	const lws_display_spd1656_spi_t *ea = lds_to_disp(lds);

	if (!state) {
		lws_spi_table_issue(ea->spi, 0, spd1656_off, LWS_ARRAY_SIZE(spd1656_off));

		if (ea->gpio)
			ea->gpio->set(ea->reset_gpio, 0);

		return 0;
	}

	return 0;
}
