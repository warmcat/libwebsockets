/*
 * lws abstract display
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
 */

#include <private-lib-core.h>

static void
sul_autodim_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_state_t *lds = lws_container_of(sul, lws_display_state_t,
						    sul_autodim);
	int next_ms = -1;

	/* we fire both to dim and to blank... if already in dim state, blank */

	switch (lds->state) {
	case LWSDISPS_BECOMING_ACTIVE:
		lws_display_state_set_brightness(lds, lds->disp->bl_active);
		lds->state = LWSDISPS_ACTIVE;
		next_ms = lds->autodim_ms;
		break;

	case LWSDISPS_ACTIVE:
		/* active -> autodimmed */
		lds->state = LWSDISPS_AUTODIMMED;
		next_ms = lds->off_ms;
		lws_display_state_set_brightness(lds, lds->disp->bl_dim);
		break;

	case LWSDISPS_AUTODIMMED:
		/* dimmed -> OFF */
		lws_display_state_set_brightness(lds, &lws_pwmseq_static_off);
		lds->state = LWSDISPS_GOING_OFF;
		next_ms = 600;
		break;

	case LWSDISPS_GOING_OFF:
		/* off dimming completed, actual display OFF */
		lws_display_state_off(lds);
		return;

	default:
		return;
	}

	if (next_ms >= 0)
		lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 next_ms * LWS_US_PER_MS);
}

void
lws_display_state_init(lws_display_state_t *lds, struct lws_context *ctx,
		       int dim_ms, int off_ms, struct lws_led_state *bl_lcs,
		       const lws_display_t *disp)
{
	memset(lds, 0, sizeof(*lds));

	lds->disp = disp;
	lds->ctx = ctx;
	lds->autodim_ms = dim_ms;
	lds->off_ms = off_ms;
	lds->bl_lcs = bl_lcs;
	lds->state = LWSDISPS_OFF;

	if (lds->bl_lcs)
		lws_led_transition(lds->bl_lcs, "backlight", &lws_pwmseq_static_off,
						     &lws_pwmseq_static_on);

	disp->init(lds);
}

void
lws_display_state_set_brightness(lws_display_state_t *lds,
				 const lws_led_sequence_def_t *pwmseq)
{
	if (lds->bl_lcs)
		lws_led_transition(lds->bl_lcs, "backlight", pwmseq,
			   lds->disp->bl_transition);
}

void
lws_display_state_active(lws_display_state_t *lds)
{
	int waiting_ms;

	if (lds->state == LWSDISPS_OFF) {
		/* power us up */
		lds->disp->power(lds, 1);
		lds->state = LWSDISPS_BECOMING_ACTIVE;
		waiting_ms = lds->disp->latency_wake_ms;
	} else {

		if (lds->state != LWSDISPS_ACTIVE && lds->bl_lcs)
			lws_display_state_set_brightness(lds,
						lds->disp->bl_active);

		lds->state = LWSDISPS_ACTIVE;
		waiting_ms = lds->autodim_ms;
	}

	/* reset the autodim timer */
	if (waiting_ms >= 0)
		lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 waiting_ms * LWS_US_PER_MS);
}

void
lws_display_state_off(lws_display_state_t *lds)
{
	/* if no control over backlight, don't bother power down display
	 * since it would continue to emit, just show all-white or whatever */
	if (lds->bl_lcs)
		lds->disp->power(lds, 0);
	lws_sul_cancel(&lds->sul_autodim);
	lds->state = LWSDISPS_OFF;
}

int
lws_display_alloc_diffusion(const lws_surface_info_t *ic, lws_surface_error_t **se)
{
	size_t size, gsize = ic->greyscale ? sizeof(lws_greyscale_error_t) :
					     sizeof(lws_colour_error_t), by;

	if (*se)
		return 0;

	/* defer creation of dlo's 2px-high dlo-width, 2 bytespp or 6 bytespp
	 * error diffusion buffer */

	by = ((ic->wh_px[0].whole + 15) / 8) * 8;
	size = gsize * 2u * (unsigned int)by;

	lwsl_info("%s: alloc'd %u for width %d\n", __func__, (unsigned int)size,
			(int)ic->wh_px[0].whole);

	se[0] = lws_zalloc(size, __func__);
	if (!se[0])
		return 1;

	se[1] = (lws_surface_error_t *)(((uint8_t *)se[0]) + (size / 2));

	return 0;
}

static void
dist_err_grey(const lws_greyscale_error_t *in, lws_greyscale_error_t *out,
							int sixteenths)
{
	out->rgb[0] = (int16_t)(out->rgb[0] +
				(int16_t)((sixteenths * in->rgb[0]) / 16));
}

static void
dist_err_col(const lws_colour_error_t *in, lws_colour_error_t *out,
							int sixteenths)
{
	out->rgb[0] = (int16_t)(out->rgb[0] +
			(int16_t)((sixteenths * in->rgb[0]) / 16));
	out->rgb[1] = (int16_t)(out->rgb[1] +
			(int16_t)((sixteenths * in->rgb[1]) / 16));
	out->rgb[2] = (int16_t)(out->rgb[2] +
			(int16_t)((sixteenths * in->rgb[2]) / 16));
}

void
dist_err_floyd_steinberg_grey(int n, int width, lws_greyscale_error_t *gedl_this,
			      lws_greyscale_error_t *gedl_next)
{
	if (n < width - 1) {
	        dist_err_grey(&gedl_this[n], &gedl_this[n + 1], 7);
	        dist_err_grey(&gedl_this[n], &gedl_next[n + 1], 1);
	}
	if (n)
		dist_err_grey(&gedl_this[n], &gedl_next[n - 1], 3);

	dist_err_grey(&gedl_this[n], &gedl_next[n], 5);

	gedl_this[n].rgb[0] = 0;
}

void
dist_err_floyd_steinberg_col(int n, int width, lws_colour_error_t *edl_this,
			     lws_colour_error_t *edl_next)
{
	if (n < width - 1) {
	        dist_err_col(&edl_this[n], &edl_this[n + 1], 7);
	        dist_err_col(&edl_this[n], &edl_next[n + 1], 1);
	}
	if (n)
	        dist_err_col(&edl_this[n], &edl_next[n - 1], 3);

	dist_err_col(&edl_this[n], &edl_next[n], 5);

	edl_this[n].rgb[0] = 0;
	edl_this[n].rgb[1] = 0;
	edl_this[n].rgb[2] = 0;
}

/*
 * #include <stdio.h>
 * #include <math.h>
 *
 * void
 * main(void)
 * {
 *       int n;
 *
 *       for (n = 0; n < 256; n++) {
 *               double d = (double)n / 255.0;
 *
 *               printf("0x%02X, ", (unsigned int)(pow(d,  (2.2)) * 255));
 *       }
 *
 * }
 */

static const uint8_t gamma2_2[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02,
	0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04,
	0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06,
	0x06, 0x06, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08,
	0x09, 0x09, 0x09, 0x0A, 0x0A, 0x0A, 0x0B, 0x0B,
	0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0F,
	0x0F, 0x10, 0x10, 0x11, 0x11, 0x12, 0x12, 0x13,
	0x13, 0x14, 0x15, 0x15, 0x16, 0x16, 0x17, 0x17,
	0x18, 0x19, 0x19, 0x1A, 0x1B, 0x1B, 0x1C, 0x1D,
	0x1D, 0x1E, 0x1F, 0x1F, 0x20, 0x21, 0x21, 0x22,
	0x23, 0x24, 0x24, 0x25, 0x26, 0x27, 0x28, 0x28,
	0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2D, 0x2E, 0x2F,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
	0x3F, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4A, 0x4B, 0x4D, 0x4E, 0x4F, 0x50,
	0x51, 0x52, 0x54, 0x55, 0x56, 0x57, 0x58, 0x5A,
	0x5B, 0x5C, 0x5D, 0x5F, 0x60, 0x61, 0x63, 0x64,
	0x65, 0x67, 0x68, 0x69, 0x6B, 0x6C, 0x6D, 0x6F,
	0x70, 0x72, 0x73, 0x75, 0x76, 0x77, 0x79, 0x7A,
	0x7C, 0x7D, 0x7F, 0x80, 0x82, 0x83, 0x85, 0x87,
	0x88, 0x8A, 0x8B, 0x8D, 0x8E, 0x90, 0x92, 0x93,
	0x95, 0x97, 0x98, 0x9A, 0x9C, 0x9D, 0x9F, 0xA1,
	0xA2, 0xA4, 0xA6, 0xA8, 0xA9, 0xAB, 0xAD, 0xAF,
	0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBB, 0xBD,
	0xBF, 0xC1, 0xC3, 0xC5, 0xC7, 0xC9, 0xCB, 0xCD,
	0xCF, 0xD1, 0xD3, 0xD5, 0xD7, 0xD9, 0xDB, 0xDD,
	0xDF, 0xE1, 0xE3, 0xE5, 0xE7, 0xE9, 0xEB, 0xED,
	0xEF, 0xF1, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFF
};

lws_display_palette_idx_t
lws_display_palettize_grey(const lws_surface_info_t *ic,
			   const lws_display_colour_t *palette, size_t pdepth,
			   lws_display_colour_t c, lws_greyscale_error_t *ectx)
{
	int best = 0x7fffffff, best_idx = 0;
	lws_colour_error_t da, d, ea;
	int sum, y;
	size_t n;

	/* put the most desirable colour (adjusted for existing error) in d */

	d.rgb[0] = (int)gamma2_2[LWSDC_R(c)];
	da.rgb[0] = d.rgb[0] + ectx->rgb[0];
	if (da.rgb[0] < 0)
		da.rgb[0] = 0;
	if (da.rgb[0] > 255)
		da.rgb[0] = 255;

	if (ic->type == LWSSURF_565) {
		y = d.rgb[0] >> 3;
		ectx->rgb[0] = (int16_t)((int)da.rgb[0] - y);

		return (lws_display_palette_idx_t)y;
	}

	/*
	 * Choose a palette colour considering the error diffusion adjustments
	 */

	for (n = 0; n < pdepth; n++) {

		y = LWSDC_ALPHA(palette[n]);

		ea.rgb[0] = (int16_t)((int)da.rgb[0] - (int)(LWSDC_R(palette[n])));

		sum = ea.rgb[0] < 0 ? -ea.rgb[0] : ea.rgb[0];

		if (sum < best) {
			best_idx = (int)n;
			best = sum;
		}
	}

	/* report the error between the unadjusted colour and what we chose */

	ectx->rgb[0] = (int16_t)((int)da.rgb[0] - (int)(LWSDC_R(palette[best_idx])));

	return (lws_display_palette_idx_t)best_idx;
}
/*
 * For error disffusion, it's better to use YUV and prioritize reducing error
 * in Y (lumience)
 */
#if 0
static void
rgb_to_yuv(uint8_t *yuv, const uint8_t *rgb)
{
	yuv[0] =  16 + ((257 * rgb[0]) / 1000) + ((504 * rgb[1]) / 1000) +
						  ((98 * rgb[2]) / 1000);
	yuv[1] = 128 - ((148 * rgb[0]) / 1000) - ((291 * rgb[1]) / 1000) +
						 ((439 * rgb[2]) / 1000);
	yuv[2] = 128 + ((439 * rgb[0]) / 1000) - ((368 * rgb[1]) / 1000) -
						  ((71 * rgb[2]) / 1000);
}

static void
yuv_to_rgb(uint8_t *rgb, const uint8_t *_yuv)
{
	unsigned int yuv[3];

	yuv[0] = _yuv[0] - 16;
	yuv[1] = _yuv[1] - 128;
	yuv[2] = _yuv[2] - 128;

	rgb[0] = ((1164 * yuv[0]) / 1000) + ((1596 * yuv[2]) / 1000);
	rgb[1] = ((1164 * yuv[0]) / 1090) -  ((392 * yuv[1]) / 1000) -
					     ((813 * yuv[2]) / 1000);
	rgb[2] = ((1164 * yuv[0]) / 1000) + ((2017 * yuv[1]) / 1000);
}
#endif

lws_display_palette_idx_t
lws_display_palettize_col(const lws_surface_info_t *ic,
			  const lws_display_colour_t *palette, size_t pdepth,
			  lws_display_colour_t c, lws_colour_error_t *ectx)
{
	int best = 0x7fffffff, best_idx = 0, yd;
	lws_colour_error_t da, d;
	uint8_t ya[3];
	size_t n;
	int y, ch;

	/* put the most desirable colour (adjusted for existing error) in d */

	d.rgb[0] = (int)gamma2_2[LWSDC_R(c)];
	da.rgb[0] = d.rgb[0] + ectx->rgb[0];
	if (da.rgb[0] < 0)
		da.rgb[0] = 0;
	if (da.rgb[0] > 255)
		da.rgb[0] = 255;
	yd = da.rgb[0];
	d.rgb[1] = (int)gamma2_2[LWSDC_G(c)];
	d.rgb[2] = (int)gamma2_2[LWSDC_B(c)];
	da.rgb[1] = d.rgb[1] + ectx->rgb[1];
	if (da.rgb[1] < 0)
		da.rgb[1] = 0;
	if (da.rgb[1] > 255)
		da.rgb[1] = 255;
	da.rgb[2] = d.rgb[2] + ectx->rgb[2];
	if (da.rgb[2] < 0)
		da.rgb[2] = 0;
	if (da.rgb[2] > 255)
		da.rgb[2] = 255;

	yd = RGB_TO_Y(da.rgb[0], da.rgb[1], da.rgb[2]);

	if (ic->type == LWSSURF_565) {
		ya[0] = d.rgb[0] >> 3;
		ectx->rgb[0] = (int16_t)((int)da.rgb[0] - (ya[0] << 3));
		ya[1] = d.rgb[1] >> 2;
		ectx->rgb[1] = (int16_t)((int)da.rgb[1] - (ya[1] << 2));
		ya[2] = d.rgb[2] >> 3;
		ectx->rgb[2] = (int16_t)((int)da.rgb[2] - (ya[2] << 3));

		return (lws_display_palette_idx_t)((ya[0] << 11) | (ya[1] << 5) | (ya[2]));
	}

	/*
	 * Choose a palette colour considering the error diffusion adjustments,
	 * separately choose the best Y match and the best RGB match
	 */

	for (n = 0; n < pdepth; n++) {
		lws_colour_error_t ea;
		int sum;

		y = LWSDC_ALPHA(palette[n]);

		ea.rgb[0] = (int16_t)((int)da.rgb[0] - (int)(LWSDC_R(palette[n])));
		ea.rgb[1] = (int16_t)((int)da.rgb[1] - (int)(LWSDC_G(palette[n])));
		ea.rgb[2] = (int16_t)((int)da.rgb[2] - (int)(LWSDC_B(palette[n])));

		/* Best considering luma match */

		sum = (yd > y ? (yd - y) : (y - yd));

		/*
		 * Best considering RGB matching
		 */

		sum += ((ea.rgb[0] < 0 ? -ea.rgb[0] : ea.rgb[0]) +
		       (ea.rgb[1] < 0 ? -ea.rgb[1] : ea.rgb[1]) +
		       (ea.rgb[2] < 0 ? -ea.rgb[2] : ea.rgb[2]));

		if (sum < best) {
			best_idx = (int)n;
			best = sum;
		}
	}

	ch = best_idx;

	/* report the error between the adjusted colour and what we chose */

	ectx->rgb[0] = (int16_t)((int)da.rgb[0] - (int)(LWSDC_R(palette[ch])));
	ectx->rgb[1] = (int16_t)((int)da.rgb[1] - (int)(LWSDC_G(palette[ch])));
	ectx->rgb[2] = (int16_t)((int)da.rgb[2] - (int)(LWSDC_B(palette[ch])));

	return (lws_display_palette_idx_t)ch;
}

