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
 * The AXS15231B is a TFT controller driving, eg, the 180 x 640 panel on the
 * LilyGo T-Display S3 Long, spoken to over quad SPI.  It can't rotate what it
 * is sent, so the surface is the panel's own portrait orientation.
 */

#if !defined(__LWS_DISPLAY_AXS15231B_QSPI_H__)
#define __LWS_DISPLAY_AXS15231B_QSPI_H__

typedef struct lws_display_axs15231b {

	lws_display_t		disp; /* use lws_display_axs15231b_ops to set */
	const lws_spi_ops_t	*spi;
	/**< spi ops for a quad bus, eg, lws_esp32_spi_ops with .quad set */

	lws_display_completion_t	cb;
	const lws_gpio_ops_t	*gpio;	      /* NULL or gpio ops */
	_lws_plat_gpio_t	reset_gpio;   /* if gpio ops, nReset gpio # */

	uint8_t			spi_index; /* cs index starting from 0 */

} lws_display_axs15231b_t;

LWS_VISIBLE LWS_EXTERN int
lws_display_axs15231b_qspi_init(lws_display_state_t *lds);
LWS_VISIBLE LWS_EXTERN int
lws_display_axs15231b_qspi_blit(lws_display_state_t *lds, const uint8_t *src,
				lws_box_t *box, lws_dll2_owner_t *ids);
LWS_VISIBLE LWS_EXTERN int
lws_display_axs15231b_qspi_power(lws_display_state_t *lds, int state);

#define lws_display_axs15231b_ops \
	.init = lws_display_axs15231b_qspi_init, \
	.blit = lws_display_axs15231b_qspi_blit, \
	.power = lws_display_axs15231b_qspi_power
#endif
