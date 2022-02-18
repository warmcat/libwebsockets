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
 */

#if !defined(__LWS_DISPLAY_SSD1306_I2C_H__)
#define __LWS_DISPLAY_SSD1306_I2C_H__

/*
 * D/C# pin on SSD1306 sets the I2C device ads
 * from these two options (7-bit address)
 */

#define SSD1306_I2C7_ADS1		0x3c
#define SSD1306_I2C7_ADS2		0x3d

typedef struct lws_display_ssd1306 {

	lws_display_t		disp; /* use lws_display_ssd1306_ops to set ops */
	const lws_i2c_ops_t	*i2c;	      /* i2c ops */

	lws_display_completion_t	cb;
	const lws_gpio_ops_t	*gpio;	      /* NULL or gpio ops */
	_lws_plat_gpio_t	reset_gpio;   /* if gpio ops, nReset gpio # */

	uint8_t			i2c7_address; /* one of SSD1306_I2C7_ADS... */

} lws_display_ssd1306_t;

int
lws_display_ssd1306_i2c_init(lws_display_state_t *lds);
int
lws_display_ssd1306_i2c_contrast(lws_display_state_t *lds, uint8_t b);
int
lws_display_ssd1306_i2c_blit(lws_display_state_t *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids);
int
lws_display_ssd1306_i2c_power(lws_display_state_t *lds, int state);

#define lws_display_ssd1306_ops \
	.init = lws_display_ssd1306_i2c_init, \
	.contrast = lws_display_ssd1306_i2c_contrast, \
	.blit = lws_display_ssd1306_i2c_blit, \
	.power = lws_display_ssd1306_i2c_power
#endif
