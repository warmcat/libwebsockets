/*
 * lws abstract display implementation for Epd 4-gray / black-red UC8176 on spi
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
 *   https://www.waveshare.com/w/upload/8/88/UC8176.pdf
 *
 * This chip takes a planar approach with two distinct framebuffers for b0 and
 * b1 of the grey levels.  That's OK in itself, but the problem is for whole-
 * frame updates, loading the planes must be done in full plane-frames
 * sequentially, ie, you must issue the whole frame of b0 and then the whole
 * frame of b1s, you can't interleave them.  So we must create a private,
 * ephemeral side buffer for b1 data and send it afterwards (15KB heap during
 * display update for 400 x 300)
 *
 * The driver detects at runtime if it should be in BE, BW + "red", or Gray mode
 * from the details in the lws_display information.  It uses direct DMA capable
 * line buffer allocations and direct DMA if available.
 *
 * There are similar chips UC8151 and EK79686 with different RESOLUTION
 * commands (smaller range), this driver attempts to cover them all by detection
 * at runtime from the details in the lws_display information.
 */

#include <private-lib-core.h>
#include <dlo/private-lib-drivers-display-dlo.h>

enum {
	UC8176_CMD_PANEL_SETTING                               = 0x00,
	UC8176_CMD_POWER_SETTING                               = 0x01,
	UC8176_CMD_POWER_OFF                                   = 0x02,
	UC8176_CMD_POWER_OFF_SEQUENCE_SETTING                  = 0x03,
	UC8176_CMD_POWER_ON                                    = 0x04,
	UC8176_CMD_POWER_ON_MEASURE                            = 0x05,
	UC8176_CMD_BOOSTER_SOFT_START                          = 0x06,
	UC8176_CMD_DEEP_SLEEP                                  = 0x07,
	UC8176_CMD_DATA_START_TRANSMISSION_1                   = 0x10,
	UC8176_CMD_DATA_STOP                                   = 0x11,
	UC8176_CMD_DISPLAY_REFRESH                             = 0x12,
	UC8176_CMD_DATA_START_TRANSMISSION_2                   = 0x13,
	UC8176_CMD_LUT_FOR_VCOM                                = 0x20,
	UC8176_CMD_LUT_WHITE_TO_WHITE                          = 0x21,
	UC8176_CMD_LUT_BLACK_TO_WHITE                          = 0x22,
	UC8176_CMD_LUT_WHITE_TO_BLACK                          = 0x23,
	UC8176_CMD_LUT_BLACK_TO_BLACK                          = 0x24,
	UC8176_CMD_LUT25				       = 0x25,
	UC8176_CMD_PLL_CONTROL                                 = 0x30,
	UC8176_CMD_TEMPERATURE_SENSOR_COMMAND                  = 0x40,
	UC8176_CMD_TEMPERATURE_SENSOR_SELECTION                = 0x41,
	UC8176_CMD_TEMPERATURE_SENSOR_WRITE                    = 0x42,
	UC8176_CMD_TEMPERATURE_SENSOR_READ                     = 0x43,
	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING              = 0x50,
	UC8176_CMD_LOW_POWER_DETECTION                         = 0x51,
	UC8176_CMD_TCON_SETTING                                = 0x60,
	UC8176_CMD_RESOLUTION_SETTING                          = 0x61,
	UC8176_CMD_GSST_SETTING                                = 0x65,
	UC8176_CMD_GET_STATUS                                  = 0x71,
	UC8176_CMD_AUTO_MEASUREMENT_VCOM                       = 0x80,
	UC8176_CMD_READ_VCOM_VALUE                             = 0x81,
	UC8176_CMD_VCOM_DC_SETTING                             = 0x82,
	UC8176_CMD_PARTIAL_WINDOW                              = 0x90,
	UC8176_CMD_PARTIAL_IN                                  = 0x91,
	UC8176_CMD_PARTIAL_OUT                                 = 0x92,
	UC8176_CMD_PROGRAM_MODE                                = 0xA0,
	UC8176_CMD_ACTIVE_PROGRAMMING                          = 0xA1,
	UC8176_CMD_READ_OTP                                    = 0xA2,
	UC8176_CMD_POWER_SAVING                                = 0xE3,
};

typedef enum {
	LWSDISPST_IDLE,
	LWSDISPST_INIT1,
	LWSDISPST_INIT2,
	LWSDISPST_INIT3,
	LWSDISPST_INIT4,
	LWSDISPST_INIT5,

	LWSDISPST_WRITE1,
	LWSDISPST_WRITE2,
	LWSDISPST_WRITE3,
	LWSDISPST_WRITE4,
	LWSDISPST_WRITE5,
} lws_display_update_state_t;

//static
const uint8_t uc8176_init1_gray[] = {
	5,	UC8176_CMD_POWER_SETTING,	   0x03, 0x00, 0x2b, 0x2b, 0x13,
	3,	UC8176_CMD_BOOSTER_SOFT_START,	   0x17, 0x17, 0x17,
	0,	UC8176_CMD_POWER_ON,
}, uc8176_init1_bw[] = {
	4,	UC8176_CMD_POWER_SETTING,	   0x03, 0x00, 0x2b, 0x2b,
	3,	UC8176_CMD_BOOSTER_SOFT_START,	   0x17, 0x17, 0x17,
	0,	UC8176_CMD_POWER_ON,
}, ek79686_init1_bw_104[] = {
	5,	UC8176_CMD_POWER_SETTING,	   0x03, 0x00, 0x2b, 0x2b, 0x03,
	3,	UC8176_CMD_BOOSTER_SOFT_START,	   0x17, 0x17, 0x17,
	0,	UC8176_CMD_POWER_ON,
}, uc8176_init1_red[] = {
	4,	UC8176_CMD_POWER_SETTING,	   0x03, 0x00, 0x2b, 0x2b,
	3,	UC8176_CMD_BOOSTER_SOFT_START,	   0x17, 0x17, 0x17,
	0,	UC8176_CMD_POWER_ON,
}, ek79686_init1_red_104[] = {
	5,	UC8176_CMD_POWER_SETTING,	   0x03, 0x00, 0x2b, 0x2b, 0x03,
	3,	UC8176_CMD_BOOSTER_SOFT_START,	   0x17, 0x17, 0x17,
	0,	UC8176_CMD_POWER_ON,
},

uc8176_init2_gray[] = {
	1, 	UC8176_CMD_PANEL_SETTING,	   0x3f,
	1,	UC8176_CMD_PLL_CONTROL,		   0x3c,
	4,	UC8176_CMD_RESOLUTION_SETTING,	   0x01, 0x90, 0x01, 0x2c,
	1,	UC8176_CMD_VCOM_DC_SETTING,	   0x28,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
}, uc8176_init2_red[] = {
	1, 	UC8176_CMD_PANEL_SETTING,	   0x0f,
	1,	UC8176_CMD_PLL_CONTROL,		   0x3c,
	4,	UC8176_CMD_RESOLUTION_SETTING,	   0x01, 0x90, 0x01, 0x2c,
	1,	UC8176_CMD_VCOM_DC_SETTING,	   0x28,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
}, uc8176_init2_bw[] = {
	2, 	UC8176_CMD_PANEL_SETTING,	   0xbf, 0x0d,
	1,	UC8176_CMD_PLL_CONTROL,		   0x3c,
	4,	UC8176_CMD_RESOLUTION_SETTING,	   0x01, 0x90, 0x01, 0x2c,
	1,	UC8176_CMD_VCOM_DC_SETTING,	   0x28,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
	44,	UC8176_CMD_LUT_FOR_VCOM,
	    0x00, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x00, 0x17, 0x17, 0x00, 0x00, 0x02,
	    0x00, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0x00, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_WHITE,
	    0x40, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x17, 0x17, 0x00, 0x00, 0x02,
	    0x40, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0xA0, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_WHITE,
	    0x40, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x17, 0x17, 0x00, 0x00, 0x02,
	    0x40, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0xA0, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_BLACK,
	    0x80, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x17, 0x17, 0x00, 0x00, 0x02,
	    0x80, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0x50, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_BLACK,
	    0x80, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x17, 0x17, 0x00, 0x00, 0x02,
	    0x80, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0x50, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}, ek79686_init2_bw_104[] = {
	1, 	UC8176_CMD_PANEL_SETTING,	   0x1f,
	1,	UC8176_CMD_PLL_CONTROL,		   0x3a,
	3,	UC8176_CMD_RESOLUTION_SETTING,	   104, 0, 212,
	1,	UC8176_CMD_VCOM_DC_SETTING,	   0x28,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0xb7,
	44,	UC8176_CMD_LUT_FOR_VCOM,
	    0x00, 0x08, 0x00, 0x00, 0x00, 0x02,
	    0x60, 0x28, 0x28, 0x00, 0x00, 0x01,
	    0x00, 0x14, 0x00, 0x00, 0x00, 0x01,
	    0x00, 0x12, 0x12, 0x00, 0x00, 0x01,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_WHITE,
	    0x40, 0x08, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
	    0x40, 0x14, 0x00, 0x00, 0x00, 0x01,
	    0xA0, 0x12, 0x12, 0x00, 0x00, 0x01,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_WHITE,
	    0x40, 0x17, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x0F, 0x0F, 0x00, 0x00, 0x03,
	    0x40, 0x0A, 0x01, 0x00, 0x00, 0x01,
	    0xA0, 0x0E, 0x0E, 0x00, 0x00, 0x02,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_BLACK,
	    0x80, 0x08, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
	    0x80, 0x14, 0x00, 0x00, 0x00, 0x01,
	    0x50, 0x12, 0x12, 0x00, 0x00, 0x01,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_BLACK,
	    0x80, 0x08, 0x00, 0x00, 0x00, 0x02,
	    0x90, 0x28, 0x28, 0x00, 0x00, 0x01,
	    0x80, 0x14, 0x00, 0x00, 0x00, 0x01,
	    0x50, 0x12, 0x12, 0x00, 0x00, 0x01,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}, ek79686_init2_red_104[] = {
	1, 	UC8176_CMD_PANEL_SETTING,	   0x0f,
	1,	UC8176_CMD_PLL_CONTROL,		   0x3c,
	3,	UC8176_CMD_RESOLUTION_SETTING,	   104, 0, 212,
	1,	UC8176_CMD_VCOM_DC_SETTING,	   0x12,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
}, uc8176_off[] = {
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING, 0xf7,
	//0,	UC8176_CMD_POWER_OFF,
}, uc8176_wp1_gray[] = {
	0,	UC8176_CMD_PARTIAL_OUT,
	1, 	UC8176_CMD_PANEL_SETTING,	   0x3f,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
	0,	UC8176_CMD_DATA_START_TRANSMISSION_1,
}, uc8176_wp1_red[] = {
	0,	UC8176_CMD_PARTIAL_OUT,
	1, 	UC8176_CMD_PANEL_SETTING,	   0x0f,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
	0,	UC8176_CMD_DATA_START_TRANSMISSION_1,
}, uc8176_wp1_bw[] = {
	0,	UC8176_CMD_PARTIAL_OUT,
	2, 	UC8176_CMD_PANEL_SETTING,	   0xbf, 0x0d,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
	0,	UC8176_CMD_DATA_START_TRANSMISSION_1,
}, uc8176_wp2[] = {
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING,	0x97,
	0,	UC8176_CMD_DATA_START_TRANSMISSION_2,
}, uc8176_complete_gray[] = {
	42,	UC8176_CMD_LUT_FOR_VCOM,
			0x00, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x60, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x00, 0x14, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x13, 0x0A, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_WHITE,
			0x40, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x90, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x10, 0x14, 0x0A, 0x00, 0x00, 0x01,
			0xA0, 0x13, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_WHITE,
			0x40, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x90, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x00, 0x14, 0x0A, 0x00, 0x00, 0x01,
			0x99, 0x0C, 0x01, 0x03, 0x04, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_WHITE_TO_BLACK,
			0x40, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x90, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x00, 0x14, 0x0A, 0x00, 0x00, 0x01,
			0x99, 0x0B, 0x04, 0x04, 0x01, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT_BLACK_TO_BLACK,
			0x80, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x90, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x20, 0x14, 0x0A, 0x00, 0x00, 0x01,
			0x50, 0x13, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	42,	UC8176_CMD_LUT25,
			0x40, 0x0A, 0x00, 0x00, 0x00, 0x01,
			0x90, 0x14, 0x14, 0x00, 0x00, 0x01,
			0x10, 0x14, 0x0A, 0x00, 0x00, 0x01,
			0xA0, 0x13, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0,	UC8176_CMD_DISPLAY_REFRESH,
}, uc8176_complete_red[] = {
	0,	UC8176_CMD_DISPLAY_REFRESH,
}, uc8176_complete_bw[] = {
	0,	UC8176_CMD_DISPLAY_REFRESH,
}, uc8176_w_dstop[] = {
	1,	UC8176_CMD_DATA_STOP, 0,
}, uc8176_partial_out_off[] = {
	0,	UC8176_CMD_PARTIAL_OUT,
	1,	UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING, 0xf7,
};

typedef struct lws_display_uc8176_spi_state {
	struct lws_display_state		*lds;

	uint32_t				*planebuf;

	uint32_t				*line[2];
	lws_surface_error_t			*u[2];
	uint32_t				*partbuf;

	uint8_t					pcmd[32];

	lws_sorted_usec_list_t			sul;

	lws_box_t				upd;

	size_t					pb_len;
	size_t					pb_pos;
	size_t					pb_sent;
	size_t					partbuf_len;
	size_t					partbuf_pos;

	int					state;
	int					budget;
	int					nplanes;

	char					ek79686;
	char					partial;
} lws_display_uc8176_spi_state_t;

#define lds_to_disp(_lds) (const lws_display_uc8176_spi_t *)_lds->disp;
#define lds_to_priv(_lds) (lws_display_uc8176_spi_state_t *)_lds->priv;

/*
 * The lws greyscale line composition buffer is width x Y bytes linearly.
 *
 * For UC8176, this is processed into a private buffer layout in priv->line that
 * is sent over SPI to the chip, the format is both packed and planar: the first
 * half is packed width x 1bpp "B&W" bits, and the second half is packed width x
 * "red" bits.
 *
 * UC8176 requires the whole frane of the B&W plane is sent first then the whole
 * frane of the RED plane, which means we have to stash the red plane in heap.
 */

/* MSB plane is in first half of priv linebuf */

#define pack_native_pixel(np, _line, _roby, _x, _c) \
	{ if (np == 2) { \
		if ((_c) & 1) \
		_line[(_roby >> 2)] |= 1 << ((_x & 31) ^ 7); else \
		_line[(_roby >> 2)] &= ~(1 << ((_x & 31) ^ 7)); \
	} \
	if ((np == 2 && ((_c) & 2)) || (np == 1 && ((_c) & 1))) \
		*_line           |= 1 << ((_x & 31) ^ 7); else \
		*_line           &= ~(1 << ((_x & 31) ^ 7)); \
	if (((_x) & 31) == 31) (_line)++; }

static void
async_cb(lws_sorted_usec_list_t *sul);

#define BUSY_TIMEOUT_BUDGET (20000 / 5)

static int
check_busy(lws_display_uc8176_spi_state_t *priv, int level)
{
	const lws_display_uc8176_spi_t *ea = lds_to_disp(priv->lds);

	if (ea->gpio->read(ea->busy_gpio) == level)
		return 0; /* good */

	if (!--priv->budget) {
		lwsl_err("%s: timeout waiting idle %d\n", __func__, level);
		return -1; /* timeout */
	}
	lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
			 LWS_US_PER_MS * 5);

	return 1; /* keeping on trying */
}

static void
async_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_uc8176_spi_state_t *priv = lws_container_of(sul,
			lws_display_uc8176_spi_state_t, sul);
	const lws_display_uc8176_spi_t *ea = lds_to_disp(priv->lds);
	const lws_surface_info_t *ic = &ea->disp.ic;
	int plane_line_bytes = ((ic->wh_px[LWS_LHPREF_WIDTH].whole + 31) / 32) * 4;
	lws_spi_desc_t desc;
	size_t s;

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
		if (check_busy(priv, 1))
			return;

		if (ic->greyscale) {
			if (ic->palette_depth > 2) {
				lwsl_notice("%s: init mode gray\n", __func__);
				lws_spi_table_issue(ea->spi, 0, uc8176_init1_gray,
						LWS_ARRAY_SIZE(uc8176_init1_gray));
			} else {
				lwsl_notice("%s: init mode BW\n", __func__);
				lws_spi_table_issue(ea->spi, 0, priv->ek79686 ? ek79686_init1_bw_104 : uc8176_init1_bw,
						priv->ek79686 ? LWS_ARRAY_SIZE(ek79686_init1_bw_104) : LWS_ARRAY_SIZE(uc8176_init1_bw));
			}
		} else {
			lwsl_err("%s: init mode RED\n", __func__);
			lws_spi_table_issue(ea->spi, 0, priv->ek79686 ? ek79686_init1_red_104 : uc8176_init1_red,
					priv->ek79686 ? LWS_ARRAY_SIZE(ek79686_init1_red_104) : LWS_ARRAY_SIZE(uc8176_init1_red));
		}

		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT4:
		if (check_busy(priv, 1))
			return;

		if (ic->greyscale) {
			if (ic->palette_depth > 2)
				lws_spi_table_issue(ea->spi, 0, uc8176_init2_gray,
						LWS_ARRAY_SIZE(uc8176_init2_gray));
			else
				lws_spi_table_issue(ea->spi, 0, priv->ek79686 ? ek79686_init2_bw_104 : uc8176_init2_bw,
						priv->ek79686 ? LWS_ARRAY_SIZE(ek79686_init2_bw_104) : LWS_ARRAY_SIZE(uc8176_init2_bw));
		} else
			lws_spi_table_issue(ea->spi, 0, priv->ek79686 ? ek79686_init2_red_104 : uc8176_init2_red,
					priv->ek79686 ? LWS_ARRAY_SIZE(ek79686_init2_red_104) : LWS_ARRAY_SIZE(uc8176_init2_red));

		priv->state++;
		priv->budget = BUSY_TIMEOUT_BUDGET;
		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul,
				 async_cb, LWS_US_PER_MS * 10);
		break;

	case LWSDISPST_INIT5:
		if (check_busy(priv, 1))
			return;

		priv->state = LWSDISPST_IDLE;
		if (ea->cb)
			ea->cb(priv->lds, 1);
		break;

	case LWSDISPST_WRITE1:

		if (check_busy(priv, 1))
			return;

		lwsl_user("%s: WRITE1\n", __func__);

		if (priv->nplanes == 2 && !priv->partial) {
			lws_spi_table_issue(ea->spi, 0, uc8176_wp2,
					    LWS_ARRAY_SIZE(uc8176_wp2));
			priv->pb_sent = 0;
			priv->state++;
		} else
			priv->state = LWSDISPST_WRITE3;

		priv->budget = BUSY_TIMEOUT_BUDGET;

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 2);
		break;

	case LWSDISPST_WRITE2:

		if (check_busy(priv, 1))
			return;

		/* issue the cached, packed LSB plane plane frame */

		s = priv->pb_pos - priv->pb_sent;
		if (s > plane_line_bytes * 4u)
			s = plane_line_bytes * 4u;

		memset(&desc, 0, sizeof(desc));
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;
		desc.data = (const uint8_t *)priv->planebuf + priv->pb_sent;
		desc.count_write = s;
		ea->spi->queue(ea->spi, &desc);

		priv->pb_sent += s;

		if (priv->pb_sent == priv->pb_pos) {
			priv->budget = BUSY_TIMEOUT_BUDGET;
			priv->state++;
		}

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb, 1);
		break;

	case LWSDISPST_WRITE3:
		if (check_busy(priv, 1))
			return;

		if (ea->spi->free_dma)
			ea->spi->free_dma(ea->spi,
					    (void **)&priv->line[0]);
		else
			lws_free_set_NULL(priv->line[0]);
		lws_free_set_NULL(priv->u[0]);

		/*
		 * Finalize the write of the planes, LUT set then REFRESH
		 */

		if (ic->greyscale) {
			if (ic->palette_depth > 2 && !priv->partial)
				lws_spi_table_issue(ea->spi, 0, uc8176_complete_gray,
						    LWS_ARRAY_SIZE(uc8176_complete_gray));
			else
				lws_spi_table_issue(ea->spi, 0, uc8176_complete_bw,
						    LWS_ARRAY_SIZE(uc8176_complete_bw));
		} else
			lws_spi_table_issue(ea->spi, 0, uc8176_complete_red,
					    LWS_ARRAY_SIZE(uc8176_complete_red));

		priv->budget = BUSY_TIMEOUT_BUDGET;
		priv->state++;

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 2);
		break;

	case LWSDISPST_WRITE4:
		if (check_busy(priv, 1))
			return;

		lws_spi_table_issue(ea->spi, 0, priv->partial ? uc8176_partial_out_off : uc8176_off,
				    priv->partial ? LWS_ARRAY_SIZE(uc8176_partial_out_off) : LWS_ARRAY_SIZE(uc8176_off));

		priv->budget = BUSY_TIMEOUT_BUDGET;
		priv->state++;

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 2);
		break;

	case LWSDISPST_WRITE5:
		if (check_busy(priv, 1))
			return;

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
lws_display_uc8176_spi_init(struct lws_display_state *lds)
{
	const lws_display_uc8176_spi_t *ea = lds_to_disp(lds);
	const lws_surface_info_t *ic = &ea->disp.ic;
	lws_display_uc8176_spi_state_t *priv;

	priv = lws_zalloc(sizeof(*priv), __func__);
	if (!priv)
		return 1;

	priv->lds = lds;
	lds->priv = priv;
	priv->ek79686 = (ic->wh_px[LWS_LHPREF_WIDTH].whole == 104) || (ic->wh_px[LWS_LHPREF_WIDTH].whole == 122);
	priv->nplanes = 1 + ((ic->greyscale && ic->palette_depth > 2) || !ic->greyscale);

	lwsl_notice("%s: ek79686: %d, nplanes: %d\n", __func__,
					priv->ek79686, priv->nplanes);

	ea->gpio->mode(ea->busy_gpio, LWSGGPIO_FL_READ | LWSGGPIO_FL_PULLUP);

	ea->gpio->mode(ea->reset_gpio, LWSGGPIO_FL_WRITE | LWSGGPIO_FL_PULLUP);

	ea->gpio->set(ea->reset_gpio, 1);
	priv->state = LWSDISPST_INIT1;
	lws_sul_schedule(lds->ctx, 0, &priv->sul, async_cb, LWS_US_PER_MS * 200);

	return 0;
}

/* no backlight */

int
lws_display_uc8176_spi_brightness(const struct lws_display *disp, uint8_t b)
{
	return 0;
}

/*
 * Partial updates can only do pure B&W
 */

static const lws_display_colour_t palette_partial[] = {
	PALETTE_RGBY(0x00, 0x00, 0x00),		/* black */
	PALETTE_RGBY(0xff, 0xff, 0xff),		/* white */
};

int
lws_display_uc8176_spi_blit(struct lws_display_state *lds, const uint8_t *src,
			     lws_box_t *box, lws_dll2_owner_t *ids)
{
	const lws_display_uc8176_spi_t *ea = lds_to_disp(lds);
	lws_display_uc8176_spi_state_t *priv = lds_to_priv(lds);
	lws_greyscale_error_t *gedl_this, *gedl_next;
	const lws_surface_info_t *ic = &ea->disp.ic;
	int plane_line_bytes = ((ic->wh_px[LWS_LHPREF_WIDTH].whole + 31) / 32) * 4;
	lws_colour_error_t *edl_this, *edl_next;
	const uint8_t *pc = src;
	lws_display_colour_t c;
	lws_display_id_t *id;
	lws_spi_desc_t desc;
	uint32_t *lo;
	int n, m;

	if (priv->state) {
		lwsl_warn("%s: ignoring as busy\n", __func__);
		return 1; /* busy */
	}

	if (!priv->line[0]) {
		/* compute separately, since we may be doing a partial */
		int maxplanes = 1 + ((ic->greyscale && ic->palette_depth > 2) ||
				      !ic->greyscale);
		size_t plane_alloc = plane_line_bytes * maxplanes;

		/*
		 * We have to allocate the packed line and error diffusion
		 * buffers.
		 *
		 * For this chip a plane is 1bpp, there can be one or two planes
		 * in a line buffer depending if BW, or BWR or 4-gray, and two
		 * line buffers for DMA ping-pong.
		 *
		 * Because it's planar in the two-plane case, we have to send
		 * plane 1 linewise, but buffer plane 2 into DMA-capable memory
		 * and send it after all of plane 1.
		 */

		priv->pb_len = 0;
		if (maxplanes == 2)
			priv->pb_len = plane_line_bytes *
						lds->disp->ic.wh_px[LWS_LHPREF_HEIGHT].whole;

		if (ea->spi->alloc_dma)
			priv->line[0] = ea->spi->alloc_dma(ea->spi,
					      (2 * plane_alloc) + priv->pb_len);
		else
			priv->line[0] = lws_malloc(2 * plane_alloc + priv->pb_len,
								__func__);

		if (!priv->line[0]) {
			lwsl_err("%s: OOM\n", __func__);
			priv->state = LWSDISPST_IDLE;
			return 0;
		}

//		memset(priv->line[0], 0, plane_line_bytes * priv->nplanes);

		priv->line[1] = (uint32_t *)(((uint8_t *)priv->line[0]) +
								plane_alloc);

		if (priv->pb_len)
			priv->planebuf = (uint32_t *)(((uint8_t *)priv->line[1]) +
								plane_alloc);
		priv->pb_pos = 0;

		if (lws_display_alloc_diffusion(ic, priv->u)) {
			if (ea->spi->free_dma)
				ea->spi->free_dma(ea->spi,
						    (void **)&priv->line[0]);
			else
				lws_free_set_NULL(priv->line[0]);

			lwsl_err("%s: OOM\n", __func__);
			priv->state = LWSDISPST_IDLE;
			return 0;
		}
	}

	switch (box->h.whole) {
	case 0: /* update needs to be finalized */

		priv->budget = BUSY_TIMEOUT_BUDGET;
		priv->state = LWSDISPST_WRITE1;

		lws_sul_schedule(priv->lds->ctx, 0, &priv->sul, async_cb,
				 LWS_US_PER_MS * 10);
		break;

	case 1:  /* single line = issue line */

		edl_this = (lws_colour_error_t *)priv->u[(box->y.whole & 1) ^ 1];
		edl_next = (lws_colour_error_t *)priv->u[box->y.whole & 1];
		gedl_this = (lws_greyscale_error_t *)edl_this;
		gedl_next = (lws_greyscale_error_t *)edl_next;
		lo = priv->line[box->y.whole & 1];

		if (src == NULL) {
			for (n = 0; n < ic->wh_px[LWS_LHPREF_WIDTH].whole; n++)
				pack_native_pixel(priv->nplanes, lo,
						  plane_line_bytes, n, (uint8_t)3);

			goto go;
		}

		if (ic->greyscale)
			for (n = 0; n < ic->wh_px[LWS_LHPREF_WIDTH].whole; n++) {
				c = (pc[0] << 16) | (pc[0] << 8) | pc[0];

				m = lws_display_palettize_grey(ic,
					priv->partial ? palette_partial : ic->palette,
					priv->partial ? 2 : ic->palette_depth,
							c, &gedl_this[n]);
				pack_native_pixel(priv->nplanes, lo,
						  plane_line_bytes, n,
						  (uint8_t)m);

				dist_err_floyd_steinberg_grey(n,
							      ic->wh_px[LWS_LHPREF_WIDTH].whole,
							      gedl_this, gedl_next);
				pc++;
			}
		else
			for (n = 0; n < ic->wh_px[LWS_LHPREF_WIDTH].whole; n++) {
				c = (pc[2] << 16) | (pc[1] << 8) | pc[0];

				m = lws_display_palettize_col(ic,
					priv->partial ? palette_partial : ic->palette,
					priv->partial ? 2: ic->palette_depth, c,
							      &edl_this[n]);
				pack_native_pixel(priv->nplanes, lo,
						  plane_line_bytes, n,
						  (uint8_t)m);

				dist_err_floyd_steinberg_col(n,
							     ic->wh_px[LWS_LHPREF_WIDTH].whole,
							     edl_this, edl_next);

				pc += 3;
			}
go:
		/* must be u32-aligned for DMA... */
		lo = priv->line[box->y.whole & 1] +
				((priv->upd.x.whole / 8) / 4);

		if (ea->spi->in_flight)
			while (ea->spi->in_flight(ea->spi))
				;
		while (priv->partial && check_busy(priv, 1))
			;

		if (priv->pb_len && !priv->partial &&
		    priv->pb_pos + plane_line_bytes <= priv->pb_len) {
			memcpy((uint8_t *)priv->planebuf + priv->pb_pos, lo,
			       (size_t)(ic->wh_px[LWS_LHPREF_WIDTH].whole + 7) / 8u);

			priv->pb_pos += (ic->wh_px[LWS_LHPREF_WIDTH].whole + 7) / 8u;
		}

		if (!box->y.whole) {
			if (priv->pb_len && !priv->partial) { /* there are two planes */
				if (ic->greyscale) {
					if (priv->nplanes > 2)
						lws_spi_table_issue(ea->spi, 0, uc8176_wp1_gray,
								LWS_ARRAY_SIZE(uc8176_wp1_gray));
					else
						lws_spi_table_issue(ea->spi, 0, uc8176_wp1_bw,
								LWS_ARRAY_SIZE(uc8176_wp1_bw));
				} else
					lws_spi_table_issue(ea->spi, 0, uc8176_wp1_red,
						    LWS_ARRAY_SIZE(uc8176_wp1_red));
			} else
				lws_spi_table_issue(ea->spi, 0, uc8176_wp2,
						    LWS_ARRAY_SIZE(uc8176_wp2));
		}

		/* During partial, we are doing the second frame */

		memset(&desc, 0, sizeof(desc));
		desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;

		desc.count_write = (ic->wh_px[LWS_LHPREF_WIDTH].whole + 7) / 8;
		if (priv->partial && priv->partbuf) {
			/* update the old copy of the partial area */
			desc.count_write = (priv->upd.w.whole + 7) / 8;
			memcpy((uint8_t *)priv->partbuf + priv->partbuf_pos,
					(uint8_t *)lo, desc.count_write);
			/* packed at byte boundaries */
			priv->partbuf_pos += desc.count_write;
		}

		desc.data = priv->pb_len || priv->partial ? (uint8_t *)lo + plane_line_bytes :
					   (uint8_t *)lo;

		ea->spi->queue(ea->spi, &desc);

		return 0;

	default: /* starting update */

		/*
		 * The initial box we get started with attempts to reflect the
		 * update area.  If it's (0,0)(ic->wh_px[LWS_LHPREF_WIDTH],
		 * ic->wh_px[LWS_LHPREF_HEIGHT]), then we do the default full update.  If it's anything else, we
		 * take it as a wish for a partial update in that region.
		 *
		 * If partial, we should only hear about lines within the region
		 * although the rasterizer may choose to rasterize from the top
		 * and skip sending us the lines above the partial in order to
		 * know what to put there.  It can end rasterization below the
		 * partial region.
		 *
		 * The renderer must apply any x offset to the line buffer
		 * before sending, this is so it's possible for renderers to
		 * ONLY prepare the partial region.
		 *
		 * "Partial update" means B&W only, no matter if red or gray
		 * capable and configured normally.
		 */

		priv->partial = 0;
		if (ids && ids->count) {
			id = lws_container_of(ids->head, lws_display_id_t, list);
			if (id->exists)
				priv->partial = 1;
		}

		priv->pb_pos = 0;

		if (priv->partial) {
			uint8_t *p = priv->pcmd;

			priv->upd = id->box;
			lws_display_render_dump_ids(ids);

			lwsl_user("%s: PARTIAL %d: (%d,%d) %dx%d\n", __func__, (int)priv->partial,
					(int)priv->upd.x.whole, (int)priv->upd.y.whole, (int)priv->upd.w.whole,
					(int)priv->upd.h.whole);

			/* lines packed at byte boundaries */
			priv->partbuf_len = ((priv->upd.w.whole + 7) / 8) * priv->upd.h.whole;

			if (!priv->partbuf_len) {
				lwsl_err("%s: partbuf_len is zero\n", __func__);
				priv->partial = 0;
				goto fully;
			}

			/*
			 * Partial being B&W has some implications.  Since it's
			 * only smaller than the whole surface, we can just use
			 * a part of the whole display dimensions line and error
			 * diffusion buffers for this update.
			 *
			 * Partial requires a copy of the data that was stored
			 * at the display in the area to be resent first.  To
			 * avoid having to keep a framebuffer of this info, we
			 * require the initial partial area after the last full
			 * update must start all-white.
			 *
			 * After the first partial, we keep a copy of the
			 * partial data around until the next full update
			 */
			priv->nplanes = 2;

			if (!priv->partbuf) {
				if (ea->spi->alloc_dma)
					priv->partbuf = ea->spi->alloc_dma(ea->spi,
							priv->partbuf_len);
				else
					priv->partbuf = lws_malloc(priv->partbuf_len,
								__func__);
				if (!priv->partbuf) {
					lwsl_err("%s: OOM: %d\n", __func__, (int)priv->partbuf_len);
					priv->state = LWSDISPST_IDLE;
					return -1;
				}

				/* we start the area off as all-white */
				memset(priv->partbuf, 0, priv->partbuf_len);
			}

			*p++ = 1;
			*p++ = UC8176_CMD_PANEL_SETTING;
			*p++ = 0x0f; /* ie, BWR mode */

			*p++ = 0;
			*p++ = UC8176_CMD_PARTIAL_IN;
			if (!priv->ek79686)
				*p++ = 9;
			else
				*p++ = 7;
			*p++ = UC8176_CMD_PARTIAL_WINDOW;
			if (!priv->ek79686)
				*p++ = (priv->upd.x.whole) >> 8;
			*p++ = priv->upd.x.whole & 0xf8;
			if (!priv->ek79686)
				*p++ = (priv->upd.x.whole + priv->upd.w.whole - 1) >> 8;
			*p++ = ((priv->upd.x.whole + priv->upd.w.whole - 1) & 0xf8) | 7;
			*p++ = priv->upd.y.whole >> 8;
			*p++ = priv->upd.y.whole & 0xff;
			*p++ = (priv->upd.y.whole + priv->upd.h.whole - 1) >> 8;
			*p++ = (priv->upd.y.whole + priv->upd.h.whole - 1) & 0xff;
			*p++ = 0x38; // 0x28; /* ??? only b0 documented */

			*p++ = 1;
			*p++ = UC8176_CMD_VCOM_AND_DATA_INTERVAL_SETTING;
			*p++ = 0x97;
			*p++ = 0;
			*p++ = UC8176_CMD_DATA_START_TRANSMISSION_1;

			lwsl_hexdump_notice(priv->pcmd, lws_ptr_diff_size_t(p, &priv->pcmd));

			lws_spi_table_issue(ea->spi, 0, priv->pcmd,
					    lws_ptr_diff_size_t(p, &priv->pcmd));

			memset(&desc, 0, sizeof(desc));
			desc.flags = LWS_SPI_FLAG_DMA_BOUNCE_NOT_NEEDED;
			desc.data = (uint8_t *)priv->partbuf; /* partial-old data first */
			/* packed at byte boundaries */
			desc.count_write = (((priv->upd.w.whole + 7) / 8) * 1) *
					      priv->upd.h.whole;
			ea->spi->queue(ea->spi, &desc);

			lwsl_user("%s: sent partial start %u\n", __func__, desc.count_write);

			/* ... let that send while we start producing lines... */

			priv->partbuf_pos = 0;

			break;
		}
fully:
		/* full update */

		priv->nplanes = 1 + ((ic->greyscale && ic->palette_depth > 2) ||
				     !ic->greyscale);

		/*
		 * Now we're doing a full update, discard the partial buffer
		 */

		if (ea->spi->free_dma)
			ea->spi->free_dma(ea->spi, (void **)&priv->partbuf);
		else
			lws_free_set_NULL(priv->partbuf);

		break;
	}

	return 0;
}

int
lws_display_uc8176_spi_power(lws_display_state_t *lds, int state)
{
	const lws_display_uc8176_spi_t *ea = lds_to_disp(lds);

	if (!state) {
		lws_spi_table_issue(ea->spi, 0, uc8176_off,
				    LWS_ARRAY_SIZE(uc8176_off));
		if (ea->gpio)
			ea->gpio->set(ea->reset_gpio, 0);

		return 0;
	}

	return 0;
}
