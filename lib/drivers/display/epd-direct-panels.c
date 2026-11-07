/*
 * lws directly-driven EPD panel descriptions
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
 * Panel models for the directly-driven EPD driver, from their datasheets
 */

#include <private-lib-core.h>

/*
 * E Ink ED047TC1, 4.7", 960 x 540, the timings from its datasheet P-511-710
 * v1.0, "Display Module AC characteristics".  The datasheet is in portrait,
 * 540 (H) x 960 (V), but its source drivers run along the long edge.
 *
 * The datasheet doesn't say which 2-bit code drives which way, or how the
 * pixels are ordered in a bus byte: these are a first guess, to be checked
 * on a panel.
 */

const lws_epd_direct_panel_t lws_epd_direct_panel_ed047tc1 = {
	.name			= "E Ink ED047TC1",
	.source_px		= 960,
	.gate_rows		= 540,
	.code_black		= 1,
	.code_white		= 2,
	.code_none		= 0,
	.ckv_max_hz		= 200000,
	.ckv_min_high_ns	= 500,
	.ckv_min_low_ns		= 500,
	.xcl_max_hz		= 60000000,	/* tcy >= 16.67ns */
	.le_min_width_ns	= 300,
	.le_min_off_ns		= 200,
	.le_min_delay_xcl_x2	= 7,		/* 3.5 tcy */
	.output_settle_us	= 20,
	.min_pass_us		= 11765,	/* 85Hz */
};
