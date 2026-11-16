/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * lws_epd_direct_esp32_encode_16l(): the epd-direct row encode for its most
 * common case, using the ESP32-S3's PIE vector instructions.  See the
 * description of .encode_16l in include/libwebsockets/lws-epd-direct.h for
 * what it's given and what it does.
 *
 * Each word is 32 pixels in flight, in two halves of 16.  For each half:
 *
 *  - the 16 ft bytes are loaded, and so are 16 bytes of the start of each
 *    pixel's span, from the table of them for the half's start byte
 *
 *  - zipping them together makes eight 16-bit lanes in each of two q regs,
 *    each start << 8 | ft, which is the pixel's index in the codes table
 *
 *  - ee.ldxq.32 loads a pixel's 32-bit code entry by its index lane.  The
 *    pixels are gathered by their place in their bus byte: q2 lane b gets the
 *    code of pixel 4b, q3 lane b of pixel 4b + 1, and so on
 *
 *  - the places are shifted to their bits in the bus byte, the first pixel
 *    in the most significant bits, and or-ed together, so the low byte of lane
 *    b is the half's bus byte b
 *
 * Then unzipping the two halves twice brings the low bytes of their lanes
 * together, the word's 8 bus bytes, which are stored.
 *
 * It's also worked out if any byte drives anything, by or-ing each word's
 * bytes xor the no drive byte into q7.
 *
 * q0 - q1 are the indexes, q2 - q5 the first half's places, q3 - q6 the
 * second's, while q2 holds the first half's bytes.
 */

#include <sdkconfig.h>

#if defined(CONFIG_IDF_TARGET_ESP32S3)

/*
 * uint32_t
 * lws_epd_direct_esp32_encode_16l(uint8_t *out, const uint8_t *ft,
 *				   const uint8_t *starts, size_t words,
 *				   const void *tables);
 *
 * a2: out, 8-byte aligned	a3: ft, 16-byte aligned
 * a4: starts, a byte for each 16 pixels
 * a5: words, at least 1	a6: tables, 16-byte aligned
 *
 * tables is LWS_EPDD_16L_EXPAND_LEN bytes of the start of each pixel in 16
 * for each start byte, then 16 bytes of the no drive byte, then the 4096
 * 32-bit code entries
 */

	.section	.iram1.text.lws_epdd_encode_16l, "ax"
	.global		lws_epd_direct_esp32_encode_16l
	.type		lws_epd_direct_esp32_encode_16l, @function
	.align		4

lws_epd_direct_esp32_encode_16l:
	entry		a1, 32

	mov.n		a8, a6			/* a8: start expansion table */
	addmi		a10, a6, 4096		/* a10: 16 no drive bytes */
	addi		a7, a10, 16		/* a7: code entries */
	ee.zero.q	q7			/* q7: any driven */

.Lword:
	/* the first 16 pixels of the word */
	l8ui		a9, a4, 0
	slli		a9, a9, 4
	add.n		a9, a9, a8
	ee.vld.128.ip	q0, a3, 16
	ee.vld.128.ip	q1, a9, 0
	ee.vzip.8	q0, q1
	ee.ldxq.32	q2, q0, a7, 0, 0
	ee.ldxq.32	q3, q0, a7, 0, 1
	ee.ldxq.32	q4, q0, a7, 0, 2
	ee.ldxq.32	q5, q0, a7, 0, 3
	ee.ldxq.32	q2, q0, a7, 1, 4
	ee.ldxq.32	q3, q0, a7, 1, 5
	ee.ldxq.32	q4, q0, a7, 1, 6
	ee.ldxq.32	q5, q0, a7, 1, 7
	ee.ldxq.32	q2, q1, a7, 2, 0
	ee.ldxq.32	q3, q1, a7, 2, 1
	ee.ldxq.32	q4, q1, a7, 2, 2
	ee.ldxq.32	q5, q1, a7, 2, 3
	ee.ldxq.32	q2, q1, a7, 3, 4
	ee.ldxq.32	q3, q1, a7, 3, 5
	ee.ldxq.32	q4, q1, a7, 3, 6
	ee.ldxq.32	q5, q1, a7, 3, 7
	ssai	6
	ee.vsl.32	q2, q2
	ssai	4
	ee.vsl.32	q3, q3
	ssai	2
	ee.vsl.32	q4, q4
	ee.orq		q2, q2, q3
	ee.orq		q4, q4, q5
	ee.orq		q2, q2, q4

	/* the second 16 */
	l8ui		a9, a4, 1
	slli		a9, a9, 4
	add.n		a9, a9, a8
	ee.vld.128.ip	q0, a3, 16
	ee.vld.128.ip	q1, a9, 0
	ee.vzip.8	q0, q1
	ee.ldxq.32	q3, q0, a7, 0, 0
	ee.ldxq.32	q4, q0, a7, 0, 1
	ee.ldxq.32	q5, q0, a7, 0, 2
	ee.ldxq.32	q6, q0, a7, 0, 3
	ee.ldxq.32	q3, q0, a7, 1, 4
	ee.ldxq.32	q4, q0, a7, 1, 5
	ee.ldxq.32	q5, q0, a7, 1, 6
	ee.ldxq.32	q6, q0, a7, 1, 7
	ee.ldxq.32	q3, q1, a7, 2, 0
	ee.ldxq.32	q4, q1, a7, 2, 1
	ee.ldxq.32	q5, q1, a7, 2, 2
	ee.ldxq.32	q6, q1, a7, 2, 3
	ee.ldxq.32	q3, q1, a7, 3, 4
	ee.ldxq.32	q4, q1, a7, 3, 5
	ee.ldxq.32	q5, q1, a7, 3, 6
	ee.ldxq.32	q6, q1, a7, 3, 7
	ssai	6
	ee.vsl.32	q3, q3
	ssai	4
	ee.vsl.32	q4, q4
	ssai	2
	ee.vsl.32	q5, q5
	ee.orq		q3, q3, q4
	ee.orq		q5, q5, q6
	ee.orq		q3, q3, q5

	/* the low bytes of each lane of q2 then q3, together */
	ee.vunzip.8	q2, q3
	ee.vunzip.8	q2, q3

	/* the second half's places used q6, so it's loaded here */
	ee.vld.128.ip	q6, a10, 0
	ee.xorq		q4, q2, q6
	ee.orq		q7, q7, q4
	ee.vst.l.64.ip	q2, a2, 8

	addi.n		a4, a4, 2
	addi.n		a5, a5, -1
	bnez.n		a5, .Lword

	/* only the low 8 bytes of q7 were stored ones */
	ee.movi.32.a	q7, a2, 0
	ee.movi.32.a	q7, a3, 1
	or		a2, a2, a3
	retw.n

	.size		lws_epd_direct_esp32_encode_16l, . - lws_epd_direct_esp32_encode_16l

#endif
