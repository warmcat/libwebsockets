/*
 * lws jpeg
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
 * Based on public domain original with notice -->
 *
 * picojpeg.c v1.1 - Public domain, Rich Geldreich <richgel99@gmail.com>
 * Nov. 27, 2010 - Initial release
 * Feb. 9, 2013 - Added H1V2/H2V1 support, cleaned up macros, signed shift fixes
 * Also integrated and tested changes from Chris Phoenix <cphoenix@gmail.com>.
 *
 * This version is rewritten for lws, changing the whole approach to decode on
 * demand to issue a line of output at a time, statefully.  This version is
 * licensed MIT to match the rest of lws.
 */

typedef struct lws_jpeg lws_jpeg_t;

/**
 * lws_jpeg_new() - Create new JPEG decode object
 *
 * Returns a new jpeg decoding object, which should be destroyed with
 * lws_jpeg_free() when done with, or NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN lws_jpeg_t *
lws_jpeg_new(void);

/**
 * lws_jpeg_free() - Destroy a JPEG decode object
 *
 * \param j: Pointer to the decode object to destroy and set to NULL
 *
 * This also frees any sub-allocations in the object.
 */
LWS_VISIBLE LWS_EXTERN void
lws_jpeg_free(lws_jpeg_t **j);

/**
 * lws_jpeg_emit_next_line() - deocde the next line
 *
 * \param j: the decode object
 * \ppix: pointer to a pointer set to the line's decoded pixel data
 * \buf: pointer to a const uint8_t array of jpeg input
 * \size: pointer to the count of bytes available at *buf
 *
 * Make jpeg input available to the decoder so it can issue the next line's
 * worth of pixels.  If the call consumed any input, *buf and *size are
 * adjusted accordingly.
 *
 * The decoder is stateful so it is not sensitive to the chunk size for the
 * input.
 *
 * If you want to process the header part without yet generating output, you can
 * feed this small chunks of data until lws_jpeg_get_bitdepth() returns nonzero.
 *
 * Return will be one of LWS_SRET_WANT_INPUT is the decoder is stalled waiting
 * for more input to be provided, LWS_SRET_WANT_OUTPUT is the decoder stopped
 * because it had produced a whole line of output pixels (which can be found
 * starting at *ppix), LWS_SRET_OK is it completed and LWS_SRET_FATAL or larger
 * if the decode failed.
 *
 * The output at *ppix is either 3-byte per pixel RGB, or 1-byte grayscale, you
 * can query lws_jpeg_get_components() to find out how many bytes per pixel.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_jpeg_emit_next_line(lws_jpeg_t *j, const uint8_t **ppix,
			const uint8_t **buf, size_t *size);

LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_width(const lws_jpeg_t *j);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_height(const lws_jpeg_t *j);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_bpp(const lws_jpeg_t *j);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_bitdepth(const lws_jpeg_t *j);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_components(const lws_jpeg_t *j);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_jpeg_get_pixelsize(const lws_jpeg_t *j);

