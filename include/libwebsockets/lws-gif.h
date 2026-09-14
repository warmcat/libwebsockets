/*
 * lws gif
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
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
 * Stateful, linewise GIF decoder for the first frame.  Compressed input is
 * consumed from arbitrarily-sized chunks and complete raster rows are issued
 * one at a time into a row buffer shared between every live gif object, so
 * heap use does not scale with anything about the gif except its logical
 * screen width (one row) and the fixed 12-bit LZW code tables.
 *
 * Rows are issued in logical screen coordinates as single bytes that index
 * the active colour table: every screen row is issued exactly once, with
 * areas the image rectangle does not cover filled with the background
 * index, and parts of the image rectangle falling outside the logical
 * screen clipped.  For interlaced images, rows are issued in gif interlace
 * order with their true y available at \p py, bookended by the background
 * rows above and below the image rectangle; linearizing interlaced rows
 * needs a whole framebuffer, so consumers that need strict top-down order
 * must re-decode from retained input, as the dlo integration does.
 *
 * Only the first image is decoded; any further images are walked structurally
 * to the trailer and their pixel data discarded.
 */

typedef struct lws_gif lws_gif_t;

/**
 * lws_gif_new() - create a gif decode object
 *
 * Returns a new gif decoding object, which should be destroyed with
 * lws_gif_free() when done with, or NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN lws_gif_t *
lws_gif_new(void);

/**
 * lws_gif_free() - destroy a gif decode object
 *
 * \param gif: pointer to the decode object pointer to destroy and set NULL
 *
 * This also frees any sub-allocations in the object, and releases the
 * object's claim on the shared row buffer pool.
 */
LWS_VISIBLE LWS_EXTERN void
lws_gif_free(lws_gif_t **gif);

/**
 * lws_gif_restart() - reset decode state, keeping allocations
 *
 * \param gif: the decode object
 *
 * Resets the parse, LZW and row state so the object expects a gif header
 * again, for re-decoding retained input (eg, to reach a different row of an
 * interlaced image).  Allocations and the shared pool claim are kept.
 */
LWS_VISIBLE LWS_EXTERN void
lws_gif_restart(lws_gif_t *gif);

/**
 * lws_gif_emit_next_line() - decode the next row
 *
 * \param gif: the decode object
 * \param ppix: set to the row's decoded palette indices on WANT_OUTPUT
 * \param py: set to the row's y position in the logical screen
 * \param buf: pointer to a const uint8_t array of gif input
 * \param len: pointer to the count of bytes available at *buf
 * \param hold_at_metadata: nonzero to stop consuming once the logical screen
 *			   descriptor has parsed
 *
 * Make gif input available to the decoder so it can issue the next row.  If
 * the call consumed any input, *buf and *len are adjusted accordingly.  The
 * decoder is stateful so it is not sensitive to the chunk size of the input.
 *
 * If \p hold_at_metadata is set, decoding stops once the logical screen
 * descriptor has been parsed, even if further input is available at *buf, so
 * image dimensions are known before committing to the decode allocations.
 *
 * Returns LWS_SRET_WANT_OUTPUT if a row was produced, with *ppix pointing at
 * logical-screen-width bytes of palette indices and *py set to the row's y;
 * LWS_SRET_WANT_INPUT if the input so far was consumed and more is needed to
 * progress; LWS_SRET_OK once the trailer has been reached, or a return with
 * LWS_SRET_FATAL set if the gif is too broken to process.  When input ends
 * without a trailer, whatever rows decoded so far were issued and the
 * retained state remains renderable.
 *
 * For non-interlaced images rows are issued with y = 0, 1, 2... in order.
 * For interlaced images they are issued in gif interlace order (pass 0 rows
 * 0, 8, 16..., then 4, 12..., then 2, 6, 10..., then 1, 3, 5...) with \p py
 * holding the row's true y position.
 *
 * The row at *ppix lives in a buffer shared by every live gif object: it is
 * valid only until the next call on any gif object.  Decoding is single-
 * threaded, like the display list it serves.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_gif_emit_next_line(lws_gif_t *gif, const uint8_t **ppix, int *py,
		       const uint8_t **buf, size_t *len, char hold_at_metadata);

/**
 * lws_gif_get_width() - get the logical screen width in px
 *
 * \param gif: the decode object
 *
 * Returns the logical screen width in px once the logical screen descriptor
 * has parsed, else 0.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_width(const lws_gif_t *gif);

/**
 * lws_gif_get_height() - get the logical screen height in px
 *
 * \param gif: the decode object
 *
 * As lws_gif_get_width(), but for the logical screen height.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_height(const lws_gif_t *gif);

/**
 * lws_gif_get_interlaced() - is the first image interlaced?
 *
 * \param gif: the decode object
 *
 * Returns nonzero if the first image's descriptor had the interlace flag
 * set.  This is only known once decoding has reached the image descriptor,
 * ie, after input was fed without hold_at_metadata.
 */
LWS_VISIBLE LWS_EXTERN char
lws_gif_get_interlaced(const lws_gif_t *gif);

/**
 * lws_gif_get_palette() - get the active colour table
 *
 * \param gif: the decode object
 *
 * Returns a pointer to the active colour table entries as RGB byte triplets,
 * or NULL if none has parsed yet.  The active table is the first image's
 * local colour table if it had one, else the global colour table.
 */
LWS_VISIBLE LWS_EXTERN const uint8_t *
lws_gif_get_palette(const lws_gif_t *gif);

/**
 * lws_gif_get_palette_count() - number of entries in the active colour table
 *
 * \param gif: the decode object
 *
 * Returns the number of RGB triplets at the pointer given by
 * lws_gif_get_palette(), a power of two up to 256, or 0 if none has parsed.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_palette_count(const lws_gif_t *gif);

/**
 * lws_gif_get_transparent_index() - transparent palette index of first frame
 *
 * \param gif: the decode object
 *
 * Returns the palette index the first image's graphic control extension (if
 * any) declared transparent, or -1 if there is none.  Rows still carry the
 * index bytes; it is the compositor's business to treat them as transparent.
 */
LWS_VISIBLE LWS_EXTERN int
lws_gif_get_transparent_index(const lws_gif_t *gif);

/* indices are one byte each; provided for symmetry with the other decoders */

LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_bpp(const lws_gif_t *gif);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_bitdepth(const lws_gif_t *gif);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_components(const lws_gif_t *gif);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_gif_get_pixelsize(const lws_gif_t *gif);
