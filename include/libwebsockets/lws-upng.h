/*
 * uPNG -- derived from LodePNG version 20100808
 *
 * Copyright (c) 2005-2010 Lode Vandevenne
 * Copyright (c) 2010 Sean Middleditch
 * Copyright (c) 2021-2022 Andy Green <andy@warmcat.com>
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.

 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must not
 *      claim that you wrote the original software. If you use this software
 *      in a product, an acknowledgment in the product documentation would be
 *	appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must not be
 *	misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *	distribution.
 *
 *  The above notice is the ZLIB license, libpng also uses it.
 *
 * This version is based on upng project's fork of lodepng and rewritten for
 * lws, changing the whole approach to decode on demand to issue a line of
 * output at a time, statefully.
 */

typedef enum lws_upng_format_t {
	LWS_UPNG_BADFORMAT,
	LWS_UPNG_RGB8,
	LWS_UPNG_RGB16,
	LWS_UPNG_RGBA8,
	LWS_UPNG_RGBA16,
	LWS_UPNG_LUMINANCE1,
	LWS_UPNG_LUMINANCE2,
	LWS_UPNG_LUMINANCE4,
	LWS_UPNG_LUMINANCE8,
	LWS_UPNG_LUMINANCE_ALPHA1,
	LWS_UPNG_LUMINANCE_ALPHA2,
	LWS_UPNG_LUMINANCE_ALPHA4,
	LWS_UPNG_LUMINANCE_ALPHA8
} lws_upng_format_t;

typedef struct lws_upng_t lws_upng_t;

/**
 * lws_upng_new() - Create new UPNG decode object
 *
 * Returns a new PNG decoding object, which should be destroyed with
 * lws_upng_free() when done with, or NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN lws_upng_t *
lws_upng_new(void);

/**
 * lws_upng_free() - Destroy a PNG decode object
 *
 * \param upng: Pointer to the decode object to destroy and set to NULL
 *
 * This also frees any sub-allocations in the object.
 */
LWS_VISIBLE LWS_EXTERN void
lws_upng_free(lws_upng_t **upng);

/**
 * lws_upng_emit_next_line() - deocde the next line
 *
 * \param upng: the decode object
 * \ppix: pointer to a pointer set to the line's decoded pixel data
 * \buf: pointer to a const uint8_t array of PNG input
 * \size: pointer to the count of bytes available at *buf
 *
 * Make PNG input available to the decoder so it can issue the next line's
 * worth of pixels.  If the call consumed any input, *buf and *size are
 * adjusted accordingly.
 *
 * The decoder is stateful so it is not sensitive to the chunk size for the
 * input.
 *
 * Return will be one of LWS_SRET_WANT_INPUT is the decoder is stalled waiting
 * for more input to be provided, LWS_SRET_WANT_OUTPUT is the decoder stopped
 * because it had produced a whole line of output pixels (which can be found
 * starting at *ppix), LWS_SRET_OK is it completed and LWS_SRET_FATAL or larger
 * if the decode failed.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_upng_emit_next_line(lws_upng_t *upng, const uint8_t **ppix,
			const uint8_t **buf, size_t *size);

LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_width(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_height(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_bpp(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_bitdepth(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_components(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN unsigned int
lws_upng_get_pixelsize(const lws_upng_t *upng);
LWS_VISIBLE LWS_EXTERN lws_upng_format_t
lws_upng_get_format(const lws_upng_t *upng);

