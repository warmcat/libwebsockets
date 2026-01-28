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
 * LIABILITY, WHETHER IN AN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
/** @file */

#include <stdint.h>
#include <stddef.h>

/** \defgroup Mnemonic Mnemonic Key Generation
 * ##Mnemonic Key Generation
 *
 * Lws provides an API to convert 128-bit entropy (e.g. AES-128 keys) to and
 * from a 12-word English mnemonic phrase following the BIP-39 standard.
 *
 * This is useful for providing a human-readable/writable backup of a key.
 */
///@{

/**
 * lws_mnemonic_generate() - Generate a mnemonic phrase from entropy
 *
 * \param ctx: lws_context (used for random if needed, or SHA256)
 * \param entropy: 16 bytes of entropy (e.g. an AES-128 key)
 * \param dest: buffer to receive the NUL-terminated mnemonic string
 * \param dest_len: size of the dest buffer (should be at least 128 bytes)
 *
 * Converts 128 bits of entropy into a 12-word mnemonic phrase.
 * Returns 0 on success, or non-zero on error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_mnemonic_generate(struct lws_context *ctx, const uint8_t *entropy,
		      char *dest, size_t dest_len);

/**
 * lws_mnemonic_to_entropy() - Recover entropy from a mnemonic phrase
 *
 * \param ctx: lws_context (used for SHA256)
 * \param src: the mnemonic phrase (12 words separated by single spaces)
 * \param dest: 16-byte buffer to receive the recovered entropy
 *
 * Converts a 12-word mnemonic phrase back into 128 bits of entropy.
 * Validates the BIP-39 checksum.
 * Returns 0 on success, or non-zero if the phrase is invalid or checksum fails.
 */
LWS_VISIBLE LWS_EXTERN int
lws_mnemonic_to_entropy(struct lws_context *ctx, const char *src,
			uint8_t *dest);

///@}
