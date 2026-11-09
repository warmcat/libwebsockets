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
 */

/*! \defgroup genkem Generic Key Encapsulation Mechanism
 * ## Generic KEM (ML-KEM, FIPS 203) related functions
 *
 * Lws provides generic Key Encapsulation Mechanism apis that work the same
 * whatever the TLS backend.  Today the KEM is ML-KEM (FIPS 203) at its three
 * parameter sets.
 *
 * Where the TLS backend has ML-KEM (eg, OpenSSL 3.5+) it is used, otherwise
 * lws uses its own implementation.  Keys and ciphertexts are the FIPS 203
 * byte strings either way, so they interoperate freely.
 *
 * The party that wants a shared secret makes a keypair and sends the
 * encapsulation key (EK) to the peer.  The peer encapsulates against the EK,
 * getting a 32-byte shared secret and a ciphertext it sends back.  The first
 * party decapsulates the ciphertext with its decapsulation key (DK) and gets
 * the same 32-byte shared secret.
 */
///@{

#if !defined(__LWS_GENKEM_H__)
#define __LWS_GENKEM_H__

enum lws_genkem_alg {
	LWS_GENKEM_ML_KEM_512,
	LWS_GENKEM_ML_KEM_768,
	LWS_GENKEM_ML_KEM_1024,

	LWS_GENKEM_COUNT
};

#define LWS_GENKEM_SS_LEN		32 /* shared secret, all algs */
#define LWS_GENKEM_SEED_LEN		64 /* d || z, all algs */

/* the largest of each kind of thing across all the algs */
#define LWS_GENKEM_MAX_EK_LEN		1568
#define LWS_GENKEM_MAX_DK_LEN		3168
#define LWS_GENKEM_MAX_CT_LEN		1568

struct lws_genkem_info {
	const char	*name;		/* eg, "ML-KEM-768" */
	uint16_t	ek_len;
	uint16_t	dk_len;
	uint16_t	ct_len;
};

#define LWS_GENKEM_CTX_CREATED_MARK 0x4c57474bu /* "LWGK" */

struct lws_genkem_ctx {
	struct lws_context	*context;
	void			*engine;  /* backend key object, if any */
	uint8_t			*ek;	  /* lws implementation's EK, if any */
	uint8_t			*dk;	  /* lws implementation's DK, if any */
	enum lws_genkem_alg	alg;
	uint32_t		created_mark;
};

/** lws_genkem_info() - get the sizes for a KEM alg
 *
 * \param alg: the KEM alg, eg LWS_GENKEM_ML_KEM_768
 *
 * Returns a const struct describing the alg's name and the sizes of its
 * keys and ciphertext, or NULL if \p alg is unknown.
 */
LWS_VISIBLE LWS_EXTERN const struct lws_genkem_info *
lws_genkem_info(enum lws_genkem_alg alg);

/** lws_genkem_create() - Create a genkem
 *
 * \param ctx: your genkem context
 * \param context: your lws_context (for RNG access)
 * \param alg: the KEM alg, eg LWS_GENKEM_ML_KEM_768
 *
 * Initializes a genkem.  \p ctx must be zeroed (eg, using memset) before it
 * is passed here the first time; if the ctx is still live from an earlier
 * create, the call fails and returns nonzero.  After lws_genkem_destroy() the
 * same ctx can be created again.
 *
 * The ctx has no key until lws_genkem_new_keypair() or lws_genkem_set_key().
 */
LWS_VISIBLE LWS_EXTERN int
lws_genkem_create(struct lws_genkem_ctx *ctx, struct lws_context *context,
		  enum lws_genkem_alg alg);

/** lws_genkem_new_keypair() - Give the genkem a new keypair
 *
 * \param ctx: your genkem context
 * \param seed: NULL for a random keypair, or LWS_GENKEM_SEED_LEN bytes of d || z
 * \param el: NULL, or array of LWS_GENCRYPTO_KEM_KEYEL_COUNT zeroed key
 *	      elements to take the new key
 *
 * Makes a keypair and applies it to the ctx, so it can then encapsulate and
 * decapsulate.
 *
 * If \p el is not NULL, the EK, DK and seed are also allocated into it, for
 * you to send or store; free them with lws_genkem_destroy_elements().  The seed alone is
 * enough to make the same keypair again, so it is a compact way to store
 * the private key.  Passing \p seed gives the same keypair every time, which
 * is how you would restore one from its stored seed.
 *
 * Returns 0 if OK.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genkem_new_keypair(struct lws_genkem_ctx *ctx, const uint8_t *seed,
		       struct lws_gencrypto_keyelem *el);

/** lws_genkem_set_key() - Apply a key to a genkem
 *
 * \param ctx: your genkem context
 * \param el: array of LWS_GENCRYPTO_KEM_KEYEL_COUNT key elements
 *
 * Applies the key to the ctx.  Exactly one kind of key is used: if
 * el[LWS_GENCRYPTO_KEM_KEYEL_SEED] has a seed, the keypair is made from that;
 * otherwise if el[LWS_GENCRYPTO_KEM_KEYEL_DK] has a DK, that is used, and it
 * contains the EK too; otherwise el[LWS_GENCRYPTO_KEM_KEYEL_EK] is used, and
 * the ctx can only encapsulate.
 *
 * Keys are checked as FIPS 203 requires before use: the length, the
 * coefficients of an EK being in range, and the hash of the EK embedded in a
 * DK matching it.  This matters for an EK, which usually comes from the peer.
 *
 * Returns 0 if OK, or nonzero if the key is invalid.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genkem_set_key(struct lws_genkem_ctx *ctx,
		   const struct lws_gencrypto_keyelem *el);

/** lws_genkem_encapsulate() - Make a shared secret and its ciphertext
 *
 * \param ctx: your genkem context, with an EK (or keypair) applied
 * \param ct: buffer for the ciphertext
 * \param ct_max: size of \p ct, at least lws_genkem_info(alg)->ct_len
 * \param ss: LWS_GENKEM_SS_LEN buffer for the shared secret
 *
 * Makes a random shared secret encapsulated to the ctx's EK.  Send the
 * ciphertext to the holder of the DK, who can then get the same shared
 * secret using lws_genkem_decapsulate().
 *
 * Returns 0 if OK.  The ciphertext is always lws_genkem_info(alg)->ct_len.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genkem_encapsulate(struct lws_genkem_ctx *ctx, uint8_t *ct, size_t ct_max,
		       uint8_t *ss);

/** lws_genkem_decapsulate() - Get the shared secret from a ciphertext
 *
 * \param ctx: your genkem context, with a DK (or keypair) applied
 * \param ct: the ciphertext from the peer
 * \param ct_len: length of \p ct
 * \param ss: LWS_GENKEM_SS_LEN buffer for the shared secret
 *
 * Returns nonzero if \p ct_len is wrong for the alg, or there is no DK.
 *
 * Note that, as FIPS 203 requires, a ciphertext of the right length that
 * was tampered with or not made for this EK is NOT reported as an error:
 * it returns 0 with a shared secret that is pseudorandom, and that the peer
 * does not have.  The disagreement shows up later, eg as a failed MAC.
 */
LWS_VISIBLE LWS_EXTERN int
lws_genkem_decapsulate(struct lws_genkem_ctx *ctx, const uint8_t *ct,
		       size_t ct_len, uint8_t *ss);

/** lws_genkem_destroy() - Destroy a genkem
 *
 * \param ctx: your genkem context
 *
 * Wipes and frees any key material held by the ctx.  The ctx can then be
 * created again.
 */
LWS_VISIBLE LWS_EXTERN void
lws_genkem_destroy(struct lws_genkem_ctx *ctx);

/** lws_genkem_destroy_elements() - Wipe and free KEM key elements
 *
 * \param el: array of LWS_GENCRYPTO_KEM_KEYEL_COUNT key elements
 *
 * Frees the element buffers allocated by lws_genkem_new_keypair(), wiping
 * them first.
 */
LWS_VISIBLE LWS_EXTERN void
lws_genkem_destroy_elements(struct lws_gencrypto_keyelem *el);

#endif
///@}
