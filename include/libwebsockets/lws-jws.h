/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/*! \defgroup jws JSON Web Signature
 * ## JSON Web Signature API
 *
 * Lws provides an API to check and create RFC7515 JSON Web Signatures
 *
 * SHA256/384/512 HMAC, and RSA 256/384/512 are supported.
 *
 * The API uses your TLS library crypto, but works exactly the same no matter
 * what your TLS backend is.
 */
///@{

/*
 * The maps are built to work with both JWS (LJWS_) and JWE (LJWE_), and are
 * sized to the slightly larger JWE case.
 */

enum enum_jws_sig_elements {

	/* JWS block namespace */
	LJWS_JOSE,
	LJWS_PYLD,
	LJWS_SIG,
	LJWS_UHDR,

	/* JWE block namespace */
	LJWE_JOSE = 0,
	LJWE_EKEY,
	LJWE_IV,
	LJWE_CTXT,
	LJWE_ATAG,
	LJWE_AAD,

	LWS_JWS_MAX_COMPACT_BLOCKS
};

struct lws_jws_map {
	const char *buf[LWS_JWS_MAX_COMPACT_BLOCKS];
	uint32_t len[LWS_JWS_MAX_COMPACT_BLOCKS];
};

#define LWS_JWS_MAX_SIGS 3

struct lws_jws {
	struct lws_jwk *jwk; /* the struct lws_jwk containing the signing key */
	struct lws_context *context; /* the lws context (used to get random) */
	struct lws_jws_map map, map_b64;
};

/* jws EC signatures do not have ASN.1 in them, meaning they're incompatible
 * with generic signatures.
 */

/**
 * lws_jws_init() - initialize a jws for use
 *
 * \param jws: pointer to the jws to initialize
 * \param jwk: the jwk to use with this jws
 * \param context: the lws_context to use
 */
LWS_VISIBLE LWS_EXTERN void
lws_jws_init(struct lws_jws *jws, struct lws_jwk *jwk,
	     struct lws_context *context);

/**
 * lws_jws_destroy() - scrub a jws
 *
 * \param jws: pointer to the jws to destroy
 *
 * Call before the jws goes out of scope.
 *
 * Elements defined in the jws are zeroed.
 */
LWS_VISIBLE LWS_EXTERN void
lws_jws_destroy(struct lws_jws *jws);

/**
 * lws_jws_sig_confirm_compact() - check signature
 *
 * \param map: pointers and lengths for each of the unencoded JWS elements
 * \param jwk: public key
 * \param context: lws_context
 * \param temp: scratchpad
 * \param temp_len: length of scratchpad
 *
 * Confirms the signature on a JWS.  Use if you have non-b64 plain JWS elements
 * in a map... it'll make a temp b64 version needed for comparison.  See below
 * for other variants.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact(struct lws_jws_map *map, struct lws_jwk *jwk,
			    struct lws_context *context,
			    char *temp, int *temp_len);

LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact_b64_map(struct lws_jws_map *map_b64,
				    struct lws_jwk *jwk,
			            struct lws_context *context,
			            char *temp, int *temp_len);

/**
 * lws_jws_sig_confirm_compact_b64() - check signature on b64 compact JWS
 *
 * \param in: pointer to b64 jose.payload[.hdr].sig
 * \param len: bytes available at \p in
 * \param map: map to take decoded non-b64 content
 * \param jwk: public key
 * \param context: lws_context
 * \param temp: scratchpad
 * \param temp_len: size of scratchpad
 *
 * Confirms the signature on a JWS.  Use if you have you have b64 compact layout
 * (jose.payload.hdr.sig) as an aggregated string... it'll make a temp plain
 * version needed for comparison.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact_b64(const char *in, size_t len,
				struct lws_jws_map *map,
				struct lws_jwk *jwk,
				struct lws_context *context,
				char *temp, int *temp_len);

/**
 * lws_jws_sig_confirm() - check signature on plain + b64 JWS elements
 *
 * \param map_b64: pointers and lengths for each of the b64-encoded JWS elements
 * \param map: pointers and lengths for each of the unencoded JWS elements
 * \param jwk: public key
 * \param context: lws_context
 *
 * Confirms the signature on a JWS.  Use if you have you already have both b64
 * compact layout (jose.payload.hdr.sig) and decoded JWS elements in maps.
 *
 * If you had the b64 string and called lws_jws_compact_decode() on it, you
 * will end up with both maps, and can use this api version, saving needlessly
 * regenerating any temp map.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm(struct lws_jws_map *map_b64, /* b64-encoded */
		    struct lws_jws_map *map,	/* non-b64 */
		    struct lws_jwk *jwk, struct lws_context *context);

/**
 * lws_jws_sign_from_b64() - add b64 sig to b64 hdr + payload
 *
 * \param jose: jose header information
 * \param jws: information to include in the signature
 * \param b64_sig: output buffer for b64 signature
 * \param sig_len: size of \p b64_sig output buffer
 *
 * This adds a b64-coded JWS signature of the b64-encoded protected header
 * and b64-encoded payload, at \p b64_sig.  The signature will be as large
 * as the N element of the RSA key when the RSA key is used, eg, 512 bytes for
 * a 4096-bit key, and then b64-encoding on top.
 *
 * In some special cases, there is only payload to sign and no header, in that
 * case \p b64_hdr may be NULL, and only the payload will be hashed before
 * signing.
 *
 * Returns the length of the encoded signature written to \p b64_sig, or -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sign_from_b64(struct lws_jose *jose, struct lws_jws *jws, char *b64_sig,
			size_t sig_len);

/**
 * lws_jws_compact_decode() - converts and maps compact serialization b64 sections
 *
 * \param in: the incoming compact serialized b64
 * \param len: the length of the incoming compact serialized b64
 * \param map: pointer to the results structure
 * \param map_b64: NULL, or pointer to a second results structure taking block
 *		   information about the undecoded b64
 * \param out: buffer to hold decoded results
 * \param out_len: size of out in bytes
 *
 * Returns number of sections (2 if "none", else 3), or -1 if illegal.
 *
 * map is set to point to the start and hold the length of each decoded block.
 * If map_b64 is non-NULL, then it's set with information about the input b64
 * blocks.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_compact_decode(const char *in, int len, struct lws_jws_map *map,
		struct lws_jws_map *map_b64, char *out, int *out_len);

LWS_VISIBLE LWS_EXTERN int
lws_jws_compact_encode(struct lws_jws_map *map_b64, /* b64-encoded */
		       const struct lws_jws_map *map,	/* non-b64 */
		       char *buf, int *out_len);

LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_json(const char *in, size_t len,
			 struct lws_jws *jws, struct lws_jwk *jwk,
			 struct lws_context *context,
			 char *temp, int *temp_len);

/**
 * lws_jws_write_flattened_json() - create flattened JSON sig
 *
 * \param jws: information to include in the signature
 * \param flattened: output buffer for JSON
 * \param len: size of \p flattened output buffer
 *
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_write_flattened_json(struct lws_jws *jws, char *flattened, size_t len);

/**
 * lws_jws_write_compact() - create flattened JSON sig
 *
 * \param jws: information to include in the signature
 * \param compact: output buffer for compact format
 * \param len: size of \p flattened output buffer
 *
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_write_compact(struct lws_jws *jws, char *compact, size_t len);



/*
 * below apis are not normally needed if dealing with whole JWS... they're
 * useful for creating from scratch
 */


/**
 * lws_jws_dup_element() - allocate space for an element and copy data into it
 *
 * \param map: map to create the element in
 * \param idx: index of element in the map to create
 * \param temp: space to allocate in
 * \param temp_len: available space at temp
 * \param in: data to duplicate into element
 * \param in_len: length of data to duplicate
 * \param actual_alloc: 0 for same as in_len, else actual allocation size
 *
 * Copies in_len from in to temp, if temp_len is sufficient.
 *
 * Returns 0 or -1 if not enough space in temp / temp_len.
 *
 * Over-allocation can be acheived by setting actual_alloc to the real
 * allocation desired... in_len will be copied into it.
 *
 * *temp_len is reduced by actual_alloc if successful.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_dup_element(struct lws_jws_map *map, int idx,
		    char *temp, int *temp_len, const void *in, size_t in_len,
		    size_t actual_alloc);

/**
 * lws_jws_randomize_element() - create an element and fill with random
 *
 * \param context: lws_context used for random
 * \param map: map to create the element in
 * \param idx: index of element in the map to create
 * \param temp: space to allocate in
 * \param temp_len: available space at temp
 * \param random_len: length of data to fill with random
 * \param actual_alloc: 0 for same as random_len, else actual allocation size
 *
 * Randomize random_len bytes at temp, if temp_len is sufficient.
 *
 * Returns 0 or -1 if not enough space in temp / temp_len.
 *
 * Over-allocation can be acheived by setting actual_alloc to the real
 * allocation desired... the first random_len will be filled with random.
 *
 * *temp_len is reduced by actual_alloc if successful.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_randomize_element(struct lws_context *context,
			  struct lws_jws_map *map,
			  int idx, char *temp, int *temp_len, size_t random_len,
			  size_t actual_alloc);

/**
 * lws_jws_alloc_element() - create an element and reserve space for content
 *
 * \param map: map to create the element in
 * \param idx: index of element in the map to create
 * \param temp: space to allocate in
 * \param temp_len: available space at temp
 * \param len: logical length of element
 * \param actual_alloc: 0 for same as len, else actual allocation size
 *
 * Allocate len bytes at temp, if temp_len is sufficient.
 *
 * Returns 0 or -1 if not enough space in temp / temp_len.
 *
 * Over-allocation can be acheived by setting actual_alloc to the real
 * allocation desired... the element logical length will be set to len.
 *
 * *temp_len is reduced by actual_alloc if successful.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_alloc_element(struct lws_jws_map *map, int idx, char *temp,
		      int *temp_len, size_t len, size_t actual_alloc);

/**
 * lws_jws_encode_b64_element() - create an b64-encoded element
 *
 * \param map: map to create the element in
 * \param idx: index of element in the map to create
 * \param temp: space to allocate in
 * \param temp_len: available space at temp
 * \param in: pointer to unencoded input
 * \param in_len: length of unencoded input
 *
 * Allocate len bytes at temp, if temp_len is sufficient.
 *
 * Returns 0 or -1 if not enough space in temp / temp_len.
 *
 * Over-allocation can be acheived by setting actual_alloc to the real
 * allocation desired... the element logical length will be set to len.
 *
 * *temp_len is reduced by actual_alloc if successful.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_encode_b64_element(struct lws_jws_map *map, int idx,
			   char *temp, int *temp_len, const void *in,
			   size_t in_len);


/**
 * lws_jws_b64_compact_map() - find block starts and lengths in compact b64
 *
 * \param in: pointer to b64 jose.payload[.hdr].sig
 * \param len: bytes available at \p in
 * \param map: output struct with pointers and lengths for each JWS element
 *
 * Scans a jose.payload[.hdr].sig b64 string and notes where the blocks start
 * and their length into \p map.
 *
 * Returns number of blocks if OK.  May return <0 if malformed.
 * May not fill all map entries.
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_b64_compact_map(const char *in, int len, struct lws_jws_map *map);


/**
 * lws_jws_base64_enc() - encode input data into b64url data
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param out: the buffer to store the b64url encoded data to
 * \param out_max: the length of \p out in bytes
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);

/**
 * lws_jws_encode_section() - encode input data into b64url data,
 *				prepending . if not first
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param first: nonzero if the first section
 * \param p: the buffer to store the b64url encoded data to
 * \param end: just past the end of p
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 * If the section is not the first one, '.' is prepended.
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_encode_section(const char *in, size_t in_len, int first, char **p,
		       char *end);
///@}
