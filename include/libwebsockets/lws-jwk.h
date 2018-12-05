/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 */

/*! \defgroup jwk JSON Web Keys
 * ## JSON Web Keys API
 *
 * Lws provides an API to parse JSON Web Keys into a struct lws_gencrypto_keyelem.
 *
 * "oct" and "RSA" type keys are supported.  For "oct" keys, they are held in
 * the "e" member of the struct lws_gencrypto_keyelem.
 *
 * Keys elements are allocated on the heap.  You must destroy the allocations
 * in the struct lws_gencrypto_keyelem by calling
 * lws_genrsa_destroy_elements() when you are finished with it.
 */
///@{

enum enum_jwk_meta_tok {
	JWK_META_KTY,
	JWK_META_KID,
	JWK_META_USE,
	JWK_META_KEY_OPS,
	JWK_META_X5C,
	JWK_META_ALG,

	LWS_COUNT_JWK_ELEMENTS
};

struct lws_jwk {
	/* key data elements */
	struct lws_gencrypto_keyelem e[LWS_GENCRYPTO_MAX_KEYEL_COUNT];
	/* generic meta key elements, like KID */
	struct lws_gencrypto_keyelem meta[LWS_COUNT_JWK_ELEMENTS];
	int kty;			/**< one of LWS_JWK_ */
};

typedef int (*lws_jwk_key_import_callback)(struct lws_jwk *s, void *user);

/** lws_jwk_import() - Create a JSON Web key from the textual representation
 *
 * \param s: the JWK object to create
 * \param cb: callback for each jwk-processed key, or NULL if importing a single
 *	      key with no parent "keys" JSON
 * \param user: pointer to be passed to the callback, otherwise ignored by lws.
 *		NULL if importing a single key with no parent "keys" JSON
 * \param in: a single JWK JSON stanza in utf-8
 * \param len: the length of the JWK JSON stanza in bytes
 *
 * Creates an lws_jwk struct filled with data from the JSON representation.
 *
 * There are two ways to use this... with some protocols a single jwk is
 * delivered with no parent "keys": [] array.  If you call this with cb and
 * user as NULL, then the input will be interpreted like that and the results
 * placed in s.
 *
 * The second case is that you are dealing with a "keys":[] array with one or
 * more keys in it.  In this case, the function iterates through the keys using
 * s as a temporary jwk, and calls the user-provided callback for each key in
 * turn while it return 0 (nonzero return from the callback terminates the
 * iteration through any further keys).
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwk_import(struct lws_jwk *s, lws_jwk_key_import_callback cb, void *user,
	       const char *in, size_t len);

/** lws_jwk_destroy() - Destroy a JSON Web key
 *
 * \param s: the JWK object to destroy
 *
 * All allocations in the lws_jwk are destroyed
 */
LWS_VISIBLE LWS_EXTERN void
lws_jwk_destroy(struct lws_jwk *s);

/** lws_jwk_export() - Export a JSON Web key to a textual representation
 *
 * \param s: the JWK object to export
 * \param _private: 0 = just export public parts, 1 = export everything
 * \param p: the buffer to write the exported JWK to
 * \param len: the length of the buffer \p p in bytes
 *
 * Returns length of the used part of the buffer if OK, or -1 for error.
 *
 * Serializes the content of the JWK into a char buffer.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwk_export(struct lws_jwk *s, int _private, char *p, size_t len);

/** lws_jwk_load() - Import a JSON Web key from a file
 *
 * \param s: the JWK object to load into
 * \param filename: filename to load from
 *
 * Returns 0 for OK or -1 for failure
 *
 * There are two ways to use this... with some protocols a single jwk is
 * delivered with no parent "keys": [] array.  If you call this with cb and
 * user as NULL, then the input will be interpreted like that and the results
 * placed in s.
 *
 * The second case is that you are dealing with a "keys":[] array with one or
 * more keys in it.  In this case, the function iterates through the keys using
 * s as a temporary jwk, and calls the user-provided callback for each key in
 * turn while it return 0 (nonzero return from the callback terminates the
 * iteration through any further keys, leaving the last one in s).
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwk_load(struct lws_jwk *s, const char *filename,
	     lws_jwk_key_import_callback cb, void *user);

/** lws_jwk_save() - Export a JSON Web key to a file
 *
 * \param s: the JWK object to save from
 * \param filename: filename to save to
 *
 * Returns 0 for OK or -1 for failure
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwk_save(struct lws_jwk *s, const char *filename);

/** lws_jwk_rfc7638_fingerprint() - jwk to RFC7638 compliant fingerprint
 *
 * \param s: the JWK object to fingerprint
 * \param digest32: buffer to take 32-byte digest
 *
 * Returns 0 for OK or -1 for failure
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwk_rfc7638_fingerprint(struct lws_jwk *s, char *digest32);

LWS_VISIBLE LWS_EXTERN int
lws_jwk_dump(struct lws_jwk *s);
///@}
