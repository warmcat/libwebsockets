/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

// #define VERBOSE

typedef struct lws_cose_sig_alg {
	lws_dll2_t			list;
	const lws_cose_key_t		*cose_key;
	struct lws_genhash_ctx		hash_ctx;
	union {
		struct lws_genec_ctx	ecdsactx;
		struct lws_genrsa_ctx	rsactx;
		struct lws_genhmac_ctx	hmacctx;
	} u;
	cose_param_t			cose_alg;
	int				keybits;
} lws_cose_sig_alg_t;

struct lws_cose_sig_val_context {
	uint8_t				ph[4][96]; /* header cbor */
	uint8_t				mac[LWS_GENHASH_LARGEST];
	lws_dll2_owner_t		*ck_set;
	lws_dll2_owner_t		single_key_set;
	lws_dll2_owner_t		algs;
	lws_dll2_owner_t		results;
	lws_cose_sign_ext_pay_cb_t	ext_cb;
	void				*ex_opaque;
	uint8_t				*payload_stash;
	struct lwsac			*ac;
	struct lecp_ctx			ctx;
	struct lws_context		*cx;
	void				*user;

	size_t				ext_len;
	size_t				payload_pos;
	size_t				payload_stash_size;

	int				type;

	cose_param_t			alg;
	cose_param_t			inner_alg;
	struct lws_gencrypto_keyelem	kid;

	int				seen;
	int				depth;

	int				outer;
	int				ph_pos[4];
	size_t				mac_pos;

	cose_param_t			map_key;

	int				tli; /* toplevel item */

	uint8_t				sub;
	uint8_t				had_outer_alg;
};

lws_cose_sig_alg_t *
lws_cose_val_alg_create(struct lws_context *cx, lws_cose_key_t *ck,
		    cose_param_t cose_alg, int op);

int
lws_cose_val_alg_hash(lws_cose_sig_alg_t *alg, const uint8_t *in, size_t in_len);

void
lws_cose_val_alg_destroy(struct lws_cose_sig_val_context *cps,
		     lws_cose_sig_alg_t **_alg, const uint8_t *against,
		     size_t against_len);
