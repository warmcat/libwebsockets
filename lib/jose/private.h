/*
 * libwebsockets - jose private header
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
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
 */

void
lws_jwk_destroy_elements(struct lws_gencrypto_keyelem *el, int m);

void
lws_jwk_init_jps(struct lejp_ctx *jctx, struct lws_jwk_parse_state *jps,
		 struct lws_jwk *jwk, lws_jwk_key_import_callback cb,
		 void *user);

int
lws_jose_render(struct lws_jose *jose, struct lws_jwk *aux_jwk,
		char *out, size_t out_len);
