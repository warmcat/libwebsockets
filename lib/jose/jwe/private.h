/*
 * libwebsockets - JSON Web Encryption support
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
 *
 */
#define LWS_AESGCM_IV 12
#define LWS_AESGCM_TAG 16

/* jwe-rsa-aescbc.c */

int
lws_jwe_auth_and_decrypt_rsa_aes_cbc_hs(struct lws_jwe *jwe);


int
lws_jwe_encrypt_rsa_aes_cbc_hs(struct lws_jwe *jwe,
			       char *temp, int *temp_len);

int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jwe *jwe, uint8_t *enc_cek,
				uint8_t *aad, int aad_len);


/* jws-rsa-aesgcm.c */

int
lws_jwe_auth_and_decrypt_gcm(struct lws_jwe *jwe, uint8_t *enc_cek,
			     uint8_t *aad, int aad_len);

int
lws_jwe_auth_and_decrypt_rsa_aes_gcm(struct lws_jwe *jwe);

int
lws_jwe_encrypt_gcm(struct lws_jwe *jwe,
		    uint8_t *enc_cek, uint8_t *aad, int aad_len);

int
lws_jwe_encrypt_rsa_aes_gcm(struct lws_jwe *jwe,
			    char *temp, int *temp_len);




/* jwe-rsa-aeskw.c */

int
lws_jwe_encrypt_aeskw_cbc_hs(struct lws_jwe *jwe,
			     char *temp, int *temp_len);

int
lws_jwe_auth_and_decrypt_aeskw_cbc_hs(struct lws_jwe *jwe);

/* aescbc.c */

int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jwe *jwe, uint8_t *enc_cek,
				uint8_t *aad, int aad_len);

int
lws_jwe_encrypt_cbc_hs(struct lws_jwe *jwe,
		       uint8_t *cek, uint8_t *aad, int aad_len);

int
lws_jwe_auth_and_decrypt_ecdh_cbc_hs(struct lws_jwe *jwe,
		char *temp, int *temp_len);

int
lws_jwe_encrypt_ecdh_cbc_hs(struct lws_jwe *jwe,
		 	     char *temp, int *temp_len);
