
/* jwe-rsa-aescbc.c */

int
lws_jwe_encrypt_rsa_aes_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
			       char *temp, int *temp_len);

int
lws_jwe_auth_and_decrypt_cbc_hs(struct lws_jose *jose,
				struct lws_jws *jws, uint8_t *enc_cek,
				uint8_t *aad, int aad_len);

int
lws_jwe_auth_and_decrypt_rsa_aes_cbc_hs(struct lws_jose *jose,
					struct lws_jws *jws);

int
lws_jwe_encrypt_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
		       uint8_t *cek, uint8_t *aad, int aad_len);


/* jws-rsa-aesgcm.c */

int
lws_jwe_auth_and_decrypt_gcm(struct lws_jose *jose,
			     struct lws_jws *jws, uint8_t *enc_cek,
			     uint8_t *aad, int aad_len);

int
lws_jwe_auth_and_decrypt_rsa_aes_gcm(struct lws_jose *jose,
				     struct lws_jws *jws);

int
lws_jwe_encrypt_gcm(struct lws_jose *jose, struct lws_jws *jws,
		    uint8_t *enc_cek, uint8_t *aad, int aad_len);

int
lws_jwe_encrypt_rsa_aes_gcm(struct lws_jose *jose, struct lws_jws *jws,
			    char *temp, int *temp_len);


/* jwe-rsa-aeskw.c */

int
lws_jwe_encrypt_aeskw_cbc_hs(struct lws_jose *jose, struct lws_jws *jws,
			     char *temp, int *temp_len);

int
lws_jwe_auth_and_decrypt_aeskw_cbc_hs(struct lws_jose *jose,
				      struct lws_jws *jws);
