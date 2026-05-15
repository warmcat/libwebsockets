/*
 * ChaCha and Poly1305 implementations have been moved to lws core.
 * This file now only contains the SSH specific wrappers.
 */

#include <libwebsockets.h>
#include "lws-ssh.h"
#include <string.h>
#include <stdlib.h>

struct lws_cipher_chacha {
	struct lws_chacha_ctx ccctx[2];
};

#define K_1(_keys) &((struct lws_cipher_chacha *)_keys->cipher)->ccctx[0]
#define K_2(_keys) &((struct lws_cipher_chacha *)_keys->cipher)->ccctx[1]

int
lws_chacha_activate(struct lws_ssh_keys *keys)
{
	if (keys->cipher) {
		free(keys->cipher);
		keys->cipher = NULL;
	}

	keys->cipher = malloc(sizeof(struct lws_cipher_chacha));
	if (!keys->cipher)
		return 1;

	memset(keys->cipher, 0, sizeof(struct lws_cipher_chacha));

	/* uses 2 x 256-bit keys, so 512 bits (64 bytes) needed */
	lws_chacha_keysetup(K_2(keys), keys->key[SSH_KEYIDX_ENC], 256);
	lws_chacha_keysetup(K_1(keys), &keys->key[SSH_KEYIDX_ENC][32], 256);

	keys->valid = 1;
	keys->full_length = 1;
	keys->padding_alignment = 8; // CHACHA_BLOCKLEN;
	keys->MAC_length = POLY1305_TAGLEN;

	return 0;
}

void
lws_chacha_destroy(struct lws_ssh_keys *keys)
{
	if (keys->cipher) {
		free(keys->cipher);
		keys->cipher = NULL;
	}
}

uint32_t
lws_chachapoly_get_length(struct lws_ssh_keys *keys, uint32_t seq,
			  const uint8_t *in4)
{
        uint8_t buf[4], seqbuf[8];

	/*
	 * When receiving a packet, the length must be decrypted first.  When 4
	 * bytes of ciphertext length have been received, they may be decrypted
	 * using the K_1 key, a nonce consisting of the packet sequence number
	 * encoded as a uint64 under the usual SSH wire encoding and a zero
	 * block counter to obtain the plaintext length.
	 */
        POKE_U64(seqbuf, seq);
	lws_chacha_ivsetup(K_1(keys), seqbuf, NULL);
        lws_chacha_encrypt_bytes(K_1(keys), in4, buf, 4);

	return PEEK_U32(buf);
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct lws_ssh_keys *keys, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
        u_char seqbuf[8];
        const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
        u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
        int r = 1;

        /*
         * Run ChaCha20 once to generate the Poly1305 key. The IV is the
         * packet sequence number.
         */
        memset(poly_key, 0, sizeof(poly_key));
        POKE_U64(seqbuf, seqnr);
        lws_chacha_ivsetup(K_2(keys), seqbuf, NULL);
        lws_chacha_encrypt_bytes(K_2(keys),
            poly_key, poly_key, sizeof(poly_key));

        /* If decrypting, check tag before anything else */
        if (!do_encrypt) {
                const u_char *tag = src + aadlen + len;

                lws_poly1305_auth(expected_tag, src, aadlen + len, poly_key);
                if (lws_timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN)) {
                        r = 2;
                        goto out;
                }
        }

        /* Crypt additional data */
        if (aadlen) {
                lws_chacha_ivsetup(K_1(keys), seqbuf, NULL);
                lws_chacha_encrypt_bytes(K_1(keys), src, dest, aadlen);
        }

        /* Set Chacha's block counter to 1 */
        lws_chacha_ivsetup(K_2(keys), seqbuf, one);
        lws_chacha_encrypt_bytes(K_2(keys), src + aadlen, dest + aadlen, len);

        /* If encrypting, calculate and append tag */
        if (do_encrypt) {
                lws_poly1305_auth(dest + aadlen + len, dest, aadlen + len,
                    poly_key);
        }
        r = 0;
 out:
        lws_explicit_bzero(expected_tag, sizeof(expected_tag));
        lws_explicit_bzero(seqbuf, sizeof(seqbuf));
        lws_explicit_bzero(poly_key, sizeof(poly_key));
        return r;
}

int
lws_chacha_decrypt(struct lws_ssh_keys *keys, uint32_t seq,
		   const uint8_t *ct, uint32_t len, uint8_t *pt)
{
	return chachapoly_crypt(keys, seq, pt, ct, len - POLY1305_TAGLEN - 4, 4,
			 POLY1305_TAGLEN, 0);
}

int
lws_chacha_encrypt(struct lws_ssh_keys *keys, uint32_t seq,
		   const uint8_t *ct, uint32_t len, uint8_t *pt)
{
	return chachapoly_crypt(keys, seq, pt, ct, len - 4, 4, 0, 1);
}
