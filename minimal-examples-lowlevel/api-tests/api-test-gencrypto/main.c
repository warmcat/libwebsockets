#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

void print_hex(const char *name, const uint8_t *data, size_t len) {
    printf("%s:\n", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, const char **argv) {
    struct lws_context_creation_info info;
    struct lws_context *context;

    memset(&info, 0, sizeof info);
    lws_cmdline_option_handle_builtin(argc, argv, &info);
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    context = lws_create_context(&info);
    if (!context) {
        printf("FAILED to create context\n");
        return 1;
    }

    uint8_t dcid[] = {0xB3, 0xA6, 0xDB, 0x3C, 0x87, 0x0C, 0x3E, 0x99};
    uint8_t salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

    uint8_t initial_secret[32];
    lws_genhkdf_extract(LWS_GENHMAC_TYPE_SHA256, salt, sizeof(salt), dcid, sizeof(dcid), initial_secret);
    print_hex("initial_secret", initial_secret, 32);

    uint8_t client_secret[32];
    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, initial_secret, 32, "client in", NULL, 0, client_secret, 32);
    print_hex("client_secret", client_secret, 32);

    uint8_t quic_key[16];
    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client_secret, 32, "quic key", NULL, 0, quic_key, 16);
    print_hex("quic_key", quic_key, 16);

    uint8_t quic_iv[12];
    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client_secret, 32, "quic iv", NULL, 0, quic_iv, 12);
    print_hex("quic_iv", quic_iv, 12);

    uint8_t quic_hp[16];
    lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, client_secret, 32, "quic hp", NULL, 0, quic_hp, 16);
    print_hex("quic_hp", quic_hp, 16);

    uint8_t header[] = {0xC1, 0x00, 0x00, 0x00, 0x01, 0x08, 0xB3, 0xA6, 0xDB, 0x3C, 0x87, 0x0C, 0x3E, 0x99, 0x08, 0x24, 0x5E, 0x0D, 0x1C, 0x06, 0xB7, 0x47, 0xDE, 0x00, 0x44, 0x96, 0x00, 0x00};
    uint8_t payload[1156];
    memset(payload, 0, sizeof(payload));

    // Copy the actual unencrypted ClientHello prefix
    uint8_t ch[] = {0x06, 0x00, 0x41, 0xA3, 0x01, 0x00, 0x01, 0x9F, 0x03, 0x03, 0x41, 0x00, 0x3D, 0x5D, 0x35, 0x60, 0x02, 0xA4, 0x04, 0x21, 0xFF, 0xEA, 0x95, 0x82, 0xA0, 0xDF, 0xC0, 0x68, 0x16, 0xCB, 0x26, 0x8E, 0xF3, 0x5A, 0xE5, 0xA3, 0xE5, 0x6C, 0xED, 0xA7, 0x5A, 0x62, 0x00, 0x00, 0x04, 0x13, 0x02, 0x13, 0x01, 0x01, 0x00, 0x01, 0x72, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x6C, 0x69, 0x62, 0x77, 0x65, 0x62, 0x73, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x73, 0x2E, 0x6F, 0x72, 0x67};
    memcpy(payload, ch, sizeof(ch));

    uint64_t full_pn = 0;
    uint8_t nonce[12];
    memcpy(nonce, quic_iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)(full_pn >> (i * 8));
    }

    struct lws_genaes_ctx aead;
    struct lws_gencrypto_keyelem el;
    el.buf = quic_key;
    el.len = 16;
    lws_genaes_create(&aead, LWS_GAESO_ENC, LWS_GAESM_GCM, &el, LWS_GAESP_NO_PADDING, NULL);

    uint8_t tag[16];
    size_t iv_len = 12;
    lws_genaes_crypt(&aead, header, sizeof(header), NULL, nonce, tag, &iv_len, 16);

    uint8_t ciphertext[1156];
    lws_genaes_crypt(&aead, payload, sizeof(payload), ciphertext, NULL, NULL, NULL, 16);
    lws_genaes_destroy(&aead, tag, 16);

    uint8_t encrypted_packet[1200];
    memcpy(encrypted_packet, header, sizeof(header));
    memcpy(encrypted_packet + sizeof(header), ciphertext, sizeof(ciphertext));
    memcpy(encrypted_packet + sizeof(header) + sizeof(ciphertext), tag, 16);

    print_hex("Encrypted packet before HP", encrypted_packet, 48);

    uint8_t sample[16];
    memcpy(sample, encrypted_packet + 26 + 4, 16);

    struct lws_genaes_ctx hp;
    el.buf = quic_hp;
    el.len = 16;
    lws_genaes_create(&hp, LWS_GAESO_ENC, LWS_GAESM_ECB, &el, LWS_GAESP_NO_PADDING, NULL);

    uint8_t mask[16];
    size_t zero = 0;
    lws_genaes_crypt(&hp, sample, 16, mask, NULL, NULL, &zero, 16);
    lws_genaes_destroy(&hp, NULL, 0);

    encrypted_packet[0] ^= mask[0] & 0x0f;
    encrypted_packet[26] ^= mask[1];
    encrypted_packet[27] ^= mask[2];

    print_hex("Encrypted packet after HP", encrypted_packet, 48);

    lws_context_destroy(context);
    return 0;
}
