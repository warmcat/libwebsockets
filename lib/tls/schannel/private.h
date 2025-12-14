#ifndef _LWS_TLS_SCHANNEL_PRIVATE_H_
#define _LWS_TLS_SCHANNEL_PRIVATE_H_

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <schannel.h>
#include <bcrypt.h>
#include <ncrypt.h>

struct lws_tls_schannel_ctx {
	CredHandle cred;
	HCERTSTORE store;
    union {
        HCRYPTPROV key_prov; /* CAPI */
        NCRYPT_KEY_HANDLE key_cng; /* CNG */
    } u;
    int key_type; /* 0 = CAPI, 1 = CNG */
	char key_container_name[64];
	int initialized;
};

struct lws_tls_schannel_conn {
	CtxtHandle ctxt;
	SecPkgContext_StreamSizes stream_sizes;

	/* Buffers for partial data */
	uint8_t *rx_buf;
	size_t rx_len;    /* Data currently in rx_buf */
	size_t rx_alloc;  /* Total allocated size of rx_buf */

	uint8_t *tx_buf; /* Pending data to be written to socket (e.g. handshake tokens OR encrypted app data) */
	size_t tx_len;
	size_t tx_pos;   /* How much we have written so far */

	/* Buffer for decrypted data pending read by user */
    struct lws_buflist *decrypted_list;

	int f_context_init; /* 1 if context initialized (handshake started) */
	int f_handshake_finished; /* 1 if handshake complete */
	int f_allow_self_signed;
	int f_socket_is_blocking; /* 1 if recv returned EWOULDBLOCK, so rx_buf might be incomplete */

	char alpn[64];
    char hostname[128];
};

struct lws_tls_schannel_x509 {
	PCCERT_CONTEXT cert;
};

/* Certificate loader prototype */
int
lws_tls_schannel_cert_info_load(struct lws_context *context,
                                const char *cert, const char *private_key,
                                const char *mem_cert, size_t len_mem_cert,
                                const char *mem_privkey, size_t mem_privkey_len,
                                PCCERT_CONTEXT *pcert, HCERTSTORE *phStore,
                                void **phKey, int *pKeyType,
                                const char *container_name);

#endif
