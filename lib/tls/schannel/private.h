#ifndef _LWS_TLS_SCHANNEL_PRIVATE_H_
#define _LWS_TLS_SCHANNEL_PRIVATE_H_

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <schannel.h>
#include <bcrypt.h>
#include <ncrypt.h>
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000130
#endif
#include <wincrypt.h>

typedef struct _LWS_TLS_PARAMETERS {
    DWORD cAlpnIds;
    void *rgstrAlpnIds;
    DWORD grbitDisabledProtocols;
    DWORD cDisabledCrypto;
    void *pDisabledCrypto;
    DWORD dwFlags;
} LWS_TLS_PARAMETERS;

typedef struct _LWS_SCH_CREDENTIALS {
    DWORD           dwVersion;
    DWORD           dwCredFormat;
    DWORD           cCreds;
    PCCERT_CONTEXT  *paCred;
    HCERTSTORE      hRootStore;
    DWORD           cMappers;
    void            **aphMappers;
    DWORD           dwSessionLifespan;
    DWORD           dwFlags;
    DWORD           cTlsParameters;
    LWS_TLS_PARAMETERS *pTlsParameters;
} LWS_SCH_CREDENTIALS;

#ifndef SECBUFFER_SEND_GENERIC_TLS_EXTENSION
#define SECBUFFER_SEND_GENERIC_TLS_EXTENSION 25
typedef struct _SEND_GENERIC_TLS_EXTENSION {
    WORD  ExtensionType;
    WORD  HandshakeType;
    DWORD Flags;
    WORD  BufferSize;
    UCHAR Buffer[1];
} SEND_GENERIC_TLS_EXTENSION, *PSEND_GENERIC_TLS_EXTENSION;
#endif

#ifndef SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION
#define SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION 26
typedef struct _TLS_EXTENSION_SUBSCRIPTION {
    WORD ExtensionType;
    WORD HandshakeType;
} TLS_EXTENSION_SUBSCRIPTION, *PTLS_EXTENSION_SUBSCRIPTION;
typedef struct _SUBSCRIBE_GENERIC_TLS_EXTENSION {
    DWORD Flags;
    DWORD SubscriptionsCount;
    TLS_EXTENSION_SUBSCRIPTION Subscriptions[1];
} SUBSCRIBE_GENERIC_TLS_EXTENSION, *PSUBSCRIBE_GENERIC_TLS_EXTENSION;
#endif

#ifndef SECBUFFER_APPLICATION_PROTOCOLS
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#endif

#ifndef SECBUFFER_TRAFFIC_SECRETS
#define SECBUFFER_TRAFFIC_SECRETS 28
#endif

#ifndef SEC_I_CONTINUE_NEEDED_MESSAGE_OK
#define SEC_I_CONTINUE_NEEDED_MESSAGE_OK 0x00090366L
#endif

#ifndef ISC_REQ_MESSAGES
#define ISC_REQ_MESSAGES 0x100000000ULL
#endif

/*
 * Our own copy of CERT_CHAIN_ENGINE_CONFIG: the SDK only declares the
 * hExclusiveRoot / dwExclusiveFlags members when NTDDI_VERSION is high
 * enough, and we decide which of the three documented sizes to ask for at
 * runtime rather than at build time
 */

typedef struct _LWS_CERT_CHAIN_ENGINE_CONFIG {
	DWORD		cbSize;
	HCERTSTORE	hRestrictedRoot;
	HCERTSTORE	hRestrictedTrust;
	HCERTSTORE	hRestrictedOther;
	DWORD		cAdditionalStore;
	HCERTSTORE	*rghAdditionalStore;
	DWORD		dwFlags;
	DWORD		dwUrlRetrievalTimeout;
	DWORD		MaximumCachedCertificates;
	DWORD		CycleDetectionModulus;
	HCERTSTORE	hExclusiveRoot;
	HCERTSTORE	hExclusiveTrustedPeople;
	DWORD		dwExclusiveFlags;
} LWS_CERT_CHAIN_ENGINE_CONFIG;

#ifndef CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG
#define CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG 0x1
#endif

struct lws_tls_schannel_ctx {
	CredHandle cred;
	HCERTSTORE store;
	/*
	 * When the app pinned a CA (ca_filepath / ca_mem, JIT trust, or the
	 * vhost CA used to check client certs), it goes in here and becomes
	 * the *exclusive* trust root via chain_engine... ie, the OS ROOT
	 * store stops being trusted for this vhost, which is what pinning
	 * means everywhere else in lws
	 */
	HCERTSTORE ca_store;
	HCERTCHAINENGINE chain_engine;
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
	/*
	 * Plaintext bytes the caller has not yet been told were written, but
	 * which are already encrypted into tx_buf: handed back for free once
	 * tx_buf has drained, so a record is never encrypted twice
	 */
	size_t tx_plain;

	/* Buffer for decrypted data pending read by user */
    struct lws_buflist *decrypted_list;

	int f_context_init; /* 1 if context initialized (handshake started) */
	int f_handshake_finished; /* 1 if handshake complete */
	unsigned int relax; /* LCCSCF_ALLOW_... bits that apply to this conn */
	int f_peer_cert_checked; /* 1 if we ran the peer cert check at all */
	int f_peer_cert_verified; /* 1 if it passed with no relaxation */
	int f_want_client_cert; /* server: we asked for a client certificate */
	int f_post_hs; /* feeding a TLS 1.3 post-handshake message to SSPI */

	/*
	 * The peer cert as it was when the handshake completed, so that a
	 * post-handshake exchange can be checked not to have changed it
	 */
	uint8_t *peer_der;
	size_t peer_der_len;

	char alpn[64];
    char hostname[128];
	int quic_secret_type_count[5];
	uint8_t quic_hs_secrets[2][48];
	size_t quic_hs_secrets_len[2];
};

struct lws_tls_schannel_x509 {
	PCCERT_CONTEXT cert;
};

/*
 * Add one DER CA to ctx->ca_store (creating it), and drop any chain engine
 * built from the old contents so it gets rebuilt with this CA included
 */
int
lws_tls_schannel_ca_add(struct lws_tls_schannel_ctx *ctx, const uint8_t *der,
			size_t der_len);

/*
 * The chain engine that has ctx->ca_store as its exclusive trust root, or
 * NULL (ie, the default engine, which trusts the OS ROOT store) when no CA
 * was pinned on this ctx
 */
HCERTCHAINENGINE
lws_tls_schannel_chain_engine(struct lws_tls_schannel_ctx *ctx);

void
lws_tls_schannel_ca_destroy(struct lws_tls_schannel_ctx *ctx);

/*
 * Confirm a peer certificate against the ctx's trust and the connection's
 * relaxation flags.  hostname NULL means "do not check the name" (ie, we are
 * checking a client certificate).  Returns 0 if the peer may be accepted.
 */
int
lws_tls_schannel_confirm_cert(struct lws_tls_schannel_ctx *ctx,
			      struct lws_tls_schannel_conn *conn,
			      PCCERT_CONTEXT pCert, const char *hostname,
			      char *ebuf, size_t ebuf_len);

/*
 * Server side: after a successful handshake on a vhost that asked for a
 * client certificate, fetch and check it.  Returns nonzero if the handshake
 * must be failed.
 */
int
lws_tls_schannel_server_client_cert(struct lws *wsi);

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
