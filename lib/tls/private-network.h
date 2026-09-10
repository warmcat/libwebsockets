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
 *
 *  This is included from private-lib-core.h if LWS_WITH_TLS
 */

struct lws_context_per_thread;
struct lws_tls_ops {
	int (*fake_POLLIN_for_buffered)(struct lws_context_per_thread *pt);
	void (*process_cleanup)(void);
};

#if defined(LWS_WITH_TLS_JIT_TRUST)
/*
 * JIT Trust creates client vhosts of its own, long after the app's creation
 * info went out of scope.  Without a copy of the app's client-side TLS
 * hardening, those vhosts would silently come up with library-default protocol
 * versions and ciphers, and without the app's client cert... ie, a remote
 * server could downgrade the client's policy just by presenting a chain we
 * have to JIT-trust.  So we keep the client-side parts of the info here.
 *
 * These are all pointers into the app's own creation info, which lws already
 * treats as having context lifetime (eg, .protocols).
 */
struct lws_tls_client_policy {
	const char	*alpn;
	const char	*cipher_list;
	const char	*ciphers_iana;
	const char	*tls_1_3_plus_cipher_list;
	const char	*ecdh_curve;
	const char	*cert_filepath;
	const char	*private_key_filepath;
	long		options_set;
	long		options_clear;
	char		captured;
};
#endif

struct lws_context_tls {
	char alpn_discovered[32];
	const char *alpn_default;
	time_t last_cert_check_s;
	struct lws_dll2_owner cc_owner;
	int count_client_contexts;
#if defined(LWS_WITH_TLS_JIT_TRUST)
	struct lws_tls_client_policy jit_client_policy;
#endif
};

struct lws_pt_tls {
	struct lws_dll2_owner dll_pending_tls_owner;
};

struct lws_tls_ss_pieces;

struct alpn_ctx {
	uint8_t data[23];
	uint8_t len;
};

struct lws_tls_ctx_ref {
	lws_dll2_t list;
	struct lws_vhost *vh;
	lws_tls_ctx *ctx;
	int refcount;
};

/*
 * Length of the digest that stands in for "which CA store is this", see
 * lws_tls_vhost_set_client_ca_id()
 */

#define LWS_TLS_CA_ID_LEN 8

struct lws_vhost_tls {
	lws_tls_ctx *ssl_ctx;
	struct lws_tls_ctx_ref *active_ctx_ref;
	lws_dll2_owner_t retired_ctx_list;

	lws_tls_ctx *ssl_client_ctx;
	struct lws_tls_client_reuse *tcr;
	const char *alpn;
	struct lws_tls_ss_pieces *ss; /* for acme tls certs */
	char *cfg_alloc_cert_path;
	char *cfg_key_path;
	char *cfg_ssl_cipher_list;
	char *cfg_tls1_3_plus_cipher_list;
	char *cfg_tls_client_cipher_list;
	char *cfg_tls_ciphers_iana;
	char *cfg_ssl_ca_filepath;
	char *cfg_ecdh_curve;
#if defined(LWS_WITH_CLIENT)
	char *cfg_client_ecdh_curve;
#endif
	const void *cfg_server_ssl_cert_mem;
	unsigned int cfg_server_ssl_cert_mem_len;
	const void *cfg_server_ssl_privkey_mem;
	unsigned int cfg_server_ssl_privkey_mem_len;
	const void *cfg_server_ssl_ca_mem;
	unsigned int cfg_server_ssl_ca_mem_len;
#if defined(LWS_WITH_CLIENT)
	/*
	 * the client-side file paths have to be kept around as well as the
	 * in-memory blobs, so a client ctx that is only created lazily (at the
	 * first client connection on a vhost that was made without client tls
	 * init) can still apply the vhost's pinned CA and mTLS cert + key
	 */
	char *cfg_client_ssl_ca_filepath;
	char *cfg_client_ssl_cert_filepath;
	char *cfg_client_ssl_private_key_filepath;
	const void *cfg_client_ssl_ca_mem;
	unsigned int cfg_client_ssl_ca_mem_len;
	const void *cfg_client_ssl_cert_mem;
	unsigned int cfg_client_ssl_cert_mem_len;
	const void *cfg_client_ssl_key_mem;
	unsigned int cfg_client_ssl_key_mem_len;
#endif
	long ssl_options_set;
	long ssl_options_clear;
#if defined(LWS_WITH_MBEDTLS)
	lws_tls_x509 *x509_client_CA;
#endif
	struct alpn_ctx alpn_ctx;

	/*
	 * Identity of the CA store this vhost verifies *client* certificates
	 * against, derived once from its client CA config (see
	 * lws_tls_vhost_set_client_ca_id()).  All-zero means the vhost has no
	 * client CA of its own.
	 */
	uint8_t client_ca_id[LWS_TLS_CA_ID_LEN];

	int use_ssl;
	int allow_non_ssl_on_ssl_port;
	int ssl_info_event_mask;

#if defined(LWS_WITH_MBEDTLS) || defined(LWS_WITH_BEARSSL) || defined(LWS_WITH_GNUTLS)
	uint32_t tls_session_cache_ttl;
#endif

#if defined(LWS_WITH_GNUTLS)
	struct gnutls_anti_replay_st *anti_replay;
	void *anti_replay_owner;
#endif

	unsigned int user_supplied_ssl_ctx:1;
	unsigned int skipped_certs:1;
};

struct lws_lws_tls {
	lws_tls_conn		*ssl;
	struct lws_tls_ctx_ref  *ctx_ref;
	lws_tls_bio		*client_bio;
#if defined(LWS_TLS_SYNTHESIZE_CB)
	lws_sorted_usec_list_t	sul_cb_synth;
#endif
#if !defined(LWS_WITH_MBEDTLS) && defined(LWS_WITH_TLS_JIT_TRUST)
	/* mbedtls has this in the wrapper, since no wsi ptr at validation */
	lws_tls_kid_chain_t	kid_chain;
#endif
	struct lws_dll2		dll_pending_tls;
	char			err_helper[64];

	uint8_t			*quic_tp_recv;
	size_t			quic_tp_recv_len;
	const uint8_t		*quic_tp_send;
	size_t			quic_tp_send_len;
	lws_tls_quic_secret_cb	quic_secret_cb;
	int			quic_alert;
	uint8_t			quic_aead; /* enum lws_tls_quic_aead, set by the
					    * TLS backend from the negotiated
					    * TLS 1.3 cipher suite */

	/*
	 * Which vhost's client-cert CA store did this connection's peer
	 * certificate actually get verified against?  Recorded as that
	 * vhost's client_ca_id rather than a vhost pointer, so it stays
	 * meaningful if the vhost is destroyed while the connection lives on.
	 *
	 * A later rebind (Host:, :authority) onto a vhost that requires a
	 * valid client cert is only allowed if that vhost's client CA store
	 * is the same one, ie, a cert verified under vhost A's CA does not
	 * satisfy vhost B's mTLS requirement under a different CA (C-318).
	 */
	uint8_t			hs_ca_id[LWS_TLS_CA_ID_LEN];

	unsigned int		use_ssl;
	unsigned int		redirect_to_https:1;
	unsigned int		ssl_accept_in_bg:1;
	unsigned int		hs_ca_id_valid:1;
	/* the SNI callback bound us to the vhost serving the handshake */
	unsigned int		sni_vh_bound:1;
};


void
lws_tls_vhost_set_client_ca_id(struct lws_vhost *vh);

void
lws_tls_wsi_record_hs_ca(struct lws *wsi, struct lws_vhost *vh);

void
lws_context_init_alpn(struct lws_vhost *vhost);
#if defined(LWS_WITH_TCP_TLS)
int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len);
int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len);
int LWS_WARN_UNUSED_RESULT
lws_ssl_pending(struct lws *wsi);
#else
#define lws_ssl_capable_read lws_ssl_capable_read_no_ssl
#define lws_ssl_capable_write lws_ssl_capable_write_no_ssl
#define lws_ssl_pending lws_ssl_pending_no_ssl
#endif

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_TCP_TLS)
int LWS_WARN_UNUSED_RESULT
lws_server_socket_service_ssl(struct lws *new_wsi, lws_sockfd_type accept_fd,
				char is_pollin);
#else
#define lws_server_socket_service_ssl(_a, _b, _c) (0)
#endif

void
lws_sess_cache_synth_cb(lws_sorted_usec_list_t *sul);

int
lws_ssl_close(struct lws *wsi);
void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost);
void
lws_ssl_context_destroy(struct lws_context *context);
void
__lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi);
LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi);
int
lws_ssl_client_bio_create(struct lws *wsi);

#if defined(LWS_WITH_TCP_TLS)
int
lws_ssl_client_connect2(struct lws *wsi, char *errbuf, size_t len);
#else
#define lws_ssl_client_connect2(_a, _b, _c) (-1)
#endif
int
lws_tls_fake_POLLIN_for_buffered(struct lws_context_per_thread *pt);
int
lws_gate_accepts(struct lws_context *context, int on);
void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, int is_client,
			const struct lws_context_creation_info *info);
void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret);
int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len);
enum lws_tls_extant
lws_tls_generic_cert_checks(struct lws_vhost *vhost, const char *cert,
			    const char *private_key);
#if defined(LWS_WITH_SERVER)
 int
 lws_context_init_server_ssl(const struct lws_context_creation_info *info,
			     struct lws_vhost *vhost);
 void
 lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost);
#else
 #define lws_context_init_server_ssl(_a, _b) (0)
 #define lws_tls_acme_sni_cert_destroy(_a)
#endif

void
lws_ssl_destroy(struct lws_vhost *vhost);

/*
* lws_tls_ abstract backend implementations
*/

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh);
int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost, struct lws *wsi);
int
lws_tls_vhost_backend_create_ctx(struct lws_vhost *vhost);

void
lws_tls_vhost_backend_free_ctx(lws_tls_ctx *ctx);

struct lws_tls_ctx_ref *
lws_tls_ctx_ref_create(struct lws_vhost *vh, lws_tls_ctx *ctx);

struct lws_tls_ctx_ref *
lws_tls_ctx_ref_get(struct lws_vhost *vh);

void
lws_tls_ctx_ref_unref(struct lws_tls_ctx_ref *ref);

void
lws_tls_ctx_ref_destroy_all(struct lws_vhost *vhost);
int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd);

#if defined(LWS_WITH_SERVER)
enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi);
int
lws_tls_server_accept_completed(struct lws *wsi, int n);
enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi);
#else
#define lws_tls_server_accept(_a) (0)
#define lws_tls_server_accept_completed(_a, _b) (0)
#define lws_tls_server_abort_connection(_a) (0)
#endif

#if defined(LWS_WITH_SERVER)

/*
 * Server-side SNI for the backends whose TLS library gives us no servername
 * callback in time to change the certificate, the client-cert policy and the
 * ALPN list (BearSSL, Schannel): they read the name out of the ClientHello
 * themselves before handing the first record over.  See the block comment at
 * the top of lib/tls/tls-server.c.
 */

enum {
	LWS_TLS_CH_SNI_BAD	= -1, /* a server_name we will not act on */
	LWS_TLS_CH_SNI_MORE	=  0, /* not enough of the ClientHello yet */
	LWS_TLS_CH_SNI_NONE	=  1, /* no SNI: keep the accepting vhost */
	LWS_TLS_CH_SNI_FOUND	=  2  /* the name is in \p name */
};

int
lws_tls_client_hello_sni(const uint8_t *buf, size_t len, char *name,
			 size_t name_len);

void
lws_tls_server_send_alert(struct lws *wsi, const uint8_t *ver, uint8_t desc);

/* RFC 6066 unrecognized_name */
#define LWS_TLS_ALERT_UNRECOGNIZED_NAME 112

int
lws_tls_server_sni_select(struct lws *wsi, const char *servername);

#endif

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi);

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len);
int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
			    const struct lws_context_creation_info *info,
			    const char *cipher_list,
			    const char *ca_filepath,
			    const void *ca_mem,
			    unsigned int ca_mem_len,
			    const char *cert_filepath,
			    const void *cert_mem,
			    unsigned int cert_mem_len,
			    const char *private_key_filepath,
			    const void *key_mem,
			    unsigned int key_mem_len);


lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi);
int
lws_ssl_get_error(struct lws *wsi, int n);

int
lws_context_init_client_ssl(const struct lws_context_creation_info *info,
		    struct lws_vhost *vhost);

void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret);

int
lws_tls_fake_POLLIN_for_buffered(struct lws_context_per_thread *pt);
