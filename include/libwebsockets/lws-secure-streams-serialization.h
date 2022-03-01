/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
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
 * included from libwebsockets.h
 *
 * This defines the Serialized Secure Streams framing, and the optional
 * lws_transport_mux framing.
 *
 * APIs are declared for lws_transport and binding those to the SSPC and proxy
 * sides in lws.
 */

#if defined(STANDALONE)
struct lws_context_standalone;
#define lws_context lws_context_standalone
#endif

#define LWSSSS_VERSION 1

typedef enum {
	/*
	 * This is the Serialized Serure Streams framing.  It's sufficient to
	 * carry all SS API actions over a point-to-point bytestream between
	 * an SSPC client and an SS oroxy, in both directions.
	 *
	 * These serialized streams may be multiplexed by the transport (eg,
	 * for unix domain sockets transport, each SS opens its own UDS socket
	 * to the proxy) or via lws_transport_mux framing encapsulation.
	 *
	 *
	 * Framing for Proxy -> Client direction
	 */

	LWSSS_SER_RXPRE_RX_PAYLOAD				= 0x55,
	/*
	 * Proxied rx
	 *
	 *   -  0: LWSSS_SER_RXPRE_RX_PAYLOAD
	 *   -  1: 2 byte MSB-first rest-of-frame length
	 *   -  3: 4-byte MSB-first flags
	 *   -  7: 4-byte MSB-first us between inbound read and wrote to client
	 *   - 11: 8-byte MSB-first us resolution unix time proxy wrote to client
	 *   - 17: (rideshare name len + rideshare name if flags &
	 *   		LWSSS_FLAG_RIDESHARE) payload
	 */
	LWSSS_SER_RXPRE_CREATE_RESULT,
	/*
	 * Proxied connection setup result
	 *
	 *   -  0: LWSSS_SER_RXPRE_CREATE_RESULT
	 *   -  1: 2 byte MSB-first rest-of-frame length (usually 00, 03)
	 *   -  3: 1 byte result, 0 = success.  On failure, proxy will close
	 *   		connection.
	 *   -  4: 4 byte client dsh allocation recommended for stream type,
	 *   		from policy (introduced in SSSv1)
	 *   -  8: 2 byte MSB-first initial tx credit
	 *   - 10: if present, comma-sep list of rideshare types from policy
	 */
	LWSSS_SER_RXPRE_CONNSTATE,
	/*
	 * Proxied state (8 or 11 byte packet)
	 *
	 *   -  0: LWSSS_SER_RXPRE_CONNSTATE
	 *   -  1: 00, 05 if state < 256, else 00, 08
	 *   -  3: 1 byte state index if state < 256, else 4-byte MSB-first
	 *   		state index
	 *   -  4 or 7: 4-byte MSB-first ordinal
	 */
	LWSSS_SER_RXPRE_TXCR_UPDATE,
	/*
	 * Proxied tx credit
	 *
	 *   -  0: LWSSS_SER_RXPRE_TXCR_UPDATE
	 *   -  1: 00, 04
	 *   -  3: 4-byte MSB-first addition tx credit bytes
	 */
	LWSSS_SER_RXPRE_METADATA,
	/*
	 * Proxied rx metadata
	 *
	 *   -  0: LWSSS_SER_RXPRE_METADATA
	 *   -  1: 2-byte MSB-first rest-of-frame length
	 *   -  3: 1-byte metadata name length
	 *   -  4: metadata name
	 *   -  ...: metadata value (for rest of packet)
	 */
	LWSSS_SER_RXPRE_TLSNEG_ENCLAVE_SIGN,
	/* reserved */
	LWSSS_SER_RXPRE_PERF,
	/*
	 * Proxied performance information
	 *
	 *   -  0: LWSSS_SER_RXPRE_PERF
	 *   -  1: 2-byte MSB-first rest-of-frame length
	 *   -  3: ... performance JSON (for rest of packet)
	 */

	/*
	 * Framing for Client -> Proxy direction
	 */

	LWSSS_SER_TXPRE_STREAMTYPE				= 0xaa,
	/*
	 * Proxied connection setup
	 *
	 *   -  0: LWSSS_SER_TXPRE_STREAMTYPE
	 *   -  1: 2-byte MSB-first rest-of-frame length
	 *   -  3: 1-byte Client SSS protocol version (introduced in SSSv1)
	 *   -  4: 4-byte Client PID (introduced in SSSv1)
	 *   -  8: 4-byte MSB-first initial tx credit
	 *   - 12: the streamtype name with no NUL
	 */
	LWSSS_SER_TXPRE_ONWARD_CONNECT,
	/*
	 * Proxied request for onward connection
	 *
	 *   -  0: LWSSS_SER_TXPRE_ONWARD_CONNECT
	 *   -  1: 00, 00
	 */
	LWSSS_SER_TXPRE_DESTROYING,
	/*
	 * Proxied secure stream destroy
	 *
	 *   -  0: LWSSS_SER_TXPRE_DESTROYING
	 *   -  1: 00, 00
	 */
	LWSSS_SER_TXPRE_TX_PAYLOAD,
	/*
	 * Proxied tx
	 *
	 *   -  0: LWSSS_SER_TXPRE_TX_PAYLOAD
	 *   -  1: 2 byte MSB-first rest-of-frame length
	 *   -  3: 4-byte MSB-first flags
	 *   -  7: 4-byte MSB-first us between client requested write and wrote
	 *   			    to proxy
	 *   - 11: 8-byte MSB-first us resolution unix time client wrote to proxy
	 *   - 19: ...payload  (for rest of packet)
	 */
	LWSSS_SER_TXPRE_METADATA,
	/*
	 * Proxied metadata - sent when one metadata item set clientside
	 *
	 *   -  0: LWSSS_SER_TXPRE_METADATA
	 *   -  1: 2-byte MSB-first rest-of-frame length
	 *   -  3: 1-byte metadata name length
	 *   -  4: metadata name
	 *   -  ...: metadata value (for rest of packet)
	 */
	LWSSS_SER_TXPRE_TXCR_UPDATE,
	/*
	 * TX credit management - sent when using tx credit apis, cf METADATA
	 *
	 *   - 0: LWSSS_SER_TXPRE_TXCR_UPDATE
	 *   - 1: 2-byte MSB-first rest-of-frame length 00, 04
	 *   - 3: 4-byte additional tx credit adjust value
	 */
	LWSSS_SER_TXPRE_TIMEOUT_UPDATE,
	/*
	 * Stream timeout management - forwarded when user applying or
	 *  	cancelling t.o.
	 *
	 *   -  0: LWSSS_SER_TXPRE_TIMEOUT_UPDATE
	 *   -  1: 2-byte MSB-first rest-of-frame length 00, 04
	 *   -  3: 4-byte MSB-first unsigned 32-bit timeout,
	 *   			0 = use policy, -1 = cancel
	 */
	LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT,
	/*
	 * Passing up payload length hint
	 *
	 *   -  0: LWSSS_SER_TXPRE_PAYLOAD_LENGTH_HINT
	 *   -  1: 2-byte MSB-first rest-of-frame length 00, 04
	 *   -  3: 4-byte MSB-first unsigned 32-bit payload length hint
	 */
	LWSSS_SER_TXPRE_TLSNEG_ENCLAVE_SIGNED,
	/* reserved */
	LWSSS_SER_TXPRE_LINK_VALIDITY_PROBE,
} lws_sss_cmds_t;

/* SSPC serialization states */

 typedef enum {
 	LPCSPROX_WAIT_INITIAL_TX = 1, /* after connect, must send streamtype */
 	LPCSPROX_REPORTING_FAIL, /* stream creation failed, wait to to tell */
 	LPCSPROX_REPORTING_OK, /* stream creation succeeded, wait to to tell */
 	LPCSPROX_OPERATIONAL, /* ready for payloads */
 	LPCSPROX_DESTROYED,

 	LPCSCLI_SENDING_INITIAL_TX,  /* after connect, must send streamtype */
 	LPCSCLI_WAITING_CREATE_RESULT,   /* wait to hear if proxy ss create OK */
 	LPCSCLI_LOCAL_CONNECTED,	      /* we are in touch with the proxy */
 	LPCSCLI_ONWARD_CONNECT,	      /* request onward ss connection */
 	LPCSCLI_OPERATIONAL, /* ready for payloads */

 } lws_ss_conn_states_t;

 /*
  * Optional multiplexing layer
  *
  * Either side can:
  *
  *  - open and close channels asynchronously
  *  - send and receive transport-level (not mux channel) timed PINGs / PONGs
  *  - send and receive data bound to an open mux channel
  *
  *  PONGs are produced and sent automatically on recipt of a PING from the peer
  *  The peer sends a PONGACK so the single transaction can validate connection
  *  viability in both directions.
  */

 enum {
	 LWSSSS_LLM_CHANNEL_REQ					= 0xf0,
	 /**<
	  * Either side proposes to open a new mux channel
	  *
	  *  - 0: LWSSSS_LLM_CHANNEL_REQ
	  *  - 1: 1-byte mux channel index, client initiated: first free from
	  *         zero up, server initiated: first free from 0xff down
	  */
	 LWSSSS_LLM_CHANNEL_ACK,
	 /**<
	  * Positive response to earlier LWSSSS_LLM_CHANNEL_REQ
	  *
	  *  - 0: LWSSSS_LLM_CHANNEL_ACK
	  *  - 1: 1-byte mux channel index, from the reqyuest
	  */
	 LWSSSS_LLM_CHANNEL_NACK,
	 /**<
	  * Negative response to earlier LWSSSS_LLM_CHANNEL_REQ.  This also acts
	  * as a FIN if one arrives on a channel unsolicited.
	  *
	  *  - 0: LWSSSS_LLM_CHANNEL_NACK
	  *  - 1: 1-byte mux channel index, from the reqyuest
	  */
	 LWSSSS_LLM_CHANNEL_CLOSE,
	 /**<
	  * Either side informs peer it is closing a mux channel
	  *
	  *  - 0: LWSSSS_LLM_CHANNEL_CLOSE
	  *  - 1: 1-byte mux channel index
	  */
	 LWSSSS_LLM_CHANNEL_CLOSE_ACK,
	 /**<
	  * Peer acknowledges closing a mux channel, so it can be reused
	  *
	  *  - 0: LWSSSS_LLM_CHANNEL_CLOSE_ACK
	  *  - 1: 1-byte mux channel index
	  */
	 LWSSSS_LLM_MUX,
	 /**<
	  * Encapsulate data on an open mux channel
	  *
	  *  - 0: LWSSSS_LLM_MUX
	  *  - 1: 1-byte mux channel index
	  *  - 2: 2-byte MSB-first rest-of-frame length
	  *  - 4... mux payload
	  */
	 LWSSSS_LLM_PING,
	 /**<
	  * Either side wants to validate communication on mux transport
	  *
	  *  - 0: LWSSSS_LLM_PING
	  *  - 1:  8-byte MSB-first us resolution unix time this was issued
	  */
	 LWSSSS_LLM_PONG,
	 /**<
	  * Either side responds to peer's PING.
	  *
	  *  - 0: LWSSSS_LLM_PONG
	  *  - 1: 8-byte MSB-first us resolution unix time from PING
	  *  - 9: 8-byte MSB-first us resolution unix time this PONG sent
	  */
	 LWSSSS_LLM_PONGACK,
	 /**<
	  * When the original PING sender receives a PONG, it immediately sends
	  * a PINGACK, which is not replied to.  This allows the other side to
	  * also know the connection is valid in both directions, with only one
	  * side needing to issue PINGs.
	  *
	  * It also synchronizes both sides' understanding of the transport
	  * validity in one transaction.
	  *
	  *  - 0: LWSSSS_LLM_PONGACK
	  *  - 1: 8-byte MSB-first us resolution unix time from PING
	  */
	 LWSSSS_LLM_RESET_TRANSPORT,
	 /**<
	  * Either side can issue this to indicate they no longer trust the
	  * transport link.  They should close all their channels and enter a
	  * state trying to resync using 3-way PINGs
	  */
};

typedef void * lws_transport_priv_t; /* care - this is a pointer type already */
struct lws_transport_mux;
struct lws_sss_proxy_conn;
struct lws_transport_client_ops;
struct lws_transport_proxy_ops;
struct lws_sspc_handle;

/*
 * These describe the path through different transport layers.  Each has an
 * 'in' and 'onw' (onward) side that can be bound to different parts in lws.
 * SSPC and the SS Proxy code in lws each exposes one of these as terminals
 * for the "path" to handle the SS Serialization on each side.
 *
 * sspc-transport-wsi and proxy-transport-wsi expose possible endpoints for the
 * paths, so you can simply "wire SSPC and proxy up to a wsi transport".
 *
 * You can also create a lws_transport_mux_t and interpose it in the transport
 * path on each side, and produce your own custom lws_transport ops implementing
 * arbitrary transport support.
 */

typedef struct lws_txp_path_client {
	const struct lws_transport_client_ops	*ops_in;
	lws_transport_priv_t			priv_in;
	const struct lws_transport_client_ops	*ops_onw;
	lws_transport_priv_t			priv_onw;
	struct lws_transport_mux		*mux;
} lws_txp_path_client_t;

typedef struct lws_txp_path_proxy {
	const struct lws_transport_proxy_ops	*ops_in;
	lws_transport_priv_t			priv_in;
	const struct lws_transport_proxy_ops	*ops_onw;
	lws_transport_priv_t			priv_onw;
	struct lws_transport_mux		*mux;
} lws_txp_path_proxy_t;

/*
 * Operations for client-side transport
 */

typedef struct lws_transport_client_ops {
	const char *name;

 	int (*event_retry_connect)(lws_txp_path_client_t *path,
 				   struct lws_sspc_handle *h);
 	/**< Attempt to create a new connection / channel to the proxy */
 	lws_ss_state_return_t (*event_connect_disposition)(
 			       struct lws_sspc_handle *h, int disposition);
 	/**< Connection attempt result, disposition 9 = success, else failed */
 	void (*req_write)(lws_transport_priv_t priv);
 	/**< Request a write to the proxy on this channel */
 	int (*_write)(lws_transport_priv_t priv, uint8_t *buf, size_t len);
 	/**< Write the requested data on the channel to the proxy *** MUST have
 	 * LWS_PRE usable behind buf */
 	lws_ss_state_return_t (*event_read)(lws_transport_priv_t priv,
 					    const uint8_t *buf, size_t len);
 	/**< len bytes at buf have been received */
 	void (*lost_coherence)(lws_transport_priv_t priv);
 	/**< report that the framing inside the mux channel is broken */
 	void (*_close)(lws_transport_priv_t priv);
 	/**< Close the channel to the proxy */
 	void (*event_stream_up)(lws_transport_priv_t priv);
 	/**< Called when a new channel to the proxy is acknowledged as up */
	void (*event_client_up)(lws_transport_priv_t priv);
	/**< Called when a client channel is acknowledged as up */
	lws_ss_state_return_t (*event_can_write)(struct lws_sspc_handle *h,
						 size_t metadata_limit);
	/**< Called when possible to write on the transport, after req_write */
	lws_ss_state_return_t (*event_closed)(lws_transport_priv_t priv /*struct lws_sspc_handle *h */);
	/**< we notice an onward proxy connection had closed */
	uint32_t			flags;
	/**< Used for DSH creation flags */
	uint32_t			dsh_splitat;
} lws_transport_client_ops_t;

/*
 * Operations for proxy-side transport
 */

typedef struct lws_transport_proxy_ops {
	const char *name;
	int (*init_proxy_server)(struct lws_context *context,
			   const struct lws_transport_proxy_ops *txp_ops_inward,
			   lws_transport_priv_t txp_priv_inward,
			   lws_txp_path_proxy_t *txp_ppath, const void *aux,
			   const char *bind, int port);
	/**< Instantiate a proxy transport... bind/port are as shown for wsi
	 * transport, but may be overloaded to provide transport-specific init */
	int (*destroy_proxy_server)(struct lws_context *context);
	lws_ss_state_return_t (*event_new_conn)(struct lws_context *cx,
				const struct lws_transport_proxy_ops *txp_ops_inward,
				lws_transport_priv_t txp_priv_inward,
	#if defined(LWS_WITH_SYS_FAULT_INJECTION)
				         const lws_fi_ctx_t *fic,
	#endif
				struct lws_sss_proxy_conn **conn,
				lws_transport_priv_t txp_priv);
	/**< proxy has received a new connection from client */
	void (*event_onward_bind)(lws_transport_priv_t priv,
				  struct lws_ss_handle *h);
	/**< Called when the proxy creates an onward SS for a client channel */
 	void (*proxy_req_write)(lws_transport_priv_t priv);
 	/**< Request a write to the proxy on this channel */
	lws_ss_state_return_t (*event_proxy_can_write)(
			lws_transport_priv_t priv
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
					, const lws_fi_ctx_t *fic
#endif
			);
	/**< Transport can now be written on, after earlier proxy_req_write */
 	int (*proxy_write)(lws_transport_priv_t priv, uint8_t *buf, size_t *len);
 	/**< Write the requested data on the channel to the proxy *** MUST have
 	 * LWS_PRE usable behind buf.  May do partial writes, len is set on return
 	 * to actual length written*/
	lws_ss_state_return_t (*event_close_conn)(
				struct lws_sss_proxy_conn *conn);
	/**< proxy sees an existing conn closes */
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	const lws_fi_ctx_t * (*fault_context)(lws_transport_priv_t priv);
	/**< Get the fault context relating to the proxy connection, if any */
#endif
 	lws_ss_state_return_t (*close_conn)(struct lws_sss_proxy_conn *conn);
 	/**< called to handle closure of underlying transport */
 	lws_ss_state_return_t (*proxy_read)(lws_transport_priv_t priv,
 					    const uint8_t *buf, size_t len);
	void (*event_client_up)(lws_transport_priv_t priv);
	/**< Called when the proxy has accepted a new client conn */
	int (*proxy_check_write_more)(lws_transport_priv_t priv);
	/**< optional, allows checking if we can write again */
	uint32_t			flags; /* dsh flags */
} lws_transport_proxy_ops_t;

/* lws_transport_mux parser states */

enum lwstmc_parser {
	LWSTMCPAR_CMD,
	LWSTMCPAR_CHIDX_DONE,
	LWSTMCPAR_CHIDX,
	LWSTMCPAR_PLENH,
	LWSTMCPAR_PLENL,
	LWSTMCPAR_PAY,
	LWSTMCPAR_T64_1,
	LWSTMCPAR_T64_2
};

/* lws_transport_mux channel definitions */

typedef uint8_t lws_mux_ch_idx_t;
#define LWS_MUCH_RANGE 256

/* lws_transport mux states */

enum {
	/* lws_transport_mux_ch_t created */
	LWSTMC_PENDING_CREATE_CHANNEL,	    /* waiting to send create channel */
	LWSTMC_AWAITING_CREATE_CHANNEL_ACK, /* sent create ch, awaiting ack */
	LWSTMC_PENDING_CREATE_CHANNEL_NACK, /* waiting to send create ch ack */
	LWSTMC_PENDING_CREATE_CHANNEL_ACK,  /* waiting to send create ch ack */
	LWSTMC_OPERATIONAL,		    /* had ack, we are operational */
	LWSTMC_PENDING_CLOSE_CHANNEL,	    /* waiting to send close channel */
	LWSTMC_AWAITING_CLOSE_CHANNEL_ACK,  /* sent close ch, awaiting ack */
	LWSTMC_PENDING_CLOSE_CHANNEL_ACK,   /* waiting to send close ch ack */
	/* lws_transport_mux_ch_t destroyed */
};

#define LWS_TRANSPORT_MUXCH_MAGIC LWS_FOURCC('T', 'm', 'C', 'h')
#define assert_is_tmch(_tm) lws_assert_fourcc(_tm->magic, LWS_TRANSPORT_MUXCH_MAGIC)

typedef struct lws_transport_mux_ch {
#if defined(_DEBUG)
	uint32_t				magic;
#endif
	lws_dll2_t				list;
	lws_dll2_t				list_pending_tx;
	lws_transport_priv_t			priv;
	lws_sorted_usec_list_t			sul;
	void					*opaque;
	lws_mux_ch_idx_t			ch_idx;
	uint8_t					state;
	uint8_t					server:1;
} lws_transport_mux_ch_t;

enum { /* states of the transport */
	LWSTM_TRANSPORT_DOWN,
	LWSTM_OPERATIONAL,
};

#define LWSTMINFO_SERVER			(1 << 0)

typedef struct lws_transport_info {
	uint32_t				ping_interval_us;
	/**< us inbetween transport mux sending pings on transport */
	uint32_t				pong_grace_us;
	/**< us we should wait for pong before assuming transport down */
	lws_txp_path_client_t			txp_cpath;
	lws_txp_path_proxy_t			txp_ppath;
	struct lws_transport_info		*onward_txp_info;
	uint32_t				flags; /* LWSTMINFO_.... */
} lws_transport_info_t;

#define LWS_TRANSPORT_MUX_MAGIC LWS_FOURCC('I', 's', 'T', 'M')
#define assert_is_tm(_tm) lws_assert_fourcc(_tm->magic, LWS_TRANSPORT_MUX_MAGIC)

typedef struct lws_transport_mux {
#if defined(_DEBUG)
	uint32_t				magic;
#endif
	struct lws_context			*cx;
	lws_transport_info_t			info;
	lws_sorted_usec_list_t			sul_ping;
	void					*txp_handle;
	void					*txp_aux;
	uint64_t				us_ping_in;
	uint64_t				us_ping_out;
	uint64_t				us_unixtime_peer;
	uint64_t				us_unixtime_peer_loc;
	uint64_t				mp_time;
	uint64_t				mp_time1;
	enum lwstmc_parser			mp_state;
	uint32_t				mp_pay; /* remaining payload */
	uint8_t					mp_cmd;
	lws_mux_ch_idx_t			mp_idx;
	uint8_t					mp_ctr;
	uint32_t				_open[LWS_MUCH_RANGE / 32];
	uint32_t				fin[LWS_MUCH_RANGE / 32];
	lws_dll2_owner_t			pending_tx;
	lws_dll2_owner_t			owner; /* lws_mux_ch_t */
	uint8_t					link_state;
	uint8_t					issue_ping:1;
	uint8_t					issue_pong:1;
	uint8_t					issue_pongack:1;
	uint8_t					awaiting_pong:1;
} lws_transport_mux_t;

lws_transport_mux_t *
lws_transport_mux_create(struct lws_context *cx, lws_transport_info_t *info,
			 void *txp_handle);

void
lws_transport_mux_destroy(lws_transport_mux_t **tm);

void
lws_transport_mux_request_tx(lws_transport_mux_t *tm);

#if defined(_DEBUG)
void
lws_transport_path_client_dump(lws_txp_path_client_t *path, const char *ctx);
void
lws_transport_path_proxy_dump(lws_txp_path_proxy_t *path, const char *ctx);
#else
#define lws_transport_path_client_dump(_a, _b)
#define lws_transport_path_proxy_dump(_a, _b)
#endif

/*
 * Callback set used to customize parser and _pending apis
 */

typedef struct lws_txp_mux_parse_cbs {
	int (*payload)(lws_transport_mux_ch_t *tmc, const uint8_t *buf,
			size_t len);
	int (*ch_opens)(lws_transport_mux_ch_t *tmc, int determination);
	int (*ch_closes)(lws_transport_mux_ch_t *tmc);
	void (*txp_req_write)(lws_transport_mux_t *tm);
	int (*txp_can_write)(lws_transport_mux_ch_t *tmc);
} lws_txp_mux_parse_cbs_t;

int
lws_transport_mux_rx_parse(lws_transport_mux_t *tm, const uint8_t *buf,
			   size_t len, const lws_txp_mux_parse_cbs_t *cbs);

int /* nonzero if the transport mux has filled buf and wants to write it */
lws_transport_mux_pending(lws_transport_mux_t *tm, uint8_t *buf, size_t *len,
			  const lws_txp_mux_parse_cbs_t *cbs);

extern const lws_transport_client_ops_t lws_transport_mux_client_ops;
extern const lws_transport_proxy_ops_t lws_transport_mux_proxy_ops;

extern const lws_transport_client_ops_t lws_txp_inside_sspc;
extern const lws_transport_proxy_ops_t lws_txp_inside_proxy;

#if defined(STANDALONE)
#undef lws_context
#endif

