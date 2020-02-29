/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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

/*
 * Secure Stream state
 */

typedef enum {
	SSSEQ_IDLE,
	SSSEQ_TRY_CONNECT,
	SSSEQ_TRY_CONNECT_NAUTH,
	SSSEQ_TRY_CONNECT_SAUTH,
	SSSEQ_RECONNECT_WAIT,
	SSSEQ_DO_RETRY,
	SSSEQ_CONNECTED,
} lws_ss_seq_state_t;


/**
 * lws_ss_handle_t: publicly-opaque secure stream object implementation
 */

typedef struct lws_ss_handle {
	lws_ss_info_t		info;	  /**< copy of stream creation info */
	struct lws_dll2		list;	  /**< pt lists active ss */
	struct lws_dll2		to_list;  /**< pt lists ss with pending to-s */

	struct lws_dll2_owner	src_list; /**< sink's list of bound sources */

	struct lws_context      *context; /**< lws context we are created on */
	const lws_ss_policy_t	*policy;  /**< system policy for stream */

	struct lws_sequencer	*seq;	  /**< owning sequencer if any */
	struct lws		*wsi;	  /**< the stream wsi if any */

	void			*nauthi;  /**< the nauth plugin instance data */
	void			*sauthi;  /**< the sauth plugin instance data */

	lws_ss_metadata_t	*metadata;
	const lws_ss_policy_t	*rideshare;

	struct lws_ss_handle	*h_sink;  /**< sink we are bound to, or NULL */
	void 			*sink_obj;/**< sink's private object representing us */

	lws_sorted_usec_list_t	sul;
	lws_ss_tx_ordinal_t	txord;

	/* protocol-specific connection helpers */

	union {

		/* ...for http-related protocols... */

		struct {

			/* common to all http-related protocols */

			/* incoming multipart parsing */

			char boundary[24];	/* --boundary from headers */
			uint8_t boundary_len;	/* length of --boundary */
			uint8_t boundary_seq;	/* current match amount */
			uint8_t boundary_dashes; /* check for -- after */
			uint8_t boundary_post; /* swallow post CRLF */

			uint8_t som:1;	/* SOM has been sent */
			uint8_t any:1;	/* any content has been sent */


			uint8_t good_respcode:1; /* 200 type response code */

			union {
				struct { /* LWSSSP_H1 */
				} h1;
				struct { /* LWSSSP_H2 */
				} h2;
				struct { /* LWSSSP_WS */
				} ws;
			} u;
		} http;

		/* details for non-http related protocols... */
#if defined(LWS_ROLE_MQTT)
		struct {
			lws_mqtt_topic_elem_t		topic_qos;
			lws_mqtt_topic_elem_t		sub_top;
			lws_mqtt_subscribe_param_t 	sub_info;
		} mqtt;
#endif
	} u;

	unsigned long		writeable_len;

	lws_ss_constate_t	connstate;/**< public connection state */
	lws_ss_seq_state_t	seqstate; /**< private connection state */

	uint16_t		retry;	  /**< retry / backoff tracking */
	int16_t			temp16;

	uint8_t			tsi;	  /**< service thread idx, usually 0 */
	uint8_t			subseq;	  /**< emulate SOM tracking */
	uint8_t			txn_ok;	  /**< 1 = transaction was OK */

	uint8_t			hanging_som:1;
	uint8_t			inside_msg:1;
	uint8_t			being_serialized:1; /* we are not the consumer */
} lws_ss_handle_t;

/* connection helper that doesn't need to hang around after connection starts */

union lws_ss_contemp {
#if defined(LWS_ROLE_MQTT)
	lws_mqtt_client_connect_param_t ccp;
#endif
};

/*
 * When allocating the opaque handle, we overallocate for:
 *
 *  1) policy->nauth_plugin->alloc (.nauthi) if any
 *  2) policy->sauth_plugin->alloc (.sauthi) if any
 *  3) copy of creation info stream type pointed to by info.streamtype... this
 *     may be arbitrarily long and since it may be coming from socket ipc and be
 *     temporary at creation time, we need a place for the copy to stay in scope
 *  4) copy of info->streamtype contents
 */


/* the user object allocation is immediately after the ss object allocation */
#define ss_to_userobj(ss) ((void *)&(ss)[1])

/*
 * serialization parser state
 */

enum {
	KIND_C_TO_P,
	KIND_SS_TO_P,
};

struct lws_ss_serialization_parser {
	char			streamtype[32];
	char			rideshare[32];
	char			metadata_name[32];

	uint64_t		ust_pwait;

	lws_ss_metadata_t	*ssmd;

	int			ps;
	int			ctr;

	uint32_t		usd_phandling;
	uint32_t		flags;
	int32_t			temp32;

	int32_t			txcr_out;
	int32_t			txcr_in;
	uint16_t		rem;

	uint8_t			type;
	uint8_t			frag1;
	uint8_t			slen;
	uint8_t			rsl_pos;
	uint8_t			rsl_idx;
};

/*
 * Unlike locally-fulfilled SS, SSS doesn't have to hold metadata on client side
 * but pass it through to the proxy.  The client side doesn't know the real
 * metadata names that are available in the policy (since it's hardcoded in code
 * no point passing them back to the client from the policy).  Because of that,
 * it doesn't know how many to allocate when we create the sspc_handle either.
 *
 * So we use a linked-list of changed-but-not-yet-proxied metadata allocated
 * on the heap and items removed as they are proxied out.  Anything on the list
 * is sent to the proxy before any requested tx is handled.
 *
 * This is also used to queue tx credit changes
 */

typedef struct lws_sspc_metadata {
	lws_dll2_t	list;
	char		name[32];  /* empty string, then actually TCXR */
	size_t		len;
	int		tx_cr_adjust;

	/* the value of length .len is overallocated after this */
} lws_sspc_metadata_t;


typedef struct lws_sspc_handle {
	char			rideshare_list[128];
	lws_ss_info_t		ssi;
	lws_sorted_usec_list_t	sul_retry;

	struct lws_ss_serialization_parser parser;

	lws_dll2_owner_t	metadata_owner;

	struct lws_dll2		client_list;
	struct lws_tx_credit	txc;

	struct lws		*cwsi;

	struct lws_dsh		*dsh;
	struct lws_context	*context;

	lws_usec_t		us_earliest_write_req;

	lws_ss_conn_states_t	state;

	int16_t			temp16;

	uint32_t		ord;

	uint8_t			rideshare_ofs[4];
	uint8_t			conn_req;
	uint8_t			rsidx;

	uint8_t			destroying:1;
} lws_sspc_handle_t;

int
lws_ss_deserialize_parse(struct lws_ss_serialization_parser *par,
			 struct lws_context *context,
			 struct lws_dsh *dsh, const uint8_t *cp, size_t len,
			 lws_ss_conn_states_t *state, void *parconn,
			 lws_ss_handle_t **pss, lws_ss_info_t *ssi, char client);
int
lws_ss_serialize_rx_payload(struct lws_dsh *dsh, const uint8_t *buf,
			    size_t len, int flags, const char *rsp);
int
lws_ss_deserialize_tx_payload(struct lws_dsh *dsh, struct lws *wsi,
			      lws_ss_tx_ordinal_t ord, uint8_t *buf,
			      size_t *len, int *flags);
int
lws_ss_serialize_state(struct lws_dsh *dsh, lws_ss_constate_t state,
		       lws_ss_tx_ordinal_t ack);

void
lws_ss_serialize_state_transition(lws_ss_conn_states_t *state, int new_state);

const lws_ss_policy_t *
lws_ss_policy_lookup(const struct lws_context *context, const char *streamtype);

/* can be used as a cb from lws_dll2_foreach_safe() to destroy ss */
int
lws_ss_destroy_dll(struct lws_dll2 *d, void *user);

int
lws_sspc_destroy_dll(struct lws_dll2 *d, void *user);


int
lws_ss_policy_parse_begin(struct lws_context *context);

int
lws_ss_policy_parse(struct lws_context *context, const uint8_t *buf, size_t len);

int
lws_ss_policy_set(struct lws_context *context, const char *name);

int
lws_ss_policy_parse_abandon(struct lws_context *context);

int
lws_ss_sys_fetch_policy(struct lws_context *context);

int
lws_ss_event_helper(lws_ss_handle_t *h, lws_ss_constate_t cs);

int
lws_ss_backoff(lws_ss_handle_t *h);

int
lws_ss_set_timeout_us(lws_ss_handle_t *h, lws_usec_t us);

void
ss_proxy_onward_txcr(void *userobj, int bump);

int
lws_ss_serialize_txcr(struct lws_dsh *dsh, int txcr);

int
lws_ss_sys_auth_api_amazon_com(struct lws_context *context);

lws_ss_metadata_t *
lws_ss_get_handle_metadata(struct lws_ss_handle *h, const char *name);
lws_ss_metadata_t *
lws_ss_policy_metadata_index(const lws_ss_policy_t *p, size_t index);

lws_ss_metadata_t *
lws_ss_policy_metadata(const lws_ss_policy_t *p, const char *name);

int
lws_ss_exp_cb_metadata(void *priv, const char *name, char *out, size_t *pos,
			size_t olen, size_t *exp_ofs);

typedef int (* const secstream_protocol_connect_munge_t)(lws_ss_handle_t *h,
		char *buf, size_t len, struct lws_client_connect_info *i,
		union lws_ss_contemp *ct);

typedef int (* const secstream_protocol_add_txcr_t)(lws_ss_handle_t *h, int add);

typedef int (* const secstream_protocol_get_txcr_t)(lws_ss_handle_t *h);

struct ss_pcols {
	const char					*name;
	const char					*alpn;
	const char					*protocol_name;
	const secstream_protocol_connect_munge_t	munge;
	const secstream_protocol_add_txcr_t		tx_cr_add;
	const secstream_protocol_get_txcr_t		tx_cr_est;
};

extern const struct ss_pcols ss_pcol_h1;
extern const struct ss_pcols ss_pcol_h2;
extern const struct ss_pcols ss_pcol_ws;
extern const struct ss_pcols ss_pcol_mqtt;

extern const struct lws_protocols protocol_secstream_h1;
extern const struct lws_protocols protocol_secstream_h2;
extern const struct lws_protocols protocol_secstream_ws;
extern const struct lws_protocols protocol_secstream_mqtt;

