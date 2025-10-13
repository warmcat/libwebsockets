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
 */

#include <private-lib-core.h>

extern const uint32_t ss_state_txn_validity[17];

#if defined(STANDALONE)

#define lws_context lws_context_standalone

static const char *state_names[] = {
	"(unset)",
	"LWSSSCS_CREATING",
	"LWSSSCS_DISCONNECTED",
	"LWSSSCS_UNREACHABLE",
	"LWSSSCS_AUTH_FAILED",
	"LWSSSCS_CONNECTED",
	"LWSSSCS_CONNECTING",
	"LWSSSCS_DESTROYING",
	"LWSSSCS_POLL",
	"LWSSSCS_ALL_RETRIES_FAILED",
	"LWSSSCS_QOS_ACK_REMOTE",
	"LWSSSCS_QOS_NACK_REMOTE",
	"LWSSSCS_QOS_ACK_LOCAL",
	"LWSSSCS_QOS_NACK_LOCAL",
	"LWSSSCS_TIMEOUT",
	"LWSSSCS_SERVER_TXN",
	"LWSSSCS_SERVER_UPGRADE",
	"LWSSSCS_EVENT_WAIT_CANCELLED",
	"LWSSSCS_UPSTREAM_LINK_RETRY",
};

const char *
lws_ss_state_name(int state)
{
	if (state >= LWSSSCS_USER_BASE)
		return "user state";

	if (state >= (int)LWS_ARRAY_SIZE(state_names))
		return "unknown";

	return state_names[state];
}

const uint32_t ss_state_txn_validity[] = {

	/* if we was last in this state...  we can legally go to these states */

	[0]				= (1 << LWSSSCS_CREATING) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_CREATING]		= (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_POLL) |
					  (1 << LWSSSCS_SERVER_UPGRADE) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_DISCONNECTED]		= (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_POLL) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_UNREACHABLE]		= (1 << LWSSSCS_ALL_RETRIES_FAILED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_POLL) |
					  (1 << LWSSSCS_CONNECTING) |
					  /* win conn failure > retry > succ */
					  (1 << LWSSSCS_CONNECTED) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_AUTH_FAILED]		= (1 << LWSSSCS_ALL_RETRIES_FAILED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_CONNECTED]		= (1 << LWSSSCS_SERVER_UPGRADE) |
					  (1 << LWSSSCS_SERVER_TXN) |
					  (1 << LWSSSCS_AUTH_FAILED) |
					  (1 << LWSSSCS_QOS_ACK_REMOTE) |
					  (1 << LWSSSCS_QOS_NACK_REMOTE) |
					  (1 << LWSSSCS_QOS_ACK_LOCAL) |
					  (1 << LWSSSCS_QOS_NACK_LOCAL) |
					  (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_POLL) | /* proxy retry */
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_CONNECTING]		= (1 << LWSSSCS_UNREACHABLE) |
					  (1 << LWSSSCS_AUTH_FAILED) |
					  (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_CONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DISCONNECTED) | /* proxy retry */
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_DESTROYING]		= 0,

	[LWSSSCS_POLL]			= (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_ALL_RETRIES_FAILED]	= (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_QOS_ACK_REMOTE]	= (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
#if defined(LWS_ROLE_MQTT)
					  (1 << LWSSSCS_QOS_ACK_REMOTE) |
#endif
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_QOS_NACK_REMOTE]	= (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_QOS_ACK_LOCAL]		= (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_QOS_NACK_LOCAL]	= (1 << LWSSSCS_DESTROYING) |
					  (1 << LWSSSCS_TIMEOUT),

	/* he can get the timeout at any point and take no action... */
	[LWSSSCS_TIMEOUT]		= (1 << LWSSSCS_CONNECTING) |
					  (1 << LWSSSCS_CONNECTED) |
					  (1 << LWSSSCS_QOS_ACK_REMOTE) |
					  (1 << LWSSSCS_QOS_NACK_REMOTE) |
					  (1 << LWSSSCS_POLL) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_UNREACHABLE) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_SERVER_TXN]		= (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DESTROYING),

	[LWSSSCS_SERVER_UPGRADE]	= (1 << LWSSSCS_SERVER_TXN) |
					  (1 << LWSSSCS_TIMEOUT) |
					  (1 << LWSSSCS_DISCONNECTED) |
					  (1 << LWSSSCS_DESTROYING),
};

char *
lws_strncpy(char *dest, const char *src, size_t size)
{
	strncpy(dest, src, size - 1);
	dest[size - 1] = '\0';

	return dest;
}

#undef lws_malloc
#define lws_malloc(a, b) malloc(a)
#undef lws_free
#define lws_free(a) free(a)

extern void
__lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	   int filter, const char *_fun, const char *format, va_list ap);

void _lws_logv(int filter, const char *format, va_list ap)
{
	__lws_logv(NULL, NULL, NULL, filter, NULL, format, ap);
}

void
_lws_log(int filter, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	_lws_logv(filter, format, ap);
	va_end(ap);
}

void
_lws_log_cx(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj,
	    int filter, const char *_fun, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	__lws_logv(cx, prep, obj, filter, _fun, format, ap);
	va_end(ap);
}

#endif

int
lws_ss_check_next_state_sspc(lws_sspc_handle_t *ss, uint8_t *prevstate,
			     lws_ss_constate_t cs)
{
	if (cs >= LWSSSCS_USER_BASE || cs == LWSSSCS_EVENT_WAIT_CANCELLED)
		/*
		 * we can't judge user or transient states, leave the old state
		 * and just wave them through
		 */
		return 0;

	if (cs >= LWS_ARRAY_SIZE(ss_state_txn_validity)) {
		/* we don't recognize this state as usable */
		lwsl_sspc_err(ss, "bad new state %u", cs);
		assert(0);
		return 1;
	}

	if (*prevstate >= LWS_ARRAY_SIZE(ss_state_txn_validity)) {
		/* existing state is broken */
		lwsl_sspc_err(ss, "bad existing state %u",
				(unsigned int)*prevstate);
		assert(0);
		return 1;
	}

	if (ss_state_txn_validity[*prevstate] & (1u << cs)) {

		lwsl_sspc_notice(ss, "%s -> %s",
			       lws_ss_state_name(*prevstate),
			       lws_ss_state_name(cs));

		/* this is explicitly allowed, update old state to new */
		*prevstate = (uint8_t)cs;

		return 0;
	}

	lwsl_sspc_err(ss, "transition from %s -> %s is illegal",
		    lws_ss_state_name(*prevstate),
		    lws_ss_state_name(cs));

	assert(0);

	return 1;
}

lws_ss_state_return_t
lws_sspc_event_helper(lws_sspc_handle_t *h, lws_ss_constate_t cs,
		      lws_ss_tx_ordinal_t flags)
{
	lws_ss_state_return_t ret;

	if (!h)
		return LWSSSSRET_OK;

	if (lws_ss_check_next_state_sspc(h, &h->prev_ss_state, cs))
		return LWSSSSRET_DESTROY_ME;

	if (!h->ssi.state)
		return LWSSSSRET_OK;

	h->h_in_svc = h;
	ret = h->ssi.state((void *)((uint8_t *)(h + 1)), NULL, cs, flags);
	h->h_in_svc = NULL;

	return ret;
}

int
lws_sspc_create(struct lws_context *context, int tsi, const lws_ss_info_t *ssi,
	        void *opaque_user_data, lws_sspc_handle_t **ppss,
	        void *reserved, const char **ppayload_fmt)
{
	lws_sspc_handle_t *h;
	uint8_t *ua;
	char *p;

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(context, tsi);
#endif

	/* allocate the handle (including ssi), the user alloc,
	 * and the streamname */

	h = malloc(sizeof(lws_sspc_handle_t) + ssi->user_alloc +
				strlen(ssi->streamtype) + 1);
	if (!h)
		return 1;
	memset(h, 0, sizeof(*h));

#if !defined(STANDALONE)
	h->lc.log_cx = context->log_cx;
#endif

#if !defined(STANDALONE) && defined(LWS_WITH_SYS_FAULT_INJECTION)
	h->fic.name = "sspc";
	lws_xos_init(&h->fic.xos, lws_xos(&context->fic.xos));
	if (ssi->fic.fi_owner.count)
		lws_fi_import(&h->fic, &ssi->fic);

	lws_fi_inherit_copy(&h->fic, &context->fic, "ss", ssi->streamtype);

	if (lws_fi(&h->fic, "sspc_create_oom")) {
		/*
		 * We have to do this a little later, so we can cleanly inherit
		 * the OOM pieces and drain the info fic
		 */
		lws_fi_destroy(&h->fic);
		free(h);
		return 1;
	}
#endif
#if !defined(STANDALONE)
	__lws_lc_tag(context, &context->lcg[LWSLCG_SSP_CLIENT], &h->lc,
			ssi->streamtype);
#else
	snprintf(h->lc.gutag, sizeof(h->lc.gutag), "[sspc|%s|%x]",
				ssi->streamtype,
				(unsigned int)(context->ssidx++));
#endif

	h->txp_path = context->txp_cpath;

	h->txp_path.ops_in = &lws_txp_inside_sspc;
	h->txp_path.priv_in = (lws_transport_priv_t)h;

	/* priv_onw filled in by onw transport */

	lwsl_sspc_info(h, "txp path %s -> %s", h->txp_path.ops_in->name,
					       h->txp_path.ops_onw->name);

	memcpy(&h->ssi, ssi, sizeof(*ssi));
	ua = (uint8_t *)(h + 1);
	memset(ua, 0, ssi->user_alloc);
	p = (char *)ua + ssi->user_alloc;
	memcpy(p, ssi->streamtype, strlen(ssi->streamtype) + 1);
	h->ssi.streamtype = (const char *)p;
	h->context = context;
	h->us_start_upstream = lws_now_usecs();

	if (!ssi->manual_initial_tx_credit)
		h->txc.peer_tx_cr_est = 500000000;
	else
		h->txc.peer_tx_cr_est = ssi->manual_initial_tx_credit;

#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_SYS_SMD)
	if (!strcmp(ssi->streamtype, LWS_SMD_STREAMTYPENAME))
		h->ignore_txc = 1;
#endif

	lws_dll2_add_head(&h->client_list, &context->
#if !defined(STANDALONE)
			pt[tsi].
#endif
			ss_client_owner);

	/* fill in the things the real api does for the caller */

	*((void **)(ua + ssi->opaque_user_data_offset)) = opaque_user_data;
	*((void **)(ua + ssi->handle_offset)) = h;

	if (ppss)
		*ppss = h;

	/* try the actual connect */

	lws_sspc_sul_retry_cb(&h->sul_retry);

	return 0;
}

/* used on context destroy when iterating listed lws_ss on a pt */

int
lws_sspc_destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_sspc_handle_t *h = lws_container_of(d, lws_sspc_handle_t,
						client_list);

	lws_sspc_destroy(&h);

	return 0;
}

void
lws_sspc_rxmetadata_destroy(lws_sspc_handle_t *h)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&h->metadata_owner_rx)) {
		lws_sspc_metadata_t *md =
				lws_container_of(d, lws_sspc_metadata_t, list);

		lws_dll2_remove(&md->list);
		lws_free(md);

	} lws_end_foreach_dll_safe(d, d1);
}

void
lws_sspc_destroy(lws_sspc_handle_t **ph)
{
	lws_sspc_handle_t *h;

	if (!*ph)
		return;

	h = *ph;
	if (h == h->h_in_svc) {
		lwsl_err("%s: illegal destroy, return LWSSSSRET_DESTROY_ME instead\n",
				__func__);
		assert(0);
		return;
	}

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	if (h->destroying)
		return;

	h->destroying = 1;

	/* if this caliper is still dangling at destroy, we failed */
#if !defined(STANDALONE) && defined(LWS_WITH_SYS_METRICS)
	/*
	 * If any hanging caliper measurement, dump it, and free any tags
	 */
	lws_metrics_caliper_report_hist(h->cal_txn, (struct lws *)NULL);
#endif
	if (h->ss_dangling_connected && h->ssi.state) {
		lws_sspc_event_helper(h, LWSSSCS_DISCONNECTED, 0);
		h->ss_dangling_connected = 0;
	}

#if !defined(STANDALONE) && defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_fi_destroy(&h->fic);
#endif

	lws_sul_cancel(&h->sul_retry);
	lws_dll2_remove(&h->client_list);

	if (h->dsh)
		lws_dsh_destroy(&h->dsh);

	h->txp_path.ops_onw->_close(h->txp_path.priv_onw);

	/* clean out any pending metadata changes that didn't make it */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&(*ph)->metadata_owner)) {
		lws_sspc_metadata_t *md =
				lws_container_of(d, lws_sspc_metadata_t, list);

		lws_dll2_remove(&md->list);
		lws_free(md);

	} lws_end_foreach_dll_safe(d, d1);

	lws_sspc_rxmetadata_destroy(h);

	lws_sspc_event_helper(h, LWSSSCS_DESTROYING, 0);
	*ph = NULL;

	lws_sul_cancel(&h->sul_retry);

#if !defined(STANDALONE)
	/* confirm no sul left scheduled in handle or user allocation object */
	lws_sul_debug_zombies(h->context, h, sizeof(*h) + h->ssi.user_alloc,
			      __func__);
#endif
#if !defined(STANDALONE)
	__lws_lc_untag(h->context, &h->lc);
#endif

	free(h);
}

lws_ss_state_return_t
lws_sspc_request_tx(lws_sspc_handle_t *h)
{
	if (!h || !h->txp_path.priv_onw)
		return LWSSSSRET_OK;

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	if (!h->us_earliest_write_req)
		h->us_earliest_write_req = lws_now_usecs();

	lwsl_info("%s: state %u, conn_req_state %u\n", __func__,
			(unsigned int)h->state,
			(unsigned int)h->conn_req_state);

	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;

	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

	return LWSSSSRET_OK;
}

/*
 * Currently we fulfil the writeable part locally by just enabling POLLOUT on
 * the UDS link, without serialization footprint, which is reasonable as far as
 * it goes.
 *
 * But for the ..._len() variant, the expected payload length hint we are being
 * told is something that must be serialized to the onward peer, since either
 * that guy or someone upstream of him is the guy who will compose the framing
 * with it that actually goes out.
 *
 * This information is needed at the upstream guy before we have sent any
 * payload, eg, for http POST, he has to prepare the content-length in the
 * headers, before any payload.  So we have to issue a serialization of the
 * length at this point.
 */

lws_ss_state_return_t
lws_sspc_request_tx_len(lws_sspc_handle_t *h, unsigned long len)
{
	/*
	 * for client conns, they cannot even complete creation of the handle
	 * without the onwared connection to the proxy, it's not legal to start
	 * using it until it's operation and has the onward connection (and the
	 * link has called CREATED state)
	 */

	if (!h)
		return LWSSSSRET_OK;

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	lwsl_sspc_notice(h, "setting writeable_len %u", (unsigned int)len);
	h->writeable_len = len;
	h->pending_writeable_len = 1;

	if (!h->us_earliest_write_req)
		h->us_earliest_write_req = lws_now_usecs();

	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;

	/*
	 * We're going to use this up with serializing h->writeable_len... that
	 * will request again.
	 */

	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

	return LWSSSSRET_OK;
}

lws_ss_state_return_t
lws_sspc_client_connect(struct lws_sspc_handle *h)
{
	if (!h || h->state == LPCSCLI_OPERATIONAL)
		return 0;

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	assert(h->state == LPCSCLI_LOCAL_CONNECTED);
	if (h->state == LPCSCLI_LOCAL_CONNECTED &&
	    h->conn_req_state == LWSSSPC_ONW_NONE)
		h->conn_req_state = LWSSSPC_ONW_REQ;
	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

	return 0;
}

struct lws_context *
lws_sspc_get_context(struct lws_sspc_handle *h)
{
	return h->context;
}

const char *
lws_sspc_rideshare(struct lws_sspc_handle *h)
{
	/*
	 * ...the serialized RX rideshare name if any...
	 */

	if (h->parser.rideshare[0]) {
		lwsl_sspc_info(h, "parser %s", h->parser.rideshare);

		return h->parser.rideshare;
	}

	/*
	 * The tx rideshare index
	 */

	if (h->rideshare_list[0]) {
		lwsl_sspc_info(h, "tx list %s",
			  &h->rideshare_list[h->rideshare_ofs[h->rsidx]]);
		return &h->rideshare_list[h->rideshare_ofs[h->rsidx]];
	}

	/*
	 * ... otherwise default to our stream type name
	 */

	lwsl_sspc_info(h, "def %s\n", h->ssi.streamtype);

	return h->ssi.streamtype;
}

static int
_lws_sspc_set_metadata(struct lws_sspc_handle *h, const char *name,
		       const void *value, size_t len, int tx_cr_adjust)
{
	lws_sspc_metadata_t *md;

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	/*
	 * Are we replacing a pending metadata of the same name?  It's not
	 * efficient to do this but user code can do what it likes... let's
	 * optimize away the old one.
	 *
	 * Tx credit adjust always has name ""
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&h->metadata_owner)) {
		md = lws_container_of(d, lws_sspc_metadata_t, list);

		if (!strcmp(name, md->name)) {
			lws_dll2_remove(&md->list);
			lws_free(md);
			break;
		}

	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * We have to stash the metadata and pass it to the proxy
	 */
#if !defined(STANDALONE)
	if (lws_fi(&h->fic, "sspc_fail_metadata_set"))
		md = NULL;
	else
#endif
		md = lws_malloc(sizeof(*md) + len, "set metadata");
	if (!md) {
		lwsl_sspc_err(h, "OOM");

		return 1;
	}

	memset(md, 0, sizeof(*md));

	md->tx_cr_adjust = tx_cr_adjust;
	h->txc.peer_tx_cr_est += tx_cr_adjust;

	lws_strncpy(md->name, name, sizeof(md->name));
	md->len = len;
	if (len)
		memcpy(&md[1], value, len);

	lws_dll2_add_tail(&md->list, &h->metadata_owner);

	if (len) {
#if !defined(STANDALONE)
		lwsl_sspc_info(h, "set metadata %s", name);
		lwsl_hexdump_sspc_info(h, value, len);
#endif
	} else
		lwsl_sspc_info(h, "serializing tx cr adj %d",
			    (int)tx_cr_adjust);

	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);

	return 0;
}

void
lws_sspc_server_ack(struct lws_sspc_handle *h, int nack)
{
	//h->txn_resp = nack;
	//h->txn_resp_set = 1;

}

int
lws_sspc_set_metadata(struct lws_sspc_handle *h, const char *name,
		      const void *value, size_t len)
{
	return _lws_sspc_set_metadata(h, name, value, len, 0);
}

int
lws_sspc_get_metadata(struct lws_sspc_handle *h, const char *name,
		      const void **value, size_t *len)
{
	lws_sspc_metadata_t *md;

	/*
	 * client side does not have access to policy
	 * and any metadata are new to it each time,
	 * we allocate them, removing any existing with
	 * the same name first
	 */

#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&h->metadata_owner_rx)) {
		md = lws_container_of(d,
			   lws_sspc_metadata_t, list);

		if (!strcmp(md->name, name)) {
			*len = md->len;
			*value = &md[1];

			return 0;
		}

	} lws_end_foreach_dll_safe(d, d1);

	return 1;
}

int
lws_sspc_add_peer_tx_credit(struct lws_sspc_handle *h, int32_t bump)
{
#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif
	lwsl_sspc_notice(h, "%d\n", (int)bump);
	return _lws_sspc_set_metadata(h, "", NULL, 0, (int)bump);
}

int
lws_sspc_get_est_peer_tx_credit(struct lws_sspc_handle *h)
{
#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif
	return h->txc.peer_tx_cr_est;
}

void
lws_sspc_start_timeout(struct lws_sspc_handle *h, unsigned int timeout_ms)
{
#if !defined(STANDALONE)
	lws_service_assert_loop_thread(h->context, 0);
#endif
	if (!h->txp_path.priv_onw)
		/* we can't fulfil it */
		return;
	h->timeout_ms = (uint32_t)timeout_ms;
	h->pending_timeout_update = 1;
	h->txp_path.ops_onw->req_write(h->txp_path.priv_onw);
}

void
lws_sspc_cancel_timeout(struct lws_sspc_handle *h)
{
	lws_sspc_start_timeout(h, (unsigned int)-1);
}

void *
lws_sspc_to_user_object(struct lws_sspc_handle *h)
{
	return (void *)(h + 1);
}

struct lws_log_cx *
lwsl_sspc_get_cx(struct lws_sspc_handle *sspc)
{
	if (!sspc)
		return NULL;

	return sspc->lc.log_cx;
}

void
lws_log_prepend_sspc(struct lws_log_cx *cx, void *obj, char **p, char *e)
{
	struct lws_sspc_handle *h = (struct lws_sspc_handle *)obj;

#if defined(STANDALONE)
	snprintf(*p, lws_ptr_diff_size_t(e, (*p)), "%s: ", h->lc.gutag);
#else
	*p += lws_snprintf(*p, lws_ptr_diff_size_t(e, (*p)), "%s: ",
			lws_sspc_tag(h));
#endif
}

void
lws_sspc_change_handlers(struct lws_sspc_handle *h, lws_sscb_rx rx,
			 lws_sscb_tx tx, lws_sscb_state state)
{
	if (rx)
		h->ssi.rx = rx;
	if (tx)
		h->ssi.tx = tx;
	if (state)
		h->ssi.state = state;
}

const char *
lws_sspc_tag(struct lws_sspc_handle *h)
{
	if (!h)
		return "[null sspc]";
#if defined(STANDALONE)
	return h->lc.gutag;
#else
	return lws_lc_tag(&h->lc);
#endif
}

int
lws_sspc_cancel_notify_dll(struct lws_dll2 *d, void *user)
{
	lws_sspc_handle_t *h = lws_container_of(d, lws_sspc_handle_t,
						client_list);

	lws_sspc_event_helper(h, LWSSSCS_EVENT_WAIT_CANCELLED, 0);

	return 0;
}


