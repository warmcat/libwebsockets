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

#include <private-lib-core.h>

static const struct ss_pcols *ss_pcols[] = {
#if defined(LWS_ROLE_H1)
	&ss_pcol_h1,		/* LWSSSP_H1 */
#else
	NULL,
#endif
#if defined(LWS_ROLE_H2)
	&ss_pcol_h2,		/* LWSSSP_H2 */
#else
	NULL,
#endif
#if defined(LWS_ROLE_WS)
	&ss_pcol_ws,		/* LWSSSP_WS */
#else
	NULL,
#endif
#if defined(LWS_ROLE_MQTT)
	&ss_pcol_mqtt,		/* LWSSSP_MQTT */
#else
	NULL,
#endif
};

static const char *state_names[] = {
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
};

const char *
lws_ss_state_name(int state)
{
	if (state >= (int)LWS_ARRAY_SIZE(state_names))
		return "unknown";

	return state_names[state];
}

int
lws_ss_event_helper(lws_ss_handle_t *h, lws_ss_constate_t cs)
{
	if (!h)
		return 0;

#if defined(LWS_WITH_SEQUENCER)
	/*
	 * A parent sequencer for the ss is optional, if we have one, keep it
	 * informed of state changes on the ss connection
	 */
	if (h->seq && cs != LWSSSCS_DESTROYING)
		lws_seq_queue_event(h->seq, LWSSEQ_SS_STATE_BASE + cs,
				    (void *)h, NULL);
#endif

	if (h->h_sink &&h->h_sink->info.state(h->sink_obj, h->h_sink, cs, 0))
		return 1;

	return h->info.state(ss_to_userobj(h), NULL, cs, 0);
}

static void
lws_ss_timeout_sul_check_cb(lws_sorted_usec_list_t *sul)
{
	lws_ss_handle_t *h = lws_container_of(sul, lws_ss_handle_t, sul);

	lwsl_err("%s: retrying ss h %p after backoff\n", __func__, h);
	/* we want to retry... */
	h->seqstate = SSSEQ_DO_RETRY;

	lws_ss_request_tx(h);
}

int
lws_ss_exp_cb_metadata(void *priv, const char *name, char *out, size_t *pos,
			size_t olen, size_t *exp_ofs)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)priv;
	const char *replace = NULL;
	size_t total, budget;
	lws_ss_metadata_t *md = lws_ss_policy_metadata(h->policy, name);

	if (!md) {
		lwsl_err("%s: Unknown metadata %s\n", __func__, name);

		return LSTRX_FATAL_NAME_UNKNOWN;
	}

	lwsl_info("%s %s %d\n", __func__, name, (int)md->length);

	replace = h->metadata[md->length].value;
	total = h->metadata[md->length].length;
	// lwsl_hexdump_err(replace, total);

	budget = olen - *pos;
	total -= *exp_ofs;
	if (total < budget)
		budget = total;

	memcpy(out + *pos, replace + (*exp_ofs), budget);
	*exp_ofs += budget;
	*pos += budget;

	if (budget == total)
		return LSTRX_DONE;

	return LSTRX_FILLED_OUT;
}

int
lws_ss_set_timeout_us(lws_ss_handle_t *h, lws_usec_t us)
{
	struct lws_context_per_thread *pt = &h->context->pt[h->tsi];

	h->sul.cb = lws_ss_timeout_sul_check_cb;
	__lws_sul_insert(&pt->pt_sul_owner, &h->sul, us);

	return 0;
}

int
lws_ss_backoff(lws_ss_handle_t *h)
{
	uint64_t ms;
	char conceal;

	if (h->seqstate == SSSEQ_RECONNECT_WAIT)
		return 0;

	/* figure out what we should do about another retry */

	lwsl_info("%s: ss %p: retry backoff after failure\n", __func__, h);
	ms = lws_retry_get_delay_ms(h->context, h->policy->retry_bo,
				    &h->retry, &conceal);
	if (!conceal) {
		lwsl_info("%s: ss %p: abandon conn attempt \n",__func__, h);
		h->seqstate = SSSEQ_IDLE;
		lws_ss_event_helper(h, LWSSSCS_ALL_RETRIES_FAILED);
		return 1;
	}

	h->seqstate = SSSEQ_RECONNECT_WAIT;
	lws_ss_set_timeout_us(h, ms * LWS_US_PER_MS);

	lwsl_info("%s: ss %p: retry wait %"PRIu64"ms\n", __func__, h, ms);

	return 0;
}

int
lws_ss_client_connect(lws_ss_handle_t *h)
{
	struct lws_client_connect_info i;
	const struct ss_pcols *ssp;
	union lws_ss_contemp ct;
	char path[128];

	if (!h->policy) {
		lwsl_err("%s: ss with no policy\n", __func__);

		return -1;
	}

	/*
	 * We are already bound to a sink?
	 */

	if (h->h_sink)
		return 0;

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
	i.context = h->context;

	if (h->policy->flags & LWSSSPOLF_TLS) {
		lwsl_info("%s: using tls\n", __func__);
		i.ssl_connection = LCCSCF_USE_SSL;

		if (!h->policy->trust_store) {
			lwsl_err("%s: tls required but no policy trust store\n",
				 __func__);

			return -1;
		}

		i.vhost = lws_get_vhost_by_name(h->context,
						h->policy->trust_store->name);
		if (!i.vhost) {
			lwsl_err("%s: missing vh for policy ca\n", __func__);

			return -1;
		}
	}

	i.address = h->policy->endpoint;
	i.port = h->policy->port;
	i.host = i.address;
	i.origin = i.address;
	i.opaque_user_data = h;
	i.seq = h->seq;
	i.retry_and_idle_policy = h->policy->retry_bo;
	i.sys_tls_client_cert = h->policy->client_cert;

	i.path = "";

	ssp = ss_pcols[(int)h->policy->protocol];
	if (!ssp) {
		lwsl_err("%s: unsupported protocol\n", __func__);

		return -1;
	}
	i.alpn = ssp->alpn;

	/*
	 * For http, we can get the method from the http object, override in
	 * the protocol-specific munge callback below if not http
	 */
	i.method = h->policy->u.http.method;
	i.protocol = ssp->protocol_name; /* lws protocol name */
	i.local_protocol_name = i.protocol;

	ssp->munge(h, path, sizeof(path), &i, &ct);

	i.pwsi = &h->wsi;

	if (h->policy->plugins[0] && h->policy->plugins[0]->munge)
		h->policy->plugins[0]->munge(h, path, sizeof(path));

	lwsl_info("%s: connecting %s, '%s' '%s' %s\n", __func__, i.method,
			i.alpn, i.address, i.path);

	h->txn_ok = 0;
	if (lws_ss_event_helper(h, LWSSSCS_CONNECTING))
		return -1;

	if (!lws_client_connect_via_info(&i)) {
		lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		lws_ss_backoff(h);

		return 1;
	}

	return 0;
}


/*
 * Public API
 */

/*
 * Create either a stream or a sink
 */

int
lws_ss_create(struct lws_context *context, int tsi, const lws_ss_info_t *ssi,
	      void *opaque_user_data, lws_ss_handle_t **ppss,
	      struct lws_sequencer *seq_owner, const char **ppayload_fmt)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	const lws_ss_policy_t *pol;
	lws_ss_metadata_t *smd;
	lws_ss_handle_t *h;
	size_t size;
	void **v;
	char *p;
	int n;

	pol = lws_ss_policy_lookup(context, ssi->streamtype);
	if (!pol) {
		lwsl_err("%s: unknown stream type %s\n", __func__,
			 ssi->streamtype);
		return 1;
	}

	if (ssi->register_sink) {
		/*
		 * This can register a secure streams sink as well as normal
		 * secure streams connections.  If that's what's happening,
		 * confirm the policy agrees that this streamtype should be
		 * directed to a sink.
		 */
		if (!(pol->flags & LWSSSPOLF_LOCAL_SINK)) {
			/*
			 * Caller wanted to create a sink for this streamtype,
			 * but the policy does not agree the streamtype should
			 * be routed to a local sink.
			 */
			lwsl_err("%s: %s policy does not allow local sink\n",
				 __func__, ssi->streamtype);

			return 1;
		}
	} else {

		if (!(pol->flags & LWSSSPOLF_LOCAL_SINK)) {

		}
//		lws_dll2_foreach_safe(&pt->ss_owner, NULL, lws_ss_destroy_dll);
	}

	/*
	 * We overallocate and point to things in the overallocation...
	 *
	 * 1) the user_alloc from the stream info
	 * 2) network auth plugin instantiation data
	 * 3) stream auth plugin instantiation data
	 * 4) as many metadata pointer structs as the policy tells
	 * 5) the streamtype name (length is not aligned)
	 *
	 * ... when we come to destroy it, just one free to do.
	 */

	size = sizeof(*h) + ssi->user_alloc + strlen(ssi->streamtype) + 1;
	if (pol->plugins[0])
		size += pol->plugins[0]->alloc;
	if (pol->plugins[1])
		size += pol->plugins[1]->alloc;
	size += pol->metadata_count * sizeof(lws_ss_metadata_t);

	h = lws_zalloc(size, __func__);
	if (!h)
		return 2;

	h->info = *ssi;
	h->policy = pol;
	h->context = context;
	h->tsi = tsi;
	h->seq = seq_owner;

	/* start of overallocated area */
	p = (char *)&h[1];

	/* set the handle pointer in the user data struct */
	v = (void **)(p + ssi->handle_offset);
	*v = h;

	/* set the opaque user data in the user data struct */
	v = (void **)(p + ssi->opaque_user_data_offset);
	*v = opaque_user_data;

	p += ssi->user_alloc;

	if (pol->plugins[0]) {
		h->nauthi = p;
		p += pol->plugins[0]->alloc;
	}
	if (pol->plugins[1]) {
		h->sauthi = p;
		p += pol->plugins[1]->alloc;
	}

	if (pol->metadata_count) {
		h->metadata = (lws_ss_metadata_t *)p;
		p += pol->metadata_count * sizeof(lws_ss_metadata_t);

		lwsl_info("%s: %s metadata count %d\n", __func__,
			  pol->streamtype, pol->metadata_count);
	}

	smd = pol->metadata;
	for (n = 0; n < pol->metadata_count; n++) {
		h->metadata[n].name = smd->name;
		if (n + 1 == pol->metadata_count)
			h->metadata[n].next = NULL;
		else
			h->metadata[n].next = &h->metadata[n + 1];
		smd = smd->next;
	}

	memcpy(p, ssi->streamtype, strlen(ssi->streamtype) + 1);
	h->info.streamtype = p;

	lws_pt_lock(pt, __func__);
	lws_dll2_add_head(&h->list, &pt->ss_owner);
	lws_pt_unlock(pt);

	if (ppss)
		*ppss = h;

	if (ppayload_fmt)
		*ppayload_fmt = pol->payload_fmt;

	if (ssi->register_sink) {
		/*
		 *
		 */
	}

	lws_ss_event_helper(h, LWSSSCS_CREATING);

	if (!ssi->register_sink && (h->policy->flags & LWSSSPOLF_NAILED_UP))
		if (lws_ss_client_connect(h))
			lws_ss_backoff(h);

	return 0;
}

void
lws_ss_destroy(lws_ss_handle_t **ppss)
{
	struct lws_context_per_thread *pt;
	lws_ss_handle_t *h = *ppss;
	lws_ss_metadata_t *pmd;

	if (!h)
		return;

	if (h->wsi) {
		/*
		 * Don't let the wsi point to us any more,
		 * we (the ss object bound to the wsi) are going away now
		 */
//		lws_set_opaque_user_data(h->wsi, NULL);
		lws_set_timeout(h->wsi, 1, LWS_TO_KILL_SYNC);
	}

	pt = &h->context->pt[h->tsi];

	lws_pt_lock(pt, __func__);
	*ppss = NULL;
	lws_dll2_remove(&h->list);
	lws_dll2_remove(&h->to_list);
	lws_ss_event_helper(h, LWSSSCS_DESTROYING);
	lws_pt_unlock(pt);

	/* in proxy case, metadata value on heap may need cleaning up */

	pmd = h->metadata;
	while (pmd) {
		lwsl_info("%s: pmd %p\n", __func__, pmd);
		if (pmd->value_on_lws_heap)
			lws_free_set_NULL(pmd->value);
		pmd = pmd->next;
	}

	lws_sul_schedule(h->context, 0, &h->sul, NULL, LWS_SET_TIMER_USEC_CANCEL);

	lws_free_set_NULL(h);
}

void
lws_ss_request_tx(lws_ss_handle_t *h)
{
	lwsl_info("%s: wsi %p\n", __func__, h->wsi);

	if (h->wsi) {
		lws_callback_on_writable(h->wsi);

		return;
	}

	if (h->seqstate != SSSEQ_IDLE &&
	    h->seqstate != SSSEQ_DO_RETRY)
		return;

	h->seqstate = SSSEQ_TRY_CONNECT;
	lws_ss_event_helper(h, LWSSSCS_POLL);

	if (lws_ss_client_connect(h))
		lws_ss_backoff(h);
}

void
lws_ss_request_tx_len(lws_ss_handle_t *h, unsigned long len)
{
	if (h->wsi)
		h->wsi->http.writeable_len = len;
	else
		h->writeable_len = len;
	lws_ss_request_tx(h);
}

/*
 * private helpers
 */

/* used on context destroy when iterating listed lws_ss on a pt */

int
lws_ss_destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_ss_handle_t *h = lws_container_of(d, lws_ss_handle_t, list);

	lws_ss_destroy(&h);

	return 0;
}

struct lws_sequencer *
lws_ss_get_sequencer(lws_ss_handle_t *h)
{
	return h->seq;
}

struct lws_context *
lws_ss_get_context(struct lws_ss_handle *h)
{
	return h->context;
}

const char *
lws_ss_rideshare(struct lws_ss_handle *h)
{
	if (!h->rideshare)
		return h->policy->streamtype;

	return h->rideshare->streamtype;
}

int
lws_ss_add_peer_tx_credit(struct lws_ss_handle *h, int32_t bump)
{
	const struct ss_pcols *ssp;

	ssp = ss_pcols[(int)h->policy->protocol];

	if (h->wsi && ssp && ssp->tx_cr_add)
		return ssp->tx_cr_add(h, bump);

	return 0;
}

int
lws_ss_get_est_peer_tx_credit(struct lws_ss_handle *h)
{
	const struct ss_pcols *ssp;

	ssp = ss_pcols[(int)h->policy->protocol];

	if (h->wsi && ssp && ssp->tx_cr_add)
		return ssp->tx_cr_est(h);

	return 0;
}
