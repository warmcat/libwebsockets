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
	&ss_pcol_raw,		/* LWSSSP_RAW */
	NULL,
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
	"LWSSSCS_TIMEOUT",
	"LWSSSCS_SERVER_TXN",
	"LWSSSCS_SERVER_UPGRADE",
};

const char *
lws_ss_state_name(int state)
{
	if (state >= (int)LWS_ARRAY_SIZE(state_names))
		return "unknown";

	return state_names[state];
}

lws_ss_state_return_t
lws_ss_event_helper(lws_ss_handle_t *h, lws_ss_constate_t cs)
{
	lws_ss_state_return_t r;

	if (!h)
		return LWSSSSRET_OK;

#if defined(LWS_WITH_SEQUENCER)
	/*
	 * A parent sequencer for the ss is optional, if we have one, keep it
	 * informed of state changes on the ss connection
	 */
	if (h->seq && cs != LWSSSCS_DESTROYING)
		lws_seq_queue_event(h->seq, LWSSEQ_SS_STATE_BASE + cs,
				    (void *)h, NULL);
#endif

	if (h->info.state) {
		r = h->info.state(ss_to_userobj(h), NULL, cs, 0);
#if defined(LWS_WITH_SERVER)
		if ((h->info.flags & LWSSSINFLAGS_ACCEPTED) &&
		    cs == LWSSSCS_DISCONNECTED)
			r = LWSSSSRET_DESTROY_ME;
#endif
		return r;
	}

	return LWSSSSRET_OK;
}

int
_lws_ss_handle_state_ret(lws_ss_state_return_t r, struct lws *wsi,
			 lws_ss_handle_t **ph)
{
	if (r == LWSSSSRET_DESTROY_ME) {
		if (wsi)
			lws_set_opaque_user_data(wsi, NULL);
		(*ph)->wsi = NULL;
		lws_ss_destroy(ph);
	}

	return -1; /* close connection */
}

static void
lws_ss_timeout_sul_check_cb(lws_sorted_usec_list_t *sul)
{
	lws_ss_handle_t *h = lws_container_of(sul, lws_ss_handle_t, sul);

	lwsl_notice("%s: retrying ss h %p (%s) after backoff\n", __func__, h,
		 h->policy->streamtype);
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

	if (out)
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
	__lws_sul_insert_us(&pt->pt_sul_owner[
	            !!(h->policy->flags & LWSSSPOLF_WAKE_SUSPEND__VALIDITY)],
		    &h->sul, us);

	return 0;
}

lws_ss_state_return_t
lws_ss_backoff(lws_ss_handle_t *h)
{
	uint64_t ms;
	char conceal;

	if (h->seqstate == SSSEQ_RECONNECT_WAIT)
		return LWSSSSRET_OK;

	/* figure out what we should do about another retry */

	lwsl_info("%s: ss %p: retry backoff after failure\n", __func__, h);
	ms = lws_retry_get_delay_ms(h->context, h->policy->retry_bo,
				    &h->retry, &conceal);
	if (!conceal) {
		lwsl_info("%s: ss %p: abandon conn attempt \n",__func__, h);
		h->seqstate = SSSEQ_IDLE;

		return lws_ss_event_helper(h, LWSSSCS_ALL_RETRIES_FAILED);
	}

	h->seqstate = SSSEQ_RECONNECT_WAIT;
	lws_ss_set_timeout_us(h, ms * LWS_US_PER_MS);

	lwsl_info("%s: ss %p: retry wait %"PRIu64"ms\n", __func__, h, ms);

	return LWSSSSRET_OK;
}

#if defined(LWS_WITH_SYS_SMD)

/*
 * Local SMD <-> SS
 *
 * We pass received messages through to the SS handler synchronously, using the
 * lws service thread context.
 *
 * After the SS is created and registered, still nothing is going to come here
 * until the peer sends us his rx_class_mask and we update his registration with
 * it, because from SS creation his rx_class_mask defaults to 0.
 */

static int
lws_smd_ss_cb(void *opaque, lws_smd_class_t _class,
	      lws_usec_t timestamp, void *buf, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)opaque;
	uint8_t *p = (uint8_t *)buf - LWS_SMD_SS_RX_HEADER_LEN;

	/*
	 * When configured with SS enabled, lws over-allocates
	 * LWS_SMD_SS_RX_HEADER_LEN bytes behind the payload of the queued
	 * message, for prepending serialized class and timestamp data in-band
	 * with the payload.
	 */

	lws_ser_wu64be(p, _class);
	lws_ser_wu64be(p + 8, timestamp);

	if (h->info.rx)
		h->info.rx((void *)&h[1], p, len + LWS_SMD_SS_RX_HEADER_LEN,
		      LWSSS_FLAG_SOM | LWSSS_FLAG_EOM);

	return 0;
}

static void
lws_ss_smd_tx_cb(lws_sorted_usec_list_t *sul)
{
	lws_ss_handle_t *h = lws_container_of(sul, lws_ss_handle_t, u.smd.sul_write);
	uint8_t buf[LWS_SMD_SS_RX_HEADER_LEN + LWS_SMD_MAX_PAYLOAD], *p;
	size_t len = sizeof(buf);
	lws_smd_class_t _class;
	int flags = 0, n;

	if (!h->info.tx)
		return;

	n = h->info.tx(&h[1], h->txord++, buf, &len, &flags);
	if (n)
		/* nonzero return means don't want to send anything */
		return;

	// lwsl_notice("%s: (SS %p bound to _lws_smd creates message) tx len %d\n", __func__, h, (int)len);
	// lwsl_hexdump_notice(buf, len);

	assert(len >= LWS_SMD_SS_RX_HEADER_LEN);
	_class = (lws_smd_class_t)lws_ser_ru64be(buf);
	p = lws_smd_msg_alloc(h->context, _class, len - LWS_SMD_SS_RX_HEADER_LEN);
	if (!p) {
		// this can be rejected if nobody listening for this class
		//lwsl_notice("%s: failed to alloc\n", __func__);
		return;
	}

	memcpy(p, buf + LWS_SMD_SS_RX_HEADER_LEN, len - LWS_SMD_SS_RX_HEADER_LEN);
	if (lws_smd_msg_send(h->context, p)) {
		lwsl_notice("%s: failed to queue\n", __func__);
		return;
	}
}

#endif

int
_lws_ss_client_connect(lws_ss_handle_t *h, int is_retry)
{
	const char *prot, *_prot, *ipath, *_ipath, *ads, *_ads;
	struct lws_client_connect_info i;
	const struct ss_pcols *ssp;
	size_t used_in, used_out;
	union lws_ss_contemp ct;
	char path[1024], ep[96];
	lws_ss_state_return_t r;
	int port, _port, tls;
	lws_strexp_t exp;

	if (!h->policy) {
		lwsl_err("%s: ss with no policy\n", __func__);

		return -1;
	}

	/*
	 * We are already bound to a sink?
	 */

//	if (h->h_sink)
//		return 0;

	if (!is_retry)
		h->retry = 0;

#if defined(LWS_WITH_SYS_SMD)
	if (h->policy == &pol_smd) {

		if (h->u.smd.smd_peer)
			return 0;

		// lwsl_notice("%s: received connect for _lws_smd, registering for class mask 0x%x\n",
		//		__func__, h->info.manual_initial_tx_credit);

		h->u.smd.smd_peer = lws_smd_register(h->context, h,
					(h->info.flags & LWSSSINFLAGS_PROXIED) ?
						LWSSMDREG_FLAG_PROXIED_SS : 0,
					h->info.manual_initial_tx_credit,
					lws_smd_ss_cb);
		if (!h->u.smd.smd_peer)
			return -1;

		if (lws_ss_event_helper(h, LWSSSCS_CONNECTING))
			return -1;
		// lwsl_err("%s: registered SS SMD\n", __func__);
		if (lws_ss_event_helper(h, LWSSSCS_CONNECTED))
			return -1;
		return 0;
	}
#endif

	/*
	 * We're going to substitute ${metadata} in the endpoint at connection-
	 * time, so this can be set dynamically...
	 */

	lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata, ep, sizeof(ep));

	if (lws_strexp_expand(&exp, h->policy->endpoint,
			      strlen(h->policy->endpoint),
			      &used_in, &used_out) != LSTRX_DONE) {
		lwsl_err("%s: address strexp failed\n", __func__);

		return -1;
	}

	/*
	 * ... in some cases, we might want the user to be able to override
	 * some policy settings by what he provided in there.  For example,
	 * if he set the endpoint to "https://myendpoint.com:4443/mypath" it
	 * might be quite convenient to override the policy to follow the info
	 * that was given for at least server, port and the url path.
	 */

	_port = port = h->policy->port;
	_prot = prot = NULL;
	_ipath = ipath = "";
	_ads = ads = ep;

	if (strchr(ep, ':') &&
	    !lws_parse_uri(ep, &_prot, &_ads, &_port, &_ipath)) {
		lwsl_debug("%s: using uri parse results '%s' '%s' %d '%s'\n",
				__func__, _prot, _ads, _port, _ipath);
		prot = _prot;
		ads = _ads;
		port = _port;
		ipath = _ipath;
	}

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
	i.context = h->context;
	tls = !!(h->policy->flags & LWSSSPOLF_TLS);

	if (prot && (!strcmp(prot, "http") || !strcmp(prot, "ws") ||
		     !strcmp(prot, "mqtt")))
		tls = 0;

	if (tls) {
		lwsl_info("%s: using tls\n", __func__);
		i.ssl_connection = LCCSCF_USE_SSL;

		if (!h->policy->trust.store)
			lwsl_info("%s: using platform trust store\n", __func__);
		else {

			i.vhost = lws_get_vhost_by_name(h->context,
					h->policy->trust.store->name);
			if (!i.vhost) {
				lwsl_err("%s: missing vh for policy %s\n",
					 __func__,
					 h->policy->trust.store->name);

				return -1;
			}
		}
	}

	if (h->policy->flags & LWSSSPOLF_WAKE_SUSPEND__VALIDITY)
		i.ssl_connection |= LCCSCF_WAKE_SUSPEND__VALIDITY;

	i.address		= ads;
	i.port			= port;
	i.host			= i.address;
	i.origin		= i.address;
	i.opaque_user_data	= h;
	i.seq			= h->seq;
	i.retry_and_idle_policy	= h->policy->retry_bo;
	i.sys_tls_client_cert	= h->policy->client_cert;

	i.path			= ipath;
		/* if this is not "", munge should use it instead of policy
		 * url path
		 */

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
	i.protocol = ssp->protocol->name; /* lws protocol name */
	i.local_protocol_name = i.protocol;

	if (ssp->munge) /* eg, raw doesn't use; endpoint strexp already done */
		ssp->munge(h, path, sizeof(path), &i, &ct);

	i.pwsi = &h->wsi;

#if defined(LWS_WITH_SSPLUGINS)
	if (h->policy->plugins[0] && h->policy->plugins[0]->munge)
		h->policy->plugins[0]->munge(h, path, sizeof(path));
#endif

	lwsl_info("%s: connecting %s, '%s' '%s' %s\n", __func__, i.method,
			i.alpn, i.address, i.path);

	h->txn_ok = 0;
	r = lws_ss_event_helper(h, LWSSSCS_CONNECTING);
	if (r)
		return r;

	if (!lws_client_connect_via_info(&i)) {
		r = lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		if (r)
			return r;

		r = lws_ss_backoff(h);
		if (r)
			return r;

		return 1;
	}

	return 0;
}

int
lws_ss_client_connect(lws_ss_handle_t *h)
{
	return _lws_ss_client_connect(h, 0);
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
		lwsl_info("%s: unknown stream type %s\n", __func__,
			  ssi->streamtype);
		return 1;
	}

	if (ssi->flags & LWSSSINFLAGS_REGISTER_SINK) {
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
#if defined(LWS_WITH_SSPLUGINS)
	if (pol->plugins[0])
		size += pol->plugins[0]->alloc;
	if (pol->plugins[1])
		size += pol->plugins[1]->alloc;
#endif
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

#if defined(LWS_WITH_SSPLUGINS)
	if (pol->plugins[0]) {
		h->nauthi = p;
		p += pol->plugins[0]->alloc;
	}
	if (pol->plugins[1]) {
		h->sauthi = p;
		p += pol->plugins[1]->alloc;
	}
#endif

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
	/* don't mark accepted ss as being the server */
	if (ssi->flags & LWSSSINFLAGS_SERVER)
		h->info.flags &= ~LWSSSINFLAGS_SERVER;
	h->info.streamtype = p;

	lws_pt_lock(pt, __func__);
	lws_dll2_add_head(&h->list, &pt->ss_owner);
	lws_pt_unlock(pt);

	if (ppss)
		*ppss = h;

	if (ppayload_fmt)
		*ppayload_fmt = pol->payload_fmt;

	if (ssi->flags & LWSSSINFLAGS_SERVER)
		/*
		 * return early for accepted connection flow
		 */
		return 0;

#if defined(LWS_WITH_SYS_SMD)
	/*
	 * For a local Secure Streams connection
	 */
	if (!(ssi->flags & LWSSSINFLAGS_PROXIED) &&
	    pol == &pol_smd) {
		lws_ss_state_return_t r;
		/*
		 * So he has asked to be wired up to SMD over a SS link.
		 * Register him as an smd participant in his own right.
		 *
		 * Just for this case, ssi->manual_initial_tx_credit is used
		 * to set the rx class mask (this is part of the SS serialization
		 * format as well)
		 */
		h->u.smd.smd_peer = lws_smd_register(context, h, 0,
						     ssi->manual_initial_tx_credit,
						     lws_smd_ss_cb);
		if (!h->u.smd.smd_peer)
			goto late_bail;
		lwsl_info("%s: registered SS SMD\n", __func__);
		r = lws_ss_event_helper(h, LWSSSCS_CONNECTING);
		if (r)
			return r;
		r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
		if (r)
			return r;
	}
#endif

#if defined(LWS_WITH_SERVER)
	if (h->policy->flags & LWSSSPOLF_SERVER) {
		const struct lws_protocols *pprot[3], **ppp = &pprot[0];
		struct lws_context_creation_info i;
		struct lws_vhost *vho;

		lwsl_info("%s: creating server\n", __func__);

		/*
		 * This streamtype represents a server, we're being asked to
		 * instantiate a corresponding vhost for it
		 */

		memset(&i, 0, sizeof i);

		i.iface		= h->policy->endpoint;
		i.vhost_name	= h->policy->streamtype;
		i.port		= h->policy->port;

		if (!ss_pcols[h->policy->protocol]) {
			lwsl_err("%s: unsupp protocol", __func__);
			goto late_bail;
		}

		*ppp++ = ss_pcols[h->policy->protocol]->protocol;
#if defined(LWS_ROLE_WS)
		if (h->policy->u.http.u.ws.subprotocol)
			/*
			 * He names a ws subprotocol, ie, we want to support
			 * ss-ws protocol in this vhost
			 */
			*ppp++ = &protocol_secstream_ws;
#endif
		*ppp = NULL;
		i.pprotocols = pprot;

#if defined(LWS_WITH_TLS)
		if (h->policy->flags & LWSSSPOLF_TLS) {
			i.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			i.server_ssl_cert_mem =
				h->policy->trust.server.cert->ca_der;
			i.server_ssl_cert_mem_len = (unsigned int)
				h->policy->trust.server.cert->ca_der_len;
			i.server_ssl_private_key_mem =
				h->policy->trust.server.key->ca_der;
			i.server_ssl_private_key_mem_len = (unsigned int)
				h->policy->trust.server.key->ca_der_len;
		}
#endif

		vho = lws_create_vhost(context, &i);
		if (!vho) {
			lwsl_err("%s: failed to create vh", __func__);
			goto late_bail;
		}

		/*
		 * Mark this vhost as having to apply ss server semantics to
		 * any incoming accepted connection
		 */
		vho->ss_handle = h;

		lwsl_notice("%s: created server %s\n", __func__,
				h->policy->streamtype);

		return 0;
	}
#endif

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)

	/*
	 * For static policy case, dynamically ref / instantiate the related
	 * trust store and vhost.  We do it by logical ss rather than connection
	 * because we don't want to expose the latency of creating the x.509
	 * trust store at the first connection.
	 *
	 * But it might be given the tls linkup takes time anyway, it can move
	 * to the ss connect code instead.
	 */

	if (!lws_ss_policy_ref_trust_store(context, h->policy, 1 /* do the ref */)) {
		lwsl_err("%s: unable to get vhost / trust store\n", __func__);
		goto late_bail;
	}
#endif

	if (lws_ss_event_helper(h, LWSSSCS_CREATING)) {
late_bail:
		lws_pt_lock(pt, __func__);
		lws_dll2_remove(&h->list);
		lws_pt_unlock(pt);
		lws_free(h);

		return 1;
	}

	if (!(ssi->flags & LWSSSINFLAGS_REGISTER_SINK) &&
	    ((h->policy->flags & LWSSSPOLF_NAILED_UP)
#if defined(LWS_WITH_SYS_SMD)
		|| ((h->policy == &pol_smd) //&&
		    //(ssi->flags & LWSSSINFLAGS_PROXIED))
				)
#endif
			    ))
		if (_lws_ss_client_connect(h, 0)) {
			if (lws_ss_backoff(h))
				/* has been destroyed */
				return 1;
		}

	return 0;
}

void *
lws_ss_to_user_object(struct lws_ss_handle *h)
{
	return (void *)&h[1];
}

void
lws_ss_destroy(lws_ss_handle_t **ppss)
{
	struct lws_context_per_thread *pt;
	lws_ss_handle_t *h = *ppss;
	lws_ss_metadata_t *pmd;

	if (!h)
		return;

	if (h->destroying) {
		lwsl_info("%s: reentrant destroy\n", __func__);
		return;
	}
	h->destroying = 1;

	if (h->wsi) {
		/*
		 * Don't let the wsi point to us any more,
		 * we (the ss object bound to the wsi) are going away now
		 */
		lws_set_opaque_user_data(h->wsi, NULL);
		lws_set_timeout(h->wsi, 1, LWS_TO_KILL_SYNC);
	}

	/*
	 * if we bound an smd registration to the SS, unregister it
	 */

#if defined(LWS_WITH_SYS_SMD)
	if (h->policy == &pol_smd && h->u.smd.smd_peer) {
		lws_smd_unregister(h->u.smd.smd_peer);
		h->u.smd.smd_peer = NULL;
	}
#endif

	pt = &h->context->pt[h->tsi];

	lws_pt_lock(pt, __func__);
	*ppss = NULL;
	lws_dll2_remove(&h->list);
	lws_dll2_remove(&h->to_list);
	lws_sul_cancel(&h->sul_timeout);

	(void)lws_ss_event_helper(h, LWSSSCS_DESTROYING);
	lws_pt_unlock(pt);

	/* in proxy case, metadata value on heap may need cleaning up */

	pmd = h->metadata;
	while (pmd) {
		lwsl_info("%s: pmd %p\n", __func__, pmd);
		if (pmd->value_on_lws_heap)
			lws_free_set_NULL(pmd->value);
		pmd = pmd->next;
	}

	lws_sul_cancel(&h->sul);

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)

	/*
	 * For static policy case, dynamically ref / instantiate the related
	 * trust store and vhost.  We do it by logical ss rather than connection
	 * because we don't want to expose the latency of creating the x.509
	 * trust store at the first connection.
	 *
	 * But it might be given the tls linkup takes time anyway, it can move
	 * to the ss connect code instead.
	 */


	lws_ss_policy_unref_trust_store(h->context, h->policy);
#endif

#if defined(LWS_WITH_SERVER)
	if (h->policy->flags & LWSSSPOLF_SERVER) {
		struct lws_vhost *v = lws_get_vhost_by_name(h->context,
							h->policy->streamtype);

		/*
		 * For server, the policy describes a vhost that implements the
		 * server, when we take down the ss, we take down the related
		 * vhost (if it got that far)
		 */
		if (v)
			lws_vhost_destroy(v);
	}
#endif

	/* confirm no sul left scheduled in handle or user allocation object */
	lws_sul_debug_zombies(h->context, h, sizeof(*h) + h->info.user_alloc,
			      __func__);

	lws_free_set_NULL(h);
}

void
lws_ss_server_ack(struct lws_ss_handle *h, int nack)
{
	h->txn_resp = nack;
	h->txn_resp_set = 1;
}

lws_ss_state_return_t
lws_ss_request_tx(lws_ss_handle_t *h)
{
	lws_ss_state_return_t r;

	// lwsl_notice("%s: h %p, wsi %p\n", __func__, h, h->wsi);

	if (h->wsi) {
		lws_callback_on_writable(h->wsi);

		return LWSSSSRET_OK;
	}

	if (h->policy->flags & LWSSSPOLF_SERVER)
		return LWSSSSRET_OK;

	/*
	 * there's currently no wsi / connection associated with the ss handle
	 */

#if defined(LWS_WITH_SYS_SMD)
	if (h->policy == &pol_smd) {
		/*
		 * He's an _lws_smd... and no wsi... since we're just going
		 * to queue it, we could call his tx() right here, but rather
		 * than surprise him let's set a sul to do it next time around
		 * the event loop
		 */

		lws_sul_schedule(h->context, 0, &h->u.smd.sul_write,
				 lws_ss_smd_tx_cb, 1);

		return LWSSSSRET_OK;
	}
#endif

	if (h->seqstate != SSSEQ_IDLE &&
	    h->seqstate != SSSEQ_DO_RETRY)
		return LWSSSSRET_OK;

	h->seqstate = SSSEQ_TRY_CONNECT;
	r = lws_ss_event_helper(h, LWSSSCS_POLL);
	if (r)
		return r;

	/*
	 * Retries operate via lws_ss_request_tx(), explicitly ask for a
	 * reconnection to clear the retry limit
	 */
	r = _lws_ss_client_connect(h, 1);
	if (r == LWSSSSRET_DESTROY_ME)
		return r;

	if (r)
		return lws_ss_backoff(h);

	return LWSSSSRET_OK;
}

lws_ss_state_return_t
lws_ss_request_tx_len(lws_ss_handle_t *h, unsigned long len)
{
	if (h->wsi &&
	    (h->policy->protocol == LWSSSP_H1 ||
	     h->policy->protocol == LWSSSP_H2 ||
	     h->policy->protocol == LWSSSP_WS))
		h->wsi->http.writeable_len = len;
	else
		h->writeable_len = len;

	return lws_ss_request_tx(h);
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

/*
 * protocol-independent handler for ss timeout
 */

static void
lws_ss_to_cb(lws_sorted_usec_list_t *sul)
{
	lws_ss_handle_t *h = lws_container_of(sul, lws_ss_handle_t, sul_timeout);
	lws_ss_state_return_t r;

	lwsl_info("%s: ss %p timeout fired\n", __func__, h);

	r = lws_ss_event_helper(h, LWSSSCS_TIMEOUT);
	if (r == LWSSSSRET_DESTROY_ME) {
		if (h->wsi)
			lws_set_timeout(h->wsi, 1, LWS_TO_KILL_ASYNC);
		_lws_ss_handle_state_ret(r, NULL, &h);
	}
}

void
lws_ss_start_timeout(struct lws_ss_handle *h, unsigned int timeout_ms)
{
	if (!timeout_ms && !h->policy->timeout_ms)
		return;

	lws_sul_schedule(h->context, 0, &h->sul_timeout, lws_ss_to_cb,
			 (timeout_ms ? timeout_ms : h->policy->timeout_ms) *
			 LWS_US_PER_MS);
}

void
lws_ss_cancel_timeout(struct lws_ss_handle *h)
{
	lws_sul_cancel(&h->sul_timeout);
}

void
lws_ss_change_handlers(struct lws_ss_handle *h,
	lws_ss_state_return_t (*rx)(void *userobj, const uint8_t *buf,
				    size_t len, int flags),
	lws_ss_state_return_t (*tx)(void *userobj, lws_ss_tx_ordinal_t ord,
				    uint8_t *buf, size_t *len, int *flags),
	lws_ss_state_return_t (*state)(void *userobj, void *h_src /* ss handle type */,
				       lws_ss_constate_t state,
				       lws_ss_tx_ordinal_t ack))
{
	if (rx)
		h->info.rx = rx;
	if (tx)
		h->info.tx = tx;
	if (state)
		h->info.state = state;
}
