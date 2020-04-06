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
 *
 * This file contains the stuff related to secure streams policy, it's always
 * built if LWS_WITH_SECURE_STREAMS enabled.
 */

#include <private-lib-core.h>

const lws_ss_policy_t *
lws_ss_policy_lookup(const struct lws_context *context, const char *streamtype)
{
	const lws_ss_policy_t *p = context->pss_policies;

	if (!streamtype)
		return NULL;

	while (p) {
		if (!strcmp(p->streamtype, streamtype))
			return p;
		p = p->next;
	}

	return NULL;
}

int
lws_ss_set_metadata(struct lws_ss_handle *h, const char *name,
		    const void *value, size_t len)
{
	lws_ss_metadata_t *omd = lws_ss_policy_metadata(h->policy, name);

	if (!omd) {
		lwsl_err("%s: unknown metadata %s\n", __func__, name);
		return 1;
	}

	h->metadata[omd->length].name = name;
	h->metadata[omd->length].value = (void *)value;
	h->metadata[omd->length].length = len;

	return 0;
}

lws_ss_metadata_t *
lws_ss_get_handle_metadata(struct lws_ss_handle *h, const char *name)
{
	lws_ss_metadata_t *omd = lws_ss_policy_metadata(h->policy, name);

	if (!omd)
		return NULL;

	return &h->metadata[omd->length];
}

lws_ss_metadata_t *
lws_ss_policy_metadata(const lws_ss_policy_t *p, const char *name)
{
	lws_ss_metadata_t *pmd = p->metadata;

	while (pmd) {
		if (pmd->name && !strcmp(name, pmd->name))
			return pmd;
		pmd = pmd->next;
	}

	return NULL;
}

lws_ss_metadata_t *
lws_ss_policy_metadata_index(const lws_ss_policy_t *p, size_t index)
{
	lws_ss_metadata_t *pmd = p->metadata;

	while (pmd) {
		if (pmd->length == index)
			return pmd;
		pmd = pmd->next;
	}

	return NULL;
}

int
lws_ss_policy_set(struct lws_context *context, const char *name)
{
#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	struct policy_cb_args *args = (struct policy_cb_args *)context->pol_args;
	lws_ss_x509_t *x;
	char buf[16];
	int m;
#endif
	const lws_ss_policy_t *pol;
	struct lws_vhost *v;
	int ret = 0;

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	/*
	 * Parsing seems to have succeeded, and we're going to use the new
	 * policy that's laid out in args->ac
	 */

	lejp_destruct(&args->jctx);

	if (context->ac_policy) {

		/*
		 * So this is a bit fun-filled, we already had a policy in
		 * force, perhaps it was the default policy that's just good for
		 * fetching the real policy, and we're doing that now.
		 *
		 * We can destroy all the policy-related direct allocations
		 * easily because they're cleanly in a single lwsac...
		 */
		lwsac_free(&context->ac_policy);

		/*
		 * ...but when we did the trust stores, we created vhosts for
		 * each.  We need to destroy those now too, and recreate new
		 * ones from the new policy, perhaps with different X.509s.
		 */

		v = context->vhost_list;
		while (v) {
			if (v->from_ss_policy) {
				struct lws_vhost *vh = v->vhost_next;
				lwsl_debug("%s: destroying vh %p\n", __func__, v);
				lws_vhost_destroy(v);
				v = vh;
				continue;
			}
			v = v->vhost_next;
		}

		lws_check_deferred_free(context, 0, 1);
	}

	context->pss_policies = args->heads[LTY_POLICY].p;
	context->ac_policy = args->ac;

	lws_humanize(buf, sizeof(buf), lwsac_total_alloc(args->ac),
			humanize_schema_si_bytes);
	if (lwsac_total_alloc(args->ac))
		m = (int)((lwsac_total_overhead(args->ac) * 100) /
				lwsac_total_alloc(args->ac));
	else
		m = 0;

	lwsl_notice("%s: %s, pad %d%c: %s\n", __func__, buf, m, '%', name);
#endif

	/* Create vhosts for each type of trust store */

	pol = context->pss_policies;
	while (pol) {
		struct lws_context_creation_info i;
		int n;

		memset(&i, 0, sizeof(i));

		/*
		 * We get called from context creation... instantiates
		 * vhosts with client tls contexts set up for each unique CA.
		 *
		 * For compatibility with static policy, we create the vhosts
		 * by walking streamtype list and create vhosts using trust
		 * store name if it doesn't already exist.
		 */

		if (!pol->trust_store) {
			pol = pol->next;
			continue;
		}
		v = lws_get_vhost_by_name(context, pol->trust_store->name);
		if (v) {
			/* vhost for this trust store already exists, skip */
			pol = pol->next;
			continue;
		}

		i.options = context->options;
		i.vhost_name = pol->trust_store->name;
		lwsl_debug("%s: %s\n", __func__, i.vhost_name);
		i.client_ssl_ca_mem = pol->trust_store->ssx509[0]->ca_der;
		i.client_ssl_ca_mem_len = (unsigned int)
				pol->trust_store->ssx509[0]->ca_der_len;
		i.port = CONTEXT_PORT_NO_LISTEN;
		lwsl_info("%s: %s trust store initial '%s'\n", __func__,
			  i.vhost_name, pol->trust_store->ssx509[0]->vhost_name);

		v = lws_create_vhost(context, &i);
		if (!v) {
			lwsl_err("%s: failed to create vhost %s\n",
				 __func__, i.vhost_name);
			ret = 1;
		} else
			v->from_ss_policy = 1;

		for (n = 1; v && n < pol->trust_store->count; n++) {
			lwsl_info("%s: add '%s' to trust store\n", __func__,
				  pol->trust_store->ssx509[n]->vhost_name);
			if (lws_tls_client_vhost_extra_cert_mem(v,
					pol->trust_store->ssx509[n]->ca_der,
					pol->trust_store->ssx509[n]->ca_der_len)) {
				lwsl_err("%s: add extra cert failed\n",
						__func__);
				ret = 1;
			}
		}

		pol = pol->next;
	}

#if defined(LWS_WITH_SOCKS5)

	/*
	 * ... we need to go through every vhost updating its understanding of
	 * which socks5 proxy to use...
	 */

	v = context->vhost_list;
	while (v) {
		lws_set_socks(v, args->socks5_proxy);
		v = v->vhost_next;
	}
	if (context->vhost_system)
		lws_set_socks(context->vhost_system, args->socks5_proxy);

	if (args->socks5_proxy)
		lwsl_notice("%s: global socks5 proxy: %s\n", __func__,
			    args->socks5_proxy);
#endif

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)

	/*
	 * For dynamic policy case, now we processed the x.509 CAs, we can free
	 * all of our originals.  For static policy, they're in .rodata, nothing
	 * to free.
	 */

	x = args->heads[LTY_X509].x;
	while (x) {
		/*
		 * Free all the DER buffers now they have been parsed into
		 * tls library X.509 objects
		 */
		lws_free((void *)x->ca_der);
		x->ca_der = NULL;
		x = x->next;
	}

	/* and we can discard the parsing args object now, invalidating args */

	lws_free_set_NULL(context->pol_args);
#endif

	return ret;
}

