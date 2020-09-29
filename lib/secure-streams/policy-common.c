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

#if defined(LWS_WITH_SYS_SMD)
const lws_ss_policy_t pol_smd = {
	.flags			= 0, /* have to set something for windows */
};
#endif

const lws_ss_policy_t *
lws_ss_policy_lookup(const struct lws_context *context, const char *streamtype)
{
	const lws_ss_policy_t *p = context->pss_policies;

	if (!streamtype)
		return NULL;

#if defined(LWS_WITH_SYS_SMD)
	if (!strcmp(streamtype, LWS_SMD_STREAMTYPENAME))
		return &pol_smd;
#endif

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
		lwsl_info("%s: unknown metadata %s\n", __func__, name);
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

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
static int
fe_lws_ss_destroy(struct lws_dll2 *d, void *user)
{
	lws_ss_handle_t *h = lws_container_of(d, lws_ss_handle_t, list);

	lws_ss_destroy(&h);

	return 0;
}
#endif

/*
 * Dynamic policy: we want to one-time create the vhost for the policy and the
 * trust store behind it.
 *
 * Static policy: We want to make use of a trust store / vhost from the policy and add to its
 * ss-refcount.
 */

struct lws_vhost *
lws_ss_policy_ref_trust_store(struct lws_context *context,
			      const lws_ss_policy_t *pol, char doref)
{
	struct lws_context_creation_info i;
	struct lws_vhost *v;
	int n;

	memset(&i, 0, sizeof(i));

	if (!pol->trust.store) {
		v = lws_get_vhost_by_name(context, "_ss_default");
		if (!v) {
			/* corner case... there's no trust store used */
			i.options = context->options;
			i.vhost_name = "_ss_default";
			i.port = CONTEXT_PORT_NO_LISTEN;
			v = lws_create_vhost(context, &i);
			if (!v) {
				lwsl_err("%s: failed to create vhost %s\n",
					 __func__, i.vhost_name);

				return NULL;
			}
		}

		goto accepted;
	}
	v = lws_get_vhost_by_name(context, pol->trust.store->name);
	if (v) {
		lwsl_debug("%s: vh already exists\n", __func__);
		goto accepted;
	}

	i.options = context->options;
	i.vhost_name = pol->trust.store->name;
	lwsl_debug("%s: %s\n", __func__, i.vhost_name);
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_CLIENT)
	i.client_ssl_ca_mem = pol->trust.store->ssx509[0]->ca_der;
	i.client_ssl_ca_mem_len = (unsigned int)
			pol->trust.store->ssx509[0]->ca_der_len;
#endif
	i.port = CONTEXT_PORT_NO_LISTEN;
	lwsl_info("%s: %s trust store initial '%s'\n", __func__,
		  i.vhost_name, pol->trust.store->ssx509[0]->vhost_name);

	v = lws_create_vhost(context, &i);
	if (!v) {
		lwsl_err("%s: failed to create vhost %s\n",
			 __func__, i.vhost_name);
		return NULL;
	} else
		v->from_ss_policy = 1;

	for (n = 1; v && n < pol->trust.store->count; n++) {
		lwsl_info("%s: add '%s' to trust store\n", __func__,
			  pol->trust.store->ssx509[n]->vhost_name);
#if defined(LWS_WITH_TLS)
		if (lws_tls_client_vhost_extra_cert_mem(v,
				pol->trust.store->ssx509[n]->ca_der,
				pol->trust.store->ssx509[n]->ca_der_len)) {
			lwsl_err("%s: add extra cert failed\n",
					__func__);
			return NULL;
		}
#endif
	}

accepted:
#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	if (doref)
		v->ss_refcount++;
#endif

	return v;
}

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
int
lws_ss_policy_unref_trust_store(struct lws_context *context,
				const lws_ss_policy_t *pol)
{
	struct lws_vhost *v;
	const char *name = "_ss_default";

	if (pol->trust.store)
		name = pol->trust.store->name;

	v = lws_get_vhost_by_name(context, name);
	if (!v || !v->from_ss_policy)
		return 0;

	assert(v->ss_refcount);

	v->ss_refcount--;
	if (!v->ss_refcount) {
		lwsl_notice("%s: destroying vh %s\n", __func__, name);
		lws_vhost_destroy(v);
	}

	return 1;
}
#endif

int
lws_ss_policy_set(struct lws_context *context, const char *name)
{
	int ret = 0;

#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	struct policy_cb_args *args = (struct policy_cb_args *)context->pol_args;
	const lws_ss_policy_t *pol;
	struct lws_vhost *v;
	lws_ss_x509_t *x;
	char buf[16];
	int m;

	/*
	 * Parsing seems to have succeeded, and we're going to use the new
	 * policy that's laid out in args->ac
	 */

	lejp_destruct(&args->jctx);

	if (context->ac_policy) {
		int n;

		/*
		 * any existing ss created with the old policy have to go away
		 * now, since they point to the shortly-to-be-destroyed old
		 * policy
		 */

		for (n = 0; n < context->count_threads; n++) {
			struct lws_context_per_thread *pt = &context->pt[n];

			lws_dll2_foreach_safe(&pt->ss_owner, NULL, fe_lws_ss_destroy);
		}

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

	(void)m;
	lwsl_info("%s: %s, pad %d%c: %s\n", __func__, buf, m, '%', name);

	/* Create vhosts for each type of trust store */

	/*
	 * We get called from context creation... instantiates
	 * vhosts with client tls contexts set up for each unique CA.
	 *
	 * We create the vhosts by walking streamtype list and create vhosts
	 * using trust store name if it's a client connection that doesn't
	 * already exist.
	 */

	pol = context->pss_policies;
	while (pol) {
		if (!(pol->flags & LWSSSPOLF_SERVER)) {
			v = lws_ss_policy_ref_trust_store(context, pol,
						  0 /* no refcount inc */);
			if (!v)
				ret = 1;
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

	/*
	 * For dynamic policy case, now we processed the x.509 CAs, we can free
	 * all of our originals.  For static policy, they're in .rodata, nothing
	 * to free.
	 */

	x = args->heads[LTY_X509].x;
	while (x) {
		/*
		 * Free all the client DER buffers now they have been parsed
		 * into tls library X.509 objects
		 */
		if (!x->keep) { /* used for server */
			lws_free((void *)x->ca_der);
			x->ca_der = NULL;
		}

		x = x->next;
	}

	/* and we can discard the parsing args object now, invalidating args */

	lws_free_set_NULL(context->pol_args);
#endif

	return ret;
}
