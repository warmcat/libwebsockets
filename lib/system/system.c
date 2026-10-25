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
 */

#include <private-lib-core.h>

/*
 * It's either a buflist (.is_direct = 0) or
 * a direct pointer + len (.is_direct = 1)
 */

const lws_system_ops_t *
lws_system_get_ops(struct lws_context *context)
{
	return context->system_ops;
}

#if !defined(LWS_WITH_SYS_NTPCLIENT)
int
lws_ntpc_trigger(struct lws_context *context)
{
	(void)context;

	return 1; /* there's no ntp client to ask */
}
#endif


void
lws_system_blob_direct_set(lws_system_blob_t *b, const uint8_t *ptr, size_t len)
{
	b->is_direct = 1;
	b->u.direct.ptr = ptr;
	b->u.direct.len = len;
}

void
lws_system_blob_heap_empty(lws_system_blob_t *b)
{
	b->is_direct = 0;
	lws_buflist_destroy_all_segments(&b->u.bl);
}

int
lws_system_blob_heap_append(lws_system_blob_t *b, const uint8_t *buf, size_t len)
{
	assert(!b->is_direct);

	lwsl_debug("%s: blob %p\n", __func__, b);

	if (lws_buflist_append_segment(&b->u.bl, buf, len) < 0)
		return -1;

	return 0;
}

size_t
lws_system_blob_get_size(lws_system_blob_t *b)
{
	if (b->is_direct)
		return b->u.direct.len;

	return lws_buflist_total_len(&b->u.bl);
}

int
lws_system_blob_get(lws_system_blob_t *b, uint8_t *buf, size_t *len, size_t ofs)
{
	int n;

	if (b->is_direct) {

		assert(b->u.direct.ptr);

		if (ofs >= b->u.direct.len) {
			*len = 0;
			return 1;
		}

		if (*len > b->u.direct.len - ofs)
			*len = b->u.direct.len - ofs;

		memcpy(buf, b->u.direct.ptr + ofs, *len);

		return 0;
	}

	n = lws_buflist_linear_copy(&b->u.bl, ofs, buf, *len);
	if (n < 0)
		return -2;

	*len = (unsigned int)n;

	return 0;
}

int
lws_system_blob_get_single_ptr(lws_system_blob_t *b, const uint8_t **ptr)
{
	if (b->is_direct) {
		*ptr = b->u.direct.ptr;
		return 0;
	}

	if (!b->u.bl)
		return -1;

	if (b->u.bl->next)
		return -1;  /* multipart buflist, no single pointer to it all */

	*ptr = (const uint8_t *)&b->u.bl[1] + LWS_PRE;

	return 0;
}

void
lws_system_blob_destroy(lws_system_blob_t *b)
{
	if (!b)
		return;
	// lwsl_info("%s: blob %p\n", __func__, b);
	if (!b->is_direct)
		lws_buflist_destroy_all_segments(&b->u.bl);
}

lws_system_blob_t *
lws_system_get_blob(struct lws_context *context, lws_system_blob_item_t type,
		    int idx)
{
	if (idx < 0 ||
	    idx >= (int)LWS_ARRAY_SIZE(context->system_blobs))
		return NULL;

	return &context->system_blobs[type + (unsigned int)idx];
}

#if defined(LWS_WITH_NETWORK)

/*
 * Caller must protect the whole call with system-specific locking
 */

int
__lws_system_attach(struct lws_context *context, int tsi, lws_attach_cb_t cb,
		    lws_system_states_t state, void *opaque,
		    struct lws_attach_item **get)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws_attach_item *item;

	if (!get) {
		/*
		 * allocate and add to the head of the pt's attach list
		 */

		item = lws_zalloc(sizeof(*item), __func__);
		if (!item)
			return 1;

		item->cb = cb;
		item->opaque = opaque;
		item->state = state;

		lws_dll2_add_head(&item->list, &pt->attach_owner);

		lws_cancel_service(context);

		return 0;
	}

	*get = NULL;
#if defined(LWS_WITH_SYS_STATE)
	if (!lws_dll2_count(&pt->attach_owner))
		return 0;

	/*
	 * If any, return the first guy whose state requirement matches
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pt->attach_owner)) {
		item = lws_container_of(d, lws_attach_item_t, list);

		if (pt->context->mgr_system.state >= (int)item->state) {
			*get = item;
			lws_dll2_remove(d);

			/*
			 * We detached it, but the caller now has the
			 * responsibility to lws_free() *get.
			 */

			return 0;
		}
	} lws_end_foreach_dll(d);
#endif

	/* nobody ready to go... leave *get as NULL and return cleanly */

	return 0;
}

int
lws_system_do_attach(struct lws_context_per_thread *pt)
{
	/*
	 * If nothing to do, we just return immediately
	 */

	while (lws_dll2_count(&pt->attach_owner)) {

		struct lws_attach_item *item;

		/*
		 * If anybody used the attach apis, there must be an
		 * implementation of the (*attach) lws_system op function
		 */

		assert(pt->context->system_ops->attach);
		if (!pt->context->system_ops->attach) {
			lwsl_err("%s: define (*attach)\n", __func__);
			return 1;
		}

		/*
		 * System locking is applied only around this next call, while
		 * we detach and get a pointer to the tail attach item.  We
		 * become responsible to free what we have detached.
		 */

		if (pt->context->system_ops->attach(pt->context, pt->tid, NULL,
						    0, NULL, &item)) {
			lwsl_err("%s: attach problem\n", __func__);
			return 1;
		}

		if (!item)
			/* there's nothing more to do at the moment */
			return 0;

		/*
		 * Do the callback from the lws event loop thread
		 */

		item->cb(pt->context, pt->tid, item->opaque);

		/* it's done, destroy the item */

		lws_free(item);
	}

	return 0;
}

/*
 * Stronger sources rank higher; a source can only set the best address
 * when no source ranked above it has one.  See lws_extip_src_t.
 */
static const uint8_t extip_src_rank[LWS_EXTIP_SRC_COUNT] = {
	[LWS_EXTIP_SRC_DHT]		= 1,
	[LWS_EXTIP_SRC_EXTIP]		= 2,
	[LWS_EXTIP_SRC_ROUTER]		= 3,
};

#if (_LWS_ENABLED_LOGS & (LLL_WARN | LLL_NOTICE | LLL_INFO))
static const char * const extip_src_name[LWS_EXTIP_SRC_COUNT] = {
	[LWS_EXTIP_SRC_DHT]		= "dht",
	[LWS_EXTIP_SRC_EXTIP]		= "extip",
	[LWS_EXTIP_SRC_ROUTER]		= "router",
};
#endif

static int
extip_af_index(int af)
{
	if (af == AF_INET)
		return 0;
#if defined(LWS_WITH_IPV6)
	if (af == AF_INET6)
		return 1;
#endif

	return -1;
}

static int
extip_sa46_same(const lws_sockaddr46 *a, const lws_sockaddr46 *b)
{
	if (a->sa4.sin_family != b->sa4.sin_family)
		return 0;

	if (a->sa4.sin_family == AF_INET)
		return a->sa4.sin_port == b->sa4.sin_port &&
		       !memcmp(&a->sa4.sin_addr, &b->sa4.sin_addr,
			       sizeof(a->sa4.sin_addr));
#if defined(LWS_WITH_IPV6)
	if (a->sa4.sin_family == AF_INET6)
		return a->sa6.sin6_port == b->sa6.sin6_port &&
		       a->sa6.sin6_scope_id == b->sa6.sin6_scope_id &&
		       !lws_sa46_compare_sin6_addr(&a->sa6.sin6_addr,
						   &b->sa6.sin6_addr);
#endif

	return 1; /* both empty */
}

static void
extip_broadcast(struct lws_context *cx)
{
	char payload[128], buf[64], *p = payload, *end = payload + sizeof(payload);
	int n, c = 0;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"ext-ips\": [");

	for (n = 0; n < (int)LWS_ARRAY_SIZE(cx->ext_ip); n++) {
		if (!cx->ext_ip[n].sa4.sin_family)
			continue;

		lws_sa46_write_numeric_address(&cx->ext_ip[n], buf, sizeof(buf));
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s\"%s\"",
				  c++ ? ", " : "", buf);
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

	lwsl_cx_info(cx, "%s", payload);
#if defined(LWS_WITH_SYS_SMD)
	lws_smd_msg_printf(cx, LWSSMDCL_NETWORK, "%s", payload);
#endif
}

void
lws_extip_report(struct lws_context *cx, lws_extip_src_t src,
		 const lws_sockaddr46 *sa46, int af, int status,
		 const lws_sockaddr46 *peers, int num_peers)
{
	int fi = extip_af_index(af), s, best_src = -1;
	lws_sockaddr46 *slot, *best = NULL;
	char buf[64];

	(void)peers;
	(void)num_peers;

	if ((unsigned int)src >= LWS_EXTIP_SRC_COUNT || fi < 0) {
		lwsl_cx_warn(cx, "ignoring report src %d af %d", (int)src, af);
		return;
	}

	slot = &cx->ext_ip_src[src][fi];

	if (status == LWS_EXTIP_STATUS_OFFLINE || !sa46 ||
	    !sa46->sa4.sin_family) {
		lwsl_cx_info(cx, "%s: IPv%c offline", extip_src_name[src],
			     fi ? '6' : '4');
		memset(slot, 0, sizeof(*slot));
	} else {
		if (sa46->sa4.sin_family != af) {
			lwsl_cx_warn(cx, "%s: address family mismatch",
				     extip_src_name[src]);
			return;
		}
		*slot = *sa46;
		lws_sa46_write_numeric_address(slot, buf, sizeof(buf));
		lwsl_cx_info(cx, "%s: IPv%c %s", extip_src_name[src],
			     fi ? '6' : '4', buf);
	}

	for (s = 0; s < LWS_EXTIP_SRC_COUNT; s++)
		if (cx->ext_ip_src[s][fi].sa4.sin_family &&
		    (best_src < 0 ||
		     extip_src_rank[s] > extip_src_rank[best_src])) {
			best_src = s;
			best = &cx->ext_ip_src[s][fi];
		}

	if (best ? extip_sa46_same(best, &cx->ext_ip[fi]) :
		   !cx->ext_ip[fi].sa4.sin_family)
		return; /* the best address for this family didn't change */

	if (best) {
		cx->ext_ip[fi] = *best;
		lws_sa46_write_numeric_address(best, buf, sizeof(buf));
		lwsl_cx_notice(cx, "external IPv%c now %s (from %s)",
			       fi ? '6' : '4', buf, extip_src_name[best_src]);
	} else {
		memset(&cx->ext_ip[fi], 0, sizeof(cx->ext_ip[fi]));
		lwsl_cx_notice(cx, "external IPv%c unknown", fi ? '6' : '4');
	}

	extip_broadcast(cx);
}

int
lws_extip_get_best(struct lws_context *cx, int af, lws_sockaddr46 *sa46)
{
	int fi = extip_af_index(af);

	if (fi >= 0 && cx->ext_ip[fi].sa4.sin_family) {
		if (sa46)
			*sa46 = cx->ext_ip[fi];
		return 0; /* found */
	}

	/* Unknown / Offline */
	if (sa46)
		memset(sa46, 0, sizeof(*sa46));

	return 1;
}

#endif
