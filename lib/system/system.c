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
	if (!pt->attach_owner.count)
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

	while (pt->attach_owner.count) {

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

#endif

void
lws_extip_report(struct lws_context *cx, lws_extip_src_t src,
                 const lws_sockaddr46 *sa46, int af, int status,
                 const lws_sockaddr46 *peers, int num_peers)
{
	lws_sockaddr46 *target = (af == AF_INET) ? &cx->ext_ipv4 : &cx->ext_ipv6;
	lws_sockaddr46 old = *target;

	if (status == 2 || !sa46 || (af == AF_INET && sa46->sa4.sin_family == 0) ||
        (af == AF_INET6 && sa46->sa6.sin6_family == 0)) {
		memset(target, 0, sizeof(*target));
	} else {
		*target = *sa46;
	}

	if (memcmp(&old, target, sizeof(*target))) {
		int c = 0;
		char payload[128], buf4[64], buf6[64];
		char *p = payload, *end = payload + sizeof(payload);

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"ext-ips\": [");

		if (cx->ext_ipv4.sa4.sin_family == AF_INET) {
			lws_sa46_write_numeric_address(&cx->ext_ipv4, buf4, sizeof(buf4));
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"%s\"", buf4);
			c++;
		}

		if (cx->ext_ipv6.sa6.sin6_family == AF_INET6) {
			lws_sa46_write_numeric_address(&cx->ext_ipv6, buf6, sizeof(buf6));
			if (c)
				p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ", ");
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"%s\"", buf6);
		}

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

		lws_smd_msg_printf(cx, LWSSMDCL_NETWORK, "%s", payload);
	}
}

int
lws_extip_get_best(struct lws_context *cx, int af, lws_sockaddr46 *sa46)
{
	lws_sockaddr46 *src = (af == AF_INET) ? &cx->ext_ipv4 : &cx->ext_ipv6;

	if ((af == AF_INET && src->sa4.sin_family == AF_INET) ||
	    (af == AF_INET6 && src->sa6.sin6_family == AF_INET6)) {
		if (sa46)
			*sa46 = *src;
		return 0; /* found */
	}
	
	/* Unknown / Offline */
	if (sa46)
		memset(sa46, 0, sizeof(*sa46));
	return 1;
}
