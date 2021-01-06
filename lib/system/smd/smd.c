/*
 * lws System Message Distribution
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

#include "private-lib-core.h"
#include <assert.h>

void *
lws_smd_msg_alloc(struct lws_context *ctx, lws_smd_class_t _class, size_t len)
{
	lws_smd_msg_t *msg;

	/* only allow it if someone wants to consume this class of event */

	if (!(ctx->smd._class_filter & _class)) {
		lwsl_info("%s: rejecting class 0x%x as no participant wants it\n",
			  __func__, (unsigned int)_class);
		return NULL;
	}

	assert(len <= LWS_SMD_MAX_PAYLOAD);


	/*
	 * If SS configured, over-allocate LWS_SMD_SS_RX_HEADER_LEN behind
	 * payload, ie,  msg_t (gap LWS_SMD_SS_RX_HEADER_LEN) payload
	 */
	msg = lws_malloc(sizeof(*msg) + LWS_SMD_SS_RX_HEADER_LEN_EFF + len,
			 __func__);
	if (!msg)
		return NULL;

	memset(msg, 0, sizeof(*msg));
	msg->timestamp = lws_now_usecs();
	msg->length = (uint16_t)len;
	msg->_class = _class;

	return ((uint8_t *)&msg[1]) + LWS_SMD_SS_RX_HEADER_LEN_EFF;
}

void
lws_smd_msg_free(void **ppay)
{
	lws_smd_msg_t *msg = (lws_smd_msg_t *)(((uint8_t *)*ppay) -
				LWS_SMD_SS_RX_HEADER_LEN_EFF - sizeof(*msg));

	/* if SS configured, actual alloc is LWS_SMD_SS_RX_HEADER_LEN behind */
	lws_free(msg);
	*ppay = NULL;
}

/*
 * Figure out what to set the initial refcount for the message to
 */

static int
_lws_smd_msg_assess_peers_interested(lws_smd_t *smd, lws_smd_msg_t *msg,
				     struct lws_smd_peer *exc)
{
	struct lws_context *ctx = lws_container_of(smd, struct lws_context, smd);
	int interested = 0;

	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->smd.owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		/*
		 * In order to optimize the tail managment into a refcount,
		 * we have to account exactly for when peers arrived and
		 * departed (including deferring the logical peer destruction
		 * until no message pending he may have contributed to the
		 * refcount of)
		 */

		if (pr != exc &&
		    pr->timestamp_joined <= msg->timestamp &&
		    (!pr->timestamp_left || /* if zombie, only contribute to
					     * refcount if msg from before we
					     * left */
		     pr->timestamp_left >= msg->timestamp) &&
		    (msg->_class & pr->_class_filter))
			/*
			 * This peer wants to consume it
			 */
			interested++;

	} lws_end_foreach_dll(p);

	return interested;
}

static int
_lws_smd_class_mask_union(lws_smd_t *smd)
{
	uint32_t mask = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   smd->owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		/* may destroy pr if zombie */
		mask |= pr->_class_filter;

	} lws_end_foreach_dll_safe(p, p1);

	smd->_class_filter = mask;

	return 0;
}

int
_lws_smd_msg_send(struct lws_context *ctx, void *pay, struct lws_smd_peer *exc)
{
	lws_smd_msg_t *msg = (lws_smd_msg_t *)(((uint8_t *)pay) -
				LWS_SMD_SS_RX_HEADER_LEN_EFF - sizeof(*msg));

	if (ctx->smd.owner_messages.count >= LWS_SMD_MAX_QUEUE_DEPTH) {
		lwsl_warn("%s: rejecting message on queue depth %d\n",
				__func__, (int)ctx->smd.owner_messages.count);
		/* reject the message due to max queue depth reached */
		return 1;
	}

	if (!ctx->smd.delivering)
		lws_mutex_lock(ctx->smd.lock_peers); /* +++++++++++++++ peers */

	msg->refcount = (uint16_t)_lws_smd_msg_assess_peers_interested(&ctx->smd, msg, exc);
	if (!msg->refcount) {
		/* possible, condsidering exc and no other participants */
		lws_free(msg);
		if (!ctx->smd.delivering)
			lws_mutex_unlock(ctx->smd.lock_peers); /* ------------- peers */

		return 0;
	}

	msg->exc = exc;

	lws_mutex_lock(ctx->smd.lock_messages); /* +++++++++++++++++ messages */
	lws_dll2_add_tail(&msg->list, &ctx->smd.owner_messages);
	lws_mutex_unlock(ctx->smd.lock_messages); /* --------------- messages */

	/*
	 * Any peer with no active tail needs to check our class to see if we
	 * should become his tail
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->smd.owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		if (pr != exc &&
		    !pr->tail && (pr->_class_filter & msg->_class))
			pr->tail = msg;

	} lws_end_foreach_dll(p);

	if (!ctx->smd.delivering)
		lws_mutex_unlock(ctx->smd.lock_peers); /* ------------- peers */

	/* we may be happening from another thread context */
	lws_cancel_service(ctx);

	return 0;
}

int
lws_smd_msg_send(struct lws_context *ctx, void *pay)
{
	return _lws_smd_msg_send(ctx, pay, NULL);
}

int
lws_smd_msg_printf(struct lws_context *ctx, lws_smd_class_t _class,
		   const char *format, ...)
{
	lws_smd_msg_t *msg;
	va_list ap;
	void *p;
	int n;

	if (!(ctx->smd._class_filter & _class))
		/*
		 * There's nobody interested in messages of this class atm.
		 * Don't bother generating it, and act like all is well.
		 */
		return 0;

	va_start(ap, format);
	n = vsnprintf(NULL, 0, format, ap);
	va_end(ap);
	if (n > LWS_SMD_MAX_PAYLOAD)
		/* too large to send */
		return 1;

	p = lws_smd_msg_alloc(ctx, _class, (size_t)n + 2);
	if (!p)
		return 1;
	msg = (lws_smd_msg_t *)(((uint8_t *)p) - LWS_SMD_SS_RX_HEADER_LEN_EFF -
								sizeof(*msg));
	msg->length = (uint16_t)n;
	va_start(ap, format);
	vsnprintf((char *)p, (unsigned int)n + 2, format, ap);
	va_end(ap);

	/*
	 * locks taken and released in here
	 */

	if (lws_smd_msg_send(ctx, p)) {
		lws_smd_msg_free(&p);
		return 1;
	}

	return 0;
}

#if defined(LWS_WITH_SECURE_STREAMS)
int
lws_smd_ss_msg_printf(const char *tag, uint8_t *buf, size_t *len,
		      lws_smd_class_t _class, const char *format, ...)
{
	char *content = (char *)buf + LWS_SMD_SS_RX_HEADER_LEN;
	va_list ap;
	int n;

	if (*len < LWS_SMD_SS_RX_HEADER_LEN)
		return 1;

	lws_ser_wu64be(buf, _class);
	lws_ser_wu64be(buf + 8, 0); /* valgrind notices uninitialized if left */

	va_start(ap, format);
	n = vsnprintf(content, (*len) - LWS_SMD_SS_RX_HEADER_LEN, format, ap);
	va_end(ap);

	if (n > LWS_SMD_MAX_PAYLOAD ||
	    (unsigned int)n > (*len) - LWS_SMD_SS_RX_HEADER_LEN)
		/* too large to send */
		return 1;

	*len = LWS_SMD_SS_RX_HEADER_LEN + (unsigned int)n;

	lwsl_notice("%s: %s send cl 0x%x, len %u\n", __func__, tag, _class,
			(unsigned int)n);

	return 0;
}

/*
 * This is a helper that user rx handler for LWS_SMD_STREAMTYPENAME SS can
 * call through to with the payload it received from the proxy.  It will then
 * forward the recieved SMD message to all local (same-context) participants
 * that are interested in that class (except ones with callback skip_cb, so
 * we don't loop).
 */

static int
_lws_smd_ss_rx_forward(struct lws_context *ctx, const char *tag,
		       struct lws_smd_peer *pr, const uint8_t *buf, size_t len)
{
	lws_smd_class_t _class;
	lws_smd_msg_t *msg;
	void *p;

	if (len < LWS_SMD_SS_RX_HEADER_LEN_EFF)
		return 1;

	if (len >= LWS_SMD_MAX_PAYLOAD + LWS_SMD_SS_RX_HEADER_LEN_EFF)
		return 1;

	_class = (lws_smd_class_t)lws_ser_ru64be(buf);

	if (_class == LWSSMDCL_METRICS) {

	}

	/* only locally forward messages that we care about in this process */

	if (!(ctx->smd._class_filter & _class))
		/*
		 * There's nobody interested in messages of this class atm.
		 * Don't bother generating it, and act like all is well.
		 */
		return 0;

	p = lws_smd_msg_alloc(ctx, _class, len);
	if (!p)
		return 1;

	msg = (lws_smd_msg_t *)(((uint8_t *)p) - LWS_SMD_SS_RX_HEADER_LEN_EFF -
								sizeof(*msg));
	msg->length = (uint16_t)(len - LWS_SMD_SS_RX_HEADER_LEN_EFF);
	/* adopt the original source timestamp, not time we forwarded it */
	msg->timestamp = (lws_usec_t)lws_ser_ru64be(buf + 8);

	/* copy the message payload in */
	memcpy(p, buf + LWS_SMD_SS_RX_HEADER_LEN_EFF, msg->length);

	/*
	 * locks taken and released in here
	 */

	if (_lws_smd_msg_send(ctx, p, pr)) {
		/* we couldn't send it after all that... */
		lws_smd_msg_free(&p);

		return 1;
	}

	lwsl_notice("%s: %s send cl 0x%x, len %u, ts %llu\n", __func__,
		    tag, _class, msg->length,
		    (unsigned long long)msg->timestamp);

	return 0;
}

int
lws_smd_ss_rx_forward(void *ss_user, const uint8_t *buf, size_t len)
{
	struct lws_ss_handle *h = (struct lws_ss_handle *)
					(((char *)ss_user) - sizeof(*h));
	struct lws_context *ctx = lws_ss_get_context(h);

	return _lws_smd_ss_rx_forward(ctx, lws_ss_tag(h), h->u.smd.smd_peer, buf, len);
}

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
int
lws_smd_sspc_rx_forward(void *ss_user, const uint8_t *buf, size_t len)
{
	struct lws_sspc_handle *h = (struct lws_sspc_handle *)
					(((char *)ss_user) - sizeof(*h));
	struct lws_context *ctx = lws_sspc_get_context(h);

	return _lws_smd_ss_rx_forward(ctx, lws_sspc_tag(h), NULL, buf, len);
}
#endif

#endif

static void
_lws_smd_peer_finalize_destroy(lws_smd_peer_t *pr)
{
	lws_dll2_remove(&pr->list);
	lws_free(pr);
}

/*
 * Peers that deregister may need to hang around as zombies, so they account
 * for refcounts on messages they already contributed to.  Because older
 * messages may be in flight over UDS links, we have to stick around and make
 * sure all cases have their refcount handled correctly.
 */

static void
_lws_smd_peer_zombify(lws_smd_peer_t *pr)
{
	lws_smd_t *smd = lws_container_of(pr->list.owner, lws_smd_t,
					  owner_peers);

	/* update the class mask union to reflect this peer no longer active */
	_lws_smd_class_mask_union(smd);

	pr->timestamp_left = lws_now_usecs();
}

static lws_smd_msg_t *
_lws_smd_msg_next_matching_filter(lws_smd_peer_t *pr)
{
	lws_smd_msg_t *msg;

	lws_dll2_t *tail = &pr->tail->list;
	lws_smd_class_t filter = pr->_class_filter;

	do {
		tail = tail->next;
		if (!tail)
			return NULL;

		msg = lws_container_of(tail, lws_smd_msg_t, list);
		if (msg->exc != pr && (msg->_class & filter))
			return msg;
	} while (1);

	return NULL;
}

/*
 * Note: May destroy zombie peers when it sees grace period has expired.
 *
 * Delivers only one message to the peer and advances the tail, or sets to NULL
 * if no more filtered queued messages.  Returns nonzero if tail non-NULL.
 *
 * For Proxied SS, only asks for writeable and does not advance or change the
 * tail.
 *
 * This is done so if multiple messages queued, we don't get a situation where
 * one participant gets them all spammed, then the next etc.  Instead they are
 * delivered round-robin.
 *
 * Requires peer lock, may take message lock
 */

static int
_lws_smd_msg_deliver_peer(struct lws_context *ctx, lws_smd_peer_t *pr)
{
	lws_smd_msg_t *msg;

	if (!pr->tail)
		return 0;

	msg = lws_container_of(pr->tail, lws_smd_msg_t, list);

	/*
	 * Check if zombie peer and the message predates our leaving
	 */

	if (pr->timestamp_left &&
	    msg->timestamp > pr->timestamp_left) {
		/*
		 * We do not need to modify message refcount, if it was
		 * generated after we became a zombie, and so we
		 * definitely did not contribute to its refcount...
		 *
		 * ...have we waited out the grace period?
		 */

		if (lws_now_usecs() - pr->timestamp_left >
			   LWS_SMD_INFLIGHT_GRACE_SECS * LWS_US_PER_SEC)
			/*
			 * ... ok, it's time for the zombie to abandon
			 * its attachment to the Earth and rejoin the
			 * cosmic mandela
			 */
			_lws_smd_peer_finalize_destroy(pr);

		/* ... either way, nothing further to do for this guy */

		return 0;
	}

	if (!pr->timestamp_left) {

		/*
		 * Peer is not a zombie... deliver the tail
		 */
#if 0
		if (pr->type == LSMDT_SECURE_STREAMS_PROXIED) {
#if defined(LWS_WITH_SECURE_STREAMS)
			if (pr->ss_handle)
				lws_ss_request_tx(pr->ss_handle);
#endif
			return 0;
		}
#endif

		lwsl_info("%s: deliver cl 0x%x, len %d, refc %d, to peer %p\n",
			   __func__, (unsigned int)msg->_class, (int)msg->length,
			   (int)msg->refcount, pr);

		pr->cb(pr->opaque, msg->_class, msg->timestamp,
		       ((uint8_t *)&msg[1]) + LWS_SMD_SS_RX_HEADER_LEN_EFF,
		       (size_t)msg->length);
	}

	assert(msg->refcount);

	/*
	 * If there is one, move forward to the next queued
	 * message that meets our filters
	 */
	pr->tail = _lws_smd_msg_next_matching_filter(pr);

	lws_mutex_lock(ctx->smd.lock_messages); /* +++++++++ messages */
	if (!--msg->refcount) {
		/*
		 * We have fully delivered the message now, it
		 * can be unlinked and destroyed
		 */
		lwsl_info("%s: destroy msg %p\n", __func__, msg);
		lws_dll2_remove(&msg->list);
		lws_free(msg);
	}
	lws_mutex_unlock(ctx->smd.lock_messages); /* messages ------- */

	/*
	 * Wait out the grace period even if no live messages
	 * for a zombie peer... there may be some in flight
	 */

	return !!pr->tail;
}

/*
 * Called when the event loop could deliver messages synchronously, eg, on
 * entry to idle
 */

int
lws_smd_msg_distribute(struct lws_context *ctx)
{
	char more;

	/* commonly, no messages and nothing to do... */

	if (!ctx->smd.owner_messages.count)
		return 0;

	ctx->smd.delivering = 1;

	do {
		more = 0;
		lws_mutex_lock(ctx->smd.lock_peers); /* +++++++++++++++ peers */

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
					   ctx->smd.owner_peers.head) {
			lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

			/* may destroy pr if zombie, hence _safe iterator */
			more = (char)(more | !!_lws_smd_msg_deliver_peer(ctx, pr));

		} lws_end_foreach_dll_safe(p, p1);

		lws_mutex_unlock(ctx->smd.lock_peers); /* ------------- peers */
	} while (more);

	ctx->smd.delivering = 0;

	return 0;
}

struct lws_smd_peer *
lws_smd_register(struct lws_context *ctx, void *opaque, int flags,
		 lws_smd_class_t _class_filter, lws_smd_notification_cb_t cb)
{
	lws_smd_peer_t *pr = lws_zalloc(sizeof(*pr), __func__);

	if (!pr)
		return NULL;

	pr->cb = cb;
	pr->opaque = opaque;
	pr->_class_filter = _class_filter;
	pr->timestamp_joined = lws_now_usecs();

	/*
	 * Figure out the type of peer from the situation...
	 */

#if 0
#if defined(LWS_WITH_SECURE_STREAMS)
	if (!ctx->smd.listen_vh) {
		/*
		 * The guy who is regsitering is actually a SS proxy link
		 * between a client and SMD
		 */
	} else
#endif
#endif
		pr->type = LSMDT_SAME_PROCESS;

	if (!ctx->smd.delivering)
		lws_mutex_lock(ctx->smd.lock_peers); /* +++++++++++++++ peers */
	lws_dll2_add_tail(&pr->list, &ctx->smd.owner_peers);

	/* update the global class mask union to account for new peer mask */
	_lws_smd_class_mask_union(&ctx->smd);
	if (!ctx->smd.delivering)
		lws_mutex_unlock(ctx->smd.lock_peers); /* ------------- peers */

	lwsl_debug("%s: registered\n", __func__);

	return pr;
}

void
lws_smd_unregister(struct lws_smd_peer *pr)
{
	lws_smd_t *smd = lws_container_of(pr->list.owner, lws_smd_t, owner_peers);

	lws_mutex_lock(smd->lock_peers); /* +++++++++++++++++++++++++++ peers */
	_lws_smd_peer_zombify(pr);
	lws_mutex_unlock(smd->lock_peers); /* ------------------------- peers */
}

int
lws_smd_message_pending(struct lws_context *ctx)
{
	int ret = 1;

	/*
	 * First cheaply check the common case no messages pending, so there's
	 * definitely nothing for this tsi or anything else
	 */

	if (!ctx->smd.owner_messages.count)
		return 0;

	/*
	 * Walk the peer list
	 */

	lws_mutex_lock(ctx->smd.lock_peers); /* +++++++++++++++++++++++ peers */
	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->smd.owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		if (pr->tail && pr->type == LSMDT_SAME_PROCESS)
			goto bail;

	} lws_end_foreach_dll(p);

	/*
	 * There's no message pending that we need to handle
	 */

	ret = 0;

bail:
	lws_mutex_unlock(ctx->smd.lock_peers); /* --------------------- peers */

	return ret;
}

int
_lws_smd_destroy(struct lws_context *ctx)
{
	/* stop any message creation */

	ctx->smd._class_filter = 0;

	/*
	 * Walk the message list, destroying them
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   ctx->smd.owner_messages.head) {
		lws_smd_msg_t *msg = lws_container_of(p, lws_smd_msg_t, list);

		lws_free(msg);

	} lws_end_foreach_dll_safe(p, p1);

	lws_mutex_destroy(ctx->smd.lock_messages);

	/*
	 * Walk the peer list, destroying them
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   ctx->smd.owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		_lws_smd_peer_finalize_destroy(pr);

	} lws_end_foreach_dll_safe(p, p1);

	lws_mutex_destroy(ctx->smd.lock_peers);

	return 0;
}
