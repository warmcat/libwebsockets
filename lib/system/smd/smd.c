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
		lwsl_info("%s: rejecting class 0x%x as no participant wants it\n", __func__,
				(unsigned int)_class);
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
_lws_smd_msg_assess_peers_interested(lws_smd_t *smd, lws_smd_msg_t *msg)
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

		if (pr->timestamp_joined <= msg->timestamp &&
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
lws_smd_msg_send(struct lws_context *ctx, void *pay)
{
	lws_smd_msg_t *msg = (lws_smd_msg_t *)(((uint8_t *)pay) -
				LWS_SMD_SS_RX_HEADER_LEN_EFF - sizeof(*msg));

	if (ctx->smd.owner_messages.count >= LWS_SMD_MAX_QUEUE_DEPTH)
		/* reject the message due to max queue depth reached */
		return 1;

	if (!ctx->smd.delivering)
		lws_mutex_lock(ctx->smd.lock_peers); /* +++++++++++++++ peers */

	msg->refcount = _lws_smd_msg_assess_peers_interested(&ctx->smd, msg);

	lws_mutex_lock(ctx->smd.lock_messages); /* +++++++++++++++++ messages */
	lws_dll2_add_tail(&msg->list, &ctx->smd.owner_messages);
	lws_mutex_unlock(ctx->smd.lock_messages); /* --------------- messages */

	/*
	 * Any peer with no active tail needs to check our class to see if we
	 * should become his tail
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->smd.owner_peers.head) {
		lws_smd_peer_t *pr = lws_container_of(p, lws_smd_peer_t, list);

		if (!pr->tail && (pr->_class_filter & msg->_class))
			pr->tail = msg;

	} lws_end_foreach_dll(p);

	if (!ctx->smd.delivering)
		lws_mutex_unlock(ctx->smd.lock_peers); /* ------------- peers */

	/* we may be happening from another thread context */
	lws_cancel_service(ctx);

	return 0;
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
	vsnprintf((char*)p, n + 2, format, ap);
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
_lws_smd_msg_next_matching_filter(lws_dll2_t *tail, lws_smd_class_t filter)
{
	lws_smd_msg_t *msg;

	do {
		tail = tail->next;
		if (!tail)
			return NULL;

		msg = lws_container_of(tail, lws_smd_msg_t, list);
		if (msg->_class & filter)
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

		pr->cb(pr->opaque, msg->_class, msg->timestamp,
		       ((uint8_t *)&msg[1]) +
			       LWS_SMD_SS_RX_HEADER_LEN_EFF,
		       (size_t)msg->length);
	}

	assert(msg->refcount);

	/*
	 * If there is one, move forward to the next queued
	 * message that meets our filters
	 */
	pr->tail = _lws_smd_msg_next_matching_filter(
			    &pr->tail->list, pr->_class_filter);

	if (!--msg->refcount) {
		/*
		 * We have fully delivered the message now, it
		 * can be unlinked and destroyed
		 */
		lws_dll2_remove(&msg->list);
		lws_free(msg);
	}

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
			more |= _lws_smd_msg_deliver_peer(ctx, pr);

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
