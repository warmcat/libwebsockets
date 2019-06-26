/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * included from libwebsockets.h
 *
 * lws_sequencer is intended to help implement sequences that:
 *
 *  - outlive a single connection lifetime,
 *  - are not associated with a particular protocol,
 *  - are not associated with a particular vhost,
 *  - must receive and issue events inside the event loop
 *
 * lws_sequencer-s are bound to a pt (per-thread) which for the default case of
 * one service thread is the same as binding to an lws_context.
 */

typedef enum {
	LWSSEQ_CREATED,		/* sequencer created */
	LWSSEQ_DESTROYED,	/* sequencer destroyed */
	LWSSEQ_TIMED_OUT,	/* sequencer timeout */
	LWSSEQ_HEARTBEAT,	/* 1Hz callback */

	LWSSEQ_USER_BASE = 100	/* define your events from here */
} lws_seq_events_t;

typedef enum lws_seq_cb_return {
	LWSSEQ_RET_CONTINUE,
	LWSSEQ_RET_DESTROY
} lws_seq_cb_return_t;

typedef struct lws_sequencer lws_sequencer_t; /* opaque */

/*
 * handler for this sequencer.  Return 0 if OK else nonzero to destroy the
 * sequencer.  LWSSEQ_DESTROYED will be called back to the handler so it can
 * close / destroy any private assets associated with the sequence.
 *
 * The callback may return either LWSSEQ_RET_CONTINUE for the sequencer to
 * resume or LWSSEQ_RET_DESTROY to indicate the sequence is finished.
 *
 * Event indexes consist of some generic ones but mainly user-defined ones
 * starting from LWSSEQ_USER_BASE.
 */
typedef lws_seq_cb_return_t (*lws_seq_event_cb)(struct lws_sequencer *seq,
			     void *user, int event, void *data);

/**
 * lws_sequencer_create() - create and bind sequencer to a pt
 *
 * \param context:	lws_context
 * \param tsi:		thread service index, 0 is safe anything else depends
 *			multiple service threads being set up
 * \param user_size:	size of the additional heap allocation to allocate after
 *			the lws sequencer object to hold user data associated
 *			with the sequence.  The start of this extra allocation
 *			is passed to the sequencer callback and in \p *puser
 * \param puser:	pointer to a void * that will be set to the start of the
 *			extra user heap allocation whose size was set by
 *			user_size.  The user area pointed to here is all zeroed
 *			after successful sequencer creation.
 * \param cb:		callback for events on this sequencer
 * \param name:		Used in sequencer logging
 *
 * This binds an abstract sequencer to a per-thread (by default, the single
 * event loop of an lws_context).  After the event loop starts, the sequencer
 * will receive an LWSSEQ_CREATED event on its callback from the event loop
 * context, where it can begin its sequence flow.
 *
 * Lws itself will only call the callback subsequently with LWSSEQ_DESTROYED
 * when the sequencer is being destroyed.
 *
 * pt locking is used to protect the related data structures.
 */
LWS_VISIBLE LWS_EXTERN lws_sequencer_t *
lws_sequencer_create(struct lws_context *context, int tsi, size_t user_size,
		     void **puser, lws_seq_event_cb cb, const char *name);

/**
 * lws_sequencer_destroy() - destroy the sequencer
 *
 * \param seq: pointer to the the opaque sequencer pointer returned by
 *	       lws_sequencer_create()
 *
 * This proceeds to destroy the sequencer, calling LWSSEQ_DESTROYED and then
 * freeing the sequencer object itself.  The pointed-to seq pointer will be
 * set to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_sequencer_destroy(lws_sequencer_t **seq);

/**
 * lws_sequencer_event() - queue an event on the given sequencer
 *
 * \param seq: the opaque sequencer pointer returned by lws_sequencer_create()
 * \param e: the event index to queue
 * \param data: associated opaque (to lws) data to provide the callback
 *
 * This queues the event on a given sequencer.  Queued events are delivered one
 * per sequencer each subsequent time around the event loop, so the cb is called
 * from the event loop thread context.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sequencer_event(lws_sequencer_t *seq, lws_seq_events_t e, void *data);

/**
 * lws_sequencer_timeout() - set a timeout by which the sequence must have
 *			     completed by a different event or inform the
 *			     sequencer
 *
 * \param seq: The sequencer to set the timeout on
 * \param secs: How many seconds in the future to fire the timeout (0 = disable)
 *
 * This api allows the sequencer to ask to be informed if it has not completed
 * or disabled its timeout after secs seconds.  Lws will send a LWSSEQ_TIMED_OUT
 * event to the sequencer if the timeout expires.
 *
 * Typically the sequencer sets the timeout when starting a step, then waits to
 * hear a queued event informing it the step completed or failed.  The timeout
 * provides a way to deal with the case the step neither completed nor failed
 * within the timeout period.
 *
 * Lws wsi timeouts are not really suitable for this since they are focused on
 * short-term protocol timeout protection and may be set and reset many times
 * in one transaction.  Wsi timeouts also enforce closure of the wsi when they
 * trigger, sequencer timeouts have no side effect except to queue the
 * LWSSEQ_TIMED_OUT message and leave it to the sequencer to decide how to
 * react appropriately.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sequencer_timeout(lws_sequencer_t *seq, int secs);

/**
 * lws_sequencer_from_user(): get the lws_sequencer_t pointer from the user ptr
 *
 * \param u: the sequencer user allocation returned by lws_sequencer_create() or
 *	     provided in the sequencer callback
 *
 * This gets the lws_sequencer_t * from the sequencer user allocation pointer.
 * Actually these are allocated at the same time in one step, with the user
 * allocation immediately after the lws_sequencer_t, so lws can compute where
 * the lws_sequencer_t is from having the user allocation pointer.  Since the
 * size of the lws_sequencer_t is unknown to user code, this helper does it for
 * you.
 */
LWS_VISIBLE LWS_EXTERN lws_sequencer_t *
lws_sequencer_from_user(void *u);

/**
 * lws_sequencer_secs_since_creation(): elapsed seconds since sequencer created
 *
 * \param seq: pointer to the lws_sequencer_t
 *
 * Returns the number of seconds elapsed since the lws_sequencer_t was
 * created.  This is useful to calculate sequencer timeouts for the current
 * step considering a global sequencer lifetime limit.
 */
LWS_VISIBLE LWS_EXTERN int
lws_sequencer_secs_since_creation(lws_sequencer_t *seq);

/**
 * lws_sequencer_name(): get the name of this sequencer
 *
 * \param seq: pointer to the lws_sequencer_t
 *
 * Returns the name given when the sequencer was created.  This is useful to
 * annotate logging when then are multiple sequencers in play.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_sequencer_name(lws_sequencer_t *seq);
