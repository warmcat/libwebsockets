/*
 * libwebsockets - lib/core-net/sequencer.c
 *
 * Copyright (C) 2019 Andy Green <andy@warmcat.com>
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
 */

#include "core/private.h"

/*
 * per pending event
 */
typedef struct lws_seq_event {
	struct lws_dll2			seq_event_list;

	void				*data;
	lws_seq_events_t		e;
} lws_seq_event_t;

/*
 * per sequencer
 */
typedef struct lws_sequencer {
	struct lws_dll2			seq_list;
	struct lws_dll2			seq_pend_list;
	struct lws_dll2			seq_to_list;

	struct lws_dll2_owner		seq_event_owner;
	struct lws_context_per_thread	*pt;
	lws_seq_event_cb		cb;
	const char			*name;

	time_t				time_created;
	time_t				timeout; /* 0 or time we timeout */

	char				going_down;
} lws_sequencer_t;

#define QUEUE_SANITY_LIMIT 10

lws_sequencer_t *
lws_sequencer_create(struct lws_context *context, int tsi, size_t user_size,
		     void **puser, lws_seq_event_cb cb, const char *name)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	lws_sequencer_t *seq = lws_zalloc(sizeof(*seq) + user_size, __func__);

	if (!seq)
		return NULL;

	seq->cb = cb;
	seq->pt = pt;
	seq->name = name;

	*puser = (void *)&seq[1];

	/* add the sequencer to the pt */

	lws_pt_lock(pt, __func__); /* ---------------------------------- pt { */

	lws_dll2_add_tail(&seq->seq_list, &pt->seq_owner);

	lws_pt_unlock(pt); /* } pt ------------------------------------------ */

	time(&seq->time_created);

	/* try to queue the creation cb */

	if (lws_sequencer_event(seq, LWSSEQ_CREATED, NULL)) {
		lws_dll2_remove(&seq->seq_list);
		lws_free(seq);

		return NULL;
	}

	return seq;
}

static int
seq_ev_destroy(struct lws_dll2 *d, void *user)
{
	lws_seq_event_t *seqe = lws_container_of(d, lws_seq_event_t,
						 seq_event_list);

	lws_dll2_remove(&seqe->seq_event_list);
	lws_free(seqe);

	return 0;
}

void
lws_sequencer_destroy(lws_sequencer_t **pseq)
{
	lws_sequencer_t *seq = *pseq;

	/* defeat another thread racing to add events while we are destroying */
	seq->going_down = 1;

	seq->cb(seq, (void *)&seq[1], LWSSEQ_DESTROYED, NULL);

	lws_pt_lock(seq->pt, __func__); /* -------------------------- pt { */

	lws_dll2_remove(&seq->seq_list);
	lws_dll2_remove(&seq->seq_to_list);
	lws_dll2_remove(&seq->seq_pend_list);
	/* remove and destroy any pending events */
	lws_dll2_foreach_safe(&seq->seq_event_owner, NULL, seq_ev_destroy);

	lws_pt_unlock(seq->pt); /* } pt ---------------------------------- */


	lws_free_set_NULL(seq);
}

int
lws_sequencer_event(lws_sequencer_t *seq, lws_seq_events_t e, void *data)
{
	lws_seq_event_t *seqe;

	if (!seq || seq->going_down)
		return 1;

	seqe = lws_zalloc(sizeof(*seqe), __func__);
	if (!seqe)
		return 1;

	seqe->e = e;
	seqe->data = data;

	// lwsl_notice("%s: seq %s: event %d\n", __func__, seq->name, e);

	lws_pt_lock(seq->pt, __func__); /* ----------------------------- pt { */

	if (seq->seq_event_owner.count > QUEUE_SANITY_LIMIT) {
		lwsl_err("%s: more than %d events queued\n", __func__,
			 QUEUE_SANITY_LIMIT);
	}

	lws_dll2_add_tail(&seqe->seq_event_list, &seq->seq_event_owner);

	/* if not already on the pending list, add us */
	if (lws_dll2_is_detached(&seq->seq_pend_list))
		lws_dll2_add_tail(&seq->seq_pend_list, &seq->pt->seq_pend_owner);

	lws_pt_unlock(seq->pt); /* } pt ------------------------------------- */

	return 0;
}

/*
 * seq should have at least one pending event (he was on the pt's list of
 * sequencers with pending events).  Send the top event in the queue.
 */

static int
lws_sequencer_next_event(struct lws_dll2 *d, void *user)
{
	lws_sequencer_t *seq = lws_container_of(d, lws_sequencer_t,
						seq_pend_list);
	lws_seq_event_t *seqe;
	struct lws_dll2 *dh;
	int n;

	/* we should be on the pending list, right? */
	assert(seq->seq_event_owner.count);

	/* events are only added at tail, so no race possible yet... */

	dh = lws_dll2_get_head(&seq->seq_event_owner);
	seqe = lws_container_of(dh, lws_seq_event_t, seq_event_list);

	n = seq->cb(seq, (void *)&seq[1], seqe->e, seqe->data);

	/* ... have to lock here though, because we will change the list */

	lws_pt_lock(seq->pt, __func__); /* ----------------------------- pt { */

	/* detach event from sequencer event list and free it */
	lws_dll2_remove(&seqe->seq_event_list);
	lws_free(seqe);

	/*
	 * if seq has no more pending, remove from pt's list of sequencers
	 * with pending events
	 */
	if (!seq->seq_event_owner.count)
		lws_dll2_remove(&seq->seq_pend_list);

	lws_pt_unlock(seq->pt); /* } pt ------------------------------------- */

	if (n) {
		lwsl_info("%s: destroying seq '%s' by request\n", __func__,
				seq->name);
		lws_sequencer_destroy(&seq);

		return LWSSEQ_RET_DESTROY;
	}

	return LWSSEQ_RET_CONTINUE;
}

/*
 * nonpublic helper for the pt to call one event per pending sequencer, if any
 * are pending
 */

int
lws_pt_do_pending_sequencer_events(struct lws_context_per_thread *pt)
{
	if (!pt->seq_pend_owner.count)
		return 0;

	return lws_dll2_foreach_safe(&pt->seq_pend_owner, NULL,
				     lws_sequencer_next_event);
}

/* set secs to zero to remove timeout */

int
lws_sequencer_timeout(lws_sequencer_t *seq, int secs)
{
	lws_dll2_remove(&seq->seq_to_list);

	if (!secs) {
		/* we are clearing the timeout */
		seq->timeout = 0;

		return 0;
	}

	time(&seq->timeout);
	seq->timeout += secs;

	/*
	 * we sort the pt's list of sequencers with pending timeouts, so it's
	 * cheap to check it every second
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   seq->pt->seq_to_owner.head) {
		lws_sequencer_t *s = lws_container_of(p, lws_sequencer_t,
						      seq_to_list);

		assert(s->timeout); /* shouldn't be on the list otherwise */
		if (s->timeout >= seq->timeout) {
			/* drop us in before this guy */
			lws_dll2_add_before(&seq->seq_to_list,
					    &s->seq_to_list);

			return 0;
		}
	} lws_end_foreach_dll_safe(p, tp);

	/*
	 * Either nobody on the list yet to compare him to, or he's the
	 * longest timeout... stick him at the tail end
	 */

	lws_dll2_add_tail(&seq->seq_to_list, &seq->pt->seq_to_owner);

	return 0;
}

/*
 * nonpublic helper to check for and handle sequencer timeouts for a whole pt
 */

int
lws_sequencer_timeout_check(struct lws_context_per_thread *pt, time_t now)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   pt->seq_to_owner.head) {
		lws_sequencer_t *s = lws_container_of(p, lws_sequencer_t,
						      seq_to_list);

		assert(s->timeout); /* shouldn't be on the list otherwise */
		if (s->timeout <= now) {
			/* seq has timed out... remove him from timeout list */
			lws_sequencer_timeout(s, 0);
			/* queue the message to inform the sequencer */
			lws_sequencer_event(s, LWSSEQ_TIMED_OUT, NULL);
		} else
			/*
			 * No need to look further if we met one later than now:
			 * the list is sorted in ascending time order
			 */
			return 0;

	} lws_end_foreach_dll_safe(p, tp);

	/* send every sequencer a heartbeat message... it can ignore it */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   pt->seq_owner.head) {
		lws_sequencer_t *s = lws_container_of(p, lws_sequencer_t,
						      seq_list);

		/* queue the message to inform the sequencer */
		lws_sequencer_event(s, LWSSEQ_HEARTBEAT, NULL);

	} lws_end_foreach_dll_safe(p, tp);

	return 0;
}

lws_sequencer_t *
lws_sequencer_from_user(void *u)
{
	return &((lws_sequencer_t *)u)[-1];
}

const char *
lws_sequencer_name(lws_sequencer_t *seq)
{
	return seq->name;
}

int
lws_sequencer_secs_since_creation(lws_sequencer_t *seq)
{
	time_t now;

	time(&now);

	return now - seq->time_created;
}
