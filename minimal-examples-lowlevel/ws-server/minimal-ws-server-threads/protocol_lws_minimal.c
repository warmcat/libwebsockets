/*
 * ws protocol handler plugin for "lws-minimal" demonstrating multithread
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The per-vhost data below is shared by the lws service thread and the
 * "spam" threads.  The rules are:
 *
 *  - connections are only ever touched by lws apis from the lws service
 *    thread.  The only lws apis that are safe to call from another thread
 *    are lws_cancel_service(), and lws_now_usecs(), which just reads the
 *    clock.
 *
 *  - the lock covers the ringbuffer, the connections' tails in it, and the
 *    membership of the list of connections, which the spam threads look at.
 *    Only the service thread changes the list, so it can walk it without the
 *    lock.
 *
 *  - nothing calls into lws while holding the lock, so it can't get mixed
 *    up with lws' own locks.
 *
 * The ringbuffer only frees a message once every connection has been sent
 * it, and the spam threads skip a message while it is full, so one client
 * that stops reading would stop it freeing anything, and every new message
 * would be skipped for everybody, for as long as that client stays
 * connected.  So a client is closed when the oldest message it hasn't been
 * sent yet has been waiting for it for MINIMAL_LAG_SECS.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/* a client with a message that has waited this long for it is closed */
#define MINIMAL_LAG_SECS 5

/* one of these created for each message in the ringbuffer */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
	lws_usec_t arrived; /* when it went in the ringbuffer */
};

/*
 * One of these is created for each client connecting to us.
 *
 * It is ONLY read or written from the lws service thread context.
 */

struct per_session_data__minimal {
	lws_dll2_t list; /* {lock_ring} in vhd->pss_list */
	struct lws *wsi;
	uint32_t tail; /* {lock_ring} */
	lws_usec_t joined; /* when we connected */
	lws_usec_t lag_from; /* the lag timer runs from here, or 0: caught up */
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_dll2_owner_t pss_list; /* {lock_ring} live pss */

	pthread_t pthread_spam[2];
	int count_spam; /* how many spam threads we started */

	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct lws_ring *ring; /* {lock_ring} ringbuffer holding unsent content */

	const char *config;
	char finished; /* {lock_ring} */
};

#if defined(WIN32)
static void usleep(unsigned long l) { Sleep(l / 1000); }
#endif

/*
 * This runs under both lws service and "spam threads" contexts.
 * Access is serialized by vhd->lock_ring.
 */

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

/*
 * {lock_ring} must be held.  Ringbuffer elements before the oldest tail of
 * any connection have been sent to everybody and can be freed.
 */

static void
__minimal_update_oldest_tail(struct per_vhost_data__minimal *vhd)
{
	struct per_session_data__minimal *oldest = NULL;
	uint32_t most = 0, w;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->pss_list)) {
		struct per_session_data__minimal *pss = lws_container_of(d,
					struct per_session_data__minimal, list);

		w = (uint32_t)lws_ring_get_count_waiting_elements(vhd->ring,
								  &pss->tail);
		if (!oldest || w > most) {
			most = w;
			oldest = pss;
		}
	} lws_end_foreach_dll(d);

	if (oldest)
		lws_ring_update_oldest_tail(vhd->ring, oldest->tail);
}

/*
 * {lock_ring} must be held.  When did the oldest message waiting to be sent
 * to this connection arrive?  0 if nothing is waiting for it.
 */

static lws_usec_t
__minimal_waiting_since(struct per_vhost_data__minimal *vhd,
			struct per_session_data__minimal *pss)
{
	const struct msg *pmsg = lws_ring_get_element(vhd->ring, &pss->tail);

	return pmsg ? pmsg->arrived : 0;
}

static lws_usec_t
minimal_waiting_since(struct per_vhost_data__minimal *vhd,
		      struct per_session_data__minimal *pss)
{
	lws_usec_t since;

	pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
	since = __minimal_waiting_since(vhd, pss);
	pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

	return since;
}

/*
 * Only from the lws service thread, without the lock held.
 *
 * since is when the oldest message waiting for the client arrived, from
 * minimal_waiting_since(), or 0 if nothing is waiting for it.
 *
 * A client is closed once the oldest message it hasn't been sent yet has been
 * waiting for it for MINIMAL_LAG_SECS (counting from when it connected, if
 * that was later).  This judges the client by how stale what it is missing
 * is, not by whether it ever gets completely caught up, which busy senders
 * could prevent: a client that keeps up is always being sent fresh messages
 * and is never closed, while one that stopped reading is closed about
 * MINIMAL_LAG_SECS after the first message it didn't take.
 */

static void
minimal_lag_update(struct per_session_data__minimal *pss, lws_usec_t since)
{
	lws_usec_t left;

	if (!since) {
		/* we have been sent everything: nothing is waiting for us */
		if (pss->lag_from) {
			pss->lag_from = 0;
			lws_set_timeout(pss->wsi, NO_PENDING_TIMEOUT, 0);
		}
		return;
	}

	if (since < pss->joined)
		since = pss->joined;
	if (since == pss->lag_from)
		/* the same message is still the oldest: the timer is right */
		return;

	pss->lag_from = since;
	left = since + (MINIMAL_LAG_SECS * LWS_US_PER_SEC) - lws_now_usecs();
	lws_set_timeout(pss->wsi, PENDING_TIMEOUT_LAGGING, left <= 0 ?
			LWS_TO_KILL_ASYNC :
			(int)((left + LWS_US_PER_SEC - 1) / LWS_US_PER_SEC));
}

/*
 * This runs under the "spam thread" thread context only.
 *
 * We spawn two threads that generate messages with this.
 *
 */

static void *
thread_spam(void *d)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)d;
	struct msg amsg;
	int len = 128, index = 1, n, whoami = 0, finished, added;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
		if (pthread_equal(pthread_self(), vhd->pthread_spam[n]))
			whoami = n + 1;

	do {
		added = 0;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		/* don't generate output if nobody connected */
		if (!vhd->pss_list.count)
			goto wait_unlock;

		/*
		 * Only create if space in ringbuffer: if a client is too slow
		 * for us, this message is skipped for everybody, until the
		 * lag timer closes it
		 */
		n = (int)lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			lwsl_user("dropping!\n");
			goto wait_unlock;
		}

		amsg.payload = malloc((unsigned int)(LWS_PRE + len));
		if (!amsg.payload) {
			lwsl_user("OOM: dropping\n");
			goto wait_unlock;
		}
		n = lws_snprintf((char *)amsg.payload + LWS_PRE, (unsigned int)len,
			         "%s: tid: %d, msg: %d", vhd->config,
			         whoami, index++);
		amsg.len = (unsigned int)n;
		amsg.arrived = lws_now_usecs();
		n = (int)lws_ring_insert(vhd->ring, &amsg, 1);
		if (n != 1) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping!\n");
		} else
			added = 1;

wait_unlock:
		finished = vhd->finished;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		if (added)
			/*
			 * This will cause a LWS_CALLBACK_EVENT_WAIT_CANCELLED
			 * in the lws service thread context.
			 */
			lws_cancel_service(vhd->context);

		if (!finished)
			usleep(100000);

	} while (!finished);

	lwsl_notice("thread_spam %d exiting\n", whoami);

	pthread_exit(NULL);

	return NULL;
}

/* this runs under the lws service thread context only */

static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_session_data__minimal *pss =
			(struct per_session_data__minimal *)user;
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options *pvo;
	const struct msg *pmsg;
	char temp[LWS_PRE + 256];
	lws_usec_t since;
	void *retval;
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		/* create our per-vhost struct */
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		if (!vhd)
			return 1;

		pthread_mutex_init(&vhd->lock_ring, NULL);

		/*
		 * We are also instantiated on vhosts that have no pvo for
		 * us (eg, Secure Streams' internal vhosts)... only our own
		 * vhost passes the pvo chain in
		 */
		if (!in)
			break;

		/* recover the pointer to the globals struct */
		pvo = lws_pvo_search(
			(const struct lws_protocol_vhost_options *)in,
			"config");
		if (!pvo || !pvo->value) {
			lwsl_err("%s: Can't find \"config\" pvo\n", __func__);
			goto init_fail;
		}
		vhd->config = pvo->value;

		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		vhd->ring = lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring) {
			lwsl_err("%s: failed to create ring\n", __func__);
			goto init_fail;
		}

		/* start the content-creating threads */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++) {
			if (pthread_create(&vhd->pthread_spam[n], NULL,
					   thread_spam, vhd)) {
				lwsl_err("thread creation failed\n");
				goto init_fail;
			}
			vhd->count_spam++;
		}
		break;

init_fail:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		vhd->finished = 1;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		for (n = 0; n < vhd->count_spam; n++)
			pthread_join(vhd->pthread_spam[n], &retval);
		vhd->count_spam = 0;

		if (vhd->ring)
			lws_ring_destroy(vhd->ring);
		vhd->ring = NULL;

		pthread_mutex_destroy(&vhd->lock_ring);
		return 1;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		vhd->finished = 1;
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		for (n = 0; n < vhd->count_spam; n++)
			pthread_join(vhd->pthread_spam[n], &retval);

		if (vhd->ring)
			lws_ring_destroy(vhd->ring);

		pthread_mutex_destroy(&vhd->lock_ring);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		if (!vhd || !vhd->ring)
			/* not a vhost we were configured on */
			return -1;

		pss->wsi = wsi;
		pss->joined = lws_now_usecs();

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* add ourselves to the list of live pss */
		lws_dll2_add_tail(&pss->list, &vhd->pss_list);
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		since = __minimal_waiting_since(vhd, pss);
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		/* we get what's in the ring already */
		if (since) {
			lws_callback_on_writable(wsi);
			minimal_lag_update(pss, since);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (!vhd || !vhd->ring)
			break;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* remove our closing pss from the list of live pss */
		if (!lws_dll2_is_detached(&pss->list)) {
			lws_dll2_remove(&pss->list);
			/* we may have been the one holding the oldest tail */
			__minimal_update_oldest_tail(vhd);
		}
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		/*
		 * Send everything waiting for us that the connection will take
		 * now: a client that can keep up must be able to catch up in
		 * one go, not one message each time around the event loop
		 */
		while (!lws_send_pipe_choked(wsi)) {
			pthread_mutex_lock(&vhd->lock_ring); /* -- ring lock { */

			pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
			if (!pmsg) {
				pthread_mutex_unlock(&vhd->lock_ring); /* } - */
				break;
			}

			/* take our copy of it to send, outside the lock */
			n = lws_snprintf(temp + LWS_PRE, sizeof(temp) - LWS_PRE,
					 "%s", (char *)pmsg->payload + LWS_PRE);

			/* we are done with that element... */
			lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);
			/* ...if it was the last one waiting for anybody, free it */
			__minimal_update_oldest_tail(vhd);

			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock -- */

			m = lws_write(wsi, (unsigned char *)temp + LWS_PRE,
				      (unsigned int)n, LWS_WRITE_TEXT);
			if (m < n) {
				lwsl_err("ERROR %d writing to ws socket\n", m);
				return -1;
			}
		}

		/* restart our lag timer from what is waiting for us now */
		since = minimal_waiting_since(vhd, pss);
		minimal_lag_update(pss, since);

		if (since)
			/* come back as soon as we can write more */
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (!vhd)
			break;
		/*
		 * When the "spam" threads add a message to the ringbuffer,
		 * they create this event in the lws service thread context
		 * using lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for all
		 * connected clients with something waiting for them, and
		 * start the lag timer of any that were caught up.
		 *
		 * Only this thread changes the list, and we are on it, so we
		 * can walk it without the lock, and without holding the lock
		 * while we call into lws.
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list)) {
			struct per_session_data__minimal *p = lws_container_of(
				d, struct per_session_data__minimal, list);

			since = minimal_waiting_since(vhd, p);
			if (since) {
				lws_callback_on_writable(p->wsi);
				minimal_lag_update(p, since);
			}
		} lws_end_foreach_dll(d);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL \
	{ \
		"lws-minimal", \
		callback_minimal, \
		sizeof(struct per_session_data__minimal), \
		128, \
		0, NULL, 0 \
	}
