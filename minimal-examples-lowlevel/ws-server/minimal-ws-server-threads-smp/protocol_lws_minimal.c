/*
 * ws protocol handler plugin for "lws-minimal" demonstrating multithread
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * There are several lws service threads, so the per-vhost data below is
 * shared by them, as well as by the "spam" threads.  The rules are:
 *
 *  - a connection is only ever touched by lws apis from the service thread
 *    it belongs to.  The only lws api that is safe to call from another
 *    thread is lws_cancel_service().
 *
 *  - so each service thread keeps its own list of its connections, which
 *    only it changes, under the lock, and only it walks to find them.
 *
 *  - the lock covers the ringbuffer, the connections' tails in it, and the
 *    membership of all the lists, since finding the oldest tail looks at
 *    every connection, whichever thread it belongs to.
 *
 *  - nothing calls into lws while holding the lock.  Some callbacks, like
 *    LWS_CALLBACK_CLOSED, come with lws' own locks held and then take ours,
 *    so taking any lws lock while holding ours could deadlock.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/* one of these created for each message in the ringbuffer */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

/*
 * One of these is created for each client connecting to us.
 *
 * It is ONLY read or written from the lws service thread context it belongs
 * to, except tail, which other threads read under the lock.
 */

struct per_session_data__minimal {
	lws_dll2_t list; /* {lock_ring} in vhd->pss_list[our tsi] */
	struct lws *wsi;
	uint32_t tail; /* {lock_ring} */
};

/*
 * One of these is created for each vhost our protocol is used with, that
 * means it is a shared resource between the SMP threads and must be locked.
 */

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	/* {lock_ring} live pss, one list per service thread */
	lws_dll2_owner_t pss_list[LWS_MAX_SMP];
	int count_pss; /* {lock_ring} pss on all the lists */

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
 * any connection, on any service thread, have been sent to everybody and
 * can be freed.
 */

static void
__minimal_update_oldest_tail(struct per_vhost_data__minimal *vhd)
{
	struct per_session_data__minimal *oldest = NULL;
	uint32_t most = 0, w;
	int n;

	for (n = 0; n < LWS_MAX_SMP; n++)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list[n])) {
			struct per_session_data__minimal *pss =
				lws_container_of(d,
					struct per_session_data__minimal, list);

			w = (uint32_t)lws_ring_get_count_waiting_elements(
							vhd->ring, &pss->tail);
			if (!oldest || w > most) {
				most = w;
				oldest = pss;
			}
		} lws_end_foreach_dll(d);

	if (oldest)
		lws_ring_update_oldest_tail(vhd->ring, oldest->tail);
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
		if (!vhd->count_pss)
			goto wait_unlock;

		/* only create if space in ringbuffer */
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
			 * in each lws service thread context.
			 */
			lws_cancel_service(vhd->context);

		if (!finished)
			usleep(100000);

	} while (!finished);

	lwsl_notice("thread_spam %d exiting\n", whoami);

	pthread_exit(NULL);

	return NULL;
}

/* this runs under the lws service thread contexts only */

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
	void *retval;
	int n, m, more;

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

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* add ourselves to our service thread's list of live pss */
		lws_dll2_add_tail(&pss->list, &vhd->pss_list[lws_wsi_tsi(wsi)]);
		vhd->count_pss++;
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_CLOSED:
		if (!vhd || !vhd->ring)
			break;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		/* remove our closing pss from the list of live pss */
		if (!lws_dll2_is_detached(&pss->list)) {
			lws_dll2_remove(&pss->list);
			vhd->count_pss--;
			/* we may have been the one holding the oldest tail */
			__minimal_update_oldest_tail(vhd);
		}
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
		if (!pmsg) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock - */
			break;
		}

		/* take our copy of it to send, outside the lock */
		n = lws_snprintf(temp + LWS_PRE, sizeof(temp) - LWS_PRE,
			      "svc, %s",
			      (char *)pmsg->payload + LWS_PRE);

		/* we are done with that element... */
		lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);
		/* ...if it was the last one waiting for anybody, free it */
		__minimal_update_oldest_tail(vhd);

		more = !!lws_ring_get_element(vhd->ring, &pss->tail);

		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

		m = lws_write(wsi, (unsigned char *)temp + LWS_PRE, (unsigned int)n,
			      LWS_WRITE_TEXT);
		if (m < n) {
			lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		if (more)
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
		 * they create this event in each lws service thread context
		 * using lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for all of
		 * this service thread's connected clients; the other service
		 * threads get this event too and do the same for theirs.
		 *
		 * Only this thread changes its list, and we are on it, so we
		 * can walk it without the lock, and without holding the lock
		 * while we call into lws.
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
			lws_dll2_get_head(&vhd->pss_list[lws_wsi_tsi(wsi)])) {
			struct per_session_data__minimal *p = lws_container_of(
				d, struct per_session_data__minimal, list);

			lws_callback_on_writable(p->wsi);
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
