/*
 * ws protocol handler plugin for "lws-minimal"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This version uses an lws_ring ringbuffer to cache up to 8 messages at a time,
 * so it's not so easy to lose messages.
 *
 * This also demonstrates what to do about clients that send faster than the
 * others can be sent to, and clients that can't keep up for some reason:
 *
 *  - the ringbuffer only frees a message once everybody has been sent it.
 *    When it is full, we stop reading from every client (lws_rx_flow_control)
 *    until it has room again, so senders are slowed to the pace of the
 *    receivers, and nothing is lost.
 *
 *  - a client is closed when the oldest message it hasn't been sent yet has
 *    been waiting for it for MINIMAL_LAG_SECS, so one that stops reading
 *    can't hold up everybody else for longer than that.  A client that keeps
 *    up is never closed, however much anybody sends, and one that reads
 *    steadily but slower than a sender just slows the sender down; only a
 *    client too slow to take a ringbuffer's worth of messages in
 *    MINIMAL_LAG_SECS while somebody is sending is closed.
 *
 * A RECEIVE callback is not a message: a message may arrive in several
 * fragments, and a fragment bigger than the rx buffer arrives in several
 * pieces, any of which may end partway through a UTF-8 character.  So we
 * collect the pieces of each message for each connection, and only pass on
 * whole messages, as the type (TEXT or BINARY) they were sent as.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/*
 * The largest message we will collect and pass on.  A client sending anything
 * bigger is closed with 1009 (Message Too Big), and none of it is passed on.
 */
#define MINIMAL_MAX_MESSAGE 4096

/* how many messages the ringbuffer holds */
#define MINIMAL_RING_DEPTH 8

/* a client with a message that has waited this long for it is closed */
#define MINIMAL_LAG_SECS 5

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
	lws_usec_t arrived; /* when it went in the ringbuffer */
	char binary; /* pass it on as a BINARY message, else TEXT */
};

/* one of these is created for each client connecting to us */

struct per_session_data__minimal {
	lws_dll2_t list; /* in vhd->pss_list */
	struct lws *wsi;
	uint8_t *rx; /* LWS_PRE + message being collected, or NULL */
	size_t rx_len; /* bytes of message in rx after LWS_PRE */
	lws_usec_t joined; /* when we connected */
	lws_usec_t lag_from; /* the lag timer runs from here, or 0: caught up */
	uint32_t tail;
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_dll2_owner_t pss_list; /* live pss */

	struct lws_ring *ring; /* ringbuffer holding unsent messages */
	char rx_paused; /* we stopped reading from clients: ring full */
};

/*
 * Messages before the oldest tail of any connection have been sent to
 * everybody and can be freed.
 */

static void
minimal_update_oldest_tail(struct per_vhost_data__minimal *vhd)
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
 * Start or stop reading from every client.  We stop when the ring is full, so
 * nobody can send us a message we have no room for, and start again when it
 * is half empty.
 */

static void
minimal_rx_flow(struct per_vhost_data__minimal *vhd, int enable)
{
	if (vhd->rx_paused == !enable)
		return;

	vhd->rx_paused = (char)!enable;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->pss_list)) {
		struct per_session_data__minimal *pss = lws_container_of(d,
					struct per_session_data__minimal, list);

		lws_rx_flow_control(pss->wsi, enable);
	} lws_end_foreach_dll(d);
}

/* if we stopped reading, and there is room again, let the senders carry on */

static void
minimal_rx_resume_if_room(struct per_vhost_data__minimal *vhd)
{
	if (vhd->rx_paused && lws_ring_get_count_free_elements(vhd->ring) >=
						MINIMAL_RING_DEPTH / 2)
		minimal_rx_flow(vhd, 1);
}

/*
 * A client is closed once the oldest message it hasn't been sent yet has been
 * waiting for it for MINIMAL_LAG_SECS (counting from when it connected, if
 * that was later): otherwise one client that stopped reading would keep the
 * ring full, and everybody else waiting, for as long as it likes.  This judges
 * the client by how stale what it is missing is, not by whether it ever gets
 * completely caught up, which a busy sender could prevent: a client that keeps
 * up is always being sent fresh messages and is never closed, while one that
 * stopped reading is closed about MINIMAL_LAG_SECS after the first message it
 * didn't take.
 *
 * Call it whenever the client's tail, or what is waiting for it, changed.
 */

static void
minimal_lag_update(struct per_vhost_data__minimal *vhd,
		   struct per_session_data__minimal *pss)
{
	const struct msg *pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
	lws_usec_t from, left;

	if (!pmsg) {
		/* we have been sent everything: nothing is waiting for us */
		if (pss->lag_from) {
			pss->lag_from = 0;
			lws_set_timeout(pss->wsi, NO_PENDING_TIMEOUT, 0);
		}
		return;
	}

	from = pmsg->arrived > pss->joined ? pmsg->arrived : pss->joined;
	if (from == pss->lag_from)
		/* the same message is still the oldest: the timer is right */
		return;

	pss->lag_from = from;
	left = from + (MINIMAL_LAG_SECS * LWS_US_PER_SEC) - lws_now_usecs();
	lws_set_timeout(pss->wsi, PENDING_TIMEOUT_LAGGING, left <= 0 ?
			LWS_TO_KILL_ASYNC :
			(int)((left + LWS_US_PER_SEC - 1) / LWS_US_PER_SEC));
}

/* destroys the message when everyone has had a copy of it */

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static void
minimal_rx_discard(struct per_session_data__minimal *pss)
{
	free(pss->rx);
	pss->rx = NULL;
	pss->rx_len = 0;
}

/*
 * Add this piece to the message the connection is sending us.  Returns 0 if
 * it was taken (lws_is_final_fragment() says if the message is complete now),
 * or -1 if the connection must be closed, with the close reason already set.
 */

static int
minimal_rx_collect(struct lws *wsi, struct per_session_data__minimal *pss,
		   const void *in, size_t len)
{
	uint8_t *p;

	if (len > MINIMAL_MAX_MESSAGE - pss->rx_len) {
		lws_close_reason(wsi, LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE,
				 (uint8_t *)"too large", 9);
		return -1;
	}

	/* notice we over-allocate by LWS_PRE */
	p = realloc(pss->rx, LWS_PRE + pss->rx_len + len);
	if (!p) {
		lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION,
				 (uint8_t *)"oom", 3);
		return -1;
	}
	pss->rx = p;
	if (len)
		memcpy(pss->rx + LWS_PRE + pss->rx_len, in, len);
	pss->rx_len += len;

	return 0;
}

/*
 * The whole message is here.  We are about to send it on to other people's
 * browsers, which must fail their connection on a TEXT message that is not
 * valid UTF-8.  lws checks TEXT only if the vhost asked it to, so make sure.
 * Returns 0 if it can be passed on, or -1 if the connection must be closed,
 * with the close reason already set.
 */

static int
minimal_rx_check(struct lws *wsi, struct per_session_data__minimal *pss)
{
	unsigned char st = 0;

	if (lws_frame_is_binary(wsi))
		return 0;

	if (lws_check_utf8(&st, pss->rx + LWS_PRE, pss->rx_len) || st) {
		lws_close_reason(wsi, LWS_CLOSE_STATUS_INVALID_PAYLOAD,
				 (uint8_t *)"bad utf8", 8);
		return -1;
	}

	return 0;
}

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
	const struct msg *pmsg;
	struct msg amsg;
	int m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		if (!vhd)
			return 1;
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		vhd->ring = lws_ring_create(sizeof(struct msg),
					    MINIMAL_RING_DEPTH,
					    __minimal_destroy_message);
		if (!vhd->ring)
			return 1;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_ring_destroy(vhd->ring);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* add ourselves to the list of live pss held in the vhd */
		lws_dll2_add_tail(&pss->list, &vhd->pss_list);
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		pss->wsi = wsi;
		pss->joined = lws_now_usecs();
		if (vhd->rx_paused)
			/* we're not reading from anybody at the moment */
			lws_rx_flow_control(wsi, 0);
		/* we get what's in the ring already */
		if (lws_ring_get_element(vhd->ring, &pss->tail)) {
			lws_callback_on_writable(wsi);
			minimal_lag_update(vhd, pss);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		/* remove our closing pss from the list of live pss */
		lws_dll2_remove(&pss->list);
		/* drop any partial message we were collecting */
		minimal_rx_discard(pss);
		/* we may have been the one holding the oldest tail */
		minimal_update_oldest_tail(vhd);
		minimal_rx_resume_if_room(vhd);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		/*
		 * Send everything waiting for us that the connection will take
		 * now: a client that can keep up must be able to catch up in
		 * one go, not one message each time around the event loop
		 */
		while (!lws_send_pipe_choked(wsi) &&
		       (pmsg = lws_ring_get_element(vhd->ring, &pss->tail))) {
			/* notice we allowed for LWS_PRE in the payload already */
			m = lws_write(wsi, ((unsigned char *)pmsg->payload) +
				      LWS_PRE, pmsg->len, pmsg->binary ?
					LWS_WRITE_BINARY : LWS_WRITE_TEXT);
			if (m < (int)pmsg->len) {
				lwsl_err("ERROR %d writing to ws socket\n", m);
				return -1;
			}

			/* we are done with that one */
			lws_ring_consume(vhd->ring, &pss->tail, NULL, 1);
		}

		/* if they were the last ones waiting for anybody, free them */
		minimal_update_oldest_tail(vhd);
		/* restart our lag timer from what is waiting for us now */
		minimal_lag_update(vhd, pss);
		/* if there's room again, let the senders carry on */
		minimal_rx_resume_if_room(vhd);

		/* more to do for us? */
		if (pss->lag_from)
			/* come back as soon as we can write more */
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (minimal_rx_collect(wsi, pss, in, len))
			return -1;

		if (!lws_is_final_fragment(wsi))
			/* wait for the rest of the message */
			break;

		if (minimal_rx_check(wsi, pss))
			return -1;

		if (!lws_ring_get_count_free_elements(vhd->ring)) {
			/*
			 * We stop reading from everybody when the ring fills,
			 * so this only happens where lws can't stop reading
			 * for us, eg, ws over an h2 stream, which h2 flow
			 * controls instead.  There's nowhere to put it.
			 */
			minimal_rx_discard(pss);
			lwsl_user("dropping!\n");
			break;
		}

		/* the collected message becomes the ring element payload */
		amsg.payload = pss->rx;
		amsg.len = pss->rx_len;
		amsg.arrived = lws_now_usecs();
		amsg.binary = (char)lws_frame_is_binary(wsi);
		pss->rx = NULL;
		pss->rx_len = 0;

		if (!lws_ring_insert(vhd->ring, &amsg, 1)) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping!\n");
			break;
		}

		/*
		 * let everybody know we want to write something on them
		 * as soon as they are ready, and anybody who was caught up
		 * starts their lag timer from this message
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list)) {
			struct per_session_data__minimal *p = lws_container_of(
				d, struct per_session_data__minimal, list);

			lws_callback_on_writable(p->wsi);
			minimal_lag_update(vhd, p);
		} lws_end_foreach_dll(d);

		if (!lws_ring_get_count_free_elements(vhd->ring))
			/* no room for another: stop reading from everybody */
			minimal_rx_flow(vhd, 0);
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
		0, \
		0, NULL, 0 \
	}
