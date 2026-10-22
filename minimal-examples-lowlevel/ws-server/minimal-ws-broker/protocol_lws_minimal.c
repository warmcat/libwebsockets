/*
 * ws protocol handler plugin for "lws-minimal-broker"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This implements a minimal "broker", for systems that look like this
 *
 * [ publisher  ws client ] <-> [ ws server  broker ws server ] <-> [ ws client subscriber ]
 *
 * The "publisher" role is to add data to the broker.
 *
 * The "subscriber" role is to hear about all data added to the system.
 *
 * The "broker" role is to manage incoming data from publishers and pass it out
 * to subscribers.
 *
 * Any number of publishers and subscribers are supported.
 *
 * This example implements a single ws server, using one ws protocol, that treats ws
 * connections as being in publisher or subscriber mode according to the URL the ws
 * connection was made to.  ws connections to "/publisher" URL are understood to be
 * publishing data and to any other URL, subscribing.
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

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
	char binary; /* pass it on as a BINARY message, else TEXT */
};

/* one of these is created for each client connecting to us */

struct per_session_data__minimal {
	struct per_session_data__minimal *pss_list;
	struct lws *wsi;
	uint8_t *rx; /* LWS_PRE + message being collected, or NULL */
	size_t rx_len; /* bytes of message in rx after LWS_PRE */
	uint32_t tail;
	char publishing; /* nonzero: peer is publishing to us */
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	struct per_session_data__minimal *pss_list; /* linked-list of live pss*/

	struct lws_ring *ring; /* ringbuffer holding unsent messages */
};

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
	char buf[32];
	int n, m;

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

		vhd->ring = lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring)
			return 1;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lws_ring_destroy(vhd->ring);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		pss->tail = lws_ring_get_oldest_tail(vhd->ring);
		pss->wsi = wsi;
		if (lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_GET_URI) > 0)
			pss->publishing = !strcmp(buf, "/publisher");
		if (!pss->publishing)
			/* add subscribers to the list of live pss held in the vhd */
			lws_ll_fwd_insert(pss, pss_list, vhd->pss_list);
		break;

	case LWS_CALLBACK_CLOSED:
		/* remove our closing pss from the list of live pss */
		lws_ll_fwd_remove(struct per_session_data__minimal, pss_list,
				  pss, vhd->pss_list);
		/* drop any partial message we were collecting */
		minimal_rx_discard(pss);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		if (pss->publishing)
			break;

		pmsg = lws_ring_get_element(vhd->ring, &pss->tail);
		if (!pmsg)
			break;

		/* notice we allowed for LWS_PRE in the payload already */
		m = lws_write(wsi, ((unsigned char *)pmsg->payload) + LWS_PRE,
			      pmsg->len, pmsg->binary ?
					LWS_WRITE_BINARY : LWS_WRITE_TEXT);
		if (m < (int)pmsg->len) {
			lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		lws_ring_consume_and_update_oldest_tail(
			vhd->ring,	/* lws_ring object */
			struct per_session_data__minimal, /* type of objects with tails */
			&pss->tail,	/* tail of guy doing the consuming */
			1,		/* number of payload objects being consumed */
			vhd->pss_list,	/* head of list of objects with tails */
			tail,		/* member name of tail in objects with tails */
			pss_list	/* member name of next object in objects with tails */
		);

		/* more to do? */
		if (lws_ring_get_element(vhd->ring, &pss->tail))
			/* come back as soon as we can write more */
			lws_callback_on_writable(pss->wsi);
		break;

	case LWS_CALLBACK_RECEIVE:

		if (!pss->publishing)
			break;

		if (minimal_rx_collect(wsi, pss, in, len))
			return -1;

		if (!lws_is_final_fragment(wsi))
			/* wait for the rest of the message */
			break;

		if (minimal_rx_check(wsi, pss))
			return -1;

		/*
		 * For test, our policy is ignore publishing when there are
		 * no subscribers connected.
		 */
		if (!vhd->pss_list) {
			minimal_rx_discard(pss);
			break;
		}

		n = (int)lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			minimal_rx_discard(pss);
			lwsl_user("dropping!\n");
			break;
		}

		/* the collected message becomes the ring element payload */
		amsg.payload = pss->rx;
		amsg.len = pss->rx_len;
		amsg.binary = (char)lws_frame_is_binary(wsi);
		pss->rx = NULL;
		pss->rx_len = 0;

		if (!lws_ring_insert(vhd->ring, &amsg, 1)) {
			__minimal_destroy_message(&amsg);
			lwsl_user("dropping 2!\n");
			break;
		}

		/*
		 * let every subscriber know we want to write something
		 * on them as soon as they are ready
		 */
		lws_start_foreach_llp(struct per_session_data__minimal **,
				      ppss, vhd->pss_list) {
			if (!(*ppss)->publishing)
				lws_callback_on_writable((*ppss)->wsi);
		} lws_end_foreach_llp(ppss, pss_list);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL \
	{ \
		"lws-minimal-broker", \
		callback_minimal, \
		sizeof(struct per_session_data__minimal), \
		128, \
		0, NULL, 0 \
	}
