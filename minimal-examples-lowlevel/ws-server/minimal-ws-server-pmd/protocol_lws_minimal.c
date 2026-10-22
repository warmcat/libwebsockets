/*
 * ws protocol handler plugin for "lws-minimal"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This version holds a single message at a time, which may be lost if a new
 * message comes.  See the minimal-ws-server-ring sample for the same thing
 * but using an lws_ring ringbuffer to hold up to 8 messages at a time.
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
	lws_dll2_t list; /* in vhd->pss_list */
	struct lws *wsi;
	uint8_t *rx; /* LWS_PRE + message being collected, or NULL */
	size_t rx_len; /* bytes of message in rx after LWS_PRE */
	int last; /* the last message number we sent */
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_dll2_owner_t pss_list; /* live pss */

	struct msg amsg; /* the one pending message... */
	int current; /* the current message number we are caching */
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
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			__minimal_destroy_message(&vhd->amsg);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* add ourselves to the list of live pss held in the vhd */
		lws_dll2_add_tail(&pss->list, &vhd->pss_list);
		pss->wsi = wsi;
		pss->last = vhd->current;
		break;

	case LWS_CALLBACK_CLOSED:
		/* remove our closing pss from the list of live pss */
		lws_dll2_remove(&pss->list);
		/* drop any partial message we were collecting */
		minimal_rx_discard(pss);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd->amsg.payload)
			break;

		if (pss->last == vhd->current)
			break;

		/* notice we allowed for LWS_PRE in the payload already */
		m = lws_write(wsi, ((unsigned char *)vhd->amsg.payload) +
			      LWS_PRE, vhd->amsg.len, vhd->amsg.binary ?
					LWS_WRITE_BINARY : LWS_WRITE_TEXT);
		if (m < (int)vhd->amsg.len) {
			lwsl_err("ERROR %d writing to ws\n", m);
			return -1;
		}

		pss->last = vhd->current;
		break;

	case LWS_CALLBACK_RECEIVE:
		if (minimal_rx_collect(wsi, pss, in, len))
			return -1;

		if (!lws_is_final_fragment(wsi))
			/* wait for the rest of the message */
			break;

		if (minimal_rx_check(wsi, pss))
			return -1;

		/* it replaces the message we were holding */
		__minimal_destroy_message(&vhd->amsg);

		/* the collected message becomes the one we hold */
		vhd->amsg.payload = pss->rx;
		vhd->amsg.len = pss->rx_len;
		vhd->amsg.binary = (char)lws_frame_is_binary(wsi);
		pss->rx = NULL;
		pss->rx_len = 0;
		vhd->current++;

		/*
		 * let everybody know we want to write something on them
		 * as soon as they are ready
		 */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list)) {
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
