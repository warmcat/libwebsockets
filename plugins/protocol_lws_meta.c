/*
 * lws meta protocol handler
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>
#include <stdlib.h>

#define MAX_SUBCHANNELS 8

enum lws_meta_parser_state {
	MP_IDLE, /* in body of message */

	MP_CMD, /* await cmd */

	MP_OPEN_SUBCHANNEL_PROTOCOL,
	MP_OPEN_SUBCHANNEL_URL,
	MP_OPEN_SUBCHANNEL_COOKIE,

	MP_CLOSE_CHID,
	MP_CLOSE_LEN,
	MP_CLOSE_CODEM,
	MP_CLOSE_CODEL,
	MP_CLOSE_PAYLOAD,

	MP_WRITE_CHID,
};

enum {
	PENDING_TYPE_OPEN_RESULT = 0,
	PENDING_TYPE_CHILD_CLOSE
};

/*
 * while we haven't reported the result yet, we keep a linked-list of
 * connection opens and their result.
 */
struct pending_conn {
	struct pending_conn *next;
	char protocol[123];
	char cookie[8];
	int ch;
	int len;

	unsigned char type;
};

/*
 * the parent, lws-meta connection
 */
struct per_session_data__lws_meta {
	struct lws *wsi[MAX_SUBCHANNELS + 1];
	char told_closing[MAX_SUBCHANNELS + 1];
	struct pending_conn *first;
	struct pending_conn *pend;
	char suburl[64];
	unsigned char close[126];
	int active_subchannel_tx, active_subchannel_rx;
	enum lws_meta_parser_state state;
	int pos;
	int count_pending;
	int round_robin;
	int close_status_16;
	int close_len;
	int which_close;
	int ch;
};

static int
lws_find_free_channel(struct per_session_data__lws_meta *pss)
{
	int n;

	for (n = 1; n <= MAX_SUBCHANNELS; n++)
		if (pss->wsi[n] == NULL)
			return n;

	return 0; /* none free */
}

static struct lws *
lws_get_channel_wsi(struct per_session_data__lws_meta *pss, int ch)
{
	if (!ch)
		return 0;
	return pss->wsi[ch];
}

static int
lws_get_channel_id(struct lws *wsi)
{
	return (lws_intptr_t)lws_get_opaque_parent_data(wsi);
}

static void
lws_set_channel_id(struct lws *wsi, int id)
{
	lws_set_opaque_parent_data(wsi, (void *)(lws_intptr_t)id);
}

static struct pending_conn *
new_pending(struct per_session_data__lws_meta *pss)
{
	struct pending_conn *pend;

	if (pss->count_pending >= MAX_SUBCHANNELS * 2) {
		lwsl_notice("too many pending open subchannel\n");

		return NULL;
	}

	pss->count_pending++;

	pend = malloc(sizeof(*pend));
	if (!pend) {
		lwsl_notice("OOM\n");

		return NULL;
	}

	memset(pend, 0, sizeof(*pend));

	return pend;
}

static int
callback_lws_meta(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_meta *pss =
			(struct per_session_data__lws_meta *)user;
	struct lws_write_passthru *pas;
	struct pending_conn *pend, *pend1;
	struct lws *cwsi;
	lws_sock_file_fd_type fd;
	unsigned char *bin, buf[LWS_PRE + 512], *start = &buf[LWS_PRE],
			*end = &buf[sizeof(buf) - 1], *p = start;
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);
		pss->state = MP_CMD;
		pss->pos = 0;
		break;

	case LWS_CALLBACK_CLOSED:
		break;

	case LWS_CALLBACK_CHILD_CLOSING:
		cwsi = (struct lws *)in;

		/* remove it from our tracking */
		pss->wsi[lws_get_channel_id(cwsi)] = NULL;

		if (pss->told_closing[lws_get_channel_id(cwsi)]) {
			pss->told_closing[lws_get_channel_id(cwsi)] = 0;
			break;
		}

		pend = new_pending(pss);
		if (!pend)
			return -1;

		/* note which channel id */
		pend->ch = lws_get_channel_id(cwsi);

		if (lws_get_close_length(cwsi)) {
			pend->len = lws_get_close_length(cwsi);
			memcpy(pend->protocol, lws_get_close_payload(cwsi),
					pend->len);
		}

		pend->type = PENDING_TYPE_CHILD_CLOSE;
		pend->next = pss->first;
		pss->first = pend;

		/*
		 * nothing else will complete from this wsi, so abandon
		 * tracking in-process messages from this wsi.
		 */

		if (pss->active_subchannel_tx == pend->ch)
			pss->active_subchannel_tx = 0;

		if (pss->active_subchannel_rx == pend->ch)
			pss->active_subchannel_rx = 0;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:

		if (!pss->active_subchannel_tx) {

			/* not in the middle of a message...
			 *
			 * PRIORITY 1: pending open and close notifications
			 */

			pend = pss->first;
			while (pend && p < end - 128) {
				switch (pend->type) {
				case PENDING_TYPE_OPEN_RESULT:
					lwsl_debug("open result %s %s\n",
						pend->cookie, pend->protocol);
					*p++ = LWS_META_CMD_OPEN_RESULT;
					memcpy(p, pend->cookie,
					       strlen(pend->cookie) + 1);
					p += strlen(pend->cookie) + 1;
					*p++ = LWS_META_TRANSPORT_OFFSET +
							pend->ch;
					memcpy(p, pend->protocol,
					       strlen(pend->protocol) + 1);
					p += strlen(pend->protocol) + 1;
					break;
				case PENDING_TYPE_CHILD_CLOSE:
					*p++ = LWS_META_CMD_CLOSE_NOTIFY;
					*p++ = LWS_META_TRANSPORT_OFFSET +
							pend->ch;
					for (n = 0; n < pend->len; n++)
						*p++ = pend->protocol[n];
					break;
				}

				pss->count_pending--;
				pend1 = pend;
				pend = pend->next;
				free(pend1);
				pss->first = pend;
			}

			if (p != start) {
				if (lws_write(wsi, start, p - start,
					      LWS_WRITE_BINARY) < 0)
					return 1;
				if (pend) /* still more */
					lws_callback_on_writable(wsi);
				break;
			}

			/* PRIORITY 2: pick a child for the writable callback */

			cwsi = NULL;
			for (n = 0; n < MAX_SUBCHANNELS; n++) {
				m = ((pss->round_robin + n) % MAX_SUBCHANNELS) + 1;
				if (pss->wsi[m] &&
				    lws_get_child_pending_on_writable(pss->wsi[m])) {
					pss->round_robin = m;
					cwsi = pss->wsi[m];
					break;
				}
			}
		} else
			/* one child is in middle of message, stay with it */
			cwsi = pss->wsi[pss->active_subchannel_tx];

		if (!cwsi)
			break;

		lws_clear_child_pending_on_writable(cwsi);
		if (lws_handle_POLLOUT_event(cwsi, NULL))
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE:
		bin = (unsigned char *)in;

		/*
		 * at the start of a message, we may have one or more
		 * lws_meta command blocks.
		 */
		while (pss->state != MP_IDLE &&
		       (unsigned int)(bin - (unsigned char *)in) < len) {

			switch (pss->state) {
			case MP_IDLE: /* in body of message */

				if (!lws_is_first_fragment(wsi))
					break;

				pss->state = MP_CMD;

				/* fallthru */

			case MP_CMD: /* await cmd */

				pss->pos = 0;

				switch (*bin++) {
				case LWS_META_CMD_OPEN_SUBCHANNEL:

					pss->pend = new_pending(pss);
					if (!pss->pend)
						return -1;

					pss->state = MP_OPEN_SUBCHANNEL_PROTOCOL;

					break;
				case LWS_META_CMD_CLOSE_NOTIFY:
				case LWS_META_CMD_CLOSE_RQ:
					pss->which_close = bin[-1];
					pss->state = MP_CLOSE_CHID;
					break;
				case LWS_META_CMD_WRITE:
					pss->state = MP_WRITE_CHID;
					break;

				// open result is also illegal to receive
				default:
					lwsl_notice("bad lws_meta cmd 0x%x\n",
						    bin[-1]);

					return -1;
				}

				break;

			case MP_OPEN_SUBCHANNEL_PROTOCOL:
				pss->pend->protocol[pss->pos++] = *bin++;
				if (pss->pos == sizeof(pss->pend->protocol) - 1) {
					lwsl_notice("protocol name too long\n");
					return -1;
				}

				if (bin[-1] != '\0')
					break;

				pss->state = MP_OPEN_SUBCHANNEL_URL;
				pss->pos = 0;
				break;

			case MP_OPEN_SUBCHANNEL_URL:
				pss->suburl[pss->pos++] = *bin++;
				if (pss->pos == sizeof(pss->suburl) - 1) {
					lwsl_notice("suburl too long\n");
					return -1;
				}

				if (bin[-1] != '\0')
					break;

				pss->state = MP_OPEN_SUBCHANNEL_COOKIE;
				pss->pos = 0;
				break;

			case MP_OPEN_SUBCHANNEL_COOKIE:
				pss->pend->cookie[pss->pos++] = *bin++;
				if (pss->pos == sizeof(pss->pend->cookie) - 1) {
					lwsl_notice("cookie too long\n");
					return -1;
				}

				if (bin[-1] != '\0')
					break;

				lwsl_debug("%s: %s / %s / %s\n", __func__,
					    pss->pend->protocol,
					    pss->suburl,
					    pss->pend->cookie);

				pss->pend->ch = lws_find_free_channel(pss);
				if (pss->pend->ch) {

					fd.sockfd = 0; // not going to be used

					cwsi = lws_adopt_descriptor_vhost(
							lws_get_vhost(wsi),
							LWS_ADOPT_WS_PARENTIO,
							fd, pss->pend->protocol,
							wsi);

					if (!cwsi) {
						lwsl_notice("open failed\n");
						pss->pend->ch = 0;
					} else {
						pss->wsi[pss->pend->ch] = cwsi;
						lws_set_channel_id(cwsi,
								pss->pend->ch);
						lwsl_debug("cwsi %p on parent %p open OK %s\n",
							cwsi, wsi, pss->pend->protocol);
					}

				} else
					lwsl_notice("no free subchannels\n");

				pss->pend->type = PENDING_TYPE_OPEN_RESULT;
				pss->pend->next = pss->first;
				pss->first = pss->pend;

				lws_callback_on_writable(wsi);

				pss->state = MP_CMD;
				pss->pos = 0;
				break;

			case MP_CLOSE_CHID:
				pss->ch = (*bin++) - LWS_META_TRANSPORT_OFFSET;
				pss->state = MP_CLOSE_LEN;
				pss->pos = 0;
				break;
			case MP_CLOSE_LEN:
				pss->close_len = (*bin++) -
					LWS_META_TRANSPORT_OFFSET;
				lwsl_debug("close len %d\n", pss->close_len);
				pss->state = MP_CLOSE_CODEM;
				pss->pos = 0;
				break;
			case MP_CLOSE_CODEM:
				pss->close[pss->pos++] = *bin;
				pss->close_status_16 = (*bin++) * 256;
				pss->state = MP_CLOSE_CODEL;
				break;
			case MP_CLOSE_CODEL:
				pss->close[pss->pos++] = *bin;
				pss->close_status_16 |= *bin++;
				pss->state = MP_CLOSE_PAYLOAD;
				break;
			case MP_CLOSE_PAYLOAD:
				pss->close[pss->pos++] = *bin++;
				if (pss->pos == sizeof(pss->close) - 1) {
					lwsl_notice("close payload too long\n");
					return -1;
				}
				if (--pss->close_len)
					break;

				pss->state = MP_CMD;

				cwsi = lws_get_channel_wsi(pss, pss->ch);
				if (!cwsi) {
					lwsl_notice("close (%d) bad ch %d\n",
						pss->which_close, pss->ch);
					break;
				}

				if (pss->which_close == LWS_META_CMD_CLOSE_RQ) {
					if (lws_get_protocol(cwsi)->callback(
					    cwsi,
					    LWS_CALLBACK_WS_PEER_INITIATED_CLOSE,
					    lws_wsi_user(cwsi), &pss->close,
					    pss->pos))
						return -1;

					/*
					 * we need to echo back the close payload
					 * when we send the close notification
					 */
					lws_close_reason(cwsi,
							 pss->close_status_16,
							 &pss->close[2],
							 pss->pos - 2);
				}

				/* so force him closed */

				lws_set_timeout(cwsi,
					PENDING_TIMEOUT_KILLED_BY_PARENT,
					LWS_TO_KILL_SYNC);
				break;

			case MP_WRITE_CHID:
				pss->active_subchannel_rx = (*bin++) -
					LWS_META_TRANSPORT_OFFSET;
				pss->state = MP_IDLE;
				break;
			}
		}

		len -= bin - (unsigned char *)in;

		if (!len)
			break;

		cwsi = lws_get_channel_wsi(pss, pss->active_subchannel_rx);
		if (!cwsi) {
			lwsl_notice("bad ch %d\n", pss->active_subchannel_rx);

			return -1;
		}

		// lwsl_debug("%s: RX len %d\n", __func__, (int)len);

		if (lws_get_protocol(cwsi)->callback(cwsi,
					LWS_CALLBACK_RECEIVE,
					lws_wsi_user(cwsi), bin, len))
			lws_set_timeout(cwsi,
				PENDING_TIMEOUT_KILLED_BY_PARENT,
				LWS_TO_KILL_SYNC);

		if (lws_is_final_fragment(wsi)) {
			pss->active_subchannel_rx = 0;
			pss->state = MP_CMD;
		}
		break;

	/*
	 * child wrote something via lws_write.... which passed it up to us to
	 * deal with, because we are the parent.  Prepend two bytes for
	 * lws-meta command and channel index, and send it out on parent
	 */
	case LWS_CALLBACK_CHILD_WRITE_VIA_PARENT:
		pas = in;
		bin = ((unsigned char *)pas->buf);

		if ((pas->wp & 7) == 4 /*LWS_WRITE_CLOSE */) {
			*p++ = LWS_META_CMD_CLOSE_NOTIFY;
			*p++ = LWS_META_TRANSPORT_OFFSET +
					lws_get_channel_id(pas->wsi);
			*p++ = (unsigned char)pas->len +
					LWS_META_TRANSPORT_OFFSET - 2;
			*p++ = *bin++;
			*p++ = *bin++;
			for (n = 0; n < (int)pas->len - 2; n++)
				*p++ = bin[n];

			if (lws_write(wsi, start, p - start,
				      LWS_WRITE_BINARY) < 0)
				return 1;

			pss->told_closing[lws_get_channel_id(pas->wsi)] = 1;
			break;
		}

		if ((pas->wp & 7) == LWS_WRITE_TEXT ||
		    (pas->wp & 7) == LWS_WRITE_BINARY) {

			if (pas->wp & LWS_WRITE_NO_FIN)
				pss->active_subchannel_tx =
						lws_get_channel_id(pas->wsi);

			/* start of message, prepend the subchannel id */

			bin -= 2;
			bin[0] = LWS_META_CMD_WRITE;
			bin[1] = lws_get_channel_id(pas->wsi) +
					LWS_META_TRANSPORT_OFFSET;
			if (lws_write(wsi, bin, pas->len + 2, pas->wp) < 0)
				return 1;
		} else
			if (lws_write(wsi, bin, pas->len, pas->wp) < 0)
				return 1;

		/* track EOM */

		if (!(pas->wp & LWS_WRITE_NO_FIN))
			pss->active_subchannel_tx = 0;
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_META { \
		"lws-meta", \
		callback_lws_meta, \
		sizeof(struct per_session_data__lws_meta), \
		1024, /* rx buf size must be >= permessage-deflate rx size */ \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_META
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_meta(struct lws_context *context,
			     struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_meta(struct lws_context *context)
{
	return 0;
}
#endif
