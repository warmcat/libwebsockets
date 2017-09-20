/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>
#include <stdlib.h>

/* lws-mirror_protocol */

#if defined(LWS_WITH_ESP8266)
#define MAX_MESSAGE_QUEUE 64
#else
#define MAX_MESSAGE_QUEUE 512
#endif

#define MAX_MIRROR_INSTANCES 10

struct lws_mirror_instance;

struct per_session_data__lws_mirror {
	struct lws *wsi;
	struct lws_mirror_instance *mi;
	struct per_session_data__lws_mirror *same_mi_pss_list;
	uint32_t tail;
};

struct a_message {
	void *payload;
	size_t len;
};

struct lws_mirror_instance {
	struct lws_mirror_instance *next;
	struct per_session_data__lws_mirror *same_mi_pss_list;
	struct lws_ring *ring;
	char name[30];
	char rx_enabled;
};

struct per_vhost_data__lws_mirror {
	struct lws_mirror_instance *mi_list;
};


/*
 * Find out which connection to this mirror instance has the longest number
 * of still unread elements in the ringbuffer and update the lws_ring with it.
 *
 * You can skip calling this if on your connection, before processing, the tail
 * was not equal to the current worst, ie,  if the tail you will work on is !=
 * lws_ring_get_oldest_tail(ring) then no need to call this when the tail
 * has changed; it wasn't the oldest so it won't change the oldest.
 *
 * Returns 0 if oldest unchanged or 1 if oldest changed from this call.
 */
static int
lws_mirror_update_worst_tail(struct lws_mirror_instance *mi)
{
	struct per_session_data__lws_mirror *pss = mi->same_mi_pss_list;
	uint32_t wai, worst = 0, worst_tail, valid = 0, oldest;

	oldest = lws_ring_get_oldest_tail(pss->mi->ring);

	while (pss) {
		wai = lws_ring_get_count_waiting_elements(mi->ring, &pss->tail);
		if (wai > worst) {
			worst = wai;
			worst_tail = pss->tail;
			valid = 1;
		}
		pss = pss->same_mi_pss_list;
	}

	if (!valid)
		return 0;

	lws_ring_update_oldest_tail(mi->ring, worst_tail);

	return oldest != lws_ring_get_oldest_tail(mi->ring);
}

/* enable or disable rx from all connections to this mirror instance */
static void
lws_mirror_rxflow_instance(struct lws_mirror_instance *mi, int enable)
{
	lws_start_foreach_ll(struct per_session_data__lws_mirror *,
			     pss, mi->same_mi_pss_list) {
		lws_rx_flow_control(pss->wsi, enable);
	} lws_end_foreach_ll(pss, same_mi_pss_list);

	mi->rx_enabled = enable;
}

static void
lws_mirror_destroy_message(void *_msg)
{
	struct a_message *msg = _msg;

	free(msg->payload);
}

static int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_mirror *pss =
			(struct per_session_data__lws_mirror *)user;
	struct per_vhost_data__lws_mirror *v =
			(struct per_vhost_data__lws_mirror *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	struct lws_mirror_instance *mi = NULL;
	const struct a_message *msg;
	struct a_message amsg;
	char name[300], update_worst, sent_something;
	uint32_t oldest_tail;
	int n, count_mi = 0;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);

		/*
		 * mirror instance name... defaults to "", but if URL includes
		 * "?mirror=xxx", will be "xxx"
		 */
		name[0] = '\0';
		if (lws_get_urlarg_by_name(wsi, "mirror", name, sizeof(name) - 1))
			lwsl_notice("get urlarg failed\n");
		lwsl_notice("%s: mirror name '%s'\n", __func__, name);

		/* is there already a mirror instance of this name? */

		lws_start_foreach_ll(struct lws_mirror_instance *, mi1, v->mi_list) {
			count_mi++;
			if (strcmp(name, mi1->name))
				continue;
			/* yes... we will join it */
			lwsl_notice("Joining existing mi %p '%s'\n", mi1, name);
			mi = mi1;
			break;
		} lws_end_foreach_ll(mi1, next);

		if (!mi) {

			/* no existing mirror instance for name */
			if (count_mi == MAX_MIRROR_INSTANCES)
				return -1;

			/* create one with this name, and join it */
			mi = malloc(sizeof(*mi));
			if (!mi)
				return 1;
			memset(mi, 0, sizeof(*mi));
			mi->ring = lws_ring_create(sizeof(struct a_message),
						   MAX_MESSAGE_QUEUE,
						   lws_mirror_destroy_message);
			if (!mi->ring) {
				free(mi);
				return 1;
			}

			mi->next = v->mi_list;
			v->mi_list = mi;
			strcpy(mi->name, name);
			mi->rx_enabled = 1;

			lwsl_info("Created new mi %p '%s'\n", mi, name);
		}

		/* add our pss to list of guys bound to this mi */

		pss->same_mi_pss_list = mi->same_mi_pss_list;
		mi->same_mi_pss_list = pss;

		/* init the pss */

		pss->mi = mi;
		pss->tail = lws_ring_get_oldest_tail(mi->ring);
		pss->wsi = wsi;

		break;

	case LWS_CALLBACK_CLOSED:

		/* detach our pss from the mirror instance */
		mi = pss->mi;
		if (!mi)
			break;

		lws_start_foreach_llp(struct per_session_data__lws_mirror **,
			ppss, mi->same_mi_pss_list) {
			if (*ppss == pss) {
				*ppss = pss->same_mi_pss_list;
				break;
			}
		} lws_end_foreach_llp(ppss, same_mi_pss_list);

		pss->mi = NULL;
		if (mi->same_mi_pss_list)
			break;

		/* last pss unbound from mi... delete mi */
		lws_start_foreach_llp(struct lws_mirror_instance **,
				pmi, v->mi_list) {
			if (*pmi != mi)
				continue;

			*pmi = (*pmi)->next;

			lws_ring_destroy(mi->ring);
			free(mi);
			break;
		} lws_end_foreach_llp(pmi, next);

		break;

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_mirror));
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		oldest_tail = lws_ring_get_oldest_tail(pss->mi->ring);
		update_worst = oldest_tail == pss->tail;
		sent_something = 0;

		do {
			msg = lws_ring_get_element(pss->mi->ring, &pss->tail);
			if (!msg)
				break;

			n = lws_write(wsi, (unsigned char *)msg->payload +
				      LWS_PRE, msg->len, LWS_WRITE_TEXT);
			if (n < 0) {
				lwsl_err("%s: WRITEABLE: ERROR %d\n", __func__, n);
				return -1;
			}
			sent_something = 1;
			lws_ring_consume(pss->mi->ring, &pss->tail, NULL, 1);

		} while (!lws_send_pipe_choked(wsi));

		/* if any left for us to send, ask for writeable again */
		if (lws_ring_get_count_waiting_elements(pss->mi->ring, &pss->tail))
			lws_callback_on_writable(wsi);

		/*
		 * If we were originally at the oldest fifo position of all the
		 * tails, now we used some up we may have changed the oldest
		 * fifo position and made some space.
		 */
		if (!sent_something || !update_worst ||
		    !lws_mirror_update_worst_tail(pss->mi))
			break;

		/*
		 * the oldest tail did move on... so we were the oldest...
		 * check if we should re-enable rx flow for the mirror instance
		 * since we made some space now
		 */
		if (!pss->mi->rx_enabled && /* rx is disabled */
		    lws_ring_get_count_free_elements(pss->mi->ring) >
					MAX_MESSAGE_QUEUE - 5)
			/* there is enough space, let's allow rx */
			lws_mirror_rxflow_instance(pss->mi, 1);
		break;

	case LWS_CALLBACK_RECEIVE:
		n = lws_ring_get_count_free_elements(pss->mi->ring);
		if (!n) {
			lwsl_notice("dropping!\n");
			if (pss->mi->rx_enabled)
				lws_mirror_rxflow_instance(pss->mi, 0);
			break;
		}

		amsg.payload = malloc(LWS_PRE + len);
		amsg.len = len;
		if (!amsg.payload) {
			lwsl_notice("OOM: dropping\n");
			break;
		}
		memcpy((char *)amsg.payload + LWS_PRE, in, len);
		lws_ring_insert(pss->mi->ring, &amsg, 1);

		if (pss->mi->rx_enabled &&
		    lws_ring_get_count_free_elements(pss->mi->ring) <
		    	    MAX_MESSAGE_QUEUE - 5)
			lws_mirror_rxflow_instance(pss->mi, 0);

		/* ask for WRITABLE callback for every wsi on this mi */
		lws_start_foreach_ll(struct per_session_data__lws_mirror *,
				     pss1, pss->mi->same_mi_pss_list) {
			lws_callback_on_writable(pss1->wsi);
		} lws_end_foreach_ll(pss1, same_mi_pss_list);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MIRROR { \
		"lws-mirror-protocol", \
		callback_lws_mirror, \
		sizeof(struct per_session_data__lws_mirror), \
		128, /* rx buf size must be >= permessage-deflate rx size */ \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_MIRROR
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_mirror(struct lws_context *context,
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
destroy_protocol_lws_mirror(struct lws_context *context)
{
	return 0;
}
#endif
