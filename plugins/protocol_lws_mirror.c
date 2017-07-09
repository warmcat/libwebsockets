/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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
	int ringbuffer_tail;
};

struct a_message {
	void *payload;
	size_t len;
};

struct lws_mirror_instance {
	struct lws_mirror_instance *next;
	struct per_session_data__lws_mirror *same_mi_pss_list;
	char name[30];
	struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
	int ringbuffer_head;
};

struct per_vhost_data__lws_mirror {
	struct lws_mirror_instance *mi_list;
};

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
	char name[30];
	int n, m, count_mi = 0;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);

		/*
		 * mirror instance name... defaults to "", but if URL includes
		 * "?mirror=xxx", will be "xxx"
		 */

		name[0] = '\0';
		lws_get_urlarg_by_name(wsi, "mirror", name, sizeof(name) - 1);

		lwsl_notice("mirror %s\n", name);

		/* is there already a mirror instance of this name? */

		lws_start_foreach_ll(struct lws_mirror_instance *,
				     mi1, v->mi_list) {
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
			memset(mi, 0, sizeof(*mi));
			mi->next = v->mi_list;
			v->mi_list = mi;
			strcpy(mi->name, name);
			mi->ringbuffer_head = 0;

			lwsl_notice("Created new mi %p '%s'\n", mi, name);
		}

		/* add our pss to list of guys bound to this mi */

		pss->same_mi_pss_list = mi->same_mi_pss_list;
		mi->same_mi_pss_list = pss;

		/* init the pss */

		pss->mi = mi;
		pss->ringbuffer_tail = mi->ringbuffer_head;
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

			lwsl_info("%s: mirror cleaniup %p\n", __func__, v);
			for (n = 0; n < ARRAY_SIZE(mi->ringbuffer); n++)
				if (mi->ringbuffer[n].payload) {
					free(mi->ringbuffer[n].payload);
					mi->ringbuffer[n].payload = NULL;
				}

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
		while (pss->ringbuffer_tail != pss->mi->ringbuffer_head) {
			m = pss->mi->ringbuffer[pss->ringbuffer_tail].len;
			n = lws_write(wsi, (unsigned char *)
					pss->mi->ringbuffer[pss->ringbuffer_tail].payload +
				   LWS_PRE, m, LWS_WRITE_TEXT);
			if (n < 0) {
				lwsl_err("ERROR %d writing to mirror socket\n", n);
				return -1;
			}
			if (n < m)
				lwsl_err("mirror partial write %d vs %d\n", n, m);

			if (pss->ringbuffer_tail == (MAX_MESSAGE_QUEUE - 1))
				pss->ringbuffer_tail = 0;
			else
				pss->ringbuffer_tail++;

			if (((pss->mi->ringbuffer_head - pss->ringbuffer_tail) &
			    (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 15))
				lws_rx_flow_allow_all_protocol(lws_get_context(wsi),
					       lws_get_protocol(wsi));

			if (lws_send_pipe_choked(wsi)) {
				lws_callback_on_writable(wsi);
				break;
			}
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (((pss->mi->ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 1)) {
			lwsl_err("dropping!\n");
			goto choke;
		}

		if (pss->mi->ringbuffer[pss->mi->ringbuffer_head].payload)
			free(pss->mi->ringbuffer[pss->mi->ringbuffer_head].payload);

		pss->mi->ringbuffer[pss->mi->ringbuffer_head].payload = malloc(LWS_PRE + len);
		pss->mi->ringbuffer[pss->mi->ringbuffer_head].len = len;
		memcpy((char *)pss->mi->ringbuffer[pss->mi->ringbuffer_head].payload +
		       LWS_PRE, in, len);
		if (pss->mi->ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			pss->mi->ringbuffer_head = 0;
		else
			pss->mi->ringbuffer_head++;

		if (((pss->mi->ringbuffer_head - pss->ringbuffer_tail) &
		    (MAX_MESSAGE_QUEUE - 1)) != (MAX_MESSAGE_QUEUE - 2))
			goto done;

choke:
		lwsl_debug("LWS_CALLBACK_RECEIVE: throttling %p\n", wsi);
		lws_rx_flow_control(wsi, 0);

done:
		/*
		 *  ask for WRITABLE callback for every wsi bound to this
		 * mirror instance
		 */
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
