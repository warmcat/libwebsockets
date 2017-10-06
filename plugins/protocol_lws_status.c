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

#include <time.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#include <gettimeofday.h>
#endif


typedef enum {
	WALK_NONE,
	WALK_INITIAL,
	WALK_LIST,
	WALK_FINAL
} e_walk;

struct per_session_data__lws_status {
	struct per_session_data__lws_status *next;
	struct lws *wsi;
	time_t time_est;
	char user_agent[128];

	e_walk walk;
	struct per_session_data__lws_status *walk_next;
	unsigned char subsequent:1;
	unsigned char changed_partway:1;
};

struct per_vhost_data__lws_status {
	struct per_session_data__lws_status *live_pss_list;
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	int count_live_pss;
};

static void
trigger_resend(struct per_vhost_data__lws_status *vhd)
{
	struct per_session_data__lws_status *pss = vhd->live_pss_list;

	while (pss) {
		if (pss->walk == WALK_NONE) {
			pss->subsequent = 0;
			pss->walk_next = vhd->live_pss_list;
			pss->walk = WALK_INITIAL;
		} else
			pss->changed_partway = 1;

		pss = pss->next;
	}

	lws_callback_on_writable_all_protocol(vhd->context, vhd->protocol);
}

/* lws-status protocol */

int
callback_lws_status(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_status *pss =
			(struct per_session_data__lws_status *)user,
			*pss1, *pss2;
	struct per_vhost_data__lws_status *vhd =
			(struct per_vhost_data__lws_status *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	char buf[LWS_PRE + 384], ip[24], *start = buf + LWS_PRE - 1, *p = start,
	     *end = buf + sizeof(buf) - 1;
	int n, m;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_status));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		break;

	case LWS_CALLBACK_ESTABLISHED:

		/*
		 * This shows how to stage sending a single ws message in
		 * multiple fragments.  In this case, it lets us trade off
		 * memory needed to make the data vs time to send it.
		 */

		vhd->count_live_pss++;
		pss->next = vhd->live_pss_list;
		vhd->live_pss_list = pss;

		time(&pss->time_est);
		pss->wsi = wsi;
		strcpy(pss->user_agent, "unknown");
		lws_hdr_copy(wsi, pss->user_agent, sizeof(pss->user_agent),
			     WSI_TOKEN_HTTP_USER_AGENT);
		trigger_resend(vhd);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		switch (pss->walk) {
		case WALK_INITIAL:
			n = LWS_WRITE_TEXT | LWS_WRITE_NO_FIN;;
			p += lws_snprintf(p, end - p,
				      "{ \"version\":\"%s\","
				      " \"hostname\":\"%s\","
				      " \"wsi\":\"%d\", \"conns\":[",
				      lws_get_library_version(),
				      lws_canonical_hostname(vhd->context),
				      vhd->count_live_pss);
			pss->walk = WALK_LIST;
			pss->walk_next = vhd->live_pss_list;
			break;
		case WALK_LIST:
			n = LWS_WRITE_CONTINUATION | LWS_WRITE_NO_FIN;
			if (!pss->walk_next)
				goto walk_final;

			if (pss->subsequent)
				*p++ = ',';
			pss->subsequent = 1;

			m = 0;
			pss2 = vhd->live_pss_list;
			while (pss2) {
				if (pss2 == pss->walk_next) {
					m = 1;
					break;
				}
				pss2 = pss2->next;
			}
			if (!m) {
				/* our next guy went away */
				pss->walk = WALK_FINAL;
				pss->changed_partway = 1;
				break;
			}

			strcpy(ip, "unknown");
			lws_get_peer_simple(pss->walk_next->wsi, ip, sizeof(ip));
			p += lws_snprintf(p, end - p,
					"{\"peer\":\"%s\",\"time\":\"%ld\","
					"\"ua\":\"%s\"}",
					ip, (unsigned long)pss->walk_next->time_est,
					pss->walk_next->user_agent);
			pss->walk_next = pss->walk_next->next;
			if (!pss->walk_next)
				pss->walk = WALK_FINAL;
			break;
		case WALK_FINAL:
walk_final:
			n = LWS_WRITE_CONTINUATION;
			p += sprintf(p, "]}");
			if (pss->changed_partway) {
				pss->subsequent = 0;
				pss->walk_next = vhd->live_pss_list;
				pss->walk = WALK_INITIAL;
			} else
				pss->walk = WALK_NONE;
			break;
		default:
			return 0;
		}

		m = lws_write(wsi, (unsigned char *)start, p - start, n);
		if (m < 0) {
			lwsl_err("ERROR %d writing to di socket\n", m);
			return -1;
		}

		if (pss->walk != WALK_NONE)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		lwsl_notice("pmd test: RX len %d\n", (int)len);
		puts(in);
		break;

	case LWS_CALLBACK_CLOSED:
		pss1 = vhd->live_pss_list;
		pss2 = NULL;

		while (pss1) {
			if (pss1 == pss) {
				if (pss2)
					pss2->next = pss->next;
				else
					vhd->live_pss_list = pss->next;

				break;
			}

			pss2 = pss1;
			pss1 = pss1->next;
		}
		trigger_resend(vhd);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_STATUS \
	{ \
		"lws-status", \
		callback_lws_status, \
		sizeof(struct per_session_data__lws_status), \
		512, /* rx buf size must be >= permessage-deflate rx size */ \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_STATUS
};


LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_status(struct lws_context *context,
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
destroy_protocol_lws_status(struct lws_context *context)
{
	return 0;
}

#endif
