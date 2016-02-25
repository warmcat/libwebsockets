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
#include "test-server.h"
#include <time.h>

static unsigned char server_info[1024];
static int server_info_len;
static int current;
static char cache[16384];
static int cache_len;
static struct per_session_data__lws_status *list;
static int live_wsi;


static void
update_status(struct lws *wsi, struct per_session_data__lws_status *pss)
{
	struct per_session_data__lws_status **pp = &list;
	int subsequent = 0;
	char *p = cache + LWS_PRE, *start = p;
	char date[128];
	time_t t;
	struct tm *ptm;
#ifndef WIN32
	struct tm tm;
#endif

	p += snprintf(p, 512, " { %s, \"wsi\":\"%d\", \"conns\":[",
		     server_info, live_wsi);

	/* render the list */
	while (*pp) {
		t = (*pp)->tv_established.tv_sec;
#ifdef WIN32
		ptm = localtime(&t);
		if (!ptm)
#else
		ptm = &tm;
		if (!localtime_r(&t, &tm))
#endif
			strcpy(date, "unknown");
		else
			strftime(date, sizeof(date), "%F %H:%M %Z", ptm);
		if ((p - start) > (sizeof(cache) - 512))
			break;
		if (subsequent)
			*p++ = ',';
		subsequent = 1;
		p += snprintf(p, sizeof(cache) - (p - start) - 1,
				"{\"peer\":\"%s\",\"time\":\"%s\","
				"\"ua\":\"%s\"}",
			     (*pp)->ip, date, (*pp)->user_agent);
		pp = &((*pp)->list);
	}

	p += sprintf(p, "]}");
	cache_len = p - start;
	lwsl_err("cache_len %d\n", cache_len);
	*p = '\0';

	/* since we changed the list, increment the 'version' */
	current++;
	/* update everyone */
	lws_callback_on_writable_all_protocol(lws_get_context(wsi),
					      lws_get_protocol(wsi));
}


/* lws-status protocol */

int
callback_lws_status(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_status *pss =
			(struct per_session_data__lws_status *)user,
			**pp;
	char name[128], rip[128];
	int m;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		/*
		 * Prepare the static server info
		 */
		server_info_len = sprintf((char *)server_info,
					  "\"version\":\"%s\","
					  " \"hostname\":\"%s\"",
					  lws_get_library_version(),
					  lws_canonical_hostname(
							lws_get_context(wsi)));
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/*
		 * we keep a linked list of live pss, so we can walk it
		 */
		pss->last = 0;
		pss->list = list;
		list = pss;
		live_wsi++;
		lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name,
				       sizeof(name), rip, sizeof(rip));
		sprintf(pss->ip, "%s (%s)", name, rip);
		gettimeofday(&pss->tv_established, NULL);
		strcpy(pss->user_agent, "unknown");
		lws_hdr_copy(wsi, pss->user_agent, sizeof(pss->user_agent),
			     WSI_TOKEN_HTTP_USER_AGENT);
		update_status(wsi, pss);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		m = lws_write(wsi, (unsigned char *)cache + LWS_PRE, cache_len,
			      LWS_WRITE_TEXT);
		if (m < server_info_len) {
			lwsl_err("ERROR %d writing to di socket\n", m);
			return -1;
		}
		break;

	case LWS_CALLBACK_CLOSED:
		/*
		 * remove ourselves from live pss list
		 */
		lwsl_err("CLOSING pss %p ********\n", pss);

		pp = &list;
		while (*pp) {
			if (*pp == pss) {
				*pp = pss->list;
				pss->list = NULL;
				live_wsi--;
				break;
			}
			pp = &((*pp)->list);
		}

		update_status(wsi, pss);
		break;

	default:
		break;
	}

	return 0;
}
