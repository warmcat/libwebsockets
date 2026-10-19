/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * Watching a domain's zone propagate across the DHT
 *
 * The domain page shows which serial of the zone each node in our DHT
 * routing table holds.  The DHT runs in this unprivileged lwsws process, so
 * the proxy answers these requests itself, not the root process: while a
 * browser watches a domain, the proxy asks every node in rounds, with the
 * dht-dnssec plugin's query_serials(), and passes each answer on as it comes.
 * Rounds come every 2s for a minute after the watch starts, or after the zone
 * is signed again, so a new serial can be seen spreading, and every 15s
 * otherwise.
 *
 * The serial they should all reach is the signed zone's, which we tell the
 * browser too: signing gives the zone a later serial than the editor saved.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "private.h"

#define MON_SERIALS_FAST_US		(2 * LWS_US_PER_SEC)
#define MON_SERIALS_SLOW_US		(15 * LWS_US_PER_SEC)
#define MON_SERIALS_FAST_SPAN_US	(60 * LWS_US_PER_SEC)
/* however often a browser asks, a round starts at most this often */
#define MON_SERIALS_MIN_US		LWS_US_PER_SEC

static const char * const serials_state[] = {
	"held",		/* LWS_DHT_DNSSEC_SERIAL_HELD */
	"none",		/* LWS_DHT_DNSSEC_SERIAL_NONE */
	"no-answer",	/* LWS_DHT_DNSSEC_SERIAL_NO_ANSWER */
};

int
monitor_ui_push(struct pss *pss, const char *format, ...)
{
	size_t room = sizeof(pss->ui_tx) - LWS_PRE - pss->ui_tx_len;
	va_list ap;
	int n;

	va_start(ap, format);
	n = vsnprintf((char *)&pss->ui_tx[LWS_PRE + pss->ui_tx_len], room,
		      format, ap);
	va_end(ap);

	/* a truncated line is left beyond ui_tx_len, so never sent */
	if (n < 0 || (size_t)n >= room)
		return 1;

	pss->ui_tx_len += (size_t)n;
	lws_callback_on_writable(pss->wsi);

	return 0;
}

static void
serials_round_cb(lws_sorted_usec_list_t *sul);

static void
serials_schedule(struct pss *pss, lws_usec_t us)
{
	lws_sul_schedule(pss->vhd->context, 0, &pss->sul_serials,
			 serials_round_cb, us);
}

static void
serials_report_cb(void *opaque, const char *domain,
		  const struct lws_dht_dnssec_serial_report *r)
{
	struct pss *pss = (struct pss *)opaque;
	char ads[64], peer[80], id[LWS_GENHASH_LARGEST * 2 + 1];
	unsigned int port;

	if (!r) {
		/* the round is over, the next one comes on our timer */
		monitor_ui_push(pss, "{\"req\":\"dht_serials_done\","
				"\"domain\":\"%s\"}\n", domain);
		serials_schedule(pss, lws_now_usecs() < pss->serials_fast_until ?
				 MON_SERIALS_FAST_US : MON_SERIALS_SLOW_US);
		return;
	}

	if (r->state >= LWS_ARRAY_SIZE(serials_state))
		return;

	peer[0] = id[0] = '\0';
	if (r->sa) {
		lws_sa46_write_numeric_address((lws_sockaddr46 *)r->sa, ads,
					       sizeof(ads));
		port = ntohs(r->sa->sa_family == AF_INET ?
			((const struct sockaddr_in *)r->sa)->sin_port :
			((const struct sockaddr_in6 *)r->sa)->sin6_port);
		if (r->sa->sa_family == AF_INET6)
			lws_snprintf(peer, sizeof(peer), "[%s]:%u", ads, port);
		else
			lws_snprintf(peer, sizeof(peer), "%s:%u", ads, port);
		if (r->id)
			/* the browser shows one entry per node, whatever route */
			lws_hex_from_byte_array(r->id->id, r->id->len, id,
						sizeof(id));
	}

	/*
	 * If there's no room the browser misses this one until the next
	 * round, which asks again
	 */
	monitor_ui_push(pss, "{\"req\":\"dht_serial\",\"domain\":\"%s\","
			"\"peer\":\"%s\",\"id\":\"%s\",\"good\":%d,"
			"\"state\":\"%s\",\"serial\":%u}\n", domain, peer, id,
			r->good, serials_state[r->state], r->serial);
}

/*
 * Tell the browser the serial of the domain's signed zone, when it changes.
 * A file changed in the same second as we last read it might have the same
 * mtime and size, so one changed that recently is read again anyway.
 */

static void
serials_check_signed(struct pss *pss)
{
	struct vhd *vhd = pss->vhd;
	char path[1024];
	uint32_t serial;
	struct stat st;

	if (!vhd->ops || !vhd->ops->zone_file_serial)
		return;

	lws_snprintf(path, sizeof(path), "%s/domains/%s/%s.zone.signed",
		     vhd->base_dir, pss->serials_domain, pss->serials_domain);

	if (stat(path, &st) ||
	    (pss->serials_signed_known &&
	     st.st_mtime == pss->serials_signed_mtime &&
	     st.st_mtime < time(NULL) - 1))
		return;

	if (vhd->ops->zone_file_serial(path, &serial))
		return;

	pss->serials_signed_mtime = st.st_mtime;

	if (pss->serials_signed_known) {
		if (serial == pss->serials_signed)
			return;

		/* signed again: watch it spread */
		pss->serials_fast_until = lws_now_usecs() +
						MON_SERIALS_FAST_SPAN_US;
	}

	pss->serials_signed_known = 1;
	pss->serials_signed = serial;
	monitor_ui_push(pss, "{\"req\":\"dht_serials\",\"domain\":\"%s\","
			"\"signed\":%u}\n", pss->serials_domain, serial);
}

static void
serials_round_cb(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul_serials);
	struct lws_dht_dnssec_query_serials_args a;
	struct vhd *vhd = pss->vhd;

	if (!vhd || !pss->serials_domain[0])
		return;

	serials_check_signed(pss);

	if (!vhd->ops || !vhd->ops->query_serials) {
		monitor_ui_push(pss, "{\"req\":\"dht_serials\",\"domain\":"
				"\"%s\",\"status\":\"error\",\"msg\":"
				"\"No DHT to ask\"}\n", pss->serials_domain);
		pss->serials_domain[0] = '\0';
		return;
	}

	memset(&a, 0, sizeof(a));
	a.vhost		= vhd->vhost;
	a.domain	= pss->serials_domain;
	a.cb		= serials_report_cb;
	a.opaque	= pss;

	pss->serials_last = lws_now_usecs();

	if (!vhd->ops->query_serials(vhd->context, &a)) {
		pss->serials_refused = 0;
		return;
	}

	/*
	 * Refused, eg, too many browsers are watching, or there's no DHT on
	 * our vhost: say so once, and keep trying
	 */
	if (!pss->serials_refused) {
		pss->serials_refused = 1;
		monitor_ui_push(pss, "{\"req\":\"dht_serials\",\"domain\":"
				"\"%s\",\"status\":\"error\",\"msg\":"
				"\"The DHT can't be asked now\"}\n",
				pss->serials_domain);
	}
	serials_schedule(pss, MON_SERIALS_SLOW_US);
}

void
monitor_serials_stop(struct pss *pss)
{
	struct lws_dht_dnssec_query_serials_args a;
	struct vhd *vhd = pss->vhd;

	lws_sul_cancel(&pss->sul_serials);
	pss->serials_domain[0] = '\0';

	if (!vhd || !vhd->ops || !vhd->ops->query_serials)
		return;

	/* the query's opaque is pss: drop it before pss goes */
	memset(&a, 0, sizeof(a));
	a.vhost		= vhd->vhost;
	a.opaque	= pss;
	a.is_cancel	= 1;

	vhd->ops->query_serials(vhd->context, &a);
}

static void
serials_start(struct pss *pss, const char *domain)
{
	lws_usec_t now = lws_now_usecs(),
		   due = pss->serials_last + MON_SERIALS_MIN_US;

	if (!pss->vhd)
		return;

	if (strcmp(pss->serials_domain, domain)) {
		monitor_serials_stop(pss);
		lws_strncpy(pss->serials_domain, domain,
			    sizeof(pss->serials_domain));
	}

	/* the browser hears the signed zone's serial again, and any refusal */
	pss->serials_signed_known = 0;
	pss->serials_refused = 0;
	pss->serials_fast_until = now + MON_SERIALS_FAST_SPAN_US;

	/* this round replaces any still in progress */
	serials_schedule(pss, due > now ? due - now : 1);
}

static const char * const serials_paths[] = {
	"req",
	"domain",
};

struct serials_req {
	char req[32];
	char domain[128];
};

static signed char
serials_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct serials_req *r = (struct serials_req *)ctx->user;

	if (reason != LEJPCB_VAL_STR_END || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case 0:
		lws_strncpy(r->req, ctx->buf, sizeof(r->req));
		if (strcmp(r->req, "dht_serials") &&
		    strcmp(r->req, "dht_serials_stop"))
			return -1; /* not ours, stop looking */
		break;
	case 1:
		lws_strncpy(r->domain, ctx->buf, sizeof(r->domain));
		break;
	}

	return 0;
}

int
monitor_serials_ui_req(struct pss *pss, const void *in, size_t len)
{
	struct serials_req r;
	struct lejp_ctx ctx;
	size_t dl;
	int n;

	memset(&r, 0, sizeof(r));
	lejp_construct(&ctx, serials_req_cb, &r, serials_paths,
		       LWS_ARRAY_SIZE(serials_paths));
	n = lejp_parse(&ctx, (const uint8_t *)in, (int)len);
	lejp_destruct(&ctx);

	if (!strcmp(r.req, "dht_serials_stop")) {
		monitor_serials_stop(pss);
		return 0;
	}

	if (strcmp(r.req, "dht_serials"))
		return -1;

	/*
	 * It goes in a path, and as it is into what we send the browser: a
	 * valid DNS name can't climb out of the domains dir, or out of a JSON
	 * string
	 */
	dl = strlen(r.domain);
	if (n < 0 || !lws_dht_valid_domain_name(r.domain) ||
	    r.domain[dl - 1] == '.') {
		monitor_ui_push(pss, "{\"req\":\"dht_serials\",\"status\":"
				"\"error\",\"msg\":\"Invalid domain\"}\n");
		return 0;
	}

	serials_start(pss, r.domain);

	return 0;
}
