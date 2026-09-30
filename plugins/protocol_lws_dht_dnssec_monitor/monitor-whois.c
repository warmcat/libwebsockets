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
 * Registry whois for each domain
 *
 * The UI shows each domain's expiry, registry nameservers and whether the
 * registry has a DS for it, from domains/<domain>/whois.json.  Talking to
 * whois servers means parsing whatever they send, so it is done here in the
 * unprivileged proxy, not the root process.  The proxy walks the domains one
 * query at a time, refreshing any whois.json that is missing or stale, and
 * sends the results as canonical JSON to the root process over the UDS IPC
 * as an authenticated "update_whois" request.  The root process purifies it
 * again before writing whois.json, and refuses anything nonconformant.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "private.h"

/* refresh a domain's whois.json when it is older than this */
#define MON_WHOIS_REFRESH_S	(24 * 3600)
/* don't ask about the same domain again sooner than this, whatever happened */
#define MON_WHOIS_RETRY_S	3600
/* look for stale domains this often when there's nothing to do */
#define MON_WHOIS_SCAN_US	(10 * 60 * LWS_US_PER_SEC)
/* ...and this soon after a query completes, to get on with the rest */
#define MON_WHOIS_NEXT_US	(2 * LWS_US_PER_SEC)
/* first scan after the root process has been spawned */
#define MON_WHOIS_START_US	(20 * LWS_US_PER_SEC)

/*
 * One query in flight.  lws_whois_query() can't be cancelled, so this, not
 * the vhd, is its opaque: if the vhd goes first, it detaches, and the
 * completion only frees this
 */

struct mon_whois_q {
	struct vhd		*vhd;
	char			domain[128];
};

/* when we last asked about a domain */

struct mon_whois_tried {
	lws_dll2_t		list;
	time_t			at;
	char			domain[128];
};

struct mon_whois_scan {
	struct vhd		*vhd;
	time_t			now;
	char			found[128];
};

static struct mon_whois_tried *
mon_whois_tried_find(struct vhd *vhd, const char *domain)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->whois_tried)) {
		struct mon_whois_tried *t = lws_container_of(d,
						struct mon_whois_tried, list);

		if (!strcmp(t->domain, domain))
			return t;
	} lws_end_foreach_dll(d);

	return NULL;
}

static void
mon_whois_tried_set(struct vhd *vhd, const char *domain, time_t now)
{
	struct mon_whois_tried *t = mon_whois_tried_find(vhd, domain);

	if (!t) {
		t = malloc(sizeof(*t));
		if (!t)
			return;
		memset(t, 0, sizeof(*t));
		lws_strncpy(t->domain, domain, sizeof(t->domain));
		lws_dll2_add_tail(&t->list, &vhd->whois_tried);
	}

	t->at = now;
}

static int
mon_whois_scan_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct mon_whois_scan *s = (struct mon_whois_scan *)user;
	struct mon_whois_tried *t;
	char path[1024];
	struct stat st;

	if (lde->name[0] == '.' ||
	    (lde->type != LDOT_DIR && lde->type != LDOT_UNKNOWN) ||
	    strlen(lde->name) >= sizeof(s->found))
		return 0;

	t = mon_whois_tried_find(s->vhd, lde->name);
	if (t && s->now - t->at < MON_WHOIS_RETRY_S)
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s/whois.json", dirpath,
		     lde->name);
	if (!stat(path, &st) && s->now - st.st_mtime < MON_WHOIS_REFRESH_S)
		return 0;

	lws_strncpy(s->found, lde->name, sizeof(s->found));

	return 1; /* one at a time */
}

static void
mon_whois_send(struct vhd *vhd, const char *domain,
	       const struct lws_whois_results *res)
{
	char canon[LWS_WHOIS_CANON_MAX + 1], b64[((LWS_WHOIS_CANON_MAX + 2) / 3) * 4 + 1],
	     jwt[1024], temp[2048], claims[256], esc[MON_ESC_DOMAIN_SZ],
	     *req;
	unsigned long long now = (unsigned long long)lws_now_secs();
	size_t jwt_len = sizeof(jwt), rl;
	int n, problems;

	n = lws_whois_results_to_json(canon, sizeof(canon), res, &problems);
	if (n < 0)
		return;
	if (problems)
		lwsl_vhost_notice(vhd->vhost, "%s: whois had content we "
				  "could not use", domain);
	if (n <= 2) {
		/* "{}"... whatever it was, it told us nothing */
		lwsl_vhost_notice(vhd->vhost, "%s: nothing usable in whois", domain);
		return;
	}

	if (vhd->auth_jwk.kty != LWS_GENCRYPTO_KTY_OCT || !vhd->whois_ipc)
		return;

	lws_snprintf(claims, sizeof(claims), "{\"iss\":\"acme-ipc\","
		     "\"aud\":\"dnssec-monitor\",\"iat\":%llu,\"nbf\":%llu,"
		     "\"exp\":%llu}", now, now - 60, now + 60);
	if (lws_jwt_sign_compact(vhd->context, &vhd->auth_jwk, "HS256", jwt,
				 &jwt_len, temp, sizeof(temp), "%s", claims)) {
		lwsl_vhost_err(vhd->vhost, "unable to sign IPC token");
		return;
	}

	if (lws_b64_encode_string(canon, n, b64, (int)sizeof(b64)) < 0)
		return;

	json_escape(esc, sizeof(esc), domain);

	rl = strlen(jwt) + strlen(esc) + strlen(b64) + 64;
	req = malloc(rl);
	if (!req)
		return;

	n = lws_snprintf(req, rl, "{\"req\":\"update_whois\",\"jwt\":\"%s\","
			 "\"domain\":\"%s\",\"zone\":\"%s\"}\n", jwt, esc, b64);
	if (lws_async_ipc_queue_payload(vhd->whois_ipc, req, (size_t)n))
		lwsl_vhost_err(vhd->vhost, "unable to queue IPC");

	lws_explicit_bzero(req, rl);
	free(req);
	lws_explicit_bzero(jwt, sizeof(jwt));
}

static void
mon_whois_cb(void *opaque, const struct lws_whois_results *res)
{
	struct mon_whois_q *q = (struct mon_whois_q *)opaque;
	struct vhd *vhd = q->vhd;

	if (vhd) {
		vhd->whois_q = NULL;

		if (res) {
			lwsl_vhost_notice(vhd->vhost, "whois for %s done", q->domain);
			mon_whois_send(vhd, q->domain, res);
		} else
			lwsl_vhost_notice(vhd->vhost, "whois for %s failed", q->domain);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_whois,
				 monitor_whois_timer_cb, MON_WHOIS_NEXT_US);
	}

	free(q);
}

void
monitor_whois_timer_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_whois);
	struct lws_whois_args a;
	struct mon_whois_scan s;
	struct mon_whois_q *q;
	char scan_path[1024];

	if (vhd->whois_q)
		/* the completion reschedules us */
		return;

	memset(&s, 0, sizeof(s));
	s.vhd = vhd;
	s.now = (time_t)lws_now_secs();

	/* forget attempts old enough not to matter, eg, for deleted domains */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->whois_tried)) {
		struct mon_whois_tried *t = lws_container_of(d,
						struct mon_whois_tried, list);

		if (s.now - t->at >= MON_WHOIS_RETRY_S) {
			lws_dll2_remove(d);
			free(t);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->base_dir);
	lws_dir(scan_path, &s, mon_whois_scan_cb);

	if (!s.found[0]) {
		lws_sul_schedule(vhd->context, 0, &vhd->sul_whois,
				 monitor_whois_timer_cb, MON_WHOIS_SCAN_US);
		return;
	}

	/* whatever happens, it's an attempt */
	mon_whois_tried_set(vhd, s.found, s.now);

	q = malloc(sizeof(*q));
	if (!q)
		goto again;
	memset(q, 0, sizeof(*q));
	q->vhd = vhd;
	lws_strncpy(q->domain, s.found, sizeof(q->domain));

	memset(&a, 0, sizeof(a));
	a.context	= vhd->context;
	a.domain	= q->domain;
	a.server	= vhd->whois_server;
	a.port		= vhd->whois_port;
	a.cb		= mon_whois_cb;
	a.opaque	= q;

	lwsl_vhost_notice(vhd->vhost, "whois for %s", q->domain);

	if (lws_whois_query(&a)) {
		/* failing to start means no completion is coming */
		lwsl_vhost_err(vhd->vhost, "unable to start whois for %s", s.found);
		free(q);
		goto again;
	}
	vhd->whois_q = q;

	return;

again:
	lws_sul_schedule(vhd->context, 0, &vhd->sul_whois,
			 monitor_whois_timer_cb, MON_WHOIS_NEXT_US);
}

/*
 * The root process answers each request with one JSON line, but it also sends
 * every connected client lines that aren't answers to anything, like
 * "cert_status" results, so only the update_whois answers are ours
 */

static void
mon_whois_ipc_line(struct vhd *vhd, const char *line, size_t len)
{
	const char *v;
	size_t vl;

	v = lws_json_simple_find(line, len, "\"req\":", &vl);
	if (!v || vl != 12 || strncmp(v, "update_whois", 12))
		return;

	v = lws_json_simple_find(line, len, "\"status\":", &vl);
	if (v && vl == 2 && !strncmp(v, "ok", 2))
		return;

	vhd->whois_refusals++;
	lwsl_vhost_warn(vhd->vhost, "root refused whois update: %.*s",
			(int)(len > 200 ? 200 : len), line);
}

static int
mon_whois_ipc_cb(const struct lws_async_ipc_cb_args *args)
{
	struct vhd *vhd = (struct vhd *)args->opaque;
	const char *p = (const char *)args->data, *end = p + args->len;

	switch (args->state) {
	case LWS_ASYNC_IPC_STATE_RX:
		/* lines may be split across reads */
		for (; p < end; p++) {
			if (*p != '\n') {
				if (vhd->whois_ipc_rx_len < sizeof(vhd->whois_ipc_rx))
					vhd->whois_ipc_rx[vhd->whois_ipc_rx_len] = *p;
				/* an overlong line is not ours, drop it */
				if (vhd->whois_ipc_rx_len <= sizeof(vhd->whois_ipc_rx))
					vhd->whois_ipc_rx_len++;
				continue;
			}
			if (vhd->whois_ipc_rx_len <= sizeof(vhd->whois_ipc_rx))
				mon_whois_ipc_line(vhd, vhd->whois_ipc_rx,
						   vhd->whois_ipc_rx_len);
			vhd->whois_ipc_rx_len = 0;
		}
		break;
	case LWS_ASYNC_IPC_STATE_CONNECTED:
		vhd->whois_ipc_rx_len = 0;
		break;
	case LWS_ASYNC_IPC_STATE_TIMEOUT:
	case LWS_ASYNC_IPC_STATE_ERROR:
		lwsl_vhost_warn(vhd->vhost, "whois update IPC failed");
		break;
	default:
		break;
	}

	return 0;
}

int
monitor_whois_start(struct vhd *vhd)
{
	struct lws_async_ipc_info ii;

	memset(&ii, 0, sizeof(ii));
	ii.cx		= vhd->context;
	ii.uds_path	= vhd->uds_path;
	ii.cb		= mon_whois_ipc_cb;
	ii.opaque	= vhd;

	vhd->whois_ipc = lws_async_ipc_create(&ii);
	if (!vhd->whois_ipc)
		return 1;

	lws_sul_schedule(vhd->context, 0, &vhd->sul_whois,
			 monitor_whois_timer_cb, MON_WHOIS_START_US);

	return 0;
}

void
monitor_whois_stop(struct vhd *vhd)
{
	lws_sul_cancel(&vhd->sul_whois);

	/* an in-flight query completes on its own and only frees its q */
	if (vhd->whois_q) {
		vhd->whois_q->vhd = NULL;
		vhd->whois_q = NULL;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->whois_tried)) {
		lws_dll2_remove(d);
		free(lws_container_of(d, struct mon_whois_tried, list));
	} lws_end_foreach_dll_safe(d, d1);

	lws_async_ipc_destroy(&vhd->whois_ipc);
}
