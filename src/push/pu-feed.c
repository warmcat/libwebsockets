/*
 * Sai push - src/push/pu-feed.c
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
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
 * Following a watch's sai-web feed: the first request gets the feed as it
 * is, and each one after asks sai-web to hold it until the feed's index
 * moves on from the one we last saw.  Held responses have their headers at
 * once and a newline every 10s until the feed follows, so a quiet connection
 * is a dead one.
 */

#include <libwebsockets.h>
#include <string.h>

#include "pu-private.h"

static const uint32_t saip_backoff_ms[] = { 1000, 2000, 5000, 10000, 30000,
					    60000 };

static const lws_retry_bo_t saip_retry = {
	.retry_ms_table			= saip_backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(saip_backoff_ms),
	.conceal_count			= LWS_RETRY_CONCEAL_ALWAYS,
	.jitter_percent			= 20,
};

static void
saip_feed_connect(lws_sorted_usec_list_t *sul)
{
	saip_watch_t *w = lws_container_of(sul, saip_watch_t, sul);
	char path[768], uenc[3 * 96 + 1];
	struct lws_client_connect_info i;
	int n;

	lws_urlencode(uenc, w->fetchurl, (int)sizeof(uenc));
	n = lws_snprintf(path, sizeof(path), "%s?fetchurl=%s", w->path, uenc);
	if (w->index[0])
		lws_snprintf(path + n, sizeof(path) - (size_t)n,
			     "&wait=%d&index=%s", SAIP_WAIT_S, w->index);

	lwsac_free(&w->a.ac);
	w->parse_done = w->parse_failed = w->handled = 0;
	w->http_status = 0;

	memset(&i, 0, sizeof(i));
	i.context		= saip.cx;
	i.address		= w->host;
	i.port			= w->port;
	i.path			= path;
	i.host			= w->host;
	i.origin		= w->host;
	i.method		= "GET";
	/*
	 * A held response is one long-lived stream: keep it the only thing
	 * on its connection
	 */
	i.alpn			= "http/1.1";
	i.ssl_connection	= w->tls ? LCCSCF_USE_SSL : 0;
	i.protocol		= protocol_saip_feed.name;
	i.pwsi			= &w->wsi;
	i.opaque_user_data	= w;

	lwsl_info("%s: %s%s\n", __func__, w->host, path);

	if (!lws_client_connect_via_info(&i))
		/* the failure went to CLIENT_CONNECTION_ERROR */
		lwsl_notice("%s: connect to %s failed\n", __func__, w->host);
}

static void
saip_feed_schedule(saip_watch_t *w, int failed)
{
	uint32_t ms = 0;

	if (failed)
		ms = lws_retry_get_delay_ms(saip.cx, &saip_retry,
					    &w->retry_count, NULL);
	else
		w->retry_count = 0;

	lws_sul_schedule(saip.cx, 0, &w->sul, saip_feed_connect,
			 (lws_usec_t)ms * LWS_US_PER_MS);
}

void
saip_feed_start(saip_watch_t *w)
{
	saip_feed_schedule(w, 0);
}

/*
 * The response is over, one way or another: act on the feed if we got all
 * of it, and ask again
 */
static void
saip_feed_done(saip_watch_t *w)
{
	if (w->handled)
		return;
	w->handled = 1;

	if (w->http_status != HTTP_STATUS_OK || !w->parse_done ||
	    w->parse_failed || !w->a.dest) {
		if (!w->http_status)
			lwsl_notice("%s: %s%s: no response, retrying\n",
				    __func__, w->host, w->path);
		else if (w->http_status != HTTP_STATUS_OK)
			lwsl_notice("%s: %s%s: http %d, retrying\n", __func__,
				    w->host, w->path, w->http_status);
		else
			lwsl_notice("%s: %s%s: incomplete feed, retrying\n",
				    __func__, w->host, w->path);

		/*
		 * Start over with a plain fetch: whatever we missed, the feed
		 * as it is then covers it
		 */
		w->index[0] = '\0';
		lwsac_free(&w->a.ac);
		saip_feed_schedule(w, 1);

		return;
	}

	saip_feed_process(w, (sai_feed_t *)w->a.dest);
	lwsac_free(&w->a.ac);
	saip_feed_schedule(w, 0);
}

static int
callback_saip_feed(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	saip_watch_t *w = (saip_watch_t *)lws_get_opaque_user_data(wsi);
	char buf[LWS_PRE + 4096], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE, m;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: %s: %s\n", __func__, w ? w->host : "?",
			    in ? (const char *)in : "connection error");
		if (w) {
			w->wsi = NULL;
			saip_feed_done(w);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!w)
			return -1;

		w->http_status = (int)lws_http_client_http_response(wsi);

		memset(&w->a, 0, sizeof(w->a));
		w->a.map_st[0]		= lsm_schema_json_map_feed;
		w->a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_schema_json_map_feed);
		w->a.ac_block_size	= 4096;
		lws_struct_json_init_parse(&w->ctx, NULL, &w->a);

		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK,
				SAIP_RX_TIMEOUT_S);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!w)
			return -1;

		/* anything, even a keepalive, means it's still alive */
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK,
				SAIP_RX_TIMEOUT_S);

		if (w->http_status != HTTP_STATUS_OK || w->parse_done ||
		    w->parse_failed)
			break;

		m = lejp_parse(&w->ctx, (uint8_t *)in, (int)len);
		if (m >= 0)
			w->parse_done = 1;
		else if (m != LEJP_CONTINUE) {
			lwsl_notice("%s: feed JSON decode failed '%s'\n",
				    __func__, lejp_error_to_string(m));
			w->parse_failed = 1;
		}
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!w)
			break;

		saip_feed_done(w);

		/* we open a new connection for each request */
		return -1;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!w)
			break;

		w->wsi = NULL;

		/*
		 * A held response is close-delimited, so this may be how its
		 * end arrives... it was complete if the feed JSON was
		 */
		saip_feed_done(w);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_saip_feed = {
	.name			= "sai-push-feed",
	.callback		= callback_saip_feed,
};

/*
 * Project names go into a filesystem path and a remote url
 */
static int
saip_is_safe_project(const char *s)
{
	size_t n = 0;

	if (!s || !*s || *s == '.' || *s == '-')
		return 0;

	for (; s[n]; n++)
		if (!((s[n] >= '0' && s[n] <= '9') ||
		      (s[n] >= 'a' && s[n] <= 'z') ||
		      (s[n] >= 'A' && s[n] <= 'Z') ||
		      s[n] == '.' || s[n] == '_' || s[n] == '-'))
			return 0;

	return n <= 64;
}

/*
 * What the first rule matching the feed branch maps it to, or NULL if no
 * rule wants it
 */
static const saip_rule_t *
saip_rule_for(saip_watch_t *w, const char *branch, char *dst, size_t dst_len)
{
	size_t bl = strlen(branch), sl;

	lws_start_foreach_dll(struct lws_dll2 *, p, w->rules.head) {
		saip_rule_t *r = lws_container_of(p, saip_rule_t, list);

		sl = strlen(r->branch_suffix);
		if (bl > sl && !strcmp(branch + bl - sl, r->branch_suffix) &&
		    !lws_strcmp_wildcard(r->match, strlen(r->match),
					 branch, bl)) {
			if (bl - sl >= dst_len)
				return NULL;
			memcpy(dst, branch, bl - sl);
			dst[bl - sl] = '\0';

			return r;
		}
	} lws_end_foreach_dll(p);

	return NULL;
}

saip_target_t *
saip_target_get(saip_watch_t *w, const char *branch)
{
	saip_target_t *t;

	lws_start_foreach_dll(struct lws_dll2 *, p, w->targets.head) {
		t = lws_container_of(p, saip_target_t, list);
		if (!strcmp(t->branch, branch))
			return t;
	} lws_end_foreach_dll(p);

	t = malloc(sizeof(*t));
	if (!t)
		return NULL;
	memset(t, 0, sizeof(*t));
	lws_strncpy(t->branch, branch, sizeof(t->branch));
	lws_dll2_add_tail(&t->list, &w->targets);

	return t;
}

/*
 * We have the feed as it is now.  For each target branch, the newest event
 * that succeeded on a feed branch mapping to it is the one that should be on
 * it: that's the latest known-good commit, even if newer events are still
 * building or failed, and older successes are superseded by it.
 *
 * The git job then only pushes it if it's still on the feed branch, and not
 * already in the target branch, so an older success coming back to the top
 * (eg, a newer event's tasks were restarted) can't rewind the target.  And
 * whatever git can tell, an event whose notification arrived before the one
 * last promoted to the target is never promoted over it.
 */
void
saip_feed_process(saip_watch_t *w, sai_feed_t *f)
{
	lws_usec_t now = lws_now_usecs();
	char dst[65], seen[16][65];
	const saip_rule_t *r;
	saip_target_t *t;
	int ns = 0, n;

	lwsl_notice("%s: %s: index %s, %d events\n", __func__, w->fetchurl,
		    f->index, (int)f->items.count);

	lws_strncpy(w->index, f->index, sizeof(w->index));

	/* the feed items are newest first */

	lws_start_foreach_dll(struct lws_dll2 *, p, f->items.head) {
		sai_feed_item_t *it = lws_container_of(p, sai_feed_item_t,
						       list);

		/*
		 * sai-web scoped the feed to our fetchurl already, but it
		 * costs nothing to be sure.  Ad-hoc events are admin scratch
		 * builds, maybe with edited build scripts: never promoted.
		 */
		if (strcmp(it->fetchurl, w->fetchurl) || it->adhoc)
			continue;

		if (strcmp(it->state_name, "succeeded"))
			continue;

		r = saip_rule_for(w, it->branch, dst, sizeof(dst));
		if (!r)
			continue;

		/* only the newest success for each target counts */
		for (n = 0; n < ns; n++)
			if (!strcmp(seen[n], dst))
				break;
		if (n < ns)
			continue;
		if (ns == (int)LWS_ARRAY_SIZE(seen))
			break;
		lws_strncpy(seen[ns++], dst, sizeof(seen[0]));

		if (!saip_is_safe_project(it->project) ||
		    !sai_is_safe_ref(it->branch) || !sai_is_safe_ref(dst) ||
		    !sai_is_git_hash(it->hash) ||
		    (strlen(it->hash) != 40 && strlen(it->hash) != 64)) {
			lwsl_warn("%s: ignoring event %s with unexpected "
				  "project, branch or hash\n", __func__,
				  it->uuid);
			continue;
		}

		t = saip_target_get(w, dst);
		if (!t)
			continue;

		if (!strcmp(t->pushed, it->hash))
			continue;

		if (it->received < t->promoted_received) {
			/* say so once, not every time the feed changes */
			if (strcmp(t->tried, it->hash)) {
				lws_strncpy(t->tried, it->hash,
					    sizeof(t->tried));
				lwsl_user("%s: %s: not promoting %.12s (event "
					  "%s) to %s: it's older than event "
					  "%s, already promoted\n", __func__,
					  it->project, it->hash, it->uuid, dst,
					  t->promoted_uuid);
			}
			continue;
		}

		if (!strcmp(t->tried, it->hash) &&
		    now - t->tried_at < (lws_usec_t)SAIP_RETRY_S *
							LWS_US_PER_SEC)
			continue;

		lws_strncpy(t->tried, it->hash, sizeof(t->tried));
		t->tried_at = now;

		saip_job_queue(w, t, it, r->force);

	} lws_end_foreach_dll(p);
}
