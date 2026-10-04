/*
 * Sai web - RSS 2.0 (and JSON) feed of recent events
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
 * Public, unauthenticated feed of the most recent events, as RSS 2.0 on
 * [/sai]/rss.xml, or the same content as JSON on [/sai]/rss.json (for tools
 * like sai-push; the JSON is sai_feed_t via lws_struct).  Either can be
 * scoped with any of ?project=<repo name>, ?fetchurl=<repo fetch url> and
 * ?branch=<branch name or full ref>.
 *
 * One item per event, newest notification first.  The item reflects the
 * event's state at the time the feed is fetched, so it changes as the build
 * goes on or tasks are restarted.  The item guid carries the event state as
 * well as the event uuid, so a reader that has already seen an event
 * "building" presents it again as a fresh item when it goes on to "failed" or
 * "succeeded" (or back to "building" after a restart); readers mostly never
 * revisit an item whose guid they already have.
 *
 * Machine-readable metadata goes in elements in our own namespace (sai:),
 * which ordinary readers ignore; the title, description and categories carry
 * the same information for humans.
 *
 * Links in the feed are relative, so they resolve against the url the feed
 * was fetched from: whoever fetched it already knows where sai's web UI is
 * published, which sai-web behind the front-end proxy can't know for sure.
 *
 * Long poll
 * ---------
 *
 * The feed carries an "index" token, which changes when an event joins or
 * leaves the feed, or an event's state name changes (the same thing that
 * changes an item guid; task counts changing alone do not change it).  A
 * request with ?wait=<secs>&index=<token> is answered at once if the token is
 * already out of date, and otherwise held until it goes out of date or the
 * wait (capped at SAIW_RSS_MAX_WAIT_S) expires, when it is answered with the
 * then-current feed either way.  So a client fetches the feed once, then
 * loops asking to wait on the index from the last response, and only hears
 * back when there is something new.
 *
 * Front-end proxies give up on a request whose response headers don't arrive
 * promptly, and idle connections get reaped, so a held request is answered
 * with its headers straight away, with no content-length, and a newline every
 * SAIW_RSS_KEEPALIVE_S until the feed follows.  Whitespace is allowed before
 * the JSON value, and between the XML declaration (sent up front) and <rss>,
 * so the body is still a valid document.
 */

#include <libwebsockets.h>
#include <string.h>
#include <time.h>

#include "w-private.h"

/* how many events the feed lists */
#define SAIW_RSS_ITEMS		10

/* feed readers are asked to wait at least this many minutes between polls */
#define SAIW_RSS_TTL_MINS	5

/* longest a long poll request is held */
#define SAIW_RSS_MAX_WAIT_S	600

/* interval between keepalive newlines on a held request */
#define SAIW_RSS_KEEPALIVE_S	10

/*
 * Held requests at once: the feed is public, and each held request pins a
 * connection here and on the front-end proxy.  Past this, requests to wait
 * are told to retry later.
 */
#define SAIW_RSS_MAX_WAITERS	64

/* identifies our metadata elements, it needn't resolve to anything */
#define SAIW_RSS_NS		"https://warmcat.com/sai/ns/rss"

#define SAIW_RSS_XML_DECL	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"

/*
 * Escaped field sizes: each input byte becomes at most 6 ("&quot;")
 */
#define SAIW_RSS_ESC(n)		((n) * 6 + 1)

/*
 * The event state as the feed reports it.  The states that mean the same
 * thing to someone following the build share a name, since the name is also
 * what distinguishes one guid for the event from another.
 */
static const char *
saiw_rss_state_name(int state)
{
	switch (state) {
	case SAIES_WAITING:
		return "waiting";
	case SAIES_PASSED_TO_BUILDER:
	case SAIES_BEING_BUILT:
		return "building";
	case SAIES_BEING_BUILT_HAS_FAILURES:
		return "failing";
	case SAIES_SUCCESS:
		return "succeeded";
	case SAIES_FAIL:
		return "failed";
	case SAIES_CANCELLED:
		return "cancelled";
	case SAIES_NOT_READY_FOR_BUILD:
		return "not-ready";
	case SAIES_PAUSED:
		return "paused";
	}

	return "unknown";
}

/*
 * Escape src for XML character data or an attribute value, into dst.
 *
 * The feed has to be well-formed utf-8 XML or strict readers refuse all of
 * it, so beyond the five entities, byte sequences that are not valid utf-8
 * and the C0 controls XML 1.0 does not allow become '?'.  If dst is too
 * small, the output is truncated on a character boundary.  dst is always
 * NUL-terminated.
 */
static const char *
saiw_xml_esc(char *dst, size_t dlen, const char *src)
{
	const uint8_t *s = (const uint8_t *)src;
	char *d = dst, *end = dst + dlen - 1;
	const char *rep;
	size_t n, m;

	while (*s) {
		rep = NULL;
		n = 1;

		switch (*s) {
		case '&':
			rep = "&amp;";
			break;
		case '<':
			rep = "&lt;";
			break;
		case '>':
			rep = "&gt;";
			break;
		case '"':
			rep = "&quot;";
			break;
		case '\'':
			rep = "&apos;";
			break;
		default:
			if (*s < 0x20 && *s != '\t' && *s != '\n' &&
			    *s != '\r') {
				rep = "?";
				break;
			}
			if (*s < 0x80)
				break;

			if (*s >= 0xc2 && *s <= 0xdf)
				n = 2;
			else if (*s >= 0xe0 && *s <= 0xef)
				n = 3;
			else if (*s >= 0xf0 && *s <= 0xf4)
				n = 4;
			else
				n = 0;

			/* stops at the NUL, which is not a continuation */
			for (m = 1; m < n && (s[m] & 0xc0) == 0x80; m++)
				;

			/* also reject overlongs, surrogates and > U+10FFFF */
			if (!n || m != n ||
			    (*s == 0xe0 && s[1] < 0xa0) ||
			    (*s == 0xed && s[1] >= 0xa0) ||
			    (*s == 0xf0 && s[1] < 0x90) ||
			    (*s == 0xf4 && s[1] >= 0x90)) {
				rep = "?";
				n = 1;
			}
			break;
		}

		if (rep) {
			m = strlen(rep);
			if (m > lws_ptr_diff_size_t(end, d))
				break;
			memcpy(d, rep, m);
			d += m;
		} else {
			if (n > lws_ptr_diff_size_t(end, d))
				break;
			memcpy(d, s, n);
			d += n;
		}
		s += n;
	}

	*d = '\0';

	return dst;
}

static const char *
saiw_rss_col(sqlite3_stmt *sm, int col)
{
	const char *s = (const char *)sqlite3_column_text(sm, col);

	return s ? s : "";
}

static int
saiw_rss_append(struct pss *pss, const void *buf, size_t len)
{
	if (lws_buflist_append_segment(&pss->rss_tx, (const uint8_t *)buf,
				       len) >= 0)
		return 0;

	lwsl_err("%s: OOM\n", __func__);

	return 1;
}

/*
 * Collect the events in the feed for this request's scope into f, allocated
 * in *ac, and compute f->index from them.  This only reads the events table,
 * so it's cheap enough to redo for each held request whenever an event
 * changes; the task counts, which need each event's own db, are filled in
 * separately by saiw_feed_counts() only when the feed is actually sent.
 */
static int
saiw_feed_query(struct vhd *vhd, struct pss *pss, sai_feed_t *f,
		struct lwsac **ac)
{
	struct lws_genhash_ctx hc;
	sqlite3_stmt *sm = NULL;
	uint8_t digest[32];
	sai_feed_item_t *it;
	const char *ref;
	int rc, ret = 1;
	char q[512];

	memset(f, 0, sizeof(*f));

	/*
	 * The project and branch come from the request url, so they must be
	 * bound rather than go via lws_struct_sq3_deserialize(), whose filter
	 * text is spliced into the sql verbatim.  Only the fixed fragment
	 * limiting it to the projects this vhost shows is spliced in.
	 */
	lws_snprintf(q, sizeof(q),
		"SELECT uuid, repo_name, ref, hash, created, state, "
			"ifnull(adhoc,0), repo_fetchurl, weburl FROM events "
		"WHERE state != ?3%s AND "
		      "(?1 IS NULL OR repo_name = ?1) AND "
		      "(?2 IS NULL OR ref = ?2 OR ref = 'refs/heads/' || ?2) AND "
		      "(?5 IS NULL OR repo_fetchurl = ?5) "
		"ORDER BY created DESC LIMIT ?4", saiw_visible_sql(vhd));

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_SHA256))
		return 1;

	if (sqlite3_prepare_v2(vhd->pdb, q, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: prepare failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		goto bail;
	}

	/* unbound parameters are NULL, meaning no scoping on that */
	if ((pss->rss_project[0] && sqlite3_bind_text(sm, 1, pss->rss_project,
					-1, SQLITE_STATIC)) ||
	    (pss->rss_branch[0] && sqlite3_bind_text(sm, 2, pss->rss_branch,
					-1, SQLITE_STATIC)) ||
	    (pss->rss_fetchurl[0] && sqlite3_bind_text(sm, 5,
					pss->rss_fetchurl, -1, SQLITE_STATIC)) ||
	    sqlite3_bind_int(sm, 3, SAIES_DELETED) ||
	    sqlite3_bind_int(sm, 4, SAIW_RSS_ITEMS)) {
		lwsl_err("%s: bind failed\n", __func__);
		goto bail;
	}

	while ((rc = sqlite3_step(sm)) == SQLITE_ROW) {
		it = lwsac_use_zero(ac, sizeof(*it), 2048);
		if (!it)
			goto bail;

		lws_strncpy(it->uuid, saiw_rss_col(sm, 0), sizeof(it->uuid));
		lws_strncpy(it->project, saiw_rss_col(sm, 1),
			    sizeof(it->project));
		lws_strncpy(it->ref, saiw_rss_col(sm, 2), sizeof(it->ref));
		ref = it->ref;
		if (!strncmp(ref, "refs/heads/", 11))
			ref += 11;
		lws_strncpy(it->branch, ref, sizeof(it->branch));
		lws_strncpy(it->hash, saiw_rss_col(sm, 3), sizeof(it->hash));
		it->received = (uint64_t)sqlite3_column_int64(sm, 4);
		it->state = sqlite3_column_int(sm, 5);
		it->adhoc = !!sqlite3_column_int(sm, 6);
		lws_strncpy(it->fetchurl, saiw_rss_col(sm, 7),
			    sizeof(it->fetchurl));
		lws_strncpy(it->weburl, saiw_rss_col(sm, 8),
			    sizeof(it->weburl));
		lws_strncpy(it->state_name, saiw_rss_state_name(it->state),
			    sizeof(it->state_name));

		lws_dll2_add_tail(&it->list, &f->items);

		if (lws_genhash_update(&hc, it->uuid, strlen(it->uuid)) ||
		    lws_genhash_update(&hc, ":", 1) ||
		    lws_genhash_update(&hc, it->state_name,
				       strlen(it->state_name)) ||
		    lws_genhash_update(&hc, "\n", 1))
			goto bail;
	}

	if (rc != SQLITE_DONE) {
		lwsl_err("%s: step failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		goto bail;
	}

	ret = 0;

bail:
	if (sm)
		sqlite3_finalize(sm);
	lws_genhash_destroy(&hc, ret ? NULL : digest);
	if (!ret)
		/* 16 bytes of it is plenty to notice a change */
		lws_hex_from_byte_array(digest, 16, f->index, sizeof(f->index));

	return ret;
}

/* the task counts live in each event's own db */

static void
saiw_feed_counts(struct vhd *vhd, sai_feed_t *f)
{
	sqlite3 *pdb;

	lws_start_foreach_dll(struct lws_dll2 *, p, f->items.head) {
		sai_feed_item_t *it = lws_container_of(p, sai_feed_item_t,
						       list);

		pdb = NULL;
		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					      vhd->sqlite3_path_lhs, it->uuid,
					      0, &pdb)) {
			saiw_event_summary_string(pdb, it->uuid, it->summary,
						  sizeof(it->summary),
						  &it->tasks_ok, &it->tasks_bad,
						  &it->tasks_building,
						  &it->tasks_wait,
						  &it->tasks_total);
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}
	} lws_end_foreach_dll(p);
}

/*
 * Render one event as an <item> and append it to the feed
 */
static int
saiw_rss_item(struct pss *pss, const sai_feed_item_t *it)
{
	char item[12288], esc_sum[SAIW_RSS_ESC(96)],
	     esc_uuid[SAIW_RSS_ESC(65)], esc_repo[SAIW_RSS_ESC(65)],
	     esc_branch[SAIW_RSS_ESC(65)], esc_hash[SAIW_RSS_ESC(65)],
	     esc_fetchurl[SAIW_RSS_ESC(96)], esc_weburl[SAIW_RSS_ESC(128)],
	     date[64];
	time_t created = (time_t)it->received;
	int n;

	if (lws_http_date_render_from_unix(date, sizeof(date), &created))
		date[0] = '\0';

	saiw_xml_esc(esc_uuid, sizeof(esc_uuid), it->uuid);
	saiw_xml_esc(esc_repo, sizeof(esc_repo), it->project);
	saiw_xml_esc(esc_branch, sizeof(esc_branch), it->branch);
	saiw_xml_esc(esc_hash, sizeof(esc_hash), it->hash);
	saiw_xml_esc(esc_sum, sizeof(esc_sum), it->summary);
	saiw_xml_esc(esc_fetchurl, sizeof(esc_fetchurl), it->fetchurl);
	saiw_xml_esc(esc_weburl, sizeof(esc_weburl), it->weburl);

	n = lws_snprintf(item, sizeof(item),
		"<item>\n"
		" <title>%s %s%s: %s%s%s</title>\n"
		" <link>index.html?event=%s</link>\n"
		" <guid isPermaLink=\"false\">%s-%s</guid>\n"
		" <pubDate>%s</pubDate>\n"
		" <description>%s%s branch %s at %.12s: %s, %u task%s "
			"(%u OK, %u bad, %u building, %u waiting)</description>\n"
		" <category>%s</category>\n"
		" <category>%s</category>\n"
		" <sai:received>%llu</sai:received>\n"
		" <sai:project>%s</sai:project>\n"
		" <sai:branch>%s</sai:branch>\n"
		" <sai:hash>%s</sai:hash>\n"
		" <sai:fetchurl>%s</sai:fetchurl>\n"
		" <sai:weburl>%s</sai:weburl>\n"
		" <sai:adhoc>%d</sai:adhoc>\n"
		" <sai:state code=\"%d\">%s</sai:state>\n"
		" <sai:tasks total=\"%u\" ok=\"%u\" bad=\"%u\" "
			"building=\"%u\" wait=\"%u\"/>\n"
		"</item>\n",

		/* title */
		esc_repo, esc_branch, it->adhoc ? " (ad-hoc)" : "",
		it->state_name, esc_sum[0] ? " - " : "", esc_sum,
		/* link */
		esc_uuid,
		/* guid */
		esc_uuid, it->state_name,
		/* pubDate */
		date,
		/* description */
		it->adhoc ? "Ad-hoc build of " : "", esc_repo, esc_branch,
		esc_hash, it->state_name, it->tasks_total,
		it->tasks_total == 1 ? "" : "s",
		it->tasks_ok, it->tasks_bad, it->tasks_building,
		it->tasks_wait,
		/* categories */
		esc_repo, esc_branch,
		/* sai: metadata */
		(unsigned long long)it->received, esc_repo, esc_branch,
		esc_hash, esc_fetchurl, esc_weburl, it->adhoc, it->state,
		it->state_name, it->tasks_total, it->tasks_ok, it->tasks_bad,
		it->tasks_building, it->tasks_wait);

	if (n >= (int)sizeof(item) - 1) {
		lwsl_err("%s: item for %s too large\n", __func__, it->uuid);

		return 1;
	}

	return saiw_rss_append(pss, item, (size_t)n);
}

/*
 * Append the feed as RSS to pss->rss_tx.  The XML declaration is left out if
 * it was already sent at the start of a held request.
 */
static int
saiw_feed_render_xml(struct pss *pss, const sai_feed_t *f, int decl)
{
	char buf[12288], uenc[SAIW_RSS_ESC(96)], esc_project[SAIW_RSS_ESC(65)],
	     esc_branch[SAIW_RSS_ESC(65)], self[1024], *sp = self,
	     *se = self + sizeof(self), esc_self[SAIW_RSS_ESC(1024)], date[64];
	int pl = !!pss->rss_project[0], bl = !!pss->rss_branch[0], n,
	    first = 1;
	const char *scope[][2] = {
		{ "project",  pss->rss_project },
		{ "fetchurl", pss->rss_fetchurl },
		{ "branch",   pss->rss_branch },
	};
	time_t now = time(NULL);
	size_t m;

	/* the feed's own (relative) url, including any scoping */

	sp += lws_snprintf(sp, lws_ptr_diff_size_t(se, sp), "rss.xml");
	for (m = 0; m < LWS_ARRAY_SIZE(scope); m++) {
		if (!scope[m][1][0])
			continue;
		lws_urlencode(uenc, scope[m][1], (int)sizeof(uenc));
		sp += lws_snprintf(sp, lws_ptr_diff_size_t(se, sp), "%c%s=%s",
				   first ? '?' : '&', scope[m][0], uenc);
		first = 0;
	}

	saiw_xml_esc(esc_self, sizeof(esc_self), self);
	saiw_xml_esc(esc_project, sizeof(esc_project), pss->rss_project);
	saiw_xml_esc(esc_branch, sizeof(esc_branch), pss->rss_branch);

	if (lws_http_date_render_from_unix(date, sizeof(date), &now))
		date[0] = '\0';

	n = lws_snprintf(buf, sizeof(buf),
		"%s"
		"<rss version=\"2.0\" "
			"xmlns:atom=\"http://www.w3.org/2005/Atom\" "
			"xmlns:sai=\"" SAIW_RSS_NS "\">\n"
		"<channel>\n"
		"<title>Sai build events%s%s%s%s</title>\n"
		"<link>index.html</link>\n"
		"<description>The latest %d Sai CI build events%s%s%s%s, "
			"newest first, with their current results"
			"</description>\n"
		"<atom:link href=\"%s\" rel=\"self\" "
			"type=\"application/rss+xml\"/>\n"
		"<generator>Sai</generator>\n"
		"<lastBuildDate>%s</lastBuildDate>\n"
		"<ttl>%d</ttl>\n"
		"<sai:index>%s</sai:index>\n",
		decl ? SAIW_RSS_XML_DECL : "",
		pl ? ": " : "", esc_project, bl ? (pl ? " " : ": ") : "",
		esc_branch,
		SAIW_RSS_ITEMS,
		pl ? " for " : "", esc_project, bl ? " branch " : "",
		esc_branch,
		esc_self, date, SAIW_RSS_TTL_MINS, f->index);

	if (n >= (int)sizeof(buf) - 1) {
		lwsl_err("%s: channel header too large\n", __func__);

		return 1;
	}

	if (saiw_rss_append(pss, buf, (size_t)n))
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, p, f->items.head) {
		if (saiw_rss_item(pss, lws_container_of(p, sai_feed_item_t,
							list)))
			return 1;
	} lws_end_foreach_dll(p);

	return saiw_rss_append(pss, "</channel>\n</rss>\n", 18);
}

static int
saiw_feed_render_json(struct pss *pss, sai_feed_t *f)
{
	lws_struct_serialize_t *js;
	lws_struct_json_serialize_result_t r;
	uint8_t buf[4096];
	size_t w;

	js = lws_struct_json_serialize_create(lsm_schema_json_map_feed,
			LWS_ARRAY_SIZE(lsm_schema_json_map_feed), 0, f);
	if (!js)
		return 1;

	do {
		w = 0;
		r = lws_struct_json_serialize(js, buf, sizeof(buf), &w);
		if (r == LSJS_RESULT_ERROR ||
		    (w && saiw_rss_append(pss, buf, w))) {
			lws_struct_json_serialize_destroy(&js);

			return 1;
		}
	} while (r == LSJS_RESULT_CONTINUE);

	lws_struct_json_serialize_destroy(&js);

	return saiw_rss_append(pss, "\n", 1);
}

/*
 * Fill in the counts and append the whole feed body for this request
 */
static int
saiw_feed_render(struct vhd *vhd, struct pss *pss, sai_feed_t *f, int decl)
{
	saiw_feed_counts(vhd, f);

	if (pss->rss_json)
		return saiw_feed_render_json(pss, f);

	return saiw_feed_render_xml(pss, f, decl);
}

static void
saiw_rss_unpark(struct pss *pss)
{
	lws_dll2_remove(&pss->rss_list);
	lws_sul_cancel(&pss->sul_rss);
}

/*
 * A held request is being answered: send the current feed to finish it
 */
static void
saiw_rss_finish(struct vhd *vhd, struct pss *pss)
{
	struct lwsac *ac = NULL;
	sai_feed_t f;

	saiw_rss_unpark(pss);

	/*
	 * The status and headers went out long ago, so a failure now can only
	 * be reported by dropping the connection, which the client handles
	 * like any other broken connection
	 */
	pss->rss_state = SAIW_RSS_FAILED;
	if (!saiw_feed_query(vhd, pss, &f, &ac) &&
	    !saiw_feed_render(vhd, pss, &f, 0))
		pss->rss_state = SAIW_RSS_FINISHING;

	lwsac_free(&ac);
	lws_callback_on_writable(pss->wsi);
}

static void
saiw_rss_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct pss *pss = lws_container_of(sul, struct pss, sul_rss);
	lws_usec_t now = lws_now_usecs(), next;

	if (now >= pss->rss_deadline) {
		/* waited as long as asked, answer with the current feed */
		saiw_rss_finish(pss->vhd, pss);

		return;
	}

	pss->rss_ka = 1;
	lws_callback_on_writable(pss->wsi);

	next = SAIW_RSS_KEEPALIVE_S * LWS_US_PER_SEC;
	if (pss->rss_deadline - now < next)
		next = pss->rss_deadline - now;

	lws_sul_schedule(pss->vhd->context, 0, &pss->sul_rss, saiw_rss_sul_cb,
			 next);
}

/*
 * Some event joined, left or changed state: answer any held requests whose
 * feed index is now out of date
 */
void
saiw_rss_event_change(struct vhd *vhd)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->rss_waiters.head) {
		struct pss *pss = lws_container_of(p, struct pss, rss_list);
		struct lwsac *ac = NULL;
		sai_feed_t f;

		if (!saiw_feed_query(vhd, pss, &f, &ac) &&
		    strcmp(f.index, pss->rss_index))
			saiw_rss_finish(vhd, pss);

		lwsac_free(&ac);
	} lws_end_foreach_dll_safe(p, p1);
}

/*
 * Copy a url arg into buf, "" if absent.  Returns nonzero if it was present
 * but too long for buf.
 */
static int
saiw_rss_urlarg(struct lws *wsi, const char *name, char *buf, size_t len)
{
	int n = lws_get_urlarg_by_name_safe(wsi, name, buf, (int)len);

	if (n < 0)
		buf[0] = '\0';

	return n == -2;
}

/*
 * Returns < 0 to close the connection, 0 if the response is under way, 1 if
 * the response was completed here, or else an http status for the caller to
 * respond with
 */
int
saiw_rss_http(struct vhd *vhd, struct pss *pss, struct lws *wsi, int json)
{
	char buf[LWS_PRE + 1024], index[33], wait_s[12];
	uint8_t *start = (uint8_t *)buf + LWS_PRE, *p = start,
		*end = (uint8_t *)buf + sizeof(buf) - 1;
	const char *ctype = json ? "application/json" :
				   "application/rss+xml; charset=utf-8";
	struct lwsac *ac = NULL;
	sai_feed_t f;
	int wait;

	saiw_rss_close(pss);
	pss->wsi = wsi;
	pss->rss_json = (uint8_t)!!json;

	if (saiw_rss_urlarg(wsi, "project=", pss->rss_project,
			    sizeof(pss->rss_project)) ||
	    saiw_rss_urlarg(wsi, "branch=", pss->rss_branch,
			    sizeof(pss->rss_branch)) ||
	    saiw_rss_urlarg(wsi, "fetchurl=", pss->rss_fetchurl,
			    sizeof(pss->rss_fetchurl)))
		/* longer than any project or ref we store */
		return HTTP_STATUS_BAD_REQUEST;

	if (saiw_rss_urlarg(wsi, "index=", index, sizeof(index)))
		/* can't be a token of ours, so it's out of date */
		index[0] = '\0';

	wait = 0;
	if (!saiw_rss_urlarg(wsi, "wait=", wait_s, sizeof(wait_s)))
		wait = atoi(wait_s);
	if (wait < 0)
		wait = 0;
	if (wait > SAIW_RSS_MAX_WAIT_S)
		wait = SAIW_RSS_MAX_WAIT_S;

	if (saiw_feed_query(vhd, pss, &f, &ac))
		goto bail;

	if (wait && index[0] && !strcmp(index, f.index)) {

		/* nothing new for them yet: hold the request */

		lwsac_free(&ac);

		if (vhd->rss_waiters.count >= SAIW_RSS_MAX_WAITERS) {
			lwsl_notice("%s: %u waiting, deferring another\n",
				    __func__,
				    (unsigned int)vhd->rss_waiters.count);

			if (lws_add_http_header_status(wsi,
					HTTP_STATUS_SERVICE_UNAVAILABLE,
					&p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_RETRY_AFTER,
					(const uint8_t *)"60", 2, &p, end) ||
			    lws_add_http_header_content_length(wsi, 0, &p, end) ||
			    lws_finalize_write_http_header(wsi, start, &p, end))
				return -1;

			return 1;
		}

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, ctype,
						LWS_ILLEGAL_HTTP_CONTENT_LEN,
						&p, end) ||
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CACHE_CONTROL,
				(const uint8_t *)"no-store", 8, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		/*
		 * We are a long-lived response now: this lifts the http
		 * timeouts (and for h2, the network connection's idle one)
		 */
		lws_http_mark_sse(wsi);

		if (!json && saiw_rss_append(pss, SAIW_RSS_XML_DECL,
					     strlen(SAIW_RSS_XML_DECL)))
			return -1;

		lws_strncpy(pss->rss_index, index, sizeof(pss->rss_index));
		pss->rss_state = SAIW_RSS_PARKED;
		pss->rss_deadline = lws_now_usecs() +
				    (lws_usec_t)wait * LWS_US_PER_SEC;
		lws_dll2_add_tail(&pss->rss_list, &vhd->rss_waiters);
		lws_sul_schedule(vhd->context, 0, &pss->sul_rss,
				 saiw_rss_sul_cb,
				 (wait < SAIW_RSS_KEEPALIVE_S ? wait :
					SAIW_RSS_KEEPALIVE_S) * LWS_US_PER_SEC);

		lws_callback_on_writable(wsi);

		return 0;
	}

	/* answer straight away */

	if (saiw_feed_render(vhd, pss, &f, 1))
		goto bail;

	lwsac_free(&ac);

	/*
	 * The whole feed is rendered, so we know the length.  The results
	 * change as builds progress, so caches may only hold it briefly.
	 */

	if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
	    lws_add_http_header_content_length(wsi,
			(lws_filepos_t)lws_buflist_total_len(&pss->rss_tx),
			&p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
			(const uint8_t *)ctype, (int)strlen(ctype), &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
			(const uint8_t *)"public, max-age=60", 18, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end)) {
		saiw_rss_close(pss);

		return -1;
	}

	pss->rss_state = SAIW_RSS_FINISHING;
	lws_callback_on_writable(wsi);

	return 0;

bail:
	lwsac_free(&ac);
	saiw_rss_close(pss);

	return HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

int
saiw_rss_writeable(struct pss *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 4096], *seg;
	size_t n;
	int final;

	if (pss->rss_state == SAIW_RSS_FAILED)
		return -1;

	n = lws_buflist_next_segment_len(&pss->rss_tx, &seg);
	if (!n) {
		/* a held request with nothing to send but a keepalive */
		if (pss->rss_state != SAIW_RSS_PARKED || !pss->rss_ka)
			return 0;

		pss->rss_ka = 0;
		buf[LWS_PRE] = '\n';

		return lws_write(wsi, buf + LWS_PRE, 1, LWS_WRITE_HTTP) != 1 ?
									-1 : 0;
	}

	if (n > sizeof(buf) - LWS_PRE)
		n = sizeof(buf) - LWS_PRE;
	memcpy(buf + LWS_PRE, seg, n);
	lws_buflist_use_segment(&pss->rss_tx, n);
	final = pss->rss_state == SAIW_RSS_FINISHING &&
		!lws_buflist_total_len(&pss->rss_tx);

	if (lws_write(wsi, buf + LWS_PRE, n, final ? LWS_WRITE_HTTP_FINAL :
						     LWS_WRITE_HTTP) != (int)n)
		return -1;

	if (!final) {
		if (lws_buflist_total_len(&pss->rss_tx))
			lws_callback_on_writable(wsi);

		return 0;
	}

	pss->rss_state = SAIW_RSS_IDLE;

	/* a held request's response was close-delimited on h1 */
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

void
saiw_rss_close(struct pss *pss)
{
	/* NULL if the conn went before per-session storage was allocated */
	if (!pss)
		return;

	saiw_rss_unpark(pss);
	lws_buflist_destroy_all_segments(&pss->rss_tx);
	pss->rss_state = SAIW_RSS_IDLE;
	pss->rss_ka = 0;
}
