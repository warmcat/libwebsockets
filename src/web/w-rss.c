/*
 * Sai web - RSS 2.0 feed of recent events
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
 * Public, unauthenticated RSS 2.0 feed of the most recent events, on
 * [/sai]/rss.xml, optionally scoped with ?project=<repo name> and / or
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
 */

#include <libwebsockets.h>
#include <string.h>
#include <time.h>

#include "w-private.h"

/* how many events the feed lists */
#define SAIW_RSS_ITEMS		10

/* feed readers are asked to wait at least this many minutes between polls */
#define SAIW_RSS_TTL_MINS	5

/* identifies our metadata elements, it needn't resolve to anything */
#define SAIW_RSS_NS		"https://warmcat.com/sai/ns/rss"

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
saiw_rss_append(struct pss *pss, const char *buf, int len)
{
	if (len >= 0 && lws_buflist_append_segment(&pss->rss_tx,
				(const uint8_t *)buf, (size_t)len) >= 0)
		return 0;

	lwsl_err("%s: OOM\n", __func__);

	return 1;
}

/*
 * Render one event as an <item> and append it to the feed
 */
static int
saiw_rss_item(struct vhd *vhd, struct pss *pss, sqlite3_stmt *sm)
{
	char item[12288], summary[96], esc_sum[SAIW_RSS_ESC(96)],
	     esc_uuid[SAIW_RSS_ESC(65)], esc_repo[SAIW_RSS_ESC(65)],
	     esc_branch[SAIW_RSS_ESC(65)], esc_hash[SAIW_RSS_ESC(65)],
	     esc_fetchurl[SAIW_RSS_ESC(96)], esc_weburl[SAIW_RSS_ESC(128)],
	     date[64];
	unsigned int good, bad, ongoing, pending, total;
	const char *uuid = saiw_rss_col(sm, 0), *ref = saiw_rss_col(sm, 2),
		   *state_name;
	time_t created = (time_t)sqlite3_column_int64(sm, 4);
	int state = sqlite3_column_int(sm, 5),
	    adhoc = sqlite3_column_int(sm, 6), n;
	sqlite3 *pdb = NULL;

	/* the task counts live in the event's own db */

	summary[0] = '\0';
	good = bad = ongoing = pending = total = 0;
	if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, uuid, 0, &pdb)) {
		saiw_event_summary_string(pdb, uuid, summary, sizeof(summary),
					  &good, &bad, &ongoing, &pending,
					  &total);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	}

	if (!strncmp(ref, "refs/heads/", 11))
		ref += 11;

	if (lws_http_date_render_from_unix(date, sizeof(date), &created))
		date[0] = '\0';

	state_name = saiw_rss_state_name(state);

	saiw_xml_esc(esc_uuid, sizeof(esc_uuid), uuid);
	saiw_xml_esc(esc_repo, sizeof(esc_repo), saiw_rss_col(sm, 1));
	saiw_xml_esc(esc_branch, sizeof(esc_branch), ref);
	saiw_xml_esc(esc_hash, sizeof(esc_hash), saiw_rss_col(sm, 3));
	saiw_xml_esc(esc_sum, sizeof(esc_sum), summary);
	saiw_xml_esc(esc_fetchurl, sizeof(esc_fetchurl), saiw_rss_col(sm, 7));
	saiw_xml_esc(esc_weburl, sizeof(esc_weburl), saiw_rss_col(sm, 8));

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
		esc_repo, esc_branch, adhoc ? " (ad-hoc)" : "", state_name,
		esc_sum[0] ? " - " : "", esc_sum,
		/* link */
		esc_uuid,
		/* guid */
		esc_uuid, state_name,
		/* pubDate */
		date,
		/* description */
		adhoc ? "Ad-hoc build of " : "", esc_repo, esc_branch, esc_hash,
		state_name, total, total == 1 ? "" : "s",
		good, bad, ongoing, pending,
		/* categories */
		esc_repo, esc_branch,
		/* sai: metadata */
		(unsigned long long)created, esc_repo, esc_branch, esc_hash,
		esc_fetchurl, esc_weburl, !!adhoc, state, state_name,
		total, good, bad, ongoing, pending);

	if (n >= (int)sizeof(item) - 1) {
		lwsl_err("%s: item for %s too large\n", __func__, uuid);

		return 1;
	}

	return saiw_rss_append(pss, item, n);
}

int
saiw_rss_http(struct vhd *vhd, struct pss *pss, struct lws *wsi)
{
	char buf[LWS_PRE + 8192], *start = buf + LWS_PRE,
	     *end = buf + sizeof(buf) - 1, project[65], branch[65],
	     uenc_project[SAIW_RSS_ESC(65)], uenc_branch[SAIW_RSS_ESC(65)],
	     esc_project[SAIW_RSS_ESC(65)], esc_branch[SAIW_RSS_ESC(65)],
	     self[512], esc_self[SAIW_RSS_ESC(512)], date[64];
	/*
	 * The query takes the project and branch from the request url, so it
	 * must bind them rather than go via lws_struct_sq3_deserialize(),
	 * whose filter text is spliced into the sql verbatim.
	 */
	static const char * const q =
		"SELECT uuid, repo_name, ref, hash, created, state, "
			"ifnull(adhoc,0), repo_fetchurl, weburl FROM events "
		"WHERE state != ?3 AND "
		      "(?1 IS NULL OR repo_name = ?1) AND "
		      "(?2 IS NULL OR ref = ?2 OR ref = 'refs/heads/' || ?2) "
		"ORDER BY created DESC LIMIT ?4";
	uint8_t *hs = (uint8_t *)start, *hp = hs,
		*he = (uint8_t *)end;
	sqlite3_stmt *sm = NULL;
	time_t now = time(NULL);
	int pl, bl, n, rc;

	lws_buflist_destroy_all_segments(&pss->rss_tx);

	pl = lws_get_urlarg_by_name_safe(wsi, "project=", project,
					 sizeof(project));
	bl = lws_get_urlarg_by_name_safe(wsi, "branch=", branch,
					 sizeof(branch));
	if (pl == -2 || bl == -2)
		/* longer than any project or ref we store */
		return HTTP_STATUS_BAD_REQUEST;
	if (pl < 0)
		pl = 0;
	if (bl < 0)
		bl = 0;
	project[pl] = '\0';
	branch[bl] = '\0';

	/* the feed's own (relative) url, including any scoping */

	lws_urlencode(uenc_project, project, (int)sizeof(uenc_project));
	lws_urlencode(uenc_branch, branch, (int)sizeof(uenc_branch));
	lws_snprintf(self, sizeof(self), "rss.xml%s%s%s%s%s%s",
		     pl || bl ? "?" : "",
		     pl ? "project=" : "", pl ? uenc_project : "",
		     pl && bl ? "&" : "",
		     bl ? "branch=" : "", bl ? uenc_branch : "");

	saiw_xml_esc(esc_self, sizeof(esc_self), self);
	saiw_xml_esc(esc_project, sizeof(esc_project), project);
	saiw_xml_esc(esc_branch, sizeof(esc_branch), branch);

	if (lws_http_date_render_from_unix(date, sizeof(date), &now))
		date[0] = '\0';

	n = lws_snprintf(start, lws_ptr_diff_size_t(end, start),
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
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
		"<ttl>%d</ttl>\n",
		pl ? ": " : "", esc_project, bl ? (pl ? " " : ": ") : "",
		esc_branch,
		SAIW_RSS_ITEMS,
		pl ? " for " : "", esc_project, bl ? " branch " : "",
		esc_branch,
		esc_self, date, SAIW_RSS_TTL_MINS);

	if (n >= lws_ptr_diff(end, start) - 1) {
		lwsl_err("%s: channel header too large\n", __func__);
		goto bail;
	}

	if (saiw_rss_append(pss, start, n))
		goto bail;

	if (sqlite3_prepare_v2(vhd->pdb, q, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: prepare failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		goto bail;
	}

	/* unbound parameters are NULL, meaning no scoping on that */
	if ((pl && sqlite3_bind_text(sm, 1, project, pl, SQLITE_STATIC)) ||
	    (bl && sqlite3_bind_text(sm, 2, branch, bl, SQLITE_STATIC)) ||
	    sqlite3_bind_int(sm, 3, SAIES_DELETED) ||
	    sqlite3_bind_int(sm, 4, SAIW_RSS_ITEMS)) {
		lwsl_err("%s: bind failed\n", __func__);
		goto bail;
	}

	while ((rc = sqlite3_step(sm)) == SQLITE_ROW)
		if (saiw_rss_item(vhd, pss, sm))
			goto bail;

	if (rc != SQLITE_DONE) {
		lwsl_err("%s: step failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		goto bail;
	}

	sqlite3_finalize(sm);
	sm = NULL;

	n = lws_snprintf(start, lws_ptr_diff_size_t(end, start),
			 "</channel>\n</rss>\n");
	if (saiw_rss_append(pss, start, n))
		goto bail;

	/*
	 * The whole feed is rendered, so we know the length.  The results
	 * change as builds progress, so caches may only hold it briefly.
	 */

	if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &hp, he) ||
	    lws_add_http_header_content_length(wsi,
			(lws_filepos_t)lws_buflist_total_len(&pss->rss_tx),
			&hp, he) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
			(const uint8_t *)"application/rss+xml; charset=utf-8",
			34, &hp, he) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
			(const uint8_t *)"public, max-age=60", 18, &hp, he) ||
	    lws_finalize_write_http_header(wsi, hs, &hp, he)) {
		lws_buflist_destroy_all_segments(&pss->rss_tx);

		return -1;
	}

	lws_callback_on_writable(wsi);

	return 0;

bail:
	if (sm)
		sqlite3_finalize(sm);
	lws_buflist_destroy_all_segments(&pss->rss_tx);

	return HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

int
saiw_rss_writeable(struct pss *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 4096], *seg;
	size_t n = lws_buflist_next_segment_len(&pss->rss_tx, &seg);
	int final;

	if (n > sizeof(buf) - LWS_PRE)
		n = sizeof(buf) - LWS_PRE;
	memcpy(buf + LWS_PRE, seg, n);
	lws_buflist_use_segment(&pss->rss_tx, n);
	final = !lws_buflist_total_len(&pss->rss_tx);

	if (lws_write(wsi, buf + LWS_PRE, n, final ? LWS_WRITE_HTTP_FINAL :
						     LWS_WRITE_HTTP) != (int)n)
		return -1;

	if (!final) {
		lws_callback_on_writable(wsi);

		return 0;
	}

	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

void
saiw_rss_close(struct pss *pss)
{
	/* NULL if the conn went before per-session storage was allocated */
	if (pss)
		lws_buflist_destroy_all_segments(&pss->rss_tx);
}
