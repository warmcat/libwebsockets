/*
 * lws-log-ingest - keeps the log lines of many log shippers in one place
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The http api, see READMEs/README.log-ship.md.  Answers are JSON, built whole
 * before they're sent, since each is bounded.
 *
 * Who may ask is decided in front of us, by lws-login on the mount, which
 * stamps the result in the x-lws-login-* headers.  We answer a user of our
 * grant, or a global admin.  The stamped service says which grant the state
 * is about, so if the mount in front of us is missing or wrong, we refuse
 * rather than let in users of another.
 */

#include "private.h"

#include <time.h>

#define LI_LIMIT_DEF		2000
#define LI_LIMIT_MAX		10000
/* the most JSON one answer may come to, past it we say it's truncated */
#define LI_BODY_MAX		(8 * 1024 * 1024)
#define LI_SRC_PATTERNS_MAX	8
#define LI_DURATION_DEF		600
#define LI_SESSIONS_LIST	50
#define LI_PANE_LINES_DEF	150
#define LI_PANE_LINES_MAX	500
#define LI_PANES_MAX		64
/* a pane's window is padded by this much either side of its session */
#define LI_PAD_US		(30ll * 1000000ll)

typedef struct {
	int		is_text;
	int64_t		i;
	const char	*t;
} li_bind_t;

typedef struct {
	li_bind_t	b[48];
	char		sql[2048];
	char		*p;
	int		count;
} li_q_t;

/* the JSON we are building, on its way to pss->tx */

typedef struct {
	struct lws_buflist	**bl;
	char			buf[4096];
	size_t			len;
	size_t			total;
	int			oom;
} li_out_t;

static void
out_flush(li_out_t *o)
{
	if (o->len && lws_buflist_append_segment(o->bl, (uint8_t *)o->buf,
						 o->len) < 0)
		o->oom = 1;
	o->total += o->len;
	o->len = 0;
}

static void
out_printf(li_out_t *o, const char *fmt, ...) LWS_FORMAT(2);

static void
out_printf(li_out_t *o, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (sizeof(o->buf) - o->len < 512)
		out_flush(o);

	va_start(ap, fmt);
	n = vsnprintf(o->buf + o->len, sizeof(o->buf) - o->len, fmt, ap);
	va_end(ap);

	if (n > 0)
		o->len += (size_t)n < sizeof(o->buf) - o->len ?
				(size_t)n : sizeof(o->buf) - o->len - 1;
}

/* a quoted JSON string, or null */

static void
out_str(li_out_t *o, const char *s)
{
	int used;

	if (!s) {
		out_printf(o, "null");
		return;
	}

	out_printf(o, "\"");
	while (*s) {
		if (sizeof(o->buf) - o->len < 64)
			out_flush(o);

		used = 0;
		lws_json_purify(o->buf + o->len, s,
				(int)(sizeof(o->buf) - o->len - 2), &used);
		o->len += strlen(o->buf + o->len);
		if (!used)
			break;
		s += used;
	}
	out_printf(o, "\"");
}

static void
out_time(li_out_t *o, uint64_t us)
{
	time_t t = (time_t)(us / 1000000ull);
	struct tm tm, *ptm;

#if defined(WIN32)
	ptm = gmtime_s(&tm, &t) ? NULL : &tm;
#else
	ptm = gmtime_r(&t, &tm);
#endif
	if (!ptm) {
		out_printf(o, "null");
		return;
	}

	out_printf(o, "\"%04d-%02d-%02dT%02d:%02d:%02d.%06uZ\"",
		   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		   tm.tm_min, tm.tm_sec, (unsigned int)(us % 1000000ull));
}

static void
q_add(li_q_t *q, const char *frag)
{
	size_t room = sizeof(q->sql) - lws_ptr_diff_size_t(q->p, q->sql);

	q->p += lws_snprintf(q->p, room, "%s", frag);
}

static void
q_bind_int(li_q_t *q, int64_t i)
{
	if (q->count == (int)LWS_ARRAY_SIZE(q->b))
		return;
	q->b[q->count].is_text = 0;
	q->b[q->count++].i = i;
}

static void
q_bind_text(li_q_t *q, const char *t)
{
	if (q->count == (int)LWS_ARRAY_SIZE(q->b))
		return;
	q->b[q->count].is_text = 1;
	q->b[q->count++].t = t;
}

static int
q_prepare(sqlite3 *pdb, li_q_t *q, sqlite3_stmt **sm)
{
	int n;

	if (sqlite3_prepare_v2(pdb, q->sql, -1, sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s\n", __func__, q->sql, sqlite3_errmsg(pdb));
		return 1;
	}

	for (n = 0; n < q->count; n++)
		if (q->b[n].is_text)
			sqlite3_bind_text(*sm, n + 1, q->b[n].t, -1,
					  SQLITE_TRANSIENT);
		else
			sqlite3_bind_int64(*sm, n + 1, q->b[n].i);

	return 0;
}

static int
parse_u64(const char *s, uint64_t *v)
{
	const char *p = s;

	for (*v = 0; *p >= '0' && *p <= '9' && p - s < 19; p++)
		*v = (*v * 10) + (uint64_t)(*p - '0');

	return p == s || *p;
}

static int
parse_digits(const char **p, int n, int *v)
{
	*v = 0;
	while (n--) {
		if (**p < '0' || **p > '9')
			return 1;
		*v = (*v * 10) + (*(*p)++ - '0');
	}

	return 0;
}

/* days since 1970-01-01 of a proleptic gregorian date, without timegm() */

static int64_t
days_from_civil(int y, int m, int d)
{
	int64_t era, yoe, doy, doe;

	y -= m <= 2;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = y - era * 400;
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

	return era * 146097 + doe - 719468;
}

/*
 * A time: epoch ms if it's all digits, "-<n>" for n seconds before now, or UTC
 * ISO 8601, "2026-10-14T08:01:02Z", with optional fractional seconds
 */

static int
parse_time(const char *s, uint64_t now, uint64_t *us)
{
	int y, mo, d, h, mi, sec, frac = 0, fd = 0;
	const char *p = s;
	uint64_t u;

	if (!*s)
		return 1;

	if (*s == '-') {
		if (parse_u64(s + 1, &u) || u > 86400ull * 365)
			return 1;
		*us = now - (u * 1000000ull);
		return 0;
	}

	for (p = s; *p >= '0' && *p <= '9'; p++)
		;
	if (!*p) {
		if (p - s > 15 || parse_u64(s, &u))
			return 1;
		*us = u * 1000ull;
		return 0;
	}

	p = s;
	if (parse_digits(&p, 4, &y) || *p++ != '-' ||
	    parse_digits(&p, 2, &mo) || *p++ != '-' ||
	    parse_digits(&p, 2, &d) || *p++ != 'T' ||
	    parse_digits(&p, 2, &h) || *p++ != ':' ||
	    parse_digits(&p, 2, &mi) || *p++ != ':' ||
	    parse_digits(&p, 2, &sec))
		return 1;

	if (*p == '.') {
		p++;
		while (*p >= '0' && *p <= '9') {
			if (fd < 6) {
				frac = (frac * 10) + (*p - '0');
				fd++;
			}
			p++;
		}
		while (fd++ < 6)
			frac *= 10;
	}

	if (*p == 'Z')
		p++;
	if (*p || y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
	    h > 23 || mi > 59 || sec > 60)
		return 1;

	*us = (uint64_t)((days_from_civil(y, mo, d) * 86400ll) +
			 (h * 3600ll) + (mi * 60ll) + sec) * 1000000ull +
	      (uint64_t)(unsigned int)frac;

	return 0;
}

/*
 * A level name means that level and everything more important; notice and
 * below include user lines, which are as important as notice
 */

static int
parse_lvl(const char *s)
{
	static const char * const lvls[] = {
		"err", "warn", "notice", "info", "debug"
	};
	int n, mask = 0;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(lvls); n++) {
		mask |= 1 << n;
		if (!strcmp(s, lvls[n]))
			return n >= 2 ? mask | LLL_USER : mask;
	}

	return -1;
}

/* a comma-separated list of patterns of [A-Za-z0-9._-*], up to 3 * each */

int
li_valid_src(const char *s)
{
	int stars = 0, n = 0;

	if (strlen(s) > LI_SRC_MAX)
		return 0;

	for (; *s; s++) {
		if (*s == ',') {
			if (!n)
				return 0;
			n = stars = 0;
			continue;
		}
		if (*s == '*' && ++stars > 3)
			return 0;
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		      (*s >= '0' && *s <= '9') || *s == '-' || *s == '_' ||
		      *s == '.' || *s == '*'))
			return 0;
		n++;
	}

	return 1;
}

static int
valid_session_id(const char *s)
{
	int n;

	for (n = 0; n < LI_SESSION_LEN; n++)
		if (!((s[n] >= '0' && s[n] <= '9') ||
		      (s[n] >= 'a' && s[n] <= 'f')))
			return 0;

	return !s[n];
}

/* a header lws-login stamped, in-process, or from a trusted front end */

static int
li_login_hdr(struct vhd *vhd, struct lws *wsi, const char *name, char *buf,
	     size_t len)
{
	int n = lws_http_get_onward_header(wsi, name, buf, len);
#if defined(LWS_WITH_CUSTOM_HEADERS)
	char hn[48];
#endif

	if (n >= 0 || !vhd->trust_login_headers)
		return n;

#if defined(LWS_WITH_CUSTOM_HEADERS)
	n = lws_snprintf(hn, sizeof(hn), "%s:", name);
	return lws_hdr_custom_copy(wsi, buf, (int)len, hn, n);
#else
	return -1;
#endif
}

static int
li_allowed(struct vhd *vhd, struct lws *wsi, char *sub, size_t sl)
{
	char state[8], service[64];
	int n, st;

	n = li_login_hdr(vhd, wsi, LWS_LOGIN_HDR_STATE, state, sizeof(state));
	if (n != 1 || state[0] < '0' || state[0] > '9') {
		lwsl_wsi_notice(wsi, "log query refused: no trustworthy %s",
				LWS_LOGIN_HDR_STATE);
		return 0;
	}
	st = state[0] - '0';

	if (li_login_hdr(vhd, wsi, LWS_LOGIN_HDR_SUB, sub, sl) <= 0)
		lws_strncpy(sub, "?", sl);

	if (st == LWS_LOGIN_STATE_GLOBAL_ADMIN)
		return 1;

	if (st < LWS_LOGIN_STATE_USER) {
		lwsl_wsi_notice(wsi, "log query by '%s' refused: state %d, not "
				"a user of the grant", sub, st);
		return 0;
	}

	if (li_login_hdr(vhd, wsi, LWS_LOGIN_HDR_SERVICE, service,
			 sizeof(service)) <= 0 || strcmp(service, vhd->service)) {
		lwsl_wsi_notice(wsi, "log query by '%s' refused: state %d is "
				"not for grant '%s'", sub, st, vhd->service);
		return 0;
	}

	return 1;
}

static int
li_answer(struct pss *pss, struct lws *wsi, li_out_t *o, unsigned int status)
{
	/* the vhost's own headers, eg, a long CSP, go in here too */
	uint8_t hb[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = hb + LWS_PRE, *p = start, *end = hb + sizeof(hb) - 1;

	out_flush(o);
	if (o->oom) {
		lws_buflist_destroy_all_segments(&pss->tx);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if (lws_add_http_header_status(wsi, status, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(uint8_t *)"application/json", 16, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
				(uint8_t *)"no-store", 8, &p, end) ||
	    lws_add_http_header_content_length(wsi, o->total, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end)) {
		lwsl_wsi_warn(wsi, "api answer's headers don't fit");
		lws_buflist_destroy_all_segments(&pss->tx);
		return -1;
	}

	pss->sending = 1;
	lws_callback_on_writable(wsi);

	return 0;
}

/* a refusal, saying why */

static int
li_error(struct pss *pss, struct lws *wsi, li_out_t *o, unsigned int status,
	 const char *why)
{
	lws_buflist_destroy_all_segments(&pss->tx);
	o->len = o->total = 0;
	out_printf(o, "{\"error\":");
	out_str(o, why);
	out_printf(o, "}");

	return li_answer(pss, wsi, o, status);
}

static void
out_session(li_out_t *o, sqlite3_stmt *sm, uint64_t now)
{
	uint64_t until = (uint64_t)sqlite3_column_int64(sm, 3);

	out_printf(o, "{\"session\":");
	out_str(o, (const char *)sqlite3_column_text(sm, 0));
	out_printf(o, ",\"created\":");
	out_time(o, (uint64_t)sqlite3_column_int64(sm, 1));
	out_printf(o, ",\"from\":");
	out_time(o, (uint64_t)sqlite3_column_int64(sm, 2));
	out_printf(o, ",\"until\":");
	out_time(o, until);
	out_printf(o, ",\"from_us\":%llu,\"until_us\":%llu,\"open\":%s,"
		   "\"lvl\":%d,\"src\":",
		   (unsigned long long)sqlite3_column_int64(sm, 2),
		   (unsigned long long)until,
		   sqlite3_column_type(sm, 4) == SQLITE_NULL && until > now ?
							"true" : "false",
		   sqlite3_column_int(sm, 5));
	out_str(o, (const char *)sqlite3_column_text(sm, 6));
	out_printf(o, ",\"who\":");
	out_str(o, (const char *)sqlite3_column_text(sm, 7));
	out_printf(o, ",\"note\":");
	out_str(o, (const char *)sqlite3_column_text(sm, 8));
	out_printf(o, "}");
}

#define LI_SESSION_COLS "id, created_us, from_us, until_us, stopped_us, lvl, " \
			"src, who, note"

/* a session's window and sources, for a query that names it */

typedef struct {
	uint64_t	from_us;
	uint64_t	until_us;
	char		src[LI_SRC_MAX + 1];
} li_sess_t;

static int
li_session_get(struct vhd *vhd, const char *id, li_sess_t *s)
{
	sqlite3_stmt *sm;
	int r = 1;

	if (!valid_session_id(id))
		return 1;

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT from_us, until_us, src FROM "
			"sessions WHERE id = ?", -1, &sm, NULL) != SQLITE_OK)
		return 1;

	sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *src = (const char *)sqlite3_column_text(sm, 2);

		s->from_us = (uint64_t)sqlite3_column_int64(sm, 0);
		s->until_us = (uint64_t)sqlite3_column_int64(sm, 1);
		lws_strncpy(s->src, src ? src : "", sizeof(s->src));
		r = 0;
	}
	sqlite3_finalize(sm);

	return r;
}

/* GET /sessions, and GET /sessions/<id> */

static int
li_sessions_list(struct vhd *vhd, struct pss *pss, struct lws *wsi,
		 li_out_t *o, const char *id)
{
	uint64_t now = lws_log_ship_utc_us();
	sqlite3_stmt *sm;
	int n = 0;

	if (id && !valid_session_id(id))
		return li_error(pss, wsi, o, HTTP_STATUS_NOT_FOUND,
				"no such session");

	if (sqlite3_prepare_v2(vhd->pdb, id ?
			"SELECT " LI_SESSION_COLS " FROM sessions WHERE id = ?" :
			"SELECT " LI_SESSION_COLS " FROM sessions ORDER BY "
			"created_us DESC LIMIT ?", -1, &sm, NULL) != SQLITE_OK)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;

	if (id)
		sqlite3_bind_text(sm, 1, id, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_int(sm, 1, LI_SESSIONS_LIST);

	if (!id)
		out_printf(o, "{\"sessions\":[");
	while (sqlite3_step(sm) == SQLITE_ROW) {
		if (n++)
			out_printf(o, ",");
		out_session(o, sm, now);
	}
	sqlite3_finalize(sm);

	if (id && !n)
		return li_error(pss, wsi, o, HTTP_STATUS_NOT_FOUND,
				"no such session");
	if (!id)
		out_printf(o, "]}");

	return li_answer(pss, wsi, o, HTTP_STATUS_OK);
}

/* GET /tags/<tag>: when lines with the tag, or under it, were seen */

static int
li_tag_window(struct vhd *vhd, struct pss *pss, struct lws *wsi, li_out_t *o,
	      const char *tag)
{
	char sub[LI_TAG_MAX + 3];
	sqlite3_stmt *sm;
	int r = 1;

	if (!li_valid_tag(tag))
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"bad tag");

	lws_snprintf(sub, sizeof(sub), "%s/*", tag);
	if (sqlite3_prepare_v2(vhd->pdb, "SELECT min(first_us), max(last_us), "
			"count(*) FROM tags WHERE tag = ? OR tag GLOB ?", -1,
			&sm, NULL) != SQLITE_OK)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;

	sqlite3_bind_text(sm, 1, tag, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 2, sub, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(sm) == SQLITE_ROW && sqlite3_column_int(sm, 2)) {
		out_printf(o, "{\"tag\":");
		out_str(o, tag);
		out_printf(o, ",\"first\":");
		out_time(o, (uint64_t)sqlite3_column_int64(sm, 0));
		out_printf(o, ",\"last\":");
		out_time(o, (uint64_t)sqlite3_column_int64(sm, 1));
		out_printf(o, ",\"first_us\":%lld,\"last_us\":%lld}",
			   (long long)sqlite3_column_int64(sm, 0),
			   (long long)sqlite3_column_int64(sm, 1));
		r = 0;
	}
	sqlite3_finalize(sm);

	if (r)
		return li_error(pss, wsi, o, HTTP_STATUS_NOT_FOUND,
				"no lines with that tag");

	return li_answer(pss, wsi, o, HTTP_STATUS_OK);
}

/*
 * GET /sources: the shippers connected now, and the sources seen lately.  Our
 * own process' lines are a source too, always there, listed first as "local".
 */

static int
li_sources(struct vhd *vhd, struct pss *pss, struct lws *wsi, li_out_t *o)
{
	uint64_t now = lws_log_ship_utc_us();
	sqlite3_stmt *sm;
	int n = 0;

	out_printf(o, "{\"connected\":[");
	if (vhd->own) {
		const char *inst = lws_log_ship_inst(vhd->own);
		long long id = -1;

		/* its id, if it has stored lines yet */
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->srcs.head) {
			li_src_t *s = lws_container_of(d, li_src_t, list);

			if (!strcmp(s->inst, inst))
				id = (long long)s->src_id;
		} lws_end_foreach_dll(d);

		if (id < 0)
			out_printf(o, "{\"id\":null");
		else
			out_printf(o, "{\"id\":%lld", id);
		out_printf(o, ",\"kind\":\"%s\",\"host\":\"%s\",\"inst\":\"%s\","
			   "\"local\":true,\"window_until\":", vhd->own_kind,
			   vhd->own_host, inst);
		if (vhd->own_window.until_us > now)
			out_time(o, vhd->own_window.until_us);
		else
			out_printf(o, "null");
		out_printf(o, "}");
		n++;
	}
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->shippers.head) {
		struct pss *sp = lws_container_of(d, struct pss, list);

		out_printf(o, "%s{\"id\":%lld,\"kind\":\"%s\",\"host\":\"%s\","
			   "\"inst\":\"%s\",\"window_until\":", n++ ? "," : "",
			   (long long)sp->src->src_id, sp->src->kind,
			   sp->src->host, sp->src->inst);
		if (sp->sent.until_us > now)
			out_time(o, sp->sent.until_us);
		else
			out_printf(o, "null");
		out_printf(o, "}");
	} lws_end_foreach_dll(d);

	out_printf(o, "],\"sources\":[");
	n = 0;
	if (sqlite3_prepare_v2(vhd->pdb, "SELECT src_id, kind, host, inst, "
			"first_us, last_us, lag_us FROM sources WHERE last_us "
			">= ? ORDER BY kind, host, src_id", -1, &sm, NULL) ==
								SQLITE_OK) {
		sqlite3_bind_int64(sm, 1, (sqlite3_int64)(now -
					86400ull * 1000000ull));
		while (sqlite3_step(sm) == SQLITE_ROW) {
			out_printf(o, "%s{\"id\":%lld,\"kind\":", n++ ? "," : "",
				   (long long)sqlite3_column_int64(sm, 0));
			out_str(o, (const char *)sqlite3_column_text(sm, 1));
			out_printf(o, ",\"host\":");
			out_str(o, (const char *)sqlite3_column_text(sm, 2));
			out_printf(o, ",\"inst\":");
			out_str(o, (const char *)sqlite3_column_text(sm, 3));
			out_printf(o, ",\"first\":");
			out_time(o, (uint64_t)sqlite3_column_int64(sm, 4));
			out_printf(o, ",\"last\":");
			out_time(o, (uint64_t)sqlite3_column_int64(sm, 5));
			out_printf(o, ",\"lag_ms\":%lld}",
				   (long long)(sqlite3_column_int64(sm, 6) / 1000));
		}
		sqlite3_finalize(sm);
	}
	out_printf(o, "]}");

	return li_answer(pss, wsi, o, HTTP_STATUS_OK);
}

/*
 * POST /sessions, a JSON body:
 *
 * {"from": "<when>", "duration": <secs>, "lvl": "<level>", "src": "<patterns>",
 *  "note": "<anything>"}
 *
 * all optional: from defaults to now, duration to 10 minutes, lvl to nothing
 * more than is logged already, src to everything
 */

typedef struct {
	char		from[40];
	char		lvl[12];
	char		src[LI_SRC_MAX + 1];
	char		note[LI_NOTE_MAX + 1];
	uint64_t	duration;
	size_t		slen;
	char		bad;
} li_start_t;

static const char * const li_start_paths[] = {
	"from", "duration", "lvl", "src", "note",
};

enum { LIS_FROM, LIS_DURATION, LIS_LVL, LIS_SRC, LIS_NOTE };

static signed char
li_start_cb(struct lejp_ctx *ctx, char reason)
{
	li_start_t *a = (li_start_t *)ctx->user;
	char *dest = NULL;
	size_t max = 0;

	if (!ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case LIS_FROM:
		dest = a->from;
		max = sizeof(a->from) - 1;
		break;
	case LIS_LVL:
		dest = a->lvl;
		max = sizeof(a->lvl) - 1;
		break;
	case LIS_SRC:
		dest = a->src;
		max = sizeof(a->src) - 1;
		break;
	case LIS_NOTE:
		dest = a->note;
		max = sizeof(a->note) - 1;
		break;
	case LIS_DURATION:
		if (reason == LEJPCB_VAL_NUM_INT &&
		    parse_u64(ctx->buf, &a->duration))
			a->bad = 1;
		else if (reason & LEJP_FLAG_CB_IS_VALUE &&
			 reason != LEJPCB_VAL_NUM_INT)
			a->bad = 1;
		return 0;
	}

	/* "from" may also be a number, epoch ms */
	if (ctx->path_match - 1 == LIS_FROM && reason == LEJPCB_VAL_NUM_INT) {
		lws_strncpy(a->from, ctx->buf, sizeof(a->from));
		return 0;
	}

	if (reason == LEJPCB_VAL_STR_START) {
		a->slen = 0;
		dest[0] = '\0';
		return 0;
	}

	if (reason != LEJPCB_VAL_STR_CHUNK && reason != LEJPCB_VAL_STR_END) {
		if (reason & LEJP_FLAG_CB_IS_VALUE)
			a->bad = 1;
		return 0;
	}

	if (a->slen + ctx->npos > max) {
		a->bad = 1;
		return 0;
	}
	memcpy(dest + a->slen, ctx->buf, ctx->npos);
	a->slen += ctx->npos;
	dest[a->slen] = '\0';

	return 0;
}

static int
li_note_ok(const char *s)
{
	for (; *s; s++)
		if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e)
			return 0;

	return 1;
}

static int
li_session_start(struct vhd *vhd, struct pss *pss, struct lws *wsi,
		 li_out_t *o, const char *who)
{
	uint64_t now = lws_log_ship_utc_us();
	struct lejp_ctx ctx;
	li_session_t *s;
	li_start_t a;
	uint8_t r[8];
	int m, lvl = 0;

	memset(&a, 0, sizeof(a));
	a.duration = LI_DURATION_DEF;

	lejp_construct(&ctx, li_start_cb, &a, li_start_paths,
		       LWS_ARRAY_SIZE(li_start_paths));
	m = lejp_parse(&ctx, (uint8_t *)pss->body, (int)pss->body_len);
	lejp_destruct(&ctx);
	if (m < 0 || a.bad)
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"body must be a JSON object of from, duration, "
				"lvl, src and note");

	s = malloc(sizeof(*s));
	if (!s)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	memset(s, 0, sizeof(*s));

	s->from_us = now;
	if (a.from[0] && parse_time(a.from, now, &s->from_us)) {
		free(s);
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"from must be UTC ISO 8601, epoch ms, or "
				"-<secs> before now");
	}
	if (s->from_us > now ||
	    now - s->from_us > (uint64_t)vhd->max_past_secs * 1000000ull) {
		free(s);
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"from must be now or in the recent past");
	}

	if (!a.duration || a.duration > vhd->max_session_secs) {
		free(s);
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"duration out of range");
	}
	s->until_us = now + (a.duration * 1000000ull);

	if (a.lvl[0]) {
		lvl = parse_lvl(a.lvl);
		if (lvl < 0) {
			free(s);
			return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
					"lvl must be err, warn, notice, info or "
					"debug");
		}
	}
	s->lvl = lvl;

	if (!li_valid_src(a.src) || !li_note_ok(a.note)) {
		free(s);
		return li_error(pss, wsi, o, HTTP_STATUS_BAD_REQUEST,
				"bad src or note");
	}
	lws_strncpy(s->src, a.src, sizeof(s->src));

	if (lws_get_random(vhd->cx, r, sizeof(r)) != sizeof(r)) {
		free(s);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	lws_hex_from_byte_array(r, sizeof(r), s->id, sizeof(s->id));

	if (li_store_session_add(vhd, s, who, a.note, now)) {
		free(s);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	lws_dll2_add_tail(&s->list, &vhd->sessions);
	lwsl_vhost_notice(vhd->vh, "session %s started by '%s': from -%llus, "
			  "%llus, lvl 0x%x, src '%s'", s->id, who,
			  (unsigned long long)((now - s->from_us) / 1000000ull),
			  (unsigned long long)a.duration, (unsigned int)lvl,
			  s->src);

	li_windows_update(vhd);

	return li_sessions_list(vhd, pss, wsi, o, s->id);
}

static int
li_session_stop(struct vhd *vhd, struct pss *pss, struct lws *wsi,
		li_out_t *o, const char *id, const char *who)
{
	uint64_t now = lws_log_ship_utc_us();

	if (!valid_session_id(id) || li_store_session_stop(vhd, id, now))
		return li_error(pss, wsi, o, HTTP_STATUS_NOT_FOUND,
				"no such open session");

	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->sessions.head) {
		li_session_t *s = lws_container_of(d, li_session_t, list);

		if (!strcmp(s->id, id)) {
			s->until_us = now;
			break;
		}
	} lws_end_foreach_dll(d);

	lwsl_vhost_notice(vhd->vh, "session %s stopped by '%s'", id, who);
	li_windows_update(vhd);

	return li_sessions_list(vhd, pss, wsi, o, id);
}

/* src= of a query: kinds or hosts, with * */

static int
li_src_arg(struct lws *wsi, char srcs[][LI_HOST_MAX + 1], int *nsrc,
	   const char *def)
{
	char a_src[LI_SRC_MAX + 1];
	const char *s, *e;

	if (lws_get_urlarg_by_name_safe(wsi, "src=", a_src,
					sizeof(a_src)) > 0)
		s = a_src;
	else
		s = def;

	if (!li_valid_src(s))
		return 1;

	while (*s) {
		e = strchr(s, ',');
		if (!e)
			e = s + strlen(s);
		if ((size_t)(e - s) > LI_HOST_MAX ||
		    *nsrc == LI_SRC_PATTERNS_MAX)
			return 1;
		memcpy(srcs[*nsrc], s, (size_t)(e - s));
		srcs[(*nsrc)++][e - s] = '\0';
		s = *e ? e + 1 : e;
	}

	return 0;
}

static void
q_src(li_q_t *q, char srcs[][LI_HOST_MAX + 1], int nsrc)
{
	int n;

	if (!nsrc)
		return;

	q_add(q, " AND (");
	for (n = 0; n < nsrc; n++) {
		q_add(q, n ? " OR s.kind GLOB ? OR s.host GLOB ?" :
			     "s.kind GLOB ? OR s.host GLOB ?");
		q_bind_text(q, srcs[n]);
		q_bind_text(q, srcs[n]);
	}
	q_add(q, ")");
}

/*
 * The window of a query: a session's, or from= and to=, or the last ten
 * minutes
 */

static int
li_window_args(struct vhd *vhd, struct lws *wsi, uint64_t *from,
	       uint64_t *to, char *src, size_t srcl, char *sess, size_t sl)
{
	uint64_t now = lws_log_ship_utc_us();
	char a_from[40], a_to[40];
	li_sess_t s;

	src[0] = '\0';
	*to = now;
	*from = now - 600ull * 1000000ull;

	if (lws_get_urlarg_by_name_safe(wsi, "session=", sess, (int)sl) > 0) {
		if (li_session_get(vhd, sess, &s))
			return HTTP_STATUS_NOT_FOUND;
		*from = s.from_us;
		*to = s.until_us < now ? s.until_us : now;
		lws_strncpy(src, s.src, srcl);
	} else
		sess[0] = '\0';

	if (lws_get_urlarg_by_name_safe(wsi, "from=", a_from,
					sizeof(a_from)) > 0 &&
	    parse_time(a_from, now, from))
		return HTTP_STATUS_BAD_REQUEST;
	if (lws_get_urlarg_by_name_safe(wsi, "to=", a_to, sizeof(a_to)) > 0 &&
	    parse_time(a_to, now, to))
		return HTTP_STATUS_BAD_REQUEST;

	return *from > *to ? HTTP_STATUS_BAD_REQUEST : 0;
}

/* GET /logs */

static int
li_logs(struct vhd *vhd, struct pss *pss, struct lws *wsi, li_out_t *o)
{
	char a_lvl[12], a_grep[132], a_limit[12], a_after[48], sess[24],
	     a_tag[LI_TAG_MAX + 1], tag_sub[LI_TAG_MAX + 3],
	     ssrc[LI_SRC_MAX + 1], srcs[LI_SRC_PATTERNS_MAX][LI_HOST_MAX + 1];
	int nsrc = 0, limit = LI_LIMIT_DEF, lvlmask = 0, n, lines = 0,
	    truncated = 0, has_after;
	int64_t after_id = 0, last_t = 0, last_id = 0;
	uint64_t from, to, after_t = 0;
	sqlite3_stmt *sm;
	li_q_t q;

	n = li_window_args(vhd, wsi, &from, &to, ssrc, sizeof(ssrc), sess,
			   sizeof(sess));
	if (n)
		return n;

	if (li_src_arg(wsi, srcs, &nsrc, ssrc))
		return HTTP_STATUS_BAD_REQUEST;

	if (lws_get_urlarg_by_name_safe(wsi, "limit=", a_limit,
					sizeof(a_limit)) > 0) {
		limit = atoi(a_limit);
		if (limit < 1 || limit > LI_LIMIT_MAX)
			return HTTP_STATUS_BAD_REQUEST;
	}

	if (lws_get_urlarg_by_name_safe(wsi, "lvl=", a_lvl, sizeof(a_lvl)) > 0) {
		lvlmask = parse_lvl(a_lvl);
		if (lvlmask < 0)
			return HTTP_STATUS_BAD_REQUEST;
	}

	if (lws_get_urlarg_by_name_safe(wsi, "grep=", a_grep,
					sizeof(a_grep)) < 0)
		a_grep[0] = '\0';

	a_tag[0] = '\0';
	if (lws_get_urlarg_by_name_safe(wsi, "tag=", a_tag,
					sizeof(a_tag)) > 0) {
		if (!li_valid_tag(a_tag))
			return HTTP_STATUS_BAD_REQUEST;
		/* "a" also finds lines tagged "a/b" */
		lws_snprintf(tag_sub, sizeof(tag_sub), "%s/*", a_tag);
	}

	has_after = lws_get_urlarg_by_name_safe(wsi, "after=", a_after,
						sizeof(a_after)) > 0;
	if (has_after) {
		/* the "next" of the last page: "<t_us>:<id>" */
		char *c = strchr(a_after, ':');
		uint64_t u;

		if (!c)
			return HTTP_STATUS_BAD_REQUEST;
		*c = '\0';
		if (parse_u64(a_after, &after_t) || parse_u64(c + 1, &u))
			return HTTP_STATUS_BAD_REQUEST;
		after_id = (int64_t)u;
	}

	out_printf(o, "{\"session\":");
	out_str(o, sess[0] ? sess : NULL);
	out_printf(o, ",\"from\":");
	out_time(o, from);
	out_printf(o, ",\"to\":");
	out_time(o, to);

	/* the sources that may have lines in the window */

	out_printf(o, ",\"sources\":[");
	if (sqlite3_prepare_v2(vhd->pdb, "SELECT src_id, kind, host, inst, "
			"lag_us FROM sources WHERE last_us >= ? AND first_us "
			"<= ? ORDER BY src_id", -1, &sm, NULL) == SQLITE_OK) {
		sqlite3_bind_int64(sm, 1, (sqlite3_int64)from - LI_SKEW_MAX_US);
		sqlite3_bind_int64(sm, 2, (sqlite3_int64)to + LI_SKEW_MAX_US);
		n = 0;
		while (sqlite3_step(sm) == SQLITE_ROW) {
			out_printf(o, "%s{\"id\":%lld,\"kind\":", n++ ? "," : "",
				   (long long)sqlite3_column_int64(sm, 0));
			out_str(o, (const char *)sqlite3_column_text(sm, 1));
			out_printf(o, ",\"host\":");
			out_str(o, (const char *)sqlite3_column_text(sm, 2));
			out_printf(o, ",\"inst\":");
			out_str(o, (const char *)sqlite3_column_text(sm, 3));
			out_printf(o, ",\"lag_ms\":%lld}",
				   (long long)(sqlite3_column_int64(sm, 4) / 1000));
		}
		sqlite3_finalize(sm);
	}
	out_printf(o, "],\"lines\":[");

	memset(&q, 0, sizeof(q));
	q.p = q.sql;
	q_add(&q, "SELECT l.id, l.t_us, l.src_id, l.seq, l.lvl, l.line, l.tag "
		  "FROM lines l JOIN sources s ON s.src_id = l.src_id WHERE "
		  "l.t_us >= ? AND l.t_us <= ?");
	q_bind_int(&q, (int64_t)from);
	q_bind_int(&q, (int64_t)to);
	q_src(&q, srcs, nsrc);

	if (a_tag[0]) {
		q_add(&q, " AND (l.tag = ? OR l.tag GLOB ?)");
		q_bind_text(&q, a_tag);
		q_bind_text(&q, tag_sub);
	}

	if (lvlmask) {
		q_add(&q, " AND (l.lvl & ?) != 0");
		q_bind_int(&q, lvlmask);
	}

	if (a_grep[0]) {
		q_add(&q, " AND instr(l.line, ?) > 0");
		q_bind_text(&q, a_grep);
	}

	if (has_after) {
		q_add(&q, " AND (l.t_us > ? OR (l.t_us = ? AND l.id > ?))");
		q_bind_int(&q, (int64_t)after_t);
		q_bind_int(&q, (int64_t)after_t);
		q_bind_int(&q, after_id);
	}

	q_add(&q, " ORDER BY l.t_us, l.id LIMIT ?");
	q_bind_int(&q, limit + 1); /* one more says there's more */

	if (q_prepare(vhd->pdb, &q, &sm))
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;

	while (sqlite3_step(sm) == SQLITE_ROW) {
		if (lines == limit || o->total + o->len > LI_BODY_MAX) {
			truncated = 1;
			break;
		}

		last_id = sqlite3_column_int64(sm, 0);
		last_t = sqlite3_column_int64(sm, 1);

		out_printf(o, "%s{\"i\":%lld,\"t\":", lines++ ? "," : "",
			   (long long)last_id);
		out_time(o, (uint64_t)last_t);
		out_printf(o, ",\"t_us\":%lld,\"src\":%lld,\"seq\":",
			   (long long)last_t,
			   (long long)sqlite3_column_int64(sm, 2));
		if (sqlite3_column_type(sm, 3) == SQLITE_NULL)
			out_printf(o, "null");
		else
			out_printf(o, "%lld", (long long)
				   sqlite3_column_int64(sm, 3));
		out_printf(o, ",\"l\":%d,\"g\":", sqlite3_column_int(sm, 4));
		out_str(o, (const char *)sqlite3_column_text(sm, 6));
		out_printf(o, ",\"x\":");
		out_str(o, (const char *)sqlite3_column_text(sm, 5));
		out_printf(o, "}");
	}
	sqlite3_finalize(sm);

	/*
	 * next is after the last line we gave, so a window still open can be
	 * followed by asking with it again later
	 */
	out_printf(o, "],\"truncated\":%s", truncated ? "true" : "false");
	if (lines)
		out_printf(o, ",\"next\":\"%lld:%lld\"", (long long)last_t,
			   (long long)last_id);
	out_printf(o, "}");

	return li_answer(pss, wsi, o, HTTP_STATUS_OK);
}

/*
 * The synchronised view: a pane for each source host with lines in the
 * window, all at one instant.  GET /sync says what the window and panes are,
 * GET /pane gives a pane's lines either side of an instant.
 */

typedef struct {
	char		kind[LI_KIND_MAX + 1];
	char		host[LI_HOST_MAX + 1];
	int64_t		lag_ms;
	int		insts;
} li_pane_t;

static int
li_pane_cmp(const void *a, const void *b)
{
	const li_pane_t *pa = a, *pb = b;
	int n = strcmp(pa->kind, pb->kind);

	return n ? n : strcmp(pa->host, pb->host);
}

/* GET /sync?session=<id>|from=&to=[&src=][&at=<us>] */

static int
li_sync(struct vhd *vhd, struct pss *pss, struct lws *wsi, li_out_t *o)
{
	char sess[24], ssrc[LI_SRC_MAX + 1], a_at[24],
	     srcs[LI_SRC_PATTERNS_MAX][LI_HOST_MAX + 1];
	li_pane_t panes[LI_PANES_MAX];
	uint64_t from, to, at, pfrom, pto;
	int n, np = 0, nsrc = 0;
	sqlite3_stmt *sm;
	li_q_t q;

	n = li_window_args(vhd, wsi, &from, &to, ssrc, sizeof(ssrc), sess,
			   sizeof(sess));
	if (n)
		return n;
	if (li_src_arg(wsi, srcs, &nsrc, ssrc))
		return HTTP_STATUS_BAD_REQUEST;

	pfrom = from > (uint64_t)LI_PAD_US ? from - (uint64_t)LI_PAD_US : 0;
	pto = to + (uint64_t)LI_PAD_US;

	at = from;
	if (lws_get_urlarg_by_name_safe(wsi, "at=", a_at, sizeof(a_at)) > 0 &&
	    parse_u64(a_at, &at))
		return HTTP_STATUS_BAD_REQUEST;

	/* newer instances first, so we keep the latest lag */
	memset(&q, 0, sizeof(q));
	q.p = q.sql;
	q_add(&q, "SELECT kind, host, lag_us FROM sources s WHERE last_us >= ? "
		  "AND first_us <= ? AND EXISTS (SELECT 1 FROM lines l WHERE "
		  "l.src_id = s.src_id AND l.t_us >= ? AND l.t_us <= ?)");
	q_bind_int(&q, (int64_t)pfrom - LI_SKEW_MAX_US);
	q_bind_int(&q, (int64_t)pto + LI_SKEW_MAX_US);
	q_bind_int(&q, (int64_t)pfrom);
	q_bind_int(&q, (int64_t)pto);
	q_src(&q, srcs, nsrc);
	q_add(&q, " ORDER BY src_id DESC");

	if (q_prepare(vhd->pdb, &q, &sm))
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;

	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *k = (const char *)sqlite3_column_text(sm, 0),
			   *h = (const char *)sqlite3_column_text(sm, 1);

		if (!k || !h)
			continue;

		for (n = 0; n < np; n++)
			if (!strcmp(panes[n].kind, k) &&
			    !strcmp(panes[n].host, h))
				break;
		if (n < np) {
			panes[n].insts++;
			continue;
		}
		if (np == LI_PANES_MAX)
			continue;

		lws_strncpy(panes[np].kind, k, sizeof(panes[np].kind));
		lws_strncpy(panes[np].host, h, sizeof(panes[np].host));
		panes[np].lag_ms = sqlite3_column_int64(sm, 2) / 1000;
		panes[np].insts = 1;
		np++;
	}
	sqlite3_finalize(sm);

	qsort(panes, (size_t)np, sizeof(panes[0]), li_pane_cmp);

	out_printf(o, "{\"session\":");
	out_str(o, sess[0] ? sess : NULL);
	out_printf(o, ",\"start_us\":%llu,\"end_us\":%llu,\"from_us\":%llu,"
		   "\"to_us\":%llu,\"at_us\":%llu,\"running\":%s,\"panes\":[",
		   (unsigned long long)from, (unsigned long long)to,
		   (unsigned long long)pfrom, (unsigned long long)pto,
		   (unsigned long long)at,
		   to >= lws_log_ship_utc_us() - 1000000ull ? "true" : "false");

	for (n = 0; n < np; n++) {
		char pid[LI_KIND_MAX + LI_HOST_MAX + 2];

		lws_snprintf(pid, sizeof(pid), "%s/%s", panes[n].kind,
			     panes[n].host);
		out_printf(o, "%s{\"pane\":", n ? "," : "");
		out_str(o, pid);
		out_printf(o, ",\"kind\":");
		out_str(o, panes[n].kind);
		out_printf(o, ",\"host\":");
		out_str(o, panes[n].host);
		out_printf(o, ",\"lag_ms\":%lld,\"insts\":%d}",
			   (long long)panes[n].lag_ms, panes[n].insts);
	}
	out_printf(o, "]}");

	return li_answer(pss, wsi, o, HTTP_STATUS_OK);
}

typedef struct {
	int64_t		id;
	uint64_t	t;
	int64_t		src;
	const char	*x;
	const char	*g;
	int		l;
} li_row_t;

/*
 * One side of the instant: the rows nearest it, the newest first before it,
 * the oldest first after it.  We keep one more than we want, to say there's
 * more.
 */

typedef struct {
	struct lwsac		**ac;
	li_row_t		*rows;
	int			count;
	int			want;
	char			later;
} li_side_t;

static int
li_row_cmp_before(const void *a, const void *b)
{
	const li_row_t *ra = a, *rb = b;

	if (ra->t != rb->t)
		return ra->t < rb->t ? 1 : -1;

	return ra->id < rb->id ? 1 : (ra->id > rb->id ? -1 : 0);
}

static int
li_row_cmp_after(const void *a, const void *b)
{
	return li_row_cmp_before(b, a);
}

static const char *
li_strdup(struct lwsac **ac, const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;

	n = strlen(s) + 1;
	p = lwsac_use(ac, n, n > 4096 ? n : 4096);
	if (p)
		memcpy(p, s, n);

	return p;
}

/*
 * A host's lines either side of the instant.  A host may have had several
 * instances, eg, it restarted, so we go through them from the one with a line
 * nearest the instant, and stop once the next one's nearest line is further
 * away than the furthest one we're keeping.
 */

static int
li_side(struct vhd *vhd, const char *kind, const char *host, uint64_t at,
	li_side_t *sd)
{
	sqlite3_stmt *ss, *sl;
	int ret = 0;

	if (!sd->want)
		return 0;

	if (sqlite3_prepare_v2(vhd->pdb, sd->later ?
			"SELECT src_id, edge FROM (SELECT src_id, (SELECT "
			"min(t_us) FROM lines l WHERE l.src_id = s.src_id AND "
			"l.t_us > ?1) AS edge FROM sources s WHERE kind = ?2 "
			"AND host = ?3) WHERE edge IS NOT NULL ORDER BY edge" :
			"SELECT src_id, edge FROM (SELECT src_id, (SELECT "
			"max(t_us) FROM lines l WHERE l.src_id = s.src_id AND "
			"l.t_us <= ?1) AS edge FROM sources s WHERE kind = ?2 "
			"AND host = ?3) WHERE edge IS NOT NULL ORDER BY edge "
			"DESC", -1, &ss, NULL) != SQLITE_OK)
		return 1;

	if (sqlite3_prepare_v2(vhd->pdb, sd->later ?
			"SELECT id, t_us, lvl, line, tag FROM lines WHERE "
			"src_id = ? AND t_us > ? ORDER BY t_us, id LIMIT ?" :
			"SELECT id, t_us, lvl, line, tag FROM lines WHERE "
			"src_id = ? "
			"AND t_us <= ? ORDER BY t_us DESC, id DESC LIMIT ?", -1,
			&sl, NULL) != SQLITE_OK) {
		sqlite3_finalize(ss);
		return 1;
	}

	sqlite3_bind_int64(ss, 1, (sqlite3_int64)at);
	sqlite3_bind_text(ss, 2, kind, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(ss, 3, host, -1, SQLITE_TRANSIENT);

	while (sqlite3_step(ss) == SQLITE_ROW) {
		int64_t src = sqlite3_column_int64(ss, 0);
		uint64_t edge = (uint64_t)sqlite3_column_int64(ss, 1);

		if (sd->count > sd->want &&
		    (sd->later ? edge > sd->rows[sd->want].t :
				 edge < sd->rows[sd->want].t))
			break;

		sqlite3_reset(sl);
		sqlite3_bind_int64(sl, 1, src);
		sqlite3_bind_int64(sl, 2, (sqlite3_int64)at);
		sqlite3_bind_int(sl, 3, sd->want + 1);

		while (sqlite3_step(sl) == SQLITE_ROW) {
			li_row_t *row = &sd->rows[sd->count++];

			row->id = sqlite3_column_int64(sl, 0);
			row->t = (uint64_t)sqlite3_column_int64(sl, 1);
			row->src = src;
			row->l = sqlite3_column_int(sl, 2);
			row->x = li_strdup(sd->ac,
				   (const char *)sqlite3_column_text(sl, 3));
			row->g = li_strdup(sd->ac,
				   (const char *)sqlite3_column_text(sl, 4));
			if (!row->x) {
				sd->count--;
				ret = 1;
				break;
			}
		}

		/* nearest the instant first, and only one more than we want */
		qsort(sd->rows, (size_t)sd->count, sizeof(sd->rows[0]),
		      sd->later ? li_row_cmp_after : li_row_cmp_before);
		if (sd->count > sd->want + 1)
			sd->count = sd->want + 1;
	}

	sqlite3_finalize(sl);
	sqlite3_finalize(ss);

	return ret;
}

static void
li_side_out(li_out_t *o, const li_side_t *sd)
{
	int i, c = sd->count < sd->want ? sd->count : sd->want;

	/* in time order, so the rows before come reversed */
	for (i = 0; i < c; i++) {
		const li_row_t *row = &sd->rows[sd->later ? i : c - 1 - i];

		out_printf(o, "%s{\"i\":%lld,\"t\":%llu,\"s\":%lld,\"l\":%d,"
			   "\"g\":", i ? "," : "", (long long)row->id,
			   (unsigned long long)row->t, (long long)row->src,
			   row->l);
		out_str(o, row->g);
		out_printf(o, ",\"x\":");
		out_str(o, row->x);
		out_printf(o, "}");
	}
}

static int
parse_count(const char *s, int *v)
{
	uint64_t u;

	if (parse_u64(s, &u) || u > LI_PANE_LINES_MAX)
		return 1;
	*v = (int)u;

	return 0;
}

/* GET /pane?pane=<kind>/<host>&at=<us>[&before=<n>][&after=<n>] */

static int
li_pane(struct vhd *vhd, struct pss *pss, struct lws *wsi, li_out_t *o)
{
	char a_pane[LI_KIND_MAX + LI_HOST_MAX + 2], a_at[24], a_n[12], *host;
	struct lwsac *ac = NULL;
	li_side_t sd[2];
	int n, ret = 0;
	uint64_t at;

	memset(sd, 0, sizeof(sd));
	sd[0].want = sd[1].want = LI_PANE_LINES_DEF;
	sd[1].later = 1;

	if (lws_get_urlarg_by_name_safe(wsi, "pane=", a_pane,
					sizeof(a_pane)) <= 0 ||
	    lws_get_urlarg_by_name_safe(wsi, "at=", a_at, sizeof(a_at)) <= 0 ||
	    parse_u64(a_at, &at))
		return HTTP_STATUS_BAD_REQUEST;

	if (lws_get_urlarg_by_name_safe(wsi, "before=", a_n, sizeof(a_n)) > 0 &&
	    parse_count(a_n, &sd[0].want))
		return HTTP_STATUS_BAD_REQUEST;
	if (lws_get_urlarg_by_name_safe(wsi, "after=", a_n, sizeof(a_n)) > 0 &&
	    parse_count(a_n, &sd[1].want))
		return HTTP_STATUS_BAD_REQUEST;

	host = strchr(a_pane, '/');
	if (!host)
		return HTTP_STATUS_BAD_REQUEST;
	*host++ = '\0';
	if (!li_valid_name(a_pane, LI_KIND_MAX) ||
	    !li_valid_name(host, LI_HOST_MAX))
		return HTTP_STATUS_BAD_REQUEST;

	/* each side may hold a source's worth more while it's merged */
	for (n = 0; n < 2; n++) {
		sd[n].ac = &ac;
		sd[n].rows = lwsac_use_zero(&ac, sizeof(li_row_t) *
					    (size_t)(2 * (sd[n].want + 1)), 0);
		if (!sd[n].rows || li_side(vhd, a_pane, host, at, &sd[n])) {
			ret = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			goto bail;
		}
	}

	out_printf(o, "{\"at_us\":%llu,\"before\":[", (unsigned long long)at);
	li_side_out(o, &sd[0]);
	out_printf(o, "],\"after\":[");
	li_side_out(o, &sd[1]);
	out_printf(o, "],\"more_before\":%s,\"more_after\":%s}",
		   sd[0].count > sd[0].want ? "true" : "false",
		   sd[1].count > sd[1].want ? "true" : "false");

	ret = li_answer(pss, wsi, o, HTTP_STATUS_OK);

bail:
	lwsac_free(&ac);

	return ret;
}

/*
 * Start the answer to a request, path being what's after our mount.  Returns
 * <0 to drop the connection, 0 if the answer is on its way, or an http status
 * to reply with instead.
 */

static int
li_api_route(struct vhd *vhd, struct pss *pss, struct lws *wsi,
	     const char *path, int is_post, const char *sub, li_out_t *o)
{
	char id[LI_SESSION_LEN + 1], ct[64];
	const char *p;
	int n;

	while (*path == '/')
		path++;

	if (is_post) {
		/*
		 * A form can't send JSON across origins without asking first,
		 * which we never agree to: that's what stops a page elsewhere
		 * making a logged-in browser start sessions
		 */
		n = lws_hdr_copy(wsi, ct, sizeof(ct),
				 WSI_TOKEN_HTTP_CONTENT_TYPE);
		if (n < 16 || strncmp(ct, "application/json", 16) ||
		    (ct[16] && ct[16] != ';'))
			return HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE;

		if (!strcmp(path, "sessions"))
			return li_session_start(vhd, pss, wsi, o, sub);

		/* sessions/<id>/stop */
		if (!strncmp(path, "sessions/", 9)) {
			p = path + 9;
			if (strlen(p) == LI_SESSION_LEN + 5 &&
			    !strcmp(p + LI_SESSION_LEN, "/stop")) {
				memcpy(id, p, LI_SESSION_LEN);
				id[LI_SESSION_LEN] = '\0';
				return li_session_stop(vhd, pss, wsi, o, id,
						       sub);
			}
		}

		return HTTP_STATUS_NOT_FOUND;
	}

	lwsl_wsi_info(wsi, "'%s': %s", sub, path);

	if (!strcmp(path, "sessions"))
		return li_sessions_list(vhd, pss, wsi, o, NULL);
	if (!strncmp(path, "sessions/", 9))
		return li_sessions_list(vhd, pss, wsi, o, path + 9);
	if (!strcmp(path, "sources"))
		return li_sources(vhd, pss, wsi, o);
	if (!strncmp(path, "tags/", 5))
		return li_tag_window(vhd, pss, wsi, o, path + 5);
	if (!strcmp(path, "logs"))
		return li_logs(vhd, pss, wsi, o);
	if (!strcmp(path, "sync"))
		return li_sync(vhd, pss, wsi, o);
	if (!strcmp(path, "pane"))
		return li_pane(vhd, pss, wsi, o);

	return HTTP_STATUS_NOT_FOUND;
}

/*
 * Every refusal says why as {"error":...}, so a client can show it
 */

int
li_api_http(struct vhd *vhd, struct pss *pss, struct lws *wsi,
	    const char *path, int is_post)
{
	char sub[LI_WHO_MAX + 1];
	const char *why;
	li_out_t o;
	int n;

	lws_buflist_destroy_all_segments(&pss->tx);
	memset(&o, 0, sizeof(o));
	o.bl = &pss->tx;

	if (!li_allowed(vhd, wsi, sub, sizeof(sub)))
		n = HTTP_STATUS_FORBIDDEN;
	else
		n = li_api_route(vhd, pss, wsi, path, is_post, sub, &o);
	if (n <= 0)
		return n;

	switch (n) {
	case HTTP_STATUS_FORBIDDEN:
		why = "not allowed: log in with the grant";
		break;
	case HTTP_STATUS_NOT_FOUND:
		why = "no such thing";
		break;
	case HTTP_STATUS_BAD_REQUEST:
		why = "bad argument";
		break;
	case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
		why = "the body must be application/json";
		break;
	default:
		why = "failed";
		break;
	}

	return li_error(pss, wsi, &o, (unsigned int)n, why);
}

int
li_api_writeable(struct pss *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 4096], *seg;
	size_t n;
	int final;

	n = lws_buflist_next_segment_len(&pss->tx, &seg);
	if (n > sizeof(buf) - LWS_PRE)
		n = sizeof(buf) - LWS_PRE;
	if (n)
		memcpy(buf + LWS_PRE, seg, n);
	lws_buflist_use_segment(&pss->tx, n);
	final = !lws_buflist_total_len(&pss->tx);

	if (lws_write(wsi, buf + LWS_PRE, n, final ? LWS_WRITE_HTTP_FINAL :
						     LWS_WRITE_HTTP) != (int)n)
		return -1;

	if (!final) {
		lws_callback_on_writable(wsi);
		return 0;
	}

	pss->sending = 0;
	li_api_close(pss);

	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

void
li_api_close(struct pss *pss)
{
	lws_buflist_destroy_all_segments(&pss->tx);
	free(pss->body);
	pss->body = NULL;
	pss->body_len = 0;
	pss->sending = 0;
}
