/*
 * libwebsockets - small server side websockets and web server implementation
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
 * Log shipping, the source side, see READMEs/README.log-ship.md
 *
 * Every line lws emits is shown to lws_log_ship_tap(), whatever thread it was
 * logged on, which copies it into a bounded backlog with its UTC time and a
 * sequence number.  That's all the tap does: anything more, like asking for a
 * writeable, might log, and the tap mustn't recurse or stall whatever was
 * logging.  So nothing done while holding the backlog lock may log.
 *
 * The ingestor decides what we send, by giving us a window: the lines from a
 * UTC time, which may be in the past and so come from the backlog, until a
 * UTC time.  A sul looks at the backlog every 500ms and, if there's anything
 * in the window, asks for a writeable.  Lines go in batches, one outstanding
 * at a time, and the ingestor acks a batch by its highest seq once it has
 * stored it: only then are its lines freed.  A batch lost with the
 * connection, or not acked in time, goes again; the ingestor ignores lines it
 * already has.
 *
 * A shipper in the ingestor's own process has a local store instead, which
 * the sul hands the lines in the window to directly.
 */

#include "private-lib-core.h"

#if defined(LWS_LOG_THREADED)
#include <pthread.h>
#endif

/* how often we look at the backlog */
#define LS_PUMP_US		(500 * LWS_US_PER_MS)
/* a batch not acked for this long is sent again */
#define LS_ACK_WAIT_US		(30 * LWS_US_PER_SEC)
/* about the most JSON a batch may come to */
#define LS_BATCH_MAX		(48 * 1024)
#define LS_BACKLOG_DEF		(4 * 1024 * 1024)
/* the most backlog a vhost's "backlog-kb" pvo may ask for, 1GiB */
#define LS_BACKLOG_KB_MAX	(1024 * 1024)
/* a control message from the ingestor */
#define LS_RX_MAX		512
#define LS_KIND_MAX		32
#define LS_HOST_MAX		64
#define LS_SECRET_MAX		256
#define LS_SESSION_MAX		32
/* the longest a window may stay open, whoever asks */
#define LS_WINDOW_MAX_US	(24ll * 3600 * LWS_US_PER_SEC)

/* the LLL_ bits a window may add, as far as they are built */
#define LS_LVL_MASK		(((1 << LLL_COUNT) - 1) & (_LWS_ENABLED_LOGS))

typedef struct ls_line {
	lws_dll2_t		list;	/* ls->lines */
	uint64_t		seq;
	uint64_t		t;
	size_t			len;
	size_t			cost;	/* what it counts against backlog_max */
	int			level;
	char			inflight;
	/* the text follows */
} ls_line_t;

struct lws_log_ship {
	lws_dll2_owner_t		lines;	/* guarded by ls_lock */
	lws_sorted_usec_list_t		sul_pump;
	lws_sorted_usec_list_t		sul_connect;
	lws_sorted_usec_list_t		sul_until;

	struct lws_context		*cx;
	struct lws_vhost		*vh;
	struct lws			*wsi;
	lws_parse_uri_t			*uri;
	char				*path;	/* with its leading / */
	char				*secret;

	lws_log_ship_store_cb_t		store;
	void				*opaque;

	ls_line_t			*hint;	/* where a batch may start */

	uint64_t			seq;
	uint64_t			from_us;
	uint64_t			until_us;
	lws_usec_t			us_batch_sent;

	size_t				backlog_max;
	size_t				held;
	unsigned int			dropped; /* lost while wanted */

	int				ssl_flags;
	int				raised;	/* LLL_ bits we added */
	int				raised_def;
	uint16_t			retry_count;

	char				kind[LS_KIND_MAX + 1];
	char				host[LS_HOST_MAX + 1];
	char				inst[17];
	char				session[LS_SESSION_MAX + 1];

	char				rx[LS_RX_MAX];
	size_t				rx_len;
	char				rx_toobig;

	char				connected;
	char				sent_hello;
	char				awaiting_ack;
	char				in_connect;
	char				connect_died;
	char				said_sysinfo;
};

/*
 * The lock guards ls_one, and what's in its backlog: lines, hint, seq, held
 * and dropped, and the window, from_us and until_us
 */

#if defined(LWS_LOG_THREADED)
static pthread_mutex_t ls_lock = PTHREAD_MUTEX_INITIALIZER;
#define ls_lock_take()		pthread_mutex_lock(&ls_lock)
#define ls_lock_release()	pthread_mutex_unlock(&ls_lock)
#else
#define ls_lock_take()
#define ls_lock_release()
#endif

static struct lws_log_ship *ls_one;

static const uint32_t ls_backoff_ms[] = { 1000, 2000, 5000, 15000, 30000,
					  60000 };

static const lws_retry_bo_t ls_retry = {
	.retry_ms_table			= ls_backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(ls_backoff_ms),
	.conceal_count			= LWS_RETRY_CONCEAL_ALWAYS,
	.secs_since_valid_ping		= 30,
	.secs_since_valid_hangup	= 70,
	.jitter_percent			= 20,
};

uint64_t
lws_log_ship_utc_us(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return ((uint64_t)tv.tv_sec * 1000000ull) + (uint64_t)tv.tv_usec;
}

struct lws_log_ship *
lws_log_ship_get(void)
{
	struct lws_log_ship *ls;

	ls_lock_take();
	ls = ls_one;
	ls_lock_release();

	return ls;
}

const char *
lws_log_ship_inst(struct lws_log_ship *ls)
{
	return ls->inst;
}

const char *
lws_log_ship_host(struct lws_log_ship *ls)
{
	return ls->host;
}

static int
ls_name_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static int
ls_valid_name(const char *s, size_t max)
{
	size_t n;

	for (n = 0; s[n]; n++)
		if (n == max || !ls_name_char(s[n]))
			return 0;

	return n > 0;
}

/* lock held */

static int
ls_wanted(const struct lws_log_ship *ls, const ls_line_t *l)
{
	return ls->until_us && l->t >= ls->from_us && l->t <= ls->until_us;
}

/* lock held */

static void
ls_free_line(struct lws_log_ship *ls, ls_line_t *l)
{
	if (ls->hint == l)
		ls->hint = NULL;
	lws_dll2_remove(&l->list);
	ls->held -= l->cost;
	free(l);
}

/*
 * Lock held.  Add a line to the backlog, making room by dropping the oldest.
 * The text is made printable ASCII, so whatever was logged is harmless in
 * JSON and in a browser.
 */

static int
ls_add(struct lws_log_ship *ls, int level, uint64_t t, const char *text,
       size_t n)
{
	size_t cost, m;
	ls_line_t *l;
	char *d;

	if (n > LWS_LOG_SHIP_LINE_MAX)
		n = LWS_LOG_SHIP_LINE_MAX;

	cost = sizeof(*l) + n + 1;
	if (cost > ls->backlog_max)
		return 1;

	while (ls->held + cost > ls->backlog_max && ls->lines.head) {
		l = lws_container_of(ls->lines.head, ls_line_t, list);
		if (l->inflight || ls_wanted(ls, l))
			ls->dropped++;
		ls_free_line(ls, l);
	}

	/* not lws_malloc(): with alloc metadata, that may log */
	l = malloc(cost);
	if (!l)
		return 1;

	memset(l, 0, sizeof(*l));
	l->cost = cost;
	l->len = n;
	l->t = t;
	l->level = level;
	l->seq = ++ls->seq;

	d = (char *)(l + 1);
	for (m = 0; m < n; m++) {
		char c = text[m];

		if (c == '\t')
			c = ' ';
		else if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e)
			c = '?';
		d[m] = c;
	}
	d[n] = '\0';

	lws_dll2_add_tail(&l->list, &ls->lines);
	ls->held += cost;

	return 0;
}

void
lws_log_ship_tap(int level, const char *line, size_t len)
{
	const char *p = line, *e;
	struct lws_log_ship *ls;

	/*
	 * lws starts the line with its own local time and level,
	 * "[2026/10/14 08:01:02:1234] N: ", we keep both separately
	 */

	if (*p == '[') {
		e = memchr(p, ']', len < 32 ? len : 32);
		if (e && (size_t)(e - p) + 5 <= len && e[1] == ' ' && e[2] &&
		    e[3] == ':' && e[4] == ' ')
			p = e + 5;
	}
	len -= (size_t)(p - line);

	while (len && (p[len - 1] == '\n' || p[len - 1] == '\r'))
		len--;
	if (!len)
		return;

	ls_lock_take();
	ls = ls_one;
	if (ls)
		ls_add(ls, level, lws_log_ship_utc_us(), p, len);
	ls_lock_release();
}

/*
 * The window's level: the bits it asks for that aren't already logged are
 * added, to the context's log cx and the processwide one, and taken away
 * again when it closes
 */

static void
ls_level(struct lws_log_ship *ls, int lvl)
{
	lws_log_cx_t *cxc = lwsl_context_get_cx(ls->cx);

	if (ls->raised && cxc) {
		cxc->lll_flags &= ~(uint32_t)ls->raised;
		ls->raised = 0;
	}
	if (ls->raised_def) {
		log_cx.lll_flags &= ~(uint32_t)ls->raised_def;
		ls->raised_def = 0;
	}

	lvl &= LS_LVL_MASK;
	if (!lvl)
		return;

	if (cxc) {
		ls->raised = lvl & ~(int)cxc->lll_flags;
		cxc->lll_flags |= (uint32_t)ls->raised;
	}
	if (cxc != &log_cx) {
		ls->raised_def = lvl & ~(int)log_cx.lll_flags;
		log_cx.lll_flags |= (uint32_t)ls->raised_def;
	}
}

static void
ls_until_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_log_ship *ls = lws_container_of(sul, struct lws_log_ship,
						   sul_until);

	/* what was logged in the window still goes, but no more is raised */
	ls_level(ls, 0);
	lwsl_cx_notice(ls->cx, "log window for session %s closed",
		       ls->session[0] ? ls->session : "-");
}

static void
ls_sysinfo(struct lws_log_ship *ls)
{
#if defined(LWS_WITH_SYS_INFO)
	const lws_sysinfo_item_t *it = NULL;
	struct lws_sysinfo *si;
	char line[256];

	/* the first window starts with what this system looks like */
	if (ls->said_sysinfo)
		return;
	ls->said_sysinfo = 1;

	si = lws_sysinfo_create(ls->cx);
	if (!si)
		return;

	while ((it = lws_sysinfo_next(si, it))) {
		lws_sysinfo_describe(it, line, sizeof(line));
		lwsl_cx_notice(ls->cx, "sysinfo: %s", line);
	}

	lws_sysinfo_destroy(&si);
#endif
}

void
lws_log_ship_window(struct lws_log_ship *ls, uint64_t from_us,
		    uint64_t until_us, int lvl)
{
	uint64_t now = lws_log_ship_utc_us();

	if (until_us > now + (uint64_t)LS_WINDOW_MAX_US)
		until_us = now + (uint64_t)LS_WINDOW_MAX_US;

	ls_lock_take();
	ls->from_us = until_us ? from_us : 0;
	ls->until_us = until_us;
	/* lines before the old window may be in the new one */
	ls->hint = NULL;
	ls_lock_release();

	lws_sul_cancel(&ls->sul_until);

	if (!until_us || until_us <= now) {
		ls_level(ls, 0);
		lwsl_cx_notice(ls->cx, "log window closed");
		return;
	}

	ls_level(ls, lvl);
	lws_sul_schedule(ls->cx, 0, &ls->sul_until, ls_until_cb,
			 (lws_usec_t)(until_us - now));

	lwsl_cx_notice(ls->cx, "log window for session %s: from %llu, %llus "
		       "more, level +0x%x", ls->session[0] ? ls->session : "-",
		       (unsigned long long)from_us,
		       (unsigned long long)((until_us - now) / LWS_US_PER_SEC),
		       (unsigned int)(lvl & LS_LVL_MASK));

	ls_sysinfo(ls);
}

/*
 * Lock held.  Account for lines lost while they were wanted, with a line of
 * our own where they would have been.
 */

static void
ls_say_dropped(struct lws_log_ship *ls)
{
	char say[96];
	size_t n;

	if (!ls->dropped || !ls->until_us)
		return;

	n = (size_t)lws_snprintf(say, sizeof(say), "log-ship: backlog full, "
				 "dropped %u lines", ls->dropped);
	if (!ls_add(ls, LLL_WARN, lws_log_ship_utc_us(), say, n))
		ls->dropped = 0;
}

/* lock held: the next line in the window not already on its way */

static ls_line_t *
ls_next(struct lws_log_ship *ls, ls_line_t *after)
{
	lws_dll2_t *d = after ? after->list.next :
			(ls->hint ? &ls->hint->list : ls->lines.head);

	while (d) {
		ls_line_t *l = lws_container_of(d, ls_line_t, list);

		if (!l->inflight && ls_wanted(ls, l))
			return l;
		d = d->next;
	}

	return NULL;
}

/* lock held */

static void
ls_clear_inflight(struct lws_log_ship *ls)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, ls->lines.head) {
		lws_container_of(d, ls_line_t, list)->inflight = 0;
	} lws_end_foreach_dll(d);

	ls->hint = NULL;
}

/*
 * A local store: everything in the window goes to it now.  The lines are
 * taken out of the backlog first, so it can log while it stores them.
 */

static void
ls_pump_local(struct lws_log_ship *ls)
{
	lws_log_ship_line_t lines[64];
	ls_line_t *took[64], *l;
	size_t n, m;

	do {
		n = 0;
		ls_lock_take();
		ls_say_dropped(ls);
		l = ls_next(ls, NULL);
		while (l && n < LWS_ARRAY_SIZE(took)) {
			ls_line_t *nx = ls_next(ls, l);

			if (ls->hint == l)
				ls->hint = NULL;
			lws_dll2_remove(&l->list);
			ls->held -= l->cost;
			took[n++] = l;
			l = nx;
		}
		ls_lock_release();

		for (m = 0; m < n; m++) {
			lines[m].seq	= took[m]->seq;
			lines[m].t_us	= took[m]->t;
			lines[m].text	= (const char *)(took[m] + 1);
			lines[m].len	= took[m]->len;
			lines[m].level	= took[m]->level;
		}

		if (n)
			ls->store(ls->opaque, ls->kind, ls->host, ls->inst,
				  lines, n);

		for (m = 0; m < n; m++)
			free(took[m]);

	} while (n == LWS_ARRAY_SIZE(took));
}

static void
ls_pump(lws_sorted_usec_list_t *sul)
{
	struct lws_log_ship *ls = lws_container_of(sul, struct lws_log_ship,
						   sul_pump);
	int any;

	if (ls->store) {
		ls_pump_local(ls);
		goto again;
	}

	if (!ls->wsi || !ls->connected || !ls->sent_hello)
		goto again;

	ls_lock_take();
	if (ls->awaiting_ack &&
	    lws_now_usecs() - ls->us_batch_sent > LS_ACK_WAIT_US) {
		/* send it again, the ingestor ignores what it has */
		ls_clear_inflight(ls);
		ls->awaiting_ack = 0;
	}
	ls_say_dropped(ls);
	any = !ls->awaiting_ack && !!ls_next(ls, NULL);
	ls_lock_release();

	if (any)
		lws_callback_on_writable(ls->wsi);

again:
	lws_sul_schedule(ls->cx, 0, &ls->sul_pump, ls_pump, LS_PUMP_US);
}

/* a JSON string member, escaped */

static char *
ls_json_str(char *p, char *end, const char *s)
{
	int used;

	*p++ = '"';
	while (*s && end - p > 8) {
		used = 0;
		lws_json_purify(p, s, lws_ptr_diff(end, p) - 2, &used);
		p += strlen(p);
		if (!used)
			break;
		s += used;
	}
	*p++ = '"';
	*p = '\0';

	return p;
}

static int
ls_write_hello(struct lws_log_ship *ls)
{
	uint8_t buf[LWS_PRE + 1024], *start = buf + LWS_PRE;
	char *p = (char *)start, *end = (char *)buf + sizeof(buf) - 1;
	uint64_t oldest = 0;
	size_t n;

	ls_lock_take();
	if (ls->lines.head)
		oldest = lws_container_of(ls->lines.head, ls_line_t, list)->t;
	ls_lock_release();

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"lws-log-ship-hello\",\"secret\":");
	p = ls_json_str(p, end - 512, ls->secret);
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  ",\"kind\":\"%s\",\"host\":\"%s\",\"inst\":\"%s\","
			  "\"lvl\":%u,\"oldest\":%llu,\"v\":\"%s\"}",
			  ls->kind, ls->host, ls->inst,
			  (unsigned int)lwsl_context_get_cx(ls->cx)->lll_flags &
							LS_LVL_MASK,
			  (unsigned long long)oldest, LWS_LIBRARY_VERSION);

	n = lws_ptr_diff_size_t(p, start);
	if (lws_write(ls->wsi, start, n, LWS_WRITE_TEXT) != (int)n) {
		lws_explicit_bzero(start, n);
		return -1;
	}

	/* it held the secret */
	lws_explicit_bzero(start, n);
	ls->sent_hello = 1;

	/* there may be a window already, from before a reconnect */
	lws_callback_on_writable(ls->wsi);

	return 0;
}

/*
 * The next batch, built straight into the tx buffer: we can't know what a line
 * will come to in JSON until it's escaped, so we stop while there's room for
 * any line's worst case
 */

static int
ls_write_batch(struct lws_log_ship *ls)
{
	size_t worst = 96 + (6 * LWS_LOG_SHIP_LINE_MAX), n;
	uint8_t *buf, *start;
	char *p, *end;
	ls_line_t *l;
	int count = 0, r;

	buf = lws_malloc(LWS_PRE + LS_BATCH_MAX + worst + 64, __func__);
	if (!buf)
		return 0; /* try again next time */

	start = buf + LWS_PRE;
	p = (char *)start;
	end = p + LS_BATCH_MAX + worst + 63;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"lws-log-ship-lines\",\"lines\":[");

	ls_lock_take();
	l = ls_next(ls, NULL);
	while (l && lws_ptr_diff_size_t(p, start) < LS_BATCH_MAX) {
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s{\"seq\":%llu,\"t\":%llu,\"l\":%d,\"x\":",
				  count++ ? "," : "",
				  (unsigned long long)l->seq,
				  (unsigned long long)l->t, l->level);
		p = ls_json_str(p, end - 8, (const char *)(l + 1));
		*p++ = '}';
		l->inflight = 1;
		ls->hint = l;
		l = ls_next(ls, l);
	}
	ls_lock_release();

	if (!count) {
		lws_free(buf);
		return 0;
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");
	n = lws_ptr_diff_size_t(p, start);

	r = lws_write(ls->wsi, start, n, LWS_WRITE_TEXT) != (int)n;
	lws_free(buf);
	if (r)
		return -1;

	ls->awaiting_ack = 1;
	ls->us_batch_sent = lws_now_usecs();

	return 0;
}

/* the ingestor's lines are freed once it acks their batch */

static void
ls_acked(struct lws_log_ship *ls, uint64_t seq)
{
	int more;

	ls_lock_take();
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ls->lines.head) {
		ls_line_t *l = lws_container_of(d, ls_line_t, list);

		if (l->inflight && l->seq <= seq)
			ls_free_line(ls, l);
	} lws_end_foreach_dll_safe(d, d1);
	ls->awaiting_ack = 0;
	more = !!ls_next(ls, NULL);
	ls_lock_release();

	if (more && ls->wsi)
		lws_callback_on_writable(ls->wsi);
}

/* what the ingestor tells us */

typedef struct {
	char		schema[32];
	char		session[LS_SESSION_MAX + 1];
	uint64_t	from;
	uint64_t	until;
	uint64_t	seq;
	int		lvl;
} ls_ctl_t;

static const char * const ls_ctl_paths[] = {
	"schema", "session", "from", "until", "lvl", "seq",
};

enum { LSC_SCHEMA, LSC_SESSION, LSC_FROM, LSC_UNTIL, LSC_LVL, LSC_SEQ };

static int
ls_ctl_u64(const char *s, uint64_t *v)
{
	const char *p = s;

	for (*v = 0; *p >= '0' && *p <= '9' && p - s < 19; p++)
		*v = (*v * 10) + (uint64_t)(*p - '0');

	return p == s || *p;
}

static signed char
ls_ctl_cb(struct lejp_ctx *ctx, char reason)
{
	ls_ctl_t *c = (ls_ctl_t *)ctx->user;
	uint64_t u;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case LSC_SCHEMA:
		lws_strncpy(c->schema, ctx->buf, sizeof(c->schema));
		break;
	case LSC_SESSION:
		if (!ls_valid_name(ctx->buf, LS_SESSION_MAX))
			return -1;
		lws_strncpy(c->session, ctx->buf, sizeof(c->session));
		break;
	case LSC_FROM:
		if (ls_ctl_u64(ctx->buf, &c->from))
			return -1;
		break;
	case LSC_UNTIL:
		if (ls_ctl_u64(ctx->buf, &c->until))
			return -1;
		break;
	case LSC_LVL:
		if (ls_ctl_u64(ctx->buf, &u) || u >= (1u << LLL_COUNT))
			return -1;
		c->lvl = (int)u;
		break;
	case LSC_SEQ:
		if (ls_ctl_u64(ctx->buf, &c->seq))
			return -1;
		break;
	}

	return 0;
}

static void
ls_rx_ctl(struct lws_log_ship *ls)
{
	struct lejp_ctx ctx;
	ls_ctl_t c;
	int m;

	memset(&c, 0, sizeof(c));
	lejp_construct(&ctx, ls_ctl_cb, &c, ls_ctl_paths,
		       LWS_ARRAY_SIZE(ls_ctl_paths));
	m = lejp_parse(&ctx, (const uint8_t *)ls->rx, (int)ls->rx_len);
	lejp_destruct(&ctx);
	if (m < 0) {
		lwsl_cx_warn(ls->cx, "bad control message from ingestor");
		return;
	}

	if (!strcmp(c.schema, "lws-log-ship-ack")) {
		ls_acked(ls, c.seq);
		return;
	}

	if (!strcmp(c.schema, "lws-log-ship-start")) {
		lws_strncpy(ls->session, c.session, sizeof(ls->session));
		lws_log_ship_window(ls, c.from, c.until, c.lvl);
		return;
	}

	if (!strcmp(c.schema, "lws-log-ship-stop")) {
		lws_log_ship_window(ls, 0, 0, 0);
		ls->session[0] = '\0';
		return;
	}
}

static int
ls_ws_ok(const lws_parse_uri_t *u)
{
	lws_sockaddr46 sa46;

	if (!strcmp(u->scheme, "wss"))
		return 1;
	if (strcmp(u->scheme, "ws"))
		return 0;

	/* the secret only goes in the clear to somewhere on this machine */
	if (u->unix_skt || lws_host_is_localhost(u->host))
		return 1;
	if (lws_sa46_parse_numeric_address(u->host, &sa46) < 0)
		return 0;
	if (sa46.sa4.sin_family == AF_INET)
		return (ntohl(sa46.sa4.sin_addr.s_addr) >> 24) == 127;
#if defined(LWS_WITH_IPV6)
	if (sa46.sa4.sin_family == AF_INET6)
		return IN6_IS_ADDR_LOOPBACK(&sa46.sa6.sin6_addr);
#endif

	return 0;
}

static void
ls_connect_cb(lws_sorted_usec_list_t *sul);

static void
ls_retry_later(struct lws_log_ship *ls)
{
	if (lws_retry_sul_schedule(ls->cx, 0, &ls->sul_connect, &ls_retry,
				   ls_connect_cb, &ls->retry_count))
		/* the policy conceals forever, but just in case */
		lws_sul_schedule(ls->cx, 0, &ls->sul_connect, ls_connect_cb,
				 60 * LWS_US_PER_SEC);
}

static void
ls_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_log_ship *ls = lws_container_of(sul, struct lws_log_ship,
						   sul_connect);
	struct lws_client_connect_info i;
	struct lws *w;

	if (ls->wsi)
		return;

	memset(&i, 0, sizeof(i));
	i.context		= ls->cx;
	i.vhost			= ls->vh;
	i.address		= ls->uri->host;
	i.host			= ls->uri->host;
	i.origin		= ls->uri->host;
	i.port			= ls->uri->port;
	i.path			= ls->path;
	i.protocol		= LWS_LOG_SHIP_WS_PROTOCOL;
	i.local_protocol_name	= "lws-log-ship";
	i.opaque_user_data	= ls;
	i.retry_and_idle_policy	= &ls_retry;
	i.fi_wsi_name		= "log-ship";
	/*
	 * Our link is ws over its own h1 connection.  Without saying so, on a
	 * vhost that serves tls, it offers the vhost's alpn, h2 among it, and
	 * as an h2 stream it would never become ws
	 */
	i.alpn			= "http/1.1";
	if (!strcmp(ls->uri->scheme, "wss"))
		i.ssl_connection = LCCSCF_USE_SSL | ls->ssl_flags;

	ls->connect_died = 0;
	ls->in_connect = 1;
	w = lws_client_connect_via_info(&i);
	ls->in_connect = 0;

	if (!w || ls->connect_died) {
		ls->wsi = NULL;
		ls_retry_later(ls);
		return;
	}

	ls->wsi = w;
}

static void
ls_disconnected(struct lws_log_ship *ls)
{
	ls->wsi = NULL;
	ls->connected = 0;
	ls->sent_hello = 0;
	ls->awaiting_ack = 0;
	ls->rx_len = 0;

	/* anything unacked goes again on the next connection */
	ls_lock_take();
	ls_clear_inflight(ls);
	ls_lock_release();
}

/*
 * A vhost given pvos for our protocol makes the process' shipper, connecting
 * from that vhost, eg, from lwsws's ws-protocols config:
 *
 *	"lws-log-ship": { "url": "wss://...", "secret": "...", "kind": "lwsws",
 *			  "host": "node1", "backlog-kb": "4096" }
 */

static int
ls_create_from_pvo(struct lws *wsi, const struct lws_protocol_vhost_options *pvo)
{
	struct lws_log_ship_info i;
	struct lws_log_ship *ls;
	const char *p;
	int kb;

	if (!pvo)
		/* the vhost didn't ask for a shipper */
		return 0;

	memset(&i, 0, sizeof(i));
	i.vhost = lws_get_vhost(wsi);

	ls = lws_log_ship_get();
	if (ls) {
		/*
		 * Eg, the lws-log-ingest plugin in this process keeps its
		 * lines itself: they already go somewhere, so this does
		 * nothing, but it isn't a failure
		 */
		lwsl_vhost_notice(i.vhost, "this process' log lines are "
				  "already kept, as %s %s, %s: lws-log-ship "
				  "here does nothing", ls->kind, ls->host,
				  ls->store ? "by the ingestor in this "
				  "process" : "by its shipper");
		return 0;
	}

	if (lws_pvo_get_str((void *)pvo, "url", &i.url) ||
	    lws_pvo_get_str((void *)pvo, "secret", &i.secret)) {
		lwsl_vhost_err(i.vhost, "lws-log-ship needs a url and a secret");
		return 1;
	}
	if (lws_pvo_get_str((void *)pvo, "kind", &i.kind))
		i.kind = "lws";
	if (lws_pvo_get_str((void *)pvo, "host", &i.host))
		i.host = NULL;
	if (!lws_pvo_get_str((void *)pvo, "backlog-kb", &p)) {
		kb = atoi(p);
		if (kb <= 0 || kb > LS_BACKLOG_KB_MAX) {
			lwsl_vhost_err(i.vhost, "lws-log-ship backlog-kb must "
				       "be 1 to %d", LS_BACKLOG_KB_MAX);
			return 1;
		}
		i.backlog_max = (size_t)kb * 1024;
	}

	return !lws_log_ship_create(&i);
}

static int
callback_log_ship(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct lws_log_ship *ls = (struct lws_log_ship *)
					lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		return ls_create_from_pvo(wsi,
				(const struct lws_protocol_vhost_options *)in);

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!ls)
			break;
		lwsl_cx_info(ls->cx, "connect to ingestor failed: %s",
			     in ? (const char *)in : "?");
		lws_set_opaque_user_data(wsi, NULL);
		ls_disconnected(ls);
		if (ls->in_connect)
			/* the connect call goes on from here */
			ls->connect_died = 1;
		else
			ls_retry_later(ls);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		if (!ls)
			return -1;
		lwsl_cx_notice(ls->cx, "connected to ingestor as %s %s, inst %s",
			       ls->kind, ls->host, ls->inst);
		ls->connected = 1;
		ls->retry_count = 0;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (!ls)
			return -1;
		if (lws_is_first_fragment(wsi)) {
			ls->rx_len = 0;
			ls->rx_toobig = 0;
		}
		if (ls->rx_len + len > sizeof(ls->rx))
			ls->rx_toobig = 1;
		else {
			memcpy(ls->rx + ls->rx_len, in, len);
			ls->rx_len += len;
		}
		if (!lws_is_final_fragment(wsi))
			break;
		if (ls->rx_toobig) {
			lwsl_cx_warn(ls->cx, "oversize control message");
			return -1;
		}
		ls_rx_ctl(ls);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (!ls)
			return -1;
		if (!ls->sent_hello)
			return ls_write_hello(ls);
		if (!ls->awaiting_ack)
			return ls_write_batch(ls);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_WSI_DESTROY:
		if (!ls || ls->wsi != wsi)
			break;
		lws_set_opaque_user_data(wsi, NULL);
		lwsl_cx_info(ls->cx, "connection to ingestor closed");
		ls_disconnected(ls);
		ls_retry_later(ls);
		break;

	default:
		break;
	}

	return 0;
}

const struct lws_protocols lws_log_ship_protocol =
	{ "lws-log-ship", callback_log_ship, 0, LS_RX_MAX, 0, NULL, 0 };

static int
ls_set_name(char *dest, size_t max, const char *src, const char *what)
{
	if (!src || !ls_valid_name(src, max)) {
		lwsl_err("%s: %s must be 1 to %u of [A-Za-z0-9._-]\n", __func__,
			 what, (unsigned int)max);
		return 1;
	}

	lws_strncpy(dest, src, max + 1);

	return 0;
}

struct lws_log_ship *
lws_log_ship_create(const struct lws_log_ship_info *info)
{
	struct lws_log_ship *ls;
	char host[LS_HOST_MAX + 1];
	uint8_t r[8];
	size_t n;

	if (!info->vhost || (!info->url && !info->store)) {
		lwsl_err("%s: needs a vhost, and a url or a store\n", __func__);
		return NULL;
	}

	ls = lws_zalloc(sizeof(*ls), __func__);
	if (!ls)
		return NULL;

	ls->vh = info->vhost;
	ls->cx = info->vhost->context;
	ls->store = info->store;
	ls->opaque = info->opaque;
	ls->ssl_flags = info->client_ssl_flags;
	ls->backlog_max = info->backlog_max ? info->backlog_max :
					      LS_BACKLOG_DEF;

	if (ls_set_name(ls->kind, LS_KIND_MAX, info->kind, "kind"))
		goto bail;

	if (info->host) {
		if (ls_set_name(ls->host, LS_HOST_MAX, info->host, "host"))
			goto bail;
	} else {
		/* our hostname, as far as it's a name we can use */
		memset(host, 0, sizeof(host));
		if (gethostname(host, sizeof(host) - 1))
			host[0] = '\0';
		for (n = 0; host[n] && ls_name_char(host[n]); n++)
			;
		host[n] = '\0';
		lws_strncpy(ls->host, host[0] ? host : "unknown",
			    sizeof(ls->host));
	}

	if (lws_get_random(ls->cx, r, sizeof(r)) != sizeof(r))
		goto bail;
	lws_hex_from_byte_array(r, sizeof(r), ls->inst, sizeof(ls->inst));

	if (!ls->store) {
		if (!info->secret || !info->secret[0] ||
		    strlen(info->secret) > LS_SECRET_MAX) {
			lwsl_err("%s: needs a secret, up to %u chars\n",
				 __func__, LS_SECRET_MAX);
			goto bail;
		}

		ls->uri = lws_parse_uri_create(info->url);
		if (!ls->uri || !ls->uri->host[0] || !ls_ws_ok(ls->uri)) {
			lwsl_err("%s: url must be wss://, or ws:// to this "
				 "machine\n", __func__);
			goto bail;
		}

		n = strlen(ls->uri->path) + 2;
		ls->path = lws_malloc(n, __func__);
		ls->secret = lws_strdup(info->secret);
		if (!ls->path || !ls->secret)
			goto bail;
		lws_snprintf(ls->path, n, "%s%s",
			     ls->uri->path[0] == '/' ? "" : "/",
			     ls->uri->path);
	}

	ls_lock_take();
	if (ls_one) {
		ls_lock_release();
		lwsl_err("%s: there's already a log shipper\n", __func__);
		goto bail;
	}
	ls_one = ls;
	ls_lock_release();

	lws_sul_schedule(ls->cx, 0, &ls->sul_pump, ls_pump, LS_PUMP_US);
	if (!ls->store)
		/* not from inside whatever is creating us, eg, the vhost */
		lws_sul_schedule(ls->cx, 0, &ls->sul_connect, ls_connect_cb,
				 LWS_US_PER_MS);

	lwsl_cx_notice(ls->cx, "keeping our logs for %s as %s %s, inst %s",
		       ls->store ? "a local store" : info->url, ls->kind,
		       ls->host, ls->inst);

	return ls;

bail:
	if (ls->secret) {
		lws_explicit_bzero(ls->secret, strlen(ls->secret));
		lws_free(ls->secret);
	}
	lws_free(ls->path);
	if (ls->uri)
		lws_parse_uri_destroy(&ls->uri);
	lws_free(ls);

	return NULL;
}

void
lws_log_ship_destroy(struct lws_log_ship **pls)
{
	struct lws_log_ship *ls = *pls;

	if (!ls)
		return;

	lws_sul_cancel(&ls->sul_pump);
	lws_sul_cancel(&ls->sul_connect);
	lws_sul_cancel(&ls->sul_until);
	ls_level(ls, 0);

	if (ls->wsi) {
		lws_set_opaque_user_data(ls->wsi, NULL);
		lws_set_timeout(ls->wsi, PENDING_TIMEOUT_KILLED_BY_PARENT,
				LWS_TO_KILL_ASYNC);
		ls->wsi = NULL;
	}

	ls_lock_take();
	if (ls_one == ls)
		ls_one = NULL;
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ls->lines.head) {
		ls_free_line(ls, lws_container_of(d, ls_line_t, list));
	} lws_end_foreach_dll_safe(d, d1);
	ls_lock_release();

	if (ls->secret) {
		lws_explicit_bzero(ls->secret, strlen(ls->secret));
		lws_free(ls->secret);
	}
	lws_free(ls->path);
	if (ls->uri)
		lws_parse_uri_destroy(&ls->uri);
	lws_free(ls);

	*pls = NULL;
}

/* the vhost the shipper connects from is going, so is the shipper */

void
lws_log_ship_destroy_on_vhost(struct lws_vhost *vh)
{
	struct lws_log_ship *ls;

	ls_lock_take();
	ls = ls_one && ls_one->vh == vh ? ls_one : NULL;
	ls_lock_release();

	if (ls)
		lws_log_ship_destroy(&ls);
}
