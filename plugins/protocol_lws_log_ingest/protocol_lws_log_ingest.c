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
 * See READMEs/README.log-ship.md
 *
 * Log shippers (lib/misc/log-ship) keep a ws connection to us, authenticated
 * by a shared secret, and send nothing until we give them a window.  Windows
 * come from sessions: someone with the grant asks for one over the http api,
 * naming a UTC time to start from, which may be a little in the past, how
 * long it lasts, which sources and how much logging.  Each shipper the open
 * sessions name gets the union of their windows, and while any is open it
 * sends us its lines, which we keep in sqlite for the api to query.
 *
 * Whatever a shipper sends is checked as if it came from anywhere: the secret
 * says it's one of ours, not that what it says is sane.
 */

#include "private.h"

#define LI_RETENTION_DAYS_DEF		14
#define LI_RATE_LINES_DEF		12000
#define LI_MAX_SESSION_SECS_DEF		3600
#define LI_MAX_PAST_SECS_DEF		3600
#define LI_SERVICE_DEF			"lws-logs"
#define LI_US_PER_DAY			(86400ull * 1000000ull)
/*
 * A source that's always in a window is given one that ends between one and
 * two of these from now, so it's only given a new one each time one passes
 */
#define LI_ALWAYS_US			(1800ull * 1000000ull)

static int
li_name_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

int
li_valid_name(const char *s, size_t max)
{
	size_t n;

	for (n = 0; s[n]; n++)
		if (n == max || !li_name_char(s[n]))
			return 0;

	return n > 0;
}

/*
 * A session's src is a comma-separated list of patterns, each matching a
 * source's kind or its host, with up to three *; empty matches everything
 */

int
li_src_matches(const char *src, const char *kind, const char *host)
{
	const char *s = src, *e;

	if (!*s)
		return 1;

	while (*s) {
		e = strchr(s, ',');
		if (!e)
			e = s + strlen(s);

		if (!lws_strcmp_wildcard(s, (size_t)(e - s), kind, strlen(kind)) ||
		    !lws_strcmp_wildcard(s, (size_t)(e - s), host, strlen(host)))
			return 1;

		s = *e ? e + 1 : e;
	}

	return 0;
}

/* the union of the windows of the open sessions that name the source */

static void
li_window_for(struct vhd *vhd, const char *kind, const char *host,
	      uint64_t now, li_window_t *w)
{
	memset(w, 0, sizeof(*w));

	/* everything it has, and keeps having */
	if (vhd->always && li_src_matches(vhd->always, kind, host)) {
		w->until_us = ((now / LI_ALWAYS_US) + 2) * LI_ALWAYS_US;
		lws_strncpy(w->session, "always", sizeof(w->session));
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->sessions)) {
		li_session_t *s = lws_container_of(d, li_session_t, list);

		if (!li_src_matches(s->src, kind, host))
			continue;

		if (!w->until_us)
			w->from_us = s->from_us;
		else if (s->from_us < w->from_us)
			w->from_us = s->from_us;
		if (s->until_us > w->until_us) {
			w->until_us = s->until_us;
			/* say the session that lasts longest */
			lws_strncpy(w->session, s->id, sizeof(w->session));
		}
		w->lvl |= s->lvl;
	} lws_end_foreach_dll(d);
}

static int
li_window_same(const li_window_t *a, const li_window_t *b)
{
	return a->from_us == b->from_us && a->until_us == b->until_us &&
	       a->lvl == b->lvl;
}

static void
li_sessions_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_sessions);

	li_windows_update(vhd);
}

/*
 * The sessions changed, or some ended: forget the ended ones, and give each
 * shipper its window if it changed
 */

void
li_windows_update(struct vhd *vhd)
{
	uint64_t now = lws_log_ship_utc_us(), next = 0;
	li_window_t w;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->sessions)) {
		li_session_t *s = lws_container_of(d, li_session_t, list);

		if (s->until_us <= now) {
			lwsl_vhost_notice(vhd->vh, "session %s ended", s->id);
			lws_dll2_remove(&s->list);
			free(s);
			continue;
		}
		if (!next || s->until_us < next)
			next = s->until_us;
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->shippers)) {
		struct pss *pss = lws_container_of(d, struct pss, list);

		li_window_for(vhd, pss->src->kind, pss->src->host, now, &w);
		/* a window that ended by itself needs no word from us */
		if (!w.until_us && pss->sent.until_us <= now)
			pss->sent = w;
		if (li_window_same(&w, &pss->sent))
			continue;

		pss->sent = w;
		pss->window_pending = 1;
		lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_dll(d);

	/* our own lines are a source like any other */
	if (vhd->own) {
		li_window_for(vhd, vhd->own_kind, vhd->own_host, now, &w);
		if (!w.until_us && vhd->own_window.until_us <= now)
			vhd->own_window = w;
		if (!li_window_same(&w, &vhd->own_window)) {
			vhd->own_window = w;
			lws_log_ship_window(vhd->own, w.from_us, w.until_us,
					    w.lvl);
		}
	}

	/* the always-on windows move on when the next period starts */
	if (vhd->always &&
	    (!next || ((now / LI_ALWAYS_US) + 1) * LI_ALWAYS_US < next))
		next = ((now / LI_ALWAYS_US) + 1) * LI_ALWAYS_US;

	lws_sul_cancel(&vhd->sul_sessions);
	if (next)
		lws_sul_schedule(vhd->cx, 0, &vhd->sul_sessions, li_sessions_cb,
				 (lws_usec_t)(next - now) + LWS_US_PER_MS);
}

/* our own lines, from our own shipper */

void
li_own_store(void *opaque, const char *kind, const char *host,
	     const char *inst, const lws_log_ship_line_t *lines, size_t count)
{
	struct vhd *vhd = (struct vhd *)opaque;
	uint64_t now = lws_log_ship_utc_us();
	li_src_t *src;
	size_t n;

	src = li_store_src(vhd, kind, host, inst, now);
	if (!src || li_store_begin(vhd))
		return;

	for (n = 0; n < count; n++)
		li_store_line(vhd, src, lines[n].seq, lines[n].t_us, now,
			      lines[n].level, lines[n].text, lines[n].len,
			      lines[n].tag);

	li_store_commit(vhd, src, now, 0);
}

/*
 * What a shipper sends us: its hello, then batches of lines
 */

static const char * const li_paths[] = {
	"schema",
	"secret",
	"kind",
	"host",
	"inst",
	"lines[].seq",
	"lines[].t",
	"lines[].l",
	"lines[].x",
	"lines[].g",
	"lines[]",
};

enum {
	LIP_SCHEMA,
	LIP_SECRET,
	LIP_KIND,
	LIP_HOST,
	LIP_INST,
	LIP_SEQ,
	LIP_T,
	LIP_L,
	LIP_X,
	LIP_G,
	LIP_LINE,
};

#define LIL_SEQ		1
#define LIL_T		2
#define LIL_L		4
#define LIL_X		8

static int
li_u64(const char *s, uint64_t *v)
{
	const char *p = s;

	for (*v = 0; *p >= '0' && *p <= '9' && p - s < 19; p++)
		*v = (*v * 10) + (uint64_t)(*p - '0');

	return p == s || *p;
}

/* a string member, which may come in pieces; 1 if it's too long */

static int
li_str(struct lejp_ctx *ctx, char reason, char *dest, size_t max,
       size_t *len)
{
	if (reason == LEJPCB_VAL_STR_START) {
		*len = 0;
		dest[0] = '\0';
		return 0;
	}

	if (*len + ctx->npos > max)
		return 1;

	memcpy(dest + *len, ctx->buf, ctx->npos);
	*len += ctx->npos;
	dest[*len] = '\0';

	return 0;
}

static void
li_take_line(struct pss *pss)
{
	struct vhd *vhd = pss->vhd;
	li_line_t *l = &pss->line;
	uint64_t now;
	int r;

	if (l->bad || l->have != (LIL_SEQ | LIL_T | LIL_L | LIL_X) ||
	    !vhd->sm_line) {
		pss->bad++;
		return;
	}

	if (l->seq > pss->max_seq)
		pss->max_seq = l->seq;

	now = lws_log_ship_utc_us();
	r = li_store_line(vhd, pss->src, l->seq, l->t, now, l->l, l->x,
			  l->xlen, l->g[0] ? l->g : NULL);
	if (r == 1)
		pss->bad++;
	if (!r && (int64_t)(now - l->t) < pss->lag)
		pss->lag = (int64_t)(now - l->t);
}

static signed char
li_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss *pss = (struct pss *)ctx->user;
	uint64_t u;

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == LIP_LINE + 1) {
		/* lines only count once we know who they're from */
		if (!pss->authed)
			return -1;
		memset(&pss->line, 0, sizeof(pss->line));
		return 0;
	}

	if (reason == LEJPCB_OBJECT_END && ctx->path_match == LIP_LINE + 1) {
		li_take_line(pss);
		return 0;
	}

	if (!ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_START || reason == LEJPCB_VAL_STR_CHUNK ||
	    reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case LIP_SCHEMA:
			return (signed char)-li_str(ctx, reason, pss->schema,
					sizeof(pss->schema) - 1, &pss->slen);
		case LIP_SECRET:
			return (signed char)-li_str(ctx, reason, pss->secret,
					sizeof(pss->secret) - 1, &pss->slen);
		case LIP_KIND:
			return (signed char)-li_str(ctx, reason, pss->kind,
					sizeof(pss->kind) - 1, &pss->slen);
		case LIP_HOST:
			return (signed char)-li_str(ctx, reason, pss->host,
					sizeof(pss->host) - 1, &pss->slen);
		case LIP_INST:
			return (signed char)-li_str(ctx, reason, pss->inst,
					sizeof(pss->inst) - 1, &pss->slen);
		case LIP_X:
			if (li_str(ctx, reason, pss->line.x,
				   sizeof(pss->line.x) - 1, &pss->line.xlen))
				pss->line.bad = 1;
			else if (reason == LEJPCB_VAL_STR_END)
				pss->line.have |= LIL_X;
			return 0;
		case LIP_G:
			/* optional, checked when it's stored */
			if (li_str(ctx, reason, pss->line.g,
				   sizeof(pss->line.g) - 1, &pss->line.glen))
				pss->line.bad = 1;
			return 0;
		default:
			pss->line.bad = 1;
			return 0;
		}
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE))
		return 0;

	switch (ctx->path_match - 1) {
	case LIP_SEQ:
		if (li_u64(ctx->buf, &pss->line.seq))
			pss->line.bad = 1;
		pss->line.have |= LIL_SEQ;
		break;
	case LIP_T:
		if (li_u64(ctx->buf, &pss->line.t))
			pss->line.bad = 1;
		pss->line.have |= LIL_T;
		break;
	case LIP_L:
		if (li_u64(ctx->buf, &u) || u >= (1u << LLL_COUNT))
			pss->line.bad = 1;
		pss->line.l = (int)u;
		pss->line.have |= LIL_L;
		break;
	}

	return 0;
}

/* a shipper's hello came: is it one of ours? */

static int
li_hello(struct vhd *vhd, struct pss *pss)
{
	size_t sl = strlen(pss->secret), ol = strlen(vhd->secret);
	int n, ok = sl == ol &&
		 !lws_timingsafe_bcmp(pss->secret, vhd->secret, (uint32_t)ol);

	lws_explicit_bzero(pss->secret, sizeof(pss->secret));
	/* the parser's buffer may hold the end of it too */
	lws_explicit_bzero(pss->ctx.buf, sizeof(pss->ctx.buf));

	if (!ok) {
		lwsl_vhost_warn(vhd->vh, "shipper refused: wrong secret");
		return -1;
	}

	for (n = 0; n < 16; n++)
		if (!((pss->inst[n] >= '0' && pss->inst[n] <= '9') ||
		      (pss->inst[n] >= 'a' && pss->inst[n] <= 'f')))
			break;

	if (!li_valid_name(pss->kind, LI_KIND_MAX) ||
	    !li_valid_name(pss->host, LI_HOST_MAX) ||
	    n != 16 || pss->inst[16]) {
		lwsl_vhost_warn(vhd->vh, "shipper refused: bad kind, host or "
				"inst");
		return -1;
	}

	pss->src = li_store_src(vhd, pss->kind, pss->host, pss->inst,
				lws_log_ship_utc_us());
	if (!pss->src) {
		lwsl_vhost_warn(vhd->vh, "shipper %s %s refused: its inst %s "
				"was someone else", pss->kind, pss->host,
				pss->inst);
		return -1;
	}

	pss->authed = 1;
	lws_dll2_add_tail(&pss->list, &vhd->shippers);
	lwsl_vhost_notice(vhd->vh, "shipper %s %s, inst %s connected",
			  pss->kind, pss->host, pss->inst);

	/* it may already be in an open session */
	li_windows_update(vhd);

	return 0;
}

static int
li_ws_rx(struct vhd *vhd, struct pss *pss, struct lws *wsi, void *in,
	 size_t len)
{
	uint64_t now;
	char say[96];
	int m, txn = 0;

	if (lws_is_first_fragment(wsi)) {
		lejp_construct(&pss->ctx, li_cb, pss, li_paths,
			       LWS_ARRAY_SIZE(li_paths));
		pss->msg_len = 0;
		pss->max_seq = 0;
		pss->lag = INT64_MAX;
		pss->bad = 0;
		pss->schema[0] = '\0';
		pss->parse_failed = 0;
	}

	pss->msg_len += len;
	if (pss->msg_len > LI_MSG_MAX) {
		lwsl_vhost_warn(vhd->vh, "shipper message over %d bytes",
				LI_MSG_MAX);
		return -1;
	}

	if (pss->authed)
		txn = !li_store_begin(vhd);

	m = lejp_parse(&pss->ctx, in, (int)len);

	if (txn)
		li_store_commit(vhd, pss->src, lws_log_ship_utc_us(),
				pss->lag);

	if (m < 0 && m != LEJP_CONTINUE) {
		lwsl_vhost_warn(vhd->vh, "shipper message bad: %s",
				lejp_error_to_string(m));
		return -1;
	}

	if (!lws_is_final_fragment(wsi))
		return 0;

	if (m == LEJP_CONTINUE) {
		lwsl_vhost_warn(vhd->vh, "shipper message ended mid-JSON");
		return -1;
	}
	lejp_destruct(&pss->ctx);

	if (!strcmp(pss->schema, "lws-log-ship-hello")) {
		if (pss->authed)
			return -1;
		return li_hello(vhd, pss);
	}

	if (!pss->authed || strcmp(pss->schema, "lws-log-ship-lines"))
		return -1;

	now = lws_log_ship_utc_us();
	if (pss->bad) {
		lws_snprintf(say, sizeof(say), "log-ingest: refused %u "
			     "malformed lines", pss->bad);
		li_store_say(vhd, pss->src, now, say);
	}

	/*
	 * The ack only has to say the latest.  Lines we refused won't do any
	 * better sent again; but if we couldn't store anything, we say nothing
	 * and the shipper sends it all again later.
	 */
	if (pss->max_seq && txn) {
		pss->ack_seq = pss->max_seq;
		pss->ack_pending = 1;
		lws_callback_on_writable(wsi);
	}

	return 0;
}

static int
li_ws_tx(struct pss *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 256], *start = buf + LWS_PRE;
	size_t n;

	if (pss->ack_pending) {
		n = (size_t)lws_snprintf((char *)start, sizeof(buf) - LWS_PRE,
				"{\"schema\":\"lws-log-ship-ack\",\"seq\":%llu}",
				(unsigned long long)pss->ack_seq);
		pss->ack_pending = 0;
	} else if (pss->window_pending) {
		if (pss->sent.until_us)
			n = (size_t)lws_snprintf((char *)start,
				sizeof(buf) - LWS_PRE,
				"{\"schema\":\"lws-log-ship-start\","
				"\"session\":\"%s\",\"from\":%llu,"
				"\"until\":%llu,\"lvl\":%d}", pss->sent.session,
				(unsigned long long)pss->sent.from_us,
				(unsigned long long)pss->sent.until_us,
				pss->sent.lvl);
		else
			n = (size_t)lws_snprintf((char *)start,
				sizeof(buf) - LWS_PRE,
				"{\"schema\":\"lws-log-ship-stop\"}");
		pss->window_pending = 0;
	} else
		return 0;

	if (lws_write(wsi, start, n, LWS_WRITE_TEXT) != (int)n)
		return -1;

	if (pss->ack_pending || pss->window_pending)
		lws_callback_on_writable(wsi);

	return 0;
}

static int
li_pvo_uint(const struct lws_protocol_vhost_options *pvo, const char *name,
	    unsigned int *v)
{
	const char *p;
	uint64_t u;

	if (lws_pvo_get_str((void *)pvo, name, &p))
		return 0;

	if (li_u64(p, &u) || !u || u > 0x7fffffff) {
		lwsl_err("%s: bad pvo %s '%s'\n", __func__, name, p);
		return 1;
	}
	*v = (unsigned int)u;

	return 0;
}

static int
li_init(struct lws *wsi, const struct lws_protocol_vhost_options *pvo)
{
	struct vhd *vhd;
	unsigned int days = LI_RETENTION_DAYS_DEF;
	const char *p, *db;

	vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					  lws_get_protocol(wsi), sizeof(*vhd));
	if (!vhd)
		return -1;

	vhd->cx = lws_get_context(wsi);
	vhd->vh = lws_get_vhost(wsi);
	vhd->service = LI_SERVICE_DEF;
	vhd->rate_lines = LI_RATE_LINES_DEF;
	vhd->max_session_secs = LI_MAX_SESSION_SECS_DEF;
	vhd->max_past_secs = LI_MAX_PAST_SECS_DEF;

	if (lws_pvo_get_str((void *)pvo, "database", &db) ||
	    lws_pvo_get_str((void *)pvo, "secret", &vhd->secret) ||
	    !vhd->secret[0] || strlen(vhd->secret) > LI_SECRET_MAX) {
		lwsl_vhost_err(vhd->vh, "lws-log-ingest needs pvos database, "
			       "and secret of 1 to %u chars", LI_SECRET_MAX);
		return -1;
	}

	if (!lws_pvo_get_str((void *)pvo, "service", &p))
		vhd->service = p;
	if (!lws_pvo_get_str((void *)pvo, "always", &vhd->always) &&
	    !li_valid_src(vhd->always)) {
		lwsl_vhost_err(vhd->vh, "bad pvo always '%s'", vhd->always);
		return -1;
	}
	if (!lws_pvo_get_str((void *)pvo, "trust-login-headers", &p))
		vhd->trust_login_headers = !!atoi(p);

	if (li_pvo_uint(pvo, "retention-days", &days) ||
	    li_pvo_uint(pvo, "rate-lines", &vhd->rate_lines) ||
	    li_pvo_uint(pvo, "max-session-secs", &vhd->max_session_secs) ||
	    li_pvo_uint(pvo, "max-past-secs", &vhd->max_past_secs))
		return -1;
	vhd->retention_us = (uint64_t)days * LI_US_PER_DAY;

	if (li_store_open(vhd, db))
		return -1;

	li_store_sessions_load(vhd);

	lws_sul_schedule(vhd->cx, 0, &vhd->sul_expire, li_store_expire_cb,
			 10 * LWS_US_PER_SEC);

	/*
	 * Our own lines are a source too, unless this process already ships
	 * its lines somewhere
	 */
	if (lws_log_ship_get())
		lwsl_vhost_notice(vhd->vh, "this process' lines already go to "
				  "its shipper, as %s, not kept here as well",
				  lws_log_ship_host(lws_log_ship_get()));
	else if (lws_pvo_get_str((void *)pvo, "own-logs", &p) || atoi(p)) {
		struct lws_log_ship_info i;

		memset(&i, 0, sizeof(i));
		i.vhost		= vhd->vh;
		i.kind		= "lws-log-ingest";
		if (!lws_pvo_get_str((void *)pvo, "own-kind", &p))
			i.kind	= p;
		i.store		= li_own_store;
		i.opaque	= vhd;
		vhd->own = lws_log_ship_create(&i);
		if (vhd->own) {
			lws_strncpy(vhd->own_kind, i.kind,
				    sizeof(vhd->own_kind));
			lws_strncpy(vhd->own_host,
				    lws_log_ship_host(vhd->own),
				    sizeof(vhd->own_host));
		}
	}

	li_windows_update(vhd);

	lwsl_vhost_notice(vhd->vh, "lines in %s, kept %u days, %u sessions "
			  "open", db, days, (unsigned int)vhd->sessions.count);

	return 0;
}

static void
li_destroy(struct vhd *vhd)
{
	lws_sul_cancel(&vhd->sul_expire);
	lws_sul_cancel(&vhd->sul_sessions);

	/* our own shipper went with the vhost, before its protocols */
	vhd->own = NULL;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&vhd->sessions)) {
		li_session_t *s = lws_container_of(d, li_session_t, list);

		lws_dll2_remove(&s->list);
		free(s);
	} lws_end_foreach_dll_safe(d, d1);

	li_store_close(vhd);
}

static int
callback_lws_log_ingest(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi), lws_get_protocol(wsi));
	struct pss *pss = (struct pss *)user;
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;
		return li_init(wsi, (const struct lws_protocol_vhost_options *)in);

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			li_destroy(vhd);
		break;

	/* a shipper */

	case LWS_CALLBACK_ESTABLISHED:
		if (!vhd)
			return -1;
		memset(pss, 0, sizeof(*pss));
		pss->vhd = vhd;
		pss->wsi = wsi;
		/* it has a little while to say hello */
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, 10);
		break;

	case LWS_CALLBACK_RECEIVE:
		if (!vhd || li_ws_rx(vhd, pss, wsi, in, len))
			return -1;
		if (pss->authed)
			lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		return li_ws_tx(pss, wsi);

	case LWS_CALLBACK_CLOSED:
		if (pss->authed)
			lwsl_vhost_notice(vhd->vh, "shipper %s %s, inst %s "
					  "went", pss->kind, pss->host,
					  pss->inst);
		lws_dll2_remove(&pss->list);
		break;

	/* the api */

	case LWS_CALLBACK_HTTP:
		if (!vhd)
			return -1;
		memset(pss, 0, sizeof(*pss));
		pss->vhd = vhd;
		pss->wsi = wsi;
		pss->is_http = 1;
		{
			const struct lws_http_mount *hit;
			char *uri;
			int ul, meth;

			/*
			 * Our route is what's after our mount, whatever the
			 * method: lws gives a GET the whole uri
			 */
			meth = lws_http_get_uri_and_method(wsi, &uri, &ul);
			if (meth < 0 || !uri)
				return -1;
			hit = lws_find_mount(wsi, uri, ul);
			if (hit && ul >= hit->mountpoint_len) {
				uri += hit->mountpoint_len;
				ul -= hit->mountpoint_len;
			}
			if ((size_t)ul >= sizeof(pss->route))
				n = HTTP_STATUS_NOT_FOUND;
			else {
				memcpy(pss->route, uri, (size_t)ul);
				pss->route[ul] = '\0';
				if (meth == LWSHUMETH_POST)
					/* the body comes next */
					return 0;
				n = li_api_http(vhd, pss, wsi, pss->route, 0);
			}
		}
		goto http_status;

	case LWS_CALLBACK_HTTP_BODY:
		if (!pss->is_http || pss->body_len + len > 4096)
			return -1;
		{
			char *nb = realloc(pss->body, pss->body_len + len + 1);

			if (!nb)
				return -1;
			pss->body = nb;
		}
		memcpy(pss->body + pss->body_len, in, len);
		pss->body_len += len;
		pss->body[pss->body_len] = '\0';
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!pss->is_http)
			return -1;
		n = li_api_http(vhd, pss, wsi, pss->route, 1);
		goto http_status;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->sending)
			break;
		return li_api_writeable(pss, wsi);

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && pss->is_http)
			li_api_close(pss);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

http_status:
	if (n < 0)
		return -1;
	if (n > 0) {
		li_api_close(pss);
		if (lws_return_http_status(wsi, (unsigned int)n, NULL))
			return -1;
		return lws_http_transaction_completed(wsi);
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_LOG_INGEST \
	{ \
		LWS_LOG_SHIP_WS_PROTOCOL, \
		callback_lws_log_ingest, \
		sizeof(struct pss), \
		4096, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_log_ingest_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_LOG_INGEST
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_log_ingest = {
	.hdr = {
		.name = "lws log ingest",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_log_ingest_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_log_ingest_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
