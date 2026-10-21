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
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>

/* the most a message from a shipper may be, whatever it claims */
#define LI_MSG_MAX		(256 * 1024)
#define LI_KIND_MAX		32
#define LI_HOST_MAX		64
#define LI_SECRET_MAX		256
#define LI_SESSION_LEN		16	/* hex */
#define LI_SRC_MAX		200	/* a session's src= */
#define LI_NOTE_MAX		200
#define LI_WHO_MAX		128
#define LI_TAG_MAX		32
/* a line's time may be this far from ours */
#define LI_SKEW_MAX_US		(24ll * 3600 * LWS_US_PER_SEC)

typedef struct li_session {
	lws_dll2_t		list;		/* vhd->sessions, the open ones */
	uint64_t		from_us;
	uint64_t		until_us;
	int			lvl;
	char			id[LI_SESSION_LEN + 1];
	char			src[LI_SRC_MAX + 1];
} li_session_t;

/* the window we last gave a shipper */

typedef struct li_window {
	uint64_t		from_us;
	uint64_t		until_us;
	int			lvl;
	char			session[LI_SESSION_LEN + 1];
} li_window_t;

/* what we know of a source while we're hearing from it */

typedef struct li_src {
	lws_dll2_t		list;		/* vhd->srcs, most recent first */
	int64_t			src_id;
	uint64_t		rate_start_us;
	unsigned int		rate_lines;
	unsigned int		over_rate;
	char			inst[17];
	char			kind[LI_KIND_MAX + 1];
	char			host[LI_HOST_MAX + 1];
} li_src_t;

struct vhd {
	struct lws_context	*cx;
	struct lws_vhost	*vh;
	sqlite3			*pdb;
	sqlite3_stmt		*sm_line;	/* in a transaction */
	sqlite3_stmt		*sm_tag;
	struct lws_log_ship	*own;		/* our own lines, if we may */

	lws_dll2_owner_t	shippers;	/* struct pss, authenticated */
	lws_dll2_owner_t	sessions;	/* li_session_t, open */
	lws_dll2_owner_t	srcs;		/* li_src_t */

	lws_sorted_usec_list_t	sul_expire;	/* old lines */
	lws_sorted_usec_list_t	sul_sessions;	/* the next session ends */

	li_window_t		own_window;
	char			own_kind[LI_KIND_MAX + 1];
	char			own_host[LI_HOST_MAX + 1];

	const char		*secret;
	const char		*service;	/* the lws-login grant */
	const char		*always;	/* sources always in a window */
	uint64_t		retention_us;
	unsigned int		rate_lines;	/* per source per minute */
	unsigned int		max_session_secs;
	unsigned int		max_past_secs;
	char			trust_login_headers;
};

/* a line from a shipper, while it's being parsed */

typedef struct li_line {
	uint64_t		seq;
	uint64_t		t;
	size_t			xlen;
	size_t			glen;
	int			l;
	char			x[LWS_LOG_SHIP_LINE_MAX + 1];
	char			g[LI_TAG_MAX + 1];	/* its tag, or "" */
	char			have;		/* which members we saw */
	char			bad;
} li_line_t;

struct pss {
	lws_dll2_t		list;		/* vhd->shippers */
	struct vhd		*vhd;
	struct lws		*wsi;

	/* a shipper */
	struct lejp_ctx		ctx;
	li_src_t		*src;		/* once it said hello */
	li_line_t		line;
	li_window_t		sent;		/* the window we last sent */
	char			schema[32];
	char			secret[LI_SECRET_MAX + 1];
	char			kind[LI_KIND_MAX + 1];
	char			host[LI_HOST_MAX + 1];
	char			inst[17];
	size_t			slen;		/* of the string being parsed */
	uint64_t		msg_len;
	uint64_t		ack_seq;
	uint64_t		max_seq;	/* in the message being parsed */
	int64_t			lag;		/* of the message being parsed */
	unsigned int		bad;		/* lines refused in it */
	char			in_tx;		/* a transaction is open */
	char			authed;
	char			ack_pending;
	char			window_pending;
	char			parse_failed;

	/* an http request */
	struct lws_buflist	*tx;
	char			*body;
	size_t			body_len;
	char			sending;
	char			is_http;
	char			route[64];
};

/* ingest-store.c */

int
li_store_open(struct vhd *vhd, const char *path);
void
li_store_close(struct vhd *vhd);
li_src_t *
li_store_src(struct vhd *vhd, const char *kind, const char *host,
	     const char *inst, uint64_t now);
int
li_store_begin(struct vhd *vhd);
int
li_store_line(struct vhd *vhd, li_src_t *src, uint64_t seq, uint64_t t,
	      uint64_t now, int lvl, const char *x, size_t xlen,
	      const char *tag);
int
li_valid_tag(const char *s);
int
li_valid_src(const char *s);
void
li_store_say(struct vhd *vhd, li_src_t *src, uint64_t now, const char *line);
void
li_store_commit(struct vhd *vhd, li_src_t *src, uint64_t now, int64_t lag);
void
li_store_expire_cb(lws_sorted_usec_list_t *sul);
int
li_store_sessions_load(struct vhd *vhd);
int
li_store_session_add(struct vhd *vhd, const li_session_t *s,
		     const char *who, const char *note, uint64_t now);
int
li_store_session_stop(struct vhd *vhd, const char *id, uint64_t now);

/* protocol_lws_log_ingest.c */

int
li_valid_name(const char *s, size_t max);
int
li_src_matches(const char *src, const char *kind, const char *host);
void
li_windows_update(struct vhd *vhd);
void
li_own_store(void *opaque, const char *kind, const char *host,
	     const char *inst, const lws_log_ship_line_t *lines,
	     size_t count);

/* ingest-api.c */

int
li_api_http(struct vhd *vhd, struct pss *pss, struct lws *wsi,
	    const char *path, int is_post);
int
li_api_writeable(struct pss *pss, struct lws *wsi);
void
li_api_close(struct pss *pss);
