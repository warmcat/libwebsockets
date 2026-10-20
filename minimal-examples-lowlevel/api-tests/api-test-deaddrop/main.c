/*
 * lws-api-test-deaddrop
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Drives the lws-deaddrop plugin, built in, over http and ws as two basic
 * auth users, "bob" and "bob_smith", whose names share the prefix "bob".
 * lws is both ends, in one process.
 *
 *  - bob_smith uploads "notes.txt", then bob uploads "smith_notes.txt"; the
 *    second upload must not land on the first (G-274)
 *
 *  - 30 ws sessions as bob_smith and one as bob: every one of them must get
 *    complete, well-formed listings, ending with all 31 users and all the
 *    files, with each file owned by exactly the user who uploaded it (G-275,
 *    G-274)
 *
 *  - bob asks to delete bob_smith's file: refused (G-274)
 *
 *  - bob sends a del of his own file truncated before its closing quote, after
 *    a message of the same length that left the closing quote in the rx
 *    buffer, and some short del frames: all ignored (G-276)
 *
 *  - bob deletes his own file properly: done, and bob_smith's file survives
 *
 *  - bob uploads x.html, x.svg and x.js, and bob_smith downloads them from
 *    get/: each must come back as an application/octet-stream attachment,
 *    with nosniff and a sandboxing CSP, never as active content (G-282)
 *
 *  - the plugin is given its upload dir as a relative path, through a
 *    symlink and with a trailing '/', which it must resolve itself for any of
 *    the above to work (G-308); and a stored name that is a symlink to a file
 *    outside it, beside the dir with the dir's name as its prefix, must not
 *    be served (G-282)
 *
 *  - on mounts that have no basic auth of their own, an upload claiming
 *    "Authorization: bob" and a download claiming "Authorization: bob_smith"
 *    are just unauthenticated, ie 403, although the vhost gave the plugin the
 *    "basic-auth" pvo (G-309)
 *
 *  - users from JWT session cookies: two 64-byte names that differ only in
 *    the last byte are two owners, a 127-byte name is a user (G-307); and
 *    "Bob" stores as "=42ob", so on a case-insensitive filesystem it can't
 *    share files with "bob" (G-307)
 */

#include <libwebsockets.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_deaddrop.c"

#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define NUM_WS		31	/* [0] is bob, the rest are bob_smith */
#define RX_MAX		16384
#define MAX_FILES	16
#define MAX_TX		8

#define SMITH_CONTENT	"bob_smith's notes\n"
#define BOB_CONTENT	"bob's notes, overwriting\n"
#define LEGACY_NAME	"bob_legacy.txt"
/* a symlink in the upload dir to a file outside it */
#define ESCAPE_NAME	"bob_escape.txt"
/*
 * the plugin is told the upload dir is here: relative, through a symlink in
 * the test's working dir, and with a trailing '/'
 */
#define UPLOAD_LINK	"dd-upload-link"

enum {
	ST_UPLOAD_SMITH,
	ST_UPLOAD_BOB,
	ST_WS_LISTINGS,
	ST_ATTACKS,
	ST_ATTACKS_SETTLE,
	ST_OWN_DEL,
	ST_UPLOAD_ACTIVE,
	ST_DOWNLOADS,
	ST_DONE
};

struct upload {
	const char		*user;
	const char		*pass;
	const char		*filename;
	const char		*content;
	const char		*path;		/* NULL: "/upload/" */
	const char		*forge;		/* raw Authorization: instead */
	const char		*stored;	/* NULL, or name it is stored as */
	const char		*sub;		/* JWT session as sub instead */
	int			expect_status;	/* 0: 200 */

	char			cookie[1024];

	int			status;
	int			part;
	char			started;
	char			done;
};

struct download {
	const char		*name;		/* stored name */
	const char		*mount;		/* NULL: "/get" */
	const char		*forge;		/* raw Authorization: instead */
	int			expect_status;
	const char		*expect_cd;	/* expected Content-Disposition */
	const char		*expect_body;

	int			status;
	char			ct[64];
	char			cd[256];
	char			nosniff[32];
	char			csp[64];
	char			body[128];
	size_t			body_len;
	char			started;
	char			done;
};

struct listing_file {
	char			name[256];
	char			uploader[64];
	unsigned long long	size;
	int			yours;
};

struct ws_client {
	struct lws		*wsi;
	const char		*user;
	const char		*pass;

	/* the message being reassembled */
	char			rx[RX_MAX];
	size_t			rx_len;
	char			in_msg;
	char			rx_overflow;

	/* from the newest listing message carrying each part */
	int			users;
	struct listing_file	files[MAX_FILES];
	int			nfiles;
	int			listings;

	/* ws messages queued to send, one per writeable */
	char			tx[MAX_TX][300];
	int			tx_head, tx_tail;

	char			established;
	char			closed;
};

#define HTML_CONTENT	"<html><script>alert(1)</script></html>\n"
#define SVG_CONTENT	"<svg xmlns=\"http://www.w3.org/2000/svg\">" \
			"<script>alert(1)</script></svg>\n"
#define JS_CONTENT	"alert(1);\n"

/* 63 bytes, so A63 "x" is as long as an auth server username may be */
#define A63		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define C63		"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

static struct upload uploads[] = {
	{ .user = "bob_smith", .pass = "smith-password",
	  .filename = "notes.txt", .content = SMITH_CONTENT },
	{ .user = "bob", .pass = "bob-password",
	  .filename = "smith_notes.txt", .content = BOB_CONTENT },
	/* active content, for the downloads */
	{ .user = "bob", .pass = "bob-password",
	  .filename = "x.html", .content = HTML_CONTENT },
	{ .user = "bob", .pass = "bob-password",
	  .filename = "x.svg", .content = SVG_CONTENT },
	{ .user = "bob", .pass = "bob-password",
	  .filename = "x.js", .content = JS_CONTENT },
	/* a claimed, unauthenticated identity on a mount with no basic auth */
	{ .filename = "forged.txt", .content = "forged\n",
	  .path = "/open/upload/", .forge = "bob", .stored = "bob_forged.txt",
	  .expect_status = 403 },
	/*
	 * JWT session users, who need no basic auth mount: two names that
	 * only differ in their 64th byte, and the longest a sub can be
	 */
	{ .filename = "long.txt", .content = "x\n", .path = "/open/upload/",
	  .sub = A63 "x", .stored = A63 "x_long.txt" },
	{ .filename = "long.txt", .content = "y\n", .path = "/open/upload/",
	  .sub = A63 "y", .stored = A63 "y_long.txt" },
	{ .filename = "max.txt", .content = "c\n", .path = "/open/upload/",
	  .sub = C63 C63 "c", .stored = C63 C63 "c_max.txt" },
	/* upper case is encoded, so "Bob" never shares names with "bob" */
	{ .filename = "case.txt", .content = "Bob\n", .path = "/open/upload/",
	  .sub = "Bob", .stored = "=42ob_case.txt" },
};

static struct download downloads[] = {
	{ .name = "bob_x.html", .expect_status = 200,
	  .expect_cd = "attachment; filename=\"x.html\"; "
		       "filename*=UTF-8''x.html",
	  .expect_body = HTML_CONTENT },
	{ .name = "bob_x.svg", .expect_status = 200,
	  .expect_cd = "attachment; filename=\"x.svg\"; "
		       "filename*=UTF-8''x.svg",
	  .expect_body = SVG_CONTENT },
	{ .name = "bob_x.js", .expect_status = 200,
	  .expect_cd = "attachment; filename=\"x.js\"; "
		       "filename*=UTF-8''x.js",
	  .expect_body = JS_CONTENT },
	{ .name = "bob_missing.html", .expect_status = 404 },
	{ .name = ESCAPE_NAME, .expect_status = 404 },
	/* a claimed, unauthenticated identity on a mount with no basic auth */
	{ .name = "bob_x.html", .mount = "/open/get", .forge = "bob_smith",
	  .expect_status = 403 },
};
static int upload_idx, download_idx;

static struct ws_client wsc[NUM_WS];
static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_tick, sul_watchdog;
static const char *server_addr = "localhost";
static char upload_dir[PATH_MAX]; /* canonical, for our own checks */
static int port = 7681, state, result = 1, failed, settle;

/* parsing a listing message */

static const char * const listing_paths[] = {
	"connected_users[].user",
	"files[].name",
	"files[].uploader",
	"files[].size",
	"files[].yours",
};

enum {
	LP_USER = 1,
	LP_FILE_NAME,
	LP_FILE_UPLOADER,
	LP_FILE_SIZE,
	LP_FILE_YOURS,
};

struct listing_parse {
	int			users;
	struct listing_file	files[MAX_FILES];
	int			nfiles;
	char			has_users;
	char			has_files;
	char			bad;
};

static signed char
listing_cb(struct lejp_ctx *ctx, char reason)
{
	struct listing_parse *lp = (struct listing_parse *)ctx->user;
	struct listing_file *f = NULL;
	int idx;

	if (reason == LEJPCB_PAIR_NAME) {
		if (!strcmp(ctx->path, "connected_users"))
			lp->has_users = 1;
		if (!strcmp(ctx->path, "files"))
			lp->has_files = 1;
		return 0;
	}

	if (!ctx->path_match || !(reason & LEJP_FLAG_CB_IS_VALUE))
		return 0;

	if (ctx->path_match == LP_USER) {
		if (reason == LEJPCB_VAL_STR_END)
			lp->users++;
		return 0;
	}

	idx = ctx->ipos ? ctx->i[ctx->ipos - 1] : 0;
	if (idx >= MAX_FILES) {
		lp->bad = 1;
		return 0;
	}
	if (idx + 1 > lp->nfiles)
		lp->nfiles = idx + 1;
	f = &lp->files[idx];

	switch (ctx->path_match) {
	case LP_FILE_NAME:
		if (reason == LEJPCB_VAL_STR_END)
			lws_strncpy(f->name, ctx->buf, sizeof(f->name));
		else
			lp->bad = 1; /* longer than we ever store */
		break;
	case LP_FILE_UPLOADER:
		if (reason == LEJPCB_VAL_STR_END)
			lws_strncpy(f->uploader, ctx->buf,
				    sizeof(f->uploader));
		break;
	case LP_FILE_SIZE:
		f->size = (unsigned long long)atoll(ctx->buf);
		break;
	case LP_FILE_YOURS:
		f->yours = atoi(ctx->buf);
		break;
	}

	return 0;
}

static void
fail(const char *why, int idx)
{
	lwsl_err("FAIL: %s (ws %d)\n", why, idx);
	failed = 1;
}

static void
listing_message(struct ws_client *c)
{
	struct listing_parse lp;
	struct lejp_ctx ctx;
	int m;

	memset(&lp, 0, sizeof(lp));
	lejp_construct(&ctx, listing_cb, &lp, listing_paths,
		       LWS_ARRAY_SIZE(listing_paths));
	m = lejp_parse(&ctx, (const uint8_t *)c->rx, (int)c->rx_len);
	lejp_destruct(&ctx);

	if (m < 0 || lp.bad) {
		lwsl_err("%s: bad listing (%d): %.*s\n", __func__, m,
			 (int)c->rx_len, c->rx);
		fail("malformed listing", (int)(c - wsc));
		return;
	}

	c->listings++;
	if (lp.has_users)
		c->users = lp.users;
	if (lp.has_files) {
		memcpy(c->files, lp.files, sizeof(c->files));
		c->nfiles = lp.nfiles;
	}
}

static int
is_ws(const void *opaque)
{
	return (const struct ws_client *)opaque >= wsc &&
	       (const struct ws_client *)opaque < wsc + NUM_WS;
}

static int
is_dl(const void *opaque)
{
	return (const struct download *)opaque >= downloads &&
	       (const struct download *)opaque <
				downloads + LWS_ARRAY_SIZE(downloads);
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct ws_client *c = (struct ws_client *)lws_get_opaque_user_data(wsi);
	struct upload *u = (struct upload *)lws_get_opaque_user_data(wsi);
	struct download *dl = (struct download *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	char rbuf[LWS_PRE + 256], *rp = rbuf + LWS_PRE;
	int rlen = (int)sizeof(rbuf) - LWS_PRE, n;
	char b[128];

	switch (reason) {

	/* both the uploads and the ws sessions authenticate as their user */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **pp = (unsigned char **)in, *e = (*pp) + len;
		int ws = is_ws(c), d = is_dl(dl);
		const char *forge = ws ? NULL : (d ? dl->forge : u->forge);

		if (!ws && !d && u->sub) {
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_COOKIE,
					(unsigned char *)u->cookie,
					(int)strlen(u->cookie), pp, e))
				return -1;
		} else if (forge) {
			/* a bare name, as if something had validated it */
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_AUTHORIZATION,
					(unsigned char *)forge,
					(int)strlen(forge), pp, e))
				return -1;
		} else
			/* bob_smith fetches the downloads */
			if (lws_http_basic_auth_gen(ws ? c->user :
					    (d ? "bob_smith" : u->user),
					    ws ? c->pass :
					    (d ? "smith-password" : u->pass),
					    b, sizeof(b)) ||
			    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_AUTHORIZATION,
				(unsigned char *)b, (int)strlen(b), pp, e))
				return -1;

		if (!ws && !d) {
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;
	}

	/* the upload POSTs */

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!u || is_ws(u) || is_dl(u))
			return 0;
		n = LWS_WRITE_HTTP;
		switch (u->part++) {
		case 0:
			if (lws_client_http_multipart(wsi, "file", u->filename,
						      "text/plain",
						      (char **)&p,
						      (char *)end))
				return -1;
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
					  "%s", u->content);
			break;
		case 1:
			if (lws_client_http_multipart(wsi, NULL, NULL, NULL,
						      (char **)&p,
						      (char *)end))
				return -1;
			lws_client_http_body_pending(wsi, 0);
			n = LWS_WRITE_HTTP_FINAL;
			break;
		default:
			return 0;
		}

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      (enum lws_write_protocol)n) !=
						lws_ptr_diff(p, start))
			return -1;
		if (n != LWS_WRITE_HTTP_FINAL)
			lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (is_dl(dl)) {
			dl->status = (int)lws_http_client_http_response(wsi);
			if (lws_hdr_copy(wsi, dl->ct, sizeof(dl->ct),
					 WSI_TOKEN_HTTP_CONTENT_TYPE) < 0)
				dl->ct[0] = '\0';
			if (lws_hdr_copy(wsi, dl->cd, sizeof(dl->cd),
					 WSI_TOKEN_HTTP_CONTENT_DISPOSITION) < 0)
				dl->cd[0] = '\0';
			if (lws_hdr_custom_copy(wsi, dl->nosniff,
					sizeof(dl->nosniff),
					"x-content-type-options:", 23) < 0)
				dl->nosniff[0] = '\0';
			if (lws_hdr_custom_copy(wsi, dl->csp, sizeof(dl->csp),
					"content-security-policy:", 24) < 0)
				dl->csp[0] = '\0';
			break;
		}
		if (u && !is_ws(u))
			u->status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &rp, &rlen) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (is_dl(dl)) {
			if (len > sizeof(dl->body) - 1 - dl->body_len)
				len = sizeof(dl->body) - 1 - dl->body_len;
			memcpy(dl->body + dl->body_len, in, len);
			dl->body_len += len;
			dl->body[dl->body_len] = '\0';
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (is_dl(dl)) {
			dl->done = 1;
			break;
		}
		if (u && !is_ws(u) && !u->done) {
			u->done = 1;
			lwsl_user("upload '%s' as %s: %d\n", u->filename,
				  u->sub ? u->sub : (u->forge ? u->forge :
				  u->user), u->status);
		}
		break;

	/* the ws sessions */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		c->established = 1;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (lws_is_first_fragment(wsi)) {
			if (c->in_msg)
				/*
				 * A new message started inside one that never
				 * got its FIN
				 */
				fail("message restarted before FIN",
				     (int)(c - wsc));
			c->rx_len	= 0;
			c->rx_overflow	= 0;
			c->in_msg	= 1;
		}
		if (!c->in_msg) {
			fail("continuation outside a message", (int)(c - wsc));
			break;
		}
		if (len > sizeof(c->rx) - c->rx_len)
			c->rx_overflow = 1;
		else {
			memcpy(c->rx + c->rx_len, in, len);
			c->rx_len += len;
		}
		if (!lws_is_final_fragment(wsi))
			break;
		c->in_msg = 0;
		if (c->rx_overflow) {
			fail("listing message too large", (int)(c - wsc));
			break;
		}
		listing_message(c);
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (c->tx_tail == c->tx_head)
			break;
		n = (int)strlen(c->tx[c->tx_tail]);
		memcpy(start, c->tx[c->tx_tail], (size_t)n);
		c->tx_tail = (c->tx_tail + 1) % MAX_TX;
		if (lws_write(wsi, start, (size_t)n, LWS_WRITE_TEXT) != n)
			return -1;
		if (c->tx_tail != c->tx_head)
			lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "");
		/* fallthru */
	case LWS_CALLBACK_CLIENT_CLOSED:
		if (is_ws(c)) {
			c->wsi = NULL;
			c->closed = 1;
			if (state != ST_DONE)
				fail("ws session closed", (int)(c - wsc));
		} else if (is_dl(dl)) {
			dl->done = 1;
			dl->status = -1;
		} else if (u && !u->done) {
			u->done = 1;
			u->status = -1;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_cli[] = {
	{ "dd-test-client", callback_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_srv[] = {
	LWS_PLUGIN_PROTOCOL_DEADDROP,
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The same plugin mounts without basic auth of their own: only an identity
 * lws actually authenticated may be believed there, and there is none
 */

static struct lws_http_mount mount_open_get = {
	.mountpoint		= "/open/get",
	.protocol		= "lws-deaddrop",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 9,
};

static struct lws_http_mount mount_open_upload = {
	.mount_next		= &mount_open_get,
	.mountpoint		= "/open/upload",
	.protocol		= "lws-deaddrop",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 12,
};

/* deaddrop serves the downloads itself */

static struct lws_http_mount mount_get = {
	.mount_next		= &mount_open_upload,
	.mountpoint		= "/get",
	.protocol		= "lws-deaddrop",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

static struct lws_http_mount mount_upload = {
	.mount_next		= &mount_get,
	.mountpoint		= "/upload",
	.protocol		= "lws-deaddrop",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 7,
};

/* a throwaway HS256 key, that the session tokens here are signed with */
static const char dd_jwk[] =
	"{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}";

static struct lws_protocol_vhost_options pvo_jwk = {
	NULL, NULL, "jwt-jwk", dd_jwk
}, pvo_ba = {
	&pvo_jwk, NULL, "basic-auth", NULL /* set from --passwords */
}, pvo_dir = {
	&pvo_ba, NULL, "upload-dir", "./" UPLOAD_LINK "/"
}, pvo = {
	NULL, &pvo_dir, "lws-deaddrop", ""
};

static void
queue_tx(struct ws_client *c, const char *msg)
{
	lws_strncpy(c->tx[c->tx_head], msg, sizeof(c->tx[0]));
	c->tx_head = (c->tx_head + 1) % MAX_TX;
	if (c->wsi)
		lws_callback_on_writable(c->wsi);
}

/* the session cookie for u->sub, as the auth server mints them */

static int
mint_cookie(struct upload *u)
{
	unsigned long long now = (unsigned long long)lws_now_secs();
	char tok[768], temp[2048];
	size_t tok_len = sizeof(tok);
	struct lws_jwk jwk;
	int r;

	if (lws_jwk_import(&jwk, NULL, NULL, dd_jwk, strlen(dd_jwk)))
		return 1;

	r = lws_jwt_sign_compact(context, &jwk, "HS256", tok, &tok_len, temp,
				 (int)sizeof(temp),
				 "{\"iss\":\"apitest\",\"pur\":\""
				 LWS_JWT_AUTH_PURPOSE_SSO "\",\"sub\":\"%s\","
				 "\"uid\":1,\"iat\":%llu,\"exp\":%llu}",
				 u->sub, now, now + 600);
	lws_jwk_destroy(&jwk);
	if (r)
		return 1;

	return lws_snprintf(u->cookie, sizeof(u->cookie), "auth_session=%s",
			    tok) >= (int)sizeof(u->cookie);
}

static int
start_upload(struct upload *u)
{
	struct lws_client_connect_info i;

	if (u->sub && mint_cookie(u))
		return 1;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.path			= u->path ? u->path : "/upload/";
	i.method		= "POST";
	i.ssl_connection	= LCCSCF_HTTP_MULTIPART_MIME;
	i.protocol		= "dd-test-client";
	i.local_protocol_name	= "dd-test-client";
	i.opaque_user_data	= u;

	return !lws_client_connect_via_info(&i);
}

static int
start_download(struct download *d)
{
	struct lws_client_connect_info i;
	char path[300];

	lws_snprintf(path, sizeof(path), "%s/%s", d->mount ? d->mount : "/get",
		     d->name);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.port			= port;
	i.path			= path;
	i.method		= "GET";
	i.protocol		= "dd-test-client";
	i.local_protocol_name	= "dd-test-client";
	i.opaque_user_data	= d;

	return !lws_client_connect_via_info(&i);
}

static int file_exists(const char *name);

static int
check_upload(const struct upload *u)
{
	int expect = u->expect_status ? u->expect_status : 200;

	if (u->status != expect) {
		lwsl_err("%s: '%s': %d, expected %d\n", __func__, u->filename,
			 u->status, expect);
		return 1;
	}

	/* only an accepted upload may have stored anything */
	if (u->stored && file_exists(u->stored) != (expect == 200)) {
		lwsl_err("%s: '%s' %sstored as '%s'\n", __func__, u->filename,
			 expect == 200 ? "not " : "", u->stored);
		return 1;
	}

	return 0;
}

static int
check_download(const struct download *d)
{
	lwsl_user("get %s: %d, ct '%s', cd '%s', nosniff '%s', csp '%s'\n",
		  d->name, d->status, d->ct, d->cd, d->nosniff, d->csp);

	if (d->status != d->expect_status)
		return 1;
	if (d->expect_status != 200)
		return 0;

	return strcmp(d->ct, "application/octet-stream") ||
	       strcmp(d->cd, d->expect_cd) ||
	       strcmp(d->nosniff, "nosniff") ||
	       strcmp(d->csp, "sandbox; default-src 'none'") ||
	       strcmp(d->body, d->expect_body);
}

static int
start_ws(int n)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.port			= port;
	i.path			= "/";
	i.protocol		= "lws-deaddrop";
	i.local_protocol_name	= "dd-test-client";
	i.opaque_user_data	= &wsc[n];
	i.pwsi			= &wsc[n].wsi;

	return !lws_client_connect_via_info(&i);
}

static int
file_exists(const char *name)
{
	char path[PATH_MAX + 260];
	struct stat s;

	lws_snprintf(path, sizeof(path), "%s/%s", upload_dir, name);

	return !stat(path, &s);
}

static const struct listing_file *
find_yours(const struct ws_client *c, const char *content, int *count)
{
	const struct listing_file *r = NULL;
	int n;

	*count = 0;
	for (n = 0; n < c->nfiles; n++)
		if (c->files[n].yours) {
			(*count)++;
			if (c->files[n].size == strlen(content))
				r = &c->files[n];
		}

	return r;
}

static char smith_name[256], bob_name[256], attacks[6][300];
static int attack;

/*
 * Check the settled listings: everyone sees all the users and files, and each
 * file is "yours" to exactly its uploader
 */

static int
listings_settled(void)
{
	int n;

	for (n = 0; n < NUM_WS; n++)
		if (!wsc[n].established || wsc[n].in_msg ||
		    wsc[n].users != NUM_WS || wsc[n].nfiles != 3)
			return 0;

	return 1;
}

static void
check_listings(void)
{
	const struct listing_file *f;
	int n, count;

	for (n = 1; n < NUM_WS; n++) {
		f = find_yours(&wsc[n], SMITH_CONTENT, &count);
		if (!f || count != 1 || strcmp(f->uploader, "bob_smith")) {
			fail("bob_smith does not own exactly his one file", n);
			return;
		}
		if (n == 1)
			lws_strncpy(smith_name, f->name, sizeof(smith_name));
		else if (strcmp(smith_name, f->name)) {
			fail("sessions disagree on bob_smith's file", n);
			return;
		}
	}

	f = find_yours(&wsc[0], BOB_CONTENT, &count);
	if (!f || count != 2 || strcmp(f->uploader, "bob")) {
		fail("bob does not own exactly his upload and the legacy file",
		     0);
		return;
	}
	lws_strncpy(bob_name, f->name, sizeof(bob_name));

	for (n = 0; n < wsc[0].nfiles; n++)
		if (!strcmp(wsc[0].files[n].name, LEGACY_NAME) &&
		    (!wsc[0].files[n].yours ||
		     strcmp(wsc[0].files[n].uploader, "bob")))
			fail("legacy file not bob's", 0);

	lwsl_user("bob_smith's file '%s', bob's '%s'\n", smith_name, bob_name);
}

/*
 * A stored name that is a symlink to a file outside the upload dir, whose path
 * starts with the upload dir's own path ("<dir>x"), so only the '/' after the
 * dir in the resolved path tells it is outside.  It is planted only now, so the
 * listings earlier do not count it.
 */

static int
plant_escape(void)
{
	char outside[PATH_MAX + 4], path[PATH_MAX + 260];
	int fd;

	lws_snprintf(outside, sizeof(outside), "%sx", upload_dir);
	fd = open(outside, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, "outside\n", 8) != 8) {
		close(fd);
		return 1;
	}
	close(fd);

	lws_snprintf(path, sizeof(path), "%s/%s", upload_dir, ESCAPE_NAME);
	unlink(path);

	return symlink(outside, path);
}

static void
tick(lws_sorted_usec_list_t *sul)
{
	char msg[300];
	int n;

	if (failed)
		goto finish;

	switch (state) {
	case ST_UPLOAD_SMITH:
	case ST_UPLOAD_BOB:
		if (!uploads[state].started) {
			uploads[state].started = 1;
			if (start_upload(&uploads[state])) {
				fail("upload connect", -1);
				goto finish;
			}
			break;
		}
		if (!uploads[state].done)
			break;
		if (uploads[state].status != 200) {
			fail("upload refused", -1);
			goto finish;
		}
		state++;
		if (state == ST_WS_LISTINGS)
			for (n = 0; n < NUM_WS; n++)
				if (start_ws(n)) {
					fail("ws connect", n);
					goto finish;
				}
		break;

	case ST_WS_LISTINGS:
		if (!listings_settled())
			break;
		check_listings();
		if (failed)
			goto finish;

		/* bob tries to delete bob_smith's file */
		lws_snprintf(attacks[0], sizeof(attacks[0]),
			     "{\"del\":\"%s\"}", smith_name);

		/*
		 * The same length as the truncated del after it, so it leaves
		 * the del's missing closing quote and brace in the server's rx
		 * buffer right after the truncated del's payload
		 */
		lws_snprintf(attacks[1], sizeof(attacks[1]),
			     "{\"xxx\":\"%s\"}", bob_name);
		lws_snprintf(attacks[2], sizeof(attacks[2]),
			     "{\"del\":\"%s", bob_name);

		/* short del frames */
		lws_strncpy(attacks[3], "{\"del\":\"", sizeof(attacks[3]));
		lws_strncpy(attacks[4], "{\"del\":\"b", sizeof(attacks[4]));
		lws_strncpy(attacks[5], "{\"del\":\"bob_", sizeof(attacks[5]));
		attack = 0;
		state = ST_ATTACKS;
		break;

	case ST_ATTACKS:
		if (wsc[0].tx_tail != wsc[0].tx_head)
			break;
		/*
		 * One per tick, so each arrives at the server in a read of its
		 * own, on top of what the one before left in the buffer
		 */
		if (attack < (int)LWS_ARRAY_SIZE(attacks)) {
			queue_tx(&wsc[0], attacks[attack++]);
			break;
		}
		/* give the server some ticks to act on them */
		settle = 10;
		state = ST_ATTACKS_SETTLE;
		break;

	case ST_ATTACKS_SETTLE:
		if (--settle)
			break;
		if (!file_exists(smith_name)) {
			fail("bob deleted bob_smith's file", 0);
			goto finish;
		}
		if (!file_exists(bob_name)) {
			fail("truncated del was acted on", 0);
			goto finish;
		}

		lws_snprintf(msg, sizeof(msg), "{\"del\":\"%s\"}", bob_name);
		queue_tx(&wsc[0], msg);
		state = ST_OWN_DEL;
		break;

	case ST_OWN_DEL:
		/* everyone must see bob's file go, and only that */
		for (n = 0; n < NUM_WS; n++)
			if (wsc[n].nfiles != 2 || wsc[n].in_msg)
				goto again;
		if (file_exists(bob_name)) {
			fail("bob could not delete his own file", 0);
			goto finish;
		}
		if (!file_exists(smith_name)) {
			fail("bob_smith's file went too", 0);
			goto finish;
		}
		for (n = 0; n < NUM_WS; n++)
			if (wsc[n].closed) {
				fail("ws closed", n);
				goto finish;
			}
		upload_idx = ST_UPLOAD_BOB + 1;
		state = ST_UPLOAD_ACTIVE;
		break;

	case ST_UPLOAD_ACTIVE:
		if (upload_idx == (int)LWS_ARRAY_SIZE(uploads)) {
			if (plant_escape()) {
				fail("could not plant the escape symlink", -1);
				goto finish;
			}
			state = ST_DOWNLOADS;
			break;
		}
		if (!uploads[upload_idx].started) {
			uploads[upload_idx].started = 1;
			if (start_upload(&uploads[upload_idx])) {
				fail("upload connect", -1);
				goto finish;
			}
			break;
		}
		if (!uploads[upload_idx].done)
			break;
		if (check_upload(&uploads[upload_idx])) {
			fail("upload not as expected", -1);
			goto finish;
		}
		upload_idx++;
		break;

	case ST_DOWNLOADS:
		if (download_idx == (int)LWS_ARRAY_SIZE(downloads)) {
			result = 0;
			goto finish;
		}
		if (!downloads[download_idx].started) {
			downloads[download_idx].started = 1;
			if (start_download(&downloads[download_idx])) {
				fail("download connect", -1);
				goto finish;
			}
			break;
		}
		if (!downloads[download_idx].done)
			break;
		if (check_download(&downloads[download_idx])) {
			fail("download not as expected", -1);
			goto finish;
		}
		download_idx++;
		break;
	}

again:
	lws_sul_schedule(context, 0, &sul_tick, tick, 50 * LWS_US_PER_MS);
	return;

finish:
	state = ST_DONE;
	lws_default_loop_exit(context);
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	int n;

	lwsl_err("FAIL: timed out in state %d\n", state);
	for (n = 0; n < NUM_WS; n++)
		lwsl_err("  ws %d: est %d, listings %d, users %d, files %d, "
			 "in_msg %d\n", n, wsc[n].established,
			 wsc[n].listings, wsc[n].users, wsc[n].nfiles,
			 wsc[n].in_msg);
	state = ST_DONE;
	lws_default_loop_exit(context);
}

static int
empty_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char path[PATH_MAX + 260];

	if (lde->type != LDOT_FILE && lde->type != LDOT_LINK)
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	unlink(path);

	return 0;
}

static int
prepare_upload_dir(const char *dir)
{
	char path[PATH_MAX + 260];
	int fd;

	/* it may be left over from an earlier run */
	if (mkdir(dir, 0700) && errno != EEXIST) {
		lwsl_err("%s: can't create %s\n", __func__, dir);
		return 1;
	}
	if (!realpath(dir, upload_dir)) {
		lwsl_err("%s: no upload dir %s\n", __func__, dir);
		return 1;
	}

	/* nothing left over from an earlier run */
	lws_dir(upload_dir, NULL, empty_dir_cb);

	/* what the plugin is told the upload dir is */
	unlink(UPLOAD_LINK);
	if (symlink(upload_dir, UPLOAD_LINK)) {
		lwsl_err("%s: can't create %s\n", __func__, UPLOAD_LINK);
		return 1;
	}

	/*
	 * A file stored by the old "<user>_<name>" scheme: bob's name encodes
	 * to itself, so it must still be bob's
	 */
	lws_snprintf(path, sizeof(path), "%s/%s", upload_dir, LEGACY_NAME);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, "legacy\n", 7) != 7) {
		close(fd);
		return 1;
	}
	close(fd);

	return 0;
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *dir = "./upload";
	int n;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--upload-dir")))
		dir = p;
	pvo_ba.value = "./ba-passwords";
	if ((p = lws_cmdline_option(argc, argv, "--passwords")))
		pvo_ba.value = p;
	mount_upload.basic_auth_login_file = pvo_ba.value;
	mount_get.basic_auth_login_file = pvo_ba.value;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: deaddrop\n");

	if (prepare_upload_dir(dir))
		return 1;

	for (n = 0; n < NUM_WS; n++) {
		wsc[n].user = n ? "bob_smith" : "bob";
		wsc[n].pass = n ? "smith-password" : "bob-password";
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port		= port;
	info.vhost_name		= "deaddrop";
	info.protocols		= protocols_srv;
	info.mounts		= &mount_upload;
	info.pvo		= &pvo;
	if (!lws_create_vhost(context, &info))
		goto bail;

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.protocols		= protocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_tick, tick, 1);
	lws_sul_schedule(context, 0, &sul_watchdog, watchdog,
			 30 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);
	context = NULL;

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;

bail:
	lws_context_destroy(context);
	lwsl_user("Completed: FAIL\n");

	return 1;
}
