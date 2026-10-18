/*
 * lws-api-test-lhp-doc-cache
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 *
 * Fences lhp's document asset cache against what the server sends.  The
 * cache keeps a copy of each payload as it arrives, so it can write it
 * through at the end: the parsers stream, so that copy is the only thing
 * holding the whole payload, and the server decides how big it is.  A server
 * vhost and lws_lhp_ss_browse() in this process, the server (on --server,
 * default 127.0.0.1) serving:
 *
 *  - a small page linking a small stylesheet: both must be laid out and
 *    cached, so the cache is known to be working;
 *
 *  - a page bigger than LWS_DLO_ASSET_BLOB_MAX_PAYLOAD: it must still be laid
 *    out, but not cached, the copy having been given up while it arrived;
 *
 *  - a small page linking a stylesheet bigger than that: the page must be
 *    cached, the stylesheet not.
 *
 * The url given to lws_lhp_ss_browse() need only last for the call.  So the
 * test scribbles on its copy after each call, and the server drops the first
 * connection for the first page, so its fetch has to connect again from the
 * url after that: the browse must have taken a copy of its own.
 */

#include <libwebsockets.h>
#include <string.h>
#include <unistd.h>	/* the blob cache level is posix-only */

#define DC_TIMEOUT_S		30
#define DC_CHUNK		4096
#define DC_BIG_FILL		(LWS_DLO_ASSET_BLOB_MAX_PAYLOAD + 65536)

/*
 * lhp fetches the document and its assets with the "__default" streamtype.
 * The built-in policy's one is tls-only; this server is plain http, so the
 * test brings its own
 */

static const char * const dc_policy =
	"{"
		"\"release\":\"1\","
		"\"product\":\"lhp-doc-cache\","
		"\"schema-version\":1,"
		"\"retry\":[{\"default\":{"
			"\"backoff\":[100,200],"
			"\"conceal\":2,"
			"\"jitterpc\":0,"
			"\"svalidping\":30,"
			"\"svalidhup\":35"
		"}}],"
		"\"s\":[{\"__default\":{"
			"\"endpoint\":\"${endpoint}\","
			"\"port\":80,"
			"\"protocol\":\"h1\","
			"\"http_method\":\"GET\","
			"\"http_url\":\"\","
			"\"metadata\":[{"
				"\"endpoint\":\"\","
				"\"acc\":\"accept\","
				"\"ua\":\"user-agent\""
			"}],"
			"\"retry\":\"default\","
			"\"timeout_ms\":10000"
		"}}]"
	"}";

static const uint8_t fira_c_r_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular10.mcufont.h"
};

/*
 * What the server can serve: head, then fill bytes of filler, then tail.
 * Each step browses the first doc of the step, and afterwards checks
 * whether each doc of the step is in the cache.
 */

struct dc_doc {
	const char		*path;
	const char		*mime;
	const char		*head;
	const char		*tail;
	size_t			fill;
	int			step;
	int			want_cached;
};

static const struct dc_doc dc_docs[] = {
	{ "/small.html", "text/html",
	  "<html><head><link rel=\"stylesheet\" href=\"/small.css\"></head>"
	  "<body><p>small</p><!--", "--></body></html>", 1024, 0, 1 },
	{ "/small.css", "text/css", "p{color:#123456}/*", "*/", 1024, 0, 1 },

	{ "/big.html", "text/html", "<html><body><p>big</p><!--",
	  "--></body></html>", DC_BIG_FILL, 1, 0 },

	{ "/big-css.html", "text/html",
	  "<html><head><link rel=\"stylesheet\" href=\"/big.css\"></head>"
	  "<body><p>big css</p><!--", "--></body></html>", 1024, 2, 1 },
	{ "/big.css", "text/css", "p{color:#654321}/*", "*/", DC_BIG_FILL, 2, 0 },
};

struct dc_pss {
	const struct dc_doc	*doc;
	size_t			pos;
	size_t			total;
};

static struct lws_context *dc_cx;
static lws_display_render_state_t dc_drs;
static lws_sorted_usec_list_t dc_sul_next, dc_sul_watchdog;
static char dc_cache_dir[256], dc_host[64], dc_url[128];
static const char *dc_server = "127.0.0.1";
static int dc_port, dc_step, dc_fails, dc_finished, dc_dropped;

static lws_surface_info_t dc_ic = {
	.wh_px = { { 600,0 },       { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
	.type  = LWSSURF_TRUECOLOR32,
};

static size_t
dc_doc_len(const struct dc_doc *d)
{
	return strlen(d->head) + d->fill + strlen(d->tail);
}

static int
dc_callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + DC_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	struct dc_pss *pss = (struct dc_pss *)user;
	size_t n, hl, room;

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->doc = NULL;
		for (n = 0; n < LWS_ARRAY_SIZE(dc_docs); n++)
			if (!strcmp((const char *)in, dc_docs[n].path))
				pss->doc = &dc_docs[n];

		if (pss->doc && !dc_dropped) {
			/* make the fetch connect again, for the first page */
			dc_dropped = 1;
			return -1;
		}

		if (!pss->doc) {
			lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
			return lws_http_transaction_completed(wsi);
		}

		pss->pos = 0;
		pss->total = dc_doc_len(pss->doc);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						pss->doc->mime, pss->total,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->doc)
			break;

		/* the next chunk of head, filler and tail */

		hl = strlen(pss->doc->head);
		room = DC_CHUNK;
		while (room && pss->pos < pss->total) {
			size_t q = pss->pos, c;

			if (q < hl) {
				c = hl - q;
				if (c > room)
					c = room;
				memcpy(p, pss->doc->head + q, c);
			} else if (q < hl + pss->doc->fill) {
				c = hl + pss->doc->fill - q;
				if (c > room)
					c = room;
				memset(p, 'x', c);
			} else {
				c = pss->total - q;
				if (c > room)
					c = room;
				memcpy(p, pss->doc->tail +
					  (q - hl - pss->doc->fill), c);
			}
			p += c;
			room -= c;
			pss->pos += c;
		}

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      pss->pos == pss->total ? LWS_WRITE_HTTP_FINAL :
						       LWS_WRITE_HTTP) < 0)
			return 1;

		if (pss->pos != pss->total) {
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (lws_http_transaction_completed(wsi))
			return -1;

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols dc_protocols_srv[] = {
	{ "http", dc_callback_srv, sizeof(struct dc_pss), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
dc_next(lws_sorted_usec_list_t *sul);

/* is the document at path in the asset cache? */

static int
dc_cached(const char *path)
{
	struct lws_cache_ttl_lru *cache = lws_dlo_asset_cache(dc_cx);
	const void *d;
	char url[128];
	size_t l;

	lws_snprintf(url, sizeof(url), "http://%s:%d%s", dc_host, dc_port,
		     path);

	return cache && !lws_cache_item_get(cache, url, &d, &l);
}

/* the browse has laid out the document, and its stylesheets are done */

static void
dc_render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	size_t n;

	if (rs->html == 1)
		/* not finished laying out */
		return;

	lws_display_list_destroy(dc_cx, &rs->displaylist);

	/* the html and css docs of this step */

	for (n = 0; n < LWS_ARRAY_SIZE(dc_docs); n++) {
		int c;

		if (dc_docs[n].step != dc_step)
			continue;

		c = dc_cached(dc_docs[n].path);

		lwsl_user("%s: %s (%u bytes): %s\n", __func__,
			  dc_docs[n].path,
			  (unsigned int)dc_doc_len(&dc_docs[n]),
			  c ? "cached" : "not cached");

		if (c != dc_docs[n].want_cached) {
			lwsl_err("%s: %s should%s be cached\n", __func__,
				 dc_docs[n].path,
				 dc_docs[n].want_cached ? "" : " not");
			dc_fails++;
		}
	}

	dc_step++;
	lws_sul_schedule(dc_cx, 0, &dc_sul_next, dc_next, 1);
}

static void
dc_watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: step %d timed out\n", __func__, dc_step);
	dc_fails++;
	dc_finished = 1;
	lws_cancel_service(dc_cx);
}

static void
dc_next(lws_sorted_usec_list_t *sul)
{
	const struct dc_doc *d = NULL;
	size_t n;

	/* the first doc of the step is the one to browse */

	for (n = 0; n < LWS_ARRAY_SIZE(dc_docs) && !d; n++)
		if (dc_docs[n].step == dc_step)
			d = &dc_docs[n];

	if (!d) {
		/* no more steps */
		dc_finished = 1;
		lws_cancel_service(dc_cx);
		return;
	}

	memset(&dc_drs, 0, sizeof(dc_drs));
	dc_drs.ic = &dc_ic;

	lws_snprintf(dc_url, sizeof(dc_url), "http://%s:%d%s", dc_host,
		     dc_port, d->path);
	lwsl_user("%s: browsing %s\n", __func__, dc_url);

	lws_sul_schedule(dc_cx, 0, &dc_sul_watchdog, dc_watchdog,
			 DC_TIMEOUT_S * LWS_US_PER_SEC);

	if (lws_lhp_ss_browse(dc_cx, &dc_drs, dc_url, dc_render)) {
		lwsl_err("%s: browse failed\n", __func__);
		dc_fails++;
		dc_finished = 1;
		lws_cancel_service(dc_cx);
	}

	/* the browse must not be using our url any more */

	memset(dc_url, 'x', sizeof(dc_url) - 1);
}

/* the scratch asset cache goes away with us */

static void
dc_cache_rm(void)
{
	lws_dir(dc_cache_dir, NULL, lws_dir_rm_rf_cb);
	if (rmdir(dc_cache_dir))
		lwsl_warn("%s: unable to remove %s\n", __func__, dc_cache_dir);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.pss_policies_json = dc_policy;

	lwsl_user("LWS API selftest: lhp document asset cache bounds\n");

	p = lws_cmdline_option(argc, argv, "--server");
	if (p)
		dc_server = p;
	/* an IPv6 literal goes in brackets in the url */
	lws_snprintf(dc_host, sizeof(dc_host), strchr(dc_server, ':') ?
					       "[%s]" : "%s", dc_server);

	/* a fresh, owner-only asset cache under the given scratch dir */

	p = lws_cmdline_option(argc, argv, "--tmpdir");
	if (!p)
		p = ".";
	lws_snprintf(dc_cache_dir, sizeof(dc_cache_dir), "%s/lhp-doc-cache-%u",
		     p, (unsigned int)getpid());
	info.dlo_asset_cache_dir = dc_cache_dir;

	dc_cx = lws_create_context(&info);
	if (!dc_cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	if (!lws_dlo_asset_cache(dc_cx)) {
		lwsl_err("%s: no asset cache\n", __func__);
		goto bail;
	}

	lws_font_register(dc_cx, fira_c_r_10, sizeof(fira_c_r_10));

	info.port = 0;
	info.protocols = dc_protocols_srv;
	info.vhost_name = "dc-srv";
	vh = lws_create_vhost(dc_cx, &info);
	if (!vh)
		goto bail;
	dc_port = lws_get_vhost_listen_port(vh);

	lws_sul_schedule(dc_cx, 0, &dc_sul_next, dc_next, 1);

	while (n >= 0 && !dc_finished)
		n = lws_service(dc_cx, 0);

	lws_sul_cancel(&dc_sul_watchdog);
	lws_sul_cancel(&dc_sul_next);
	lws_context_destroy(dc_cx);

	dc_cache_rm();

	if (!dc_finished) {
		lwsl_err("%s: service loop ended early\n", __func__);
		return 1;
	}

	lwsl_user("Completed: %s\n", dc_fails ? "FAIL" : "PASS");

	return !!dc_fails;

bail:
	lwsl_err("%s: setup failed\n", __func__);
	lws_context_destroy(dc_cx);
	dc_cache_rm();

	return 1;
}
