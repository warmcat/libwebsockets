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
 */

#include "private-lws-hls.h"
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Remove one media file by its plain name, and the container subdir the
 * name may have been in if that is now empty.  Purified here regardless of
 * who asks, so neither the http endpoint nor the stub UDS can point it
 * outside media-dir.
 *
 * Returns 0 on success, else the errno from unlink() (EINVAL if the name
 * did not survive purification).
 */
static int
hls_delete_media(struct per_vhost_data__lws_hls *vhd, char *filename)
{
	char path[512], *dir_path;
	int en;

	lws_filename_purify_inplace(filename);
	if (!filename[0] || strchr(filename, '/')) {
		lwsl_warn("%s: refusing to delete '%s'\n", __func__, filename);
		return EINVAL;
	}

	lws_snprintf(path, sizeof(path), "%s/%s", vhd->media_dir, filename);

	/* whatever happens to the media, its index and audio shadows are
	 * no use any more */
	lws_hls_index_unlink(vhd->media_dir, filename);
	lws_hls_atrans_unlink(vhd->media_dir, filename);

	lwsl_notice("%s: deleting media %s\n", __func__, path);
	if (unlink(path)) {
		en = errno;
		lwsl_warn("%s: unlink %s failed: %d (%s)\n", __func__, path, en,
			  strerror(en));
		return en;
	}

	/* if there was a container subdir, and it is now empty, remove it */
	dir_path = dirname(path);
	if (dir_path && !strncmp(dir_path, vhd->media_dir, strlen(vhd->media_dir)) &&
	    strcmp(dir_path, vhd->media_dir))
		rmdir(dir_path); /* rmdir only succeeds if directory is empty */

	return 0;
}

/*
 * The stub child's stderr arrives in pipe-sized chunks holding several log
 * lines; the log emitter only shows up to the first newline, so split them
 * or everything after the first line of each chunk silently disappears.
 */
static void
hls_relay_stub_log(const char *in, size_t len)
{
	while (len) {
		const char *nl = memchr(in, '\n', len);
		size_t ll = nl ? (size_t)(nl - in) : len;

		if (ll)
			lwsl_notice("[HLS-STUB] %.*s\n", (int)ll, in);

		if (!nl)
			break;
		in += ll + 1;
		len -= ll + 1;
	}
}

/*
 * Stub child only: the one vhd that consumed the secret and owns the UDS
 * listener.  Requests arrive on the listener vhost, which has no vhd of
 * its own (see PROTOCOL_INIT), so they find their config through this.
 */
static struct per_vhost_data__lws_hls *stub_vhd;

static const char * const stub_req_paths[] = { "secret", "delete" };

static signed char
stub_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct per_session_data__lws_hls *pss = (struct per_session_data__lws_hls *)ctx->user;
	struct per_vhost_data__lws_hls *vhd;
	size_t sl;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case 0:
			lws_strncpy(pss->stub_secret, ctx->buf,
				    sizeof(pss->stub_secret));
			break;
		case 1:
			lws_strncpy(pss->stub_delete, ctx->buf,
				    sizeof(pss->stub_delete));
			break;
		}

		return 0;
	}

	if (reason != LEJPCB_COMPLETE)
		return 0;

	vhd = stub_vhd;
	if (!vhd)
		return -1;

	/*
	 * Only the file permissions on the UDS gate who may connect here, and
	 * those are applied after the bind(); so, like the cert-dist stub, we
	 * require the peer to prove it knows the secret our parent handed us
	 * on stdin before we act on anything it says.
	 */
	sl = strlen(vhd->stub_secret);
	if (!sl || strlen(pss->stub_secret) != sl ||
	    lws_timingsafe_bcmp(pss->stub_secret, vhd->stub_secret,
				(uint32_t)sl)) {
		lwsl_err("%s: stub request secret mismatch\n", __func__);
		return -1;
	}

	if (pss->stub_delete[0]) {
		char filename[256];
		int en;

		lws_strncpy(filename, pss->stub_delete, sizeof(filename));
		/* one request per object; don't replay it on the next one */
		pss->stub_delete[0] = '\0';
		en = hls_delete_media(vhd, filename);

		/* tell the requester how it went, from our writeable cb */
		pss->stub_reply_len = (size_t)lws_snprintf(pss->stub_reply + LWS_PRE,
				sizeof(pss->stub_reply) - LWS_PRE,
				"{\"result\":%d}", en);
		lws_callback_on_writable(pss->wsi);
	}

	return 0;
}

#if defined(LWS_WITH_STUB)
/*
 * http side: the stub's reply to our delete request.  The request ends
 * exactly once, with LEJPCB_DESTRUCTED, whether the reply completed, the
 * UDS dropped, or we cancelled it because the http connection went away;
 * only in the first two cases is there still a browser to answer, and it
 * is answered from its own HTTP_WRITEABLE.
 */
static const char * const stub_reply_paths[] = { "result" };

static signed char
stub_reply_cb(struct lejp_ctx *ctx, char reason)
{
	struct per_session_data__lws_hls *pss =
			(struct per_session_data__lws_hls *)ctx->user;

	if (reason == LEJPCB_VAL_NUM_INT && ctx->path_match == 1) {
		pss->stub_del_result = atoi(ctx->buf);
		return 0;
	}

	if (reason != LEJPCB_DESTRUCTED || !pss->stub_req)
		return 0;

	pss->stub_req = 0;
	lws_callback_on_writable(pss->wsi);

	return 0;
}
#endif

#if defined(LWS_PLUGIN_STATIC)
int
#else
static int
#endif
callback_lws_hls(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len);

/*
 * A route's media name may span subdirectories under media-dir (the
 * listing walks them), so it is a relative path rather than a single
 * component.  Validate it as such and copy it: every '/'-separated
 * component non-empty and neither "." nor "..", and no control characters
 * anywhere (a leading or trailing '/' is an empty component, so those
 * fail too).  Returns 0, else -1.
 */
static int
hls_media_name_copy(char *filename, size_t fn_sz, const char *p, size_t len)
{
	size_t i, cs = 0;

	if (!len || len >= fn_sz)
		return -1;

	for (i = 0; i <= len; i++) {
		char c = (i < len) ? p[i] : '/';

		if (c == '/') {
			size_t cl = i - cs;

			if (!cl || (cl == 1 && p[cs] == '.') ||
			    (cl == 2 && p[cs] == '.' && p[cs + 1] == '.'))
				return -1;
			cs = i + 1;
		} else if ((unsigned char)c < 0x20 || (unsigned char)c == 0x7f)
			return -1;
	}

	memcpy(filename, p, len);
	filename[len] = '\0';

	return 0;
}

/* is [s, s+l) a rendition selector, "v" or "aN" ? */
static int
hls_sel_valid(const char *s, size_t l)
{
	size_t i;

	if (l == 1 && s[0] == 'v')
		return 1;
	if (l < 2 || l > 4 || s[0] != 'a')
		return 0;
	for (i = 1; i < l; i++)
		if (s[i] < '0' || s[i] > '9')
			return 0;

	return 1;
}

/* is [s, s+l) a subtitle track id, "eN" or "sN" ? */
static int
hls_trackid_valid(const char *s, size_t l)
{
	size_t i;

	if (l < 2 || l > 8 || (s[0] != 'e' && s[0] != 's'))
		return 0;
	for (i = 1; i < l; i++)
		if (s[i] < '0' || s[i] > '9')
			return 0;

	return 1;
}

/* is [s, s+l) all digits, ie an index or a thumbnail time? */
static int
hls_digits(const char *s, size_t l)
{
	size_t i;

	if (!l || l > 7)
		return 0;
	for (i = 0; i < l; i++)
		if (s[i] < '0' || s[i] > '9')
			return 0;

	return 1;
}

/*
 * Split "<media-name>[/<sel>][/<idx>]" from an A/V route into its parts,
 * parsing from the right: media names always end in a media-file
 * extension, so the trailing route elements are unambiguous however deep
 * the media sits under media-dir.  sel is the rendition selector (""
 * when absent, see hls_parse_sel()).  When want_idx is set, a trailing
 * all-digits element is required and returned in *idx.
 *
 * Returns -1 if the path does not fit the shape.
 */
static int
hls_split_sel(const char *p, char *filename, size_t fn_sz, char *sel,
	      size_t sel_sz, int want_idx, int *idx)
{
	char work[512];
	char *ls;
	size_t wl;
	enum hls_sel_kind kind;
	int dummy;

	sel[0] = '\0';
	if (idx)
		*idx = -1;

	wl = strlen(p);
	if (!wl || wl >= sizeof(work))
		return -1;
	memcpy(work, p, wl + 1);

	/* a trailing all-digits element: the segment index */
	if (want_idx) {
		ls = strrchr(work, '/');
		{
			const char *tail = ls ? ls + 1 : work;

			if (!hls_digits(tail, strlen(tail)))
				return -1;
			*idx = atoi(tail);
			if (!ls)
				return -1;	/* no room for a name */
			*ls = '\0';
		}
	}

	/* an optional selector element before that */
	ls = strrchr(work, '/');
	if (ls && hls_sel_valid(ls + 1, strlen(ls + 1))) {
		size_t sl = strlen(ls + 1);

		if (sl >= sel_sz)
			return -1;
		memcpy(sel, ls + 1, sl + 1);
		if (hls_parse_sel(sel, &kind, &dummy))
			return -1;
		*ls = '\0';
	}

	return hls_media_name_copy(filename, fn_sz, work, strlen(work));
}

static const struct lws_protocols stub_prots[] = {
	LWS_PLUGIN_PROTOCOL_LWS_HLS,
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The fixed set of player assets this protocol serves itself from www_dir,
 * beside the listing and the endpoints: with these on board the whole app
 * is one flat callback mount, which is what keeps it working unchanged
 * behind a reverse proxy at an arbitrary point of a public URL space.
 * Names are matched exactly against the whole (relative) url, so nothing
 * from www_dir is reachable that is not listed here.
 */
static const struct hls_asset {
	const char	*name;
	const char	*ctype;
} hls_assets[] = {
	{ "player.html",	"text/html; charset=utf-8"		},
	{ "player.js",		"text/javascript; charset=utf-8"	},
	{ "player.css",		"text/css; charset=utf-8"		},
	{ "dir.js",		"text/javascript; charset=utf-8"	},
	{ "dir.css",		"text/css; charset=utf-8"		},
	{ "hls.min.js",		"text/javascript; charset=utf-8"	},
	{ "favicon.ico",	"image/x-icon"				},
};

/*
 * Serve one of hls_assets[] from vhd->www_dir, through the same response
 * pump the worker's task bodies use.  Returns 0 if it was handed to the
 * pump, 1 when the url is not one of ours (or nothing to serve it).
 */
static int
hls_serve_asset(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
		struct per_session_data__lws_hls *pss, const char *url)
{
	char path[sizeof(vhd->www_dir) + 256];
	struct stat st;
	uint8_t *buf;
	size_t len;
	int fd, i;

	if (url[0] != '/')
		return 1;
	url++;		/* the router's urls are mountpoint-relative */

	for (i = 0; i < (int)LWS_ARRAY_SIZE(hls_assets); i++)
		if (!strcmp(url, hls_assets[i].name))
			break;
	if (i == (int)LWS_ARRAY_SIZE(hls_assets))
		return 1;

	lws_snprintf(path, sizeof(path), "%s/%s", vhd->www_dir,
		     hls_assets[i].name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/*
		 * A whitelisted name that is missing from www-dir is an
		 * installation problem worth naming in the log, not just a
		 * mystery 404
		 */
		lwsl_wsi_warn(wsi, "asset %s not in www-dir %s",
			      hls_assets[i].name, vhd->www_dir);
		return 1;
	}
	if (fstat(fd, &st) || st.st_size < 0 ||
	    (size_t)st.st_size > 8 * 1024 * 1024) {
		close(fd);
		return 1;
	}
	len = (size_t)st.st_size;

	/* the existing body pump delivers from segment_buf + LWS_PRE */
	buf = malloc(LWS_PRE + len);
	if (!buf) {
		close(fd);
		return 1;
	}
	if (read(fd, buf + LWS_PRE, len) != (ssize_t)len) {
		free(buf);
		close(fd);
		return 1;
	}
	close(fd);

	free(pss->segment_buf);
	pss->segment_buf	= buf;
	pss->segment_len	= len;
	pss->segment_pos	= 0;
	pss->resp_status	= HTTP_STATUS_OK;
	pss->resp_content_type	= hls_assets[i].ctype;
	pss->resp_ready		= 1;

	lws_callback_on_writable(wsi);

	return 0;
}

/*
 * Decide whether the request may delete media (the listing's bin buttons
 * and the /delete/ endpoint): the logged-in user needs a grant level of 2
 * or more.
 *
 * The grant name, the login validation and the grant matching are entirely
 * the bouncer's business: an lws-login mount (eg the /lws-login-media
 * interceptor with service-name media) has already matched its grant and
 * stamped the cooked result on the request as x-lws-login-grant-level --
 * the named grant's level, or the "*" wildcard's when there is no named
 * one, so media:2 and *:2 arrive as 2 and *:1 as 1.  We know no grant
 * names, only the threshold:
 *
 *  1. the x-lws-login-grant-level an in-process lws-login bouncer stamped
 *     on this wsi.  Only an interceptor can stamp it, so it needs no
 *     configuration to be trusted
 *
 *  2. with trust-login-headers=1: the same header as it arrives in the
 *     request, forwarded by an lws reverse proxy whose mount is gated by
 *     lws-login on the box in front of us.  The bouncer snips the
 *     browser's own copy before stamping its own, so it is trustworthy
 *     from that path; the operator asserts with the pvo that this vhost
 *     is not reachable any other way (an internal box).  Off by default
 *
 *  3. with jwt-jwk (the auth server's public jwk): the auth_session cookie
 *     itself, for the service-name grant at level >= 2.  Only for a vhost
 *     that has the bouncer neither in-process nor in front of it; a
 *     deployment with a bouncer never reaches this
 */

/*
 * why / wl: a short description of how the decision was reached, so a
 * refusal can be logged and reported with what was actually looked at
 * rather than a bare 403.
 */

static int
hls_can_delete(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
	       char *why, size_t wl)
{
	char st[16];
	int n;

	if (lws_http_get_onward_header(wsi, LWS_LOGIN_HDR_GRANT_LEVEL, st,
				       sizeof(st)) > 0) {
		n = atoi(st);
		lws_snprintf(why, wl, "in-process login grant level %d "
				      "(need >= 2)", n);
		return n >= 2;
	}

#if defined(LWS_WITH_CUSTOM_HEADERS)
	if (vhd->trust_login_headers) {
		if (lws_hdr_custom_copy(wsi, st, sizeof(st),
					LWS_LOGIN_HDR_GRANT_LEVEL ":",
					(int)strlen(LWS_LOGIN_HDR_GRANT_LEVEL ":")) > 0) {
			n = atoi(st);
			lws_snprintf(why, wl,
				     "forwarded login grant level %d "
				     "(need >= 2)", n);
			return n >= 2;
		}
		lwsl_wsi_info(wsi, "trust-login-headers set but no %s header",
			      LWS_LOGIN_HDR_GRANT_LEVEL);
	}
#else
	if (vhd->trust_login_headers)
		lwsl_wsi_warn(wsi, "trust-login-headers needs "
				   "LWS_WITH_CUSTOM_HEADERS");
#endif

	if (vhd->has_jwk) {
		struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk,
					"auth_session", NULL, wsi, NULL);
		int ok = 0;

		if (!ja) {
			lws_snprintf(why, wl, "no valid auth_session jwt");
			return 0;
		}

		{
			uint64_t exp = lws_jwt_auth_get_exp(ja);

			/*
			 * lws_jwt_auth_create() returns a token that verified
			 * but has already expired, leaving the expiry decision
			 * to us: an expired session cookie grants nothing
			 */
			n = lws_jwt_auth_query_grant(ja, vhd->service_name);
			if (!exp || exp <= (uint64_t)lws_now_secs())
				lws_snprintf(why, wl, "auth_session jwt expired");
			else if (n >= 2) {
				/* the named grant, or "*" when there is none */
				lws_snprintf(why, wl, "jwt grant level %d for "
						      "'%s'", n,
					     vhd->service_name);
				ok = 1;
			} else
				lws_snprintf(why, wl,
					     "jwt grant level %d for '%s' "
					     "(need >= 2)", n,
					     vhd->service_name);

			lws_jwt_auth_destroy(&ja);
		}

		return ok;
	}

	lws_snprintf(why, wl, "no login grant level: not stamped in-process, "
			      "trust-login-headers=%d, jwt-jwk=%d",
		     vhd->trust_login_headers, vhd->has_jwk);

	return 0;
}

#if defined(LWS_PLUGIN_STATIC)
int
#else
static int
#endif
callback_lws_hls(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options *pvo;
#if defined(LWS_WITH_STUB)
	const char *stub;
#endif

	struct per_session_data__lws_hls *pss =
			(struct per_session_data__lws_hls *)user;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
#if defined(LWS_WITH_STUB)
		stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");
		if (stub && strcmp(stub, "lws-hls-stub"))
			return 0;
#endif

		/*
		 * We are offered to every vhost.  One that has no pvo for us
		 * simply doesn't want us: leave silently without a vhd, so the
		 * other callbacks stay inert on it.  The stub child gets its
		 * config over the UDS instead of by pvo, so it is exempt.
		 */
		if (!in
#if defined(LWS_WITH_STUB)
		    && !stub
#endif
		   )
			return 0;

#if defined(LWS_WITH_STUB)
		/*
		 * In the stub child we are instantiated on every vhost,
		 * including the UDS listener vhost lws_stub_server_init()
		 * itself creates, but the secret can only be consumed from
		 * stdin once: a second lws_stub_server_init() blocks forever
		 * on the pipe, leaving the listener bound but never serviced.
		 * The first instantiation does it, the rest stay inert.
		 */
		if (stub && stub_vhd)
			return 0;
#endif

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(struct per_vhost_data__lws_hls));
		if (!vhd)
			return 1;

#if defined(LWS_WITH_STUB)
		if (stub) {
			struct lws_stub_config sc;
			char extra[512];

			stub_vhd = vhd;
			memset(&sc, 0, sizeof(sc));
			memset(extra, 0, sizeof(extra));
			sc.cx = lws_get_context(wsi);
			sc.vh = lws_get_vhost(wsi);
			sc.stub_name = "lws-hls-stub";
			sc.uds_path = "/tmp/lws-hls-stub.sock"; // NOSONAR
			sc.protocols = stub_prots;
			
			/* kept in vhd so stub_req_cb() can authenticate the
			 * peer on the UDS before acting on its request */
			if (lws_stub_server_init(&sc, vhd->stub_secret, extra,
						 sizeof(extra)) < 0)
				return 1;
				
			/* Update our media_dir to the one provided by the parent via extra_payload */
			if (extra[0])
				vhd->media_dir = strdup(extra);
			else
				vhd->media_dir = "/tmp";
				
			return 0;
		}
#endif

		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "media-dir")))
			vhd->media_dir = pvo->value;
		else {
			lwsl_vhost_err(lws_get_vhost(wsi), "%s: media-dir pvo required", __func__);
			return 1;
		}

		/*
		 * Where the player page and its assets sit, relative to
		 * wherever this protocol's listing is served from: composed
		 * into the listing's relative links only.  The default is one
		 * level up, ie the static mount is the parent of the callback
		 * mount (the minimal example's /hls + /hls/hls shape, and the
		 * lwsws layout in the plugin README).  The minimal example
		 * instead mounts this protocol at / with the assets under
		 * hls/, so it passes "hls".  An absolute path is refused: the
		 * whole point is that the app works behind a reverse proxy
		 * that mounts it at an unknown point of a public URL space.
		 */
		/*
		 * The default asset prefix is the same directory: this
		 * protocol serves the player page and its assets itself from
		 * www_dir, beside the listing.  A different relative fragment
		 * suits deployments serving the assets from their own mount.
		 */
		lws_strncpy(vhd->asset_prefix, ".", sizeof(vhd->asset_prefix));
		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "asset-prefix"))) {
			if (pvo->value[0] == '/' || strchr(pvo->value, ':')) {
				lwsl_vhost_err(lws_get_vhost(wsi),
					       "%s: asset-prefix must be relative, "
					       "ignoring '%s'", __func__,
					       pvo->value);
			} else
				lws_strncpy(vhd->asset_prefix, pvo->value,
					    sizeof(vhd->asset_prefix));
		}

		lws_snprintf(vhd->www_dir, sizeof(vhd->www_dir), "%s/mount-origin",
			     vhd->media_dir);
		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "www-dir")))
			lws_strncpy(vhd->www_dir, pvo->value,
				    sizeof(vhd->www_dir));

		/* see hls_can_delete() for what these three do */

		vhd->service_name = "hls";
		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "service-name")))
			vhd->service_name = pvo->value;

		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "trust-login-headers")))
			vhd->trust_login_headers = atoi(pvo->value);

		if ((pvo = lws_pvo_search((const struct lws_protocol_vhost_options *)in, "jwt-jwk"))) {
			if (pvo->value[0] == '{' || lws_jwk_load(&vhd->jwk, pvo->value, NULL, NULL)) {
				if (lws_jwk_import(&vhd->jwk, NULL, NULL, pvo->value, strlen(pvo->value))) {
					lwsl_vhost_err(lws_get_vhost(wsi), "%s: failed to load/import JWK", __func__);
					return 1;
				}
			}
			vhd->has_jwk = 1;
		}

#if defined(LWS_WITH_STUB)
		{
			struct lws_stub_config sc;
			memset(&sc, 0, sizeof(sc));
			sc.cx = lws_get_context(wsi);
			sc.vh = lws_get_vhost(wsi);
			sc.stub_name = "lws-hls-stub";
			sc.uds_path = "/tmp/lws-hls-stub.sock"; // NOSONAR
			sc.protocols = stub_prots;
			sc.parent_protocol_name = "lws-hls";
			sc.extra_payload = vhd->media_dir;
			sc.extra_payload_len = strlen(vhd->media_dir) + 1;
			vhd->stub_mgr = lws_stub_spawn(&sc);
		}
#endif

		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		av_log_set_level(AV_LOG_ERROR);

		pthread_mutex_init(&vhd->lock, NULL);
		pthread_cond_init(&vhd->cond, NULL);
		pthread_mutex_init(&vhd->sub_lock, NULL);
		vhd->thread_exit = 0;
		vhd->current_task_t = HLS_THUMB_DEFAULT_T;
		if (pthread_create(&vhd->worker_thread, NULL, lws_hls_worker, vhd)) {
			lwsl_err("Failed to create worker thread\n");
			return 1;
		}
		pthread_cond_init(&vhd->index_cond, NULL);
		if (pthread_create(&vhd->indexer_thread, NULL, lws_hls_indexer,
				   vhd)) {
			lwsl_err("Failed to create indexer thread\n");
			pthread_mutex_lock(&vhd->lock);
			vhd->thread_exit = 1;
			pthread_cond_signal(&vhd->cond);
			pthread_mutex_unlock(&vhd->lock);
			pthread_join(vhd->worker_thread, NULL);
			return 1;
		}
		pthread_cond_init(&vhd->atrans_cond, NULL);
		if (pthread_create(&vhd->atrans_thread, NULL,
				   lws_hls_atrans_thread, vhd)) {
			lwsl_err("Failed to create atrans thread\n");
			pthread_mutex_lock(&vhd->lock);
			vhd->thread_exit = 1;
			pthread_cond_signal(&vhd->cond);
			pthread_cond_signal(&vhd->index_cond);
			pthread_mutex_unlock(&vhd->lock);
			pthread_join(vhd->worker_thread, NULL);
			pthread_join(vhd->indexer_thread, NULL);
			return 1;
		}

		lws_hls_index_sweep_start(vhd);
		lws_hls_purge_empty_dirs(vhd);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
#if defined(LWS_WITH_STUB)
		if (vhd == stub_vhd) {
			/* the stub child never started the worker or caches */
			stub_vhd = NULL;
			break;
		}
#endif
		lws_hls_index_sweep_stop(vhd);

		pthread_mutex_lock(&vhd->lock);
		vhd->thread_exit = 1;
		/* don't wait for a long build to finish for nobody */
		if (vhd->running)
			vhd->running->cancel = 1;
		pthread_cond_signal(&vhd->cond);
		pthread_cond_signal(&vhd->index_cond);
		pthread_cond_signal(&vhd->atrans_cond);
		pthread_mutex_unlock(&vhd->lock);
		pthread_join(vhd->worker_thread, NULL);
		pthread_join(vhd->indexer_thread, NULL);
		pthread_join(vhd->atrans_thread, NULL);
		pthread_mutex_destroy(&vhd->lock);
		pthread_cond_destroy(&vhd->cond);
		pthread_cond_destroy(&vhd->index_cond);
		pthread_cond_destroy(&vhd->atrans_cond);
		lws_hls_indexer_destroy(vhd);
		lws_hls_atrans_destroy(vhd);
		
		/* free cache */
		while (lws_dll2_get_head(&vhd->thumb_cache)) {
			struct thumb_cache *c = lws_container_of(
					lws_dll2_get_head(&vhd->thumb_cache),
					struct thumb_cache, list);

			lws_dll2_remove(&c->list);
			free(c->data);
			free(c);
		}

		/* free task queue, and anything finished but not collected */
		while (lws_dll2_get_head(&vhd->tasks)) {
			struct hls_task *t = lws_container_of(
					lws_dll2_get_head(&vhd->tasks),
					struct hls_task, list);

			lws_dll2_remove(&t->list);
			lws_hls_task_free(t);
		}
		while (lws_dll2_get_head(&vhd->done)) {
			struct hls_task *t = lws_container_of(
					lws_dll2_get_head(&vhd->done),
					struct hls_task, list);

			lws_dll2_remove(&t->list);
			lws_hls_task_free(t);
		}

		/* free index cache */
		while (lws_dll2_get_head(&vhd->index_list)) {
			struct hls_file_index *idx = lws_container_of(
					lws_dll2_get_head(&vhd->index_list),
					struct hls_file_index, list);

			lws_dll2_remove(&idx->list);
			free(idx->entries);
			free(idx);
		}

		/* free subtitle cue cache */
		pthread_mutex_lock(&vhd->sub_lock);
		while (lws_dll2_get_head(&vhd->sub_cache)) {
			struct hls_sub_cache *sc = lws_container_of(
					lws_dll2_get_head(&vhd->sub_cache),
					struct hls_sub_cache, list);
			int j;

			lws_dll2_remove(&sc->list);
			if (sc->cues) {
				for (j = 0; j < sc->n_cues; j++)
					free(sc->cues[j].text);
				free(sc->cues);
			}
			free(sc);
		}
		pthread_mutex_unlock(&vhd->sub_lock);
		pthread_mutex_destroy(&vhd->sub_lock);

#if defined(LWS_WITH_STUB)
		if (vhd->stub_mgr)
			lws_stub_destroy(&vhd->stub_mgr);
#endif
		if (vhd->has_jwk)
			lws_jwk_destroy(&vhd->jwk);
		break;

	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		if (vhd && pss) {
			pss->wsi = wsi;
			lws_dll2_add_head(&pss->pss_list, &vhd->pss_list);
		}
		break;

	case LWS_CALLBACK_HTTP:
	{
		/*
		 * The url is relative to whatever mountpoint this protocol
		 * was served from: a mount at /hls/hls hands us
		 * "/stream/<file>" with its leading slash, a mount at the
		 * toplevel hands us "stream/<file>" without.  Normalize so
		 * the routes (and the asset whitelist) always see the slash,
		 * whatever depth we are mounted at.
		 */
		char urlnorm[600];
		const char *url = (const char *)in;
		char why[96];

		if (url && url[0] && url[0] != '/' &&
		    strlen(url) < sizeof(urlnorm) - 2) {
			urlnorm[0] = '/';
			memcpy(urlnorm + 1, url, strlen(url) + 1);
			url = urlnorm;
		}

		if (!vhd)
			return lws_callback_http_dummy(wsi, reason, user, in, len);

		pss->can_delete = hls_can_delete(wsi, vhd, why, sizeof(why));

		lwsl_notice("HLS-TRACE: request '%s'\n", url ? url : "NULL");

		lwsl_info("HLS HTTP REQ: url='%s', waiting=%d\n", url ? url : "NULL", pss->waiting_for_thumbnail);

		if (!strcmp(url, "")) {
			char uri[512];
			int ulen = lws_hdr_copy(wsi, uri, sizeof(uri) - 2, WSI_TOKEN_GET_URI);
			if (ulen > 0) {
				unsigned char redirect_buf[512 + LWS_PRE];
				unsigned char *p_red = redirect_buf + LWS_PRE;
				unsigned char *end_red = redirect_buf + sizeof(redirect_buf) - 1;

				/*
				 * The uri is already slash-terminated when we
				 * are the toplevel mount ("/"): that is the
				 * media listing itself, not something to add
				 * another slash to
				 */
				if (uri[ulen - 1] == '/')
					return lws_hls_serve_dir(wsi, vhd);

				/* Redirect to add trailing slash */
				uri[ulen] = '/';
				uri[ulen + 1] = '\0';
				ulen++;

				int m = lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
							  (unsigned char *)uri, ulen, &p_red, end_red);
				if (m < 0)
					return -1;
				return lws_http_transaction_completed(wsi);
			}
		}

		/* Simple routing based on URL prefix */
		if (!strcmp(url, "/") || !strcmp(url, "/index.html")) {
			return lws_hls_serve_dir(wsi, vhd);
		}
		else if (!strncmp(url, "/preview/", 9)) {
			/*
			 * /preview/<filename>[/<secs>]: the default frame, or
			 * one at the viewer's resume position.  The name may
			 * span subdirectories, so the time is a trailing
			 * all-digits element (media names end in an extension,
			 * which keeps that unambiguous)
			 */
			char filename[256];
			const char *ls;
			int t = HLS_THUMB_DEFAULT_T;

			ls = strrchr(url + 9, '/');
			if (ls && hls_digits(ls + 1, strlen(ls + 1))) {
				t = atoi(ls + 1);
				if (t < 0)
					t = HLS_THUMB_DEFAULT_T;
				if (ls == url + 9)
					goto err_404;
			} else
				ls = url + 9 + strlen(url + 9);

			if (hls_media_name_copy(filename, sizeof(filename),
						url + 9,
						(size_t)(ls - (url + 9))))
				goto err_404;
			return lws_hls_serve_thumbnail(wsi, vhd->media_dir,
						       filename, t);
		}
		else if (!strncmp(url, "/index/", 7)) {
			/* is the keyframe index built?  asking starts it */
			char filename[256], jb[LWS_PRE + 160],
			     *json = jb + LWS_PRE;
			uint8_t buf[LWS_PRE + 1024], *start = buf + LWS_PRE,
				*p = start, *end = buf + sizeof(buf) - 1;
			int n;

			if (hls_media_name_copy(filename, sizeof(filename),
						url + 7, strlen(url + 7)))
				goto err_404;

			n = lws_hls_index_status(vhd, filename, json,
						 sizeof(jb) - LWS_PRE,
						 pss->can_delete);

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"application/json", (lws_filepos_t)n,
					&p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CACHE_CONTROL,
					(const uint8_t *)"no-store", 8, &p, end) ||
			    lws_finalize_write_http_header(wsi, start, &p, end))
				return -1;

			if (lws_write(wsi, (uint8_t *)json, (size_t)n,
				      LWS_WRITE_HTTP_FINAL) != n)
				return -1;

			return lws_http_transaction_completed(wsi) ? -1 : 0;
		}
		else if (!strncmp(url, "/stream/", 8)) {
			char filename[256];

			if (hls_media_name_copy(filename, sizeof(filename),
						url + 8, strlen(url + 8)))
				goto err_404;
			/* master playlist if subtitles exist, else the A/V
			 * media playlist unchanged */
			return lws_hls_queue_task(wsi, vhd, HLS_TASK_STREAM,
						  filename, NULL, 0);
		}
		else if (!strncmp(url, "/avstream/", 10)) {
			/* /avstream/<filename>[/<sel>] */
			char filename[256], sel[16];

			if (hls_split_sel(url + 10, filename, sizeof(filename),
					  sel, sizeof(sel), 0, NULL))
				goto err_404;
			return lws_hls_queue_task(wsi, vhd, HLS_TASK_MANIFEST,
						  filename, sel, 0);
		}
		else if (!strncmp(url, "/subsm/", 7)) {
			/*
			 * /subsm/<filename>/<trackid>: the name may span
			 * subdirectories, so the track id is the trailing
			 * element
			 */
			const char *p = url + 7;
			const char *sep = strrchr(p, '/');
			char filename[256], trackid[16];
			size_t tid_len;

			if (!sep)
				goto err_404;
			tid_len = strlen(sep + 1);
			if (!hls_trackid_valid(sep + 1, tid_len) ||
			    tid_len >= sizeof(trackid))
				goto err_404;
			lws_strncpy(trackid, sep + 1, sizeof(trackid));

			if (hls_media_name_copy(filename, sizeof(filename), p,
						(size_t)(sep - p)))
				goto err_404;

			return lws_hls_queue_task(wsi, vhd, HLS_TASK_SUB_PLAYLIST,
						  filename, trackid, 0);
		}
		else if (!strncmp(url, "/subseg/", 8)) {
			/*
			 * /subseg/<filename>/<trackid>/<idx>: trailing
			 * elements from the right, however deep the name
			 */
			const char *p = url + 8;
			const char *sep2 = strrchr(p, '/');
			const char *sep1;
			char filename[256], trackid[16];
			size_t tid_len;

			if (!sep2 || !hls_digits(sep2 + 1, strlen(sep2 + 1)))
				goto err_404;

			sep1 = NULL;
			{
				const char *q;

				for (q = sep2; q > p; q--)
					if (q[-1] == '/') {
						sep1 = q - 1;
						break;
					}
			}
			if (!sep1)
				goto err_404;
			tid_len = (size_t)(sep2 - (sep1 + 1));
			if (!hls_trackid_valid(sep1 + 1, tid_len) ||
			    tid_len >= sizeof(trackid))
				goto err_404;
			memcpy(trackid, sep1 + 1, tid_len);
			trackid[tid_len] = '\0';

			if (hls_media_name_copy(filename, sizeof(filename), p,
						(size_t)(sep1 - p)))
				goto err_404;

			return lws_hls_queue_task(wsi, vhd, HLS_TASK_SUB_SEGMENT,
						  filename, trackid,
						  atoi(sep2 + 1));
		}
		else if (!strncmp(url, "/init/", 6)) {
			/* /init/<filename>[/<sel>] */
			char filename[256], sel[16];

			if (hls_split_sel(url + 6, filename, sizeof(filename),
					  sel, sizeof(sel), 0, NULL))
				goto err_404;
			return lws_hls_queue_task(wsi, vhd, HLS_TASK_INIT,
						  filename, sel, 0);
		}
		else if (!strncmp(url, "/segment/", 9)) {
			/* /segment/<filename>[/<sel>]/<idx> */
			char filename[256], sel[16];
			int idx;

			if (hls_split_sel(url + 9, filename, sizeof(filename),
					  sel, sizeof(sel), 1, &idx))
				goto err_404;
			return lws_hls_queue_task(wsi, vhd, HLS_TASK_SEGMENT,
						  filename, sel, idx);
		} else if (!strncmp(url, "/delete/", 8)) {
			char filename[256];

			if (!pss->can_delete) {
				lwsl_wsi_notice(wsi, "delete '%s' refused: %s",
						url + 8, why);
				lws_return_http_status(wsi,
						       HTTP_STATUS_FORBIDDEN, why);
				return -1;
			}

			/*
			 * POST only: the session cookie is SameSite=Lax, which
			 * still goes out on a cross-site top-level GET, so a
			 * link elsewhere must not be able to delete media
			 */
			if (!lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				lws_return_http_status(wsi, HTTP_STATUS_METHOD_NOT_ALLOWED, "POST required");
				return -1;
			}

			lws_strncpy(filename, url + 8, sizeof(filename));
			lws_filename_purify_inplace(filename);
			if (!filename[0] || strchr(filename, '/')) {
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "Not Found");
				return -1;
			}

			/* our cached index of it goes regardless of who does
			 * the unlink; the stub child has no cache */
			lws_hls_index_forget(vhd, filename);
			lws_hls_atrans_forget(vhd, filename);
#if defined(LWS_WITH_STUB)
			if (vhd->stub_mgr) {
				const char *sec = lws_stub_get_secret(vhd->stub_mgr);
				char json[512];

				/* purify leaves '"' alone, and it would break
				 * out of the JSON string we are composing */
				if (!sec || strchr(filename, '"')) {
					lws_return_http_status(wsi,
						HTTP_STATUS_NOT_FOUND, "Not Found");
					return -1;
				}

				lws_snprintf(json, sizeof(json),
					     "{\"secret\":\"%s\",\"delete\":\"%s\"}",
					     sec, filename);
				pss->stub_del_result = -1;
				pss->stub_del_pending = 1;
				pss->stub_req = lws_stub_request_h(vhd->stub_mgr,
						json, stub_reply_paths,
						LWS_ARRAY_SIZE(stub_reply_paths),
						stub_reply_cb, NULL, pss);
				if (!pss->stub_req) {
					pss->stub_del_pending = 0;
					lws_return_http_status(wsi,
						HTTP_STATUS_INTERNAL_SERVER_ERROR,
						"could not ask the stub");
					return -1;
				}

				/*
				 * The answer comes on HTTP_WRITEABLE when the
				 * stub replies; if it never does, don't leave
				 * the browser hanging
				 */
				lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, 10);

				return 0;
			} else
#endif
			{
				/* no stub child to do it: do it ourselves */
				int en = hls_delete_media(vhd, filename);

				if (en) {
					lws_return_http_status(wsi,
						en == ENOENT ?
						    HTTP_STATUS_NOT_FOUND :
						    HTTP_STATUS_INTERNAL_SERVER_ERROR,
						strerror(en));
					return -1;
				}
			}

			lws_return_http_status(wsi, HTTP_STATUS_OK, "OK");
			return -1;
		} else {
			/*
			 * The player page and its assets, served from www_dir
			 * so the app is one flat mount.  Anything else is not
			 * ours: a clean 404, never the hung transaction the
			 * dummy callback leaves behind (behind a proxy that
			 * shows up at the browser as a corrupted response)
			 */
			if (!hls_serve_asset(wsi, vhd, pss, url))
				return 0;

			lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
			return -1;
		}

		return 0;

err_404:
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:

		if (!vhd)
			break;

		/* the worker finished something: hand bodies to their
		 * sessions... */
		lws_hls_collect_done(vhd);

		/* ...and wake anyone waiting on a thumbnail */
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&vhd->pss_list)) {
			struct per_session_data__lws_hls *ps = lws_container_of(d,
						struct per_session_data__lws_hls, pss_list);

			if (ps->waiting_for_thumbnail)
				lws_callback_on_writable(ps->wsi);
		} lws_end_foreach_dll(d);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
#if defined(LWS_WITH_STUB)
		if (pss && pss->stub_del_pending) {
			int en = pss->stub_del_result;

			if (pss->stub_req)
				/* not the stub's reply that woke us */
				return 0;

			pss->stub_del_pending = 0;

			if (en < 0) {
				lwsl_wsi_warn(wsi, "delete: no reply from stub");
				lws_return_http_status(wsi, HTTP_STATUS_BAD_GATEWAY,
						       "stub did not answer");
				return -1;
			}
			if (en) {
				lws_return_http_status(wsi, en == ENOENT ?
						HTTP_STATUS_NOT_FOUND :
						HTTP_STATUS_INTERNAL_SERVER_ERROR,
					strerror(en));
				return -1;
			}

			lws_return_http_status(wsi, HTTP_STATUS_OK, "OK");
			return -1;
		}
#endif
		if (pss && pss->resp_ready) {
			/* a task result arrived: start the response */
			uint8_t buf[LWS_PRE + 2048];
			uint8_t *start = buf + LWS_PRE;
			uint8_t *p = start;
			uint8_t *end = buf + sizeof(buf) - 1;

			pss->resp_ready = 0;

			lwsl_notice("HLS-TRACE: sending response status=%d len=%zu ct=%s\n",
				    pss->resp_status, pss->segment_len,
				    pss->resp_content_type ? pss->resp_content_type : "?");

			if (pss->resp_status != HTTP_STATUS_OK) {
				free(pss->segment_buf);
				pss->segment_buf = NULL;
				lws_return_http_status(wsi,
					(unsigned int)pss->resp_status, NULL);
				return -1;
			}

			if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					pss->resp_content_type,
					(lws_filepos_t)pss->segment_len,
					&p, end) ||
			    lws_finalize_write_http_header(wsi, start, &p, end))
				return -1;

			/* the body pump below takes it from here */
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (pss && pss->waiting_for_thumbnail) {
			pthread_mutex_lock(&vhd->lock);
			struct thumb_cache *c = NULL;
			lws_start_foreach_dll(struct lws_dll2 *, d,
					      lws_dll2_get_head(&vhd->thumb_cache)) {
				struct thumb_cache *cc = lws_container_of(d,
							struct thumb_cache, list);

				if (!strcmp(cc->filename, pss->thumb_filename) &&
				    cc->t == pss->thumb_t) {
					c = cc;
					break;
				}
			} lws_end_foreach_dll(d);
			
			if (c) {
				/* Found it in cache! */
				size_t len = c->len;
				uint8_t buf[LWS_PRE + 2048];
				uint8_t *start = buf + LWS_PRE;
				uint8_t *p = start;
				uint8_t *end = buf + sizeof(buf) - 1;

				lwsl_info("HLS WRITEABLE: sending headers for '%s', len=%zu\n", c->filename, len);

				if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "image/jpeg",
								(lws_filepos_t)len, &p, end)) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				if (lws_finalize_http_header(wsi, &p, end)) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				size_t hl = lws_ptr_diff_size_t(p, start);
				if (lws_write(wsi, start, hl, LWS_WRITE_HTTP_HEADERS) != (int)hl) {
					pthread_mutex_unlock(&vhd->lock);
					return 1;
				}
				
				pss->segment_buf = malloc(LWS_PRE + len);
				if (!pss->segment_buf) {
					pthread_mutex_unlock(&vhd->lock);
					return -1;
				}
				
				memcpy(pss->segment_buf + LWS_PRE, c->data, len);
				pss->segment_len = len;
				pss->segment_pos = 0;
				

				
				pss->waiting_for_thumbnail = 0;
				pthread_mutex_unlock(&vhd->lock);
				
				lws_callback_on_writable(wsi);
				return 0;
			}
			
			/* Not in cache. Did it fail? */
			int is_pending = 0;
			lws_start_foreach_dll(struct lws_dll2 *, d2,
					      lws_dll2_get_head(&vhd->tasks)) {
				struct hls_task *t = lws_container_of(d2,
							struct hls_task, list);

				if (t->type == HLS_TASK_THUMB &&
				    t->segment_idx == pss->thumb_t &&
				    !strcmp(t->filename, pss->thumb_filename)) {
					is_pending = 1;
					break;
				}
			} lws_end_foreach_dll(d2);

			if (!is_pending && vhd->current_task_filename[0] &&
			    vhd->current_task_t == pss->thumb_t &&
			    !strcmp(vhd->current_task_filename, pss->thumb_filename)) {
				is_pending = 1;
			}
			
			pthread_mutex_unlock(&vhd->lock);
			
			if (!is_pending) {
				/* Not pending and not in cache -> extraction failed */
				pss->waiting_for_thumbnail = 0;
				lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}
			
			/* Still pending, keep waiting */
			return 0;
		}

		if (!pss || !pss->segment_buf || pss->segment_pos >= pss->segment_len)
			return 1; /* Done or nothing to write */
			
		size_t rem = pss->segment_len - pss->segment_pos;
		size_t chunk = rem;
		if (chunk > 4096) {
			chunk = 4096;
		}

		int flags = (pss->segment_pos + chunk == pss->segment_len) ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;
		lwsl_debug("HLS WRITEABLE chunk: pos=%zu, chunk=%zu, total=%zu, final=%d\n", pss->segment_pos, chunk, pss->segment_len, flags == LWS_WRITE_HTTP_FINAL);

		int m = lws_write(wsi, pss->segment_buf + LWS_PRE + pss->segment_pos, chunk, (enum lws_write_protocol)flags);
		lwsl_debug("HLS WRITEABLE chunk: lws_write returned %d\n", m);
		
		if (m < 0) {
			free(pss->segment_buf);
			pss->segment_buf = NULL;
			return -1;
		}
		
		pss->segment_pos += (size_t)m;
		if (pss->segment_pos < pss->segment_len) {
			if (m > 0)
				lws_callback_on_writable(wsi);
			return 0;
		}
		
		free(pss->segment_buf);
		pss->segment_buf = NULL;
		lwsl_info("HLS WRITEABLE: transaction completed\n");
		return lws_http_transaction_completed(wsi);

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss) {
			if (vhd) {
				if (pss->task)
					lwsl_notice("HLS-TRACE: connection closed with task in flight (type=%d seg=%d)\n",
						    pss->task->type, pss->task->segment_idx);
				lws_dll2_remove(&pss->pss_list);
				/* a task in flight must not deliver to us */
				lws_hls_task_detach(vhd, pss);
#if defined(LWS_WITH_STUB)
				if (pss->stub_req) {
					/* nor a stub reply: the cb sees the
					 * handle already zeroed and stays
					 * off this pss */
					lws_stub_req_h h = pss->stub_req;

					pss->stub_req = 0;
					lws_stub_request_cancel(vhd->stub_mgr, h);
				}
#endif
			}
			pss->resp_ready = 0;
			if (pss->segment_buf) {
				free(pss->segment_buf);
				pss->segment_buf = NULL;
			}
		}
		break;

	case LWS_CALLBACK_RAW_RX: {
		int n;

		if (!pss)
			break;
		if (!pss->parser_valid) {
			/* before lejp_construct(), which calls the cb */
			pss->wsi = wsi;
			lejp_construct(&pss->jctx, stub_req_cb, pss,
				       stub_req_paths,
				       (unsigned char)LWS_ARRAY_SIZE(stub_req_paths));
			pss->parser_valid = 1;
		}
		n = lejp_parse(&pss->jctx, (uint8_t *)in, (int)len);
		if (n < 0 && n != LEJP_CONTINUE) {
			lwsl_err("Stub lejp parse failed: %d\n", n);
			return -1;
		}
		if (!n) {
			/*
			 * That object is done, and a completed parser takes
			 * no more input: rebuild it for the next request on
			 * this connection
			 */
			lejp_destruct(&pss->jctx);
			lejp_construct(&pss->jctx, stub_req_cb, pss,
				       stub_req_paths,
				       (unsigned char)LWS_ARRAY_SIZE(stub_req_paths));
		}
		break;
	}

	case LWS_CALLBACK_RAW_WRITEABLE:
		/* stub side: the reply to the last request on this UDS conn */
		if (!pss || !pss->stub_reply_len)
			break;
		if (lws_write(wsi, (unsigned char *)pss->stub_reply + LWS_PRE,
			      pss->stub_reply_len, LWS_WRITE_RAW) < 0)
			return -1;
		pss->stub_reply_len = 0;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (pss && pss->parser_valid) {
			lejp_destruct(&pss->jctx);
			pss->parser_valid = 0;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		/*
		 * As the protocol named by the stub's parent_protocol_name,
		 * we must keep the stub's spawn object informed about its
		 * stdwsi closing, so it can track and clean up after the
		 * child process
		 */
#if defined(LWS_WITH_STUB)
		if (vhd && vhd->stub_mgr && lws_stub_get_lsp(vhd->stub_mgr))
			lws_spawn_stdwsi_closed(
				lws_stub_get_lsp(vhd->stub_mgr), wsi);
#endif
		break;

	case LWS_CALLBACK_RAW_RX_FILE: {
		char buf[512];
		ssize_t n;

		if (in) {
			/*
			 * On Windows, the spawn pipe poll delivers the data
			 * itself in `in` / `len`, since the stdwsi pipe has a
			 * HANDLE rather than a POSIX fd we could read
			 */
			hls_relay_stub_log((const char *)in, len);
			break;
		}

		int fd = (int)lws_get_socket_fd(wsi);

		if (fd < 0)
			return -1;

		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		if (n == 0)
			return -1;

		hls_relay_stub_log(buf, (size_t)n);
		break;
	}

	default:
		break;
	}

	return 0;
}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols lws_hls_protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_HLS
};

LWS_VISIBLE const lws_plugin_protocol_t lws_hls = {
	.hdr = {
		.name = "lws hls",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = lws_hls_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_hls_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
