/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

const char * const method_names[] = {
	"GET", "POST",
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	"OPTIONS", "PUT", "PATCH", "DELETE",
#endif
	"CONNECT", "HEAD",
#ifdef LWS_WITH_HTTP2
	":path",
#endif
	};

#if defined(LWS_WITH_FILE_OPS)
static const char * const intermediates[] = { "private", "public" };
#endif

/*
 * return 0: all done
 *        1: nonfatal error
 *       <0: fatal error
 *
 *       REQUIRES CONTEXT LOCK HELD
 */


/*
 * Match a name to a vhost on the listener a connection arrived on (the one
 * listening vhost lv shares, see lws_vhost_shares_listener()), exactly
 * (priority 1) or as the parent of a *.name wildcard (priority 2).  Returns
 * NULL if the name names no vhost on that listener at all... what that should
 * mean is up to the caller, it is not the same answer for a TLS SNI name as
 * it is for a Host: header.
 *
 * A vhost on the same port but another interface is never a candidate: it has
 * a listen socket of its own, and its interface may be the only thing that
 * keeps peers on the other one from reaching it.
 */

struct lws_vhost *
lws_select_vhost_by_name(struct lws_vhost *lv, const char *servername)
{
	struct lws_vhost *vhost = lws_vhost_first(lv->context);
	const char *p;
	int n, colon;

	n = (int)strlen(servername);
	colon = n;
	p = (char *)strchr(servername, ':');
	if (p)
		colon = lws_ptr_diff(p, servername);

	/*
	 * Priority 1: first try exact matches.  The name must match to its
	 * end, not just for the length of the SNI: a client naming "abc" must
	 * not be handed a vhost called "abcdef".  A vhost that is being
	 * destroyed can no longer be selected either (its connections would be
	 * served from a dying config, and refused at bind anyway).
	 */

	while (vhost) {
		if (!vhost->being_destroyed &&
		    lws_vhost_shares_listener(lv, vhost) &&
		    strlen(vhost->name) == (size_t)colon &&
		    !strncmp(vhost->name, servername, (unsigned int)colon)) {
			lwsl_info("SNI: Found: %s\n", servername);
			return vhost;
		}
		vhost = lws_vhost_next(vhost);
	}

	/*
	 * Priority 2: if no exact matches, try matching *.vhost-name
	 * unintentional matches are possible but resolve to x.com for *.x.com
	 * which is reasonable.  If exact match exists we already chose it and
	 * never reach here.  SSL will still fail it if the cert doesn't allow
	 * *.x.com.
	 */
	vhost = lws_vhost_first(lv->context);
	while (vhost) {
		int m = (int)strlen(vhost->name);
		if (!vhost->being_destroyed &&
		    lws_vhost_shares_listener(lv, vhost) &&
		    m <= (colon - 2) &&
		    servername[colon - m - 1] == '.' &&
		    !strncmp(vhost->name, servername + colon - m, (unsigned int)m)) {
			lwsl_info("SNI: Found %s on wildcard: %s\n",
				    servername, vhost->name);
			return vhost;
		}
		vhost = lws_vhost_next(vhost);
	}

	/* the name doesn't name any vhost on this listener */

	return NULL;
}

struct lws_vhost *
lws_select_vhost(struct lws_vhost *lv, const char *servername)
{
	struct lws_vhost *vhost = lws_select_vhost_by_name(lv, servername);

	if (vhost)
		return vhost;

	/*
	 * Priority 3: match the first vhost on our listener.
	 *
	 * This is the answer for a Host: header, since a server with a single
	 * vhost is reached by IP address, or by any of the names that resolve
	 * to it, all the time.  It is deliberately NOT the answer for a TLS
	 * SNI name, see lws_select_vhost_sni().
	 */

	vhost = lws_vhost_first(lv->context);
	while (vhost) {
		if (!vhost->being_destroyed &&
		    lws_vhost_shares_listener(lv, vhost)) {
			lwsl_info("%s: vhost match to %s based on listener %d\n",
					__func__, vhost->name, lv->listen_port);
			return vhost;
		}
		vhost = lws_vhost_next(vhost);
	}

	/* no match */

	return NULL;
}

struct lws_vhost *
lws_select_vhost_sni(struct lws_vhost *lv, const char *servername)
{
	struct lws_vhost *vhost = lws_select_vhost_by_name(lv, servername),
			 *only = NULL;
	int n = 0;

	if (vhost)
		return vhost;

	/*
	 * He named something that is not served here.  Handing him "the first
	 * vhost on the listener" would let him decide by vhost creation order
	 * which certificate he is shown, and which client certificate policy
	 * he meets, just by naming something that does not exist.
	 *
	 * So only a vhost the configuration explicitly nominated as the
	 * fallback for this listener may take an unrecognized name... unless
	 * the listener has exactly one vhost anyway, in which case there is
	 * nothing for him to steer between and refusing would only break
	 * every single-vhost server whose vhost name is not what clients
	 * dial (eg, "default" reached as https://localhost).
	 */

	vhost = lws_vhost_first(lv->context);
	while (vhost) {
		if (!vhost->being_destroyed &&
		    lws_vhost_shares_listener(lv, vhost)) {
			if (lws_check_opt(vhost->options,
					  LWS_SERVER_OPTION_SNI_FALLBACK)) {
				lwsl_info("%s: unrecognized name -> fallback vhost %s\n",
					  __func__, vhost->name);
				return vhost;
			}
			only = vhost;
			n++;
		}
		vhost = lws_vhost_next(vhost);
	}

	if (n == 1)
		return only;

	/* nobody nominated a fallback... the caller must refuse him */

	return NULL;
}

/*
 * Move a server http request, h1 or an h3 stream, onto the vhost its Host: or
 * :authority selected, before it is served.
 *
 * He may still be bound to a protocol of the vhost he is leaving: an h1
 * keep-alive connection is left bound to its vhost's protocols[0] between
 * requests (lws_http_transaction_completed()), and an h3 stream to its
 * connection's protocol.  That is only a placeholder until lws_http_action()
 * binds the protocol that serves the request, but a bound protocol can't be
 * carried onto another vhost (lws_vhost_bind_wsi()).  So give it back first,
 * on the vhost it belongs to, and arrive on the new vhost as a new connection
 * would have, on the old vhost's default protocol, unbound, which the move
 * then swaps for the new vhost's.
 *
 * Returns 0 if he is on vh now, else nonzero: the move was refused and he
 * must not be served by the vhost he is still on as if he had named it.
 */

int
lws_http_server_rebind(struct lws *wsi, struct lws_vhost *vh)
{
	struct lws_vhost *ov = wsi->a.vhost;

	if (ov == vh)
		return 0;

	if (ov && wsi->protocol_bind_balance) {
		if (lws_bind_protocol(wsi, NULL, "vhost rebind"))
			return 1;
		if (ov->count_protocols)
			wsi->a.protocol = &ov->protocols[
				ov->default_protocol_index <
					ov->count_protocols ?
					ov->default_protocol_index : 0];
	}

	return lws_vhost_bind_wsi(vh, wsi);
}

static const struct lws_mimetype {
	const char *extension;
	const char *mimetype;
} server_mimetypes[] = {
	{ ".html", "text/html" },
	{ ".htm", "text/html" },
	{ ".js", "text/javascript" },
	{ ".css", "text/css" },
	{ ".png", "image/png" },
	{ ".jpg", "image/jpeg" },
	{ ".jpeg", "image/jpeg" },
	{ ".ico", "image/x-icon" },
	{ ".gif", "image/gif" },
	{ ".svg", "image/svg+xml" },
	{ ".ttf", "application/x-font-ttf" },
	{ ".otf", "application/font-woff" },
	{ ".woff", "application/font-woff" },
	{ ".woff2", "application/font-woff2" },
	{ ".gz", "application/gzip" },
	{ ".txt", "text/plain" },
	{ ".xml", "application/xml" },
	{ ".json", "application/json" },
	{ ".babylon", "application/json" },
	{ ".mjs", "text/javascript" },
	{ ".wasm", "application/wasm" },
};

const char *
lws_get_mimetype(const char *file, const struct lws_http_mount *m)
{
	const struct lws_protocol_vhost_options *pvo;
	size_t n = strlen(file), len, i;
	const char *fallback_mimetype = NULL;
	const struct lws_mimetype *mt;

	/* prioritize user-defined mimetypes */
	for (pvo = m ? m->extra_mimetypes : NULL; pvo; pvo = pvo->next) {
		/* ie, match anything */
		if (!fallback_mimetype && pvo->name[0] == '*') {
			fallback_mimetype = pvo->value;
			continue;
		}

		len = strlen(pvo->name);
		if (n > len && !strcasecmp(&file[n - len], pvo->name)) {
			lwsl_info("%s: match to user mimetype: %s\n", __func__,
				  pvo->value);
			return pvo->value;
		}
	}

	/* fallback to server-defined mimetypes */
	for (i = 0; i < LWS_ARRAY_SIZE(server_mimetypes); ++i) {
		mt = &server_mimetypes[i];

		len = strlen(mt->extension);
		if (n > len && !strcasecmp(&file[n - len], mt->extension)) {
			lwsl_info("%s: match to server mimetype: %s\n", __func__,
				  mt->mimetype);
			return mt->mimetype;
		}
	}

	/* fallback to '*' if defined */
	if (fallback_mimetype) {
		lwsl_info("%s: match to any mimetype: %s\n", __func__,
			  fallback_mimetype);
		return fallback_mimetype;
	}

	return NULL;
}

#if defined(LWS_WITH_FILE_OPS)
static lws_fop_flags_t
lws_vfs_prepare_flags(struct lws *wsi)
{
	/* what the request said, as it was dispatched */
	return wsi->http.accept_gzip ? LWS_FOP_FLAG_COMPR_ACCEPTABLE_GZIP : 0;
}

/*
 * Does the path have a component that is exactly ".."?  "..." or "..x" are
 * ordinary names, only a whole ".." component walks up a directory.
 */

static int
lws_path_has_dotdot(const char *p)
{
	const char *seg = p;

	do {
		if (*p == '/' || !*p) {
			if (p - seg == 2 && seg[0] == '.' && seg[1] == '.')
				return 1;
			seg = p + 1;
		}
	} while (*p++);

	return 0;
}

#if defined(WIN32)
/*
 * Win32 drops the dots and spaces a name ends with, so "admin." and "admin "
 * open "admin".  No file's own name ends in one.
 */
static int
lws_path_has_win32_alias(const char *p)
{
	for (; *p; p++)
		if ((*p == '.' || *p == ' ') && (!p[1] || p[1] == '/'))
			return 1;

	return 0;
}
#endif

#if defined(LWS_PLAT_FS_FOLDS_NAMES)
/*
 * Is the canonical path f inside the canonical directory d?  The filesystem
 * folds case, so the comparison does as well.
 */
static int
lws_path_is_under(const char *f, const char *d)
{
	size_t n = strlen(d);

	while (n && (d[n - 1] == '/' || d[n - 1] == '\\'))
		n--;

	return !strncasecmp(f, d, n) && (f[n] == '/' || f[n] == '\\');
}

/*
 * A mount is chosen by the bytes of the URI, but this filesystem also finds
 * a file by other names (/ADMIN, and on windows /admin., /admin%20, ADMIN~1).
 * So a URI that misses a mount by its spelling can still reach that mount's
 * files through a mount whose origin holds its origin, without whatever
 * protects it (basic auth, an interceptor).  A file is only served through
 * the file mount whose origin holds it most closely.
 *
 * Nonzero if the file at path is another mount's, or that can't be told.
 */
static int
lws_http_serve_is_foreign(struct lws *wsi, const struct lws_http_mount *m,
			  const char *path)
{
	char f[1024], o[1024], d[1024];
	const struct lws_http_mount *hm;
	int others = 0;
	size_t ol;

	for (hm = wsi->a.vhost->http.mount_list; hm; hm = hm->mount_next)
		if (hm != m && hm->origin_protocol == LWSMPRO_FILE &&
		    hm->origin)
			others = 1;
	if (!others)
		/* the only file mount has no other mount's files */
		return 0;

	if (lws_plat_path_canonical(path, f, sizeof(f)) ||
	    lws_plat_path_canonical(m->origin, o, sizeof(o)))
		return 1;
	ol = strlen(o);

	for (hm = wsi->a.vhost->http.mount_list; hm; hm = hm->mount_next) {
		if (hm == m || hm->origin_protocol != LWSMPRO_FILE ||
		    !hm->origin ||
		    /* an origin that is not there holds no files */
		    lws_plat_path_canonical(hm->origin, d, sizeof(d)))
			continue;

		if (strlen(d) > ol && lws_path_is_under(f, d))
			return 1;
	}

	return 0;
}
#endif

/*
 * The mount's interpret entry whose file suffix the path has, if any: that
 * protocol makes the response from the file instead of it being sent as it is
 */

static const struct lws_protocol_vhost_options *
lws_http_serve_interpreter(const char *path,
			   const struct lws_protocol_vhost_options *pvo)
{
	size_t n = strlen(path);

	while (pvo) {
		if (n > strlen(pvo->name) &&
		    !strcmp(&path[n - strlen(pvo->name)], pvo->name))
			return pvo;
		pvo = pvo->next;
	}

	return NULL;
}

static int
lws_http_serve(struct lws *wsi, char *uri, const char *origin,
	       const struct lws_http_mount *m)
{
	const struct lws_protocol_vhost_options *pvo = m->interpret;
	const struct lws_protocols *ipp;
	struct lws_process_html_args args;
	const char *mimetype;
#if !defined(_WIN32_WCE)
	const struct lws_plat_file_ops *fops;
	const char *vpath;
	lws_fop_flags_t fflags = LWS_O_RDONLY;
#if defined(WIN32) && defined(LWS_HAVE__STAT32I64)
	struct _stat32i64 st;
#else
	struct stat st;
#endif
	int spin = 0;
#endif
	char path[1024], sym[2048];
	unsigned char *p = (unsigned char *)sym + 32 + LWS_PRE, *start = p;
	unsigned char *end = p + sizeof(sym) - 32 - LWS_PRE;
#if !defined(WIN32) && !defined(LWS_PLAT_FREERTOS)
	size_t len;
#endif
	int n;

	wsi->handling_404 = 0;
	if (!wsi->a.vhost)
		return -1;

	/*
	 * The URI parsers normalise ".." components away before a request URI
	 * reaches here, but this is the last stop before the path is opened
	 * under the mount origin, so it must not rely on every route here
	 * having been through them.  A ".." left in the path at this point
	 * is an attempt to reach outside the mount, refuse it.
	 */
	if (lws_path_has_dotdot(uri)) {
		lwsl_wsi_notice(wsi, "refusing \"..\" in served path");
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		return -1;
	}

#if defined(WIN32)
	/*
	 * The URI sanitiser only knows '/' as the path separator, but
	 * CreateFileW() treats '\\' the same way, so a backslash (%5C) in the
	 * requested path could form a ".." component the sanitiser never saw
	 * and walk out of the mount.  There is no legitimate use for it in a
	 * path we serve from a mount.
	 */
	if (strchr(uri, '\\')) {
		lwsl_wsi_notice(wsi, "refusing backslash in served path");
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		return -1;
	}

	if (lws_path_has_win32_alias(uri)) {
		lwsl_wsi_notice(wsi, "refusing a name ending in '.' or ' '");
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		return -1;
	}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
	if (wsi->a.vhost->http.error_document_404) {
		const char *e = wsi->a.vhost->http.error_document_404;
		if (*e == '/')
			e++;
		const char *u = uri;
		if (*u == '/')
			u++;
		if (!strcmp(u, e))
			wsi->handling_404 = 1;
	}
#endif

	lws_snprintf(path, sizeof(path) - 1, "%s/%s", origin, uri);

#if !defined(_WIN32_WCE)

	fflags |= lws_vfs_prepare_flags(wsi);
	memset(&st, 0, sizeof(st));

	do {
		spin++;
		fops = lws_vfs_select_fops(wsi->a.context->fops, path, &vpath);

		if (wsi->http.fop_fd)
			lws_vfs_file_close(&wsi->http.fop_fd);

		wsi->http.fop_fd = fops->LWS_FOP_OPEN(fops, wsi->a.context->fops,
							path, vpath, &fflags);
		if (!wsi->http.fop_fd) {
			lwsl_info("%s: Unable to open '%s': errno %d\n",
				  __func__, path, errno);

			return 1;
		}

		/* if it can't be statted, don't try */
		if (fflags & LWS_FOP_FLAG_VIRTUAL)
			break;
#if defined(LWS_PLAT_FREERTOS)
		break;
#endif
#if !defined(WIN32)
		if (fstat(wsi->http.fop_fd->fd, &st)) {
			lwsl_info("unable to stat %s\n", path);
			goto notfound;
		}
#else
#if defined(LWS_HAVE__STAT32I64)
		{
			WCHAR buf[MAX_PATH];

			/* a path that does not fit is unterminated garbage */
			if (MultiByteToWideChar(CP_UTF8, 0, path, -1, buf,
						LWS_ARRAY_SIZE(buf)) <= 0 ||
			    _wstat32i64(buf, &st)) {
				lwsl_info("unable to stat %s\n", path);
				goto notfound;
			}
		}
#else
		if (stat(path, &st)) {
			lwsl_info("unable to stat %s\n", path);
			goto notfound;
		}
#endif
#endif

		wsi->http.fop_fd->mod_time = (uint32_t)st.st_mtime;
		fflags |= LWS_FOP_FLAG_MOD_TIME_VALID;

#if !defined(WIN32) && !defined(LWS_PLAT_FREERTOS)
		if ((S_IFMT & st.st_mode) == S_IFLNK) {
			len = (size_t)readlink(path, sym, sizeof(sym) - 1);
			if (len) {
				lwsl_err("Failed to read link %s\n", path);
				goto notfound;
			}
			sym[len] = '\0';
			lwsl_debug("symlink %s -> %s\n", path, sym);
			lws_snprintf(path, sizeof(path) - 1, "%s", sym);
		}
#endif
		if ((S_IFMT & st.st_mode) == S_IFDIR) {
			lwsl_debug("default filename append to dir\n");
			lws_snprintf(path, sizeof(path) - 1, "%s/%s/%s",
				 origin, uri, m->def ? m->def : "index.html");
		}

	} while ((S_IFMT & st.st_mode) != S_IFREG && spin < 5);

	/*
	 * Still not a regular file: a device, a fifo, a socket, or a chain of
	 * directories named like the default document.  None of them is ours
	 * to serve, and reading a device or fifo can block the event loop
	 */
#if !defined(LWS_PLAT_FREERTOS)
	if (!(fflags & LWS_FOP_FLAG_VIRTUAL) &&
	    (S_IFMT & st.st_mode) != S_IFREG) {
		lwsl_wsi_notice(wsi, "refusing to serve a non-regular file");
		lws_vfs_file_close(&wsi->http.fop_fd);
		if (lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;

		return 0;
	}
#endif

#if defined(LWS_PLAT_FS_FOLDS_NAMES)
	if (!(fflags & LWS_FOP_FLAG_VIRTUAL) &&
	    fops == &wsi->a.context->fops_platform &&
	    lws_http_serve_is_foreign(wsi, m, path)) {
		lwsl_wsi_notice(wsi, "refusing another mount's file");
		lws_vfs_file_close(&wsi->http.fop_fd);
		if (lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;

		return 0;
	}
#endif
#endif

	/*
	 * Only serve what the mount, or the server's own table, has a mimetype
	 * for.  A mount that wants to serve anything at all says so with a "*"
	 * extra mimetype; nothing else falls through to being served as
	 * application/octet-stream.  Decide it before the conditional GET
	 * handling below, so a guessed ETag can't get a 304 for a file we would
	 * refuse.
	 */
	mimetype = lws_get_mimetype(path, m);
	if (!mimetype) {
		lwsl_info("unknown mimetype for %s\n", path);
#if !defined(_WIN32_WCE)
		lws_vfs_file_close(&wsi->http.fop_fd);
#endif
		if (lws_return_http_status(wsi,
				HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, NULL) ||
		    lws_http_transaction_completed(wsi))
			return -1;

		return 0;
	}
	if (!mimetype[0])
		lwsl_debug("sending no mimetype for %s\n", path);

#if !defined(_WIN32_WCE)
	n = lws_snprintf(sym, sizeof(sym), "%08llX%08lX",
		    (unsigned long long)lws_vfs_get_length(wsi->http.fop_fd),
		    (unsigned long)lws_vfs_get_mod_time(wsi->http.fop_fd));

#if defined(LWS_WITH_RANGES)
	/* disable ranges if IF_RANGE token invalid */

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_IF_RANGE))
		if (strcmp(sym, lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_IF_RANGE)))
			/* differs - defeat Range: */
			lws_ranges_destroy(&wsi->http.range);
#endif

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_IF_NONE_MATCH)) {
		/*
		 * he thinks he has some version of it already,
		 * check if the tag matches
		 */
		if (!strcmp(sym, lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_IF_NONE_MATCH))) {

			char cache_control[50], *cc = "no-store";
			int cclen = 8;

			lwsl_debug("%s: ETAG match %s %s\n", __func__,
				   uri, origin);

			/* we don't need to send the payload */
			if (lws_add_http_header_status(wsi,
					HTTP_STATUS_NOT_MODIFIED, &p, end)) {
				lwsl_err("%s: failed adding not modified\n",
						__func__);
				return -1;
			}

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_ETAG,
					(unsigned char *)sym, n, &p, end))
				return -1;

			/*
			 * A 304 carries the Vary the 200 would have had
			 * (RFC 9110 15.4.5): the coding of the file is chosen
			 * from Accept-Encoding when it is served gzipped, or
			 * when it is a type we would compress ourselves
			 */
			if (((wsi->http.fop_fd->flags &
					LWS_FOP_FLAG_COMPR_IS_GZIP)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
			     || (!lws_http_serve_interpreter(path, pvo) &&
				 lws_http_compression_candidate(wsi, mimetype))
#endif
			    ) && lws_http_add_vary_accept_encoding(wsi, &p, end))
				return -1;

			/* but we still need to send cache control... */

			if (m->cache_max_age && m->cache_reusable) {
				if (!m->cache_revalidate) {
					cc = cache_control;
					cclen = lws_snprintf(cache_control, sizeof(cache_control),
						"%s, max-age=%u",
						intermediates[wsi->cache_intermediaries],
						m->cache_max_age);
				} else {
					cc = cache_control;
                                        cclen = lws_snprintf(cache_control, sizeof(cache_control),
                                        	"must-revalidate, %s, max-age=%u",
                                                intermediates[wsi->cache_intermediaries],
                                                m->cache_max_age);
				}
			}

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CACHE_CONTROL,
					(unsigned char *)cc, cclen, &p, end))
				return -1;

			if (lws_finalize_http_header(wsi, &p, end))
				return -1;

			n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
				      LWS_WRITE_HTTP_HEADERS |
				      LWS_WRITE_H2_STREAM_END);
			if (n != lws_ptr_diff(p, start)) {
				lwsl_err("_write returned %d from %ld\n", n,
					 (long)(p - start));
				return -1;
			}

			lws_vfs_file_close(&wsi->http.fop_fd);

			if (lws_http_transaction_completed(wsi))
				return -1;

			return 0;
		}
	}

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_ETAG,
			(unsigned char *)sym, n, &p, end))
		return -1;
#endif

	wsi->sending_chunked = 0;
	wsi->interpreting = 0;

	/*
	 * The mount's own protocol adds its headers first, bound with its own
	 * per-session data.  An interpreter, if the file has one, is bound
	 * after, so that it makes the response with its own per-session data:
	 * binding a protocol frees the previous one's, so binding the mount
	 * protocol after the interpreter left the interpreter's callback
	 * running with the mount protocol's per-session data as its state
	 */
	if (m->protocol) {
		const struct lws_protocols *pp = lws_vhost_name_to_protocol(
						       wsi->a.vhost, m->protocol);

		if (!pp || lws_bind_protocol(wsi, pp, __func__))
			return -1;
		args.p = (char *)p;
		args.max_len = lws_ptr_diff(end, p);
		if (pp->callback(wsi, LWS_CALLBACK_ADD_HEADERS,
					  wsi->user_space, &args, 0))
			return -1;
		p = (unsigned char *)args.p;
	}

	/*
	 * check if this is in the list of file suffixes to be interpreted by
	 * a protocol
	 */
	pvo = lws_http_serve_interpreter(path, pvo);
	if (pvo) {
		wsi->interpreting = 1;
		/*
		 * On h1 the interpreter's output goes chunked, since
		 * its length isn't known until it is made.  An empty
		 * file is never given to the interpreter: it goes as
		 * the empty body it is, with a Content-Length of 0,
		 * since nothing would send a chunked one's last-chunk
		 */
		if (!wsi->mux_substream &&
		    lws_vfs_get_length(wsi->http.fop_fd))
			wsi->sending_chunked = 1;

		/*
		 * What goes out is the interpreter's output, not the
		 * file: byte ranges of the file mean nothing in it,
		 * and the range framing doesn't survive the transform
		 */
#if defined(LWS_WITH_RANGES)
		lws_ranges_destroy(&wsi->http.range);
#endif

		ipp = lws_vhost_name_to_protocol(wsi->a.vhost, pvo->value);
		if (!ipp || ipp - wsi->a.vhost->protocols > 127) {
			lwsl_err("%s: no usable interpreter protocol %s\n",
				 __func__, pvo->value);
			return -1;
		}
		wsi->protocol_interpret_idx = (char)(ipp -
						     wsi->a.vhost->protocols);

		lwsl_debug("want %s interpreted by %s (pcol is %s)\n", path,
			    ipp->name, wsi->a.protocol ?
					wsi->a.protocol->name : "none");
		if (lws_bind_protocol(wsi, ipp, __func__))
			return -1;

		if (lws_ensure_user_space(wsi))
			return -1;
	}

	if (wsi->sending_chunked) {
		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_TRANSFER_ENCODING,
				(unsigned char *)"chunked", 7,
				&p, end))
			return -1;
	}

	*p = '\0';
	n = lws_serve_http_file(wsi, path, mimetype, (char *)start,
				lws_ptr_diff(p, start));

	if (n < 0 || ((n > 0) && lws_http_transaction_completed(wsi)))
		return -1; /* error or can't reuse connection: close the socket */

	return 0;

notfound:

	return 1;
}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
LWS_VISIBLE const struct lws_http_mount *
lws_find_mount(struct lws *wsi, const char *uri_ptr, int uri_len)
{
	const struct lws_http_mount *hm, *hit = NULL;
	int best = 0;

	lwsl_debug("H3_TRACE: lws_find_mount: wsi %p, role %s, uri '%.*s' (len %d), mux_substream %d\n",
		    wsi, wsi->role_ops ? wsi->role_ops->name : "none",
		    uri_len, uri_ptr ? uri_ptr : "NULL", uri_len, wsi->mux_substream);

	hm = wsi->a.vhost->http.mount_list;
	while (hm) {
		/*
		 * A CONNECT mount's mountpoint is an authority, not a path:
		 * only lws_http_connect_protocol() looks at it
		 */
		if (hm->origin_protocol == LWSMPRO_CONNECT) {
			hm = hm->mount_next;
			continue;
		}

		int cond1 = uri_len >= hm->mountpoint_len;
		int cond2 = cond1 && !strncmp(uri_ptr, hm->mountpoint, hm->mountpoint_len);
		int cond3 = cond2 && (hm->exact_match ?
				      (uri_len == hm->mountpoint_len) :
				      (uri_ptr[hm->mountpoint_len] == '\0' ||
				       uri_ptr[hm->mountpoint_len] == '/' ||
				       hm->mountpoint_len == 1));

		lwsl_debug("  mount check: mnt '%s' (len %d), exact %d, origin '%s', protocol %d -> match_conds: %d %d %d\n",
			    hm->mountpoint, hm->mountpoint_len, hm->exact_match,
			    hm->origin ? hm->origin : "NULL", hm->origin_protocol,
			    cond1, cond2, cond3);

		if (cond3) {
#if defined(LWS_WITH_SYS_METRICS)
			lws_metrics_tag_wsi_add(wsi, "mnt", hm->mountpoint);
#endif

			if (hm->no_ws_upgrades &&
			    lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
				lwsl_notice("    skip due to no_ws_upgrades\n");
				hm = hm->mount_next;
				continue;
			}

			if (hm->origin_protocol == LWSMPRO_NO_MOUNT) {
				lwsl_notice("    origin LWSMPRO_NO_MOUNT -> NULL\n");
				return NULL;
			}

			int has_token = (hm->origin_protocol == LWSMPRO_CALLBACK ||
					 hm->origin_protocol == LWSMPRO_CGI ||
					 lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) ||
					 lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) ||
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
					 lws_hdr_total_length(wsi, WSI_TOKEN_PUT_URI) ||
					 lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI) ||
					 lws_hdr_total_length(wsi, WSI_TOKEN_DELETE_URI) ||
#endif
					 lws_hdr_total_length(wsi, WSI_TOKEN_HEAD_URI) ||
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
					 (wsi->mux_substream &&
					  lws_hdr_total_length(wsi,
							WSI_TOKEN_HTTP_COLON_PATH)) ||
#endif
					 hm->protocol);

			int is_better = hm->mountpoint_len > best ||
					(hm->mountpoint_len == best &&
					 hm->exact_match && (!hit || !hit->exact_match));

			lwsl_debug("    has_token: %d, is_better: %d (best was %d)\n",
				    has_token, is_better, best);

			if (has_token && is_better) {
				best = hm->mountpoint_len;
				hit = hm;
				lwsl_debug("    => selected mount %s\n", hit->mountpoint);
			}
		}
		hm = hm->mount_next;
	}

	lwsl_debug("  lws_find_mount result: %s\n", hit ? hit->mountpoint : "NULL");
	return hit;
}
#endif

#if defined(LWS_WITH_HTTP_BASIC_AUTH) && !defined(LWS_PLAT_FREERTOS) && defined(LWS_WITH_FILE_OPS)
static int
lws_find_string_in_file(const char *filename, const char *string, int stringlen)
{
	char buf[256];
	int fd, n = 0, hit = 0;
	size_t pos = 0;

	fd = lws_open(filename, O_RDONLY);
	if (fd < 0) {
		lwsl_err("can't open auth file: %s\n", filename);
		return 0;
	}

	while (1) {
		n = (int)read(fd, buf + pos, LWS_POSIX_LENGTH_CAST(sizeof(buf) - 1 - pos));
		if (n <= 0)
			break;
		
		pos += (size_t)n;
		buf[pos] = '\0';
		
		char *line = buf;
		char *nl = strchr(line, '\n');
		while (nl) {
			*nl = '\0';
			if (nl > line && *(nl - 1) == '\r')
				*(nl - 1) = '\0';
			
			size_t line_len = strlen(line);
			if (line_len == (size_t)stringlen) {
				if (!lws_timingsafe_bcmp(line, string, (uint32_t)stringlen)) {
					hit = 1;
					break;
				}
			}
			
			line = nl + 1;
			nl = strchr(line, '\n');
		}
		
		if (hit) break;
		
		size_t rem = pos - (size_t)(line - buf);
		if (rem > 0)
			memmove(buf, line, rem);
		pos = rem;
		if (pos == sizeof(buf) - 1) {
			/* Line too long, truncate it */
			pos = 0;
		}
	}
	
	if (!hit && pos > 0) {
		if (pos == (size_t)stringlen && !lws_timingsafe_bcmp(buf, string, (uint32_t)stringlen))
			hit = 1;
	}

	close(fd);

	return hit;
}
#endif

#if defined(LWS_WITH_HTTP_BASIC_AUTH)

static int
lws_unauthorised_basic_auth_composed(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	unsigned char *start = pt->compose_buf + LWS_PRE, *p = start,
		      *end = start + wsi->a.context->pt_serv_buf_size - LWS_PRE;
	char buf[64];
	int n;

	/* no auth... tell him it is required */

	if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end))
		return -1;

	n = lws_snprintf(buf, sizeof(buf), "Basic realm=\"lwsws\"");
	if (lws_add_http_header_by_token(wsi,
			WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
			(unsigned char *)buf, n, &p, end))
		return -1;

	if (lws_add_http_header_content_length(wsi, 0, &p, end))
		return -1;

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_HEADERS |
					     LWS_WRITE_H2_STREAM_END);
	if (n < 0)
		return -1;

	return lws_http_transaction_completed(wsi);

}

int
lws_unauthorised_basic_auth(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int sb = lws_servbuf_claim(pt, pt->compose_buf + LWS_PRE,
				   wsi->a.context->pt_serv_buf_size - LWS_PRE,
				   "lws_unauthorised_basic_auth");
	int r = lws_unauthorised_basic_auth_composed(wsi);

	lws_servbuf_release(pt, sb);

	return r;
}

#endif

int lws_clean_url(char *p)
{
	if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p') {
		p += 4;
		if (*p == 's')
			p++;
		if (*p == ':') {
			p++;
			if (*p == '/')
				p++;
		}
	}

	while (*p) {
		if (p[0] == '/' && p[1] == '/') {
			char *p1 = p;
			while (*p1) {
				*p1 = p1[1];
				p1++;
			}
			continue;
		}
		p++;
	}

	return 0;
}

static const unsigned char methods[] = {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_POST_URI,
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
	WSI_TOKEN_OPTIONS_URI,
	WSI_TOKEN_PUT_URI,
	WSI_TOKEN_PATCH_URI,
	WSI_TOKEN_DELETE_URI,
#endif
	WSI_TOKEN_CONNECT,
	WSI_TOKEN_HEAD_URI,
#if defined(LWS_WITH_HTTP2) || defined(LWS_ROLE_H3)
	WSI_TOKEN_HTTP_COLON_PATH,
#endif
};

int
lws_http_get_uri_and_method(struct lws *wsi, char **puri_ptr, int *puri_len)
{
	int n, count = 0;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n]))
			count++;
	if (!count) {
		lwsl_warn("Missing URI in HTTP request\n");
		return -1;
	}

	if (count != 1 &&
	    !((wsi->mux_substream || wsi->h23_stream_carries_ws)
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
			    &&
	      lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_PATH)
#endif
	      )) {
		lwsl_warn("multiple methods?\n");
		return -1;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n])) {
			int tl = lws_hdr_total_length(wsi, methods[n]);

			/*
			 * We hand out (ptr, len) together, and every consumer
			 * of it assumes the two agree, ie, that len bytes of
			 * contiguous, NUL-terminated URI live at ptr.  That is
			 * only true while the method URI token is a single
			 * fragment: lws_hdr_total_length() sums the fragments
			 * and their separators, while lws_hdr_simple_ptr()
			 * only points at the first one, so a fragmented URI
			 * would walk consumers past the token's NUL into
			 * unrelated ah data.  Nothing legitimately fragments
			 * it, so refuse rather than paper over it.
			 */
			if (tl != lws_hdr_fragment_length(wsi, methods[n], 0)) {
				lwsl_wsi_warn(wsi, "fragmented method URI");
				return -1;
			}

			*puri_ptr = lws_hdr_simple_ptr(wsi, methods[n]);
			*puri_len = tl;

			return n;
		}

	return -1;
}

#if defined(LWS_WITH_HTTP_BASIC_AUTH)

/*
 * For compatibility, once a request's credentials have passed every basic auth
 * check it meets, WSI_TOKEN_HTTP_AUTHORIZATION is rewritten so it is just the
 * authorized user name.  Not by lws_check_basic_auth() itself: a ws upgrade
 * can meet two checks, its mount's and its protocol's "basic-auth" pvo, and
 * the second must see the credentials as they were sent.
 */
void
lws_http_basic_auth_rewrite(struct lws *wsi)
{
	char *p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	size_t len;
	int fi;

	/* a non-NULL p proves the ah is attached and the header is there */
	if (!p || !wsi->http.basic_auth_user)
		return;

	fi = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_AUTHORIZATION];
	len = strlen(wsi->http.basic_auth_user);
	/* the name was decoded from this header, so it always fits in it */
	if (len > wsi->stream.ah->frags[fi].len)
		return;

	memcpy(p, wsi->http.basic_auth_user, len);
	p[len] = '\0';
	wsi->stream.ah->frags[fi].len = (uint16_t)len;
}

enum lws_check_basic_auth_results
lws_check_basic_auth(struct lws *wsi, const char *basic_auth_login_file,
		     unsigned int auth_mode)
{
#if defined(LWS_WITH_FILE_OPS)
	char b64[160], plain[(sizeof(b64) * 3) / 4], *pcolon;
	int m, ml, fi, bar;
	size_t le;

	if (!basic_auth_login_file && auth_mode == LWSAUTHM_DEFAULT)
		return LCBA_CONTINUE;

	/* Did he send auth? */
	ml = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	if (!ml)
		return LCBA_FAILED_AUTH;

	/* Disallow fragmentation monkey business */

	fi = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_AUTHORIZATION];
	if (wsi->stream.ah->frags[fi].nfrag) {
		lwsl_err("fragmented basic auth header not allowed\n");
		return LCBA_FAILED_AUTH;
	}

	m = lws_hdr_copy(wsi, b64, sizeof(b64),
			 WSI_TOKEN_HTTP_AUTHORIZATION);
	if (m < 7) {
		lwsl_err("b64 auth too long\n");
		return LCBA_END_TRANSACTION;
	}

	b64[5] = '\0';
	if (strcasecmp(b64, "Basic")) {
		lwsl_err("auth missing basic: %s\n", b64);
		return LCBA_END_TRANSACTION;
	}

	/* It'll be like Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l */

	m = lws_b64_decode_string(b64 + 6, plain, sizeof(plain) - 1);
	if (m < 0) {
		lwsl_err("plain auth too long\n");
		return LCBA_END_TRANSACTION;
	}

	plain[m] = '\0';
	pcolon = (char *)strchr(plain, ':');
	if (!pcolon) {
		lwsl_err("basic auth format broken\n");
		return LCBA_END_TRANSACTION;
	}

	switch (auth_mode) {
	case LWSAUTHM_DEFAULT:
		if (lws_find_string_in_file(basic_auth_login_file, plain, m))
			break;
		lwsl_err("%s: basic auth lookup failed\n", __func__);
		return LCBA_FAILED_AUTH;

	case LWSAUTHM_BASIC_AUTH_CALLBACK:
		bar = wsi->a.protocol->callback(wsi,
				LWS_CALLBACK_VERIFY_BASIC_AUTHORIZATION,
				wsi->user_space, plain, (unsigned int)m);
		if (!bar)
			return LCBA_FAILED_AUTH;
		break;
	default:
		/* Invalid auth mode so lets fail all authentication attempts */
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Keep the authorized user name on the wsi, where it outlives the
	 * request headers.  The caller publishes it in the request headers
	 * too, with lws_http_basic_auth_rewrite(), once the request has met
	 * every check it is going to.
	 */

	le = lws_ptr_diff_size_t(pcolon, plain);
	plain[le] = '\0';

	lws_free(wsi->http.basic_auth_user);
	wsi->http.basic_auth_user = lws_strdup(plain);
	lws_explicit_bzero(plain, sizeof(plain));
	if (!wsi->http.basic_auth_user)
		return LCBA_END_TRANSACTION;

	lwsl_wsi_info(wsi, "%s: basic auth accepted for '%s'\n", __func__,
		      wsi->http.basic_auth_user);

	return LCBA_CONTINUE;
#else
	if (!basic_auth_login_file && auth_mode == LWSAUTHM_DEFAULT)
		return LCBA_CONTINUE;
	return LCBA_FAILED_AUTH;
#endif
}

#endif

#if defined(LWS_WITH_HTTP_BASIC_AUTH)
const char *
lws_http_basic_auth_user(struct lws *wsi)
{
	return wsi->http.basic_auth_user;
}
#endif

/*
 * Percent-encode one decoded uri component, eg, for an onward request line,
 * or a redirect.
 *
 * The request URI we hold is the DECODED one: the parser turned every %XX
 * (and '+') into the byte it stood for as it went into the ah.  Spliced
 * into the onward "GET <path> HTTP/1.1" as it is, a space ends the path
 * early ("/stream/The Something" reaches the backend as "/stream/The"), a
 * '?' that was %3F starts a query, a '#' truncates, a decoded '&' splits a
 * query value in two, and a non-ascii byte is simply not a valid request
 * target.  So the path and each query name / value are re-encoded here.
 *
 * Keeps RFC 3986 unreserved bytes and the given extra set literally and
 * encodes everything else, '%' and '+' included ('+' would be decoded to a
 * space again by an lws peer; over-encoding is always safe, the far side
 * decodes).  Returns the encoded length, or -1 if it does not fit; dst is
 * NUL terminated on success.
 */

static int
lws_http_pct_encode(char *dst, size_t dlen, const char *src, size_t slen,
		     const char *keep)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t o = 0;

	while (slen--) {
		unsigned char c = (unsigned char)*src++;

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
		    c == '_' || c == '~' ||
		    (c && c < 0x80 && strchr(keep, (int)c))) {
			if (o + 1 >= dlen)
				return -1;
			dst[o++] = (char)c;
			continue;
		}

		if (o + 3 >= dlen)
			return -1;
		dst[o++] = '%';
		dst[o++] = hex[c >> 4];
		dst[o++] = hex[c & 15];
	}
	dst[o] = '\0';

	return (int)o;
}

/* pchar minus '+', '&' and ';' (see above) */
#define LWS_PROXY_KEEP_PATH	"/:@!$'()*,="
/* a query name or value on its own: no '=' or '&' either */
#define LWS_PROXY_KEEP_QUERY	"/:@!$'()*,"

/*
 * The request's query, put back together for repeating it to somebody else,
 * eg, the backend a proxy forwards to, or a redirect's Location.  The parser
 * split it at every '&' / ';' and decoded each piece; this joins them again
 * one "name=value" at a time, with the name and value encoded separately, so
 * a decoded '=' or '&' inside either cannot change the split the next one
 * sees.
 *
 * Returns the length written to dst, 0 if there's no query, or -1 if it
 * doesn't fit or is malformed.  dst is NUL terminated, without the '?'.
 */

static int
lws_http_requery(struct lws *wsi, char *dst, size_t dlen)
{
	int na = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS),
	    frag = 0, fl, el;
	char *p = dst, *end = dst + dlen, *frg, *eq;
	size_t nl;

	if (!dlen)
		return -1;
	*dst = '\0';
	if (na <= 0)
		return 0;

	frg = lws_malloc((size_t)na + 1, __func__);
	if (!frg)
		return -1;

	while ((fl = lws_hdr_copy_fragment(wsi, frg, na + 1,
					   WSI_TOKEN_HTTP_URI_ARGS,
					   frag)) >= 0) {
		eq = strchr(frg, '=');
		nl = eq ? (size_t)(eq - frg) : (size_t)fl;

		if (frag++) {
			if (p + 1 >= end)
				goto bail;
			*p++ = '&';
		}

		el = lws_http_pct_encode(p, (size_t)(end - p), frg, nl,
					 LWS_PROXY_KEEP_QUERY);
		if (el < 0)
			goto bail;
		p += el;

		if (!eq)
			continue;

		if (p + 1 >= end)
			goto bail;
		*p++ = '=';

		el = lws_http_pct_encode(p, (size_t)(end - p), eq + 1,
					 (size_t)fl - nl - 1,
					 LWS_PROXY_KEEP_QUERY);
		if (el < 0)
			goto bail;
		p += el;
	}

	if (fl == -2) /* a fragment did not fit */
		goto bail;

	lws_free(frg);
	*p = '\0';

	return (int)(p - dst);

bail:
	lws_free(frg);

	return -1;
}

#if defined(LWS_WITH_TLS)
/*
 * He spoke plaintext to a tls listener whose vhost has
 * LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS.  All he is ever told is to come
 * back over https for exactly the url he asked for: the authority he named
 * in Host:, the path and the query, nothing from any vhost's config.  The
 * path and query are re-encoded from the parsed, decoded pieces, so the https
 * request parses to the same ones; a Host: that could make the Location
 * point anywhere else is refused.
 *
 * Returns 0 if the redirect was sent, else nonzero: close the connection.
 */
static int
lws_http_redirect_to_https(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	/*
	 * The Location is made in the first half of compose_buf, the
	 * response headers after it in the second
	 */
	unsigned char *start = pt->compose_buf + LWS_PRE, *p = start,
		      *end = pt->compose_buf +
				(wsi->a.context->pt_serv_buf_size / 2),
		      *hend = pt->compose_buf +
				wsi->a.context->pt_serv_buf_size;
	const char *host = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST);
	int hl = lws_hdr_total_length(wsi, WSI_TOKEN_HOST), uri_len, n;
	char *uri_ptr = NULL;

	if (!host || hl <= 0 || hl > 128 ||
	    lws_http_authority_check(host, (size_t)hl) ||
	    lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len) < 0 ||
	    !uri_ptr || uri_ptr[0] != '/') {
		lwsl_wsi_info(wsi, "can't make an https url of his request");
		lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);

		return 1;
	}

	p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "https://");
	if (hl >= lws_ptr_diff(end, p))
		goto too_long;
	memcpy(p, host, (size_t)hl);
	p += hl;

	n = lws_http_pct_encode((char *)p, lws_ptr_diff_size_t(end, p),
				uri_ptr, (size_t)uri_len, LWS_PROXY_KEEP_PATH);
	if (n < 0)
		goto too_long;
	p += n;

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS) > 0) {
		if (p + 2 >= end)
			goto too_long;
		*p++ = '?';
		n = lws_http_requery(wsi, (char *)p, lws_ptr_diff_size_t(end, p));
		if (n < 0)
			goto too_long;
		p += n;
	}

	n = lws_ptr_diff(p, start);
	p = end + LWS_PRE;

	return lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY, start, n,
				 &p, hend) < 0;

too_long:
	lws_return_http_status(wsi, HTTP_STATUS_REQ_URI_TOO_LONG, NULL);

	return 1;
}
#endif

#if defined(LWS_WITH_HTTP_DIGEST_AUTH)

/*
 * Parse an htdigest-format file (username:realm:HA1hex\n per line).
 * Returns 1 and copies HA1 hex into ha1_hex if the username:realm pair is
 * found, otherwise returns 0.
 */
static int
lws_find_htdigest_ha1(const char *filename, const char *username,
		      const char *realm, char *ha1_hex, size_t ha1_hex_len)
{
	size_t ulen = strlen(username), rlen = strlen(realm);
	char buf[256], cbuf[128];
	int fd, n = 0, pos = 0, found = 0;
	int field = 0, cpos = 0;
	int umatch = 0, rmatch = 0;

	if (!filename || !username || !realm)
		return 0;

	fd = lws_open(filename, O_RDONLY);
	if (fd < 0) {
		lwsl_err("can't open htdigest file: %s\n", filename);
		return 0;
	}

	for (;;) {
		char c;

		if (pos == n) {
			do {
				n = (int)read(fd, buf, sizeof(buf));
			} while (n < 0 && errno == EINTR);
			if (n <= 0) {
				/* flush last line with no trailing newline */
				if (field == 2 && umatch && rmatch && cpos > 0 &&
				    (size_t)cpos < ha1_hex_len) {
					memcpy(ha1_hex, cbuf, (size_t)cpos);
					ha1_hex[cpos] = '\0';
					found = 1;
				}
				break;
			}
			pos = 0;
		}
		c = buf[pos++];

		if (c == '\r')
			continue;

		if (c == '\n') {
			if (field == 2 && umatch && rmatch && cpos > 0 &&
			    (size_t)cpos < ha1_hex_len) {
				memcpy(ha1_hex, cbuf, (size_t)cpos);
				ha1_hex[cpos] = '\0';
				found = 1;
				break;
			}
			/* reset for next line */
			field = 0;
			cpos = 0;
			umatch = 0;
			rmatch = 0;
			continue;
		}

		if (c == ':' && field < 2) {
			/* end of a colon-separated field */
			cbuf[cpos] = '\0';
			if (field == 0)
				umatch = ((size_t)cpos == ulen &&
					  !strncmp(cbuf, username, ulen));
			else /* field == 1 */
				rmatch = ((size_t)cpos == rlen &&
					  !strncmp(cbuf, realm, rlen));
			field++;
			cpos = 0;
			continue;
		}

		if (cpos < (int)sizeof(cbuf) - 1)
			cbuf[cpos++] = c;
	}

	close(fd);

	return found;
}

/*
 * Send HTTP 401 Unauthorized with a Digest auth challenge.
 * Generates a fresh random nonce, stores it in the wsi for later verification
 * on keep-alive connections, and writes the response.
 */
int
lws_unauthorised_digest_auth(struct lws *wsi, const char *realm)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	unsigned char *start = pt->serv_buf + LWS_PRE,
		      *p = start, *end = p + 2048;
	char buf[256], nonce[33];
	int n;

	if (!realm)
		realm = "lwsws";

	/* Generate a fresh random nonce and remember it for later validation */
	lws_free_set_NULL(wsi->http.digest_auth_nonce);
	wsi->http.digest_auth_nc = 0;
	if (lws_hex_random(wsi->a.context, nonce, sizeof(nonce)))
		return -1;

	wsi->http.digest_auth_nonce = lws_strdup(nonce);
	if (!wsi->http.digest_auth_nonce)
		return -1;

	if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end))
		return -1;

	n = lws_snprintf(buf, sizeof(buf),
			 "Digest realm=\"%s\", nonce=\"%s\", "
			 "algorithm=MD5, qop=\"auth\"",
			 realm, nonce);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
					 (unsigned char *)buf, n, &p, end))
		return -1;

	if (lws_add_http_header_content_length(wsi, 0, &p, end))
		return -1;

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      LWS_WRITE_HTTP_HEADERS | LWS_WRITE_H2_STREAM_END);
	if (n < 0)
		return -1;

	return lws_http_transaction_completed(wsi);
}

/* token indices matching the srv_digest_toks array below */
#define SDT_DIGEST    0
#define SDT_USERNAME  1
#define SDT_REALM     2
#define SDT_NONCE     3
#define SDT_URI       4
#define SDT_RESPONSE  5
#define SDT_OPAQUE    6
#define SDT_QOP       7
#define SDT_ALGORITHM 8
#define SDT_NC        9
#define SDT_CNONCE   10

static const char * const srv_digest_toks[] = {
	"Digest",    /* SDT_DIGEST    */
	"username",  /* SDT_USERNAME  */
	"realm",     /* SDT_REALM     */
	"nonce",     /* SDT_NONCE     */
	"uri",       /* SDT_URI       */
	"response",  /* SDT_RESPONSE  */
	"opaque",    /* SDT_OPAQUE    */
	"qop",       /* SDT_QOP       */
	"algorithm", /* SDT_ALGORITHM */
	"nc",        /* SDT_NC        */
	"cnonce",    /* SDT_CNONCE    */
};

#define SDIGST_PEND_NAME_EQ  -1   /* expecting name= token */
#define SDIGST_PEND_DELIM    -2   /* expecting comma delimiter */
#define SDIGST_PEND_SKIP     -3   /* skip next value (unknown field) */

/*
 * Parse the incoming Authorization: Digest ... header and validate it against
 * the specified htdigest file.  htdigest file format is one entry per line:
 *
 *   username:realm:HA1_hex
 *
 * where HA1_hex = lowercase hex MD5("username:realm:password").
 *
 * On success (LCBA_CONTINUE), rewrites WSI_TOKEN_HTTP_AUTHORIZATION to
 * contain only the authenticated username, matching the Basic Auth behaviour.
 */
enum lws_check_basic_auth_results
lws_check_digest_auth(struct lws *wsi, const char *htdigest_file,
		      const char *realm)
{
#if defined(LWS_WITH_FILE_OPS)
	char b64[512];
	char username[64], req_realm[64], nonce_in[256], uri_in[256];
	char response_hex[LWS_GENHASH_LARGEST * 2 + 1];
	char cnonce[256], qop[32], nc_str[16];
	/* ha1_hex is exactly 32 hex chars for MD5 */
	char ha1_hex[LWS_GENHASH_LARGEST * 2 + 1];
	char tmp[sizeof(ha1_hex) + sizeof(nonce_in) + sizeof(nc_str) +
		 sizeof(cnonce) + sizeof(qop) +
		 (LWS_GENHASH_LARGEST * 2 + 1) + 32];
	char a2_hex[LWS_GENHASH_LARGEST * 2 + 1];
	char expected_hex[LWS_GENHASH_LARGEST * 2 + 1];
	uint8_t digest_raw[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hc;
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int seen = 0, pend = SDIGST_PEND_NAME_EQ, m, fi, n;
	const char *method, *eff_realm;
	char *uri_ptr;
	int uri_len;

	if (!htdigest_file)
		return LCBA_CONTINUE;

	eff_realm = realm ? realm : "lwsws";

	/* Did the client send an Authorization header? */
	m = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	if (!m)
		return LCBA_FAILED_AUTH;

	/* Disallow header fragmentation */
	fi = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_AUTHORIZATION];
	if (wsi->stream.ah->frags[fi].nfrag) {
		lwsl_err("fragmented digest auth header not allowed\n");
		return LCBA_FAILED_AUTH;
	}

	m = lws_hdr_copy(wsi, b64, sizeof(b64), WSI_TOKEN_HTTP_AUTHORIZATION);
	if (m < 7)
		return LCBA_END_TRANSACTION;

	/* Initialise field buffers */
	username[0] = '\0';
	req_realm[0] = '\0';
	nonce_in[0] = '\0';
	uri_in[0] = '\0';
	response_hex[0] = '\0';
	cnonce[0] = '\0';
	qop[0] = '\0';
	nc_str[0] = '\0';

	lws_tokenize_init(&ts, b64, LWS_TOKENIZE_F_MINUS_NONTERM |
				    LWS_TOKENIZE_F_NO_INTEGERS |
				    LWS_TOKENIZE_F_RFC7230_DELIMS);
	do {
		int do_str_val = 0;

		e = lws_tokenize(&ts);
		switch (e) {

		case LWS_TOKZE_TOKEN:
			if (pend >= 0 || pend == SDIGST_PEND_SKIP) {
				do_str_val = 1;
				break;
			}

			/* First token must be "Digest" */
			if (!strncasecmp(ts.token, "Digest", ts.token_len) &&
			    ts.token_len == 6) {
				seen |= 1 << SDT_DIGEST;
				break;
			}
			lwsl_err("digest auth: not a Digest authorization\n");
			return LCBA_END_TRANSACTION;

		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			if (!(seen & (1 << SDT_DIGEST)) ||
			    pend != SDIGST_PEND_NAME_EQ)
				return LCBA_END_TRANSACTION;

			for (n = 0; n < (int)LWS_ARRAY_SIZE(srv_digest_toks); n++)
				if (!strncasecmp(ts.token, srv_digest_toks[n],
						 ts.token_len) &&
				    srv_digest_toks[n][ts.token_len] == '\0')
					break;

			if (n == (int)LWS_ARRAY_SIZE(srv_digest_toks)) {
				pend = SDIGST_PEND_SKIP; /* unknown field */
				break;
			}

			pend = n;
			break;

		case LWS_TOKZE_QUOTED_STRING:
			do_str_val = 1;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == ',') {
				if (pend != SDIGST_PEND_DELIM)
					return LCBA_END_TRANSACTION;
				pend = SDIGST_PEND_NAME_EQ;
				break;
			}
			break;

		case LWS_TOKZE_ENDED:
			break;

		default:
			lwsl_err("digest auth: unexpected token %d\n", e);
			return LCBA_END_TRANSACTION;
		}

		if (do_str_val) {
			if (pend == SDIGST_PEND_SKIP) {
				pend = SDIGST_PEND_DELIM;
				continue;
			}
			if (pend < 0)
				return LCBA_END_TRANSACTION;

			switch (pend) {
			case SDT_USERNAME:
				if (ts.token_len >= (int)sizeof(username))
					return LCBA_END_TRANSACTION;
				strncpy(username, ts.token, ts.token_len);
				username[ts.token_len] = '\0';
				break;
			case SDT_REALM:
				if (ts.token_len >= (int)sizeof(req_realm))
					return LCBA_END_TRANSACTION;
				strncpy(req_realm, ts.token, ts.token_len);
				req_realm[ts.token_len] = '\0';
				break;
			case SDT_NONCE:
				if (ts.token_len >= (int)sizeof(nonce_in))
					return LCBA_END_TRANSACTION;
				strncpy(nonce_in, ts.token, ts.token_len);
				nonce_in[ts.token_len] = '\0';
				break;
			case SDT_URI:
				if (ts.token_len >= (int)sizeof(uri_in))
					return LCBA_END_TRANSACTION;
				strncpy(uri_in, ts.token, ts.token_len);
				uri_in[ts.token_len] = '\0';
				break;
			case SDT_RESPONSE:
				if (ts.token_len >= (int)sizeof(response_hex))
					return LCBA_END_TRANSACTION;
				strncpy(response_hex, ts.token, ts.token_len);
				response_hex[ts.token_len] = '\0';
				break;
			case SDT_OPAQUE:
				break; /* ignored */
			case SDT_QOP:
				if (ts.token_len >= (int)sizeof(qop))
					return LCBA_END_TRANSACTION;
				strncpy(qop, ts.token, ts.token_len);
				qop[ts.token_len] = '\0';
				break;
			case SDT_ALGORITHM:
				/* htdigest stores MD5-based HA1; reject others */
				if (ts.token_len != 3 ||
				    strncasecmp(ts.token, "MD5", 3)) {
					lwsl_err("digest auth: only MD5 supported\n");
					return LCBA_END_TRANSACTION;
				}
				break;
			case SDT_NC:
				if (ts.token_len >= (int)sizeof(nc_str))
					return LCBA_END_TRANSACTION;
				strncpy(nc_str, ts.token, ts.token_len);
				nc_str[ts.token_len] = '\0';
				break;
			case SDT_CNONCE:
				if (ts.token_len >= (int)sizeof(cnonce))
					return LCBA_END_TRANSACTION;
				strncpy(cnonce, ts.token, ts.token_len);
				cnonce[ts.token_len] = '\0';
				break;
			}
			seen |= 1 << pend;
			pend = SDIGST_PEND_DELIM;
		}
	} while (e > 0);

	/* Require at minimum: username, realm, nonce, response */
	if (!(seen & (1 << SDT_USERNAME)) ||
	    !(seen & (1 << SDT_REALM))    ||
	    !(seen & (1 << SDT_NONCE))    ||
	    !(seen & (1 << SDT_RESPONSE))) {
		lwsl_err("digest auth: missing required fields (seen=0x%x)\n",
			 seen);
		return LCBA_END_TRANSACTION;
	}

	/*
	 * Reject legacy no-qop responses: qop="auth" is mandatory to
	 * prevent a replay-downgrade attack where an MITM strips
	 * qop="auth" from the 401 challenge so the client omits nc.
	 * Without nc there is no nonce-count replay check on the
	 * same connection (RFC 7616 §3.4.1).
	 */
	if (!(seen & (1 << SDT_QOP)) || strcasecmp(qop, "auth")) {
		lwsl_err("digest auth: qop=\"auth\" required\n");
		return LCBA_FAILED_AUTH;
	}

	/* When qop is "auth", nc and cnonce MUST be present (RFC 7616). */
	if (!(seen & (1 << SDT_NC)) || !(seen & (1 << SDT_CNONCE))) {
		lwsl_err("digest auth: nc and cnonce required\n");
		return LCBA_FAILED_AUTH;
	}

	/* Verify realm matches our configuration */
	if (strcmp(req_realm, eff_realm)) {
		lwsl_err("digest auth: realm mismatch: got '%s', expected '%s'\n",
			 req_realm, eff_realm);
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Verify nonce matches the one we issued for this connection.
	 * If no nonce has been issued (new connection without prior 401),
	 * the client cannot be pre-emptively authenticated.
	 */
	if (!wsi->http.digest_auth_nonce ||
	    strcmp(nonce_in, wsi->http.digest_auth_nonce)) {
		lwsl_err("digest auth: %s\n",
			 wsi->http.digest_auth_nonce ?
				"nonce mismatch" :
				"no nonce stored for this connection");
		return LCBA_FAILED_AUTH;
	}

	/* Look up the pre-hashed HA1 in the htdigest file */
	if (!lws_find_htdigest_ha1(htdigest_file, username, eff_realm,
				   ha1_hex, sizeof(ha1_hex))) {
		lwsl_err("digest auth: user '%s' not found in htdigest\n",
			 username);
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Get the HTTP method for HA2 = MD5(method:uri).
	 * H2 mux substreams carry the method in :method pseudo-header
	 * and path in :path.
	 */
	method = NULL;
#if defined(LWS_ROLE_H2)
	if (wsi->mux_substream) {
		method = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
		uri_ptr = lws_hdr_simple_ptr(wsi,
					     WSI_TOKEN_HTTP_COLON_PATH);
		uri_len = lws_hdr_total_length(wsi,
					       WSI_TOKEN_HTTP_COLON_PATH);
	} else
#endif
	{
		int methidx = lws_http_get_uri_and_method(wsi, &uri_ptr,
							  &uri_len);
		if (methidx >= 0 &&
		    methidx < (int)LWS_ARRAY_SIZE(method_names))
			method = method_names[methidx];
	}
	if (!method)
		method = "GET";

	/*
	 * Validate URI from Authorization header matches the actual
	 * request URI (RFC 7616 section 3.4.1).  Without this check an
	 * attacker could reuse a valid auth header captured from one
	 * endpoint to access a different resource.
	 *
	 * H2 :path already includes the query string; for H1 we must
	 * reconstruct the full URI from the path + query args.
	 */
	if (uri_ptr && uri_in[0]) {
		char full_uri[512];

#if defined(LWS_ROLE_H2)
		if (wsi->mux_substream)
			lws_strnncpy(full_uri, uri_ptr, (size_t)uri_len,
				     sizeof(full_uri));
		else
#endif
		{
			int flen = lws_snprintf(full_uri, sizeof(full_uri),
						"%s", uri_ptr);
			if (lws_hdr_total_length(wsi,
						 WSI_TOKEN_HTTP_URI_ARGS)) {
				int qlen = lws_hdr_copy(wsi,
					    full_uri +
						    (unsigned int)(flen + 1),
					    (int)sizeof(full_uri) - flen - 1,
					    WSI_TOKEN_HTTP_URI_ARGS);
				if (qlen > 0) {
					full_uri[flen] = '?';
					flen += 1 + qlen;
					full_uri[flen] = '\0';
				}
			}
		}
		if (strcmp(uri_in, full_uri)) {
			lwsl_err("digest auth: uri mismatch (header '%s' != "
				 "request '%s')\n", uri_in, full_uri);
			return LCBA_FAILED_AUTH;
		}
	}

	/* HA2 = MD5(method ":" uri) -- use uri from auth header per RFC 2617 */
	n = lws_snprintf(tmp, sizeof(tmp), "%s:%s",
			 method, uri_in[0] ? uri_in : "/");
	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_MD5) ||
	    lws_genhash_update(&hc, tmp, (size_t)n) ||
	    lws_genhash_destroy(&hc, digest_raw)) {
		lws_genhash_destroy(&hc, NULL);
		return LCBA_FAILED_AUTH;
	}
	lws_hex_from_byte_array(digest_raw,
				lws_genhash_size(LWS_GENHASH_TYPE_MD5),
				a2_hex, sizeof(a2_hex));

	/*
	 * Compute the expected response:
	 *   qop=auth:  MD5(HA1:nonce:nc:cnonce:qop:HA2)
	 *   no qop:    MD5(HA1:nonce:HA2)
	 */
	if (qop[0])
		n = lws_snprintf(tmp, sizeof(tmp), "%s:%s:%s:%s:%s:%s",
				 ha1_hex, nonce_in, nc_str, cnonce, qop,
				 a2_hex);
	else
		n = lws_snprintf(tmp, sizeof(tmp), "%s:%s:%s",
				 ha1_hex, nonce_in, a2_hex);

	if (lws_genhash_init(&hc, LWS_GENHASH_TYPE_MD5) ||
	    lws_genhash_update(&hc, tmp, (size_t)n) ||
	    lws_genhash_destroy(&hc, digest_raw)) {
		lws_genhash_destroy(&hc, NULL);
		return LCBA_FAILED_AUTH;
	}
	lws_hex_from_byte_array(digest_raw,
				lws_genhash_size(LWS_GENHASH_TYPE_MD5),
				expected_hex, sizeof(expected_hex));

	/* Constant-time comparison to avoid timing side-channels */
	if (strlen(expected_hex) != strlen(response_hex) ||
	    lws_timingsafe_bcmp(expected_hex, response_hex,
				(uint32_t)strlen(expected_hex))) {
		lwsl_err("digest auth: response mismatch for user '%s'\n",
			 username);
		return LCBA_FAILED_AUTH;
	}

	/*
	 * Validate nonce count (nc) to detect replay within the same
	 * keep-alive connection.  The nc value must increase monotonically.
	 */
	if (nc_str[0]) {
		unsigned long ul;
		char *endptr;

		ul = strtoul(nc_str, &endptr, 16);
		if (*endptr || !endptr || ul == ULONG_MAX ||
		    (uint32_t)ul <= wsi->http.digest_auth_nc) {
			lwsl_err("digest auth: nc replay detected "
				 "(nc=%lu, last=%u)\n",
				 ul, wsi->http.digest_auth_nc);
			return LCBA_FAILED_AUTH;
		}
		wsi->http.digest_auth_nc = (uint32_t)ul;
	}

	/*
	 * Rewrite WSI_TOKEN_HTTP_AUTHORIZATION so it contains only the
	 * authenticated username -- same convention as Basic Auth.
	 */
	lws_free(wsi->http.basic_auth_user);
	wsi->http.basic_auth_user = lws_strdup(username);
	if (!wsi->http.basic_auth_user)
		return LCBA_END_TRANSACTION;

	lwsl_wsi_info(wsi, "digest auth accepted for '%s'\n", username);

	return LCBA_CONTINUE;
#else
	if (!htdigest_file)
		return LCBA_CONTINUE;
	return LCBA_FAILED_AUTH;
#endif
}

#endif /* LWS_WITH_HTTP_DIGEST_AUTH */

#if defined(LWS_WITH_HTTP_PROXY)

/*
 * Set up an onward http proxy connection according to the mount this
 * uri falls under.  Notice this can also be starting the proxying of what was
 * originally an incoming h1 upgrade, or an h2 ws "upgrade".
 */
/*
 * Copy the request headers the proxy forwards to the backend from the ah
 * onto wsi->http.extra_onward_headers, so the onward handshake composer
 * never has to look at the ah (see lws_http_proxy_start()).
 */

static int
lws_http_proxy_snapshot_onward(struct lws *wsi, char ws)
{
	static const uint8_t fwd_http[] = {
		WSI_TOKEN_HTTP_CONTENT_LENGTH,
		WSI_TOKEN_HTTP_AUTHORIZATION,
		WSI_TOKEN_HTTP_CONTENT_TYPE,
		WSI_TOKEN_HTTP_ETAG,
		WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
		WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
		WSI_TOKEN_HTTP_ACCEPT_ENCODING,
		WSI_TOKEN_HTTP_CACHE_CONTROL,
		WSI_TOKEN_HTTP_COOKIE,
	}, fwd_ws[] = {
		WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
		WSI_TOKEN_HTTP_COOKIE,
	};
	const uint8_t *fwd = ws ? fwd_ws : fwd_http;
	size_t count = ws ? LWS_ARRAY_SIZE(fwd_ws) : LWS_ARRAY_SIZE(fwd_http), n;

	for (n = 0; n < count; n++) {
		enum lws_token_indexes tok = (enum lws_token_indexes)fwd[n];
		const char *ts = (const char *)lws_token_to_string(tok);
		char name[48], *val;
		int len, r;

		len = lws_hdr_total_length(wsi, tok);
		if (len < 1 || !ts)
			continue;

		/* the token string carries its trailing ':' */
		lws_strnncpy(name, ts, strlen(ts) - 1, sizeof(name));

		val = lws_malloc((size_t)len + 1, __func__);
		if (!val)
			return 1;

		if (lws_hdr_copy(wsi, val, len + 1, tok) < 0) {
			lws_free(val);

			return 1;
		}

		/*
		 * The raw appender: the public lws_http_add_onward_header()
		 * zaps the name from the ah first, which is right for a
		 * trusted header an interceptor stamps, and wrong for the
		 * peer's own Content-Length or Cookie we are merely copying
		 */
		r = lws_http_onward_header_append(wsi, name, val);
		lws_free(val);
		if (r)
			return 1;
	}

	return 0;
}

int
lws_http_proxy_start(struct lws *wsi, const struct lws_http_mount *hit,
		     char *uri_ptr, char ws)
{
	const char *pcolon, *pslash;
	/* ads holds any dns name, host that and ":<port>" */
	char ads[256], host[256 + 8], unix_skt = 0, zero_body = 0;
	struct lws_client_connect_info i;
	struct lws *cwsi;
	int n, na;
	unsigned int max_http_header_data = wsi->a.context->max_http_header_data > 256 ?
					    wsi->a.context->max_http_header_data : 256;
	char *rpath = NULL, *enc = NULL;

#if defined(LWS_ROLE_WS)
	if (ws)
		/*
		 * Neither our inbound ws upgrade request side, nor our onward
		 * ws client connection on our side can bind to the actual
		 * protocol that only the remote inbound side and the remote
		 * onward side understand.
		 *
		 * Instead these are both bound to our built-in "lws-ws-proxy"
		 * protocol, which understands how to proxy between the two
		 * sides.
		 *
		 * We bind the parent, inbound part here and our side of the
		 * onward client connection is bound to the same handler using
		 * the .local_protocol_name.
		 */
		lws_bind_protocol(wsi, &lws_ws_proxy, __func__);
#endif
	memset(&i, 0, sizeof(i));
	i.context = lws_get_context(wsi);

	if (hit->origin[0] == '+')
		unix_skt = 1;

	pcolon = (char *)strchr(hit->origin, ':');
	pslash = (char *)strchr(hit->origin, '/');
	if (!pslash) {
		lwsl_err("Proxy mount origin '%s' must have /\n", hit->origin);
		return -1;
	}

	if (unix_skt) {
		if (!pcolon) {
			lwsl_err("Proxy mount origin for unix skt must "
				 "have address delimited by :\n");

			return -1;
		}
		n = lws_ptr_diff(pcolon, hit->origin);
		pslash = pcolon;
#if defined(LWS_WITH_UNIX_SOCK)
		/*
		 * The client connects to the path after the '+', which must
		 * fit sun_path whole with its NUL: cut short, it names some
		 * other socket
		 */
		if (n - 1 >= (int)sizeof(((struct sockaddr_un *)0)->sun_path)) {
			lwsl_err("Proxy mount origin unix skt path too long\n");

			return -1;
		}
#endif
	} else {
		if (pcolon > pslash)
			pcolon = NULL;

		if (pcolon)
			n = (int)(pcolon - hit->origin);
		else
			n = (int)(pslash - hit->origin);
	}

	/* nor do we shorten a host name, which would name another host */
	if (n >= (int)sizeof(ads)) {
		lwsl_err("Proxy mount origin address too long\n");

		return -1;
	}

	memcpy(ads, hit->origin, (unsigned int)n);
	ads[n] = '\0';

	i.address = ads;
	i.port = 80;
	if (hit->origin_protocol == LWSMPRO_HTTPS) {
		i.port = 443;
		i.ssl_connection = 1;
	}
	/* for a unix socket, what follows the colon is the path, not a port */
	if (pcolon && !unix_skt)
		i.port = atoi(pcolon + 1);

	rpath = lws_malloc(max_http_header_data, __func__);
	if (!rpath)
		return -1;

	/* scratch for the encoded path remainder, then each query fragment */
	enc = lws_malloc(max_http_header_data, __func__);
	if (!enc) {
		lws_free(rpath);

		return -1;
	}

	/*
	 * Only the part of the path that came from the request is re-encoded
	 * (see lws_http_pct_encode()); the origin's own path prefix is the
	 * operator's literal config and goes on as written.  The encoding
	 * keeps '/' and '.', so cleaning the composed url afterwards works
	 * the same as it did on the decoded one.
	 */

	if (lws_http_pct_encode(enc, max_http_header_data,
				 uri_ptr + hit->mountpoint_len,
				 strlen(uri_ptr + hit->mountpoint_len),
				 LWS_PROXY_KEEP_PATH) < 0) {
		lwsl_info("%s: encoded path longer than we can handle\n",
			  __func__);
		goto bail_len;
	}

	/* rpath needs cleaning after this... ---> */

	n = lws_snprintf(rpath, max_http_header_data - 1, "/%s/%s",
			 pslash + 1, enc) - 1;
	lws_clean_url(rpath);
	n = (int)strlen(rpath);
	{
		int orig_had_slash = 0;
		int u_len = (int)strlen(uri_ptr);
		if (u_len && uri_ptr[u_len - 1] == '/')
			orig_had_slash = 1;
		if (!orig_had_slash && n && rpath[n - 1] == '/')
			n--;
	}

	na = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS);
	if (na) {
		char *p, *end = &rpath[max_http_header_data - 1];

		if (!n) /* don't start with the ?... use the first / if so */
			n++;

		p = rpath + n;

		if (p + 1 >= end)
			goto bail_query_len;

		*p++ = '?';

		if (lws_http_requery(wsi, p, (size_t)(end - p)) < 0)
			goto bail_query_len;
	}

	lws_free_set_NULL(enc);

	i.path = rpath;
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	{
		char lp[128];

		lwsl_wsi_info(wsi, "proxied path '%s'",
			      lws_http_log_path(lp, sizeof(lp), i.path));
	}
#endif

	/* incoming may be h1 or h2... if he sends h1 HOST, use that
	 * directly, otherwise we must convert h2 :authority to h1
	 * host */

#if 0
	i.host = NULL;
#if defined(LWS_ROLE_H2)
	n = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY);
	if (n > 0)
		i.host = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY);
	else
#endif
	{
		n = lws_hdr_total_length(wsi, WSI_TOKEN_HOST);
		if (n > 0)
			i.host = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST);
	}
#endif
	i.host = i.address;

#if 0
	if (i.address[0] != '+' ||
	    !lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST))
		i.host = i.address;
	else
		i.host = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST);
#endif
	i.origin = NULL;
	if (!ws) {
		if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_POST_URI)
#if defined(LWS_WITH_HTTP2)
								|| (
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD) &&
			!strcmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_COLON_METHOD), "post")
			)
#endif
		)
			i.method = "POST";
		else if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PUT_URI)
#if defined(LWS_WITH_HTTP2)
								|| (
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD) &&
			!strcmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_COLON_METHOD), "put")
			)
#endif
		)
			i.method = "PUT";
		else if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PATCH_URI)
#if defined(LWS_WITH_HTTP2)
								|| (
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD) &&
			!strcmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_COLON_METHOD), "patch")
			)
#endif
		)
			i.method = "PATCH";
		else if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_DELETE_URI)
#if defined(LWS_WITH_HTTP2)
								|| (
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD) &&
			!strcmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_COLON_METHOD), "delete")
			)
#endif
		)
			i.method = "DELETE";
		else
			i.method = "GET";
	}

	if (i.host)
		lws_snprintf(host, sizeof(host), "%s:%u", i.host,
					wsi->a.vhost->listen_port);
	else
		lws_snprintf(host, sizeof(host), "%s:%d", i.address, i.port);

	i.host = host;

	i.alpn = "http/1.1";
	i.parent_wsi = wsi;
	i.pwsi = &cwsi;

	/*
	 * How the onward request, which is always h1, frames the body (C-698).
	 * A validated Content-Length is forwarded as it is.  A body with no
	 * length must not follow the onward request raw: without framing the
	 * backend takes the request as bodyless, and the body as whatever the
	 * client wants the next request on that connection to be, one the
	 * mount's interceptors never saw.
	 *
	 *  - h1 chunked, or an h2 stream with no content-length: the length is
	 *    only known when the body ends, so the onward request is chunked,
	 *    the body chunk-encoded as it goes and ended by a last-chunk at
	 *    the body completion
	 *
	 *  - an h1 POST / PUT / PATCH with neither header has no body (RFC
	 *    9112 6.3), and was framed as a Content-Length of zero when its
	 *    head was parsed (lws_http_request_body_framing()), so it is a
	 *    validated Content-Length here
	 *
	 *  - an h3 stream with no content-length ends its body with the FIN,
	 *    which gives us no body completion, so we could never end the
	 *    onward body: refuse it rather than hang both legs
	 *
	 * A POST / PUT / PATCH going onward with an empty body says so with a
	 * Content-Length of zero: an h1 backend that takes an unframed one as
	 * having a body would otherwise wait for it for ever.
	 */

	wsi->http.proxy_body_chunked = 0;
	wsi->http.proxy_body_complete = 0;
	wsi->http.proxy_body_ended = 0;

	if (!ws && !wsi->http.content_length_given &&
	    wsi->http.rx_content_length) {
		if (wsi->http.rx_chunked ||
		    (lwsi_role_h2(wsi) && wsi->mux_substream))
			wsi->http.proxy_body_chunked = 1;
		else {
			lwsl_wsi_notice(wsi, "proxy: request body has no length");
			lws_free(rpath);
			lws_return_http_status(wsi, HTTP_STATUS_LENGTH_REQUIRED,
					       NULL);

			return 1;
		}
	}

	if (!ws && !wsi->http.proxy_body_chunked &&
	    !wsi->http.rx_content_length &&
	    !lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
	    (!strcmp(i.method, "POST") || !strcmp(i.method, "PUT") ||
	     !strcmp(i.method, "PATCH")))
		zero_body = 1;

	/*
	 * Snapshot the request headers the onward leg forwards NOW, while the
	 * ah is certainly attached, onto the extra onward headers that both
	 * legs replay when they compose their handshake.  The composer runs
	 * asynchronously, arbitrarily far from LWS_CALLBACK_HTTP, and must not
	 * depend on the ah still being there (C-460).  This runs after the
	 * mount's interceptors, so anything they zapped is already gone and
	 * anything they injected is already in the list.  The body framing
	 * decided above goes with them.
	 */

	if (lws_http_proxy_snapshot_onward(wsi, ws) ||
	    (wsi->http.proxy_body_chunked &&
	     lws_http_onward_header_append(wsi, "transfer-encoding",
					   "chunked")) ||
	    (zero_body &&
	     lws_http_onward_header_append(wsi, "content-length", "0"))) {
		lws_free(rpath);

		return 1;
	}
#if defined(LWS_ROLE_WS)
	i.protocol = lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL);
	if (ws)
		i.local_protocol_name = "lws-ws-proxy";
#endif

//	i.uri_replace_from = hit->origin;
//	i.uri_replace_to = hit->mountpoint;

	/* the onward path was logged as "proxied path" above, without its query */
	lwsl_info("proxying to %s port %d, ssl %d\n", i.address, i.port,
		  i.ssl_connection);

	if (!lws_io_client_connect(&i)) {
		lwsl_err("proxy connect fail\n");

		/*
		 * ... we can't do the proxy action, but we can
		 * cleanly return him a 503 and a description
		 */

		lws_return_http_status(wsi,
			HTTP_STATUS_SERVICE_UNAVAILABLE,
			"<h1>Service Temporarily Unavailable</h1>"
			"The server is temporarily unable to service "
			"your request due to maintenance downtime or "
			"capacity problems. Please try again later.");
		lws_free(rpath);
		return 1;
	}
	lws_free(rpath);

	lwsl_info("%s: setting proxy clientside on %s (parent %s)\n",
		  __func__, lws_wsi_tag(cwsi), lws_wsi_tag(lws_get_parent(cwsi)));

	cwsi->http.mount_specific_keepalive_timeout_secs = (unsigned int)lws_wsi_keepalive_timeout_eff(wsi);

	cwsi->http.proxy_clientside = 1;
	if (!ws)
		wsi->http.proxy_relaying = 1;

	/*
	 * The onward leg used to decide this from the parent's Content-Length
	 * while composing its handshake; that is a late ah read, decide it
	 * here from the same header instead
	 */
	if (!ws && wsi->http.rx_content_length)
		cwsi->client_http_body_pending = 1;

	if (ws) {
		wsi->proxied_ws_parent = 1;
		cwsi->h1_ws_proxied = 1;
		if (i.protocol) {
			lwsl_debug("%s: (requesting '%s')\n",
					__func__, i.protocol);
		}
	}

	return 0;

bail_query_len:
	lwsl_info("%s: query string longer than we can handle\n", __func__);
bail_len:
	lws_free(enc);
	lws_free(rpath);

	return -1;
}
#endif


static const char * const oprot[] = {
	"http://", "https://"
};


static int
lws_http_redirect_hit(struct lws_context_per_thread *pt, struct lws *wsi,
		      const struct lws_http_mount *hit, char *uri_ptr,
		      int uri_len, int *h)
{
	char *s;
	int n;

	*h = 0;
	s = uri_ptr + hit->mountpoint_len;

	lwsl_debug("%s: hit %p, mountpoint '%s', origin '%s', protocol %d, s '%s'\n",
		    __func__, hit, hit->mountpoint, hit->origin ? hit->origin : "NULL",
		    hit->origin_protocol, s);

	/*
	 * if we have a mountpoint like https://xxx.com/yyy
	 * there is an implied / at the end for our purposes since
	 * we can only mount on a "directory".
	 *
	 * But if we just go with that, the browser cannot understand
	 * that he is actually looking down one "directory level", so
	 * even though we give him /yyy/abc.html he acts like the
	 * current directory level is /.  So relative urls like "x.png"
	 * wrongly look outside the mountpoint.
	 *
	 * Therefore if we didn't come in on a url with an explicit
	 * / at the end, we must redirect to add it so the browser
	 * understands he is one "directory level" down.
	 */
	if ((hit->origin_protocol == LWSMPRO_REDIR_HTTP ||
	     hit->origin_protocol == LWSMPRO_REDIR_HTTPS) ||
	    (hit->mountpoint_len > 1 &&
	     (uri_ptr[0] && uri_ptr[strlen(uri_ptr) - 1] != '/') &&
	     *s != '/' &&
	     hit->origin_protocol != LWSMPRO_CGI &&
	     hit->origin_protocol != LWSMPRO_CALLBACK)) {
		char peer_buf[64];
		unsigned char *start = pt->compose_buf + LWS_PRE, *p = start,
			      *end = p + wsi->a.context->pt_serv_buf_size -
					LWS_PRE - 512;

		*h = 1;

		lws_io_peer_address(wsi, peer_buf, sizeof(peer_buf));

		// lwsl_notice("Doing 301 '%s' (vhost port %d, peer %s) org %s\n", s,
		//	    wsi->a.vhost->listen_port, peer_buf, hit->origin);

		/* > at start indicates deal with by redirect */
		if (hit->origin_protocol == LWSMPRO_REDIR_HTTP ||
		    hit->origin_protocol == LWSMPRO_REDIR_HTTPS) {
			if (hit->append_path) {
				size_t ol = strlen(hit->origin);

				/*
				 * What follows the mountpoint is a path of
				 * its own after the origin.  A mountpoint of
				 * "/" leaves it without its leading '/', and
				 * appended straight on to an origin that has
				 * no trailing '/', it would carry on the
				 * origin's host name instead (/.x.example,
				 * /@x.example)
				 */
				n = lws_snprintf((char *)end, 256, "%s%s%s%s",
					    oprot[hit->origin_protocol & 1],
					    hit->origin,
					    *s && *s != '/' && (!ol ||
					      hit->origin[ol - 1] != '/') ?
								"/" : "", s);
			} else
				n = lws_snprintf((char *)end, 256, "%s%s",
					    oprot[hit->origin_protocol & 1],
					    hit->origin);
		} else {
			const char *host_hdr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST);
#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
			if (!host_hdr) {
				host_hdr = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY);
			}
#endif
			if (!host_hdr)
				goto bail_nuke_ah;

			if (host_hdr[0] == '+' || strchr(host_hdr, '/')) {
				n = lws_snprintf((char *)end, 256, "%s/", uri_ptr);
			} else {
				n = lws_snprintf((char *)end, 256,
				    "%s%s%s/", oprot[!!lws_is_ssl(wsi)],
				    host_hdr, uri_ptr);
			}
		}

		// lwsl_notice("%s: redirecting to '%s' (vhost port %d, peer %s)\n",
		//	    __func__, (char *)end, wsi->a.vhost->listen_port, peer_buf);

		lws_clean_url((char *)end);
		n = (int)strlen((char *)end);

		/*
		 * The request's query goes with it, where what follows the
		 * mountpoint does: to the same mount with its '/', or a
		 * redirect mount's origin that's given the rest of the path.
		 * It goes in after the url is cleaned, which is only for the
		 * path.  There are 512 bytes for all of it at end; if the
		 * query doesn't fit, say so rather than send it on without
		 */
		if ((!(hit->origin_protocol == LWSMPRO_REDIR_HTTP ||
		       hit->origin_protocol == LWSMPRO_REDIR_HTTPS) ||
		     hit->append_path) &&
		    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_URI_ARGS) > 0) {
			int q = -1;

			if (n + 2 < 511) {
				((char *)end)[n] = '?';
				q = lws_http_requery(wsi, (char *)end + n + 1,
						     (size_t)(511 - n - 1));
			}
			if (q < 0) {
				if (lws_return_http_status(wsi,
						HTTP_STATUS_REQ_URI_TOO_LONG,
						NULL))
					goto bail_nuke_ah;

				return lws_http_transaction_completed(wsi);
			}
			n += 1 + q;
		}

		n = lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
				      end, n, &p, end);
		if ((int)n < 0)
			goto bail_nuke_ah;

		return lws_http_transaction_completed(wsi);
	}

	return 0;

bail_nuke_ah:
	lws_header_table_detach(wsi, 1);

	return 1;
}

/*
 * Walk the mount's interceptor chain and give each interceptor protocol the
 * chance to take the request away from the mount it was aimed at.
 *
 * This is the single place the decision is made, for every role and every
 * method, through lws_http_mount_gates(): http requests arrive there from
 * lws_http_action() below, and h2 POSTs from
 * lws_h2_bind_for_post_before_action(), which dispatches them itself and
 * would otherwise be a way in that no interceptor ever sees; upgrades on any
 * role from lws_http_upgrade_gates().  It must be called before the mount's
 * protocol is bound and before LWS_CALLBACK_HTTP is delivered, ie, before any
 * user code for the protected mount can run.
 *
 * Returns
 *
 *  - the interceptor's mount, having pointed uri_ptr / uri_len at its
 *    mountpoint (a forced internal redirect), if an interceptor took the
 *    request.  wsi->http.interceptor_diverted is then set for this
 *    transaction, so the interceptor's own LWS_CALLBACK_HTTP can tell a
 *    request that was gated and sent to it from one the peer addressed to
 *    its own mountpoint (eg, a captcha or login form POST)
 *
 *  - hit unchanged, if the request may proceed to the mount it asked for
 *
 *  - NULL if the chain cannot be evaluated (a configured interceptor
 *    protocol does not exist).  This fails CLOSED: the caller must refuse
 *    the request rather than serve the mount
 *
 * The chain is asked once per transaction, whatever path the request takes
 * through the gates.  Asking the interceptors twice had each of them do
 * whatever it does for a request twice: lws-login stamped its x-lws-login-*
 * headers twice, and a backend rightly refuses duplicates as a possible
 * spoof.  Later calls for the same mount get the first answer.
 */

const struct lws_http_mount *
lws_http_evaluate_interceptors(struct lws *wsi, const struct lws_http_mount *hit,
			       char **uri_ptr, int *uri_len)
{
#if defined(LWS_WITH_JOSE)
	const struct lws_http_mount *curr = hit;

	if (wsi->http.interceptors_evaluated &&
	    wsi->http.interceptor_hit == hit) {
		const struct lws_http_mount *r = wsi->http.interceptor_result;

		if (r != hit) {
			*uri_ptr = (char *)r->mountpoint;
			*uri_len = (int)r->mountpoint_len;
		}

		return r;
	}

	while (curr && curr->interceptor_path) {
		const struct lws_http_mount *m_interceptor = lws_find_mount(wsi,
					curr->interceptor_path, (int)strlen(curr->interceptor_path));

		if (!m_interceptor || !m_interceptor->protocol)
			break;

		const struct lws_protocols *p = lws_vhost_name_to_protocol(
							wsi->a.vhost, m_interceptor->protocol);

		if (p) {
			if (p->callback(wsi, LWS_CALLBACK_HTTP_INTERCEPTOR_CHECK,
				       wsi->user_space, (void *)p, 0)) {

				*uri_ptr = (char *)m_interceptor->mountpoint; /* forced internal redirect */
				*uri_len = (int)m_interceptor->mountpoint_len;
				wsi->http.interceptor_diverted = 1;
				wsi->http.interceptors_evaluated = 1;
				wsi->http.interceptor_hit = hit;
				wsi->http.interceptor_result = m_interceptor;
				return m_interceptor;
			}
		} else {
			lwsl_err("%s: Interceptor protocol '%s' not found, denying access\n",
				 __func__, m_interceptor->protocol);
			return NULL; /* Fail CLOSED */
		}
		curr = m_interceptor;
	}

	wsi->http.interceptors_evaluated = 1;
	wsi->http.interceptor_hit = hit;
	wsi->http.interceptor_result = hit;
#endif

	return hit;
}

/*
 * Is the request's Expect exactly "100-continue" (case-insensitive, surrounding
 * whitespace ignored)?  That is the only expectation defined; any other
 * value is 417 Expectation Failed (RFC 9110 10.1.1).
 */

static int
lws_http_expect_is_continue(struct lws *wsi)
{
	char ex[32], *p = ex, *e;

	if (lws_hdr_copy_fragment(wsi, ex, sizeof(ex) - 1,
				  WSI_TOKEN_HTTP_EXPECT, 1) != -1)
		return 0;

	if (lws_hdr_copy(wsi, ex, sizeof(ex) - 1, WSI_TOKEN_HTTP_EXPECT) <= 0)
		return 0;

	while (*p == ' ' || *p == '\t')
		p++;
	e = p + strlen(p);
	while (e > p && (e[-1] == ' ' || e[-1] == '\t'))
		e--;

	return e - p == 12 && !strncasecmp(p, "100-continue", 12);
}

/*
 * Did the h2 / h3 request's header block not fit, so it is to be answered
 * with 431?
 */
static int
lws_http_hdrs_oversized(struct lws *wsi)
{
#if defined(LWS_WITH_HTTP2)
	if (lws_wsi_is_h2(wsi) && wsi->h2.hdrs_oversized)
		return 1;
#endif
#if defined(LWS_ROLE_H3)
	if (lws_wsi_is_h3(wsi) && wsi->h3.hdrs_oversized)
		return 1;
#endif
	(void)wsi;

	return 0;
}

/*
 * What an h1 request says of how it is to be answered: the version the
 * answer speaks, and whether the connection is kept after it
 */
static void
lws_h1_request_framing(struct lws *wsi)
{
	enum http_conn_type conn_type;
	char http_conn_str[20];

	wsi->stream.request_version = lws_h1_request_version(wsi);

	/* HTTP/1.1 defaults to "keep-alive", 1.0 to "close" */
	if (wsi->stream.request_version == HTTP_VERSION_1_1)
		conn_type = HTTP_CONNECTION_KEEP_ALIVE;
	else
		conn_type = HTTP_CONNECTION_CLOSE;

	/* Override default if http "Connection:" header: */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION) &&
	    lws_hdr_copy(wsi, http_conn_str, sizeof(http_conn_str) - 1,
			 WSI_TOKEN_CONNECTION) > 0) {
		http_conn_str[sizeof(http_conn_str) - 1] = '\0';
		if (!strcasecmp(http_conn_str, "keep-alive"))
			conn_type = HTTP_CONNECTION_KEEP_ALIVE;
		else
			if (!strcasecmp(http_conn_str, "close"))
				conn_type = HTTP_CONNECTION_CLOSE;
	}
	wsi->http.conn_type = conn_type;
}

/*
 * A request body's timeout.  Each piece renews the wait for the next, up to
 * timeout_secs, but the body as a whole must also keep up with the vhost's
 * minimum rate (G-028): it may take the grace time from its request's
 * headers, plus a second for each http_body_min_rate bytes of it taken so
 * far.  Whichever comes sooner is armed.  A body already behind is given up
 * on now, as the timeout would, which resets an h2 / h3 stream, giving back
 * its ah, or closes an h1 connection.
 */
void
lws_http_body_timeout_arm(struct lws *wsi)
{
	const struct lws_vhost *vh = wsi->a.vhost;
	lws_usec_t to = (lws_usec_t)wsi->a.context->timeout_secs *
							LWS_US_PER_SEC,
		   now, spent, allowed;
	uint64_t secs;

	if (vh->http_body_min_rate == LWS_HTTP_BODY_MIN_RATE_NONE ||
	    wsi->mux_stream_immortal) {
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
				(int)wsi->a.context->timeout_secs);
		return;
	}

	now = lws_wsi_now(wsi);
	if (!wsi->http.rx_body_start)
		wsi->http.rx_body_start = now;
	spent = now - wsi->http.rx_body_start;

	/* a day's worth of credit is as good as no limit, and can't wrap */
	secs = wsi->http.rx_body_count / vh->http_body_min_rate;
	if (secs < 86400) {
		allowed = (lws_usec_t)(vh->http_body_grace_secs + secs) *
								LWS_US_PER_SEC +
			  (lws_usec_t)(((wsi->http.rx_body_count %
				vh->http_body_min_rate) * LWS_US_PER_SEC) /
					vh->http_body_min_rate);

		if (spent >= allowed) {
			lwsl_wsi_notice(wsi, "body too slow: %llu bytes in "
					"%llums, giving up",
					(unsigned long long)
						wsi->http.rx_body_count,
					(unsigned long long)
						(spent / LWS_US_PER_MS));
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
					LWS_TO_KILL_ASYNC);
			return;
		}

		if (allowed - spent < to)
			to = allowed - spent;
	}

	lws_set_timeout_us(wsi, PENDING_TIMEOUT_HTTP_CONTENT, to);
}

/*
 * How the request's body is framed: its Content-Length, or a chunked
 * Transfer-Encoding, validated into rx_content_length, rx_content_remain,
 * content_length_given and rx_chunked.  A request we might frame differently
 * from its peer, or from something in front of us, is answered here, and the
 * caller closes (nonzero return).
 *
 * The completion of the transaction relies on it: it is what says how much of
 * what follows the head is this request's body, to be stepped over, and not
 * the next request.  So it must be decided before anything can answer the
 * request: for h1 that is as soon as the head is parsed, in
 * lws_handshake_server(), since the mount's redirect and a refused upgrade are
 * answered there.  h2 / h3 frame their bodies themselves, and decide it in
 * lws_http_action_gates(), whichever path dispatches the request.
 */
static int
lws_http_request_body_framing(struct lws *wsi)
{
	uint64_t max_body = wsi->a.vhost->max_http_body_size ?
			wsi->a.vhost->max_http_body_size : 100 * 1024 * 1024;
	char content_length_str[32];

	wsi->http.rx_content_length = 0;
	wsi->http.content_length_explicitly_zero = 0;
	/* per-transaction: the last request's framing says nothing of this one's */
	wsi->http.content_length_given = 0;
	wsi->http.rx_body_done = 0;
	/* the body's minimum rate is counted from its request's headers */
	wsi->http.rx_body_start = lws_wsi_now(wsi);
	wsi->http.rx_body_count = 0;
	wsi->http.expect_continue = 0;
	/* no status line has been built for this transaction yet */
	wsi->http.response_code = 0;
	/*
	 * An h2 / h3 stream's body ends with the stream: a body-bearing method
	 * with no Content-Length is read until then, bounded by the body
	 * limit.  An h1 request has no such end, and one with neither
	 * Content-Length nor Transfer-Encoding has no body at all, whatever
	 * its method (RFC 9112 6.3): that is decided below, once both headers
	 * have been looked at.
	 */
	if (wsi->mux_substream &&
	    (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
			||
	     lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI) ||
	     lws_hdr_total_length(wsi, WSI_TOKEN_PUT_URI)
#endif
	    )) {
		wsi->http.rx_content_length = max_body;
		if (!wsi->http.rx_content_remain)
			wsi->http.rx_content_remain = max_body;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
		lwsl_warn("%s: Both Content-Length and Transfer-Encoding present\n", __func__);
		lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
		return 1;
	}

	/*
	 * RFC 9112 3.2: more than one Host is a 400.  Vhost selection,
	 * the proxy and cgi read the first fragment and the redirect
	 * path the joined value, so two of them would let a request
	 * be routed by one name and act under another.
	 */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HOST) &&
	    wsi->stream.ah->frags[wsi->stream.ah->frag_index[
				WSI_TOKEN_HOST]].nfrag) {
		lwsl_wsi_notice(wsi, "more than one Host header");
		lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, NULL);
		return 1;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_EXPECT) &&
	    !lws_http_expect_is_continue(wsi)) {
		lwsl_wsi_notice(wsi, "unsupported Expect");
		lws_return_http_status(wsi,
			HTTP_STATUS_EXPECTATION_FAILED, NULL);
		return 1;
	}
	/* what lws_http_action() decides on after the headers may be gone */
	wsi->http.expect_continue =
			!!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_EXPECT);

	wsi->http.rx_chunked = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
		/*
		 * h2 and h3 refuse Transfer-Encoding at their framing
		 * layer, so this is an h1 request.  The only coding we
		 * decode is a lone "chunked": anything else, including
		 * a list that ends in chunked, gets 501 (RFC 7230
		 * 3.3.1), since a body we would frame differently from
		 * the peer or an intermediary is not something to
		 * guess at.
		 */
		if (!lws_http_te_is_chunked(wsi)) {
			lwsl_wsi_notice(wsi, "unsupported Transfer-Encoding");
			lws_return_http_status(wsi,
				HTTP_STATUS_NOT_IMPLEMENTED, NULL);
			return 1;
		}

		wsi->http.rx_chunked = 1;
		wsi->http.chunk_parser = ELCP_HEX;
		wsi->http.chunk_remaining = 0;
		wsi->http.chunk_skip = 0;

		/*
		 * The body length is only known when the last-chunk
		 * arrives: rx_content_remain counts the decoded payload
		 * down from the body limit instead.  This applies to
		 * any method: a GET with a chunked body still has a
		 * body we must decode past to stay in sync with the
		 * peer.
		 */
		wsi->http.rx_content_length = max_body;
		wsi->http.rx_content_remain = max_body;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		uint64_t cl_val = 0;

		/*
		 * More than one Content-Length is a framing
		 * disagreement waiting to happen.  A second fragment
		 * exists unless lws_hdr_copy_fragment() reports there
		 * is none (-1)... -2 means there is one but it did not
		 * fit in our buffer, which is just as unacceptable.
		 */

		if (lws_hdr_copy_fragment(wsi, content_length_str,
					  sizeof(content_length_str) - 1,
					  WSI_TOKEN_HTTP_CONTENT_LENGTH,
					  1) != -1) {
			lwsl_warn("%s: multiple Content-Length headers\n",
				  __func__);
			lws_return_http_status(wsi,
					HTTP_STATUS_BAD_REQUEST, NULL);
			return 1;
		}

		/*
		 * A Content-Length that is too long for us to even
		 * copy must be rejected rather than ignored: ignoring
		 * it leaves us framing the connection differently from
		 * whatever intermediary did understand it.
		 */

		if (lws_hdr_copy(wsi, content_length_str,
				 sizeof(content_length_str) - 1,
				 WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0 ||
		    lws_http_parse_content_length(content_length_str,
						  &cl_val)) {
			lwsl_warn("%s: invalid Content-Length: %s\n",
				  __func__, content_length_str);
			lws_return_http_status(wsi,
					HTTP_STATUS_BAD_REQUEST, NULL);
			return 1;
		}

		if (cl_val > max_body) {
			lwsl_warn("%s: rejected Content-Length %llu > max %llu\n",
				  __func__, (unsigned long long)cl_val,
				  (unsigned long long)max_body);
			lws_return_http_status(wsi,
				HTTP_STATUS_REQ_ENTITY_TOO_LARGE, NULL);
			return 1;
		}

		wsi->http.rx_content_remain = wsi->http.rx_content_length =
				(lws_filepos_t)cl_val;
		wsi->http.content_length_given = 1;
		if (!wsi->http.rx_content_length) {
			wsi->http.content_length_explicitly_zero = 1;
			lwsl_debug("%s: explicit 0 content-length\n", __func__);
		}
	}
#if defined(LWS_ROLE_H2)
	else if (lwsi_role_h2(wsi) && wsi->mux_substream && wsi->h2.END_STREAM &&
		 !wsi->buflist) {
		/*
		 * h2 with no Content-Length, but END_STREAM already arrived on
		 * the HEADERS (and nothing is stashed on the buflist: since
		 * C-378 END_STREAM is also latched by the DATA frame that ends
		 * a body, and a body that arrived stashed with the HEADERS
		 * must not be zeroed away here, lws_read_h1() completes it
		 * from the buflist instead): the request body is empty and
		 * complete.  Without
		 * this, a body-bearing method (POST/PUT/PATCH) would be left
		 * waiting on the 100MB default above for a body that will never
		 * come, stalling the request until it times out.  Treat it as an
		 * explicit zero-length body, exactly as an explicit
		 * "Content-Length: 0" would (h3 does the equivalent in ops-h3.c).
		 */
		wsi->http.rx_content_remain = wsi->http.rx_content_length = 0;
		wsi->http.content_length_given = 1;
		wsi->http.content_length_explicitly_zero = 1;
		lwsl_debug("%s: h2 END_STREAM, no content-length: empty body\n",
			   __func__);
	}
#endif
	else if (!wsi->mux_substream && !wsi->http.rx_chunked) {
		/*
		 * An h1 request with neither Content-Length nor
		 * Transfer-Encoding has no body, whatever its method (RFC
		 * 9112 6.3): what follows its head on the connection is the
		 * next request.  A POST is told so as one saying
		 * "Content-Length: 0" is, an empty HTTP_BODY and then its
		 * HTTP_BODY_COMPLETION, so an app that takes a form from
		 * those sees the same either way.
		 */
		wsi->http.rx_content_remain = wsi->http.rx_content_length = 0;
		wsi->http.content_length_given = 1;
		wsi->http.content_length_explicitly_zero = 1;
	}

	return 0;
}

/*
 * The request has been dispatched as far as user code is ever allowed to look
 * at its headers: after LWS_CALLBACK_HTTP for a request with no body, after
 * LWS_CALLBACK_HTTP_BODY_COMPLETION for one with.  Everything the library
 * itself still needs from them is snapshotted on the wsi by then (the method,
 * the http version, the connection type, the compression, the Range, the
 * access log line, the proxy's onward headers), so the ah can go back to the
 * pool instead of being held for the whole transaction.  This is the same
 * thing the ws upgrade has always done after LWS_CALLBACK_ESTABLISHED, cgi
 * does at spawn, and SSE does at lws_http_mark_sse().
 *
 * It is done for mux streams (h2, h3): a stream carries exactly one
 * transaction, and every one of a connection's concurrent streams used to pin
 * an ah for its whole life, so a few connections could hold the whole pool and
 * stall everyone else's header parsing (C-021).  An h1 connection keeps its ah
 * until the transaction completes for now: its rx path attaches a table to a
 * connection without one as soon as a pipelined request arrives, which reset
 * the transaction under the response (what sent the first attempt at this,
 * C-460, back).  User code must not rely on that: the documented window is the
 * same for every role.
 *
 * Deciding whether this wsi may let go lives here rather than at the call
 * sites, so every role reaches the same conclusion.
 */

void
lws_http_mux_body_completed(struct lws *wsi)
{
	/*
	 * Not if the callback completed the transaction, or closed: the body
	 * is nothing to that stream any more
	 */
	if (lwsi_state(wsi) == LRS_BODY || lwsi_state(wsi) == LRS_ISSUING_FILE)
		lws_wsi_event(wsi, LWS_WSIEV_BODY_COMPLETE);
}

int
lws_http_body_completion(struct lws *wsi)
{
	/*
	 * The peer can make the body look complete again after it was, eg,
	 * with more DATA on an h2 stream whose content-length was met, or a
	 * trailers block and an empty DATA on h3.  The roles refuse that, but
	 * whatever gets here, user code is told once: it may answer, free its
	 * per-request state or act on the request then, and a second time
	 * would be a second request it never got.
	 */
	if (wsi->http.rx_body_done)
		return 0;

	wsi->http.rx_body_done = 1;

	return wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP_BODY_COMPLETION,
					 wsi->user_space, NULL, 0);
}

void
lws_http_ah_release_after_dispatch(struct lws *wsi, char body_done)
{
	if (!wsi->stream.ah || !wsi->mux_substream)
		return;

#if defined(LWS_WITH_CLIENT)
	if (lwsi_role_client(wsi))
		/* a client ah holds the response headers, not a request */
		return;
#endif

	if (lwsi_hdrs_pending(wsi) ||
	    lwsi_state(wsi) == LRS_DEFERRING_ACTION)
		/* not dispatched yet: the headers are still the request's */
		return;

	if (!body_done)
		switch (lwsi_state(wsi)) {
		case LRS_BODY:
		case LRS_DISCARD_BODY:
			/*
			 * A request body is still to come, and user code may
			 * read the request headers up to and including
			 * LWS_CALLBACK_HTTP_BODY_COMPLETION: the body
			 * completion path calls us again with body_done set
			 */
			return;
		default:
			break;
		}

#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi)
		/* cgi owns the ah lifetime itself, and let go at spawn time */
		return;
#endif

#if defined(LWS_WITH_HTTP_PROXY)
	if (wsi->http.proxy_clientside || lws_get_child(wsi))
		/*
		 * A proxy leg: the onward leg's ah is its own client-side
		 * business, and the client-facing parent's is released when
		 * its transaction ends
		 */
		return;
#endif

	lwsl_wsi_debug(wsi, "releasing request headers after dispatch");

	/*
	 * autoservice 0: a wsi waiting for an ah gets this one with its
	 * POLLIN re-enabled and is serviced by the event loop, not
	 * reentrantly from inside the dispatch we are completing
	 */
	lws_header_table_detach(wsi, 0);
}

/*
 * The request gates.
 *
 * Everything a request passes before anything mounted may act on it lives in
 * these three helpers, run in this order: lws_http_action_request(), then
 * lws_http_action_gates(), then for a mount bound to a protocol,
 * lws_http_action_bind_mount().  lws_http_action() uses them for every role,
 * and so does lws_h2_bind_for_post_before_action(), which dispatches h2 POSTs
 * itself because of how their body is delivered.  Keeping the gates here, and
 * only here, is what stops a gate added later from applying on one path and
 * not the other: the h2 POST path used to carry its own partial copy, and
 * skipped the app's FILTER_HTTP_CONNECTION and CHECK_ACCESS_RIGHTS and the
 * body size limits (G-001), as it had skipped the interceptors (C-461).
 *
 * The part of lws_http_action_gates() that belongs to the mount the request
 * landed in, its redirect, its interceptor chain and its basic auth, is
 * lws_http_mount_gates().
 *
 * Each returns 0 to let the request on, or 1 if it decided the request
 * (answered it, refused it, or the app took it over): g->verdict is then what
 * lws_http_action() returns for it.
 */

/*
 * Take a copy of the request's Content-Type, if it has one, replacing
 * anything left from an earlier request on the connection.  The ah bounds
 * how long it can be.  Returns nonzero only on OOM.
 */
static int
lws_http_snapshot_content_type(struct lws *wsi)
{
	int len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE);

	lws_free_set_NULL(wsi->http.content_type);

	if (len <= 0)
		return 0;

	wsi->http.content_type = lws_malloc((size_t)len + 1, "content-type");
	if (!wsi->http.content_type)
		return 1;

	if (lws_hdr_copy(wsi, wsi->http.content_type, len + 1,
			 WSI_TOKEN_HTTP_CONTENT_TYPE) != len) {
		lws_free_set_NULL(wsi->http.content_type);

		return 1;
	}

	return 0;
}

static int
lws_http_gate_bail(struct lws *wsi, struct lws_http_gate *g)
{
	lws_header_table_detach(wsi, 1);
	g->verdict = 1;

	return 1;
}

int
lws_http_action_request(struct lws *wsi, struct lws_http_gate *g)
{
	/*
	 * An h2 / h3 request whose headers did not fit was decoded to the end
	 * without keeping them, so there is nothing here to act on: say why.
	 * (h1 answers the same from its parser, since it cannot get this far
	 * without the whole request line and headers.)
	 */
	if (lws_http_hdrs_oversized(wsi)) {
		lws_return_http_status(wsi,
				HTTP_STATUS_REQ_HEADER_FIELDS_TOO_LARGE,
				"Oversized headers");
		return lws_http_gate_bail(wsi, g);
	}

	g->meth = lws_http_get_uri_and_method(wsi, &g->uri_ptr, &g->uri_len);
	if (g->meth < 0) {
		lwsl_debug("%s: %p: no uri and method\n", __func__, wsi);
		return lws_http_gate_bail(wsi, g);
	}

	if (g->meth >= (int)LWS_ARRAY_SIZE(method_names)) {
#if (_LWS_ENABLED_LOGS & LLL_WARN)
		char name[LWS_PEER_DESC_LEN];
		lwsl_wsi_warn(wsi, "invalid method %d: %s", g->meth,
			      lws_io_peer_describe(wsi, name, sizeof(name),
						   LWS_PEER_DESC_BARE_SINGLE));
#endif
		return lws_http_gate_bail(wsi, g);
	}

	/*
	 * Snapshot what the method was, while the ah is certainly still
	 * attached: the request headers are released once the request has been
	 * dispatched (C-460), but the file-serve path still has to know not to
	 * emit a body for a HEAD, and lws_http_action() whether an empty body
	 * is a POST's after a cgi mount let the headers go.  Re-decided for
	 * every request, so a keepalive connection cannot carry a stale answer
	 * into the next one.
	 */

	wsi->http.method_head = methods[g->meth] == WSI_TOKEN_HEAD_URI;
	wsi->http.method_post = methods[g->meth] == WSI_TOKEN_POST_URI;

	/*
	 * ... and the Content-Type, for an lws_spa created after the headers
	 * may have gone (lws_urldecode_s_create()): without it a multipart
	 * form would silently be parsed as urlencoded
	 */
	if (lws_http_snapshot_content_type(wsi))
		return lws_http_gate_bail(wsi, g);
#if defined(LWS_WITH_HTTP_BASIC_AUTH)
	/* an earlier request's authorization says nothing about this one */
	lws_free_set_NULL(wsi->http.basic_auth_user);
#endif

	/*
	 * ... and what a file served for it later needs to know: whether a
	 * pre-gzipped copy is acceptable, the codings the answer may be
	 * compressed with on the fly (on every role), and the Range: it asked
	 * for
	 */
	{
		const char *ae = lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_ACCEPT_ENCODING);

		wsi->http.accept_gzip = ae && strstr(ae, "gzip");
	}
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	lws_http_compression_validate(wsi);
#endif
#if defined(LWS_WITH_RANGES)
	if (lws_ranges_snapshot(wsi, &wsi->http.range))
		return lws_http_gate_bail(wsi, g);
#endif

	lws_metrics_tag_wsi_add(wsi, "vh", wsi->a.vhost->name);
	lws_metrics_tag_wsi_add(wsi, "meth", method_names[g->meth]);

	/* we insist on absolute paths */

	if (!g->uri_ptr || g->uri_ptr[0] != '/') {
#if (_LWS_ENABLED_LOGS & LLL_WARN)
		char name[LWS_PEER_DESC_LEN];
		lwsl_wsi_warn(wsi, "missing or non-absolute uri_ptr (meth=%d, "
			      "uri_len=%d, uri_ptr=%p): peer %s", g->meth,
			      (int)g->uri_len, (void *)g->uri_ptr,
			      lws_io_peer_describe(wsi, name, sizeof(name),
						   LWS_PEER_DESC_BARE_SINGLE));
#endif
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		return lws_http_gate_bail(wsi, g);
	}

	lwsl_debug("Method: '%s' (%d), request for '%s' (vhost '%s')\n",
		   method_names[g->meth], g->meth, g->uri_ptr,
		   wsi->a.vhost->name);

	return 0;
}

/*
 * The mount's own gates, for a request that landed in it: its redirect, its
 * interceptor chain and its basic auth, in that order.  g->uri_ptr / uri_len
 * are the request path, and are repointed at the interceptor's mountpoint if
 * an interceptor takes the request.  For an upgrade, an interceptor that would
 * take the request refuses it with 401 instead.  Returns 0 with g->hit set to
 * the mount to act on, or 1 having decided the request, with g->verdict set.
 */
static int
lws_http_mount_gates(struct lws *wsi, struct lws_http_gate *g,
		     const struct lws_http_mount *hit, int upgrade)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const struct lws_http_mount *ihit;
	int ha, n;

	n = lws_http_redirect_hit(pt, wsi, hit, g->uri_ptr, g->uri_len, &ha);
	if (ha) {
		g->verdict = n;

		return 1;
	}

	/*
	 * If the mount has a interceptor requirement, and the plugin that implements
	 * it says we are not authorized, divert the connection to the interceptor
	 * mount
	 */
	ihit = lws_http_evaluate_interceptors(wsi, hit, &g->uri_ptr, &g->uri_len);
	if (!ihit) {
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
		return lws_http_gate_bail(wsi, g);
	}

	if (upgrade && ihit != hit) {
		/*
		 * An interceptor would not let the upgrade through.  A login
		 * page is no answer to an upgrade, so refuse it instead of
		 * diverting it
		 */
		lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
		return lws_http_gate_bail(wsi, g);
	}

#if defined(LWS_WITH_HTTP_BASIC_AUTH)

#if defined(LWS_WITH_HTTP_DIGEST_AUTH)
	/* digest auth? */

	if ((ihit->auth_mask & AUTH_MODE_MASK) == LWSAUTHM_DIGEST_AUTH)
		switch (lws_check_digest_auth(wsi, ihit->basic_auth_login_file,
					      ihit->basic_auth_realm)) {
		case LCBA_CONTINUE:
		case LCBA_AUTH_RETRY_KEEPALIVE:
			break;
		case LCBA_FAILED_AUTH:
			g->verdict = lws_unauthorised_digest_auth(wsi,
							ihit->basic_auth_realm);
			return 1;
		case LCBA_END_TRANSACTION:
			lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN,
					       NULL);
			g->verdict = lws_http_transaction_completed(wsi);
			return 1;
		}
	else
#endif
	/* basic auth? */

	switch (lws_check_basic_auth(wsi, ihit->basic_auth_login_file,
				     ihit->auth_mask & AUTH_MODE_MASK)) {
	case LCBA_CONTINUE:
	case LCBA_AUTH_RETRY_KEEPALIVE:
		break;
	case LCBA_FAILED_AUTH:
		g->verdict = lws_unauthorised_basic_auth(wsi);
		return 1;
	case LCBA_END_TRANSACTION:
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
		g->verdict = lws_http_transaction_completed(wsi);
		return 1;
	}

	/*
	 * An http request meets no other basic auth check after this one.  An
	 * upgrade may still meet its protocol's "basic-auth" pvo, which has to
	 * see the credentials as sent: that publishes the user instead.
	 */
	if (!upgrade)
		lws_http_basic_auth_rewrite(wsi);
#endif

	g->hit = ihit;

	return 0;
}

/*
 * The gates for an upgrade: a ws upgrade on any role (h1, or an h2 / h3
 * extended CONNECT), and a WebTransport CONNECT.  Before anything binds a
 * protocol for it or proxies it onward, it passes the gates of the mount its
 * path lands in, as an http request to the same path would, the mount's basic
 * auth included.  A ws upgrade to a proxying mount used to go straight to the
 * backend, unauthenticated (G-489).
 *
 * g->uri_ptr / uri_len are the request path.  Returns 0 to let the upgrade
 * on, or 1 having decided the request, with g->verdict set.
 */
static int
lws_http_upgrade_gates(struct lws *wsi, struct lws_http_gate *g)
{
	const struct lws_http_mount *hit;

	g->hit = NULL;
	g->mount_rel = NULL;

	hit = lws_find_mount(wsi, g->uri_ptr, g->uri_len);
	if (!hit)
		return 0;

	/* the basic auth callback, and the interceptors, are given it */
	if (lws_ensure_user_space(wsi))
		return lws_http_gate_bail(wsi, g);

	g->mount_rel = g->uri_ptr + hit->mountpoint_len;

	return lws_http_mount_gates(wsi, g, hit, 1);
}

int
lws_http_action_gates(struct lws *wsi, struct lws_http_gate *g)
{
	const struct lws_http_mount *hit;
	unsigned int n;

	g->hit = NULL;
	g->mount_rel = NULL;

	if (lws_ensure_user_space(wsi))
		return lws_http_gate_bail(wsi, g);

	/*
	 * An h1 request's body framing was decided with its head, in
	 * lws_handshake_server(), before anything could answer it
	 */
	if (wsi->mux_substream && lws_http_request_body_framing(wsi)) {
		g->verdict = 1;
		return 1;
	}

	if (wsi->mux_substream)
		wsi->stream.request_version = HTTP_VERSION_2;
	else
		lws_h1_request_framing(wsi);

	n = (unsigned int)wsi->a.protocol->callback(wsi,
				LWS_CALLBACK_FILTER_HTTP_CONNECTION,
				wsi->user_space, g->uri_ptr,
				(unsigned int)g->uri_len);
	if (n) {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
		char name[LWS_PEER_DESC_LEN];

		lwsl_notice("User code denied HTTP connection: protocol=%s, "
			    "peer=%s, uri=%s\n", wsi->a.protocol->name,
			    lws_io_peer_describe(wsi, name, sizeof(name),
						 LWS_PEER_DESC_BARE_SINGLE),
			    g->uri_ptr);
#endif
		g->verdict = 1;

		return 1;
	}
	/*
	 * if there is content supposed to be coming,
	 * put a timeout on it having arrived
	 */
	if (!wsi->mux_stream_immortal)
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
				(int)wsi->a.context->timeout_secs);

#ifdef LWS_WITH_ACCESS_LOG
	lws_prepare_access_log_info(wsi, g->uri_ptr, g->uri_len, g->meth);
#endif

	/* can we serve it from the mount list? */

	wsi->mount_hit = 0;
	wsi->http.mount_specific_headers = NULL;
	wsi->http.mount_specific_keepalive_timeout_secs = 0;

	hit = lws_find_mount(wsi, g->uri_ptr, g->uri_len);
	lwsl_debug("%s: lws_find_mount returned %p (%s) for wsi %p\n", __func__,
		   hit, hit ? hit->mountpoint : "none", wsi);
	if (!hit)
		/* nothing further to gate: the vhost's own protocol has it */
		return 0;

	wsi->mount_hit = 1;
	wsi->http.mount_specific_headers = hit->headers;
	wsi->http.mount_specific_keepalive_timeout_secs = hit->keepalive_timeout;

	if (hit->max_http_body_size) {
		if (wsi->http.content_length_given) {
			if (wsi->http.rx_content_length > hit->max_http_body_size) {
				lwsl_warn("%s: mount rejected Content-Length %llu > max %llu\n",
					__func__, (unsigned long long)wsi->http.rx_content_length,
					(unsigned long long)hit->max_http_body_size);
				lws_return_http_status(wsi, HTTP_STATUS_REQ_ENTITY_TOO_LARGE, NULL);
				g->verdict = 1;

				return 1;
			}
		} else if (wsi->http.rx_content_length >
						hit->max_http_body_size) {
			/*
			 * A body with no length up front (chunked, or an h2 /
			 * h3 stream's, ended by the stream): the mount's limit
			 * is its countdown.  A request with no body has none
			 * to limit, and must not be given one to wait for.
			 */
			wsi->http.rx_content_length = hit->max_http_body_size;
			wsi->http.rx_content_remain = hit->max_http_body_size;
		}
	}

	/*
	 * What follows the mountpoint in the path the peer asked for, taken
	 * before an interceptor may repoint the path at its own mountpoint
	 */
	g->mount_rel = g->uri_ptr + hit->mountpoint_len;

	return lws_http_mount_gates(wsi, g, hit, 0);
}

int
lws_http_action_bind_mount(struct lws *wsi, struct lws_http_gate *g)
{
	const struct lws_http_mount *hit = g->hit;
	struct lws_process_html_args args;
	const struct lws_protocols *pp;
	const char *name = hit->protocol ? hit->protocol : hit->origin;

	/*
	 * For the duration of this http transaction, bind us to the
	 * protocol mounted here
	 */

	pp = lws_vhost_name_to_protocol(wsi->a.vhost, name);
	if (!pp) {
		lwsl_err("Unable to find plugin '%s'\n", name);
		g->verdict = 1;

		return 1;
	}

	if (lws_bind_protocol(wsi, pp, "http action CALLBACK bind")) {
		g->verdict = 1;

		return 1;
	}

	lwsl_debug("%s: %s, checking access rights for mask 0x%x\n",
			__func__, hit->origin, hit->auth_mask);

	args.p = g->uri_ptr;
	args.len = g->uri_len;
	args.max_len = hit->auth_mask & ~AUTH_MODE_MASK;
	args.final = 0; /* used to signal callback dealt with it */
	args.chunked = 0;

	if (wsi->a.protocol->callback(wsi, LWS_CALLBACK_CHECK_ACCESS_RIGHTS,
				      wsi->user_space, &args, 0)) {
		lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, NULL);
		return lws_http_gate_bail(wsi, g);
	}
	if (args.final) { /* callback completely handled it well */
		g->verdict = 0;

		return 1;
	}

	if (hit->cgienv && wsi->a.protocol->callback(wsi,
			LWS_CALLBACK_HTTP_PMO,
			wsi->user_space, (void *)hit->cgienv, 0)) {
		g->verdict = 1;

		return 1;
	}

	return 0;
}

int
lws_http_action(struct lws *wsi)
{
	const struct lws_http_mount *hit = NULL;
	struct lws_http_gate g;
	int uri_len = 0, m;
	char *uri_ptr = NULL;
#if defined(LWS_WITH_FILE_OPS)
	char *s;
#endif
	/*
	 * Set once the request has had its LWS_CALLBACK_HTTP (or was served
	 * from a file mount).  The cgi and proxy paths jump straight into the
	 * body handling with it clear: they own their own ah lifetime.
	 */
	char dispatched = 0;
#if defined(LWS_WITH_FILE_OPS) || defined(LWS_WITH_CGI) || \
    defined(LWS_WITH_HTTP_PROXY)
	unsigned int n;
#endif

	lwsl_debug("H3_TRACE: lws_http_action entered for wsi %p. vhost=%s, mux_substream=%d\n", 
		wsi, wsi->a.vhost ? wsi->a.vhost->name : "none", wsi->mux_substream);

	memset(&g, 0, sizeof(g));
	if (lws_http_action_request(wsi, &g))
		return g.verdict;
	uri_ptr = g.uri_ptr;
	uri_len = g.uri_len;

#if (defined(LWS_ROLE_WS) && (defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3))) || \
    defined(LWS_ROLE_WT)
	/*
	 * A ws upgrade carried as an h2 / h3 extended CONNECT (RFC 8441 /
	 * 9220), or a WebTransport CONNECT on h3, is taken by check_upgrades
	 * below, before lws_http_action_gates() ever runs: it passes the
	 * upgrade gates here instead, as an h1 upgrade does in
	 * lws_handshake_server().  Only for the upgrades check_upgrades will
	 * actually take, so a request that falls through to the http path
	 * below is not gated (and injected into by interceptors) twice.
	 */
	{
		const char *cp;

		if (wsi->mux_substream &&
		    wsi->a.vhost->h2.set.s[H2SET_ENABLE_CONNECT_PROTOCOL] &&
		    (cp = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD)) &&
		    !strcmp(cp, "CONNECT") &&
		    (cp = lws_hdr_simple_ptr(wsi, WSI_TOKEN_COLON_PROTOCOL)) &&
		    (0
#if defined(LWS_ROLE_WS)
		     || !strcmp(cp, "websocket")
#endif
#if defined(LWS_ROLE_WT)
		     || (lwsi_role_h3(wsi) && !strcmp(cp, "webtransport"))
#endif
		    ) && lws_http_upgrade_gates(wsi, &g))
			return g.verdict;
	}
#endif

	if (wsi->role_ops &&
	    lws_rops_fidx(wsi->role_ops, LWS_ROPS_check_upgrades))
		switch (lws_rops_func_fidx(wsi->role_ops,
					   LWS_ROPS_check_upgrades).
							check_upgrades(wsi)) {
		case LWS_UPG_RET_DONE:
			return 0;
		case LWS_UPG_RET_CONTINUE:
			break;
		case LWS_UPG_RET_BAIL:
			goto bail_nuke_ah;
		}

	g.uri_ptr = uri_ptr;
	g.uri_len = uri_len;
	if (lws_http_action_gates(wsi, &g))
		return g.verdict;
	uri_ptr = g.uri_ptr;
	uri_len = g.uri_len;
	hit = g.hit;

	if (!hit) {
		/* deferred cleanup and reset to protocols[0] */

		lwsl_info("no hit\n");

		if (lws_bind_protocol(wsi, &wsi->a.vhost->protocols[0],
				      "no mount hit"))
			return 1;

		lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

		m = wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP,
				    wsi->user_space, uri_ptr, (unsigned int)uri_len);

		goto after;
	}

#if defined(LWS_WITH_FILE_OPS)
	s = g.mount_rel;
#endif

#if defined(LWS_WITH_HTTP_PROXY)
	/*
	 * The mount is a reverse proxy?
	 */

	// if (hit)
	// lwsl_notice("%s: origin_protocol: %d\n", __func__, hit->origin_protocol);
	//else
	//	lwsl_notice("%s: no hit\n", __func__);

	if (hit->origin_protocol == LWSMPRO_HTTPS ||
	    hit->origin_protocol == LWSMPRO_HTTP) {
		/*
		 * The relayed response is this transaction, as much as one
		 * a callback makes: on h1, a request pipelined behind it waits
		 * for it to complete, rather than being parsed now and given a
		 * second onward connection under the same parent
		 */
		lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

		n = (unsigned int)lws_http_proxy_start(wsi, hit, uri_ptr, 0);
		// lwsl_notice("proxy start says %d\n", n);
		if (n)
			return (int)n;

		goto deal_body;
	}
#endif

	/*
	 * A particular protocol callback is mounted here?
	 *
	 * For the duration of this http transaction, bind us to the
	 * associated protocol
	 */
	if (hit->origin_protocol == LWSMPRO_CALLBACK || hit->protocol) {
		if (lws_http_action_bind_mount(wsi, &g))
			return g.verdict;

		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
			lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

			m = wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP,
					    wsi->user_space,
					    uri_ptr + hit->mountpoint_len,
					    (unsigned int)uri_len - hit->mountpoint_len);
			goto after;
		}
	}

#ifdef LWS_WITH_CGI
	/* did we hit something with a cgi:// origin? */
	if (hit->origin_protocol == LWSMPRO_CGI) {
		const char *cmd[] = {
			NULL, /* replace with cgi path */
			NULL
		};
		struct lws_cgi_info cgiinfo;

		lwsl_debug("%s: cgi\n", __func__);
		cmd[0] = hit->origin;

		n = 5;
		if (hit->cgi_timeout)
			n = (unsigned int)hit->cgi_timeout;

		memset (&cgiinfo, 0, sizeof (cgiinfo));
		cgiinfo.wsi = wsi;
		cgiinfo.exec_array = cmd;
		cgiinfo.script_uri_path_len = hit->mountpoint_len;
		cgiinfo.timeout_secs = (int)n;
		cgiinfo.mp_cgienv = hit->cgienv;
		cgiinfo.chroot_path = hit->cgi_chroot_path;
		cgiinfo.wd = hit->cgi_wd;

		/*
		 * The cgi's answer is this transaction, as the proxy's and a
		 * callback's are: on h1, a request pipelined behind it waits
		 * parked for it to complete.  Left in ESTABLISHED, the
		 * connection went on reading and parsing while the child ran,
		 * and a second request reached lws_cgi_via_info() with the
		 * first cgi still live, orphaning its struct on the pt list
		 * with its wsi pointer to be dereferenced after the close.
		 */
		lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

		n = (unsigned int)lws_io_cgi_start(&cgiinfo);
		if (n) {
			/*
			 * No child: nothing else is going to answer this
			 * request, eg, the fds table had no room for its
			 * stdio pipes
			 */
			lwsl_err("%s: cgi failed\n", __func__);
			lws_return_http_status(wsi,
				HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
			goto bail_nuke_ah;
		}

		goto deal_body;
	}
#endif

#if defined(LWS_WITH_FILE_OPS)
	n = (unsigned int)(uri_len - lws_ptr_diff(s, uri_ptr));
	if (s[0] == '\0' || (n == 1 && s[n - 1] == '/'))
		s = (char *)hit->def;
	if (!s)
		s = "index.html";
#endif

	wsi->cache_secs = (unsigned int)hit->cache_max_age;
	wsi->cache_reuse = hit->cache_reusable;
	wsi->cache_revalidate = hit->cache_revalidate;
	wsi->cache_no = hit->cache_no;
	wsi->cache_intermediaries = hit->cache_intermediaries;

#if defined(LWS_WITH_FILE_OPS)
	m = 1;
	if (hit->origin_protocol == LWSMPRO_FILE)
		m = lws_http_serve(wsi, s, hit->origin, hit);

	if (m > 0)
#endif
	{
		/*
		 * lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		 */
		if (hit->protocol) {
			const struct lws_protocols *pp =
					lws_vhost_name_to_protocol(
						wsi->a.vhost, hit->protocol);
			/* coverity */
			if (!pp)
				return 1;

			lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

			if (lws_bind_protocol(wsi, pp, "http_action HTTP"))
				return 1;

			m = pp->callback(wsi, LWS_CALLBACK_HTTP,
					 wsi->user_space,
					 uri_ptr + hit->mountpoint_len,
					 (size_t)(uri_len - hit->mountpoint_len));
		} else {
			lws_wsi_event(wsi, LWS_WSIEV_ACTION_BEGIN);

			m = wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP,
				    wsi->user_space, uri_ptr, (size_t)uri_len);
		}
	}

after:
	if (m) {
		lwsl_info("LWS_CALLBACK_HTTP closing\n");

		return 1;
	}

	dispatched = 1;

#if defined(LWS_WITH_CGI) || defined(LWS_WITH_HTTP_PROXY)
deal_body:
#endif
	/*
	 * If we're not issuing a file, check for content_length or
	 * HTTP keep-alive. No keep-alive header allocation for
	 * ISSUING_FILE, as this uses HTTP/1.0.
	 *
	 * In any case, return 0 and let lws_read decide how to
	 * proceed based on state
	 */
	if (lwsi_state(wsi) == LRS_ISSUING_FILE)
		goto no_more_body;

	/* Prepare to read body if we have a content length: */
	lwsl_debug("wsi->http.rx_content_length %lld %d %d\n",
		   (long long)wsi->http.rx_content_length,
		   lws_wsi_is_mux_nwsi(wsi), wsi->mux_substream);

#if defined(LWS_WITH_CGI)
	if (wsi->http.content_length_explicitly_zero && wsi->http.cgi) {
		/*
		 * A cgi takes its body on its stdin, and no body callbacks:
		 * the end of the body ends its stdin (as the body reader does
		 * at a body's end), and with no body that is now.  Otherwise a
		 * script reading its stdin to the end waits for the cgi
		 * timeout.  It is the framing that says there is no body, an
		 * explicit Content-Length: 0, an h2 / h3 stream ended with its
		 * headers, or an h1 request with no framing at all, whatever
		 * the method: a PUT or PATCH has a body as much as a POST.
		 */
		lws_cgi_stdin_body_end(wsi);

		goto no_more_body;
	}
#endif

	if (wsi->http.content_length_explicitly_zero &&
	    wsi->http.method_post) {

		/*
		 * POST with an explicit content-length of zero
		 *
		 * If we don't give the user code the empty HTTP_BODY callback,
		 * he may become confused to hear the HTTP_BODY_COMPLETION (due
		 * to, eg, instantiation of lws_spa never happened).
		 *
		 * HTTP_BODY_COMPLETION is responsible for sending the result
		 * status code and result body if any, and to do the transaction
		 * complete processing.
		 *
		 * But not if the app already answered the request and
		 * completed the transaction from LWS_CALLBACK_HTTP, its answer
		 * maybe still queued: as for a body that comes after that,
		 * the empty one is nobody's, and an app answering from the
		 * completion would answer twice.
		 */
		if (lwsi_state(wsi) == LRS_TXN_COMPLETING ||
		    lwsi_state(wsi) == LRS_TXN_COMPLETED)
			goto no_more_body;

		if (wsi->a.protocol->callback(wsi, LWS_CALLBACK_HTTP_BODY,
					    wsi->user_space, NULL, 0))
			return 1;
		if (lws_http_body_completion(wsi))
			return 1;

		goto no_more_body;
	}

	if (wsi->http.rx_content_length == 0 ||
	    wsi->http.rx_content_length == LWS_ILLEGAL_HTTP_CONTENT_LEN)
		goto no_more_body;

	/*
	 * Not if the app refused or answered the request and completed it,
	 * even while the answer is still queued: the body is then discarded
	 * as it comes
	 */
	if (lwsi_state(wsi) != LRS_DISCARD_BODY &&
	    lwsi_state(wsi) != LRS_TXN_COMPLETING) {
		lws_wsi_event(wsi, LWS_WSIEV_BODY_BEGIN);
		lwsl_info("%s: %s: LRS_BODY state set (0x%x)\n", __func__,
			  lws_wsi_tag(wsi), (int)wsi->wsistate);

		/*
		 * Expect: 100-continue (validated above): the client is
		 * holding its body back until we say we will read it.  We are
		 * about to, and nothing has answered the request yet, so tell
		 * it.  If the request had already been refused (413 over the
		 * body limit, 501 for the transfer-coding, the app's own 401
		 * from LWS_CALLBACK_HTTP...), the refusal went out instead and
		 * the client is spared sending the body, which is the point
		 * of the exchange.  h1.1 only: h2 and h3 do not use it and a
		 * 1.0 client cannot parse an interim response.
		 */
		if (!wsi->mux_substream &&
		    wsi->stream.request_version == HTTP_VERSION_1_1 &&
		    !wsi->http.response_code &&
		    wsi->http.expect_continue) {
			uint8_t ib[LWS_PRE + 32];
			static const char cont[] =
				"HTTP/1.1 100 Continue\x0d\x0a\x0d\x0a";

			memcpy(&ib[LWS_PRE], cont, sizeof(cont) - 1);
			lwsl_wsi_info(wsi, "sending 100 Continue");
			if (lws_write(wsi, &ib[LWS_PRE], sizeof(cont) - 1,
				      LWS_WRITE_HTTP) != (int)(sizeof(cont) - 1))
				return 1;
			/* an interim response is not the head of the answer */
			wsi->http.tx_head_ended = 0;
			wsi->http.tx_head_crlf = 0;
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
					(int)wsi->a.context->timeout_secs);
		}
	}
	wsi->http.rx_content_remain = wsi->http.rx_content_length;

	/*
	 * At this point we have transitioned from deferred
	 * action to expecting BODY on the stream wsi, if it's
	 * in a bundle like h2.  So if the stream wsi has its
	 * own buflist, we need to deal with that first.
	 *
	 * This is only for mux stream wsis, whose DATA arrives via the
	 * network wsi and is parked on the stream's own buflist while it
	 * was deferring.  For h1 we are called from inside the outer
	 * lws_read_h1() which is itself working through the head segment
	 * of wsi->buflist when a pipelined request was stashed there: the
	 * segment has not been marked consumed yet, so draining it here
	 * would re-read the request head as body, double-count it, and
	 * (once the inner read completes the transaction and the state
	 * moves on without consuming) never make progress.  The outer
	 * lws_read_h1() already handles any body bytes that arrived with
	 * the h1 headers and stashes the remainder.
	 */

	if (!wsi->mux_substream)
		return 0;

	while (1) {
		struct lws_tokens ebuf;
		int m;

		ebuf.len = (int)lws_buflist_next_segment_len(&wsi->buflist,
							     &ebuf.token);
		if (!ebuf.len)
			break;

		lwsl_debug("%s: consuming %d\n", __func__, (int)ebuf.len);
		m = lws_read_h1(wsi, ebuf.token, (lws_filepos_t)ebuf.len, 0);
		if (m < 0)
			return -1;

		if (lws_buflist_aware_finished_consuming(wsi, &ebuf, m, 1,
							 __func__))
			return -1;

		/*
		 * The read consumed nothing (eg, the state no longer wants
		 * body): nothing further will change, do not spin
		 */
		if (!m)
			break;
	}

	/*
	 * The peer may have ended the stream while we deferred, after a body
	 * with no content-length, or with no body at all: once all that was
	 * stashed is taken, that's the end of it too.  Nothing else will say
	 * so, the stream's end has been and gone.
	 */
	if ((lwsi_state(wsi) == LRS_BODY ||
	     lwsi_state(wsi) == LRS_DISCARD_BODY) &&
	    lws_http_mux_body_ended_by_peer(wsi) &&
	    lws_read_h1(wsi, NULL, 0, 0) < 0)
		return -1;

	return 0;

no_more_body:
	/*
	 * The request is dispatched and no body will follow, so nothing else
	 * will ever legitimately look at the request headers: let them go.
	 * Not for cgi or proxy mounts, which jumped in above with `dispatched`
	 * clear because they own their own ah lifetime.
	 */
	if (dispatched) {
		/* nor body: any that comes is not this request's */
		wsi->http.rx_body_done = 1;
		lws_http_ah_release_after_dispatch(wsi, 0);
	}

	return 0;

bail_nuke_ah:
	lws_header_table_detach(wsi, 1);

	return 1;
}

int
lws_confirm_host_header(struct lws *wsi)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int port = 80, n;
	char buf[128];

	/*
	 * this vhost wants us to validate what the
	 * client sent against our vhost name
	 */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST)) {
		lwsl_info("%s: missing host on upgrade\n", __func__);

		return 1;
	}

#if defined(LWS_WITH_TLS)
	if (lws_is_ssl(wsi))
		port = 443;
#endif
	n = lws_hdr_copy(wsi, buf, sizeof(buf) - 1, WSI_TOKEN_HOST);
	if (n <= 0) {
		lwsl_info("%s: missing or oversize host header\n", __func__);
		return 1;
	}
	ts.len = (size_t)n;
	lws_tokenize_init(&ts, buf, LWS_TOKENIZE_F_DOT_NONTERM /* server.com */|
				    LWS_TOKENIZE_F_NO_FLOATS /* 1.server.com */|
				    LWS_TOKENIZE_F_MINUS_NONTERM /* a-b.com */);

	if (lws_tokenize(&ts) != LWS_TOKZE_TOKEN)
		goto bad_format;

	if (strncmp(ts.token, wsi->a.vhost->name, ts.token_len)) {
		buf[(size_t)(ts.token - buf) + ts.token_len] = '\0';
		lwsl_info("%s: '%s' in host hdr but vhost name %s\n",
			  __func__, ts.token, wsi->a.vhost->name);
		return 1;
	}

	e = lws_tokenize(&ts);
	if (e == LWS_TOKZE_DELIMITER && ts.token[0] == ':') {
		if (lws_tokenize(&ts) != LWS_TOKZE_INTEGER)
			goto bad_format;
		else
			port = atoi(ts.token);
	} else
		if (e != LWS_TOKZE_ENDED)
			goto bad_format;

	if (wsi->a.vhost->listen_port != port &&
		wsi->a.vhost->listen_port != CONTEXT_PORT_NO_LISTEN_SERVER) {
		lwsl_info("%s: host port %d mismatches vhost port %d\n",
			  __func__, port, wsi->a.vhost->listen_port);
		return 1;
	}

	lwsl_debug("%s: host header OK\n", __func__);

	return 0;

bad_format:
	lwsl_info("%s: bad host header format\n", __func__);

	return 1;
}

#if defined(LWS_WITH_SERVER)
/*
 * The protocol of the vhost's CONNECT mount for the authority an h1 CONNECT
 * asks for, or NULL if there is none, or it names a protocol the vhost does
 * not have.  The authority must match the mountpoint exactly, the host part
 * in any case (RFC 9110 4.2.3): a CONNECT is only ever taken where something
 * was registered to take it.
 */
static const struct lws_protocols *
lws_http_connect_protocol(struct lws *wsi)
{
	const char *target = lws_hdr_simple_ptr(wsi, WSI_TOKEN_CONNECT);
	int tlen = lws_hdr_total_length(wsi, WSI_TOKEN_CONNECT);
	const struct lws_http_mount *hm;
	const struct lws_protocols *pr;
	const char *name;

	if (!target || tlen <= 0)
		return NULL;

	for (hm = wsi->a.vhost->http.mount_list; hm; hm = hm->mount_next) {
		if (hm->origin_protocol != LWSMPRO_CONNECT ||
		    hm->mountpoint_len != tlen ||
		    strncasecmp(target, hm->mountpoint,
				(size_t)hm->mountpoint_len))
			continue;

		name = hm->protocol ? hm->protocol : hm->origin;
		pr = name ? lws_vhost_name_to_protocol(wsi->a.vhost, name) :
			    NULL;
		if (!pr)
			lwsl_wsi_err(wsi, "CONNECT mount %s: no protocol '%s' "
					  "on vhost %s", hm->mountpoint,
					  name ? name : "(none)",
					  wsi->a.vhost->name);

		return pr;
	}

	return NULL;
}

/*
 * The connection leaves http for a raw role, taking the whole read with it.
 * connect_pr is NULL for the vhost's fallback (listen_accept_role and
 * listen_accept_protocol), or the protocol of the CONNECT mount that took the
 * request.  A CONNECT's connection stays under the vhost's validity policy
 * (retry_and_idle_policy): with no ping of its own, the raw connection is
 * hung up once secs_since_valid_hangup passes without the protocol saying it
 * saw it alive, with lws_validity_confirmed().  The fallback is for
 * connections lws cannot see into at all (eg, ssh through raw-proxy), which
 * no protocol could ever confirm, so it is left without one.
 */
static int
lws_http_to_raw(struct lws *wsi, const struct lws_protocols *connect_pr,
		unsigned char *obuf, size_t olen)
{
	const struct lws_role_ops *role = &role_ops_raw_skt;
	const struct lws_protocols *p1, *protocol =
			 &wsi->a.vhost->protocols[wsi->a.vhost->raw_protocol_index];
	char ipbuf[LWS_PEER_DESC_LEN];
	int n;

	if (wsi->a.vhost->listen_accept_role &&
	    lws_role_by_name(wsi->a.vhost->listen_accept_role))
		role = lws_role_by_name(wsi->a.vhost->listen_accept_role);

	if (connect_pr)
		protocol = connect_pr;
	else if (wsi->a.vhost->listen_accept_protocol) {
		p1 = lws_vhost_name_to_protocol(wsi->a.vhost,
			    wsi->a.vhost->listen_accept_protocol);
		if (p1)
			protocol = p1;
	}

	lws_bind_protocol(wsi, protocol, __func__);

	lws_wsi_event_role(wsi, LWS_WSIEV_RAW_UPGRADED, role);

	lws_header_table_detach(wsi, 0);
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/*
	 * Before the protocol hears of it, so it can confirm validity from
	 * its first callback
	 */
	if (connect_pr)
		_lws_validity_confirmed_role(wsi);

	n = LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED;
	if (wsi->role_ops->adoption_cb[1])
		n = wsi->role_ops->adoption_cb[1];

	ipbuf[0] = '\0';
#if !defined(LWS_PLAT_OPTEE)
	lws_io_peer_describe(wsi, ipbuf, sizeof(ipbuf),
			     LWS_PEER_DESC_BARE_SINGLE);
#endif

	lwsl_notice("%s: vh %s, peer: %s, role %s, "
		    "protocol %s, cb %d, ah %p\n", __func__, wsi->a.vhost->name,
		    ipbuf, role ? role->name : "null", protocol->name, n,
		    wsi->stream.ah);

	if ((wsi->a.protocol->callback)(wsi, (enum lws_callback_reasons)n, wsi->user_space, NULL, 0))
		return 1;

	/*
	 * The tls fallback only peeked at what came, it has nothing to give
	 * here: the bytes arrive by the normal read.  Don't send the protocol
	 * an RX with nothing in it.
	 */
	if (!obuf || !olen)
		return 0;

	n = LWS_CALLBACK_RAW_RX;
	if (wsi->role_ops->rx_cb[lwsi_role_server(wsi)])
		n = wsi->role_ops->rx_cb[lwsi_role_server(wsi)];
	if (wsi->a.protocol->callback(wsi, (enum lws_callback_reasons)n, wsi->user_space, obuf, olen))
		return 1;

	return 0;
}

int
lws_http_to_fallback(struct lws *wsi, unsigned char *obuf, size_t olen)
{
	return lws_http_to_raw(wsi, NULL, obuf, olen);
}

int
lws_handshake_server(struct lws *wsi, unsigned char **buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	const struct lws_protocols *connect_pr = NULL;
#if defined(LWS_WITH_HTTP2)
	struct allocated_headers *ah;
#endif
	unsigned char *obuf = *buf;
#if defined(LWS_WITH_HTTP2)
	struct lws_h2_protocol_send *pps;
	char tbuf[128], *p;
#endif
	size_t olen = len;
	int n = 0, m, i;

	if (len >= 10000000) {
		lwsl_err("%s: assert: len %ld\n", __func__, (long)len);
		assert(0);
	}

	if (!wsi->stream.ah) {
		lwsl_err("%s: assert: NULL ah\n", __func__);
		assert(0);
		/* under NDEBUG this would hand a NULL ah to lws_parse() */
		return 1;
	}

	while (len) {
		if (!lwsi_role_server(wsi) || !lwsi_role_http(wsi)) {
			lwsl_err("%s: bad wsi role 0x%x\n", __func__,
					(int)lwsi_role(wsi));
			goto bail_nuke_ah;
		}

		i = (int)len;
		m = lws_parse(wsi, *buf, &i);
		lwsl_info("%s: parsed count %d\n", __func__, (int)len - i);
		if (m == LPR_FAIL)
			lws_parse_fail_diag(wsi, *buf, (int)len - i, (int)len);
		(*buf) += (int)len - i;
		len = (unsigned int)i;

		if (m == LPR_DO_FALLBACK) {

			/*
			 * http parser went off the rails and
			 * LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_
			 * ACCEPT_CONFIG is set on this vhost.
			 *
			 * We are transitioning from http with an AH, to
			 * a backup role (raw-skt, by default).  Drop
			 * the ah, bind to the role with mode as
			 * ESTABLISHED.
			 */
raw_transition:

			if (lws_http_to_raw(wsi, connect_pr, obuf, olen)) {
				lwsl_info("%s: fallback -> close\n", __func__);
				goto bail_nuke_ah;
			}

			(*buf) = obuf + olen;

			return 0;
		}
		if (m) {
			lwsl_info("lws_parse failed\n");
			goto bail_nuke_ah;
		}

		/* coverity... */
		if (!wsi->stream.ah)
			goto bail_nuke_ah;

		if (wsi->stream.ah->parser_state != WSI_PARSING_COMPLETE)
			continue;

		lwsl_parser("%s: lws_parse sees parsing complete\n", __func__);

		/*
		 * Whatever answers the request, a refusal included, speaks the
		 * version it was asked in, and keeps the connection as it asked
		 */
		lws_h1_request_framing(wsi);

		/*
		 * select vhost: only among those served by the listener he
		 * arrived on, whatever he names.  One who is only ever
		 * answered with a redirect to https (below) stays where he
		 * is: that answer is the listener's vhost's to give.
		 */

		if (!wsi->redirect_to_https && wsi->a.vhost->listen_port &&
		    lws_hdr_total_length(wsi, WSI_TOKEN_HOST)) {
			struct lws_vhost *vhost = lws_select_vhost(
				wsi->a.vhost,
				lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST));

			/*
			 * 421 Misdirected Request if he named a vhost his
			 * connection can't be moved to, eg, because it needs
			 * a client cert his handshake didn't satisfy, or he
			 * has no tls at all: only the tls listener's own
			 * vhost said that is ok, another sharing it may
			 * expect to be reached over tls only
			 */
			if (vhost && ((vhost != wsi->a.vhost &&
				       wsi->plaintext_on_tls_listener) ||
				      lws_vhost_rebind_mtls_refused(wsi, vhost) ||
				      lws_http_server_rebind(wsi, vhost))) {
				lws_return_http_status(wsi, 421, NULL);
				goto bail_nuke_ah;
			}
		} else
			lwsl_info("no host\n");

		if ((!lwsi_role_h2(wsi) || !lwsi_role_server(wsi)) &&
		    (!wsi->conn_stat_done))
			wsi->conn_stat_done = 1;

		/*
		 * check for unwelcome guests, before anything else, even a
		 * CONNECT, is done for them
		 */
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
		if (wsi->a.context->reject_service_keywords) {
			const struct lws_protocol_vhost_options *rej =
					wsi->a.context->reject_service_keywords;
			char ua[384];
			const char *msg = NULL;

			if (lws_hdr_copy(wsi, ua, sizeof(ua) - 1,
					 WSI_TOKEN_HTTP_USER_AGENT) > 0) {
#ifdef LWS_WITH_ACCESS_LOG
				char *uri_ptr = NULL;
				int meth, uri_len;
#endif
				ua[sizeof(ua) - 1] = '\0';
				while (rej) {
					if (!(char *)strstr(ua, rej->name)) {
						rej = rej->next;
						continue;
					}

					msg = (char *)strchr(rej->value, ' ');
					if (msg)
						msg++;
					lws_return_http_status(wsi,
						(unsigned int)atoi(rej->value), msg);
#ifdef LWS_WITH_ACCESS_LOG
					meth = lws_http_get_uri_and_method(wsi,
							&uri_ptr, &uri_len);
					if (meth >= 0)
						lws_prepare_access_log_info(wsi,
							uri_ptr, uri_len, meth);

					/* wsi close will do the log */
#endif
					/*
					 * We don't want anything from
					 * this rejected guy.  Follow
					 * the close flow, not the
					 * transaction complete flow.
					 */
					goto bail_nuke_ah;
				}
			}
		}
#endif

		/*
		 * A CONNECT is only taken where the vhost has a CONNECT mount
		 * for the authority it asks for.  It goes raw to the mount's
		 * protocol with the whole read, headers and all, so it is
		 * decided before anything of the read is parked.  Anywhere
		 * else nothing is allowed for it: 405, with an empty Allow
		 * (RFC 9110 10.2.1), and the connection closed, since the
		 * peer may already be sending what it wanted to tunnel.
		 */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_CONNECT)) {
			/* nothing is tunneled for him without tls */
			connect_pr = wsi->redirect_to_https ? NULL :
					lws_http_connect_protocol(wsi);
			if (connect_pr) {
				lwsl_info("Changing to RAW mode\n");
				goto raw_transition;
			}

			lwsl_wsi_info(wsi, "CONNECT: nothing mounted for it");
			_lws_return_http_status(wsi,
					HTTP_STATUS_METHOD_NOT_ALLOWED, NULL,
					WSI_TOKEN_HTTP_ALLOW, "");
			goto bail_nuke_ah;
		}

		/*
		 * Whatever follows the headers in this read is request body,
		 * or the next pipelined request.  If it is sitting in
		 * pt->serv_buf, the action below can overwrite it before it
		 * is looked at: lws_return_http_status(), lws_serve_http_file()
		 * and lws_http_redirect() build their response in that same
		 * buffer, synchronously, from inside the user's
		 * LWS_CALLBACK_HTTP.  A Content-Length body that got clobbered
		 * was only ever going to be counted and discarded, but a
		 * chunked body's framing has to survive intact, and a
		 * pipelined request must not be lost.
		 *
		 * Nor is the action the only thing that composes in it: an
		 * upgrade's 101 is built there too, and so is a refusal, while
		 * a ws client that did not wait for the 101 (RFC 6455 4.1
		 * says it must) may have frames in the same read.
		 *
		 * Park it on the buflist now, ahead of everything that acts
		 * on the request, the mount's redirect and its interceptors
		 * as much as the action: user code must not run while it is
		 * still in serv_buf.  Our caller then sees the whole read as
		 * consumed, and the parked bytes are offered again from the
		 * buflist once the action or upgrade has left us in a state
		 * that can take them.
		 */
		if (len && *buf >= pt->serv_buf &&
		    *buf < pt->serv_buf + context->pt_serv_buf_size) {
			m = lws_buflist_append_segment(&wsi->buflist, *buf, len);
			if (m < 0)
				goto bail_nuke_ah;
			if (m && lws_dll2_is_detached(&wsi->dll_buflist))
				lws_dll2_add_head(&wsi->dll_buflist,
						  &pt->dll_buflist_owner);
			*buf += len;
			len = 0;
		}

		/*
		 * From here on the request is acted on, and serv_buf composed
		 * in: whatever of the read was ours is parsed or parked, the
		 * pump's claim on it is done with (it ends at *buf)
		 */
		lws_servbuf_release_containing(pt, *buf);

		/*
		 * The request's headers are complete: whatever acts on it from
		 * here, the mount's redirect included, completes a transaction
		 */
		lws_wsi_event(wsi, LWS_WSIEV_REQ_HDRS_COMPLETE);
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/*
		 * Before anything answers the request, know how its body is
		 * framed: some answers are given right here, the mount's
		 * redirect and a refused upgrade, and completing any of them
		 * has to step over exactly this request's body (or close,
		 * where its end cannot be known) rather than parse it as the
		 * next request
		 */
		if (lws_http_request_body_framing(wsi))
			goto bail_nuke_ah;

#if defined(LWS_WITH_TLS)
		/*
		 * He spoke plaintext to a tls listener only to be told to use
		 * https: that is his whole answer, whatever he asked for, with
		 * no mount, interceptor or upgrade acting on it first
		 */
		if (wsi->redirect_to_https) {
			if (lws_http_redirect_to_https(wsi))
				goto bail_nuke_ah;

			return lws_http_transaction_completed(wsi);
		}
#endif

		/*
		 * A new request: whatever the interceptors decided for an
		 * earlier one on this connection is nothing to do with it,
		 * however that one ended
		 */
		wsi->http.interceptors_evaluated = 0;
		wsi->http.interceptor_hit = NULL;
		wsi->http.interceptor_result = NULL;

		/*
		 * So he may have come to us requesting one or another kind
		 * of upgrade from http... but the mount his path lands in
		 * gates it first, as it would gate the same request as http:
		 * its redirect, its interceptors and its basic auth.  A plain
		 * http request meets the same gates in lws_http_action().
		 */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
			struct lws_http_gate g;

			memset(&g, 0, sizeof(g));
			if (lws_http_get_uri_and_method(wsi, &g.uri_ptr,
							&g.uri_len) >= 0 &&
			    lws_http_upgrade_gates(wsi, &g))
				return g.verdict;
		}

		if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {

			const char *up = lws_hdr_simple_ptr(wsi,
							    WSI_TOKEN_UPGRADE);

			if (strcasecmp(up, "websocket") &&
			    strcasecmp(up, "h2c")) {
				lwsl_info("Unknown upgrade '%s'\n", up);

				if (lws_return_http_status(wsi,
						HTTP_STATUS_FORBIDDEN, NULL) ||
				    lws_http_transaction_completed(wsi))
					goto bail_nuke_ah;

				/*
				 * That was the whole response: going on to
				 * act on the request as plain http sent a
				 * second one after the 403
				 */
				return 0;
			} else {
				/*
				 * What follows the head of an upgrade is the
				 * new protocol's.  A request with a body of its
				 * own cannot be upgraded: its body would be
				 * read as that protocol, where anything in
				 * front of us saw it as this request's body
				 */
				if (wsi->http.rx_content_length) {
					lwsl_info("upgrade with a body\n");
					lws_return_http_status(wsi,
						HTTP_STATUS_BAD_REQUEST, NULL);
					goto bail_nuke_ah;
				}

				n = user_callback_handle_rxflow(wsi->a.protocol->callback,
						wsi, LWS_CALLBACK_HTTP_CONFIRM_UPGRADE,
						wsi->user_space, (char *)up, 0);

				/* just hang up? */

				if (n < 0)
					goto bail_nuke_ah;

				/*
				 * The callback answered the request itself, and
				 * the upgrade is not done.  An answer it has
				 * sent is complete; a file it is serving is
				 * completed by the file's own completion, once
				 * it has all gone, as when it is the answer to
				 * the request in LWS_CALLBACK_HTTP
				 */

				if (n > 0) {
				    if (lwsi_state(wsi) == LRS_ISSUING_FILE ||
					lwsi_state(wsi) == LRS_AWAITING_FILE_READ)
					return 0;

				    if (lws_http_transaction_completed(wsi))
					goto bail_nuke_ah;

				    /* continue on */

				    return 0;
				}

				/* callback said 0, it was allowed */

				if (wsi->a.vhost->options &
					LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK &&
					lws_confirm_host_header(wsi))
				    goto bail_nuke_ah;

				if (!strcasecmp(up, "websocket")) {
#if defined(LWS_ROLE_WS)
					lws_metrics_tag_wsi_add(wsi, "upg", "ws");
					lwsl_info("Upgrade to ws\n");
					goto upgrade_ws;
#endif
				}
#if defined(LWS_WITH_HTTP2)
				if (!strcasecmp(up, "h2c")) {
				    lws_metrics_tag_wsi_add(wsi, "upg", "h2c");
				    lwsl_info("Upgrade to h2c\n");
				    goto upgrade_h2c;
				}
#endif
			}
		}

		/* no upgrade ack... he remained as HTTP */

		lwsl_info("%s: %s: No upgrade\n", __func__, lws_wsi_tag(wsi));

		lws_wsi_event(wsi, LWS_WSIEV_REQ_PLAIN_HTTP);
#if defined(LWS_WITH_FILE_OPS)
		wsi->http.fop_fd = NULL;
#endif

		lwsl_debug("%s: %s: ah %p\n", __func__, lws_wsi_tag(wsi),
			   (void *)wsi->stream.ah);

		n = lws_http_action(wsi);

		return n;

#if defined(LWS_WITH_HTTP2)
upgrade_h2c:
		if (!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP2_SETTINGS)) {
			lwsl_info("missing http2_settings\n");
			goto bail_nuke_ah;
		}

		lwsl_info("h2c upgrade...\n");

		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP2_SETTINGS);
		/* convert the peer's HTTP-Settings */
		n = lws_b64_decode_string(p, tbuf, sizeof(tbuf));
		if (n < 0) {
			lwsl_parser("HTTP2_SETTINGS too long\n");
			return 1;
		}

		/* adopt the header info */

		ah = wsi->stream.ah;
		lws_wsi_event(wsi, LWS_WSIEV_H2_SELECTED);

		/* http2 union member has http union struct at start */
		wsi->stream.ah = ah;

		if (!wsi->h2.h2n) {
			wsi->h2.h2n = lws_zalloc(sizeof(*wsi->h2.h2n), "h2n");
			if (!wsi->h2.h2n)
				return 1;
		}

		lws_h2_init(wsi);

		/* HTTP2 union */

		lws_h2_settings(wsi, &wsi->h2.h2n->peer_set, (uint8_t *)tbuf, n);

		if (lws_hpack_dynamic_size(wsi, (int)wsi->h2.h2n->peer_set.s[
		                                      H2SET_HEADER_TABLE_SIZE]))
			return 1;

		/* our answer to the upgrade goes first, the h2 after it */
		pps = lws_h2_new_pps(LWS_H2_PPS_H2C_101);
		if (!pps)
			return 1;
		lws_pps_schedule(wsi, pps);

		return 0;
#endif
#if defined(LWS_ROLE_WS)
upgrade_ws:
		if (lws_process_ws_upgrade(wsi))
			goto bail_nuke_ah;

		return 0;
#endif
	} /* while all chars are handled */

	return 0;

bail_nuke_ah:
	/* drop the header info */
	lws_header_table_detach(wsi, 1);

	return 1;
}
#endif

static void
lws_http_response_watchdog(struct lws *wsi)
{
	unsigned int secs = wsi->a.context->timeout_secs;

	if (secs < 30)
		secs = 30;

	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_RESPONSE, (int)secs);
}

void
lws_http_response_started(struct lws *wsi)
{
	if (!wsi || wsi->http.sent_response_headers)
		return;

	wsi->http.sent_response_headers = 1;

	/*
	 * Immortal streams (SSE, long-poll) opt out of idle timeouts via
	 * lws_http_mark_sse() / lws_mux_mark_immortal(); they intentionally
	 * stay open after the response headers and must not be armed with a
	 * response-completion watchdog.  An h1 connection is no mux stream:
	 * only its SSE mark says so there.
	 */
	if (wsi->mux_stream_immortal || wsi->http_carries_sse)
		return;

	lws_http_response_watchdog(wsi);
}

/*
 * More of the response was sent: it is not stalled, however long the whole
 * of it takes, so its watchdog starts again.  Only while that is the
 * timeout the wsi is under: another one armed since (eg, a close's flush)
 * is left alone.
 */
void
lws_http_response_progress(struct lws *wsi)
{
	if (wsi->pending_timeout == PENDING_TIMEOUT_HTTP_RESPONSE)
		lws_http_response_watchdog(wsi);
}

int
lws_http_tx_is_head_body(struct lws *wsi, int base)
{
	return (base == LWS_WRITE_HTTP || base == LWS_WRITE_HTTP_FINAL) &&
	       wsi->http.method_head && !lwsi_role_client(wsi);
}

/*
 * Whether an h1 answer is being completed short of what its head said it
 * would be.  An h1 response has no end of its own: what the peer reads after
 * it is the next response, framed by where this one's Content-Length says it
 * ends.  Kept alive, a short one has the peer read the next answer as the
 * rest of it.  lws knows two ways an answer is short: a file still being
 * served (its sender closes it before its completion callback), or fewer
 * bytes written than the Content-Length lws added (HEAD, 1xx, 204 and 304
 * answers have one but no body).  An h2 or h3 stream ends with the stream,
 * whatever the answer was, and is not asked.
 */
static int
lws_h1_answer_short(struct lws *wsi)
{
	unsigned int code = wsi->http.response_code;

	if (wsi->mux_substream || lwsi_role_client(wsi))
		return 0;

#if defined(LWS_WITH_FILE_OPS)
	if (wsi->http.fop_fd)
		return 1;
#endif

	if (!wsi->http.tx_content_length || !wsi->http.tx_content_remain ||
	    wsi->http.method_head)
		return 0;

	return lws_http_status_has_body(code);
}

int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed(struct lws *wsi)
{
	lws_free_set_NULL(wsi->http.extra_onward_headers);
	lws_free_set_NULL(wsi->http.content_type);
#if defined(LWS_WITH_HTTP_BASIC_AUTH)
	lws_free_set_NULL(wsi->http.basic_auth_user);
#endif

	/*
	 * A connection already closing has no transaction left to complete,
	 * eg, an h3 stream whose file answer has gone, flushing to close,
	 * when the app's own timer completes it as well
	 */
	if (lwsi_close_started(wsi))
		return 0;

#if defined(LWS_WITH_ASYNC_QUEUE) && defined(LWS_WITH_FILE_OPS)
	/*
	 * A file the app abandoned while a read of it was out on a worker
	 * (completing from LRS_AWAITING_FILE_READ, or from LRS_ISSUING_FILE
	 * with the read back but not yet sent): the read is finished with
	 * before the file is closed under it at the completion, and its
	 * result, wanted by nobody, is not left for the next file served on
	 * the connection to take as its own first fragment
	 */
	if (wsi->async_worker_job &&
	    wsi->async_worker_job->type == LWS_AQ_FILE_READ)
		lws_async_worker_wait_and_reap(wsi);
#endif

	if (lws_h1_answer_short(wsi)) {
		lwsl_wsi_notice(wsi, "answer completed short of its framing, "
				     "closing");

		return 1;
	}

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	/*
	 * A coded h1 answer goes chunked, framing lws chose in place of the
	 * app's Content-Length, and it ends with the coder's end and the
	 * last-chunk, which only a FINAL write through the coder sends.  An
	 * app that completes the transaction without one (its body written
	 * as LWS_WRITE_HTTP to its length, or none at all) leaves the peer
	 * waiting for the end, and reading the next answer as chunk data:
	 * lws owes the end of its own framing, so it goes now, and the
	 * completion waits below for it to drain like any other partial.  A
	 * HEAD's answer has no body to end.
	 */
	if (!wsi->mux_substream && wsi->http.lcs &&
	    wsi->http.comp_ctx.chunking && !wsi->http.method_head &&
	    !wsi->http.comp_ctx.final_on_input_side) {
		uint8_t fin[LWS_PRE + 1];

		lwsl_wsi_info(wsi, "ending the coded answer left open");
		if (lws_write(wsi, fin + LWS_PRE, 0, LWS_WRITE_HTTP_FINAL) < 0)
			return 1;
	}
#endif

	/* rx parked behind a file transfer may be read again now */
	lws_rx_flow_control(wsi, LWS_RXFLOW_REASON_APPLIES_ENABLE |
				 LWS_RXFLOW_REASON_HTTP_RXBUFFER);

	if (wsi->http.cgi_transaction_complete)
		return 0;

	if (lws_has_buffered_out(wsi)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
			|| wsi->http.comp_ctx.buflist_comp ||
	    wsi->http.comp_ctx.may_have_more
#endif
	) {
		/*
		 * ...so he tried to send something large as the http reply,
		 * it went as a partial, but he immediately said the
		 * transaction was completed.
		 *
		 * Defer the transaction completed until the last part of the
		 * partial is sent.
		 */
		lwsl_debug("%s: %s: deferring due to partial\n", __func__,
				lws_wsi_tag(wsi));
		if (lws_wsi_event(wsi, LWS_WSIEV_TXN_COMPLETING)) {
			/*
			 * a state we did not expect to complete from: nothing
			 * would ever pick the completion up again
			 */
			lwsl_wsi_err(wsi, "cannot defer completion");

			return 1;
		}
		lws_callback_on_writable(wsi);

		return 0;
	}
	/*
	 * Are we finishing the transaction before we have consumed any body?
	 *
	 * For h1 this would kill keepalive pipelining, and for h2, considering
	 * it can extend over multiple DATA frames, it would kill the network
	 * connection.
	 */
	if (wsi->http.rx_content_length && wsi->http.rx_content_remain) {
		/*
		 * If we don't know where the body ends (an h2 / h3 stream's,
		 * whose end has not come), we cannot discard the remainder to
		 * resync for pipelining: drop the connection.  A chunked body
		 * carries its own end marker, so it is discarded up to its
		 * last-chunk exactly like a Content-Length body.
		 */
		if (!wsi->http.content_length_given && !wsi->http.rx_chunked) {
			lwsl_notice("%s: %s: unread body but no content length, closing\n",
				  __func__, lws_wsi_tag(wsi));
			return 1;
		}
		/*
		 * are we already in LRS_DISCARD_BODY and didn't clear the
		 * remaining before trying to complete the transaction again?
		 */
		if (lwsi_state(wsi) == LRS_DISCARD_BODY)
			return -1;
		/*
		 * let's defer transaction completed processing until we
		 * discarded the remaining body... which has to be read: the
		 * h1 rx policy stopped reading while the answer drained
		 */
		lws_wsi_event(wsi, LWS_WSIEV_BODY_DISCARD);

		if (lws_io_read_after_drain(wsi))
			return 1;

		return 0;
	}

	/*
	 * Nothing defers the completion any more.  Only now is the response
	 * of the transaction behind us: while it was deferred, its headers
	 * had still been sent.  Whether an interceptor took the request is
	 * as much a property of the transaction, not the connection: the
	 * next request on a keepalive connection re-evaluates the chain from
	 * scratch.
	 */
	wsi->http.sent_response_headers = 0;
	wsi->http.interceptor_diverted = 0;
	wsi->http.interceptors_evaluated = 0;
	wsi->http.interceptor_hit = NULL;
	wsi->http.interceptor_result = NULL;

#if defined(LWS_WITH_SYS_METRICS)
	{
		char tmp[10];

		lws_snprintf(tmp, sizeof(tmp), "%u", wsi->http.response_code);
		lws_metrics_tag_wsi_add(wsi, "status", tmp);
	}
#endif

	lwsl_info("%s: %s\n", __func__, lws_wsi_tag(wsi));

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	lws_http_compression_destroy(wsi);
#endif
	lws_access_log(wsi);

	if (lwsi_state(wsi) == LRS_HEADERS
#if defined(LWS_WITH_CGI)
			&& !wsi->http.cgi
#endif
	) {
		char peer[LWS_PEER_DESC_LEN];

#if !defined(LWS_PLAT_OPTEE)
		lws_io_peer_describe(wsi, peer, sizeof(peer),
				     LWS_PEER_DESC_BARE_SINGLE);
#else
		peer[0] = '\0';
#endif
		lwsl_info("%s: (from %s) ignoring, ah parsing incomplete\n",
				__func__, peer);
		return 0;
	}

#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi) {
		lwsl_debug("%s: cleaning cgi\n", __func__);
		wsi->http.cgi_transaction_complete = 1;
		lws_cgi_remove_and_kill(wsi);
		lws_cgi_release(wsi);
		wsi->http.cgi_transaction_complete = 0;
	}
#endif

	/* if we can't go back to accept new headers, drop the connection */
	if (wsi->mux_substream)
		return 1;

	if (wsi->seen_zero_length_recv)
		return 1;

	if (wsi->http.conn_type != HTTP_CONNECTION_KEEP_ALIVE) {
		lwsl_info("%s: %s: close connection\n", __func__, lws_wsi_tag(wsi));
		return 1;
	}

	if (lws_bind_protocol(wsi, &wsi->a.vhost->protocols[0], __func__))
		return 1;

	/*
	 * otherwise set ourselves up ready to go again, but because we have no
	 * idea about the wsi writability, we make put it in a holding state
	 * until we can verify POLLOUT.  The part of this that confirms POLLOUT
	 * with no partials is in lws_server_socket_service() below.
	 */
	lwsl_debug("%s: %s: setting DEF_ACT from 0x%x: %p\n", __func__,
		   lws_wsi_tag(wsi), (int)wsi->wsistate, wsi->buflist);
	lws_wsi_event(wsi, LWS_WSIEV_TXN_COMPLETED);
	wsi->http.tx_content_length = 0;
	wsi->http.tx_content_remain = 0;
	wsi->http.tx_head_ended = 0;
	wsi->http.tx_head_crlf = 0;
	/*
	 * Until the next request is dispatched, nothing answers a HEAD: an
	 * error refusing it before then sends its body
	 */
	wsi->http.method_head = 0;
	wsi->sending_chunked = 0;
	/* an SSE stream the app ended: the next request needs a table */
	wsi->http_carries_sse = 0;
	/* the next response a relay ends needs its own end of stream */
	wsi->http.did_stream_close = 0;
#if defined(LWS_WITH_HTTP_PROXY)
	wsi->http.proxy_relaying = 0;
#endif
	/* serving the 404 document was this transaction's, not the next's */
	wsi->handling_404 = 0;
	/*
	 * So was the interpreter of the file it served, if any: a file the
	 * next request has served from a callback, with lws_serve_http_file(),
	 * was given to this one's interpreter protocol's callback with the
	 * user_space of whatever protocol is bound then (G-493)
	 */
	wsi->interpreting = 0;
	wsi->protocol_interpret_idx = 0;
	/*
	 * ... and the caching policy of the mount it was served from, which
	 * only some requests' dispatch sets: a file the next request has
	 * served from a callback went out with this one's Cache-Control
	 */
	wsi->cache_secs = 0;
	wsi->cache_reuse = 0;
	wsi->cache_revalidate = 0;
	wsi->cache_no = 0;
	wsi->cache_intermediaries = 0;
	/*
	 * ... and the mount's own response headers, which only the http gates
	 * set: an h1 upgrade, or a request refused before the gates, was
	 * answered with this one's mount's
	 */
	wsi->http.mount_specific_headers = NULL;
#ifdef LWS_WITH_ACCESS_LOG
	wsi->stream.access_log.sent = 0;
#endif
#if defined(LWS_WITH_FILE_OPS) && (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3))
	if (lwsi_role_http(wsi) && lwsi_role_server(wsi) &&
	    wsi->http.fop_fd != NULL)
		lws_vfs_file_close(&wsi->http.fop_fd);
#endif

	{
		enum pending_timeout ept = NO_PENDING_TIMEOUT;

		if (wsi->a.vhost->keepalive_timeout
#if defined(LWS_WITH_SERVER)
			|| wsi->http.mount_specific_keepalive_timeout_secs
#endif
   	   )
			ept = PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE;
		lws_set_timeout(wsi, ept, lws_wsi_keepalive_timeout_eff(wsi));
	}

	/*
	 * We already know we are on http1.1 / keepalive and the next thing
	 * coming will be another header set.
	 *
	 * If there is no pending rx and we still have the ah, drop it and
	 * reacquire a new ah when the new headers start to arrive.  (Otherwise
	 * we needlessly hog an ah indefinitely.)
	 *
	 * However if there is pending rx and we know from the keepalive state
	 * that is already at least the start of another header set, simply
	 * reset the existing header table and keep it.
	 */
	if (wsi->stream.ah) {
		// lws_buflist_describe(&wsi->buflist, wsi, __func__);
		if (!lws_buflist_next_segment_len(&wsi->buflist, NULL)) {
			wsi->http.pipeline_count = 0;
			lwsl_debug("%s: %s: nothing in buflist, detaching ah\n",
				  __func__, lws_wsi_tag(wsi));
			lws_header_table_detach(wsi, 1);
#ifdef LWS_WITH_TLS
			/*
			 * additionally... if we are hogging an SSL instance
			 * with no pending pipelined headers (or ah now), and
			 * SSL is scarce, drop this connection without waiting
			 */

			if (wsi->a.vhost->tls.use_ssl &&
			    wsi->a.context->simultaneous_ssl_restriction &&
			    wsi->a.context->simultaneous_ssl ==
				   wsi->a.context->simultaneous_ssl_restriction) {
				lwsl_info("%s: simultaneous_ssl_restriction\n",
					  __func__);
				return 1;
			}
#endif
		} else {
			if (++wsi->http.pipeline_count > 64) {
				lwsl_warn("%s: %s: too many pipelined requests\n",
					  __func__, lws_wsi_tag(wsi));
				return 1;
			}
			lwsl_info("%s: %s: resetting/keeping ah as pipeline\n",
				  __func__, lws_wsi_tag(wsi));
			lws_header_table_reset(wsi, 0);
			/*
			 * If we kept the ah, we should restrict the amount
			 * of time we are willing to keep it.  Otherwise it
			 * will be bound the whole time the connection remains
			 * open.
			 */
			lws_set_timeout(wsi, PENDING_TIMEOUT_HOLDING_AH,
					wsi->a.vhost->keepalive_timeout);
		}
		/* If we're (re)starting on headers, need other implied init */
		if (wsi->stream.ah)
			wsi->stream.ah->ues = URIES_IDLE;

		//lwsi_set_state(wsi, LRS_ESTABLISHED); // !!!
	} else
		if (lws_buflist_next_segment_len(&wsi->buflist, NULL))
			switch (lws_header_table_attach(wsi, 0)) {
			case LWS_AH_ATTACH_OK:
				lwsl_debug("acquired ah\n");
				break;
			case LWS_AH_ATTACH_WSI_GONE:
				/*
				 * Can't happen here (a server wsi with
				 * autoservice off reaches neither reentrant
				 * path in the attach), and this function has
				 * no way to tell its caller the wsi is gone
				 * (1 means "please close him", ie, close him
				 * a second time).  Shout, and at least do
				 * nothing more with him in here.
				 */
				lwsl_err("%s: wsi vanished in ah attach\n",
					 __func__);

				return 0;
			default:
				lwsl_debug("%s: waiting for ah\n", __func__);
				break;
			}

	lwsl_debug("%s: %s: keep-alive await new transaction (state 0x%x)\n",
		   __func__, lws_wsi_tag(wsi), (int)wsi->wsistate);
	lws_callback_on_writable(wsi);

	return 0;
}

#if defined(LWS_WITH_FILE_OPS)
static int
lws_is_ascii_headers(const char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)buf[i];
		if (c < 0x20 && c != '\r' && c != '\n' && c != '\t')
			return 0;
		if (c >= 0x7f)
			return 0;
	}

	return 1;
}

static int
lws_serve_http_file_composed(struct lws *wsi, const char *file, const char *content_type,
		    const char *other_headers, int other_headers_len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	unsigned char *response = pt->compose_buf + LWS_PRE;
#if defined(LWS_WITH_RANGES)
	struct lws_range_parsing *rp = &wsi->http.range;
#endif
	int ret = 0, cclen = 8, n = HTTP_STATUS_OK, no_body;
	char cache_control[50], *cc = "no-store";
#if defined(LWS_WITH_RANGES)
	char mp_ct[64];
	/* scratch for sizing a multipart part header, bounded by the part
	 * header format, the boundary, the mimetype and three decimal file
	 * offsets */
	char part_hdr[256];
#endif
	lws_fop_flags_t fflags = LWS_O_RDONLY;
	const struct lws_plat_file_ops *fops;
	lws_filepos_t total_content_length;
	unsigned char *p = response;
	unsigned char *end = p + context->pt_serv_buf_size - LWS_PRE;
	const char *vpath;
#if defined(LWS_WITH_RANGES)
	int ranges;
#endif

	if (wsi->handling_404)
		n = HTTP_STATUS_NOT_FOUND;

	/*
	 * We either call the platform fops .open with first arg platform fops,
	 * or we call fops_zip .open with first arg platform fops, and fops_zip
	 * open will decide whether to switch to fops_zip or stay with fops_def.
	 *
	 * If wsi->http.fop_fd is already set, the caller already opened it
	 */
	if (!wsi->http.fop_fd) {
		fops = lws_vfs_select_fops(wsi->a.context->fops, file, &vpath);
		fflags |= lws_vfs_prepare_flags(wsi);
#if defined(LWS_WITH_LATENCY)
		lws_usec_t _lws_start = lws_now_usecs();
#endif
		wsi->http.fop_fd = fops->LWS_FOP_OPEN(fops, wsi->a.context->fops,
							file, vpath, &fflags);
#if defined(LWS_WITH_LATENCY)
		if ((lws_now_usecs() - _lws_start) > 500) {
			lws_latency_note(pt, _lws_start, 500, "open:%uus ",
				(unsigned int)(lws_now_usecs() - _lws_start));
			lws_latency_append_annotation(pt, "file:%s ", file);
		}
#endif
		if (!wsi->http.fop_fd) {
			lwsl_info("%s: Unable to open: '%s': errno %d\n",
				  __func__, file, errno);
			/* nothing composed yet: the status page has the buffer */
			lws_servbuf_release_containing(pt, response);
			if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND,
						   NULL))
						return -1;
			return !wsi->mux_substream;
		}
	}

	/*
	 * Caution... wsi->http.fop_fd is live from here
	 */

#if defined(LWS_WITH_LATENCY)
	{
		lws_usec_t _lws_start = lws_now_usecs();
		wsi->http.filelen = lws_vfs_get_length(wsi->http.fop_fd);
		if ((lws_now_usecs() - _lws_start) > 500) {
			lws_latency_note(pt, _lws_start, 500, "fstat:%uus ",
				(unsigned int)(lws_now_usecs() - _lws_start));
			lws_latency_append_annotation(pt, "file:%s ", file);
		}
	}
#else
	{
		wsi->http.filelen = lws_vfs_get_length(wsi->http.fop_fd);
	}
#endif
	total_content_length = wsi->http.filelen;

#if 0
#if defined(LWS_ROLE_QUIC)
	{
		uint64_t sid = wsi->quic.qs ? wsi->quic.qs->stream_id : 0;
		lwsl_notice("SERVE FILE: file='%s', filelen=%llu, mux_substream=%d, stream_id=%llu\n",
			    file, (unsigned long long)wsi->http.filelen, wsi->mux_substream, (unsigned long long)sid);
	}
#else
	lwsl_notice("SERVE FILE: file='%s', filelen=%llu, mux_substream=%d, stream_id=0\n",
		    file, (unsigned long long)wsi->http.filelen, wsi->mux_substream);
#endif
#endif

#if defined(LWS_WITH_RANGES)
	ranges = lws_ranges_init(rp, wsi->http.filelen);

	lwsl_debug("Range count %d\n", ranges);
	/*
	 * no ranges -> 200;
	 *  1 range  -> 206 + Content-Type: normal; Content-Range;
	 *  more     -> 206 + Content-Type: multipart/byteranges
	 *  		Repeat the true Content-Type in each multipart header
	 *  		along with Content-Range
	 */
	if (ranges < 0) {
		/*
		 * It means he expressed a range in Range:, but it was
		 * illegal, or asked for more of them than we will compose.
		 *
		 * RFC 7233 4.4: tell him the length he was working from, so
		 * a client whose range went past the end of a representation
		 * that has since changed can see that and ask again, rather
		 * than having to guess why we refused
		 */

		lws_snprintf(cache_control, sizeof(cache_control),
			     "bytes */%llu",
			     (unsigned long long)wsi->http.filelen);

		/* nothing composed yet: the status page has the buffer */
		lws_servbuf_release_containing(pt, response);
		_lws_return_http_status(wsi,
				HTTP_STATUS_REQ_RANGE_NOT_SATISFIABLE, NULL,
				WSI_TOKEN_HTTP_CONTENT_RANGE, cache_control);
		/* the file is no part of the answer: closed first */
		lws_vfs_file_close(&wsi->http.fop_fd);
		if (lws_http_transaction_completed(wsi))
			goto bail; /* <0 means just hang up */

		return 0; /* == 0 means we did the transaction complete */
	}

	/*
	 * Every part of a multipart/byteranges repeats the content type, from
	 * a copy of bounded size.  One that doesn't fit can't be repeated as
	 * it is, and the Content-Length computed from it would not match the
	 * parts sent: ignore the Range and send the whole representation,
	 * which a server may always do (RFC 9110 14.2)
	 */
	if (ranges >= 2 && (!content_type ||
	    strlen(content_type) >= sizeof(wsi->http.multipart_content_type))) {
		lwsl_wsi_info(wsi, "mimetype too long for multipart, sending all");
		lws_ranges_destroy(rp);
		ranges = 0;
	}

	if (ranges)
		n = HTTP_STATUS_PARTIAL_CONTENT;
#endif

	if (lws_add_http_header_status(wsi, (unsigned int)n, &p, end))
		goto bail;

	if ((wsi->http.fop_fd->flags & (LWS_FOP_FLAG_COMPR_ACCEPTABLE_GZIP |
		       LWS_FOP_FLAG_COMPR_IS_GZIP)) ==
	    (LWS_FOP_FLAG_COMPR_ACCEPTABLE_GZIP | LWS_FOP_FLAG_COMPR_IS_GZIP)) {
		if (lws_add_http_header_by_token(wsi,
			WSI_TOKEN_HTTP_CONTENT_ENCODING,
			(unsigned char *)"gzip", 4, &p, end) ||
		    lws_http_add_vary_accept_encoding(wsi, &p, end))
			goto bail;
		lwsl_info("file is being provided in gzip\n");
	}
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	else {
		/*
		 * if we know its very compressible, and we can use
		 * compression, then use the most preferred compression
		 * method that the client said he will accept
		 */

		/*
		 * ... but not a 206: its Content-Range and multipart part
		 * headers describe byte offsets in the file, and a coding
		 * applied over them would have them describe the coded
		 * bytes instead (RFC 9110 14.4)
		 */
		if (!wsi->interpreting &&
#if defined(LWS_WITH_RANGES)
		    !ranges &&
#endif
		    lws_http_compression_candidate(wsi, content_type))
			lws_http_compression_apply(wsi, NULL, &p, end, 0);
	}
#endif

	if (
#if defined(LWS_WITH_RANGES)
	    ranges < 2 &&
#endif
	    content_type && content_type[0])
		if (lws_add_http_header_by_token(wsi,
						 WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)content_type,
						 (int)strlen(content_type),
						 &p, end))
			goto bail;

#if defined(LWS_WITH_RANGES)
	if (ranges >= 2) { /* multipart byteranges */
		lws_strncpy(wsi->http.multipart_content_type, content_type,
			sizeof(wsi->http.multipart_content_type));

		if (lws_ranges_boundary_create(context, rp))
			goto bail;

		/*
		 * The boundary has to be declared here: it is the only thing
		 * that tells the client how the parts below are delimited
		 */

		n = lws_snprintf(mp_ct, sizeof(mp_ct),
				 "multipart/byteranges; boundary=%s",
				 rp->boundary);

		if (lws_add_http_header_by_token(wsi,
						 WSI_TOKEN_HTTP_CONTENT_TYPE,
						 (unsigned char *)mp_ct, n,
						 &p, end))
			goto bail;

		/*
		 *  our overall content length has to include
		 *
		 *  - n x the part header (delimiter, Content-Type,
		 *    Content-Range and the empty line ending them)
		 *  - the close delimiter
		 *  - the actual payloads (aggregated in rp->agg)
		 *
		 *  Precompute it for the main response header, composing each
		 *  part header exactly as the tx will, so the length we
		 *  promise cannot drift from the framing we send
		 */

		total_content_length = (lws_filepos_t)rp->agg +
				       (lws_filepos_t)lws_ranges_close_len(rp);

		lws_ranges_reset(rp);
		while (lws_ranges_next(rp) == 1) {
			n = lws_snprintf(part_hdr, sizeof(part_hdr),
					 LWS_RANGES_PART_HDR,
					 rp->boundary, content_type,
					 rp->start, rp->end, rp->extent);

			total_content_length = total_content_length +
					       (lws_filepos_t)n;
		}

		lws_ranges_reset(rp);
		lws_ranges_next(rp);
	}

	if (ranges == 1) {
		total_content_length = (lws_filepos_t)rp->agg;
		n = lws_snprintf(cache_control, sizeof(cache_control),
				 "bytes %llu-%llu/%llu",
				 rp->start, rp->end, rp->extent);

		if (lws_add_http_header_by_token(wsi,
						 WSI_TOKEN_HTTP_CONTENT_RANGE,
						 (unsigned char *)cache_control,
						 n, &p, end))
			goto bail;
	}

	wsi->http.range.inside = 0;

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_ACCEPT_RANGES,
					 (unsigned char *)"bytes", 5, &p, end))
		goto bail;
#endif

	if (!wsi->mux_substream) {
		/* for http/1.1 ... */
		if (!wsi->sending_chunked
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
				&& !wsi->http.lcs
#endif
		) {
			/* ... if not already using chunked and not using an
			 * http compression translation, then send the naive
			 * content length
			 */
			if (lws_add_http_header_content_length(wsi,
						total_content_length, &p, end))
				goto bail;
		} else {

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
			if (wsi->http.lcs) {

				/* ...otherwise, for http 1 it must go chunked.
				 * For the compression case, the reason is we
				 * compress on the fly and do not know the
				 * compressed content-length until it has all
				 * been sent.  Http/1.1 pipelining must be able
				 * to know where the transaction boundaries are
				 * ... so chunking...
				 */
				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_TRANSFER_ENCODING,
						(unsigned char *)"chunked", 7,
						&p, end))
					goto bail;

				/*
				 * ...this is fun, isn't it :-)  For h1 that is
				 * using an http compression translation, the
				 * compressor must chunk its output privately.
				 *
				 * h2 doesn't need (or support) any of this
				 * crap.
				 */
				lwsl_debug("setting chunking\n");
				wsi->http.comp_ctx.chunking = 1;
			}
#endif
		}
	}

	if (wsi->cache_no) {
		cc = cache_control;
		cclen = lws_snprintf(cache_control, sizeof(cache_control), "no-cache");
	}
	else if (wsi->cache_secs && wsi->cache_reuse) {
		if (!wsi->cache_revalidate) {
			cc = cache_control;
			cclen = lws_snprintf(cache_control, sizeof(cache_control), "%s, max-age=%u",
                         intermediates[wsi->cache_intermediaries],
                         wsi->cache_secs);
		} else {
			cc = cache_control;
			cclen = lws_snprintf(cache_control, sizeof(cache_control),
                         "must-revalidate, %s, max-age=%u",
                         intermediates[wsi->cache_intermediaries],
                         wsi->cache_secs);
		}
	}

	{
		int has_cache_control = 0;
		if (other_headers && other_headers_len > 0 &&
		    lws_is_ascii_headers(other_headers, other_headers_len)) {
			if (strstr(other_headers, "cache-control") ||
			    strstr(other_headers, "Cache-Control"))
				has_cache_control = 1;
		}

		/* Only add cache control if its not specified by any other_headers. */
		if (!has_cache_control) {
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CACHE_CONTROL,
					(unsigned char *)cc, cclen, &p, end))
				goto bail;
		}
	}

	if (other_headers && other_headers_len > 0) {
#if defined(LWS_ROLE_H3) || defined(LWS_WITH_HTTP2)
		if ((
#if defined(LWS_ROLE_H3)
		     lws_wsi_is_h3(wsi) ||
#endif
#if defined(LWS_WITH_HTTP2)
		     lws_wsi_is_h2(wsi) ||
#endif
		     0) && lws_is_ascii_headers(other_headers, other_headers_len)) {
			const char *lh = other_headers;
			const char *lh_end = other_headers + other_headers_len;

			while (lh < lh_end) {
				const char *line_end = lh;
				while (line_end < lh_end && *line_end != '\n' && *line_end != '\r')
					line_end++;

				if (line_end > lh) {
					const char *colon = lh;
					while (colon < line_end && *colon != ':')
						colon++;

					if (colon < line_end) {
						const char *name = lh;
						int name_len = (int)(colon - name);
						const char *val = colon + 1;

						while (val < line_end && (*val == ' ' || *val == '\t'))
							val++;

						while (name_len > 0 && (name[name_len - 1] == ' ' || name[name_len - 1] == '\t'))
							name_len--;

						int val_len = (int)(line_end - val);
						while (val_len > 0 && (val[val_len - 1] == ' ' || val[val_len - 1] == '\t'))
							val_len--;

						if (name_len > 0) {
							if (name[0] == ':') {
								/* Skip pseudo-headers */
								lh = line_end;
								while (lh < lh_end && (*lh == '\r' || *lh == '\n'))
									lh++;
								continue;
							}
							char name_buf[128];
							if (name_len < (int)sizeof(name_buf)) {
								memcpy(name_buf, name, (size_t)name_len);
								name_buf[name_len] = '\0';

								if (lws_add_http_header_by_name(wsi,
										(const unsigned char *)name_buf,
										(const unsigned char *)val,
										val_len, &p, end))
									goto bail;
							}
						}
					}
				}

				lh = line_end;
				while (lh < lh_end && (*lh == '\r' || *lh == '\n'))
					lh++;
			}
		} else
#endif
		{
			if ((end - p) < other_headers_len)
				goto bail;
			memcpy(p, other_headers, (unsigned int)other_headers_len);
			p += other_headers_len;
		}
	}

	if (lws_finalize_http_header(wsi, &p, end))
		goto bail;

	/*
	 * For HEAD, no body will follow the headers: the response is complete
	 * at this point, so on h2 / h3 the headers write must also carry
	 * END_STREAM.  Otherwise the stream is left half-closed locally with
	 * the peer waiting for a body that will never come.
	 *
	 * The same for an empty file sent as it is: there is nothing for the
	 * file sender to write, so nothing it writes can end the stream (a
	 * compressed or chunked one still has bytes to send for its end)
	 */
	no_body = wsi->http.method_head;
	if (!wsi->http.filelen && !wsi->sending_chunked
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    && !wsi->http.lcs
#endif
	   )
		no_body = 1;

	n = LWS_WRITE_HTTP_HEADERS;
	if (no_body)
		n |= LWS_WRITE_H2_STREAM_END;

	ret = lws_write(wsi, response, lws_ptr_diff_size_t(p, response),
			(enum lws_write_protocol)n);
	if (ret != (p - response)) {
		lwsl_err("_write returned %d from %ld\n", ret,
			 (long)(p - response));
		goto bail;
	}

	wsi->http.filepos = 0;
	lws_wsi_event(wsi, LWS_WSIEV_FILE_BEGIN);

	if (no_body) {
		/* we do not emit the body */
		lws_vfs_file_close(&wsi->http.fop_fd);

		/*
		 * The file phase is over before it started... we must leave
		 * it explicitly, the transaction cannot complete from inside
		 * it.  Otherwise the connection goes back to keepalive idle
		 * still in LRS_ISSUING_FILE with no fop_fd, and the next
		 * POLLOUT re-enters the file sender on the closed file.
		 */
		lws_wsi_event(wsi, LWS_WSIEV_FILE_COMPLETE);

		if (lws_http_transaction_completed(wsi))
			goto bail;

		return 0;
	}

	lws_callback_on_writable(wsi);

	return 0;

bail:
	lws_vfs_file_close(&wsi->http.fop_fd);

	return -1;
}

int
lws_serve_http_file(struct lws *wsi, const char *file, const char *content_type,
		    const char *other_headers, int other_headers_len)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int sb = lws_servbuf_claim(pt, pt->compose_buf + LWS_PRE,
				   wsi->a.context->pt_serv_buf_size - LWS_PRE,
				   "lws_serve_http_file");
	int r = lws_serve_http_file_composed(wsi, file, content_type, other_headers, other_headers_len);

	lws_servbuf_release(pt, sb);

	return r;
}
#endif

#if defined(LWS_WITH_FILE_OPS)

/*
 * sansIO tx of the file being served (README.sans-io-split.md, "A content
 * source's tx").  Fills buf, of which max may be used, with the payload of
 * the next lws_write(): any multipart range header, then the file bytes,
 * transformed in place if the mount asks, sized by what the peer allows (h2
 * max frame size, tx credit, the Range budget) and what the framing needs.
 * The file position advances by what was produced.
 *
 * Returns the count of bytes at *pp, with *wp how the role frames them and
 * *last whether they end the response; 0 when there is nothing more;
 * LWS_TX_WAIT when there is nothing now and want_write is asked for when
 * there is (the read went to a worker thread, tx credit is spent);
 * LWS_TX_FAIL when the source failed, with the file closed.
 */
int
lws_http_file_tx(struct lws *wsi, unsigned char *buf, size_t max,
		 unsigned char **pp, enum lws_write_protocol *wp, int *last)
{
#if defined(LWS_WITH_LATENCY)
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#endif
	struct lws_process_html_args args;
	lws_filepos_t amount, poss, room;
	unsigned char *p, *pstart, *bufend;
#if defined(LWS_ROLE_H2)
	struct lws *nwsi;
#endif
	int n;

	*last = 0;
	*wp = LWS_WRITE_HTTP;

	/*
	 * We are going to read the file: if it is not open, the only thing
	 * we can do with the connection is close it.  It means somebody left
	 * us in LRS_ISSUING_FILE without a file, which is a bug, but it must
	 * not be a remote crash.
	 */
	if (!wsi->http.fop_fd) {
		lwsl_wsi_err(wsi, "issuing file with no file open");

		return LWS_TX_FAIL;
	}

again:
	/*
	 * Without ranges, the end of the file is the end of the response.
	 * With them, only the end of the last range is: the parts can come in
	 * any order, so an earlier one may end at the end of the file with
	 * more still to go, which starts by seeking back for it below
	 */
	if (wsi->http.filepos == wsi->http.filelen
#if defined(LWS_WITH_RANGES)
	    && (!wsi->http.range.count_ranges || wsi->http.range.inside)
#endif
	)
		return 0;

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.count_ranges && !wsi->http.range.inside &&
	    (wsi->http.range.state == LWSRS_COMPLETED ||
	     wsi->http.range.state == LWSRS_SYNTAX))
		/* the last range's budget was spent */
		return 0;
#endif

	n = 0;
	p = pstart = buf;
	bufend = buf + max;

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.count_ranges && !wsi->http.range.inside) {

		lwsl_notice("%s: doing range start %llu\n", __func__,
			    wsi->http.range.start);

		if ((long long)lws_vfs_file_seek_cur(wsi->http.fop_fd,
					   (lws_fileofs_t)wsi->http.range.start -
					   (lws_fileofs_t)wsi->http.filepos) < 0)
			goto file_had_it;

		wsi->http.filepos = wsi->http.range.start;

		wsi->http.range.budget = wsi->http.range.end -
					   wsi->http.range.start + 1;
		wsi->http.range.inside = 1;
	}

	if (wsi->http.range.count_ranges > 1 &&
	    wsi->http.range.budget == wsi->http.range.end -
				      wsi->http.range.start + 1) {
		/*
		 * At the start of a part: its header goes ahead of its
		 * bytes.  Regenerated here rather than kept, since the
		 * read of the part's first bytes may go to a worker thread
		 * and come back in a later call, into a serv_buf that has
		 * been used for other things meanwhile.
		 */
		n =  lws_snprintf((char *)p,
				lws_ptr_diff_size_t(bufend, p),
			LWS_RANGES_PART_HDR,
			wsi->http.range.boundary,
			wsi->http.multipart_content_type,
			wsi->http.range.start,
			wsi->http.range.end,
			wsi->http.range.extent);
		p += n;
	}
#endif

	poss = (lws_filepos_t)max;

#if defined(LWS_ROLE_H2)
	/*
	 * If it's h2, restrict any lump that we are sending to the
	 * max h2 frame size the peer indicated he could handle in
	 * his SETTINGS
	 */
	nwsi = lws_get_network_wsi(wsi);
	if (nwsi->h2.h2n &&
	    poss > (lws_filepos_t)nwsi->h2.h2n->peer_set.s[H2SET_MAX_FRAME_SIZE])
		poss = (lws_filepos_t)nwsi->h2.h2n->peer_set.s[H2SET_MAX_FRAME_SIZE];
#endif
	/*
	 * The h2 frame header and the multipart part header we may
	 * just have written are part of the same lump... take them
	 * off the budget, saturating rather than wrapping if the
	 * peer chose a max frame size smaller than the part header
	 */
	if (poss > (lws_filepos_t)(n + LWS_H2_FRAME_HEADER_LENGTH))
		poss -= (lws_filepos_t)(n + LWS_H2_FRAME_HEADER_LENGTH);
	else
		poss = 0;

	if (wsi->http.tx_content_length)
		if (poss > wsi->http.tx_content_remain)
			poss = wsi->http.tx_content_remain;

	/*
	 * If there is a hint about how much we will do well to send at
	 * one time, restrict ourselves to only trying to send that.
	 */
	if (wsi->a.protocol->tx_packet_size &&
	    poss > wsi->a.protocol->tx_packet_size)
		poss = wsi->a.protocol->tx_packet_size;

	if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_credit)) {
		int txc = lws_rops_func_fidx(wsi->role_ops,
					     LWS_ROPS_tx_credit).
				tx_credit(wsi, LWSTXCR_US_TO_PEER, 0);

		if (txc <= 0) {
			/*
			 * tx credit is 0. This can happen because the
			 * QUIC pending_tx buffer throttle (64KB cap) kicked
			 * in *between* the POLLOUT handler's check and here.
			 * lws_callback_on_writable propagates requested_POLLOUT
			 * up the full parent chain so the post-ACK wakeup loop
			 * can restart us once the buffer drains.
			 */
			lwsl_notice("%s: %s: no tx credit\n", __func__,
					lws_wsi_tag(wsi));
			lws_callback_on_writable(wsi);

			return LWS_TX_WAIT;
		}
		if ((lws_filepos_t)txc < poss)
			poss = (lws_filepos_t)txc;

		/*
		 * Tracking consumption of the actual payload amount
		 * will be handled when the role data frame is sent...
		 */
	}

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.count_ranges &&
	    poss > wsi->http.range.budget)
		poss = wsi->http.range.budget;
#endif
	if (wsi->sending_chunked)
		/* we need to drop the chunk size in here */
		p += 10;

	/*
	 * Everything above clamps poss against lengths the peer chose
	 * (his window, his tx credit, his Range budget), none of which
	 * are related to the size of pt->serv_buf.  So compute what is
	 * really left in the buffer at p, minus what we must keep back
	 * for framing we will add after the content, and apply that as
	 * the last word on the read length.
	 */

	room = p < bufend ?
		(lws_filepos_t)lws_ptr_diff_size_t(bufend, p) : 0;

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.count_ranges > 1) {
		/* allow for the close delimiter, and the NUL lws_snprintf
		 * keeps room for after it */
		lws_filepos_t cl = (lws_filepos_t)
				lws_ranges_close_len(&wsi->http.range) + 1;

		room = room > cl ? room - cl : 0;
	}
#endif

	if (wsi->interpreting)
		/* allow for the chunk to grow by 128 in translation */
		room = room > 128 ? room - 128 : 0;

	if (poss > room)
		poss = room;

	if (!poss) {
		/*
		 * There is no space at all for content this time...
		 * that can only mean the buffer is too small for the
		 * framing, or a length we were given is 0; either way
		 * looping would never make progress
		 */
		lwsl_wsi_err(wsi, "no room for file content");

		goto file_had_it;
	}

#if defined(LWS_WITH_ASYNC_QUEUE)
	if (wsi->async_worker_job == NULL &&
	    wsi->http.fop_fd->fops == wsi->a.context->fops) {
		/* Do the read asynchronously instead of blocking */
		struct lws_async_job *job = lws_malloc(sizeof(*job) + poss, "async_fs");
		if (!job)
			goto file_had_it;
		memset(job, 0, sizeof(*job));
		wsi->async_worker_job = job;
		job->wsi = wsi;
		job->type = LWS_AQ_FILE_READ;
		job->u.fs.fop_fd = wsi->http.fop_fd;
		job->u.fs.buf = (uint8_t *)&job[1];
		job->u.fs.len = poss;

		if (lws_async_queue_submit(wsi->a.context, job)) {
			/*
			 * The workers are saturated.  That is backpressure,
			 * not a file error: read this fragment on the event
			 * loop, as a build without the async queue always
			 * does, rather than fail the request.  (Behind a
			 * peer's concurrent stream limit, the last streams
			 * to be granted send credit found ten siblings'
			 * reads already queued and were closed with no
			 * body, intermittently.)
			 */
			lws_free(job);
			wsi->async_worker_job = NULL;
			lwsl_wsi_info(wsi, "async read queue full, reading inline");
		} else {
			lws_wsi_event(wsi, LWS_WSIEV_FILE_READ_QUEUED);
			return LWS_TX_WAIT; /* the worker's completion drives us */
		}
	}

	/* We are returning from async read logic here, amount would be pre-filled */
	if (wsi->async_worker_job == NULL) {
#endif
		amount = 0;
#if defined(LWS_WITH_LATENCY)
		{
			lws_usec_t _lws_start = lws_now_usecs();
#endif
		if (lws_vfs_file_read(wsi->http.fop_fd, &amount, p, poss) < 0)
			goto file_had_it; /* caller will close */

		/*
		 * A 0-byte success short of the length the fops
		 * reported at open means the backing data is
		 * truncated; retrying would never progress, and
		 * this loop only exits on progress or a choked pipe
		 */
		if (!amount && poss &&
		    wsi->http.filepos < wsi->http.filelen) {
			lwsl_wsi_notice(wsi, "short file read at %llu / %llu",
					(unsigned long long)wsi->http.filepos,
					(unsigned long long)wsi->http.filelen);
			goto file_had_it;
		}
#if defined(LWS_WITH_LATENCY)
			lws_latency_note(pt, _lws_start, 500, "read:%uus ",
				(unsigned int)(lws_now_usecs() - _lws_start));
		}
#endif
#if defined(LWS_WITH_ASYNC_QUEUE)
	} else {
		amount = wsi->async_worker_job->u.fs.amount;
		if ((int)amount < 0) {
			goto file_had_it;
		}
		memcpy(p, wsi->async_worker_job->u.fs.buf, amount);

		/* Clean up job */
		wsi->async_worker_job->wsi = NULL;
		lws_free(wsi->async_worker_job);
		wsi->async_worker_job = NULL;
	}
#endif

	if (wsi->sending_chunked)
		n = (int)amount;
	else
		n = lws_ptr_diff(p, pstart) + (int)amount;

	if (!n)
		return 0;

	if (wsi->interpreting) {
		args.p = (char *)p;
		args.len = n;
		/*
		 * the transform may grow the content in
		 * place: it may use everything that is
		 * actually left in serv_buf at p, no more
		 */
		args.max_len = lws_ptr_diff(bufend, p);
		args.final = wsi->http.filepos + (unsigned int)n ==
					wsi->http.filelen;
		args.chunked = wsi->sending_chunked;
		if (user_callback_handle_rxflow(
		     wsi->a.vhost->protocols[
		     (int)wsi->protocol_interpret_idx].callback,
		     wsi, LWS_CALLBACK_PROCESS_HTML,
		     wsi->user_space, &args, 0) < 0)
			goto file_had_it;
		n = args.len;
		p = (unsigned char *)args.p;

		if (!n && !args.final) {
			/*
			 * The interpreter holds all of this lump back until
			 * it sees more (it ends in what may be the start of
			 * a variable): nothing is to go yet, but it is not
			 * the end of the file either, which is what nothing
			 * to send means to our caller.  Read on.
			 */
			wsi->http.filepos += amount;
			goto again;
		}
	} else
		p = pstart;

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.send_ctr + 1 ==
		wsi->http.range.count_ranges && // last range
	    wsi->http.range.count_ranges > 1 && // was 2+ ranges (ie, multipart)
	    wsi->http.range.budget - amount == 0) {// final part
		/* + 1: the NUL lws_snprintf keeps room for after it */
		n += lws_snprintf((char *)pstart + n,
				  lws_ranges_close_len(&wsi->http.range) + 1,
				  LWS_RANGES_CLOSE, wsi->http.range.boundary);
		lwsl_debug("added close delimiter\n");
	}
#endif

	*pp = p;

	/*
	 * What was produced is IO's now: the position moves on, IO buffers
	 * whatever the transport does not take at once
	 */
	wsi->http.filepos += amount;

#if defined(LWS_WITH_RANGES)
	if (wsi->http.range.count_ranges >= 1) {
		wsi->http.range.budget -= amount;
		if (wsi->http.range.budget == 0) {
			lwsl_notice("range budget exhausted\n");
			wsi->http.range.inside = 0;
			wsi->http.range.send_ctr++;

			if (lws_ranges_next(&wsi->http.range) < 1)
				*last = 1;
		}
	} else
#endif
	if (wsi->http.filepos >= wsi->http.filelen)
		*last = 1;

	/*
	 * The last lump of the response is what the role has to frame as
	 * final: the end of a range response is where the ranges run out,
	 * which for all but the last range is short of the end of the file
	 */

	*wp = *last ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP;

	return n;

file_had_it:
	lws_vfs_file_close(&wsi->http.fop_fd);

	return LWS_TX_FAIL;
}

/*
 * The whole file went out and none of it is left with IO: the response is
 * complete.  Returns 1, or -1 (1 on a substream, whose completion is the
 * stream's business, not the connection's) if the user's completion
 * callback failed.
 */
int
lws_http_file_complete(struct lws *wsi)
{
	lws_wsi_event(wsi, LWS_WSIEV_FILE_COMPLETE);
	/* we might be in keepalive, so close it off here */
	lws_vfs_file_close(&wsi->http.fop_fd);
#if defined(LWS_WITH_RANGES)
	lws_ranges_destroy(&wsi->http.range);
#endif

	lwsl_debug("file completed\n");

	if (wsi->a.protocol->callback &&
	    user_callback_handle_rxflow(wsi->a.protocol->callback,
			wsi, LWS_CALLBACK_HTTP_FILE_COMPLETION,
			wsi->user_space, NULL, 0) < 0) {
			/*
			 * For http/1.x, the choices from
			 * transaction_completed are either
			 * 0 to use the connection for pipelined
			 * or nonzero to hang it up.
			 *
			 * However for http/2. while we are
			 * still interested in hanging up the
			 * nwsi if there was a network-level
			 * fatal error, simply completing the
			 * transaction is a matter of the stream
			 * state, not the root connection at the
			 * network level
			 */

			if (wsi->mux_substream)
				return 1;
			else
				return -1;
		}

	/*
	 * If the completion above was deferred because the
	 * request body still has to be discarded (we are in
	 * LRS_DISCARD_BODY), the transaction is not over yet.
	 * Resetting the ah here would clear
	 * hdr_parsing_completed, and the completion that
	 * follows the discard would then be ignored as
	 * "parsing incomplete", leaving the connection
	 * spinning on the bytes of the next request.  The
	 * discard path completes the transaction, and with
	 * it the ah, once the body is gone.
	 */
	if (wsi->stream.ah &&
	    lwsi_state(wsi) != LRS_DISCARD_BODY)
		lws_header_table_reset(wsi, 0);

	return 1;  /* >0 indicates completed */
}

/* IO could not send what was produced: the source is done with */
void
lws_http_file_tx_abort(struct lws *wsi)
{
	lws_vfs_file_close(&wsi->http.fop_fd);
#if defined(LWS_WITH_RANGES)
	lws_ranges_destroy(&wsi->http.range);
#endif
}

#endif

#if defined(LWS_WITH_SERVER)
void
lws_server_get_canonical_hostname(struct lws_context *context,
				  const struct lws_context_creation_info *info)
{
	if (lws_check_opt(info->options,
			LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME))
		return;
#if !defined(LWS_PLAT_FREERTOS)
	/* find canonical hostname */
	if (gethostname((char *)context->canonical_hostname,
		        sizeof(context->canonical_hostname) - 1))
		lws_strncpy((char *)context->canonical_hostname, "unknown",
			    sizeof(context->canonical_hostname));

	lwsl_cx_info(context, " canonical_hostname = %s\n",
					context->canonical_hostname);
#else
	(void)context;
#endif
}
#endif

/*
 * Substitute the variables in one lump of a file being interpreted, in place,
 * and frame it as an h1 chunk if asked to.
 *
 * A variable may start in one lump and end in the next.  What of one the lump
 * ends with is held back in s->swallow, and put in front of the next lump
 * before that is looked at, so a variable is only ever matched, and replaced,
 * whole inside the buffer.  The last lump of the file has nothing after it:
 * there, it is just text.
 *
 * The content grows in place, up to args->max_len from args->p, keeping back
 * the 7 bytes the chunk trailers need.  A chunk's size line goes in front of
 * args->p, where the caller leaves room for it.  A lump that is all held back
 * leaves args->len 0: nothing goes, not even a chunk, since an empty chunk
 * would end the body.
 */
int
lws_chunked_html_process(struct lws_process_html_args *args,
			 struct lws_process_html_state *s)
{
	int len = args->len, i = 0, hit = 0, hits, m, n, k, vl;
	char *p = args->p, buffer[16];
	const char *pc;

	if (len < 0 || s->pos < 0 || s->pos >= (int)sizeof(s->swallow))
		return -1;

	if (len + s->pos + 7 >= args->max_len) {
		lwsl_err("Used up interpret padding\n");
		return -1;
	}

	if (s->pos) {
		/* the start of a variable the last lump ended with goes first */
		memmove(p + s->pos, p, (size_t)len);
		memcpy(p, s->swallow, (size_t)s->pos);
		len += s->pos;
		s->pos = 0;
	}

	while (i < len) {
		if (p[i] != '$') {
			i++;
			continue;
		}

		/*
		 * Match a character more at a time, until exactly one variable
		 * is matched whole, or none can be, or the lump runs out first
		 */
		hits = 0;
		for (m = 1; m < (int)sizeof(s->swallow) - 1 && i + m <= len;
		     m++) {
			hits = 0;
			for (k = 0; k < s->count_vars; k++) {
				vl = (int)strlen(s->vars[k]);
				if (vl >= m && !memcmp(p + i, s->vars[k],
						       (size_t)m)) {
					hits++;
					hit = k;
				}
			}
			if (!hits || (hits == 1 &&
				      m == (int)strlen(s->vars[hit])))
				break;
		}

		if (hits && i + m > len && m < (int)sizeof(s->swallow) - 1 &&
		    !args->final) {
			/* it may still be a variable: that is up to what follows */
			s->pos = len - i;
			memcpy(s->swallow, p + i, (size_t)s->pos);
			s->swallow[s->pos] = '\0';
			len = i;
			break;
		}

		if (hits != 1 || i + m > len ||
		    m == (int)sizeof(s->swallow) - 1 ||
		    m != (int)strlen(s->vars[hit])) {
			/* the '$' was just text: look again after it */
			i++;
			continue;
		}

		pc = s->replace(s->data, hit);
		if (!pc)
			pc = "NULL";
		n = (int)strlen(pc);

		if (len - m + n + 7 >= args->max_len) {
			lwsl_err("Used up interpret padding\n");
			return -1;
		}

		memmove(p + i + n, p + i + m, (size_t)(len - i - m));
		memcpy(p + i, pc, (size_t)n);
		len += n - m;

		/* what we put in is not looked at for variables again */
		i += n;
	}

	args->len = len;

	if (!args->chunked || (!len && !args->final))
		return 0;

	if (len) {
		n = lws_snprintf(buffer, sizeof(buffer), "%X\x0d\x0a", len);
		args->p -= n;
		memcpy(args->p, buffer, (size_t)n);
		args->len += n;
		memcpy(args->p + args->len, "\x0d\x0a", 2);
		args->len += 2;
	}

	if (args->final) {
		/* the last-chunk, with no trailers */
		memcpy(args->p + args->len, "0\x0d\x0a\x0d\x0a", 5);
		args->len += 5;
	}

	return 0;
}
//#endif
