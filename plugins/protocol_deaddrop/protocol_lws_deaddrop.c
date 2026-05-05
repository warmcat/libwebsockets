/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifdef WIN32
#include <io.h>
#endif
#if defined(__linux__)
#include <limits.h>
#endif
#include <stdio.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif

struct dir_entry {
	lws_list_ptr next; /* sorted by mtime */
	char user[32];
	unsigned long long size;
	time_t mtime;
};
/* filename follows */

#define lp_to_dir_entry(p, _n) lws_list_ptr_container(p, struct dir_entry, _n)

struct pss_deaddrop;

struct vhd_deaddrop {
	struct lws_context		*context;
	struct lws_vhost		*vh;
	const struct lws_protocols	*protocol;

	struct pss_deaddrop		*pss_head;

	const char			*upload_dir;
	const char			*cookie_name;

	struct lwsac			*lwsac_head;
	struct dir_entry		*dire_head;
	int				filelist_version;
	int				userlist_version;

	unsigned long long		max_size;

#if defined(__linux__)
	int				inotify_fd;
#endif
	struct lws_jwk			jwk;
	uint8_t				has_jwk:1;
};

struct pss_deaddrop {
	struct lws_spa			*spa;
	struct vhd_deaddrop		*vhd;
	struct lws			*wsi;
	char				result[LWS_PRE + 2048];
	char				filename[256];
	char				platform[32];
	char				browser[32];
	char				user[64];
	char				tab_id[32];
	char				ip[46];
	unsigned long long		file_length;
	lws_filefd_type			fd;
	int				response_code;

	struct pss_deaddrop		*pss_list;

	struct lwsac			*lwsac_head;
	struct dir_entry		*dire;
	int				filelist_version;
	int				userlist_version;
	int				sending_filelist_version;
	int				sending_userlist_version;

	uint8_t				completed:1;
	uint8_t				sent_headers:1;
	uint8_t				sent_body:1;
	uint8_t				first:1;
	uint8_t				sent_initial:1;
	uint8_t				ws_ongoing_send:1;
	uint8_t				has_star_grant:1;
};

static const char * const param_names[] = {
	"text",
	"send",
	"file",
	"upload",
};

enum enum_param_names {
	EPN_TEXT,
	EPN_SEND,
	EPN_FILE,
	EPN_UPLOAD,
};

static void
deaddrop_parse_user_agent(const char *ua, char *platform, size_t plat_len,
		 char *browser, size_t browser_len)
{
	lws_strncpy(platform, "Unknown", plat_len);
	lws_strncpy(browser, "Unknown", browser_len);

	/* Guess platform from UA */

	if (strstr(ua, "Windows"))
		lws_strncpy(platform, "Windows", plat_len);
	else if (strstr(ua, "Linux"))
		lws_strncpy(platform, "Linux", plat_len);
	else if (strstr(ua, "Macintosh") || strstr(ua, "Mac OS"))
		lws_strncpy(platform, "macOS", plat_len);

	/* Guess browser / client from UA */

	if (strstr(ua, "curl"))
		lws_strncpy(browser, "curl", browser_len);
	else if (strstr(ua, "Wget"))
		lws_strncpy(browser, "Wget", browser_len);
	else if (strstr(ua, "Edg/"))
		lws_strncpy(browser, "Edge", browser_len);
	else if (strstr(ua, "Firefox/"))
		lws_strncpy(browser, "Firefox", browser_len);
	else if (strstr(ua, "Chrome/") && strstr(ua, "Safari/"))
		lws_strncpy(browser, "Chrome", browser_len);
}

static int
deaddrop_de_mtime_sort(lws_list_ptr a, lws_list_ptr b)
{
	struct dir_entry *p1 = lp_to_dir_entry(a, next),
			 *p2 = lp_to_dir_entry(b, next);

	return (int)(p2->mtime - p1->mtime);
}

static void
deaddrop_start_sending_dir(struct pss_deaddrop *pss)
{
	if (pss->lwsac_head)
		lwsac_unreference(&pss->lwsac_head);

	if (pss->vhd->lwsac_head)
		lwsac_reference(pss->vhd->lwsac_head);
	pss->lwsac_head = pss->vhd->lwsac_head;
	pss->dire = pss->vhd->dire_head;
	pss->sending_filelist_version = pss->vhd->filelist_version;
	pss->sending_userlist_version = pss->vhd->userlist_version;
	pss->first = 1;
	pss->ws_ongoing_send = 1;
}

static void
deaddrop_broadcast_userlist_update(struct vhd_deaddrop *vhd)
{
	vhd->userlist_version++;

	lws_start_foreach_llp(struct pss_deaddrop **, ppss, vhd->pss_head) {
		if (!(*ppss)->ws_ongoing_send)
			deaddrop_start_sending_dir(*ppss);
		lws_callback_on_writable((*ppss)->wsi);
	} lws_end_foreach_llp(ppss, pss_list);
}

static void
deaddrop_broadcast_filelist_update(struct vhd_deaddrop *vhd)
{
	vhd->filelist_version++;

	lws_start_foreach_llp(struct pss_deaddrop **, ppss, vhd->pss_head) {
		if (!(*ppss)->ws_ongoing_send)
			deaddrop_start_sending_dir(*ppss);
		lws_callback_on_writable((*ppss)->wsi);
	} lws_end_foreach_llp(ppss, pss_list);
}


static int
deaddrop_scan_upload_dir(struct vhd_deaddrop *vhd)
{
	char filepath[512], *p_owner_end;
	struct lwsac *lwsac_head = NULL;
	lws_list_ptr sorted_head = NULL;
	struct dir_entry *dire;
	struct dirent *de;
	size_t m;
	struct stat s;
	DIR *dir;

	dir = opendir(vhd->upload_dir);
	if (!dir) {
		lwsl_err("%s: Unable to walk upload dir '%s'\n", __func__,
			 vhd->upload_dir);
		return -1;
	}

	while ((de = readdir(dir))) {
		/* ignore temp files */
		if (de->d_name[strlen(de->d_name) - 1] == '~' ||
		    !strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		lws_snprintf(filepath, sizeof(filepath), "%s/%s",
				  vhd->upload_dir, de->d_name);

		if (stat(filepath, &s))
			continue;

		if (S_ISDIR(s.st_mode))
			continue;

		m = strlen(de->d_name) + 1;
		dire = lwsac_use(&lwsac_head, sizeof(*dire) + m, 0);
		if (!dire) {
			lwsac_free(&lwsac_head);
			closedir(dir);
			return -1;
		}

		dire->next = NULL;
		dire->size = (unsigned long long)s.st_size;
		dire->mtime = s.st_mtime;
		dire->user[0] = '\0';

		p_owner_end = strchr(de->d_name, '_');
		if (p_owner_end) {
			size_t owner_len = (size_t)(p_owner_end - de->d_name);
			if (owner_len < sizeof(dire->user)) {
				memcpy(dire->user, de->d_name, owner_len);
				dire->user[owner_len] = '\0';
			}
		}

		memcpy(&dire[1], de->d_name, m);

		lws_list_ptr_insert(&sorted_head, &dire->next, deaddrop_de_mtime_sort);
	}

	closedir(dir);

	int changed = 0;
	struct dir_entry *old_dire = vhd->dire_head;
	struct dir_entry *new_dire = sorted_head ? lp_to_dir_entry(sorted_head, next) : NULL;

	while (old_dire && new_dire) {
		if (old_dire->size != new_dire->size ||
		    old_dire->mtime != new_dire->mtime ||
		    strcmp(old_dire->user, new_dire->user) ||
		    strcmp((const char *)&old_dire[1], (const char *)&new_dire[1])) {
			changed = 1;
			break;
		}
		old_dire = lp_to_dir_entry(old_dire->next, next);
		new_dire = lp_to_dir_entry(new_dire->next, next);
	}
	if (old_dire || new_dire)
		changed = 1;

	/* the old lwsac continues to live while someone else is consuming it */
	if (vhd->lwsac_head)
		lwsac_detach(&vhd->lwsac_head);

	/* we replace it with the fresh one */
	vhd->lwsac_head = lwsac_head;
	if (sorted_head)
		vhd->dire_head = lp_to_dir_entry(sorted_head, next);
	else
		vhd->dire_head = NULL;

	if (changed)
		deaddrop_broadcast_filelist_update(vhd);

	return 0;
}

static int
deaddrop_file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int _len, enum lws_spa_fileupload_states state)
{
	lwsl_warn("%s: entered, state %d, pss->user: '%s'\n", __func__,
		  state, ((struct pss_deaddrop *)data)->user);

	struct pss_deaddrop *pss = (struct pss_deaddrop *)data;
	char filename2[256];
	size_t len = (size_t)_len;
	int n;

	(void)n;

	switch (state) {
	case LWS_UFS_OPEN:
		/* REQUIRE an authenticated user on the upload POST itself */
		if (!pss->user[0]) {
			pss->response_code = HTTP_STATUS_FORBIDDEN;
			lwsl_wsi_warn(pss->wsi, "%s: no authenticated user"
						" (pss %p)\n", __func__, pss);
			return -1;
		}

		lws_urldecode(filename2, filename, sizeof(filename2) - 1);
		lws_filename_purify_inplace(filename2);
		lws_filename_purify_inplace(pss->user);

		/*
		 * Server is authoritative: construct filename from
		 * authenticated user and the base filename from the
		 * request.
		 */
		lws_snprintf(pss->filename, sizeof(pss->filename),
			     "%s/%s_%s~", pss->vhd->upload_dir,
			     pss->user, filename2);
		lwsl_notice("%s: filename '%s'\n", __func__, pss->filename);

		pss->fd = (lws_filefd_type)(long long)lws_open(pss->filename,
			      O_CREAT | O_TRUNC | O_RDWR, 0600);
		if (pss->fd == LWS_INVALID_FILE) {
			pss->response_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			lwsl_err("%s: unable to open %s (errno %d)\n", __func__,
					pss->filename, errno);
			return -1;
		}
		break;

	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (len) {
			pss->file_length += (unsigned int)len;

			/* if the file length is too big, drop it */
			if (pss->file_length > pss->vhd->max_size) {
				pss->response_code =
					HTTP_STATUS_REQ_ENTITY_TOO_LARGE;
				close((int)(lws_intptr_t)pss->fd);
				pss->fd = LWS_INVALID_FILE;
				unlink(pss->filename);

				return -1;
			}

			if (pss->fd != LWS_INVALID_FILE) {
				n = (int)write((int)(lws_intptr_t)pss->fd, buf,
						(unsigned int)len);
				lwsl_debug("%s: write %d says %d\n", __func__,
					   (int)len, n);
				lws_set_timeout(pss->wsi,
						PENDING_TIMEOUT_HTTP_CONTENT, 30);
			}
		}
		if (state == LWS_UFS_CONTENT)
			break;

		if (pss->fd != LWS_INVALID_FILE)
			close((int)(lws_intptr_t)pss->fd);

		/* the temp filename without the ~ */
		lws_strncpy(filename2, pss->filename, sizeof(filename2));
		filename2[strlen(filename2) - 1] = '\0';
		if (rename(pss->filename, filename2) < 0)
			lwsl_err("%s: unable to rename\n", __func__);

		pss->fd = LWS_INVALID_FILE;
		pss->response_code = HTTP_STATUS_OK;
		deaddrop_scan_upload_dir(pss->vhd);

		break;
	case LWS_UFS_CLOSE:
		break;
	}

	return 0;
}

/*
 * returns length in bytes
 */

static int
deaddrop_format_result(struct pss_deaddrop *pss)
{
	/*
	 * We don't want to send any entity body back for the upload
	 * POST.  The success / failure is indicated by the
	 * HTTP response code.  The javascript on the client side that
	 * did the post is not expecting to navigate to a new page.
	 */
	return 0;
}


static int
deaddrop_handler_server_protocol_init(struct lws *wsi, void *in)
{
	struct vhd_deaddrop *vhd;
	const char *cp;

	if (!in)
		return 0;

	lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				    lws_get_protocol(wsi),
				    sizeof(struct vhd_deaddrop));

	vhd = (struct vhd_deaddrop *)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					 lws_get_protocol(wsi));
	if (!vhd)
		return 0;

#if defined(__linux__)
	vhd->inotify_fd = -1;
#endif

	vhd->context	= lws_get_context(wsi);
	vhd->vh		= lws_get_vhost(wsi);
	vhd->protocol	= lws_get_protocol(wsi);
	vhd->max_size	= 20 * 1024 * 1024; /* default without pvo */
	vhd->cookie_name = "auth_session";

	if (!lws_pvo_get_str(in, "max-size", &cp))
		vhd->max_size = (unsigned long long)atoll(cp);
	if (lws_pvo_get_str(in, "cookie-name", &vhd->cookie_name))
		lwsl_info("%s: using default cookie-name\n", __func__);
	if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
		if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
			if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
				lwsl_err("%s: failed to load/import JWK\n", __func__);
				return -1;
			}
		}
		vhd->has_jwk = 1;
	}
	if (lws_pvo_get_str(in, "upload-dir", &vhd->upload_dir)) {
		lwsl_vhost_warn(lws_get_vhost(wsi), "%s: requires 'upload-dir' pvo\n", __func__);
		return 0;
	}

#if defined(__linux__)
	/*
	 * Set up inotify on the upload dir and adopt it into the
	 * lws event loop on our vhost, so we can be told about
	 * external changes to the dir contents
	 */
	vhd->inotify_fd = inotify_init1(IN_NONBLOCK);
	if (vhd->inotify_fd >= 0) {
		if (inotify_add_watch(vhd->inotify_fd, vhd->upload_dir,
				      IN_CLOSE_WRITE | IN_DELETE |
				      IN_MOVED_FROM | IN_MOVED_TO) >= 0)
			lws_adopt_descriptor_vhost(vhd->vh,
				LWS_ADOPT_RAW_FILE_DESC,
				(lws_sock_file_fd_type)vhd->inotify_fd,
				vhd->protocol->name, NULL);
		else
			lwsl_err("%s: inotify_add_watch failed\n",
				 __func__);
	}
#endif

	deaddrop_scan_upload_dir(vhd);

	lwsl_notice("  deaddrop: vh %s, upload dir %s, max size %llu\n",
		    lws_get_vhost_name(vhd->vh), vhd->upload_dir,
		    vhd->max_size);

	return 0;
}

static void
deaddrop_handler_server_protocol_destroy(struct vhd_deaddrop *vhd)
{
	if (!vhd)
		return;

	if (vhd->has_jwk)
		lws_jwk_destroy(&vhd->jwk);

	lwsac_free(&vhd->lwsac_head);
#if defined(__linux__)
	if (vhd->inotify_fd != -1)
		close(vhd->inotify_fd);
#endif
}

static int
deaddrop_handler_server_http(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
		    struct lws *wsi)
{
	char *uri_ptr;
	int uri_len;
	int meth;

	memset(pss, 0, sizeof(*pss));
	pss->user[0] = '\0';

	pss->user[0] = '\0';
	/* Correctly get username after lws basic auth processing */
	if (lws_hdr_copy(wsi, pss->user, sizeof(pss->user),
			 WSI_TOKEN_HTTP_AUTHORIZATION) > 0 &&
	    strncmp(pss->user, "Basic ", 6) && strncmp(pss->user, "Bearer ", 7)) {
		lwsl_wsi_info(wsi, "%s: POST auth user (pss %p): '%s'\n",
			      __func__, (void *)pss, pss->user);
	} else {
		pss->user[0] = '\0'; /* flush raw headers if basic auth skipped */
		if (vhd->has_jwk) {
			struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, wsi);
			if (ja) {
				const char *sub = lws_jwt_auth_get_sub(ja);
				if (sub) {
					lws_strncpy(pss->user, sub, sizeof(pss->user));
					lwsl_wsi_info(wsi, "%s: POST JWT user (pss %p): '%s'\n",
						__func__, (void *)pss, pss->user);
				}
				lws_jwt_auth_destroy(&ja);
			}
		}
		if (!pss->user[0])
			lwsl_wsi_warn(wsi, "%s: HTTP POST: no auth\n", __func__);
	}

	meth = lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len);
	if (meth != LWSHUMETH_POST || !uri_ptr)
		return 1;
	if (!strstr(uri_ptr, "/upload/"))
		return 1;

	pss->vhd = vhd;
	pss->wsi = wsi;

	if (lws_hdr_copy(wsi, pss->filename, sizeof(pss->filename), WSI_TOKEN_HTTP_URI_ARGS) > 0)
		return 0;

	return 1;
}

static int
deaddrop_handler_server_http_body(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			 struct lws *wsi, void *in, size_t len)
{
	/* create the POST argument parser if not already existing */
	if (!pss->spa) {
		pss->spa = lws_spa_create(wsi, param_names,
					  LWS_ARRAY_SIZE(param_names),
					  1024, deaddrop_file_upload_cb, pss);
		if (!pss->spa)
			return -1;

		pss->filename[0] = '\0';
		pss->file_length = 0;
		pss->response_code = HTTP_STATUS_SERVICE_UNAVAILABLE;
	}

	/* let it parse the POST data */
	if (lws_spa_process(pss->spa, in, (int)len)) {
		lwsl_notice("spa saw a problem\n");
		/* some problem happened */
		lws_spa_finalize(pss->spa);

		pss->completed = 1;
		lws_callback_on_writable(wsi);
	}

	return 0;
}

static void
deaddrop_handler_server_http_body_completion(struct pss_deaddrop *pss, struct lws *wsi)
{
	/* call to inform no more payload data coming */
	lws_spa_finalize(pss->spa);

	pss->completed = 1;
	lws_callback_on_writable(wsi);
}

static int
deaddrop_handler_server_http_writeable(struct vhd_deaddrop *vhd,
			      struct pss_deaddrop *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + 2048], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (!pss->completed)
		return 0;

	p = (unsigned char *)pss->result + LWS_PRE;
	start = p;
	end = p + sizeof(pss->result) - LWS_PRE - 1;

	if (!pss->sent_headers) {
		int n = deaddrop_format_result(pss);

		if (lws_add_http_header_status(wsi,
				(unsigned int)pss->response_code,
					       &p, end))
			return 1;

		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9,
				&p, end))
			return 1;
		if (lws_add_http_header_content_length(wsi, (lws_filepos_t)n, &p, end))
			return 1;
		if (lws_finalize_http_header(wsi, &p, end))
			return 1;

		/* first send the headers ... */
		n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      LWS_WRITE_HTTP_HEADERS );//|
			      //LWS_WRITE_H2_STREAM_END);
		if (n < 0)
			return 1;

		pss->sent_headers = 1;
		lws_callback_on_writable(wsi);
		return 0;
	}

	if (!pss->sent_body) {
		int n = deaddrop_format_result(pss);
		n = lws_write(wsi, (unsigned char *)start, (unsigned int)n,
			      LWS_WRITE_HTTP_FINAL);

		pss->sent_body = 1;
		if (n < 0) {
			lwsl_err("%s: writing body failed\n", __func__);
			return 1;
		}
		return 2;
	}

	return 0;
}

static int
deaddrop_handler_server_raw_file_rx(struct vhd_deaddrop *vhd, struct lws *wsi)
{
#if defined(__linux__)
	char ev_buf[1024];

	/* inotify has told us something changed in the upload dir */
	int n, fd = lws_get_socket_fd(wsi);

	if (fd < 0)
		return 0;

	n = (int)read(fd, ev_buf, sizeof(ev_buf));
	lwsl_info("%s: inotify event (%d), rescanning upload dir\n", __func__, n);
	deaddrop_scan_upload_dir(vhd);

	return n;
#else
	return 0;
#endif
}

static int
deaddrop_handler_server_ws_filter_protocol_connection(struct vhd_deaddrop *vhd,
					     struct pss_deaddrop *pss, struct lws *wsi)
{
	char ua_buf[256];

	pss->user[0]		= '\0';
	pss->platform[0]	= '\0';
	pss->browser[0]		= '\0';

	/* Correctly get username after lws basic auth processing */
	if (lws_hdr_copy(wsi, pss->user, sizeof(pss->user),
			 WSI_TOKEN_HTTP_AUTHORIZATION) > 0 &&
	    strncmp(pss->user, "Basic ", 6) && strncmp(pss->user, "Bearer ", 7)) {
		lwsl_wsi_info(wsi, "%s: WS filter auth user (pss %p): '%s'\n",
			  __func__, (void *)pss, pss->user);
	} else {
		pss->user[0] = '\0'; /* flush raw headers if basic auth skipped */
		if (vhd->has_jwk) {
			int cookie_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);

			if (cookie_len > 0) {
				char *cookie_buf = NULL;

				/* lws_jwt_auth_create uses 1024 stack buf, bypass if too large */
				if (cookie_len > 1000) {
					cookie_buf = malloc((size_t)cookie_len + 1);
					if (cookie_buf && lws_hdr_copy(wsi, cookie_buf, cookie_len + 1, WSI_TOKEN_HTTP_COOKIE) > 0) {
						char *p = strstr(cookie_buf, vhd->cookie_name);
						if (p) {
							p += strlen(vhd->cookie_name);
							if (*p == '=') {
								p++;
								char *jwt = p, *end = p;
								while (*end && *end != ';')
									end++;
								*end = '\0';

								/* Manual parsing for large cookie bypass using public APIs */
								char temp[2048], out[2048];
								size_t out_len = sizeof(out);
								int ret = lws_jwt_signed_validate(lws_get_context(wsi), &vhd->jwk,
									"ES256,ES384,ES512,RS256,RS384,RS512,HS256",
									jwt, strlen(jwt), temp, sizeof(temp), out, &out_len);

								if (ret == 0) {
									size_t alen = 0;
									const char *sub = lws_json_simple_find(out, out_len, "\"sub\":", &alen);
									if (sub && alen < sizeof(pss->user)) {
										lws_strncpy(pss->user, sub, alen + 1);
									}
									const char *grant = lws_json_simple_find(out, out_len, "\"grant\":", &alen);
									if (grant && ((alen == 1 && grant[0] == '*') || (alen > 1 && !strncmp(grant, "*", 1)))) {
										pss->has_star_grant = 1;
									}
								}
							}
						}
					}
					if (cookie_buf)
						free(cookie_buf);
				} else {
					struct lws_jwt_auth *ja = lws_jwt_auth_create(wsi, &vhd->jwk, vhd->cookie_name, NULL, wsi);
					if (ja) {
						const char *sub = lws_jwt_auth_get_sub(ja);
						if (sub) {
							lws_strncpy(pss->user, sub, sizeof(pss->user));
						}

						if (lws_jwt_auth_query_grant(ja, "*") >= 1) {
							pss->has_star_grant = 1;
						}
						lws_jwt_auth_destroy(&ja);
					}
				}
			}
		}
		// if (!pss->user[0])
		//	lwsl_wsi_warn(wsi, "WS filter: no auth\n");
	}

	if (lws_hdr_copy(wsi, ua_buf, sizeof(ua_buf),
			 WSI_TOKEN_HTTP_USER_AGENT) > 0)
		deaddrop_parse_user_agent(ua_buf, pss->platform,  sizeof(pss->platform),
				 pss->browser, sizeof(pss->browser));

	if (lws_get_urlarg_by_name_safe(wsi, "tabId=", pss->tab_id, sizeof(pss->tab_id)) < 0)
		pss->tab_id[0] = '\0';

	return 0;
}

static void
deaddrop_handler_server_ws_established(struct vhd_deaddrop *vhd,
			      struct pss_deaddrop *pss, struct lws *wsi)
{
	pss->vhd		= vhd;
	pss->wsi		= wsi;

	lws_get_peer_simple(wsi, pss->ip, sizeof(pss->ip));

	/* add ourselves to the list of live pss held in the vhd */
	pss->pss_list		= vhd->pss_head;
	vhd->pss_head		= pss;

	deaddrop_broadcast_userlist_update(vhd);
}

static void
deaddrop_handler_server_ws_closed(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss)
{
	lwsl_notice("%s: WS connection closed (user: '%s', ip: %s)\n",
		    __func__, pss->user, pss->ip);

	if (pss->lwsac_head)
		lwsac_unreference(&pss->lwsac_head);
	/* remove our closing pss from the list of live pss */
	lws_start_foreach_llp(struct pss_deaddrop **,
			      ppss, vhd->pss_head) {
		if (*ppss == pss) {
			*ppss = pss->pss_list;
			break;
		}
	} lws_end_foreach_llp(ppss, pss_list);

	deaddrop_broadcast_userlist_update(vhd);
}

static void
deaddrop_handler_server_ws_rx(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
		     struct lws *wsi, void *in, size_t len)
{
#if defined(__linux__)
	char path[512], resolved_path[PATH_MAX];
#else
	char path[512];
#endif
	char fname[256], *wp;
	const char *cp;
	int n;

	/* we get this kind of thing {"del":"user_agreen.txt"} */
	if (!pss || len < 10)
		return;

	if (strncmp((const char *)in, "{\"del\":\"", 8))
		return;

	cp = strchr((const char *)in + 8, '_');
	if (!cp) {
		lwsl_warn("%s: del: no owner in filename\n", __func__);
		return;
	}

	/* Check if the authenticated user matches the file owner prefix */
	n = (int)(cp - (((const char *)in) + 8));

	if (!pss->has_star_grant && ((int)strlen(pss->user) != n ||
	    strncmp(pss->user, ((const char *)in) + 8, (unsigned int)n))) {
		lwsl_wsi_notice(wsi, "del: auth mismatch "
			    " user '%s' tried to delete file with "
			    "owner '%.*s'", pss->user, n,
			    ((const char *)in) + 8);
		return;
	}

	lws_strncpy(fname, ((const char *)in) + 8, sizeof(fname));
	wp = strchr((const char *)fname, '\"');
	if (wp)
		*wp = '\0';

	lws_filename_purify_inplace(fname);

	lws_snprintf(path, sizeof(path), "%s/%s", vhd->upload_dir,
		     fname);

#if defined(__linux__)
	if (!realpath(path, resolved_path)) {
		lwsl_wsi_warn(wsi, "delete: realpath failed %s", path);
		return;
	}

	if (strncmp(resolved_path, vhd->upload_dir,
		    strlen(vhd->upload_dir))) {
		lwsl_err("%s: illegal delete attempt '%s' -> '%s'\n",
			 __func__, path, resolved_path);
		return;
	}
	lws_strncpy(path, resolved_path, sizeof(path));
#endif

	lwsl_wsi_notice(wsi, "deleting '%s'", path);

	if (unlink(path) < 0)
		lwsl_err("%s: unlink %s failed: %s\n", __func__,
				path, strerror(errno));

	deaddrop_scan_upload_dir(vhd);
}

static int
deaddrop_handler_server_ws_writeable(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			    struct lws *wsi)
{
	uint8_t buf[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n, was = 0;

	/* if nothing to write, write nothing */
	if (!pss->ws_ongoing_send)
		return 0;

	int send_users = (pss->userlist_version != pss->sending_userlist_version) || !pss->sent_initial;
	int send_files = (pss->filelist_version != pss->sending_filelist_version) || !pss->sent_initial;

	if (pss->first) {
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "{\"max_size\":%llu, \"user\":\"%s\", \"cookie\":\"%s\"",
				  vhd->max_size,
				  pss->user[0] ? pss->user : "",
				  vhd->cookie_name);

		if (send_users) {
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
					  ", \"connected_users\":[");

			int first_user = 1;
			lws_start_foreach_llp(struct pss_deaddrop **, ppss,
					      vhd->pss_head) {
				/* Only list authenticated connections */
				if ((*ppss)->wsi && (*ppss)->user[0]) {
					p += lws_snprintf((char *)p,
							  lws_ptr_diff_size_t(end, p),
						"%c{\"user\":\"%s\", \"ip\":\"%s\", "
						"\"platform\":\"%s\", \"browser\":\"%s\"%s%s}",
						first_user ? ' ' : ',',
						(*ppss)->user, (*ppss)->ip, (*ppss)->platform,
						(*ppss)->browser,
						(*ppss)->has_star_grant ? ", \"is_admin\":1" : "",
						((*ppss) == pss) ? ", \"is_self\":1" : "");

					first_user = 0;
				}
			} lws_end_foreach_llp(ppss, pss_list);

			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "]");
		}

		if (send_files) {
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
					  ", \"files\": [");
			was = 1;
		} else {
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p), "}");
			pss->dire = NULL;
			was = 1;
		}
	}

	n = 5;
	while (n-- && pss->dire) {
		int is_yours = (pss->has_star_grant || !strcmp(pss->user, pss->dire->user)) &&
			       pss->user[0];
		const char *fname = (const char *)&pss->dire[1];
		const char *p_fn = fname;
		int is_text = 0;

		if (pss->dire->user[0])
			p_fn += strlen(pss->dire->user) + 1;

		/* check for YYYY-MM-DD_HH-MM-SS.txt format */
		if (strlen(p_fn) == 23 &&
		    p_fn[4] == '-' && p_fn[7] == '-' &&
		    p_fn[10] == '_' && p_fn[13] == '-' &&
		    p_fn[16] == '-' && !strcmp(p_fn + 19, ".txt"))
			is_text = 1;

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "%c{\"name\":\"%s\", "
				  "\"uploader\":\"%s\","
				  "\"size\":%llu,"
				  "\"mtime\":%llu,"
				  "\"yours\":%d,"
				  "\"is_text\":%d}",
				  pss->first ? ' ' : ',',
				  fname,
				  pss->dire->user,
				  pss->dire->size,
				  (unsigned long long)pss->dire->mtime,
				  is_yours, is_text);
		pss->first = 0;
		pss->dire = lp_to_dir_entry(pss->dire->next, next);
	}

	if (!pss->dire) {
		int send_files = (pss->filelist_version != pss->sending_filelist_version) || !pss->sent_initial;
		if (send_files) {
			p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
					  "]}");
		}
		if (pss->lwsac_head) {
			lwsac_unreference(&pss->lwsac_head);
			pss->lwsac_head = NULL;
		}
		pss->ws_ongoing_send = 0;
		pss->sent_initial = 1;
		pss->userlist_version = pss->sending_userlist_version;
		pss->filelist_version = pss->sending_filelist_version;
	}

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      lws_write_ws_flags(LWS_WRITE_TEXT, was, !pss->dire));
	if (n < 0) {
		lwsl_notice("%s: ws write failed\n", __func__);
		return 1;
	}
	if (pss->ws_ongoing_send) {
		lws_callback_on_writable(wsi);

		return 0;
	}

	/* ie, we finished */

	if (pss->filelist_version != pss->vhd->filelist_version ||
	    pss->userlist_version != pss->vhd->userlist_version) {
		lwsl_info("%s: restart send\n", __func__);
		/* what we just sent is already out of date */
		deaddrop_start_sending_dir(pss);
		lws_callback_on_writable(wsi);
	}

	return 0;
}

static int
_deaddrop_callback_deaddrop(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct vhd_deaddrop *vhd = (struct vhd_deaddrop *)
				lws_protocol_vh_priv_get(lws_get_vhost(wsi),
							 lws_get_protocol(wsi));
	struct pss_deaddrop *pss = (struct pss_deaddrop *)user;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */

		if (!in)
			return 0;

		deaddrop_handler_server_protocol_init(wsi, in);
		break;

	case LWS_CALLBACK_HTTP:
		if (!deaddrop_handler_server_http(vhd, pss, wsi))
			return 0;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		deaddrop_handler_server_protocol_destroy(vhd);
		break;

	case LWS_CALLBACK_RAW_RX_FILE:
		deaddrop_handler_server_raw_file_rx(vhd, wsi);
		break;

	/* WS-related */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		if (deaddrop_handler_server_ws_filter_protocol_connection(vhd, pss, wsi))
			return 1;
		return 0;

	case LWS_CALLBACK_ESTABLISHED:
		deaddrop_handler_server_ws_established(vhd, pss, wsi);
		return 0;

	case LWS_CALLBACK_CLOSED:
		deaddrop_handler_server_ws_closed(vhd, pss);
		return 0;

	case LWS_CALLBACK_RECEIVE:
		deaddrop_handler_server_ws_rx(vhd, pss, wsi, in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		deaddrop_handler_server_ws_writeable(vhd, pss, wsi);
		return 0;

	/* POST-related */

	case LWS_CALLBACK_HTTP_BODY:
		return deaddrop_handler_server_http_body(vhd, pss, wsi, in, len);

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		deaddrop_handler_server_http_body_completion(pss, wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		switch (deaddrop_handler_server_http_writeable(vhd, pss, wsi)) {
		case 0:
			return 0;
		case 1:
			goto bail;
		case 2:
			goto try_to_reuse;
		}
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

bail:

	return 1;

try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
deaddrop_callback_deaddrop(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	int r = _deaddrop_callback_deaddrop(wsi, reason, user, in, len);

	if (r && reason != LWS_CALLBACK_HTTP_WRITEABLE &&
	    reason != LWS_CALLBACK_SERVER_WRITEABLE &&
	    reason != LWS_CALLBACK_HTTP_BODY) {
		lwsl_notice("%s: returning %d for reason %d on wsi %p\n", __func__, r, reason, wsi);
	}

	return r;
}

#define LWS_PLUGIN_PROTOCOL_DEADDROP \
	{ \
		"lws-deaddrop", \
		deaddrop_callback_deaddrop, \
		sizeof(struct pss_deaddrop), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols deaddrop_protocols[] = {
	LWS_PLUGIN_PROTOCOL_DEADDROP
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t deaddrop = {
	.hdr = {
		.name = "deaddrop",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},

	.protocols = deaddrop_protocols,
	.count_protocols = LWS_ARRAY_SIZE(deaddrop_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
