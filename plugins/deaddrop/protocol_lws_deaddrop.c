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

	struct lwsac			*lwsac_head;
	struct dir_entry		*dire_head;
	int				filelist_version;

	unsigned long long		max_size;

#if defined(__linux__)
	int				inotify_fd;
#endif
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
	unsigned long long		file_length;
	lws_filefd_type			fd;
	int				response_code;

	struct pss_deaddrop		*pss_list;

	struct lwsac			*lwsac_head;
	struct dir_entry		*dire;
	int				filelist_version;

	uint8_t				completed:1;
	uint8_t				sent_headers:1;
	uint8_t				sent_body:1;
	uint8_t				first:1;
	uint8_t				ws_ongoing_send:1;
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
parse_user_agent(const char *ua, char *platform, size_t plat_len,
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
de_mtime_sort(lws_list_ptr a, lws_list_ptr b)
{
	struct dir_entry *p1 = lp_to_dir_entry(a, next),
			 *p2 = lp_to_dir_entry(b, next);

	return (int)(p2->mtime - p1->mtime);
}

static void
start_sending_dir(struct pss_deaddrop *pss)
{
	if (pss->lwsac_head)
		lwsac_unreference(&pss->lwsac_head);

	if (pss->vhd->lwsac_head)
		lwsac_reference(pss->vhd->lwsac_head);
	pss->lwsac_head = pss->vhd->lwsac_head;
	pss->dire = pss->vhd->dire_head;
	pss->filelist_version = pss->vhd->filelist_version;
	pss->first = 1;
	pss->ws_ongoing_send = 1;
}

static void
broadcast_state_update(struct vhd_deaddrop *vhd)
{
	vhd->filelist_version++; /* Invalidate client cache */

	lws_start_foreach_llp(struct pss_deaddrop **, ppss, vhd->pss_head) {
		if (!(*ppss)->ws_ongoing_send)
			start_sending_dir(*ppss);
		lws_callback_on_writable((*ppss)->wsi);
	} lws_end_foreach_llp(ppss, pss_list);
}


static int
scan_upload_dir(struct vhd_deaddrop *vhd)
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

		lws_list_ptr_insert(&sorted_head, &dire->next, de_mtime_sort);
	}

	closedir(dir);

	/* the old lwsac continues to live while someone else is consuming it */
	if (vhd->lwsac_head)
		lwsac_detach(&vhd->lwsac_head);

	/* we replace it with the fresh one */
	vhd->lwsac_head = lwsac_head;
	if (sorted_head)
		vhd->dire_head = lp_to_dir_entry(sorted_head, next);
	else
		vhd->dire_head = NULL;

	broadcast_state_update(vhd);

	return 0;
}

static int
file_upload_cb(void *data, const char *name, const char *filename,
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
		scan_upload_dir(pss->vhd);

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
format_result(struct pss_deaddrop *pss)
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
handler_server_protocol_init(struct lws *wsi, void *in)
{
	struct vhd_deaddrop *vhd;
	const char *cp;

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

	if (!lws_pvo_get_str(in, "max-size", &cp))
		vhd->max_size = (unsigned long long)atoll(cp);
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

	scan_upload_dir(vhd);

	lwsl_notice("  deaddrop: vh %s, upload dir %s, max size %llu\n",
		    lws_get_vhost_name(vhd->vh), vhd->upload_dir,
		    vhd->max_size);

	return 0;
}

static void
handler_server_protocol_destroy(struct vhd_deaddrop *vhd)
{
	if (!vhd)
		return;

	lwsac_free(&vhd->lwsac_head);
#if defined(__linux__)
	if (vhd->inotify_fd != -1)
		close(vhd->inotify_fd);
#endif
}

static int
handler_server_http(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
		    struct lws *wsi)
{
	char *uri_ptr;
	int uri_len;
	int meth;

	memset(pss, 0, sizeof(*pss));
	pss->user[0] = '\0';

	/* Correctly get username after lws basic auth processing */
	if (lws_hdr_copy(wsi, pss->user, sizeof(pss->user),
			 WSI_TOKEN_HTTP_AUTHORIZATION) > 0)
		lwsl_wsi_info(wsi, "%s: POST auth user (pss %p): '%s'\n",
			      __func__, (void *)pss, pss->user);
	else
		lwsl_wsi_warn(wsi, "%s: HTTP POST: no auth\n", __func__);

	meth = lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len);
	if (meth != LWSHUMETH_POST || !uri_ptr)
		return 1;
	if (!strstr(uri_ptr, "/upload/"))
		return 1;

	pss->vhd = vhd;
	pss->wsi = wsi;

	return 0;
}

static int
handler_server_http_body(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			 struct lws *wsi, void *in, size_t len)
{
	/* create the POST argument parser if not already existing */
	if (!pss->spa) {
		pss->spa = lws_spa_create(wsi, param_names,
					  LWS_ARRAY_SIZE(param_names),
					  1024, file_upload_cb, pss);
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
handler_server_http_body_completion(struct pss_deaddrop *pss, struct lws *wsi)
{
	/* call to inform no more payload data coming */
	lws_spa_finalize(pss->spa);

	pss->completed = 1;
	lws_callback_on_writable(wsi);
}

static int
handler_server_http_writeable(struct vhd_deaddrop *vhd,
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
		int n = format_result(pss);

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
		int n = format_result(pss);
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
handler_server_raw_file_rx(struct vhd_deaddrop *vhd, struct lws *wsi)
{
#if defined(__linux__)
	char ev_buf[1024];

	/* inotify has told us something changed in the upload dir */
	int n, fd = lws_get_socket_fd(wsi);

	if (fd < 0)
		return 0;

	n = (int)read(fd, ev_buf, sizeof(ev_buf));
	lwsl_info("%s: inotify event (%d), rescanning upload dir\n", __func__, n);
	scan_upload_dir(vhd);

	return n;
#else
	return 0;
#endif
}

static void
handler_server_ws_established(struct vhd_deaddrop *vhd,
			      struct pss_deaddrop *pss, struct lws *wsi)
{
	char ua_buf[256];

	pss->vhd		= vhd;
	pss->wsi		= wsi;
	/* add ourselves to the list of live pss held in the vhd */
	pss->pss_list		= vhd->pss_head;
	vhd->pss_head		= pss;

	pss->user[0]		= '\0';
	pss->platform[0]	= '\0';
	pss->browser[0]		= '\0';

	/* Correctly get username after lws basic auth processing */
	if (lws_hdr_copy(wsi, pss->user, sizeof(pss->user),
			 WSI_TOKEN_HTTP_AUTHORIZATION) > 0)
		lwsl_wsi_info(wsi, "%s: WS connect auth user (pss %p): '%s'\n",
			  __func__, (void *)pss, pss->user);
	else
		lwsl_wsi_warn(wsi, "%s: WS connect: no auth\n", __func__);

	if (lws_hdr_copy(wsi, ua_buf, sizeof(ua_buf),
			 WSI_TOKEN_HTTP_USER_AGENT) > 0)
		parse_user_agent(ua_buf, pss->platform,  sizeof(pss->platform),
				 pss->browser, sizeof(pss->browser));

	broadcast_state_update(vhd);
}

static void
handler_server_ws_closed(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss)
{
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

	broadcast_state_update(vhd);
}

static void
handler_server_ws_rx(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
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

	if ((int)strlen(pss->user) != n ||
	    strncmp(pss->user, ((const char *)in) + 8, (unsigned int)n)) {
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

	scan_upload_dir(vhd);
}

static int
handler_server_ws_writeable(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			    struct lws *wsi)
{
	uint8_t buf[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE],
		*start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n, was = 0;

	/* if nothing to write, write nothing */
	if (!pss->ws_ongoing_send)
		return 0;

	if (pss->first) {
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "{\"max_size\":%llu, \"user\":\"%s\", ",
				  vhd->max_size,
				  pss->user[0] ? pss->user : "");

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "\"connected_users\":[");

		int first_user = 1;
		lws_start_foreach_llp(struct pss_deaddrop **, ppss,
				      vhd->pss_head) {
			char ip[46];

			/* Only list authenticated connections */
			if (!(*ppss)->wsi || !(*ppss)->user[0])
				continue;

			lws_get_peer_simple((*ppss)->wsi, ip, sizeof(ip));

			p += lws_snprintf((char *)p,
					  lws_ptr_diff_size_t(end, p),
				"%c{\"user\":\"%s\", \"ip\":\"%s\", "
				"\"platform\":\"%s\", \"browser\":\"%s\"}",
				first_user ? ' ' : ',',
				(*ppss)->user, ip, (*ppss)->platform,
				(*ppss)->browser);

			first_user = 0;
		} lws_end_foreach_llp(ppss, pss_list);

		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "], \"files\": [");
		was = 1;
	}

	n = 5;
	while (n-- && pss->dire) {
		int is_yours = !strcmp(pss->user, pss->dire->user) &&
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
				  "\"size\":%llu,"
				  "\"mtime\":%llu,"
				  "\"yours\":%d,"
				  "\"is_text\":%d}",
				  pss->first ? ' ' : ',',
				  fname,
				  pss->dire->size,
				  (unsigned long long)pss->dire->mtime,
				  is_yours, is_text);
		pss->first = 0;
		pss->dire = lp_to_dir_entry(pss->dire->next, next);
	}

	if (!pss->dire) {
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  "]}");
		if (pss->lwsac_head) {
			lwsac_unreference(&pss->lwsac_head);
			pss->lwsac_head = NULL;
		}
		pss->ws_ongoing_send = 0;
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

	if (pss->filelist_version != pss->vhd->filelist_version) {
		lwsl_info("%s: restart send\n", __func__);
		/* what we just sent is already out of date */
		start_sending_dir(pss);
		lws_callback_on_writable(wsi);
	}
	
	return 0;
}

static int
callback_deaddrop(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct vhd_deaddrop *vhd = (struct vhd_deaddrop *)
				lws_protocol_vh_priv_get(lws_get_vhost(wsi),
							 lws_get_protocol(wsi));
	struct pss_deaddrop *pss = (struct pss_deaddrop *)user;

	switch (reason) {
	
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		handler_server_protocol_init(wsi, in);
		break;

	case LWS_CALLBACK_HTTP:
		if (!handler_server_http(vhd, pss, wsi))
			return 0;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		handler_server_protocol_destroy(vhd);
		break;

	case LWS_CALLBACK_RAW_RX_FILE:
		handler_server_raw_file_rx(vhd, wsi);
		break;

	/* WS-related */

	case LWS_CALLBACK_ESTABLISHED:
		handler_server_ws_established(vhd, pss, wsi);
		return 0;

	case LWS_CALLBACK_CLOSED:
		handler_server_ws_closed(vhd, pss);
		return 0;

	case LWS_CALLBACK_RECEIVE:
		handler_server_ws_rx(vhd, pss, wsi, in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		handler_server_ws_writeable(vhd, pss, wsi);
		return 0;

	/* POST-related */

	case LWS_CALLBACK_HTTP_BODY:
		return handler_server_http_body(vhd, pss, wsi, in, len);

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		handler_server_http_body_completion(pss, wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		switch (handler_server_http_writeable(vhd, pss, wsi)) {
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

#define LWS_PLUGIN_PROTOCOL_DEADDROP \
	{ \
		"lws-deaddrop", \
		callback_deaddrop, \
		sizeof(struct pss_deaddrop), \
		1024, \
		0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)

LWS_VISIBLE const struct lws_protocols deaddrop_protocols[] = {
	LWS_PLUGIN_PROTOCOL_DEADDROP
};

LWS_VISIBLE const lws_plugin_protocol_t deaddrop = {
	.hdr = {
		"deaddrop",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = deaddrop_protocols,
	.count_protocols = LWS_ARRAY_SIZE(deaddrop_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};

#endif
