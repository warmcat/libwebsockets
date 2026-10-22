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
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif

/*
 * Uploaded files are stored as "<owner>_<name>" directly in the upload dir,
 * and the ownership of a file is nothing more than that <owner> prefix.  So
 * the prefix has to identify the uploader unambiguously: it is the
 * authenticated username encoded so it can never contain '_' (nor '/'),
 * which makes the first '_' in an on-disk name always the end of the owner.
 * Bytes outside [a-z0-9.@+-] become "=xx" (lowercase hex), so the encoding
 * is one-to-one, and "bob" and "bob_smith" ("bob=5fsmith") can never claim
 * each other's files.  Upper-case letters are encoded too, so the prefix is
 * also unique on a case-insensitive filesystem: "Bob" ("=42ob") and "bob"
 * are different accounts and must not name the same files there.
 *
 * And the whole username is the owner: one that does not fit pss->user is no
 * user at all, never a truncated one that would be shared with others.  The
 * buffer holds the longest a JWT "sub" can be (lws_jwt_auth keeps 127 bytes)
 * and any basic auth name lws accepts.
 *
 * Usernames made only of [a-z0-9.@+-] encode to themselves, so files stored
 * by the earlier "<purified user>_<name>" scheme keep their owner.  Files
 * stored earlier by a user whose name contained anything else, including an
 * upper-case letter, are attributed to whatever precedes their first '_', and
 * should be renamed to the new encoding (or deleted) by the administrator,
 * eg "Bob_notes.txt" -> "=42ob_notes.txt".
 */

#define DEADDROP_USER_MAX	128
#define DEADDROP_OWNER_MAX	(((DEADDROP_USER_MAX - 1) * 3) + 1)
/* a user name JSON-escaped, worst case: every byte \u00xx, and purify's slack */
#define DEADDROP_USER_ESC_MAX	(((DEADDROP_USER_MAX - 1) * 6) + 7)

struct dir_entry {
	lws_list_ptr next; /* sorted by mtime */
	size_t owner_len; /* length of the owner prefix of the name, or 0 */
	unsigned long long size;
	time_t mtime;
};
/* filename follows */

/*
 * One connected user, rendered as a JSON object when a listing send starts,
 * so a listing that spans several writeables neither depends on the other
 * connections staying alive nor sees the list change halfway through
 */

struct deaddrop_user_snap {
	lws_dll2_t		list;
	size_t			len;
	/* rendered JSON object follows, NUL-terminated */
};

/*
 * A listing message is streamed out over as many writeables as it needs, in
 * these phases
 */

enum deaddrop_send_phase {
	DDSP_HEADER,
	DDSP_USERS,
	DDSP_FILES_OPEN,
	DDSP_FILES,
	DDSP_DONE
};

/* the only ws message we accept, {"del":"<name>"}, JSON-escaped */
#define DEADDROP_RX_MAX		1024

#define lp_to_dir_entry(p, _n) lws_list_ptr_container(p, struct dir_entry, _n)

struct pss_deaddrop;

struct vhd_deaddrop {
	struct lws_context		*context;
	struct lws_vhost		*vh;
	const struct lws_protocols	*protocol;

	lws_dll2_owner_t		pss_head; /* list of live pss */

	/*
	 * the "upload-dir" pvo canonicalised once at init (absolute, no
	 * symlinks, no trailing '/'), since every stored name is resolved and
	 * then required to be inside it.  Empty if the vhost has no usable
	 * upload dir, in which case we serve nothing.
	 */
	char				upload_dir[PATH_MAX];
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
	/*
	 * set if this vhost gave the protocol a "basic-auth" pvo, ie, users
	 * that lws's own basic auth accepted are deaddrop users: lws checks
	 * the ws upgrade against the pvo's file, and http requests against
	 * their mount's login file, if it has one
	 */
	uint8_t				basic_auth:1;
	/* set by the "allow-anonymous" pvo: serve unauthenticated ws peers */
	uint8_t				allow_anon:1;
	/*
	 * set by the "require-origin" pvo: also refuse requests that carry no
	 * Origin header at all, ie, non-browser clients
	 */
	uint8_t				require_origin:1;

	/* the "origin-allow" pvo: extra origins accepted, comma-separated */
	const char			*origin_allow;
};

struct pss_deaddrop {
	struct lws_spa			*spa;
	struct vhd_deaddrop		*vhd;
	struct lws			*wsi;
	char				result[LWS_PRE + 2048];
	char				filename[512];
	char				platform[32];
	char				browser[32];
	char				user[DEADDROP_USER_MAX];
	/* user, encoded as the owner prefix of the files it uploads */
	char				owner[DEADDROP_OWNER_MAX];
	char				rx[DEADDROP_RX_MAX];
	size_t				rx_len;
	char				tab_id[32];
	char				ip[46];
	unsigned long long		file_length;
	lws_filefd_type			fd;
	int				response_code;

	lws_dll2_t			pss_list; /* vhd->pss_head membership */

	struct lwsac			*lwsac_head;
	struct dir_entry		*dire;

	struct lwsac			*users_ac;	/* user snapshot */
	lws_dll2_owner_t		users;
	lws_dll2_t			*users_cursor;

	int				filelist_version;
	int				userlist_version;
	int				sending_filelist_version;
	int				sending_userlist_version;

	uint8_t				phase; /* enum deaddrop_send_phase */

	uint8_t				completed:1;
	uint8_t				sent_headers:1;
	uint8_t				sent_body:1;
	uint8_t				sent_initial:1;
	uint8_t				ws_ongoing_send:1;
	uint8_t				has_star_grant:1;
	uint8_t				send_users:1;
	uint8_t				send_files:1;
	uint8_t				item_first:1;
	uint8_t				rx_overflow:1;
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

	if ((char *)strstr(ua, "Windows"))
		lws_strncpy(platform, "Windows", plat_len);
	else if ((char *)strstr(ua, "Linux"))
		lws_strncpy(platform, "Linux", plat_len);
	else if ((char *)strstr(ua, "Macintosh") || (char *)strstr(ua, "Mac OS"))
		lws_strncpy(platform, "macOS", plat_len);

	/* Guess browser / client from UA */

	if ((char *)strstr(ua, "curl"))
		lws_strncpy(browser, "curl", browser_len);
	else if ((char *)strstr(ua, "Wget"))
		lws_strncpy(browser, "Wget", browser_len);
	else if ((char *)strstr(ua, "Edg/"))
		lws_strncpy(browser, "Edge", browser_len);
	else if ((char *)strstr(ua, "Firefox/"))
		lws_strncpy(browser, "Firefox", browser_len);
	else if ((char *)strstr(ua, "Chrome/") && (char *)strstr(ua, "Safari/"))
		lws_strncpy(browser, "Chrome", browser_len);
}

static int
deaddrop_owner_char_ok(char c)
{
	/* no upper case: see the comment at the top */
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       c == '.' || c == '@' || c == '+' || c == '-';
}

/*
 * Encode username into the owner prefix used on disk (see the comment at the
 * top).  Returns 0, or -1 if it is empty or would not fit in dst.
 */

static int
deaddrop_owner_encode(char *dst, size_t dst_len, const char *user)
{
	size_t o = 0;

	while (*user) {
		if (deaddrop_owner_char_ok(*user)) {
			if (o + 1 >= dst_len)
				return -1;
			dst[o++] = *user++;
			continue;
		}

		if (o + 3 >= dst_len)
			return -1;
		dst[o++] = '=';
		lws_hex_from_byte_array((const uint8_t *)user++, 1, dst + o, 3);
		o += 2;
	}

	dst[o] = '\0';

	return o ? 0 : -1;
}

/*
 * The username an owner prefix stands for, for display.  A prefix that is not
 * a valid encoding (eg, from a file placed in the upload dir by other means)
 * is shown as it is.
 */

static const char *
deaddrop_owner_decode(char *dst, size_t dst_len, const char *owner,
		      size_t owner_len)
{
	size_t o = 0, n = 0;
	uint8_t b;

	while (n < owner_len && o + 1 < dst_len) {
		if (owner[n] != '=') {
			if (!deaddrop_owner_char_ok(owner[n]))
				goto as_is;
			dst[o++] = owner[n++];
			continue;
		}

		if (n + 3 > owner_len ||
		    lws_hex_len_to_byte_array(owner + n + 1, 2, &b, 1) != 1 ||
		    !b)
			goto as_is;
		dst[o++] = (char)b;
		n += 3;
	}

	if (n == owner_len) {
		dst[o] = '\0';

		return dst;
	}

as_is:
	lws_strnncpy(dst, owner, owner_len, dst_len);

	return dst;
}

/*
 * Establish the authenticated identity for this connection into pss->user
 * (left empty if there is none), pss->owner and pss->has_star_grant.
 *
 * Two sources are accepted:
 *
 *  - if this vhost gave us the "basic-auth" pvo, the user lws's own basic
 *    auth accepted for this very request (lws_http_basic_auth_user()): the
 *    pvo's file on the ws upgrade, or the mount's login file on http.  Never
 *    the Authorization header itself: the pvo only makes lws check the ws
 *    upgrade, so on a mount without its own basic auth the header is just
 *    what the peer typed, eg "Authorization: alice".
 *
 *  - the JWT session cookie, which must both verify and still be live:
 *    lws_jwt_auth_create() deliberately hands back a token that verified but
 *    has expired, leaving the expiry policy to us.  For a session credential,
 *    expired means no session.  And it must be a session token, signed with
 *    the auth server's "sso" purpose: the jwk may be shared with other
 *    minters, eg an interceptor whose visit token, sub = the peer IP, is
 *    handed to anyone (G-188).
 */

static void
deaddrop_get_auth_identity_user(struct vhd_deaddrop *vhd,
				struct pss_deaddrop *pss, struct lws *wsi)
{
	struct lws_jwt_auth_info ai;
	struct lws_jwt_auth *ja;
	const char *sub;

	pss->user[0] = '\0';

#if defined(LWS_WITH_HTTP_BASIC_AUTH) && defined(LWS_WITH_SERVER)
	sub = vhd->basic_auth ? lws_http_basic_auth_user(wsi) : NULL;
	if (sub) {
		/* a name that does not fit is no user, never a shorter one */
		if (strlen(sub) >= sizeof(pss->user)) {
			lwsl_wsi_notice(wsi, "%s: basic auth user too long",
					__func__);

			return;
		}
		lws_strncpy(pss->user, sub, sizeof(pss->user));
		lwsl_wsi_info(wsi, "%s: basic auth user '%s'", __func__,
			      pss->user);

		return;
	}
#endif

	if (!vhd->has_jwk)
		return;

	memset(&ai, 0, sizeof(ai));
	ai.jwk		= &vhd->jwk;
	ai.cookie_name	= vhd->cookie_name;
	ai.purpose	= LWS_JWT_AUTH_PURPOSE_SSO;
	ai.user		= wsi;

	ja = lws_jwt_auth_create_via_info(wsi, &ai, NULL);
	if (!ja)
		return;

	if (lws_jwt_auth_get_exp(ja) <= (uint64_t)lws_now_secs()) {
		lwsl_wsi_notice(wsi, "%s: JWT session expired", __func__);
		lws_jwt_auth_destroy(&ja);

		return;
	}

	sub = lws_jwt_auth_get_sub(ja);
	if (sub && strlen(sub) >= sizeof(pss->user)) {
		/* a name that does not fit is no user, never a shorter one */
		lwsl_wsi_notice(wsi, "%s: JWT sub too long", __func__);
		lws_jwt_auth_destroy(&ja);

		return;
	}
	if (sub)
		lws_strncpy(pss->user, sub, sizeof(pss->user));

	if (pss->user[0] && lws_jwt_auth_query_grant(ja, "*") >= 1)
		pss->has_star_grant = 1;

	lwsl_wsi_info(wsi, "%s: JWT user '%s'", __func__, pss->user);

	lws_jwt_auth_destroy(&ja);
}

static void
deaddrop_get_auth_identity(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			   struct lws *wsi)
{
	pss->user[0]		= '\0';
	pss->owner[0]		= '\0';
	pss->has_star_grant	= 0;

	deaddrop_get_auth_identity_user(vhd, pss, wsi);

	if (pss->user[0] &&
	    deaddrop_owner_encode(pss->owner, sizeof(pss->owner), pss->user)) {
		/* can't happen with owner sized for user, but fail closed */
		pss->user[0]		= '\0';
		pss->has_star_grant	= 0;
	}
}

/*
 * Both the ws upgrade and the upload POST are authenticated by an ambient
 * credential (the JWT session cookie, or basic auth), and neither is subject
 * to the same-origin policy by itself: a ws upgrade is exempt, and a
 * multipart POST is a CORS "simple request".  So without this, any page the
 * victim visits while logged in can open our ws (and receive the whole file
 * listing plus every connected user's IP), delete the victim's files, and
 * upload files in the victim's name.
 *
 * Returns 0 if the request may proceed, nonzero to refuse it.
 *
 * Policy when the request carries no Origin at all: allow, unless the vhost
 * gave us the "require-origin" pvo.  Browsers always send Origin on a ws
 * upgrade and on any POST, so no Origin means a non-browser client (curl, a
 * script, another service), and it is precisely the browser that a hostile
 * page can aim at us with the victim's cookie attached.  Refusing those
 * would break scripted use of the drop without closing anything, so it is
 * the deployment's choice; "require-origin" is right for a vhost that only
 * ever serves browsers.  Note that a sandboxed or otherwise opaque document
 * sends the literal "null", which is not absent, and never matches.
 */

static int
deaddrop_origin_ok(struct vhd_deaddrop *vhd, struct lws *wsi)
{
	return lws_http_origin_check(wsi, vhd->origin_allow,
				     vhd->require_origin ?
					LWS_HOC_REQUIRE_ORIGIN : 0);
}

static int
deaddrop_de_mtime_sort(lws_list_ptr a, lws_list_ptr b)
{
	struct dir_entry *p1 = lp_to_dir_entry(a, next),
			 *p2 = lp_to_dir_entry(b, next);

	return (int)(p2->mtime - p1->mtime);
}

/*
 * JSON-escape src into dst (which is clamped and always terminated).
 * Usernames and uploader names are attacker-influenced and must not be able
 * to close the string and forge members, nor emit invalid JSON that kills
 * JSON.parse() in every connected client's UI.
 */

static const char *
deaddrop_json_esc(char *dst, size_t dst_len, const char *src)
{
	int in_used = 0;

	return lws_json_purify(dst, src, (int)dst_len, &in_used);
}

/*
 * Worst-case emitted length of the listing header, one connected-user and one
 * file object below.  Every writeable has room for the header plus at least
 * one entry, so each one makes progress.
 */
#define DEADDROP_HEADER_MAX	(DEADDROP_USER_ESC_MAX + 256)
#define DEADDROP_USER_ENTRY_MAX	(DEADDROP_USER_ESC_MAX + 256)
#define DEADDROP_FILE_ENTRY_MAX	(DEADDROP_USER_ESC_MAX + 512 + 256)
#define DEADDROP_SEND_BUF	4096

#if DEADDROP_SEND_BUF < DEADDROP_HEADER_MAX + DEADDROP_FILE_ENTRY_MAX + 16
#error "deaddrop send buffer can't hold the header and one file entry"
#endif

static void
deaddrop_users_snapshot_free(struct pss_deaddrop *pss)
{
	lwsac_free(&pss->users_ac);
	lws_dll2_owner_clear(&pss->users);
	pss->users_cursor = NULL;
}

/*
 * Render the connected (authenticated) users for this pss's listing as it
 * stands now
 */

static void
deaddrop_users_snapshot(struct pss_deaddrop *pss)
{
	char esc_user[DEADDROP_USER_ESC_MAX], line[DEADDROP_USER_ENTRY_MAX];
	struct deaddrop_user_snap *us;
	int n;

	deaddrop_users_snapshot_free(pss);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&pss->vhd->pss_head)) {
		struct pss_deaddrop *pss1 = lws_container_of(d,
					struct pss_deaddrop, pss_list);

		/* Only list authenticated connections */
		if (!pss1->wsi || !pss1->user[0])
			continue;

		n = lws_snprintf(line, sizeof(line),
				 "{\"user\":\"%s\", \"ip\":\"%s\", "
				 "\"platform\":\"%s\", \"browser\":\"%s\"%s%s}",
				 deaddrop_json_esc(esc_user, sizeof(esc_user),
						   pss1->user),
				 pss1->ip, pss1->platform, pss1->browser,
				 pss1->has_star_grant ? ", \"is_admin\":1" : "",
				 (pss1 == pss) ? ", \"is_self\":1" : "");
		if (n >= (int)sizeof(line))
			/* can't happen, the fields are all bounded */
			continue;

		us = lwsac_use(&pss->users_ac, sizeof(*us) + (size_t)n + 1, 0);
		if (!us) {
			lwsl_wsi_warn(pss->wsi, "%s: OOM", __func__);
			break;
		}

		memset(&us->list, 0, sizeof(us->list));
		us->len = (size_t)n;
		memcpy(&us[1], line, (size_t)n + 1);
		lws_dll2_add_tail(&us->list, &pss->users);
	} lws_end_foreach_dll(d);

	pss->users_cursor = lws_dll2_get_head(&pss->users);
}

/*
 * Drop our reference on the file list lwsac; lwsac_unreference() only frees
 * it (and NULLs our pointer) when we were the last user of a detached one
 */

static void
deaddrop_release_filelist(struct pss_deaddrop *pss)
{
	if (pss->lwsac_head)
		lwsac_unreference(&pss->lwsac_head);
	pss->lwsac_head	= NULL;
	pss->dire	= NULL;
}

static void
deaddrop_start_sending_dir(struct pss_deaddrop *pss)
{
	deaddrop_release_filelist(pss);

	pss->sending_filelist_version = pss->vhd->filelist_version;
	pss->sending_userlist_version = pss->vhd->userlist_version;
	pss->send_users = pss->userlist_version !=
				pss->sending_userlist_version ||
			  !pss->sent_initial;
	pss->send_files = pss->filelist_version !=
				pss->sending_filelist_version ||
			  !pss->sent_initial;

	if (pss->send_files) {
		if (pss->vhd->lwsac_head)
			lwsac_reference(pss->vhd->lwsac_head);
		pss->lwsac_head = pss->vhd->lwsac_head;
		pss->dire = pss->vhd->dire_head;
	}

	if (pss->send_users)
		deaddrop_users_snapshot(pss);
	else
		deaddrop_users_snapshot_free(pss);

	pss->phase = DDSP_HEADER;
	pss->ws_ongoing_send = 1;
}

static void
deaddrop_broadcast_userlist_update(struct vhd_deaddrop *vhd)
{
	vhd->userlist_version++;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->pss_head)) {
		struct pss_deaddrop *pss = lws_container_of(d, struct pss_deaddrop,
						    pss_list);

		if (!pss->ws_ongoing_send)
			deaddrop_start_sending_dir(pss);
		lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_dll(d);
}

static void
deaddrop_broadcast_filelist_update(struct vhd_deaddrop *vhd)
{
	vhd->filelist_version++;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->pss_head)) {
		struct pss_deaddrop *pss = lws_container_of(d, struct pss_deaddrop,
						    pss_list);

		if (!pss->ws_ongoing_send)
			deaddrop_start_sending_dir(pss);
		lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_dll(d);
}


static int
deaddrop_scan_upload_dir(struct vhd_deaddrop *vhd)
{
	char filepath[512];
	const char *p_owner_end;
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

		/* the owner prefix can't contain '_', so ends at the first */
		p_owner_end = strchr(de->d_name, '_');
		dire->owner_len = p_owner_end ?
				(size_t)(p_owner_end - de->d_name) : 0;

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

/*
 * An upload that did not complete: close its file and remove the partial
 * temp file, so it leaves neither an fd nor a file behind
 */

static void
deaddrop_upload_abandon(struct pss_deaddrop *pss)
{
	if (pss->fd == LWS_INVALID_FILE)
		return;

	close((int)(lws_intptr_t)pss->fd);
	pss->fd = LWS_INVALID_FILE;
	if (pss->filename[0])
		unlink(pss->filename);
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
		/*
		 * One file at a time: a file still open here did not
		 * complete, and would otherwise be leaked by the open below
		 */
		deaddrop_upload_abandon(pss);

		/*
		 * We can be bound to the protocol by a POST that never
		 * matched our "/upload/" path (eg, straight to the
		 * mountpoint itself), in which case we have no vhd
		 */
		if (!pss->vhd) {
			pss->response_code = HTTP_STATUS_NOT_FOUND;

			return -1;
		}

		/* REQUIRE an authenticated user on the upload POST itself */
		if (!pss->user[0]) {
			pss->response_code = HTTP_STATUS_FORBIDDEN;
			lwsl_wsi_warn(pss->wsi, "%s: no authenticated user"
						" (pss %p)\n", __func__, pss);
			return -1;
		}

		/*
		 * lws_urldecode() only terminates its output after a clean
		 * run: on a malformed % escape it returns -1 having written
		 * no NUL.  Consuming filename2 then walks off the end of an
		 * uninitialized stack buffer, so refuse the upload instead.
		 */
		filename2[0] = '\0';
		if (lws_urldecode(filename2, filename, sizeof(filename2) - 1)) {
			pss->response_code = HTTP_STATUS_BAD_REQUEST;
			lwsl_wsi_warn(pss->wsi, "%s: bad urlencoded filename",
				      __func__);

			return -1;
		}
		/* it is one path component in the upload dir */
		lws_filename_purify_inplace(filename2);

		if (!filename2[0] || !pss->owner[0]) {
			pss->response_code = HTTP_STATUS_BAD_REQUEST;

			return -1;
		}

		/*
		 * Server is authoritative: construct filename from the
		 * authenticated user's owner prefix and the base filename
		 * from the request.  The owner prefix contains no '_', so
		 * whatever the request's filename is, it can only ever
		 * name a file of this user.
		 */
		if (lws_snprintf(pss->filename, sizeof(pss->filename),
				 "%s/%s_%s~", pss->vhd->upload_dir,
				 pss->owner, filename2) >=
						(int)sizeof(pss->filename)) {
			pss->filename[0] = '\0';
			pss->response_code = HTTP_STATUS_BAD_REQUEST;
			lwsl_wsi_warn(pss->wsi, "%s: filename too long",
				      __func__);

			return -1;
		}
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
				deaddrop_upload_abandon(pss);

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

		if (pss->fd == LWS_INVALID_FILE)
			/* no file in progress to complete */
			break;

		close((int)(lws_intptr_t)pss->fd);

		/* the temp filename without the ~ */
		{
			char final_name[sizeof(pss->filename)];

			lws_strncpy(final_name, pss->filename,
				    sizeof(final_name));
			final_name[strlen(final_name) - 1] = '\0';
			if (rename(pss->filename, final_name) < 0)
				lwsl_err("%s: unable to rename\n", __func__);
		}

		pss->fd = LWS_INVALID_FILE;
		pss->response_code = HTTP_STATUS_OK;
		deaddrop_scan_upload_dir(pss->vhd);

		break;
	case LWS_UFS_CLOSE:
		/*
		 * The spa delivers this even when the client vanished
		 * mid-body: in that case LWS_UFS_FINAL_CONTENT never came, so
		 * the fd is still open and the partial temp file is still on
		 * disk.  Without cleaning both up here, every aborted upload
		 * leaks an fd and a file for the life of the process.
		 */
		deaddrop_upload_abandon(pss);
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
	/*
	 * This is the same pvo lws itself consults to apply basic auth to the
	 * ws upgrade; we only note whether it exists, so we know if the
	 * Authorization header we see was validated and rewritten by lws
	 */
	if (!lws_pvo_get_str(in, "basic-auth", &cp))
		vhd->basic_auth = 1;
	if (!lws_pvo_get_str(in, "allow-anonymous", &cp) &&
	    strcmp(cp, "off") && strcmp(cp, "0"))
		vhd->allow_anon = 1;
	if (!lws_pvo_get_str(in, "require-origin", &cp) &&
	    strcmp(cp, "off") && strcmp(cp, "0"))
		vhd->require_origin = 1;
	if (lws_pvo_get_str(in, "origin-allow", &vhd->origin_allow))
		vhd->origin_allow = NULL;
	if (!lws_pvo_get_str(in, "jwt-jwk", &cp)) {
		if (cp[0] == '{' || lws_jwk_load(&vhd->jwk, cp, NULL, NULL)) {
			if (lws_jwk_import(&vhd->jwk, NULL, NULL, cp, strlen(cp))) {
				lwsl_err("%s: failed to load/import JWK\n", __func__);
				return -1;
			}
		}
		vhd->has_jwk = 1;
	}
	if (lws_pvo_get_str(in, "upload-dir", &cp)) {
		lwsl_vhost_warn(lws_get_vhost(wsi), "%s: requires 'upload-dir' pvo\n", __func__);
		return 0;
	}

	/*
	 * Names are checked to be inside the upload dir by comparing their
	 * realpath() against it, so it must be in the same canonical form, or
	 * a relative dir, one with a trailing '/', or one reached through a
	 * symlink would never match anything
	 */
#if !defined(WIN32) && !defined(_WIN32) && !defined(LWS_WITH_ESP32)
	if (!realpath(cp, vhd->upload_dir)) {
		vhd->upload_dir[0] = '\0';
		lwsl_vhost_err(lws_get_vhost(wsi), "%s: upload-dir '%s' unusable "
			       "(errno %d)", __func__, cp, errno);
		return 0;
	}
#else
	lws_strncpy(vhd->upload_dir, cp, sizeof(vhd->upload_dir));
#endif

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

/*
 * Turn a stored file name from a peer into its path in the upload dir, into
 * path (which must be PATH_MAX).  The name must be a single path component,
 * and the file it names must really be inside the upload dir.  Returns 0 if
 * path is usable.
 */

static int
deaddrop_resolve_name(struct vhd_deaddrop *vhd, struct lws *wsi,
		      const char *fname, char *path, size_t path_len)
{
#if !defined(WIN32) && !defined(_WIN32) && !defined(LWS_WITH_ESP32)
	char resolved_path[PATH_MAX];
	size_t ul;
#endif

	if (!fname[0] || strchr(fname, '/') || !strcmp(fname, ".") ||
	    !strcmp(fname, ".."))
		return 1;

	if (lws_snprintf(path, path_len, "%s/%s", vhd->upload_dir,
			 fname) >= (int)path_len)
		return 1;

#if !defined(WIN32) && !defined(_WIN32) && !defined(LWS_WITH_ESP32)
	if (!realpath(path, resolved_path))
		return 1;

	/*
	 * Both are canonical, so inside means the upload dir followed by a
	 * '/' (once canonical, the dir itself only ends in one if it is "/")
	 */
	ul = strlen(vhd->upload_dir);
	if (ul && vhd->upload_dir[ul - 1] == '/')
		ul--;
	if (strncmp(resolved_path, vhd->upload_dir, ul) ||
	    resolved_path[ul] != '/') {
		lwsl_wsi_err(wsi, "illegal path '%s' -> '%s'", path,
			     resolved_path);
		return 1;
	}
	lws_strncpy(path, resolved_path, path_len);
#endif

	return 0;
}

/*
 * RFC 8187 attr-char, the characters a filename*= value may carry as they are
 */

static int
deaddrop_attr_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || strchr("!#$&+-.^_`|~", c);
}

/*
 * Content-Disposition for a download: the name without its owner prefix, as a
 * plain ASCII filename= with anything risky in a quoted-string replaced, and
 * exactly as a percent-encoded UTF-8 filename*=
 */

static int
deaddrop_content_disposition(char *buf, size_t len, const char *fname)
{
	const char *cp = strchr(fname, '_'), *q;
	size_t o;

	if (cp && cp != fname && cp[1])
		fname = cp + 1;

	o = (size_t)lws_snprintf(buf, len, "attachment; filename=\"");
	for (q = fname; *q && o + 2 < len; q++)
		buf[o++] = (*q >= 0x20 && *q < 0x7f && *q != '\"' &&
			    *q != '\\') ? *q : '_';
	if (o + 20 >= len)
		return 1;
	o += (size_t)lws_snprintf(buf + o, len - o, "\"; filename*=UTF-8''");

	for (q = fname; *q; q++) {
		if (o + 4 >= len)
			return 1;
		if (deaddrop_attr_char(*q)) {
			buf[o++] = *q;
			continue;
		}
		buf[o++] = '%';
		lws_hex_from_byte_array((const uint8_t *)q, 1, buf + o, 3);
		o += 2;
	}
	buf[o] = '\0';

	return 0;
}

/*
 * deaddrop only ever hands files back to be saved, never to be rendered: it
 * moves text where there is no clipboard, and binary files.  So whatever the
 * uploader named it, a download goes out as an octet-stream attachment that
 * may not be sniffed, and that a browser would sandbox with nothing allowed
 * if it rendered it anyway.  Otherwise a shared .html / .svg / .js would run
 * as active content on our origin, as whoever opened the link.
 *
 * Returns 0 if the transaction continues, -1 to close.
 */

static int
deaddrop_serve_download(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			struct lws *wsi, const char *in, size_t len)
{
	uint8_t hdrs[1536], *p = hdrs, *end = &hdrs[sizeof(hdrs) - 1];
	char fname[256], path[PATH_MAX], cd[1024];
	int status = HTTP_STATUS_NOT_FOUND, n;
	struct stat s;

	if (!pss->user[0] && !vhd->allow_anon) {
		status = HTTP_STATUS_FORBIDDEN;
		goto refuse;
	}

	/* we get "/<stored name>", the part of the url after the mountpoint */
	if (!in || len < 2 || len > sizeof(fname) || *in != '/' ||
	    memchr(in, '\0', len))
		goto refuse;
	memcpy(fname, in + 1, len - 1);
	fname[len - 1] = '\0';

	/* temp files are uploads still in progress */
	if (fname[strlen(fname) - 1] == '~' ||
	    deaddrop_resolve_name(vhd, wsi, fname, path, sizeof(path)) ||
	    stat(path, &s) || !S_ISREG(s.st_mode))
		goto refuse;

	if (deaddrop_content_disposition(cd, sizeof(cd), fname) ||
	    lws_add_http_header_by_name(wsi,
			(const unsigned char *)"content-disposition:",
			(const unsigned char *)cd, (int)strlen(cd), &p, end) ||
	    lws_add_http_header_by_name(wsi,
			(const unsigned char *)"x-content-type-options:",
			(const unsigned char *)"nosniff", 7, &p, end) ||
	    lws_add_http_header_by_name(wsi,
			(const unsigned char *)"content-security-policy:",
			(const unsigned char *)"sandbox; default-src 'none'",
			27, &p, end)) {
		status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto refuse;
	}
	*p = '\0';

	n = lws_serve_http_file(wsi, path, "application/octet-stream",
				(const char *)hdrs, lws_ptr_diff(p, hdrs));
	if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi)))
		return -1;

	return 0;

refuse:
	lwsl_wsi_info(wsi, "refusing download (%d)", status);
	if (lws_return_http_status(wsi, (unsigned int)status, NULL) ||
	    lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static int
deaddrop_handler_server_http(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			     struct lws *wsi, const char *in, size_t len)
{
	char *uri_ptr;
	int uri_len;
	int meth;

	memset(pss, 0, sizeof(*pss));
	/* 0 is a perfectly good fd number, so this cannot be left memset */
	pss->fd = LWS_INVALID_FILE;
	pss->wsi = wsi;

	deaddrop_get_auth_identity(vhd, pss, wsi);
	if (!pss->user[0])
		lwsl_wsi_warn(wsi, "%s: HTTP POST: no auth\n", __func__);

	meth = lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len);
	if (meth == LWSHUMETH_GET || meth == LWSHUMETH_HEAD)
		return deaddrop_serve_download(vhd, pss, wsi, in, len) ? -1 : 2;
	if (meth != LWSHUMETH_POST || !uri_ptr)
		return 1;
	if (!(char *)strstr(uri_ptr, "/upload/"))
		return 1;

	/*
	 * A cross-origin multipart POST is a CORS "simple request", ie, it is
	 * sent with the victim's cookie and no preflight.  Refuse it here,
	 * before any of the body is parsed or any file is created.
	 */
	if (deaddrop_origin_ok(vhd, wsi)) {
		lwsl_wsi_notice(wsi, "%s: refusing upload, bad Origin",
				__func__);
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		return -1;
	}

	pss->vhd = vhd;

	return 0;
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
		pss->fd = LWS_INVALID_FILE;
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

	pss->platform[0]	= '\0';
	pss->browser[0]		= '\0';

	deaddrop_get_auth_identity(vhd, pss, wsi);

	/*
	 * The ws upgrade never passes through mounts or the lws-login
	 * bouncer: this callback is the only place the upgrade can be
	 * refused.  Anonymous sessions otherwise receive the whole file
	 * listing and every logged-in user's IP, so unless the vhost
	 * explicitly asked for that, they end here.
	 */
	if (!pss->user[0] && !vhd->allow_anon) {
		lwsl_wsi_notice(wsi, "%s: refusing unauthenticated ws",
				__func__);

		return 1;
	}

	/*
	 * The upgrade is authenticated by the ambient session cookie and the
	 * ws handshake is exempt from the same-origin policy, so without this
	 * any page the victim visits can open this socket as the victim.
	 */
	if (deaddrop_origin_ok(vhd, wsi)) {
		lwsl_wsi_notice(wsi, "%s: refusing ws, bad Origin", __func__);

		return 1;
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
	lws_dll2_add_head(&pss->pss_list, &vhd->pss_head);

	deaddrop_broadcast_userlist_update(vhd);
}

static void
deaddrop_handler_server_ws_closed(struct vhd_deaddrop *vhd,
				  struct pss_deaddrop *pss, struct lws *wsi)
{
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	char desc[LWS_PEER_DESC_LEN];

	/* every layer of who he was, where there is more than his address */
	lwsl_notice("%s: WS connection closed (user: '%s', ip: %s)\n",
		    __func__, pss->user, lws_peer_describe(wsi, desc,
				sizeof(desc), LWS_PEER_DESC_BARE_SINGLE));
#else
	(void)wsi;
#endif

	deaddrop_release_filelist(pss);
	deaddrop_users_snapshot_free(pss);
	/* remove our closing pss from the list of live pss */
	lws_dll2_remove(&pss->pss_list);

	deaddrop_broadcast_userlist_update(vhd);
}

/*
 * The ws protocol from the client has one message, {"del":"<name>"}, composed
 * by JSON.stringify(), so the name may arrive escaped
 */

static const char * const deaddrop_rx_paths[] = {
	"del",
};

struct deaddrop_rx_del {
	char		name[256];
	size_t		len;
	uint8_t		seen:1;
	uint8_t		bad:1;
};

static signed char
deaddrop_rx_cb(struct lejp_ctx *ctx, char reason)
{
	struct deaddrop_rx_del *r = (struct deaddrop_rx_del *)ctx->user;

	if (!ctx->path_match)
		return 0;

	switch (reason) {
	case LEJPCB_VAL_STR_START:
		r->len	= 0;
		r->seen	= 0;
		r->bad	= 0;
		break;
	case LEJPCB_VAL_STR_CHUNK:
	case LEJPCB_VAL_STR_END:
		if (r->len + ctx->npos >= sizeof(r->name) ||
		    memchr(ctx->buf, '\0', ctx->npos)) {
			r->bad = 1;
			break;
		}
		memcpy(r->name + r->len, ctx->buf, ctx->npos);
		r->len += ctx->npos;
		r->name[r->len] = '\0';
		if (reason == LEJPCB_VAL_STR_END)
			r->seen = 1;
		break;
	default:
		break;
	}

	return 0;
}

static void
deaddrop_del(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
	     struct lws *wsi, const char *fname)
{
	char path[PATH_MAX];
	const char *cp;
	size_t n;

	/* it must have an owner prefix */
	cp = strchr(fname, '_');
	if (!cp || cp == fname) {
		lwsl_wsi_notice(wsi, "del: refusing bad name");
		return;
	}

	/*
	 * The owner prefix ends at the first '_', since an encoded owner never
	 * contains one.  Only that exact owner (or an admin) may delete it.
	 */
	n = (size_t)(cp - fname);
	if (!pss->has_star_grant && (strlen(pss->owner) != n ||
	    strncmp(pss->owner, fname, n))) {
		lwsl_wsi_notice(wsi, "del: auth mismatch, user '%s' tried to "
				"delete a file of owner '%.*s'", pss->user,
				(int)n, fname);
		return;
	}

	if (deaddrop_resolve_name(vhd, wsi, fname, path, sizeof(path))) {
		lwsl_wsi_notice(wsi, "del: refusing bad name");
		return;
	}

	lwsl_wsi_notice(wsi, "deleting '%s'", path);

	if (unlink(path) < 0)
		lwsl_err("%s: unlink %s failed: %s\n", __func__,
				path, strerror(errno));

	deaddrop_scan_upload_dir(vhd);
}

static void
deaddrop_handler_server_ws_rx(struct vhd_deaddrop *vhd, struct pss_deaddrop *pss,
			      struct lws *wsi, void *in, size_t len)
{
	struct deaddrop_rx_del r;
	struct lejp_ctx ctx;
	int m;

	/*
	 * An anonymous session owns nothing, so it has nothing it may ask us
	 * to do: ignore everything it sends
	 */
	if (!pss || !pss->user[0] || !pss->owner[0])
		return;

	/* collect the whole message, which may arrive in pieces */

	if (lws_is_first_fragment(wsi)) {
		pss->rx_len		= 0;
		pss->rx_overflow	= 0;
	}

	if (len > sizeof(pss->rx) - pss->rx_len)
		pss->rx_overflow = 1;
	else if (!pss->rx_overflow) {
		memcpy(pss->rx + pss->rx_len, in, len);
		pss->rx_len += len;
	}

	if (!lws_is_final_fragment(wsi))
		return;

	if (pss->rx_overflow) {
		lwsl_wsi_notice(wsi, "ignoring oversize message");
		return;
	}

	memset(&r, 0, sizeof(r));
	lejp_construct(&ctx, deaddrop_rx_cb, &r, deaddrop_rx_paths,
		       LWS_ARRAY_SIZE(deaddrop_rx_paths));
	m = lejp_parse(&ctx, (const uint8_t *)pss->rx, (int)pss->rx_len);
	lejp_destruct(&ctx);

	pss->rx_len = 0;

	if (m < 0 || !r.seen || r.bad) {
		lwsl_wsi_notice(wsi, "ignoring malformed message");
		return;
	}

	deaddrop_del(vhd, pss, wsi, r.name);
}

/*
 * Append one listing file entry at p, returning the new p, or NULL if this
 * entry should be skipped
 */

static uint8_t *
deaddrop_render_file(struct pss_deaddrop *pss, uint8_t *p, uint8_t *end,
		     const struct dir_entry *dire)
{
	char esc_fname[512], esc_up[DEADDROP_USER_ESC_MAX],
	     up[DEADDROP_USER_MAX];
	const char *fname = (const char *)&dire[1], *p_fn = fname;
	int is_yours, is_text = 0, in_used = 0, n;

	is_yours = pss->user[0] &&
		   (pss->has_star_grant ||
		    (dire->owner_len &&
		     dire->owner_len == strlen(pss->owner) &&
		     !strncmp(fname, pss->owner, dire->owner_len)));

	up[0] = '\0';
	if (dire->owner_len) {
		deaddrop_owner_decode(up, sizeof(up), fname, dire->owner_len);
		p_fn += dire->owner_len + 1;
	}

	/* check for YYYY-MM-DD_HH-MM-SS.txt format */
	if (strlen(p_fn) == 23 &&
	    p_fn[4] == '-' && p_fn[7] == '-' &&
	    p_fn[10] == '_' && p_fn[13] == '-' &&
	    p_fn[16] == '-' && !strcmp(p_fn + 19, ".txt"))
		is_text = 1;

	/* a name we can't send intact can be neither fetched nor deleted */
	lws_json_purify(esc_fname, fname, sizeof(esc_fname), &in_used);
	if ((size_t)in_used != strlen(fname))
		return NULL;

	n = lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
			 "%c{\"name\":\"%s\", "
			 "\"uploader\":\"%s\","
			 "\"size\":%llu,"
			 "\"mtime\":%llu,"
			 "\"yours\":%d,"
			 "\"is_text\":%d}",
			 pss->item_first ? ' ' : ',',
			 esc_fname,
			 deaddrop_json_esc(esc_up, sizeof(esc_up), up),
			 dire->size, (unsigned long long)dire->mtime,
			 is_yours, is_text);
	if (n >= (int)lws_ptr_diff_size_t(end, p))
		/* can't happen, the caller ensured room for the worst case */
		return NULL;

	return p + n;
}

/*
 * Stream the listing message out, a buffer per writeable.  Each writeable
 * either completes the message or sends at least one more entry of it, and
 * the message is one ws message: the first buffer starts it, the rest
 * continue it, and the last one is FIN.
 */

static int
deaddrop_handler_server_ws_writeable(struct vhd_deaddrop *vhd,
				     struct pss_deaddrop *pss, struct lws *wsi)
{
	uint8_t buf[LWS_PRE + DEADDROP_SEND_BUF], *start = &buf[LWS_PRE],
		*p = start, *end = &buf[sizeof(buf) - 1], *np;
	char esc_user[DEADDROP_USER_ESC_MAX], esc_cookie[64];
	struct deaddrop_user_snap *us;
	int som, n;

	/* if nothing to write, write nothing */
	if (!pss->ws_ongoing_send)
		return 0;

	som = pss->phase == DDSP_HEADER;

	while (pss->phase != DDSP_DONE) {
		switch (pss->phase) {
		case DDSP_HEADER:
			p += lws_snprintf((char *)p,
				lws_ptr_diff_size_t(end, p),
				"{\"max_size\":%llu, \"user\":\"%s\", "
				"\"cookie\":\"%s\"",
				vhd->max_size,
				deaddrop_json_esc(esc_user, sizeof(esc_user),
						  pss->user),
				deaddrop_json_esc(esc_cookie,
						  sizeof(esc_cookie),
						  vhd->cookie_name));
			if (pss->send_users) {
				p += lws_snprintf((char *)p,
					lws_ptr_diff_size_t(end, p),
					", \"connected_users\":[");
				pss->item_first	= 1;
				pss->phase	= DDSP_USERS;
			} else
				pss->phase	= DDSP_FILES_OPEN;
			break;

		case DDSP_USERS:
			if (!pss->users_cursor) {
				if (lws_ptr_diff_size_t(end, p) < 2)
					goto send;
				*p++ = ']';
				pss->phase = DDSP_FILES_OPEN;
				break;
			}
			us = lws_container_of(pss->users_cursor,
					      struct deaddrop_user_snap, list);
			if (lws_ptr_diff_size_t(end, p) < us->len + 2)
				goto send;
			*p++ = pss->item_first ? ' ' : ',';
			memcpy(p, &us[1], us->len);
			p += us->len;
			pss->item_first		= 0;
			pss->users_cursor	= pss->users_cursor->next;
			break;

		case DDSP_FILES_OPEN:
			if (lws_ptr_diff_size_t(end, p) < 16)
				goto send;
			if (pss->send_files) {
				p += lws_snprintf((char *)p,
					lws_ptr_diff_size_t(end, p),
					", \"files\": [");
				pss->item_first	= 1;
				pss->phase	= DDSP_FILES;
			} else {
				*p++		= '}';
				pss->phase	= DDSP_DONE;
			}
			break;

		case DDSP_FILES:
			if (!pss->dire) {
				if (lws_ptr_diff_size_t(end, p) < 3)
					goto send;
				*p++		= ']';
				*p++		= '}';
				pss->phase	= DDSP_DONE;
				break;
			}
			/*
			 * Stop before the entry could be truncated: pss->dire
			 * is our resume cursor, so the rest goes out in the
			 * next writeable
			 */
			if (lws_ptr_diff_size_t(end, p) <
						DEADDROP_FILE_ENTRY_MAX)
				goto send;
			np = deaddrop_render_file(pss, p, end, pss->dire);
			if (np) {
				p = np;
				pss->item_first = 0;
			}
			pss->dire = lp_to_dir_entry(pss->dire->next, next);
			break;

		default:
			pss->phase = DDSP_DONE;
			break;
		}
	}

send:
	if (pss->phase == DDSP_DONE) {
		deaddrop_release_filelist(pss);
		deaddrop_users_snapshot_free(pss);
		pss->ws_ongoing_send	= 0;
		pss->sent_initial	= 1;
		pss->userlist_version	= pss->sending_userlist_version;
		pss->filelist_version	= pss->sending_filelist_version;
	}

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
		      lws_write_ws_flags(LWS_WRITE_TEXT, som,
					 pss->phase == DDSP_DONE));
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

	/*
	 * lws offers every loaded plugin protocol on every vhost, but only
	 * calls PROTOCOL_INIT for a vhost that has a pvo for it.  On any other
	 * vhost of the same process, vhd stays NULL forever, and a peer can
	 * still bind us with "Sec-WebSocket-Protocol: lws-deaddrop" or by a
	 * callback mount.  Refuse those cleanly rather than deref NULL, and
	 * likewise on a vhost whose upload dir could not be used.
	 */

	switch (reason) {
	case LWS_CALLBACK_HTTP:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_RAW_RX_FILE:
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
	case LWS_CALLBACK_ESTABLISHED:
	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_RECEIVE:
	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd || !vhd->upload_dir[0])
			return -1;
		break;
	default:
		break;
	}

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;

		if (!in)
			return 0;

		deaddrop_handler_server_protocol_init(wsi, in);
		break;

	case LWS_CALLBACK_HTTP:
		switch (deaddrop_handler_server_http(vhd, pss, wsi,
						     (const char *)in, len)) {
		case 0:
		case 2:		 /* download dealt with */
			return 0;
		case -1:	 /* refused, status already sent */
			return -1;
		default:	 /* not a POST for us, let the dummy handle it */
			break;
		}
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
		deaddrop_handler_server_ws_closed(vhd, pss, wsi);
		return 0;

	case LWS_CALLBACK_RECEIVE:
		deaddrop_handler_server_ws_rx(vhd, pss, wsi, in, len);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (deaddrop_handler_server_ws_writeable(vhd, pss, wsi))
			return -1;
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
