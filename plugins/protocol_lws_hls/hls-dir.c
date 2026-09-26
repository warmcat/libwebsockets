#include "private-lws-hls.h"
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>

struct file_entry {
	char name[256];
	time_t mtime;
	enum hls_media_state state;	/* anything but GONE */
};

/*
 * How often the listing is rewalked for changes while any page showing it
 * is subscribed to them (hls_watch_sul()), and how long a subscriber may go
 * without hearing from us before it gets a keepalive, which is also what
 * finds out it has gone
 */
#define HLS_WATCH_US		(3 * LWS_US_PER_SEC)
#define HLS_WATCH_KEEPALIVE_US	(30 * LWS_US_PER_SEC)

/* escaped form of the longest possible name (255 chars, each expanding to
 * the 5-char entity "&#39;") plus the NUL */
#define HLS_DIR_ESC_MAX (255 * 5 + 1)

/* fixed markup budget per listing entry, exclusive of the escaped name
 * (which is interpolated four times) and the mtime digits; the actual
 * per-entry markup is ~180 bytes */
#define HLS_DIR_ENTRY_FIXED 256

/*
 * Maximum directory nesting we will walk below media_dir.  lws_dir() reports
 * a symlink as LDOT_DIR wherever the platform has no d_type and _fill_lde()
 * falls back to stat() (which follows the link), so a symlink to '.' or to
 * an ancestor would otherwise recurse until the stack is exhausted - each
 * level costs the 1KB path[] here plus lws_dir()'s own frame.  Compare
 * lws_dir_rm_rf_cb() in lib/misc/dir.c, which guards the same case.
 */
#define HLS_DIR_MAX_DEPTH 8

struct dir_state {
	struct file_entry *entries;
	size_t count;
	size_t max;
	const char *base_dir;
	int depth;
	/*
	 * The listing's generation: a token of what it holds, pushed to the
	 * pages showing it so they can tell when it changed (see
	 * lws_hls_watch_add()).  With gen_only, the walk only computes this.
	 */
	uint64_t gen;
	int gen_only;
};

/*
 * One listed file's part of the listing generation: everything the listing
 * shows of it that can change, from stat alone.  Its name, and whether it
 * is still arriving, which also changes with time alone; for a settled
 * file, its size and date, which decide whether it stopped short and date
 * its link.  Not the size or date of a file still being written, which
 * change all the time and show as nothing but "still arriving".  The parts
 * are summed, so the walk order does not matter.
 */
static uint64_t
hls_dir_gen_part(const char *name, const struct stat *st)
{
	uint64_t h = 0xcbf29ce484222325ull, v[3];
	const uint8_t *p = (const uint8_t *)name;
	size_t n;

	while (*p) {
		h ^= *p++;
		h *= 0x100000001b3ull;
	}

	memset(v, 0, sizeof(v));
	v[0] = (uint64_t)lws_hls_media_settling(st);
	if (!v[0]) {
		v[1] = (uint64_t)st->st_size;
		v[2] = (uint64_t)st->st_mtime;
	}
	p = (const uint8_t *)v;
	for (n = 0; n < sizeof(v); n++) {
		h ^= p[n];
		h *= 0x100000001b3ull;
	}

	return h;
}

static int
hls_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct dir_state *ds = (struct dir_state *)user;
	const char *rel_path;
	enum hls_media_state ms;
	size_t base_len;
	struct stat st;
	char path[1024];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (lde->type == LDOT_DIR) {
		/* .index holds our keyframe indexes, not media */
		if (lde->name[0] == '.')
			return 0;
		if (ds->depth >= HLS_DIR_MAX_DEPTH) {
			lwsl_notice("%s: depth limit at %s\n", __func__, path);
			return 0;
		}
		ds->depth++;
		lws_dir(path, ds, hls_dir_cb);
		ds->depth--;
		return 0;
	}

	if (lde->type != LDOT_FILE)
		return 0;

	/* only list media files */
	if (!lws_hls_is_media_name(lde->name))
		return 0;

	rel_path = path;
	base_len = strlen(ds->base_dir);
	if (!strncmp(path, ds->base_dir, base_len) && path[base_len] == '/')
		rel_path = path + base_len + 1;

	if (ds->gen_only) {
		/* the same files the listing would show, from stat alone */
		if (!stat(path, &st) && S_ISREG(st.st_mode))
			ds->gen += hls_dir_gen_part(rel_path, &st);
		return 0;
	}

	if (ds->count >= ds->max) {
		struct file_entry *ne;

		ds->max += 64;
		ne = realloc(ds->entries, ds->max * sizeof(struct file_entry));
		if (!ne)
			return 1;
		ds->entries = ne;
	}

	/* is it all there, or still being copied in? */
	ms = lws_hls_media_state(ds->base_dir, rel_path, &st);
	if (ms == HLS_MEDIA_GONE)
		return 0;

	ds->gen += hls_dir_gen_part(rel_path, &st);

	lws_strncpy(ds->entries[ds->count].name, rel_path,
		    sizeof(ds->entries[ds->count].name));
	ds->entries[ds->count].mtime = st.st_mtime;
	ds->entries[ds->count].state = ms;
	ds->count++;

	return 0;
}

static int
cmp_mtime(const void *a, const void *b)
{
	const struct file_entry *fa = (const struct file_entry *)a;
	const struct file_entry *fb = (const struct file_entry *)b;
	if (fb->mtime > fa->mtime) return 1;
	if (fb->mtime < fa->mtime) return -1;
	return 0;
}

/* state for the purge walk: has playable media been seen below here? */
struct hls_purge_state {
	int has_media;
	int depth;
};

/*
 * Purge probe: does this subtree still hold anything the user could play?
 * The playable test is the listing's (hls_dir_cb), lws_hls_is_media_name().
 * Dot-dirs are our caches or hidden state: not playable, and the toplevel
 * ones are not ours to purge.
 *
 * A file of any name that is still being written counts as well: media is
 * often copied in under a temporary name (rsync's .Film.mkv.Xq3v9A, a
 * downloader's .part) and renamed when it is complete, and the directory
 * it is arriving in must not be removed from under the copy.
 */
static int
hls_purge_probe_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct hls_purge_state *ps = (struct hls_purge_state *)user;
	char path[1024];
	struct stat st;

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (lde->type == LDOT_DIR) {
		if (lde->name[0] == '.')
			return 0;
		/* the depth cap also bounds symlink loops, as in hls_dir_cb */
		if (ps->depth >= HLS_DIR_MAX_DEPTH)
			return 0;
		ps->depth++;
		lws_dir(path, ps, hls_purge_probe_cb);
		ps->depth--;

		return ps->has_media; /* stop the parents' walks too */
	}

	if (lws_hls_is_media_name(lde->name) ||
	    (!stat(path, &st) && lws_hls_media_settling(&st))) {
		ps->has_media = 1;
		return 1;
	}

	return 0;
}

/* path is a toplevel subdirectory of media-dir: remove it if it is dead */
static void
hls_purge_one(struct per_vhost_data__lws_hls *vhd, const char *path)
{
	struct hls_purge_state st;

	memset(&st, 0, sizeof(st));
	lws_dir(path, &st, hls_purge_probe_cb);
	if (st.has_media)
		return;

	lwsl_notice("HLS-DIR: %s: nothing playable left in %s, removing it\n",
		    vhd->media_dir, path);

	lws_dir(path, NULL, lws_dir_rm_rf_cb);
	if (rmdir(path))
		lwsl_warn("%s: rmdir %s failed %d\n", __func__, path, errno);
}

/* the toplevel walk: only whole subdirectories are purge candidates */
static int
hls_purge_top_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct per_vhost_data__lws_hls *vhd =
			(struct per_vhost_data__lws_hls *)user;
	char path[1024];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	/* toplevel files, and the .index / .atrans cache dirs, stay */
	if (lde->type != LDOT_DIR || lde->name[0] == '.')
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	hls_purge_one(vhd, path);

	return 0;
}

void
lws_hls_purge_subdir(struct per_vhost_data__lws_hls *vhd, const char *top,
		     size_t len)
{
	char path[1024];
	struct stat st;

	/* the same candidates as the toplevel walk: a real directory (never
	 * a link out of media-dir), not one of our dot-dirs */
	if (!len || top[0] == '.' || !hls_media_name_valid(top, len) ||
	    memchr(top, '/', len))
		return;

	lws_snprintf(path, sizeof(path), "%s/%.*s", vhd->media_dir, (int)len,
		     top);
	if (lstat(path, &st) || !S_ISDIR(st.st_mode))
		return;

	hls_purge_one(vhd, path);
}

void
lws_hls_purge_empty_dirs(struct per_vhost_data__lws_hls *vhd)
{
	/* nothing there yet is the usual case */
	if (access(vhd->media_dir, F_OK))
		return;

	lws_dir(vhd->media_dir, vhd, hls_purge_top_cb);
}

/*
 * HTML-escape a media filename before it reaches any markup context
 * (element text, and the single-quoted href / src / data-file
 * attributes): & < > " ' become entities, the F-021 render-boundary
 * escape set.  Filenames come off the filesystem unvalidated (F-059:
 * stored XSS otherwise).  Writes at most cap - 1 bytes plus the NUL;
 * returns the escaped length the input requires (excluding NUL), so a
 * buffer can be sized exactly with a first cap = 0 pass.
 */
static size_t
hls_dir_esc(char *o, size_t cap, const char *in)
{
	size_t n = 0;

	while (*in) {
		const char *e = NULL;
		size_t l = 1;

		switch (*in) {
		case '&':	e = "&amp;";  break;
		case '<':	e = "&lt;";   break;
		case '>':	e = "&gt;";   break;
		case '"':	e = "&quot;"; break;
		case '\'':	e = "&#39;";  break;
		}
		if (e)
			l = strlen(e);

		if (n + 1 < cap) {
			size_t copy = l;

			if (n + copy > cap - 1)
				copy = cap - 1 - n;
			if (e)
				memcpy(o + n, e, copy);
			else
				o[n] = *in;
		}
		n += l;
		in++;
	}

	if (cap)
		o[n < cap ? n : cap - 1] = '\0';

	return n;
}

/*
 * Is this already-separated token part of the release furniture rather
 * than the title?  Release names put the year, the resolution and the
 * codec / source tags after the title, so the first of these ends it:
 *
 *   Word.word.word.2026.1080p.word.word.2.0.H.264-grp  ->  "Word word word"
 *
 * The caller never asks about the first token: a title can itself be
 * "1917", "300" or start with "2001".
 */
static int
hls_dir_junk_token(const char *tok, size_t tl)
{
	static const char * const junk[] = {
		"web", "webrip", "web-dl", "bluray", "blu-ray", "brrip",
		"bdrip", "dvdrip", "hdrip", "hdtv", "x264", "x265", "h264",
		"h265", "hevc", "xvid", "divx", "avc", "aac", "ac3", "eac3",
		"dts", "dts-hd", "truehd", "10bit", "8bit", "hdr", "sdr",
		"multi", "remux", "repack", "proper", NULL
	};
	char lc[16];
	size_t i;
	int j;

	if (!tl || tl >= sizeof(lc))
		return 0;
	for (i = 0; i < tl; i++)
		lc[i] = (char)tolower((unsigned char)tok[i]);
	lc[tl] = '\0';

	/* a year: 19xx / 20xx */
	if (tl == 4 && ((lc[0] == '1' && lc[1] == '9') ||
			(lc[0] == '2' && lc[1] == '0')) &&
	    lc[2] >= '0' && lc[2] <= '9' && lc[3] >= '0' && lc[3] <= '9')
		return 1;

	/* a resolution: 480..2160, with an optional p / i */
	if (tl >= 3 && tl <= 5) {
		size_t dl = (lc[tl - 1] == 'p' || lc[tl - 1] == 'i') ?
								tl - 1 : tl;

		if (dl == 3 || dl == 4) {
			int dig = 1;

			for (i = 0; i < dl; i++)
				if (lc[i] < '0' || lc[i] > '9')
					dig = 0;
			if (dig)
				return 1;
		}
	}

	for (j = 0; junk[j]; j++)
		if (!strcmp(lc, junk[j]))
			return 1;

	return 0;
}

/*
 * Friendly display name for a media file: the movie title rather than the
 * release filename.  From the basename, drop the extension, snip [..] and
 * (..) groups, turn '.' separators between words into spaces, collapse
 * runs and trim, and stop at the first release-furniture token that
 * follows the title (see hls_dir_junk_token()).  It only ever drops
 * characters or replaces them one-for-one, so the result cannot be longer
 * than the input basename; if nothing at all survives, the caller wants
 * the filename shown as it is.
 */
static void
hls_dir_friendly(char *o, size_t cap, const char *in)
{
	char tmp[sizeof(((struct file_entry *)0)->name)];
	const char *base = strrchr(in, '/');
	size_t n = 0;
	int ingroup = 0, sp = 0;
	char *p;

	base = base ? base + 1 : in;
	lws_strncpy(tmp, base, sizeof(tmp));

	/* the extension is not part of the title */
	{
		char *ext = strrchr(tmp, '.');

		if (ext > tmp)
			*ext = '\0';
	}

	/* pass 1: strip bracket groups, '.' becomes ' ' */
	for (p = tmp; *p; p++) {
		if (*p == '[' || *p == '(') {
			ingroup = 1;
			sp = 1;
		} else if (*p == ']' || *p == ')') {
			ingroup = 0;
			sp = 1;
		} else if (ingroup) {
			continue;
		} else if (*p == '.' || *p == ' ' || *p == '\t') {
			sp = 1;
		} else {
			if (n && sp && n + 1 < cap)
				o[n++] = ' ';
			if (n + 1 < cap)
				o[n++] = *p;
			sp = 0;
		}
	}
	o[n < cap ? n : cap - 1] = '\0';

	/* pass 2: the title ends at the first release-furniture token */
	{
		char *q = o;
		int ti = 0;

		while (*q) {
			char *s = q, *e;

			while (*s == ' ')
				s++;
			if (!*s)
				break;
			e = s;
			while (*e && *e != ' ')
				e++;

			if (ti++ && hls_dir_junk_token(s, (size_t)(e - s))) {
				/* trim any separator before it */
				while (q < s && s[-1] == ' ')
					s--;
				*s = '\0';
				break;
			}
			q = e;
		}
	}
}

int
lws_hls_serve_dir(struct lws *wsi, struct per_vhost_data__lws_hls *vhd)
{
	struct dir_state ds;
	char esc[HLS_DIR_ESC_MAX];
	size_t need, len, i;
	char *html, *body, *q;
	uint8_t *buf, *start, *p, *end;
	struct per_session_data__lws_hls *pss;
	char friendly[256], fesc[HLS_DIR_ESC_MAX];
	int can_delete;

	const char *media_dir = vhd->media_dir;
	char apref[80];	/* asset_prefix as a URL fragment, "" for same-dir */

	memset(&ds, 0, sizeof(ds));
	ds.base_dir = media_dir;

	/*
	 * The listing's links are relative to the page itself, prefixed by
	 * asset_prefix when the assets are not in the same "directory": this
	 * app has to work behind a reverse proxy that mounts it at an
	 * unknown point of a public server's URL space, so absolute paths
	 * are never an option.  "." or "" means the same directory.
	 */
	if (!strcmp(vhd->asset_prefix, "."))
		apref[0] = '\0';
	else
		lws_snprintf(apref, sizeof(apref), "%s/",
			     vhd->asset_prefix);

	lws_dir(media_dir, &ds, hls_dir_cb);

	if (ds.count > 0 && ds.entries)
		qsort(ds.entries, ds.count, sizeof(struct file_entry), cmp_mtime);

	/*
	 * Size the composition buffer exactly: the fixed page chrome, plus
	 * per entry the fixed markup, three interpolations of the escaped
	 * name (href, img src, and the delete button's data-file) and the
	 * escaped friendly name shown as the link text (which is never
	 * longer than the name).  Composition still goes through the
	 * clamped hls_append_fmt(), so any accounting error can only
	 * truncate, never overshoot (F-059: the old fixed 512-per-entry
	 * estimate vs ~1.2 KB reality made the raw-snprintf cursor pass the
	 * allocation and underflow rem).
	 */
	need = 1024 + strlen(apref) * 4; /* page chrome + tail + slack */
	for (i = 0; i < ds.count; i++) {
		const char *display = ds.entries[i].name;

		hls_dir_friendly(friendly, sizeof(friendly), ds.entries[i].name);
		if (friendly[0])
			display = friendly;

		need += hls_dir_esc(NULL, 0, ds.entries[i].name) * 3 +
			hls_dir_esc(NULL, 0, display) + HLS_DIR_ENTRY_FIXED;
	}

	html = malloc(LWS_PRE + need);
	if (!html) {
		if (ds.entries) free(ds.entries);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return -1;
	}

	body = html + LWS_PRE;
	pss = (struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	can_delete = pss ? pss->can_delete : 0;

	q = hls_append_fmt(body, body, need,
		"<html><head><meta charset=\"utf-8\">"
		"<title>LWS HLS Media</title>"
		"<link rel=\"icon\" href=\"%sfavicon.ico\">"
		"<link rel=\"stylesheet\" href=\"%sdir.css\">"
		"<script src=\"/lws-login-media/lws-login.js\"></script>"
		"<script src=\"%sdir.js\" defer></script>"
		"</head><body data-gen='%016llx'>"
		"<div id=\"auth-status\"></div>"
		"<h1>Media Directory</h1><div>", apref, apref, apref,
		(unsigned long long)ds.gen);

	for (i = 0; i < ds.count; i++) {
		const char *display = ds.entries[i].name;

		hls_dir_friendly(friendly, sizeof(friendly), ds.entries[i].name);
		if (friendly[0])
			display = friendly;

		hls_dir_esc(esc, sizeof(esc), ds.entries[i].name);
		hls_dir_esc(fesc, sizeof(fesc), display);

		if (ds.entries[i].state != HLS_MEDIA_COMPLETE) {
			/*
			 * Not all there yet: listed, so the viewer can see it
			 * coming (and an admin can delete a copy that died),
			 * but with nothing to play and no thumbnail to cut
			 * from it.  The server refuses both anyway.
			 */
			q = hls_append_fmt(q, body, need,
				"<div class='item pending' data-t='%llu'>"
				"<div class='thumb pending-thumb'>%s</div>"
				"<br>%s%s%s%s</div>",
				(unsigned long long)ds.entries[i].mtime,
				ds.entries[i].state == HLS_MEDIA_ARRIVING ?
					"still arriving" : "incomplete",
				fesc,
				can_delete ? "<button class='del-btn' title='Delete' data-file='" : "",
				can_delete ? esc : "",
				can_delete ? "'>&#x1F5D1;</button>" : "");
			continue;
		}

		q = hls_append_fmt(q, body, need,
			"<div class='item'>"
			"<a href='%splayer.html?v=stream/%s&t=%llu'>"
			"<img class='thumb' src='preview/%s' alt='Thumbnail'>"
			"<br>%s</a>%s%s%s</div>",
			apref, esc, (unsigned long long)ds.entries[i].mtime, esc, fesc,
			/* no inline handler: the page's CSP has no
			 * 'unsafe-inline'; dir.js binds the click */
			can_delete ? "<button class='del-btn' title='Delete' data-file='" : "",
			can_delete ? esc : "",
			can_delete ? "'>&#x1F5D1;</button>" : "");
	}

	q = hls_append_fmt(q, body, need, "</div></body></html>");
	len = (size_t)(q - body);

	buf = malloc(LWS_PRE + 2048);

	if (!buf) {
		free(html);
		if (ds.entries) free(ds.entries);
		return -1;
	}

	start = buf + LWS_PRE;
	p = start;
	end = p + 2048;

	/*
	 * The charset matters beyond this page: dir.js has no charset of its
	 * own, so the browser decodes it as the document it was loaded from,
	 * and without this the badge glyph came out as windows-1252 mojibake
	 */
	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"text/html; charset=utf-8",
					(lws_filepos_t)len, &p, end)) {
		free(buf);
		free(html);
		if (ds.entries) free(ds.entries);
		return lws_http_transaction_completed(wsi);
	}

	if (lws_finalize_write_http_header(wsi, start, &p, end)) {
		free(buf);
		free(html);
		if (ds.entries) free(ds.entries);
		return lws_http_transaction_completed(wsi);
	}

	/* Write body */
	lws_write(wsi, (uint8_t *)body, len, LWS_WRITE_HTTP_FINAL);

	free(buf);
	free(html);
	if (ds.entries) free(ds.entries);

	return lws_http_transaction_completed(wsi);
}

/*
 * Change feed for the pages showing the listing.
 *
 * A page subscribes with an SSE request to "events" beside it.  While there
 * is anyone subscribed, the media dir is rewalked every HLS_WATCH_US, from
 * stat alone, for the listing's generation; every subscriber is sent the
 * generation when it subscribes and whenever it changes, and the page
 * compares it with the one it was built from (data-gen on its body) to know
 * it is out of date: media arrived, finished arriving, or went.
 *
 * Polling rather than a directory notifier: media lives in subdirectories
 * as well, and what a page needs to hear about includes a copy finishing,
 * which is only the passing of time.  The walk is stat()s of the listing's
 * files, and only happens while somebody is looking.
 */

uint64_t
lws_hls_listing_gen(struct per_vhost_data__lws_hls *vhd)
{
	struct dir_state ds;

	memset(&ds, 0, sizeof(ds));
	ds.base_dir = vhd->media_dir;
	ds.gen_only = 1;
	lws_dir(vhd->media_dir, &ds, hls_dir_cb);

	return ds.gen;
}

static void
hls_watch_sul(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__lws_hls *vhd = lws_container_of(sul,
				struct per_vhost_data__lws_hls, sul_watch);
	lws_usec_t now = lws_now_usecs();
	uint64_t gen;

	if (!vhd->watchers.count)
		/* nobody looking: stop until somebody is */
		return;

	gen = lws_hls_listing_gen(vhd);
	if (gen != vhd->watch_gen) {
		lwsl_info("%s: listing changed, telling %d page(s)\n",
			  __func__, (int)vhd->watchers.count);
		vhd->watch_gen = gen;
	}

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->watchers)) {
		struct per_session_data__lws_hls *pss = lws_container_of(d,
				struct per_session_data__lws_hls, watch_list);

		if (pss->watch_sent_gen != vhd->watch_gen ||
		    now - pss->watch_tx > HLS_WATCH_KEEPALIVE_US)
			lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_dll(d);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_watch, hls_watch_sul,
			 HLS_WATCH_US);
}

void
lws_hls_watch_kick(struct per_vhost_data__lws_hls *vhd)
{
	if (vhd->watchers.count)
		lws_sul_schedule(vhd->context, 0, &vhd->sul_watch,
				 hls_watch_sul, 1);
}

int
lws_hls_watch_add(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
		  struct per_session_data__lws_hls *pss)
{
	/* room for the vhost's own headers too, eg a CSP */
	uint8_t buf[LWS_PRE + 2048], *start = buf + LWS_PRE, *p = start,
		*end = buf + sizeof(buf) - 1;

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
					"text/event-stream",
					LWS_ILLEGAL_HTTP_CONTENT_LEN, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
					 (const uint8_t *)"no-store", 8,
					 &p, end) ||
	    /* a buffering proxy in front would hold the events back */
	    lws_add_http_header_by_name(wsi,
					(const uint8_t *)"x-accel-buffering:",
					(const uint8_t *)"no", 2, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return -1;

	/* no longer an http transaction with a timeout, but a feed */
	lws_http_mark_sse(wsi);

	/*
	 * The first subscriber starts the watch, from the listing as it is
	 * now; a later one is told what the watch last saw, and anything
	 * since is at most HLS_WATCH_US away
	 */
	if (!vhd->watchers.count) {
		vhd->watch_gen = lws_hls_listing_gen(vhd);
		lws_sul_schedule(vhd->context, 0, &vhd->sul_watch,
				 hls_watch_sul, HLS_WATCH_US);
	}

	pss->watching = 1;
	pss->watch_sent = 0;
	lws_dll2_add_tail(&pss->watch_list, &vhd->watchers);
	lws_callback_on_writable(wsi);

	return 0;
}

void
lws_hls_watch_remove(struct per_vhost_data__lws_hls *vhd,
		     struct per_session_data__lws_hls *pss)
{
	if (!pss->watching)
		return;

	pss->watching = 0;
	lws_dll2_remove(&pss->watch_list);
	if (!vhd->watchers.count)
		lws_sul_cancel(&vhd->sul_watch);
}

int
lws_hls_watch_writeable(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
			struct per_session_data__lws_hls *pss)
{
	char buf[LWS_PRE + 64], *start = buf + LWS_PRE;
	int n;

	if (!pss->watch_sent || pss->watch_sent_gen != vhd->watch_gen) {
		n = lws_snprintf(start, sizeof(buf) - LWS_PRE,
				 "data: %016llx\r\n\r\n",
				 (unsigned long long)vhd->watch_gen);
		pss->watch_sent_gen = vhd->watch_gen;
		pss->watch_sent = 1;
	} else
		/* an SSE comment: the page ignores it, the connection lives */
		n = lws_snprintf(start, sizeof(buf) - LWS_PRE, ":\r\n\r\n");

	if (lws_write(wsi, (uint8_t *)start, (size_t)n, LWS_WRITE_HTTP) != n)
		return -1;

	pss->watch_tx = lws_now_usecs();

	return 0;
}
