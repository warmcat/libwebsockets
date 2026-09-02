#include "private-lws-hls.h"
#include <sys/stat.h>
#include <stdlib.h>

struct file_entry {
	char name[256];
	time_t mtime;
};

/* escaped form of the longest possible name (255 chars, each expanding to
 * the 5-char entity "&#39;") plus the NUL */
#define HLS_DIR_ESC_MAX (255 * 5 + 1)

/* fixed markup budget per listing entry, exclusive of the escaped name
 * (which is interpolated four times) and the mtime digits; the actual
 * per-entry markup is ~180 bytes */
#define HLS_DIR_ENTRY_FIXED 256

struct dir_state {
	struct file_entry *entries;
	size_t count;
	size_t max;
	const char *base_dir;
};

static int
hls_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct dir_state *ds = (struct dir_state *)user;
	struct stat st;
	char path[1024];

	if (!strcmp(lde->name, ".") || !strcmp(lde->name, ".."))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (lde->type == LDOT_DIR) {
		lws_dir(path, ds, hls_dir_cb);
		return 0;
	}

	if (lde->type != LDOT_FILE)
		return 0;

	/* only list media files */
	if (!strstr(lde->name, ".mp4") && !strstr(lde->name, ".mkv"))
		return 0;

	if (ds->count >= ds->max) {
		struct file_entry *ne;

		ds->max += 64;
		ne = realloc(ds->entries, ds->max * sizeof(struct file_entry));
		if (!ne)
			return 1;
		ds->entries = ne;
	}

	if (stat(path, &st) == 0) {
		const char *rel_path = path;
		size_t base_len = strlen(ds->base_dir);
		if (!strncmp(path, ds->base_dir, base_len) && path[base_len] == '/')
			rel_path = path + base_len + 1;

		lws_strncpy(ds->entries[ds->count].name, rel_path,
			    sizeof(ds->entries[ds->count].name));
		ds->entries[ds->count].mtime = st.st_mtime;
		ds->count++;
	}

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

int
lws_hls_serve_dir(struct lws *wsi, const char *media_dir)
{
	struct dir_state ds;
	char esc[HLS_DIR_ESC_MAX];
	size_t need, len, i;
	char *html, *body, *q;
	uint8_t *buf, *start, *p, *end;
	struct per_session_data__lws_hls *pss;
	int can_delete;

	memset(&ds, 0, sizeof(ds));
	ds.base_dir = media_dir;

	lws_dir(media_dir, &ds, hls_dir_cb);

	if (ds.count > 0 && ds.entries)
		qsort(ds.entries, ds.count, sizeof(struct file_entry), cmp_mtime);

	/*
	 * Size the composition buffer exactly: the fixed page chrome, plus
	 * per entry the fixed markup and four interpolations of the escaped
	 * name (href, img src, text, and the delete button's data-file).
	 * Composition still goes through the clamped hls_append_fmt(), so
	 * any accounting error can only truncate, never overshoot (F-059:
	 * the old fixed 512-per-entry estimate vs ~1.2 KB reality made the
	 * raw-snprintf cursor pass the allocation and underflow rem).
	 */
	need = 1024; /* page chrome + tail + slack */
	for (i = 0; i < ds.count; i++)
		need += hls_dir_esc(NULL, 0, ds.entries[i].name) * 4 +
			HLS_DIR_ENTRY_FIXED;

	html = malloc(LWS_PRE + need);
	if (!html) {
		if (ds.entries) free(ds.entries);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return -1;
	}

	body = html + LWS_PRE;
	pss = (struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	can_delete = pss ? pss->has_star_grant : 0;

	q = hls_append_fmt(body, body, need,
		"<html><head><title>LWS HLS Media</title>"
		"<link rel=\"stylesheet\" href=\"../dir.css\">"
		"<script src=\"/lws-login-media/lws-login.js\"></script>"
		"<script src=\"../dir.js\" defer></script>"
		"</head><body>"
		"<div id=\"auth-status\"></div>"
		"<h1>Media Directory</h1><div>");

	for (i = 0; i < ds.count; i++) {
		hls_dir_esc(esc, sizeof(esc), ds.entries[i].name);
		q = hls_append_fmt(q, body, need,
			"<div class='item'>"
			"<a href='../player.html?v=hls/stream/%s&t=%llu'>"
			"<img class='thumb' src='preview/%s' alt='Thumbnail'>"
			"<br>%s</a>%s%s%s</div>",
			esc, (unsigned long long)ds.entries[i].mtime, esc, esc,
			can_delete ? "<button class='del-btn' onclick='delFile(this, event)' data-file='" : "",
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

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/html",
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
