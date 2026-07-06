#include "private-lws-hls.h"
#include <sys/stat.h>
#include <stdlib.h>

struct file_entry {
	char name[256];
	time_t mtime;
};

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

	snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

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
		ds->max += 64;
		ds->entries = realloc(ds->entries, ds->max * sizeof(struct file_entry));
		if (!ds->entries)
			return 1;
	}

	if (stat(path, &st) == 0) {
		const char *rel_path = path;
		size_t base_len = strlen(ds->base_dir);
		if (!strncmp(path, ds->base_dir, base_len) && path[base_len] == '/')
			rel_path = path + base_len + 1;
			
		strncpy(ds->entries[ds->count].name, rel_path, sizeof(ds->entries[ds->count].name) - 1);
		ds->entries[ds->count].name[sizeof(ds->entries[ds->count].name) - 1] = '\0';
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

int
lws_hls_serve_dir(struct lws *wsi, const char *media_dir)
{
	struct dir_state ds;
	memset(&ds, 0, sizeof(ds));
	ds.base_dir = media_dir;
	
	lws_dir(media_dir, &ds, hls_dir_cb);
	
	if (ds.count > 0 && ds.entries)
		qsort(ds.entries, ds.count, sizeof(struct file_entry), cmp_mtime);

	/* Generate HTML */
	size_t html_size = 8192 + (ds.count * 512);
	char *html = malloc(LWS_PRE + html_size);
	if (!html) {
		if (ds.entries) free(ds.entries);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return -1;
	}
	
	char *p_html = html + LWS_PRE;
	p_html += snprintf(p_html, html_size, 
		"<html><head><title>LWS HLS Media</title>"
		"<link rel=\"stylesheet\" href=\"../dir.css\">"
		"<script src=\"/lws-login-media/lws-login.js\"></script>"
		"<script src=\"../dir.js\" defer></script>"
		"</head><body>"
		"<div id=\"auth-status\"></div>"
		"<h1>Media Directory</h1><div>");
		
	for (size_t i = 0; i < ds.count; i++) {
		size_t rem = html_size - (size_t)(p_html - (html + LWS_PRE));
		p_html += snprintf(p_html, rem,
			"<div class='item'>"
			"<a href='../player.html?v=hls/stream/%s'>"
			"<img class='thumb' src='preview/%s' alt='Thumbnail'>"
			"<br>%s</a></div>",
			ds.entries[i].name, ds.entries[i].name, ds.entries[i].name);
	}
	
	size_t rem = html_size - (size_t)(p_html - (html + LWS_PRE));
	snprintf(p_html, rem, "</div></body></html>");
	
	size_t len = strlen(html + LWS_PRE);
	
	uint8_t *buf = malloc(LWS_PRE + 2048);
	if (!buf) {
		free(html);
		if (ds.entries) free(ds.entries);
		return -1;
	}
	
	uint8_t *start = buf + LWS_PRE;
	uint8_t *p = start;
	uint8_t *end = p + 2048;
	
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
	lws_write(wsi, (uint8_t *)(html + LWS_PRE), len, LWS_WRITE_HTTP_FINAL);
	
	free(buf);
	free(html);
	if (ds.entries) free(ds.entries);
	
	return lws_http_transaction_completed(wsi);
}
