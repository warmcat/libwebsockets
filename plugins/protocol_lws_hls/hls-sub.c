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

/*
 * WebVTT subtitle support for the HLS plugin.
 *
 * Subtitles are delivered as a parallel set of WebVTT segments, referenced
 * from a master playlist via #EXT-X-MEDIA:TYPE=SUBTITLES. The existing
 * combined audio+video fMP4 path is left untouched; this file only adds:
 *
 *   - track discovery (embedded text streams + sibling .srt/.vtt sidecars)
 *   - cue decoding/parsing into a shared cue list (cached per file+track)
 *   - a master-playlist dispatcher at /stream/<file>
 *   - a subtitle media playlist at /subsm/<file>/<trackid>
 *   - a WebVTT segment at /subseg/<file>/<trackid>/<idx>
 *
 * Bitmap subtitle formats (PGS/VOBSUB/DVB/...) cannot be turned into WebVTT
 * losslessly and are intentionally skipped (see is_text_subtitle()).
 */

#include "private-lws-hls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static int
is_text_subtitle(enum AVCodecID id)
{
	switch (id) {
	case AV_CODEC_ID_SUBRIP:
	case AV_CODEC_ID_MOV_TEXT:
	case AV_CODEC_ID_ASS:
	case AV_CODEC_ID_SSA:
	case AV_CODEC_ID_WEBVTT:
	case AV_CODEC_ID_MICRODVD:
	case AV_CODEC_ID_JACOSUB:
		return 1;
	default:
		return 0;
	}
}

static const char *
lang_name(const char *code)
{
	static const struct { const char *iso; const char *name; } map[] = {
		{ "en", "English" },    { "es", "Spanish" },   { "fr", "French" },
		{ "de", "German" },     { "it", "Italian" },   { "pt", "Portuguese" },
		{ "ru", "Russian" },    { "ja", "Japanese" },  { "zh", "Chinese" },
		{ "ko", "Korean" },     { "ar", "Arabic" },    { "hi", "Hindi" },
		{ "nl", "Dutch" },      { "pl", "Polish" },    { "tr", "Turkish" },
		{ "sv", "Swedish" },    { "no", "Norwegian" }, { "da", "Danish" },
		{ "fi", "Finnish" },    { "cs", "Czech" },     { "th", "Thai" },
		{ "he", "Hebrew" },     { "el", "Greek" },     { "uk", "Ukrainian" },
		{ "hu", "Hungarian" },  { "ro", "Romanian" },
		/* 3-letter ISO 639-2/3 bibliographic codes that ffmpeg/mkv often
		 * emit for the same languages above. */
		{ "eng", "English" },   { "spa", "Spanish" },  { "fra", "French" },
		{ "ger", "German" },    { "deu", "German" },   { "ita", "Italian" },
		{ "por", "Portuguese" },{ "rus", "Russian" },  { "jpn", "Japanese" },
		{ "chi", "Chinese" },   { "zho", "Chinese" },  { "kor", "Korean" },
		{ "ara", "Arabic" },    { "hin", "Hindi" },    { "nld", "Dutch" },
		{ "pol", "Polish" },    { "tur", "Turkish" },  { "swe", "Swedish" },
		{ "nor", "Norwegian" }, { "fin", "Finnish" },  { "tha", "Thai" },
		{ "heb", "Hebrew" },    { "ell", "Greek" },    { "ukr", "Ukrainian" },
		{ "hun", "Hungarian" }, { "ron", "Romanian" },
	};
	size_t i, clen = code ? strlen(code) : 0;

	/* "und" (or empty) = language unknown; show a readable placeholder
	 * rather than the raw ISO code. The LANGUAGE attribute is still
	 * emitted as "und" so clients can treat it as unspecified. */
	if (!clen || !strcmp(code, "und"))
		return "Subtitles";

	/* match on the primary subtag (before any '-'), case-insensitive */
	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		size_t ml = strlen(map[i].iso);
		if (clen >= ml &&
		    !strncasecmp(code, map[i].iso, ml) &&
		    (clen == ml || code[ml] == '-'))
			return map[i].name;
	}
	return code;
}

/* Strip the leading "Dialogue: ...,text" SSA styling from an ASS event line,
 * leaving the readable text with \N converted to newlines. Writes a freshly
 * malloc'd plain-text string (may be empty); returns NULL on OOM. */
static char *
ass_to_text(const char *ass)
{
	const char *p = ass;
	int commas = 0;

	/* libavcodec's AVSubtitleRect.ass may or may not carry the leading
	 * "Dialogue:" token; drop it if present. After it (or from the start),
	 * the SSA event is: ReadOrder,Layer,Style,Name,MarginL,MarginR,
	 * MarginV,Effect,Text  -> exactly 8 commas before the readable text. */
	if (!strncmp(p, "Dialogue:", 9))
		p += 9;
	while (*p == ' ' || *p == '\t')
		p++;
	while (*p && commas < 8) {
		if (*p == ',')
			commas++;
		p++;
	}

	size_t n = strlen(p);
	char *out = malloc(n + 1);
	if (!out)
		return NULL;

	size_t o = 0;
	for (; *p; p++) {
		if (p[0] == '\\' && (p[1] == 'N' || p[1] == 'n')) {
			out[o++] = '\n';
			p++;
		} else if (p[0] == '\\' && p[1]) {
			/* drop \h etc. (hard space / formatting escapes) */
			p++;
		} else if (p[0] == '{') {
			/* skip {...} override blocks */
			p++;
			while (*p && *p != '}')
				p++;
			if (*p != '}')
				p--; /* ran off end; let loop terminate */
		} else {
			out[o++] = *p;
		}
	}
	out[o] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* track discovery                                                     */
/* ------------------------------------------------------------------ */

void
lws_hls_free_tracks(struct hls_sub_track *tracks, int count)
{
	/* All track fields are value types; only the array itself is owned. */
	(void)count;
	free(tracks);
}

int
lws_hls_find_track(struct hls_sub_track *tracks, int count, const char *trackid)
{
	int i;
	if (!trackid)
		return -1;
	for (i = 0; i < count; i++)
		if (!strcmp(tracks[i].id, trackid))
			return i;
	return -1;
}

/* state for the sidecar scan callback */
struct sidecar_state {
	const char *base;        /* media basename without extension */
	struct hls_sub_track *out;
	int count;
	int cap;
};

static int
ends_with_ci(const char *s, const char *suf)
{
	size_t ls = strlen(s), lf = strlen(suf);
	return ls >= lf && !strcasecmp(s + ls - lf, suf);
}

/* lws_dir callback: collect sibling .srt/.vtt sidecars for one video */
static int
sidecar_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct sidecar_state *st = (struct sidecar_state *)user;
	const char *name = lde->name;
	size_t blen;

	(void)dirpath;

	if (lde->type != LDOT_FILE)
		return 0;

	/* must start with "<base>." */
	blen = strlen(st->base);
	if (strncasecmp(name, st->base, blen) || name[blen] != '.')
		return 0;

	/* only .srt / .vtt */
	if (!ends_with_ci(name, ".srt") && !ends_with_ci(name, ".vtt"))
		return 0;

	/* name layout: "<base>" "." [lang "."] (srt|vtt) */
	{
		const char *rest = name + blen + 1; /* after "<base>." */
		const char *dot = strchr(rest, '.');
		const char *lang = NULL;
		size_t langlen = 0;
		struct hls_sub_track *t;

		if (dot) {
			/* "<base>.<lang>.<ext>" */
			lang = rest;
			langlen = (size_t)(dot - rest);
		}
		/* else "<base>.<ext>" -> no language tag */

		if (st->count >= st->cap) {
			int newcap = st->cap ? st->cap * 2 : 8;
			struct hls_sub_track *nn = realloc(st->out,
					(size_t)newcap * sizeof(*nn));
			if (!nn)
				return 1;
			st->out = nn;
			st->cap = newcap;
		}

		t = &st->out[st->count];
		memset(t, 0, sizeof(*t));
		t->kind = HLS_SUB_SIDECAR;
		/* id is (re)assigned later, after alphabetical sort */
		snprintf(t->id, sizeof(t->id), "s%d", st->count);
		if (lang && langlen > 0 && langlen < sizeof(t->lang)) {
			memcpy(t->lang, lang, langlen);
			t->lang[langlen] = '\0';
		} else {
			strcpy(t->lang, "und");
		}
		/* Disambiguate untagged sidecars by filename so multiple ones
		 * are distinguishable in the dropdown. */
		if (strcmp(t->lang, "und"))
			snprintf(t->name, sizeof(t->name), "%s",
				 lang_name(t->lang));
		else
			snprintf(t->name, sizeof(t->name), "Subtitles (%s)",
				 name);
		t->is_vtt = ends_with_ci(name, ".vtt");
		lws_strncpy(t->path, name, sizeof(t->path));
		lwsl_notice("HLS-SUB: sidecar '%s' (lang '%s') -> accepted\n",
			    name, t->lang);
		st->count++;
	}
	return 0;
}

static int
track_cmp(const void *a, const void *b)
{
	const struct hls_sub_track *ta = a, *tb = b;
	/* Order tracks naturally for display: embedded tracks first (ordered by
	 * their AVStream index, so e2, e3, ..., e10, e11 — NOT the lexicographic
	 * e10, e11, e2 that strcmp would give), then sidecar files (ordered
	 * alphabetically by filename). The display name embeds the id, so this
	 * is also the dropdown order the user sees. */
	int ea = (ta->kind == HLS_SUB_EMBEDDED);
	int eb = (tb->kind == HLS_SUB_EMBEDDED);
	if (ea != eb)
		return ea ? -1 : 1; /* embedded before sidecar */
	if (ea)
		return (ta->stream_index < tb->stream_index) ? -1 :
		       (ta->stream_index > tb->stream_index) ? 1 : 0;
	return strcmp(ta->path, tb->path); /* sidecars by filename */
}

struct hls_sub_track *
lws_hls_discover_tracks(const char *media_dir, const char *filename, int *out_count)
{
	struct hls_sub_track *tracks = NULL;
	int count = 0, cap = 0;
	char base[256];
	const char *dot;
	AVFormatContext *ic = NULL;

	*out_count = 0;

	/* basename = filename without its final extension */
	dot = strrchr(filename, '.');
	if (dot) {
		size_t bl = (size_t)(dot - filename);
		if (bl >= sizeof(base))
			bl = sizeof(base) - 1;
		memcpy(base, filename, bl);
		base[bl] = '\0';
	} else {
		lws_strncpy(base, filename, sizeof(base));
	}

	/* ---- embedded subtitle streams ---- */
	{
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", media_dir, filename);
		if (!avformat_open_input(&ic, path, NULL, NULL)) {
			if (!avformat_find_stream_info(ic, NULL)) {
				unsigned int i;
				int nsub_seen = 0, nsub_skipped = 0;
				for (i = 0; i < ic->nb_streams; i++) {
					AVStream *st = ic->streams[i];
					AVDictionaryEntry *lg;
					AVDictionaryEntry *tg;
					struct hls_sub_track *t;
					const char *codec_name;
					int is_text;

					if (st->codecpar->codec_type !=
					    AVMEDIA_TYPE_SUBTITLE)
						continue;

					nsub_seen++;
					codec_name = avcodec_get_name(
							st->codecpar->codec_id);
					is_text = is_text_subtitle(
							st->codecpar->codec_id);
					lg = av_dict_get(st->metadata,
							 "language", NULL, 0);
					/* MKV/MP4 often carry a human-readable track
					 * title (e.g. "Director's Commentary",
					 * "English (Forced)") we can surface. */
					tg = av_dict_get(st->metadata,
							 "title", NULL, 0);

					if (!is_text) {
						nsub_skipped++;
						lwsl_notice("HLS-SUB: %s: stream %u "
							"codec '%s' lang '%s' is "
							"bitmap/non-text -> SKIPPED "
							"(no lossless WebVTT path)\n",
							filename, i,
							codec_name ? codec_name : "?",
							(lg && lg->value) ?
								lg->value : "und");
						continue;
					}

					lwsl_notice("HLS-SUB: %s: stream %u codec "
						"'%s' lang '%s' title '%s' -> "
						"accepted as e%u\n", filename, i,
						codec_name ? codec_name : "?",
						(lg && lg->value) ? lg->value
								  : "und",
						(tg && tg->value) ? tg->value
								  : "(none)", i);

					if (count >= cap) {
						int nc = cap ? cap * 2 : 8;
						struct hls_sub_track *nn =
							realloc(tracks,
								(size_t)nc *
								sizeof(*nn));
						if (!nn)
							goto done_embedded;
						tracks = nn;
						cap = nc;
					}
					t = &tracks[count];
					memset(t, 0, sizeof(*t));
					t->kind = HLS_SUB_EMBEDDED;
					snprintf(t->id, sizeof(t->id), "e%d",
						 (int)i);
					t->stream_index = (int)i;
					if (lg && lg->value && *lg->value)
						lws_strncpy(t->lang, lg->value,
							    sizeof(t->lang));
					else
						strcpy(t->lang, "und");

					/* Build a display name, in priority order:
					 *   1. the container's track TITLE tag
					 *      (most descriptive when present)
					 *   2. a human-readable language name
					 *      (mapped from the ISO code)
					 *   3. a disambiguated placeholder using
					 *      the stream index + codec. Some release
					 *      MKVs ship many subtitle tracks with no
					 *      language/title tags at all; without a
					 *      real label the dropdown would be a wall
					 *      of identical entries. Including the
					 *      stream id (e<n>) also matches the
					 *      server logs so users can correlate. */
					if (tg && tg->value && *tg->value) {
						lws_strncpy(t->name, tg->value,
							    sizeof(t->name));
					} else if (strcmp(t->lang, "und")) {
						snprintf(t->name, sizeof(t->name),
							 "%s", lang_name(t->lang));
					} else {
						snprintf(t->name, sizeof(t->name),
							 "Subtitles [e%u, %s]",
							 i, codec_name ?
								codec_name : "text");
					}
					count++;
				}

				if (nsub_seen)
					lwsl_notice("HLS-SUB: %s: %d embedded sub "
						"stream(s): %d accepted, %d "
						"skipped\n", filename, nsub_seen,
						nsub_seen - nsub_skipped,
						nsub_skipped);
			}
done_embedded:
			avformat_close_input(&ic);
		} else {
			lwsl_notice("HLS-SUB: %s: could not open for sub "
				    "discovery\n", filename);
		}
	}

	/* ---- sidecar .srt/.vtt sibling files ---- */
	{
		struct sidecar_state st;
		memset(&st, 0, sizeof(st));
		st.base = base;
		/* fold any embedded tracks we already found in */
		st.out = tracks;
		st.count = count;
		st.cap = cap;

		lws_dir(media_dir, &st, sidecar_cb);

		tracks = st.out;
		count = st.count;
		cap = st.cap;
	}

	/* assign stable sidecar ids (s0, s1, ...) AFTER sorting alphabetically
	 * so the order is deterministic regardless of readdir order. Only the
	 * sidecar entries need renumbering. */
	if (count > 0) {
		int sidx = 0, i;
		qsort(tracks, (size_t)count, sizeof(*tracks), track_cmp);
		for (i = 0; i < count; i++) {
			if (tracks[i].kind == HLS_SUB_SIDECAR) {
				snprintf(tracks[i].id, sizeof(tracks[i].id),
					 "s%d", sidx++);
			}
		}
	}

	if (count == 0) {
		free(tracks);
		tracks = NULL;
	}

	lwsl_notice("HLS-SUB: %s: discovery complete -> %d usable track(s)\n",
		    filename, count);

	*out_count = count;
	return tracks;
}

/* ------------------------------------------------------------------ */
/* cue loading                                                         */
/* ------------------------------------------------------------------ */

static void
free_cues(struct hls_webvtt_cue *cues, int n)
{
	int i;
	if (!cues)
		return;
	for (i = 0; i < n; i++)
		free(cues[i].text);
	free(cues);
}

static int
push_cue(struct hls_webvtt_cue **pcues, int *pn, int *pcap,
	 double start, double end, char *text)
{
	struct hls_webvtt_cue *arr = *pcues;
	int n = *pn, cap = *pcap;

	if (n >= cap) {
		int nc = cap ? cap * 2 : 64;
		struct hls_webvtt_cue *nn = realloc(arr, (size_t)nc * sizeof(*nn));
		if (!nn) {
			free(text);
			return -1;
		}
		arr = nn;
		cap = nc;
	}
	arr[n].start = start;
	arr[n].end = end;
	arr[n].text = text;
	*pcues = arr;
	*pn = n + 1;
	*pcap = cap;
	return 0;
}

/* Decode an embedded text subtitle stream into cues (seconds from start). */
static int
load_embedded_cues(const char *media_dir, const char *filename, int stream_index,
		   struct hls_webvtt_cue **out_cues, int *out_n)
{
	AVFormatContext *ic = NULL;
	AVCodecContext *dec = NULL;
	const AVCodec *codec = NULL;
	struct hls_webvtt_cue *cues = NULL;
	int n = 0, cap = 0, ret = -1;
	char path[512];
	AVPacket *pkt = NULL;

	snprintf(path, sizeof(path), "%s/%s", media_dir, filename);
	if (avformat_open_input(&ic, path, NULL, NULL) < 0)
		return -1;
	if (avformat_find_stream_info(ic, NULL) < 0)
		goto out;
	if ((unsigned int)stream_index >= ic->nb_streams)
		goto out;

	codec = avcodec_find_decoder(
			ic->streams[stream_index]->codecpar->codec_id);
	if (!codec)
		goto out;
	dec = avcodec_alloc_context3(codec);
	if (!dec)
		goto out;
	if (avcodec_parameters_to_context(dec,
			ic->streams[stream_index]->codecpar) < 0)
		goto out;
	if (avcodec_open2(dec, codec, NULL) < 0)
		goto out;

	pkt = av_packet_alloc();
	if (!pkt)
		goto out;

	while (av_read_frame(ic, pkt) >= 0) {
		AVSubtitle sub;
		int got = 0;

		if (pkt->stream_index != stream_index) {
			av_packet_unref(pkt);
			continue;
		}

		memset(&sub, 0, sizeof(sub));
		if (avcodec_decode_subtitle2(dec, &sub, &got, pkt) < 0 || !got) {
			avsubtitle_free(&sub);
			av_packet_unref(pkt);
			continue;
		}

		if (sub.num_rects > 0) {
			/* Subtitle PTS lives on the PACKET (sub.pts is usually
			 * AV_NOPTS_VALUE for text formats like mov_text/ass),
			 * expressed in the stream's time_base. Duration comes
			 * from pkt->duration (text formats) or, when the
			 * container sets it, sub.end_display_time (ms). */
			AVStream *st = ic->streams[stream_index];
			double tb = av_q2d(st->time_base);
			double start_s = (pkt->pts != AV_NOPTS_VALUE)
				? (double)pkt->pts * tb
				: 0.0;
			start_s += (double)sub.start_display_time / 1000.0;
			double dur_s = (pkt->duration > 0)
				? (double)pkt->duration * tb
				: 2.0;
			if (sub.end_display_time > 0)
				dur_s = (double)sub.end_display_time / 1000.0;
			double end_s = start_s + dur_s;
			unsigned r;

			for (r = 0; r < sub.num_rects; r++) {
				AVSubtitleRect *rect = sub.rects[r];
				char *text = NULL;
				if (rect->type == SUBTITLE_TEXT && rect->text)
					text = strdup(rect->text);
				else if (rect->type == SUBTITLE_ASS && rect->ass)
					text = ass_to_text(rect->ass);
				if (text) {
					if (push_cue(&cues, &n, &cap,
						     start_s, end_s, text) < 0)
						text = NULL;
				}
			}
		}

		avsubtitle_free(&sub);
		av_packet_unref(pkt);
	}

	*out_cues = cues;
	*out_n = n;
	cues = NULL;
	ret = 0;

out:
	av_packet_free(&pkt);
	if (dec)
		avcodec_free_context(&dec);
	avformat_close_input(&ic);
	free_cues(cues, n);
	return ret;
}

/* Parse a timestamp of the form [HH:]MM:SS[,|.]mmm into seconds. Returns
 * -1 on parse failure. Both SRT (comma) and WebVTT (period) decimal
 * separators are accepted. */
static double
parse_ts(const char *s)
{
	char buf[40], *comma;
	double h = 0.0, m = 0.0, sec = 0.0;
	int consumed = 0;

	/* strtod/sscanf only accept '.' as a decimal separator; SRT uses ','. */
	lws_strncpy(buf, s, sizeof(buf));
	comma = strchr(buf, ',');
	if (comma)
		*comma = '.';

	if (sscanf(buf, "%lf:%lf:%lf%n", &h, &m, &sec, &consumed) >= 3 && consumed > 0)
		return h * 3600.0 + m * 60.0 + sec;
	if (sscanf(buf, "%lf:%lf%n", &m, &sec, &consumed) >= 2 && consumed > 0)
		return m * 60.0 + sec;
	return -1.0;
}

/* Read a whole (small) text file into a malloc'd NUL-terminated buffer. */
static char *
slurp(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	long sz;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0)
		goto err;
	sz = ftell(f);
	if (sz < 0)
		goto err;
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf)
		goto err;
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		buf = NULL;
		goto err;
	}
	buf[sz] = '\0';
	if (out_len)
		*out_len = (size_t)sz;
err:
	fclose(f);
	return buf;
}

/* parse a sidecar file (.srt or .vtt) into cues */
static int
load_sidecar_cues(const char *media_dir, const char *sidecar_name, int is_vtt,
		  struct hls_webvtt_cue **out_cues, int *out_n)
{
	char path[512];
	char *body, *p, *nl;
	struct hls_webvtt_cue *cues = NULL;
	int n = 0, cap = 0, ret = -1;

	snprintf(path, sizeof(path), "%s/%s", media_dir, sidecar_name);
	body = slurp(path, NULL);
	if (!body)
		return -1;

	/* Iterate lines in place, NUL-terminating each and trimming a trailing
	 * '\r'. We walk with strchr('\n') rather than a tokenizer because cue
	 * boundaries in SRT/VTT are blank lines: tokenizers (strtok, and
	 * lws_tokenize, which treats newlines as whitespace to skip) collapse
	 * runs of delimiters and so cannot report the empty lines that delimit
	 * cues. Empty lines are semantically significant here. */
	p = body;
	while (p && *p) {
		char *line = p;
		char *arrow, *endp;
		double start, end;
		char textbuf[4096];
		size_t tlen = 0;

		nl = strchr(p, '\n');
		if (nl) {
			*nl = '\0';
			p = nl + 1;
		} else {
			p = NULL;
		}
		/* strip trailing CR */
		{
			size_t L = strlen(line);
			if (L && line[L - 1] == '\r')
				line[L - 1] = '\0';
		}

		/* vtt: skip header / NOTE / STYLE / REGION blocks.
		 * NOTE blocks run to the next blank line. */
		if (is_vtt) {
			if (!strncmp(line, "WEBVTT", 6))
				continue;
			if (!strncmp(line, "STYLE", 5) || !strncmp(line, "REGION", 6))
				continue;
		}

		/* srt: skip a bare integer (the cue index) */
		if (!is_vtt) {
			int allnum = line[0] != '\0';
			const char *q;
			for (q = line; *q; q++)
				if (!isdigit((unsigned char)*q)) {
					allnum = 0;
					break;
				}
			if (allnum)
				continue;
		}

		/* a cue header must contain the time arrow */
		arrow = strstr(line, "-->");
		if (!arrow)
			continue;
		*arrow = '\0';
		start = parse_ts(line);
		if (start < 0)
			continue;

		/* end time follows "-->"; may carry trailing cue settings
		 * (e.g. "align:start" in vtt) separated by whitespace. */
		endp = arrow + 3;
		while (*endp == ' ' || *endp == '\t')
			endp++;
		{
			char ebuf[64], *sp;
			lws_strncpy(ebuf, endp, sizeof(ebuf));
			sp = strpbrk(ebuf, " \t");
			if (sp)
				*sp = '\0';
			end = parse_ts(ebuf);
			if (end < 0)
				end = start + 2.0;
		}

		/* gather cue body lines until a blank line or end of input */
		textbuf[0] = '\0';
		while (1) {
			char *bline;
			size_t ll, need_nl;

			if (!p || !*p)
				break; /* EOF */
			bline = p;
			nl = strchr(p, '\n');
			if (nl) {
				*nl = '\0';
				p = nl + 1;
			} else {
				p = NULL;
			}
			{
				size_t L = strlen(bline);
				if (L && bline[L - 1] == '\r')
					bline[L - 1] = '\0';
			}
			if (bline[0] == '\0')
				break; /* blank line ends the cue */

			/* vtt NOTE inside a body shouldn't happen, but bail */
			if (is_vtt && (!strncmp(bline, "NOTE", 4) ||
				       !strncmp(bline, "STYLE", 5))) {
				/* skip to next blank line */
				while (p && *p) {
					char *bl = p;
					char *nnl = strchr(p, '\n');
					if (nnl) { *nnl = '\0'; p = nnl + 1; }
					else { p = NULL; }
					{
						size_t L = strlen(bl);
						if (L && bl[L-1] == '\r') bl[L-1]='\0';
					}
					if (bl[0] == '\0') break;
				}
				break;
			}

			ll = strlen(bline);
			need_nl = (tlen > 0) ? 1u : 0u;
			if (tlen + ll + need_nl + 1 > sizeof(textbuf))
				break;
			if (need_nl)
				textbuf[tlen++] = '\n';
			memcpy(textbuf + tlen, bline, ll);
			tlen += ll;
			textbuf[tlen] = '\0';
		}

		/* trim the srt/vtt inline tags like <i>, <b>, <font ...> */
		{
			char *dst = textbuf, *src = textbuf;
			int in_tag = 0;
			while (*src) {
				if (*src == '<') {
					in_tag = 1;
					src++;
				} else if (*src == '>' && in_tag) {
					in_tag = 0;
					src++;
				} else {
					if (!in_tag)
						*dst++ = *src;
					src++;
				}
			}
			*dst = '\0';
		}

		if (textbuf[0] == '\0')
			continue;
		{
			char *dup = strdup(textbuf);
			if (!dup)
				goto sc_err;
			if (push_cue(&cues, &n, &cap, start, end, dup) < 0)
				goto sc_err;
		}
	}

	*out_cues = cues;
	*out_n = n;
	cues = NULL;
	ret = 0;

sc_err:
	free(body);
	free_cues(cues, n);
	return ret;
}

/* ------------------------------------------------------------------ */
/* cue cache (keyed by "<filename>|<trackid>")                         */
/* ------------------------------------------------------------------ */

#define HLS_SUB_CACHE_CAP 8

static int
load_track_cues(struct hls_sub_track *tk, const char *media_dir,
		const char *filename, struct hls_webvtt_cue **out, int *out_n)
{
	if (tk->kind == HLS_SUB_EMBEDDED)
		return load_embedded_cues(media_dir, filename, tk->stream_index,
					  out, out_n);
	return load_sidecar_cues(media_dir, tk->path, tk->is_vtt, out, out_n);
}

/* Returns a borrowed pointer to the cached cue list for (filename, trackid),
 * decoding on first access. Caller must hold vhd->sub_lock. */
static struct hls_sub_cache *
cache_get(struct per_vhost_data__lws_hls *vhd, const char *filename,
	  const char *trackid, struct hls_sub_track *tk, const char *media_dir)
{
	struct hls_sub_cache *c, *prev = NULL;
	char key[sizeof(c->key)];

	snprintf(key, sizeof(key), "%s|%s", filename, trackid);

	for (c = vhd->sub_cache_head; c; prev = c, c = c->next) {
		if (!strcmp(c->key, key)) {
			/* LRU: move to head */
			if (prev) {
				prev->next = c->next;
				c->next = vhd->sub_cache_head;
				vhd->sub_cache_head = c;
			}
			return c;
		}
	}

	/* miss: decode + insert at head, evicting oldest if over cap */
	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	lws_strncpy(c->key, key, sizeof(c->key));
	if (load_track_cues(tk, media_dir, filename, &c->cues, &c->n_cues) < 0) {
		lwsl_notice("HLS-SUB: %s: track %s -> cue decode FAILED\n",
			    filename, trackid);
		free(c);
		return NULL;
	}
	{
		double first = (c->n_cues > 0) ? c->cues[0].start : 0.0;
		double last = (c->n_cues > 0) ? c->cues[c->n_cues - 1].end : 0.0;
		lwsl_notice("HLS-SUB: %s: decoded track %s -> %d cue(s) "
			    "spanning %.2fs..%.2fs\n", filename, trackid,
			    c->n_cues, first, last);
	}
	c->next = vhd->sub_cache_head;
	vhd->sub_cache_head = c;
	vhd->sub_cache_count++;

	while (vhd->sub_cache_count > HLS_SUB_CACHE_CAP &&
	       vhd->sub_cache_head) {
		/* drop the tail */
		struct hls_sub_cache *t = vhd->sub_cache_head, *p2 = NULL;
		while (t->next) {
			p2 = t;
			t = t->next;
		}
		if (p2)
			p2->next = NULL;
		else
			vhd->sub_cache_head = NULL;
		free_cues(t->cues, t->n_cues);
		free(t);
		vhd->sub_cache_count--;
	}

	return c;
}

/* ------------------------------------------------------------------ */
/* shared segment timeline (mirrors serve_manifest's math)             */
/* ------------------------------------------------------------------ */

struct seg_timeline {
	int count;
	int target_duration;
	double *durations; /* count entries, seconds */
};

static void
timeline_free(struct seg_timeline *tl)
{
	free(tl->durations);
	tl->durations = NULL;
	tl->count = 0;
}

/* Open the file, find the video stream, and build the per-segment duration
 * list using the same lws_hls_get_segment_info() the A/V playlist uses. */
static int
build_timeline(struct per_vhost_data__lws_hls *vhd, const char *media_dir,
	       const char *filename, struct seg_timeline *out)
{
	AVFormatContext *ic = NULL;
	char path[512];
	int video_idx = -1, total = 0, i;
	unsigned int ui;
	int ret = -1;

	memset(out, 0, sizeof(*out));
	snprintf(path, sizeof(path), "%s/%s", media_dir, filename);
	if (avformat_open_input(&ic, path, NULL, NULL) < 0)
		return -1;
	if (avformat_find_stream_info(ic, NULL) < 0)
		goto out;

	for (ui = 0; ui < ic->nb_streams; ui++) {
		if (ic->streams[ui]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			video_idx = (int)ui;
			break;
		}
	}
	if (video_idx < 0)
		goto out;

	{
		struct hls_segment_info info;
		memset(&info, 0, sizeof(info));
		info.end_pts = AV_NOPTS_VALUE;
		lws_hls_get_segment_info(vhd, filename, ic, video_idx, 0, &info,
					 &total);
	}

	if (total <= 0) {
		/* fall back to duration / HLS_SEGMENT_DUR like serve_manifest */
		double dur = ic->duration > 0 ? (double)ic->duration /
				(double)AV_TIME_BASE : 0.0;
		total = (int)(dur / (double)HLS_SEGMENT_DUR + 0.999);
		if (total <= 0)
			total = 1;
	}

	out->durations = calloc((size_t)total, sizeof(double));
	if (!out->durations)
		goto out;
	out->count = total;
	out->target_duration = 0;

	for (i = 0; i < total; i++) {
		struct hls_segment_info info;
		double d;
		memset(&info, 0, sizeof(info));
		info.end_pts = AV_NOPTS_VALUE;
		if (lws_hls_get_segment_info(vhd, filename, ic, video_idx, i,
					     &info, NULL) == 0 &&
		    info.duration_sec > 0.0)
			d = info.duration_sec;
		else
			d = (double)HLS_SEGMENT_DUR;
		out->durations[i] = d;
		if ((int)(d + 0.999) > out->target_duration)
			out->target_duration = (int)(d + 0.999);
	}
	if (out->target_duration == 0)
		out->target_duration = HLS_SEGMENT_DUR;

	ret = 0;
out:
	avformat_close_input(&ic);
	if (ret)
		timeline_free(out);
	return ret;
}

/* ------------------------------------------------------------------ */
/* response helpers                                                    */
/* ------------------------------------------------------------------ */

/* printf into a growing-but-fixed buffer safely; see hls_append_fmt() in
 * private-lws-hls.h (shared with hls-dir.c) for why the naive
 * `q += snprintf(q, rem, ...)` cursor pattern is a heap smash. */

/* Stash a body in pss and begin an HTTP response with the given content type
 * and length. The generic LWS_CALLBACK_HTTP_WRITEABLE handler drains it. */
static int
send_body(struct lws *wsi, const char *content_type, const uint8_t *body,
	  size_t len)
{
	struct per_session_data__lws_hls *pss =
			(struct per_session_data__lws_hls *)lws_wsi_user(wsi);
	uint8_t *buf, *start, *p, *end;
	uint8_t *seg;

	if (!pss)
		return -1;

	seg = malloc(LWS_PRE + len);
	if (!seg) {
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}
	memcpy(seg + LWS_PRE, body, len);
	pss->segment_buf = seg;
	pss->segment_len = len;
	pss->segment_pos = 0;

	buf = malloc(LWS_PRE + 2048);
	if (!buf) {
		free(seg);
		pss->segment_buf = NULL;
		return -1;
	}
	start = buf + LWS_PRE;
	p = start;
	end = p + 2048;

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, content_type,
					(lws_filepos_t)len, &p, end)) {
		free(buf);
		return -1;
	}
	if (lws_finalize_write_http_header(wsi, start, &p, end)) {
		free(buf);
		return -1;
	}

	free(buf);
	lws_callback_on_writable(wsi);
	return 0;
}

/* ------------------------------------------------------------------ */
/* manifest / segment rendering                                        */
/* ------------------------------------------------------------------ */

int
lws_hls_serve_stream(struct lws *wsi, const char *media_dir, const char *filename)
{
	struct hls_sub_track *tracks;
	int ntracks;

	tracks = lws_hls_discover_tracks(media_dir, filename, &ntracks);
	if (ntracks == 0 || !tracks) {
		/* no subtitles: behave exactly like the old media playlist */
		lws_hls_free_tracks(tracks, ntracks);
		return lws_hls_serve_manifest(wsi, media_dir, filename);
	}

	/* Build a master playlist.
	 *
	 * hls.js / Safari resolve relative URIs per RFC 3986 against the
	 * playlist URL (/hls/hls/stream/<file>), so "../avstream/<file>"
	 * -> /hls/hls/avstream/<file> and "../subsm/<file>/<id>" likewise.
	 */
	{
		char *buf, *q;
		/* Each MEDIA line repeats the filename twice (NAME may also be
		 * long for untagged tracks) and the STREAM-INF repeats it; size
		 * generously from the actual string lengths rather than a guess. */
		size_t fnlen = strlen(filename);
		size_t cap = 256 + (size_t)ntracks * (320 + fnlen * 2) + fnlen * 2;
		int i, ret;

		buf = malloc(cap);
		if (!buf) {
			lws_hls_free_tracks(tracks, ntracks);
			lws_return_http_status(wsi,
					HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
			return -1;
		}
		q = buf;
		q = hls_append_fmt(q, buf, cap,
			       "#EXTM3U\n"
			       "#EXT-X-VERSION:7\n\n");

		for (i = 0; i < ntracks; i++) {
			q = hls_append_fmt(q, buf, cap,
				"#EXT-X-MEDIA:TYPE=SUBTITLES,"
				"GROUP-ID=\"subs\",NAME=\"%s\","
				"DEFAULT=NO,AUTOSELECT=NO,FORCED=NO,"
				"LANGUAGE=\"%s\",URI=\"../subsm/%s/%s\"\n",
				tracks[i].name, tracks[i].lang, filename,
				tracks[i].id);
		}

		q = hls_append_fmt(q, buf, cap,
			"\n#EXT-X-STREAM-INF:BANDWIDTH=1,AVERAGE-BANDWIDTH=1,"
			"SUBTITLES=\"subs\"\n"
			"../avstream/%s\n",
			filename);

		ret = send_body(wsi, "application/vnd.apple.mpegurl",
				(uint8_t *)buf, (size_t)(q - buf));
		free(buf);
		lws_hls_free_tracks(tracks, ntracks);
		return ret;
	}
}

int
lws_hls_serve_sub_playlist(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
			   const char *media_dir, const char *filename,
			   const char *trackid)
{
	struct hls_sub_track *tracks;
	int ntracks, ti, i;
	struct seg_timeline tl;
	char *buf, *q;
	size_t cap;
	int ret;

	tracks = lws_hls_discover_tracks(media_dir, filename, &ntracks);
	ti = lws_hls_find_track(tracks, ntracks, trackid);
	if (ti < 0) {
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	memset(&tl, 0, sizeof(tl));
	if (build_timeline(vhd, media_dir, filename, &tl) < 0) {
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}

	lwsl_notice("HLS-SUB: %s: sub playlist track=%s -> %d segment(s), "
		    "target_duration=%d\n", filename, trackid, tl.count,
		    tl.target_duration);

	/* Each segment entry embeds the filename once (../../subseg/<file>/<id>/<idx>).
	 * Size from real lengths so long filenames + many segments can't overflow. */
	{
		size_t fnlen = strlen(filename);
		cap = 256 + (size_t)tl.count * (64 + fnlen + 16);
	}
	buf = malloc(cap);
	if (!buf) {
		timeline_free(&tl);
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}
	q = buf;
	q = hls_append_fmt(q, buf, cap,
		"#EXTM3U\n"
		"#EXT-X-VERSION:7\n"
		"#EXT-X-TARGETDURATION:%d\n"
		"#EXT-X-MEDIA-SEQUENCE:0\n"
		"#EXT-X-PLAYLIST-TYPE:VOD\n",
		tl.target_duration);

	/* The sub playlist is at /subsm/<file>/<id>, so segment URIs are
	 * two levels up: ../../subseg/<file>/<id>/<idx>. */
	for (i = 0; i < tl.count; i++) {
		q = hls_append_fmt(q, buf, cap,
			"#EXTINF:%f,\n"
			"../../subseg/%s/%s/%d\n",
			tl.durations[i], filename, trackid, i);
	}
	q = hls_append_fmt(q, buf, cap, "#EXT-X-ENDLIST\n");

	ret = send_body(wsi, "application/vnd.apple.mpegurl",
			(uint8_t *)buf, (size_t)(q - buf));
	free(buf);
	timeline_free(&tl);
	lws_hls_free_tracks(tracks, ntracks);
	return ret;
}

static void
fmt_vtt_ts(char *buf, size_t bufsz, double t)
{
	if (t < 0)
		t = 0;
	unsigned hh = (unsigned)(t / 3600.0);
	unsigned mm = (unsigned)((t - hh * 3600.0) / 60.0);
	unsigned ss_whole = (unsigned)(t - hh * 3600.0 - mm * 60.0);
	unsigned ms = (unsigned)((t - (double)(hh * 3600 + mm * 60 + ss_whole)) * 1000.0);
	if (ms >= 1000) {
		ms -= 1000;
		ss_whole++;
		if (ss_whole >= 60) {
			ss_whole -= 60;
			mm++;
		}
	}
	snprintf(buf, bufsz, "%02u:%02u:%02u.%03u", hh, mm, ss_whole, ms);
}

int
lws_hls_serve_sub_segment(struct lws *wsi, struct per_vhost_data__lws_hls *vhd,
			  const char *media_dir, const char *filename,
			  const char *trackid, int seg_idx)
{
	struct hls_sub_track *tracks;
	int ntracks, ti;
	struct seg_timeline tl;
	struct hls_sub_cache *cache;
	struct lws_buf_s {
		char *p;
		size_t len;
		size_t cap;
	} out = { NULL, 0, 0 };
	double t0 = 0.0, t1 = 0.0;
	int i, ret = -1;
	char ts0[16], ts1[16];

	tracks = lws_hls_discover_tracks(media_dir, filename, &ntracks);
	ti = lws_hls_find_track(tracks, ntracks, trackid);
	if (ti < 0) {
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	memset(&tl, 0, sizeof(tl));
	if (build_timeline(vhd, media_dir, filename, &tl) < 0) {
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR,
				       NULL);
		return -1;
	}
	if (seg_idx < 0 || seg_idx >= tl.count) {
		timeline_free(&tl);
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	/* [t0, t1) = absolute time window of this segment */
	for (i = 0; i <= seg_idx; i++) {
		if (i < seg_idx)
			t0 += tl.durations[i];
		else
			t1 = t0 + tl.durations[i];
	}
	timeline_free(&tl);

	/* fetch / decode cues under the cache lock */
	pthread_mutex_lock(&vhd->sub_lock);
	cache = cache_get(vhd, filename, trackid, &tracks[ti], media_dir);
	if (!cache) {
		pthread_mutex_unlock(&vhd->sub_lock);
		lws_hls_free_tracks(tracks, ntracks);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
	}

	/* Render cues that overlap [t0, t1), rebased to segment-relative
	 * timestamps and clamped to the window. */
	out.cap = 256;
	out.p = malloc(out.cap);
	if (!out.p) {
		pthread_mutex_unlock(&vhd->sub_lock);
		lws_hls_free_tracks(tracks, ntracks);
		return -1;
	}
#define APPEND(s) do { \
	size_t _l = strlen(s); \
	if (out.len + _l + 1 > out.cap) { \
		size_t _nc = out.cap * 2 + _l; \
		char *_np = realloc(out.p, _nc); \
		if (!_np) goto seg_done; \
		out.p = _np; out.cap = _nc; \
	} \
	memcpy(out.p + out.len, s, _l); out.len += _l; out.p[out.len] = '\0'; \
} while (0)
	APPEND("WEBVTT\n");

	/* X-TIMESTAMP-MAP: ties the segment-local WebVTT clock (LOCAL, which
	 * our cues use, rebased to start at 0.000 for each segment) to the
	 * absolute timeline via an MPEGTS (90kHz) anchor at the segment's
	 * start. RFC 8216 §4.3.4.3 requires this; without it hls.js can't map
	 * segment-relative cue times onto the playback timeline and they all
	 * collapse onto the start of the asset. LOCAL:00:00:00.000 maps to
	 * MPEGTS:<segment_start * 90000>, so a cue at local T lands at
	 * absolute (segment_start + T). MPEGTS wraps at 2^33; mask it. */
	{
		char mapline[96];
		int64_t mpegts = (int64_t)(t0 * 90000.0) & INT64_C(0x1ffffffff);
		snprintf(mapline, sizeof(mapline),
			 "X-TIMESTAMP-MAP=MPEGTS:%lld,LOCAL:00:00:00.000\n\n",
			 (long long)mpegts);
		APPEND(mapline);
	}

	{
		int emitted = 0;
		for (i = 0; i < cache->n_cues; i++) {
			struct hls_webvtt_cue *c = &cache->cues[i];
			double cs, ce;
			char header[64];

			if (c->end <= t0 || c->start >= t1)
				continue; /* no overlap */

		cs = c->start - t0;
		if (cs < 0.0)
			cs = 0.0;
		ce = c->end - t0;
		if (ce > (t1 - t0))
			ce = t1 - t0;
		if (ce <= cs)
			continue;

		fmt_vtt_ts(ts0, sizeof(ts0), cs);
		fmt_vtt_ts(ts1, sizeof(ts1), ce);
		snprintf(header, sizeof(header), "%s --> %s\n", ts0, ts1);
		APPEND(header);
		APPEND(c->text ? c->text : "");
		APPEND("\n\n");
		emitted++;
	}

		lwsl_notice("HLS-SUB: %s: sub seg track=%s idx=%d window=[%.2f,%.2f)s "
			    "total_cues=%d emitted=%d body_len=%zu\n",
			    filename, trackid, seg_idx, t0, t1,
			    cache->n_cues, emitted, out.len);
	}

	pthread_mutex_unlock(&vhd->sub_lock);

	ret = send_body(wsi, "text/vtt; charset=\"utf-8\"",
			(uint8_t *)out.p, out.len);
seg_done:
	free(out.p);
	lws_hls_free_tracks(tracks, ntracks);
	return ret;
#undef APPEND
}
