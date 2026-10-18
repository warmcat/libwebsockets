/*
 * lws-api-test-hls-latestream
 *
 * Fences G-048 in the HLS plugin's segment builder
 * (lws_hls_build_segment()): its input -> output stream map is sized from
 * nb_streams after avformat_find_stream_info(), but that count is not
 * final.  Demuxers flagged AVFMTCTX_NOHEADER (mpegts, flv, ...) add an
 * AVStream whenever a new elementary stream first shows up, anywhere in
 * the file, and av_read_frame() then returns packets whose stream_index is
 * past the end of the map.  The builder used that index unchecked, reading
 * past the map's heap allocation and using whatever it found to index
 * out_ctx->streams[] and write the packet dts into a stack array.
 *
 * The whole plugin is folded into the test statically (as api-test-hls-dir
 * does).  The fixture is built at runtime with libavformat: an MPEG-TS
 * in three parts, each with its own PMT version, carrying
 *
 *  - [0, LATE_SECS): only an MPEG-4 part 2 video stream,
 *  - [LATE_SECS, GONE_SECS): the video plus an MP2 audio stream,
 *  - [GONE_SECS, FIXTURE_SECS): only the video again.
 *
 * find_stream_info() probes the start of the file and, for mpegts, also
 * reads the tail to estimate the duration, so the audio has to be absent
 * from both for it to be "late".  The last part carries noise, so it is
 * several times the size of the tail the duration estimate reads.  The file
 * is named .mkv, since that is what the plugin lists and serves, and the
 * framing check leaves content that is not matroska to libavformat.
 *
 * The test first confirms the fixture has the shape it needs (one stream
 * after the probe, a packet of a second stream later), so it cannot pass
 * vacuously on a libavformat that behaves differently.  An in-process
 * client then fetches the playlist and every segment it lists, which
 * between them cover the whole timeline including the point the new
 * stream appears, and asserts each answers 200, with media in at least
 * one.  Under ASan, the unfixed builder aborts on the segment spanning
 * LATE_SECS.
 *
 * How the plugin divides an mpegts timeline into segments is not pinned
 * here: it is not a container the plugin claims to serve, and its index
 * for it is the sparse one libavformat keeps, so the split (and a near
 * empty trailing segment) may change without that mattering to G-048.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>

/* import the whole of the HLS plugin statically */
#include <lws-plugin-hls-static-build-includes.h>

#define FIXTURE_NAME	"late-stream.mkv"
#define FIXTURE_SECS	26	/* segments 0, 1, 2 at HLS_SEGMENT_DUR 10s */
#define LATE_SECS	12	/* the audio stream first appears here... */
#define GONE_SECS	20	/* ...and is not in the PMT from here on */
#define LATE_FPS	25

static struct lws_context *context;
static struct lws *cli_wsi;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_connect;
static int result = 1;
static int tests, fail;

static uint16_t port_hls = 21090;

static char fixture_dir[128];

/*
 * Collected response for the request in flight: the playlist whole, and
 * for segments the head (to check the box type) and the total length
 */

static char body[64 * 1024];
static size_t body_len, body_kept;
static int got_status;
static int done;		/* 1 = completed, -1 = failed */

/* req_idx -1 is the playlist, then 0 .. n_segs - 1 the segments it lists */
static int req_idx = -1, n_segs, n_media_segs;
static int walk_done, walk_failed;

/* -------------------------------------------------------------- server */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_hls = LWS_PLUGIN_PROTOCOL_LWS_HLS,
	prot_cli = { "lws-api-test-hls-latestream-cli", callback_cli, 0, 0, 0,
		     NULL, 0 };

static const struct lws_protocols
	*pprotocols_hls[] = { &defprot, &prot_hls, NULL },
	*pprotocols_cli[]  = { &defprot, &prot_cli, NULL };

/*
 * We composed the plugin into ourselves: tell lws, so it runs the plugin's
 * one-time init and deinit for our copy, and ignores any copy of the same
 * plugin built into lws or found as a dlopenable plugin
 */
static const lws_plugin_protocol_t * const composed_plugins[] = {
	&lws_hls, NULL
};

static const struct lws_http_mount
	mount_hls = {
		.mountpoint		= "/media",
		.protocol		= "lws-hls",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 6,
	};

/* pvo chain handing the plugin its fixture media dir */
static struct lws_protocol_vhost_options
	pvo_hls		= { NULL, NULL, "lws-hls", NULL },
	pvo_media_dir	= { NULL, NULL, "media-dir", NULL };

/* -------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		got_status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buffer[4096 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int alen = (int)sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_kept + len < sizeof(body)) {
			memcpy(body + body_kept, in, len);
			body_kept += len;
			body[body_kept] = '\0';
		}
		body_len += len;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		done = 1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection error: %s\n", __func__,
			 in ? (const char *)in : "?");
		done = -1;
		walk_failed = 1;
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------ fixtures */

/* encoder packet out to whichever mpegts mux currently owns that stream */
static int
mux_packet(AVFormatContext *oc, AVPacket *pkt, AVRational enc_tb, int idx)
{
	av_packet_rescale_ts(pkt, enc_tb, oc->streams[idx]->time_base);
	pkt->stream_index = idx;

	return av_interleaved_write_frame(oc, pkt);
}

/*
 * Open an mpegts mux writing to the shared pb, with a video stream and,
 * for the second part, an audio stream.  tables_version makes the second
 * part's PMT a new version, which is what tells a demuxer to re-read it.
 */
static AVFormatContext *
open_ts_part(AVIOContext *pb, const AVCodecContext *vc,
	     const AVCodecContext *ac, int tables_version)
{
	AVFormatContext *oc = NULL;
	AVDictionary *opts = NULL;
	AVStream *st;
	char tv[8];

	if (avformat_alloc_output_context2(&oc, NULL, "mpegts", NULL) < 0 ||
	    !oc)
		return NULL;

	st = avformat_new_stream(oc, NULL);
	if (!st)
		goto bail;
	st->time_base = vc->time_base;
	avcodec_parameters_from_context(st->codecpar, vc);

	if (ac) {
		st = avformat_new_stream(oc, NULL);
		if (!st)
			goto bail;
		st->time_base = (AVRational){ 1, ac->sample_rate };
		avcodec_parameters_from_context(st->codecpar, ac);
	}

	oc->pb = pb;
	lws_snprintf(tv, sizeof(tv), "%d", tables_version);
	av_dict_set(&opts, "tables_version", tv, 0);
	if (avformat_write_header(oc, &opts) < 0) {
		av_dict_free(&opts);
		goto bail;
	}
	av_dict_free(&opts);

	return oc;

bail:
	oc->pb = NULL;
	avformat_free_context(oc);

	return NULL;
}

static void
close_ts_part(AVFormatContext **oc)
{
	if (!*oc)
		return;
	av_write_trailer(*oc);
	(*oc)->pb = NULL;	/* shared: the caller closes it */
	avformat_free_context(*oc);
	*oc = NULL;
}

/*
 * <fixture_dir>/late-stream.mkv: MPEG-TS, MPEG-4 part 2 video with 1s
 * keyframes throughout, and an MP2 stereo stream only in
 * [LATE_SECS, GONE_SECS), which the first PMT does not mention.  Returns
 * 0 if the file is there.
 */
static int
build_fixture_media(void)
{
	AVFormatContext *oc = NULL;
	AVCodecContext *vc = NULL, *ac = NULL;
	const AVCodec *vc_enc, *ac_enc;
	AVFrame *vframe = NULL, *aframe = NULL;
	AVIOContext *pb = NULL;
	AVPacket *pkt = NULL;
	int64_t next_audio_pts;
	int n_video = 0, ret = 1, with_audio = 0, v;
	uint32_t noise = 0x12345678;
	char path[384];

	/* lives in /tmp so it works from any cwd; mkdtemp gives it an
	 * unpredictable, owner-private name */
	lws_strncpy(fixture_dir, "/tmp/lws-hls-latestream-test-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));

	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		return 1;
	}
	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);

	vc_enc = avcodec_find_encoder(AV_CODEC_ID_MPEG4);
	ac_enc = avcodec_find_encoder(AV_CODEC_ID_MP2);
	if (!vc_enc || !ac_enc) {
		lwsl_err("%s: no mpeg4/mp2 encoder in this libavcodec\n",
			 __func__);
		goto out;
	}

	vc = avcodec_alloc_context3(vc_enc);
	if (!vc)
		goto out;
	vc->width = 320;
	vc->height = 240;
	vc->time_base = (AVRational){ 1, LATE_FPS };
	vc->framerate = (AVRational){ LATE_FPS, 1 };
	vc->pix_fmt = AV_PIX_FMT_YUV420P;
	vc->bit_rate = 200000;
	vc->gop_size = LATE_FPS;	/* a keyframe every second */
	vc->max_b_frames = 0;
	if (avcodec_open2(vc, vc_enc, NULL) < 0)
		goto out;

	ac = avcodec_alloc_context3(ac_enc);
	if (!ac)
		goto out;
	ac->sample_rate = 48000;
	ac->sample_fmt = AV_SAMPLE_FMT_S16;
	ac->bit_rate = 128000;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
	av_channel_layout_default(&ac->ch_layout, 2);
#else
	ac->channels = 2;
	ac->channel_layout = AV_CH_LAYOUT_STEREO;
#endif
	if (avcodec_open2(ac, ac_enc, NULL) < 0)
		goto out;
	next_audio_pts = (int64_t)LATE_SECS * ac->sample_rate;

	if (avio_open(&pb, path, AVIO_FLAG_WRITE) < 0)
		goto out;

	oc = open_ts_part(pb, vc, NULL, 0);
	if (!oc)
		goto out;

	vframe = av_frame_alloc();
	aframe = av_frame_alloc();
	pkt = av_packet_alloc();
	if (!vframe || !aframe || !pkt)
		goto out;

	vframe->format = vc->pix_fmt;
	vframe->width = vc->width;
	vframe->height = vc->height;
	if (av_frame_get_buffer(vframe, 32) < 0)
		goto out;

	aframe->format = ac->sample_fmt;
	aframe->sample_rate = ac->sample_rate;
	aframe->nb_samples = ac->frame_size;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
	av_channel_layout_copy(&aframe->ch_layout, &ac->ch_layout);
#else
	aframe->channels = ac->channels;
	aframe->channel_layout = ac->channel_layout;
#endif
	if (av_frame_get_buffer(aframe, 0) < 0)
		goto out;

	while (n_video < FIXTURE_SECS * LATE_FPS) {

		if (n_video == LATE_SECS * LATE_FPS ||
		    n_video == GONE_SECS * LATE_FPS) {
			/*
			 * The next part, with a new PMT version: the audio
			 * comes, then goes.  The MP2 encoder holds nothing
			 * back (one packet per frame), so there is no audio
			 * to drain when it goes.
			 */
			with_audio = n_video == LATE_SECS * LATE_FPS;
			close_ts_part(&oc);
			oc = open_ts_part(pb, vc, with_audio ? ac : NULL,
					  with_audio ? 1 : 2);
			if (!oc)
				goto out;
		}

		/* one video frame: a grey ramp, with noise in the tail */
		if (av_frame_make_writable(vframe) < 0)
			goto out;
		memset(vframe->data[0], (n_video * 3) & 0xff,
		       (size_t)(vframe->linesize[0] * vframe->height));
		if (n_video >= GONE_SECS * LATE_FPS)
			/* the top quarter: enough to make the tail big */
			for (v = 0; v < vframe->linesize[0] * vframe->height / 4;
			     v++) {
				noise = noise * 1664525u + 1013904223u;
				vframe->data[0][v] = (uint8_t)(noise >> 24);
			}
		for (v = 1; v < 3; v++)
			memset(vframe->data[v], 128,
			       (size_t)(vframe->linesize[v] * vframe->height >> 1));
		vframe->pts = n_video++;

		if (avcodec_send_frame(vc, vframe) < 0)
			goto out;
		while (!avcodec_receive_packet(vc, pkt)) {
			if (mux_packet(oc, pkt, vc->time_base, 0) < 0)
				goto out;
			av_packet_unref(pkt);
		}

		if (!with_audio)
			continue;

		/* the audio that goes with the frames so far */
		while (next_audio_pts <
		       (int64_t)n_video * ac->sample_rate / LATE_FPS) {
			int16_t *s = (int16_t *)aframe->data[0];
			int i;

			if (av_frame_make_writable(aframe) < 0)
				goto out;
			for (i = 0; i < aframe->nb_samples; i++) {
				double t = (double)(next_audio_pts + i) /
					   ac->sample_rate;

				s[2 * i] = s[2 * i + 1] = (int16_t)
					(8000 * sin(2 * M_PI * 440 * t));
			}
			aframe->pts = next_audio_pts;
			next_audio_pts += aframe->nb_samples;

			if (avcodec_send_frame(ac, aframe) < 0)
				goto out;
			while (!avcodec_receive_packet(ac, pkt)) {
				if (mux_packet(oc, pkt, (AVRational){ 1,
						ac->sample_rate }, 1) < 0)
					goto out;
				av_packet_unref(pkt);
			}
		}
	}

	/* drain the video encoder into the last part */
	avcodec_send_frame(vc, NULL);
	while (!avcodec_receive_packet(vc, pkt)) {
		mux_packet(oc, pkt, vc->time_base, 0);
		av_packet_unref(pkt);
	}
	close_ts_part(&oc);
	avio_closep(&pb);

	/*
	 * The plugin builds nothing from media written in the last
	 * HLS_MEDIA_SETTLE_SECS (it may be a copy still going on): make
	 * ours look like it has been sitting there a while
	 */
	{
		struct timeval tv[2];

		gettimeofday(&tv[0], NULL);
		tv[0].tv_sec -= 3600;
		tv[1] = tv[0];
		if (utimes(path, tv))
			goto out;
	}
	ret = 0;

	{
		struct stat st;

		if (!stat(path, &st))
			lwsl_notice("%s: wrote %s (%d video frames, %lld bytes)\n",
				    __func__, path, n_video,
				    (long long)st.st_size);
	}

out:
	av_packet_free(&pkt);
	av_frame_free(&vframe);
	av_frame_free(&aframe);
	close_ts_part(&oc);
	if (pb)
		avio_closep(&pb);
	if (vc)
		avcodec_free_context(&vc);
	if (ac)
		avcodec_free_context(&ac);
	if (ret)
		unlink(path);

	return ret;
}

/*
 * The fixture is only a test of anything if libavformat reports a single
 * stream after the probe and then hands back a packet of another one
 */
static int
fixture_has_late_stream(void)
{
	AVFormatContext *ic = NULL;
	unsigned int probed;
	char path[384];
	AVPacket pkt;
	int late = 0;

	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);

	if (avformat_open_input(&ic, path, NULL, NULL) < 0)
		return 0;
	if (avformat_find_stream_info(ic, NULL) < 0) {
		avformat_close_input(&ic);
		return 0;
	}

	probed = ic->nb_streams;
	while (!late && av_read_frame(ic, &pkt) >= 0) {
		if (pkt.stream_index >= 0 &&
		    (unsigned int)pkt.stream_index >= probed)
			late = 1;
		av_packet_unref(&pkt);
	}
	avformat_close_input(&ic);

	lwsl_notice("%s: %u stream(s) after probe, later stream seen: %d\n",
		    __func__, probed, late);

	return probed == 1 && late;
}

/* empty one directory of plain files, then remove it */
static void
remove_dir_files(const char *dir)
{
	struct dirent *de;
	char ent[600];
	DIR *d;

	d = opendir(dir);
	if (d) {
		while ((de = readdir(d))) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			lws_snprintf(ent, sizeof(ent), "%s/%s", dir, de->d_name);
			unlink(ent);
		}
		closedir(d);
	}
	rmdir(dir);
}

static void
remove_fixture_dir(void)
{
	char path[512];

	if (!fixture_dir[0])
		return;

	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);
	unlink(path);

	/* the keyframe index the plugin persisted next to the media */
	lws_snprintf(path, sizeof(path), "%s/.index", fixture_dir);
	remove_dir_files(path);
	/* nothing here needs an audio shadow, but be sure */
	lws_snprintf(path, sizeof(path), "%s/.atrans", fixture_dir);
	remove_dir_files(path);

	rmdir(fixture_dir);
}

/* ------------------------------------------------------------ assertions */

static void
expect(const char *name, int cond)
{
	tests++;
	if (!cond) {
		fail++;
		lwsl_err("FAIL: %s\n", name);
	}
}

static void
check_request(int idx, int status, const char *b, size_t kept, size_t bl)
{
	const char *q;

	if (idx < 0) {
		/* the playlist: how many segments does it list? */
		expect("playlist: HTTP 200", status == HTTP_STATUS_OK);
		expect("playlist: complete", kept == bl &&
					     !!strstr(b, "#EXT-X-ENDLIST"));
		for (q = b; (q = strstr(q, "#EXTINF:")); q++)
			n_segs++;
		lwsl_notice("%s: playlist lists %d segment(s)\n", __func__,
			    n_segs);
		expect("playlist: lists segments", n_segs > 0);
		return;
	}

	lwsl_notice("%s: segment %d: status %d, %zu bytes\n", __func__, idx,
		    status, bl);
	expect("segment: HTTP 200", status == HTTP_STATUS_OK);
	if (kept > 12 && !memcmp(b + 4, "moof", 4))
		n_media_segs++;
}

/* ------------------------------------------------------------ sequencing */

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: timed out\n", __func__);
	expect("walk finished in time", 0);
	walk_done = 1;
	lws_cancel_service(context);
}

static void
next_step_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	char path[128];

	(void)sul;

	if (req_idx < 0)
		lws_snprintf(path, sizeof(path), "/media/stream/" FIXTURE_NAME);
	else
		lws_snprintf(path, sizeof(path), "/media/segment/"
			     FIXTURE_NAME "/%d", req_idx);

	lwsl_notice("%s: fetching %s\n", __func__, path);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= path;
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-latestream-cli";
	i.pwsi			= &cli_wsi;

	body_len = body_kept = 0;
	body[0] = '\0';
	got_status = 0;
	done = 0;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		walk_failed = 1;
		done = -1;
	}
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

/*
 * We are the plugin's stub child (LWS_WITH_STUB): the plugin in the parent
 * re-ran this executable with --lws-stub=lws-hls-stub.  We never ask it to
 * delete anything, but it must come up and wait for the parent to go away,
 * not run the test again.  The plugin's init does the stub side.
 */
static int
run_stub(struct lws_context_creation_info *info)
{
	int n = 0;

	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info->plugins = composed_plugins;

	context = lws_create_context(info);
	if (!context)
		return 1;

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	p = lws_cmdline_option(argc, argv, "-p");
	if (p)
		port_hls = (uint16_t)atoi(p);

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);

	if (lws_cmdline_option(argc, argv, "--lws-stub="))
		return run_stub(&info);

	lwsl_user("LWS API selftest: HLS segment with a stream added mid-file\n");

	if (build_fixture_media())
		goto bail;

	expect("fixture: a stream appears after the probe",
	       fixture_has_late_stream());
	if (fail)
		goto bail;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.plugins = composed_plugins;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		goto bail;
	}

	/* HLS vhost serving the fixture media dir */
	pvo_media_dir.value	= fixture_dir;
	pvo_hls.options		= &pvo_media_dir;

	info.port		= port_hls;
	info.vhost_name		= "hls";
	info.pprotocols		= pprotocols_hls;
	info.mounts		= &mount_hls;
	info.pvo		= &pvo_hls;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create hls vhost\n");
		goto bail;
	}

	/* client vhost: no listener */
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.pprotocols		= pprotocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 90 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_connect, next_step_cb,
			 100 * LWS_US_PER_MS);

	while (n >= 0 && !walk_done) {
		n = lws_service(context, 0);

		if (!done)
			continue;

		check_request(req_idx, done > 0 ? got_status : 0, body,
			      body_kept, body_len);
		req_idx++;
		done = 0;
		if (walk_failed || req_idx >= n_segs) {
			walk_done = 1;
			break;
		}
		lws_sul_schedule(context, 0, &sul_connect, next_step_cb,
				 100 * LWS_US_PER_MS);
	}

	lws_sul_cancel(&sul_timeout);

	expect("every segment answered", n_segs > 0 && req_idx == n_segs);
	expect("moof-led media in the segments", n_media_segs > 0);

	result = !!fail;

bail:
	if (context)
		lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
