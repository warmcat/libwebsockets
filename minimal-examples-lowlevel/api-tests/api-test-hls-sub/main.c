/*
 * lws-api-test-hls-sub
 *
 * Fences the HLS plugin's WebVTT segments for a subtitle track embedded in
 * the media (hls-sub.c).  Each /subseg/ segment is decoded from just the
 * part of the media around it, the segment before it included, so a cue
 * that started earlier and is still showing is found; decoding the whole
 * file for every segment took minutes on a large one, longer than the
 * player waited, and it never completed.
 *
 * The whole plugin is folded into the test statically (as api-test-hls-dir
 * does).  The fixture media dir is built at runtime with libavformat: a
 * 45s MKV with an MPEG-4 part 2 video track (1s GOP, so five 10s segments)
 * and a SubRip track with four cues:
 *
 *    alpha    2s -  4s		segment 0
 *    bravo   17s - 24s		segment 1, still showing into segment 2
 *    charlie 33s - 35s		segment 3
 *    delta   41s - 42s		segment 4
 *
 * An in-process client fetches the subtitle playlist, then the segments in
 * the order a player that seeks would, the far one first, and asserts each
 * is WebVTT with exactly the cues overlapping its window, rebased to it:
 * bravo must be in segment 2 from 00:00:00.000, although its packet is
 * stored back in segment 1's part of the file.  Segment 2 is fetched again
 * at the end, which the event loop answers from the cache of rendered
 * segments, and must be the same.
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

/* import the whole of the HLS plugin statically */
#include <lws-plugin-hls-static-build-includes.h>

#define FIXTURE_NAME	"sub-test.mkv"
#define FIXTURE_SECS	45
#define FIXTURE_FPS	25
#define SUBS		"/media/subseg/" FIXTURE_NAME "/e1/"

static const struct {
	const char	*text;
	int		start_ms;
	int		end_ms;
} fixture_cues[] = {
	{ "alpha",	 2000,  4000 },
	{ "bravo",	17000, 24000 },
	{ "charlie",	33000, 35000 },
	{ "delta",	41000, 42000 },
};

static struct lws_context *context;
static struct lws *cli_wsi;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_connect;
static int result = 1;
static int tests, fail;

static uint16_t port_hls = 21090;

static char fixture_dir[128];

/* collected response for the request in flight */

static char body[256 * 1024];
static size_t body_len;
static int got_status;
static int done;		/* the request in flight has ended */
static int ended;		/* ... and was reported, once */

static const char *const req_paths[] = {
	"/media/subsm/" FIXTURE_NAME "/e1",
	SUBS "3",	/* a far seek first, nothing decoded yet */
	SUBS "2",
	SUBS "0",
	SUBS "1",
	SUBS "4",
	SUBS "2",	/* again: from the cache of rendered segments */
};

static int req_idx;
static int walk_done, walk_failed;
static char seg2[4096];

/* -------------------------------------------------------------- server */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_hls = LWS_PLUGIN_PROTOCOL_LWS_HLS,
	prot_cli = { "lws-api-test-hls-sub-cli", callback_cli, 0, 0, 0, NULL, 0 };

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
		if (body_len + len >= sizeof(body)) {
			lwsl_err("%s: body overran collection buffer\n",
				 __func__);
			return -1;
		}
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection error: %s\n", __func__,
			 in ? (const char *)in : "?");
		walk_failed = 1;
		/* fallthru */
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* whichever comes first ends the request */
		if (!ended)
			ended = done = 1;
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------ fixtures */

static int
write_video_pkts(AVFormatContext *oc, AVCodecContext *vc, AVStream *vs,
		 AVPacket *pkt)
{
	while (!avcodec_receive_packet(vc, pkt)) {
		av_packet_rescale_ts(pkt, vc->time_base, vs->time_base);
		pkt->stream_index = vs->index;
		if (av_interleaved_write_frame(oc, pkt) < 0)
			return -1;
		av_packet_unref(pkt);
	}

	return 0;
}

/*
 * <fixture_dir>/sub-test.mkv, MPEG-4 part 2 video with 1s keyframes as
 * stream 0 and the SubRip cues above as stream 1.  Returns 0 if the file is
 * there.
 */
static int
build_fixture_media(void)
{
	char path[384];
	AVFormatContext *oc = NULL;
	AVCodecContext *vc = NULL;
	const AVCodec *vc_enc;
	AVStream *vs, *ss;
	AVFrame *vframe = NULL;
	AVPacket *pkt = NULL;
	int n_video = 0, next_cue = 0, ret = 1, v;

	/* lives in /tmp so it works from any cwd; mkdtemp gives it an
	 * unpredictable, owner-private name */
	lws_strncpy(fixture_dir, "/tmp/lws-hls-sub-test-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));

	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		return 1;
	}
	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);

	vc_enc = avcodec_find_encoder(AV_CODEC_ID_MPEG4);
	if (!vc_enc) {
		lwsl_err("%s: no mpeg4 encoder in this libavcodec\n", __func__);
		goto out;
	}

	if (avformat_alloc_output_context2(&oc, NULL, NULL, path) < 0 || !oc)
		goto out;

	vs = avformat_new_stream(oc, NULL);
	ss = avformat_new_stream(oc, NULL);
	if (!vs || !ss)
		goto out;

	vc = avcodec_alloc_context3(vc_enc);
	if (!vc)
		goto out;
	vc->width = 320;
	vc->height = 240;
	vc->time_base = (AVRational){ 1, FIXTURE_FPS };
	vc->framerate = (AVRational){ FIXTURE_FPS, 1 };
	vc->pix_fmt = AV_PIX_FMT_YUV420P;
	vc->bit_rate = 200000;
	vc->gop_size = FIXTURE_FPS;	/* a keyframe every second */
	if (avcodec_open2(vc, vc_enc, NULL) < 0)
		goto out;
	vs->time_base = vc->time_base;
	avcodec_parameters_from_context(vs->codecpar, vc);

	ss->codecpar->codec_type = AVMEDIA_TYPE_SUBTITLE;
	ss->codecpar->codec_id = AV_CODEC_ID_SUBRIP;
	ss->time_base = (AVRational){ 1, 1000 };
	av_dict_set(&ss->metadata, "language", "eng", 0);

	if (avio_open(&oc->pb, path, AVIO_FLAG_WRITE) < 0)
		goto out;
	if (avformat_write_header(oc, NULL) < 0)
		goto out;

	vframe = av_frame_alloc();
	pkt = av_packet_alloc();
	if (!vframe || !pkt)
		goto out;
	vframe->format = vc->pix_fmt;
	vframe->width = vc->width;
	vframe->height = vc->height;
	if (av_frame_get_buffer(vframe, 32) < 0)
		goto out;

	while (n_video < FIXTURE_SECS * FIXTURE_FPS) {
		int64_t now_ms = (int64_t)n_video * 1000 / FIXTURE_FPS;

		/* the cues that start by now, stored where they start */
		while (next_cue < (int)LWS_ARRAY_SIZE(fixture_cues) &&
		       fixture_cues[next_cue].start_ms <= now_ms) {
			const char *t = fixture_cues[next_cue].text;

			if (av_new_packet(pkt, (int)strlen(t)) < 0)
				goto out;
			memcpy(pkt->data, t, strlen(t));
			pkt->pts = pkt->dts = fixture_cues[next_cue].start_ms;
			pkt->duration = fixture_cues[next_cue].end_ms -
					fixture_cues[next_cue].start_ms;
			pkt->stream_index = ss->index;
			pkt->flags |= AV_PKT_FLAG_KEY;
			if (av_interleaved_write_frame(oc, pkt) < 0)
				goto out;
			av_packet_unref(pkt);
			next_cue++;
		}

		/* one grey-ramping video frame */
		if (av_frame_make_writable(vframe) < 0)
			goto out;
		memset(vframe->data[0], (n_video * 3) & 0xff,
		       (size_t)(vframe->linesize[0] * vframe->height));
		for (v = 1; v < 3; v++)
			memset(vframe->data[v], 128,
			       (size_t)(vframe->linesize[v] *
					vframe->height >> 1));
		vframe->pts = n_video++;

		if (avcodec_send_frame(vc, vframe) < 0 ||
		    write_video_pkts(oc, vc, vs, pkt))
			goto out;
	}

	/* drain the encoder */
	avcodec_send_frame(vc, NULL);
	if (write_video_pkts(oc, vc, vs, pkt))
		goto out;

	if (av_write_trailer(oc) < 0)
		goto out;
	avio_closep(&oc->pb);

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

	lwsl_notice("%s: wrote %s (%d video frames, %d cues)\n", __func__,
		    path, n_video, next_cue);

out:
	av_packet_free(&pkt);
	av_frame_free(&vframe);
	if (vc)
		avcodec_free_context(&vc);
	if (oc) {
		if (oc->pb)
			avio_closep(&oc->pb);
		avformat_free_context(oc);
	}
	if (ret)
		unlink(path);

	return ret;
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
			if (!strcmp(de->d_name, ".") ||
			    !strcmp(de->d_name, ".."))
				continue;
			lws_snprintf(ent, sizeof(ent), "%s/%s", dir,
				     de->d_name);
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

	/* the keyframe index the plugin persisted next to the media */
	lws_snprintf(path, sizeof(path), "%s/.index", fixture_dir);
	remove_dir_files(path);
	remove_dir_files(fixture_dir);
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

/*
 * A subtitle segment must be WebVTT anchored to its start, carrying the cue
 * line "<from> --> <to>\n<text>" for each fixture cue overlapping it, and no
 * other cue
 */
static void
check_segment(int seg, const char *b, const char *const *want)
{
	char name[96], line[128];
	size_t n;
	int wanted;

	lws_snprintf(name, sizeof(name), "seg%d: WebVTT", seg);
	expect(name, !strncmp(b, "WEBVTT\n", 7) &&
		     !!strstr(b, "X-TIMESTAMP-MAP=MPEGTS:"));

	for (n = 0; n < LWS_ARRAY_SIZE(fixture_cues); n++) {
		const char *const *w;

		wanted = 0;
		for (w = want; *w; w += 2)
			if (!strcmp(*w, fixture_cues[n].text)) {
				lws_snprintf(line, sizeof(line), "%s\n%s\n",
					     w[1], *w);
				wanted = 1;
				break;
			}

		lws_snprintf(name, sizeof(name), "seg%d: %s %s", seg,
			     wanted ? "has" : "lacks", fixture_cues[n].text);
		if (wanted)
			expect(name, !!strstr(b, line));
		else
			expect(name, !strstr(b, fixture_cues[n].text));
	}
}

static void
check_request(int idx, int status, const char *b, size_t bl)
{
	/* the expected cues, rebased and clamped to each 10s segment */
	static const char *const want0[] = {
		"alpha", "00:00:02.000 --> 00:00:04.000", NULL },
	*const want1[] = {
		"bravo", "00:00:07.000 --> 00:00:10.000", NULL },
	*const want2[] = {
		"bravo", "00:00:00.000 --> 00:00:04.000", NULL },
	*const want3[] = {
		"charlie", "00:00:03.000 --> 00:00:05.000", NULL },
	*const want4[] = {
		"delta", "00:00:01.000 --> 00:00:02.000", NULL };
	char name[64];

	lws_snprintf(name, sizeof(name), "%s: HTTP 200", req_paths[idx]);
	expect(name, status == HTTP_STATUS_OK);
	if (status != HTTP_STATUS_OK) {
		lwsl_err("%s: %s -> %d\n", __func__, req_paths[idx], status);
		return;
	}

	lwsl_notice("%s: %s:\n%s\n", __func__, req_paths[idx], b);

	switch (idx) {
	case 0:	/* the subtitle playlist: five segments */
		expect("playlist: five segments", !!strstr(b, "e1/4\n") &&
						  !strstr(b, "e1/5\n"));
		break;
	case 1:
		check_segment(3, b, want3);
		break;
	case 2:
		check_segment(2, b, want2);
		lws_strncpy(seg2, b, sizeof(seg2));
		break;
	case 3:
		check_segment(0, b, want0);
		break;
	case 4:
		check_segment(1, b, want1);
		break;
	case 5:
		check_segment(4, b, want4);
		break;
	case 6:
		expect("seg2 again: the same", bl < sizeof(seg2) &&
						 !strcmp(b, seg2));
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------ sequencing */

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: timed out\n", __func__);
	walk_failed = 1;
	lws_default_loop_exit(context);
}

static void
next_step_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	(void)sul;

	lwsl_notice("%s: fetching %s\n", __func__, req_paths[req_idx]);

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= req_paths[req_idx];
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-sub-cli";
	i.pwsi			= &cli_wsi;

	body_len = 0;
	body[0] = '\0';
	got_status = 0;
	done = ended = 0;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		walk_failed = 1;
		lws_default_loop_exit(context);
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
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	{
		const char *p = lws_cmdline_option(argc, argv, "-p");
		if (p)
			port_hls = (uint16_t)atoi(p);
	}

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);

	if (lws_cmdline_option(argc, argv, "--lws-stub="))
		return run_stub(&info);

	lwsl_user("LWS API selftest: HLS embedded subtitle segments\n");

	if (build_fixture_media())
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

	while (n >= 0 && !walk_done && !walk_failed) {
		n = lws_service(context, 0);

		if (done) {
			check_request(req_idx, got_status, body, body_len);
			req_idx++;
			done = 0;
			if (req_idx >= (int)LWS_ARRAY_SIZE(req_paths)) {
				walk_done = 1;
				break;
			}
			lws_sul_schedule(context, 0, &sul_connect,
					 next_step_cb, 50 * LWS_US_PER_MS);
		}
	}

	lws_sul_cancel(&sul_timeout);

	expect("walked every request", walk_done && !walk_failed);

	result = !!fail;

bail:
	lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
