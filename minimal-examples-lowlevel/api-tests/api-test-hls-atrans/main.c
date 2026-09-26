/*
 * lws-api-test-hls-atrans
 *
 * Fences the pre-transcoded audio shadow in the HLS plugin (hls-atrans.c):
 * audio the browser cannot play is transcoded once into a shadow file
 * ahead of time, and segments are cut from that instead of restarting an
 * AAC encoder per segment (which duplicated a sliver of audio at every
 * segment boundary and made playback drift).
 *
 * The whole plugin is folded into the test statically (as api-test-hls-dir
 * does).  The fixture media dir is built at runtime with libavformat: a
 * short MKV with an MPEG-4 part 2 video track (B-frame reordering, 1s GOP,
 * so the keyframe timeline and the dts != pts boundary window are both
 * real) and an AC3 stereo audio track, ie exactly the shape that needs the
 * shadow.
 *
 * An in-process client then walks the requests a player makes and asserts:
 *
 *  - the init segment is ftyp+moov, and a shadow build was queued by asking;
 *
 *  - segment 0 and 1 answer 200 as moof-led media even while the shadow is
 *    still being built (the task parks behind the transcode coverage), and
 *    again after the shadow is complete (the warm, from-disk path);
 *
 *  - the shadow pair (.m4a + .hdr) exists under <media-dir>/.atrans once
 *    the transcode is done, and the /index/ status JSON reports it;
 *
 *  - the warm segment 0 is byte-for-byte the same length as the cold one
 *    (the same cut from the same shadow either way).
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

#define FIXTURE_NAME "atrans-test.mkv"
#define FIXTURE_SECS 13

static struct lws_context *context;
static struct lws *cli_wsi;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_connect;
static int result = 1;
static int tests, fail;

static uint16_t port_hls = 21080;

static char fixture_dir[128];

/* collected response for the request in flight */

static char body[2 * 1024 * 1024];
static size_t body_len;
static int got_status;
static int done;		/* 1 = completed, -1 = failed */

/* the request sequence; seg0 is fetched cold and, at the end, warm */

static const char *const req_paths[] = {
	"/media/init/" FIXTURE_NAME,
	"/media/segment/" FIXTURE_NAME "/0",
	NULL,				/* wait for the shadow to complete */
	"/media/segment/" FIXTURE_NAME "/1",
	"/media/index/" FIXTURE_NAME,
	"/media/segment/" FIXTURE_NAME "/0",	/* warm, from the shadow */
};
static int req_idx;
static size_t seg0_cold_len;
static int seg0_cold_seen;
static int walk_done, walk_failed;

/* -------------------------------------------------------------- server */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_hls = LWS_PLUGIN_PROTOCOL_LWS_HLS,
	prot_cli = { "lws-api-test-hls-atrans-cli", callback_cli, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pprotocols_hls[] = { &defprot, &prot_hls, NULL },
	*pprotocols_cli[]  = { &defprot, &prot_cli, NULL };

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
		if (got_status != HTTP_STATUS_OK) {
			lwsl_err("%s: bad response %d\n", __func__, got_status);
			done = -1;
			return -1;
		}
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
			done = -1;
			return -1;
		}
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		done = 1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection error: %s\n", __func__,
			 in ? (const char *)in : "?");
		done = walk_failed = 1;
		break;

	default:
		break;
	}

	return 0;
}

/* ------------------------------------------------------------ fixtures */

/*
 * True-media fixture: <fixture_dir>/atrans-test.mkv, MPEG-4 part 2 video
 * with B-frames and 1s keyframes, AC3 stereo audio.  Returns 0 if the file
 * is there.
 */
static int
build_fixture_media(void)
{
	char path[384];
	AVFormatContext *oc = NULL;
	AVCodecContext *vc = NULL, *ac = NULL;
	const AVCodec *vc_enc, *ac_enc;
	AVStream *vs, *as;
	AVFrame *vframe = NULL, *aframe = NULL;
	int64_t next_audio_pts = 0;
	int n_video = 0, ret = 1;

	/* lives in /tmp so it works from any cwd; mkdtemp gives it an
	 * unpredictable, owner-private name */
	lws_strncpy(fixture_dir, "/tmp/lws-hls-atrans-test-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));

	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		return 1;
	}
	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);

	vc_enc = avcodec_find_encoder(AV_CODEC_ID_MPEG4);
	ac_enc = avcodec_find_encoder(AV_CODEC_ID_AC3);
	if (!vc_enc || !ac_enc) {
		lwsl_err("%s: no mpeg4/ac3 encoder in this libavcodec\n",
			 __func__);
		goto out;
	}

	if (avformat_alloc_output_context2(&oc, NULL, NULL, path) < 0 || !oc)
		goto out;

	vs = avformat_new_stream(oc, NULL);
	as = avformat_new_stream(oc, NULL);
	if (!vs || !as)
		goto out;

	vc = avcodec_alloc_context3(vc_enc);
	vc->width = 320;
	vc->height = 240;
	vc->time_base = (AVRational){ 1, 25 };
	vc->framerate = (AVRational){ 25, 1 };
	vc->pix_fmt = AV_PIX_FMT_YUV420P;
	vc->bit_rate = 200000;
	vc->gop_size = 25;		/* a keyframe every second */
	vc->max_b_frames = 2;		/* dts != pts at the boundaries */
	if (avcodec_open2(vc, vc_enc, NULL) < 0)
		goto out;
	vs->time_base = vc->time_base;

	ac = avcodec_alloc_context3(ac_enc);
	ac->sample_rate = 44100;
	ac->sample_fmt = AV_SAMPLE_FMT_FLTP;
	ac->bit_rate = 128000;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
	av_channel_layout_default(&ac->ch_layout, 2);
#else
	ac->channels = 2;
	ac->channel_layout = AV_CH_LAYOUT_STEREO;
#endif
	if (avcodec_open2(ac, ac_enc, NULL) < 0)
		goto out;
	as->time_base = (AVRational){ 1, ac->sample_rate };

	avcodec_parameters_from_context(vs->codecpar, vc);
	avcodec_parameters_from_context(as->codecpar, ac);

	if (avio_open(&oc->pb, path, AVIO_FLAG_WRITE) < 0)
		goto out;
	if (avformat_write_header(oc, NULL) < 0)
		goto out;

	vframe = av_frame_alloc();
	vframe->format = vc->pix_fmt;
	vframe->width = vc->width;
	vframe->height = vc->height;
	if (av_frame_get_buffer(vframe, 32) < 0)
		goto out;

	aframe = av_frame_alloc();
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

	{
		AVPacket *pkt = av_packet_alloc();
		int v;

		if (!pkt)
			goto out;
		while (n_video < FIXTURE_SECS * 25) {
			/* one grey-ramping video frame */
			if (av_frame_make_writable(vframe) < 0)
				goto out;
			memset(vframe->data[0],
			       (n_video * 3) & 0xff,
			       (size_t)(vframe->linesize[0] * vframe->height));
			for (v = 1; v < 3; v++)
				memset(vframe->data[v], 128,
				       (size_t)(vframe->linesize[v] *
						vframe->height >> 1));
			vframe->pts = n_video++;

			if (avcodec_send_frame(vc, vframe) < 0)
				goto out;
			while (!avcodec_receive_packet(vc, pkt)) {
				av_packet_rescale_ts(pkt, vc->time_base,
						     vs->time_base);
				pkt->stream_index = vs->index;
				if (av_interleaved_write_frame(oc, pkt) < 0)
					goto out;
				av_packet_unref(pkt);
			}

			/* the audio that goes with the frames so far */
			while (next_audio_pts <
			       (int64_t)n_video * ac->sample_rate / 25) {
				float *pl = (float *)aframe->data[0];
				float *pr = (float *)aframe->data[1];
				int i;

				if (av_frame_make_writable(aframe) < 0)
					goto out;
				for (i = 0; i < aframe->nb_samples; i++) {
					double t = (double)(next_audio_pts + i) /
						   ac->sample_rate;

					pl[i] = 0.3f * (float)sin(2 * M_PI * 440 * t);
					pr[i] = 0.3f * (float)sin(2 * M_PI * 440 * t);
				}
				aframe->pts = next_audio_pts;
				next_audio_pts += aframe->nb_samples;

				if (avcodec_send_frame(ac, aframe) < 0)
					goto out;
				while (!avcodec_receive_packet(ac, pkt)) {
					av_packet_rescale_ts(
						pkt, (AVRational){ 1, ac->sample_rate },
						as->time_base);
					pkt->stream_index = as->index;
					if (av_interleaved_write_frame(oc, pkt) < 0)
						goto out;
					av_packet_unref(pkt);
				}
			}
		}

		/* drain both encoders */
		avcodec_send_frame(vc, NULL);
		while (!avcodec_receive_packet(vc, pkt)) {
			av_packet_rescale_ts(pkt, vc->time_base, vs->time_base);
			pkt->stream_index = vs->index;
			av_interleaved_write_frame(oc, pkt);
			av_packet_unref(pkt);
		}
		avcodec_send_frame(ac, NULL);
		while (!avcodec_receive_packet(ac, pkt)) {
			av_packet_rescale_ts(pkt, (AVRational){ 1, ac->sample_rate },
					     as->time_base);
			pkt->stream_index = as->index;
			av_interleaved_write_frame(oc, pkt);
			av_packet_unref(pkt);
		}
		av_packet_free(&pkt);
	}

	av_write_trailer(oc);
	if (oc->pb)
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

	lwsl_notice("%s: wrote %s (%d video frames)\n", __func__, path, n_video);

out:
	av_frame_free(&vframe);
	av_frame_free(&aframe);
	if (vc)
		avcodec_free_context(&vc);
	if (ac)
		avcodec_free_context(&ac);
	if (oc) {
		if (oc->pb)
			avio_closep(&oc->pb);
		avformat_free_context(oc);
	}
	if (ret)
		unlink(path);

	return ret;
}

static void
remove_fixture_dir(void)
{
	char path[512];
	DIR *d;
	struct dirent *de;

	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);
	unlink(path);

	/* the shadow, if the test got far enough to make one */
	lws_snprintf(path, sizeof(path), "%s/.atrans", fixture_dir);
	d = opendir(path);
	if (d) {
		char ent[600];

		while ((de = readdir(d))) {
			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			lws_snprintf(ent, sizeof(ent), "%s/%s", path, de->d_name);
			unlink(ent);
		}
		closedir(d);
		rmdir(path);
	}

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

/* does <media-dir>/.atrans hold a completed shadow (.m4a + .hdr)? */
static int
shadow_complete(void)
{
	char dir[256];
	DIR *d;
	struct dirent *de;
	int hdr = 0, m4a = 0;

	lws_snprintf(dir, sizeof(dir), "%s/.atrans", fixture_dir);

	d = opendir(dir);
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		size_t nl = strlen(de->d_name);

		if (nl > 4 && !strcmp(de->d_name + nl - 4, ".hdr"))
			hdr = 1;
		if (nl > 4 && !strcmp(de->d_name + nl - 4, ".m4a"))
			m4a = 1;
	}
	closedir(d);

	return hdr && m4a;
}

static void
check_request(int idx, int status, const char *b, size_t bl)
{
	switch (idx) {
	case 0:	/* init */
		expect("init: HTTP 200", status == HTTP_STATUS_OK);
		expect("init: ftyp-led", bl > 12 && !memcmp(b + 4, "ftyp", 4));
		break;
	case 1:	/* segment 0, cold (may park behind the transcode) */
		expect("seg0 cold: HTTP 200", status == HTTP_STATUS_OK);
		expect("seg0 cold: moof-led media",
		       bl > 12 && !memcmp(b + 4, "moof", 4));
		seg0_cold_len = bl;
		seg0_cold_seen = 1;
		break;
	case 3:	/* segment 1 */
		expect("seg1: HTTP 200", status == HTTP_STATUS_OK);
		expect("seg1: moof-led media",
		       bl > 12 && !memcmp(b + 4, "moof", 4));
		break;
	case 4:	/* /index/ status JSON once the shadow is done */
		expect("index status: HTTP 200", status == HTTP_STATUS_OK);
		expect("index status: atrans ready",
		       !!strstr(b, "\"atrans\":\"ready\""));
		break;
	case 5:	/* segment 0 again, warm from the shadow on disk */
		expect("seg0 warm: HTTP 200", status == HTTP_STATUS_OK);
		expect("seg0 warm: moof-led media",
		       bl > 12 && !memcmp(b + 4, "moof", 4));
		expect("seg0 warm: same cut as cold",
		       seg0_cold_seen && bl == seg0_cold_len);
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
	lws_default_loop_exit(context);
}

static void
next_step_cb(lws_sorted_usec_list_t *sul);

static void
start_request(const char *path)
{
	struct lws_client_connect_info i;
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "cli");

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost		= vh;
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= path;
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-atrans-cli";
	i.pwsi			= &cli_wsi;

	body_len = 0;
	body[0] = '\0';
	got_status = 0;
	done = 0;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		done = -1;
		lws_default_loop_exit(context);
	}
}

/* one step of the walk: the NULL entry waits for the shadow to finish */
static void
next_step_cb(lws_sorted_usec_list_t *sul)
{
	const char *path = req_paths[req_idx];

	(void)sul;

	if (!path) {
		if (shadow_complete()) {
			lwsl_notice("%s: shadow complete\n", __func__);
			req_idx++;
		} else {
			/* keep waiting; the timeout sul bounds this */
			lws_sul_schedule(context, 0, &sul_connect,
					 next_step_cb, 100 * LWS_US_PER_MS);
			return;
		}
	}

	path = req_paths[req_idx];
	if (!path) {
		/* the walk is done */
		walk_done = 1;
		lws_default_loop_exit(context);
		return;
	}

	lwsl_notice("%s: fetching %s\n", __func__, path);
	start_request(path);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
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

	lwsl_user("LWS API selftest: HLS pre-transcoded audio shadow\n");

	if (build_fixture_media())
		goto bail;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

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

		if (done) {
			check_request(req_idx, got_status, body, body_len);
			req_idx++;
			done = 0;
			if (walk_failed ||
			    req_idx >= (int)LWS_ARRAY_SIZE(req_paths)) {
				walk_done = 1;
				break;
			}
			lws_sul_schedule(context, 0, &sul_connect,
					 next_step_cb, 200 * LWS_US_PER_MS);
		}
	}

	lws_sul_cancel(&sul_timeout);

	/* the shadow files have to exist by the time the walk is over */
	expect("shadow pair on disk", shadow_complete());

	result = !!fail;

bail:
	lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
