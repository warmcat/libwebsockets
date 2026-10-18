/*
 * lws-api-test-hls-queue
 *
 * Fences G-049 in the HLS plugin's thumbnail queue.  Anybody may ask for
 * /preview/<file>/<secs>, and each distinct secs value used to queue its
 * own thumbnail task, owned by nobody, on the single worker's FIFO, in
 * front of whatever playback work came after it: one client could grow
 * the queue without bound, leave, and still keep every viewer's playlists
 * and segments waiting behind the decodes it left there.
 *
 * The whole plugin is folded into the test statically (as api-test-hls-dir
 * does), serving a fixture film built at runtime with libavformat: a
 * matroska file of MPEG-4 part 2 video with a single keyframe, so every
 * thumbnail costs the worker a few hundred decoded frames.  In-process
 * clients, all from 127.0.0.1, then
 *
 *  - fetch the playlist once, so the file's index is built and later
 *    playlists are quick;
 *  - ask for BURST thumbnails at distinct times, all at once, and once the
 *    server has every one of them waiting, ask for the playlist again.
 *    Only HLS_THUMB_TIMED_PENDING_PER_HOST of the timed thumbnails may be
 *    pending (the rest get the default one), and the playlist must not
 *    wait for more than the thumbnail already running: at most
 *    QT_PLAYLIST_THUMBS more timed thumbnails may be finished by the time
 *    its answer arrives.  Every thumbnail request is still answered 200,
 *    and no more timed ones are ever made than the cap, plus the one that
 *    was running;
 *  - ask for GONE more thumbnails at new times, and once the server has
 *    them all waiting, drop the connections: the ones not started yet
 *    must be dropped unrun, so at most QT_GONE_RUN more of them are ever
 *    made than had been started when we dropped them.
 *
 * Before the fix: all BURST timed thumbnails are queued, the playlist
 * waits for nearly all of them, and all GONE are made for nobody.
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
#include <errno.h>

/* import the whole of the HLS plugin statically */
#include <lws-plugin-hls-static-build-includes.h>

#define FIXTURE_NAME	"queue-test.mkv"
#define FIXTURE_SECS	12
#define FIXTURE_FPS	25

#define BURST		24	/* distinct timed thumbnails asked at once */
#define GONE		8	/* asked, then abandoned before they run */
#define BURST_T0	1000	/* their times, QT_BUCKET apart */
#define GONE_T0		3000
#define QT_BUCKET	5	/* HLS_THUMB_T_BUCKET, the client's bucket */

/* the per-host cap the fix enforces (HLS_THUMB_TIMED_PENDING_PER_HOST) */
#define QT_TIMED_PER_HOST	8
/* timed thumbnails allowed to finish while the playlist is waiting: the
 * one running when it was asked for, and one for luck */
#define QT_PLAYLIST_THUMBS	2
/* abandoned ones the worker may still start after we dropped them, before
 * the server has seen the connections close */
#define QT_GONE_RUN		1

enum {
	RQ_WARMUP,
	RQ_BURST,
	RQ_PLAYLIST = RQ_BURST + BURST,
	RQ_GONE,

	RQ_COUNT = RQ_GONE + GONE
};

enum {
	PH_WARMUP,		/* first playlist in flight */
	PH_BURST,		/* thumbnails asked, waiting for all to queue */
	PH_PLAYLIST,		/* playlist asked behind them */
	PH_BURST_DRAIN,		/* waiting for every thumbnail to be answered */
	PH_GONE,		/* abandoned ones asked, waiting for all to queue */
	PH_GONE_DRAIN,		/* dropped, waiting for the worker to idle */
	PH_DONE
};

static struct lws_context *context;
static struct lws_vhost *vh_hls;
static lws_sorted_usec_list_t sul_poll, sul_timeout;
static struct lws *wsis[RQ_COUNT];
static int status[RQ_COUNT], done[RQ_COUNT];
static int tests, fail, result = 1, phase, finished;
static int cached_at_playlist, started_at_gone;
static lws_usec_t t_playlist, t_settle;

static uint16_t port_hls = 21100;
static char fixture_dir[128];

/* -------------------------------------------------------------- server */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_hls = LWS_PLUGIN_PROTOCOL_LWS_HLS,
	prot_cli = { "lws-api-test-hls-queue-cli", callback_cli, 0, 0, 0,
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

static struct lws_protocol_vhost_options
	pvo_hls		= { NULL, NULL, "lws-hls", NULL },
	pvo_media_dir	= { NULL, NULL, "media-dir", NULL };

static struct per_vhost_data__lws_hls *
srv_vhd(void)
{
	const struct lws_protocols *p = lws_vhost_name_to_protocol(vh_hls,
								   "lws-hls");

	return p ? (struct per_vhost_data__lws_hls *)
			lws_protocol_vh_priv_get(vh_hls, p) : NULL;
}

/* the worker's queue thumbnails wait on, before and after the fix */
#if defined(HLS_THUMB_TIMED_PENDING_PER_HOST)
#define QT_THUMB_QUEUE(_v) (&(_v)->thumb_tasks)
#else
#define QT_THUMB_QUEUE(_v) (&(_v)->tasks)
#endif

/* how many timed thumbnails are pending on the worker */
static int
srv_timed_pending(struct per_vhost_data__lws_hls *vhd)
{
	int n = 0;

	pthread_mutex_lock(&vhd->lock);
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(QT_THUMB_QUEUE(vhd))) {
		struct hls_task *t = lws_container_of(d, struct hls_task, list);

		if (t->type == HLS_TASK_THUMB && t->segment_idx >= 0)
			n++;
	} lws_end_foreach_dll(d);
	pthread_mutex_unlock(&vhd->lock);

	return n;
}

/* is the worker idle, with nothing queued? */
static int
srv_idle(struct per_vhost_data__lws_hls *vhd)
{
	int idle;

	pthread_mutex_lock(&vhd->lock);
	idle = !vhd->running && !lws_dll2_get_head(&vhd->tasks) &&
	       !lws_dll2_get_head(QT_THUMB_QUEUE(vhd));
	pthread_mutex_unlock(&vhd->lock);

	return idle;
}

/* how many thumbnails of the fixture in [t0, t1) have been made */
static int
srv_cached(struct per_vhost_data__lws_hls *vhd, int t0, int t1)
{
	int n = 0;

	pthread_mutex_lock(&vhd->lock);
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->thumb_cache)) {
		struct thumb_cache *c = lws_container_of(d, struct thumb_cache,
							 list);

		if (!strcmp(c->filename, FIXTURE_NAME) && c->t >= t0 &&
		    c->t < t1)
			n++;
	} lws_end_foreach_dll(d);
	pthread_mutex_unlock(&vhd->lock);

	return n;
}

/* is the worker making a thumbnail of the fixture in [t0, t1)? */
static int
srv_running(struct per_vhost_data__lws_hls *vhd, int t0, int t1)
{
	int r;

	pthread_mutex_lock(&vhd->lock);
	r = !strcmp(vhd->current_task_filename, FIXTURE_NAME) &&
	    vhd->current_task_t >= t0 && vhd->current_task_t < t1;
	pthread_mutex_unlock(&vhd->lock);

	return r;
}

/* how many sessions are waiting on a thumbnail (event loop state) */
static int
srv_thumb_waiters(struct per_vhost_data__lws_hls *vhd)
{
	int n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&vhd->pss_list)) {
		struct per_session_data__lws_hls *pss = lws_container_of(d,
				struct per_session_data__lws_hls, pss_list);

		if (pss->waiting_for_thumbnail)
			n++;
	} lws_end_foreach_dll(d);

	return n;
}

/* -------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	int idx = (int)(intptr_t)lws_get_opaque_user_data(wsi) - 1;

	if (idx < 0 || idx >= RQ_COUNT)
		return 0;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status[idx] = (int)lws_http_client_http_response(wsi);
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
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		done[idx] = 1;
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: request %d: connection error: %s\n", __func__,
			    idx, in ? (const char *)in : "?");
		/* fallthru */
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!done[idx])
			done[idx] = -1;
		wsis[idx] = NULL;
		break;

	default:
		break;
	}

	return 0;
}

static int
cli_get(int idx, const char *path)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= path;
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-queue-cli";
	i.opaque_user_data	= (void *)(intptr_t)(idx + 1);
	i.pwsi			= &wsis[idx];

	done[idx] = 0;
	status[idx] = 0;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect %d failed\n", __func__, idx);
		done[idx] = -1;
		return 1;
	}

	return 0;
}

static int
cli_thumb(int idx, int secs)
{
	char path[128];

	lws_snprintf(path, sizeof(path), "/media/preview/" FIXTURE_NAME "/%d",
		     secs);

	return cli_get(idx, path);
}

/* ------------------------------------------------------------ fixtures */

/*
 * <fixture_dir>/queue-test.mkv: FIXTURE_SECS of 640x480 MPEG-4 part 2
 * video with a keyframe only at the start.  Returns 0 if it is there.
 */
static int
build_fixture_media(void)
{
	AVFormatContext *oc = NULL;
	AVCodecContext *vc = NULL;
	const AVCodec *enc;
	AVFrame *frame = NULL;
	AVPacket *pkt = NULL;
	AVStream *st;
	char path[384];
	int n = 0, ret = 1, v;

	lws_strncpy(fixture_dir, "/tmp/lws-hls-queue-test-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));
	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		fixture_dir[0] = '\0';
		return 1;
	}
	lws_snprintf(path, sizeof(path), "%s/" FIXTURE_NAME, fixture_dir);

	enc = avcodec_find_encoder(AV_CODEC_ID_MPEG4);
	if (!enc) {
		lwsl_err("%s: no mpeg4 encoder in this libavcodec\n", __func__);
		goto out;
	}

	if (avformat_alloc_output_context2(&oc, NULL, "matroska", path) < 0 ||
	    !oc)
		goto out;

	vc = avcodec_alloc_context3(enc);
	if (!vc)
		goto out;
	vc->width	= 640;
	vc->height	= 480;
	vc->time_base	= (AVRational){ 1, FIXTURE_FPS };
	vc->framerate	= (AVRational){ FIXTURE_FPS, 1 };
	vc->pix_fmt	= AV_PIX_FMT_YUV420P;
	vc->bit_rate	= 200000;
	vc->gop_size	= FIXTURE_SECS * FIXTURE_FPS; /* the one keyframe */
	vc->max_b_frames = 0;
	if (oc->oformat->flags & AVFMT_GLOBALHEADER)
		vc->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
	if (avcodec_open2(vc, enc, NULL) < 0)
		goto out;

	st = avformat_new_stream(oc, NULL);
	if (!st)
		goto out;
	st->time_base = vc->time_base;
	avcodec_parameters_from_context(st->codecpar, vc);

	if (avio_open(&oc->pb, path, AVIO_FLAG_WRITE) < 0)
		goto out;
	if (avformat_write_header(oc, NULL) < 0)
		goto out;

	frame = av_frame_alloc();
	pkt = av_packet_alloc();
	if (!frame || !pkt)
		goto out;
	frame->format = vc->pix_fmt;
	frame->width = vc->width;
	frame->height = vc->height;
	if (av_frame_get_buffer(frame, 32) < 0)
		goto out;

	while (n < FIXTURE_SECS * FIXTURE_FPS) {
		if (av_frame_make_writable(frame) < 0)
			goto out;
		/* a moving ramp, so the frames are not all the same */
		for (v = 0; v < frame->height; v++)
			memset(frame->data[0] + v * frame->linesize[0],
			       (v + n * 3) & 0xff, (size_t)frame->width);
		for (v = 1; v < 3; v++)
			memset(frame->data[v], 128,
			       (size_t)(frame->linesize[v] * frame->height >> 1));
		frame->pts = n++;

		if (avcodec_send_frame(vc, frame) < 0)
			goto out;
		while (!avcodec_receive_packet(vc, pkt)) {
			av_packet_rescale_ts(pkt, vc->time_base, st->time_base);
			pkt->stream_index = st->index;
			if (av_interleaved_write_frame(oc, pkt) < 0)
				goto out;
		}
	}

	avcodec_send_frame(vc, NULL);
	while (!avcodec_receive_packet(vc, pkt)) {
		av_packet_rescale_ts(pkt, vc->time_base, st->time_base);
		pkt->stream_index = st->index;
		av_interleaved_write_frame(oc, pkt);
	}
	if (av_write_trailer(oc) < 0)
		goto out;
	avio_closep(&oc->pb);

	/*
	 * The plugin builds nothing from media written in the last
	 * HLS_MEDIA_SETTLE_SECS (it may be a copy still going on): make ours
	 * look like it has been sitting there a while
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

out:
	av_packet_free(&pkt);
	av_frame_free(&frame);
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
	} else
		lwsl_user("ok: %s\n", name);
}

static int
all_done(int from, int count)
{
	int n;

	for (n = from; n < from + count; n++)
		if (!done[n])
			return 0;

	return 1;
}

/* ------------------------------------------------------------ sequencing */

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out in phase %d\n", __func__, phase);
	expect("finished in time", 0);
	finished = 1;
	lws_cancel_service(context);
}

static void
sul_poll_cb(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__lws_hls *vhd = srv_vhd();
	int n, m;

	if (!vhd) {
		expect("plugin instantiated", 0);
		finished = 1;
		return;
	}

	switch (phase) {
	case PH_WARMUP:
		if (!done[RQ_WARMUP])
			break;
		expect("first playlist answered 200", done[RQ_WARMUP] > 0 &&
					status[RQ_WARMUP] == HTTP_STATUS_OK);

		lwsl_user("%s: asking for %d timed thumbnails at once\n",
			  __func__, BURST);
		for (n = 0; n < BURST; n++)
			cli_thumb(RQ_BURST + n,
				  BURST_T0 + n * QT_BUCKET);
		phase = PH_BURST;
		break;

	case PH_BURST:
		/* every one waiting on the server, or already answered */
		m = 0;
		for (n = 0; n < BURST; n++)
			m += !!done[RQ_BURST + n];
		if (srv_thumb_waiters(vhd) + m < BURST)
			break;

		n = srv_timed_pending(vhd);
		lwsl_user("%s: all queued: %d timed pending, %d answered\n",
			  __func__, n, m);
		expect("timed thumbnails pending from one host within the cap",
		       n <= QT_TIMED_PER_HOST);

		cached_at_playlist = srv_cached(vhd, BURST_T0, GONE_T0);
		t_playlist = lws_now_usecs();
		cli_get(RQ_PLAYLIST, "/media/stream/" FIXTURE_NAME);
		phase = PH_PLAYLIST;
		break;

	case PH_PLAYLIST:
		if (!done[RQ_PLAYLIST])
			break;
		n = srv_cached(vhd, BURST_T0, GONE_T0) - cached_at_playlist;
		lwsl_user("%s: playlist answered in %lldms, %d timed "
			  "thumbnails made meanwhile\n", __func__,
			  (long long)(lws_now_usecs() - t_playlist) /
							LWS_US_PER_MS, n);
		expect("playlist answered 200", done[RQ_PLAYLIST] > 0 &&
				status[RQ_PLAYLIST] == HTTP_STATUS_OK);
		expect("playlist waited for at most the running thumbnail",
		       n <= QT_PLAYLIST_THUMBS);
		phase = PH_BURST_DRAIN;
		break;

	case PH_BURST_DRAIN:
		if (!all_done(RQ_BURST, BURST) || !srv_idle(vhd))
			break;
		m = 0;
		for (n = 0; n < BURST; n++)
			m += done[RQ_BURST + n] > 0 &&
			     status[RQ_BURST + n] == HTTP_STATUS_OK;
		n = srv_cached(vhd, BURST_T0, GONE_T0);
		lwsl_user("%s: %d of %d thumbnails answered 200, %d timed "
			  "ones made\n", __func__, m, BURST, n);
		expect("every thumbnail request answered 200", m == BURST);
		/* the pending ones, and the one running when we looked */
		expect("no more timed thumbnails made than the cap",
		       n <= QT_TIMED_PER_HOST + 1);

		lwsl_user("%s: asking for %d thumbnails, then leaving\n",
			  __func__, GONE);
		for (n = 0; n < GONE; n++)
			cli_thumb(RQ_GONE + n, GONE_T0 + n * QT_BUCKET);
		phase = PH_GONE;
		break;

	case PH_GONE:
		if (srv_thumb_waiters(vhd) < GONE && !all_done(RQ_GONE, GONE))
			break;
		/* the clients go away while their thumbnails are queued */
		started_at_gone = srv_cached(vhd, GONE_T0, GONE_T0 + 1000) +
				  srv_running(vhd, GONE_T0, GONE_T0 + 1000);
		for (n = 0; n < GONE; n++)
			if (wsis[RQ_GONE + n])
				lws_set_timeout(wsis[RQ_GONE + n],
						PENDING_TIMEOUT_USER_OK,
						LWS_TO_KILL_ASYNC);
		t_settle = lws_now_usecs();
		phase = PH_GONE_DRAIN;
		break;

	case PH_GONE_DRAIN:
		/* the server must see the closes before the worker idling
		 * means anything */
		if (srv_thumb_waiters(vhd) || !srv_idle(vhd) ||
		    lws_now_usecs() - t_settle < 500 * LWS_US_PER_MS)
			break;
		n = srv_cached(vhd, GONE_T0, GONE_T0 + 1000);
		lwsl_user("%s: %d of %d abandoned thumbnails made, %d started "
			  "when abandoned\n", __func__, n, GONE,
			  started_at_gone);
		expect("abandoned thumbnails not started are dropped",
		       n <= started_at_gone + QT_GONE_RUN);
		phase = PH_DONE;
		finished = 1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_poll, sul_poll_cb,
			 10 * LWS_US_PER_MS);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

/*
 * We are the plugin's stub child (LWS_WITH_STUB): the plugin in the parent
 * re-ran this executable with --lws-stub=lws-hls-stub.  It must come up and
 * wait for the parent to go away, not run the test again.
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

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER, NULL);

	if (lws_cmdline_option(argc, argv, "--lws-stub="))
		return run_stub(&info);

	lwsl_user("LWS API selftest: HLS thumbnail queue bounds\n");

	if (build_fixture_media())
		goto bail;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.plugins = composed_plugins;
	/* our clients and the server's sessions, all at once */
	info.max_http_header_pool = 2 * RQ_COUNT + 8;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		goto bail;
	}

	pvo_media_dir.value	= fixture_dir;
	pvo_hls.options		= &pvo_media_dir;

	info.port		= port_hls;
	info.vhost_name		= "hls";
	info.pprotocols		= pprotocols_hls;
	info.mounts		= &mount_hls;
	info.pvo		= &pvo_hls;

	vh_hls = lws_create_vhost(context, &info);
	if (!vh_hls) {
		lwsl_err("Failed to create hls vhost\n");
		goto bail;
	}

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
			 100 * LWS_US_PER_SEC);
	cli_get(RQ_WARMUP, "/media/stream/" FIXTURE_NAME);
	lws_sul_schedule(context, 0, &sul_poll, sul_poll_cb,
			 20 * LWS_US_PER_MS);

	while (n >= 0 && !finished)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_poll);
	lws_sul_cancel(&sul_timeout);

	expect("every phase ran", phase == PH_DONE);

	result = !!fail;

bail:
	if (context)
		lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
