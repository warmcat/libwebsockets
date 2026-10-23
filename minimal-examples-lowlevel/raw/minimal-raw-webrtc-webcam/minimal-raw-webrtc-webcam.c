/*
 * lws-minimal-raw-webrtc-webcam
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_HELP,
	LWS_SW_IP,
	LWS_SW_MOUNT_ORIGIN,
	LWS_SW_VIDEO_DEVICE,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HELP]	= { "--help",          "Show this help information" },
	[LWS_SW_IP]	= { "--ip",            "Enable --ip feature" },
	[LWS_SW_MOUNT_ORIGIN]	= { "--mount-origin",  "Enable --mount-origin feature" },
	[LWS_SW_VIDEO_DEVICE]	= { "--video-device",  "Enable --video-device feature" },
};

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>

#include "webcam-media.h"

#if !defined(WIN32) && !defined(_WIN32)
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/videodev2.h>
#include <arpa/inet.h>
#include <libwebsockets/lws-v4l2.h>
#include <libwebsockets/lws-alsa.h>
#include <libwebsockets/lws-rtp.h>

const struct lws_webrtc_ops *we_ops;

int
relay_to_session(struct pss_webrtc *pss, void *user)
{
	struct relay_data *rd = (struct relay_data *)user;

	if (rd->is_video) {
		uint32_t pts = (uint32_t)(lws_now_usecs() * 9 / 100);
		return we_ops->send_video(we_ops->get_media(pss), rd->buf, rd->len, LWS_WEBRTC_CODEC_H264, pts);
	}

	return we_ops->send_audio(we_ops->get_media(pss), rd->buf, rd->len, 0);
}

#if defined(LWS_WITH_OPUS)
static void alsa_audio_cb(void *user_data, const uint8_t *payload, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)user_data;
	if (we_ops && we_ops->send_audio && vhd && vhd->vhd) {
		struct relay_data rd_a = { payload, len, 0 };
		we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_a);
	}
}
#endif

/*
 * The sizes a client may ask us to encode at with request_res.  The camera
 * itself is opened at whatever it supports nearest, but the scaler, frames and
 * encoder are sized from what the client asked for, so it must be bounded.
 */
#define WEBCAM_MIN_DIM		16
#define WEBCAM_MAX_WIDTH	1920
#define WEBCAM_MAX_HEIGHT	1080

/*
 * The capture fds belong to lws_v4l2 / lws_alsa, which close them in their
 * own destroy, while lws closes whatever it adopted when that wsi closes.  So
 * lws gets its own reference, a dup() of the fd: each side closes exactly the
 * fd it owns, and neither can end up closing an fd number the other already
 * gave back to the OS and that something else got.
 */

static struct lws *
webcam_adopt_fd(struct lws_vhost *vh, int fd)
{
	struct lws_adopt_desc ad;
	struct lws *w;
	int dfd;

	if (fd < 0)
		return NULL;

	dfd = dup(fd);
	if (dfd < 0)
		return NULL;

	memset(&ad, 0, sizeof(ad));
	ad.vh = vh;
	ad.type = LWS_ADOPT_RAW_FILE_DESC;
	ad.fd.filefd = (lws_filefd_type)(lws_intptr_t)dfd;
	ad.vh_prot_name = "lws-webrtc-webcam";

	w = lws_adopt_descriptor_vhost_via_info(&ad);
	if (!w)
		/* a failed file adopt leaves the fd with the caller */
		close(dfd);

	return w;
}

/*
 * A decimal integer JSON value from a peer, eg as found by
 * lws_json_simple_find(), which is not NUL-terminated.  Returns 0 and sets
 * *out if it is all digits (with an optional leading -) and in [min, max].
 */

static int
webcam_json_int(const char *v, size_t alen, int64_t min, int64_t max,
		int64_t *out)
{
	int64_t u = 0;
	size_t n = 0;
	int neg = 0;

	if (!v || !alen)
		return 1;

	if (v[0] == '-') {
		neg = 1;
		n++;
	}

	if (n == alen || alen - n > 10)
		return 1;

	for (; n < alen; n++) {
		if (v[n] < '0' || v[n] > '9')
			return 1;
		u = (u * 10) + (v[n] - '0');
	}

	if (neg)
		u = -u;
	if (u < min || u > max)
		return 1;

	*out = u;

	return 0;
}

static int
v4l2_init(struct per_vhost_data *vhd)
{
	struct lws_v4l2_info info;

	memset(&info, 0, sizeof(info));
	info.device_path = vhd->video_device;
	info.width = vhd->width;
	info.height = vhd->height;
	info.pixelformat = V4L2_PIX_FMT_H264;

	vhd->v4l2_ctx = lws_v4l2_create(&info);
	if (!vhd->v4l2_ctx) {
		lwsl_err("%s: Failed to create V4L2 context\n", __func__);
		return -1;
	}

	lws_v4l2_get_info(vhd->v4l2_ctx, &info);
	vhd->width = info.width;
	vhd->height = info.height;
	vhd->pixelformat = info.pixelformat;

	lwsl_notice("%s: V4L2 negotiated %dx%d, format 0x%x\n", __func__, vhd->width, vhd->height, vhd->pixelformat);

	media_update_scaler(vhd);

	vhd->yuv_size = (vhd->width * vhd->height * 3) / 2;
	if (vhd->yuv_frame) free(vhd->yuv_frame);
	vhd->yuv_frame = malloc(vhd->yuv_size);
	if (!vhd->yuv_frame)
		goto bail;

	if (media_init(vhd) < 0)
		goto bail;

	return 0;

bail:
	lws_v4l2_destroy(&vhd->v4l2_ctx);
	return -1;
}

static void
v4l2_reinit(struct per_vhost_data *vhd)
{
	lwsl_notice("%s: Re-initializing V4L2 with %dx%d\n", __func__, vhd->target_width, vhd->target_height);

	if (vhd->wsi_v4l2) {
		/*
		 * lws closes the old wsi, and its own dup() of the old capture
		 * fd, later; until then it is no longer ours, so anything it
		 * reports is ignored
		 */
		lws_set_timeout(vhd->wsi_v4l2, PENDING_TIMEOUT_KILLED_BY_PARENT, LWS_TO_KILL_ASYNC);
		vhd->wsi_v4l2 = NULL;
	}

	if (vhd->v4l2_ctx)
		lws_v4l2_destroy(&vhd->v4l2_ctx);

	/* the encoder, frames and scaler for the old sizes go too */
	media_deinit(vhd);

	vhd->width = vhd->target_width;
	vhd->height = vhd->target_height;

	if (v4l2_init(vhd) == 0)
		vhd->wsi_v4l2 = webcam_adopt_fd(we_ops->get_vhost(vhd->vhd),
					lws_v4l2_get_fd(vhd->v4l2_ctx));
}

static struct lws_context *cx;
static lws_state_notify_link_t nl, *const app_notifier_list[] = {&nl, NULL};

/*
 * The device_controls message lists every control the camera driver has, and
 * a driver can have any number of them, with names we only know are short
 * strings.  So build it with the end of the buffer in view: each entry is
 * formatted on its own and only added if it fits whole, keeping room for the
 * closing brackets, and the enumeration stops at the first one that does not,
 * so the message is always complete JSON however many controls there are.
 */

/* the same as the rtc_camera plugin uses for its control list */
#define WEBCAM_CONTROLS_BUF	4096
/* room kept for the "],\"audio\":[" + "]}" that close the message */
#define WEBCAM_JSON_TAIL	16

struct webcam_json {
	char		*p;
	char		*end;
	int		first;
	int		truncated;
};

/* add len bytes of s if they fit with keep bytes still free afterwards */

static int
webcam_json_add(struct webcam_json *j, const char *s, size_t len, size_t keep)
{
	if (len + keep > lws_ptr_diff_size_t(j->end, j->p)) {
		j->truncated = 1;
		return 1;
	}

	memcpy(j->p, s, len);
	j->p += len;

	return 0;
}

static int
append_v4l2_control(void *user, const struct lws_v4l2_control *c)
{
	struct webcam_json *j = (struct webcam_json *)user;
	char safe_name[6 * sizeof(c->name)], entry[384];
	int n;

	/* the name comes from the driver: escape it for JSON */
	lws_json_purify(safe_name, c->name, (int)sizeof(safe_name), NULL);

	n = lws_snprintf(entry, sizeof(entry),
			 "%s{\"id\":%u,\"name\":\"%s\",\"min\":%d,"
			 "\"max\":%d,\"step\":%d,\"val\":%d}",
			 j->first ? "" : ",", c->id, safe_name, c->min,
			 c->max, c->step, c->val);
	if (n >= (int)sizeof(entry)) {
		/* can't happen with the sizes above, but don't send a cut one */
		j->truncated = 1;
		return 1;
	}

	if (webcam_json_add(j, entry, (size_t)n, WEBCAM_JSON_TAIL))
		return 1; /* stop the enumeration, there is no more room */

	j->first = 0;

	return 0;
}

#define WEBCAM_JSON_LIT(j, s, keep) webcam_json_add(j, s, sizeof(s) - 1, keep)

static void
send_controls(struct lws *wsi, struct per_vhost_data *vhd)
{
	char buf[LWS_PRE + WEBCAM_CONTROLS_BUF], *start = buf + LWS_PRE;
	struct webcam_json j;

	j.p		= start;
	j.end		= buf + sizeof(buf);
	j.first		= 1;
	j.truncated	= 0;

	WEBCAM_JSON_LIT(&j, "{\"type\":\"device_controls\",\"video\":[",
			WEBCAM_JSON_TAIL);
	lws_v4l2_enum_controls(vhd->v4l2_ctx, append_v4l2_control, &j);
#if defined(LWS_WITH_OPUS)
	WEBCAM_JSON_LIT(&j, "],\"audio\":[", 2);
	if (vhd->alsa_cap) {
		/*
		 * Take the array of controls out of the audio capabilities
		 * message {"type":"capabilities","kind":"audio","controls":[...]}
		 */
		char abuf[1024];
		const char *as, *ae;
		int n = lws_alsa_opus_send_capabilities(vhd->alsa_cap, abuf,
							sizeof(abuf));

		if (n > 0 && n < (int)sizeof(abuf)) {
			abuf[n] = '\0';
			as = strstr(abuf, "\"controls\":[");
			if (as) {
				as += 12; /* skip "\"controls\":[" */
				ae = strrchr(as, ']');
				if (ae && ae > as && ae[-1] == ',')
					ae--;
				if (ae)
					/* all of it or none of it */
					webcam_json_add(&j, as,
						lws_ptr_diff_size_t(ae, as), 2);
			}
		}
	}
#endif
	WEBCAM_JSON_LIT(&j, "]}", 0);

	if (j.truncated)
		lwsl_notice("%s: too many controls, sending the first ones\n",
			    __func__);

	if (lws_write(wsi, (uint8_t *)start, lws_ptr_diff_size_t(j.p, start),
		      LWS_WRITE_TEXT) < 0)
		lwsl_notice("%s: write failed\n", __func__);
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_HTTP_FILE_COMPLETION) {
		lwsl_info("%s: HTTP_FILE_COMPLETION\n", __func__);
                return -1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_webrtc_webcam(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	struct per_vhost_data *vhd = (struct per_vhost_data *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	int n;

	if (reason == LWS_CALLBACK_RECEIVE) {
		lwsl_warn("%s: LWS_CALLBACK_RECEIVE (%zu bytes): %.*s\n", __func__, len, (int)len, (const char *)in);
	}

	if (reason != LWS_CALLBACK_PROTOCOL_INIT &&
	    reason != LWS_CALLBACK_PROTOCOL_DESTROY) {
		if (vhd && vhd->vhd && we_ops && we_ops->shared_callback) {
			n = we_ops->shared_callback(wsi, reason, user, in, len, vhd->vhd);
			if (n)
				return n;
		}
	}

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		send_controls(wsi, vhd);
		break;

	case LWS_CALLBACK_RECEIVE:
	{
		/*
		 * This comes from any client: everything in it is checked
		 * before we act on it, and the values are not NUL-terminated
		 */
		size_t alen, wlen, hlen, klen, ilen, vlen;
		const char *val = lws_json_simple_find((const char *)in, len, "\"type\":", &alen);
		int64_t w64, h64, id64, v64;

		if (!vhd || !val)
			break;

		if (alen == 11 && !strncmp(val, "request_res", 11)) {
			const char *w = lws_json_simple_find((const char *)in, len, "\"width\":", &wlen);
			const char *h = lws_json_simple_find((const char *)in, len, "\"height\":", &hlen);

			if (webcam_json_int(w, wlen, WEBCAM_MIN_DIM,
					    WEBCAM_MAX_WIDTH, &w64) ||
			    webcam_json_int(h, hlen, WEBCAM_MIN_DIM,
					    WEBCAM_MAX_HEIGHT, &h64) ||
			    (w64 & 1) || (h64 & 1)) {
				lwsl_notice("%s: ignoring bad request_res\n", __func__);
				break;
			}

			vhd->target_width = (uint32_t)w64;
			vhd->target_height = (uint32_t)h64;
			lwsl_notice("%s: Requested resolution switch to %dx%d\n", __func__, vhd->target_width, vhd->target_height);
			v4l2_reinit(vhd);
			break;
		}

		if (alen == 11 && !strncmp(val, "set_control", 11)) {
			const char *kind = lws_json_simple_find((const char *)in, len, "\"kind\":", &klen);
			const char *id = lws_json_simple_find((const char *)in, len, "\"id\":", &ilen);
			const char *v = lws_json_simple_find((const char *)in, len, "\"val\":", &vlen);

			if (!kind ||
			    webcam_json_int(id, ilen, 0, UINT32_MAX, &id64) ||
			    webcam_json_int(v, vlen, INT32_MIN, INT32_MAX, &v64))
				break;

			if (klen == 5 && !strncmp(kind, "video", 5))
				lws_v4l2_set_control(vhd->v4l2_ctx, (uint32_t)id64, (int32_t)v64);
#if defined(LWS_WITH_OPUS)
			else if (klen == 5 && !strncmp(kind, "audio", 5) &&
				 vhd->alsa_cap)
				lws_alsa_opus_set_control(vhd->alsa_cap, (uint32_t)id64, (long)v64);
#endif
		}
	}
		break;

	case LWS_CALLBACK_PROTOCOL_INIT:
	{
		const struct lws_protocols *p;
#if defined(LWS_WITH_OPUS)
		struct lws_alsa_info ainfo;
#endif

		lwsl_vhost_notice(lws_get_vhost(wsi), "lws-webrtc-webcam: PROTOCOL_INIT");

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct per_vhost_data));
		if (!vhd)
			return -1;

		p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
		if (p) {
			vhd->vhd = (struct vhd_webrtc *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), p);
			we_ops = (const struct lws_webrtc_ops *)p->user;
		}

		if (!vhd->vhd || !we_ops || we_ops->abi_version != LWS_WEBRTC_OPS_ABI_VERSION) {
			lwsl_err("%s: plugin WebRTC missing or ABI mismatch (got %u, expected %u)\n",
				 __func__, we_ops ? we_ops->abi_version : 0, LWS_WEBRTC_OPS_ABI_VERSION);
			return -1;
		}

		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		const struct lws_protocol_vhost_options *pvo_dev = NULL;

		if (pvo)
			pvo_dev = lws_pvo_search(pvo, "video-device");

		if (pvo_dev && pvo_dev->value)
			vhd->video_device = pvo_dev->value;
		else
			vhd->video_device = "/dev/video0";

		vhd->width = LWS_RTP_VIDEO_WIDTH_720P;
                vhd->height = LWS_RTP_VIDEO_HEIGHT_720P;
		vhd->target_width = LWS_RTP_VIDEO_WIDTH_360P;
		vhd->target_height = LWS_RTP_VIDEO_HEIGHT_360P;

		if (v4l2_init(vhd))
			/* we carry on without video */
			media_deinit(vhd);

#if defined(LWS_WITH_OPUS)
		memset(&ainfo, 0, sizeof(ainfo));
		ainfo.device_name = "default";
		ainfo.rate = AUDIO_RATE;
		ainfo.channels = AUDIO_CHANNELS;
		ainfo.samples_per_frame = AUDIO_SAMPLES_PER_FRAME;

		vhd->alsa_cap = lws_alsa_opus_capture_create(&ainfo, alsa_audio_cb, vhd);
#endif

		if (vhd->v4l2_ctx)
			vhd->wsi_v4l2 = webcam_adopt_fd(we_ops->get_vhost(vhd->vhd),
						lws_v4l2_get_fd(vhd->v4l2_ctx));

#if defined(LWS_WITH_OPUS)
		if (vhd->alsa_cap)
			vhd->wsi_alsa = webcam_adopt_fd(we_ops->get_vhost(vhd->vhd),
						lws_alsa_opus_get_fd(vhd->alsa_cap));
#endif
		break;
	}

	case LWS_CALLBACK_GET_PSS_SIZE:
	{
		const struct lws_protocols *p = lws_vhost_name_to_protocol(lws_get_vhost(wsi), "lws-webrtc");
		if (p)
			return (int)p->per_session_data_size;
		return 0;
	}

	case LWS_CALLBACK_RAW_RX_FILE:
		if (!vhd)
			break;
#if defined(LWS_WITH_OPUS)
		if (wsi == vhd->wsi_alsa) {
			if (vhd->alsa_cap)
				lws_alsa_opus_read(vhd->alsa_cap);
		} else
#endif
		if (wsi == vhd->wsi_v4l2) {
			/* (an old capture wsi waiting to be closed is ignored) */
			struct v4l2_buffer buf_v;
			void *start;
			size_t len;

			memset(&buf_v, 0, sizeof(buf_v));
			buf_v.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf_v.memory = V4L2_MEMORY_MMAP;
			if (ioctl(lws_v4l2_get_fd(vhd->v4l2_ctx), VIDIOC_DQBUF, &buf_v) >= 0) {
				vhd->frame_count++;
				if (we_ops && we_ops->send_video) {
					if (vhd->pixelformat == V4L2_PIX_FMT_H264) {
						if (!lws_v4l2_get_buffer(vhd->v4l2_ctx, (int)buf_v.index, &start, &len) &&
						    buf_v.bytesused <= len) {
							struct relay_data rd_v = { start, buf_v.bytesused, 1 };
							we_ops->foreach_session(vhd->vhd, relay_to_session, &rd_v);
						}
					} else {
						media_process_video_frame(vhd, (int)buf_v.index, (size_t)buf_v.bytesused);
					}
				}
				if (ioctl(lws_v4l2_get_fd(vhd->v4l2_ctx), VIDIOC_QBUF, &buf_v) < 0)
					lwsl_err("%s: VIDIOC_QBUF failed: %s\n", __func__, strerror(errno));
			}
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		/* lws closed one of our capture wsi */
		if (!vhd)
			break;
		if (wsi == vhd->wsi_v4l2)
			vhd->wsi_v4l2 = NULL;
#if defined(LWS_WITH_OPUS)
		if (wsi == vhd->wsi_alsa)
			vhd->wsi_alsa = NULL;
#endif
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
#if defined(LWS_WITH_OPUS)
		if (vhd->alsa_cap)
			lws_alsa_opus_capture_destroy(&vhd->alsa_cap);
#endif
		lws_v4l2_destroy(&vhd->v4l2_ctx);
		if (vhd->jpeg_dec)
			lws_jpeg_free((lws_jpeg_t **)&vhd->jpeg_dec);
		free(vhd->yuv_frame);
		media_deinit(vhd);
		break;

	default: break;
	}

	return 0;
}

#else
static struct lws_context *cx;
static lws_state_notify_link_t nl, *const app_notifier_list[] = {&nl, NULL};

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
callback_webrtc_webcam(struct lws *wsi, enum lws_callback_reasons reason,
		       void *user, void *in, size_t len)
{
	return 0;
}

#endif

static struct lws_protocols protocols[] = {
	{ "app-http", callback_http, 0, 0, 0, NULL, 0 },
	{ "lws-webrtc-webcam", callback_webrtc_webcam, 0, 4096, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_http_mount mount = {
	.mountpoint = "/", .origin = "./mount-origin", .def = "index.html",
	.protocol = "app-http", .origin_protocol = LWSMPRO_FILE, .mountpoint_len = 1,
};

void sigint_handler(int sig) { lws_default_loop_exit(cx); }

static struct lws_protocol_vhost_options pvos[] = {
        { &pvos[1], &pvos[3], "lws-webrtc", "ok" },
        { NULL, &pvos[2], "external-ip", "127.0.0.1" },
        { NULL, NULL, "video-device", "/dev/video0" },
        { &pvos[1], &pvos[4], "lws-webrtc-udp", "ok" },
        { &pvos[1], &pvos[5], "lws-webrtc-webcam", "ok" },
        { NULL, NULL, "app-http", "ok" },
};

static int
app_system_state_nf(lws_state_manager_t *mgr,
                    lws_state_notify_link_t *link, int current,
                    int target) {
        struct lws_context *cx = lws_system_context_from_system_mgr(mgr);
        struct lws_context_creation_info info;
        struct lws_vhost *vh;

        switch (target) {
        case LWS_SYSTATE_OPERATIONAL:
                if (current == LWS_SYSTATE_OPERATIONAL)
                        break;

                lwsl_user("%s: OPERATIONAL->creating vhost\n", __func__);
                lws_context_info_defaults(&info, NULL);info.vhost_name         = "webrtc";
		info.port		= 7681;
		info.protocols          = protocols;
                info.pvo                = pvos;
                info.mounts             = &mount;
                info.options            = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

                vh = lws_create_vhost(cx, &info);
                if (!vh) {
                        lwsl_err("vhost creation failed\n");
                        return 0;
                }

                lws_finalize_startup(cx, __func__);
                break;
        }

        return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *opt;

        lws_context_info_defaults(&info, NULL);
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

        lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		printf("Usage: %s [options]\n", argv[0]);
		printf("Options:\n");
		printf("  --help		Show this help message\n");
		printf("  --video-device	Video device to use (default: /dev/video0)\n");
		printf("  --ip = IP		IP address to bind to (default: 127.0.0.1)\n");
		printf("  --mount-origin = DIR	Directory to serve (default: ./mount-origin)\n");
		return 0;
	}

        signal(SIGINT, sigint_handler);

	info.port               	= 7681;
	info.protocols          	= protocols;
	info.pvo                	= pvos;
        info.options            	= LWS_SERVER_OPTION_SKIP_PROTOCOL_INIT |
					  LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	static const char * const plugin_dirs[] = { "./lib", "./build/lib", NULL };
	info.plugin_dirs = plugin_dirs;

        nl.name				= "app";
        nl.notify_cb			= app_system_state_nf;
        info.register_notifier_list	= app_notifier_list;

        if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_IP].sw)))
                pvos[1].value = opt;
        if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_VIDEO_DEVICE].sw)))
                pvos[2].value = opt;
	if ((opt = lws_cmdline_option(argc, argv, switches[LWS_SW_MOUNT_ORIGIN].sw)))
                mount.origin = opt;

        cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws_create_context failed\n");
		return 1;
	}

        while (lws_service(cx, 0) >= 0)
                ;

	lws_context_destroy(cx);

        return lws_cmdline_passfail(argc, argv, 0);
}
