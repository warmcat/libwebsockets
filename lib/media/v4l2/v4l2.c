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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>

#if defined(LWS_WITH_V4L2) && defined(LWS_HAVE_LINUX_VIDEODEV2_H)
#include <linux/videodev2.h>

#define LWS_V4L2_BUF_COUNT 4

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "private-lib-core.h"

#if defined(LWS_HAVE_LIBV4L2)
#include <libv4l2.h>
#endif

struct lws_v4l2_ctx {
	struct lws_v4l2_info	info;
	int			fd;

	struct {
		void		*start;
		size_t		length;
	} *buffers;
	int			n_buffers;
};

struct lws_v4l2_ctx *
lws_v4l2_create(const struct lws_v4l2_info *info)
{
	struct lws_v4l2_ctx *ctx = lws_zalloc(sizeof(*ctx), "v4l2-ctx");
	struct v4l2_requestbuffers req;
	struct v4l2_capability cap;
	struct v4l2_format fmt;

	if (!ctx)
		return NULL;

	ctx->info = *info;
    /* Use raw open for video path to ensure reliability */
	ctx->fd = open(info->device_path, O_RDWR | O_NONBLOCK, 0);
	if (ctx->fd < 0)
		goto bail;

	if (ioctl(ctx->fd, VIDIOC_QUERYCAP, &cap) < 0)
		goto bail;

	memset(&fmt, 0, sizeof(fmt));
	fmt.type		= V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width       = info->width;
	fmt.fmt.pix.height      = info->height;
	fmt.fmt.pix.pixelformat = info->pixelformat;
	fmt.fmt.pix.field       = V4L2_FIELD_ANY;

	if (ioctl(ctx->fd, VIDIOC_S_FMT, &fmt) < 0)
		goto bail;

	ctx->info.width = fmt.fmt.pix.width;
	ctx->info.height = fmt.fmt.pix.height;
	ctx->info.pixelformat = fmt.fmt.pix.pixelformat;

	memset(&req, 0, sizeof(req));
	req.count               = LWS_V4L2_BUF_COUNT;
	req.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory              = V4L2_MEMORY_MMAP;

	if (ioctl(ctx->fd, VIDIOC_REQBUFS, &req) < 0)
		goto bail;

	ctx->buffers = lws_zalloc(sizeof(*ctx->buffers) * req.count, "v4l2-bufs");
	if (!ctx->buffers)
		goto bail;

	for (ctx->n_buffers = 0; (uint32_t)ctx->n_buffers < req.count; ctx->n_buffers++) {
		struct v4l2_buffer buf;

		memset(&buf, 0, sizeof(buf));
		buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory      = V4L2_MEMORY_MMAP;
		buf.index       = (uint32_t)ctx->n_buffers;
		if (ioctl(ctx->fd, VIDIOC_QUERYBUF, &buf) < 0)
			goto bail;

		ctx->buffers[ctx->n_buffers].length = buf.length;
		ctx->buffers[ctx->n_buffers].start = mmap(NULL, buf.length,
				PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, buf.m.offset);

		if (ioctl(ctx->fd, VIDIOC_QBUF, &buf) < 0)
			goto bail;
	}

	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(ctx->fd, VIDIOC_STREAMON, &type) < 0)
		goto bail;

	return ctx;

bail:
	lws_v4l2_destroy(&ctx);
	return NULL;
}

void
lws_v4l2_destroy(struct lws_v4l2_ctx **ctx)
{
	if (!ctx || !*ctx)
		return;

	if ((*ctx)->fd >= 0) {
		enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		ioctl((*ctx)->fd, VIDIOC_STREAMOFF, &type);

		for (int i = 0; i < (*ctx)->n_buffers; i++)
			munmap((*ctx)->buffers[i].start, (*ctx)->buffers[i].length);

		close((*ctx)->fd);
	}

	lws_free((*ctx)->buffers);
	lws_free(*ctx);
	*ctx = NULL;
}

int
lws_v4l2_get_buffer(struct lws_v4l2_ctx *ctx, int index, void **start, size_t *len)
{
	if (!ctx || index < 0 || index >= ctx->n_buffers)
		return -1;

	if (start)
		*start = ctx->buffers[index].start;
	if (len)
		*len = ctx->buffers[index].length;

	return 0;
}

int
lws_v4l2_get_fd(struct lws_v4l2_ctx *ctx)
{
	return ctx ? ctx->fd : -1;
}

int
lws_v4l2_get_info(struct lws_v4l2_ctx *ctx, struct lws_v4l2_info *info)
{
	if (!ctx || !info)
		return -1;

	*info = ctx->info;

	return 0;
}

/*
 * Hybrid Control Handling:
 * Open a separate fd using v4l2_open (if available) to leverage libv4l2 for controls.
 * This avoids breaking the main video stream which relies on raw ioctls.
 */
int
lws_v4l2_enum_controls(struct lws_v4l2_ctx *ctx, lws_v4l2_control_cb cb, void *user)
{
	struct v4l2_queryctrl queryctrl;
	struct lws_v4l2_control c;
	struct v4l2_control control;
    int cfd;
    int res;

	if (!ctx)
		return -1;

    /* Open a separate fd for controls */
#if defined(LWS_HAVE_LIBV4L2)
    cfd = v4l2_open(ctx->info.device_path, O_RDWR, 0);
    lwsl_notice("%s: Using v4l2_open for controls, fd %d\n", __func__, cfd);
#else
    cfd = open(ctx->info.device_path, O_RDWR, 0);
    lwsl_notice("%s: Using raw open for controls, fd %d\n", __func__, cfd);
#endif

    if (cfd < 0) {
        lwsl_err("%s: Failed to open control fd\n", __func__);
        return -1;
    }

	memset(&queryctrl, 0, sizeof(queryctrl));
	queryctrl.id = V4L2_CTRL_FLAG_NEXT_CTRL;

    /* Use local macro to switch between ioctl and v4l2_ioctl based on build */
#if defined(LWS_HAVE_LIBV4L2)
    #define LWS_CTRL_IOCTL(fd, req, arg) v4l2_ioctl(fd, req, arg)
#else
    #define LWS_CTRL_IOCTL(fd, req, arg) ioctl(fd, req, arg)
#endif

	while ((res = LWS_CTRL_IOCTL(cfd, VIDIOC_QUERYCTRL, &queryctrl)) == 0) {
		if (!(queryctrl.flags & V4L2_CTRL_FLAG_DISABLED)) {
			memset(&c, 0, sizeof(c));
			c.id = queryctrl.id;
			lws_strncpy(c.name, (const char *)queryctrl.name, sizeof(c.name));
			c.min = queryctrl.minimum;
			c.max = queryctrl.maximum;
			c.step = queryctrl.step;
			c.def = queryctrl.default_value;

			memset(&control, 0, sizeof(control));
			control.id = queryctrl.id;
			if (LWS_CTRL_IOCTL(cfd, VIDIOC_G_CTRL, &control) == 0)
				c.val = control.value;

			if (cb(user, &c))
				break;
		}
		queryctrl.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
	}

	/* Fallback if NEXT_CTRL is not supported */
	if (queryctrl.id == V4L2_CTRL_FLAG_NEXT_CTRL) {
        lwsl_notice("%s: NEXT_CTRL failed, trying legacy scan...\n", __func__);
#if defined(VIDIOC_QUERY_EXT_CTRL)
        struct v4l2_query_ext_ctrl ext_ctrl;
#endif
		for (queryctrl.id = V4L2_CID_BASE; queryctrl.id < V4L2_CID_LASTP1; queryctrl.id++) {
            int found = 0;
			if (LWS_CTRL_IOCTL(cfd, VIDIOC_QUERYCTRL, &queryctrl) == 0) {
                 found = 1;
            }
#if defined(VIDIOC_QUERY_EXT_CTRL)
            else if (errno == ENOTTY || errno == EINVAL) {
                 /* Try extended QUERY_EXT_CTRL */
                 memset(&ext_ctrl, 0, sizeof(ext_ctrl));
                 ext_ctrl.id = queryctrl.id;
                 if (LWS_CTRL_IOCTL(cfd, VIDIOC_QUERY_EXT_CTRL, &ext_ctrl) == 0) {
                      queryctrl.type = ext_ctrl.type;
                      lws_strncpy((char *)queryctrl.name, (const char *)ext_ctrl.name, sizeof(queryctrl.name));
                      queryctrl.minimum = (int32_t)ext_ctrl.minimum;
                      queryctrl.maximum = (int32_t)ext_ctrl.maximum;
                      queryctrl.step = (int32_t)ext_ctrl.step;
                      queryctrl.default_value = (int32_t)ext_ctrl.default_value;
                      queryctrl.flags = ext_ctrl.flags;
                      found = 1;
                 }
            }
#endif
            if (found) {
				if (!(queryctrl.flags & V4L2_CTRL_FLAG_DISABLED)) {
					memset(&c, 0, sizeof(c));
					c.id = queryctrl.id;
                    c.type = queryctrl.type;
					lws_strncpy(c.name, (const char *)queryctrl.name, sizeof(c.name));
					c.min = queryctrl.minimum;
					c.max = queryctrl.maximum;
					c.step = queryctrl.step;
					c.def = queryctrl.default_value;

					memset(&control, 0, sizeof(control));
					control.id = queryctrl.id;
					if (LWS_CTRL_IOCTL(cfd, VIDIOC_G_CTRL, &control) == 0)
						c.val = control.value;

					if (cb(user, &c))
						break;
				}
			}
		}
	}

#if defined(LWS_HAVE_LIBV4L2)
    v4l2_close(cfd);
#else
    close(cfd);
#endif
	return 0;
 }

int
lws_v4l2_set_control(struct lws_v4l2_ctx *ctx, uint32_t id, int32_t val)
{
	struct v4l2_control control;
    int cfd;

	if (!ctx)
		return -1;

#if defined(LWS_HAVE_LIBV4L2)
    cfd = v4l2_open(ctx->info.device_path, O_RDWR, 0);
#else
    cfd = open(ctx->info.device_path, O_RDWR, 0);
#endif

    if (cfd < 0) {
        lwsl_err("%s: Failed to open control fd\n", __func__);
        return -1;
    }

	memset(&control, 0, sizeof(control));
	control.id = id;
	control.value = val;

	if (LWS_CTRL_IOCTL(cfd, VIDIOC_S_CTRL, &control) < 0) {
		lwsl_err("%s: VIDIOC_S_CTRL failed for 0x%x\n", __func__, id);
#if defined(LWS_HAVE_LIBV4L2)
        v4l2_close(cfd);
#else
        close(cfd);
#endif
		return -1;
	}

#if defined(LWS_HAVE_LIBV4L2)
    v4l2_close(cfd);
#else
    close(cfd);
#endif
	return 0;
 }

int
lws_v4l2_native_ioctl(struct lws_v4l2_ctx *ctx, unsigned long request, void *arg)
{
    if (!ctx) return -1;
    return ioctl(ctx->fd, request, arg);
}

#endif
