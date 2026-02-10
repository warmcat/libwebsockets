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
#include <libwebsockets/lws-alsa.h>
#include <alsa/asoundlib.h>
#include <string.h>

#include "private-lib-core.h"

struct lws_alsa_ctx {
	struct lws_alsa_info	info;
	snd_pcm_t		*pcm_capture;
	snd_mixer_t		*mixer;
};

struct lws_alsa_ctx *
lws_alsa_create_capture(const struct lws_alsa_info *info)
{
	struct lws_alsa_ctx *ctx = lws_zalloc(sizeof(*ctx), "alsa-ctx");
	snd_pcm_hw_params_t *params;
	unsigned int rate;
	int n;

	if (!ctx)
		return NULL;

	ctx->info = *info;
	rate = info->rate;

	n = snd_pcm_open(&ctx->pcm_capture, info->device_name, SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
	if (n < 0)
		goto bail;

	n = snd_pcm_hw_params_malloc(&params);
	if (n < 0)
		goto bail;

	snd_pcm_hw_params_any(ctx->pcm_capture, params);
	snd_pcm_hw_params_set_access(ctx->pcm_capture, params, SND_PCM_ACCESS_RW_INTERLEAVED);
	snd_pcm_hw_params_set_format(ctx->pcm_capture, params, SND_PCM_FORMAT_S16_LE);
	snd_pcm_hw_params_set_channels(ctx->pcm_capture, params, info->channels);
	snd_pcm_hw_params_set_rate_near(ctx->pcm_capture, params, &rate, 0);

	n = snd_pcm_hw_params(ctx->pcm_capture, params);
	snd_pcm_hw_params_free(params);
	if (n < 0)
		goto bail;

	ctx->info.rate = rate;

	/* Setup mixer for controls */
	if (snd_mixer_open(&ctx->mixer, 0) == 0) {
		if (snd_mixer_attach(ctx->mixer, info->device_name) < 0 ||
		    snd_mixer_selem_register(ctx->mixer, NULL, NULL) < 0 ||
		    snd_mixer_load(ctx->mixer) < 0) {
			snd_mixer_close(ctx->mixer);
			ctx->mixer = NULL;
		}
	}

	return ctx;

bail:
	lws_alsa_destroy(&ctx);
	return NULL;
}

void
lws_alsa_destroy(struct lws_alsa_ctx **ctx)
{
	if (!ctx || !*ctx)
		return;

	if ((*ctx)->pcm_capture)
		snd_pcm_close((*ctx)->pcm_capture);

	if ((*ctx)->mixer)
		snd_mixer_close((*ctx)->mixer);

	lws_free(*ctx);
	*ctx = NULL;
}

int
lws_alsa_get_fd(struct lws_alsa_ctx *ctx)
{
	struct pollfd pfd;

	if (!ctx || !ctx->pcm_capture)
		return -1;

	if (snd_pcm_poll_descriptors(ctx->pcm_capture, &pfd, 1) != 1)
		return -1;

	return pfd.fd;
}

int
lws_alsa_read(struct lws_alsa_ctx *ctx, void *buf, size_t samples)
{
	int n;

	if (!ctx || !ctx->pcm_capture)
		return -1;

	n = (int)snd_pcm_readi(ctx->pcm_capture, buf, samples);
	if (n < 0) {
		if (n == -EPIPE)
			snd_pcm_prepare(ctx->pcm_capture);
		return 0;
	}

	return n;
}

int
lws_alsa_enum_controls(struct lws_alsa_ctx *ctx, lws_alsa_control_cb cb, void *user)
{
	snd_mixer_elem_t *elem;
	struct lws_alsa_control c;
	long min, max;
	int count = 0;

	if (!ctx || !ctx->mixer)
		return -1;

	for (elem = snd_mixer_first_elem(ctx->mixer); elem; elem = snd_mixer_elem_next(elem)) {
		if (!snd_mixer_selem_is_active(elem))
			continue;

		if (snd_mixer_selem_has_capture_volume(elem)) {
			memset(&c, 0, sizeof(c));
			c.id = (uint32_t)count++;
			lws_strncpy(c.name, snd_mixer_selem_get_name(elem), sizeof(c.name));
			snd_mixer_selem_get_capture_volume_range(elem, &min, &max);
			c.min = min;
			c.max = max;
			c.step = 1;
			snd_mixer_selem_get_capture_volume(elem, SND_MIXER_SCHN_FRONT_LEFT, &c.val);

			if (cb(user, &c))
				return 0;
		}
	}

	return 0;
}

int
lws_alsa_set_control(struct lws_alsa_ctx *ctx, uint32_t id, long val)
{
	snd_mixer_elem_t *elem;
	uint32_t count = 0;

	if (!ctx || !ctx->mixer)
		return -1;

	for (elem = snd_mixer_first_elem(ctx->mixer); elem; elem = snd_mixer_elem_next(elem)) {
		if (!snd_mixer_selem_is_active(elem))
			continue;

		if (snd_mixer_selem_has_capture_volume(elem)) {
			if (count == id) {
				snd_mixer_selem_set_capture_volume_all(elem, val);
				return 0;
			}
			count++;
		}
	}

	return -1;
}
