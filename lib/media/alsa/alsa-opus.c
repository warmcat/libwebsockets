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

#include <libwebsockets.h>

#if defined(LWS_WITH_OPUS) && defined(LWS_WITH_ALSA)

#include <opus/opus.h>
#include <string.h>

struct lws_alsa_opus_capture {
	struct lws_alsa_ctx *alsa_ctx;
	OpusEncoder *opus_enc;
	lws_alsa_opus_encoded_cb_t cb;
	void *user_data;

	uint32_t samples_per_frame;
	int16_t *audio_samples;
	uint8_t opus_out[512];
};

struct lws_alsa_opus_capture *
lws_alsa_opus_capture_create(const struct lws_alsa_info *info, lws_alsa_opus_encoded_cb_t cb, void *user_data)
{
	struct lws_alsa_opus_capture *cap;
	int err;

	cap = lws_malloc(sizeof(*cap), __func__);
	if (!cap)
		return NULL;

	memset(cap, 0, sizeof(*cap));

	cap->alsa_ctx = lws_alsa_create_capture(info);
	if (!cap->alsa_ctx) {
		lwsl_err("%s: Failed to create ALSA capture\n", __func__);
		goto bail;
	}

	cap->opus_enc = opus_encoder_create((opus_int32)info->rate, (int)info->channels, OPUS_APPLICATION_VOIP, &err);
	if (!cap->opus_enc || err != OPUS_OK) {
		lwsl_err("%s: Failed to create Opus encoder\n", __func__);
		goto bail;
	}

	cap->samples_per_frame = info->samples_per_frame;
	cap->audio_samples = lws_malloc(cap->samples_per_frame * sizeof(int16_t) * info->channels, __func__);
	if (!cap->audio_samples)
		goto bail;

	cap->cb = cb;
	cap->user_data = user_data;

	return cap;

bail:
	lws_alsa_opus_capture_destroy(&cap);
	return NULL;
}

void
lws_alsa_opus_capture_destroy(struct lws_alsa_opus_capture **_cap)
{
	struct lws_alsa_opus_capture *cap = *_cap;

	if (!cap)
		return;

	if (cap->alsa_ctx)
		lws_alsa_destroy(&cap->alsa_ctx);

	if (cap->opus_enc)
		opus_encoder_destroy(cap->opus_enc);

	if (cap->audio_samples)
		lws_free(cap->audio_samples);

	lws_free(cap);
	*_cap = NULL;
}

int
lws_alsa_opus_get_fd(struct lws_alsa_opus_capture *cap)
{
	if (!cap || !cap->alsa_ctx)
		return -1;
	return lws_alsa_get_fd(cap->alsa_ctx);
}

int
lws_alsa_opus_read(struct lws_alsa_opus_capture *cap)
{
	int n, opus_len;

	if (!cap || !cap->alsa_ctx || !cap->opus_enc)
		return -1;

	n = lws_alsa_read(cap->alsa_ctx, cap->audio_samples, cap->samples_per_frame);
	if (n <= 0)
		return 0;

	opus_len = opus_encode(cap->opus_enc, cap->audio_samples, n, cap->opus_out, sizeof(cap->opus_out));
	if (opus_len > 0 && cap->cb) {
		cap->cb(cap->user_data, cap->opus_out, (size_t)opus_len);
	}

	return 0;
}

struct json_dump_ctx {
	char *p;
	char *end;
	int first;
};

static int alsa_json_control_cb(void *user, const struct lws_alsa_control *c)
{
	struct json_dump_ctx *j = (struct json_dump_ctx *)user;
	char safe_name[256];
	int len;

	if (lws_ptr_diff_size_t(j->end, j->p) < 128)
		return 1;

	if (!j->first)
		*j->p++ = ',';

	j->first = 0;

	lws_json_purify(safe_name, c->name, sizeof(safe_name), &len);

	j->p += lws_snprintf(
			j->p, lws_ptr_diff_size_t(j->end, j->p),
			"{\"id\":%u,\"name\":\"%s\","
			"\"min\":%ld,\"max\":%ld,\"step\":%ld,\"val\":%ld}",
			c->id, safe_name, c->min, c->max, c->step, c->val);

	return 0;
}

int
lws_alsa_opus_send_capabilities(struct lws_alsa_opus_capture *cap, char *buf, size_t max_len)
{
	struct json_dump_ctx j;

	if (!cap || !cap->alsa_ctx)
		return -1;

	j.p = buf;
	j.end = buf + max_len;
	j.first = 1;

	j.p += lws_snprintf(j.p, lws_ptr_diff_size_t(j.end, j.p),
			"{\"type\":\"capabilities\",\"kind\":\"audio\",\"controls\":[");

	lws_alsa_enum_controls(cap->alsa_ctx, alsa_json_control_cb, &j);

	j.p += lws_snprintf(j.p, lws_ptr_diff_size_t(j.end, j.p), "]}");

	return (int)lws_ptr_diff_size_t(j.p, buf);
}

int
lws_alsa_opus_set_control(struct lws_alsa_opus_capture *cap, uint32_t id, long val)
{
	if (!cap || !cap->alsa_ctx)
		return -1;
	return lws_alsa_set_control(cap->alsa_ctx, id, val);
}

#endif
