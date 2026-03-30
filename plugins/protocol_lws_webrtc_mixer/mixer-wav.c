/*
 * lws-webrtc-mixer - wav loader and mixer
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "mixer-media.h"

/* Minimal WAV header parsing */
struct wav_header {
	uint8_t     riff[4];        /* "RIFF" */
	uint32_t    overall_size;
	uint8_t     wave[4];        /* "WAVE" */
	uint8_t     fmt_chunk_marker[4]; /* "fmt " */
	uint32_t    length_fmt;
	uint16_t    format_type;    /* 1 = PCM */
	uint16_t    channels;
	uint32_t    sample_rate;
	uint32_t    byterate;
	uint16_t    block_align;
	uint16_t    bits_per_sample;
	uint8_t     data_chunk_header[4]; /* "data" */
	uint32_t    data_size;
} __attribute__((packed));

int
load_sound_clip(struct sound_clip *sc, const char *path)
{
	int fd = open(path, O_RDONLY);
	struct wav_header h;
	ssize_t n;
	int16_t *orig_samples;

	if (fd < 0) {
		lwsl_err("%s: Unable to open '%s'\n", __func__, path);
		return -1;
	}

	n = read(fd, &h, sizeof(h));
	if (n != sizeof(h)) {
		lwsl_err("%s: Bad header read in '%s'\n", __func__, path);
		close(fd);
		return -1;
	}

	if (memcmp(h.riff, "RIFF", 4) || memcmp(h.wave, "WAVE", 4)) {
		lwsl_err("%s: invalid wav format '%s'\n", __func__, path);
		close(fd);
		return -1;
	}

	if (h.format_type != 1) {
		lwsl_err("%s: only PCM supported '%s'\n", __func__, path);
		close(fd);
		return -1;
	}

	if (h.bits_per_sample != 16) {
		lwsl_err("%s: only 16-bit supported '%s'\n", __func__, path);
		close(fd);
		return -1;
	}

	size_t samples_count = h.data_size / 2;
	orig_samples = malloc(h.data_size);
	if (!orig_samples) {
		close(fd);
		return -1;
	}

	n = read(fd, orig_samples, h.data_size);
	close(fd);
	if (n != h.data_size) {
		lwsl_warn("%s: short read on data\n", __func__);
	}

	/* Resampling / Channel mixing if needed */
	/* Target: AUDIO_RATE (48000), 1 Channel */

	if (h.sample_rate == AUDIO_RATE && h.channels == 1) {
		sc->samples = orig_samples;
		sc->length_samples = samples_count;
		sc->channels = 1;
		lwsl_notice("%s: Loaded '%s': %lu samples, 48kHz Mono\n", __func__, path, (unsigned long)sc->length_samples);
		return 0;
	}

	/* Naive Resampling / Mixing */
	size_t frames_in = samples_count / h.channels;
	size_t frames_out = (size_t)((uint64_t)frames_in * AUDIO_RATE / h.sample_rate);

	int16_t *new_samples = malloc(frames_out * sizeof(int16_t));
	if (!new_samples) {
		free(orig_samples);
		return -1;
	}

	for (size_t i = 0; i < frames_out; i++) {
		size_t src_idx = (size_t)((uint64_t)i * h.sample_rate / AUDIO_RATE);
		if (src_idx >= frames_in) src_idx = frames_in - 1;

		int32_t val = 0;
		if (h.channels == 1) {
			val = orig_samples[src_idx];
		} else {
			/* Mix stereo to mono */
			val = (orig_samples[src_idx * 2] + orig_samples[src_idx * 2 + 1]) / 2;
		}
		new_samples[i] = (int16_t)val;
	}

	free(orig_samples);
	sc->samples = new_samples;
	sc->length_samples = frames_out;
	sc->channels = 1;

	lwsl_notice("%s: Loaded '%s' (Resampled): %lu samples\n", __func__, path, (unsigned long)sc->length_samples);

	return 0;
}

void
play_sound(struct mixer_room *r, struct sound_clip *sc, struct participant *exclude)
{
	if (!sc || !sc->samples) return;

	struct active_sound *as = malloc(sizeof(*as));
	if (!as) return;

	memset(as, 0, sizeof(*as));
	as->clip = sc;
	as->offset = 0;
	as->exclude_p = exclude;
	as->last_mix_len = 0;

	lws_dll2_add_tail(&as->list, &r->playing_sounds);
}

void
mix_sounds(struct mixer_room *r, int32_t *mix_buf, int samples)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&r->playing_sounds)) {
		struct active_sound *as = lws_container_of(d, struct active_sound, list);

		int samples_to_mix = samples;
		int remaining_in_clip = (int)(as->clip->length_samples - as->offset);

		if (samples_to_mix > remaining_in_clip)
			samples_to_mix = remaining_in_clip;

		for (int i = 0; i < samples_to_mix; i++) {
			mix_buf[i] += as->clip->samples[as->offset + (size_t)i];
		}

		as->offset += (size_t)samples_to_mix;
		as->last_mix_len = samples_to_mix;

		/* We do NOT remove here anymore, we wait for prune_sounds after broadcast */
	} lws_end_foreach_dll_safe(d, d1);
}

void
prune_sounds(struct mixer_room *r)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&r->playing_sounds)) {
		struct active_sound *as = lws_container_of(d, struct active_sound, list);

		if (as->offset >= as->clip->length_samples) {
			lws_dll2_remove(&as->list);
			free(as);
		}
	} lws_end_foreach_dll_safe(d, d1);
}
