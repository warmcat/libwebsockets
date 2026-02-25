#include "mixer-media.h"
#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

struct speaker_part {
	struct mixer_media_session *s;
	int energy_history[25];
	int energy_idx;
	uint64_t total_energy;
	lws_usec_t last_speaker_time;
	lws_usec_t join_time;
	int valid_this_update;
};

struct lm_speaker_ctx {
	struct mixer_room *room;
	struct lws_mixer_layout_region *regions;
	int num_regions;
	int max_regions;

	struct speaker_part *parts;
	int num_parts;
	int max_parts;

	struct mixer_media_session *current_speaker;
};

static void *
lm_speaker_create(struct mixer_room *r)
{
	struct lm_speaker_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	
	ctx->room = r;
	return ctx;
}

static void
lm_speaker_destroy(void *vctx)
{
	struct lm_speaker_ctx *ctx = (struct lm_speaker_ctx *)vctx;
	if (ctx) {
		if (ctx->regions)
			free(ctx->regions);
		if (ctx->parts)
			free(ctx->parts);
		free(ctx);
	}
}

static int
sort_parts(const void *a, const void *b)
{
	const struct speaker_part *pa = (const struct speaker_part *)a;
	const struct speaker_part *pb = (const struct speaker_part *)b;

	/* 1. Sort by last speaker time (descending) */
	if (pa->last_speaker_time != pb->last_speaker_time)
		return pa->last_speaker_time > pb->last_speaker_time ? -1 : 1;

	/* 2. Sort by join time (descending: last person to join at the top) */
	if (pa->join_time != pb->join_time)
		return pa->join_time > pb->join_time ? -1 : 1;

	return 0;
}

static void
lm_speaker_update(struct mixer_room *r, void *vctx)
{
	struct lm_speaker_ctx *ctx = (struct lm_speaker_ctx *)vctx;
	struct vhd_mixer *vhd = r->vhd;
	int num_active = 0;

	/* Mark all as invalid for this pass */
	for (int i = 0; i < ctx->num_parts; i++)
		ctx->parts[i].valid_this_update = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
		struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
		
		if (strcmp(s->room_name, r->name))
			goto skip;
		
		if (!s->joined && !s->out_only)
			goto skip;

		num_active++;

		/* Find or create part state */
		struct speaker_part *part = NULL;
		for (int i = 0; i < ctx->num_parts; i++) {
			if (ctx->parts[i].s == s) {
				part = &ctx->parts[i];
				break;
			}
		}

		if (!part) {
			if (ctx->num_parts == ctx->max_parts) {
				ctx->max_parts = ctx->max_parts ? ctx->max_parts * 2 : 16;
				ctx->parts = realloc(ctx->parts, (size_t)ctx->max_parts * sizeof(*ctx->parts));
			}
			part = &ctx->parts[ctx->num_parts++];
			memset(part, 0, sizeof(*part));
			part->s = s;
			part->join_time = lws_now_usecs();
		}

		part->valid_this_update = 1;

		/* Update energy history (last 25 ticks ~ 1 second) */
		part->total_energy -= (uint64_t)part->energy_history[part->energy_idx];
		part->energy_history[part->energy_idx] = s->audio_energy;
		part->total_energy += (uint64_t)s->audio_energy;
		part->energy_idx = (part->energy_idx + 1) % 25;

skip:
	} lws_end_foreach_dll(d);

	/* Compact parts list */
	int w = 0;
	for (int i = 0; i < ctx->num_parts; i++) {
		if (ctx->parts[i].valid_this_update) {
			if (w != i)
				ctx->parts[w] = ctx->parts[i];
			w++;
		} else {
			if (ctx->current_speaker == ctx->parts[i].s)
				ctx->current_speaker = NULL;
		}
	}
	ctx->num_parts = w;

	if (!ctx->num_parts) {
		ctx->num_regions = 0;
		return;
	}

	/* Find highest energy */
	struct speaker_part *best_part = NULL;
	uint64_t max_energy = 0;
	for (int i = 0; i < ctx->num_parts; i++) {
		if (!best_part || ctx->parts[i].total_energy > max_energy) {
			best_part = &ctx->parts[i];
			max_energy = ctx->parts[i].total_energy;
		}
	}

	/* Keep current speaker if energy isn't significantly higher than 0 and there is a current speaker.
	 * Or just switch to max. We'll switch to the one with the highest energy.
	 * If max_energy is 0, keep current speaker if still active, else pick join_time oldest/newest. */
	if (max_energy == 0 && ctx->current_speaker) {
		for (int i = 0; i < ctx->num_parts; i++) {
			if (ctx->parts[i].s == ctx->current_speaker) {
				best_part = &ctx->parts[i];
				break;
			}
		}
	}

	if (best_part) {
		ctx->current_speaker = best_part->s;
		best_part->last_speaker_time = lws_now_usecs();
	}

	/* Allocate regions */
	if (ctx->num_parts > ctx->max_regions) {
		ctx->max_regions = ctx->num_parts;
		ctx->regions = realloc(ctx->regions, (size_t)ctx->max_regions * sizeof(*ctx->regions));
	}
	ctx->num_regions = ctx->num_parts;

	/* Create temporary array for sorting non-speakers */
	struct speaker_part **margin_parts = malloc((size_t)(ctx->num_parts) * sizeof(struct speaker_part *));
	int num_margin = 0;
	for (int i = 0; i < ctx->num_parts; i++) {
		if (ctx->parts[i].s != ctx->current_speaker)
			margin_parts[num_margin++] = &ctx->parts[i];
	}

	/* Sort margin parts */
	// Wait, we can't use qsort on array of pointers easily with our sort_parts unless we adapt it.
	// Actually, sort_parts takes `struct speaker_part *` direct, so we need to deref for pointer array.
	// Let's use a simple insertion sort since N is small.
	for (int i = 1; i < num_margin; i++) {
		struct speaker_part *key = margin_parts[i];
		int j = i - 1;
		while (j >= 0 && sort_parts(margin_parts[j], key) > 0) {
			margin_parts[j + 1] = margin_parts[j];
			j = j - 1;
		}
		margin_parts[j + 1] = key;
	}

	int base_w = (int)r->master_w;
	int base_h = (int)r->master_h;
	
	/* Layout strategy for 1080p:
	 * Speaker: Most space, bottom-left aligned.
	 * Max width for speaker if margin is taking some space: base_w - margin_w
	 */
	int margin_w = base_w > 1280 ? (base_w * 160) / 1920 : (base_w * 15) / 100; // ~160px on 1080p
	int speaker_max_w = base_w - margin_w - 10; // 10px spacing
	
	/* 16:9 ratio for speaker max height */
	int speaker_max_h = (speaker_max_w * 9) / 16;
	if (speaker_max_h > base_h) {
		speaker_max_h = base_h;
		speaker_max_w = (speaker_max_h * 16) / 9;
	}

	// Bottom-left aligned: x=0, y=base_h - speaker_max_h
	int speaker_x = 0;
	// Make sure y doesn't become negative
	int speaker_y = base_h > speaker_max_h ? base_h - speaker_max_h : 0;

	/* Place Speaker */
	ctx->regions[0].s = ctx->current_speaker;
	ctx->regions[0].x = speaker_x;
	ctx->regions[0].y = speaker_y;
	ctx->regions[0].w = speaker_max_w;
	ctx->regions[0].h = speaker_max_h;

	/* Place Margin */
	int margin_item_w = margin_w;
	int margin_item_h = (margin_item_w * 9) / 16;
	int margin_x = base_w - margin_w;
	int margin_y = 10;

	for (int i = 0; i < num_margin; i++) {
		ctx->regions[i + 1].s = margin_parts[i]->s;
		ctx->regions[i + 1].x = margin_x;
		ctx->regions[i + 1].y = margin_y;
		ctx->regions[i + 1].w = margin_item_w;
		ctx->regions[i + 1].h = margin_item_h;

		margin_y += margin_item_h + 10; // 10px spacing between margin items
	}

	free(margin_parts);
}

static const struct lws_mixer_layout_region *
lm_speaker_get_regions(void *vctx, int *count)
{
	struct lm_speaker_ctx *ctx = (struct lm_speaker_ctx *)vctx;
	*count = ctx->num_regions;
	return ctx->regions;
}

static char *
lm_speaker_get_json(void *vctx)
{
	struct lm_speaker_ctx *ctx = (struct lm_speaker_ctx *)vctx;
	char buf[LWS_PRE + 4096];
	char *p = buf + LWS_PRE;
	char *end = buf + sizeof(buf);
	int i;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"type\":\"layout\",\"regions\":[");

	for (i = 0; i < ctx->num_regions; i++) {
		struct lws_mixer_layout_region *reg = &ctx->regions[i];
		struct mixer_media_session *s = reg->s;
		struct participant *part = (struct participant *)s->parent_p;
		
		/* Calculate percentages */
		int x_pct = (reg->x * 100) / (int)ctx->room->master_w;
		int y_pct = (reg->y * 100) / (int)ctx->room->master_h;
		int w_pct = (reg->w * 100) / (int)ctx->room->master_w;
		int h_pct = (reg->h * 100) / (int)ctx->room->master_h;

		if (i > 0)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ",");

		char name_esc[64] = {0};
		char stats_esc[128] = {0};
		if (part) {
			lws_json_purify(name_esc, part->name, sizeof(name_esc), NULL);
			lws_json_purify(stats_esc, part->stats, sizeof(stats_esc), NULL);
		}

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), 
			"{\"x\":%d,\"y\":%d,\"w\":%d,\"h\":%d,\"text\":\"%s\\n%s\"}",
			x_pct, y_pct, w_pct, h_pct, name_esc, stats_esc);
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");

	return strdup(buf + LWS_PRE);
}

LWS_VISIBLE const struct layout_manager_ops lm_speaker_ops = {
	.create = lm_speaker_create,
	.destroy = lm_speaker_destroy,
	.update = lm_speaker_update,
	.get_regions = lm_speaker_get_regions,
	.get_json = lm_speaker_get_json,
};
