#include "mixer-media.h"
#include <libwebsockets.h>

struct lm_quad_ctx {
	struct mixer_room *room;
	struct lws_mixer_layout_region regions[4];
	int num_regions;
};

static void *
lm_quad_create(struct mixer_room *r)
{
	struct lm_quad_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	
	ctx->room = r;
	return ctx;
}

static void
lm_quad_destroy(void *vctx)
{
	struct lm_quad_ctx *ctx = (struct lm_quad_ctx *)vctx;
	if (ctx)
		free(ctx);
}

static void
lm_quad_update(struct mixer_room *r, void *vctx)
{
	struct lm_quad_ctx *ctx = (struct lm_quad_ctx *)vctx;
	struct vhd_mixer *vhd = r->vhd;
	int index = 0;

	ctx->num_regions = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->sessions)) {
		struct mixer_media_session *s = lws_container_of(d, struct mixer_media_session, list);
		
		if (strcmp(s->room_name, r->name))
			goto next_session;
		
		if (!s->joined && !s->out_only)
			goto next_session;

		if (index < 4) {
			int slot_w = (int)r->master_w / 2;
			int slot_h = (int)r->master_h / 2;
			int x = (index % 2) * slot_w;
			int y = (index / 2) * slot_h;

			ctx->regions[index].s = s;
			ctx->regions[index].x = x;
			ctx->regions[index].y = y;
			ctx->regions[index].w = slot_w;
			ctx->regions[index].h = slot_h;
			ctx->num_regions++;
			index++;
		}
next_session:;
	} lws_end_foreach_dll(d);
}

static const struct lws_mixer_layout_region *
lm_quad_get_regions(void *vctx, int *count)
{
	struct lm_quad_ctx *ctx = (struct lm_quad_ctx *)vctx;
	*count = ctx->num_regions;
	return ctx->regions;
}

static char *
lm_quad_get_json(void *vctx)
{
	struct lm_quad_ctx *ctx = (struct lm_quad_ctx *)vctx;
	char buf[LWS_PRE + 2048];
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

LWS_VISIBLE const struct layout_manager_ops lm_quad_ops = {
	.create = lm_quad_create,
	.destroy = lm_quad_destroy,
	.update = lm_quad_update,
	.get_regions = lm_quad_get_regions,
	.get_json = lm_quad_get_json,
};
