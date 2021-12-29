/*
 * lws abstract display
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
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
 *
 * Secure Streams as DLO transport
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

LWS_SS_USER_TYPEDEF
	sul_cb_t			on_rx;
	lhp_ctx_t			*lhp;
	lws_sorted_usec_list_t		*ssevsul; /* sul to use to resume rz */
	lws_sorted_usec_list_t		sul; /* used for initial metadata cb */
	lws_dlo_image_t			u; /* we use the lws_flow_t in here */
	lws_dll2_t			active_asset_list; /*cx->active_assets*/
	uint8_t				type; /* LWSDLOSS_TYPE_ */
	char				url[96];
} dloss_t;

/*
 * dlo images call back here when they have their dimensions (or have failed)
 */

void
lws_lhp_image_dimensions_cb(lws_sorted_usec_list_t *sul)
{
	dloss_t *m = lws_container_of(sul, dloss_t, sul);
	lws_display_render_state_t *rs = lws_container_of(m->ssevsul,
				lws_display_render_state_t, sul);
	lws_dlo_dim_t dim;
	lws_dlo_t *dlo = &m->u.u.dlo_png->dlo;

	if (m->u.failed) {
		dlo->box.w.whole = -1;
		dlo->box.h.whole = -1;
		lwsl_notice("%s: Failing %s\n", __func__, m->url);
	} else {

		dlo->box.w.whole = (int32_t)lws_dlo_image_width(&m->u);
		dlo->box.h.whole = (int32_t)lws_dlo_image_height(&m->u);

		lwsl_err("%s: setting dlo box %d x %d\n", __func__,
			(int)dlo->box.w.whole, (int)dlo->box.h.whole);
#if 1
		lws_dlo_contents(dlo, &dim);
		lws_display_dlo_adjust_dims(dlo, &dim);

		if (dlo->list.owner) {
			dlo = lws_container_of(dlo->list.owner, lws_dlo_t, children);

			lws_dlo_contents(dlo, &dim);
			lws_display_dlo_adjust_dims(dlo, &dim);
		}
#endif
	}

	if (rs->html != 1) {
		lws_sul_schedule(lws_ss_get_context(m->ss), 0, m->ssevsul, m->on_rx, 1);
		return;
	}

	/* we are resuming the html parsing */
	lws_lhp_ss_html_parse_from_lhp(m->lhp);
}

/* secure streams payload interface */

static lws_ss_state_return_t
dloss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	dloss_t *m = (dloss_t *)userobj;
	lws_stateful_ret_t r;

	lwsl_info("%s: %u\n", __func__, (unsigned int)len);

	if (m->type == LWSDLOSS_TYPE_CSS) {
		m->lhp->finish_css = !!(flags & LWSSS_FLAG_EOM);
		m->lhp->is_css = 1;
		r = lws_lhp_parse(m->lhp, &buf, &len);
		m->lhp->is_css = 0;

		if (flags & LWSSS_FLAG_EOM)
			lws_dll2_remove(&m->active_asset_list);

		if (r & LWS_SRET_FATAL)
			return LWSSSSRET_DISCONNECT_ME;

		if (r & LWS_SRET_AWAIT_RETRY) {
			lwsl_warn("%s: returning to await retry\n", __func__);
			if (!m->lhp->await_css_done)
				lws_sul_schedule(lws_ss_get_context(m->ss), 0,
						 m->lhp->sshtmlevsul,
						 m->lhp->sshtmlevcb, 1);
		}
		goto okie;
	}

	/* .flow is at the same offset in both dlo_jpeg and dlo_png */

	if (len &&
	    lws_buflist_append_segment(&m->u.u.dlo_jpeg->flow.bl, buf, len) < 0) {
		m->u.failed = 1;
		lws_sul_schedule(lws_ss_get_context(m->ss), 0,
				&m->sul, lws_lhp_image_dimensions_cb, 1);
		return LWSSSSRET_DISCONNECT_ME;
	}

	// lwsl_notice("%s: buflen size %d\n", __func__,
	//		(int)lws_buflist_total_len(&m->u.u.dlo_jpeg->flow.bl));

	if (flags & LWSSS_FLAG_EOM) {
		m->u.u.dlo_jpeg->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		return LWSSSSRET_DISCONNECT_ME;
	}

	if (!lws_dlo_image_width(&m->u)) {
		lws_flow_feed(&m->u.u.dlo_jpeg->flow);
		r = lws_dlo_image_metadata_scan(&m->u);
		lws_flow_req(&m->u.u.dlo_jpeg->flow);

		if (r & LWS_SRET_FATAL) {
			m->u.failed = 1;
			lws_sul_schedule(lws_ss_get_context(m->ss), 0,
					&m->sul, lws_lhp_image_dimensions_cb, 1);
			return LWSSSSRET_DISCONNECT_ME;
		}

		if (r != LWS_SRET_WANT_INPUT) {
			lwsl_notice("%s: seen metadata\n", __func__);
			lws_sul_schedule(lws_ss_get_context(m->ss), 0,
					&m->sul, lws_lhp_image_dimensions_cb, 1);
		} //else
			//lwsl_err("%s: metadata scan no end yet\n", __func__);

		return LWSSSSRET_OK;
	}
okie:
	lws_sul_schedule(lws_ss_get_context(m->ss), 0, m->ssevsul, m->on_rx, 1);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
dloss_state(void *userobj, void *sh, lws_ss_constate_t state,
	    lws_ss_tx_ordinal_t ack)
{
	dloss_t *m = (dloss_t *)userobj;

	switch (state) {
	case LWSSSCS_CREATING:
		break;

	case LWSSSCS_DESTROYING:
		lws_sul_cancel(&m->sul);
		lws_dll2_remove(&m->active_asset_list);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("__default", dloss_t)
	.rx				= dloss_rx,
	.state				= dloss_state
};

/*
 * If we have an active image asset from this URL, return a pointer to its
 * dlo image (ie, dlo_jpeg or dlo_png)
 */

int
lws_dlo_ss_find(struct lws_context *cx, const char *url, lws_dlo_image_t *u)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);

		if (!strcmp(url, ds->url)) {
			*u = ds->u;

			return 0; /* found */
		}

	} lws_end_foreach_dll(d);

	return 1; /* not found */
}

int
lws_dlo_ss_create(lws_dlo_ss_create_info_t *i, lws_dlo_t **pdlo)
{
	lws_dlo_jpeg_t *dlo_jpeg = NULL;
	lws_dlo_png_t *dlo_png = NULL;
	size_t ul = strlen(i->url);
	struct lws_ss_handle *h;
	lws_dlo_t *dlo = NULL;
	lws_ss_info_t ssi;
	dloss_t *dloss;
	uint8_t type;

	if (ul < 5)
		return 1;

	if (!strcmp(i->url + ul - 4, ".png"))
		type = LWSDLOSS_TYPE_PNG;
	else
		if (!strcmp(i->url + ul - 4, ".jpg") ||
		    !strcmp(i->url + ul - 5, ".jpeg"))
			type = LWSDLOSS_TYPE_JPEG;
		else
			if (!strcmp(i->url + ul - 4, ".css"))
				type = LWSDLOSS_TYPE_CSS;
			else {
				lwsl_err("%s: unknown file type %s\n", __func__, i->url);
				return 1;
			}

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		dlo_png = lws_display_dlo_png_new(i->dl, i->dlo_parent, i->box);
		if (!dlo_png)
			return 1;

		i->u->u.dlo_png = dlo_png;

		dlo_png->dlo.box.w.whole = (int32_t)
			lws_upng_get_width(dlo_png->png);
		dlo_png->dlo.box.w.frac = 0;
		dlo_png->dlo.box.h.whole = (int32_t)
			lws_upng_get_height(dlo_png->png);
		dlo_png->dlo.box.h.frac = 0;

		dlo = &dlo_png->dlo;
		break;

	case LWSDLOSS_TYPE_JPEG:
		dlo_jpeg = lws_display_dlo_jpeg_new(i->dl, i->dlo_parent, i->box);
		if (!dlo_jpeg)
			return 1;

		i->u->u.dlo_jpeg = dlo_jpeg;

		dlo_jpeg->dlo.box.w.whole = (int32_t)
			lws_jpeg_get_width(dlo_jpeg->j);
		dlo_jpeg->dlo.box.w.frac = 0;
		dlo_jpeg->dlo.box.h.whole = (int32_t)
			lws_jpeg_get_height(dlo_jpeg->j);
		dlo_jpeg->dlo.box.h.frac = 0;

		dlo = &dlo_jpeg->dlo;
		break;
	}

	/* we adapt the initial tx credit also to the requested window */

	ssi = ssi_dloss_t;
	ssi.manual_initial_tx_credit = i->window;

	if (lws_ss_create(i->cx, 0, &ssi, (void *)dlo, &h, NULL, NULL)) {
		lwsl_notice("%s: unable to create ss\n", __func__);
		return 1;
	}

	dloss = (dloss_t *)lws_ss_to_user_object(h);
	dloss->u.type = (lws_dlo_image_type_t)type;
	dloss->on_rx = i->on_rx;
	dloss->ssevsul = i->on_rx_sul;
	dloss->lhp = i->lhp;
	dloss->type = type;

	lws_strncpy(dloss->url, i->url, sizeof(dloss->url));

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		dloss->u.u.dlo_png = dlo_png;
		dlo_png->flow.h = h;
		dlo_png->flow.window = i->window;
		break;
	case LWSDLOSS_TYPE_JPEG:
		dloss->u.u.dlo_jpeg = dlo_jpeg;
		dlo_jpeg->flow.h = h;
		dlo_jpeg->flow.window = i->window;
		break;
	}

	if (lws_ss_alloc_set_metadata(h, "endpoint", i->url, ul)) {
		lwsl_err("%s: unable to set endpoint\n", __func__);
		goto fail;
	}

	if (lws_ss_client_connect(dloss->ss)) {
		lwsl_err("%s: unable to do client connection\n", __func__);
		goto fail;
	}

	lws_dll2_add_tail(&dloss->active_asset_list, &i->cx->active_assets);

	lwsl_notice("%s: starting %s (dlo %p)\n", __func__, i->url, dlo);

	*pdlo = dlo;

	return 0;

fail:
	lws_ss_destroy(&h);

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		lws_display_dlo_png_destroy(&dlo_png->dlo);
		break;
	case LWSDLOSS_TYPE_JPEG:
		lws_display_dlo_jpeg_destroy(&dlo_jpeg->dlo);
		break;
	}

	return 1;
}
