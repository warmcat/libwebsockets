/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 * SS bindings for html5 parser
 */

#include <private-lib-core.h>

LWS_SS_USER_TYPEDEF
	lws_flow_t			flow;
	lhp_ctx_t			lhp; /* html ss owns html parser */
	lws_dl_rend_t			drt;
	lws_sorted_usec_list_t		sul;
	lws_display_render_state_t	*rs;
	struct lws_context		*cx;
} htmlss_t;

static void
lws_lhp_ss_html_parse(lws_sorted_usec_list_t *sul)
{
	htmlss_t *m = lws_container_of(sul, htmlss_t, sul);
	lws_stateful_ret_t r;
	size_t zero = 0;

	do {
		if (lws_flow_feed(&m->flow)) {
			lwsl_notice("%s: returning from flow_feed\n", __func__);
			return;
		}

		// lwsl_notice("%s: html_parse in len %d\n", __func__, (int)m->flow.len);

		/* creates display list objects from html */
		r = lws_lhp_parse(&m->lhp, (const uint8_t **)&m->flow.data,
				       (size_t *)&m->flow.len);

		lws_flow_req(&m->flow);

		if ((r & LWS_SRET_WANT_INPUT) && !m->flow.len && !m->lhp.await_css_done) {
			if (m->flow.state == LWSDLOFLOW_STATE_READ) {
				lwsl_warn("%s: returning to await more input\n", __func__);
				return;
			}
			lwsl_warn("%s: inferring we are finished\n", __func__);
			break;
		}

		if (r & LWS_SRET_AWAIT_RETRY) {
			if (!m->lhp.await_css_done)
				lws_sul_schedule(m->cx, 0, &m->sul, lws_lhp_ss_html_parse, 1);

			return;
		}

		if (r & (LWS_SRET_NO_FURTHER_OUT | LWS_SRET_FATAL)) {
			lwsl_warn("%s: r 0x%x\n", __func__, r);
			break;
		}
	} while (1);

	/* Finalize the html parse and clean up */

	lwsl_notice("%s: DESTROYING the lhp\n", __func__);

	m->lhp.flags = LHP_FLAG_DOCUMENT_END;
	lws_lhp_parse(&m->lhp, (const uint8_t **)NULL, &zero);
	lws_lhp_destruct(&m->lhp);
	m->rs->html = 2; /* html completed.. rs outlives the html ss and priv */

	lws_display_dl_dump(m->drt.dl);

        /* schedule starting the render */

	lws_sul_schedule(m->cx, 0, &m->rs->sul, m->lhp.ssevcb, 1);
	lws_ss_destroy(&m->ss);
}

void
lws_lhp_ss_html_parse_from_lhp(lhp_ctx_t *lhp)
{
	htmlss_t *m = lws_container_of(lhp, htmlss_t, lhp);

	lws_lhp_ss_html_parse(&m->sul);
}

/* secure streams payload interface */

static lws_ss_state_return_t
htmlss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	htmlss_t *m = (htmlss_t *)userobj;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (len &&
	    lws_buflist_append_segment(&m->flow.bl, buf, len) < 0)
		return LWSSSSRET_DISCONNECT_ME;

	lwsl_notice("%s: buflen size %d\n", __func__,
			(int)lws_buflist_total_len(&m->flow.bl));

	if (flags & LWSSS_FLAG_EOM) {
		m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		r = LWSSSSRET_DISCONNECT_ME;
	}

	lws_sul_schedule(m->cx, 0, &m->sul, lws_lhp_ss_html_parse, 1);

	return r;
}

static lws_ss_state_return_t
htmlss_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	htmlss_t *m = (htmlss_t *)userobj;

	switch (state) {
	case LWSSSCS_CREATING:
		break;

	case LWSSSCS_DISCONNECTED:
		m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		m->flow.h = NULL;
		break;

	case LWSSSCS_DESTROYING:
		lws_lhp_destruct(&m->lhp);
		lws_buflist_destroy_all_segments(&m->flow.bl);
		m->drt.dl = NULL;
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("__default", htmlss_t)
	.rx				= htmlss_rx,
	.state				= htmlss_state,
	.manual_initial_tx_credit	= 1024
};

/* prep rs->displaylist, rs->ic */

int
lws_lhp_ss_browse(struct lws_context *cx, lws_display_render_state_t *rs,
		  const char *url, sul_cb_t render)
{
	struct lws_ss_handle *h = NULL;
	lws_ss_info_t ssi;
	int32_t w = 64 * 1024;
	htmlss_t *m;

	/* fetch via SS */
#if defined(LWS_PLAT_BAREMETAL) || defined(LWS_PLAT_FREERTOS)
	w = 4096;
#endif

	ssi = ssi_htmlss_t;
	ssi.manual_initial_tx_credit = w;

	if (lws_ss_create(cx, 0, &ssi, NULL, &h, NULL, NULL)) {
		lwsl_err("%s: ss create failed\n", __func__);
		return 1; /* failed */
	}

	m = (htmlss_t *)lws_ss_to_user_object(h);
	m->cx = cx;
	m->flow.h = h;
	m->flow.window = w;

	m->drt.dl = &rs->displaylist;
	m->drt.w = rs->ic->wh_px[0].whole;
	m->drt.h = rs->ic->wh_px[1].whole;

	m->rs = rs;
	m->rs->html = 1; /* render must wait for html to complete */

	if (lws_lhp_construct(&m->lhp, lhp_displaylist_layout, &m->drt, rs->ic)) {
		lwsl_err("%s: lhp create %s failed\n", __func__, url);
		goto bail1;
	}

	m->lhp.user1 = cx;
	m->lhp.base_url = strdup(url);
	m->lhp.ssevcb = render;
	m->lhp.ssevsul = &rs->sul;
	m->lhp.sshtmlevcb = lws_lhp_ss_html_parse;
	m->lhp.sshtmlevsul = &m->sul;
	m->lhp.ids = &rs->ids;

	if (lws_ss_set_metadata(m->ss, "endpoint", url, strlen(url))) {
		lwsl_err("%s: failed to use metadata %s\n", __func__, url);
		goto bail2;
	}

	if (lws_ss_set_metadata(m->ss, "ua", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0", 76)) {
		lwsl_err("%s: failed to use metadata ua\n", __func__);
		goto bail2;
	}

	if (lws_ss_set_metadata(m->ss, "acc", "text/html,image/jpeg,image/png,", 30)) {
		lwsl_err("%s: failed to use metadata ua\n", __func__);
		goto bail2;
	}

	if (lws_ss_client_connect(m->ss))
		goto bail2;

	return 0;

bail2:
	lws_lhp_destruct(&m->lhp);

bail1:
	lws_ss_destroy(&h);

	return 1;
}
