/*
 * lws-api-test-ssjpeg
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

/*
 * The dlo and the flow are inside the context of the SS
 */

LWS_SS_USER_TYPEDEF
	lws_flow_t			flow;
	lws_jpeg_t			*j;
} myss_t;

static lws_dlo_rasterize_t dlo_rasterize;
struct lws_context *cx;
static int fdout = 1, result = 1;

/* sul to produce some lines of output bitmap */

static void
rasterize(lws_sorted_usec_list_t *sul)
{
	lws_dlo_rasterize_t *rast = lws_container_of(sul, lws_dlo_rasterize_t, sul);
	lws_flow_t *flow = lws_container_of(rast->owner.head, lws_flow_t, list);
	myss_t *m = lws_container_of(flow, myss_t, flow);
	const uint8_t *pix = NULL;
	lws_stateful_ret_t r;
	ssize_t os;

	do {
		if (!flow->len) {
			if (flow->blseglen)
				lws_buflist_use_segment(&flow->bl, flow->blseglen);
			flow->len = lws_buflist_next_segment_len(
					&flow->bl, (uint8_t **)&flow->data);
			flow->blseglen = (uint32_t)flow->len;
			if (!flow->len)
				return;
		}

		r = lws_jpeg_emit_next_line(m->j, &pix,
				(const uint8_t **)&flow->data, &flow->len, 0);
		if (!flow->len && flow->blseglen) {
			lws_buflist_use_segment(&flow->bl, flow->blseglen);
			flow->blseglen = 0;
		}
		if (r == LWS_SRET_WANT_INPUT) {
			if (lws_buflist_next_segment_len(&flow->bl, NULL))
				continue;

			if (r == LWS_SRET_WANT_INPUT && flow->h) {
				int32_t est = lws_ss_get_est_peer_tx_credit(flow->h) +
					(int)lws_buflist_total_len(&flow->bl) +
					(int)flow->len;

				lwsl_debug("%s: est %d\n", __func__, est);
				if (est < flow->window)
					lws_ss_add_peer_tx_credit(flow->h, flow->window);
			}

			return;
		}

		if (r >= LWS_SRET_FATAL) {
			lwsl_notice("%s: emit returned FATAL\n", __func__);
			flow->state = LWSDLOFLOW_STATE_READ_FAILED;
			lws_default_loop_exit(cx);
			return;
		}

		if (!pix)
			return;

		os = (ssize_t)(lws_jpeg_get_width(m->j) *
				(lws_jpeg_get_pixelsize(m->j) / 8));

		if (write(fdout, pix,
#if defined(WIN32)
					(unsigned int)
#endif
					(size_t)os) < os) {
			lwsl_err("%s: write %d failed %d\n", __func__,
					(int)os, errno);
			goto bail1;
		}

		lwsl_debug("%s: wrote %d: r %u (left %u)\n", __func__,
				(int)os, r, (unsigned int)flow->len);

		if (r == LWS_SRET_OK) {
			lwsl_notice("%s: feels complete\n", __func__);
			flow->state = LWSDLOFLOW_STATE_READ_COMPLETED;
			result = 0;
			lws_default_loop_exit(cx);
			return;
		}

	} while (1);

	return;

bail1:
	return;
}

/* secure streams payload interface */

static lws_ss_state_return_t
myss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	myss_t *m = (myss_t *)userobj;
	lws_dlo_rasterize_t *rast1 = lws_container_of(m->flow.list.owner,
						lws_dlo_rasterize_t, owner);

	if (len && lws_buflist_append_segment(&m->flow.bl, buf, len) < 0)
		return LWSSSSRET_DISCONNECT_ME;

	if (flags & LWSSS_FLAG_EOM) {
		m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		return LWSSSSRET_DISCONNECT_ME;
	}

	lws_sul_schedule(lws_ss_get_context(m->ss), 0, &rast1->sul, rasterize, 1);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	myss_t *m = (myss_t *)userobj;
	const char *url = (const char*)m->opaque_data;
	lws_ss_state_return_t r;

	switch (state) {
	case LWSSSCS_CREATING:
		m->flow.h = m->ss;
		m->flow.window = 4096;
		m->j = lws_jpeg_new();
		if (!m->j) {
			lwsl_err("%s: failed to allocate\n", __func__);
			return LWSSSSRET_DESTROY_ME;
		}

		if (lws_ss_set_metadata(m->ss, "endpoint", url, strlen(url))) {
			lwsl_err("%s: failed to use metadata %s\n", __func__,
					url);
			return LWSSSSRET_DESTROY_ME;
		}

		r = lws_ss_client_connect(m->ss);
		if (r)
			return r;

		lws_dll2_add_tail(&m->flow.list, &dlo_rasterize.owner);
		break;

	case LWSSSCS_DESTROYING:
		m->flow.h = NULL;
		lws_buflist_destroy_all_segments(&m->flow.bl);
		lws_jpeg_free(&m->j);
		lws_dll2_remove(&m->flow.list);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("default", myss_t)
	.rx				= myss_rx,
	.state				= myss_state,
	.manual_initial_tx_credit	= 1400
};

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	size_t l = 0;

	lwsl_user("LWS SS JPEG test client   <https://server/my.jpg>\n");

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--stdout"))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			lwsl_err("%s: unable to open stdout file\n", __func__);
			goto bail;
		}
	}

	info.fd_limit_per_thread = 1 + 6 + 1;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

	/* create the cx */

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* create the SS to the jpg using the URL on argv[1] */

	if (lws_ss_create(cx, 0, &ssi_myss_t, (void *)argv[1], NULL, NULL, NULL)) {
		lws_context_destroy(cx);
		goto bail2;
	}

	lws_context_default_loop_run_destroy(cx);

bail2:
	if (fdout != 1)
		close(fdout);

bail:
	lwsl_user("Completed: %s (read %u)\n", result ? "FAIL" : "PASS",
							(unsigned int)l);

	return result;
}
