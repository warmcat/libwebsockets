/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include <private-lib-core.h>

static int
rops_handle_POLLIN_cgi(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_pollfd *pollfd)
{
	struct lws_cgi_args args;

	assert(wsi->role_ops == &role_ops_cgi);

	if (wsi->lsp_channel >= LWS_STDOUT &&
	    !(pollfd->revents & pollfd->events & LWS_POLLIN))
		return LWS_HPI_RET_HANDLED;

	if (wsi->lsp_channel == LWS_STDIN &&
	    !(pollfd->revents & pollfd->events & LWS_POLLOUT))
		return LWS_HPI_RET_HANDLED;

	if (wsi->lsp_channel == LWS_STDIN &&
	    lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
		lwsl_info("failed at set pollfd\n");
		return LWS_HPI_RET_WSI_ALREADY_DIED;
	}

	if (!wsi->parent) {
		lwsl_notice("%s: stdwsi content with parent\n",
				__func__);

		return LWS_HPI_RET_HANDLED;
	}

	if (!wsi->parent->http.cgi) {
		lwsl_notice("%s: stdwsi content with deleted cgi object\n",
				__func__);

		return LWS_HPI_RET_HANDLED;
	}

	if (!wsi->parent->http.cgi->lsp) {
		lwsl_notice("%s: stdwsi content with reaped lsp\n",
				__func__);

		return LWS_HPI_RET_HANDLED;
	}

	args.ch = wsi->lsp_channel;
	args.stdwsi = &wsi->parent->http.cgi->lsp->stdwsi[0];
	args.hdr_state = wsi->hdr_state;

	lwsl_debug("CGI LWS_STDOUT %p wsistate 0x%x\n",
		   wsi->parent, wsi->wsistate);

	if (user_callback_handle_rxflow(wsi->parent->a.protocol->callback,
					wsi->parent, LWS_CALLBACK_CGI,
					wsi->parent->user_space,
					(void *)&args, 0))
		return 1;

	return LWS_HPI_RET_HANDLED;
}

static int
rops_handle_POLLOUT_cgi(struct lws *wsi)
{
	return LWS_HP_RET_USER_SERVICE;
}

static int
rops_destroy_role_cgi(struct lws *wsi)
{
#if defined(LWS_WITH_ZLIB)
	if (!wsi->http.cgi)
		return 0;
	if (!wsi->http.cgi->gzip_init)
		return 0;

	inflateEnd(&wsi->http.cgi->inflate);
	wsi->http.cgi->gzip_init = 0;
#endif

	return 0;
}

static void
lws_cgi_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_cgi);

	lws_cgi_kill_terminated(pt);

	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &pt->sul_cgi, 3 * LWS_US_PER_SEC);
}

static int
rops_pt_init_destroy_cgi(struct lws_context *context,
		    const struct lws_context_creation_info *info,
		    struct lws_context_per_thread *pt, int destroy)
{
	if (!destroy) {

		pt->sul_cgi.cb = lws_cgi_sul_cb;

		__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
				    &pt->sul_cgi, 3 * LWS_US_PER_SEC);
	} else
		lws_dll2_remove(&pt->sul_cgi.list);

	return 0;
}

static int
rops_close_role_cgi(struct lws_context_per_thread *pt, struct lws *wsi)
{
	if (wsi->parent && wsi->parent->http.cgi && wsi->parent->http.cgi->lsp)
		lws_spawn_stdwsi_closed(wsi->parent->http.cgi->lsp, wsi);

	return 0;
}


const struct lws_role_ops role_ops_cgi = {
	/* role name */			"cgi",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* pt_init_destroy */		rops_pt_init_destroy_cgi,
	/* init_vhost */		NULL,
	/* destroy_vhost */		NULL,
	/* service_flag_pending */	NULL,
	/* handle_POLLIN */		rops_handle_POLLIN_cgi,
	/* handle_POLLOUT */		rops_handle_POLLOUT_cgi,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	NULL,
	/* close_role */		rops_close_role_cgi,
	/* close_kill_connection */	NULL,
	/* destroy_role */		rops_destroy_role_cgi,
	/* adoption_bind */		NULL,
	/* client_bind */		NULL,
	/* issue_keepalive */		NULL,
	/* adoption_cb clnt, srv */	{ 0, 0 },
	/* rx_cb clnt, srv */		{ 0, 0 },
	/* writeable cb clnt, srv */	{ 0, 0 },
	/* close cb clnt, srv */	{ 0, 0 },
	/* protocol_bind_cb c,s */	{ 0, 0 },
	/* protocol_unbind_cb c,s */	{ 0, 0 },
	/* file_handle */		0,
};
