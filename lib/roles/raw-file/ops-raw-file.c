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
rops_handle_POLLIN_raw_file(struct lws_context_per_thread *pt, struct lws *wsi,
			    struct lws_pollfd *pollfd)
{
	int n;

	if (pollfd->revents & LWS_POLLOUT) {
		n = lws_callback_as_writeable(wsi);
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_info("failed at set pollfd\n");
			return LWS_HPI_RET_WSI_ALREADY_DIED;
		}
		if (n)
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	if (pollfd->revents & LWS_POLLIN) {
		if (user_callback_handle_rxflow(wsi->protocol->callback,
						wsi, LWS_CALLBACK_RAW_RX_FILE,
						wsi->user_space, NULL, 0)) {
			lwsl_debug("raw rx callback closed it\n");
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		}
	}

	if (pollfd->revents & LWS_POLLHUP)
		if (!(pollfd->revents & LWS_POLLIN))
			return LWS_HPI_RET_PLEASE_CLOSE_ME;

	return LWS_HPI_RET_HANDLED;
}

static int
rops_adoption_bind_raw_file(struct lws *wsi, int type, const char *vh_prot_name)
{
	/* no socket or http: it can only be a raw file */
	if ((type & LWS_ADOPT_HTTP) || (type & LWS_ADOPT_SOCKET) ||
	    (type & _LWS_ADOPT_FINISH))
		return 0; /* no match */

	lws_role_transition(wsi, 0, LRS_ESTABLISHED, &role_ops_raw_file);

	if (!vh_prot_name) {
		if (wsi->vhost->default_protocol_index >=
		    wsi->vhost->count_protocols)
			return 0;

		wsi->protocol = &wsi->vhost->protocols[
					wsi->vhost->default_protocol_index];
	}

	return 1; /* bound */
}

const struct lws_role_ops role_ops_raw_file = {
	/* role name */			"raw-file",
	/* alpn id */			NULL,
	/* check_upgrades */		NULL,
	/* pt_init_destroy */		NULL,
	/* init_vhost */		NULL,
	/* destroy_vhost */		NULL,
	/* service_flag_pending */	NULL,
	/* handle_POLLIN */		rops_handle_POLLIN_raw_file,
	/* handle_POLLOUT */		NULL,
	/* perform_user_POLLOUT */	NULL,
	/* callback_on_writable */	NULL,
	/* tx_credit */			NULL,
	/* write_role_protocol */	NULL,
	/* encapsulation_parent */	NULL,
	/* alpn_negotiated */		NULL,
	/* close_via_role_protocol */	NULL,
	/* close_role */		NULL,
	/* close_kill_connection */	NULL,
	/* destroy_role */		NULL,
	/* adoption_bind */		rops_adoption_bind_raw_file,
	/* client_bind */		NULL,
	/* issue_keepalive */		NULL,
	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_RAW_ADOPT_FILE,
					  LWS_CALLBACK_RAW_ADOPT_FILE },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RAW_RX_FILE,
					  LWS_CALLBACK_RAW_RX_FILE },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_RAW_WRITEABLE_FILE,
					  LWS_CALLBACK_RAW_WRITEABLE_FILE},
	/* close cb clnt, srv */	{ LWS_CALLBACK_RAW_CLOSE_FILE,
					  LWS_CALLBACK_RAW_CLOSE_FILE},
	/* protocol_bind cb c, srv */	{ LWS_CALLBACK_RAW_FILE_BIND_PROTOCOL,
					  LWS_CALLBACK_RAW_FILE_BIND_PROTOCOL },
	/* protocol_unbind cb c, srv */	{ LWS_CALLBACK_RAW_FILE_DROP_PROTOCOL,
					  LWS_CALLBACK_RAW_FILE_DROP_PROTOCOL },
	/* file_handle */		1,
};
