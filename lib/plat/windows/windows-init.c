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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"

int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_set)
{
	return 0;
}

int
lws_plat_context_early_init(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro from Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (!err)
		return 0;
	/*
	 * Tell the user that we could not find a usable
	 * Winsock DLL
	 */
	lwsl_err("WSAStartup failed with error: %d\n", err);

	return 1;
}

#if defined(LWS_WITH_PLUGINS)
static int
protocol_plugin_cb(struct lws_plugin *pin, void *each_user)
{
	struct lws_context *context = (struct lws_context *)each_user;
	const lws_plugin_protocol_t *plpr =
			(const lws_plugin_protocol_t *)pin->hdr;

	context->plugin_protocol_count += plpr->count_protocols;
	context->plugin_extension_count += plpr->count_extensions;

	return 0;
}
#endif

int
lws_plat_init(struct lws_context *context,
	      const struct lws_context_creation_info *info)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int i, n = context->count_threads;

	for (i = 0; i < FD_HASHTABLE_MODULUS; i++) {
		context->fd_hashtable[i].wsi =
			lws_zalloc(sizeof(struct lws*) * context->max_fds,
				   "win hashtable");

		if (!context->fd_hashtable[i].wsi)
			return -1;
	}

	while (n--) {
               int m;
		pt->fds_count = 0;
               for (m = 0; m < WSA_MAXIMUM_WAIT_EVENTS; m++)
                       pt->events[m] = WSACreateEvent();
		InitializeCriticalSection(&pt->interrupt_lock);

		pt++;
	}

	context->fd_random = 0;

#if defined(LWS_WITH_PLUGINS)
	if (info->plugin_dirs)
		lws_plat_plugins_init(&context->plugin_list, info->plugin_dirs,
				      "lws_protocol_plugin",
				      protocol_plugin_cb, context);
#endif

	return 0;
}

void
lws_plat_context_early_destroy(struct lws_context *context)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	int n = context->count_threads;

	while (n--) {
		int m;
		for (m = 0; m < WSA_MAXIMUM_WAIT_EVENTS; m++)
			WSACloseEvent(pt->events[m]);
		DeleteCriticalSection(&pt->interrupt_lock);
		pt++;
	}
}

void
lws_plat_context_late_destroy(struct lws_context *context)
{
	int n;

#ifdef LWS_WITH_PLUGINS
	if (context->plugin_list)
		lws_plugins_destroy(&context->plugin_list);
#endif

	for (n = 0; n < FD_HASHTABLE_MODULUS; n++) {
		if (context->fd_hashtable[n].wsi)
			lws_free(context->fd_hashtable[n].wsi);
	}

	WSACleanup();
}
