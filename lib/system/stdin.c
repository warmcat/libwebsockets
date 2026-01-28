/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

static int
callback_system_stdin(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	struct lws_context *cx;
	char buf[256];
	ssize_t n;
	int fd;

	switch (reason) {

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		cx = wsi->a.context;
		if (!(cx->stdin_flags & LWS_SAS_FLAG__APPEND_COMMANDLINE)) {
			if (!cx->system_ops || !cx->system_ops->stdin_rx)
				return -1;
			cx->system_ops->stdin_rx(cx, NULL, 0);
		} else {
			char *p, *end, *s, esc = 0;
			int m;

			/*
			 * Bring in the process argv 
			 */

			if (cx->argc > (int)LWS_ARRAY_SIZE(cx->stdin_argv)) {
				lwsl_err("%s: Too many commandline args\n", __func__);
				return -1;
			}

			for (m = 0; m < cx->argc; m++)
				cx->stdin_argv[cx->stdin_argc++] = cx->argv[m];

			/*
			 * linearize stdin
			 */

			cx->stdin_linear_size = lws_buflist_total_len(&cx->stdin_buflist);
			cx->stdin_linear = lws_malloc(cx->stdin_linear_size, __func__);
			if (!cx->stdin_linear) {
				lws_buflist_destroy_all_segments(&cx->stdin_buflist);
				return -1;
			}
			lws_buflist_linear_use(&cx->stdin_buflist, (uint8_t *)cx->stdin_linear,
					       cx->stdin_linear_size);

			/*
			 * segment the linear buffer
			 */

			s = p = cx->stdin_linear;
			end = p + cx->stdin_linear_size;
			while (p < end) {
				if (esc) {
					esc = 0;
					goto next;
				}
				if (*p == '\\') {
					esc = 1;
					goto next;
				}
				if (*p == '\n' || *p == ' ') {
					*p = '\0';
					cx->stdin_argv[cx->stdin_argc++] = s;
					if (cx->stdin_argc >= (int)LWS_ARRAY_SIZE(cx->stdin_argv) - 1) {
						lwsl_err("%s: reached stdin argv limit\n", __func__);
						break;
					}
					s = p + 1;
				}
next:
				p++;
			}
			if (p != s)
				cx->stdin_argv[cx->stdin_argc++] = s;

		}

#if 0
		for (int m = 0; m < cx->stdin_argc; m++)
			lwsl_notice("%s: %d: '%s'\n", __func__, m, cx->stdin_argv[m]);
#endif
#if defined(LWS_WITH_SYS_STATE)
		lws_state_transition_steps(&cx->mgr_system, LWS_SYSTATE_OPERATIONAL);
#endif
		break;

	case LWS_CALLBACK_RAW_RX_FILE:
		cx = wsi->a.context;
		if (!(cx->stdin_flags & LWS_SAS_FLAG__APPEND_COMMANDLINE))
			if (!cx->system_ops || !cx->system_ops->stdin_rx)
				return -1;

		fd = (int)lws_get_socket_fd(wsi);
		if (fd < 0)
			return -1;
		n = read(fd, buf, sizeof(buf));
		if (n < 0)
			return -1;

		if (!(cx->stdin_flags & LWS_SAS_FLAG__APPEND_COMMANDLINE)) {
			if (cx->system_ops->stdin_rx(cx, buf, (size_t)n) || !n)
				return -1;
			break;
		}

		if (n && lws_buflist_append_segment(&cx->stdin_buflist, (const uint8_t *)buf, (size_t)n))
			return -1;
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols lws_system_protocol_stdin = /* imported by lib/core/context.c */
	{ "lws-stdin", callback_system_stdin, 0, 0, 0, NULL, 0 };

int
lws_system_adopt_stdin(struct lws_context *cx, unsigned int flags)
{
	lws_sock_file_fd_type sock;
	struct lws_vhost *vh;

	sock.filefd		= 0; /* stdin */
	cx->stdin_flags		= flags;

#if defined(LWS_WITH_SYS_STATE)
	/* if there's no stdin_rx callback, there's nothing for us to do */

	if (!cx->system_ops || !cx->system_ops->stdin_rx)
		lws_state_transition_steps(&cx->mgr_system, LWS_SYSTATE_OPERATIONAL);
#endif

	vh = lws_get_vhost_by_name(cx, "system");
	if (!vh) {
		lwsl_err("%s: unable to find system vh\n", __func__);
		return 1;
	}

	if (!lws_adopt_descriptor_vhost(vh, LWS_ADOPT_RAW_FILE_DESC, sock, "lws-stdin", NULL)) {
		lwsl_err("%s: stdin adoption failed\n", __func__);
		return 1;
	}

	return 0;
}

