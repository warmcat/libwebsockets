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
 *
 *  This is included from private-lib-core.h
 */

enum lws_event_lib_ops_flags {
	LELOF_ISPOLL				= (1 >> 0),
	LELOF_DESTROY_FINAL			= (1 >> 1),
};

struct lws_event_loop_ops {
	const char *name;
	/* event loop-specific context init during context creation */
	int (*init_context)(struct lws_context *context,
			    const struct lws_context_creation_info *info);
	/* called during lws_destroy_context */
	int (*destroy_context1)(struct lws_context *context);
	/* called during lws_destroy_context2 */
	int (*destroy_context2)(struct lws_context *context);
	/* init vhost listening wsi */
	int (*init_vhost_listen_wsi)(struct lws *wsi);
	/* init the event loop for a pt */
	int (*init_pt)(struct lws_context *context, void *_loop, int tsi);
	/* called at end of first phase of close_free_wsi()  */
	int (*wsi_logical_close)(struct lws *wsi);
	/* return nonzero if client connect not allowed  */
	int (*check_client_connect_ok)(struct lws *wsi);
	/* close handle manually  */
	void (*close_handle_manually)(struct lws *wsi);
	/* event loop accept processing  */
	int (*sock_accept)(struct lws *wsi);
	/* control wsi active events  */
	void (*io)(struct lws *wsi, int flags);
	/* run the event loop for a pt */
	void (*run_pt)(struct lws_context *context, int tsi);
	/* called before pt is destroyed */
	void (*destroy_pt)(struct lws_context *context, int tsi);
	/* called just before wsi is freed  */
	void (*destroy_wsi)(struct lws *wsi);

	uint8_t	flags;

	uint16_t	evlib_size_ctx;
	uint16_t	evlib_size_pt;
	uint16_t	evlib_size_vh;
	uint16_t	evlib_size_wsi;
};
