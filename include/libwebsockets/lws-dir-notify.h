/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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

#ifndef __LWS_DIR_NOTIFY_H__
#define __LWS_DIR_NOTIFY_H__

struct lws_dir_notify;

/**
 * lws_dir_notify_cb_t() - Callback for directory/file modification events
 *
 * \param path:   The absolute path of the file or directory that was modified
 * \param is_file: Non-zero if the modified entry was a file, zero if a directory
 * \param user:    Opaque pointer passed in during lws_dir_notify_create
 */
typedef void (*lws_dir_notify_cb_t)(const char *path, int is_file, void *user);

/**
 * lws_dir_notify_create() - Create a cross-platform directory/file monitor
 *
 * \param ctx:   The lws_context the monitor should bind to
 * \param path:  The absolute path of the directory or file to monitor
 * \param cb:    The event callback that is routed when changes are detected
 * \param user:  Opaque object passed back in the callback
 *
 * Returns an allocated and initialized `struct lws_dir_notify` bound to the
 * context event loop, or NULL on failure.
 *
 * On Linux, this will use an inotify FD and adopt it into the event loop.
 * On macOS/BSD, this will use kqueue.
 * On Windows, this will use ReadDirectoryChangesW/FindFirstChangeNotification.
 */
LWS_VISIBLE LWS_EXTERN struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user);

/**
 * lws_dir_notify_destroy() - Destroy the monitor
 *
 * \param pdn: Pointer to the lws_dir_notify pointer to clean up
 *
 * Closes underlying resources and frees the monitor structure. Sets pointer to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dir_notify_destroy(struct lws_dir_notify **pdn);

#endif
