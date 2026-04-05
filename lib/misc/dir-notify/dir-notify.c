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

#include "private-lib-core.h"

#if defined(LWS_WITH_DIR)

struct lws_dir_notify {
	struct lws_context *ctx;
	lws_dir_notify_cb_t cb;
	void *user;
	int fd;
	int dir_fd;
	struct lws *wsi;
	lws_dll2_t list;
};

#if !defined(LWS_WITH_NETWORK)

/* Stubs for no-network */
static int
lws_dir_notify_rx(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	return 0;
}

const struct lws_protocols protocol_lws_dir_notify = {
	"lws-dir-notify",
	lws_dir_notify_rx,
	0, 0, 0, NULL, 0
};

struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user)
{
	lwsl_err("%s: lws_dir_notify requires LWS_WITH_NETWORK\n", __func__);
	return NULL;
}

void
lws_dir_notify_destroy(struct lws_dir_notify **pdn)
{
}

#else

#if defined(__linux__) || defined(__linux)
#include <sys/inotify.h>
#include <limits.h>

static int
lws_dir_notify_rx(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct lws_dir_notify *dn = (struct lws_dir_notify *)lws_get_opaque_user_data(wsi);
	if (reason == LWS_CALLBACK_RAW_RX_FILE) {
		char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
		const struct inotify_event *event;
		ssize_t n;

		n = read(dn->fd, buf, sizeof(buf));
		if (n <= 0)
			return 0;

		for (char *ptr = buf; ptr < buf + n; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *)ptr;
			/* We only notify if there's actually a filename provided. */
			if (event->len) {
				int is_file = !(event->mask & IN_ISDIR);
				dn->cb(event->name, is_file, dn->user);
			}
		}
	} else if (reason == LWS_CALLBACK_RAW_CLOSE_FILE) {
		/* Clean up if the raw file wsi closes unexpectedly */
		if (dn) {
			if (dn->fd >= 0)
				close(dn->fd);
			dn->fd = -1;
			dn->wsi = NULL;
			/* we can't safely free(dn) if lws_dir_notify_destroy
			 * hasn't been called, since user code holds a ptr. */
		}
	}
	return 0;
}

const struct lws_protocols protocol_lws_dir_notify = {
	"lws-dir-notify",
	lws_dir_notify_rx,
	0, 0, 0, NULL, 0
};

struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user)
{
	struct lws_dir_notify *dn;
	struct lws_vhost *vh = lws_get_vhost_by_name(ctx, "system");
	lws_sock_file_fd_type sock;
	int wd;

	if (!vh) {
		vh = ctx->vhost_list;
		if (!vh)
			return NULL;
	}

	dn = lws_malloc(sizeof(*dn), __func__);
	if (!dn)
		return NULL;

	dn->ctx = ctx;
	dn->cb = cb;
	dn->user = user;

	dn->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (dn->fd < 0)
		goto bail;

	wd = inotify_add_watch(dn->fd, path, IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
	if (wd < 0) {
		close(dn->fd);
		goto bail;
	}

	sock.filefd = dn->fd;
	dn->wsi = lws_adopt_descriptor_vhost(vh, LWS_ADOPT_RAW_FILE_DESC, sock,
					     protocol_lws_dir_notify.name, NULL);
	if (!dn->wsi) {
		close(dn->fd);
		goto bail;
	}

	lws_set_opaque_user_data(dn->wsi, dn);

	return dn;

bail:
	lws_free(dn);
	return NULL;
}

void
lws_dir_notify_destroy(struct lws_dir_notify **pdn)
{
	struct lws_dir_notify *dn = *pdn;
	if (!dn)
		return;

	if (dn->wsi)
		lws_set_timeout(dn->wsi, 1, LWS_TO_KILL_ASYNC);
	else if (dn->fd >= 0)
		close(dn->fd);

	lws_free(dn);
	*pdn = NULL;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>

static int
lws_dir_notify_rx(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct lws_dir_notify *dn = (struct lws_dir_notify *)lws_get_opaque_user_data(wsi);
	if (reason == LWS_CALLBACK_RAW_RX_FILE) {
		struct kevent kev;
		struct timespec ts = {0, 0};
		int n;

		n = kevent(dn->fd, NULL, 0, &kev, 1, &ts);
		if (n > 0) {
			/* We got an event. kqueue doesn't cleanly separate files and dirs
			 * within the directory for EVFILT_VNODE. But we can trigger the callback
			 * with is_file=0 for the dir itself. */
			dn->cb("", 0, dn->user);
		}
	} else if (reason == LWS_CALLBACK_RAW_CLOSE_FILE) {
		if (dn) {
			if (dn->fd >= 0)
				close(dn->fd);
			if (dn->dir_fd >= 0)
				close(dn->dir_fd);
			dn->fd = -1;
			dn->dir_fd = -1;
			dn->wsi = NULL;
		}
	}
	return 0;
}

const struct lws_protocols protocol_lws_dir_notify = {
	"lws-dir-notify",
	lws_dir_notify_rx,
	0, 0, 0, NULL, 0
};

struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user)
{
	struct lws_dir_notify *dn;
	struct lws_vhost *vh = lws_get_vhost_by_name(ctx, "system");
	lws_sock_file_fd_type sock;
	struct kevent kev;

	if (!vh) {
		vh = ctx->vhost_list;
		if (!vh)
			return NULL;
	}

	dn = lws_malloc(sizeof(*dn), __func__);
	if (!dn)
		return NULL;

	dn->ctx = ctx;
	dn->cb = cb;
	dn->user = user;

	dn->dir_fd = open(path, O_RDONLY | O_NONBLOCK);
	if (dn->dir_fd < 0)
		goto bail;

	dn->fd = kqueue();
	if (dn->fd < 0) {
		close(dn->dir_fd);
		goto bail;
	}

	EV_SET(&kev, dn->dir_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	       NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE | NOTE_DELETE,
	       0, NULL);

	if (kevent(dn->fd, &kev, 1, NULL, 0, NULL) == -1) {
		close(dn->dir_fd);
		close(dn->fd);
		goto bail;
	}

	sock.filefd = dn->fd;
	dn->wsi = lws_adopt_descriptor_vhost(vh, LWS_ADOPT_RAW_FILE_DESC, sock,
					     protocol_lws_dir_notify.name, NULL);
	if (!dn->wsi) {
		close(dn->dir_fd);
		close(dn->fd);
		goto bail;
	}

	lws_set_opaque_user_data(dn->wsi, dn);

	return dn;

bail:
	lws_free(dn);
	return NULL;
}

void
lws_dir_notify_destroy(struct lws_dir_notify **pdn)
{
	struct lws_dir_notify *dn = *pdn;
	if (!dn)
		return;

	if (dn->wsi)
		lws_set_timeout(dn->wsi, 1, LWS_TO_KILL_ASYNC);
	else {
		if (dn->fd >= 0)
			close(dn->fd);
		if (dn->dir_fd >= 0)
			close(dn->dir_fd);
	}

	lws_free(dn);
	*pdn = NULL;
}

#elif defined(WIN32)

struct dir_event {
	lws_dll2_t list;
	char name[MAX_PATH];
	int is_file;
};

struct lws_dir_notify_thread_ctx {
	struct lws_dir_notify *dn;
	HANDLE hDir;
	HANDLE hEvent;
	HANDLE hQuitEvent;
	HANDLE hThread;
	volatile int quit;
	CRITICAL_SECTION cs;
	lws_dll2_owner_t events;
	uint8_t buffer[4096];
	OVERLAPPED overlapped;
};

static lws_dll2_owner_t windows_dn_owner;

static DWORD WINAPI
lws_dir_notify_windows_thread(LPVOID lpParam)
{
	struct lws_dir_notify_thread_ctx *tctx = (struct lws_dir_notify_thread_ctx *)lpParam;
	DWORD bytes_used;
	HANDLE handles[2];

	handles[0] = tctx->hEvent;
	handles[1] = tctx->hQuitEvent;

	while (!tctx->quit) {
		memset(&tctx->overlapped, 0, sizeof(tctx->overlapped));
		tctx->overlapped.hEvent = tctx->hEvent;

		if (!ReadDirectoryChangesW(tctx->hDir, tctx->buffer, sizeof(tctx->buffer), FALSE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
				FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
				FILE_NOTIFY_CHANGE_LAST_WRITE, NULL, &tctx->overlapped, NULL)) {
			break;
		}

		DWORD wait_status = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

		if (wait_status == WAIT_OBJECT_0 + 1) {
			CancelIo(tctx->hDir);
			break;
		}

		if (wait_status != WAIT_OBJECT_0) {
			break;
		}

		if (GetOverlappedResult(tctx->hDir, &tctx->overlapped, &bytes_used, FALSE)) {
			FILE_NOTIFY_INFORMATION *fni;
			int trigger = 0;

			if (bytes_used == 0)
				continue;

			fni = (FILE_NOTIFY_INFORMATION *)tctx->buffer;

			do {
				struct dir_event *ev;
				if (fni->Action == FILE_ACTION_MODIFIED ||
				    fni->Action == FILE_ACTION_ADDED ||
				    fni->Action == FILE_ACTION_REMOVED ||
				    fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
					ev = lws_malloc(sizeof(*ev), "dir_event");
					if (ev) {
						int n = WideCharToMultiByte(CP_UTF8, 0, fni->FileName,
							fni->FileNameLength / 2, ev->name, sizeof(ev->name) - 1, NULL, NULL);
						ev->name[n] = '\0';
						ev->is_file = 1;

						EnterCriticalSection(&tctx->cs);
						lws_dll2_add_tail(&ev->list, &tctx->events);
						LeaveCriticalSection(&tctx->cs);
						trigger = 1;
					}
				}

				if (fni->NextEntryOffset == 0)
					break;
				fni = (FILE_NOTIFY_INFORMATION *)((uint8_t *)fni + fni->NextEntryOffset);
			} while (1);

			if (trigger)
				lws_cancel_service(tctx->dn->ctx);
		}
	}
	return 0;
}

static int
lws_dir_notify_rx(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_EVENT_WAIT_CANCELLED) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, lws_dll2_get_head(&windows_dn_owner)) {
			struct lws_dir_notify *dn = lws_container_of(p, struct lws_dir_notify, list);
			struct lws_dir_notify_thread_ctx *tctx = (struct lws_dir_notify_thread_ctx *)dn->wsi;

			EnterCriticalSection(&tctx->cs);
			while (tctx->events.count) {
				struct dir_event *ev = lws_container_of(lws_dll2_get_head(&tctx->events), struct dir_event, list);
				lws_dll2_remove(&ev->list);
				LeaveCriticalSection(&tctx->cs);

				dn->cb(ev->name, ev->is_file, dn->user);
				lws_free(ev);

				EnterCriticalSection(&tctx->cs);
			}
			LeaveCriticalSection(&tctx->cs);
		} lws_end_foreach_dll_safe(p, p1);
	}
	return 0;
}

const struct lws_protocols protocol_lws_dir_notify = {
	"lws-dir-notify",
	lws_dir_notify_rx,
	0, 0, 0, NULL, 0
};

struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user)
{
	struct lws_dir_notify *dn;
	struct lws_dir_notify_thread_ctx *tctx;
	WCHAR wpath[MAX_PATH];

	dn = lws_malloc(sizeof(*dn), __func__);
	if (!dn)
		return NULL;

	tctx = lws_zalloc(sizeof(*tctx), __func__);
	if (!tctx) {
		lws_free(dn);
		return NULL;
	}

	dn->ctx = ctx;
	dn->cb = cb;
	dn->user = user;
	dn->wsi = (struct lws *)tctx;
	lws_dll2_clear(&dn->list);

	InitializeCriticalSection(&tctx->cs);

	MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, LWS_ARRAY_SIZE(wpath));

	tctx->hDir = CreateFileW(wpath,
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
		NULL);

	if (tctx->hDir == INVALID_HANDLE_VALUE) {
		DeleteCriticalSection(&tctx->cs);
		lws_free(tctx);
		lws_free(dn);
		return NULL;
	}

	tctx->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	tctx->hQuitEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (!tctx->hEvent || !tctx->hQuitEvent) {
		if (tctx->hEvent) CloseHandle(tctx->hEvent);
		if (tctx->hQuitEvent) CloseHandle(tctx->hQuitEvent);
		CloseHandle(tctx->hDir);
		DeleteCriticalSection(&tctx->cs);
		lws_free(tctx);
		lws_free(dn);
		return NULL;
	}

	tctx->dn = dn;
	tctx->hThread = CreateThread(NULL, 0, lws_dir_notify_windows_thread, tctx, 0, NULL);
	if (!tctx->hThread) {
		CloseHandle(tctx->hEvent);
		CloseHandle(tctx->hQuitEvent);
		CloseHandle(tctx->hDir);
		DeleteCriticalSection(&tctx->cs);
		lws_free(tctx);
		lws_free(dn);
		return NULL;
	}

	lws_dll2_add_tail(&dn->list, &windows_dn_owner);

	return dn;
}

void
lws_dir_notify_destroy(struct lws_dir_notify **pdn)
{
	struct lws_dir_notify *dn = *pdn;
	struct lws_dir_notify_thread_ctx *tctx;

	if (!dn)
		return;

	tctx = (struct lws_dir_notify_thread_ctx *)dn->wsi;
	if (tctx) {
		tctx->quit = 1;
		SetEvent(tctx->hQuitEvent);
		WaitForSingleObject(tctx->hThread, INFINITE);
		CloseHandle(tctx->hThread);
		CloseHandle(tctx->hEvent);
		CloseHandle(tctx->hQuitEvent);
		CloseHandle(tctx->hDir);

		while (tctx->events.count) {
			struct dir_event *ev = lws_container_of(lws_dll2_get_head(&tctx->events), struct dir_event, list);
			lws_dll2_remove(&ev->list);
			lws_free(ev);
		}

		DeleteCriticalSection(&tctx->cs);
		lws_free(tctx);
	}

	lws_dll2_remove(&dn->list);
	lws_free(dn);
	*pdn = NULL;
}

#else
/* Stubs for non-Linux implementations */
static int
lws_dir_notify_rx(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	return 0;
}

const struct lws_protocols protocol_lws_dir_notify = {
	"lws-dir-notify",
	lws_dir_notify_rx,
	0, 0, 0, NULL, 0
};

struct lws_dir_notify *
lws_dir_notify_create(struct lws_context *ctx, const char *path,
		      lws_dir_notify_cb_t cb, void *user)
{
	lwsl_err("%s: lws_dir_notify not yet implemented natively on this platform\n", __func__);
	return NULL;
}

void
lws_dir_notify_destroy(struct lws_dir_notify **pdn)
{
}
#endif

#endif /* LWS_WITH_NETWORK */

#endif /* LWS_WITH_DIR_NOTIFY */
