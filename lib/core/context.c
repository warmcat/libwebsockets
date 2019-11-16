/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "core/private.h"

#ifndef LWS_BUILD_HASH
#define LWS_BUILD_HASH "unknown-build-hash"
#endif


static const char *library_version = LWS_LIBRARY_VERSION " " LWS_BUILD_HASH;

/**
 * lws_get_library_version: get version and git hash library built from
 *
 *	returns a const char * to a string like "1.1 178d78c"
 *	representing the library version followed by the git head hash it
 *	was built from
 */
LWS_VISIBLE const char *
lws_get_library_version(void)
{
	return library_version;
}

#if defined(LWS_WITH_STATS)
static void
lws_sul_stats_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_stats);

	lws_stats_log_dump(pt->context);

	__lws_sul_insert(&pt->pt_sul_owner, &pt->sul_stats, 10 * LWS_US_PER_SEC);
}
#endif
#if defined(LWS_WITH_PEER_LIMITS)
static void
lws_sul_peer_limits_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context_per_thread *pt = lws_container_of(sul,
			struct lws_context_per_thread, sul_peer_limits);

	lws_peer_cull_peer_wait_list(pt->context);

	__lws_sul_insert(&pt->pt_sul_owner, &pt->sul_peer_limits, 10 * LWS_US_PER_SEC);
}
#endif


LWS_VISIBLE struct lws_context *
lws_create_context(const struct lws_context_creation_info *info)
{
	struct lws_context *context = NULL;
	struct lws_plat_file_ops *prev;
#ifndef LWS_NO_DAEMONIZE
	pid_t pid_daemon = get_daemonize_pid();
#endif
#if defined(LWS_WITH_NETWORK)
	int n;
#endif
#if defined(__ANDROID__)
	struct rlimit rt;
#endif

	lwsl_info("Initial logging level %d\n", log_level);
	lwsl_info("Libwebsockets version: %s\n", library_version);

#ifdef LWS_WITH_IPV6
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_info("IPV6 compiled in and enabled\n");
	else
		lwsl_info("IPV6 compiled in but disabled\n");
#else
	lwsl_info("IPV6 not compiled in\n");
#endif

	lwsl_info(" LWS_DEF_HEADER_LEN    : %u\n", LWS_DEF_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS     : %u\n", LWS_MAX_PROTOCOLS);
	lwsl_info(" LWS_MAX_SMP           : %u\n", LWS_MAX_SMP);
	lwsl_info(" sizeof (*info)        : %ld\n", (long)sizeof(*info));
#if defined(LWS_WITH_STATS)
	lwsl_info(" LWS_WITH_STATS        : on\n");
#endif
	lwsl_info(" SYSTEM_RANDOM_FILEPATH: '%s'\n", SYSTEM_RANDOM_FILEPATH);
#if defined(LWS_WITH_HTTP2)
	lwsl_info(" HTTP2 support         : available\n");
#else
	lwsl_info(" HTTP2 support         : not configured\n");
#endif
	if (lws_plat_context_early_init())
		return NULL;

	context = lws_zalloc(sizeof(struct lws_context), "context");
	if (!context) {
		lwsl_err("No memory for websocket context\n");
		return NULL;
	}

	context->uid = info->uid;
	context->gid = info->gid;
	context->username = info->username;
	context->groupname = info->groupname;
	context->system_ops = info->system_ops;

	/* if he gave us names, set the uid / gid */
	if (lws_plat_drop_app_privileges(context, 0))
		goto bail;

lwsl_info("context created\n");
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_NETWORK)
#if defined(LWS_WITH_MBEDTLS)
	context->tls_ops = &tls_ops_mbedtls;
#else
	context->tls_ops = &tls_ops_openssl;
#endif
#endif

	if (info->pt_serv_buf_size)
		context->pt_serv_buf_size = info->pt_serv_buf_size;
	else
		context->pt_serv_buf_size = 4096;

#if defined(LWS_ROLE_H2)
	role_ops_h2.init_context(context, info);
#endif

#if LWS_MAX_SMP > 1
	lws_mutex_refcount_init(&context->mr);
#endif

#if defined(LWS_WITH_ESP32)
	context->last_free_heap = esp_get_free_heap_size();
#endif

	/* default to just the platform fops implementation */

	context->fops_platform.LWS_FOP_OPEN	= _lws_plat_file_open;
	context->fops_platform.LWS_FOP_CLOSE	= _lws_plat_file_close;
	context->fops_platform.LWS_FOP_SEEK_CUR	= _lws_plat_file_seek_cur;
	context->fops_platform.LWS_FOP_READ	= _lws_plat_file_read;
	context->fops_platform.LWS_FOP_WRITE	= _lws_plat_file_write;
	context->fops_platform.fi[0].sig	= NULL;

	/*
	 *  arrange a linear linked-list of fops starting from context->fops
	 *
	 * platform fops
	 * [ -> fops_zip (copied into context so .next settable) ]
	 * [ -> info->fops ]
	 */

	context->fops = &context->fops_platform;
	prev = (struct lws_plat_file_ops *)context->fops;

#if defined(LWS_WITH_ZIP_FOPS)
	/* make a soft copy so we can set .next */
	context->fops_zip = fops_zip;
	prev->next = &context->fops_zip;
	prev = (struct lws_plat_file_ops *)prev->next;
#endif

	/* if user provided fops, tack them on the end of the list */
	if (info->fops)
		prev->next = info->fops;

	context->reject_service_keywords = info->reject_service_keywords;
	if (info->external_baggage_free_on_destroy)
		context->external_baggage_free_on_destroy =
			info->external_baggage_free_on_destroy;
#if defined(LWS_WITH_NETWORK)
	context->time_up = lws_now_usecs();
#endif
	context->pcontext_finalize = info->pcontext;

	context->simultaneous_ssl_restriction =
			info->simultaneous_ssl_restriction;

	context->options = info->options;

#ifndef LWS_NO_DAEMONIZE
	if (pid_daemon) {
		context->started_with_parent = pid_daemon;
		lwsl_info(" Started with daemon pid %u\n", (unsigned int)pid_daemon);
	}
#endif
#if defined(__ANDROID__)
		n = getrlimit(RLIMIT_NOFILE, &rt);
		if (n == -1) {
			lwsl_err("Get RLIMIT_NOFILE failed!\n");

			return NULL;
		}
		context->max_fds = rt.rlim_cur;
#else
#if defined(WIN32) || defined(_WIN32) || defined(LWS_AMAZON_RTOS)
		context->max_fds = getdtablesize();
#else
		context->max_fds = sysconf(_SC_OPEN_MAX);
#endif
#endif

		if (context->max_fds < 0) {
			lwsl_err("%s: problem getting process max files\n",
				 __func__);

			return NULL;
		}

	if (info->count_threads)
		context->count_threads = info->count_threads;
	else
		context->count_threads = 1;

	if (context->count_threads > LWS_MAX_SMP)
		context->count_threads = LWS_MAX_SMP;

	/*
	 * deal with any max_fds override, if it's reducing (setting it to
	 * more than ulimit -n is meaningless).  The platform init will
	 * figure out what if this is something it can deal with.
	 */
	if (info->fd_limit_per_thread) {
		int mf = info->fd_limit_per_thread * context->count_threads;

		if (mf < context->max_fds) {
			context->max_fds_unrelated_to_ulimit = 1;
			context->max_fds = mf;
		}
	}

	context->token_limits = info->token_limits;

#if defined(LWS_WITH_NETWORK)

	/*
	 * set the context event loops ops struct
	 *
	 * after this, all event_loop actions use the generic ops
	 */

#if defined(LWS_WITH_POLL)
	context->event_loop_ops = &event_loop_ops_poll;
#endif

	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
#if defined(LWS_WITH_LIBUV)
		context->event_loop_ops = &event_loop_ops_uv;
#else
		goto fail_event_libs;
#endif

	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEV))
#if defined(LWS_WITH_LIBEV)
		context->event_loop_ops = &event_loop_ops_ev;
#else
		goto fail_event_libs;
#endif

	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEVENT))
#if defined(LWS_WITH_LIBEVENT)
		context->event_loop_ops = &event_loop_ops_event;
#else
		goto fail_event_libs;
#endif

	if (!context->event_loop_ops)
		goto fail_event_libs;

	lwsl_info("Using event loop: %s\n", context->event_loop_ops->name);
#endif

#if defined(LWS_WITH_TLS) && defined(LWS_WITH_NETWORK)
	time(&context->tls.last_cert_check_s);
	if (info->alpn)
		context->tls.alpn_default = info->alpn;
	else {
		char *p = context->tls.alpn_discovered, first = 1;

		LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar) {
			if (ar->alpn) {
				if (!first)
					*p++ = ',';
				p += lws_snprintf(p,
					context->tls.alpn_discovered +
					sizeof(context->tls.alpn_discovered) -
					2 - p, "%s", ar->alpn);
				first = 0;
			}
		} LWS_FOR_EVERY_AVAILABLE_ROLE_END;

		context->tls.alpn_default = context->tls.alpn_discovered;
	}

	lwsl_info("Default ALPN advertisment: %s\n", context->tls.alpn_default);
#endif

	if (info->timeout_secs)
		context->timeout_secs = info->timeout_secs;
	else
		context->timeout_secs = AWAITING_TIMEOUT;

	context->ws_ping_pong_interval = info->ws_ping_pong_interval;

	lwsl_info(" default timeout (secs): %u\n", context->timeout_secs);

	if (info->max_http_header_data)
		context->max_http_header_data = info->max_http_header_data;
	else
		if (info->max_http_header_data2)
			context->max_http_header_data =
					info->max_http_header_data2;
		else
			context->max_http_header_data = LWS_DEF_HEADER_LEN;

	if (info->max_http_header_pool)
		context->max_http_header_pool = info->max_http_header_pool;
	else
		if (info->max_http_header_pool2)
			context->max_http_header_pool =
					info->max_http_header_pool2;
		else
			context->max_http_header_pool = context->max_fds;

	if (info->fd_limit_per_thread)
		context->fd_limit_per_thread = info->fd_limit_per_thread;
	else
		context->fd_limit_per_thread = context->max_fds /
					       context->count_threads;

#if defined(LWS_WITH_NETWORK)
	/*
	 * Allocate the per-thread storage for scratchpad buffers,
	 * and header data pool
	 */
	for (n = 0; n < context->count_threads; n++) {
		context->pt[n].serv_buf = lws_malloc(
				context->pt_serv_buf_size + sizeof(struct lws),
						     "pt_serv_buf");
		if (!context->pt[n].serv_buf) {
			lwsl_err("OOM\n");
			return NULL;
		}

		context->pt[n].context = context;
		context->pt[n].tid = n;

		/*
		 * We overallocated for a fakewsi (can't compose it in the
		 * pt because size isn't known at that time).  point to it
		 * and zero it down.  Fakewsis are needed to make callbacks work
		 * when the source of the callback is not actually from a wsi
		 * context.
		 */
		context->pt[n].fake_wsi = (struct lws *)(context->pt[n].serv_buf +
						context->pt_serv_buf_size);

		memset(context->pt[n].fake_wsi, 0, sizeof(struct lws));

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		context->pt[n].http.ah_list = NULL;
		context->pt[n].http.ah_pool_length = 0;
#endif
		lws_pt_mutex_init(&context->pt[n]);
#if defined(LWS_WITH_SEQUENCER)
		lws_seq_pt_init(&context->pt[n]);
#endif
	}

	lwsl_info(" Threads: %d each %d fds\n", context->count_threads,
		    context->fd_limit_per_thread);

	if (!info->ka_interval && info->ka_time > 0) {
		lwsl_err("info->ka_interval can't be 0 if ka_time used\n");
		return NULL;
	}

#if defined(LWS_WITH_PEER_LIMITS)
	/* scale the peer hash table according to the max fds for the process,
	 * so that the max list depth averages 16.  Eg, 1024 fd -> 64,
	 * 102400 fd -> 6400
	 */

	context->pl_hash_elements =
		(context->count_threads * context->fd_limit_per_thread) / 16;
	context->pl_hash_table = lws_zalloc(sizeof(struct lws_peer *) *
			context->pl_hash_elements, "peer limits hash table");

	context->ip_limit_ah = info->ip_limit_ah;
	context->ip_limit_wsi = info->ip_limit_wsi;
#endif

	lwsl_info(" mem: context:         %5lu B (%ld ctx + (%ld thr x %d))\n",
		  (long)sizeof(struct lws_context) +
		  (context->count_threads * context->pt_serv_buf_size),
		  (long)sizeof(struct lws_context),
		  (long)context->count_threads,
		  context->pt_serv_buf_size);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	lwsl_info(" mem: http hdr size:   (%u + %lu), max count %u\n",
		    context->max_http_header_data,
		    (long)sizeof(struct allocated_headers),
		    context->max_http_header_pool);
#endif

	/*
	 * fds table contains pollfd structs for as many pollfds as we can
	 * handle... spread across as many service threads as we have going
	 */
	n = sizeof(struct lws_pollfd) * context->count_threads *
	    context->fd_limit_per_thread;
	context->pt[0].fds = lws_zalloc(n, "fds table");
	if (context->pt[0].fds == NULL) {
		lwsl_err("OOM allocating %d fds\n", context->max_fds);
		goto bail;
	}
	lwsl_info(" mem: pollfd map:      %5u B\n", n);
#endif
	if (info->server_string) {
		context->server_string = info->server_string;
		context->server_string_len = (short)
				strlen(context->server_string);
	}

#if LWS_MAX_SMP > 1
	/* each thread serves his own chunk of fds */
	for (n = 1; n < (int)context->count_threads; n++)
		context->pt[n].fds = context->pt[n - 1].fds +
				     context->fd_limit_per_thread;
#endif

	if (lws_plat_init(context, info))
		goto bail;

#if defined(LWS_WITH_NETWORK)
	if (context->event_loop_ops->init_context)
		if (context->event_loop_ops->init_context(context, info))
			goto bail;


	if (context->event_loop_ops->init_pt)
		for (n = 0; n < context->count_threads; n++) {
			void *lp = NULL;

			if (info->foreign_loops)
				lp = info->foreign_loops[n];

			if (context->event_loop_ops->init_pt(context, lp, n))
				goto bail;
		}

#if !defined(LWS_AMAZON_RTOS)
	if (lws_create_event_pipes(context))
		goto bail;
#endif
#endif

	lws_context_init_ssl_library(info);

	context->user_space = info->user;
#if defined(LWS_WITH_NETWORK)
	/*
	 * if he's not saying he'll make his own vhosts later then act
	 * compatibly and make a default vhost using the data in the info
	 */
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS))
		if (!lws_create_vhost(context, info)) {
			lwsl_err("Failed to create default vhost\n");
			for (n = 0; n < context->count_threads; n++)
				lws_free_set_NULL(context->pt[n].serv_buf);
#if defined(LWS_WITH_PEER_LIMITS)
			lws_free_set_NULL(context->pl_hash_table);
#endif
			goto fail_clean_pipes;
		}

	lws_context_init_extensions(info, context);

	lwsl_info(" mem: per-conn:        %5lu bytes + protocol rx buf\n",
		    (unsigned long)sizeof(struct lws));
#endif
	strcpy(context->canonical_hostname, "unknown");
#if defined(LWS_WITH_NETWORK)
	lws_server_get_canonical_hostname(context, info);
#endif

#if defined(LWS_WITH_STATS)
	context->pt[0].sul_stats.cb = lws_sul_stats_cb;
	__lws_sul_insert(&context->pt[0].pt_sul_owner, &context->pt[0].sul_stats,
			 10 * LWS_US_PER_SEC);
#endif
#if defined(LWS_WITH_PEER_LIMITS)
	context->pt[0].sul_peer_limits.cb = lws_sul_peer_limits_cb;
	__lws_sul_insert(&context->pt[0].pt_sul_owner,
			 &context->pt[0].sul_peer_limits, 10 * LWS_US_PER_SEC);
#endif

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	memcpy(context->caps, info->caps, sizeof(context->caps));
	context->count_caps = info->count_caps;
#endif

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS))
		if (lws_plat_drop_app_privileges(context, 1))
			goto bail;

#if defined(LWS_WITH_NETWORK)
	/* expedite post-context init (eg, protocols) */
	lws_cancel_service(context);
#endif

	return context;

#if defined(LWS_WITH_NETWORK)
fail_clean_pipes:
	for (n = 0; n < context->count_threads; n++)
		lws_destroy_event_pipe(context->pt[n].pipe_wsi);

	lws_free_set_NULL(context->pt[0].fds);
	lws_plat_context_late_destroy(context);
	lws_free_set_NULL(context);

	return NULL;
#endif

bail:
	lws_context_destroy(context);

	return NULL;

#if defined(LWS_WITH_NETWORK)
fail_event_libs:
	lwsl_err("Requested event library support not configured, available:\n");
	{
		extern const struct lws_event_loop_ops *available_event_libs[];
		const struct lws_event_loop_ops **elops = available_event_libs;

		while (*elops) {
			lwsl_err("  - %s\n", (*elops)->name);
			elops++;
		}
	}
#endif
	lws_free(context);

	return NULL;
}

LWS_VISIBLE LWS_EXTERN int
lws_context_is_deprecated(struct lws_context *context)
{
	return context->deprecated;
}

/*
 * When using an event loop, the context destruction is in three separate
 * parts.  This is to cover both internal and foreign event loops cleanly.
 *
 *  - lws_context_destroy() simply starts a soft close of all wsi and
 *     related allocations.  The event loop continues.
 *
 *     As the closes complete in the event loop, reference counting is used
 *     to determine when everything is closed.  It then calls
 *     lws_context_destroy2().
 *
 *  - lws_context_destroy2() cleans up the rest of the higher-level logical
 *     lws pieces like vhosts.  If the loop was foreign, it then proceeds to
 *     lws_context_destroy3().  If it the loop is internal, it stops the
 *     internal loops and waits for lws_context_destroy() to be called again
 *     outside the event loop (since we cannot destroy the loop from
 *     within the loop).  That will cause lws_context_destroy3() to run
 *     directly.
 *
 *  - lws_context_destroy3() destroys any internal event loops and then
 *     destroys the context itself, setting what was info.pcontext to NULL.
 */

/*
 * destroy the actual context itself
 */

static void
lws_context_destroy3(struct lws_context *context)
{
	struct lws_context **pcontext_finalize = context->pcontext_finalize;
#if defined(LWS_WITH_NETWORK)
	int n;

	lwsl_debug("%s\n", __func__);

	for (n = 0; n < context->count_threads; n++) {
		struct lws_context_per_thread *pt = &context->pt[n];
		(void)pt;
#if defined(LWS_WITH_SEQUENCER)
		lws_seq_destroy_all_on_pt(pt);
#endif

		if (context->event_loop_ops->destroy_pt)
			context->event_loop_ops->destroy_pt(context, n);

		lws_free_set_NULL(context->pt[n].serv_buf);

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		while (pt->http.ah_list)
			_lws_destroy_ah(pt, pt->http.ah_list);
#endif
	}

	if (context->pt[0].fds)
		lws_free_set_NULL(context->pt[0].fds);
#endif
	lws_context_deinit_ssl_library(context);

	lws_free(context);
	lwsl_info("%s: ctx %p freed\n", __func__, context);

	if (pcontext_finalize)
		*pcontext_finalize = NULL;
}

/*
 * really start destroying things
 */

void
lws_context_destroy2(struct lws_context *context)
{
#if defined(LWS_WITH_NETWORK)
	struct lws_vhost *vh = NULL, *vh1;
#endif
#if defined(LWS_WITH_PEER_LIMITS)
	uint32_t nu;
#endif

	lwsl_info("%s: ctx %p\n", __func__, context);

	lws_context_lock(context, "context destroy 2"); /* ------ context { */

	context->being_destroyed2 = 1;
#if defined(LWS_WITH_NETWORK)
	/*
	 * free all the per-vhost allocations
	 */

	vh = context->vhost_list;
	while (vh) {
		vh1 = vh->vhost_next;
		__lws_vhost_destroy2(vh);
		vh = vh1;
	}

	lwsl_debug("%p: post vh listl\n", __func__);

	/* remove ourselves from the pending destruction list */

	while (context->vhost_pending_destruction_list)
		/* removes itself from list */
		__lws_vhost_destroy2(context->vhost_pending_destruction_list);
#endif

	lwsl_debug("%p: post pdl\n", __func__);

	lws_stats_log_dump(context);
#if defined(LWS_WITH_NETWORK)
	lws_ssl_context_destroy(context);
#endif
	lws_plat_context_late_destroy(context);

#if defined(LWS_WITH_PEER_LIMITS)
	for (nu = 0; nu < context->pl_hash_elements; nu++)	{
		lws_start_foreach_llp(struct lws_peer **, peer,
				      context->pl_hash_table[nu]) {
			struct lws_peer *df = *peer;
			*peer = df->next;
			lws_free(df);
			continue;
		} lws_end_foreach_llp(peer, next);
	}
	lws_free(context->pl_hash_table);
#endif

	lwsl_debug("%p: baggage\n", __func__);

	if (context->external_baggage_free_on_destroy)
		free(context->external_baggage_free_on_destroy);

#if defined(LWS_WITH_NETWORK)
	lws_check_deferred_free(context, 0, 1);
#endif

#if LWS_MAX_SMP > 1
	lws_mutex_refcount_destroy(&context->mr);
#endif
#if defined(LWS_WITH_NETWORK)
	if (context->event_loop_ops->destroy_context2)
		if (context->event_loop_ops->destroy_context2(context)) {
			lws_context_unlock(context); /* } context ----------- */
			context->finalize_destroy_after_internal_loops_stopped = 1;
			return;
		}

	lwsl_debug("%p: post dc2\n", __func__);

	if (!context->pt[0].event_loop_foreign) {
		int n;
		for (n = 0; n < context->count_threads; n++)
			if (context->pt[n].inside_service) {
				lwsl_debug("%p: bailing as inside service\n", __func__);
				lws_context_unlock(context); /* } context --- */
				return;
			}
	}
#endif
	lws_context_unlock(context); /* } context ------------------- */

	lws_context_destroy3(context);
}

/*
 * Begin the context takedown
 */

LWS_VISIBLE void
lws_context_destroy(struct lws_context *context)
{
#if defined(LWS_WITH_NETWORK)
	volatile struct lws_foreign_thread_pollfd *ftp, *next;
	volatile struct lws_context_per_thread *vpt;
	struct lws_vhost *vh = NULL;
	struct lws wsi;
	int n, m;
#endif

	if (!context)
		return;
#if defined(LWS_WITH_NETWORK)
	if (context->finalize_destroy_after_internal_loops_stopped) {
		if (context->event_loop_ops->destroy_context2)
			context->event_loop_ops->destroy_context2(context);
		lws_context_destroy3(context);

		return;
	}
#endif
	if (context->being_destroyed1) {
		if (!context->being_destroyed2) {
			lws_context_destroy2(context);

			return;
		}
		lwsl_info("%s: ctx %p: already being destroyed\n",
			    __func__, context);

		lws_context_destroy3(context);
		return;
	}

	lwsl_info("%s: ctx %p\n", __func__, context);

	context->being_destroyed = 1;
	context->being_destroyed1 = 1;
	context->requested_kill = 1;

#if defined(LWS_WITH_NETWORK)
	m = context->count_threads;
	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

#ifdef LWS_LATENCY
	if (context->worst_latency_info[0])
		lwsl_notice("Worst latency: %s\n", context->worst_latency_info);
#endif

	while (m--) {
		struct lws_context_per_thread *pt = &context->pt[m];
		vpt = (volatile struct lws_context_per_thread *)pt;

		ftp = vpt->foreign_pfd_list;
		while (ftp) {
			next = ftp->next;
			lws_free((void *)ftp);
			ftp = next;
		}
		vpt->foreign_pfd_list = NULL;

		for (n = 0; (unsigned int)n < context->pt[m].fds_count; n++) {
			struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;

			if (wsi->event_pipe)
				lws_destroy_event_pipe(wsi);
			else
				lws_close_free_wsi(wsi,
					LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY,
					"ctx destroy"
					/* no protocol close */);
			n--;
		}
		lws_pt_mutex_destroy(pt);
	}

	/*
	 * inform all the protocols that they are done and will have no more
	 * callbacks.
	 *
	 * We can't free things until after the event loop shuts down.
	 */
	if (context->protocol_init_done)
		vh = context->vhost_list;
	while (vh) {
		struct lws_vhost *vhn = vh->vhost_next;
		lws_vhost_destroy1(vh);
		vh = vhn;
	}
#endif

	lws_plat_context_early_destroy(context);

#if defined(LWS_WITH_NETWORK)

	/*
	 * We face two different needs depending if foreign loop or not.
	 *
	 * 1) If foreign loop, we really want to advance the destroy_context()
	 *    past here, and block only for libuv-style async close completion.
	 *
	 * 2a) If poll, and we exited by ourselves and are calling a final
	 *     destroy_context() outside of any service already, we want to
	 *     advance all the way in one step.
	 *
	 * 2b) If poll, and we are reacting to a SIGINT, service thread(s) may
	 *     be in poll wait or servicing.  We can't advance the
	 *     destroy_context() to the point it's freeing things; we have to
	 *     leave that for the final destroy_context() after the service
	 *     thread(s) are finished calling for service.
	 */

	if (context->event_loop_ops->destroy_context1) {
		context->event_loop_ops->destroy_context1(context);

		return;
	}
#endif

#if defined(LWS_WITH_ESP32)
#if defined(LWS_AMAZON_RTOS)
	context->last_free_heap = xPortGetFreeHeapSize();
#else
	context->last_free_heap = esp_get_free_heap_size();
#endif
#endif

	lws_context_destroy2(context);
}

