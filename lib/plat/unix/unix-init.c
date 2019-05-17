/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#define _GNU_SOURCE
#include "core/private.h"

#include <pwd.h>
#include <grp.h>

#ifdef LWS_WITH_PLUGINS
#include <dlfcn.h>
#endif
#include <dirent.h>

int
lws_plat_init(struct lws_context *context,
	      const struct lws_context_creation_info *info)
{
	int fd;
#if defined(LWS_WITH_NETWORK)
	/*
	 * master context has the process-global fd lookup array.  This can be
	 * done two different ways now; one or the other is done depending on if
	 * info->fd_limit_per_thread was snonzero
	 *
	 *  - default: allocate a worst-case lookup array sized for ulimit -n
	 *             and use the fd directly as an index into it
	 *
	 *  - slow:    allocate context->max_fds entries only (which can be
	 *             forced at context creation time to be
	 *             info->fd_limit_per_thread * the number of threads)
	 *             and search the array to lookup fds
	 *
	 * the default way is optimized for server, if you only use one or two
	 * client wsi the slow way may save a lot of memory.
	 *
	 * Both ways allocate an array of struct lws *... one allocates it for
	 * all possible fd indexes the process could produce and uses it as a
	 * map, the other allocates for an amount of wsi the lws context is
	 * expected to use and searches through it to manipulate it.
	 */

	context->lws_lookup = lws_zalloc(sizeof(struct lws *) *
					 context->max_fds, "lws_lookup");

	if (!context->lws_lookup) {
		lwsl_err("%s: OOM on alloc lws_lookup array for %d conn\n",
			 __func__, context->max_fds);
		return 1;
	}

	lwsl_info(" mem: platform fd map: %5lu B\n",
		    (unsigned long)(sizeof(struct lws *) * context->max_fds));
#endif
	fd = lws_open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);

	context->fd_random = fd;
	if (context->fd_random < 0) {
		lwsl_err("Unable to open random device %s %d\n",
			 SYSTEM_RANDOM_FILEPATH, context->fd_random);
		return 1;
	}

#if defined(LWS_WITH_PLUGINS)
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif

	return 0;
}

int
lws_plat_context_early_init(void)
{
#if !defined(LWS_AVOID_SIGPIPE_IGN)
	signal(SIGPIPE, SIG_IGN);
#endif

	return 0;
}

void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

void
lws_plat_context_late_destroy(struct lws_context *context)
{
#ifdef LWS_WITH_PLUGINS
	if (context->plugin_list)
		lws_plat_plugins_destroy(context);
#endif
#if defined(LWS_WITH_NETWORK)
	if (context->lws_lookup)
		lws_free_set_NULL(context->lws_lookup);
#endif
	if (!context->fd_random)
		lwsl_err("ZERO RANDOM FD\n");
	if (context->fd_random != LWS_INVALID_FILE)
		close(context->fd_random);
}
