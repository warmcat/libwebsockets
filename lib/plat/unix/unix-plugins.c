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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

#include <pwd.h>
#include <grp.h>

#ifdef LWS_WITH_PLUGINS
#include <dlfcn.h>
#endif
#include <dirent.h>

static int filter(const struct dirent *ent)
{
	if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
		return 0;

	return 1;
}

int
lws_plat_plugins_init(struct lws_context * context, const char * const *d)
{
	struct lws_plugin_capability lcaps;
	struct lws_plugin *plugin;
	lws_plugin_init_func initfunc;
	struct dirent **namelist;
	int n, i, m, ret = 0;
	char path[256];
	void *l;

#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)
	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return lws_uv_plugins_init(context, d);
#endif

	lwsl_notice("  Plugins:\n");

	while (d && *d) {
		n = scandir(*d, &namelist, filter, alphasort);
		if (n < 0) {
			lwsl_err("Scandir on %s failed\n", *d);
			return 1;
		}

		for (i = 0; i < n; i++) {
			if (strlen(namelist[i]->d_name) < 7)
				goto inval;

			lwsl_notice("   %s\n", namelist[i]->d_name);

			lws_snprintf(path, sizeof(path) - 1, "%s/%s", *d,
				 namelist[i]->d_name);
			l = dlopen(path, RTLD_NOW);
			if (!l) {
				lwsl_err("Error loading DSO: %s\n", dlerror());
				while (i++ < n)
					free(namelist[i]);
				goto bail;
			}
			/* we could open it, can we get his init function? */
			m = lws_snprintf(path, sizeof(path) - 1, "init_%s",
				     namelist[i]->d_name + 3 /* snip lib... */);
			path[m - 3] = '\0'; /* snip the .so */
			initfunc = dlsym(l, path);
			if (!initfunc) {
				lwsl_err("%s: Failed to get init '%s' on %s: %s\n",
					__func__, path, namelist[i]->d_name, dlerror());
				goto skip;
			}
			lcaps.api_magic = LWS_PLUGIN_API_MAGIC;
			m = initfunc(context, &lcaps);
			if (m) {
				lwsl_err("Initializing %s failed %d\n",
					namelist[i]->d_name, m);
				goto skip;
			}

			plugin = lws_malloc(sizeof(*plugin), "plugin");
			if (!plugin) {
				dlclose(l);
				lwsl_err("OOM\n");
				goto bail;
			}
			plugin->list = context->plugin_list;
			context->plugin_list = plugin;
			lws_strncpy(plugin->name, namelist[i]->d_name,
				    sizeof(plugin->name));
			plugin->l = l;
			plugin->caps = lcaps;
			context->plugin_protocol_count += lcaps.count_protocols;
			context->plugin_extension_count += lcaps.count_extensions;

			free(namelist[i]);
			continue;

	skip:
			dlclose(l);
	inval:
			free(namelist[i]);
		}
		free(namelist);
		d++;
	}

	return 0;

bail:
	free(namelist);

	return ret;
}

int
lws_plat_plugins_destroy(struct lws_context * context)
{
	struct lws_plugin *plugin = context->plugin_list, *p;
	lws_plugin_destroy_func func;
	char path[256];
	int m;

#if defined(LWS_WITH_PLUGINS) && (UV_VERSION_MAJOR > 0)
	if (lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV))
		return lws_uv_plugins_destroy(context);
#endif

	if (!plugin)
		return 0;

	lwsl_notice("%s\n", __func__);

	while (plugin) {
		p = plugin;
		m = lws_snprintf(path, sizeof(path) - 1, "destroy_%s",
				 plugin->name + 3);
		path[m - 3] = '\0';
		func = dlsym(plugin->l, path);
		if (!func) {
			lwsl_err("Failed to get destroy on %s: %s",
					plugin->name, dlerror());
			goto next;
		}
		m = func(context);
		if (m)
			lwsl_err("Initializing %s failed %d\n",
				plugin->name, m);
next:
		dlclose(p->l);
		plugin = p->list;
		p->list = NULL;
		free(p);
	}

	context->plugin_list = NULL;

	return 0;
}
