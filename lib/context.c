/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2015 Andy Green <andy@warmcat.com>
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

#include "private-libwebsockets.h"

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

static const char * const mount_protocols[] = {
	"http://",
	"https://",
	"file://",
	"cgi://",
	">http://",
	">https://",
};

LWS_VISIBLE void *
lws_protocol_vh_priv_zalloc(struct lws_vhost *vhost, const struct lws_protocols *prot,
			    int size)
{
	int n = 0;

	/* allocate the vh priv array only on demand */
	if (!vhost->protocol_vh_privs) {
		vhost->protocol_vh_privs = (void **)lws_zalloc(
				vhost->count_protocols * sizeof(void *));
		if (!vhost->protocol_vh_privs)
			return NULL;
	}

	while (n < vhost->count_protocols && &vhost->protocols[n] != prot)
		n++;

	if (n == vhost->count_protocols)
		return NULL;

	vhost->protocol_vh_privs[n] = lws_zalloc(size);
	return vhost->protocol_vh_privs[n];
}

LWS_VISIBLE void *
lws_protocol_vh_priv_get(struct lws_vhost *vhost, const struct lws_protocols *prot)
{
	int n = 0;

	if (!vhost->protocol_vh_privs)
		return NULL;

	while (n < vhost->count_protocols && &vhost->protocols[n] != prot)
		n++;

	if (n == vhost->count_protocols) {
		lwsl_err("%s: unknown protocol %p\n", __func__, prot);
		return NULL;
	}

	return vhost->protocol_vh_privs[n];
}

static const struct lws_protocol_vhost_options *
lws_vhost_protocol_options(struct lws_vhost *vh, const char *name)
{
	const struct lws_protocol_vhost_options *pvo = vh->pvo;

	while (pvo) {
		// lwsl_notice("%s: '%s' '%s'\n", __func__, pvo->name, name);
		if (!strcmp(pvo->name, name))
			return pvo;
		pvo = pvo->next;
	}

	return NULL;
}

int
lws_protocol_init(struct lws_context *context)
{
	struct lws_vhost *vh = context->vhost_list;
	const struct lws_protocol_vhost_options *pvo, *pvo1;
	struct lws wsi;
	int n;

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

	lwsl_notice("%s\n", __func__);

	while (vh) {
		wsi.vhost = vh;

		/* initialize supported protocols on this vhost */

		for (n = 0; n < vh->count_protocols; n++) {
			wsi.protocol = &vh->protocols[n];

			pvo = lws_vhost_protocol_options(vh,
							 vh->protocols[n].name);
			if (pvo) {
				/*
				 * linked list of options specific to
				 * vh + protocol
				 */
				pvo1 = pvo;
				pvo = pvo1->options;

				while (pvo) {
					lwsl_notice("    vh %s prot %s opt %s\n",
							vh->name,
							vh->protocols[n].name,
							pvo->name);

					if (!strcmp(pvo->name, "default")) {
						lwsl_notice("Setting default "
						   "protocol for vh %s to %s\n",
						   vh->name,
						   vh->protocols[n].name);
						vh->default_protocol_index = n;
					}
					pvo = pvo->next;
				}

				pvo = pvo1->options;
			}

			/*
			 * inform all the protocols that they are doing their one-time
			 * initialization if they want to.
			 *
			 * NOTE the wsi is all zeros except for the context, vh and
			 * protocol ptrs so lws_get_context(wsi) etc can work
			 */
			vh->protocols[n].callback(&wsi,
				LWS_CALLBACK_PROTOCOL_INIT, NULL,
				(void *)pvo, 0);
		}

		vh = vh->vhost_next;
	}

	context->protocol_init_done = 1;

	return 0;
}

static int callback_http_dummy(
		struct lws *wsi, enum lws_callback_reasons reason, void *user,
		  void *in, size_t len)
{
	return 0;
}

/* list of supported protocols and callbacks */

static const struct lws_protocols protocols_dummy[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",		/* name */
		callback_http_dummy,		/* callback */
		0,	/* per_session_data_size */
		0,			/* max frame size / rx buffer */
	},
	/*
	 * the other protocols are provided by lws plugins
	 */
	{ NULL, NULL, 0, 0 } /* terminator */
};

LWS_VISIBLE struct lws_vhost *
lws_create_vhost(struct lws_context *context,
		 struct lws_context_creation_info *info)
{
	struct lws_vhost *vh = lws_zalloc(sizeof(*vh)),
			 **vh1 = &context->vhost_list;
	const struct lws_http_mount *mounts;
#ifdef LWS_WITH_PLUGINS
	struct lws_plugin *plugin = context->plugin_list;
	struct lws_protocols *lwsp;
	int m, n, f = !info->pvo;
#endif
	char *p;

	if (!vh)
		return NULL;

	if (!info->protocols)
		info->protocols = &protocols_dummy[0];

	vh->context = context;
	if (!info->vhost_name)
		vh->name = "default";
	else
		vh->name = info->vhost_name;

	vh->iface = info->iface;
	for (vh->count_protocols = 0;
	     info->protocols[vh->count_protocols].callback;
	     vh->count_protocols++)
		;

	vh->options = info->options;
	vh->pvo = info->pvo;
	vh->keepalive_timeout = info->keepalive_timeout;

#ifdef LWS_WITH_PLUGINS
	if (plugin) {
		/*
		 * give the vhost a unified list of protocols including the
		 * ones that came from plugins
		 */
		lwsp = lws_zalloc(sizeof(struct lws_protocols) *
					   (vh->count_protocols +
					   context->plugin_protocol_count + 1));
		if (!lwsp)
			return NULL;

		m = vh->count_protocols;
		memcpy(lwsp, info->protocols,
		       sizeof(struct lws_protocols) * m);

		/* for compatibility, all protocols enabled on vhost if only
		 * the default vhost exists.  Otherwise only vhosts who ask
		 * for a protocol get it enabled.
		 */

		if (info->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS)
			f = 0;

		while (plugin) {
			for (n = 0; n < plugin->caps.count_protocols; n++) {
				/*
				 * for compatibility's sake, no pvo implies
				 * allow all protocols
				 */
				if (f || lws_vhost_protocol_options(vh,
				    plugin->caps.protocols[n].name)) {
					memcpy(&lwsp[m],
					       &plugin->caps.protocols[n],
					       sizeof(struct lws_protocols));
					m++;
					vh->count_protocols++;
				}
			}
			plugin = plugin->list;
		}
		vh->protocols = lwsp;
	} else
#endif
		vh->protocols = info->protocols;

	vh->same_vh_protocol_list = (struct lws **)
			lws_zalloc(sizeof(struct lws *) * vh->count_protocols);

	vh->mount_list = info->mounts;

#ifdef LWS_USE_UNIX_SOCK
	if (LWS_UNIX_SOCK_ENABLED(context)) {
		lwsl_notice("Creating Vhost '%s' path \"%s\", %d protocols\n",
				vh->name, info->iface, vh->count_protocols);
	} else
#endif
	lwsl_notice("Creating Vhost '%s' port %d, %d protocols\n",
			vh->name, info->port, vh->count_protocols);

	mounts = info->mounts;
	while (mounts) {
		lwsl_notice("   mounting %s%s to %s\n",
				mount_protocols[mounts->origin_protocol],
				mounts->origin, mounts->mountpoint);
		mounts = mounts->mount_next;
	}

#ifndef LWS_NO_EXTENSIONS
#ifdef LWS_WITH_PLUGINS
	if (context->plugin_extension_count) {

		m = 0;
		while (info->extensions && info->extensions[m].callback)
			m++;

		/*
		 * give the vhost a unified list of extensions including the
		 * ones that came from plugins
		 */
		vh->extensions = lws_zalloc(sizeof(struct lws_extension) *
					   (m +
					   context->plugin_extension_count + 1));
		if (!vh->extensions)
			return NULL;

		memcpy((struct lws_extension *)vh->extensions, info->extensions,
		       sizeof(struct lws_extension) * m);
		plugin = context->plugin_list;
		while (plugin) {
			memcpy((struct lws_extension *)&vh->extensions[m],
				plugin->caps.extensions,
			       sizeof(struct lws_extension) *
			       plugin->caps.count_extensions);
			m += plugin->caps.count_extensions;
			plugin = plugin->list;
		}
	} else
#endif
		vh->extensions = info->extensions;
#endif

	vh->listen_port = info->port;
	vh->http_proxy_port = 0;
	vh->http_proxy_address[0] = '\0';

	/* either use proxy from info, or try get it from env var */

	if (info->http_proxy_address) {
		/* override for backwards compatibility */
		if (info->http_proxy_port)
			vh->http_proxy_port = info->http_proxy_port;
		lws_set_proxy(vh, info->http_proxy_address);
	} else {
#ifdef LWS_HAVE_GETENV
		p = getenv("http_proxy");
		if (p)
			lws_set_proxy(vh, p);
#endif
	}

	vh->ka_time = info->ka_time;
	vh->ka_interval = info->ka_interval;
	vh->ka_probes = info->ka_probes;

	if (vh->options & LWS_SERVER_OPTION_STS)
		lwsl_notice("   STS enabled\n");

#ifdef LWS_WITH_ACCESS_LOG
	if (info->log_filepath) {
		vh->log_fd = open(info->log_filepath, O_CREAT | O_APPEND | O_RDWR, 0600);
		if (vh->log_fd == LWS_INVALID_FILE) {
			lwsl_err("unable to open log filepath %s\n",
				 info->log_filepath);
			goto bail;
		}
#ifndef WIN32
		if (context->uid != -1)
			if (chown(info->log_filepath, context->uid,
				  context->gid) == -1)
				lwsl_err("unable to chown log file %s\n",
						info->log_filepath);
#endif
	} else
		vh->log_fd = LWS_INVALID_FILE;
#endif

	if (lws_context_init_server_ssl(info, vh))
		goto bail;

	if (lws_context_init_client_ssl(info, vh))
		goto bail;

	if (lws_context_init_server(info, vh))
		goto bail;

	while (1) {
		if (!(*vh1)) {
			*vh1 = vh;
			break;
		}
		vh1 = &(*vh1)->vhost_next;
	};

	return vh;

bail:
	lws_free(vh);

	return NULL;
}

/**
 * lws_create_context() - Create the websocket handler
 * @info:	pointer to struct with parameters
 *
 *	This function creates the listening socket (if serving) and takes care
 *	of all initialization in one step.
 *
 *	After initialization, it returns a struct lws_context * that
 *	represents this server.  After calling, user code needs to take care
 *	of calling lws_service() with the context pointer to get the
 *	server's sockets serviced.  This must be done in the same process
 *	context as the initialization call.
 *
 *	The protocol callback functions are called for a handful of events
 *	including http requests coming in, websocket connections becoming
 *	established, and data arriving; it's also called periodically to allow
 *	async transmission.
 *
 *	HTTP requests are sent always to the FIRST protocol in @protocol, since
 *	at that time websocket protocol has not been negotiated.  Other
 *	protocols after the first one never see any HTTP callack activity.
 *
 *	The server created is a simple http server by default; part of the
 *	websocket standard is upgrading this http connection to a websocket one.
 *
 *	This allows the same server to provide files like scripts and favicon /
 *	images or whatever over http and dynamic data over websockets all in
 *	one place; they're all handled in the user callback.
 */
LWS_VISIBLE struct lws_context *
lws_create_context(struct lws_context_creation_info *info)
{
	struct lws_context *context = NULL;
	struct lws wsi;
#ifndef LWS_NO_DAEMONIZE
	int pid_daemon = get_daemonize_pid();
#endif
	int n, m;
#if defined(__ANDROID__)
	struct rlimit rt;
#endif

	lwsl_notice("Initial logging level %d\n", log_level);
	lwsl_notice("Libwebsockets version: %s\n", library_version);
#if LWS_POSIX
#ifdef LWS_USE_IPV6
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_notice("IPV6 compiled in and enabled\n");
	else
		lwsl_notice("IPV6 compiled in but disabled\n");
#else
	lwsl_notice("IPV6 not compiled in\n");
#endif
	lws_feature_status_libev(info);
	lws_feature_status_libuv(info);
#endif
	lwsl_info(" LWS_DEF_HEADER_LEN    : %u\n", LWS_DEF_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS     : %u\n", LWS_MAX_PROTOCOLS);
	lwsl_info(" LWS_MAX_SMP           : %u\n", LWS_MAX_SMP);
	lwsl_info(" SPEC_LATEST_SUPPORTED : %u\n", SPEC_LATEST_SUPPORTED);
	lwsl_info(" sizeof (*info)        : %u\n", sizeof(*info));
#if LWS_POSIX
	lwsl_info(" SYSTEM_RANDOM_FILEPATH: '%s'\n", SYSTEM_RANDOM_FILEPATH);
#endif
	if (lws_plat_context_early_init())
		return NULL;

	context = lws_zalloc(sizeof(struct lws_context));
	if (!context) {
		lwsl_err("No memory for websocket context\n");
		return NULL;
	}

	context->time_up = time(NULL);
#ifndef LWS_NO_DAEMONIZE
	if (pid_daemon) {
		context->started_with_parent = pid_daemon;
		lwsl_notice(" Started with daemon pid %d\n", pid_daemon);
	}
#endif
#if defined(__ANDROID__)
		n = getrlimit ( RLIMIT_NOFILE,&rt);
		if (-1 == n) {
			lwsl_err("Get RLIMIT_NOFILE failed!\n");
			return NULL;
		}
		context->max_fds = rt.rlim_cur;
#else
		context->max_fds = getdtablesize();
#endif

	if (info->count_threads)
		context->count_threads = info->count_threads;
	else
		context->count_threads = 1;

	if (context->count_threads > LWS_MAX_SMP)
		context->count_threads = LWS_MAX_SMP;

	context->token_limits = info->token_limits;

	context->options = info->options;

	if (info->timeout_secs)
		context->timeout_secs = info->timeout_secs;
	else
		context->timeout_secs = AWAITING_TIMEOUT;

	lwsl_info(" default timeout (secs): %u\n", context->timeout_secs);

	if (info->max_http_header_data)
		context->max_http_header_data = info->max_http_header_data;
	else
		context->max_http_header_data = LWS_DEF_HEADER_LEN;
	if (info->max_http_header_pool)
		context->max_http_header_pool = info->max_http_header_pool;
	else
		context->max_http_header_pool = LWS_DEF_HEADER_POOL;

	/*
	 * Allocate the per-thread storage for scratchpad buffers,
	 * and header data pool
	 */
	for (n = 0; n < context->count_threads; n++) {
		context->pt[n].serv_buf = lws_zalloc(LWS_MAX_SOCKET_IO_BUF);
		if (!context->pt[n].serv_buf) {
			lwsl_err("OOM\n");
			return NULL;
		}

		context->pt[n].context = context;
		context->pt[n].tid = n;
		context->pt[n].http_header_data = lws_malloc(context->max_http_header_data *
						       context->max_http_header_pool);
		if (!context->pt[n].http_header_data)
			goto bail;

		context->pt[n].ah_pool = lws_zalloc(sizeof(struct allocated_headers) *
					      context->max_http_header_pool);
		for (m = 0; m < context->max_http_header_pool; m++)
			context->pt[n].ah_pool[m].data =
				(char *)context->pt[n].http_header_data +
				(m * context->max_http_header_data);
		if (!context->pt[n].ah_pool)
			goto bail;

		lws_pt_mutex_init(&context->pt[n]);
	}

	if (info->fd_limit_per_thread)
		context->fd_limit_per_thread = info->fd_limit_per_thread;
	else
		context->fd_limit_per_thread = context->max_fds /
					       context->count_threads;

	lwsl_notice(" Threads: %d each %d fds\n", context->count_threads,
		    context->fd_limit_per_thread);

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

	if (!info->ka_interval && info->ka_time > 0) {
		lwsl_err("info->ka_interval can't be 0 if ka_time used\n");
		return NULL;
	}

#ifdef LWS_USE_LIBEV
	/* (Issue #264) In order to *avoid breaking backwards compatibility*, we
	 * enable libev mediated SIGINT handling with a default handler of
	 * lws_sigint_cb. The handler can be overridden or disabled
	 * by invoking lws_sigint_cfg after creating the context, but
	 * before invoking lws_initloop:
	 */
	context->use_ev_sigint = 1;
	context->lws_ev_sigint_cb = &lws_ev_sigint_cb;
#endif /* LWS_USE_LIBEV */
#ifdef LWS_USE_LIBUV
	/* (Issue #264) In order to *avoid breaking backwards compatibility*, we
	 * enable libev mediated SIGINT handling with a default handler of
	 * lws_sigint_cb. The handler can be overridden or disabled
	 * by invoking lws_sigint_cfg after creating the context, but
	 * before invoking lws_initloop:
	 */
	context->use_ev_sigint = 1;
	context->lws_uv_sigint_cb = &lws_uv_sigint_cb;
#endif

	lwsl_info(" mem: context:         %5u bytes (%d ctx + (%d thr x %d))\n",
		  sizeof(struct lws_context) +
		  (context->count_threads * LWS_MAX_SOCKET_IO_BUF),
		  sizeof(struct lws_context),
		  context->count_threads,
		  LWS_MAX_SOCKET_IO_BUF);

	lwsl_info(" mem: http hdr rsvd:   %5u bytes (%u thr x (%u + %u) x %u))\n",
		    (context->max_http_header_data +
		     sizeof(struct allocated_headers)) *
		    context->max_http_header_pool * context->count_threads,
		    context->count_threads,
		    context->max_http_header_data,
		    sizeof(struct allocated_headers),
		    context->max_http_header_pool);
	n = sizeof(struct lws_pollfd) * context->count_threads *
	    context->fd_limit_per_thread;
	context->pt[0].fds = lws_zalloc(n);
	if (context->pt[0].fds == NULL) {
		lwsl_err("OOM allocating %d fds\n", context->max_fds);
		goto bail;
	}
	lwsl_info(" mem: pollfd map:      %5u\n", n);

	if (info->server_string) {
		context->server_string = info->server_string;
		context->server_string_len = (short)
				strlen(context->server_string);
	} else {
		context->server_string = "libwebsockets";
		context->server_string_len = 13;
	}

#if LWS_MAX_SMP > 1
	/* each thread serves his own chunk of fds */
	for (n = 1; n < (int)info->count_threads; n++)
		context->pt[n].fds = context->pt[n - 1].fds +
				     context->fd_limit_per_thread;
#endif

	if (lws_plat_init(context, info))
		goto bail;

	lws_context_init_ssl_library(info);

	context->user_space = info->user;

	/*
	 * if he's not saying he'll make his own vhosts later then act
	 * compatibly and make a default vhost using the data in the info
	 */
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS))
		if (!lws_create_vhost(context, info)) {
			lwsl_err("Failed to create default vhost\n");
			return NULL;
		}

	lws_context_init_extensions(info, context);

	lwsl_notice(" mem: per-conn:        %5u bytes + protocol rx buf\n",
		    sizeof(struct lws));

	strcpy(context->canonical_hostname, "unknown");
	lws_server_get_canonical_hostname(context, info);

	context->uid = info->uid;
	context->gid = info->gid;

	/*
	 * drop any root privs for this process
	 * to listen on port < 1023 we would have needed root, but now we are
	 * listening, we don't want the power for anything else
	 */
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS))
		lws_plat_drop_app_privileges(info);

	/*
	 * give all extensions a chance to create any per-context
	 * allocations they need
	 */
	if (info->port != CONTEXT_PORT_NO_LISTEN) {
		if (lws_ext_cb_all_exts(context, NULL,
			LWS_EXT_CB_SERVER_CONTEXT_CONSTRUCT, NULL, 0) < 0)
			goto bail;
	} else
		if (lws_ext_cb_all_exts(context, NULL,
			LWS_EXT_CB_CLIENT_CONTEXT_CONSTRUCT, NULL, 0) < 0)
			goto bail;

	return context;

bail:
	lws_context_destroy(context);
	return NULL;
}

/**
 * lws_context_destroy() - Destroy the websocket context
 * @context:	Websocket context
 *
 *	This function closes any active connections and then frees the
 *	context.  After calling this, any further use of the context is
 *	undefined.
 */
LWS_VISIBLE void
lws_context_destroy(struct lws_context *context)
{
	const struct lws_protocols *protocol = NULL;
	struct lws_context_per_thread *pt;
	struct lws_vhost *vh = NULL, *vh1;
	struct lws wsi;
	int n, m;

	lwsl_notice("%s\n", __func__);

	if (!context)
		return;

	m = context->count_threads;
	context->being_destroyed = 1;

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

#ifdef LWS_LATENCY
	if (context->worst_latency_info[0])
		lwsl_notice("Worst latency: %s\n", context->worst_latency_info);
#endif

	while (m--) {
		pt = &context->pt[m];

		for (n = 0; (unsigned int)n < context->pt[m].fds_count; n++) {
			struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;

			lws_close_free_wsi(wsi,
				LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY
				/* no protocol close */);
			n--;
		}
		lws_pt_mutex_destroy(pt);
	}
	/*
	 * give all extensions a chance to clean up any per-context
	 * allocations they might have made
	 */

	n = lws_ext_cb_all_exts(context, NULL,
				LWS_EXT_CB_SERVER_CONTEXT_DESTRUCT, NULL, 0);

	n = lws_ext_cb_all_exts(context, NULL,
				LWS_EXT_CB_CLIENT_CONTEXT_DESTRUCT, NULL, 0);

	/*
	 * inform all the protocols that they are done and will have no more
	 * callbacks.
	 *
	 * We can't free things until after the event loop shuts down.
	 */
	if (context->protocol_init_done)
		vh = context->vhost_list;
	while (vh) {
		wsi.vhost = vh;
		protocol = vh->protocols;
		if (protocol) {
			n = 0;
			while (n < vh->count_protocols) {
				wsi.protocol = protocol;
				protocol->callback(&wsi, LWS_CALLBACK_PROTOCOL_DESTROY,
						   NULL, NULL, 0);
				protocol++;
				n++;
			}
		}

		vh = vh->vhost_next;
	}

	for (n = 0; n < context->count_threads; n++) {
		pt = &context->pt[n];

		lws_libev_destroyloop(context, n);
		lws_libuv_destroyloop(context, n);

		lws_free_set_NULL(context->pt[n].serv_buf);
		if (pt->ah_pool)
			lws_free(pt->ah_pool);
		if (pt->http_header_data)
			lws_free(pt->http_header_data);
	}
	lws_plat_context_early_destroy(context);
	lws_ssl_context_destroy(context);

	if (context->pt[0].fds)
		lws_free_set_NULL(context->pt[0].fds);

	/* free all the vhost allocations */

	vh = context->vhost_list;
	while (vh) {
		protocol = vh->protocols;
		if (protocol) {
			n = 0;
			while (n < vh->count_protocols) {
				if (vh->protocol_vh_privs &&
				    vh->protocol_vh_privs[n]) {
					lws_free(vh->protocol_vh_privs[n]);
					vh->protocol_vh_privs[n] = NULL;
				}
				protocol++;
				n++;
			}
		}
		if (vh->protocol_vh_privs)
			lws_free(vh->protocol_vh_privs);
		lws_ssl_SSL_CTX_destroy(vh);
		lws_free(vh->same_vh_protocol_list);
#ifdef LWS_WITH_PLUGINS
		if (context->plugin_list)
			lws_free((void *)vh->protocols);
#ifndef LWS_NO_EXTENSIONS
		if (context->plugin_extension_count)
			lws_free((void *)vh->extensions);
#endif
#endif
#ifdef LWS_WITH_ACCESS_LOG
		if (vh->log_fd != LWS_INVALID_FILE)
			close(vh->log_fd);
#endif

		vh1 = vh->vhost_next;
		lws_free(vh);
		vh = vh1;
	}

	lws_plat_context_late_destroy(context);

	lws_free(context);
}
