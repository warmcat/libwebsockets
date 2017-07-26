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
	"callback://"
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

	if (n == vhost->count_protocols) {
		n = 0;
		while (n < vhost->count_protocols &&
		       strcmp(vhost->protocols[n].name, prot->name))
			n++;

		if (n == vhost->count_protocols)
			return NULL;
	}

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
		n = 0;
		while (n < vhost->count_protocols &&
		       strcmp(vhost->protocols[n].name, prot->name))
			n++;

		if (n == vhost->count_protocols) {
			lwsl_err("%s: unknown protocol %p\n", __func__, prot);
			return NULL;
		}
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

/*
 * inform every vhost that hasn't already done it, that
 * his protocols are initializing
 */
LWS_VISIBLE int
lws_protocol_init(struct lws_context *context)
{
	struct lws_vhost *vh = context->vhost_list;
	const struct lws_protocol_vhost_options *pvo, *pvo1;
	struct lws wsi;
	int n;

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

	lwsl_info("%s\n", __func__);

	while (vh) {
		wsi.vhost = vh;

		/* only do the protocol init once for a given vhost */
		if (vh->created_vhost_protocols)
			goto next;

		/* initialize supported protocols on this vhost */

		for (n = 0; n < vh->count_protocols; n++) {
			wsi.protocol = &vh->protocols[n];
			if (!vh->protocols[n].name)
				continue;
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
					if (!strcmp(pvo->name, "raw")) {
						lwsl_notice("Setting raw "
						   "protocol for vh %s to %s\n",
						   vh->name,
						   vh->protocols[n].name);
						vh->raw_protocol_index = n;
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
			if (vh->protocols[n].callback(&wsi,
				LWS_CALLBACK_PROTOCOL_INIT, NULL,
				(void *)pvo, 0))
				return 1;
		}

		vh->created_vhost_protocols = 1;
next:
		vh = vh->vhost_next;
	}

	if (!context->protocol_init_done)
		lws_finalize_startup(context);

	context->protocol_init_done = 1;

	return 0;
}

LWS_VISIBLE int
lws_callback_http_dummy(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
#ifdef LWS_WITH_CGI
	struct lws_cgi_args *args;
#endif
#if defined(LWS_WITH_CGI) || defined(LWS_WITH_HTTP_PROXY)
	char buf[512];
	int n;
#endif


	switch (reason) {
	case LWS_CALLBACK_HTTP:
#ifndef LWS_NO_SERVER
		if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL))
			return -1;

		if (lws_http_transaction_completed(wsi))
#endif
			return -1;
		break;
#if !defined(LWS_NO_SERVER)
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		if (lws_http_transaction_completed(wsi))
			return -1;
		break;
#endif

	case LWS_CALLBACK_HTTP_WRITEABLE:
#ifdef LWS_WITH_CGI
		if (wsi->reason_bf & 1) {
			if (lws_cgi_write_split_stdout_headers(wsi) < 0)
				return -1;

			if (wsi->reason_bf & 8)
				wsi->reason_bf &= ~8;
			else
				wsi->reason_bf &= ~1;
			break;
		}
#endif
#if defined(LWS_WITH_HTTP_PROXY)
		if (wsi->reason_bf & 2) {
			char *px = buf + LWS_PRE;
			int lenx = sizeof(buf) - LWS_PRE;
			/*
			 * our sink is writeable and our source has something
			 * to read.  So read a lump of source material of
			 * suitable size to send or what's available, whichever
			 * is the smaller.
			 */


			wsi->reason_bf &= ~2;
			if (!lws_get_child(wsi))
				break;
			if (lws_http_client_read(lws_get_child(wsi), &px, &lenx) < 0)
				return -1;
			break;
		}
#endif
		break;

#if defined(LWS_WITH_HTTP_PROXY)
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		//lwsl_err("LWS_CALLBACK_RECEIVE_CLIENT_HTTP: wsi %p\n", wsi);
		assert(lws_get_parent(wsi));
		if (!lws_get_parent(wsi))
			break;
		lws_get_parent(wsi)->reason_bf |= 2;
		lws_callback_on_writable(lws_get_parent(wsi));
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		//lwsl_err("LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ len %d\n", (int)len);
		assert(lws_get_parent(wsi));
		n = lws_write(lws_get_parent(wsi), (unsigned char *)in,
				len, LWS_WRITE_HTTP);
		if (n < 0)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: {
		unsigned char *p, *end;
		char ctype[64], ctlen = 0;

		//lwsl_err("LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP\n");
	
		p = (unsigned char *)buf + LWS_PRE;
		end = p + sizeof(buf) - LWS_PRE;

		if (lws_add_http_header_status(lws_get_parent(wsi), HTTP_STATUS_OK, &p, end))
			return 1;
		if (lws_add_http_header_by_token(lws_get_parent(wsi),
				WSI_TOKEN_HTTP_SERVER,
			    	(unsigned char *)"libwebsockets",
				13, &p, end))
			return 1;

		ctlen = lws_hdr_copy(wsi, ctype, sizeof(ctype), WSI_TOKEN_HTTP_CONTENT_TYPE);
		if (ctlen > 0) {
			if (lws_add_http_header_by_token(lws_get_parent(wsi),
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)ctype, ctlen, &p, end))
				return 1;
		}
#if 0
		if (lws_add_http_header_content_length(lws_get_parent(wsi),
						       file_len, &p, end))
			return 1;
#endif
		if (lws_finalize_http_header(lws_get_parent(wsi), &p, end))
			return 1;

		*p = '\0';
//		lwsl_info("%s\n", buf + LWS_PRE);

		n = lws_write(lws_get_parent(wsi), (unsigned char *)buf + LWS_PRE,
			      p - ((unsigned char *)buf + LWS_PRE),
			      LWS_WRITE_HTTP_HEADERS);
		if (n < 0)
			return -1;

		break; }

#endif

#ifdef LWS_WITH_CGI
	/* CGI IO events (POLLIN/OUT) appear here, our default policy is:
	 *
	 *  - POST data goes on subprocess stdin
	 *  - subprocess stdout goes on http via writeable callback
	 *  - subprocess stderr goes to the logs
	 */
	case LWS_CALLBACK_CGI:
		args = (struct lws_cgi_args *)in;
		switch (args->ch) { /* which of stdin/out/err ? */
		case LWS_STDIN:
			/* TBD stdin rx flow control */
			break;
		case LWS_STDOUT:
			wsi->reason_bf |= 1;
			/* when writing to MASTER would not block */
			lws_callback_on_writable(wsi);
			break;
		case LWS_STDERR:
			n = read(lws_get_socket_fd(args->stdwsi[LWS_STDERR]),
						   buf, sizeof(buf) - 2);
			if (n > 0) {
				if (buf[n - 1] != '\n')
					buf[n++] = '\n';
				buf[n] = '\0';
				lwsl_notice("CGI-stderr: %s\n", buf);
			}
			break;
		}
		break;

	case LWS_CALLBACK_CGI_TERMINATED:
		return -1;

	case LWS_CALLBACK_CGI_STDIN_DATA:  /* POST body for stdin */
		args = (struct lws_cgi_args *)in;
		args->data[args->len] = '\0';
		n = write(lws_get_socket_fd(args->stdwsi[LWS_STDIN]),
			  args->data, args->len);
		if (n < args->len)
			lwsl_notice("LWS_CALLBACK_CGI_STDIN_DATA: "
				    "sent %d only %d went", n, args->len);
		return n;
#endif

	case LWS_CALLBACK_SSL_INFO:
		{
			struct lws_ssl_info *si = in;

			(void)si;
			lwsl_notice("LWS_CALLBACK_SSL_INFO: where: 0x%x, ret: 0x%x\n",
					si->where, si->ret);
		}
		break;

	default:
		break;
	}

	return 0;
}

/* list of supported protocols and callbacks */

static const struct lws_protocols protocols_dummy[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",		/* name */
		lws_callback_http_dummy,		/* callback */
		0,	/* per_session_data_size */
		0,			/* max frame size / rx buffer */
		0, NULL, 0
	},
	/*
	 * the other protocols are provided by lws plugins
	 */
	{ NULL, NULL, 0, 0, 0, NULL, 0} /* terminator */
};

#ifdef LWS_PLAT_OPTEE
#undef LWS_HAVE_GETENV
#endif

LWS_VISIBLE struct lws_vhost *
lws_create_vhost(struct lws_context *context,
		 struct lws_context_creation_info *info)
{
	struct lws_vhost *vh = lws_zalloc(sizeof(*vh)),
			 **vh1 = &context->vhost_list;
	const struct lws_http_mount *mounts;
	const struct lws_protocol_vhost_options *pvo;
#ifdef LWS_WITH_PLUGINS
	struct lws_plugin *plugin = context->plugin_list;
#endif
	struct lws_protocols *lwsp;
	int m, f = !info->pvo;
#ifdef LWS_HAVE_GETENV
	char *p;
#endif
	int n;

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
#if !defined(LWS_WITH_ESP8266) && !defined(LWS_WITH_ESP32) && !defined(OPTEE_TA) && !defined(WIN32)
	vh->bind_iface = info->bind_iface;
#endif

	for (vh->count_protocols = 0;
	     info->protocols[vh->count_protocols].callback;
	     vh->count_protocols++)
		;

	vh->options = info->options;
	vh->pvo = info->pvo;
	vh->headers = info->headers;
	vh->ssl_info_event_mask = info->ssl_info_event_mask;
	if (info->keepalive_timeout)
		vh->keepalive_timeout = info->keepalive_timeout;
	else
		vh->keepalive_timeout = 5;

	if (info->timeout_secs_ah_idle)
		vh->timeout_secs_ah_idle = info->timeout_secs_ah_idle;
	else
		vh->timeout_secs_ah_idle = 10;

	/*
	 * give the vhost a unified list of protocols including the
	 * ones that came from plugins
	 */
	lwsp = lws_zalloc(sizeof(struct lws_protocols) *
				   (vh->count_protocols +
				   context->plugin_protocol_count + 1));
	if (!lwsp) {
		lwsl_err("OOM\n");
		return NULL;
	}

	m = vh->count_protocols;
	memcpy(lwsp, info->protocols, sizeof(struct lws_protocols) * m);

	/* for compatibility, all protocols enabled on vhost if only
	 * the default vhost exists.  Otherwise only vhosts who ask
	 * for a protocol get it enabled.
	 */

	if (context->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS)
		f = 0;
	(void)f;
#ifdef LWS_WITH_PLUGINS
	if (plugin) {

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
	}
#endif

	if (
#ifdef LWS_WITH_PLUGINS
	    (context->plugin_list) ||
#endif
	    context->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS)
		vh->protocols = lwsp;
	else {
		vh->protocols = info->protocols;
		free(lwsp);
	}

	vh->same_vh_protocol_list = (struct lws **)
			lws_zalloc(sizeof(struct lws *) * vh->count_protocols);

	vh->mount_list = info->mounts;

#ifdef LWS_USE_UNIX_SOCK
	if (LWS_UNIX_SOCK_ENABLED(context)) {
		lwsl_notice("Creating Vhost '%s' path \"%s\", %d protocols\n",
				vh->name, info->iface, vh->count_protocols);
	} else
#endif
	lwsl_notice("Creating Vhost '%s' port %d, %d protocols, IPv6 %s\n",
			vh->name, info->port, vh->count_protocols, LWS_IPV6_ENABLED(vh) ? "on" : "off");

	mounts = info->mounts;
	while (mounts) {
		(void)mount_protocols[0];
		lwsl_notice("   mounting %s%s to %s\n",
				mount_protocols[mounts->origin_protocol],
				mounts->origin, mounts->mountpoint);

		/* convert interpreter protocol names to pointers */
		pvo = mounts->interpret;
		while (pvo) {
			for (n = 0; n < vh->count_protocols; n++)
				if (!strcmp(pvo->value, vh->protocols[n].name)) {
					((struct lws_protocol_vhost_options *)pvo)->value =
							(const char *)(lws_intptr_t)n;
					break;
				}
			if (n == vh->count_protocols)
				lwsl_err("ignoring unknown interpret protocol %s\n", pvo->value);
			pvo = pvo->next;
		}

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
#if !defined(LWS_WITH_ESP8266)
	vh->http_proxy_port = 0;
	vh->http_proxy_address[0] = '\0';
#if defined(LWS_WITH_SOCKS5)
	vh->socks_proxy_port = 0;
	vh->socks_proxy_address[0] = '\0';
#endif

	/* either use proxy from info, or try get it from env var */

	/* http proxy */
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
#if defined(LWS_WITH_SOCKS5)
	/* socks proxy */
	if (info->socks_proxy_address) {
		/* override for backwards compatibility */
		if (info->socks_proxy_port)
			vh->socks_proxy_port = info->socks_proxy_port;
		lws_set_socks(vh, info->socks_proxy_address);
	} else {
#ifdef LWS_HAVE_GETENV
		p = getenv("socks_proxy");
		if (p)
			lws_set_socks(vh, p);
#endif
	}
#endif
#endif

	vh->ka_time = info->ka_time;
	vh->ka_interval = info->ka_interval;
	vh->ka_probes = info->ka_probes;

	if (vh->options & LWS_SERVER_OPTION_STS)
		lwsl_notice("   STS enabled\n");

#ifdef LWS_WITH_ACCESS_LOG
	if (info->log_filepath) {
		vh->log_fd = open(info->log_filepath, O_CREAT | O_APPEND | O_RDWR, 0600);
		if (vh->log_fd == (int)LWS_INVALID_FILE) {
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
		vh->log_fd = (int)LWS_INVALID_FILE;
#endif
	if (lws_context_init_server_ssl(info, vh))
		goto bail;
	if (lws_context_init_client_ssl(info, vh))
		goto bail;
	if (lws_context_init_server(info, vh)) {
		lwsl_err("init server failed\n");
		goto bail;
	}

	while (1) {
		if (!(*vh1)) {
			*vh1 = vh;
			break;
		}
		vh1 = &(*vh1)->vhost_next;
	};
	/* for the case we are adding a vhost much later, after server init */

	if (context->protocol_init_done)
		lws_protocol_init(context);

	return vh;

bail:
	lws_free(vh);

	return NULL;
}

LWS_VISIBLE int
lws_init_vhost_client_ssl(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost)
{
	struct lws_context_creation_info i;

	memcpy(&i, info, sizeof(i));
	i.port = CONTEXT_PORT_NO_LISTEN;

	return lws_context_init_client_ssl(&i, vhost);
}

LWS_VISIBLE struct lws_context *
lws_create_context(struct lws_context_creation_info *info)
{
	struct lws_context *context = NULL;
	struct lws_plat_file_ops *prev;
#ifndef LWS_NO_DAEMONIZE
	int pid_daemon = get_daemonize_pid();
#endif
	int n, m;
#if defined(__ANDROID__)
	struct rlimit rt;
#endif

	lwsl_notice("Initial logging level %d\n", log_level);
	lwsl_notice("Libwebsockets version: %s\n", library_version);
#if defined(GCC_VER)
	lwsl_notice("Compiled with  %s\n", GCC_VER);
#endif
#if LWS_POSIX
#ifdef LWS_USE_IPV6
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DISABLE_IPV6))
		lwsl_notice("IPV6 compiled in and enabled\n");
	else
		lwsl_notice("IPV6 compiled in but disabled\n");
#else
	lwsl_notice("IPV6 not compiled in\n");
#endif
#if !defined(LWS_PLAT_OPTEE) && !defined(LWS_PLAT_ESP32)
	lws_feature_status_libev(info);
	lws_feature_status_libuv(info);
#endif
#endif
	lwsl_info(" LWS_DEF_HEADER_LEN    : %u\n", LWS_DEF_HEADER_LEN);
	lwsl_info(" LWS_MAX_PROTOCOLS     : %u\n", LWS_MAX_PROTOCOLS);
	lwsl_info(" LWS_MAX_SMP           : %u\n", LWS_MAX_SMP);
	lwsl_info(" SPEC_LATEST_SUPPORTED : %u\n", SPEC_LATEST_SUPPORTED);
	lwsl_info(" sizeof (*info)        : %ld\n", (long)sizeof(*info));
#if defined(LWS_WITH_STATS)
	lwsl_notice(" LWS_WITH_STATS        : on\n");
#endif
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
	if (info->pt_serv_buf_size)
		context->pt_serv_buf_size = info->pt_serv_buf_size;
	else
		context->pt_serv_buf_size = 4096;

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

	context->time_up = time(NULL);

	context->simultaneous_ssl_restriction = info->simultaneous_ssl_restriction;

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
		context->max_http_header_pool = LWS_DEF_HEADER_POOL;

	/*
	 * Allocate the per-thread storage for scratchpad buffers,
	 * and header data pool
	 */
	for (n = 0; n < context->count_threads; n++) {
		context->pt[n].serv_buf = lws_zalloc(context->pt_serv_buf_size);
		if (!context->pt[n].serv_buf) {
			lwsl_err("OOM\n");
			return NULL;
		}

#ifdef LWS_USE_LIBUV
		context->pt[n].context = context;
#endif
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
#ifdef LWS_USE_LIBEVENT
	/* (Issue #264) In order to *avoid breaking backwards compatibility*, we
	 * enable libev mediated SIGINT handling with a default handler of
	 * lws_sigint_cb. The handler can be overridden or disabled
	 * by invoking lws_sigint_cfg after creating the context, but
	 * before invoking lws_initloop:
	 */
	context->use_ev_sigint = 1;
	context->lws_event_sigint_cb = &lws_event_sigint_cb;
#endif /* LWS_USE_LIBEVENT */

	lwsl_info(" mem: context:         %5lu bytes (%ld ctx + (%ld thr x %d))\n",
		  (long)sizeof(struct lws_context) +
		  (context->count_threads * context->pt_serv_buf_size),
		  (long)sizeof(struct lws_context),
		  (long)context->count_threads,
		  context->pt_serv_buf_size);

	lwsl_info(" mem: http hdr rsvd:   %5lu bytes (%u thr x (%u + %lu) x %u))\n",
		    (long)(context->max_http_header_data +
		     sizeof(struct allocated_headers)) *
		    context->max_http_header_pool * context->count_threads,
		    context->count_threads,
		    context->max_http_header_data,
		    (long)sizeof(struct allocated_headers),
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

	lwsl_notice(" mem: per-conn:        %5lu bytes + protocol rx buf\n",
		    (unsigned long)sizeof(struct lws));

	strcpy(context->canonical_hostname, "unknown");
	lws_server_get_canonical_hostname(context, info);

	context->uid = info->uid;
	context->gid = info->gid;

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

LWS_VISIBLE LWS_EXTERN void
lws_context_deprecate(struct lws_context *context, lws_reload_func cb)
{
	struct lws_vhost *vh = context->vhost_list, *vh1;
	struct lws *wsi;

	/*
	 * "deprecation" means disable the context from accepting any new
	 * connections and free up listen sockets to be used by a replacement
	 * context.
	 *
	 * Otherwise the deprecated context remains operational, until its
	 * number of connected sockets falls to zero, when it is deleted.
	 */

	/* for each vhost, close his listen socket */

	while (vh) {
		wsi = vh->lserv_wsi;
		if (wsi) {
			wsi->socket_is_permanently_unusable = 1;
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);
			wsi->context->deprecation_pending_listen_close_count++;
			/*
			 * other vhosts can share the listen port, they
			 * point to the same wsi.  So zap those too.
			 */
			vh1 = context->vhost_list;
			while (vh1) {
				if (vh1->lserv_wsi == wsi)
					vh1->lserv_wsi = NULL;
				vh1 = vh1->vhost_next;
			}
		}
		vh = vh->vhost_next;
	}

	context->deprecated = 1;
	context->deprecation_cb = cb;
}

LWS_VISIBLE LWS_EXTERN int
lws_context_is_deprecated(struct lws_context *context)
{
	return context->deprecated;
}

LWS_VISIBLE void
lws_context_destroy2(struct lws_context *context);


static void
lws_vhost_destroy1(struct lws_vhost *vh)
{
	const struct lws_protocols *protocol = NULL;
	struct lws_context_per_thread *pt;
	int n, m = vh->context->count_threads;
	struct lws_context *context = vh->context;
	struct lws wsi;

	lwsl_notice("%s\n", __func__);

	if (vh->being_destroyed)
		return;

	vh->being_destroyed = 1;

	/*
	 * Are there other vhosts that are piggybacking on our listen socket?
	 * If so we need to hand the listen socket off to one of the others
	 * so it will remain open.  If not, leave it attached to the closing
	 * vhost and it will get closed.
	 */

	if (vh->lserv_wsi)
		lws_start_foreach_ll(struct lws_vhost *, v, context->vhost_list) {
			if (v != vh &&
			    !v->being_destroyed &&
			    v->listen_port == vh->listen_port &&
			    ((!v->iface && !vh->iface) ||
			    (v->iface && vh->iface &&
			    !strcmp(v->iface, vh->iface)))) {
				/*
				 * this can only be a listen wsi, which is
				 * restricted... it has no protocol or other
				 * bindings or states.  So we can simply
				 * swap it to a vhost that has the same
				 * iface + port, but is not closing.
				 */
				assert(v->lserv_wsi == NULL);
				v->lserv_wsi = vh->lserv_wsi;
				vh->lserv_wsi = NULL;
				v->lserv_wsi->vhost = v;

				lwsl_notice("%s: listen skt from %s to %s\n",
					    __func__, vh->name, v->name);
				break;
			}
		} lws_end_foreach_ll(v, vhost_next);

	/*
	 * Forcibly close every wsi assoicated with this vhost.  That will
	 * include the listen socket if it is still associated with the closing
	 * vhost.
	 */

	while (m--) {
		pt = &context->pt[m];

		for (n = 0; (unsigned int)n < context->pt[m].fds_count; n++) {
			struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->vhost != vh)
				continue;

			lws_close_free_wsi(wsi,
				LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY
				/* no protocol close */);
			n--;
		}
	}

	/*
	 * let the protocols destroy the per-vhost protocol objects
	 */

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = vh->context;
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

	/*
	 * remove vhost from context list of vhosts
	 */

	lws_start_foreach_llp(struct lws_vhost **, pv, context->vhost_list) {
		if (*pv == vh) {
			*pv = vh->vhost_next;
			break;
		}
	} lws_end_foreach_llp(pv, vhost_next);

	/* add ourselves to the pending destruction list */

	vh->vhost_next = vh->context->vhost_pending_destruction_list;
	vh->context->vhost_pending_destruction_list = vh;
}

static void
lws_vhost_destroy2(struct lws_vhost *vh)
{
	const struct lws_protocols *protocol = NULL;
	struct lws_context *context = vh->context;
	struct lws_deferred_free *df;
	int n;

	lwsl_notice("%s: %p\n", __func__, vh);

	/* if we are still on deferred free list, remove ourselves */

	lws_start_foreach_llp(struct lws_deferred_free **, pdf, context->deferred_free_list) {
		if ((*pdf)->payload == vh) {
			df = *pdf;
			*pdf = df->next;
			lws_free(df);
			break;
		}
	} lws_end_foreach_llp(pdf, next);

	/* remove ourselves from the pending destruction list */

	lws_start_foreach_llp(struct lws_vhost **, pv, context->vhost_pending_destruction_list) {
		if ((*pv) == vh) {
			*pv = (*pv)->vhost_next;
			break;
		}
	} lws_end_foreach_llp(pv, vhost_next);

	/*
	 * Free all the allocations associated with the vhost
	 */

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
	if (LWS_LIBUV_ENABLED(context)) {
		if (context->plugin_list)
			lws_free((void *)vh->protocols);
	} else
#endif
	{
		if (context->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS)
			lws_free((void *)vh->protocols);
	}

#ifdef LWS_WITH_PLUGINS
#ifndef LWS_NO_EXTENSIONS
	if (context->plugin_extension_count)
		lws_free((void *)vh->extensions);
#endif
#endif
#ifdef LWS_WITH_ACCESS_LOG
	if (vh->log_fd != (int)LWS_INVALID_FILE)
		close(vh->log_fd);
#endif

	/*
	 * although async event callbacks may still come for wsi handles with
	 * pending close in the case of asycn event library like libuv,
	 * they do not refer to the vhost.  So it's safe to free.
	 */

	lwsl_notice("  %s: Freeing vhost %p\n", __func__, vh);

	memset(vh, 0, sizeof(*vh));
	free(vh);
}

int
lws_check_deferred_free(struct lws_context *context, int force)
{
	struct lws_deferred_free *df;
	time_t now = lws_now_secs();

	lws_start_foreach_llp(struct lws_deferred_free **, pdf, context->deferred_free_list) {
		if (now > (*pdf)->deadline || force) {
			df = *pdf;
			*pdf = df->next;
			/* finalize vh destruction */
			lwsl_notice("doing deferred vh %p destroy\n", df->payload);
			lws_vhost_destroy2(df->payload);
			lws_free(df);
			continue; /* after deletion we already point to next */
		}
	} lws_end_foreach_llp(pdf, next);

	return 0;
}

LWS_VISIBLE void
lws_vhost_destroy(struct lws_vhost *vh)
{
	struct lws_deferred_free *df = malloc(sizeof(*df));

	if (!df)
		return;

	lws_vhost_destroy1(vh);

	/* part 2 is deferred to allow all the handle closes to complete */

	df->next = vh->context->deferred_free_list;
	df->deadline = lws_now_secs() + 5;
	df->payload = vh;
	vh->context->deferred_free_list = df;
}

LWS_VISIBLE void
lws_context_destroy(struct lws_context *context)
{
	struct lws_context_per_thread *pt;
	struct lws_vhost *vh = NULL;
	struct lws wsi;
	int n, m;

	if (!context) {
		lwsl_notice("%s: ctx %p\n", __func__, context);
		return;
	}
	if (context->being_destroyed1) {
		lwsl_notice("%s: ctx %p: already being destroyed\n", __func__, context);
		return;
	}

	lwsl_notice("%s: ctx %p\n", __func__, context);

	m = context->count_threads;
	context->being_destroyed = 1;
	context->being_destroyed1 = 1;

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
		lws_vhost_destroy1(vh);
		vh = vh->vhost_next;
	}

	for (n = 0; n < context->count_threads; n++) {
		pt = &context->pt[n];

		lws_libev_destroyloop(context, n);
		lws_libuv_destroyloop(context, n);
		lws_libevent_destroyloop(context, n);

		lws_free_set_NULL(context->pt[n].serv_buf);
		if (pt->ah_pool)
			lws_free(pt->ah_pool);
		if (pt->http_header_data)
			lws_free(pt->http_header_data);
	}
	lws_plat_context_early_destroy(context);

	if (context->pt[0].fds)
		lws_free_set_NULL(context->pt[0].fds);

	if (!LWS_LIBUV_ENABLED(context))
		lws_context_destroy2(context);
}

/*
 * call the second one after the event loop has been shut down cleanly
 */

LWS_VISIBLE void
lws_context_destroy2(struct lws_context *context)
{
	struct lws_vhost *vh = NULL, *vh1;

	lwsl_notice("%s: ctx %p\n", __func__, context);

	/*
	 * free all the per-vhost allocations
	 */

	vh = context->vhost_list;
	while (vh) {
		vh1 = vh->vhost_next;
		lws_vhost_destroy2(vh);
		vh = vh1;
	}

	/* remove ourselves from the pending destruction list */

	while (context->vhost_pending_destruction_list)
		/* removes itself from list */
		lws_vhost_destroy2(context->vhost_pending_destruction_list);


	lws_stats_log_dump(context);

	lws_ssl_context_destroy(context);
	lws_plat_context_late_destroy(context);

	if (context->external_baggage_free_on_destroy)
		free(context->external_baggage_free_on_destroy);

	lws_check_deferred_free(context, 1);

	lws_free(context);
}
