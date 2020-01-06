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

const struct lws_role_ops *available_roles[] = {
#if defined(LWS_ROLE_H2)
	&role_ops_h2,
#endif
#if defined(LWS_ROLE_H1)
	&role_ops_h1,
#endif
#if defined(LWS_ROLE_WS)
	&role_ops_ws,
#endif
#if defined(LWS_ROLE_DBUS)
	&role_ops_dbus,
#endif
#if defined(LWS_ROLE_RAW_PROXY)
	&role_ops_raw_proxy,
#endif
	NULL
};

const struct lws_event_loop_ops *available_event_libs[] = {
#if defined(LWS_WITH_POLL)
	&event_loop_ops_poll,
#endif
#if defined(LWS_WITH_LIBUV)
	&event_loop_ops_uv,
#endif
#if defined(LWS_WITH_LIBEVENT)
	&event_loop_ops_event,
#endif
#if defined(LWS_WITH_LIBEV)
	&event_loop_ops_ev,
#endif
	NULL
};

#if defined(LWS_WITH_ABSTRACT)
const struct lws_protocols *available_abstract_protocols[] = {
#if defined(LWS_ROLE_RAW)
	&protocol_abs_client_raw_skt,
#endif
	NULL
};
#endif

static const char * const mount_protocols[] = {
	"http://",
	"https://",
	"file://",
	"cgi://",
	">http://",
	">https://",
	"callback://"
};

const struct lws_role_ops *
lws_role_by_name(const char *name)
{
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (!strcmp(ar->name, name))
			return ar;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	if (!strcmp(name, role_ops_raw_skt.name))
		return &role_ops_raw_skt;

	if (!strcmp(name, role_ops_raw_file.name))
		return &role_ops_raw_file;

	return NULL;
}

int
lws_role_call_alpn_negotiated(struct lws *wsi, const char *alpn)
{
#if defined(LWS_WITH_TLS)
	if (!alpn)
		return 0;

	lwsl_info("%s: '%s'\n", __func__, alpn);

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->alpn && !strcmp(ar->alpn, alpn) && ar->alpn_negotiated)
			return ar->alpn_negotiated(wsi, alpn);
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;
#endif
	return 0;
}

//#if !defined(LWS_WITHOUT_SERVER)
int
lws_role_call_adoption_bind(struct lws *wsi, int type, const char *prot)
{
	int n;

	/*
	 * if the vhost is told to bind accepted sockets to a given role,
	 * then look it up by name and try to bind to the specific role.
	 */
	if (lws_check_opt(wsi->vhost->options,
			  LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG) &&
	    wsi->vhost->listen_accept_role) {
		const struct lws_role_ops *role =
			lws_role_by_name(wsi->vhost->listen_accept_role);

		if (!prot)
			prot = wsi->vhost->listen_accept_protocol;

		if (!role)
			lwsl_err("%s: can't find role '%s'\n", __func__,
				  wsi->vhost->listen_accept_role);

		if (role && role->adoption_bind) {
			n = role->adoption_bind(wsi, type, prot);
			if (n < 0)
				return -1;
			if (n) /* did the bind */
				return 0;
		}

		if (type & _LWS_ADOPT_FINISH) {
			lwsl_debug("%s: leaving bound to role %s\n", __func__,
				   wsi->role_ops->name);
			return 0;
		}


		lwsl_warn("%s: adoption bind to role '%s', "
			  "protocol '%s', type 0x%x, failed\n", __func__,
			  wsi->vhost->listen_accept_role, prot, type);
	}

	/*
	 * Otherwise ask each of the roles in order of preference if they
	 * want to bind to this accepted socket
	 */

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->adoption_bind && ar->adoption_bind(wsi, type, prot))
			return 0;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	/* fall back to raw socket role if, eg, h1 not configured */

	if (role_ops_raw_skt.adoption_bind &&
	    role_ops_raw_skt.adoption_bind(wsi, type, prot))
		return 0;

	/* fall back to raw file role if, eg, h1 not configured */

	if (role_ops_raw_file.adoption_bind &&
	    role_ops_raw_file.adoption_bind(wsi, type, prot))
		return 0;

	return 1;
}
//#endif

#if !defined(LWS_WITHOUT_CLIENT)
int
lws_role_call_client_bind(struct lws *wsi,
			  const struct lws_client_connect_info *i)
{
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->client_bind) {
			int m = ar->client_bind(wsi, i);
			if (m < 0)
				return m;
			if (m)
				return 0;
		}
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	/* fall back to raw socket role if, eg, h1 not configured */

	if (role_ops_raw_skt.client_bind &&
	    role_ops_raw_skt.client_bind(wsi, i))
		return 0;

	return 1;
}
#endif

LWS_VISIBLE void *
lws_protocol_vh_priv_zalloc(struct lws_vhost *vhost,
			    const struct lws_protocols *prot, int size)
{
	int n = 0;

	/* allocate the vh priv array only on demand */
	if (!vhost->protocol_vh_privs) {
		vhost->protocol_vh_privs = (void **)lws_zalloc(
				vhost->count_protocols * sizeof(void *),
				"protocol_vh_privs");
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

	vhost->protocol_vh_privs[n] = lws_zalloc(size, "vh priv");
	return vhost->protocol_vh_privs[n];
}

LWS_VISIBLE void *
lws_protocol_vh_priv_get(struct lws_vhost *vhost,
			 const struct lws_protocols *prot)
{
	int n = 0;

	if (!vhost || !vhost->protocol_vh_privs || !prot)
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

const struct lws_protocol_vhost_options *
lws_vhost_protocol_options(struct lws_vhost *vh, const char *name)
{
	const struct lws_protocol_vhost_options *pvo = vh->pvo;

	if (!name)
		return NULL;

	while (pvo) {
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
	int n, any = 0;

	if (context->doing_protocol_init)
		return 0;

	context->doing_protocol_init = 1;

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = context;

	lwsl_info("%s\n", __func__);

	while (vh) {
		wsi.vhost = vh;

		/* only do the protocol init once for a given vhost */
		if (vh->created_vhost_protocols ||
		    (vh->options & LWS_SERVER_OPTION_SKIP_PROTOCOL_INIT))
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
					lwsl_debug(
						"    vhost \"%s\", "
						"protocol \"%s\", "
						"option \"%s\"\n",
							vh->name,
							vh->protocols[n].name,
							pvo->name);

					if (!strcmp(pvo->name, "default")) {
						lwsl_info("Setting default "
						   "protocol for vh %s to %s\n",
						   vh->name,
						   vh->protocols[n].name);
						vh->default_protocol_index = n;
					}
					if (!strcmp(pvo->name, "raw")) {
						lwsl_info("Setting raw "
						   "protocol for vh %s to %s\n",
						   vh->name,
						   vh->protocols[n].name);
						vh->raw_protocol_index = n;
					}
					pvo = pvo->next;
				}

				pvo = pvo1->options;
			}

#if defined(LWS_WITH_TLS)
			any |= !!vh->tls.ssl_ctx;
#endif

			/*
			 * inform all the protocols that they are doing their
			 * one-time initialization if they want to.
			 *
			 * NOTE the wsi is all zeros except for the context, vh
			 * + protocol ptrs so lws_get_context(wsi) etc can work
			 */
			if (vh->protocols[n].callback(&wsi,
					LWS_CALLBACK_PROTOCOL_INIT, NULL,
					(void *)pvo, 0)) {
				if (vh->protocol_vh_privs[n]) {
					lws_free(vh->protocol_vh_privs[n]);
					vh->protocol_vh_privs[n] = NULL;
				}
				lwsl_err("%s: protocol %s failed init\n",
					 __func__, vh->protocols[n].name);

				return 1;
			}
		}

		vh->created_vhost_protocols = 1;
next:
		vh = vh->vhost_next;
	}

	context->doing_protocol_init = 0;

	if (!context->protocol_init_done && lws_finalize_startup(context))
		return 1;

	context->protocol_init_done = 1;

	if (any)
		lws_tls_check_all_cert_lifetimes(context);

	return 0;
}


/* list of supported protocols and callbacks */

static const struct lws_protocols protocols_dummy[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",			/* name */
		lws_callback_http_dummy,	/* callback */
		0,				/* per_session_data_size */
		0,				/* rx_buffer_size */
		0,				/* id */
		NULL,				/* user */
		0				/* tx_packet_size */
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
		 const struct lws_context_creation_info *info)
{
	struct lws_vhost *vh = lws_zalloc(sizeof(*vh), "create vhost"),
			 **vh1 = &context->vhost_list;
	const struct lws_http_mount *mounts;
	const struct lws_protocols *pcols = info->protocols;
#ifdef LWS_WITH_PLUGINS
	struct lws_plugin *plugin = context->plugin_list;
#endif
	struct lws_protocols *lwsp;
	int m, f = !info->pvo, fx = 0, abs_pcol_count = 0;
	char buf[96];
#if (!defined(LWS_WITHOUT_CLIENT) || defined(LWS_WITH_SOCKS5)) && defined(LWS_HAVE_GETENV)
	char *p;
#endif
	int n;

	if (!vh)
		return NULL;

#if LWS_MAX_SMP > 1
	pthread_mutex_init(&vh->lock, NULL);
#endif

	if (!pcols && !info->pprotocols)
		pcols = &protocols_dummy[0];

	vh->context = context;
	if (!info->vhost_name)
		vh->name = "default";
	else
		vh->name = info->vhost_name;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.error_document_404 = info->error_document_404;
#endif

	if (info->options & LWS_SERVER_OPTION_ONLY_RAW)
		lwsl_info("%s set to only support RAW\n", vh->name);

	vh->iface = info->iface;
#if !defined(LWS_WITH_ESP32) && \
    !defined(OPTEE_TA) && !defined(WIN32)
	vh->bind_iface = info->bind_iface;
#endif

	/*
	 * let's figure out how many protocols the user is handing us, using the
	 * old or new way depending on what he gave us
	 */

	if (!pcols)
		for (vh->count_protocols = 0;
			info->pprotocols[vh->count_protocols];
			vh->count_protocols++)
			;
	else
		for (vh->count_protocols = 0;
			pcols[vh->count_protocols].callback;
			vh->count_protocols++)
				;

	vh->options = info->options;
	vh->pvo = info->pvo;
	vh->headers = info->headers;
	vh->user = info->user;
	vh->finalize = info->finalize;
	vh->finalize_arg = info->finalize_arg;
	vh->listen_accept_role = info->listen_accept_role;
	vh->listen_accept_protocol = info->listen_accept_protocol;
	vh->unix_socket_perms = info->unix_socket_perms;

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->init_vhost)
			if (ar->init_vhost(vh, info))
				return NULL;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;


	if (info->keepalive_timeout)
		vh->keepalive_timeout = info->keepalive_timeout;
	else
		vh->keepalive_timeout = 5;

	if (info->timeout_secs_ah_idle)
		vh->timeout_secs_ah_idle = info->timeout_secs_ah_idle;
	else
		vh->timeout_secs_ah_idle = 10;

#if defined(LWS_WITH_TLS)

	vh->tls.alpn = info->alpn;
	vh->tls.ssl_info_event_mask = info->ssl_info_event_mask;

	if (info->ecdh_curve)
		lws_strncpy(vh->tls.ecdh_curve, info->ecdh_curve,
			    sizeof(vh->tls.ecdh_curve));

	/* carefully allocate and take a copy of cert + key paths if present */
	n = 0;
	if (info->ssl_cert_filepath)
		n += (int)strlen(info->ssl_cert_filepath) + 1;
	if (info->ssl_private_key_filepath)
		n += (int)strlen(info->ssl_private_key_filepath) + 1;

	if (n) {
		vh->tls.key_path = vh->tls.alloc_cert_path =
					lws_malloc(n, "vh paths");
		if (info->ssl_cert_filepath) {
			n = (int)strlen(info->ssl_cert_filepath) + 1;
			memcpy(vh->tls.alloc_cert_path,
			       info->ssl_cert_filepath, n);
			vh->tls.key_path += n;
		}
		if (info->ssl_private_key_filepath)
			memcpy(vh->tls.key_path, info->ssl_private_key_filepath,
			       strlen(info->ssl_private_key_filepath) + 1);
	}
#endif

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_ROLE_WS)
	fx = 1;
#endif
#if defined(LWS_WITH_ABSTRACT)
	abs_pcol_count = (int)LWS_ARRAY_SIZE(available_abstract_protocols) - 1;
#endif

	/*
	 * give the vhost a unified list of protocols including:
	 *
	 * - internal, abstracted ones
	 * - the ones that came from plugins
	 * - his user protocols
	 */
	lwsp = lws_zalloc(sizeof(struct lws_protocols) *
				(vh->count_protocols +
				   abs_pcol_count +
				   context->plugin_protocol_count +
				   fx + 1),
			  "vhost-specific plugin table");
	if (!lwsp) {
		lwsl_err("OOM\n");
		return NULL;
	}

	/*
	 * 1: user protocols (from pprotocols or protocols)
	 */

	m = vh->count_protocols;
	if (!pcols) {
		for (n = 0; n < m; n++)
			memcpy(&lwsp[n], info->pprotocols[n], sizeof(lwsp[0]));
	} else
		memcpy(lwsp, pcols, sizeof(struct lws_protocols) * m);

	/*
	 * 2: abstract protocols
	 */
#if defined(LWS_WITH_ABSTRACT)
	for (n = 0; n < abs_pcol_count; n++) {
		memcpy(&lwsp[m++], available_abstract_protocols[n],
		       sizeof(*lwsp));
		vh->count_protocols++;
	}
#endif

	/*
	 * 3: For compatibility, all protocols enabled on vhost if only
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

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_ROLE_WS)
	memcpy(&lwsp[m++], &lws_ws_proxy, sizeof(*lwsp));
	vh->count_protocols++;
#endif

	vh->protocols = lwsp;
	vh->allocated_vhost_protocols = 1;

	vh->same_vh_protocol_owner = (struct lws_dll2_owner *)
			lws_zalloc(sizeof(struct lws_dll2_owner) *
				   vh->count_protocols, "same vh list");
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.mount_list = info->mounts;
#endif

#ifdef LWS_WITH_UNIX_SOCK
	if (LWS_UNIX_SOCK_ENABLED(vh)) {
		lwsl_info("Creating Vhost '%s' path \"%s\", %d protocols\n",
				vh->name, vh->iface, vh->count_protocols);
	} else
#endif
	{
		switch(info->port) {
		case CONTEXT_PORT_NO_LISTEN:
			strcpy(buf, "(serving disabled)");
			break;
		case CONTEXT_PORT_NO_LISTEN_SERVER:
			strcpy(buf, "(no listener)");
			break;
		default:
			lws_snprintf(buf, sizeof(buf), "port %u", info->port);
			break;
		}
		lwsl_info("Creating Vhost '%s' %s, %d protocols, IPv6 %s\n",
			    vh->name, buf, vh->count_protocols,
			    LWS_IPV6_ENABLED(vh) ? "on" : "off");
	}
	mounts = info->mounts;
	while (mounts) {
		(void)mount_protocols[0];
		lwsl_info("   mounting %s%s to %s\n",
			  mount_protocols[mounts->origin_protocol],
			  mounts->origin, mounts->mountpoint);

		mounts = mounts->mount_next;
	}

	vh->listen_port = info->port;
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.http_proxy_port = 0;
	vh->http.http_proxy_address[0] = '\0';
#endif
#if defined(LWS_WITH_SOCKS5)
	vh->socks_proxy_port = 0;
	vh->socks_proxy_address[0] = '\0';
#endif

#if !defined(LWS_WITHOUT_CLIENT)
	/* either use proxy from info, or try get it from env var */
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/* http proxy */
	if (info->http_proxy_address) {
		/* override for backwards compatibility */
		if (info->http_proxy_port)
			vh->http.http_proxy_port = info->http_proxy_port;
		lws_set_proxy(vh, info->http_proxy_address);
	} else
#endif
	{
#ifdef LWS_HAVE_GETENV
		p = getenv("http_proxy");
		if (p) {
			lws_strncpy(buf, p, sizeof(buf));

			lws_set_proxy(vh, buf);
		}
#endif
	}
#endif
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
		if (p && strlen(p) > 0 && strlen(p) < 95)
			lws_set_socks(vh, p);
#endif
	}
#endif

	vh->ka_time = info->ka_time;
	vh->ka_interval = info->ka_interval;
	vh->ka_probes = info->ka_probes;

	if (vh->options & LWS_SERVER_OPTION_STS)
		lwsl_notice("   STS enabled\n");

#ifdef LWS_WITH_ACCESS_LOG
	if (info->log_filepath) {
		vh->log_fd = lws_open(info->log_filepath,
				  O_CREAT | O_APPEND | O_RDWR, 0600);
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
	if (lws_context_init_server_ssl(info, vh)) {
		lwsl_err("%s: lws_context_init_server_ssl failed\n", __func__);
		goto bail1;
	}
	if (lws_context_init_client_ssl(info, vh)) {
		lwsl_err("%s: lws_context_init_client_ssl failed\n", __func__);
		goto bail1;
	}
	lws_context_lock(context, "create_vhost");
	n = _lws_vhost_init_server(info, vh);
	lws_context_unlock(context);
	if (n < 0) {
		lwsl_err("init server failed\n");
		goto bail1;
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
		if (lws_protocol_init(context)) {
			lwsl_err("%s: lws_protocol_init failed\n", __func__);
			goto bail1;
		}

	return vh;

bail1:
	lws_vhost_destroy(vh);

	return NULL;

#ifdef LWS_WITH_ACCESS_LOG
bail:
	lws_free(vh);
#endif

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

LWS_VISIBLE void
lws_cancel_service_pt(struct lws *wsi)
{
	lws_plat_pipe_signal(wsi);
}

LWS_VISIBLE void
lws_cancel_service(struct lws_context *context)
{
	struct lws_context_per_thread *pt = &context->pt[0];
	short m = context->count_threads;

	if (context->being_destroyed1)
		return;

	lwsl_info("%s\n", __func__);

	while (m--) {
		if (pt->pipe_wsi)
			lws_plat_pipe_signal(pt->pipe_wsi);
		pt++;
	}
}

int
lws_create_event_pipes(struct lws_context *context)
{
	struct lws *wsi;
	int n;

	/*
	 * Create the pt event pipes... these are unique in that they are
	 * not bound to a vhost or protocol (both are NULL)
	 */

	for (n = 0; n < context->count_threads; n++) {
		if (context->pt[n].pipe_wsi)
			continue;

		wsi = lws_zalloc(sizeof(*wsi), "event pipe wsi");
		if (!wsi) {
			lwsl_err("%s: Out of mem\n", __func__);
			return 1;
		}
		wsi->context = context;
		lws_role_transition(wsi, 0, LRS_UNCONNECTED, &role_ops_pipe);
		wsi->protocol = NULL;
		wsi->tsi = n;
		wsi->vhost = NULL;
		wsi->event_pipe = 1;
		wsi->desc.sockfd = LWS_SOCK_INVALID;
		context->pt[n].pipe_wsi = wsi;
		context->count_wsi_allocated++;

		if (lws_plat_pipe_create(wsi))
			/*
			 * platform code returns 0 if it actually created pipes
			 * and initialized pt->dummy_pipe_fds[].  If it used
			 * some other mechanism outside of signaling in the
			 * normal event loop, we skip treating the pipe as
			 * related to dummy_pipe_fds[], adding it to the fds,
			 * etc.
			 */
			continue;

		wsi->desc.sockfd = context->pt[n].dummy_pipe_fds[0];
		lwsl_debug("event pipe fd %d\n", wsi->desc.sockfd);

#if !defined(LWS_AMAZON_RTOS)
		if (context->event_loop_ops->accept)
			if (context->event_loop_ops->accept(wsi))
				return 1;
#endif

		if (__insert_wsi_socket_into_fds(context, wsi))
			return 1;
	}

	return 0;
}

void
lws_destroy_event_pipe(struct lws *wsi)
{
	lwsl_info("%s\n", __func__);
	__remove_wsi_socket_from_fds(wsi);

	if (wsi->context->event_loop_ops->wsi_logical_close) {
		wsi->context->event_loop_ops->wsi_logical_close(wsi);
		lws_plat_pipe_close(wsi);
		return;
	}

	if (wsi->context->event_loop_ops->destroy_wsi)
		wsi->context->event_loop_ops->destroy_wsi(wsi);
	lws_plat_pipe_close(wsi);
	wsi->context->count_wsi_allocated--;
	lws_free(wsi);
}


void
lws_vhost_destroy1(struct lws_vhost *vh)
{
	struct lws_context *context = vh->context;

	lwsl_info("%s\n", __func__);

	lws_context_lock(context, "vhost destroy 1"); /* ---------- context { */

	if (vh->being_destroyed)
		goto out;

	lws_vhost_lock(vh); /* -------------- vh { */

	vh->being_destroyed = 1;
#if defined(LWS_WITH_NETWORK)
	/*
	 * PHASE 1: take down or reassign any listen wsi
	 *
	 * Are there other vhosts that are piggybacking on our listen socket?
	 * If so we need to hand the listen socket off to one of the others
	 * so it will remain open.
	 *
	 * If not, leave it attached to the closing vhost, the vh being marked
	 * being_destroyed will defeat any service and it will get closed in
	 * later phases.
	 */

	if (vh->lserv_wsi)
		lws_start_foreach_ll(struct lws_vhost *, v,
				     context->vhost_list) {
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

				lwsl_notice("%s: listen skt from %s to %s\n",
					    __func__, vh->name, v->name);

				if (v->lserv_wsi) {
					lws_vhost_unbind_wsi(vh->lserv_wsi);
					lws_vhost_bind_wsi(v, v->lserv_wsi);
				}

				break;
			}
		} lws_end_foreach_ll(v, vhost_next);

#endif

	lws_vhost_unlock(vh); /* } vh -------------- */

	/*
	 * lws_check_deferred_free() will notice there is a vhost that is
	 * marked for destruction during the next 1s, for all tsi.
	 *
	 * It will start closing all wsi on this vhost.  When the last wsi
	 * is closed, it will trigger lws_vhost_destroy2()
	 */

out:
	lws_context_unlock(context); /* --------------------------- context { */
}

#if defined(LWS_WITH_ABSTRACT)
static int
destroy_ais(struct lws_dll2 *d, void *user)
{
	lws_abs_t *ai = lws_container_of(d, lws_abs_t, abstract_instances);

	lws_abs_destroy_instance(&ai);

	return 0;
}
#endif

void
__lws_vhost_destroy2(struct lws_vhost *vh)
{
	const struct lws_protocols *protocol = NULL;
	struct lws_context *context = vh->context;
	struct lws_deferred_free *df;
	struct lws wsi;
	int n;

	/*
	 * destroy any pending timed events
	 */

	while (vh->timed_vh_protocol_list)
		__lws_timed_callback_remove(vh, vh->timed_vh_protocol_list);

	/*
	 * let the protocols destroy the per-vhost protocol objects
	 */

	memset(&wsi, 0, sizeof(wsi));
	wsi.context = vh->context;
	wsi.vhost = vh; /* not a real bound wsi */
	protocol = vh->protocols;
	if (protocol && vh->created_vhost_protocols) {
		n = 0;
		while (n < vh->count_protocols) {
			wsi.protocol = protocol;

			if (protocol->callback)
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

	lwsl_info("%s: %p\n", __func__, vh);

	/* if we are still on deferred free list, remove ourselves */

	lws_start_foreach_llp(struct lws_deferred_free **, pdf,
			      context->deferred_free_list) {
		if ((*pdf)->payload == vh) {
			df = *pdf;
			*pdf = df->next;
			lws_free(df);
			break;
		}
	} lws_end_foreach_llp(pdf, next);

	/* remove ourselves from the pending destruction list */

	lws_start_foreach_llp(struct lws_vhost **, pv,
			      context->vhost_pending_destruction_list) {
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
	lws_free(vh->same_vh_protocol_owner);

	if (context->plugin_list ||
	    (context->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS) ||
	    vh->allocated_vhost_protocols)
		lws_free((void *)vh->protocols);
#if defined(LWS_WITH_NETWORK)
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (ar->destroy_vhost)
			ar->destroy_vhost(vh);
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;
#endif

#ifdef LWS_WITH_ACCESS_LOG
	if (vh->log_fd != (int)LWS_INVALID_FILE)
		close(vh->log_fd);
#endif

#if defined (LWS_WITH_TLS)
	lws_free_set_NULL(vh->tls.alloc_cert_path);
#endif

#if LWS_MAX_SMP > 1
       pthread_mutex_destroy(&vh->lock);
#endif

#if defined(LWS_WITH_UNIX_SOCK)
	if (LWS_UNIX_SOCK_ENABLED(vh)) {
		n = unlink(vh->iface);
		if (n)
			lwsl_info("Closing unix socket %s: errno %d\n",
				  vh->iface, errno);
	}
#endif
	/*
	 * although async event callbacks may still come for wsi handles with
	 * pending close in the case of asycn event library like libuv,
	 * they do not refer to the vhost.  So it's safe to free.
	 */

	if (vh->finalize)
		vh->finalize(vh, vh->finalize_arg);

#if defined(LWS_WITH_ABSTRACT)
	/*
	 * abstract instances
	 */

	lws_dll2_foreach_safe(&vh->abstract_instances_owner, NULL, destroy_ais);
#endif

	lwsl_info("  %s: Freeing vhost %p\n", __func__, vh);

	memset(vh, 0, sizeof(*vh));
	lws_free(vh);
}

/*
 * each service thread calls this once a second or so
 */

int
lws_check_deferred_free(struct lws_context *context, int tsi, int force)
{
	struct lws_context_per_thread *pt;
	int n;

	/*
	 * If we see a vhost is being destroyed, forcibly close every wsi on
	 * this tsi associated with this vhost.  That will include the listen
	 * socket if it is still associated with the closing vhost.
	 *
	 * For SMP, we do this once per tsi per destroyed vhost.  The reference
	 * counting on the vhost as the bound wsi close will notice that there
	 * are no bound wsi left, that vhost destruction can complete,
	 * and perform it.  It doesn't matter which service thread does that
	 * because there is nothing left using the vhost to conflict.
	 */

	lws_context_lock(context, "check deferred free"); /* ------ context { */

	lws_start_foreach_ll_safe(struct lws_vhost *, v, context->vhost_list, vhost_next) {
		if (v->being_destroyed
#if LWS_MAX_SMP > 1
			&& !v->close_flow_vs_tsi[tsi]
#endif
		) {

			pt = &context->pt[tsi];

			lws_pt_lock(pt, "vhost removal"); /* -------------- pt { */

#if LWS_MAX_SMP > 1
			v->close_flow_vs_tsi[tsi] = 1;
#endif

			for (n = 0; (unsigned int)n < pt->fds_count; n++) {
				struct lws *wsi = wsi_from_fd(context, pt->fds[n].fd);
				if (!wsi)
					continue;
				if (wsi->vhost != v)
					continue;

				__lws_close_free_wsi(wsi,
					LWS_CLOSE_STATUS_NOSTATUS_CONTEXT_DESTROY,
					"vh destroy"
					/* no protocol close */);
				n--;
			}

			lws_pt_unlock(pt); /* } pt -------------- */
		}
	} lws_end_foreach_ll_safe(v);


	lws_context_unlock(context); /* } context ------------------- */

	return 0;
}


LWS_VISIBLE void
lws_vhost_destroy(struct lws_vhost *vh)
{
	struct lws_deferred_free *df = lws_malloc(sizeof(*df), "deferred free");
	struct lws_context *context = vh->context;

	if (!df)
		return;

	lws_context_lock(context, __func__); /* ------ context { */

	lws_vhost_destroy1(vh);

	if (!vh->count_bound_wsi) {
		/*
		 * After listen handoff, there are already no wsi bound to this
		 * vhost by any pt: nothing can be servicing any wsi belonging
		 * to it any more.
		 *
		 * Finalize the vh destruction immediately
		 */
		__lws_vhost_destroy2(vh);
		lws_free(df);

		goto out;
	}

	/* part 2 is deferred to allow all the handle closes to complete */

	df->next = vh->context->deferred_free_list;
	df->deadline = lws_now_secs();
	df->payload = vh;
	vh->context->deferred_free_list = df;

out:
	lws_context_unlock(context); /* } context ------------------- */
}


LWS_EXTERN void *
lws_vhost_user(struct lws_vhost *vhost)
{
	return vhost->user;
}

LWS_VISIBLE LWS_EXTERN int
lws_get_vhost_listen_port(struct lws_vhost *vhost)
{
	return vhost->listen_port;
}


LWS_VISIBLE LWS_EXTERN void
lws_context_deprecate(struct lws_context *context, lws_reload_func cb)
{
	struct lws_vhost *vh = context->vhost_list, *vh1;

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
		struct lws *wsi = vh->lserv_wsi;

		if (wsi) {
			wsi->socket_is_permanently_unusable = 1;
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "ctx deprecate");
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

#if defined(LWS_WITH_NETWORK)
struct lws_vhost *
lws_get_vhost_by_name(struct lws_context *context, const char *name)
{
	lws_start_foreach_ll(struct lws_vhost *, v,
			     context->vhost_list) {
		if (!strcmp(v->name, name))
			return v;

	} lws_end_foreach_ll(v, vhost_next);

	return NULL;
}
#endif
