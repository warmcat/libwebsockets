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
 *
 * A vhost's creation and destruction: the listen sockets, the tls contexts,
 * the async dns, the closing of every connection bound to it.  Context and
 * vhost creation are the transport half's api (README.sans-io-split.md,
 * "The headers"); the vhost's protocols, roles and connection-reuse
 * decisions stay in core-net/vhost.c.
 */

#include "private-lib-core.h"

void
lws_tls_session_vh_destroy(struct lws_vhost *vh);

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
static const char * const mount_protocols[] = {
	"http://",
	"https://",
	"file://",
	"cgi://",
	">http://",
	">https://",
	"callback://"
};
#endif

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

struct lws_vhost *
lws_create_vhost(struct lws_context *context,
		 const struct lws_context_creation_info *info)
{
	struct lws_vhost *vh;
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	const struct lws_http_mount *mounts;
#endif
	const struct lws_protocols *pcols = info->protocols;
#if defined(LWS_WITH_PROTOCOL_PLUGINS)
	struct lws_plugin *plugin = context->plugin_list;
#endif
	struct lws_protocols *lwsp;
	int m, f = !info->pvo, fx = 0, abs_pcol_count = 0, sec_pcol_count = 0, dht_count = 0;
	const char *name = "default";
	char buf[96];
	char *p;
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	extern struct lws_protocols lws_async_dns_protocol;
#endif
#if defined(LWS_WITH_DHT)
	extern const struct lws_protocols lws_dht_protocol;
#endif
#if defined(LWS_WITH_CLIENT)
	extern const struct lws_protocols lws_async_ipc_protocol;
#endif
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	extern const struct lws_protocols lws_sspc_protocols[];
#endif
	int n;


	if (!pcols && context->protocols_copy)
		pcols = context->protocols_copy;

	if (info->vhost_name)
		name = info->vhost_name;

	if (lws_fi(&info->fic, "vh_create_oom"))
		vh = NULL;
	else
		vh = lws_zalloc(sizeof(*vh) + strlen(name) + 1
#if defined(LWS_WITH_EVENT_LIBS)
			+ context->event_loop_ops->evlib_size_vh
#endif
			, __func__);
	if (!vh)
		goto early_bail;

	if (info->log_cx)
		vh->lc.log_cx = info->log_cx;
	else
		vh->lc.log_cx = &log_cx;

#if defined(LWS_WITH_EVENT_LIBS)
	vh->evlib_vh = (void *)&vh[1];
	vh->name = (const char *)vh->evlib_vh +
			context->event_loop_ops->evlib_size_vh;
#else
	vh->name = (const char *)&vh[1];
#endif
	memcpy((char *)vh->name, name, strlen(name) + 1);

#if LWS_MAX_SMP > 1
	lws_mutex_refcount_init(&vh->mr);
#endif

	if (!pcols && !info->pprotocols)
		pcols = &protocols_dummy[0];

	vh->context = context;
	{
		char *end = buf + sizeof(buf) - 1;
		p = buf;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "%s", vh->name);
		if (info->iface)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "|%s", info->iface);
		if (info->port && !(info->port & 0xffff))
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "|%u", info->port);
	}

	__lws_lc_tag(context, &context->lcg[LWSLCG_VHOST], &vh->lc, "%s|%s|%d",
		     buf, info->iface ? info->iface : "", info->port);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	vh->fic.name = "vh";
	if (lws_dll2_count(&info->fic.fi_owner))
		/*
		 * This moves all the lws_fi_t from info->fi to the vhost fi,
		 * leaving it empty
		 */
		lws_fi_import(&vh->fic, &info->fic);

	lws_fi_inherit_copy(&vh->fic, &context->fic, "vh", vh->name);
	if (lws_fi(&vh->fic, "vh_create_oom"))
		goto bail;
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.error_document_404 = info->error_document_404;
#endif

	if (lws_check_opt(info->options, LWS_SERVER_OPTION_ONLY_RAW))
		lwsl_vhost_info(vh, "set to only support RAW");

	vh->iface = info->iface;
#if !defined(LWS_PLAT_FREERTOS) && !defined(OPTEE_TA) && !defined(WIN32)
	vh->bind_iface = info->bind_iface;
#endif
#if defined(LWS_WITH_CLIENT)
	if (info->connect_timeout_secs)
		vh->connect_timeout_secs = (int)info->connect_timeout_secs;
	else
		vh->connect_timeout_secs = 20;
#endif
	/* apply the context default lws_retry */

	if (info->retry_and_idle_policy)
		vh->retry_policy = info->retry_and_idle_policy;
	else
		vh->retry_policy = &context->default_retry;

	/*
	 * let's figure out how many protocols the user is handing us, using the
	 * old or new way depending on what he gave us
	 */

	if (!pcols) {
		for (vh->count_protocols = 0;
			info->pprotocols[vh->count_protocols];
			vh->count_protocols++)
				;

	} else
		for (vh->count_protocols = 0;
			pcols[vh->count_protocols].callback;
			vh->count_protocols++)
				;

	vh->options                     = info->options;
	vh->quic_preferred_addresses    = info->quic_preferred_addresses;
	vh->pvo                         = info->pvo;
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->headers			= info->headers;
#endif
	vh->user			= info->user;
	vh->finalize			= info->finalize;
	vh->finalize_arg		= info->finalize_arg;
	vh->listen_accept_role		= info->listen_accept_role;
	vh->listen_accept_protocol	= info->listen_accept_protocol;
	vh->unix_socket_perms		= info->unix_socket_perms;
	vh->fo_listen_queue		= info->fo_listen_queue;
	vh->max_http_body_size		= info->max_http_body_size;

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
	if (lws_rops_fidx(ar, LWS_ROPS_init_vhost) &&
	    (lws_rops_func_fidx(ar, LWS_ROPS_init_vhost)).init_vhost(vh, info))
		/* not "return NULL"... that leaks the vhost and leaves its
		 * lifecycle group node pointing at it forever */
		goto bail;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;


	if (info->keepalive_timeout)
		vh->keepalive_timeout = info->keepalive_timeout;
	else
		vh->keepalive_timeout = 5;

	if (info->timeout_secs_ah_idle)
		vh->timeout_secs_ah_idle = (int)info->timeout_secs_ah_idle;
	else
		vh->timeout_secs_ah_idle = 10;

#if defined(LWS_WITH_TLS)

	vh->tls.alpn = info->alpn;
	vh->tls.ssl_info_event_mask = info->ssl_info_event_mask;

	if (info->ecdh_curve)
		vh->tls.cfg_ecdh_curve = lws_strdup(info->ecdh_curve);
#if defined(LWS_WITH_CLIENT)
	if (info->client_ecdh_curve)
		vh->tls.cfg_client_ecdh_curve =
					lws_strdup(info->client_ecdh_curve);
#endif

	if (info->ssl_cipher_list)
		vh->tls.cfg_ssl_cipher_list = lws_strdup(info->ssl_cipher_list);
	if (info->tls1_3_plus_cipher_list)
		vh->tls.cfg_tls1_3_plus_cipher_list = lws_strdup(info->tls1_3_plus_cipher_list);
#if defined(LWS_WITH_CLIENT)
        if (info->client_ssl_cipher_list)
                vh->tls.cfg_tls_client_cipher_list = lws_strdup(info->client_ssl_cipher_list);
#endif
	if (info->tls_ciphers_iana)
		vh->tls.cfg_tls_ciphers_iana = lws_strdup(info->tls_ciphers_iana);
	if (info->ssl_ca_filepath)
		vh->tls.cfg_ssl_ca_filepath = lws_strdup(info->ssl_ca_filepath);

	vh->tls.cfg_server_ssl_cert_mem = info->server_ssl_cert_mem;
	vh->tls.cfg_server_ssl_cert_mem_len = info->server_ssl_cert_mem_len;
	vh->tls.cfg_server_ssl_privkey_mem = info->server_ssl_private_key_mem;
	vh->tls.cfg_server_ssl_privkey_mem_len = info->server_ssl_private_key_mem_len;
	vh->tls.cfg_server_ssl_ca_mem = info->server_ssl_ca_mem;
	vh->tls.cfg_server_ssl_ca_mem_len = info->server_ssl_ca_mem_len;

	/*
	 * Both sources of the client-cert CA store are known now: reduce them
	 * to the identity a connection records when its peer cert is verified
	 * against this vhost's store (C-318)
	 */

	lws_tls_vhost_set_client_ca_id(vh);

#if defined(LWS_WITH_CLIENT)
	if (info->client_ssl_ca_filepath)
		vh->tls.cfg_client_ssl_ca_filepath =
				lws_strdup(info->client_ssl_ca_filepath);
	if (info->client_ssl_cert_filepath)
		vh->tls.cfg_client_ssl_cert_filepath =
				lws_strdup(info->client_ssl_cert_filepath);
	if (info->client_ssl_private_key_filepath)
		vh->tls.cfg_client_ssl_private_key_filepath =
				lws_strdup(info->client_ssl_private_key_filepath);

	vh->tls.cfg_client_ssl_ca_mem = info->client_ssl_ca_mem;
	vh->tls.cfg_client_ssl_ca_mem_len = info->client_ssl_ca_mem_len;
	vh->tls.cfg_client_ssl_cert_mem = info->client_ssl_cert_mem;
	vh->tls.cfg_client_ssl_cert_mem_len = info->client_ssl_cert_mem_len;
	vh->tls.cfg_client_ssl_key_mem = info->client_ssl_key_mem;
	vh->tls.cfg_client_ssl_key_mem_len = info->client_ssl_key_mem_len;
#endif

	vh->tls.ssl_options_set = info->ssl_options_set;
	vh->tls.ssl_options_clear = info->ssl_options_clear;

	/* carefully allocate and take a copy of cert + key paths if present */
	n = 0;
	if (info->ssl_cert_filepath)
		n += (int)strlen(info->ssl_cert_filepath) + 1;
	if (info->ssl_private_key_filepath)
		n += (int)strlen(info->ssl_private_key_filepath) + 1;

	if (n) {
		vh->tls.cfg_key_path = vh->tls.cfg_alloc_cert_path =
					lws_malloc((unsigned int)n, "vh paths");
		if (!vh->tls.cfg_alloc_cert_path)
			goto bail;
		if (info->ssl_cert_filepath) {
			n = (int)strlen(info->ssl_cert_filepath) + 1;
			memcpy(vh->tls.cfg_alloc_cert_path,
			       info->ssl_cert_filepath, (unsigned int)n);
			vh->tls.cfg_key_path += n;
		}
		if (info->ssl_private_key_filepath)
			memcpy(vh->tls.cfg_key_path, info->ssl_private_key_filepath,
			       strlen(info->ssl_private_key_filepath) + 1);
	}
#endif

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_ROLE_WS)
	fx = 1;
#endif
	/* the tables are NULL-terminated */
#if defined(LWS_WITH_ABSTRACT)
	while (available_abstract_protocols[abs_pcol_count])
		abs_pcol_count++;
#endif
#if defined(LWS_WITH_SECURE_STREAMS)
	while (available_secstream_protocols[sec_pcol_count])
		sec_pcol_count++;
#endif
#if defined(LWS_WITH_DHT)
	dht_count = 1;
#endif

	/*
	 * give the vhost a unified list of protocols including:
	 *
	 * - internal, async_dns if enabled (first vhost only)
	 * - internal, abstracted ones
	 * - the ones that came from plugins
	 * - his user protocols
	 */

	if (lws_fi(&vh->fic, "vh_create_pcols_oom"))
		lwsp = NULL;
	else
		lwsp = lws_zalloc(sizeof(struct lws_protocols) *
				((unsigned int)vh->count_protocols +
				   (unsigned int)abs_pcol_count +
				   (unsigned int)sec_pcol_count +
				   (unsigned int)dht_count +
#if defined(LWS_WITH_SYS_ASYNC_DNS)
				   /*
				    * the async-dns protocol we may append to
				    * the first vhost below has to have its own
				    * slot, or it eats the NULL terminator slot
				    */
				   1 +
#endif
#if defined(LWS_WITH_CLIENT)
				   1 +
#endif
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
				   1 +
#endif
				   (unsigned int)context->plugin_protocol_count +
				   (unsigned int)fx + 1), "vh plugin table");
	if (!lwsp) {
		lwsl_err("OOM\n");
		goto bail;
	}

	/*
	 * 1: user protocols (from pprotocols or protocols)
	 */

	m = vh->count_protocols;
	if (!pcols) {
		for (n = 0; n < m; n++)
			memcpy(&lwsp[n], info->pprotocols[n], sizeof(lwsp[0]));
	} else
		memcpy(lwsp, pcols, sizeof(struct lws_protocols) * (unsigned int)m);

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
	 * 3: async dns protocol (first vhost only)
	 */
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	if(lws_dll2_is_empty(&context->vhost_list_owner)) {
		uint8_t seen = 0;

		for (n = 0; n < m; n++)
			if (lwsp[n].name && !strcmp(lwsp[n].name, lws_async_dns_protocol.name)) {
				/* Already defined */
				seen = 1;
				break;
			}

		if (!seen) {
			memcpy(&lwsp[m++], &lws_async_dns_protocol,
			       sizeof(struct lws_protocols));
			vh->count_protocols++;
		}
	}
#endif

#if defined(LWS_WITH_SECURE_STREAMS)
	for (n = 0; n < sec_pcol_count; n++) {
		memcpy(&lwsp[m++], available_secstream_protocols[n],
		       sizeof(*lwsp));
		vh->count_protocols++;
	}
#endif

#if defined(LWS_WITH_DHT)
	memcpy(&lwsp[m], &lws_dht_protocol, sizeof(*lwsp));
	m++;
	vh->count_protocols++;
#endif

#if defined(LWS_WITH_CLIENT)
	memcpy(&lwsp[m], &lws_async_ipc_protocol, sizeof(*lwsp));
	m++;
	vh->count_protocols++;
#endif

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	memcpy(&lwsp[m], &lws_sspc_protocols[0], sizeof(*lwsp));
	m++;
	vh->count_protocols++;
#endif


	/*
	 * 3: For compatibility, all protocols enabled on vhost if only
	 * the default vhost exists.  Otherwise only vhosts who ask
	 * for a protocol get it enabled.
	 */

	if ((context->options & LWS_SERVER_OPTION_EXPLICIT_VHOSTS) &&
	    !(vh->options & LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS))
		f = 0;
	(void)f;
#if defined(LWS_WITH_PROTOCOL_PLUGINS)
	if (plugin) {
		vh->plugin_protocol_bind = m;
		while (plugin) {
			const lws_plugin_protocol_t *plpr =
				(const lws_plugin_protocol_t *)plugin->hdr;

			for (n = 0; n < plpr->count_protocols; n++) {
				/*
				 * for compatibility's sake, no pvo implies
				 * allow all protocols
				 */
				if (f || lws_vhost_protocol_options(vh,
						plpr->protocols[n].name)) {
					memcpy(&lwsp[m],
					       &plpr->protocols[n],
					       sizeof(struct lws_protocols));
					m++;
					vh->count_protocols++;
					vh->plugin_protocol_count++;
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
				   (unsigned int)vh->count_protocols, "same vh list");
	if (!vh->same_vh_protocol_owner) {
		/*
		 * lws_same_vh_protocol_insert() indexes this unguarded, ie,
		 * it would write through NULL + n * sizeof(owner) at the first
		 * protocol bind... don't let the vhost exist without it
		 */
		lwsl_err("OOM\n");
		goto bail;
	}
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.mount_list = info->mounts;
#endif

#if defined(LWS_WITH_SYS_METRICS) && defined(LWS_WITH_SERVER)
	{
		char *end = buf + sizeof(buf) - 1;
		p = buf;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "vh.%s", vh->name);
		if (info->iface)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ".%s", info->iface);
		if (info->port && !(info->port & 0xffff))
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ".%u", info->port);
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), ".rx");
		vh->mt_traffic_rx = lws_metric_create(context, 0, buf);
		p[-2] = 't';
		vh->mt_traffic_tx = lws_metric_create(context, 0, buf);
	}
#endif

#ifdef LWS_WITH_UNIX_SOCK
	if (LWS_UNIX_SOCK_ENABLED(vh)) {
		lwsl_vhost_info(vh, "Creating '%s' path \"%s\", %d protocols",
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
		lwsl_vhost_info(vh, "Creating Vhost '%s' %s, %d protocols, IPv6 %s",
			    vh->name, buf, vh->count_protocols,
			    LWS_IPV6_ENABLED(vh) ? "on" : "off");
	}
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	mounts = info->mounts;
	while (mounts) {
		(void)mount_protocols[0];
		lwsl_vhost_info(vh, "   mounting %s%s to %s",
			  mount_protocols[mounts->origin_protocol],
			  mounts->origin ? mounts->origin : "none",
			  mounts->mountpoint);

		mounts = mounts->mount_next;
	}
#endif

	vh->listen_port = info->port;

#if defined(LWS_WITH_SOCKS5)
	vh->socks_proxy_port = 0;
	vh->socks_proxy_address[0] = '\0';
#endif

#if defined(LWS_WITH_CLIENT) && defined(LWS_CLIENT_HTTP_PROXYING)
	/* either use proxy from info, or try get it from env var */
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	vh->http.http_proxy_port = 0;
	vh->http.http_proxy_address[0] = '\0';
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
#if defined(__COVERITY__)
		p = NULL;
#else
		p = getenv("http_proxy"); /* coverity[tainted_scalar] */
		if (p) {
			lws_strncpy(buf, p, sizeof(buf));
			lws_set_proxy(vh, buf);
		}
#endif
#endif
	}
#endif
#if defined(LWS_WITH_SOCKS5)
	if (lws_socks5c_ads_server(vh, info)) {
		lwsl_vhost_err(vh, "bad socks proxy address");
		goto bail;
	}
#endif

	vh->ka_time = info->ka_time;
	vh->ka_interval = info->ka_interval;

	vh->quic_mtu = info->quic_mtu ? info->quic_mtu : 1280;
	vh->ka_probes = info->ka_probes;

	if (vh->options & LWS_SERVER_OPTION_STS)
		lwsl_vhost_notice(vh, "   STS enabled");

#ifdef LWS_WITH_ACCESS_LOG
	if (info->log_filepath) {
		if (lws_fi(&vh->fic, "vh_create_access_log_open_fail"))
			vh->log_fd = (int)LWS_INVALID_FILE;
		else
			vh->log_fd = lws_open(info->log_filepath,
				  O_CREAT | O_APPEND | O_RDWR, 0600);
		if (vh->log_fd == (int)LWS_INVALID_FILE) {
			lwsl_vhost_err(vh, "unable to open log filepath %s",
					   info->log_filepath);
			goto bail;
		}
#ifndef WIN32
		if (context->uid != (uid_t)-1)
			if (chown(info->log_filepath, context->uid,
				  context->gid) == -1)
				lwsl_vhost_err(vh, "unable to chown log file %s",
						   info->log_filepath);
#endif
	} else
		vh->log_fd = (int)LWS_INVALID_FILE;
#endif
	if (lws_fi(&vh->fic, "vh_create_ssl_srv") ||
	    lws_context_init_server_ssl(info, vh)) {
		lwsl_vhost_err(vh, "lws_context_init_server_ssl failed");
		goto bail1;
	}
#if defined(LWS_WITH_CLIENT)
	if (lws_fi(&vh->fic, "vh_create_ssl_cli") ||
	    lws_context_init_client_ssl(info, vh)) {
		lwsl_vhost_err(vh, "lws_context_init_client_ssl failed");
		goto bail1;
	}
#endif
#if defined(LWS_WITH_SERVER)
	lws_context_lock(context, __func__);
	if (lws_fi(&vh->fic, "vh_create_srv_init"))
		n = -1;
	else
		n = _lws_vhost_init_server(info, vh);
	lws_context_unlock(context);
	if (n < 0) {
		lwsl_vhost_err(vh, "init server failed\n");
		goto bail1;
	}
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	n = !!lws_dll2_get_head(&context->vhost_list_owner);
#endif

	lws_dll2_add_tail(&vh->vhost_list, &context->vhost_list_owner);

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	if (!n)
		lws_async_dns_init(context);
#endif

	/* for the case we are adding a vhost much later, after server init */

	if (context->protocol_init_done)
		if (lws_fi(&vh->fic, "vh_create_protocol_init") ||
		    lws_protocol_init(context)) {
			lwsl_vhost_err(vh, "lws_protocol_init failed");
			goto bail1;
		}

	return vh;

bail1:
	lws_vhost_destroy(vh);

	return NULL;

bail:
	/*
	 * We can be entered here from any point after the vhost struct itself
	 * exists, ie, with any subset of the allocations below already done.
	 * The vhost is not on the context vhost list and has no wsi bound to
	 * it yet, so we can't use lws_vhost_destroy(); free by hand what
	 * __lws_vhost_destroy2() would have freed, all of it NULL-tolerant.
	 */
#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_SYS_METRICS)
	lws_metric_destroy(&vh->mt_traffic_rx, 0);
	lws_metric_destroy(&vh->mt_traffic_tx, 0);
#endif
#if defined(LWS_WITH_TLS)
	lws_free_set_NULL(vh->tls.cfg_alloc_cert_path);
	lws_free_set_NULL(vh->tls.cfg_ssl_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls1_3_plus_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls_client_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls_ciphers_iana);
	lws_free_set_NULL(vh->tls.cfg_ssl_ca_filepath);
	lws_free_set_NULL(vh->tls.cfg_ecdh_curve);
#if defined(LWS_WITH_CLIENT)
	lws_free_set_NULL(vh->tls.cfg_client_ecdh_curve);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_ca_filepath);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_cert_filepath);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_private_key_filepath);
#endif
	vh->tls.cfg_key_path = NULL;
#endif
	lws_free_set_NULL(vh->same_vh_protocol_owner);
	if (vh->allocated_vhost_protocols) {
		lws_free((void *)vh->protocols);
		vh->protocols = NULL;
	}

	__lws_lc_untag(vh->context, &vh->lc);
	lws_fi_destroy(&vh->fic);
	lws_free(vh);

early_bail:
	lws_fi_destroy(&info->fic);

	return NULL;
}

void
lws_vhost_set_mounts(struct lws_vhost *vh, const struct lws_http_mount *mounts)
{
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
        vh->http.mount_list = mounts;
#endif
}

int
lws_init_vhost_client_ssl(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost)
{
	struct lws_context_creation_info i;

	memcpy(&i, info, sizeof(i));
	i.port = CONTEXT_PORT_NO_LISTEN;

	return lws_context_init_client_ssl(&i, vhost);
}


/*
 * Start close process for any wsi bound to this vhost that belong to the
 * service thread we are called from.  Because of async event lib close, or
 * protocol staged close on wsi, latency with pts joining in closing their
 * wsi on the vhost, this may take some time.
 *
 * When the wsi count bound to the vhost (from all pts) drops to zero, the
 * vhost destruction will be finalized.
 */

void
__lws_vhost_destroy_pt_wsi_dieback_start(struct lws_vhost *vh)
{
#if LWS_MAX_SMP > 1
	/* calling pt thread has done its wsi dieback */
	int tsi = lws_pthread_self_to_tsi(vh->context);
#else
	int tsi = 0;
#endif
	struct lws_context *ctx = vh->context;
	struct lws_context_per_thread *pt = &ctx->pt[tsi];
	unsigned int n;

#if LWS_MAX_SMP > 1
	if (vh->close_flow_vs_tsi[lws_pthread_self_to_tsi(vh->context)])
		/* this pt has already done its bit */
		return;
#endif

	/*
	 * destroy any wsi that are associated with us but have no socket
	 * (and will otherwise be missed for destruction)
	 */
	lws_io_socket_waiters_close(vh, tsi);

	/*
	 * Close any wsi on this pt bound to the vhost
	 */

	n = 0;
	while (n < pt->fds_count) {
		struct lws *wsi = wsi_from_fd(ctx, pt->fds[n].fd);

		if (wsi && wsi->tsi == tsi && wsi->a.vhost == vh) {

			lwsl_wsi_debug(wsi, "pt %d: closin, role %s", tsi,
					    wsi->role_ops->name);

			lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);

			if (pt->pipe_wsi == wsi)
				pt->pipe_wsi = NULL;
		}
		n++;
	}

#if LWS_MAX_SMP > 1
	/* calling pt thread has done its wsi dieback */
	vh->close_flow_vs_tsi[lws_pthread_self_to_tsi(vh->context)] = 1;
#endif
}

#if defined(LWS_WITH_NETWORK)

/* returns nonzero if v1 and v2 can share listen sockets */
int
lws_vhost_compare_listen(struct lws_vhost *v1, struct lws_vhost *v2)
{
	return ((!v1->iface && !v2->iface) ||
		 (v1->iface && v2->iface && !strcmp(v1->iface, v2->iface))) &&
		v1->listen_port == v2->listen_port;
}

/* helper to interate every listen socket on any vhost and call cb on it */
int
lws_vhost_foreach_listen_wsi(struct lws_context *cx, void *arg,
			     lws_dll2_foreach_cb_t cb)
{
	struct lws_vhost *v = lws_vhost_first(cx);
	int n;

	while (v) {

		n = lws_dll2_foreach_safe(&v->listen_wsi, arg, cb);
		if (n)
			return n;

		v = lws_vhost_next(v);
	}

	return 0;
}

#endif

/*
 * Mark the vhost as being destroyed, so things trying to use it abort.
 *
 * Dispose of the listen socket.
 */

void
lws_vhost_destroy1(struct lws_vhost *vh)
{
	struct lws_context *context = vh->context;
	int n;

	lwsl_vhost_info(vh, "\n");

	lws_context_lock(context, "vhost destroy 1"); /* ---------- context { */

	if (vh->being_destroyed)
		goto out;

	/*
	 * let's lock all the pts, to enforce pt->vh order... pt is refcounted
	 * so it's OK if we acquire it later inside this
	 */

	for (n = 0; n < context->count_threads; n++)
		lws_pt_lock((&context->pt[n]), __func__);

	lws_vhost_lock(vh); /* -------------- vh { */

#if defined(LWS_WITH_TLS_SESSIONS) && defined(LWS_WITH_TLS)
	lws_tls_session_vh_destroy(vh);
#endif

	vh->being_destroyed = 1;
	vh->count_bound_wsi++; /* protect from opportunistic destroy */
	lws_dll2_add_tail(&vh->vh_being_destroyed_list,
			  &context->owner_vh_being_destroyed);

#if defined(LWS_WITH_NETWORK) && defined(LWS_WITH_SERVER)
	/*
	 * PHASE 1: take down or reassign any listen wsi
	 *
	 * Are there other vhosts that are piggybacking on our listen sockets?
	 * If so we need to hand each listen socket off to one of the others
	 * so it will remain open.
	 *
	 * If not, close the listen socket now.
	 *
	 * Either way the listen socket response to the vhost close is
	 * immediately performed.
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			      lws_dll2_get_head(&vh->listen_wsi)) {
		struct lws *wsi = lws_container_of(d, struct lws, listen_list);

		/*
		 * For each of our listen sockets, check every other vhost to
		 * see if another vhost should be given our listen socket.
		 *
		 * ipv4 and ipv6 sockets will both match and be migrated.
		 */

		lws_start_foreach_vhost(v, context) {
			if (v != vh && !v->being_destroyed &&
			    lws_vhost_compare_listen(v, vh)) {
				/*
				 * this can only be a listen wsi, which is
				 * restricted... it has no protocol or other
				 * bindings or states.  So we can simply
				 * swap it to a vhost that has the same
				 * iface + port, but is not closing.
				 */

				lwsl_vhost_notice(vh, "listen skt migrate -> %s",
						      lws_vh_tag(v));

				lws_dll2_remove(&wsi->listen_list);
				lws_dll2_add_tail(&wsi->listen_list,
						  &v->listen_wsi);

				/* req cx + vh lock */
				/*
				 * If the vhost sees it's being destroyed and
				 * in the unbind the number of wsis bound to
				 * it falls to zero, it will destroy the
				 * vhost opportunistically before we can
				 * complete the transfer.  Add a fake wsi
				 * bind temporarily to disallow this...
				 */
				v->count_bound_wsi++;
				__lws_vhost_unbind_wsi(wsi);
				lws_vhost_bind_wsi(v, wsi);
				/*
				 * ... remove the fake wsi bind
				 */
				v->count_bound_wsi--;
				break;
			}
		} lws_end_foreach_vhost(v);

	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * If any listen wsi left we couldn't pass to other vhosts, close them
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			           lws_dll2_get_head(&vh->listen_wsi)) {
		struct lws *wsi = lws_container_of(d, struct lws, listen_list);

		lws_dll2_remove(&wsi->listen_list);
		lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);

	} lws_end_foreach_dll_safe(d, d1);

#endif
#if defined(LWS_WITH_TLS_JIT_TRUST)
	lws_sul_cancel(&vh->sul_unref);
#endif

	vh->count_bound_wsi--;
	lws_vhost_unlock(vh); /* } vh -------------- */

	for (n = 0; n < context->count_threads; n++)
		lws_pt_unlock((&context->pt[n]));

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

/*
 * Either start close or destroy any wsi on the vhost that belong to this pt,
 * if SMP mark the vh that we have done it for
 *
 * Must not have lock on vh
 */

void
__lws_vhost_destroy2(struct lws_vhost *vh)
{
	const struct lws_protocols *protocol = NULL;
#if defined(__COVERITY__)
	struct lws wsi = { 0 };
#else
	struct lws wsi;
#endif
	int n;

	vh->being_destroyed = 0;

	// lwsl_info("%s: %s\n", __func__, vh->name);

	/*
	 * remove ourselves from the defer binding list.  Vhosts that bound
	 * their listener normally (or never had one, like the internal
	 * system vhost) were never on it; that is the common case and not
	 * an error.
	 */
	if (!lws_dll2_is_detached(&vh->no_listener_vlist)) {
		lwsl_debug("deferred iface: removing vh %s\n", vh->name);
		lws_dll2_remove(&vh->no_listener_vlist);
	}

	/*
	 * let the protocols destroy the per-vhost protocol objects
	 */

#if !defined(__COVERITY__)
	memset((void *)&wsi, 0, sizeof(wsi));
#endif
	wsi.a.context = vh->context;
	wsi.a.vhost = vh; /* not a real bound wsi */

#if defined(LWS_WITH_DHT)
	lws_dht_destroy_all_on_vhost(vh);
#endif

	protocol = vh->protocols;
	if (protocol && vh->created_vhost_protocols) {
		n = 0;
		while (n < vh->count_protocols) {
			wsi.a.protocol = protocol;

			if (protocol->callback && lws_vh_pinit_get(vh, n)) {
				lwsl_vhost_debug(vh, "protocol %s destroy", protocol->name);
				protocol->callback(&wsi, LWS_CALLBACK_PROTOCOL_DESTROY,
					   NULL, NULL, 0);
			}
			protocol++;
			n++;
		}
	}

#if defined(LWS_WITH_STUB)
	/*
	 * Destroy stubs spawned on this vhost that are still alive, eg,
	 * because PROTOCOL_DESTROY was never delivered for their parent
	 * protocol to clean them up (in a plugins build, vhost protocols
	 * that were never instantiated with pvos get no protocol
	 * callbacks at all).  This is done after the explicit protocol
	 * destroys above, so those have already taken down their stubs
	 * and removed them from the tracking list.
	 */
	lws_stub_destroy_all_on_vhost(vh);
#endif

	/*
	 * remove vhost from context list of vhosts
	 */

	lws_dll2_remove(&vh->vhost_list);

	/* add ourselves to the pending destruction list */

	if (lws_dll2_is_detached(&vh->vhost_list))
		lws_dll2_add_head(&vh->vhost_list,
				  &vh->context->vhost_pending_destruction_owner);

	//lwsl_debug("%s: do dfl '%s'\n", __func__, vh->name);

	/* remove ourselves from the pending destruction list */

	lws_dll2_remove(&vh->vhost_list);

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
	lws_free_set_NULL(vh->protocol_init);
#if defined(LWS_WITH_SERVER)
	lws_tls_ctx_ref_destroy_all(vh);
#endif
	lws_ssl_SSL_CTX_destroy(vh);
	lws_free(vh->same_vh_protocol_owner);

	if (
#if defined(LWS_WITH_PROTOCOL_PLUGINS)
		vh->context->plugin_list ||
#endif
	    vh->allocated_vhost_protocols)
		lws_free((void *)vh->protocols);
#if defined(LWS_WITH_NETWORK)
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
	if (lws_rops_fidx(ar, LWS_ROPS_destroy_vhost))
		lws_rops_func_fidx(ar, LWS_ROPS_destroy_vhost).
							destroy_vhost(vh);
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;
#endif

#ifdef LWS_WITH_ACCESS_LOG
	if (vh->log_fd != (int)LWS_INVALID_FILE)
		close(vh->log_fd);
#endif

#if defined (LWS_WITH_TLS)
	lws_free_set_NULL(vh->tls.cfg_alloc_cert_path);
	lws_free_set_NULL(vh->tls.cfg_ssl_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls1_3_plus_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls_client_cipher_list);
	lws_free_set_NULL(vh->tls.cfg_tls_ciphers_iana);
	lws_free_set_NULL(vh->tls.cfg_ssl_ca_filepath);
	lws_free_set_NULL(vh->tls.cfg_ecdh_curve);
#if defined(LWS_WITH_CLIENT)
	lws_free_set_NULL(vh->tls.cfg_client_ecdh_curve);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_ca_filepath);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_cert_filepath);
	lws_free_set_NULL(vh->tls.cfg_client_ssl_private_key_filepath);
#endif
	vh->tls.cfg_key_path = NULL;
#endif

#if LWS_MAX_SMP > 1
	lws_mutex_refcount_destroy(&vh->mr);
#endif

#if defined(LWS_WITH_UNIX_SOCK)
	if (LWS_UNIX_SOCK_ENABLED(vh)) {
		n = unlink(vh->iface);
		if (n)
			lwsl_vhost_info(vh, "Closing unix socket %s: errno %d\n",
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

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_SYS_METRICS)
	lws_metric_destroy(&vh->mt_traffic_rx, 0);
	lws_metric_destroy(&vh->mt_traffic_tx, 0);
#endif

	lws_dll2_remove(&vh->vh_being_destroyed_list);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	lws_fi_destroy(&vh->fic);
#endif
#if defined(LWS_WITH_TLS_JIT_TRUST)
	lws_sul_cancel(&vh->sul_unref);
#endif

	__lws_lc_untag(vh->context, &vh->lc);

	memset(vh, 0, sizeof(*vh));
	lws_free(vh);
}

/*
 * Starts the vhost destroy process
 *
 * Vhosts are not simple to deal with because they are an abstraction that
 * crosses SMP thread boundaries, a wsi on any pt can bind to any vhost.  If we
 * want another pt to do something to its wsis safely, we have to asynchronously
 * ask it to do it.
 *
 * In addition, with event libs, closing any handles (which are bound to vhosts
 * in their wsi) can happens asynchronously, so we can't just linearly do some
 * cleanup flow and free it in one step.
 *
 * The vhost destroy is cut into two pieces:
 *
 * 1) dispose of the listen socket, either by passing it on to another vhost
 *    that was already sharing it, or just closing it.
 *
 *    If any wsi bound to the vhost, mark the vhost as in the process of being
 *    destroyed, triggering each pt to close all wsi bound to the vhost next
 *    time around the event loop.  Call lws_cancel_service() so all the pts wake
 *    to deal with this without long poll waits making delays.
 *
 * 2) When the number of wsis bound to the vhost reaches zero, do the final
 *    vhost destroy flow, this can be triggered from any pt.
 */

void
lws_vhost_destroy(struct lws_vhost *vh)
{
	struct lws_context *context = vh->context;

	lws_context_lock(context, __func__); /* ------ context { */

	/* dispose of the listen socket one way or another */
	lws_vhost_destroy1(vh);

	vh->count_bound_wsi++; /* protect from opportunistic destroy */
	/* start async closure of all wsi on this pt thread attached to vh */
	__lws_vhost_destroy_pt_wsi_dieback_start(vh);
	vh->count_bound_wsi--;

	lwsl_vhost_info(vh, "count_bound_wsi %d", vh->count_bound_wsi);

	/* if there are none, finalize now since no further chance */
	if (!vh->count_bound_wsi) {
		__lws_vhost_destroy2(vh);

		goto out;
	}

	/*
	 * We have some wsi bound to this vhost, we have to wait for these to
	 * complete close and unbind before progressing the vhost removal.
	 *
	 * When the last bound wsi on this vh is destroyed we will auto-call
	 * __lws_vhost_destroy2() to finalize vh destruction
	 */

#if LWS_MAX_SMP > 1
	/* alert other pts they also need to do dieback flow for their wsi */
	lws_cancel_service(context);
#endif

out:
	lws_context_unlock(context); /* } context ------------------- */
}

#if defined(LWS_WITH_SERVER)
void
lws_context_deprecate(struct lws_context *cx, lws_reload_func cb)
{
	struct lws_vhost *vh = lws_vhost_first(cx);

	/*
	 * "deprecation" means disable the cx from accepting any new
	 * connections and free up listen sockets to be used by a replacement
	 * cx.
	 *
	 * Otherwise the deprecated cx remains operational, until its
	 * number of connected sockets falls to zero, when it is deleted.
	 *
	 * So, for each vhost, close his listen sockets
	 */

	while (vh) {

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&vh->listen_wsi)) {
			struct lws *wsi = lws_container_of(d, struct lws,
							   listen_list);

			lwsi_set_skt_unusable(wsi, 1);
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   __func__);
			cx->deprecation_pending_listen_close_count++;

		} lws_end_foreach_dll_safe(d, d1);

		vh = lws_vhost_next(vh);
	}

	cx->deprecated = 1;
	cx->deprecation_cb = cb;
}
#endif
