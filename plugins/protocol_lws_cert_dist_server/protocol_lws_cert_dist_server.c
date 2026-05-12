#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

struct vhd_cert_dist_server {
	struct lws_context                  *cx;
	struct lws_vhost                    *vh;
	const struct lws_protocols          *protocol;
	char                                pki_root[256];
	struct lws_dll2_owner               connections;
#if defined(LWS_WITH_DIR)
	struct lws_dir_notify               *dn;
#endif

	struct lws_dll2                     list_vhd;
	char                                vh_name[128];

	int                                 is_stub;
	char                                secret[129];
	struct lws_stub_manager             *stub_mgr;
};

static struct lws_dll2_owner active_server_vhds;

struct pss_cert_dist_server {
	struct lws_dll2                     list;
	struct lws                          *wsi;
	char                                subdomain[128];
	char                                domain[128];
	int                                 established;
	int                                 needs_cert_update;

	struct lws                          *wsi_uds;
	char                                *uds_tx;
	int                                 uds_tx_len;
	int                                 uds_tx_pos;

	char                                *uds_rx;
	int                                 uds_rx_len;
	int                                 uds_rx_pos;
	char                                hash[65];
};

/* --- STUB SERVER IMPLEMENTATION --- */

static char *
read_newest_file_in_dir(const char *dirpath, const char *suffix)
{
	DIR                     *dir;
	struct dirent           *de;
	char                    best_name[256];
	char                    path[512];
	struct stat             st;
	int                     fd;
	char                    *buf = NULL;

	best_name[0] = '\0';

	dir = opendir(dirpath);
	if (!dir)
		return NULL;

	while ((de = readdir(dir))) {
		size_t l = strlen(de->d_name);
		size_t sl = strlen(suffix);
		if (l > sl && !strcmp(de->d_name + l - sl, suffix)) {
			if (!best_name[0] || strcmp(de->d_name, best_name) > 0)
				lws_strncpy(best_name, de->d_name, sizeof(best_name));
		}
	}
	closedir(dir);

	if (!best_name[0])
		return NULL;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, best_name);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0 && (buf = malloc((size_t)st.st_size + 1))) {
			if (read(fd, buf, (size_t)st.st_size) == (ssize_t)st.st_size)
				buf[st.st_size] = '\0';
			else {
				free(buf);
				buf = NULL;
			}
		}
		close(fd);
	}

	return buf;
}

static const char * const stub_req_paths[] = {
	"secret",
	"subdomain",
	"domain",
	"hash"
};

enum stub_req_paths_enum {
	STUB_SECRET,
	STUB_SUBDOMAIN,
	STUB_DOMAIN,
	STUB_HASH,
};

struct stub_req_args {
	struct vhd_cert_dist_server         *vhd;
	struct lws                          *wsi;
	char                                secret[129];
	char                                subdomain[128];
	char                                domain[128];
	char                                hash[65];
};

static signed char
stub_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct stub_req_args *a = (struct stub_req_args *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case STUB_SECRET:
			lws_strncpy(a->secret, ctx->buf, sizeof(a->secret));
			break;
		case STUB_SUBDOMAIN:
			lws_strncpy(a->subdomain, ctx->buf, sizeof(a->subdomain));
			break;
		case STUB_DOMAIN:
			lws_strncpy(a->domain, ctx->buf, sizeof(a->domain));
			break;
		case STUB_HASH:
			lws_strncpy(a->hash, ctx->buf, sizeof(a->hash));
			break;
		}
	}

	if (reason == LEJPCB_OBJECT_END)
		lws_callback_on_writable(a->wsi);

	return 0;
}

struct pss_stub_server {
	struct lejp_ctx                 jctx;
	struct stub_req_args            args;
	int                               parser_valid;
	char                            *response;
	int                             response_len;
	int                             response_pos;
};

static int
callback_cert_dist_server_stub(struct lws *wsi, enum lws_callback_reasons reason,
			       void *user, void *in, size_t len)
{
	struct vhd_cert_dist_server *vhd = NULL;
	if (active_server_vhds.head)
		vhd = lws_container_of(active_server_vhds.head, struct vhd_cert_dist_server, list_vhd);
	struct pss_stub_server *pss = (struct pss_stub_server *)user;

	if (!vhd) return -1;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("%s: Stub accepted new UDS connection\n", __func__);
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_notice("%s: Stub received %d bytes\n", __func__, (int)len);
		if (!pss->parser_valid) {
			memset(&pss->args, 0, sizeof(pss->args));
			pss->args.vhd = vhd;
			pss->args.wsi = wsi;
			lejp_construct(&pss->jctx, stub_req_cb, &pss->args, stub_req_paths, LWS_ARRAY_SIZE(stub_req_paths));
			pss->parser_valid = 1;
		}
		{
			int m = lejp_parse(&pss->jctx, (uint8_t *)in, (int)len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_err("%s: lejp parse failed\n", __func__);
				return -1;
			}
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->response) {
			lwsl_notice("%s: Stub writing %d bytes to proxy\n", __func__, pss->response_len - pss->response_pos);
			int m = lws_write(wsi, (unsigned char *)pss->response + LWS_PRE + pss->response_pos, (size_t)(pss->response_len - pss->response_pos), LWS_WRITE_RAW);
			if (m < 0) return -1;
			pss->response_pos += m;
			if (pss->response_pos < pss->response_len)
				lws_callback_on_writable(wsi);
			else
				return -1; /* Done */
			break;
		}

		/* We need to generate the response */
		if (!pss->parser_valid) break;

		if (strcmp(pss->args.secret, vhd->secret)) {
			lwsl_err("%s: Secret mismatch\n", __func__);
			return -1;
		}

		if (strchr(pss->args.subdomain, '/') || strstr(pss->args.subdomain, "..") ||
		    strchr(pss->args.domain, '/') || strstr(pss->args.domain, "..")) {
			lwsl_err("%s: Path traversal\n", __func__);
			return -1;
		}

		{
			char cert_path[512], key_path[512];
			char *cert_buf = NULL, *key_buf = NULL;

			lws_snprintf(cert_path, sizeof(cert_path), "%s/domains/%s/certs/production/crt",
				     vhd->pki_root, pss->args.domain);
			lws_snprintf(key_path, sizeof(key_path), "%s/domains/%s/certs/production/key",
				     vhd->pki_root, pss->args.domain);

			lwsl_notice("%s: Looking for newest cert in %s\n", __func__, cert_path);
			cert_buf = read_newest_file_in_dir(cert_path, ".crt");

			if (cert_buf && pss->args.hash[0]) {
				unsigned char digest[20];
				char current_hash[41];
				lws_SHA1((unsigned char *)cert_buf, strlen(cert_buf), digest);
				lws_hex_from_byte_array(digest, 20, current_hash, sizeof(current_hash));
				if (!strcmp(current_hash, pss->args.hash)) {
					lwsl_notice("%s: Hash matches %s, returning unchanged\n", __func__, pss->args.hash);
					pss->response = malloc(LWS_PRE + 256);
					if (pss->response) {
						pss->response_len = lws_snprintf(pss->response + LWS_PRE, 256,
							"{\"subdomain\":\"%s\",\"fullchain\":\"\",\"privkey\":\"\"}", pss->args.subdomain);
						pss->response_pos = 0;
					}
					free(cert_buf);
					cert_buf = NULL;
				}
			}

			if (cert_buf) {
				lwsl_notice("%s: Looking for newest key in %s\n", __func__, key_path);
				key_buf = read_newest_file_in_dir(key_path, ".key");

				if (key_buf) {
					lwsl_notice("%s: Found both cert and key for %s, preparing response\n", __func__, pss->args.domain);
					size_t jlen = (strlen(cert_buf) * 2) + (strlen(key_buf) * 2) + 512;
					pss->response = malloc(LWS_PRE + jlen);
					if (pss->response) {
						char *p = pss->response + LWS_PRE, *end = pss->response + LWS_PRE + jlen;
						p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "{\"subdomain\":\"%s\",\"fullchain\":\"", pss->args.subdomain);
						char *src = cert_buf;
						while (*src && p < end - 4) {
							if (*src == '\n') { *p++ = '\\'; *p++ = 'n'; }
							else if (*src == '\r') { *p++ = '\\'; *p++ = 'r'; }
							else if (*src == '"') { *p++ = '\\'; *p++ = '"'; }
							else *p++ = *src;
							src++;
						}
						p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\",\"privkey\":\"");
						src = key_buf;
						while (*src && p < end - 4) {
							if (*src == '\n') { *p++ = '\\'; *p++ = 'n'; }
							else if (*src == '\r') { *p++ = '\\'; *p++ = 'r'; }
							else if (*src == '"') { *p++ = '\\'; *p++ = '"'; }
							else *p++ = *src;
							src++;
						}
						p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\"}");
						pss->response_len = (int)(p - (pss->response + LWS_PRE));
						pss->response_pos = 0;
						lwsl_notice("%s: Stub JSON response built (%d bytes), requesting write\n", __func__, pss->response_len);
						lws_callback_on_writable(wsi);
					}
					free(key_buf);
				} else {
					lwsl_notice("%s: Key not found yet for %s\n", __func__, pss->args.domain);
					free(cert_buf);
					return -1;
				}
				free(cert_buf);
			} else {
				if (!pss->response) {
					lwsl_notice("%s: Cert not found yet for %s\n", __func__, pss->args.domain);
					return -1;
				}
			}
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (pss->parser_valid) lejp_destruct(&pss->jctx);
		if (pss->response) free(pss->response);
		break;

	default:
		break;
	}
	return 0;
}

static const struct lws_protocols stub_protocols[] = {
	{
		.name			= "lws-cert-dist-server-stub",
		.callback		= callback_cert_dist_server_stub,
		.per_session_data_size	= sizeof(struct pss_stub_server),
		.rx_buffer_size		= 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};



static void
cert_dist_server_raw_cb(const char *in, size_t len, void *user)
{
	struct pss_cert_dist_server *pss = (struct pss_cert_dist_server *)user;

	if (!pss->uds_rx) {
		pss->uds_rx = malloc(LWS_PRE + 65536);
		pss->uds_rx_len = 0;
		pss->uds_rx_pos = 0;
	}
	if ((size_t)pss->uds_rx_len + len < 65536) {
		memcpy(pss->uds_rx + LWS_PRE + pss->uds_rx_len, in, len);
		pss->uds_rx_len += (int)len;
		lws_callback_on_writable(pss->wsi);
	}
}

/* --- MAIN SERVER IMPLEMENTATION --- */

#if defined(LWS_WITH_DIR)
static void
dist_server_dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd_cert_dist_server *vhd = (struct vhd_cert_dist_server *)user;

	if (strstr(path, "fullchain.pem") || strstr(path, "privkey.pem") || strstr(path, "crt") || strstr(path, "key")) {
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->connections.head) {
			struct pss_cert_dist_server *pss = lws_container_of(d, struct pss_cert_dist_server, list);
			if (strstr(path, pss->domain)) {
				pss->needs_cert_update = 1;
				lws_callback_on_writable(pss->wsi);
			}
		} lws_end_foreach_dll(d);
	}
}
#endif

static int
callback_cert_dist_server(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	struct vhd_cert_dist_server *vhd = (struct vhd_cert_dist_server *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	struct pss_cert_dist_server *pss = (struct pss_cert_dist_server *)user;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT: {
		const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");
		const char *vh_name = lws_get_vhost_name(lws_get_vhost(wsi));

		/* Only initialize if the plugin is explicitly enabled on this vhost */
		if (!in)
			return 0;

		/* Prevent spawning inside other plugins' stubs */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-dht-dnssec-monitor-root") ||
		    lws_cmdline_option_cx(lws_get_context(wsi), "--lws-acme-client-root"))
			return 0;

		if (stub) {
			/* In the stub process, we only initialize the specific vhost we were spawned for */
			char expected_stub[256];
			lws_snprintf(expected_stub, sizeof(expected_stub), "stub-%s", vh_name);
			if (strcmp(stub, expected_stub))
				return 0;
		}

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_cert_dist_server));
		if (!vhd) return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		lws_strncpy(vhd->vh_name, vh_name, sizeof(vhd->vh_name));

		lws_strncpy(vhd->pki_root, "/var/dnssec", sizeof(vhd->pki_root));
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "pki-root"))
				lws_strncpy(vhd->pki_root, pvo->value, sizeof(vhd->pki_root));
			pvo = pvo->next;
		}

		char uds_path[256];
		lws_snprintf(uds_path, sizeof(uds_path), "/var/run/lws-cert-dist-server-stub-%s.sock", vh_name);

		char stub_name[256];
		lws_snprintf(stub_name, sizeof(stub_name), "stub-%s", vh_name);

		if (stub) {
			vhd->is_stub = 1;

			struct lws_stub_config sc;
			memset(&sc, 0, sizeof(sc));
			sc.cx = vhd->cx;
			sc.vh = vhd->vh;
			sc.stub_name = stub_name;
			sc.uds_path = uds_path;
			sc.protocols = stub_protocols;

			lws_dll2_add_tail(&vhd->list_vhd, &active_server_vhds);
			if (lws_stub_server_init(&sc, vhd->secret, NULL, 0)) {
				lws_dll2_remove(&vhd->list_vhd);
				return -1;
			}
			return 0;
		}

		struct vhd_cert_dist_server *old_vhd = NULL;
		lws_start_foreach_dll(struct lws_dll2 *, d, active_server_vhds.head) {
			struct vhd_cert_dist_server *v = lws_container_of(d, struct vhd_cert_dist_server, list_vhd);
			if (!strcmp(v->vh_name, vh_name)) {
				old_vhd = v;
				break;
			}
		} lws_end_foreach_dll(d);

		if (old_vhd) {
			/* Hot-reload: Take over the stub manager from the old vhost */
			lwsl_vhost_notice(lws_get_vhost(wsi), "%s: Hot-reloading cert-dist-server, taking over stub manager\n", __func__);
			vhd->stub_mgr = old_vhd->stub_mgr;
			old_vhd->stub_mgr = NULL;
		} else {
			struct lws_stub_config sc;
			memset(&sc, 0, sizeof(sc));
			sc.cx = vhd->cx;
			sc.vh = vhd->vh;
			sc.stub_name = stub_name;
			sc.uds_path = uds_path;
			sc.protocols = stub_protocols;

			vhd->stub_mgr = lws_stub_spawn(&sc);
			if (!vhd->stub_mgr)
				return -1;
		}

		lws_dll2_add_tail(&vhd->list_vhd, &active_server_vhds);

#if defined(LWS_WITH_DIR)
		char scan_path[512];
		lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->pki_root);
		vhd->dn = lws_dir_notify_create(vhd->cx, scan_path, dist_server_dir_notify_cb, vhd);
#endif
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_dll2_remove(&vhd->list_vhd);
			if (vhd->stub_mgr)
				lws_stub_destroy(&vhd->stub_mgr);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED: {
		uint8_t buf[256];
		union lws_tls_cert_info_results *ir = (union lws_tls_cert_info_results *)buf;
		char *p;

		if (vhd->is_stub) return -1; /* Stub doesn't accept WSS */

		if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, ir, sizeof(buf))) {
			lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, (unsigned char *)"No CN in client cert", 20);
			return -1;
		}

		lws_strncpy(pss->subdomain, ir->ns.name, sizeof(pss->subdomain));
		pss->wsi = wsi;

		{
			int dots = 0;
			char *q;
			for (q = pss->subdomain; *q; q++) if (*q == '.') dots++;
			if (dots > 1) {
				p = strchr(pss->subdomain, '.');
				lws_strncpy(pss->domain, p + 1, sizeof(pss->domain));
			} else {
				lws_strncpy(pss->domain, pss->subdomain, sizeof(pss->domain));
			}
		}

		lws_dll2_add_tail(&pss->list, &vhd->connections);
		pss->established = 1;
		pss->needs_cert_update = 0;
		/* Give the client 2 seconds to send its hash */
		lws_set_timer_usecs(wsi, 2 * LWS_USEC_PER_SEC);
		break;
	}

	case LWS_CALLBACK_TIMER:
		if (!vhd->is_stub && pss->established && !pss->wsi_uds && !pss->needs_cert_update) {
			/* Timer expired without getting a hash, fetch anyway */
			pss->needs_cert_update = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (!vhd->is_stub && pss->established && !pss->needs_cert_update) {
			/* Expecting {"hash":"..."} */
			char *h = strstr((char *)in, "\"hash\":\"");
			if (h) {
				h += 8;
				char *end = strchr(h, '"');
				if (end) {
					*end = '\0';
					lws_strncpy(pss->hash, h, sizeof(pss->hash));
					lwsl_notice("%s: Received hash from client: %s\n", __func__, pss->hash);
				}
			}
			/* Cancel timer and fetch */
			lws_set_timer_usecs(wsi, LWS_SET_TIMER_USEC_CANCEL);
			pss->needs_cert_update = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (!vhd->is_stub && pss->established) {
			lws_dll2_remove(&pss->list);
			if (pss->uds_tx) free(pss->uds_tx);
			if (pss->uds_rx) free(pss->uds_rx);
			if (pss->wsi_uds) {
				/* disconnect UDS safely */
				lws_set_opaque_user_data(pss->wsi_uds, NULL);
			}
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (vhd->is_stub) break;
		if (!pss->established) return -1;

		/* If we have the payload from the UDS, write it to WSS */
		if (pss->uds_rx && pss->uds_rx_len > 0) {
			int m = lws_write(wsi, (unsigned char *)pss->uds_rx + LWS_PRE + pss->uds_rx_pos, (size_t)(pss->uds_rx_len - pss->uds_rx_pos), LWS_WRITE_TEXT);
			if (m < 0) return -1;
			pss->uds_rx_pos += m;
			if (pss->uds_rx_pos < pss->uds_rx_len)
				lws_callback_on_writable(wsi);
			else {
				lwsl_notice("%s: Sent complete cert update to WSS client for %s\n", __func__, pss->domain);
				free(pss->uds_rx);
				pss->uds_rx = NULL;
				/* Keep connection open for future updates */
			}
			break;
		}

		/* If we haven't asked UDS yet, ask UDS */
		if (!pss->wsi_uds && pss->needs_cert_update) {
			pss->needs_cert_update = 0;

			if (!vhd || !vhd->stub_mgr) {
				lwsl_err("%s: No stub manager present on vhost '%s', cannot request certs!\n",
					__func__, lws_get_vhost_name(lws_get_vhost(wsi)));
				return -1;
			}

			char tx[512];
			lwsl_notice("%s: Requesting cert for %s from server UDS stub\n", __func__, pss->domain);
			if (pss->hash[0]) {
				lws_snprintf(tx, sizeof(tx),
					"{\"secret\":\"\",\"subdomain\":\"%s\",\"domain\":\"%s\",\"hash\":\"%s\"}",
					pss->subdomain, pss->domain, pss->hash);
			} else {
				lws_snprintf(tx, sizeof(tx),
					"{\"secret\":\"\",\"subdomain\":\"%s\",\"domain\":\"%s\"}",
					pss->subdomain, pss->domain);
			}

			if (lws_stub_request(vhd->stub_mgr, tx, NULL, 0, NULL, cert_dist_server_raw_cb, pss) < 0) {
				lwsl_err("%s: lws_stub_request failed\n", __func__);
				pss->needs_cert_update = 1;
				lws_set_timer_usecs(wsi, 1 * LWS_USEC_PER_SEC);
			} else {
				/* We use pss->wsi_uds = (void *)1 just as a marker that a request is pending */
				pss->wsi_uds = (struct lws *)1;
			}
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
    {
        .name                   = "lws-cert-dist-server",
        .callback               = callback_cert_dist_server,
        .per_session_data_size  = sizeof(struct pss_cert_dist_server),
        .rx_buffer_size         = 65536,
    }
};

LWS_VISIBLE const lws_plugin_protocol_t lws_cert_dist_server = {
	.hdr = {
		.name = "cert dist server",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
};
