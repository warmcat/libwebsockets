#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
struct vhd_cert_dist_server {
	struct lws_context *cx;
	struct lws_vhost *vh;
	const struct lws_protocols *protocol;
	char pki_root[256];
	struct lws_dll2_owner connections;
#if defined(LWS_WITH_DIR)
	struct lws_dir_notify *dn;
#endif

	int is_stub;
	char secret[129];
	struct lws_spawn_piped *lsp;
};

static struct vhd_cert_dist_server *global_cert_dist_server_vhd = NULL;

struct pss_cert_dist_server {
	struct lws_dll2 list;
	struct lws *wsi;
	char subdomain[128];
	char domain[128];
	int established;
	int needs_cert_update;

	struct lws *wsi_uds;
	char *uds_tx;
	int uds_tx_len;
	int uds_tx_pos;

	char *uds_rx;
	int uds_rx_len;
	int uds_rx_pos;
};

/* --- STUB SERVER IMPLEMENTATION --- */

static char *
read_newest_file_in_dir(const char *dirpath, const char *suffix)
{
	DIR *dir;
	struct dirent *de;
	char best_name[256];
	char path[512];
	struct stat st;
	int fd;
	char *buf = NULL;

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
	"domain"
};

enum stub_req_paths_enum {
	STUB_SECRET,
	STUB_SUBDOMAIN,
	STUB_DOMAIN,
};

struct stub_req_args {
	struct vhd_cert_dist_server *vhd;
	struct lws *wsi;
	char secret[129];
	char subdomain[128];
	char domain[128];
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
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		lws_callback_on_writable(a->wsi);
	}

	return 0;
}

struct pss_stub_server {
	struct lejp_ctx jctx;
	struct stub_req_args args;
	int parser_valid;
	char *response;
	int response_len;
	int response_pos;
};

static int
callback_cert_dist_server_stub(struct lws *wsi, enum lws_callback_reasons reason,
			       void *user, void *in, size_t len)
{
	struct vhd_cert_dist_server *vhd = global_cert_dist_server_vhd;
	struct pss_stub_server *pss = (struct pss_stub_server *)user;

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

			lwsl_notice("%s: Looking for newest key in %s\n", __func__, key_path);
			key_buf = read_newest_file_in_dir(key_path, ".key");

			if (cert_buf && key_buf) {
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
			} else {
				lwsl_notice("%s: Cert or key not found yet for %s\n", __func__, pss->args.domain);
				/* Not ready yet */
				return -1;
			}

			if (cert_buf) free(cert_buf);
			if (key_buf) free(key_buf);
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
	{ "lws-cert-dist-server-stub", callback_cert_dist_server_stub, sizeof(struct pss_stub_server), 4096, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static int
dist_server_stub_run(struct vhd_cert_dist_server *vhd)
{
	struct lws_context_creation_info info;

	lwsl_notice("%s: Starting privileged stub for cert dist server\n", __func__);

	/* Read secret from stdin */
	if (read(0, vhd->secret, 128) != 128) {
		lwsl_err("%s: Failed to read secret from stdin\n", __func__);
		return -1;
	}
	vhd->secret[128] = '\0';

	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = "/var/run/lws-cert-dist-server-stub.sock";
	info.protocols = stub_protocols;
	info.vhost_name = "cert-dist-server-stub";

	unlink(info.iface);
	if (!lws_create_vhost(vhd->cx, &info)) {
		lwsl_err("%s: Failed to create stub vhost\n", __func__);
		return -1;
	}

	chmod(info.iface, 0666);
	return 0;
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

		/* Do not process if the plugin is not enabled on this vhost, unless we are the stub */
		if (!in && (!stub || strcmp(stub, "distribution-server")))
			return 0;

		/* Prevent spawning inside other plugins' stubs */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-dht-dnssec-monitor-root") ||
		    lws_cmdline_option_cx(lws_get_context(wsi), "--lws-acme-client-root"))
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_cert_dist_server));
		if (!vhd) return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		vhd->protocol = lws_get_protocol(wsi);

		lws_strncpy(vhd->pki_root, "/var/dnssec", sizeof(vhd->pki_root));
		int has_pvo = 0;
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			has_pvo = 1;
			if (!strcmp(pvo->name, "pki-root"))
				lws_strncpy(vhd->pki_root, pvo->value, sizeof(vhd->pki_root));
			pvo = pvo->next;
		}

		if (stub && !strcmp(stub, "distribution-server")) {
			if (global_cert_dist_server_vhd) return 0;
			global_cert_dist_server_vhd = vhd;
			vhd->is_stub = 1;
			return dist_server_stub_run(vhd);
		}

		if (stub) return 0;

		if (has_pvo && geteuid() == 0 && !global_cert_dist_server_vhd) {
			struct lws_spawn_piped_info spawn_info;
			static const char *exec_array[10];
			int n = 0;

			global_cert_dist_server_vhd = vhd;

			uint8_t rand[64];
			lws_get_random(vhd->cx, rand, sizeof(rand));
			lws_hex_from_byte_array(rand, sizeof(rand), vhd->secret, sizeof(vhd->secret));

			memset(&spawn_info, 0, sizeof(spawn_info));
			const char *exe_path = lws_cmdline_option_cx_argv0(vhd->cx);
#if defined(__linux__)
			static char plat_exe_buf[256];
			if (!exe_path || exe_path[0] != '/') {
				int m = (int)readlink("/proc/self/exe", plat_exe_buf, sizeof(plat_exe_buf) - 1);
				if (m > 0) {
					plat_exe_buf[m] = '\0';
					exe_path = plat_exe_buf;
				} else exe_path = "/usr/local/bin/lwsws";
			}
#endif
			exec_array[n++] = exe_path;
			exec_array[n++] = "--lws-stub=distribution-server";
			exec_array[n++] = NULL;

			spawn_info.exec_array = exec_array;
			spawn_info.vh = vhd->vh;
			spawn_info.protocol_name = "lws-cert-dist-server";

			vhd->lsp = lws_spawn_piped(&spawn_info);
			if (vhd->lsp) {
				int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
				if (stdin_fd >= 0) {
					if (write(stdin_fd, vhd->secret, 128) < 0)
						lwsl_err("Failed writing secret to pipe\n");
				}
			}
		}

#if defined(LWS_WITH_DIR)
		char scan_path[512];
		lws_snprintf(scan_path, sizeof(scan_path), "%s/domains", vhd->pki_root);
		vhd->dn = lws_dir_notify_create(vhd->cx, scan_path, dist_server_dir_notify_cb, vhd);
#endif
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->lsp)
			lws_spawn_piped_kill_child_process(vhd->lsp);
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
		pss->needs_cert_update = 1;
		lws_callback_on_writable(wsi);
		break;
	}

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
			size_t est_len = 512;
			lwsl_notice("%s: Requesting cert for %s from server UDS stub\n", __func__, pss->domain);
			pss->uds_tx = malloc(est_len + LWS_PRE);
			if (!pss->uds_tx) return -1;
			pss->uds_tx_len = lws_snprintf(pss->uds_tx + LWS_PRE, est_len,
				"{\"secret\":\"%s\",\"subdomain\":\"%s\",\"domain\":\"%s\"}",
				vhd->secret, pss->subdomain, pss->domain);
			pss->uds_tx_pos = 0;

			struct lws_client_connect_info i;
			memset(&i, 0, sizeof(i));
			i.context = vhd->cx;
			i.vhost = vhd->vh;
			i.address = "+/var/run/lws-cert-dist-server-stub.sock";
			i.port = 0;
			i.host = "localhost";
			i.origin = "localhost";
			i.method = "RAW";
			i.local_protocol_name = "lws-cert-dist-server";
			i.opaque_user_data = pss;

			pss->wsi_uds = lws_client_connect_via_info(&i);
			if (!pss->wsi_uds) {
				lwsl_err("%s: [DEBUG] lws_client_connect_via_info failed immediately, retrying in 1s\n", __func__);
				free(pss->uds_tx);
				pss->uds_tx = NULL;
				pss->needs_cert_update = 1;
				lws_set_timer_usecs(wsi, 1 * LWS_USEC_PER_SEC);
			} else {
				lwsl_notice("%s: [DEBUG] lws_client_connect_via_info returned valid wsi %p\n", __func__, pss->wsi_uds);
			}
		}
		break;

	/* UDS Client Callbacks handled in the same protocol callback */
	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_notice("%s: [DEBUG] RAW_CONNECTED fired on wsi %p\n", __func__, wsi);
		if (!vhd->is_stub && lws_get_opaque_user_data(wsi)) {
			lwsl_notice("%s: [DEBUG] Proxy connected to stub UDS, triggering writable\n", __func__);
			lws_callback_on_writable(wsi);
		} else {
			lwsl_notice("%s: [DEBUG] RAW_CONNECTED ignored (is_stub=%d, opaque=%p)\n", __func__, vhd->is_stub, lws_get_opaque_user_data(wsi));
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: [DEBUG] CLIENT_CONNECTION_ERROR: %s\n", __func__, in ? (char *)in : "(null)");
		if (!vhd->is_stub && lws_get_opaque_user_data(wsi)) {
			struct pss_cert_dist_server *up_pss = (struct pss_cert_dist_server *)lws_get_opaque_user_data(wsi);
			lwsl_err("%s: [DEBUG] Proxy failed to connect to stub UDS (retrying in 1s)\n", __func__);
			up_pss->wsi_uds = NULL;
			if (up_pss->uds_tx) { free(up_pss->uds_tx); up_pss->uds_tx = NULL; }
			lws_set_timer_usecs(up_pss->wsi, 1 * LWS_USEC_PER_SEC);
		} else {
			lwsl_notice("%s: [DEBUG] CLIENT_CONNECTION_ERROR ignored (is_stub=%d, opaque=%p)\n", __func__, vhd->is_stub, lws_get_opaque_user_data(wsi));
		}
		break;

	case LWS_CALLBACK_TIMER:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
	case LWS_CALLBACK_CLIENT_WRITEABLE: {
		struct pss_cert_dist_server *up_pss = (struct pss_cert_dist_server *)lws_get_opaque_user_data(wsi);
		lwsl_notice("%s: [DEBUG] WRITEABLE fired on wsi %p (up_pss=%p)\n", __func__, wsi, up_pss);
		if (up_pss && up_pss->uds_tx) {
			lwsl_notice("%s: [DEBUG] Proxy writing %d bytes to stub UDS\n", __func__, up_pss->uds_tx_len - up_pss->uds_tx_pos);
			int m = lws_write(wsi, (unsigned char *)up_pss->uds_tx + LWS_PRE + up_pss->uds_tx_pos, (size_t)(up_pss->uds_tx_len - up_pss->uds_tx_pos), LWS_WRITE_RAW);
			if (m < 0) return -1;
			up_pss->uds_tx_pos += m;
			if (up_pss->uds_tx_pos < up_pss->uds_tx_len)
				lws_callback_on_writable(wsi);
			else {
				lwsl_notice("%s: Proxy finished writing to stub UDS\n", __func__);
				free(up_pss->uds_tx);
				up_pss->uds_tx = NULL;
			}
		}
		break;
	}

	case LWS_CALLBACK_RAW_RX: {
		struct pss_cert_dist_server *up_pss = (struct pss_cert_dist_server *)lws_get_opaque_user_data(wsi);
		if (up_pss) {
			lwsl_notice("%s: Proxy received %d bytes from stub UDS\n", __func__, (int)len);
			if (!up_pss->uds_rx) {
				up_pss->uds_rx = malloc(LWS_PRE + 65536);
				up_pss->uds_rx_len = 0;
				up_pss->uds_rx_pos = 0;
			}
			if ((size_t)up_pss->uds_rx_len + len < 65536) {
				memcpy(up_pss->uds_rx + LWS_PRE + up_pss->uds_rx_len, in, len);
				up_pss->uds_rx_len += (int)len;
			}
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_RAW_CLOSE: {
		struct pss_cert_dist_server *up_pss = (struct pss_cert_dist_server *)lws_get_opaque_user_data(wsi);
		lwsl_notice("%s: [DEBUG] CLOSE event fired on wsi %p (up_pss=%p, rx_len=%d)\n", __func__, wsi, up_pss, up_pss ? up_pss->uds_rx_len : -1);
		if (up_pss) {
			up_pss->wsi_uds = NULL;
			if (up_pss->uds_tx) { free(up_pss->uds_tx); up_pss->uds_tx = NULL; }
			if (up_pss->uds_rx_len > 0)
				lws_callback_on_writable(up_pss->wsi); /* Forward to WSS */
			else {
				lwsl_err("%s: [DEBUG] Stub UDS closed prematurely, retrying in 1s\n", __func__);
				up_pss->needs_cert_update = 1;
				lws_set_timer_usecs(up_pss->wsi, 1 * LWS_USEC_PER_SEC);
			}
		}
		break;
	}

	case LWS_CALLBACK_RAW_RX_FILE: {
		char buf[512];
		ssize_t n;
		int fd = (int)lws_get_socket_fd(wsi);

		if (fd < 0)
			return -1;

		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		if (n == 0)
			return -1;

		buf[n] = '\0';
		lwsl_notice("[DIST-STUB] %s", buf);
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-cert-dist-server",
		callback_cert_dist_server,
		sizeof(struct pss_cert_dist_server),
		65536, /* rx buf size */
		0, /* id */
		NULL, 0 /* user, tx_idl */
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 } /* terminator */
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
