#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct vhd_cert_dist_server {
	struct lws_context *cx;
	struct lws_vhost *vh;
	const struct lws_protocols *protocol;
	char pki_root[256];
	struct lws_dll2_owner connections;
#if defined(LWS_WITH_DIR)
	struct lws_dir_notify *dn;
#endif
};

struct pss_cert_dist_server {
	struct lws_dll2 list;
	struct lws *wsi;
	char subdomain[128];
	char domain[128];
	int established;
};

#if defined(LWS_WITH_DIR)
static void
dist_server_dir_notify_cb(const char *path, int is_file, void *user)
{
	struct vhd_cert_dist_server *vhd = (struct vhd_cert_dist_server *)user;

	lwsl_info("%s: FS change: %s\n", __func__, path);

	/*
	 * If a fullchain.pem or privkey.pem changed, trigger updates for
	 * clients belonging to that domain.
	 */
	if (strstr(path, "fullchain.pem") || strstr(path, "privkey.pem")) {
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->connections.head) {
			struct pss_cert_dist_server *pss =
				lws_container_of(d, struct pss_cert_dist_server, list);

			if (strstr(path, pss->domain)) {
				lwsl_notice("%s: Triggering update for %s\n", __func__, pss->subdomain);
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
	union lws_tls_cert_info_results ir;
	char path[512], *p;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_cert_dist_server));
		if (!vhd)
			return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		vhd->protocol = lws_get_protocol(wsi);

		lws_strncpy(vhd->pki_root, "/var/dnssec/domains/", sizeof(vhd->pki_root));
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "pki-root"))
				lws_strncpy(vhd->pki_root, pvo->value, sizeof(vhd->pki_root));
			pvo = pvo->next;
		}

#if defined(LWS_WITH_DIR)
		/* Watch the pki_root/ directory for changes */
		char scan_path[512];
		lws_snprintf(scan_path, sizeof(scan_path), "%s", vhd->pki_root);
		vhd->dn = lws_dir_notify_create(vhd->cx, scan_path, dist_server_dir_notify_cb, vhd);
#endif
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/*
		 * Extract the identity from the client certificate.
		 * The CN should be the subdomain.
		 */
		if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME, &ir, sizeof(ir.ns.name))) {
			lwsl_err("%s: No client cert common name found\n", __func__);
			return -1;
		}

		lws_strncpy(pss->subdomain, ir.ns.name, sizeof(pss->subdomain));
		pss->wsi = wsi;

		/* Derive domain from subdomain (assume last two parts or similar) */
		p = strchr(pss->subdomain, '.');
		if (p)
			lws_strncpy(pss->domain, p + 1, sizeof(pss->domain));
		else
			lws_strncpy(pss->domain, pss->subdomain, sizeof(pss->domain));

		/* Verify the client cert still exists in the monitor's data dir */
		lws_snprintf(path, sizeof(path), "%s/%s/dist-client/distribution-client-%s.crt",
			     vhd->pki_root, pss->domain, pss->subdomain);

		if (access(path, F_OK)) {
			lwsl_err("%s: Client cert file %s not found on server\n", __func__, path);
			return -1;
		}

		lwsl_notice("%s: Validated distribution client for %s\n", __func__, pss->subdomain);
		lws_dll2_add_tail(&pss->list, &vhd->connections);
		pss->established = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLOSED:
		lws_dll2_remove(&pss->list);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!pss->established)
			return -1;

		{
			char cert_path[512], key_path[512];
			char *cert_buf = NULL, *key_buf = NULL;
			struct stat st;
			int fd, m;

			lws_snprintf(cert_path, sizeof(cert_path), "%s/%s/fullchain.pem",
				     vhd->pki_root, pss->domain);
			lws_snprintf(key_path, sizeof(key_path), "%s/%s/privkey.pem",
				     vhd->pki_root, pss->domain);

			/* Read cert */
			fd = open(cert_path, O_RDONLY);
			if (fd >= 0) {
				if (fstat(fd, &st) == 0) {
					cert_buf = malloc((size_t)st.st_size + 1);
					if (cert_buf) {
						if (read(fd, cert_buf, (size_t)st.st_size) != (ssize_t)st.st_size) {
							free(cert_buf);
							cert_buf = NULL;
						} else {
							cert_buf[st.st_size] = '\0';
						}
					}
				}
				close(fd);
			}

			/* Read key */
			fd = open(key_path, O_RDONLY);
			if (fd >= 0) {
				if (fstat(fd, &st) == 0) {
					key_buf = malloc((size_t)st.st_size + 1);
					if (key_buf) {
						if (read(fd, key_buf, (size_t)st.st_size) != (ssize_t)st.st_size) {
							free(key_buf);
							key_buf = NULL;
						} else {
							key_buf[st.st_size] = '\0';
						}
					}
				}
				close(fd);
			}

			if (cert_buf && key_buf) {
				/* Prepare JSON payload */
				size_t jlen = strlen(cert_buf) + strlen(key_buf) + 512;
				char *json = malloc(LWS_PRE + jlen);
				char *start = json + LWS_PRE, *p = start, *end = json + LWS_PRE + jlen;

				if (json) {
					p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
						"{\"subdomain\":\"%s\",\"fullchain\":\"", pss->subdomain);

					/* Escape newlines for JSON */
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

					lwsl_notice("%s: Sending %d bytes to %s\n", __func__, (int)(p - start), pss->subdomain);
					m = lws_write(wsi, (unsigned char *)start, lws_ptr_diff_size_t(p, start), LWS_WRITE_TEXT);
					if (m < 0) {
						lwsl_err("%s: Write failed\n", __func__);
						free(json);
						goto bail;
					}
					free(json);
				}
			}

bail:
			if (cert_buf) free(cert_buf);
			if (key_buf) free(key_buf);
		}
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
		1024, /* rx buf size */
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
