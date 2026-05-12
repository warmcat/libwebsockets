#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static struct vhd_cert_dist_client *global_cert_dist_vhd = NULL;

struct vhd_cert_dist_client {
	struct lws_context *cx;
	struct lws_vhost *vh;
	const struct lws_protocols *protocol;
	char base_dir[256];
	char secret[129];
	char reload_cmd[256];
	struct lws_spawn_piped *lsp;
	struct lws_dll2_owner clients;
	int is_stub;
	struct lws_vhost *vh_uds;
	const char *server_url;
};

struct pss_cert_dist_client {
	lws_sorted_usec_list_t sul;
	struct lws *wsi;
	struct lws *wsi_uds;
	char subdomain[128];
	char domain[128];
	struct lws_vhost *vh_client;

	struct lejp_ctx jctx;
	char *cert;
	char *key;
	int cert_len;
	int key_len;

	char *uds_tx;
	int uds_tx_len;
	int uds_tx_pos;
};

struct dist_client_conn {
	struct lws_dll2 list;
	lws_sorted_usec_list_t sul;
	struct lws *wsi;
	uint16_t retry_count;
	struct vhd_cert_dist_client *vhd;
	struct lws_vhost *vh;
	char addr[64];
	int port;
	char prot[16];
	char name[64];
};

static const uint32_t backoff_ms[] = { 1000, 2000, 3000, 4000, 5000 };

static const lws_retry_bo_t retry = {
	.retry_ms_table			= backoff_ms,
	.retry_ms_table_count		= LWS_ARRAY_SIZE(backoff_ms),
	.conceal_count			= LWS_RETRY_CONCEAL_ALWAYS,
	.secs_since_valid_ping		= 30,
	.secs_since_valid_hangup	= 35,
	.jitter_percent			= 20,
};

static void
connect_client(lws_sorted_usec_list_t *sul)
{
	struct dist_client_conn *conn = lws_container_of(sul, struct dist_client_conn, sul);
	struct lws_client_connect_info cci;

	memset(&cci, 0, sizeof(cci));
	cci.context = conn->vhd->cx;
	cci.vhost = conn->vh;
	cci.address = conn->addr;
	cci.host = conn->addr;
	cci.origin = conn->addr;
	cci.port = conn->port;
	cci.path = "/";
	cci.protocol = "lws-cert-dist-server";
	cci.local_protocol_name = "lws-cert-dist-client";
	cci.pwsi = &conn->wsi;
	cci.retry_and_idle_policy = &retry;
	cci.opaque_user_data = conn;

	if (!strcmp(conn->prot, "wss") || !strcmp(conn->prot, "https")) {
		cci.ssl_connection = LCCSCF_USE_SSL | LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM | LCCSCF_H2_QUIRK_OVERFLOWS_TXCR;
		cci.alpn = "http/1.1";
	}

	lwsl_notice("%s: Initiating connection to %s:%d (prot=%s)\n", __func__, conn->addr, conn->port, conn->prot);

	if (!lws_client_connect_via_info(&cci)) {
		if (lws_retry_sul_schedule(conn->vhd->cx, 0, sul, &retry,
					   connect_client, &conn->retry_count)) {
			lwsl_err("%s: connection attempts exhausted\n", __func__);
		}
	}
}

static const char * const client_rx_paths[] = {
	"subdomain",
	"fullchain",
	"privkey",
};

enum client_rx_paths_enum {
	CRX_SUBDOMAIN,
	CRX_CERT,
	CRX_KEY,
};

static signed char
client_rx_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)ctx->user;

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case CRX_SUBDOMAIN:
			if (reason == LEJPCB_VAL_STR_END)
				lws_strncpy(pss->subdomain, ctx->buf, sizeof(pss->subdomain));
			break;
		case CRX_CERT:
			if (!pss->cert) {
				pss->cert = malloc(ctx->npos + 1);
				if (pss->cert) {
					memcpy(pss->cert, ctx->buf, ctx->npos);
					pss->cert_len = ctx->npos;
					pss->cert[pss->cert_len] = '\0';
				}
			} else {
				char *tmp = realloc(pss->cert, (size_t)pss->cert_len + ctx->npos + 1);
				if (tmp) {
					pss->cert = tmp;
					memcpy(pss->cert + pss->cert_len, ctx->buf, ctx->npos);
					pss->cert_len += ctx->npos;
					pss->cert[pss->cert_len] = '\0';
				}
			}
			break;
		case CRX_KEY:
			if (!pss->key) {
				pss->key = malloc(ctx->npos + 1);
				if (pss->key) {
					memcpy(pss->key, ctx->buf, ctx->npos);
					pss->key_len = ctx->npos;
					pss->key[pss->key_len] = '\0';
				}
			} else {
				char *tmp = realloc(pss->key, (size_t)pss->key_len + ctx->npos + 1);
				if (tmp) {
					pss->key = tmp;
					memcpy(pss->key + pss->key_len, ctx->buf, ctx->npos);
					pss->key_len += ctx->npos;
					pss->key[pss->key_len] = '\0';
				}
			}
			break;
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		lwsl_notice("%s: [DEBUG] JSON object complete. cert_len=%d, key_len=%d, subdomain='%s'\n",
			    __func__, pss->cert_len, pss->key_len, pss->subdomain);
		lws_callback_on_writable(pss->wsi);
	}

	return 0;
}

static const char * const stub_req_paths[] = {
	"secret",
	"subdomain",
	"fullchain",
	"privkey",
};

enum stub_req_paths_enum {
	STUB_SECRET,
	STUB_SUBDOMAIN,
	STUB_FULLCHAIN,
	STUB_PRIVKEY,
};

struct stub_req_args {
	struct vhd_cert_dist_client *vhd;
	char secret[129];
	char subdomain[128];
	char *fullchain;
	char *privkey;
	int fc_len;
	int pk_len;
	struct lejp_ctx jctx;
	int parser_valid;
};

static signed char
stub_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct stub_req_args *a = (struct stub_req_args *)ctx->user;

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		switch (ctx->path_match - 1) {
		case STUB_SECRET:
			if (reason == LEJPCB_VAL_STR_END) {
				lws_strncpy(a->secret, ctx->buf, sizeof(a->secret));
				lwsl_notice("%s: Parsed secret (len %d)\n", __func__, (int)strlen(a->secret));
			}
			break;
		case STUB_SUBDOMAIN:
			if (reason == LEJPCB_VAL_STR_END) {
				lws_strncpy(a->subdomain, ctx->buf, sizeof(a->subdomain));
				lwsl_notice("%s: Parsed subdomain: %s\n", __func__, a->subdomain);
			}
			break;
		case STUB_FULLCHAIN:
			if (!a->fullchain) {
				a->fullchain = malloc(ctx->npos + 1);
				if (a->fullchain) {
					memcpy(a->fullchain, ctx->buf, ctx->npos);
					a->fc_len = ctx->npos;
					a->fullchain[a->fc_len] = '\0';
				}
			} else {
				char *tmp = realloc(a->fullchain, (size_t)a->fc_len + ctx->npos + 1);
				if (tmp) {
					a->fullchain = tmp;
					memcpy(a->fullchain + a->fc_len, ctx->buf, ctx->npos);
					a->fc_len += ctx->npos;
					a->fullchain[a->fc_len] = '\0';
				}
			}
			break;
		case STUB_PRIVKEY:
			if (!a->privkey) {
				a->privkey = malloc(ctx->npos + 1);
				if (a->privkey) {
					memcpy(a->privkey, ctx->buf, ctx->npos);
					a->pk_len = ctx->npos;
					a->privkey[a->pk_len] = '\0';
				}
			} else {
				char *tmp = realloc(a->privkey, (size_t)a->pk_len + ctx->npos + 1);
				if (tmp) {
					a->privkey = tmp;
					memcpy(a->privkey + a->pk_len, ctx->buf, ctx->npos);
					a->pk_len += ctx->npos;
					a->privkey[a->pk_len] = '\0';
				}
			}
			break;
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		char path[512], path2[512], sym[512], timestamp[64];
		struct timeval tv;
		int fd;

		lwsl_notice("%s: LEJPCB_OBJECT_END reached, validating secret\n", __func__);

		/* All parts received, validate and write */
		if (strcmp(a->secret, a->vhd->secret)) {
			lwsl_err("%s: Secret mismatch\n", __func__);
			return 1;
		}

		/* STRICT ENFORCEMENT: prevent directory traversal */
		if (strchr(a->subdomain, '/') || strstr(a->subdomain, "..")) {
			lwsl_err("%s: Invalid domain format (path traversal detected)\n", __func__);
			return 1;
		}

		lwsl_notice("%s: Valid command for %s\n", __func__, a->subdomain);

		gettimeofday(&tv, NULL);
		lws_snprintf(timestamp, sizeof(timestamp), "%lld", (long long)tv.tv_sec);

		/* 1. Ensure directory exists */
		lws_snprintf(path, sizeof(path), "%s/%s", a->vhd->base_dir, a->subdomain);
		if (mkdir(path, 0700) < 0 && errno != EEXIST) {
			lwsl_err("%s: Failed to create directory '%s': %s (errno=%d)\n", __func__, path, strerror(errno), errno);
			return 1;
		}

		/* 1.5 Check if certificate actually changed */
		lws_snprintf(sym, sizeof(sym), "%s/%s/fullchain.pem", a->vhd->base_dir, a->subdomain);
		fd = open(sym, O_RDONLY);
		if (fd >= 0) {
			struct stat st;
			if (!fstat(fd, &st) && st.st_size == a->fc_len) {
				char *buf = malloc((size_t)st.st_size);
				if (buf) {
					if (read(fd, buf, (size_t)st.st_size) == st.st_size) {
						if (!memcmp(buf, a->fullchain, (size_t)st.st_size)) {
							lwsl_notice("%s: Cert for %s is unchanged, skipping update\n", __func__, a->subdomain);
							free(buf);
							close(fd);
							return 0; /* Success, no need to write again */
						}
					}
					free(buf);
				}
			}
			close(fd);
		}

		/* 2. Write fullchain */
		lws_snprintf(path, sizeof(path), "%s/%s/fullchain.pem.%s", a->vhd->base_dir, a->subdomain, timestamp);
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			if (write(fd, a->fullchain, (size_t)a->fc_len) < 0)
				lwsl_err("%s: Failed writing fullchain\n", __func__);
			close(fd);
		}

		/* 3. Write privkey */
		lws_snprintf(path2, sizeof(path2), "%s/%s/privkey.pem.%s", a->vhd->base_dir, a->subdomain, timestamp);
		fd = open(path2, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			if (write(fd, a->privkey, (size_t)a->pk_len) < 0)
				lwsl_err("%s: Failed writing privkey\n", __func__);
			close(fd);
		}

		/* 4. Atomic symlink update */
		lws_snprintf(sym, sizeof(sym), "%s/%s/fullchain.pem", a->vhd->base_dir, a->subdomain);
		unlink(sym);
		symlink(path, sym);

		lws_snprintf(sym, sizeof(sym), "%s/%s/privkey.pem", a->vhd->base_dir, a->subdomain);
		unlink(sym);
		symlink(path2, sym);

		lwsl_notice("%s: Files updated for %s, active vhosts will rotate dynamically via proxy\n", __func__, a->subdomain);
	}

	return 0;
}

/* UDS Protocol for Stub <-> Client communication */
static int
callback_cert_dist_stub(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct vhd_cert_dist_client *vhd = global_cert_dist_vhd;
	struct stub_req_args *a = (struct stub_req_args *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("%s: UDS connection established\n", __func__);
		if (a) {
			memset(a, 0, sizeof(*a));
			a->vhd = vhd;
			lejp_construct(&a->jctx, stub_req_cb, a, stub_req_paths, LWS_ARRAY_SIZE(stub_req_paths));
			a->parser_valid = 1;
		}
		break;
	case LWS_CALLBACK_RAW_RX:
		if (a && a->parser_valid) {
			lwsl_notice("%s: Parsing %d bytes of JSON\n", __func__, (int)len);
			int m = lejp_parse(&a->jctx, (uint8_t *)in, (int)len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_err("%s: lejp parse failed: %d\n", __func__, m);
				a->parser_valid = 0;
				return -1;
			} else if (m == 0) {
				lwsl_notice("%s: lejp parse completed successfully\n", __func__);
				return -1; /* Close connection after successful processing */
			}
		}
		break;
	case LWS_CALLBACK_RAW_CLOSE:
		if (a) {
			if (a->parser_valid) lejp_destruct(&a->jctx);
			if (a->fullchain) free(a->fullchain);
			if (a->privkey) free(a->privkey);
		}
		break;
	default:
		break;
	}
	return 0;
}

static const struct lws_protocols stub_protocols[] = {
	{
		"lws-cert-dist-stub",
		callback_cert_dist_stub,
		sizeof(struct stub_req_args), 4096, 0, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static int
dist_client_stub_run(struct vhd_cert_dist_client *vhd)
{
	struct lws_context_creation_info info;

	lwsl_notice("%s: Stub process starting (running as root)\n", __func__);

	/* 1. Read secret from stdin */
	if (read(0, vhd->secret, 128) < 64) {
		lwsl_err("%s: Failed to read secret from stdin\n", __func__);
		return -1;
	}
	vhd->secret[128] = '\0';

	/* 1.5 Read reload_cmd from stdin */
	ssize_t n = read(0, vhd->reload_cmd, 256);
	if (n > 0)
		vhd->reload_cmd[n - 1] = '\0'; /* Null terminate within bounds */
	else
		vhd->reload_cmd[0] = '\0';

	/* 2. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = "/var/run/lws-cert-dist-stub.sock";
	info.protocols = stub_protocols;
	info.vhost_name = "cert-dist-stub";

	unlink(info.iface);
	vhd->vh_uds = lws_create_vhost(vhd->cx, &info);
	if (!vhd->vh_uds) {
		lwsl_err("%s: Failed to create UDS vhost\n", __func__);
		return -1;
	}

	chmod(info.iface, 0600); /* Only root and unprivileged client can talk */

	/* Signal to proxy that UDS server is ready */
	lwsl_notice("DIST-STUB-READY\n");

	return 0;
}

static const struct lws_protocols protocols[];

static int
callback_cert_dist_client(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	struct vhd_cert_dist_client *vhd = (struct vhd_cert_dist_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (lws_http_client_http_response(wsi) != 101) {
			lwsl_err("%s: Server REJECTED WebSocket upgrade! HTTP Status: %u\n", __func__,
				 lws_http_client_http_response(wsi));
			return -1; /* Abort connection */
		}
		return 0; /* Allow 101 to proceed to WS upgrade */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_notice("%s: Server sent HTTP body: %.*s\n", __func__, (int)len, (const char *)in);
		return 0;

	case LWS_CALLBACK_WSI_CREATE:
		lwsl_notice("%s: WSI_CREATE (wsi=%p)\n", __func__, wsi);
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		lwsl_notice("%s: WSI_DESTROY (wsi=%p)\n", __func__, wsi);
		break;

	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
		lwsl_notice("%s: TLS Handshake: Performing server cert verification!\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("%s: Connected to distribution server\n", __func__);
		{
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)user;
			if (pss) {
				pss->wsi = wsi;
				lejp_construct(&pss->jctx, client_rx_cb, pss, client_rx_paths, LWS_ARRAY_SIZE(client_rx_paths));
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		{
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)user;
			if (!pss) break;

			lwsl_notice("%s: Received chunk of JSON from distribution server (%d bytes)\n", __func__, (int)len);
			int m = lejp_parse(&pss->jctx, (uint8_t *)in, (int)len);
			if (m < 0 && m != LEJP_CONTINUE) {
				lwsl_err("%s: lejp parse failed\n", __func__);
			} else if (m >= 0) {
				lwsl_notice("%s: lejp parsing complete, resetting parser for next update\n", __func__);
				lejp_destruct(&pss->jctx);
				lejp_construct(&pss->jctx, client_rx_cb, pss, client_rx_paths, LWS_ARRAY_SIZE(client_rx_paths));
			}
		}
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lwsl_notice("%s: [DEBUG] RAW_CONNECTED fired on wsi %p\n", __func__, wsi);
		if (lws_get_opaque_user_data(wsi)) {
			lwsl_notice("%s: [DEBUG] Proxy connected to stub UDS, triggering writable\n", __func__);
			lws_callback_on_writable(wsi);
		} else {
			lwsl_notice("%s: [DEBUG] RAW_CONNECTED ignored (opaque=NULL)\n", __func__);
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			struct pss_cert_dist_client *pss = NULL;
			struct lws_vhost *vh = lws_get_vhost(wsi);
			if (vh && !strncmp(lws_get_vhost_name(vh), "dist-client-", 12)) {
				pss = (struct pss_cert_dist_client *)user;
				struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);
				if (conn && conn->vhd) vhd = conn->vhd;
			} else {
				pss = (struct pss_cert_dist_client *)lws_get_opaque_user_data(wsi);
			}
			if (!pss || !vhd) break;

			lwsl_notice("%s: [DEBUG] WRITEABLE fired on wsi %p (pss->wsi=%p, cert=%p, key=%p, wsi_uds=%p)\n",
				    __func__, wsi, pss->wsi, pss->cert, pss->key, pss->wsi_uds);

			if (pss->wsi == wsi && pss->cert && pss->key && !pss->wsi_uds) {
				/* Build UDS payload */
				/* Expected by stub: {"secret":"...","subdomain":"...","fullchain":"...","privkey":"..."} */
				int est_len = (pss->cert_len * 2) + (pss->key_len * 2) + (int)strlen(pss->subdomain) + (int)strlen(vhd->secret) + 128;
				pss->uds_tx = malloc((size_t)est_len + LWS_PRE);
				if (!pss->uds_tx) {
					lwsl_err("%s: OOM alloc uds tx\n", __func__);
					break;
				}
				pss->uds_tx_len = lws_snprintf(pss->uds_tx + LWS_PRE, (size_t)est_len,
					"{\"secret\":\"%s\",\"subdomain\":\"%s\",\"fullchain\":\"",
					vhd->secret, pss->subdomain);

				char *p = pss->uds_tx + LWS_PRE + pss->uds_tx_len;
				char *src = pss->cert;
				while (*src) { if (*src == '\n') { *p++ = '\\'; *p++ = 'n'; } else if (*src != '\r') { *p++ = *src; } src++; }

				pss->uds_tx_len = (int)(p - (pss->uds_tx + LWS_PRE));
				pss->uds_tx_len += lws_snprintf(pss->uds_tx + LWS_PRE + pss->uds_tx_len, (size_t)(est_len - pss->uds_tx_len), "\",\"privkey\":\"");

				p = pss->uds_tx + LWS_PRE + pss->uds_tx_len;
				src = pss->key;
				while (*src) { if (*src == '\n') { *p++ = '\\'; *p++ = 'n'; } else if (*src != '\r') { *p++ = *src; } src++; }

				pss->uds_tx_len = (int)(p - (pss->uds_tx + LWS_PRE));
				pss->uds_tx_len += lws_snprintf(pss->uds_tx + LWS_PRE + pss->uds_tx_len, (size_t)(est_len - pss->uds_tx_len), "\"}\n");
				pss->uds_tx_pos = 0;

				lwsl_notice("%s: JSON payload built, connecting to UDS stub for %s\n", __func__, pss->subdomain);

				/* Initiate UDS connection */
				struct lws_client_connect_info i;
				memset(&i, 0, sizeof(i));
				i.context = vhd->cx;
				i.vhost = vhd->vh;
				i.vhost = vhd->vh;
				i.address = "+/var/run/lws-cert-dist-stub.sock";
				i.port = 0;
				i.host = "localhost";
				i.origin = "localhost";
				i.method = "RAW";
				i.local_protocol_name = "lws-cert-dist-client";
				i.opaque_user_data = pss;

				pss->wsi_uds = lws_client_connect_via_info(&i);
				if (!pss->wsi_uds) {
					lwsl_err("%s: [DEBUG] Failed connecting to local UDS stub immediately, retrying in 1s\n", __func__);
					lws_set_timer_usecs(pss->wsi, 1 * LWS_USEC_PER_SEC);
				} else {
					lwsl_notice("%s: [DEBUG] lws_client_connect_via_info returned valid wsi %p\n", __func__, pss->wsi_uds);
				}
			} else if (pss->wsi_uds == wsi && pss->uds_tx) {
				lwsl_notice("%s: [DEBUG] Attempting to write %d bytes to UDS socket\n", __func__, (int)(pss->uds_tx_len - pss->uds_tx_pos));
				int m = lws_write(wsi, (unsigned char *)pss->uds_tx + LWS_PRE + pss->uds_tx_pos, (size_t)(pss->uds_tx_len - pss->uds_tx_pos), LWS_WRITE_RAW);
				if (m < 0) {
					lwsl_err("%s: Write to UDS failed (m=%d)\n", __func__, m);
					return -1;
				}
				lwsl_notice("%s: [DEBUG] lws_write returned %d\n", __func__, m);
				pss->uds_tx_pos += m;
				if (pss->uds_tx_pos < pss->uds_tx_len) {
					lwsl_notice("%s: [DEBUG] Partial write (%d < %d), scheduling writable\n", __func__, pss->uds_tx_pos, pss->uds_tx_len);
					lws_callback_on_writable(wsi);
				} else {
					char certpath[256];
					char keypath[256];

					lwsl_notice("%s: Sent complete cert update to local UDS stub for %s\n", __func__, pss->subdomain);

					lws_snprintf(certpath, sizeof(certpath), "%s/%s/fullchain.pem",
						     vhd->base_dir, pss->subdomain);
					lws_snprintf(keypath, sizeof(keypath), "%s/%s/privkey.pem",
						     vhd->base_dir, pss->subdomain);

					if (lws_tls_cert_updated(vhd->cx, certpath, keypath,
								 pss->cert, (size_t)pss->cert_len,
								 pss->key, (size_t)pss->key_len))
						lwsl_err("%s: Failed to dynamically update vhosts\n", __func__);
					else
						lwsl_notice("%s: Successfully rotated active vhosts for %s\n",
							    __func__, pss->subdomain);

					if (pss->cert) { free(pss->cert); pss->cert = NULL; pss->cert_len = 0; }
					if (pss->key) { free(pss->key); pss->key = NULL; pss->key_len = 0; }
					if (pss->uds_tx) { free(pss->uds_tx); pss->uds_tx = NULL; }

					/* Do not close the socket here. The stub needs to read all chunks.
					 * The stub will close the socket when it finishes parsing the JSON. */
					return 0;
				}
			}
		}
		break;

	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		lwsl_notice("%s: Server initiated close: len %d, msg '%.*s'\n", __func__,
			    (int)len, (int)len, in ? (const char *)in : "none");
		break;

	case LWS_CALLBACK_TIMER:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		{
			struct lws_vhost *vh = lws_get_vhost(wsi);
			if (vh && !strncmp(lws_get_vhost_name(vh), "dist-client-", 12)) {
				struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);
				lwsl_err("%s: Main connection error: %s. Retrying...\n", __func__, in ? (char *)in : "(null)");
				if (conn && conn->vhd) {
					if (lws_retry_sul_schedule_retry_wsi(wsi, &conn->sul, connect_client, &conn->retry_count)) {
						lwsl_err("%s: Main connection attempts exhausted\n", __func__);
					}
				}
				return -1;
			}

			/* UDS connection error */
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)lws_get_opaque_user_data(wsi);
			lwsl_notice("%s: [DEBUG] UDS CLIENT_CONNECTION_ERROR: %s (pss=%p)\n", __func__, in ? (char *)in : "(null)", pss);
			if (pss) {
				lwsl_err("%s: [DEBUG] Proxy failed to connect to UDS stub: %s (retrying in 1s)\n", __func__, in ? (char *)in : "unknown");
				pss->wsi_uds = NULL;
				if (pss->uds_tx) { free(pss->uds_tx); pss->uds_tx = NULL; }
				lws_set_timer_usecs(pss->wsi, 1 * LWS_USEC_PER_SEC);
				return -1;
			}
		}
		/* fallthru */
	case LWS_CALLBACK_CLIENT_CLOSED:
	case LWS_CALLBACK_RAW_CLOSE:
		{
			struct lws_vhost *vh = lws_get_vhost(wsi);
			if (vh && !strncmp(lws_get_vhost_name(vh), "dist-client-", 12)) {
				struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);
				if (conn && conn->vhd) {
					if (lws_retry_sul_schedule_retry_wsi(wsi, &conn->sul, connect_client, &conn->retry_count)) {
						lwsl_err("%s: Main connection attempts exhausted\n", __func__);
					}
				}
			}

			struct pss_cert_dist_client *pss = NULL;
			if (vh && !strncmp(lws_get_vhost_name(vh), "dist-client-", 12)) {
				pss = (struct pss_cert_dist_client *)user;
			} else {
				pss = (struct pss_cert_dist_client *)lws_get_opaque_user_data(wsi);
			}

			lwsl_notice("%s: [DEBUG] CLOSE event fired on wsi %p (pss=%p, reason=%d)\n", __func__, wsi, pss, reason);
			if (pss) {
				if (pss->wsi == wsi) {
					if (pss->cert) { free(pss->cert); pss->cert = NULL; }
					if (pss->key) { free(pss->key); pss->key = NULL; }
					if (pss->uds_tx) { free(pss->uds_tx); pss->uds_tx = NULL; }
					lejp_destruct(&pss->jctx);
					pss->wsi = NULL;
				} else if (pss->wsi_uds == wsi) {
					pss->wsi_uds = NULL;
				}
			}
		}
		break;
	case LWS_CALLBACK_PROTOCOL_INIT:
		{
			const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");

			if (!in && !(stub && !strcmp(stub, "distribution-client"))) {
				lwsl_notice("%s: leaving early (!in && not stub)\n", __func__);
				return 0;
			}

			lwsl_notice("%s: proceeding with init (in=%p, stub=%s)\n", __func__, in, stub ? stub : "NULL");

			if (!strncmp(lws_get_vhost_name(lws_get_vhost(wsi)), "dist-client-", 12)) {
				lwsl_notice("%s: dynamically created vhost '%s', skipping recursive init\n",
							__func__, lws_get_vhost_name(lws_get_vhost(wsi)));
				return 0;
			}

			vhd = lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
			if (vhd) {
				lwsl_notice("%s: vhd already allocated, leaving\n", __func__);
				return 0;
			}

			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
							  lws_get_protocol(wsi),
							  sizeof(struct vhd_cert_dist_client));
			if (!vhd) {
				lwsl_err("%s: Failed to allocate vhd\n", __func__);
				return -1;
			}

			lwsl_notice("%s: allocated vhd\n", __func__);

			vhd->cx = lws_get_context(wsi);
			vhd->vh = lws_get_vhost(wsi);
			vhd->protocol = lws_get_protocol(wsi);
			vhd->server_url = "wss://distribution-server.local";

			lws_strncpy(vhd->base_dir, "/etc/lwsws-pki", sizeof(vhd->base_dir));

			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			const struct lws_protocol_vhost_options *certs_pvo = NULL;
			const char *ca_filepath = NULL;

			lwsl_notice("%s: parsing PVOs\n", __func__);

			while (pvo) {
				lwsl_notice("%s: PVO name='%s', value='%s'\n",
							__func__, pvo->name, pvo->value ? pvo->value : "NULL");
				if (!strcmp(pvo->name, "base-dir"))
					lws_strncpy(vhd->base_dir, pvo->value, sizeof(vhd->base_dir));
				if (!strcmp(pvo->name, "server-url"))
					vhd->server_url = pvo->value;
				if (!strcmp(pvo->name, "certs[]") || !strcmp(pvo->name, "certs"))
					certs_pvo = pvo->options;
				if (!strcmp(pvo->name, "ca-filepath"))
					ca_filepath = pvo->value;
				if (!strcmp(pvo->name, "reload-cmd"))
					lws_strncpy(vhd->reload_cmd, pvo->value, sizeof(vhd->reload_cmd));
				pvo = pvo->next;
			}

			lwsl_notice("%s: done parsing PVOs\n", __func__);

			if (stub && !strcmp(stub, "distribution-client")) {
				if (global_cert_dist_vhd) {
					/* If a subsequent vhost has PVOs, apply them to the global vhd */
					if (strcmp(vhd->base_dir, "/etc/lwsws-pki"))
						lws_strncpy(global_cert_dist_vhd->base_dir, vhd->base_dir, sizeof(global_cert_dist_vhd->base_dir));
					if (vhd->reload_cmd[0])
						lws_strncpy(global_cert_dist_vhd->reload_cmd, vhd->reload_cmd, sizeof(global_cert_dist_vhd->reload_cmd));
					return 0;
				}
				global_cert_dist_vhd = vhd;
				vhd->is_stub = 1;
				return dist_client_stub_run(vhd);
			}

			if (stub) {
				lwsl_notice("%s: is stub, not spawning further\n", __func__);
				return 0; /* Stubs don't spawn other stubs */
			}

			lwsl_notice("%s: evaluating spawn: certs_pvo=%p, getuid()=%d, global_vhd=%p\n",
						__func__, certs_pvo, getuid(), global_cert_dist_vhd);

			if (certs_pvo && getuid() == 0 && !global_cert_dist_vhd) {
				struct lws_spawn_piped_info spawn_info;
				static const char *exec_array[10];
				int n = 0;

				lwsl_notice("%s: Root detected and certs configured, spawning privileged stub\n", __func__);
				global_cert_dist_vhd = vhd;

				/* Generate secret */
				uint8_t rand[64];
				lws_get_random(vhd->cx, rand, sizeof(rand));
				lws_hex_from_byte_array(rand, sizeof(rand), vhd->secret, sizeof(vhd->secret));

				/* Unlink any stale UDS socket BEFORE spawning the stub to prevent the proxy from
				 * racing and connecting to a dead socket left over from a previous crash.
				 * This forces the proxy to gracefully retry until the new stub binds the socket. */
				unlink("/var/run/lws-cert-dist-stub.sock");

				memset(&spawn_info, 0, sizeof(spawn_info));

				const char *exe_path = lws_cmdline_option_cx_argv0(vhd->cx);
#if defined(__linux__)
				static char plat_exe_buf[256];
				if (!exe_path || exe_path[0] != '/') {
					int m = (int)readlink("/proc/self/exe", plat_exe_buf, sizeof(plat_exe_buf) - 1);
					if (m > 0) {
						plat_exe_buf[m] = '\0';
						exe_path = plat_exe_buf;
					} else {
						exe_path = "/usr/local/bin/lwsws";
					}
				}
#endif
				exec_array[n++] = exe_path;
				exec_array[n++] = "--lws-stub=distribution-client";
				exec_array[n++] = NULL;

				for (int i = 0; i < n - 1; i++)
					lwsl_notice("%s: spawn exec_array[%d]: '%s'\n", __func__, i, exec_array[i]);

				spawn_info.exec_array = exec_array;
				spawn_info.timeout_us = 0;
				spawn_info.vh = vhd->vh;
				spawn_info.protocol_name = "lws-cert-dist-client";

				vhd->lsp = lws_spawn_piped(&spawn_info);
				if (vhd->lsp) {
					int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
					if (stdin_fd >= 0) {
						char rc[256];
						memset(rc, 0, sizeof(rc));
						lws_strncpy(rc, vhd->reload_cmd, sizeof(rc));
						if (write(stdin_fd, vhd->secret, 128) < 0)
							lwsl_err("%s: Failed writing secret to pipe\n", __func__);
						if (write(stdin_fd, rc, 256) < 0)
							lwsl_err("%s: Failed writing reload cmd to pipe\n", __func__);
					}
				}
			}

		/* Start connections for each cert */
		while (certs_pvo) {
			struct lws_context_creation_info ci;
			char vh_name[128];
			const struct lws_protocol_vhost_options *c_pvo = certs_pvo->options;
			const char *cert_path = NULL;
			const char *key_path = NULL;

			while (c_pvo) {
				if (!strcmp(c_pvo->name, "cert"))
					cert_path = c_pvo->value;
				if (!strcmp(c_pvo->name, "key"))
					key_path = c_pvo->value;
				c_pvo = c_pvo->next;
			}

			if (!cert_path || !key_path) {
				lwsl_err("%s: certs PVO missing cert or key path\n", __func__);
				certs_pvo = certs_pvo->next;
				continue;
			}

			lws_snprintf(vh_name, sizeof(vh_name), "dist-client-%s", certs_pvo->name);

			memset(&ci, 0, sizeof(ci));
			ci.vhost_name = vh_name;
			ci.port = CONTEXT_PORT_NO_LISTEN;
			ci.client_ssl_cert_filepath = cert_path;
			ci.client_ssl_private_key_filepath = key_path;
			if (ca_filepath)
				ci.client_ssl_ca_filepath = ca_filepath;
			ci.protocols = protocols;
			ci.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

			struct lws_vhost *vh = lws_create_vhost(vhd->cx, &ci);
			if (vh) {
				const char *prot, *addr, *path;
				int port;
				char url_copy[256];

				lwsl_notice("%s: Created client vhost for %s\n", __func__, certs_pvo->name);

				lws_strncpy(url_copy, vhd->server_url, sizeof(url_copy));
				if (!lws_parse_uri(url_copy, &prot, &addr, &port, &path)) {
					struct dist_client_conn *conn = malloc(sizeof(*conn));
					if (conn) {
						memset(conn, 0, sizeof(*conn));
						conn->vhd = vhd;
						conn->vh = vh;
						lws_strncpy(conn->addr, addr, sizeof(conn->addr));
						conn->port = port;
						lws_strncpy(conn->prot, prot, sizeof(conn->prot));
						lws_strncpy(conn->name, certs_pvo->name, sizeof(conn->name));
						lws_dll2_add_tail(&conn->list, &vhd->clients);

						/* Will start connection attempt after stub signals ready */
					}
				} else {
					lwsl_err("%s: Failed to parse server url %s\n", __func__, vhd->server_url);
				}
			} else {
				lwsl_err("%s: Failed to create client vhost '%s'! (Check if cert %s and key %s exist and are valid)\n",
						 __func__, vh_name, cert_path, key_path);
			}

			certs_pvo = certs_pvo->next;
		}
		}
		break;

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

		if (strstr(buf, "DIST-STUB-READY")) {
			lwsl_notice("%s: Received ready signal from stub, initiating proxy connections\n", __func__);
			if (vhd) {
				lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(&vhd->clients)) {
					struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);
					lws_sul_schedule(vhd->cx, 0, &conn->sul, connect_client, 1);
				} lws_end_foreach_dll_safe(p, tp);
			}
		}
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			if (vhd->lsp)
				lws_spawn_piped_kill_child_process(vhd->lsp);
			lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(&vhd->clients)) {
				struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);
				lws_sul_cancel(&conn->sul);
				lws_dll2_remove(&conn->list);
				free(conn);
			} lws_end_foreach_dll_safe(p, tp);
		}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"lws-cert-dist-client",
		callback_cert_dist_client,
		sizeof(struct pss_cert_dist_client),
		1024, 0, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

LWS_VISIBLE const lws_plugin_protocol_t lws_cert_dist_client = {
	.hdr = {
		.name = "cert dist client",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
};
