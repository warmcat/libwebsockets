#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static struct lws_dll2_owner active_client_vhds;

struct vhd_cert_dist_client {
	struct lws_dll2                 list_vhd;
	char                            vh_name[128];
	struct lws_context              *cx;
	struct lws_vhost                *vh;
	const struct lws_protocols      *protocol;
	char                            base_dir[256];
	char                            secret[129];
	char                            reload_cmd[256];
	struct lws_stub_manager         *stub_mgr;
	struct lws_dll2_owner           clients;
	int                             is_stub;
	const char                      *server_url;
};

struct pss_cert_dist_client {
	lws_sorted_usec_list_t          sul;
	struct lws                      *wsi;
	struct lws                      *wsi_uds;
	char                            subdomain[128];
	char                            domain[128];
	struct lws_vhost                *vh_client;

	struct lejp_ctx                 jctx;
	char                            *cert;
	char                            *key;
	int                             cert_len;
	int                             key_len;

	char                            *uds_tx;
	int                             uds_tx_len;
	int                             uds_tx_pos;
};

struct dist_client_conn {
	struct lws_dll2                 list;
	lws_sorted_usec_list_t          sul;
	struct lws                      *wsi;
	uint16_t                        retry_count;
	struct vhd_cert_dist_client     *vhd;
	struct lws_vhost                *vh;
	char                            addr[64];
	int                             port;
	char                            prot[16];
	char                            name[64];
	char                            hash[65];
	int                             fetching_hash;
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
	cci.context                     = conn->vhd->cx;
	cci.vhost                       = conn->vh;
	cci.address                     = conn->addr;
	cci.host                        = conn->addr;
	cci.origin                      = conn->addr;
	cci.port                        = conn->port;
	cci.path                        = "/";
	cci.protocol                    = "lws-cert-dist-server";
	cci.local_protocol_name         = "lws-cert-dist-client";
	cci.pwsi                        = &conn->wsi;
	cci.retry_and_idle_policy       = &retry;
	cci.opaque_user_data            = conn;

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

static signed char
hash_rx_cb(struct lejp_ctx *ctx, char reason)
{
	struct dist_client_conn *conn = (struct dist_client_conn *)ctx->user;

	if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		if (ctx->path_match - 1 == 0) { /* "hash" */
			if (reason == LEJPCB_VAL_STR_END) {
				lws_strncpy(conn->hash, ctx->buf, sizeof(conn->hash));
				lwsl_notice("%s: Got hash %s for %s\n", __func__, conn->hash, conn->name);
			}
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		conn->fetching_hash = 0;
		/* Hash acquired (or empty), now connect via WSS */
		lws_sul_schedule(conn->vhd->cx, 0, &conn->sul, connect_client, 1);
	}

	return 0;
}

static const char * const hash_paths[] = { "hash" };

/*
 * If we have a cert currently, let's hash it and let the server tell us
 * if the remote one is newer. If we don't have a cert, we don't have
 * anything to hash and want to get any remote cert.
 */

static void
fetch_local_hash(lws_sorted_usec_list_t *sul)
{
	struct dist_client_conn *conn = lws_container_of(sul, struct dist_client_conn, sul);
	char req[256];

	if (!conn->vhd->stub_mgr) {
		/* no local stub (maybe not root?), just connect to remote */
		conn->hash[0] = '\0';
		connect_client(&conn->sul);
		return;
	}

	conn->fetching_hash = 1;
	lws_snprintf(req, sizeof(req), "{\"secret\":\"%s\",\"subdomain\":\"%s\",\"get_hash\":true}",
		     conn->vhd->secret, conn->name);

	if (lws_stub_request(conn->vhd->stub_mgr, req, hash_paths, 1, hash_rx_cb, NULL, conn) < 0) {
		lwsl_err("%s: Failed requesting hash for %s\n", __func__, conn->name);
		/* connect anyway without hash */
		conn->hash[0] = '\0';
		conn->fetching_hash = 0;
		lws_sul_schedule(conn->vhd->cx, 0, &conn->sul, connect_client, 1);
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

        switch (reason) {
        case LEJPCB_VAL_STR_CHUNK:
        case LEJPCB_VAL_STR_END:
		switch (ctx->path_match - 1) {
		case CRX_SUBDOMAIN:
                        if (reason == LEJPCB_VAL_STR_END)
				lws_strncpy(pss->subdomain, ctx->buf, sizeof(pss->subdomain));
			break;
		case CRX_CERT:
			if (!pss->cert) {
				pss->cert = malloc((size_t)ctx->npos + 1);
				if (pss->cert) {
					memcpy(pss->cert, ctx->buf, ctx->npos);
					pss->cert_len = ctx->npos;
					pss->cert[pss->cert_len] = '\0';
				}
			} else {
				char *tmp = realloc(pss->cert, (size_t)pss->cert_len + (size_t)ctx->npos + 1);
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
				pss->key = malloc((size_t)ctx->npos + 1);
				if (pss->key) {
					memcpy(pss->key, ctx->buf, ctx->npos);
					pss->key_len = ctx->npos;
					pss->key[pss->key_len] = '\0';
				}
			} else {
				char *tmp = realloc(pss->key, (size_t)pss->key_len + (size_t)ctx->npos + 1);
				if (tmp) {
					pss->key = tmp;
					memcpy(pss->key + pss->key_len, ctx->buf, ctx->npos);
					pss->key_len += ctx->npos;
					pss->key[pss->key_len] = '\0';
				}
			}
			break;
		}
		break;

        case LEJPCB_OBJECT_END:
		if (!pss->cert_len && !pss->key_len) {
			lwsl_info("%s: Server reported certificate unchanged, skipping\n", __func__);
			/* We successfully checked, keep connection open */
                        break;
		}
		lwsl_info("%s: New certificate received, scheduling update\n", __func__);
		lws_callback_on_writable(pss->wsi);
		break;
        default:
            break;
	}

	return 0;
}

static const char * const stub_req_paths[] = {
	"secret",
	"subdomain",
	"fullchain",
	"privkey",
	"get_hash",
};

enum stub_req_paths_enum {
	STUB_SECRET,
	STUB_SUBDOMAIN,
	STUB_FULLCHAIN,
	STUB_PRIVKEY,
	STUB_GET_HASH,
};

struct stub_req_args {
	struct vhd_cert_dist_client *vhd;
	char                        secret[129];
	char                        subdomain[128];
	char                        *fullchain;
	char                        *privkey;
	int                         fc_len;
	int                         pk_len;
	struct lejp_ctx             jctx;
	int                         parser_valid;
	int                         get_hash;
	char                        *response;
	int                         response_len;
	int                         response_pos;
	struct lws                  *wsi;
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
				a->fullchain = malloc((size_t)ctx->npos + 1);
				if (a->fullchain) {
					memcpy(a->fullchain, ctx->buf, ctx->npos);
					a->fc_len = ctx->npos;
					a->fullchain[a->fc_len] = '\0';
				}
			} else {
				char *tmp = realloc(a->fullchain, (size_t)a->fc_len + (size_t)ctx->npos + 1);
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
				a->privkey = malloc((size_t)ctx->npos + 1);
				if (a->privkey) {
					memcpy(a->privkey, ctx->buf, ctx->npos);
					a->pk_len = ctx->npos;
					a->privkey[a->pk_len] = '\0';
				}
			} else {
				char *tmp = realloc(a->privkey, (size_t)a->pk_len + (size_t)ctx->npos + 1);
				if (tmp) {
					a->privkey = tmp;
					memcpy(a->privkey + a->pk_len, ctx->buf, ctx->npos);
					a->pk_len += ctx->npos;
					a->privkey[a->pk_len] = '\0';
				}
			}
			break;
		case STUB_GET_HASH:
			a->get_hash = 1;
			break;
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		char path[512], path2[512], sym[512], timestamp[64];
		struct timeval tv;
		int fd;

		lwsl_notice("%s: LEJPCB_OBJECT_END reached, validating secret\n", __func__);

		if (strcmp(a->secret, a->vhd->secret)) {
			lwsl_err("%s: Secret mismatch\n", __func__);
			return 1;
		}

		/* STRICT ENFORCEMENT: prevent directory traversal */
		if ((char *)strchr(a->subdomain, '/') || (char *)strstr(a->subdomain, "..")) {
			lwsl_err("%s: Invalid domain format (path traversal detected)\n", __func__);
			return 1;
		}

		if (a->get_hash) {
			char hash[41];
			hash[0] = '\0';
			char sym2[512];
			lws_snprintf(sym2, sizeof(sym2), "%s/%s/fullchain.pem", a->vhd->base_dir, a->subdomain);
			int fd = open(sym2, O_RDONLY);
			if (fd >= 0) {
				struct stat st;
				if (!fstat(fd, &st)) {
					char *buf = malloc((size_t)st.st_size);
					if (buf && read(fd, buf, (size_t)st.st_size) == st.st_size) {
						unsigned char digest[20];
						lws_SHA1((unsigned char *)buf, (size_t)st.st_size, digest);
						lws_hex_from_byte_array(digest, 20, hash, sizeof(hash));
					}
					if (buf) free(buf);
				}
				close(fd);
			}

			a->response = malloc(256 + LWS_PRE);
			if (a->response) {
				a->response_len = lws_snprintf(a->response + LWS_PRE, 256, "{\"hash\":\"%s\"}", hash);
				a->response_pos = 0;
				lws_callback_on_writable(a->wsi);
			}
			return 0;
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
	struct vhd_cert_dist_client *vhd = NULL;
	if (active_client_vhds.head)
		vhd = lws_container_of(active_client_vhds.head, struct vhd_cert_dist_client, list_vhd);
	struct stub_req_args *a = (struct stub_req_args *)user;

	if (!vhd) return -1;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("%s: UDS connection established\n", __func__);
		if (a) {
			memset(a, 0, sizeof(*a));
			a->vhd = vhd;
			a->wsi = wsi;
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
				if (!a->get_hash) {
					lwsl_info("%s: lejp parse completed successfully (no hash requested)\n", __func__);
					return -1; /* Close connection after successful processing */
				}
				/* Write response back */
				lwsl_info("%s: hash computed, waiting for writable\n", __func__);
			}
		}
		break;
	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!a || !a->response)
                        break;
		int m = lws_write(wsi, (unsigned char *)a->response + LWS_PRE + a->response_pos,
                                  (size_t)(a->response_len - a->response_pos), LWS_WRITE_RAW);
		if (m < 0)
                        return -1;
		a->response_pos += m;
		if (a->response_pos >= a->response_len)
                        return -1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!a)
                        break;
		if (a->parser_valid) lejp_destruct(&a->jctx);
		if (a->fullchain) free(a->fullchain);
		if (a->privkey) free(a->privkey);
		if (a->response) free(a->response);
		break;
	default:
		break;
	}
	return 0;
}

static const struct lws_protocols stub_protocols[] = {
	{
		.name			= "lws-cert-dist-stub",
		.callback		= callback_cert_dist_stub,
		.per_session_data_size	= sizeof(struct stub_req_args),
		.rx_buffer_size		= 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};

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
			lwsl_wsi_warn(wsi, "REJECTED ws upgrade: %u\n",
				 lws_http_client_http_response(wsi));
			return -1; /* Abort connection */
		}
		return 0; /* Allow 101 to proceed to WS upgrade */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("%s: Connected to distribution server\n", __func__);
		{
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)user;
			if (pss) {
				pss->wsi = wsi;
				lejp_construct(&pss->jctx, client_rx_cb, pss, client_rx_paths, LWS_ARRAY_SIZE(client_rx_paths));
			}
			lws_callback_on_writable(wsi);
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
                                break;
			}
                        if (m >= 0) {
				lwsl_notice("%s: lejp parsing complete, resetting parser for next update\n", __func__);
				lejp_destruct(&pss->jctx);
				lejp_construct(&pss->jctx, client_rx_cb, pss, client_rx_paths, LWS_ARRAY_SIZE(client_rx_paths));
			}
		}
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		{
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)user;
			struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);

			if (conn && conn->vhd) vhd = conn->vhd;
			if (!pss || !vhd) break;

			/* Send hash if we have one */
			if (conn && conn->hash[0]) {
				char msg[128];
				int n = lws_snprintf(msg + LWS_PRE, sizeof(msg) - LWS_PRE, "{\"hash\":\"%s\"}", conn->hash);
				lwsl_notice("%s: Sending hash to server: %s\n", __func__, conn->hash);
				lws_write(wsi, (unsigned char *)msg + LWS_PRE, (size_t)n, LWS_WRITE_TEXT);
				conn->hash[0] = '\0'; /* Don't send again */
				break;
			}

			lwsl_notice("%s: [DEBUG] WRITEABLE fired on wsi %p (pss->wsi=%p, cert=%p, key=%p, wsi_uds=%p)\n",
				    __func__, wsi, pss->wsi, pss->cert, pss->key, pss->wsi_uds);

			if (pss->wsi == wsi && pss->cert && pss->key && !pss->wsi_uds) {
				if (!vhd->stub_mgr) {
					lwsl_err("%s: No local stub available to save certs!\n", __func__);
					break;
				}

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

				lwsl_notice("%s: JSON payload built, pushing to UDS stub for %s\n", __func__, pss->subdomain);

				if (lws_stub_request(vhd->stub_mgr, pss->uds_tx + LWS_PRE, NULL, 0, NULL, NULL, pss) < 0) {
					lwsl_err("%s: Failed pushing to UDS stub\n", __func__);
				} else {
					pss->wsi_uds = (struct lws *)1;
					lwsl_notice("%s: Sent complete cert update to local UDS stub for %s\n", __func__, pss->subdomain);
				}

				free(pss->uds_tx);
				pss->uds_tx = NULL;

				/* Clear the memory so we don't save it twice */
				free(pss->cert); pss->cert = NULL;
				free(pss->key); pss->key = NULL;
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
			struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);
			lwsl_err("%s: Main connection error: %s. Retrying...\n", __func__, in ? (char *)in : "(null)");
			if (conn && conn->vhd) {
				if (lws_retry_sul_schedule_retry_wsi(wsi, &conn->sul, fetch_local_hash, &conn->retry_count)) {
					lwsl_err("%s: Main connection attempts exhausted\n", __func__);
				}
			}
			return -1;
		}
		/* fallthru */
	case LWS_CALLBACK_CLIENT_CLOSED:
		{
			struct pss_cert_dist_client *pss = (struct pss_cert_dist_client *)user;
			struct dist_client_conn *conn = (struct dist_client_conn *)lws_get_opaque_user_data(wsi);

			if (conn && conn->vhd) {
				if (lws_retry_sul_schedule_retry_wsi(wsi, &conn->sul, fetch_local_hash, &conn->retry_count)) {
					lwsl_err("%s: Main connection attempts exhausted\n", __func__);
				}
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
                        char uds_path[256];
                        char stub_name[256];

                        if (!in)
				return 0;

			const char *vh_name = lws_get_vhost_name(lws_get_vhost(wsi));

			if (stub) {
				char expected_stub[256];
				lws_snprintf(expected_stub, sizeof(expected_stub), "stub-%s", vh_name);
				if (strcmp(stub, expected_stub))
					return 0;
			}

			vhd = lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
			if (vhd)
				return 0;

			vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
							  lws_get_protocol(wsi),
							  sizeof(struct vhd_cert_dist_client));
			if (!vhd) {
				lwsl_err("%s: Failed to allocate vhd\n", __func__);
				return -1;
			}

			lws_strncpy(vhd->vh_name, vh_name, sizeof(vhd->vh_name));
			lws_snprintf(uds_path, sizeof(uds_path), "/var/run/lws-cert-dist-stub-%s.sock", vh_name);
			lws_snprintf(stub_name, sizeof(stub_name), "stub-%s", vh_name);

			lwsl_notice("%s: allocated vhd\n", __func__);

			vhd->cx = lws_get_context(wsi);
			vhd->vh = lws_get_vhost(wsi);
			vhd->protocol = lws_get_protocol(wsi);
			vhd->server_url = "wss://distribution-server.local";

			lws_strncpy(vhd->base_dir, "/etc/lwsws-pki", sizeof(vhd->base_dir));

			const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
			const struct lws_protocol_vhost_options *certs_pvo = NULL;
			const char *ca_filepath = NULL;

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


		if (stub) {
                        struct lws_stub_config sc;

			vhd->is_stub = 1;
			memset(&sc, 0, sizeof(sc));
			sc.cx = vhd->cx;
			sc.vh = vhd->vh;
			sc.stub_name = stub_name;
			sc.uds_path = uds_path;
			sc.protocols = stub_protocols;

			lws_dll2_add_tail(&vhd->list_vhd, &active_client_vhds);
			if (lws_stub_server_init(&sc, vhd->secret, vhd->reload_cmd, sizeof(vhd->reload_cmd))) {
				lws_dll2_remove(&vhd->list_vhd);
				return -1;
			}
			return 0;
		}

		lwsl_vhost_notice(lws_get_vhost(wsi), "%s: Protocol init. euid=%d\n", __func__, (int)getuid());

		struct vhd_cert_dist_client *old_vhd = NULL;
		lws_start_foreach_dll(struct lws_dll2 *, d, active_client_vhds.head) {
			struct vhd_cert_dist_client *v = lws_container_of(d, struct vhd_cert_dist_client, list_vhd);
			if (!strcmp(v->vh_name, vh_name)) {
				old_vhd = v;
				break;
			}
		} lws_end_foreach_dll(d);

		if (old_vhd) {
			/* Hot-reload: Take over the stub manager from the old vhost */
			lwsl_vhost_notice(lws_get_vhost(wsi), "%s: Hot-reloading cert-dist-client, taking over stub manager\n", __func__);
			vhd->stub_mgr = old_vhd->stub_mgr;
			old_vhd->stub_mgr = NULL;
		} else if (certs_pvo) {
			/* Unlink any stale UDS socket BEFORE spawning the stub */
			unlink(uds_path);

			struct lws_stub_config sc;
			memset(&sc, 0, sizeof(sc));
			sc.cx = vhd->cx;
			sc.vh = vhd->vh;
			sc.stub_name = stub_name;
			sc.uds_path = uds_path;
			sc.protocols = stub_protocols;

			char rc[256];
			memset(rc, 0, sizeof(rc));
			lws_strncpy(rc, vhd->reload_cmd, sizeof(rc));
			sc.extra_payload = rc;
			sc.extra_payload_len = 256;

			vhd->stub_mgr = lws_stub_spawn(&sc);
			if (!vhd->stub_mgr)
				return -1;
		}

		lws_dll2_add_tail(&vhd->list_vhd, &active_client_vhds);

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
			const struct lws_protocols *pp[] = { protocols, NULL };
			ci.pprotocols = pp;
			ci.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

			struct lws_vhost *vh = lws_create_vhost(vhd->cx, &ci);
			if (vh) {
				lws_parse_uri_t *pcuri;

				lwsl_notice("%s: Created client vhost for %s\n", __func__, certs_pvo->name);

				pcuri = lws_parse_uri_create(vhd->server_url);
				if (pcuri) {
					struct dist_client_conn *conn = malloc(sizeof(*conn));
					if (conn) {
						memset(conn, 0, sizeof(*conn));
						conn->vhd = vhd;
						conn->vh = vh;
						lws_strncpy(conn->addr, pcuri->host, sizeof(conn->addr));
						conn->port = pcuri->port;
						lws_strncpy(conn->prot, pcuri->scheme, sizeof(conn->prot));
						lws_strncpy(conn->name, certs_pvo->name, sizeof(conn->name));

						/* Schedule connection for this domain by fetching hash first */
						lws_sul_schedule(vhd->cx, 0, &conn->sul, fetch_local_hash, 100 * LWS_US_PER_MS);
					}
					lws_parse_uri_destroy(&pcuri);
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

		if (!(char *)strstr(buf, "DIST-STUB-READY") || !vhd)
			break;

		lwsl_notice("%s: Received ready signal from stub, initiating proxy connections\n", __func__);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(&vhd->clients)) {
			struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);
			lws_sul_schedule(vhd->cx, 0, &conn->sul, connect_client, 1);
		} lws_end_foreach_dll_safe(p, tp);
	}
	break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;

		lws_dll2_remove(&vhd->list_vhd);
		if (vhd->stub_mgr)
			lws_stub_destroy(&vhd->stub_mgr);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(&vhd->clients)) {
			struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);

			lws_sul_cancel(&conn->sul);
			lws_dll2_remove(&conn->list);
			free(conn);
		} lws_end_foreach_dll_safe(p, tp);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "lws-cert-dist-client",
		.callback		= callback_cert_dist_client,
		.per_session_data_size	= sizeof(struct pss_cert_dist_client),
		.rx_buffer_size		= 1024,
	}
};

LWS_VISIBLE const lws_plugin_protocol_t lws_cert_dist_client = {
	.hdr = {
		.name           = "cert dist client",
		._class         = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic      = LWS_PLUGIN_API_MAGIC,
	},
	.protocols              = protocols,
	.count_protocols        = LWS_ARRAY_SIZE(protocols),
};
