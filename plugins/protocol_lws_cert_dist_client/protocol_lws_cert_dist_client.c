#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#if !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif

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
	const char                      *server_url;
};

/*
 * Stub child only: what the plugin init (cert_dist_client_init()) was handed
 * by the parent on stdin, the secret, base_dir and reload_cmd.  Requests
 * arrive on the UDS listener vhost, where no vhost instantiates us, so they
 * find their config through this.
 */
static struct vhd_cert_dist_client *cdc_stub;

/*
 * The parent hands its stub {"base_dir":"...","reload_cmd":"..."} as the stub
 * extra payload.  Room for both fields JSON-escaped at the worst case of 6
 * chars per input char, and the rest of the object; it stays below PIPE_BUF,
 * so the parent's write of it is atomic
 */
#define CDC_PAYLOAD_MAX \
	((sizeof(((struct vhd_cert_dist_client *)0)->base_dir) + \
	  sizeof(((struct vhd_cert_dist_client *)0)->reload_cmd)) * 6 + 64)

static const char * const cdc_payload_paths[] = {
	"base_dir",
	"reload_cmd",
};

struct cdc_payload_parse {
	struct vhd_cert_dist_client	*v;
	size_t				len; /* of the string being collected */
};

static signed char
cdc_payload_cb(struct lejp_ctx *ctx, char reason)
{
	struct cdc_payload_parse *pp = (struct cdc_payload_parse *)ctx->user;
	size_t cap;
	char *dest;

	if (!ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case 0:
		dest = pp->v->base_dir;
		cap = sizeof(pp->v->base_dir);
		break;
	default:
		dest = pp->v->reload_cmd;
		cap = sizeof(pp->v->reload_cmd);
		break;
	}

	switch (reason) {
	case LEJPCB_VAL_STR_START:
		pp->len = 0;
		dest[0] = '\0';
		return 0;

	case LEJPCB_VAL_STR_CHUNK:
	case LEJPCB_VAL_STR_END:
		/* a value we cannot hold whole is refused, not truncated */
		if (pp->len + ctx->npos >= cap)
			return -1;
		memcpy(dest + pp->len, ctx->buf, ctx->npos);
		pp->len += ctx->npos;
		dest[pp->len] = '\0';
		return 0;

	default:
		/* anything but a string there is not from our parent */
		if (reason & LEJP_FLAG_CB_IS_VALUE)
			return -1;
		return 0;
	}
}

/*
 * A PEM cert chain or key larger than this is not something we are going to
 * install, and accepting one lets the server make us buffer without limit
 */
#define CERT_DIST_MAX_PEM	(256 * 1024)

/* the name a cert is installed under, ie, the certs[] PVO name */
#define CERT_DIST_NAME_LEN	64

struct pss_cert_dist_client {
	lws_sorted_usec_list_t          sul;
	struct lws                      *wsi;
	char                            subdomain[128];
	char                            domain[128];
	struct lws_vhost                *vh_client;

	struct lejp_ctx                 jctx;
	char                            *cert;
	char                            *key;
	int                             cert_len;
	int                             key_len;
	int                             oversize;

	char                            *uds_tx;
	int                             uds_tx_len;
	int                             uds_tx_pos;
	lws_stub_req_h                  stub_req;
};

struct dist_client_conn {
	struct lws_dll2                 list;
	lws_sorted_usec_list_t          sul;
	lws_sorted_usec_list_t          sul_timeout;
	struct lws                      *wsi;
	uint16_t                        retry_count;
	struct vhd_cert_dist_client     *vhd;
	struct lws_vhost                *vh;
	char                            addr[64];
	int                             port;
	char                            prot[16];
	char                            name[CERT_DIST_NAME_LEN];
	char                            hash[65];
	int                             fetching_hash;
	lws_stub_req_h                  hash_req;
};

/*
 * The install name becomes a directory under base_dir, and is interpolated
 * into JSON: only accept something that can safely be both.  Nothing that
 * gets here should ever fail this, so failing closed costs nothing.
 */

static int
cert_dist_valid_name(const char *s, size_t max)
{
	size_t n = strlen(s);
	const char *p;

	if (!n || n >= max)
		return 0;

	if (*s == '.' || *s == '-')
		return 0;

	for (p = s; *p; p++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' ||
		      *p == '_'))
			return 0;
		if (*p == '.' && p[1] == '.')
			return 0;
	}

	return 1;
}

/*
 * Create or open a file we are about to write a cert or a key into, as root,
 * in a directory an unprivileged local user may be able to create entries in
 * if it pre-existed.  It must not already exist and must not be a symlink.
 */

static int
cert_dist_create_excl(int dfd, const char *name)
{
	int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
			0600);

	if (fd < 0)
		lwsl_err("%s: unable to create '%s': %s\n", __func__, name,
			 strerror(errno));

	return fd;
}

/*
 * Atomically point the symlink \p name in the directory \p dfd at \p target,
 * a sibling file in the same directory
 */

static void
cert_dist_symlink_at(int dfd, const char *target, const char *name)
{
	char tmp[80];

	lws_snprintf(tmp, sizeof(tmp), "%s.tmp", name);
	unlinkat(dfd, tmp, 0);
	if (symlinkat(target, dfd, tmp))
		lwsl_err("%s: symlink %s failed: %s\n", __func__, tmp,
			 strerror(errno));
	else if (renameat(dfd, tmp, dfd, name))
		lwsl_err("%s: rename %s failed: %s\n", __func__, name,
			 strerror(errno));
}

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

	if (reason == LEJPCB_DESTRUCTED)
		/* the request is over, however it ended: our handle is dead */
		conn->hash_req = 0;

	return 0;
}

static const char * const hash_paths[] = { "hash" };

/*
 * If the stub never answers the hash request, proceed without the hash
 * rather than waiting forever
 */
static void
hash_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct dist_client_conn *conn = lws_container_of(sul, struct dist_client_conn, sul_timeout);

	if (!conn->fetching_hash)
		return; /* hash reply beat us to it */

	lwsl_warn("%s: no hash reply for %s, connecting without it\n",
		  __func__, conn->name);
	conn->fetching_hash = 0;
	conn->hash[0] = '\0';

	/*
	 * We are done waiting for it: drop it, so a late reply cannot come
	 * back and start a second connection underneath the one we are about
	 * to make
	 */
	lws_stub_request_cancel(conn->vhd->stub_mgr, conn->hash_req);
	conn->hash_req = 0;

	lws_sul_schedule(conn->vhd->cx, 0, &conn->sul, connect_client, 1);
}

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
	{
		/* the secret is owned by the stub manager, vhd->secret is
		 * only filled in on the stub child side */
		const char *sec = lws_stub_get_secret(conn->vhd->stub_mgr);
		lws_snprintf(req, sizeof(req), "{\"secret\":\"%s\",\"subdomain\":\"%s\",\"get_hash\":true}",
			     sec ? sec : "", conn->name);
	}

	conn->hash_req = lws_stub_request_h(conn->vhd->stub_mgr, req, hash_paths,
					    1, hash_rx_cb, NULL, conn);
	if (!conn->hash_req) {
		lwsl_err("%s: Failed requesting hash for %s\n", __func__, conn->name);
		/* connect anyway without hash */
		conn->hash[0] = '\0';
		conn->fetching_hash = 0;
		lws_sul_schedule(conn->vhd->cx, 0, &conn->sul, connect_client, 1);
	} else
		lws_sul_schedule(conn->vhd->cx, 0, &conn->sul_timeout, hash_timeout_cb,
				 5 * LWS_US_PER_SEC);
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
			if ((size_t)pss->cert_len + (size_t)ctx->npos >
							CERT_DIST_MAX_PEM) {
				pss->oversize = 1;
				break;
			}
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
			if ((size_t)pss->key_len + (size_t)ctx->npos >
							CERT_DIST_MAX_PEM) {
				pss->oversize = 1;
				break;
			}
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
		if (pss->oversize) {
			lwsl_err("%s: server sent > %d of PEM, dropping\n",
				 __func__, (int)CERT_DIST_MAX_PEM);
			if (pss->cert) { free(pss->cert); pss->cert = NULL; }
			if (pss->key) { free(pss->key); pss->key = NULL; }
			pss->cert_len = 0;
			pss->key_len = 0;
			pss->oversize = 0;

			return 1;
		}
		if (!pss->cert_len || !pss->key_len) {
			/*
			 * The server answers an unchanged cert with empty
			 * strings; an update with only one side is malformed.
			 * Either way there is nothing to install, and the
			 * empty buffers must go now, or the next writable on
			 * this connection (eg, a ws ping) would push them as
			 * a "new" cert and blank the installed key material.
			 */
			if (pss->cert_len || pss->key_len)
				lwsl_warn("%s: server sent a one-sided update, dropping\n",
					  __func__);
			else
				lwsl_info("%s: Server reported certificate unchanged, skipping\n",
					  __func__);
			free(pss->cert);
			pss->cert = NULL;
			pss->cert_len = 0;
			free(pss->key);
			pss->key = NULL;
			pss->key_len = 0;

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

	/* "get_hash":true is a JSON bool, not a string */
	if (reason == LEJPCB_VAL_TRUE && ctx->path_match - 1 == STUB_GET_HASH)
		a->get_hash = 1;

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
		char path[512], fn_fc[80], fn_pk[80], timestamp[64];
		struct timeval tv;
		struct stat sd;
		int fd, dfd;

		lwsl_notice("%s: LEJPCB_OBJECT_END reached, validating secret\n", __func__);

		if (strlen(a->secret) != strlen(a->vhd->secret) || lws_timingsafe_bcmp(a->secret, a->vhd->secret, (uint32_t)strlen(a->secret))) {
			lwsl_err("%s: Secret mismatch\n", __func__);
			return 1;
		}

		/*
		 * STRICT ENFORCEMENT: the name is a directory under
		 * base_dir, it must not be empty (which would collapse the
		 * paths into base_dir itself), escape it, or be anything but
		 * a plain name
		 */
		if (!cert_dist_valid_name(a->subdomain, sizeof(a->subdomain))) {
			lwsl_err("%s: Invalid domain format\n", __func__);
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

		/*
		 * Nothing that arrives here may replace working key material
		 * with junk: both sides must be non-empty and actually look
		 * like PEM.  Empty strings reach here as zero-length buffers,
		 * and write(fd, NULL-ish, 0) "succeeds", so without this the
		 * symlink flip would atomically install 0-byte certs.
		 */
		if (a->fc_len <= 0 || a->pk_len <= 0 ||
		    !strstr(a->fullchain, "-----BEGIN CERTIFICATE-----") ||
		    !strstr(a->fullchain, "-----END CERTIFICATE-----") ||
		    !strstr(a->privkey, "-----BEGIN") ||
		    !strstr(a->privkey, "PRIVATE KEY-----")) {
			lwsl_err("%s: refusing to install non-PEM cert or key for %s (fc %d, pk %d)\n",
				 __func__, a->subdomain, a->fc_len, a->pk_len);

			return 1;
		}

		gettimeofday(&tv, NULL);
		lws_snprintf(timestamp, sizeof(timestamp), "%lld.%06lld",
			     (long long)tv.tv_sec, (long long)tv.tv_usec);

		/* 1. Ensure directory exists */
		lws_snprintf(path, sizeof(path), "%s/%s", a->vhd->base_dir, a->subdomain);
		if (mkdir(path, 0700) < 0 && errno != EEXIST) {
			lwsl_err("%s: Failed to create directory '%s': %s (errno=%d)\n", __func__, path, strerror(errno), errno);
			return 1;
		}

		/*
		 * We are root and about to write a private key in there: if
		 * the directory already existed, it must be a real directory
		 * that we own and that nobody else can write to, or a local
		 * user could have planted symlinks in it.
		 *
		 * Open it (refusing to follow a symlink) and check the open
		 * fd rather than the path, then do everything below relative
		 * to that fd, so what we checked and what we write into are
		 * the same directory even if the path is swapped out from
		 * under us in between.
		 */
		dfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
		if (dfd < 0 || fstat(dfd, &sd) || !S_ISDIR(sd.st_mode) ||
		    sd.st_uid != geteuid() ||
		    (sd.st_mode & (S_IWGRP | S_IWOTH))) {
			lwsl_err("%s: '%s' is not a private directory "
				 "we own\n", __func__, path);
			if (dfd >= 0)
				close(dfd);
			return 1;
		}

		/* 1.5 Check if certificate actually changed */
		fd = openat(dfd, "fullchain.pem", O_RDONLY);
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
							close(dfd);
							return 0; /* Success, no need to write again */
						}
					}
					free(buf);
				}
			}
			close(fd);
		}

		/* 2. Write fullchain */
		lws_snprintf(fn_fc, sizeof(fn_fc), "fullchain.pem.%s", timestamp);
		fd = cert_dist_create_excl(dfd, fn_fc);
		if (fd < 0)
			goto bail;
		if (write(fd, a->fullchain, (size_t)a->fc_len) != (ssize_t)a->fc_len) {
			lwsl_err("%s: Failed writing fullchain\n", __func__);
			close(fd);
			goto bail_fc;
		}
		close(fd);

		/* 3. Write privkey */
		lws_snprintf(fn_pk, sizeof(fn_pk), "privkey.pem.%s", timestamp);
		fd = cert_dist_create_excl(dfd, fn_pk);
		if (fd < 0)
			goto bail_fc;
		if (write(fd, a->privkey, (size_t)a->pk_len) != (ssize_t)a->pk_len) {
			lwsl_err("%s: Failed writing privkey\n", __func__);
			close(fd);
			unlinkat(dfd, fn_pk, 0);
			goto bail_fc;
		}
		close(fd);

		/* 4. Atomic symlink update, targets are siblings in the dir */
		cert_dist_symlink_at(dfd, fn_fc, "fullchain.pem");
		cert_dist_symlink_at(dfd, fn_pk, "privkey.pem");

		lwsl_notice("%s: Files updated for %s, active vhosts will rotate dynamically via proxy\n", __func__, a->subdomain);
		close(dfd);

		return 0;

bail_fc:
		unlinkat(dfd, fn_fc, 0);
bail:
		close(dfd);

		return 1;
	}

	return 0;
}

/*
 * Forget one request, so the connection is ready for the next: the parent
 * sends them one after another on the same connection, and does not wait for
 * the ones it expects no reply to
 */
static void
cdc_stub_req_release(struct stub_req_args *a)
{
	if (a->parser_valid)
		lejp_destruct(&a->jctx);

	/* it may be holding a private key */
	if (a->fullchain) {
		lws_explicit_bzero(a->fullchain, (size_t)a->fc_len);
		free(a->fullchain);
	}
	if (a->privkey) {
		lws_explicit_bzero(a->privkey, (size_t)a->pk_len);
		free(a->privkey);
	}
	free(a->response);
	lws_explicit_bzero(a->secret, sizeof(a->secret));

	a->parser_valid	= 0;
	a->fullchain	= NULL;
	a->privkey	= NULL;
	a->fc_len	= 0;
	a->pk_len	= 0;
	a->response	= NULL;
	a->get_hash	= 0;
	a->subdomain[0]	= '\0';
}

/* UDS Protocol for Stub <-> Client communication */
static int
callback_cert_dist_stub(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct vhd_cert_dist_client *vhd = cdc_stub;
	struct stub_req_args *a = (struct stub_req_args *)user;
	const uint8_t *p = (const uint8_t *)in;
	int m;

	if (!vhd) return -1;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("%s: UDS connection established\n", __func__);
		memset(a, 0, sizeof(*a));
		a->vhd = vhd;
		a->wsi = wsi;
		break;

	case LWS_CALLBACK_RAW_RX:
		while (len) {
			if (a->response) {
				/*
				 * The parent waits for our answer before it
				 * sends anything else
				 */
				lwsl_err("%s: request while one is being "
					 "answered\n", __func__);
				return -1;
			}

			if (!a->parser_valid) {
				lejp_construct(&a->jctx, stub_req_cb, a,
					       stub_req_paths,
					       LWS_ARRAY_SIZE(stub_req_paths));
				a->parser_valid = 1;
			}

			/* acts on the request as it completes */
			m = lejp_parse(&a->jctx, p, (int)len);
			if (m == LEJP_CONTINUE)
				break;
			if (m < 0) {
				lwsl_err("%s: lejp parse failed: %d\n",
					 __func__, m);
				return -1;
			}

			/* m is what is left after the completed request */
			p += len - (size_t)m;
			len = (size_t)m;

			if (!a->response)
				/* nothing to answer, ready for the next */
				cdc_stub_req_release(a);
		}
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!a->response)
			break;
		m = lws_write(wsi, (unsigned char *)a->response + LWS_PRE +
					a->response_pos,
			      (size_t)(a->response_len - a->response_pos),
			      LWS_WRITE_RAW);
		if (m < 0)
			return -1;
		a->response_pos += m;
		if (a->response_pos < a->response_len) {
			lws_callback_on_writable(wsi);
			break;
		}

		/* answered, ready for the next */
		cdc_stub_req_release(a);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		cdc_stub_req_release(a);
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
				/*
				 * The parser is left in an indeterminate
				 * state: drop the connection rather than
				 * feed it more of what the server is saying
				 */
				lwsl_err("%s: lejp parse failed\n", __func__);

				return -1;
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

			if (pss->wsi == wsi && pss->cert && pss->key &&
			    pss->cert_len && pss->key_len) {
				size_t est_len;
				const char *sec;

				if (!vhd->stub_mgr) {
					lwsl_err("%s: No local stub available to save certs!\n", __func__);
					break;
				}

				if (!conn) {
					lwsl_err("%s: no conn for wsi\n", __func__);
					break;
				}

				/*
				 * We install under the name we asked for, not
				 * under whatever name the server chose to
				 * answer with: otherwise one connection lets
				 * the server replace the cert and key of every
				 * other domain this host serves
				 */
				if (pss->subdomain[0] &&
				    strcmp(pss->subdomain, conn->name))
					lwsl_warn("%s: server answered for '%s' "
						  "on the '%s' link, using "
						  "'%s'\n", __func__,
						  pss->subdomain, conn->name,
						  conn->name);

				sec = lws_stub_get_secret(vhd->stub_mgr);

				/*
				 * Escaping expands by at most 2x, and both
				 * PEMs are capped at CERT_DIST_MAX_PEM, so
				 * this cannot overflow size_t
				 */
				est_len = ((size_t)pss->cert_len * 2) +
					  ((size_t)pss->key_len * 2) +
					  strlen(conn->name) +
					  (sec ? strlen(sec) : 0) + 128;
				pss->uds_tx = malloc(est_len + LWS_PRE);
				if (!pss->uds_tx) {
					lwsl_err("%s: OOM alloc uds tx\n", __func__);
					break;
				}
				pss->uds_tx_len = lws_snprintf(pss->uds_tx + LWS_PRE, est_len,
					"{\"secret\":\"%s\",\"subdomain\":\"%s\",\"fullchain\":\"",
					sec ? sec : "", conn->name);

				char *p = pss->uds_tx + LWS_PRE + pss->uds_tx_len;
				char *src = pss->cert;
				while (*src) {
					if (*src == '\n') {
						*p++ = '\\';
						*p++ = 'n';
					} else
						if (*src != '\r')
							*p++ = *src;
					src++;
				}

				pss->uds_tx_len = (int)(p - (pss->uds_tx + LWS_PRE));
				pss->uds_tx_len += lws_snprintf(pss->uds_tx + LWS_PRE + pss->uds_tx_len, est_len - (size_t)pss->uds_tx_len, "\",\"privkey\":\"");

				p = pss->uds_tx + LWS_PRE + pss->uds_tx_len;
				src = pss->key;
				while (*src) {
					if (*src == '\n') {
						*p++ = '\\';
						*p++ = 'n';
					} else
						if (*src != '\r')
							*p++ = *src;
					src++;
				}

				pss->uds_tx_len = (int)(p - (pss->uds_tx + LWS_PRE));
				pss->uds_tx_len += lws_snprintf(pss->uds_tx + LWS_PRE + pss->uds_tx_len, est_len - (size_t)pss->uds_tx_len, "\"}\n");

				lwsl_notice("%s: JSON payload built, pushing to UDS stub for %s\n", __func__, conn->name);

				/*
				 * The server pushes every renewal down the same
				 * link: an older install of ours that is still
				 * queued is superseded by this one
				 */
				lws_stub_request_cancel(vhd->stub_mgr,
							pss->stub_req);
				pss->stub_req = lws_stub_request_h(vhd->stub_mgr,
						pss->uds_tx + LWS_PRE, NULL, 0,
						NULL, NULL, pss);
				if (!pss->stub_req)
					lwsl_err("%s: Failed pushing to UDS stub\n", __func__);
				else
					lwsl_notice("%s: Sent complete cert update to local UDS stub for %s\n", __func__, conn->name);

				/*
				 * The stub request took its own copy.  Clear
				 * ours, it holds the private key, and so we
				 * don't save it twice
				 */
				lws_explicit_bzero(pss->uds_tx + LWS_PRE,
						   (size_t)pss->uds_tx_len);
				free(pss->uds_tx);
				pss->uds_tx = NULL;

				free(pss->cert);
				pss->cert = NULL;
				pss->cert_len = 0;
				lws_explicit_bzero(pss->key, (size_t)pss->key_len);
				free(pss->key);
				pss->key = NULL;
				pss->key_len = 0;
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

	case LWS_CALLBACK_WSI_DESTROY:
		{
			/*
			 * lws only wrote conn->wsi at connect time, forget it
			 * as the wsi goes.  We are the protocols[0] of the
			 * conn's vhost, so we hear about this however the wsi
			 * ended, even during context destroy.
			 */
			struct dist_client_conn *conn = (struct dist_client_conn *)
						lws_get_opaque_user_data(wsi);

			if (conn && conn->wsi == wsi)
				conn->wsi = NULL;
		}
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

					/*
					 * lws is about to free the pss: an
					 * install request of ours may still be
					 * queued, holding the private key it
					 * would have sent
					 */
					if (vhd) {
						lws_stub_request_cancel(
							vhd->stub_mgr,
							pss->stub_req);
						pss->stub_req = 0;
					}

					pss->wsi = NULL;
				}
			}
		}
		break;
	case LWS_CALLBACK_PROTOCOL_INIT:
		{
			const char *stub = lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub");

			/*
			 * A stub process, ours or anybody's, never takes the
			 * client role: our own stub's side is set up once by
			 * the plugin init
			 */
			if (stub)
				return 0;

			if (!in)
				return 0;

			const char *vh_name = lws_get_vhost_name(lws_get_vhost(wsi));

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

			char uds_path[256];
			char stub_name[256];
			lws_strncpy(vhd->vh_name, vh_name, sizeof(vhd->vh_name));
			lws_snprintf(uds_path, sizeof(uds_path), "/var/run/lws-cert-dist-stub-%s.sock", vh_name);
			lws_snprintf(stub_name, sizeof(stub_name), "certdistcli-%s", vh_name);

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
			sc.parent_protocol_name = "lws-cert-dist-client";

			/*
			 * The stub child process starts with a clean context
			 * and can't see our PVOs: pass it what it needs to
			 * build file paths (base_dir) plus the reload command
			 * via the stub extra payload
			 */
			char rc[CDC_PAYLOAD_MAX],
			     ebd[sizeof(vhd->base_dir) * 6],
			     erc[sizeof(vhd->reload_cmd) * 6];

			lws_json_purify(ebd, vhd->base_dir, (int)sizeof(ebd),
					NULL);
			lws_json_purify(erc, vhd->reload_cmd, (int)sizeof(erc),
					NULL);
			sc.extra_payload = rc;
			sc.extra_payload_len = (size_t)lws_snprintf(rc, sizeof(rc),
				     "{\"base_dir\":\"%s\",\"reload_cmd\":\"%s\"}",
				     ebd, erc) + 1;

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

			/*
			 * The certs[] name is what we install under: it goes
			 * into the JSON we send the privileged stub and
			 * becomes a directory under base_dir there
			 */
			if (!cert_dist_valid_name(certs_pvo->name,
						  CERT_DIST_NAME_LEN)) {
				lwsl_err("%s: certs PVO name '%s' unusable\n",
					 __func__, certs_pvo->name);
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

						/*
						 * Track it on vhd->clients: otherwise
						 * vhost teardown can't cancel its suls or
						 * free it, and the DIST-STUB-READY pass
						 * that kick-starts connections finds
						 * nothing
						 */
						lws_dll2_add_tail(&conn->list, &vhd->clients);

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
			lws_sul_schedule(vhd->cx, 0, &conn->sul, fetch_local_hash, 1);
		} lws_end_foreach_dll_safe(p, tp);
	}
	break;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		/*
		 * As the protocol named by the stub's parent_protocol_name,
		 * we must keep the stub's spawn object informed about its
		 * stdwsi closing, so it can track and clean up after the
		 * child process
		 */
		if (vhd && vhd->stub_mgr && lws_stub_get_lsp(vhd->stub_mgr))
			lws_spawn_stdwsi_closed(
				lws_stub_get_lsp(vhd->stub_mgr), wsi);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;

		lws_dll2_remove(&vhd->list_vhd);

		/*
		 * Drop any hash request still pointing at a conn before the
		 * conns are freed below
		 */
		lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(&vhd->clients)) {
			struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);

			lws_stub_request_cancel(vhd->stub_mgr, conn->hash_req);
			conn->hash_req = 0;
		} lws_end_foreach_dll(p);

		if (vhd->stub_mgr)
			lws_stub_destroy(&vhd->stub_mgr);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(&vhd->clients)) {
			struct dist_client_conn *conn = lws_container_of(p, struct dist_client_conn, list);

			lws_sul_cancel(&conn->sul);
			lws_sul_cancel(&conn->sul_timeout);

			/*
			 * The client wsi holds conn as its opaque user data,
			 * and both it and the vhost we created for it outlive
			 * this callback.  Detach the wsi and take the vhost
			 * down (asynchronously, if wsi are still bound to it)
			 * before conn goes away, or the close or connection
			 * error callback re-arms conn->sul inside freed
			 * memory
			 */
			if (conn->wsi) {
				lws_set_opaque_user_data(conn->wsi, NULL);
				conn->wsi = NULL;
			}
			if (conn->vh) {
				struct lws_vhost *cvh = conn->vh;

				conn->vh = NULL;
				/*
				 * If the whole context is going down, it
				 * destroys every vhost itself, and may already
				 * have freed this one
				 */
				if (!lws_context_is_being_destroyed(vhd->cx))
					lws_vhost_destroy(cvh);
			}

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

/*
 * Once per context, however many vhosts instantiate us.  Only our own stub
 * child has anything to do here: read the secret and the base_dir and
 * reload_cmd the parent hands it on stdin, and listen on the UDS the parent
 * will connect to.
 */
static int
cert_dist_client_init(struct lws_context *cx)
{
	const char *stub = lws_cmdline_option_cx(cx, "--lws-stub");
	char uds_path[256], payload[CDC_PAYLOAD_MAX + 1];
	struct cdc_payload_parse pp;
	struct lws_stub_config sc;
	struct lejp_ctx jctx;
	const char *orig_vh;
	int m;

	/*
	 * Only claim our own stub children.  The prefix must not be a prefix
	 * of any other plugin's stub name, or we consume its stdin secret and
	 * break its UDS listener
	 */
	if (!stub || strncmp(stub, "certdistcli-", 12))
		return 0;

	orig_vh = stub + 12;

	cdc_stub = calloc(1, sizeof(*cdc_stub));
	if (!cdc_stub)
		return 1;

	cdc_stub->cx = cx;
	lws_strncpy(cdc_stub->vh_name, orig_vh, sizeof(cdc_stub->vh_name));
	/* preload defaults in case there is no payload */
	lws_strncpy(cdc_stub->base_dir, "/etc/lwsws-pki",
		    sizeof(cdc_stub->base_dir));

	lws_snprintf(uds_path, sizeof(uds_path),
		     "/var/run/lws-cert-dist-stub-%s.sock", orig_vh);

	memset(&sc, 0, sizeof(sc));
	sc.cx		= cx;
	sc.stub_name	= stub;
	sc.uds_path	= uds_path;
	sc.protocols	= stub_protocols;

	memset(payload, 0, sizeof(payload));
	if (lws_stub_server_init(&sc, cdc_stub->secret, payload,
				 sizeof(payload) - 1))
		goto bail;

	/* the parent packs {"base_dir":...,"reload_cmd":...} as the payload */
	if (!payload[0])
		return 0; /* nothing from the parent, keep the defaults */

	memset(&pp, 0, sizeof(pp));
	pp.v = cdc_stub;
	lejp_construct(&jctx, cdc_payload_cb, &pp, cdc_payload_paths,
		       LWS_ARRAY_SIZE(cdc_payload_paths));
	m = lejp_parse(&jctx, (uint8_t *)payload, (int)strlen(payload));
	lejp_destruct(&jctx);
	if (m) {
		/* incomplete (LEJP_CONTINUE) is as bad as malformed */
		lwsl_err("%s: stub '%s': bad payload from parent (%d)\n",
			 __func__, stub, m);
		goto bail;
	}

	return 0;

bail:
	lws_explicit_bzero(cdc_stub->secret, sizeof(cdc_stub->secret));
	free(cdc_stub);
	cdc_stub = NULL;

	return 1;
}

static void
cert_dist_client_deinit(struct lws_context *cx)
{
	(void)cx;

	if (!cdc_stub)
		return;

	lws_explicit_bzero(cdc_stub->secret, sizeof(cdc_stub->secret));
	free(cdc_stub);
	cdc_stub = NULL;
}

LWS_VISIBLE const lws_plugin_protocol_t lws_cert_dist_client = {
	.hdr = {
		.name           = "cert dist client",
		._class         = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic      = LWS_PLUGIN_API_MAGIC,
	},
	.protocols              = protocols,
	.count_protocols        = LWS_ARRAY_SIZE(protocols),
	.init                   = cert_dist_client_init,
	.deinit                 = cert_dist_client_deinit,
};
