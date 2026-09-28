#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

struct vhd_cert_dist_server {
	struct lws_context                  *cx;
	struct lws_vhost                    *vh;
	const struct lws_protocols          *protocol;
	char                                pki_root[256];
	struct lws_dll2_owner               connections;
#if defined(LWS_WITH_DIR)
	struct lws_dll2_owner               watches; /* struct cds_watch */
#endif

	struct lws_dll2                     list_vhd;
	char                                vh_name[128];

	char                                secret[129];
	struct lws_stub_manager             *stub_mgr;
};

static struct lws_dll2_owner active_server_vhds;

/*
 * Stub child only: what the plugin init (cert_dist_server_init()) was handed
 * by the parent on stdin, the secret and our pki_root.  Requests arrive on
 * the UDS listener vhost, where no vhost instantiates us, so they find their
 * config through this.
 */
static struct vhd_cert_dist_server *cds_stub;

/*
 * The parent hands its stub {"pki_root":"..."} as the stub extra payload.
 * Room for the field JSON-escaped at the worst case of 6 chars per input
 * char, and the rest of the object
 */
#define CDS_PAYLOAD_MAX \
	(sizeof(((struct vhd_cert_dist_server *)0)->pki_root) * 6 + 32)

static const char * const cds_payload_paths[] = {
	"pki_root",
};

struct cds_payload_parse {
	struct vhd_cert_dist_server	*v;
	size_t				len; /* of the string being collected */
};

static signed char
cds_payload_cb(struct lejp_ctx *ctx, char reason)
{
	struct cds_payload_parse *pp = (struct cds_payload_parse *)ctx->user;

	if (!ctx->path_match)
		return 0;

	switch (reason) {
	case LEJPCB_VAL_STR_START:
		pp->len = 0;
		pp->v->pki_root[0] = '\0';
		return 0;

	case LEJPCB_VAL_STR_CHUNK:
	case LEJPCB_VAL_STR_END:
		/* a value we cannot hold whole is refused, not truncated */
		if (pp->len + ctx->npos >= sizeof(pp->v->pki_root))
			return -1;
		memcpy(pp->v->pki_root + pp->len, ctx->buf, ctx->npos);
		pp->len += ctx->npos;
		pp->v->pki_root[pp->len] = '\0';
		return 0;

	default:
		/* anything but a string there is not from our parent */
		if (reason & LEJP_FLAG_CB_IS_VALUE)
			return -1;
		return 0;
	}
}

struct pss_cert_dist_server {
	struct lws_dll2                     list;
	struct lws                          *wsi;
	char                                subdomain[128];
	char                                domain[128];
	int                                 established;
	int                                 needs_cert_update;

	lws_stub_req_h                      stub_req;
	char                                *uds_tx;
	int                                 uds_tx_len;
	int                                 uds_tx_pos;

	char                                *uds_rx;
	int                                 uds_rx_len;
	int                                 uds_rx_pos;
	char                                hash[65];
};

/*
 * The client cert CN ends up as a path component under the pki root, and
 * inside the JSON we hand to the privileged stub.  Only accept something
 * that can be a hostname, so it can neither escape the pki root nor break
 * out of its JSON string.
 */

static int
cert_dist_valid_name(const char *s, size_t max)
{
	size_t n = strlen(s);
	const char *p;

	if (!n || n >= max)
		return 0;

	if (*s == '.' || *s == '-' || s[n - 1] == '.' || s[n - 1] == '-')
		return 0;

	for (p = s; *p; p++) {
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '.' || *p == '-'))
			return 0;
		if (*p == '.' && p[1] == '.')
			return 0;
	}

	return 1;
}

/*
 * The cert hash is a SHA-1 in hex: anything else cannot match and has no
 * business being interpolated into the stub request JSON
 */

static int
cert_dist_valid_hash(const char *s, size_t len)
{
	size_t n;

	if (!len || len > 40)
		return 0;

	for (n = 0; n < len; n++)
		if (!((s[n] >= '0' && s[n] <= '9') ||
		      (s[n] >= 'a' && s[n] <= 'f') ||
		      (s[n] >= 'A' && s[n] <= 'F')))
			return 0;

	return 1;
}

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
		if (fstat(fd, &st) == 0) {
			buf = malloc((size_t)st.st_size + 1);
			if (buf) {
				if (read(fd, buf, (size_t)st.st_size) == (ssize_t)st.st_size)
					buf[st.st_size] = '\0';
				else {
					free(buf);
					buf = NULL;
				}
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
	char                                complete; /* all of it arrived */
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

	if (reason == LEJPCB_OBJECT_END) {
		a->complete = 1;
		lws_callback_on_writable(a->wsi);
	}

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

/*
 * Forget one request, so the connection is ready for the next: the parent
 * sends the next one on the same connection once it has had our answer
 */
static void
cds_stub_req_release(struct pss_stub_server *pss)
{
	if (pss->parser_valid)
		lejp_destruct(&pss->jctx);
	pss->parser_valid = 0;

	if (pss->response) {
		/* it may be holding a private key */
		lws_explicit_bzero(pss->response + LWS_PRE,
				   (size_t)pss->response_len);
		free(pss->response);
		pss->response = NULL;
	}

	lws_explicit_bzero(&pss->args, sizeof(pss->args));
}

static int
callback_cert_dist_server_stub(struct lws *wsi, enum lws_callback_reasons reason,
			       void *user, void *in, size_t len)
{
	struct vhd_cert_dist_server *vhd = cds_stub;
	struct pss_stub_server *pss = (struct pss_stub_server *)user;

	if (!vhd) return -1;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_notice("%s: Stub accepted new UDS connection\n", __func__);
		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_notice("%s: Stub received %d bytes\n", __func__, (int)len);
		if (pss->args.complete) {
			/*
			 * The parent waits for our answer before it sends
			 * anything else
			 */
			lwsl_err("%s: request while one is being answered\n",
				 __func__);
			return -1;
		}
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
				/* answered, ready for the next */
				cds_stub_req_release(pss);
			break;
		}

		/* We need to generate the response */
		if (!pss->parser_valid || !pss->args.complete)
			break;

		if (strlen(pss->args.secret) != strlen(vhd->secret) || lws_timingsafe_bcmp(pss->args.secret, vhd->secret, (uint32_t)strlen(vhd->secret))) {
			lwsl_err("%s: Secret mismatch (received secret len %d, expected len %d)\n", __func__, (int)strlen(pss->args.secret), (int)strlen(vhd->secret));
			return -1;
		}

		if (!cert_dist_valid_name(pss->args.subdomain,
					  sizeof(pss->args.subdomain)) ||
		    !cert_dist_valid_name(pss->args.domain,
					  sizeof(pss->args.domain))) {
			lwsl_err("%s: Bad subdomain or domain\n", __func__);
			return -1;
		}

		/*
		 * Authorisation: the peer authenticated with a cert its CN
		 * says is for <subdomain>, but that alone must not be enough
		 * to hand out <domain>'s private key.  We require that this
		 * server was explicitly provisioned to distribute <domain> to
		 * <subdomain>, by the presence of the distribution client
		 * cert we issued for it.  Fail closed.
		 */
		{
			char auth_path[512];
			struct stat sta;

			lws_snprintf(auth_path, sizeof(auth_path),
				     "%s/domains/%s/dist-client/"
				     "distribution-client-%s.crt",
				     vhd->pki_root, pss->args.domain,
				     pss->args.subdomain);

			if (stat(auth_path, &sta) || !S_ISREG(sta.st_mode)) {
				lwsl_err("%s: '%s' not authorized for '%s' "
					 "(no %s)\n", __func__,
					 pss->args.subdomain,
					 pss->args.domain, auth_path);
				return -1;
			}
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
				if (strlen(current_hash) == strlen(pss->args.hash) && !lws_timingsafe_bcmp(current_hash, pss->args.hash, (uint32_t)strlen(current_hash))) {
					lwsl_notice("%s: Hash matches %s, returning unchanged\n", __func__, pss->args.hash);
					free(cert_buf);
					cert_buf = NULL;

					pss->response = malloc(LWS_PRE + 256);
					if (!pss->response)
						return -1;

					pss->response_len = lws_snprintf(pss->response + LWS_PRE, 256,
						"{\"subdomain\":\"%s\",\"fullchain\":\"\",\"privkey\":\"\"}", pss->args.subdomain);
					pss->response_pos = 0;
					/*
					 * We are inside the writeable that
					 * generated it: ask for another one to
					 * actually send it, or the requester
					 * never hears back
					 */
					lws_callback_on_writable(wsi);
				}
			}

			if (cert_buf) {
				lwsl_notice("%s: Looking for newest key in %s\n", __func__, key_path);
				key_buf = read_newest_file_in_dir(key_path, ".key");

				if (key_buf) {
					lwsl_notice("%s: Found both cert and key for %s, preparing response\n", __func__, pss->args.domain);
					size_t jlen = (strlen(cert_buf) * 2) + (strlen(key_buf) * 2) + 512;
					pss->response = malloc(LWS_PRE + jlen);
					if (!pss->response) {
						free(key_buf);
						free(cert_buf);

						return -1;
					}
					{
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

	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_CLOSED:
		if (pss)
			cds_stub_req_release(pss);
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



/*
 * We take the stub reply verbatim and have no interest in its contents, we
 * just forward it to the ws client that asked for it.
 *
 * The stub layer calls us with NULL / 0 exactly once when the request is
 * over, however it ended, which is where our handle for it dies.  The pss
 * cancels the request if it goes away first, so we can only be called while
 * it is alive.
 */

static void
cert_dist_server_raw_cb(const char *in, size_t len, void *user)
{
	struct pss_cert_dist_server *pss =
			(struct pss_cert_dist_server *)user;

	if (!in) {
		pss->stub_req = 0;
		/* the cert changed again while we were asking */
		if (pss->needs_cert_update)
			lws_callback_on_writable(pss->wsi);
		return;
	}

	if (!pss->uds_rx) {
		pss->uds_rx = malloc(LWS_PRE + 65536);
		if (!pss->uds_rx)
			return;
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
/*
 * We push a renewed cert and key to the links for its domain as soon as they
 * change on disk.  Directory monitors are not recursive and only name the
 * entry that changed, so each provisioned domain gets one on each of the two
 * dirs the stub reads its cert and key from.
 */

struct cds_watch {
	struct lws_dll2			list;	/* vhd->watches */
	lws_sorted_usec_list_t		sul;	/* debounce */
	struct vhd_cert_dist_server	*vhd;
	struct lws_dir_notify		*dn_crt;
	struct lws_dir_notify		*dn_key;
	char				domain[128];
};

/*
 * A renewal arrives as a new cert and a new key: let it finish landing before
 * we push, so a link is not handed the new cert with the old key
 */
#define CDS_WATCH_SETTLE_US	(500 * LWS_US_PER_MS)

static void
cds_watch_settled(lws_sorted_usec_list_t *sul)
{
	struct cds_watch *w = lws_container_of(sul, struct cds_watch, sul);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&w->vhd->connections)) {
		struct pss_cert_dist_server *pss = lws_container_of(d,
					struct pss_cert_dist_server, list);

		if (!strcmp(pss->domain, w->domain)) {
			lwsl_notice("%s: %s changed, updating %s\n", __func__,
				    w->domain, pss->subdomain);
			pss->needs_cert_update = 1;
			lws_callback_on_writable(pss->wsi);
		}
	} lws_end_foreach_dll(d);
}

static int
cds_suffix(const char *name, const char *suffix)
{
	size_t n = strlen(name), sl = strlen(suffix);

	return n > sl && !strcmp(name + n - sl, suffix);
}

/*
 * The monitors give us the name of the entry that changed in their dir, or
 * where the platform cannot say (kqueue), an empty name for "something in it"
 */

static void
cds_watch_changed(struct cds_watch *w, const char *name, int is_file,
		  const char *suffix)
{
	/* the stub only ever reads *<suffix> from there */
	if (!name[0] || (is_file && cds_suffix(name, suffix)))
		lws_sul_schedule(w->vhd->cx, 0, &w->sul, cds_watch_settled,
				 CDS_WATCH_SETTLE_US);
}

static void
cds_watch_crt_cb(const char *name, int is_file, void *user)
{
	cds_watch_changed((struct cds_watch *)user, name, is_file, ".crt");
}

static void
cds_watch_key_cb(const char *name, int is_file, void *user)
{
	cds_watch_changed((struct cds_watch *)user, name, is_file, ".key");
}

static void
cds_watch_destroy(struct cds_watch *w)
{
	lws_sul_cancel(&w->sul);
	/*
	 * The monitors are adopted on the system vhost, not ours, so they
	 * outlive the vhd they point at unless we take them down here
	 */
	if (w->dn_crt)
		lws_dir_notify_destroy(&w->dn_crt);
	if (w->dn_key)
		lws_dir_notify_destroy(&w->dn_key);
	lws_dll2_remove(&w->list);
	free(w);
}

/*
 * lws_dir() callback over <pki_root>/domains: watch each domain that is
 * provisioned to be distributed, ie, that has a dist-client dir
 */

static int
cds_watch_domain(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct vhd_cert_dist_server *vhd = (struct vhd_cert_dist_server *)user;
	char path[512];
	struct cds_watch *w;
	struct stat s;

	if (lde->type != LDOT_DIR ||
	    !cert_dist_valid_name(lde->name, sizeof(w->domain)))
		return 0; /* includes . and .. */

	lws_snprintf(path, sizeof(path), "%s/%s/dist-client", dirpath,
		     lde->name);
	if (stat(path, &s) || !S_ISDIR(s.st_mode))
		return 0; /* nobody gets this one */

	w = calloc(1, sizeof(*w));
	if (!w)
		return 1;

	w->vhd = vhd;
	lws_strncpy(w->domain, lde->name, sizeof(w->domain));
	lws_dll2_add_tail(&w->list, &vhd->watches);

	lws_snprintf(path, sizeof(path), "%s/%s/certs/production/crt",
		     dirpath, lde->name);
	w->dn_crt = lws_dir_notify_create(vhd->cx, path, cds_watch_crt_cb, w);
	lws_snprintf(path, sizeof(path), "%s/%s/certs/production/key",
		     dirpath, lde->name);
	w->dn_key = lws_dir_notify_create(vhd->cx, path, cds_watch_key_cb, w);

	if (!w->dn_crt || !w->dn_key)
		lwsl_vhost_warn(vhd->vh, "%s: unable to watch %s, its "
				"renewals will only reach links made after "
				"them\n", __func__, lde->name);

	return 0;
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

		/*
		 * A stub process, ours or anybody's, never takes the server
		 * role: our own stub's side is set up once by the plugin init
		 */
		if (stub)
			return 0;

		/* Only initialize unprivileged side if the plugin is explicitly enabled on this vhost */
		if (!in)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_cert_dist_server));
		if (!vhd) return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		lws_strncpy(vhd->vh_name, vh_name, sizeof(vhd->vh_name));

		lws_strncpy(vhd->pki_root, "/var/dnssec", sizeof(vhd->pki_root));
		const char *stub_dir = "/var/run";
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "pki-root"))
				lws_strncpy(vhd->pki_root, pvo->value, sizeof(vhd->pki_root));
			if (!strcmp(pvo->name, "stub-dir"))
				stub_dir = pvo->value;
			pvo = pvo->next;
		}

		/*
		 * The stub child listens wherever we say, lws_stub_spawn()
		 * tells it on its cmdline
		 */
		char uds_path[256];
		if (lws_snprintf(uds_path, sizeof(uds_path),
				 "%s/lws-cert-dist-server-stub-%s.sock",
				 stub_dir, vh_name) >= (int)sizeof(uds_path) - 1) {
			lwsl_vhost_err(lws_get_vhost(wsi), "%s: stub-dir too long\n",
				       __func__);
			return -1;
		}

		char stub_name[256];
		lws_snprintf(stub_name, sizeof(stub_name), "certdistsrv-%s", vh_name);

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
			sc.parent_protocol_name = "lws-cert-dist-server";

			/* hand the stub child our pki_root via the extra payload */
			char ep[CDS_PAYLOAD_MAX], epr[sizeof(vhd->pki_root) * 6];

			lws_json_purify(epr, vhd->pki_root, (int)sizeof(epr),
					NULL);
			sc.extra_payload = ep;
			sc.extra_payload_len = (size_t)lws_snprintf(ep, sizeof(ep),
					"{\"pki_root\":\"%s\"}", epr) + 1;

			vhd->stub_mgr = lws_stub_spawn(&sc);
			if (!vhd->stub_mgr)
				return -1;
		}

		lws_dll2_add_tail(&vhd->list_vhd, &active_server_vhds);

#if defined(LWS_WITH_DIR)
		{
			/*
			 * Under lwsws we are still privileged here, and the
			 * monitors keep working after privileges are dropped
			 */
			char scan_path[512];

			lws_snprintf(scan_path, sizeof(scan_path), "%s/domains",
				     vhd->pki_root);
			lws_dir(scan_path, vhd, cds_watch_domain);
		}
#endif
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_dll2_remove(&vhd->list_vhd);
#if defined(LWS_WITH_DIR)
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					lws_dll2_get_head(&vhd->watches)) {
				cds_watch_destroy(lws_container_of(d,
						struct cds_watch, list));
			} lws_end_foreach_dll_safe(d, d1);
#endif
			/*
			 * Every ws connection is gone by now, so it already
			 * cancelled any stub request of its own; this retires
			 * whatever else is still queued
			 */
			if (vhd->stub_mgr)
				lws_stub_destroy(&vhd->stub_mgr);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED: {
		uint8_t buf[256];
		union lws_tls_cert_info_results *ir = (union lws_tls_cert_info_results *)buf;
		char *p;

		if (!vhd)
			return -1;

		/*
		 * The len argument is the space available for ir->ns.name[]
		 * alone, not the size of the array backing the union
		 * (see lws-x509.h)
		 */
		if (lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					   ir, sizeof(buf) - sizeof(*ir) +
					       sizeof(ir->ns.name))) {
			lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, (unsigned char *)"No CN in client cert", 20);
			return -1;
		}

		if (!cert_dist_valid_name(ir->ns.name, sizeof(pss->subdomain))) {
			lwsl_wsi_warn(wsi, "%s: client cert CN is not a "
					   "hostname\n", __func__);
			lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION,
					 (unsigned char *)"Bad CN in client cert", 21);
			return -1;
		}

		lws_strncpy(pss->subdomain, ir->ns.name, sizeof(pss->subdomain));
		pss->wsi = wsi;

		{
			int dots = 0;
			char *q;
			for (q = pss->subdomain; *q; q++) if (*q == '.') dots++;
			if (dots > 1) {
				p = (char *)strchr(pss->subdomain, '.');
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
		if (vhd && pss->established && !pss->stub_req && !pss->needs_cert_update) {
			/* Timer expired without getting a hash, fetch anyway */
			pss->needs_cert_update = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		if (vhd && pss->established && !pss->needs_cert_update) {
			/*
			 * Expecting {"hash":"..."}.  lws only NUL-terminates
			 * the ws rx buffer if the frame had a payload, so the
			 * parse must be bounded by len; and we must not write
			 * into the rx buffer either.
			 */
			size_t alen = 0;
			const char *h = in && len ?
				lws_json_simple_find((const char *)in, len,
						     "\"hash\":", &alen) : NULL;

			if (h && cert_dist_valid_hash(h, alen)) {
				lws_strnncpy(pss->hash, h, alen,
					     sizeof(pss->hash));
				lwsl_notice("%s: Received hash from client: %s\n", __func__, pss->hash);
			}
			/* Cancel timer and fetch */
			lws_set_timer_usecs(wsi, LWS_SET_TIMER_USEC_CANCEL);
			pss->needs_cert_update = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLOSED:
		if (vhd && pss && pss->established) {
			lws_dll2_remove(&pss->list);
			if (pss->uds_tx) free(pss->uds_tx);
			if (pss->uds_rx) {
				/* it may hold the private key */
				lws_explicit_bzero(pss->uds_rx + LWS_PRE,
						   (size_t)pss->uds_rx_len);
				free(pss->uds_rx);
			}

			/*
			 * lws is about to free the pss: a stub request we
			 * queued may still be waiting or in flight and
			 * pointing at it.  Cancel it, so nothing can reach
			 * the pss through it and any reply is discarded.
			 */
			lws_stub_request_cancel(vhd->stub_mgr, pss->stub_req);
			pss->stub_req = 0;
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd)
                        break;
		if (!pss || !pss->established)
                        return -1;

		/* If we have the payload from the UDS, write it to WSS */
		if (pss->uds_rx && pss->uds_rx_len > 0) {
			int m = lws_write(wsi, (unsigned char *)pss->uds_rx + LWS_PRE + pss->uds_rx_pos, (size_t)(pss->uds_rx_len - pss->uds_rx_pos), LWS_WRITE_TEXT);
			if (m < 0) return -1;
			pss->uds_rx_pos += m;
			if (pss->uds_rx_pos < pss->uds_rx_len)
				lws_callback_on_writable(wsi);
			else {
				lwsl_notice("%s: Sent complete cert update to WSS client for %s\n", __func__, pss->domain);
				/* it holds the private key */
				lws_explicit_bzero(pss->uds_rx + LWS_PRE,
						   (size_t)pss->uds_rx_len);
				free(pss->uds_rx);
				pss->uds_rx = NULL;
				/* Keep connection open for future updates */
				if (pss->needs_cert_update && !pss->stub_req)
					/* it changed again meanwhile */
					lws_callback_on_writable(wsi);
			}
			break;
		}

		/* If we haven't asked UDS yet, ask UDS */
		if (!pss->stub_req && pss->needs_cert_update) {
			pss->needs_cert_update = 0;

			if (!vhd->stub_mgr) {
				lwsl_err("%s: No stub manager present on vhost '%s', cannot request certs!\n",
					__func__, lws_get_vhost_name(lws_get_vhost(wsi)));
				return -1;
			}

			const char *sec = lws_stub_get_secret(vhd->stub_mgr);
			char tx[512];

			/*
			 * subdomain and domain came from the client cert CN
			 * and passed cert_dist_valid_name(), and hash passed
			 * cert_dist_valid_hash(), so none of them can contain
			 * anything needing JSON escaping here
			 */
			lwsl_notice("%s: Requesting cert for %s from server UDS stub\n", __func__, pss->domain);
			if (pss->hash[0]) {
				lws_snprintf(tx, sizeof(tx),
					"{\"secret\":\"%s\",\"subdomain\":\"%s\",\"domain\":\"%s\",\"hash\":\"%s\"}",
					sec ? sec : "", pss->subdomain, pss->domain, pss->hash);
			} else {
				lws_snprintf(tx, sizeof(tx),
					"{\"secret\":\"%s\",\"subdomain\":\"%s\",\"domain\":\"%s\"}",
					sec ? sec : "", pss->subdomain, pss->domain);
			}

			pss->stub_req = lws_stub_request_h(vhd->stub_mgr, tx,
							   NULL, 0, NULL,
							   cert_dist_server_raw_cb,
							   pss);
			if (!pss->stub_req) {
				lwsl_err("%s: lws_stub_request failed\n", __func__);
				pss->needs_cert_update = 1;
				lws_set_timer_usecs(wsi, 1 * LWS_USEC_PER_SEC);
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
		lwsl_notice("[DIST-SERVER-STUB] %s", buf);
		break;
	}

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

/*
 * Once per context, however many vhosts instantiate us.  Only our own stub
 * child has anything to do here: read the secret and our pki_root the parent
 * hands it on stdin, and listen on the UDS the parent will connect to.
 */
static int
cert_dist_server_init(struct lws_context *cx)
{
	const char *stub = lws_cmdline_option_cx(cx, "--lws-stub");
	char payload[CDS_PAYLOAD_MAX + 1];
	struct cds_payload_parse pp;
	struct lws_stub_config sc;
	struct lejp_ctx jctx;
	const char *orig_vh;
	int m;

	/*
	 * Only claim our own stub children.  The prefix must not be a prefix
	 * of any other plugin's stub name, or we consume its stdin secret and
	 * break its UDS listener
	 */
	if (!stub || strncmp(stub, "certdistsrv-", 12))
		return 0;

	orig_vh = stub + 12;

	cds_stub = calloc(1, sizeof(*cds_stub));
	if (!cds_stub)
		return 1;

	cds_stub->cx = cx;
	lws_strncpy(cds_stub->vh_name, orig_vh, sizeof(cds_stub->vh_name));
	lws_strncpy(cds_stub->pki_root, "/var/dnssec",
		    sizeof(cds_stub->pki_root));

	/* sc.uds_path NULL: listen where the parent told us on our cmdline */
	memset(&sc, 0, sizeof(sc));
	sc.cx		= cx;
	sc.stub_name	= stub;
	sc.protocols	= stub_protocols;

	/*
	 * The parent packs {"pki_root":...} into the extra payload at spawn
	 * time, since the stub child cannot see PVOs
	 */
	memset(payload, 0, sizeof(payload));
	if (lws_stub_server_init(&sc, cds_stub->secret, payload,
				 sizeof(payload) - 1))
		goto bail;

	if (!payload[0])
		return 0; /* nothing from the parent, keep the default */

	memset(&pp, 0, sizeof(pp));
	pp.v = cds_stub;
	lejp_construct(&jctx, cds_payload_cb, &pp, cds_payload_paths,
		       LWS_ARRAY_SIZE(cds_payload_paths));
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
	lws_explicit_bzero(cds_stub->secret, sizeof(cds_stub->secret));
	free(cds_stub);
	cds_stub = NULL;

	return 1;
}

static void
cert_dist_server_deinit(struct lws_context *cx)
{
	(void)cx;

	if (!cds_stub)
		return;

	lws_explicit_bzero(cds_stub->secret, sizeof(cds_stub->secret));
	free(cds_stub);
	cds_stub = NULL;
}

/*
 * An application composing us into itself (LWS_PLUGIN_STATIC) gets the same
 * export, private to it, to list in its context creation info->plugins
 */
#if defined(LWS_PLUGIN_STATIC)
#define LWS_CDS_EXPORT static
#else
#define LWS_CDS_EXPORT LWS_VISIBLE
#endif

LWS_CDS_EXPORT const lws_plugin_protocol_t lws_cert_dist_server = {
	.hdr = {
		.name = "cert dist server",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
	},
	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
	.init = cert_dist_server_init,
	.deinit = cert_dist_server_deinit,
};
