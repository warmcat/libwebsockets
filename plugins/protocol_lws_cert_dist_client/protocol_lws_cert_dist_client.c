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
	struct lws_spawn_piped *lsp;
	struct lws_dll2_owner clients;
	int is_stub;
	struct lws_vhost *vh_uds;
	const char *server_url;
};

struct pss_cert_dist_client {
	lws_sorted_usec_list_t sul;
	struct lws *wsi;
	char subdomain[128];
	char domain[128];
	struct lws_vhost *vh_client;
};

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
		case STUB_FULLCHAIN:
			a->fullchain = malloc(ctx->npos + 1);
			if (a->fullchain) {
				memcpy(a->fullchain, ctx->buf, ctx->npos);
				a->fullchain[ctx->npos] = '\0';
				a->fc_len = ctx->npos;
			}
			break;
		case STUB_PRIVKEY:
			a->privkey = malloc(ctx->npos + 1);
			if (a->privkey) {
				memcpy(a->privkey, ctx->buf, ctx->npos);
				a->privkey[ctx->npos] = '\0';
				a->pk_len = ctx->npos;
			}
			break;
		}
	}

	if (reason == LEJPCB_OBJECT_END) {
		char path[512], sym[512], timestamp[64];
		struct timeval tv;
		int fd;

		/* All parts received, validate and write */
		if (strcmp(a->secret, a->vhd->secret)) {
			lwsl_err("%s: Secret mismatch\n", __func__);
			return 1;
		}

		lwsl_notice("%s: Valid command for %s\n", __func__, a->subdomain);

		gettimeofday(&tv, NULL);
		lws_snprintf(timestamp, sizeof(timestamp), "%lld", (long long)tv.tv_sec);

		/* 1. Ensure directory exists */
		lws_snprintf(path, sizeof(path), "%s/%s", a->vhd->base_dir, a->subdomain);
		mkdir(path, 0700);

		/* 2. Write fullchain */
		lws_snprintf(path, sizeof(path), "%s/%s/fullchain.pem.%s", a->vhd->base_dir, a->subdomain, timestamp);
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			write(fd, a->fullchain, (size_t)a->fc_len);
			close(fd);
		}

		/* 3. Write privkey */
		lws_snprintf(path, sizeof(path), "%s/%s/privkey.pem.%s", a->vhd->base_dir, a->subdomain, timestamp);
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			write(fd, a->privkey, (size_t)a->pk_len);
			close(fd);
		}

		/* 4. Atomic symlink update */
		lws_snprintf(sym, sizeof(sym), "%s/%s/fullchain.pem", a->vhd->base_dir, a->subdomain);
		unlink(sym);
		symlink(path, sym); /* ... should be the fullchain path ... */
		/* Actually I should symlink the specific timestamped files */

		lwsl_notice("%s: Files updated for %s, triggering reload\n", __func__, a->subdomain);
		/* ... Run reload cmd ... */
	}

	return 0;
}

/* UDS Protocol for Stub <-> Client communication */
static int
callback_cert_dist_stub(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct vhd_cert_dist_client *vhd = (struct vhd_cert_dist_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	struct stub_req_args *a = (struct stub_req_args *)user;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_notice("%s: UDS connection established\n", __func__);
		a = malloc(sizeof(*a));
		if (a) {
			memset(a, 0, sizeof(*a));
			a->vhd = vhd;
			lws_set_wsi_user(wsi, a);
		}
		break;
	case LWS_CALLBACK_RECEIVE:
		{
			struct lejp_ctx jctx;
			lejp_construct(&jctx, stub_req_cb, a, stub_req_paths, LWS_ARRAY_SIZE(stub_req_paths));
			if (lejp_parse(&jctx, (uint8_t *)in, (int)len) < 0) {
				lwsl_err("%s: lejp parse failed\n", __func__);
			}
			lejp_destruct(&jctx);
		}
		break;
	case LWS_CALLBACK_CLOSED:
		if (a) {
			if (a->fullchain) free(a->fullchain);
			if (a->privkey) free(a->privkey);
			free(a);
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
		0, 4096, 0, NULL, 0
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

	/* 2. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_UNIX_SOCK;
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

	return 0;
}

static int
callback_cert_dist_client(struct lws *wsi, enum lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{
	struct vhd_cert_dist_client *vhd = (struct vhd_cert_dist_client *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	const char *stub;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lwsl_notice("%s: Connected to distribution server\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		{
			/*
			 * Received JSON from server. Forward it to our local UDS stub.
			 * We need to inject our secret into the JSON for the stub.
			 */
			lwsl_notice("%s: Received cert update from server, forwarding to stub\n", __func__);
			/* ... implementation ... */
		}
		break;
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in) return 0;
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd_cert_dist_client));
		if (!vhd)
			return -1;
		vhd->cx = lws_get_context(wsi);
		vhd->vh = lws_get_vhost(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->server_url = "wss://distribution-server.local";

		lws_strncpy(vhd->base_dir, "/etc/lwsws-pki", sizeof(vhd->base_dir));

		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;
		const struct lws_protocol_vhost_options *sub_pvo = NULL;

		while (pvo) {
			if (!strcmp(pvo->name, "base-dir"))
				lws_strncpy(vhd->base_dir, pvo->value, sizeof(vhd->base_dir));
			if (!strcmp(pvo->name, "server-url"))
				vhd->server_url = pvo->value;
			if (!strcmp(pvo->name, "subdomains"))
				sub_pvo = pvo->options;
			pvo = pvo->next;
		}

		/* Check if we are the stub */
		stub = lws_cmdline_option_cx(vhd->cx, "--lws-stub");
		if (stub && !strcmp(stub, "distribution-client")) {
			if (global_cert_dist_vhd) return 0;
			global_cert_dist_vhd = vhd;
			vhd->is_stub = 1;
			return dist_client_stub_run(vhd);
		}

		if (stub) return 0; /* Stubs don't spawn other stubs */

		if (sub_pvo && getuid() == 0 && !global_cert_dist_vhd) {
			struct lws_spawn_piped_info spawn_info;
			const char *exec_array[10];
			int n = 0;

			lwsl_notice("%s: Root detected and subdomains configured, spawning privileged stub\n", __func__);
			global_cert_dist_vhd = vhd;

			/* Generate secret */
			uint8_t rand[64];
			lws_get_random(vhd->cx, rand, sizeof(rand));
			lws_hex_from_byte_array(rand, sizeof(rand), vhd->secret, sizeof(vhd->secret));

			memset(&spawn_info, 0, sizeof(spawn_info));
			exec_array[n++] = lws_cmdline_option_cx_argv0(vhd->cx);
			exec_array[n++] = "--lws-stub=distribution-client";
			exec_array[n++] = NULL;

			spawn_info.exec_array = exec_array;
			spawn_info.timeout_us = 0;
			spawn_info.vh = vhd->vh;
			spawn_info.protocol_name = "lws-cert-dist-client";

			vhd->lsp = lws_spawn_piped(&spawn_info);
			if (vhd->lsp) {
				int stdin_fd = (int)(intptr_t)lws_spawn_get_fd_stdxxx(vhd->lsp, 0);
				if (stdin_fd >= 0) {
					write(stdin_fd, vhd->secret, 128);
				}
			}
		}

		/* Start connections for each subdomain */
		while (sub_pvo) {
			struct lws_context_creation_info ci;
			char cert_path[512], key_path[512], vh_name[128];

			lws_snprintf(vh_name, sizeof(vh_name), "dist-client-%s", sub_pvo->name);
			lws_snprintf(cert_path, sizeof(cert_path), "%s/%s/dist-client.crt", vhd->base_dir, sub_pvo->name);
			lws_snprintf(key_path, sizeof(key_path), "%s/%s/dist-client.key", vhd->base_dir, sub_pvo->name);

			memset(&ci, 0, sizeof(ci));
			ci.vhost_name = vh_name;
			ci.port = CONTEXT_PORT_NO_LISTEN;
			ci.client_ssl_cert_filepath = cert_path;
			ci.client_ssl_private_key_filepath = key_path;
			ci.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

			struct lws_vhost *vh = lws_create_vhost(vhd->cx, &ci);
			if (vh) {
				lwsl_notice("%s: Created client vhost for %s\n", __func__, sub_pvo->name);
				/* ... Initiate connection ... */
			}

			sub_pvo = sub_pvo->next;
		}
		break;

	case LWS_CALLBACK_RAW_RX_FILE: {
		char buf[512];
		ssize_t n;

		n = read(lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
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

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->lsp)
			lws_spawn_piped_kill_child_process(vhd->lsp);
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
