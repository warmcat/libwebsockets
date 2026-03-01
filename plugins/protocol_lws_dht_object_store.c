/*
 * lws-dht-object-store
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a DHT node that can store and retrieve data/files
 * using the lws-dht UDP data transport, encapsulated as a plugin.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <libwebsockets/lws-dht.h>

#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <sys/stat.h>

#define LWS_DHT_FRAGMENT_SIZE		(1024 * 1024)
#define LWS_DHT_STORE_GENHASH		LWS_GENHASH_TYPE_SHA256

struct vhd_dht_store {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_dht_ctx		*dht;
	lws_sorted_usec_list_t		sul_bulk;
	lws_sorted_usec_list_t		sul_speed;
	lws_sorted_usec_list_t		sul_stats;
	lws_xos_t			xos;
	uint64_t			bulk_sent;
	uint64_t			bulk_total;
	uint64_t			last_bulk_sent;
	struct lws_dll2_owner		fragments;
	char				current_fragment_hash[LWS_GENHASH_LARGEST * 2 + 1];

	uint32_t			manifest_fragments_requested;
	uint32_t			manifest_fragments_completed;
	uint64_t			manifest_next_offset;

	uint8_t				bulk_fragment_checking:1;
	uint8_t				cli_bulk:1;
	uint8_t				gen_manifest:1;
	int				bulk_fragment_check_retries;

	uint64_t			bulk_heads[4];
	uint64_t			bulk_seq_offset;

	char				manifest_hashes[16][65];
	char				manifest_line[128];
	int				manifest_pos;
	uint32_t			manifest_fragments_total;
	int				bulk_fd;
	int				main_result;

	const char			*storage_path;
	const char			*dht_iface;
	int				dht_port;
	const char			*target_ip;
	int				target_port;
	const char			*cli_put_file;
	const char			*cli_get_hash;

	lws_dht_store_completion_cb_t cb_completion;
	void				*cb_closure;

	struct lws_jwk			jwk;
	struct lws_jwk			*trusted_keys;
	const char			*policy_allow;
	const char			*policy_deny;
	const char			*cli_jwk_path;
	char				pending_nonce[16];
	uint64_t			pending_nonce_time;
	int				test_handshake;
};

struct dht_fragment {
	lws_dll2_t			list;
	struct lws_genhash_ctx		ctx;
	char				safe_hash[LWS_GENHASH_LARGEST * 2 + 1];
	uint64_t			total_len;
	uint64_t			received_len;
	int				fd;
	int				hash_init_done;
	int				retries;
};

typedef struct lws_dht_ts {
	lws_dll2_t			list;
	struct lws_transport_sequencer	*ts;
	struct sockaddr_storage		sa;
	size_t				salen;
	struct lws_dht_ctx		*ctx;
} lws_dht_ts_t;

/* --- Helpers --- */

static struct dht_fragment *
find_fragment(struct vhd_dht_store *vhd, const char *hash)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *frag = lws_container_of(d, struct dht_fragment, list);
		if (!strcmp(frag->safe_hash, hash))
			return frag;
	} lws_end_foreach_dll(d);

	return NULL;
}

static void
sul_put_cb(void *v);

static void
sul_get_cb(void *v);

static int
jwk_load_or_gen(struct vhd_dht_store *vhd)
{
	if (!vhd->cli_jwk_path || !*vhd->cli_jwk_path)
		vhd->cli_jwk_path = "dht.jwk";

	if (!lws_jwk_load(&vhd->jwk, vhd->cli_jwk_path, NULL, NULL)) {
		lwsl_notice("Loaded JWK from %s\n", vhd->cli_jwk_path);
		return 0;
	}

	lwsl_notice("Generating new EC JWK to %s\n", vhd->cli_jwk_path);
	if (lws_jwk_generate(vhd->context, &vhd->jwk, LWS_GENCRYPTO_KTY_EC, 256, "P-256")) {
		lwsl_err("JWK generation failed\n");
		return 1;
	}

	if (lws_jwk_save(&vhd->jwk, vhd->cli_jwk_path)) {
		lwsl_err("Unable to save JWK to %s\n", vhd->cli_jwk_path);
		return 1;
	}

	return 0;
}

/* --- Verb Handlers --- */

static int
verb_put_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_dht_get_closure(ctx);
	struct dht_fragment *frag;
	char path[256];
	int n;

	lwsl_user("%s: PUT %s offset %llu len %llu\n", __func__, msg->hash, msg->offset, msg->len);

	frag = find_fragment(vhd, msg->hash);
	if (!frag) {
		frag = calloc(1, sizeof(*frag));
		if (!frag) return -1;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));
		frag->total_len = msg->len;
		lws_dll2_add_tail(&frag->list, &vhd->fragments);
		
		lws_snprintf(path, sizeof(path), "%s/%s", vhd->storage_path, frag->safe_hash);
		mkdir(vhd->storage_path, 0777);
		frag->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (frag->fd < 0) {
			lwsl_err("%s: Failed to open %s\n", __func__, path);
			lws_dll2_remove(&frag->list);
			free(frag);
			return -1;
		}

		if (lws_genhash_init(&frag->ctx, LWS_DHT_STORE_GENHASH)) {
			close(frag->fd);
			lws_dll2_remove(&frag->list);
			free(frag);
			return -1;
		}
		frag->hash_init_done = 1;
	}

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) return -1;
	n = (int)write(frag->fd, msg->payload, msg->payload_len);
	if (n < 0 || (size_t)n != msg->payload_len) {
		lwsl_err("%s: write failed\n", __func__);
		return -1;
	}

	if (lws_genhash_update(&frag->ctx, msg->payload, msg->payload_len)) return -1;
	frag->received_len += msg->payload_len;

	if (frag->received_len >= frag->total_len) {
		uint8_t hash[LWS_GENHASH_LARGEST];
		char hex[LWS_GENHASH_LARGEST * 2 + 1];

		lws_genhash_destroy(&frag->ctx, hash);
		frag->hash_init_done = 0;
		lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hex, sizeof(hex));
		lwsl_user("%s: Finished %s, hash %s\n", __func__, frag->safe_hash, hex);

		close(frag->fd);
		frag->fd = -1;

		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 0);
	}

	/* Send ACK */
	{
		char ack[128];
		lws_dht_msg_gen(ack, sizeof(ack), "ACK", msg->hash, msg->offset, msg->payload_len);
		lws_dht_send_data(ctx, from, ack, strlen(ack));
	}

	return 0;
}

static int
verb_get_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_dht_get_closure(ctx);
	char path[256], *buf;
	int fd, n;
	size_t blen = 1024 + 1024;

	lwsl_user("%s: GET %s offset %llu len %llu\n", __func__, msg->hash, msg->offset, msg->len);

	lws_snprintf(path, sizeof(path), "%s/%s", vhd->storage_path, msg->hash);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: Not found %s\n", __func__, path);
		return -1;
	}

	buf = malloc(blen);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (lseek(fd, (off_t)msg->offset, SEEK_SET) < 0) goto fail;
	n = (int)read(fd, buf + 1024, 1024);
	if (n < 0) goto fail;

	lws_dht_msg_gen(buf, 1024, "RSP", msg->hash, msg->offset, (unsigned long long)n);
	lws_dht_send_data(ctx, from, buf, 1024 + (size_t)n);

	free(buf);
	close(fd);
	return 0;

fail:
	free(buf);
	close(fd);
	return -1;
}

static int
verb_ack_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_dht_get_closure(ctx);
	lwsl_user("%s: ACK for %s offset %llu\n", __func__, msg->hash, msg->offset);
	if (vhd->cli_put_file) {
		vhd->bulk_sent += msg->len;
		if (vhd->bulk_sent >= vhd->bulk_total) {
			lwsl_user("PUT complete\n");
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 0);
		} else {
			sul_put_cb(vhd);
		}
	}
	return 0;
}

static int
verb_rsp_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_dht_get_closure(ctx);
	struct dht_fragment *frag;

	lwsl_user("%s: RSP for %s offset %llu len %llu payload %zu\n", __func__, msg->hash, msg->offset, msg->len, msg->payload_len);

	frag = find_fragment(vhd, msg->hash);
	if (!frag) {
		frag = calloc(1, sizeof(*frag));
		if (!frag) return -1;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));
		frag->total_len = msg->len;
		lws_dll2_add_tail(&frag->list, &vhd->fragments);
		
		frag->fd = open(frag->safe_hash, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (frag->fd < 0) return -1;
		if (lws_genhash_init(&frag->ctx, LWS_DHT_STORE_GENHASH)) return -1;
		frag->hash_init_done = 1;
	}

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) return -1;
	if (write(frag->fd, msg->payload, msg->payload_len) < 0) return -1;
	if (lws_genhash_update(&frag->ctx, msg->payload, msg->payload_len)) return -1;

	frag->received_len += msg->payload_len;
	if (frag->received_len >= frag->total_len) {
		lwsl_user("GET complete for %s\n", frag->safe_hash);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 0);
	}

	return 0;
}

static int
verb_nonce_req_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)lws_dht_get_closure(ctx);
	char buf[128];

	lwsl_user("%s\n", __func__);
	lws_get_random(vhd->context, vhd->pending_nonce, sizeof(vhd->pending_nonce));
	lws_dht_msg_gen(buf, sizeof(buf), "NONC_RSP", "0000", 0, 0);
	lws_dht_send_data(ctx, from, buf, strlen(buf));
	return 0;
}

static int
verb_nonce_rsp_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
	return 0;
}

static int
verb_sign_req_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		      const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
	return 0;
}

	return 0;
}

/* --- Core Callback --- */

static void
cb_dht(void *closure, int event, const lws_dht_hash_t *info_hash,
       const void *data, size_t data_len, const struct sockaddr *from,
       size_t fromlen)
{
	(void)closure;
	switch (event) {
	case LWS_DHT_EVENT_DATA:
		/* Already handled by verbs if it was a verb-based message */
		break;
	default:
		break;
	}
}

/* --- Timers --- */

static void
sul_stats_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_store *vhd = lws_container_of(sul, struct vhd_dht_store, sul_stats);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 5 * LWS_US_PER_SEC);
}

static void
sul_put_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	char hash_hex[LWS_GENHASH_LARGEST * 2 + 1], header[256], packet[1500];
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;
	struct sockaddr_in sin;
	int fd, n, hlen;
	struct stat st;
	char buf[1500];

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)vhd->target_port);
	inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr);

	lwsl_user("Sending PUT %s to %s:%d\n", vhd->cli_put_file, vhd->target_ip, vhd->target_port);

	fd = open(vhd->cli_put_file, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", vhd->cli_put_file);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	fstat(fd, &st);
	n = (int)read(fd, buf + 256, 1024);
	close(fd);

	if (n < 0) return;

	if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&ctx, buf + 256, (size_t)n) ||
	    lws_genhash_destroy(&ctx, hash)) {
		lwsl_err("Hash calculation failed\n");
		return;
	}
	lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hash_hex, sizeof(hash_hex));

	hlen = lws_dht_msg_gen((char *)header, sizeof(header), "PUT",
			hash_hex, vhd->bulk_sent, (unsigned long long)st.st_size);
	memcpy(packet, header, (size_t)hlen);
	memcpy(packet + hlen, buf + 256, (size_t)n);

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, packet, (size_t)(hlen + n));
}

static void
sul_get_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	struct sockaddr_in sin;
	char buf[256];

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)vhd->target_port);
	inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr);

	lwsl_user("Sending GET %s to %s:%d\n", vhd->cli_get_hash, vhd->target_ip, vhd->target_port);

	lws_dht_msg_gen(buf, sizeof(buf), "GET", vhd->cli_get_hash, 0, 1024);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, buf, strlen(buf));
}

/* --- Protocol Handler --- */

static int
callback_dht_object_store(struct lws* wsi, enum lws_callback_reasons reason,
	void* user, void* in, size_t len)
{
	struct vhd_dht_store* vhd = (struct vhd_dht_store*)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options* pvo;
	lws_dht_info_t vdi;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	struct lws_protocols *protocol = (struct lws_protocols *)lws_get_protocol(wsi);
	const char *p = NULL;

	switch (reason) {
	case LWS_CALLBACK_DHT_VERB_DISPATCH: {
		struct lws_dht_verb_dispatch_args *args =
			(struct lws_dht_verb_dispatch_args *)in;

		if (!strcmp(args->msg->verb, "PUT")) return verb_put_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "GET")) return verb_get_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "ACK")) return verb_ack_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "RSP")) return verb_rsp_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_REQ")) return verb_nonce_req_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_RSP")) return verb_nonce_rsp_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "SIGN_REQ")) return verb_sign_req_handler(args->ctx, args->msg, args->from, args->fromlen);
		
		return -1;
	}

	case LWS_CALLBACK_PROTOCOL_INIT: {
		struct lws_dht_verb store_verbs[] = {
			{ "PUT", protocol },
			{ "GET", protocol },
			{ "ACK", protocol },
			{ "RSP", protocol },
			{ "NONC_REQ", protocol },
			{ "NONC_RSP", protocol },
			{ "SIGN_REQ", protocol },
		};
		lwsl_user("%s: LWS_CALLBACK_PROTOCOL_INIT\n", __func__);
		vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(struct vhd_dht_store));
		if (!vhd) return -1;
		vhd->context = lws_get_context(wsi); vhd->vhost = vhost;
		lws_dll2_owner_clear(&vhd->fragments);
		vhd->bulk_fd = -1;
		vhd->main_result = 1;

		/* Default settings */
		vhd->target_ip = "127.0.0.1";
		vhd->target_port = 5000;
		vhd->dht_port = 5000;
		vhd->storage_path = "./dht-store";

		/* Override from PVOs */
		lws_pvo_get_str(in, "dht-storage-path", &vhd->storage_path);
		if ((pvo = lws_pvo_search(in, "dht-port"))) vhd->dht_port = atoi(pvo->value);
		lws_pvo_get_str(in, "dht-iface", &vhd->dht_iface);
		lws_pvo_get_str(in, "target-ip", &vhd->target_ip);
		if ((pvo = lws_pvo_search(in, "target-port")) && pvo->value && pvo->value[0]) vhd->target_port = atoi(pvo->value);
		if (!lws_pvo_get_str(in, "put-file", &p) && p && p[0]) vhd->cli_put_file = p;
		if (!lws_pvo_get_str(in, "get-hash", &p) && p && p[0]) vhd->cli_get_hash = p;
		if (!lws_pvo_get_str(in, "bulk", &p) && p && p[0]) vhd->cli_bulk = 1;
		if (!lws_pvo_get_str(in, "gen-manifest", &p) && p && p[0]) vhd->gen_manifest = 1;
		if (!lws_pvo_get_str(in, "dht-jwk", &p) && p && p[0]) vhd->cli_jwk_path = p;
		if (!lws_pvo_get_str(in, "dht-policy-allow", &p) && p && p[0]) vhd->policy_allow = p;
		if (!lws_pvo_get_str(in, "dht-policy-deny", &p) && p && p[0]) vhd->policy_deny = p;
		if (!lws_pvo_get_str(in, "dht-test-handshake", &p) && p && p[0]) vhd->test_handshake = 1;

		if ((pvo = lws_pvo_search(in, "completion-cb"))) vhd->cb_completion = (lws_dht_store_completion_cb_t)(void *)pvo->value;
		if ((pvo = lws_pvo_search(in, "completion-cb-arg"))) vhd->cb_closure = (void *)pvo->value;

		if (jwk_load_or_gen(vhd)) return -1;

		memset(&vdi, 0, sizeof(vdi));
		vdi.vhost = vhost;
		vdi.port = vhd->dht_port;
		vdi.ipv6 = 1;
		vdi.cb = cb_dht;
		vdi.closure = vhd;
		vdi.iface = vhd->dht_iface;

		vhd->dht = lws_dht_create(&vdi);
		if (!vhd->dht) {
			lwsl_vhost_err(vhd->vhost, "%s: failed to create DHT", __func__);
			return -1;
		}

		/* Register our "verbs" */
		lws_dht_register_verbs(vhd->dht, store_verbs, LWS_ARRAY_SIZE(store_verbs));

		lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 100 * LWS_US_PER_MS);

		if (vhd->test_handshake) {
			lwsl_user("Initiating Handshake TEST... sending NONCE_REQ\n");
			char buf[1024];
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = htons((uint16_t)vhd->target_port);
			inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr);

			lws_dht_msg_gen(buf, sizeof(buf), "NONC_REQ", "0000", 0, 0);
			lws_dht_send_data(vhd->dht, (const struct sockaddr *)&sin, buf, strlen(buf));
		} else if (vhd->cli_put_file) {
			lwsl_user("%s: Starting PUT task\n", __func__);
			sul_put_cb(vhd);
		} else if (vhd->cli_get_hash) {
			lwsl_user("%s: Starting GET task\n", __func__);
			sul_get_cb(vhd);
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_sul_cancel(&vhd->sul_stats);
			lws_sul_cancel(&vhd->sul_speed);
			lws_sul_cancel(&vhd->sul_bulk);
			lws_jwk_destroy(&vhd->jwk);
			lws_start_foreach_dll_safe(struct lws_dll2*, d, d1, lws_dll2_get_head(&vhd->fragments)) {
				struct dht_fragment* frag = lws_container_of(d, struct dht_fragment, list);
				if (frag->hash_init_done)
					lws_genhash_destroy(&frag->ctx, NULL);
				if (frag->fd >= 0)
					close(frag->fd);
				lws_dll2_remove(&frag->list);
				free(frag);
			} lws_end_foreach_dll_safe(d, d1);
			if (vhd->dht)
				lws_dht_destroy(&vhd->dht);
			if (vhd->bulk_fd >= 0)
				close(vhd->bulk_fd);
		}
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE const struct lws_protocols lws_dht_object_store_protocols[] = {
	{ "lws-dht-object-store", callback_dht_object_store, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

LWS_VISIBLE const lws_plugin_protocol_t protocol_lws_dht_object_store = {
	.hdr = {
		.name = "lws dht object store",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = lws_dht_object_store_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_object_store_protocols) - 1,
	.extensions = NULL,
	.count_extensions = 0,
};
