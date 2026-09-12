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

#if !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif

#define LWS_DHT_FRAGMENT_SIZE		(1024 * 1024)
#define LWS_DHT_STORE_GENHASH		LWS_GENHASH_TYPE_SHA256

/*
 * Everything a PUT or a RSP costs us is attacker-chosen and unauthenticated,
 * so all of it has to be bounded.  These are the defaults; dht-max-object-size
 * and dht-store-quota override the sizes from pvos.
 */

#define LWS_DHT_STORE_MAX_OBJECT	(16u * 1024 * 1024)
	/**< largest object we will accept, in bytes */
#define LWS_DHT_STORE_QUOTA		(256u * 1024 * 1024)
	/**< total bytes we will commit to the store while we are up */
#define LWS_DHT_STORE_MAX_INFLIGHT	16
	/**< concurrent incomplete transfers, ie, open fds + genhash contexts */
#define LWS_DHT_STORE_XFER_TIMEOUT_US	(30 * LWS_US_PER_SEC)
	/**< an in-flight transfer that stalls this long is discarded */
#define LWS_DHT_STORE_REQ_TIMEOUT_US	(30 * LWS_US_PER_SEC)
	/**< how long a GET we sent stays outstanding for a RSP to match */
#define LWS_DHT_STORE_GET_BURST		32
	/**< GET responses we will emit back-to-back */
#define LWS_DHT_STORE_GET_REFILL_US	(1 * LWS_US_PER_SEC)
	/**< the GET token bucket refills by one burst per this interval */

struct vhd_dht_store {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_dht_ctx		*dht;
	lws_sorted_usec_list_t		sul_bulk;
	lws_sorted_usec_list_t		sul_speed;
	lws_sorted_usec_list_t		sul_stats;
	lws_sorted_usec_list_t		sul_get_tokens;
	lws_xos_t			xos;
	uint64_t			bulk_sent;
	uint64_t			bulk_total;
	uint64_t			last_bulk_sent;
	struct lws_dll2_owner		fragments;
	struct lws_dll2_owner		requests;

	uint64_t			max_object;
	uint64_t			quota;
	uint64_t			store_bytes;
	uint32_t			get_tokens;

	char				current_fragment_hash[LWS_GENHASH_LARGEST * 2 + 1];

	uint32_t			manifest_fragments_requested;
	uint32_t			manifest_fragments_completed;
	uint64_t			manifest_next_offset;

	uint8_t				bulk_fragment_checking:1;
	uint8_t				cli_bulk:1;
	uint8_t				gen_manifest:1;
	uint8_t				client_mode:1;
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
	int				cli_receiver;
};

struct dht_fragment {
	lws_dll2_t			list;
	lws_sorted_usec_list_t		sul_timeout;
	struct lws_genhash_ctx		ctx;
	struct vhd_dht_store		*vhd;
	struct sockaddr_storage		from_sa;
	size_t				from_salen;
	char				safe_hash[LWS_GENHASH_LARGEST * 2 + 1];
	uint64_t			total_len;
	uint64_t			received_len;
	int				fd;
	int				hash_init_done;
	int				retries;
};

/*
 * A GET we sent and are still willing to accept a RSP for.  RSP is only
 * honoured against one of these, so an unsolicited RSP cannot make us create
 * anything.
 */

struct dht_request {
	lws_dll2_t			list;
	lws_sorted_usec_list_t		sul_timeout;
	struct vhd_dht_store		*vhd;
	char				hash[LWS_GENHASH_LARGEST * 2 + 1];
};

/* --- Helpers --- */

static struct dht_fragment *
dht_obj_store_find_fragment(struct vhd_dht_store *vhd, const char *hash)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *frag = lws_container_of(d, struct dht_fragment, list);
		if (!strcmp(frag->safe_hash, hash))
			return frag;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * Compose <storage_path>/[.]<hash>[.part].  Truncation would alias two
 * different keys onto one path, so it is a hard failure.
 */

static int
dht_obj_store_path(struct vhd_dht_store *vhd, const char *hash, int partial,
		   char *path, size_t path_len)
{
	int n = lws_snprintf(path, path_len, "%s/%s%s%s", vhd->storage_path,
			     partial ? "." : "", hash, partial ? ".part" : "");

	if (n < 0 || (size_t)n >= path_len - 1) {
		lwsl_err("%s: storage path for %s too long\n", __func__, hash);

		return -1;
	}

	return 0;
}

static void
dht_obj_store_fragment_destroy(struct dht_fragment **pfrag)
{
	struct dht_fragment *frag = *pfrag;
	char path[256];

	if (!frag)
		return;

	*pfrag = NULL;

	lws_sul_cancel(&frag->sul_timeout);

	if (frag->hash_init_done) {
		lws_genhash_destroy(&frag->ctx, NULL);
		frag->hash_init_done = 0;
	}

	if (frag->fd >= 0) {
		close(frag->fd);
		frag->fd = -1;
	}

	/* an incomplete or failed transfer never becomes visible */

	if (!dht_obj_store_path(frag->vhd, frag->safe_hash, 1, path,
				sizeof(path)))
		unlink(path);

	lws_dll2_remove(&frag->list);
	free(frag);
}

static void
dht_obj_store_frag_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct dht_fragment *frag = lws_container_of(sul, struct dht_fragment,
						     sul_timeout);

	lwsl_notice("%s: discarding stalled transfer %s\n", __func__,
		    frag->safe_hash);

	dht_obj_store_fragment_destroy(&frag);
}

static struct dht_request *
dht_obj_store_find_request(struct vhd_dht_store *vhd, const char *hash)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->requests)) {
		struct dht_request *req = lws_container_of(d, struct dht_request, list);

		if (!strcmp(req->hash, hash))
			return req;
	} lws_end_foreach_dll(d);

	return NULL;
}

static void
dht_obj_store_request_destroy(struct dht_request **preq)
{
	struct dht_request *req = *preq;

	if (!req)
		return;

	*preq = NULL;

	lws_sul_cancel(&req->sul_timeout);
	lws_dll2_remove(&req->list);
	free(req);
}

static void
dht_obj_store_req_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct dht_request *req = lws_container_of(sul, struct dht_request,
						   sul_timeout);

	lwsl_notice("%s: GET for %s timed out\n", __func__, req->hash);

	dht_obj_store_request_destroy(&req);
}

static int
dht_obj_store_request_add(struct vhd_dht_store *vhd, const char *hash)
{
	struct dht_request *req;

	if (dht_obj_store_find_request(vhd, hash))
		return 0;

	req = calloc(1, sizeof(*req));
	if (!req)
		return -1;

	req->vhd = vhd;
	lws_strncpy(req->hash, hash, sizeof(req->hash));
	lws_dll2_add_tail(&req->list, &vhd->requests);
	lws_sul_schedule(vhd->context, 0, &req->sul_timeout,
			 dht_obj_store_req_timeout_cb,
			 LWS_DHT_STORE_REQ_TIMEOUT_US);

	return 0;
}

/*
 * dht-policy-allow / dht-policy-deny are comma-separated lists of lowercase
 * hex object-key prefixes.  Deny is checked first and wins; if an allow list
 * was given, the key must also match one of its prefixes.
 */

static int
dht_obj_store_policy_match(const char *list, const char *hash)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;

	if (!list || !*list)
		return 0;

	lws_tokenize_init(&ts, list, LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_NO_FLOATS |
				     LWS_TOKENIZE_F_COMMA_SEP_LIST);
	ts.len = strlen(list);

	do {
		e = lws_tokenize(&ts);

		if (e == LWS_TOKZE_TOKEN && ts.token_len &&
		    ts.token_len <= strlen(hash) &&
		    !strncmp(hash, ts.token, ts.token_len))
			return 1;

	} while (e > 0);

	return 0;
}

static int
dht_obj_store_policy_allows(struct vhd_dht_store *vhd, const char *hash)
{
	if (dht_obj_store_policy_match(vhd->policy_deny, hash))
		return 0;

	if (vhd->policy_allow && *vhd->policy_allow &&
	    !dht_obj_store_policy_match(vhd->policy_allow, hash))
		return 0;

	return 1;
}

static void
dht_obj_store_get_tokens_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_store *vhd = lws_container_of(sul, struct vhd_dht_store,
						     sul_get_tokens);

	vhd->get_tokens = LWS_DHT_STORE_GET_BURST;
	lws_sul_schedule(vhd->context, 0, &vhd->sul_get_tokens,
			 dht_obj_store_get_tokens_cb,
			 LWS_DHT_STORE_GET_REFILL_US);
}

static void
dht_obj_store_sul_put_cb(void *v);

static void
dht_obj_store_sul_get_cb(void *v);

static int
dht_obj_store_jwk_load_or_gen(struct vhd_dht_store *vhd)
{
	if (!vhd->cli_jwk_path || !*vhd->cli_jwk_path)
		vhd->cli_jwk_path = "dht.jwk";

	if (!lws_jwk_load(&vhd->jwk, vhd->cli_jwk_path, NULL, NULL)) {
		lwsl_notice("(obj store) Loaded JWK from %s\n", vhd->cli_jwk_path);
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

/*
 * Common receive path for PUT (a peer pushing an object at us) and RSP (the
 * answer to a GET we sent).  Everything arriving here is unauthenticated and
 * attacker-chosen, so
 *
 *  - the object size, the number of concurrent transfers and the total bytes
 *    we will ever commit to the store are all capped
 *  - chunks must arrive strictly in order, so there is no attacker-chosen
 *    lseek() (which could otherwise produce a petabyte-apparent-size file from
 *    one datagram) and the streaming digest actually describes the file
 *  - content goes to a .part temp file created O_EXCL | O_NOFOLLOW, and is
 *    only rename()d onto the key's name once its SHA-256 matches the key it
 *    was offered under, so we never serve content that does not hash to the
 *    content-address it is filed at, and never write through a planted symlink
 *  - a stalled transfer is discarded by a per-transfer timeout, releasing the
 *    fd, the digest context and the partial file
 *  - a transfer belongs to the address that opened it, since the key is public
 *    and transfers are otherwise found by key alone
 *
 * Returns 0 if the chunk was accepted, and sets *completed if that finished
 * and committed the object.
 */

static int
dht_obj_store_ingest(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd,
		     const struct lws_dht_msg *msg, const struct sockaddr *from,
		     size_t fromlen, int *completed)
{
	char path[256], final[256], hex[LWS_GENHASH_LARGEST * 2 + 1];
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct dht_fragment *frag;
	ssize_t w;

	*completed = 0;

	if (!msg->payload || !msg->payload_len)
		return -1;

	if (!dht_obj_store_policy_allows(vhd, msg->hash)) {
		lwsl_notice("%s: policy rejects %s\n", __func__, msg->hash);

		return -1;
	}

	frag = dht_obj_store_find_fragment(vhd, msg->hash);
	if (!frag) {
		if (msg->len < (unsigned long long)msg->payload_len ||
		    msg->len > vhd->max_object) {
			lwsl_notice("%s: %s: object len %llu out of range\n",
				    __func__, msg->hash, msg->len);

			return -1;
		}

		if (lws_dll2_count(&vhd->fragments) >= LWS_DHT_STORE_MAX_INFLIGHT) {
			lwsl_notice("%s: %u transfers already in flight\n",
				    __func__, lws_dll2_count(&vhd->fragments));

			return -1;
		}

		if (vhd->store_bytes + msg->len > vhd->quota) {
			lwsl_notice("%s: store quota %llu exhausted\n", __func__,
				    (unsigned long long)vhd->quota);

			return -1;
		}

		if (dht_obj_store_path(vhd, msg->hash, 1, path, sizeof(path)))
			return -1;

		if (mkdir(vhd->storage_path, 0700) < 0 && errno != EEXIST) {
			lwsl_err("%s: unable to create storage dir %s (errno %d)\n",
				 __func__, vhd->storage_path, errno);

			return -1;
		}

		frag = calloc(1, sizeof(*frag));
		if (!frag)
			return -1;

		frag->vhd = vhd;
		frag->fd = -1;
		frag->total_len = msg->len;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));

		if (from && fromlen && fromlen <= sizeof(frag->from_sa)) {
			memcpy(&frag->from_sa, from, fromlen);
			frag->from_salen = fromlen;
		}

		lws_dll2_add_tail(&frag->list, &vhd->fragments);

		/*
		 * Drop any leftover partial from an earlier, interrupted
		 * transfer (unlink() acts on the symlink, not its target) and
		 * then insist on creating the temp file ourselves
		 */

		unlink(path);

		frag->fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
				0600);
		if (frag->fd < 0) {
			lwsl_err("%s: unable to create %s (errno %d)\n",
				 __func__, path, errno);
			goto drop;
		}

		if (lws_genhash_init(&frag->ctx, LWS_DHT_STORE_GENHASH))
			goto drop;

		frag->hash_init_done = 1;
	} else {

		/*
		 * The key is public, so without this any peer can inject a
		 * chunk into (or, since a bad chunk drops the transfer, tear
		 * down) a transfer another peer opened.
		 */

		if (frag->from_salen && from &&
		    lws_sa46_compare_ads((const lws_sockaddr46 *)&frag->from_sa,
					 (const lws_sockaddr46 *)from)) {
			lwsl_notice("%s: %s: chunk from an address other than "
				    "the one that opened the transfer\n",
				    __func__, frag->safe_hash);

			return -1;
		}
	}

	if (msg->offset != frag->received_len ||
	    (unsigned long long)msg->payload_len >
				frag->total_len - frag->received_len) {
		lwsl_notice("%s: %s: chunk at %llu len %zu rejected, wanted %llu\n",
			    __func__, frag->safe_hash, msg->offset,
			    msg->payload_len,
			    (unsigned long long)frag->received_len);
		goto drop;
	}

	w = write(frag->fd, msg->payload, msg->payload_len);
	if (w < 0 || (size_t)w != msg->payload_len) {
		lwsl_err("%s: write failed (errno %d)\n", __func__, errno);
		goto drop;
	}

	if (lws_genhash_update(&frag->ctx, msg->payload, msg->payload_len))
		goto drop;

	frag->received_len += msg->payload_len;

	if (frag->received_len < frag->total_len) {
		lws_sul_schedule(vhd->context, 0, &frag->sul_timeout,
				 dht_obj_store_frag_timeout_cb,
				 LWS_DHT_STORE_XFER_TIMEOUT_US);

		return 0;
	}

	frag->hash_init_done = 0;
	if (lws_genhash_destroy(&frag->ctx, digest))
		goto drop;

	lws_hex_from_byte_array(digest,
				(size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH),
				hex, sizeof(hex));

	if (strcmp(hex, frag->safe_hash)) {
		lwsl_warn("%s: content hashes to %s but was offered as %s\n",
			  __func__, hex, frag->safe_hash);
		goto drop;
	}

	close(frag->fd);
	frag->fd = -1;

	if (dht_obj_store_path(vhd, frag->safe_hash, 1, path, sizeof(path)) ||
	    dht_obj_store_path(vhd, frag->safe_hash, 0, final, sizeof(final)))
		goto drop;

	/* rename() replaces the name, it does not follow a symlink at it */

	if (rename(path, final) < 0) {
		lwsl_err("%s: unable to commit %s (errno %d)\n", __func__,
			 final, errno);
		goto drop;
	}

	vhd->store_bytes += frag->total_len;

	lwsl_user("%s: %s committed, %llu bytes\n", __func__, frag->safe_hash,
		  (unsigned long long)frag->total_len);

	/* Notify anyone subscribed to this key */

	{
		uint8_t raw_hash[32];

		if (lws_hex_to_byte_array(frag->safe_hash, raw_hash,
					  (int)sizeof(raw_hash)) ==
						(int)sizeof(raw_hash)) {
			lws_dht_hash_t *id = lws_dht_hash_create(
					LWS_DHT_HASH_TYPE_SHA256,
					(int)sizeof(raw_hash), raw_hash);

			if (id) {
				lws_dht_notify_subscribers(ctx, id, digest,
							   NULL, 0);
				lws_dht_hash_destroy(&id);
			}
		}
	}

	*completed = 1;
	dht_obj_store_fragment_destroy(&frag);

	return 0;

drop:
	dht_obj_store_fragment_destroy(&frag);

	return -1;
}

static int
verb_put_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	char ack[128];
	int completed;

	if (dht_obj_store_ingest(ctx, vhd, msg, from, fromlen, &completed))
		return -1;

	if (completed && vhd->client_mode && vhd->cb_completion)
		vhd->cb_completion(vhd->cb_closure, 0);

	lws_dht_msg_gen(ack, sizeof(ack), "ACK", msg->hash, msg->offset,
			(unsigned long long)msg->payload_len);
	lws_dht_send_data(ctx, from, ack, strlen(ack));

	return 0;
}

static int
verb_get_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	char path[256], *buf;
	int fd, n;
	size_t blen = 1024 + 1024;
	int hlen;

	(void)fromlen;

	/*
	 * GET is unauthenticated, needs no reply from the peer to be useful,
	 * and answers ~100 bytes of request with ~1200 bytes at whatever
	 * source address the request claimed... ie, it is an amplifier aimed
	 * at a spoofable third party.  There is no per-peer state here to hang
	 * a per-source bucket on, so cap the responses we will emit at all.
	 */

	if (!vhd->get_tokens) {
		lwsl_notice("%s: GET response rate cap reached\n", __func__);

		return -1;
	}

	if (!dht_obj_store_policy_allows(vhd, msg->hash)) {
		lwsl_notice("%s: policy rejects GET %s\n", __func__, msg->hash);

		return -1;
	}

	if (dht_obj_store_path(vhd, msg->hash, 0, path, sizeof(path)))
		return -1;

	fd = open(path, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		/* peer-driven, so not an error level */
		lwsl_info("%s: not found %s\n", __func__, path);

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

	hlen = lws_dht_msg_gen(buf, 1024, "RSP", msg->hash, msg->offset, (unsigned long long)n);
	if (hlen < 0) goto fail;
	memmove((uint8_t *)buf + hlen, (uint8_t *)buf + 1024, (size_t)n);

	vhd->get_tokens--;
	lws_dht_send_data(ctx, from, buf, (size_t)hlen + (size_t)n);

	free(buf);
	close(fd);
	return 0;

fail:
	free(buf);
	close(fd);
	return -1;
}

static int
verb_ack_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	(void)ctx;
	(void)from;
	(void)fromlen;

	lwsl_user("%s: ACK for %s offset %llu\n", __func__, msg->hash, msg->offset);

	if (!vhd->client_mode)
		return 0;

	if (vhd->cli_put_file) {
		vhd->bulk_sent += msg->len;
		if (vhd->bulk_sent >= vhd->bulk_total) {
			lwsl_user("PUT complete\n");
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 0);
		} else {
			dht_obj_store_sul_put_cb(vhd);
		}
	} else if (vhd->cli_bulk || vhd->gen_manifest) {
		lwsl_user("BULK mock PUT complete\n");
		if (vhd->gen_manifest) {
			/* Write the hash to stdout so the receiver test can read it */
			printf("%s\n", msg->hash);
			fflush(stdout);
		}
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 0);
	}
	return 0;
}

static int
verb_rsp_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct dht_request *req;
	int completed;

	lwsl_user("%s: RSP for %s offset %llu len %llu payload %zu\n", __func__, msg->hash, msg->offset, msg->len, msg->payload_len);

	/*
	 * A RSP is only meaningful as the answer to a GET we sent.  Without
	 * this, any peer can hand us an unsolicited RSP and make us create and
	 * fill a file of its choosing, permanently costing an fd and a digest
	 * context per distinct key it invents.
	 */

	req = dht_obj_store_find_request(vhd, msg->hash);
	if (!req) {
		lwsl_notice("%s: unsolicited RSP for %s ignored\n", __func__,
			    msg->hash);

		return -1;
	}

	if (dht_obj_store_ingest(ctx, vhd, msg, from, fromlen, &completed))
		return -1;

	if (!completed)
		return 0;

	lwsl_user("%s: GET complete for %s\n", __func__, msg->hash);

	dht_obj_store_request_destroy(&req);

	if (vhd->client_mode && vhd->cb_completion)
		vhd->cb_completion(vhd->cb_closure, 0);

	return 0;
}

static int
verb_nonce_req_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	char buf[128];

	lwsl_user("%s\n", __func__);
	lws_get_random(vhd->context, vhd->pending_nonce, sizeof(vhd->pending_nonce));
	lws_dht_msg_gen(buf, sizeof(buf), "NONC_RSP", "0000", 0, 0);
	lws_dht_send_data(ctx, from, buf, strlen(buf));
	return 0;
}

static int
verb_nonce_rsp_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
	return 0;
}

static int
verb_sign_req_handler(struct lws_dht_ctx *ctx, struct vhd_dht_store *vhd, const struct lws_dht_msg *msg,
		      const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
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
dht_obj_store_sul_put_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	char hash_hex[LWS_GENHASH_LARGEST * 2 + 1], header[256], packet[1500];
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;
	lws_sockaddr46 sa46;
	int fd, n, hlen;
	struct stat st;
	char buf[1500];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		lwsl_err("Failed to parse target-ip: %s\n", vhd->target_ip);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

	lwsl_user("Sending PUT %s to %s:%d\n", vhd->cli_put_file, vhd->target_ip, vhd->target_port);

	fd = open(vhd->cli_put_file, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Cannot open %s\n", vhd->cli_put_file);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	if (fstat(fd, &st) < 0) {
		lwsl_err("Cannot stat %s\n", vhd->cli_put_file);
		close(fd);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	vhd->bulk_total = (uint64_t)st.st_size;

	/*
	 * The advertised key has to cover the whole object, not just the
	 * first chunk, so hash the file in a first pass before chunking it
	 * out; each pass then sends the bytes that belong at bulk_sent.
	 */
	{
		char hb[1024];
		int hm;

		if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH)) {
			lwsl_err("Hash calculation failed\n");
			close(fd);
			return;
		}

		while ((hm = (int)read(fd, hb, (size_t)sizeof(hb))) > 0)
			if (lws_genhash_update(&ctx, hb, (size_t)hm)) {
				lwsl_err("Hash calculation failed\n");
				lws_genhash_destroy(&ctx, NULL);
				close(fd);
				return;
			}

		if (hm < 0 || lws_genhash_destroy(&ctx, hash)) {
			lwsl_err("Hash calculation failed\n");
			close(fd);
			return;
		}
	}

	if (lseek(fd, (off_t)vhd->bulk_sent, SEEK_SET) < 0) {
		close(fd);
		return;
	}

	n = (int)read(fd, buf + 256, 1024);
	close(fd);

	if (n < 0) return;

	lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hash_hex, sizeof(hash_hex));

	hlen = lws_dht_msg_gen((char *)header, sizeof(header), "PUT",
			hash_hex, vhd->bulk_sent, (unsigned long long)st.st_size);
	memcpy(packet, header, (size_t)hlen);
	memcpy(packet + hlen, buf + 256, (size_t)n);

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, packet, (size_t)(hlen + n));
}

static void
dht_obj_store_sul_get_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	lws_sockaddr46 sa46;
	char buf[256];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		lwsl_err("Failed to parse target-ip: %s\n", vhd->target_ip);
		return;
	}
	sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

	lwsl_user("Sending GET %s to %s:%d\n", vhd->cli_get_hash, vhd->target_ip, vhd->target_port);

	/* only a RSP matching this is allowed to make us write anything */

	if (dht_obj_store_request_add(vhd, vhd->cli_get_hash))
		return;

	lws_dht_msg_gen(buf, sizeof(buf), "GET", vhd->cli_get_hash, 0, 1024);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, buf, strlen(buf));
}

static void
dht_obj_store_sul_bulk_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	char hash_hex[LWS_GENHASH_LARGEST * 2 + 1], header[256], packet[1500];
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;
	lws_sockaddr46 sa46;
	int hlen;
	char buf[1024];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		lwsl_err("Failed to parse target-ip: %s\n", vhd->target_ip);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

	lwsl_user("Sending mock bulk data to %s:%d\n", vhd->target_ip, vhd->target_port);

	memset(buf, 0x42, sizeof(buf));

	if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&ctx, buf, sizeof(buf)) ||
	    lws_genhash_destroy(&ctx, hash)) {
		lwsl_err("Hash calculation failed\n");
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hash_hex, sizeof(hash_hex));

	if (vhd->gen_manifest) {
		printf("%s\n", hash_hex);
		fflush(stdout);
	}

	hlen = lws_dht_msg_gen((char *)header, sizeof(header), "PUT",
			hash_hex, 0, sizeof(buf));
	if (hlen < 0) {
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}
	memcpy(packet, header, (size_t)hlen);
	memcpy(packet + hlen, buf, sizeof(buf));

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, packet, (size_t)hlen + sizeof(buf));
}

static void
dht_obj_store_sul_manifest_rcv_cb(void *v)
{
	struct vhd_dht_store *vhd = (struct vhd_dht_store *)v;
	char buf[128], *p;

	if (!fgets(buf, sizeof(buf), stdin)) {
		lwsl_err("Failed to read manifest from stdin\n");
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}

	p = (char *)strchr(buf, '\n');
	if (p) *p = 0;

	lws_strncpy(vhd->manifest_hashes[0], buf, sizeof(vhd->manifest_hashes[0]));
	vhd->cli_get_hash = vhd->manifest_hashes[0];
	lwsl_user("Receiver parsed hash: %s\n", vhd->cli_get_hash);

	dht_obj_store_sul_get_cb(vhd);
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
		const char *h;

		/*
		 * Verbs are only registered after our vhd exists, but the DHT
		 * ctx can be shared with other protocols on this vhost
		 */

		if (!args || !vhd)
			return -1;

		h = args->msg->hash;

		while (*h) {
			if (!(*h >= '0' && *h <= '9') && !(*h >= 'a' && *h <= 'f') && !(*h >= 'A' && *h <= 'F')) {
				lwsl_err("Invalid characters in DHT msg->hash\n");
				return -1;
			}
			h++;
		}

		if (!strcmp(args->msg->verb, "PUT")) return verb_put_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "GET")) return verb_get_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "ACK")) return verb_ack_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "RSP")) return verb_rsp_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_REQ")) return verb_nonce_req_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_RSP")) return verb_nonce_rsp_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "SIGN_REQ")) return verb_sign_req_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);

		return -1;
	}

	case LWS_CALLBACK_PROTOCOL_INIT: {
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-stub"))
			return 0;
		const char *store_verbs[] = {
			"PUT",
			"GET",
			"ACK",
			"RSP",
			"NONC_REQ",
			"NONC_RSP",
			"SIGN_REQ",
		};
		if (!in)
			return 0;
		if (!lws_pvo_search(in, "dht-port"))
			return 0;
		lwsl_user("%s: LWS_CALLBACK_PROTOCOL_INIT\n", __func__);
		vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(struct vhd_dht_store));
		if (!vhd) return -1;
		vhd->context = lws_get_context(wsi); vhd->vhost = vhost;
		lws_dll2_owner_clear(&vhd->fragments);
		lws_dll2_owner_clear(&vhd->requests);
		vhd->bulk_fd = -1;
		vhd->main_result = 1;

		/* Default settings */
		vhd->target_ip = "127.0.0.1";
		vhd->target_port = 49100;
		vhd->dht_port = 49100;
		vhd->storage_path = "./dht-store";
		vhd->max_object = LWS_DHT_STORE_MAX_OBJECT;
		vhd->quota = LWS_DHT_STORE_QUOTA;
		vhd->get_tokens = LWS_DHT_STORE_GET_BURST;

		/* Override from PVOs */
		if (lws_pvo_get_str(in, "dht-storage-path", &vhd->storage_path))
			lwsl_info("no pvo for dht-storage-path\n");
		if ((pvo = lws_pvo_search(in, "dht-port"))) vhd->dht_port = atoi(pvo->value);
		if (lws_pvo_get_str(in, "dht-iface", &vhd->dht_iface))
			lwsl_info("no pvo for dht-iface\n");
		if (lws_pvo_get_str(in, "target-ip", &vhd->target_ip))
			lwsl_info("no pvo for target-ip\n");
		if ((pvo = lws_pvo_search(in, "target-port")) && pvo->value && pvo->value[0]) vhd->target_port = atoi(pvo->value);
		if (!lws_pvo_get_str(in, "put-file", &p) && p && p[0]) vhd->cli_put_file = p;
		if (!lws_pvo_get_str(in, "get-hash", &p) && p && p[0]) vhd->cli_get_hash = p;
		if (!lws_pvo_get_str(in, "bulk", &p) && p && p[0]) vhd->cli_bulk = 1;
		if (!lws_pvo_get_str(in, "gen-manifest", &p) && p && p[0]) vhd->gen_manifest = 1;
		if (!lws_pvo_get_str(in, "dht-jwk", &p) && p && p[0]) vhd->cli_jwk_path = p;
		if (!lws_pvo_get_str(in, "dht-policy-allow", &p) && p && p[0]) vhd->policy_allow = p;
		if (!lws_pvo_get_str(in, "dht-policy-deny", &p) && p && p[0]) vhd->policy_deny = p;
		if (!lws_pvo_get_str(in, "dht-test-handshake", &p) && p && p[0]) vhd->test_handshake = 1;
		if (!lws_pvo_get_str(in, "receiver", &p) && p && p[0]) vhd->cli_receiver = 1;

		if ((pvo = lws_pvo_search(in, "dht-max-object-size")) && pvo->value && pvo->value[0])
			vhd->max_object = strtoull(pvo->value, NULL, 10);
		if ((pvo = lws_pvo_search(in, "dht-store-quota")) && pvo->value && pvo->value[0])
			vhd->quota = strtoull(pvo->value, NULL, 10);
		if (!vhd->max_object || vhd->max_object > LWS_DHT_STORE_MAX_OBJECT)
			vhd->max_object = LWS_DHT_STORE_MAX_OBJECT;
		if (vhd->quota < vhd->max_object)
			vhd->quota = vhd->max_object;

		/*
		 * The client / test modes are the only reason the completion
		 * callback exists.  Its pvo value is a raw function pointer,
		 * which is only meaningful when the pvo list was built
		 * programmatically... from a JSON config, pvo->value is a
		 * pointer into the parsed config text.  So only look at it at
		 * all when one of those modes was asked for, which keeps it
		 * out of reach of anything a server deployment can be driven
		 * into by a datagram.
		 */

		vhd->client_mode = !!(vhd->cli_put_file || vhd->cli_get_hash ||
				      vhd->cli_bulk || vhd->gen_manifest ||
				      vhd->cli_receiver || vhd->test_handshake);

		if (vhd->client_mode) {
			if ((pvo = lws_pvo_search(in, "completion-cb"))) vhd->cb_completion = (lws_dht_store_completion_cb_t)(void *)pvo->value;
			if ((pvo = lws_pvo_search(in, "completion-cb-arg"))) vhd->cb_closure = (void *)pvo->value;
		}

		if (dht_obj_store_jwk_load_or_gen(vhd)) {
			lwsl_vhost_warn(vhd->vhost, "Failed to load or generate JWK at '%s'\n", vhd->cli_jwk_path);
			return -1;
		}

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
		lws_dht_register_verbs(vhd->dht, store_verbs, LWS_ARRAY_SIZE(store_verbs), protocol);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 100 * LWS_US_PER_MS);
		lws_sul_schedule(vhd->context, 0, &vhd->sul_get_tokens,
				 dht_obj_store_get_tokens_cb,
				 LWS_DHT_STORE_GET_REFILL_US);

		lwsl_vhost_notice(vhd->vhost, "Attached lws-dht-object-store to UDP port %d (JWK at %s, store at %s)\n",
				 vhd->dht_port, vhd->cli_jwk_path, vhd->storage_path);

		if (vhd->test_handshake) {
			lwsl_user("Initiating Handshake TEST... sending NONCE_REQ\n");
			char buf[1024];
			lws_sockaddr46 sa46;
			if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
				lwsl_err("Failed to parse target-ip: %s\n", vhd->target_ip);
				break;
			}
			sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

			lws_dht_msg_gen(buf, sizeof(buf), "NONC_REQ", "0000", 0, 0);
			lws_dht_send_data(vhd->dht, (const struct sockaddr *)&sa46, buf, strlen(buf));
		} else if (vhd->cli_put_file) {
			lwsl_user("%s: Starting PUT task\n", __func__);
			dht_obj_store_sul_put_cb(vhd);
		} else if (vhd->cli_bulk || vhd->gen_manifest) {
			lwsl_user("%s: Starting BULK task\n", __func__);
			dht_obj_store_sul_bulk_cb(vhd);
		} else if (vhd->cli_receiver) {
			lwsl_user("%s: Starting RECEIVER task\n", __func__);
			dht_obj_store_sul_manifest_rcv_cb(vhd);
		}
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd) {
			lws_sul_cancel(&vhd->sul_stats);
			lws_sul_cancel(&vhd->sul_speed);
			lws_sul_cancel(&vhd->sul_bulk);
			lws_sul_cancel(&vhd->sul_get_tokens);
			lws_jwk_destroy(&vhd->jwk);
			lws_start_foreach_dll_safe(struct lws_dll2*, d, d1, lws_dll2_get_head(&vhd->fragments)) {
				struct dht_fragment* frag = lws_container_of(d, struct dht_fragment, list);

				dht_obj_store_fragment_destroy(&frag);
			} lws_end_foreach_dll_safe(d, d1);
			lws_start_foreach_dll_safe(struct lws_dll2*, d, d1, lws_dll2_get_head(&vhd->requests)) {
				struct dht_request* req = lws_container_of(d, struct dht_request, list);

				dht_obj_store_request_destroy(&req);
			} lws_end_foreach_dll_safe(d, d1);
			/* vhd->dht is already torn down by lws_vhost_destroy2() */
			vhd->dht = NULL;
			if (vhd->bulk_fd >= 0) {
				close(vhd->bulk_fd);
				vhd->bulk_fd = -1;
			}
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

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_dht_object_store = {
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
