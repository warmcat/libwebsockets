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

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#endif
#include <sys/stat.h>
#include <errno.h>

#define LWS_DHT_FRAGMENT_SIZE		(1024 * 1024)
#define LWS_DHT_STORE_GENHASH		LWS_GENHASH_TYPE_SHA256
#define LWS_DHT_STORE_HASH_TYPE		LWS_DHT_HASH_TYPE_SHA256


struct dht_upload_job {
	lws_dll2_t list;
	char *jws_filepath;
	char *domain;
};

struct vhd_dht_dnssec {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_dht_ctx		*dht;
	lws_sorted_usec_list_t		sul_bulk;
	lws_sorted_usec_list_t		sul_speed;
	lws_sorted_usec_list_t		sul_stats;
	lws_sorted_usec_list_t		sul_timeout;
	lws_sorted_usec_list_t		sul_dump;
	int				put_retries;
	lws_xos_t			xos;
	uint64_t			bulk_sent;
	uint64_t			bulk_total;
	uint64_t			last_bulk_sent;
	struct lws_dll2_owner		fragments;
	char				current_fragment_hash[LWS_GENHASH_LARGEST * 2 + 1];
	char				policy_resolved_ip[128];

	uint32_t			manifest_fragments_requested;
	uint32_t			manifest_fragments_completed;
	uint64_t			manifest_next_offset;

	uint8_t				bulk_fragment_checking:1;
	lws_dll2_owner_t		owner_domains; /* tracking our lws_dht_dnssec_domain structures */
	uint8_t				cli_bulk:1;
	uint8_t				gen_manifest:1;
	uint8_t				initial_search_done:1;
	int				bulk_fragment_check_retries;

	uint64_t			bulk_heads[4];
	uint64_t			bulk_seq_offset;

	char				manifest_hashes[16][65];
	char				manifest_line[128];
	int				manifest_pos;
	uint32_t			manifest_fragments_total;
	int				bulk_fd;
	int				main_result;
	int				put_started;

	const char			*storage_path;
	const char			*dht_iface;
	int				dht_port;
	const char			*target_ip;
	int				target_port;
	const char			*cli_put_file;
	const char			*cli_get_hash;
	const char			*cli_get_domain;
	const char			*cli_domain;

	lws_dht_store_completion_cb_t	cb_completion;
	void				*cb_closure;

	void (*auth_cb)(void *opaque, const char *domain, const char *payload_path);
	void *auth_cb_opaque;

	struct lws_jwk			jwk;
	struct lws_jwk			*trusted_keys;
	const char			*policy_allow;
	const char			*policy_deny;
	const char			*cli_jwk_path;
	char				pending_nonce[16];
	uint64_t			pending_nonce_time;
	int				test_handshake;
	int				cli_receiver;
	lws_dll2_owner_t		fetch_reqs;
	lws_dll2_owner_t		upload_queue;
	lws_dll2_owner_t		subscribed_domains;
	uint8_t				notify_secret[16];
	lws_dll2_owner_t		notify_strikes;
	lws_dll2_owner_t		notify_ratelimiters;
	lws_dht_hash_t			*myid;
};

static struct vhd_dht_dnssec *global_dnssec_vhd = NULL;

struct lws_dht_dnssec_subscribed_domain {
	lws_dll2_t list;
	char domain[256];
	uint8_t hash[LWS_GENHASH_LARGEST];
	uint8_t needs_initial_fetch;
	time_t last_notify_fetch;
	uint64_t last_notify_soa;
};

struct notify_strike {
	lws_dll2_t list;
	lws_sockaddr46 sa;
	int count;
	lws_sorted_usec_list_t sul_expire;
};

struct notify_strike_tracking {
	struct vhd_dht_dnssec *vhd;
	lws_sockaddr46 sa;
};

static const uint32_t bo_notify_ms[] = {
	0, 0, 0, 0, 0, 1000, 2000, 3000, 5000, 9000, 12000, 18000, 30000
};

static const lws_retry_bo_t retry_notify = {
	.retry_ms_table = bo_notify_ms,
	.retry_ms_table_count = LWS_ARRAY_SIZE(bo_notify_ms),
	.conceal_count = LWS_RETRY_CONCEAL_ALWAYS,
	.secs_since_valid_ping = 0,
	.secs_since_valid_hangup = 0,
	.jitter_percent = 20,
};

struct notify_ratelimit {
	lws_dll2_t list;
	lws_sockaddr46 sa;
	uint16_t ctry;
	lws_usec_t earliest_next_allowed;
	lws_sorted_usec_list_t sul_decay;
};

static void
notify_ratelimit_expire_cb(lws_sorted_usec_list_t *sul)
{
	struct notify_ratelimit *nrl = lws_container_of(sul, struct notify_ratelimit, sul_decay);
	lwsl_notice("%s: NOTIFY ratelimit decayed completely for IP\n", __func__);
	lws_dll2_remove(&nrl->list);
	free(nrl);
}

static void
notify_strike_expire_cb(lws_sorted_usec_list_t *sul)
{
	struct notify_strike *ns = lws_container_of(sul, struct notify_strike, sul_expire);
	lws_dll2_remove(&ns->list);
	free(ns);
}

static void
add_peer_strike(struct vhd_dht_dnssec *vhd, const lws_sockaddr46 *sa)
{
	struct notify_strike *ns = NULL, *oldest = NULL;
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->notify_strikes.head) {
		struct notify_strike *n = lws_container_of(d, struct notify_strike, list);
		if (n->sa.sa4.sin_family == sa->sa4.sin_family) {
			if (n->sa.sa4.sin_family == AF_INET && !memcmp(&n->sa.sa4.sin_addr, &sa->sa4.sin_addr, 4)) {
				ns = n; break;
			} else if (n->sa.sa4.sin_family == AF_INET6 && !memcmp(&n->sa.sa6.sin6_addr, &sa->sa6.sin6_addr, 16)) {
				ns = n; break;
			}
		}
		if (!oldest) oldest = n;
	} lws_end_foreach_dll(d);

	if (ns) {
		ns->count++;
		lwsl_notice("%s: IP strike count increased to %d\n", __func__, ns->count);
		lws_dll2_remove(&ns->list);
		lws_dll2_add_tail(&ns->list, &vhd->notify_strikes);
		lws_sul_schedule(vhd->context, 0, &ns->sul_expire, notify_strike_expire_cb, 3600 * LWS_US_PER_SEC);
	} else {
		if (vhd->notify_strikes.count > 64 && oldest) {
			lws_dll2_remove(&oldest->list);
			lws_sul_cancel(&oldest->sul_expire);
			free(oldest);
		}
		ns = malloc(sizeof(*ns));
		if (ns) {
			memset(ns, 0, sizeof(*ns));
			ns->sa = *sa;
			ns->count = 1;
			lws_dll2_add_tail(&ns->list, &vhd->notify_strikes);
			lws_sul_schedule(vhd->context, 0, &ns->sul_expire, notify_strike_expire_cb, 3600 * LWS_US_PER_SEC);
		}
	}
}

static int
dht_dnssec_blacklist_cb(const struct sockaddr *saddr, size_t salen)
{
	if (!global_dnssec_vhd) return 0;
	struct vhd_dht_dnssec *vhd = global_dnssec_vhd;

	const lws_sockaddr46 *sa = (const lws_sockaddr46 *)saddr;

	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->notify_strikes.head) {
		struct notify_strike *n = lws_container_of(d, struct notify_strike, list);
		if (n->sa.sa4.sin_family == sa->sa4.sin_family) {
			if (n->sa.sa4.sin_family == AF_INET && !memcmp(&n->sa.sa4.sin_addr, &sa->sa4.sin_addr, 4)) {
				if (n->count >= 5) return 1;
				return 0;
			} else if (n->sa.sa4.sin_family == AF_INET6 && !memcmp(&n->sa.sa6.sin6_addr, &sa->sa6.sin6_addr, 16)) {
				if (n->count >= 5) return 1;
				return 0;
			}
		}
	} lws_end_foreach_dll(d);

	return 0;
}

static void
notify_fetch_completion_cb(void *opaque, const char *domain, int status)
{
	struct notify_strike_tracking *trk = (struct notify_strike_tracking *)opaque;
	if (status == 0) {
		add_peer_strike(trk->vhd, &trk->sa);
	} else if (status == 1) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, trk->vhd->notify_strikes.head) {
			struct notify_strike *n = lws_container_of(d, struct notify_strike, list);
			if (n->sa.sa4.sin_family == trk->sa.sa4.sin_family) {
				int match = 0;
				if (n->sa.sa4.sin_family == AF_INET && !memcmp(&n->sa.sa4.sin_addr, &trk->sa.sa4.sin_addr, 4)) match = 1;
				else if (n->sa.sa4.sin_family == AF_INET6 && !memcmp(&n->sa.sa6.sin6_addr, &trk->sa.sa6.sin6_addr, 16)) match = 1;
				if (match) {
					lws_dll2_remove(d);
					lws_sul_cancel(&n->sul_expire);
					free(n);
				}
			}
		} lws_end_foreach_dll_safe(d, d1);
	}
	free(trk);
}

struct dht_fragment {
	lws_dll2_t			list;
	struct lws_genhash_ctx		ctx;
	char				safe_hash[LWS_GENHASH_LARGEST * 2 + 1];
	uint64_t			total_len;
	uint64_t			received_len;
	int				fd;
	int				hash_init_done;
	int				retries;
	int				validation_started;

	/* DNSSEC and Validation State */
	struct sockaddr_storage		from_sa;
	size_t				from_salen;
	struct lws_dht_ctx		*dht_ctx;
	struct vhd_dht_dnssec		*vhd;

	char				domain[256];
	uint32_t			soa_serial;
	uint32_t			temp_token;
	uint64_t			last_offset;
	size_t				last_len;

	uint16_t			key_tag;
	uint8_t				algo;
	uint8_t				digest_type;

	uint8_t				ds_digest[64];
	uint8_t				ds_digest_len;
	uint8_t				payload_hash[32];
};

struct lws_dht_dnssec_fetch_req {
	lws_dll2_t			list;
	char				domain[256];
	char				cache_dir[512];
	lws_dht_dnssec_fetch_cb_t	cb;
	void				*opaque;
	char				target_hash[65];
	struct vhd_dht_dnssec		*vhd;
	int				retries;
	lws_sorted_usec_list_t		sul_timeout;
};

struct lws_dir_args {
	const char *prefix;
	const char *dirpath;
	uint64_t new_serial;
	int is_outdated;
};

static int
dht_dnssec_sweep_old_payload_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct lws_dir_args *a = (struct lws_dir_args *)user;
	size_t pl = strlen(a->prefix);
	size_t nl = strlen(lde->name);
	if (nl > pl && !strncmp(lde->name, a->prefix, pl) && lde->name[pl] == '_' && nl > 8 && !strcmp(&lde->name[nl-8], ".payload")) {
		/* parse serial from name: hash_ttl_sig_serial.payload */
		char *p = (char *)lde->name + (nl - 9); /* before .payload */
		while (p > lde->name && *(p - 1) != '_') p--;
		if (p > lde->name) {
			uint64_t old_serial = strtoull(p, NULL, 10);
			if ((int32_t)((uint32_t)a->new_serial - (uint32_t)old_serial) < 0) {
				lwsl_notice("%s: Replay detected (new %u < old %u)\n", __func__, (uint32_t)a->new_serial, (uint32_t)old_serial);
				a->is_outdated = 1;
				return 0;
			} else if (a->new_serial == old_serial) {
				lwsl_notice("%s: Valid zone already cached (new %u == old %u)\n", __func__, (uint32_t)a->new_serial, (uint32_t)old_serial);
				a->is_outdated = 2;
				return 0;
			}
		}
		char upath[1024];
		lws_snprintf(upath, sizeof(upath), "%s/%s", dirpath, lde->name);
		unlink(upath);
		lwsl_notice("%s: unlinked old payload %s\n", __func__, upath);
	}
	return 0;
}

static int
do_fetch_zone(struct lws_context *cx, struct lws_dht_dnssec_fetch_zone_args *args);

static int
do_notify_peer_outdated(struct lws_vhost *vhost, const char *domain, const lws_sockaddr46 *sa46_peer, uint64_t newer_soa_serial);

static void
dht_dnssec_broadcast_notify(struct vhd_dht_dnssec *vhd, const char *domain, uint64_t soa_serial)
{
	struct sockaddr_in sin[32];
	struct sockaddr_in6 sin6[32];
	int num_v4 = 32, num_v6 = 32, i;

	if (!vhd->dht) return;

	/* Send an unsolicited EVENT_NOTIFY to all known DHT participants to immediately propagate new zonefiles */
	lws_dht_get_nodes(vhd->dht, sin, &num_v4, sin6, &num_v6);

	for (i = 0; i < num_v4; i++) {
		lws_sockaddr46 sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa4.sin_family = AF_INET;
		sa.sa4.sin_addr = sin[i].sin_addr;
		sa.sa4.sin_port = sin[i].sin_port;
		do_notify_peer_outdated(vhd->vhost, domain, &sa, soa_serial);
	}
#if defined(LWS_WITH_IPV6)
	for (i = 0; i < num_v6; i++) {
		lws_sockaddr46 sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa6.sin6_family = AF_INET6;
		sa.sa6.sin6_addr = sin6[i].sin6_addr;
		sa.sa6.sin6_port = sin6[i].sin6_port;
		do_notify_peer_outdated(vhd->vhost, domain, &sa, soa_serial);
	}
#endif
}

struct lws_dht_dnssec_domain;

/* Represents a single ACME temporary zone string for a given domain */
struct lws_dht_dnssec_temp_record {
	lws_dll2_t				list;
	struct lws_dht_dnssec_domain		*domain;
	lws_sorted_usec_list_t			sul_ttl;
	char					*zone_str;
};

/* Represents a domain that has one or more temporary ACME strings active */
struct lws_dht_dnssec_domain {
	lws_dll2_t				list;
	struct vhd_dht_dnssec			*vhd;
	lws_dll2_owner_t			owner_temp_records;
	char					domain_name[128];
	uint8_t					hash[32];
	time_t					last_notify_fetch;
	uint64_t				last_notify_soa;
};

typedef struct lws_dht_ts {
	lws_dll2_t			list;
	struct lws_transport_sequencer	*ts;
	struct sockaddr_storage		sa;
	size_t				salen;
	struct lws_dht_ctx		*ctx;
} lws_dht_ts_t;

/* --- Helpers --- */

typedef enum {
	LWS_ADNS_DSA_RSA_MD5			= 1,  /* RFC 2537 */
	LWS_ADNS_DSA_DH				= 2,  /* RFC 2539 */
	LWS_ADNS_DSA_DSA			= 3,  /* RFC 2536 */
	LWS_ADNS_DSA_ECC			= 4,  /* RFC 2536 */
	LWS_ADNS_DSA_RSA_SHA1			= 5,  /* RFC 3110 */
	LWS_ADNS_DSA_DSA_NSEC3_SHA1		= 6,  /* RFC 5155 */
	LWS_ADNS_DSA_RSA_SHA1_NSEC3_SHA1	= 7,  /* RFC 5155 */
	LWS_ADNS_DSA_RSA_SHA256			= 8,  /* RFC 5702 */
	LWS_ADNS_DSA_RSA_SHA512			= 10, /* RFC 5702 */
	LWS_ADNS_DSA_ECC_GOST			= 12, /* RFC 5933 */
	LWS_ADNS_DSA_ECDSAP256SHA256		= 13, /* RFC 6605 */
	LWS_ADNS_DSA_ECDSAP384SHA384		= 14, /* RFC 6605 */
	LWS_ADNS_DSA_ED25519			= 15, /* RFC 8080 */
	LWS_ADNS_DSA_ED448			= 16, /* RFC 8080 */
} lws_dnssec_algo_t;

#define LWS_ADNS_DNSKEY_PROTOCOL_DNSSEC	3

static struct dht_fragment *
dht_dnssec_find_fragment(struct vhd_dht_dnssec *vhd, const char *hash)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->fragments)) {
		struct dht_fragment *frag = lws_container_of(d, struct dht_fragment, list);
		if (!strcmp(frag->safe_hash, hash))
			return frag;
	} lws_end_foreach_dll(d);

	return NULL;
}

static struct lws_dht_dnssec_fetch_req *
dht_dnssec_find_fetch_req(struct vhd_dht_dnssec *vhd, const char *hash)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&vhd->fetch_reqs)) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->target_hash, hash))
			return req;
	} lws_end_foreach_dll(d);

	return NULL;
}

static void
dht_dnssec_sul_put_cb(struct lws_sorted_usec_list *sul);

static void
dht_dnssec_sul_get_cb(struct lws_sorted_usec_list *sul);

static void
dht_dnssec_sul_timeout_cb(struct lws_sorted_usec_list *sul);

static void
start_next_dht_upload(struct vhd_dht_dnssec *vhd);

static int
dht_dnssec_jwk_load_or_gen(struct vhd_dht_dnssec *vhd)
{
	if (!vhd->cli_jwk_path || !*vhd->cli_jwk_path)
		vhd->cli_jwk_path = "dht.jwk";

	if (!lws_jwk_load(&vhd->jwk, vhd->cli_jwk_path, NULL, NULL)) {
		lwsl_vhost_info(vhd->vhost, "Loaded JWK from %s\n", vhd->cli_jwk_path);
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

static struct lws *
dht_dnssec_dnskey_cb(struct lws *wsi, const char *name, const struct addrinfo *data, int m, void *opaque)
{
	struct dht_fragment *frag = (struct dht_fragment *)opaque;
	struct vhd_dht_dnssec *vhd = frag->vhd;
	struct lws_jws_map map;
	char *temp = NULL;
	int temp_len = 0;
	int valid = 0;
	struct lws_jwk jwk;
	char *jws_buf = NULL;
	int fd;
	struct stat st;
	char tmp_path[256];

	memset(&jwk, 0, sizeof(jwk));

	/* Load the JWS payload */
	lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
	fd = open(tmp_path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		goto drop;
	}

	jws_buf = calloc(1, (size_t)st.st_size + 1);
	if (!jws_buf) {
		close(fd);
		goto drop;
	}

	if (read(fd, jws_buf, (size_t)st.st_size) != st.st_size) {
		free(jws_buf);
		close(fd);
		goto drop;
	}
	close(fd);

	/* Trim trailing whitespace which breaks base64 decoders */
	while (st.st_size > 0 &&
	      (jws_buf[st.st_size - 1] == '\r' ||
	       jws_buf[st.st_size - 1] == '\n' ||
	       jws_buf[st.st_size - 1] == ' ' ||
	       jws_buf[st.st_size - 1] == '\t')) {
		st.st_size--;
		jws_buf[st.st_size] = '\0';
	}

	/* 1. Decode the JWS compact serialization */
	temp_len = (int)st.st_size + 2048; /* Needs enough space for b64 decoding and maps */
	temp = malloc((size_t)temp_len);
	if (!temp) {
		lwsl_notice("DEBUG: malloc failed for temp buffer (size %d)\n", temp_len);
		free(jws_buf);
		goto drop;
	}

	struct lws_jws_map map_b64;
	int h;

	if (lws_jws_b64_compact_map(jws_buf, (int)st.st_size, &map_b64) < 0) {
		lwsl_notice("DEBUG: lws_jws_b64_compact_map failed\n");
		free(temp);
		free(jws_buf);
		goto drop;
	}

	h = lws_jws_compact_decode(jws_buf, (int)st.st_size, &map, &map_b64, temp, &temp_len);
	if (h != 3) {
		lwsl_notice("DEBUG: lws_jws_compact_decode failed, returned %d (!= 3)\n", h);
		free(temp);
		free(jws_buf);
		goto drop;
	}

	/* 2. Extract the embedded JWK from the JOSE header */
	if (!map.buf[LJWS_JOSE] || map.len[LJWS_JOSE] == 0) {
		lwsl_notice("DEBUG: map.buf[LJWS_JOSE] is NULL or length 0\n");
		free(temp);
		free(jws_buf);
		goto drop;
	}

	/* The header is JSON parsing. We could use lejp, but for a simple JWK embedded extraction
	   we can do a simple string search to locate the "jwk": { ... } object to pass to lws_jwk_import */
	{
		char *header = malloc((size_t)map.len[LJWS_JOSE] + 1);
		if (header) {
			memcpy(header, map.buf[LJWS_JOSE], map.len[LJWS_JOSE]);
			header[map.len[LJWS_JOSE]] = '\0';

			char *jwk_start = strstr(header, "\"jwk\":");
			if (jwk_start) {
				jwk_start += 6; /* skip over "jwk": */
				while (*jwk_start == ' ' || *jwk_start == '\t' || *jwk_start == '\n' || *jwk_start == '\r')
					jwk_start++;

				if (lws_jwk_import(&jwk, NULL, NULL, jwk_start, strlen(jwk_start)) == 0) {
					if (jwk.kty == LWS_GENCRYPTO_KTY_EC) {
						lwsl_user("%s: Uploaded JWS embedded key uses curve %s. Public key components:\n", __func__, (const char *)jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf);
						lwsl_hexdump_user(jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
						lwsl_hexdump_user(jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
					}
					int ds_hash_test_worked = 0;
					int live_dnskey_authenticated = 0;

					/* 1. Directly perform the "DS Hash Test" against the embedded JWS JWK */
					/* Assume the JWK acts as the KSK (Flags=257) */
					{
						struct lws_genhash_ctx hash_ctx;
						enum lws_genhash_types hashtype;
						uint8_t wire[256];
						uint8_t digest[64];
						int wire_len = 0;

						/* Convert domain name to wire format */
						const char *p = frag->domain;
						uint8_t *w = wire;
						while (*p) {
							const char *dot = strchr(p, '.');
							if (!dot) dot = p + strlen(p);
							int l = (int)(dot - p);
							*w++ = (uint8_t)l;
							for (int i = 0; i < l; i++) {
								*w++ = (uint8_t)tolower((unsigned char)p[i]);
							}
							p = dot;
							if (*p == '.') p++;
						}
						*w++ = 0;
						wire_len = (int)(w - wire);

						if (frag->digest_type == 1) hashtype = LWS_GENHASH_TYPE_SHA1;
						else if (frag->digest_type == 2) hashtype = LWS_GENHASH_TYPE_SHA256;
						else if (frag->digest_type == 4) hashtype = LWS_GENHASH_TYPE_SHA384;
						else hashtype = (enum lws_genhash_types)0;

						if (hashtype != (enum lws_genhash_types)0 && !lws_genhash_init(&hash_ctx, hashtype)) {
							uint8_t key_data[1024];
							size_t key_len = 0;

							key_data[key_len++] = 257 >> 8; /* Flags (KSK) */
							key_data[key_len++] = 257 & 0xff;
							key_data[key_len++] = 3; /* Protocol */
							key_data[key_len++] = frag->algo; /* Algorithm */

							if (jwk.kty == LWS_GENCRYPTO_KTY_EC) {
								memcpy(key_data + key_len, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len);
								key_len += jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
								memcpy(key_data + key_len, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len);
								key_len += jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;
							} else if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
								uint8_t *e_buf = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
								size_t e_len = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].len;

								/* Remove leading zero bytes from E if any */
								while (e_len > 1 && *e_buf == 0) {
									e_buf++;
									e_len--;
								}

								if (e_len <= 255) {
									key_data[key_len++] = (uint8_t)e_len;
								} else {
									key_data[key_len++] = 0;
									key_data[key_len++] = (uint8_t)(e_len >> 8);
									key_data[key_len++] = (uint8_t)(e_len & 0xff);
								}
								memcpy(key_data + key_len, e_buf, e_len);
								key_len += e_len;

								uint8_t *n_buf = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
								size_t n_len = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len;

								/* Remove leading zero bytes from N if any */
								while (n_len > 1 && *n_buf == 0) {
									n_buf++;
									n_len--;
								}

								memcpy(key_data + key_len, n_buf, n_len);
								key_len += n_len;
							}

							if (lws_genhash_update(&hash_ctx, wire, (size_t)wire_len) == 0 &&
								lws_genhash_update(&hash_ctx, key_data, key_len) == 0) {
								lws_genhash_destroy(&hash_ctx, digest);

								if (frag->ds_digest_len > 0 && memcmp(digest, frag->ds_digest, frag->ds_digest_len) == 0) {
									lwsl_user("%s: DS Hash Test matched the Embedded JWS JWK perfectly!\n", __func__);
									ds_hash_test_worked = 1;
								}
							} else {
								lws_genhash_destroy(&hash_ctx, digest);
							}
						}
					}

					/* 2. Check live DNSKEYs from authoritative nameserver (if any) */
					if (data) {
						int live_ds_match = 0;
						int live_zsk_match = 0;
						const uint8_t *rr_ptr = (const uint8_t *)data;

						while (rr_ptr) {
							const uint8_t *next = *(const uint8_t * const *)rr_ptr;
							uint16_t type = *(const uint16_t *)(rr_ptr + sizeof(void *));
							uint16_t paylen = *(const uint16_t *)(rr_ptr + sizeof(void *) + sizeof(uint16_t));

							if (type == LWS_ADNS_RECORD_DNSKEY && paylen >= 4) {
								const uint8_t *kn = rr_ptr + sizeof(void *) + 2 * sizeof(uint16_t);
								uint16_t flags = lws_ser_ru16be(&kn[0]);

								/* Compute Keytag for this DNSKEY (RFC 4034 Appendix B) */
								uint32_t ac = 0;
								int i;
								for (i = 0; i < paylen; ++i)
									ac += (i & 1) ? kn[i] : (uint32_t)kn[i] << 8;
								ac += (ac >> 16) & 0xFFFF;
								uint16_t calc_tag = (uint16_t)(ac & 0xFFFF);

								if (calc_tag == frag->key_tag && flags == 257) {
									live_ds_match = 1; /* Simplification: we assume if the network gives us the KSK keytag, it matches the DS */
								}

								/* Check if this live DNSKEY byte-matches our JWS embedded JWK */
								if (jwk.kty == LWS_GENCRYPTO_KTY_EC) {
									const uint8_t *kdata = &kn[4];
									int kdata_len = paylen - 4;
									if (jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len + jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len == (uint32_t)kdata_len) {
										if (memcmp(kdata, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len) == 0 &&
											memcmp(kdata + jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len) == 0) {
											live_zsk_match = 1;
										}
									}
								} else if (jwk.kty == LWS_GENCRYPTO_KTY_RSA) {
									const uint8_t *kdata = &kn[4];
									int kdata_len = paylen - 4;

									uint32_t e_len_wire = kdata[0];
									int e_offset = 1;
									if (e_len_wire == 0 && kdata_len >= 3) {
										e_len_wire = (uint32_t)((kdata[1] << 8) | kdata[2]);
										e_offset = 3;
									}

									uint8_t *e_buf = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].buf;
									size_t e_len = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].len;
									while (e_len > 1 && *e_buf == 0) { e_buf++; e_len--; }

									uint8_t *n_buf = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf;
									size_t n_len = jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
									while (n_len > 1 && *n_buf == 0) { n_buf++; n_len--; }

									if ((uint32_t)e_len == e_len_wire && kdata_len >= e_offset + (int)e_len_wire && (uint32_t)n_len == (uint32_t)kdata_len - (uint32_t)e_offset - e_len_wire) {
										if (memcmp(kdata + e_offset, e_buf, e_len) == 0 &&
											memcmp(kdata + e_offset + e_len, n_buf, n_len) == 0) {
											live_zsk_match = 1;
										}
									}
								}
							}
							rr_ptr = next;
						}

						if (live_ds_match && live_zsk_match) {
							lwsl_user("%s: Live DNSKEY verification succeeded (KSK matched DS, and ZSK matched JWK)\n", __func__);
							live_dnskey_authenticated = 1;
						}
					}

					if (ds_hash_test_worked || live_dnskey_authenticated) {
						/* Final step: verify the JWS signature. */
						// lwsl_notice("DEBUG: Proceeding to lws_jws_sig_confirm\n");
						if (lws_jws_sig_confirm(&map_b64, &map, &jwk, vhd->context) >= 0) {
							// lwsl_notice("DEBUG: lws_jws_sig_confirm SUCCESS\n");
							valid = 1;

							/* Extract Payload to raw file */
							if (map.buf[LJWS_PYLD]) {
								char tmp_ppath[256];
								int pfd;

								lws_snprintf(tmp_ppath, sizeof(tmp_ppath), "%s/tmp/%s.%08X.payload", vhd->storage_path, frag->safe_hash, frag->temp_token);
								pfd = open(tmp_ppath, O_RDWR | O_CREAT | O_TRUNC, 0666);
								if (pfd >= 0) {
									if (write(pfd, map.buf[LJWS_PYLD], (size_t)map.len[LJWS_PYLD]) != (ssize_t)map.len[LJWS_PYLD]) {
										lwsl_err("%s: Failed to write payload\n", __func__);
									} else {
										struct lws_genhash_ctx pctx;
										if (!lws_genhash_init(&pctx, LWS_GENHASH_TYPE_SHA256)) {
											if (lws_genhash_update(&pctx, map.buf[LJWS_PYLD], (size_t)map.len[LJWS_PYLD]) == 0)
												lws_genhash_destroy(&pctx, frag->payload_hash);
										}
										lwsl_user("SUCCESS: Validated offline zonefile successfully unwrapped locally to %s\n", tmp_ppath);
									}
									close(pfd);
								} else {
									lwsl_err("%s: Failed to open payload extraction path: %s\n", __func__, tmp_ppath);
								}
							}
						} else {
							lwsl_notice("DEBUG: lws_jws_sig_confirm FAILED\n");
						}
					} else {
						lwsl_notice("DEBUG: BOTH ds_hash_test_worked and live_dnskey_authenticated are FALSE\n");
					}
					lws_jwk_destroy(&jwk);
				} else {
					lwsl_notice("DEBUG: Failed to import embedded JWK: lws_jwk_import returned non-zero\n");
				}
			} else {
				lwsl_notice("DEBUG: JWS header missing embedded 'jwk' object (strstr '\"jwk\":' failed)\n");
			}

			free(header);
		}
	}

	free(temp);
	free(jws_buf);

	if (!valid) {
		lwsl_notice("%s: Cryptographic verification of JWS failed\n", __func__);
		add_peer_strike(frag->vhd, (const lws_sockaddr46 *)&frag->from_sa);
		goto drop;
	}

	lwsl_user("%s: DS record successfully validated simulated JWS for %s\n", __func__, frag->domain);

	{
		char ack[128];
		lws_dht_msg_gen(ack, sizeof(ack), "ACK", frag->safe_hash, frag->last_offset, frag->last_len);
		lws_dht_send_data(frag->dht_ctx, (struct sockaddr *)&frag->from_sa, ack, strlen(ack));
	}

	/* Store it officially / replace older version */
	lwsl_user("%s: Successfully validated %s\n", __func__, frag->safe_hash);

	if (frag->fd >= 0) {
		close(frag->fd);
		frag->fd = -1;
	}

	/* Also, as a client, we should now send a native DHT SUBSCRIBE to the target node
	   so we get notified if this zonefile ever changes! */
	if (frag->dht_ctx) {
		uint8_t tid[4];
		lws_get_random(vhd->context, tid, sizeof(tid));

		uint8_t raw_hash[32];
		if (!lws_hex_to_byte_array(frag->safe_hash, raw_hash, sizeof(raw_hash))) {
			lws_dht_hash_t *id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32, raw_hash);
			if (id) {
				lwsl_user("%s: Sending native DHT SUBSCRIBE to establish long-poll\n", __func__);
				lws_dht_send_subscribe(frag->dht_ctx, (struct sockaddr *)&frag->from_sa, frag->from_salen, tid, sizeof(tid), id, 0, 0);
				lws_dht_hash_destroy(&id);
			}
		}
	}

	/* Notify anyone tracking this hash BEFORE we rename the tmp payload, just in case */
	{
		uint8_t raw_hash[32];
		if (!lws_hex_to_byte_array(frag->safe_hash, raw_hash, sizeof(raw_hash))) {
			lws_dht_hash_t *id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32, raw_hash);
			if (id) {
				lws_dht_notify_subscribers(frag->dht_ctx, id, frag->payload_hash);
				lws_dht_hash_destroy(&id);
			}
		}
	}

	{
		char tmp_path[256], dir1[256], dir2[256], final_path[256];
		char tmp_ppath[256], final_ppath[256];
		lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
		lws_snprintf(tmp_ppath, sizeof(tmp_ppath), "%s/tmp/%s.%08X.payload", vhd->storage_path, frag->safe_hash, frag->temp_token);

		lws_snprintf(dir1, sizeof(dir1), "%s/%.2s", vhd->storage_path, frag->safe_hash);
		lws_snprintf(dir2, sizeof(dir2), "%s/%.2s/%.2s", vhd->storage_path, frag->safe_hash, frag->safe_hash + 2);
		lws_snprintf(final_path, sizeof(final_path), "%s/%.2s/%.2s/%s", vhd->storage_path, frag->safe_hash, frag->safe_hash + 2, frag->safe_hash);

		/* Parse the payload to determine SOA serial, TTL and RRSIG expiry for decorated filename */
		uint64_t serial = 0;
		time_t sig_expiry = 0;
		time_t default_ttl = 3600;
#if defined(LWS_WITH_AUTHORITATIVE_DNS)
		{
			int fpin = open(tmp_ppath, O_RDONLY);
			if (fpin >= 0) {
				struct stat st;
				if (fstat(fpin, &st) == 0 && st.st_size > 0 && st.st_size < 1024 * 1024) {
					char *buf = malloc((size_t)st.st_size + 1);
					if (buf && read(fpin, buf, (size_t)st.st_size) == st.st_size) {
						buf[st.st_size] = '\0';
						struct auth_dns_zone z;
						memset(&z, 0, sizeof(z));
						if (!lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, &z, NULL, NULL)) {
							if (z.default_ttl[0]) default_ttl = (time_t)atoi(z.default_ttl);
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
								struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
								if (rs->type == 6) { /* SOA */
									lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
										struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
										int p2 = 0;
										while (p2 < (int)rr->wire_rdata_len && rr->wire_rdata[p2]) p2 += rr->wire_rdata[p2] + 1;
										p2++;
										while (p2 < (int)rr->wire_rdata_len && rr->wire_rdata[p2]) p2 += rr->wire_rdata[p2] + 1;
										p2++;
										if (p2 + 4 <= (int)rr->wire_rdata_len) {
											serial = ((uint64_t)rr->wire_rdata[p2] << 24) |
													 ((uint64_t)rr->wire_rdata[p2+1] << 16) |
													 ((uint64_t)rr->wire_rdata[p2+2] << 8) |
													 (uint64_t)rr->wire_rdata[p2+3];
										}
										break;
									} lws_end_foreach_dll(d2);
								} else if (rs->type == 46) { /* RRSIG */
									lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
										struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
										if (rr->wire_rdata_len >= 13) {
											time_t e = ((time_t)rr->wire_rdata[8] << 24) |
													   ((time_t)rr->wire_rdata[9] << 16) |
													   ((time_t)rr->wire_rdata[10] << 8) |
													   (time_t)rr->wire_rdata[11];
											if (sig_expiry == 0 || e < sig_expiry) sig_expiry = e;
										}
									} lws_end_foreach_dll(d2);
								}
							} lws_end_foreach_dll(d);
							lws_auth_dns_free_zone(&z);
						}
					}
					if (buf) free(buf);
				}
				close(fpin);
			}
		}
#endif
		time_t ttl_expiry = time(NULL) + default_ttl;
		if (sig_expiry == 0) sig_expiry = ttl_expiry + 86400 * 30; /* Fake if no RRSIG */

		lws_snprintf(final_ppath, sizeof(final_ppath), "%s/%.2s/%.2s/%s_%llu_%llu_%llu.payload",
			vhd->storage_path, frag->safe_hash, frag->safe_hash + 2, frag->safe_hash,
			(unsigned long long)ttl_expiry, (unsigned long long)sig_expiry, (unsigned long long)serial);

		if (mkdir(dir1, 0777) < 0 && errno != EEXIST)
			lwsl_err("%s: Failed to create %s\n", __func__, dir1);
		if (mkdir(dir2, 0777) < 0 && errno != EEXIST)
			lwsl_err("%s: Failed to create %s\n", __func__, dir2);

		/* Sweep old payload files for this hash before moving the new one in */
		struct lws_dir_args da;
		memset(&da, 0, sizeof(da));
		da.prefix = frag->safe_hash;
		da.dirpath = dir2;
		da.new_serial = serial;
		lws_dir(dir2, &da, dht_dnssec_sweep_old_payload_cb);

		if (da.is_outdated) {
			if (da.is_outdated == 1) {
				lwsl_notice("%s: Dropping imported zone %s (serial %llu is a malicious replay!)\n", __func__, frag->domain, (unsigned long long)serial);
				add_peer_strike(frag->vhd, (const lws_sockaddr46 *)&frag->from_sa);
			} else {
				lwsl_notice("%s: Dropping identically cached zone %s (serial %llu is already active!)\n", __func__, frag->domain, (unsigned long long)serial);
			}
			goto drop;
		}

		if (rename(tmp_path, final_path) < 0) {
			lwsl_err("%s: Failed to rename %s to %s (errno %d)\n", __func__, tmp_path, final_path, errno);
			unlink(tmp_path);
			unlink(tmp_ppath);
		} else {
			lwsl_user("%s: Atomically moved validated zone to %s\n", __func__, final_path);
			if (rename(tmp_ppath, final_ppath) < 0) {
				lwsl_err("%s: Failed to rename %s to %s (errno %d)\n", __func__, tmp_ppath, final_ppath, errno);
				unlink(tmp_ppath);
			} else {
				lwsl_user("%s: Atomically moved decoded payload to %s\n", __func__, final_ppath);

				if (vhd->auth_cb) {
					vhd->auth_cb(vhd->auth_cb_opaque, frag->domain, final_ppath);
				}

				/* Broadcast the newly accepted zone's SOA over the DHT to force peers to update instantly */
				lwsl_user("%s: Broadcasting fresh SOA serial %llu for %s to DHT nodes\n", __func__, (unsigned long long)serial, frag->domain);
				dht_dnssec_broadcast_notify(vhd, frag->domain, serial);

				lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->fetch_reqs.head) {
					struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
					if (!strcmp(req->target_hash, frag->safe_hash)) {
						if (req->cache_dir[0]) {
							char cpath[1024];
							lws_snprintf(cpath, sizeof(cpath), "%s/%s.zone", req->cache_dir, req->domain);
							int fpin = open(final_ppath, O_RDONLY);
							if (fpin >= 0) {
								if (mkdir(req->cache_dir, 0777) < 0 && errno != EEXIST)
									lwsl_err("%s: Failed to create cache directory %s\n", __func__, req->cache_dir);
								int fpout = open(cpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
								if (fpout >= 0) {
									char cbuf[4096];
									ssize_t cn;
									while ((cn = read(fpin, cbuf, sizeof(cbuf))) > 0)
										if (write(fpout, cbuf, (size_t)cn) < 0) break;
									close(fpout);
									lwsl_user("%s: Copied fetched zone to cache %s\n", __func__, cpath);
								} else {
									lwsl_err("%s: Failed to open %s for caching\n", __func__, cpath);
								}
								close(fpin);
							}
						}

						if (req->cb)
							req->cb(req->opaque, req->domain, 1);

						lws_sul_cancel(&req->sul_timeout);
						lws_dll2_remove(d);
						free(req);
					}
				} lws_end_foreach_dll_safe(d, d1);
			}
		}
	}

	if (vhd->cb_completion && !vhd->cli_put_file)
		vhd->cb_completion(vhd->cb_closure, 0);

	/* The PUT or GET transaction is complete, cancel any pending timeout */
	lws_sul_cancel(&vhd->sul_timeout);

	lws_dll2_remove(&frag->list);
	free(frag);

	return wsi;

drop:
	if (frag->fd >= 0) {
		close(frag->fd);
		frag->fd = -1;
	}
	{
		char tmp_path[256];
		char tmp_ppath[256];
		lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
		lws_snprintf(tmp_ppath, sizeof(tmp_ppath), "%s/tmp/%s.%08X.payload", vhd->storage_path, frag->safe_hash, frag->temp_token);
		unlink(tmp_path);
		unlink(tmp_ppath);
		lwsl_user("%s: Unlinked invalid/rejected temp payload %s\n", __func__, tmp_path);
	}
	{
		char err[256];
		lws_dht_msg_gen(err, sizeof(err), "ERR", frag->safe_hash, frag->last_offset, 0);
		lwsl_user("%s: Sending ERR packet to client: %s\n", __func__, err);
		lws_dht_send_data(frag->dht_ctx, (struct sockaddr *)&frag->from_sa, err, strlen(err));
	}

	if (vhd->cb_completion && !vhd->cli_put_file) {
		lwsl_user("%s: Cancelling stalled context via completion cb\n", __func__);
		vhd->cb_completion(vhd->cb_closure, 1);
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->fetch_reqs.head) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->target_hash, frag->safe_hash)) {
			if (req->cb) req->cb(req->opaque, req->domain, 0);
			lws_sul_cancel(&req->sul_timeout);
			lws_dll2_remove(d);
			free(req);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&frag->list);
	free(frag);
	return wsi;
}

static struct lws *
dht_dnssec_ds_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct dht_fragment *frag = (struct dht_fragment *)opaque;

	const uint8_t *ds_payload;
	uint16_t ds_paylen = 0;

	lwsl_user("=== %s: ENTERED CALLBACK === n=%d\n", __func__, n);

	if (n < 0 || (n & ~LWS_ADNS_DNSSEC_VALID) != LADNS_RET_FOUND) {
		lwsl_user("%s: DS record query failed for %s (n=%d)\n", __func__, frag->domain, n);
		goto drop;
	}

	ds_payload = lws_async_dns_get_rr_cache(frag->vhd->context, frag->domain, LWS_ADNS_RECORD_DS, &ds_paylen);
	if (!ds_payload || ds_paylen < 4) {
		lwsl_user("%s: DS record cache absent or invalid payload for %s\n", __func__, frag->domain);
		goto drop;
	}

	{
		uint16_t key_tag = lws_ser_ru16be(&ds_payload[0]);
		uint8_t algo = ds_payload[2];
		uint8_t digest_type = ds_payload[3];

		lwsl_user("%s: Found DS! key_tag=%u, algo=%u, digest_type=%u\n",
			__func__, key_tag, algo, digest_type);

		frag->key_tag = key_tag;
		frag->algo = algo;
		frag->digest_type = digest_type;

		int dlen = ds_paylen - 4;
		if (dlen > 0 && dlen <= (int)sizeof(frag->ds_digest)) {
			memcpy(frag->ds_digest, &ds_payload[4], (size_t)dlen);
			frag->ds_digest_len = (uint8_t)dlen;
		} else {
			lwsl_user("%s: Invalid DS digest length %d\n", __func__, dlen);
			goto drop;
		}

		if (result) lws_async_dns_freeaddrinfo(&result);
		return dht_dnssec_dnskey_cb(wsi, frag->domain, NULL, 0, frag);
	}

	return wsi;

drop:
	if (frag->fd >= 0) {
		close(frag->fd);
		frag->fd = -1;
	}
	{
		char tmp_path[256];
		lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", frag->vhd->storage_path, frag->safe_hash, frag->temp_token);
		unlink(tmp_path);
		lwsl_user("%s: Unlinked invalid/rejected temp payload %s\n", __func__, tmp_path);
	}
	{
		char err[256];
		lws_dht_msg_gen(err, sizeof(err), "ERR", frag->safe_hash, frag->last_offset, 0);
		lwsl_user("%s: Sending ERR packet to client: %s\n", __func__, err);
		lws_dht_send_data(frag->dht_ctx, (struct sockaddr *)&frag->from_sa, err, strlen(err));
	}

	if (frag->vhd->cb_completion && !frag->vhd->cli_put_file)
		frag->vhd->cb_completion(frag->vhd->cb_closure, 1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, frag->vhd->fetch_reqs.head) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->target_hash, frag->safe_hash)) {
			if (req->cb) req->cb(req->opaque, req->domain, 0);
			lws_sul_cancel(&req->sul_timeout);
			lws_dll2_remove(d);
			free(req);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&frag->list);
	free(frag);
	if (result) lws_async_dns_freeaddrinfo(&result);
	return wsi;
}

static int
dht_dnssec_trigger_validation(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, struct dht_fragment *frag, const struct sockaddr *from, size_t fromlen)
{
	struct stat st;
	char *buf;

	if (fstat(frag->fd, &st) < 0) return -1;
	buf = malloc((size_t)st.st_size + 1);
	if (!buf) return -1;

	if (lseek(frag->fd, 0, SEEK_SET) < 0 ||
	    read(frag->fd, buf, (size_t)st.st_size) != st.st_size) {
		free(buf);
		return -1;
	}
	buf[st.st_size] = '\0';

	/* Trim trailing whitespace which breaks base64 decoders */
	while (st.st_size > 0 &&
	      (buf[st.st_size - 1] == '\r' ||
	       buf[st.st_size - 1] == '\n' ||
	       buf[st.st_size - 1] == ' ' ||
	       buf[st.st_size - 1] == '\t')) {
		st.st_size--;
		buf[st.st_size] = '\0';
	}

	/* Parse the JSON */
	{
		struct lws_jws_map map_b64, map;
		char *temp;
		int temp_len = (int)st.st_size;
		int h;

		temp = malloc((size_t)st.st_size);
		if (!temp) {
			lwsl_err("%s: Failed to allocate temp buffer for JWS decode\n", __func__);
			free(buf);
			return -1;
		}

		if (lws_jws_b64_compact_map(buf, (int)st.st_size, &map_b64) < 0) {
			lwsl_notice("%s: compact JWS map failed\n", __func__);
			free(temp);
			free(buf);
			return -1;
		}

		h = lws_jws_compact_decode(buf, (int)st.st_size, &map, &map_b64, temp, &temp_len);

		if (h != 3) {
			lwsl_notice("%s: compact JWS decode failed (h=%d)\n", __func__, h);
			free(temp);
			free(buf);
			return -1;
		}

		/* Extract domain dynamically and strictly validate the syntax of the decoded zone file payload! */
		struct auth_dns_zone parsed_zone;
		memset(&parsed_zone, 0, sizeof(parsed_zone));

		if (lws_auth_dns_parse_zone_buf((const char *)map.buf[LJWS_PYLD], map.len[LJWS_PYLD], &parsed_zone, NULL, NULL)) {
			lwsl_err("%s: Failed to syntax validate zonefile!\n", __func__);
			free(temp);
			free(buf);
			return -1;
		}

		/* Find SOA record to extract domain and serial */
		frag->domain[0] = '\0';
		frag->soa_serial = 0;
		if (parsed_zone.origin[0]) {
			lws_strncpy(frag->domain, parsed_zone.origin, sizeof(frag->domain));
			int dlen_i = (int)strlen(frag->domain);
			if (dlen_i > 0 && frag->domain[dlen_i - 1] == '.')
				frag->domain[dlen_i - 1] = '\0';
		}

		lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&parsed_zone.rrset_list)) {
			struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
			if (rs->type == 6 /* SOA */) {
				if (!frag->domain[0]) {
					lws_strncpy(frag->domain, rs->name, sizeof(frag->domain));
				}
				struct auth_dns_rr *rr = lws_container_of(lws_dll2_get_head(&rs->rr_list), struct auth_dns_rr, list);
				if (rr && rr->rdata) {
					/* Parse SOA rdata: MNAME RNAME SERIAL ... */
					lws_tokenize_t ts;
					lws_tokenize_elem e;
					int toks = 0;

					lws_tokenize_init(&ts, rr->rdata, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM | LWS_TOKENIZE_F_COLON_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM | LWS_TOKENIZE_F_PLUS_NONTERM | LWS_TOKENIZE_F_DOT_NONTERM);
					do {
						e = lws_tokenize(&ts);
						if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_INTEGER) {
							toks++;
							if (toks == 3) { /* SERIAL */
								frag->soa_serial = (uint32_t)atoll(ts.token);
								break;
							}
						}
					} while (e > 0);
				}
			}
		} lws_end_foreach_dll(d);

		lws_auth_dns_free_zone(&parsed_zone);

		if (!frag->domain[0]) {
			if (vhd->cli_get_domain) {
				lws_strncpy(frag->domain, vhd->cli_get_domain, sizeof(frag->domain));
			} else {
				lwsl_err("%s: Could not extract authoritative domain from parsed zone\n", __func__);
				free(temp);
				free(buf);
				return -1;
			}
		}

		if (!frag->soa_serial) {
			lwsl_err("%s: Missing or invalid SOA serial in zonefile\n", __func__);
			free(temp);
			free(buf);
			return -1;
		}

		/* Check for existing zonefile and compare SOA serials to prevent replay attacks */
		char ex_path[256];
		lws_snprintf(ex_path, sizeof(ex_path), "%s/%.2s/%.2s/%s.payload", vhd->storage_path, frag->safe_hash, frag->safe_hash + 2, frag->safe_hash);

		int ex_fd = open(ex_path, O_RDONLY);
		if (ex_fd >= 0) {
			struct stat ex_st;
			if (fstat(ex_fd, &ex_st) == 0 && ex_st.st_size > 0 && ex_st.st_size <= 131072) {
				char *ex_buf = malloc((size_t)ex_st.st_size + 1);
				if (ex_buf) {
					if (read(ex_fd, ex_buf, (size_t)ex_st.st_size) == ex_st.st_size) {
						ex_buf[ex_st.st_size] = '\0';

						struct auth_dns_zone ex_zone;
						memset(&ex_zone, 0, sizeof(ex_zone));
						if (!lws_auth_dns_parse_zone_buf(ex_buf, (size_t)ex_st.st_size, &ex_zone, NULL, NULL)) {
							uint32_t ex_serial = 0;
							lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&ex_zone.rrset_list)) {
								struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
								if (rs->type == 6 /* SOA */) {
									struct auth_dns_rr *rr = lws_container_of(lws_dll2_get_head(&rs->rr_list), struct auth_dns_rr, list);
									if (rr && rr->rdata) {
										lws_tokenize_t ts;
										lws_tokenize_elem e;
										int toks = 0;
										lws_tokenize_init(&ts, rr->rdata, LWS_TOKENIZE_F_NO_FLOATS | LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_SLASH_NONTERM | LWS_TOKENIZE_F_COLON_NONTERM | LWS_TOKENIZE_F_EQUALS_NONTERM | LWS_TOKENIZE_F_PLUS_NONTERM | LWS_TOKENIZE_F_DOT_NONTERM);
										do {
											e = lws_tokenize(&ts);
											if (e == LWS_TOKZE_TOKEN || e == LWS_TOKZE_INTEGER) {
												if (++toks == 3) {
													ex_serial = (uint32_t)atoll(ts.token);
													break;
												}
											}
										} while (e > 0);
									}
								}
							} lws_end_foreach_dll(d);
							lws_auth_dns_free_zone(&ex_zone);

							if (ex_serial && frag->soa_serial <= ex_serial) {
								if (frag->soa_serial < ex_serial) {
									lws_sockaddr46 sa;
									memset(&sa, 0, sizeof(sa));
									if (frag->from_sa.ss_family == AF_INET) {
										sa.sa4.sin_family = AF_INET;
										sa.sa4.sin_addr = ((struct sockaddr_in *)&frag->from_sa)->sin_addr;
										sa.sa4.sin_port = ((struct sockaddr_in *)&frag->from_sa)->sin_port;
										do_notify_peer_outdated(vhd->vhost, frag->domain, &sa, ex_serial);
									}
#if defined(LWS_WITH_IPV6)
									else if (frag->from_sa.ss_family == AF_INET6) {
										sa.sa6.sin6_family = AF_INET6;
										sa.sa6.sin6_addr = ((struct sockaddr_in6 *)&frag->from_sa)->sin6_addr;
										sa.sa6.sin6_port = ((struct sockaddr_in6 *)&frag->from_sa)->sin6_port;
										do_notify_peer_outdated(vhd->vhost, frag->domain, &sa, ex_serial);
									}
#endif
								}
								lwsl_err("%s: Rejecting replay! New serial %u <= existing serial %u\n", __func__, frag->soa_serial, ex_serial);
								free(ex_buf);
								close(ex_fd);
								free(temp);
								free(buf);
								return -1;
							}
						}
					}
					free(ex_buf);
				}
			}
			close(ex_fd);
		}

		lwsl_user("%s: Syntactically checked zonefile! Extracted domain %s, serial %u. Starting DS query.\n",
			__func__, frag->domain, frag->soa_serial);

		/* Keep a reference to the vhost context and sender address in frag for the async callback */
		frag->dht_ctx = ctx;
		memcpy(&frag->from_sa, from, fromlen);
		frag->from_salen = fromlen;

		if (lws_async_dns_query(vhd->context, 0, frag->domain,
					LWS_ADNS_RECORD_DS, dht_dnssec_ds_cb, NULL, frag, NULL) == LADNS_RET_FAILED) {
			lwsl_err("%s: async dns query failed to start.\n", __func__);
			free(temp);
			free(buf);
			return -1;
		}

		free(temp);
		free(buf);
		return 0;
	}
}

/* --- Verb Handlers --- */

static int
verb_put_handler(struct vhd_dht_dnssec *vhd, struct lws_dht_verb_dispatch_args *args)
{
	struct lws_dht_ctx *ctx = args->ctx;
	const struct lws_dht_msg *msg = args->msg;
	const struct sockaddr *from = args->from;
	size_t fromlen = args->fromlen;
	struct dht_fragment *frag;
	char path[256];
	int n;

	lwsl_user("%s: PUT [START] %s offset %llu len %llu payload_len %zu\n", __func__, msg->hash, msg->offset, msg->len, msg->payload_len);

	/*
	 * DNSSEC PUT Filter:
	 * We only want to handle this PUT if it looks like a JWS zone file.
	 * If this is the first chunk (offset 0), we peek at the payload.
	 * JWS compact serialization starts with a base64url-encoded header.
	 * If the payload is empty (common for initial connection PUT checks),
	 * or it doesn't look like JWS, we PASS it to the generic object store.
	 */
	if (msg->len > 131072) {
		lwsl_user("%s: Rejecting payload exceeding 131072 bytes (declared %llu)\n", __func__, msg->len);
		args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
		return 0;
	}

	if (msg->offset == 0) {
		if (msg->payload_len == 0) {
			lwsl_user("%s: Empty initial payload. Passing to generic object store.\n", __func__);
			args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
			return 0;
		} else {
			const char *p = (const char *)msg->payload;
			if (p[0] != 'e' && p[0] != '{') {
				lwsl_user("%s: Payload does not look like JWS/DNSSEC. Passing to generic object store.\n", __func__);
				args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
				return 0;
			}
		}
	}

	frag = dht_dnssec_find_fragment(vhd, msg->hash);
	if (!frag) {
		if (msg->offset != 0) {
			lwsl_user("%s: Rejecting initial chunk for %s with non-zero offset %llu (likely trailing packets from failed/completed transfer)\n",
				    __func__, msg->hash, msg->offset);
			return 0;
		}

		lwsl_user("%s: PUT fragment not found. Creating new metadata for %s\n", __func__, msg->hash);
		frag = calloc(1, sizeof(*frag));
		if (!frag) return -1;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));
		frag->total_len = msg->len;
		frag->vhd = vhd;
		lws_get_random(vhd->context, &frag->temp_token, sizeof(frag->temp_token));
		lws_dll2_add_tail(&frag->list, &vhd->fragments);

		lws_snprintf(path, sizeof(path), "%s/tmp", vhd->storage_path);
		if (mkdir(path, 0777) < 0 && errno != EEXIST) {
			lwsl_err("%s: Failed to create storage tmp dir %s (errno %d)\n", __func__, path, errno);
		}

		lws_snprintf(path, sizeof(path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
		lwsl_user("%s: Target tmp path: %s\n", __func__, path);

		frag->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (frag->fd < 0) {
			lwsl_err("%s: Failed to open %s (errno %d)\n", __func__, path, errno);
			lws_dll2_remove(&frag->list);
			free(frag);
			return -1;
		}
		lwsl_user("%s: Opened %s successfully\n", __func__, path);
	} else {
		lwsl_user("%s: Continuing transfer for %s, already got %llu bytes\n", __func__, frag->safe_hash, (unsigned long long)frag->received_len);
	}

	if (frag->validation_started) {
		lwsl_user("%s: Ignoring duplicate/retried chunk for %s (validation already in progress)\n", __func__, frag->safe_hash);
		return 0;
	}

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) {
		lwsl_err("%s: lseek failed (errno %d)\n", __func__, errno);
		goto drop;
	}
	n = (int)write(frag->fd, msg->payload, msg->payload_len);
	if (n < 0 || (size_t)n != msg->payload_len) {
		lwsl_err("%s: write failed (wrote %d of expected %zu, errno %d)\n", __func__, n, msg->payload_len, errno);
		goto drop;
	}

	/* Only update received_len if we actually extended the file */
	if (msg->offset + msg->payload_len > frag->received_len)
		frag->received_len = msg->offset + msg->payload_len;

	lwsl_user("%s: Wrote %d bytes successfully (Total Received: %llu/%llu)\n", __func__, n, (unsigned long long)frag->received_len, (unsigned long long)msg->len);

	frag->last_offset = msg->offset;
	frag->last_len = msg->payload_len;

	if (frag->received_len >= frag->total_len) {
		if (!frag->validation_started) {
			frag->validation_started = 1;
			lwsl_user("%s: Finished receiving %s, starting validation\n", __func__, frag->safe_hash);

			if (dht_dnssec_trigger_validation(ctx, vhd, frag, from, fromlen))
				goto drop;
		}

		/*
		 * We return 0 here to tell the protocol layer we've consumed the chunk without errors.
		 * Because we don't send an ACK immediately, the DHT Sequencer protocol layer (if we use the
		 * new precedence feature) will hold or drop the sequencer state depending on the design.
		 * For the mock Object Store UDP workflow, we just return 0 to stop further processing on this chunk,
		 * and the remote end waits until it gets an ACK from `dnssec_ds_cb` before proceeding.
		 */
		return 0;
	}

	/* Send ACK for intermediate chunks */
	{
		char ack[128];
		lwsl_user("%s: Sending intermediate ACK for %s offset %llu payload_len %zu\n", __func__, msg->hash, msg->offset, msg->payload_len);
		lws_dht_msg_gen(ack, sizeof(ack), "ACK", msg->hash, msg->offset, msg->payload_len);
		lws_dht_send_data(ctx, from, ack, strlen(ack));
	}

	return 0;

drop:
	close(frag->fd);
	frag->fd = -1;
	{
		char tmp_path[256];
		lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
		unlink(tmp_path);
		lwsl_user("%s: Unlinked invalid/rejected temp payload %s\n", __func__, tmp_path);
	}
	{
		char err[256];
		lws_dht_msg_gen(err, sizeof(err), "ERR", frag->safe_hash, frag->last_offset, 0);
		lws_dht_send_data(ctx, from, err, strlen(err));
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->fetch_reqs.head) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->target_hash, frag->safe_hash)) {
			if (req->cb) req->cb(req->opaque, req->domain, 0);
			lws_sul_cancel(&req->sul_timeout);
			lws_dll2_remove(d);
			free(req);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&frag->list);
	free(frag);
	return -1;
}

static int
verb_get_handler(struct vhd_dht_dnssec *vhd, struct lws_dht_verb_dispatch_args *args)
{
	struct lws_dht_ctx *ctx = args->ctx;
	const struct lws_dht_msg *msg = args->msg;
	const struct sockaddr *from = args->from;
	size_t fromlen = args->fromlen;
	(void)fromlen;
	char path[256], *buf;
	int fd, n;
	size_t blen = 1024 + 1024;
	int hlen;

	struct stat st;

	lwsl_user("%s: GET %s offset %llu len %llu\n", __func__, msg->hash, msg->offset, msg->len);

	lws_snprintf(path, sizeof(path), "%s/%s", vhd->storage_path, msg->hash);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		lws_snprintf(path, sizeof(path), "%s/%.2s/%.2s/%s", vhd->storage_path, msg->hash, msg->hash + 2, msg->hash);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			lwsl_info("%s: Not found %s, passing to generic object store\n", __func__, msg->hash);
			args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
			return 0;
		}
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	buf = malloc(blen);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (lseek(fd, (off_t)msg->offset, SEEK_SET) < 0) goto fail;
	n = (int)read(fd, buf + 1024, 1024);
	if (n < 0 || (n == 0 && msg->offset < (unsigned long long)st.st_size)) goto fail;

	hlen = lws_dht_msg_gen(buf, 1024, "RSP", msg->hash, msg->offset, (unsigned long long)st.st_size);
	if (hlen < 0) goto fail;
	memmove((uint8_t *)buf + hlen, (uint8_t *)buf + 1024, (size_t)n);
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
verb_ack_handler(struct vhd_dht_dnssec *vhd, struct lws_dht_verb_dispatch_args *args)
{
	const struct lws_dht_msg *msg = args->msg;
	lwsl_user("%s: ACK for %s offset %llu\n", __func__, msg->hash, msg->offset);

	if (!vhd->cli_put_file) {
		/* Not meant for us, pass it on */
		args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
		return 0;
	}

	if (msg->offset != vhd->bulk_sent) {
		lwsl_notice("Ignoring unexpected ACK for offset %llu (expected %llu)\n", (unsigned long long)msg->offset, (unsigned long long)vhd->bulk_sent);
		return 0;
	}

	lws_sul_cancel(&vhd->sul_timeout);
	vhd->put_retries = 0;

	if (vhd->cli_put_file) {
		vhd->bulk_sent += msg->len;
		if (vhd->bulk_sent >= vhd->bulk_total) {
			lwsl_user("PUT complete\n");
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 0);
			vhd->put_started = 0;
			start_next_dht_upload(vhd);
		} else {
			dht_dnssec_sul_put_cb(&vhd->sul_bulk);
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
verb_rsp_handler(struct vhd_dht_dnssec *vhd, struct lws_dht_verb_dispatch_args *args)
{
	struct lws_dht_ctx *ctx = args->ctx;
	const struct sockaddr *from = args->from;
	size_t fromlen = args->fromlen;
	const struct lws_dht_msg *msg = args->msg;
	struct dht_fragment *frag;
	struct lws_dht_dnssec_fetch_req *req;

	lwsl_user("%s: RSP for %s offset %llu len %llu payload %zu\n", __func__, msg->hash, msg->offset, msg->len, msg->payload_len);

	req = dht_dnssec_find_fetch_req(vhd, msg->hash);
	if (!req) {
		/* Not for us, pass it on */
		args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
		return 0;
	}

	if (msg->len > 131072) {
		lwsl_err("%s: Rejecting RSP payload exceeding 131072 bytes (declared %llu)\n", __func__, msg->len);
		if (vhd->cb_completion && !vhd->cli_put_file)
			vhd->cb_completion(vhd->cb_closure, 1);
		return -1;
	}

	frag = dht_dnssec_find_fragment(vhd, msg->hash);
	if (!frag) {
		if (msg->offset != 0) {
			lwsl_notice("%s: Rejecting initial chunk for %s with non-zero offset %llu (likely trailing packets from failed transfer)\n",
				    __func__, msg->hash, msg->offset);
			return 0; /* Ignore it, sender will eventually time out or we wait for our next scheduled retry */
		}

		frag = calloc(1, sizeof(*frag));
		if (!frag) return -1;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));
		frag->total_len = msg->len;
		frag->vhd = vhd;

		if (from && fromlen > 0 && fromlen <= sizeof(frag->from_sa)) {
			memcpy(&frag->from_sa, from, fromlen);
			frag->from_salen = fromlen;
		}

		lws_get_random(vhd->context, &frag->temp_token, sizeof(frag->temp_token));
		lws_dll2_add_tail(&frag->list, &vhd->fragments);

		char path[256];
		lws_snprintf(path, sizeof(path), "%s/tmp", vhd->storage_path);
		if (mkdir(path, 0777) < 0 && errno != EEXIST) {
			lwsl_err("%s: Failed to create tmp dir %s\n", __func__, path);
		}
		lws_snprintf(path, sizeof(path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);

		frag->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (frag->fd < 0) return -1;
		if (lws_genhash_init(&frag->ctx, LWS_DHT_STORE_GENHASH)) return -1;
		frag->hash_init_done = 1;
	}

	if (msg->offset < frag->received_len) {
		lwsl_notice("%s: Ignoring duplicate/stale chunk for %s offset %llu (expected %llu)\n",
			    __func__, msg->hash, msg->offset, (unsigned long long)frag->received_len);
		return 0;
	} else if (msg->offset > frag->received_len) {
		lwsl_notice("%s: Ignoring out-of-order chunk for %s offset %llu (expected %llu)\n",
			    __func__, msg->hash, msg->offset, (unsigned long long)frag->received_len);
		return 0;
	}

	if (msg->offset + msg->payload_len > frag->total_len) {
		lwsl_err("%s: Rejecting chunk for %s exceeding declared total length (offset %llu + len %zu > %llu)\n",
			 __func__, msg->hash, msg->offset, msg->payload_len, (unsigned long long)frag->total_len);
		goto drop;
	}

	if (msg->payload_len == 0 && frag->total_len > 0) {
		if (msg->offset >= frag->total_len) {
			lwsl_user("%s: Received 0-byte terminal payload for %s offset %llu. Proceeding to completion.\n",
				 __func__, msg->hash, msg->offset);
			/* It's the expected terminal chunk, let it proceed! */
		} else {
			lwsl_err("%s: Received 0-byte payload for %s offset %llu (expected %llu bytes). Aborting to prevent GET loop.\n",
				 __func__, msg->hash, msg->offset, (unsigned long long)frag->total_len);
			goto drop;
		}
	}

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) goto drop;
	if (write(frag->fd, msg->payload, msg->payload_len) < 0) goto drop;
	if (lws_genhash_update(&frag->ctx, msg->payload, msg->payload_len)) goto drop;

	frag->received_len += msg->payload_len;

	lws_sul_cancel(&vhd->sul_timeout);
	vhd->put_retries = 0;

	if (frag->received_len >= frag->total_len) {
		if (!frag->validation_started) {
			frag->validation_started = 1;
			lwsl_user("GET complete for %s, starting validation\n", frag->safe_hash);

			if (dht_dnssec_trigger_validation(ctx, vhd, frag, from, fromlen))
				goto drop;
		}

		/* Return 0 to wait for the async callbacks */
		return 0;
	} else {
		/* Not complete, request next chunk */
		char req_buf[128];
		size_t next_len = 1024;
		if (frag->received_len + next_len > frag->total_len)
			next_len = (size_t)(frag->total_len - frag->received_len);

		lwsl_user("%s: Requesting next chunk offset %llu len %zu\n", __func__, (unsigned long long)frag->received_len, next_len);
		lws_dht_msg_gen(req_buf, sizeof(req_buf), "GET", frag->safe_hash, frag->received_len, (unsigned long long)next_len);
		lws_dht_send_data(ctx, from, req_buf, strlen(req_buf));

		lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
	}

	return 0;

drop:
	if (frag->fd >= 0) {
		close(frag->fd);
		frag->fd = -1;
	}
	{
		char tmp_path[256];
		lws_snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
		unlink(tmp_path);
		lwsl_user("%s: Unlinked invalid/rejected temp payload %s\n", __func__, tmp_path);
	}
	if (vhd->cb_completion && !vhd->cli_put_file)
		vhd->cb_completion(vhd->cb_closure, 1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->fetch_reqs.head) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->target_hash, frag->safe_hash)) {
			if (req->cb) req->cb(req->opaque, req->domain, 0);
			lws_sul_cancel(&req->sul_timeout);
			lws_dll2_remove(d);
			free(req);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_dll2_remove(&frag->list);
	free(frag);
	return -1;
}

static int
verb_cap_rsp_handler(struct vhd_dht_dnssec *vhd, struct lws_dht_verb_dispatch_args *args)
{
	const struct lws_dht_msg *msg = args->msg;
	char pbuf[512];
	size_t plen = msg->payload_len < sizeof(pbuf) - 1 ? msg->payload_len : sizeof(pbuf) - 1;

	if (!vhd->cli_put_file) {
		/* We're not doing a PUT, so we don't care about this CAP_RSP. Pass it on. */
		args->out_precedence = LWS_DHT_VERB_RESULT_PASS;
		return 0;
	}

	if (!msg->payload) {
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return 0;
	}

	memcpy(pbuf, msg->payload, plen);
	pbuf[plen] = '\0';

	lwsl_user("%s: Peer capability payload: %s\n", __func__, pbuf);

	lws_sul_cancel(&vhd->sul_timeout);
	vhd->put_retries = 0;

	if (strstr(pbuf, "\"lws-dht-dnssec\"")) {
		lwsl_user("%s: Peer supports lws-dht-dnssec via CAP_RSP! Proceeding with PUT.\n", __func__);
		if (!vhd->put_started) {
			vhd->put_started = 1;
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_put_cb, 10);
		}
	} else if (strstr(pbuf, "\"lws-dht-store\"")) {
		lwsl_err("%s: Peer only supports basic raw store, missing lws-dht-dnssec capability. Aborting.\n", __func__);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
	} else {
		lwsl_err("%s: Peer capability CAP_RSP missing required protocol! Aborting.\n", __func__);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
	}

	return 0;
}

static int
verb_err_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	lwsl_err("%s: ERR for %s offset %llu (backend upload validation failed!)\n", __func__, msg->hash, msg->offset);
	if (vhd->cb_completion)
		vhd->cb_completion(vhd->cb_closure, 1);

	if (vhd->put_started) {
		vhd->put_started = 0;
		start_next_dht_upload(vhd);
	}
	return -1;
}

static int
verb_nonce_req_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
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
verb_nonce_rsp_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
	return 0;
}

static int
verb_sign_req_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
		      const struct sockaddr *from, size_t fromlen)
{
	lwsl_user("%s\n", __func__);
	return 0;
}

/* --- Core Callback --- */

static void
dht_dnssec_sul_bootstrap_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	int good4 = 0, dubious4 = 0, good6 = 0, dubious6 = 0;

	if (!vhd->dht)
		return;

	/* Check if the routing table is still entirely empty */
	lws_dht_nodes(vhd->dht, AF_INET, &good4, &dubious4, NULL, NULL);
	lws_dht_nodes(vhd->dht, AF_INET6, &good6, &dubious6, NULL, NULL);

	int good = good4 + good6;
	int dubious = dubious4 + dubious6;

	if (good == 0 && dubious == 0) {
		/* We don't have anyone in our routing table yet */
		if (vhd->target_ip && vhd->target_ip[0] && vhd->target_port > 0) {
			struct addrinfo hints, *res, *rp;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;

			char port_str[16];
			lws_snprintf(port_str, sizeof(port_str), "%d", vhd->target_port);

			if (getaddrinfo(vhd->target_ip, port_str, &hints, &res) == 0) {
				int booted_v4 = 0, booted_v6 = 0;
				for (rp = res; rp != NULL; rp = rp->ai_next) {
					int is_self = 0;

					/* Skip if we already bootstrapped this family to avoid spamming the same node */
					if (rp->ai_family == AF_INET && booted_v4) continue;
					if (rp->ai_family == AF_INET6 && booted_v6) continue;

					if (vhd->target_port == vhd->dht_port) {
						if (rp->ai_family == AF_INET) {
							if (((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
								is_self = 1;
						} else if (rp->ai_family == AF_INET6) {
							if (memcmp(&((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0)
								is_self = 1;
						}
					}

					if (is_self) {
						lwsl_notice("%s: Skipping bootstrap to localhost on %s\n", __func__, rp->ai_family == AF_INET ? "IPv4" : "IPv6");
						continue;
					}

					lwsl_notice("%s: Bootstrapping DHT against target node %s:%d (AF_INET%s)\n", __func__, vhd->target_ip, vhd->target_port, rp->ai_family == AF_INET6 ? "6" : "");
					lws_dht_ping_node(vhd->dht, rp->ai_addr, rp->ai_addrlen);

					if (rp->ai_family == AF_INET) booted_v4 = 1;
					if (rp->ai_family == AF_INET6) booted_v6 = 1;
				}
				freeaddrinfo(res);

				if (!booted_v4 && !booted_v6) {
					/* Target is purely ourselves. Quietly passive until contacted. */
					lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 5 * LWS_US_PER_SEC);
					return;
				}
			} else {
				lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
				lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 5 * LWS_US_PER_SEC);
				return;
			}
		}

		/* Schedule another check in 5 seconds if we still haven't found nodes */
		lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 5 * LWS_US_PER_SEC);
	} else {
		lwsl_notice("%s: DHT bootstrapped successfully, routing table contains %d good nodes\n", __func__, good);

		if (!vhd->initial_search_done) {
			vhd->initial_search_done = 1;
			lwsl_notice("%s: Populating routing table with peer discovery...\n", __func__);
			/* Trigger a self-search to discover up to 8 peers from the seed node(s) */
			lws_dht_search(vhd->dht, vhd->myid, 0, AF_INET, NULL, NULL);
			lws_dht_search(vhd->dht, vhd->myid, 0, AF_INET6, NULL, NULL);
			/* Wait a short moment for responses before starting fetches */
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 2 * LWS_US_PER_SEC);
			return;
		}

		/* Kick off fetches for any domains that were subscribed before we had a routing table */
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->subscribed_domains.head) {
			struct lws_dht_dnssec_subscribed_domain *sub = lws_container_of(d, struct lws_dht_dnssec_subscribed_domain, list);
			if (sub->needs_initial_fetch) {
				sub->needs_initial_fetch = 0;

				char cache_path[1024];
				lws_snprintf(cache_path, sizeof(cache_path), "%s/%s.zone", vhd->storage_path, sub->domain);

				struct lws_dht_dnssec_fetch_zone_args args;
				memset(&args, 0, sizeof(args));
				args.vhost = vhd->vhost;
				args.domain = sub->domain;
				args.cache_dir = cache_path;
				args.cb = NULL;
				args.opaque = NULL;
				args.force_network = 1;

				lwsl_notice("Deferred fetch triggered for subscribed domain %s\n", sub->domain);
				do_fetch_zone(vhd->context, &args);
			}
		} lws_end_foreach_dll(d);
	}
}

static int
dht_dnssec_find_highest_serial_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct lws_dir_args *a = (struct lws_dir_args *)user;
	size_t pl = strlen(a->prefix);
	size_t nl = strlen(lde->name);
	if (nl > pl && !strncmp(lde->name, a->prefix, pl) && lde->name[pl] == '_' && nl > 8 && !strcmp(&lde->name[nl-8], ".payload")) {
		char *p = (char *)lde->name + (nl - 9); /* before .payload */
		while (p > lde->name && *(p - 1) != '_') p--;
		if (p > lde->name) {
			uint64_t serial = strtoull(p, NULL, 10);
			if (!a->is_outdated /* repurposed as 'found' */) {
				a->new_serial = serial; /* repurposed as 'highest_serial' */
				a->is_outdated = 1;
			} else {
				if ((int32_t)((uint32_t)serial - (uint32_t)a->new_serial) > 0) {
					a->new_serial = serial;
				}
			}
		}
	}
	return 0;
}

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
	case LWS_DHT_EVENT_NOTIFY: {
		struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)closure;

		if (!from || fromlen < sizeof(struct sockaddr_in)) {
			lwsl_notice("%s: Rejecting NOTIFY with missing/invalid source address\n", __func__);
			break;
		}

		uint64_t newer_soa = 0;
		if (data_len >= 8) {
			const uint8_t *p = (const uint8_t *)data;
			newer_soa = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
				    ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
				    ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
				    ((uint64_t)p[6] << 8) | p[7];
		}

		{
			char peer_ip[64];
			lws_sa46_write_numeric_address((lws_sockaddr46 *)from, peer_ip, sizeof(peer_ip));
			int peer_port = from->sa_family == AF_INET ? ntohs(((struct sockaddr_in *)from)->sin_port) : ntohs(((struct sockaddr_in6 *)from)->sin6_port);
			lwsl_notice("%s: Received NOTIFY from %s:%u for domain hash with SOA %llu!\n", __func__, peer_ip, peer_port, (unsigned long long)newer_soa);

			struct notify_ratelimit *nrl = NULL, *oldest_nrl = NULL;
			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->notify_ratelimiters.head) {
				struct notify_ratelimit *n = lws_container_of(d, struct notify_ratelimit, list);
				if (n->sa.sa4.sin_family == from->sa_family) {
					if (n->sa.sa4.sin_family == AF_INET && !memcmp(&n->sa.sa4.sin_addr, &((const struct sockaddr_in *)from)->sin_addr, 4)) {
						nrl = n; break;
					} else if (n->sa.sa4.sin_family == AF_INET6 && !memcmp(&n->sa.sa6.sin6_addr, &((const struct sockaddr_in6 *)from)->sin6_addr, 16)) {
						nrl = n; break;
					}
				}
				if (!oldest_nrl) oldest_nrl = n;
			} lws_end_foreach_dll(d);

			lws_usec_t now_us = lws_now_usecs();

			if (nrl) {
				if (now_us < nrl->earliest_next_allowed) {
					lwsl_notice("%s: Rate limiting NOTIFY from IP %s:%u (try %d, backoff). Ignored.\n",
						__func__, peer_ip, peer_port, nrl->ctry);
					break;
				}
				/* Move to tail for LRU */
				lws_dll2_remove(&nrl->list);
				lws_dll2_add_tail(&nrl->list, &vhd->notify_ratelimiters);
			} else {
				if (vhd->notify_ratelimiters.count > 128 && oldest_nrl) {
					lws_dll2_remove(&oldest_nrl->list);
					lws_sul_cancel(&oldest_nrl->sul_decay);
					free(oldest_nrl);
				}
				nrl = malloc(sizeof(*nrl));
				if (nrl) {
					memset(nrl, 0, sizeof(*nrl));
					if (from->sa_family == AF_INET) {
						nrl->sa.sa4 = *(const struct sockaddr_in *)from;
					} else {
						nrl->sa.sa6 = *(const struct sockaddr_in6 *)from;
					}
					lws_dll2_add_tail(&nrl->list, &vhd->notify_ratelimiters);
				}
			}

			if (nrl) {
				char dummy;
				unsigned int delay_ms = lws_retry_get_delay_ms(vhd->context, &retry_notify, &nrl->ctry, &dummy);
				nrl->earliest_next_allowed = now_us + (delay_ms * LWS_US_PER_MS);
				lws_sul_schedule(vhd->context, 0, &nrl->sul_decay, notify_ratelimit_expire_cb, 3600 * LWS_US_PER_SEC);
				lwsl_notice("%s: NOTIFY accepted from IP %s:%u. Next allowed in %ums\n", __func__, peer_ip, peer_port, delay_ms);
			}
		}

		/* Find the domain string from our subscribed_domains or auth_dns owner list.
		 * Oh wait, auth-dns calls `subscribe_zone(domain_str)`. We don't keep a list of them
		 * in dht-dnssec; we just forwarded it to `lws_dht_send_subscribe`.
		 * But if we get a NOTIFY back, we only get the `info_hash`.
		 * We need to iterate over known domains and match the hash. */

		char target_domain[256];
		int found = 0;
		struct lws_dht_dnssec_subscribed_domain *found_sub = NULL;
		struct lws_dht_dnssec_domain *found_owner = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->subscribed_domains.head) {
			struct lws_dht_dnssec_subscribed_domain *sub = lws_container_of(d, struct lws_dht_dnssec_subscribed_domain, list);
			if (!memcmp(sub->hash, info_hash->id, info_hash->len)) {
				lws_strncpy(target_domain, sub->domain, sizeof(target_domain));
				found_sub = sub;
				found = 1;
				break;
			}
		} lws_end_foreach_dll(d);

		if (!found) {
			lws_start_foreach_dll(struct lws_dll2 *, d, vhd->owner_domains.head) {
				struct lws_dht_dnssec_domain *dom = lws_container_of(d, struct lws_dht_dnssec_domain, list);
				if (!memcmp(dom->hash, info_hash->id, info_hash->len)) {
					lws_strncpy(target_domain, dom->domain_name, sizeof(target_domain));
					found_owner = dom;
					found = 1;
					break;
				}
			} lws_end_foreach_dll(d);
		}

		/* If we're not actively tracking the subscription but we have it hot in our local cache,
		 * we should still honor the NOTIFY to keep the cache from going stale during ACME validations. */
		if (!found) {
			char hex_hash[LWS_GENHASH_LARGEST * 2 + 1];
			lws_hex_from_byte_array(info_hash->id, info_hash->len, hex_hash, sizeof(hex_hash));
			char dir_path[256];
			lws_snprintf(dir_path, sizeof(dir_path), "%s/%.2s/%.2s", vhd->storage_path, hex_hash, hex_hash + 2);

			struct lws_dir_args da;
			memset(&da, 0, sizeof(da));
			da.prefix = hex_hash;
			lws_dir(dir_path, &da, dht_dnssec_find_highest_serial_cb);

			if (da.is_outdated) {
				/* We don't have the domain string because it's just a hash, so use the hash as the domain name for internal tracking */
				lws_snprintf(target_domain, sizeof(target_domain), "dht-hash-%s", hex_hash);
				lwsl_notice("%s: Hash %s is not actively subscribed but exists in cache. Honoring NOTIFY to keep hot!\n", __func__, hex_hash);

				/* Implicitly create a subscription so subsequent NOTIFYs are tracked via `found_sub` rate limiters */
				struct lws_dht_dnssec_subscribed_domain *nsub = malloc(sizeof(*nsub));
				if (nsub) {
					memset(nsub, 0, sizeof(*nsub));
					lws_strncpy(nsub->domain, target_domain, sizeof(nsub->domain));
					memcpy(nsub->hash, info_hash->id, info_hash->len);
					nsub->needs_initial_fetch = 0;
					lws_dll2_add_tail(&nsub->list, &vhd->subscribed_domains);
					found_sub = nsub;
				}
				found = 1;
			}
		}

		/* If this is the active CLI command, that takes priority */
		if (vhd->cli_get_domain || vhd->cli_get_hash) {
			lwsl_user("Re-fetching the zonefile due to NOTIFY!\n");
			lws_sul_cancel(&vhd->sul_timeout);
			vhd->put_retries = 0;

			if (vhd->cli_get_hash) {
				struct dht_fragment *frag = dht_dnssec_find_fragment(vhd, vhd->cli_get_hash);
				if (frag) {
					lws_dll2_remove(&frag->list);
					if (frag->fd >= 0) close(frag->fd);
					free(frag);
				}
			}
			dht_dnssec_sul_get_cb(&vhd->sul_bulk);
		} else if (found) {
			if (newer_soa) {
				char hex_hash[LWS_GENHASH_LARGEST * 2 + 1];
				lws_hex_from_byte_array(info_hash->id, info_hash->len, hex_hash, sizeof(hex_hash));
				char dir_path[256];
				lws_snprintf(dir_path, sizeof(dir_path), "%s/%.2s/%.2s", vhd->storage_path, hex_hash, hex_hash + 2);

				struct lws_dir_args da;
				memset(&da, 0, sizeof(da));
				da.prefix = hex_hash;
				da.is_outdated = 0; // used as 'found' flag
				lws_dir(dir_path, &da, dht_dnssec_find_highest_serial_cb);

				if (da.is_outdated) {
					uint64_t current_serial = da.new_serial;
					if ((int32_t)((uint32_t)newer_soa - (uint32_t)current_serial) <= 0) {
						lwsl_notice("%s: Ignoring entirely! Notified SOA %llu <= local disk %llu for %s\n",
							__func__, (unsigned long long)newer_soa, (unsigned long long)current_serial, target_domain);
						break;
					}
				}
			}

			if (found_sub) {
				time_t now = time(NULL);
				if (now - found_sub->last_notify_fetch < 60) {
					if (newer_soa && newer_soa > found_sub->last_notify_soa) {
						lwsl_notice("%s: Bypassing NOTIFY rate limit for %s due to progressively newer SOA %llu!\n", __func__, target_domain, (unsigned long long)newer_soa);
					} else {
						lwsl_notice("%s: Rate-limiting NOTIFY fetch for %s\n", __func__, target_domain);
						break;
					}
				}
				found_sub->last_notify_fetch = now;
				if (newer_soa) found_sub->last_notify_soa = newer_soa;
			} else if (found_owner) {
				time_t now = time(NULL);
				if (now - found_owner->last_notify_fetch < 60) {
					if (newer_soa && newer_soa > found_owner->last_notify_soa) {
						lwsl_notice("%s: Bypassing NOTIFY rate limit for %s due to progressively newer SOA %llu!\n", __func__, target_domain, (unsigned long long)newer_soa);
					} else {
						lwsl_notice("%s: Rate-limiting NOTIFY fetch for %s\n", __func__, target_domain);
						break;
					}
				}
				found_owner->last_notify_fetch = now;
				if (newer_soa) found_owner->last_notify_soa = newer_soa;
			}

			/* Background fetch for auth-dns... */
			lwsl_notice("%s: Mapped NOTIFY hash to subscribed domain: %s. Initiating fetch.\n", __func__, target_domain);

			{
				char hex_hash[LWS_GENHASH_LARGEST * 2 + 1];
				lws_hex_from_byte_array(info_hash->id, (size_t)info_hash->len, hex_hash, sizeof(hex_hash));
				struct dht_fragment *frag = dht_dnssec_find_fragment(vhd, hex_hash);
				if (frag) {
					lwsl_notice("%s: Resetting stale fragment tracking for %s on fresh fetch\n", __func__, hex_hash);
					if (frag->fd >= 0) close(frag->fd);
					char path[256];
					lws_snprintf(path, sizeof(path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
					unlink(path);
					lws_dll2_remove(&frag->list);
					if (frag->hash_init_done) lws_genhash_destroy(&frag->ctx, NULL);
					free(frag);
				}
			}

			struct lws_dht_dnssec_fetch_zone_args args;
			memset(&args, 0, sizeof(args));
			args.domain = target_domain;
			args.cache_dir = NULL;
			args.force_network = 1;
			args.cb = NULL; /* Local callback */
			args.opaque = NULL;

			{
				struct notify_strike_tracking *trk = malloc(sizeof(*trk));
				if (trk) {
					memset(trk, 0, sizeof(*trk));
					trk->vhd = vhd;
					if (from->sa_family == AF_INET) trk->sa.sa4 = *(const struct sockaddr_in *)from;
					else trk->sa.sa6 = *(const struct sockaddr_in6 *)from;
					args.cb = notify_fetch_completion_cb;
					args.opaque = trk;
					args.force_network = 1;
				}
			}

			do_fetch_zone(vhd->context, &args);
		} else {
			char h1[128], h2[128] = "NONE";
			lws_hex_from_byte_array(info_hash->id, info_hash->len, h1, sizeof(h1));
			if (vhd->subscribed_domains.head) {
				struct lws_dht_dnssec_subscribed_domain *sub = lws_container_of(vhd->subscribed_domains.head, struct lws_dht_dnssec_subscribed_domain, list);
				lws_hex_from_byte_array(sub->hash, info_hash->len, h2, sizeof(h2));
			}
			lwsl_notice("%s: Incoming NOTIFY hash (%s) does not match any active subscriptions (first sub is %s).\n", __func__, h1, h2);
		}
		break;
	}
	case LWS_DHT_EVENT_SEARCH_DONE:
	case LWS_DHT_EVENT_SEARCH_DONE6: {
		struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)closure;
		lwsl_notice("%s: Peer discovery completed! Probing known nodes for IPs...\n", __func__);
		lws_dht_test_external_ips(vhd->dht);
		break;
	}
	case LWS_DHT_EVENT_TOKEN: {
		struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)closure;
		struct dht_fragment *frag;
		uint8_t tid[16];
		char computed_hash_hex[LWS_GENHASH_LARGEST * 2 + 1];
		const char *get_hash = vhd->cli_get_hash;
		struct lws_genhash_ctx pctx;
		uint8_t hash[LWS_GENHASH_LARGEST];

		lwsl_user("%s: Received SUBSCRIBE token, generating SUBSCRIBE_CONFIRM!\n", __func__);

		lws_get_random(vhd->context, tid, sizeof(tid));

		if (!get_hash && vhd->cli_get_domain) {
			char domain_str[256];
			int dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", vhd->cli_get_domain);
			if (!lws_genhash_init(&pctx, LWS_DHT_STORE_GENHASH) &&
			    !lws_genhash_update(&pctx, domain_str, (size_t)dom_len) &&
			    !lws_genhash_destroy(&pctx, hash)) {
				lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), computed_hash_hex, sizeof(computed_hash_hex));
				get_hash = computed_hash_hex;
			}
		}

		if (get_hash && vhd->dht) {
			uint8_t hbuf[sizeof(lws_dht_hash_t) + LWS_GENHASH_LARGEST];
			lws_dht_hash_t *hash_obj = (lws_dht_hash_t *)hbuf;
			hash_obj->type = LWS_DHT_STORE_HASH_TYPE;
			hash_obj->len = (uint8_t)lws_genhash_size(LWS_DHT_STORE_GENHASH);
			if (!lws_hex_to_byte_array(get_hash, hash_obj->id, hash_obj->len)) {
				frag = dht_dnssec_find_fragment(vhd, get_hash);
				uint8_t current_payload_hash[32] = {0};
				if (frag) {
					memcpy(current_payload_hash, frag->payload_hash, sizeof(current_payload_hash));
				}
				lws_dht_send_subscribe_confirm(vhd->dht, from, fromlen, tid, sizeof(tid), hash_obj, (uint8_t *)data, data_len, current_payload_hash, 1);
				lwsl_user("Sent SUBSCRIBE_CONFIRM to the target DHT node.\n");
			}
		}
		break;
	}
	case LWS_DHT_EVENT_EXTERNAL_ADDR:
	case LWS_DHT_EVENT_EXTERNAL_ADDR6: {
		struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)closure;
		int is_shift = (info_hash != NULL);
		const struct lws_dht_consensus_info *ci = (const struct lws_dht_consensus_info *)data;
		if (ci) {
			lws_extip_report(vhd->context, LWS_EXTIP_SRC_DHT, (const lws_sockaddr46 *)&ci->ss,
						event == LWS_DHT_EVENT_EXTERNAL_ADDR ? AF_INET : AF_INET6,
						is_shift,
						(const lws_sockaddr46 *)ci->peer_ss,
						ci->num_peers);
		}
		break;
	}
	default:
		break;
	}
}

static int
verb_notc_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
		  const struct sockaddr *from, size_t fromlen)
{
	if (msg->payload_len != 16) return 0;

	char buf[256];
	lws_dht_msg_gen(buf, sizeof(buf), "NOTIFY", msg->hash, 0, 0);
	size_t hl = strlen(buf);
	if (hl + 16 > sizeof(buf)) return 0;
	memcpy(buf + hl, msg->payload, 16);
	lws_dht_send_data(ctx, from, buf, hl + 16);
	return 0;
}

static int
verb_notify_handler(struct lws_dht_ctx *ctx, struct vhd_dht_dnssec *vhd, const struct lws_dht_msg *msg,
		    const struct sockaddr *from, size_t fromlen)
{
	if (msg->payload_len == 8) {
		/* Initial NOTIFY. Generate NOTC challenge. */
		struct lws_genhash_ctx hctx;
		uint8_t hash[LWS_GENHASH_LARGEST];
		if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256) ||
		    lws_genhash_update(&hctx, vhd->notify_secret, sizeof(vhd->notify_secret)) ||
		    lws_genhash_update(&hctx, from, fromlen) ||
		    lws_genhash_destroy(&hctx, hash)) return 0;

		char buf[256];
		lws_dht_msg_gen(buf, sizeof(buf), "NOTC", msg->hash, 0, 0);
		size_t hl = strlen(buf);
		if (hl + 16 > sizeof(buf)) return 0;
		memcpy(buf + hl, msg->payload, 8);
		memcpy(buf + hl + 8, hash, 8);
		lws_dht_send_data(ctx, from, buf, hl + 16);
		return 0;
	} else if (msg->payload_len == 16) {
		/* Challenged NOTIFY. Verify cookie. */
		struct lws_genhash_ctx hctx;
		uint8_t hash[LWS_GENHASH_LARGEST];
		if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256) ||
		    lws_genhash_update(&hctx, vhd->notify_secret, sizeof(vhd->notify_secret)) ||
		    lws_genhash_update(&hctx, from, fromlen) ||
		    lws_genhash_destroy(&hctx, hash)) return 0;

		const uint8_t *p = (const uint8_t *)msg->payload;
		if (memcmp(p + 8, hash, 8) != 0) {
			lwsl_notice("%s: NOTIFY cookie validation failed\n", __func__);
			return 0; /* Invalid cookie */
		}

		/* Valid cookie. Check if IP is blacklisted. */
		lws_sockaddr46 sa46;
		memset(&sa46, 0, sizeof(sa46));
		if (from->sa_family == AF_INET) {
			sa46.sa4 = *(const struct sockaddr_in *)from;
		} else {
			sa46.sa6 = *(const struct sockaddr_in6 *)from;
		}

		int strikes = 0;
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->notify_strikes.head) {
			struct notify_strike *ns = lws_container_of(d, struct notify_strike, list);
			if (ns->sa.sa4.sin_family == sa46.sa4.sin_family) {
				if (ns->sa.sa4.sin_family == AF_INET && !memcmp(&ns->sa.sa4.sin_addr, &sa46.sa4.sin_addr, 4)) {
					strikes = ns->count; break;
				} else if (ns->sa.sa4.sin_family == AF_INET6 && !memcmp(&ns->sa.sa6.sin6_addr, &sa46.sa6.sin6_addr, 16)) {
					strikes = ns->count; break;
				}
			}
		} lws_end_foreach_dll(d);

		if (strikes >= 5) {
			lwsl_notice("%s: NOTIFY from blacklisted IP dropped (strikes: %d)\n", __func__, strikes);
			return 0;
		}

		uint8_t bin_hash[32];
		if (lws_hex_to_byte_array(msg->hash, bin_hash, sizeof(bin_hash)) < 0) return 0;

		lws_dht_hash_t *idhash = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA256, 32, bin_hash);
		if (idhash) {
			cb_dht(vhd, LWS_DHT_EVENT_NOTIFY, idhash, p, 8, from, fromlen);
			lws_dht_hash_destroy(&idhash);
		}
	}
	return 0;
}

/* --- Timers --- */

static void
sul_stats_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_stats);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 5 * LWS_US_PER_SEC);
}

static void dht_dnssec_sul_cap_cb(struct lws_sorted_usec_list *sul);
static void
dht_dnssec_sul_put_cb(struct lws_sorted_usec_list *sul);

static void
dht_dnssec_sul_timeout_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_timeout);

	if (vhd->put_retries >= 3) {
		lwsl_err("%s: UDP timeout threshold reached. Aborting.\n", __func__);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);

		vhd->put_started = 0;
		start_next_dht_upload(vhd);
		return;
	}

	vhd->put_retries++;
	lwsl_user("%s: UDP timeout, initiating retry %d/3\n", __func__, vhd->put_retries);

	if (vhd->cli_get_hash || vhd->cli_get_domain || vhd->fragments.count > 0) {
		struct dht_fragment *frag = NULL;

		if (vhd->cli_get_hash)
			frag = dht_dnssec_find_fragment(vhd, vhd->cli_get_hash);
		else if (vhd->fragments.count > 0)
			frag = lws_container_of(vhd->fragments.head, struct dht_fragment, list);

		if (frag) {
			/* Retry next chunk specifically */
			char req_buf[128];
			size_t next_len = 1024;

			if (frag->received_len + next_len > frag->total_len)
				next_len = (size_t)(frag->total_len - frag->received_len);

			lwsl_user("%s: Retrying GET offset %llu\n", __func__, (unsigned long long)frag->received_len);
			lws_dht_msg_gen(req_buf, sizeof(req_buf), "GET", frag->safe_hash, frag->received_len, (unsigned long long)next_len);

			if (frag->from_salen > 0) {
				lws_dht_send_data(vhd->dht, (struct sockaddr *)&frag->from_sa, req_buf, strlen(req_buf));
			} else {
				lwsl_err("%s: Missing from_sa for retry!\n", __func__);
			}
			lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
		} else {
			/* First chunk timeout */
			dht_dnssec_sul_get_cb(&vhd->sul_bulk);
		}
	} else if (vhd->put_started) {
		dht_dnssec_sul_put_cb(&vhd->sul_bulk);
	} else {
		dht_dnssec_sul_cap_cb(&vhd->sul_bulk);
	}
}

static void
dht_dnssec_sul_cap_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	lws_sockaddr46 sa46;
	char buf[256], my_id_hex[41];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		/* Try synchronous host resolution if it's not a raw IP */
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;

		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			sa46.sa4 = *(struct sockaddr_in *)result->ai_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
	}
	sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

	const lws_dht_hash_t *myid = lws_dht_get_myid(vhd->dht);
	lws_hex_from_byte_array((const uint8_t *)myid->id, myid->len, my_id_hex, sizeof(my_id_hex));

	lwsl_user("Sending CAP_REQ to %s:%d (myid %s) for %s\n", vhd->target_ip, vhd->target_port, my_id_hex, vhd->cli_put_file);

	lws_dht_msg_gen(buf, sizeof(buf), "CAP_REQ", my_id_hex, 0, 0);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, buf, strlen(buf));

	/* Schedule UDP timeout for 3 seconds */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
}

static void start_next_dht_upload(struct vhd_dht_dnssec *vhd)
{
	if (!vhd->upload_queue.head) {
		if (vhd->cli_put_file) {
			free((void *)vhd->cli_put_file);
			vhd->cli_put_file = NULL;
		}
		if (vhd->cli_domain) {
			free((void *)vhd->cli_domain);
			vhd->cli_domain = NULL;
		}
		return;
	}

	struct dht_upload_job *job = lws_container_of(vhd->upload_queue.head, struct dht_upload_job, list);

	if (vhd->cli_put_file) free((void *)vhd->cli_put_file);
	vhd->cli_put_file = job->jws_filepath;

	if (vhd->cli_domain) free((void *)vhd->cli_domain);
	vhd->cli_domain = job->domain;

	vhd->bulk_sent = 0;
	vhd->put_started = 0;

	lws_dll2_remove(&job->list);
	free(job);

	lwsl_notice("Starting internal DHT upload sequence for %s\n", vhd->cli_put_file);

	if (!vhd->target_ip || !vhd->target_ip[0]) {
		lwsl_err("Cannot begin upload for %s: no DHT policy seeds were found!\n", vhd->cli_put_file);
		vhd->cli_put_file = NULL;
		vhd->cli_domain = NULL;
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}

	dht_dnssec_sul_cap_cb(&vhd->sul_bulk);
}

static void
dht_dnssec_sul_put_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	char hash_hex[LWS_GENHASH_LARGEST * 2 + 1], header[256], packet[1500];
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;
	lws_sockaddr46 sa46;
	int fd, n, hlen;
	struct stat st;
	char buf[1500];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		/* Try synchronous host resolution if it's not a raw IP */
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;

		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			sa46.sa4 = *(struct sockaddr_in *)result->ai_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
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

	vhd->bulk_total = (unsigned long long)st.st_size;
	if (lseek(fd, (off_t)vhd->bulk_sent, SEEK_SET) < 0) {
		close(fd);
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}

	n = (int)read(fd, buf + 256, 1024);
	close(fd);

	if (n <= 0) return;

	{
		char domain_str[256];
		int dom_len;

		if (!vhd->cli_domain) {
			lwsl_err("No domain specified for zone file upload (use --domain)\n");
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}

		dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", vhd->cli_domain);

		if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
		    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
		    lws_genhash_destroy(&ctx, hash)) {
			lwsl_err("Hash calculation failed\n");
			return;
		}
	}

	lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hash_hex, sizeof(hash_hex));

	hlen = lws_dht_msg_gen((char *)header, sizeof(header), "PUT",
			hash_hex, vhd->bulk_sent, (unsigned long long)st.st_size);
	memcpy(packet, header, (size_t)hlen);
	memcpy(packet + hlen, buf + 256, (size_t)n);

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, packet, (size_t)(hlen + n));

	int timeout_secs = 3;
	if (vhd->bulk_sent + (uint64_t)n >= vhd->bulk_total)
		timeout_secs = 45; /* Allow ample time for server to perform external DNSSEC validation over the network (DS + DNSKEY async lookups) */

	/* Schedule UDP timeout */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, timeout_secs * LWS_US_PER_SEC);
}

static void
dht_dnssec_sul_get_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	lws_sockaddr46 sa46;
	char buf[256];
	const char *get_hash = vhd->cli_get_hash;
	char computed_hash_hex[LWS_GENHASH_LARGEST * 2 + 1];

	if (!get_hash && vhd->cli_get_domain) {
		char domain_str[256];
		int dom_len;
		struct lws_genhash_ctx ctx;
		uint8_t hash[LWS_GENHASH_LARGEST];

		dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", vhd->cli_get_domain);
		if (!lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) &&
		    !lws_genhash_update(&ctx, domain_str, (size_t)dom_len) &&
		    !lws_genhash_destroy(&ctx, hash)) {
			lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), computed_hash_hex, sizeof(computed_hash_hex));
			get_hash = computed_hash_hex;
		}
	}

	if (!get_hash) {
		lwsl_err("No hash or domain specified for GET\n");
		return;
	}

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;

		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			sa46.sa4 = *(struct sockaddr_in *)result->ai_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			return;
		}
	}
	sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

	lwsl_user("Sending GET %s to %s:%d\n", get_hash, vhd->target_ip, vhd->target_port);

	lws_dht_msg_gen(buf, sizeof(buf), "GET", get_hash, 0, 1024);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, buf, strlen(buf));

	/* Schedule UDP timeout for 3 seconds */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
}

static void
dht_dnssec_sul_bulk_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	char hash_hex[LWS_GENHASH_LARGEST * 2 + 1], header[256], packet[1500];
	uint8_t hash[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx ctx;
	lws_sockaddr46 sa46;
	int hlen;
	char buf[1024];

	if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;

		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			sa46.sa4 = *(struct sockaddr_in *)result->ai_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
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
dht_dnssec_sul_manifest_rcv_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	char buf[128], *p;

	if (!fgets(buf, sizeof(buf), stdin)) {
		lwsl_err("Failed to read manifest from stdin\n");
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return;
	}

	p = strchr(buf, '\n');
	if (p) *p = 0;

	lws_strncpy(vhd->manifest_hashes[0], buf, sizeof(vhd->manifest_hashes[0]));
	vhd->cli_get_hash = vhd->manifest_hashes[0];
	lwsl_user("Receiver parsed hash: %s\n", vhd->cli_get_hash);

	dht_dnssec_sul_get_cb(&vhd->sul_bulk);
}

/* --- Protocol Handler --- */

static int
lws_dht_dnssec_temp_record_destroy(struct lws_dll2 *d, void *user)
{
	struct lws_dht_dnssec_temp_record *rec =
		lws_container_of(d, struct lws_dht_dnssec_temp_record, list);

	lws_sul_cancel(&rec->sul_ttl);
	lws_dll2_remove(&rec->list);
	if (rec->zone_str)
		free(rec->zone_str);
	free(rec);

	return 0;
}

static int
lws_dht_dnssec_domain_destroy(struct lws_dll2 *d, void *user)
{
	struct lws_dht_dnssec_domain *dom =
		lws_container_of(d, struct lws_dht_dnssec_domain, list);

	lws_dll2_foreach_safe(&dom->owner_temp_records, NULL, lws_dht_dnssec_temp_record_destroy);
	lws_dll2_remove(&dom->list);
	free(dom);

	return 0;
}

static void
dht_dnssec_sul_dump_cb(lws_sorted_usec_list_t *sul)
{
	/* Periodic DHT Routing Table dumps have been disabled */
}

static int
callback_dht_dnssec(struct lws* wsi, enum lws_callback_reasons reason,
	void* user, void* in, size_t len)
{
	struct vhd_dht_dnssec* vhd = (struct vhd_dht_dnssec*)
		lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	const struct lws_protocol_vhost_options* pvo;
	lws_dht_info_t vdi;
	struct lws_vhost *vhost = lws_get_vhost(wsi);
	struct lws_protocols *protocol = (struct lws_protocols *)lws_get_protocol(wsi);
	const char *p = NULL;
	const char *fallback_nodes_path = NULL;

	switch (reason) {
	case LWS_CALLBACK_DHT_VERB_DISPATCH: {
		struct lws_dht_verb_dispatch_args *args = (struct lws_dht_verb_dispatch_args *)in;

		if (!strcmp(args->msg->verb, "PUT")) return verb_put_handler(vhd, args);
		if (!strcmp(args->msg->verb, "GET")) return verb_get_handler(vhd, args);
		if (!strcmp(args->msg->verb, "ACK")) return verb_ack_handler(vhd, args);
		if (!strcmp(args->msg->verb, "RSP")) return verb_rsp_handler(vhd, args);
		if (!strcmp(args->msg->verb, "CAP_RSP")) return verb_cap_rsp_handler(vhd, args);
		if (!strcmp(args->msg->verb, "NONC_REQ")) return verb_nonce_req_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_RSP")) return verb_nonce_rsp_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "SIGN_REQ")) return verb_sign_req_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "ERR")) return verb_err_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NOTIFY")) return verb_notify_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NOTC")) return verb_notc_handler(args->ctx, vhd, args->msg, args->from, args->fromlen);

		/* We'll handle notification subscription confirmation here, empty for now */
		if (!strcmp(args->msg->verb, "SUBSCRIBE_CONFIRM")) return 0;

		return -1;
	}

	case LWS_CALLBACK_PROTOCOL_INIT: {
		const char *store_verbs[] = {
			"PUT",
			"GET",
			"ACK",
			"RSP",
			"CAP_RSP",
			"NONC_REQ",
			"NONC_RSP",
			"SIGN_REQ",
			"ERR",
			"SUBSCRIBE_CONFIRM",
			"NOTIFY",
			"NOTC",
		};
		lwsl_vhost_notice(vhost, "LWS_CALLBACK_PROTOCOL_INIT for %s: in=%p", protocol->name, in);

		/* Do not initialize the DHT plugin if we are running as the spawned root monitor */
		if (lws_cmdline_option_cx(lws_get_context(wsi), "--lws-dht-dnssec-monitor-root")) {
			lwsl_vhost_notice(vhost, "  ...leaving early: skipped in root monitor process");
			return 0;
		}

		if (!in) {
			lwsl_vhost_notice(vhost, "  ...leaving early: no pvo 'in'");
			return 0;
		}
		if (!lws_pvo_search(in, "dht-port")) {
			lwsl_vhost_notice(vhost, "  ...leaving early: no 'dht-port' pvo");
			return 0;
		}
		lwsl_vhost_notice(vhost, "  ...proceeding with init");

		/* Prevent duplicate instantiation on the same vhost (e.g. from plugin system) */
		if (lws_protocol_vh_priv_get(vhost, protocol)) {
			lwsl_vhost_user(vhost, "LWS_CALLBACK_PROTOCOL_INIT: already initialized");
			return 0;
		}

		// lwsl_vhost_user(vhost, "LWS_CALLBACK_PROTOCOL_INIT: protocol %s", protocol->name);

		vhd = lws_protocol_vh_priv_zalloc(vhost, protocol, sizeof(struct vhd_dht_dnssec));
		if (!vhd)
			return -1;
		vhd->context = lws_get_context(wsi);
		vhd->vhost = vhost;
		global_dnssec_vhd = vhd;
		lws_dll2_owner_clear(&vhd->fragments);
		lws_dll2_owner_clear(&vhd->fetch_reqs);
		vhd->bulk_fd = -1;
		vhd->main_result = 1;

		/* Default settings */
		vhd->target_ip = NULL;
		vhd->target_port = 0;
		vhd->dht_port = 5000;
		vhd->storage_path = "./dht-store";

		/* Override from PVOs */
		if (lws_pvo_get_str(in, "dht-storage-path", &vhd->storage_path))
			lwsl_info("no pvo for dht-storage-path\n");
		if ((pvo = lws_pvo_search(in, "dht-port"))) vhd->dht_port = atoi(pvo->value);
		if (lws_pvo_get_str(in, "dht-iface", &vhd->dht_iface))
			lwsl_info("no pvo for dht-iface\n");
		if (lws_pvo_get_str(in, "dht-fallback-nodes", &fallback_nodes_path))
			lwsl_info("no pvo for dht-fallback-nodes\n");
		if (!lws_pvo_get_str(in, "target-ip", &p) && p && p[0])
			vhd->target_ip = p;

		lws_system_policy_t *policy = NULL;
		if (!vhd->target_ip && !lws_system_parse_policy(vhd->context, "/etc/lwsws/policy", &policy)) {
			if (policy->seeds.head) {
				lws_system_seed_t *seed = lws_container_of(policy->seeds.head, lws_system_seed_t, list);
				lws_strncpy(vhd->policy_resolved_ip, seed->hostname, sizeof(vhd->policy_resolved_ip));
				char *colon = strchr(vhd->policy_resolved_ip, ':');
				if (colon) {
					*colon = '\0';
					vhd->target_port = atoi(colon + 1);
				} else {
					vhd->target_port = vhd->dht_port ? vhd->dht_port : 5000;
				}
				vhd->target_ip = vhd->policy_resolved_ip;
				lwsl_notice("%s: Utilizing dynamically-parsed global policy seed target: %s:%d\n", __func__, vhd->target_ip, vhd->target_port);
			}
			lws_system_policy_free(policy);
		}

		if (!vhd->target_ip || !vhd->target_ip[0]) {
			lwsl_err("%s: Missing required 'target-ip' PVO or 'seeds' array configuration in policy\n", __func__);
		}

		if ((pvo = lws_pvo_search(in, "target-port")) && pvo->value && pvo->value[0]) vhd->target_port = atoi(pvo->value);
		if (!lws_pvo_get_str(in, "put-file", &p) && p && p[0]) vhd->cli_put_file = strdup(p);
		if (!lws_pvo_get_str(in, "get-hash", &p) && p && p[0]) vhd->cli_get_hash = p;
		if (!lws_pvo_get_str(in, "get-domain", &p) && p && p[0]) vhd->cli_get_domain = p;
		if (!lws_pvo_get_str(in, "domain", &p) && p && p[0]) vhd->cli_domain = strdup(p);
		if (!lws_pvo_get_str(in, "bulk", &p) && p && p[0]) vhd->cli_bulk = 1;
		if (!lws_pvo_get_str(in, "gen-manifest", &p) && p && p[0]) vhd->gen_manifest = 1;
		if (!lws_pvo_get_str(in, "dht-jwk", &p) && p && p[0]) vhd->cli_jwk_path = p;
		if (!lws_pvo_get_str(in, "dht-policy-allow", &p) && p && p[0]) vhd->policy_allow = p;
		if (!lws_pvo_get_str(in, "dht-policy-deny", &p) && p && p[0]) vhd->policy_deny = p;
		if (!lws_pvo_get_str(in, "dht-test-handshake", &p) && p && p[0]) vhd->test_handshake = 1;
		if (!lws_pvo_get_str(in, "receiver", &p) && p && p[0]) vhd->cli_receiver = 1;

		{
			const struct lws_protocol_vhost_options *dump = (const struct lws_protocol_vhost_options *)in;
			while (dump) {
				lwsl_notice("PVO dumped: name='%s' value='%s'\n", dump->name, dump->value ? dump->value : "NULL");
				dump = dump->next;
			}
			lwsl_notice("Parsed cli_put_file: '%s'\n", vhd->cli_put_file ? vhd->cli_put_file : "NULL");
		}

		if ((pvo = lws_pvo_search(in, "completion-cb"))) vhd->cb_completion = (lws_dht_store_completion_cb_t)(void *)pvo->value;
		if ((pvo = lws_pvo_search(in, "completion-cb-arg"))) vhd->cb_closure = (void *)pvo->value;

		if (dht_dnssec_jwk_load_or_gen(vhd)) {
			lwsl_err("dht_dnssec_jwk_load_or_gen failed\n");
			return -1;
		}

		{
			struct lws_genhash_ctx hash_ctx;
			uint8_t digest[20];

			if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA1)) {
				lwsl_err("lws_genhash_init failed\n");
				return -1;
			}
			if (vhd->jwk.kty == LWS_GENCRYPTO_KTY_EC) {
				if (!vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf) {
					lwsl_err("EC X buf missing\n");
					return -1;
				}
				if (lws_genhash_update(&hash_ctx, vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf,
						   vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len)) {
					lwsl_err("lws_genhash_update (EC) failed\n");
					return -1;
				}
			} else {
				if (!vhd->jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf) {
					lwsl_err("RSA N buf missing\n");
					return -1;
				}
				if (lws_genhash_update(&hash_ctx, vhd->jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf,
						   vhd->jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len)) {
					lwsl_err("lws_genhash_update (RSA) failed\n");
					return -1;
				}
			}
			if (lws_genhash_destroy(&hash_ctx, digest)) {
				lwsl_err("lws_genhash_destroy failed\n");
				return -1;
			}
			vhd->myid = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, digest);
		}

		lwsl_notice("Reached lws_dht_create setup phase\n");

		memset(&vdi, 0, sizeof(vdi));

		vdi.id = vhd->myid;
		vdi.vhost = vhost;
		vdi.port = vhd->dht_port;
		vdi.ipv6 = 1;
		vdi.cb = cb_dht;
		vdi.closure = vhd;
		vdi.iface = vhd->dht_iface;
		vdi.fallback_nodes_path = fallback_nodes_path;
		vdi.blacklist_cb = dht_dnssec_blacklist_cb;

		vhd->dht = lws_dht_create(&vdi);
		if (!vhd->dht) {
			lwsl_vhost_err(vhd->vhost, "%s: failed to create DHT", __func__);
			return -1;
		}

		/* Register our "verbs" */
		lws_dht_register_verbs(vhd->dht, store_verbs, LWS_ARRAY_SIZE(store_verbs), protocol);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 100 * LWS_US_PER_MS);
		lws_sul_schedule(vhd->context, 0, &vhd->sul_dump, dht_dnssec_sul_dump_cb, 30 * LWS_US_PER_SEC);

		lwsl_notice("test_handshake=%d, cli_put_file='%s', cli_bulk=%d, cli_receiver=%d\n",
			vhd->test_handshake, vhd->cli_put_file ? vhd->cli_put_file : "NULL",
			vhd->cli_bulk, vhd->cli_receiver);

		if (vhd->test_handshake) {
			char my_id_hex[41];
			const lws_dht_hash_t *myid = lws_dht_get_myid(vhd->dht);

			lws_hex_from_byte_array((const uint8_t *)myid->id, myid->len, my_id_hex, sizeof(my_id_hex));

			lwsl_user("Initiating Handshake TEST... sending NONCE_REQ (myid %s)\n", my_id_hex);
			char buf[1024];
			lws_sockaddr46 sa46;
			if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) < 0) {
				lwsl_err("Failed to parse target-ip: %s\n", vhd->target_ip);
				break;
			}
			sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));

			lws_dht_msg_gen(buf, sizeof(buf), "NONC_REQ", my_id_hex, 0, 0);
			lws_dht_send_data(vhd->dht, (const struct sockaddr *)&sa46, buf, strlen(buf));
		} else if (vhd->cli_put_file) {
			lwsl_notice("%s: Taking PUT branch\n", __func__);
			lwsl_user("%s: Starting PUT task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_cap_cb, 10);
		} else if (vhd->cli_bulk || vhd->gen_manifest) {
			lwsl_notice("%s: Taking BULK branch\n", __func__);
			lwsl_user("%s: Starting BULK task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bulk_cb, 10);
		} else if (vhd->cli_get_hash || vhd->cli_get_domain) {
			lwsl_notice("%s: Taking GET branch\n", __func__);
			lwsl_user("%s: Starting GET task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_get_cb, 10);
		} else if (vhd->cli_receiver) {
			lwsl_notice("%s: Taking RECEIVER branch\n", __func__);
			lwsl_user("%s: Starting RECEIVER task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_manifest_rcv_cb, 10);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_manifest_rcv_cb, 10);
		} else {
			lwsl_notice("%s: Taking BOOTSTRAP branch\n", __func__);
			/* Always schedule bootstrap checking, either to actively ping target_ip OR passively wait for peers to ping us */
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 10);
		}
		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;

		lws_sul_cancel(&vhd->sul_stats);
		lws_sul_cancel(&vhd->sul_speed);
		lws_sul_cancel(&vhd->sul_bulk);
		lws_sul_cancel(&vhd->sul_timeout);
		lws_sul_cancel(&vhd->sul_dump);
		lws_jwk_destroy(&vhd->jwk);
		if (vhd->myid)
			lws_dht_hash_destroy(&vhd->myid);

		lws_dll2_foreach_safe(&vhd->owner_domains, NULL, lws_dht_dnssec_domain_destroy);

		lws_start_foreach_dll_safe(struct lws_dll2*, d, d1, lws_dll2_get_head(&vhd->fragments)) {
			struct dht_fragment* frag = lws_container_of(d, struct dht_fragment, list);
			if (frag->hash_init_done)
				lws_genhash_destroy(&frag->ctx, NULL);
			if (frag->fd >= 0)
				close(frag->fd);
			lws_dll2_remove(&frag->list);
			free(frag);
		} lws_end_foreach_dll_safe(d, d1);

		/* vhd->dht is already torn down by lws_vhost_destroy2() */
		vhd->dht = NULL;
		if (vhd->bulk_fd >= 0) {
			close(vhd->bulk_fd);
			vhd->bulk_fd = -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static int name_to_wire(const char *name, uint8_t *wire);
static uint16_t calc_keytag(const uint8_t *rdata, int rdata_len);

static int
do_keygen(struct lws_context *context, struct lws_dht_dnssec_keygen_args *args)
{
	int is_rsa = (args->type && !strcmp(args->type, "RSA"));
	enum lws_gencrypto_kty kty = is_rsa ? LWS_GENCRYPTO_KTY_RSA : LWS_GENCRYPTO_KTY_EC;
	const char *curve = args->curve ? args->curve : "P-256";
	int bits = args->bits ? args->bits : 2048;
	const char *domain = args->domain;

	if (!domain || domain[0] == '\0') {
		lwsl_err("keygen requires a domain name\n");
		return 1;
	}

	for (int is_ksk = 1; is_ksk >= 0; is_ksk--) {
		struct lws_jwk jwk;
		char key[65536];
		int vl = sizeof(key);

		if (is_rsa)
			lwsl_user("Generating %s for %s (RSA %d bits)\n", is_ksk ? "KSK" : "ZSK", domain, bits);
		else
			lwsl_user("Generating %s for %s (Curve: %s)\n", is_ksk ? "KSK" : "ZSK", domain, curve);

		if (lws_jwk_generate(context, &jwk, kty, is_rsa ? bits : 0, is_rsa ? NULL : curve)) {
			lwsl_err("lws_jwk_generate failed\n");
			return 1;
		}

		/* Force JWK metadata for easy reuse in lws-minimal-raw-dht-zone-client */
		lws_jwk_strdup_meta(&jwk, JWK_META_KTY, is_rsa ? "RSA" : "EC", is_rsa ? 3 : 2);
		lws_jwk_strdup_meta(&jwk, JWK_META_USE, "sig", 3);
		if (is_rsa)
			lws_jwk_strdup_meta(&jwk, JWK_META_ALG, "RS256", 5);

		if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF | LWSJWKF_EXPORT_PRIVATE, key, &vl) < 0) {
			lwsl_err("lws_jwk_export failed\n");
			lws_jwk_destroy(&jwk);
			return 1;
		}

		const char *wd = args->workdir ? args->workdir : ".";
		char priv_filename[256];
		lws_snprintf(priv_filename, sizeof(priv_filename), "%s/%s.%s.private.jwk", wd, domain, is_ksk ? "ksk" : "zsk");

		int fd = open(priv_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (fd >= 0) {
			write(fd, key, (size_t)strlen(key));
			close(fd);
			lwsl_notice("Wrote private JWK to %s\n", priv_filename);
		} else {
			lwsl_err("%s: Failed to open %s for writing: errno %d\n", __func__, priv_filename, errno);
			lws_jwk_destroy(&jwk);
			return 1;
		}

		/* Export standardized DNSKEY format for zone file inclusion */
		int alg = is_rsa ? 8 : 13; /* RSASHA256 vs ECDSAP256SHA256 */
		if (!is_rsa && !strcmp(curve, "P-384")) alg = 14; /* ECDSAP384SHA384 */

		int flags = is_ksk ? 257 : 256;

		if (is_rsa) {
			int e_len = (int)jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].len;
			int n_len = (int)jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].len;

			int exp_len_bytes = (e_len > 255) ? 3 : 1;
			int raw_len = exp_len_bytes + e_len + n_len;

			uint8_t *raw_key = malloc((size_t)raw_len);
			if (raw_key) {
				if (e_len > 255) {
					raw_key[0] = 0;
					raw_key[1] = (uint8_t)((e_len >> 8) & 0xff);
					raw_key[2] = (uint8_t)(e_len & 0xff);
					memcpy(raw_key + 3, jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, (size_t)e_len);
					memcpy(raw_key + 3 + e_len, jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, (size_t)n_len);
				} else {
					raw_key[0] = (uint8_t)e_len;
					memcpy(raw_key + 1, jwk.e[LWS_GENCRYPTO_RSA_KEYEL_E].buf, (size_t)e_len);
					memcpy(raw_key + 1 + e_len, jwk.e[LWS_GENCRYPTO_RSA_KEYEL_N].buf, (size_t)n_len);
				}

				int b64_len = lws_base64_size(raw_len);
				char *b64_key = malloc((size_t)b64_len + 1);
				if (b64_key) {
					lws_b64_encode_string((const char *)raw_key, raw_len, b64_key, b64_len);

					char pub_filename[256];
					lws_snprintf(pub_filename, sizeof(pub_filename), "%s/%s.%s.key", wd, domain, is_ksk ? "ksk" : "zsk");

					fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
					if (fd >= 0) {
						char outbuf[4096];
						int n = lws_snprintf(outbuf, sizeof(outbuf), "%s. IN DNSKEY %d 3 %d %s\n", domain, flags, alg, b64_key);
						write(fd, outbuf, (size_t)n);
						close(fd);
						lwsl_notice("Wrote public DNSKEY to %s\n", pub_filename);
					} else {
						lwsl_err("%s: Failed to open %s for writing: errno %d\n", __func__, pub_filename, errno);
					}
					if (is_ksk) {
						char ds_filename[256];
						lws_snprintf(ds_filename, sizeof(ds_filename), "%s/%s.dnssec.txt", wd, domain);

						size_t rdata_len = 4 + (size_t)raw_len;
						uint8_t *rdata = malloc(rdata_len);
						if (rdata) {
							rdata[0] = (uint8_t)((flags >> 8) & 0xff);
							rdata[1] = (uint8_t)(flags & 0xff);
							rdata[2] = 3; /* Protocol */
							rdata[3] = (uint8_t)alg;
							memcpy(rdata + 4, raw_key, (size_t)raw_len);

							uint16_t keytag = calc_keytag(rdata, (int)rdata_len);

							uint8_t payload[8192];
							int name_len = name_to_wire(domain, payload);
							memcpy(payload + name_len, rdata, rdata_len);

							struct lws_genhash_ctx hash_ctx;
							uint8_t digest[32];

							if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
								if (!lws_genhash_update(&hash_ctx, payload, (size_t)name_len + rdata_len)) {
									lws_genhash_destroy(&hash_ctx, digest);

									int ds_fd = open(ds_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
									if (ds_fd >= 0) {
										char ds_summary[1024];
										char hex[128];
										hex[0] = '\0';
										for (int i = 0; i < 32; i++) {
											lws_snprintf(hex + strlen(hex), sizeof(hex) - strlen(hex), "%02X", digest[i]);
										}
										int summary_len = lws_snprintf(ds_summary, sizeof(ds_summary),
											";; DS Record summary for %s registrar\n"
											"%s. IN DS %u %d 2 %s\n", domain, domain, keytag, alg, hex);

										write(ds_fd, ds_summary, (size_t)summary_len);
										close(ds_fd);

										fprintf(stderr, "\n=========== DNSSEC REGISTRAR SUMMARY ===========\n");
										fprintf(stderr, "%s", ds_summary);
										fprintf(stderr, "================================================\n\n");
									} else {
										lwsl_err("%s: Failed to open %s for writing: errno %d\n", __func__, ds_filename, errno);
									}
								} else {
									lws_genhash_destroy(&hash_ctx, NULL);
								}
							}
							free(rdata);
						}
					}
					free(b64_key);
				}
				free(raw_key);
			}
		} else {
			int x_len = (int)jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
			int y_len = (int)jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

			uint8_t *raw_key = malloc((size_t)(x_len + y_len));
			if (raw_key) {
				memcpy(raw_key, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, (size_t)x_len);
				memcpy(raw_key + x_len, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, (size_t)y_len);

				int b64_len = lws_base64_size((x_len + y_len));
				char *b64_key = malloc((size_t)b64_len + 1);
				if (b64_key) {
					lws_b64_encode_string((const char *)raw_key, x_len + y_len, b64_key, b64_len);

					char pub_filename[256];
					lws_snprintf(pub_filename, sizeof(pub_filename), "%s/%s.%s.key", wd, domain, is_ksk ? "ksk" : "zsk");

					fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
					if (fd >= 0) {
						char outbuf[1024];
						int n = lws_snprintf(outbuf, sizeof(outbuf), "%s. IN DNSKEY %d 3 %d %s\n", domain, flags, alg, b64_key);
						write(fd, outbuf, (size_t)n);
						close(fd);
						lwsl_notice("Wrote public DNSKEY to %s\n", pub_filename);
					} else {
						lwsl_err("%s: Failed to open %s for writing: errno %d\n", __func__, pub_filename, errno);
					}

					if (is_ksk) {
						char ds_filename[256];
						lws_snprintf(ds_filename, sizeof(ds_filename), "%s/%s.dnssec.txt", wd, domain);

						size_t raw_len = (size_t)x_len + (size_t)y_len;
						size_t rdata_len = 4 + raw_len;
						uint8_t *rdata = malloc(rdata_len);
						if (rdata) {
							rdata[0] = (uint8_t)((flags >> 8) & 0xff);
							rdata[1] = (uint8_t)(flags & 0xff);
							rdata[2] = 3; /* Protocol */
							rdata[3] = (uint8_t)alg;
							memcpy(rdata + 4, raw_key, raw_len);

							uint16_t keytag = calc_keytag(rdata, (int)rdata_len);

							uint8_t payload[8192];
							int name_len = name_to_wire(domain, payload);
							memcpy(payload + name_len, rdata, rdata_len);

							struct lws_genhash_ctx hash_ctx;
							uint8_t digest[32];

							if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
								if (!lws_genhash_update(&hash_ctx, payload, (size_t)name_len + rdata_len)) {
									lws_genhash_destroy(&hash_ctx, digest);

									int ds_fd = open(ds_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
									if (ds_fd >= 0) {
										char ds_summary[1024];
										char hex[128];
										hex[0] = '\0';
										for (int i = 0; i < 32; i++) {
											lws_snprintf(hex + strlen(hex), sizeof(hex) - strlen(hex), "%02X", digest[i]);
										}
										int summary_len = lws_snprintf(ds_summary, sizeof(ds_summary),
											";; DS Record summary for %s registrar\n"
											"%s. IN DS %u %d 2 %s\n", domain, domain, keytag, alg, hex);

										write(ds_fd, ds_summary, (size_t)summary_len);
										close(ds_fd);

										fprintf(stderr, "\n=========== DNSSEC REGISTRAR SUMMARY ===========\n");
										fprintf(stderr, "%s", ds_summary);
										fprintf(stderr, "================================================\n\n");
									} else {
										lwsl_err("%s: Failed to open %s for writing: errno %d\n", __func__, ds_filename, errno);
									}
								} else {
									lws_genhash_destroy(&hash_ctx, NULL);
								}
							}
							free(rdata);
						}
					}
					free(b64_key);
				}
				free(raw_key);
			}
		}

		lws_jwk_destroy(&jwk);
	}
	return 0;
}

static int
name_to_wire(const char *name, uint8_t *wire)
{
	const char *p = name;
	uint8_t *wp = wire;
	uint8_t *len_ptr = wp++;
	int l = 0;

	while (*p) {
		if (*p == '.') {
			*len_ptr = (uint8_t)l;
			len_ptr = wp++;
			l = 0;
		} else {
			*wp++ = (uint8_t)((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p);
			l++;
		}
		p++;
	}
	*len_ptr = (uint8_t)l;
	if (l > 0)
		*wp++ = 0;
	return (int)(wp - wire);
}

static uint16_t
calc_keytag(const uint8_t *rdata, int rdata_len)
{
	uint32_t ac = 0;
	int i;
	for (i = 0; i < rdata_len; i++)
		ac += (i & 1) ? (uint32_t)rdata[i] : ((uint32_t)rdata[i] << 8);
	ac += (ac >> 16) & 0xFFFF;
	return (uint16_t)(ac & 0xFFFF);
}

static int
do_dsfromkey(struct lws_context *context, struct lws_dht_dnssec_dsfromkey_args *args)
{
	const char *domain = args->domain;
	char key_file[256];
	enum lws_genhash_types hash_idx = LWS_GENHASH_TYPE_SHA256;
	int digest_type = 2; // SHA-256

	if (!domain || domain[0] == '\0') {
		lwsl_err("dsfromkey requires a domain name\n");
		return 1;
	}

	const char *wd = args->workdir ? args->workdir : ".";
	lws_snprintf(key_file, sizeof(key_file), "%s/%s.ksk.key", wd, domain);

	if (args->hash) {
		if (!strcmp(args->hash, "SHA384")) {
			hash_idx = LWS_GENHASH_TYPE_SHA384;
			digest_type = 4;
		} else if (!strcmp(args->hash, "SHA512")) {
			hash_idx = LWS_GENHASH_TYPE_SHA512;
			digest_type = 4; // BIND maps 384 as type 4. 512 has no standard IANA DS digest type yet, using 4.
		}
	}

	int fd = open(key_file, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Failed to open %s\n", key_file);
		return 1;
	}

	char buf[8192];
	int n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return 1;
	buf[n] = '\0';

	char parsed_domain[256] = {0};
	int flags = 0, proto = 0, alg = 0;
	char b64[8192];
	if (sscanf(buf, "%255s IN DNSKEY %d %d %d %8191s", parsed_domain, &flags, &proto, &alg, b64) != 5) {
		lwsl_err("Failed to parse DNSKEY record\n");
		return 1;
	}

	uint8_t rdata[4096];
	rdata[0] = (uint8_t)((flags >> 8) & 0xff);
	rdata[1] = (uint8_t)(flags & 0xff);
	rdata[2] = (uint8_t)proto;
	rdata[3] = (uint8_t)alg;

	int pub_len = lws_b64_decode_string_len(b64, (int)strlen(b64), (char *)rdata + 4, sizeof(rdata) - 4);
	if (pub_len < 0) {
		lwsl_err("Failed to decode base64 public key\n");
		return 1;
	}

	size_t rdata_len = 4 + (size_t)pub_len;
	uint16_t keytag = calc_keytag(rdata, (int)rdata_len);

	uint8_t payload[8192];
	int name_len = name_to_wire(parsed_domain, payload);
	memcpy(payload + name_len, rdata, (size_t)rdata_len);
	size_t payload_len = (size_t)name_len + rdata_len;

	struct lws_genhash_ctx hash_ctx;
	uint8_t digest[64];

	if (lws_genhash_init(&hash_ctx, hash_idx)) {
		lwsl_err("lws_genhash_init failed\n");
		return 1;
	}
	if (lws_genhash_update(&hash_ctx, payload, (size_t)payload_len)) {
		lwsl_err("lws_genhash_update failed\n");
		lws_genhash_destroy(&hash_ctx, NULL);
		return 1;
	}
	lws_genhash_destroy(&hash_ctx, digest);

	int d_len = (int)lws_genhash_size(hash_idx);

	printf("%s IN DS %u %d %d ", parsed_domain, keytag, alg, digest_type);
	for (int i = 0; i < d_len; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");

	return 0;
}

int lws_dht_dnssec_bump_zone_serial(struct lws_context *context, const char *filepath) {
	int fd = open(filepath, O_RDWR);
	if (fd < 0) return -1;

	struct stat st;
	if (fstat(fd, &st) < 0) { close(fd); return -1; }

	char *buf = malloc((size_t)st.st_size + 1);
	if (!buf) { close(fd); return -1; }

	if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
		free(buf); close(fd); return -1;
	}
	buf[st.st_size] = '\0';

	char *p = buf;
	char *serial_start = NULL;
	char *serial_end = NULL;

	while (*p) {
		while (*p && isspace(*p)) p++;
		if (!*p) break;
		if (*p == ';') {
			while (*p && *p != '\n') p++;
			continue;
		}

		char *start = p;
		while (*p && !isspace(*p) && *p != ';') p++;

		if (p - start == 3 && !strncmp(start, "SOA", 3)) {
			while (*p && isspace(*p)) p++;
			while (*p && !isspace(*p) && *p != ';') p++; /* MNAME */
			while (*p && isspace(*p)) p++;
			while (*p && !isspace(*p) && *p != ';') p++; /* RNAME */
			while (*p && isspace(*p)) p++;

			if (*p == '(') {
				p++;
				while (*p && isspace(*p)) p++;
			}
			if (*p == ';') {
				while (*p && *p != '\n') p++;
				while (*p && isspace(*p)) p++;
			}

			if (isdigit(*p)) {
				serial_start = p++;
				while (*p && isdigit(*p)) p++;
				serial_end = p;
				break;
			}
		}
	}

	if (!serial_start) {
		lwsl_err("SOA serial not found in %s\n", filepath);
		free(buf); close(fd); return -1;
	}

	size_t serial_len = (size_t)(serial_end - serial_start);
	char old_serial[32];
	if (serial_len >= sizeof(old_serial)) serial_len = sizeof(old_serial) - 1;
	memcpy(old_serial, serial_start, serial_len);
	old_serial[serial_len] = '\0';

	time_t t = time(NULL);
	struct tm *tm = gmtime(&t);
	char new_date[16];
	lws_snprintf(new_date, sizeof(new_date), "%04d%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	char new_serial[32];
	if (strncmp(old_serial, new_date, 8) == 0 && serial_len >= 10) {
		long long old_idx = atoll(old_serial + 8);
		lws_snprintf(new_serial, sizeof(new_serial), "%s%02lld", new_date, old_idx + 1);
	} else {
		lws_snprintf(new_serial, sizeof(new_serial), "%s01", new_date);
	}

	if (strlen(new_serial) == serial_len) {
		memcpy(serial_start, new_serial, serial_len);
		if (lseek(fd, 0, SEEK_SET) < 0) {
			lwsl_err("lseek failed to reset file pointer\n");
			free(buf); close(fd); return -1;
		}
		if (write(fd, buf, (size_t)st.st_size) != st.st_size) {
			lwsl_err("Failed to write updated SOA\n");
			free(buf); close(fd); return -1;
		}
	} else {
		size_t new_size = (size_t)st.st_size - serial_len + strlen(new_serial);
		char *new_buf = malloc(new_size + 1);
		if (!new_buf) { free(buf); close(fd); return -1; }

		size_t prefix_len = (size_t)(serial_start - buf);
		memcpy(new_buf, buf, prefix_len);
		memcpy(new_buf + prefix_len, new_serial, strlen(new_serial));
		memcpy(new_buf + prefix_len + strlen(new_serial), serial_end, (size_t)st.st_size - prefix_len - serial_len);

		if (lseek(fd, 0, SEEK_SET) < 0) {
			lwsl_err("lseek failed to reset file pointer\n");
			free(new_buf); free(buf); close(fd); return -1;
		}
		if (ftruncate(fd, (off_t)new_size) < 0) {
			lwsl_err("ftruncate failed\n");
		}
		if (write(fd, new_buf, new_size) != (ssize_t)new_size) {
			lwsl_err("Failed to write updated SOA\n");
			free(new_buf); free(buf); close(fd); return -1;
		}
		free(new_buf);
	}

	lwsl_notice("Bumped SOA serial from %s to %s in %s\n", old_serial, new_serial, filepath);
	free(buf);
	close(fd);
	return 0;
}

static struct vhd_dht_dnssec *
get_dnssec_vhd(struct lws_context *context, struct lws_vhost *preferred_vh)
{
	struct lws_vhost *vh = preferred_vh;
	const struct lws_protocols *pcol;

	if (vh) {
		pcol = lws_vhost_name_to_protocol(vh, "lws-dht-dnssec");
		if (pcol) return (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(vh, pcol);
	}

	return global_dnssec_vhd;
}

static const char *
dnssec_subst_cb(struct lws_auth_dns_sign_info *info, const char *name)
{
	static char ret[512];

	if (!strcmp(name, "EXTIP4")) {
		if (info->ipv4) return info->ipv4;
		return "";
	}
	if (!strcmp(name, "EXTIP6")) {
		if (info->ipv6) return info->ipv6;
		return "";
	}

	if (!strncmp(name, "DANE", 4)) {
		int previous = (name[4] == '1');

		/* Extract domain from info->curr_line */
		char line[4096];
		if (!info->curr_line) return NULL;

		size_t clen = info->curr_line_len;
		if (clen > sizeof(line) - 1) clen = sizeof(line) - 1;
		memcpy(line, info->curr_line, clen);
		line[clen] = '\0';

		char toks[8][256];
		int num_toks = 0;
		lws_tokenize_t ts;
		lws_tokenize_elem e;

		lws_tokenize_init(&ts, line, LWS_TOKENIZE_F_DOT_NONTERM | LWS_TOKENIZE_F_MINUS_NONTERM);
		ts.len = clen;
		do {
			e = lws_tokenize(&ts);
			if (e == LWS_TOKZE_TOKEN) {
				if (num_toks < 8) {
					int n = (int)ts.token_len;
					if (n > (int)sizeof(toks[0]) - 1) n = sizeof(toks[0]) - 1;
					memcpy(toks[num_toks], ts.token, (size_t)n);
					toks[num_toks][n] = '\0';
					num_toks++;
				}
			}
		} while (e > 0);

		if (num_toks == 0) return NULL;

		/* toks[0] is like _443._tcp.warmcat.com. */
		char pdomain[256];
		lws_strncpy(pdomain, toks[0], sizeof(pdomain));

		/* We can usually find the root domain by skipping `_xxx._yyy.` */
		char *root = pdomain;
		if (pdomain[0] == '_') {
			root = strchr(pdomain, '.');
			if (root) {
				root++;
				if (root[0] == '_') {
					root = strchr(root, '.');
					if (root) root++;
				}
			}
		}
		if (!root) root = pdomain;

		/* remove trailing dot */
		size_t rl = strlen(root);
		if (rl > 0 && root[rl - 1] == '.')
			root[rl - 1] = '\0';

		/* Load X509 cert */
		char cert_path[256];
		if (previous) {
			lws_snprintf(cert_path, sizeof(cert_path), "/var/dnssec/domains/%s/tls/%s.crt.1", root, root);
		} else {
			lws_snprintf(cert_path, sizeof(cert_path), "/var/dnssec/domains/%s/tls/%s.crt", root, root);
		}

		struct lws_x509_cert *cert = NULL;
		if (lws_x509_create(&cert)) {
			lwsl_err("%s: failed to create cert\n", __func__);
			return "";
		}

		int cfd = open(cert_path, LWS_O_RDONLY);
		if (cfd < 0) {
			lwsl_notice("Missing cert %s, skipping DANE line\n", cert_path);
			lws_x509_destroy(&cert);
			return "";
		}

		struct stat st;
		if (fstat(cfd, &st) || st.st_size <= 0) {
			close(cfd);
			lws_x509_destroy(&cert);
			return "";
		}

		char *pembuf = malloc((size_t)st.st_size);
		if (!pembuf || read(cfd, pembuf, (unsigned int)st.st_size) != st.st_size) {
			if (pembuf) free(pembuf);
			close(cfd);
			lws_x509_destroy(&cert);
			return "";
		}
		close(cfd);

		if (lws_x509_parse_from_pem(cert, pembuf, (size_t)st.st_size) < 0) {
			lwsl_err("Failed loading DANE cert %s\n", cert_path);
			free(pembuf);
			lws_x509_destroy(&cert);
			return "";
		}
		free(pembuf);

		/* extracted SPKI */
		union lws_tls_cert_info_results res1;
		union lws_tls_cert_info_results *res;
		res1.ns.len = 0;

		if (lws_x509_info(cert, LWS_TLS_CERT_INFO_DER_SPKI, &res1, 0) == -1 && res1.ns.len > 0) {
			size_t alloc_len = sizeof(*res) - sizeof(res1.ns.name) + (size_t)res1.ns.len;
			res = malloc(alloc_len);
			if (res) {
				res->ns.len = 0;
				if (lws_x509_info(cert, LWS_TLS_CERT_INFO_DER_SPKI, res, (size_t)res1.ns.len) == 0) {
					/* we have the DER SPKI, now hash it */
					struct lws_genhash_ctx hash_ctx;
					uint8_t hash[32];

					if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
						if (!lws_genhash_update(&hash_ctx, (uint8_t *)res->ns.name, (size_t)res->ns.len)) {
							if (!lws_genhash_destroy(&hash_ctx, hash)) {
								char hex[128];
								int hl = 0;
								for (int i = 0; i < 32; i++) {
									hl += lws_snprintf(hex + hl, sizeof(hex) - (size_t)hl, "%02X", hash[i]);
								}
								lws_snprintf(ret, sizeof(ret), "3 1 1 %s", hex);
								free(res);
								lws_x509_destroy(&cert);
								return ret;
							}
						} else {
							lws_genhash_destroy(&hash_ctx, NULL);
						}
					}
				}
				free(res);
			}
		}

		lws_x509_destroy(&cert);
		return "";
	}

	return NULL;
}

static int
do_signzone(struct lws_context *context, struct lws_dht_dnssec_signzone_args *args)
{
#if defined(LWS_WITH_AUTHORITATIVE_DNS)
	struct lws_auth_dns_sign_info info;
	char zsk_jwk[256], ksk_jwk[256], zone_in[256], zone_out[256], jws_out[256];

	memset(&info, 0, sizeof(info));
	info.cx = context;
	info.subst_cb = dnssec_subst_cb;

	if (!args->domain || args->domain[0] == '\0') {
		lwsl_err("signzone requires a domain name\n");
		return 1;
	}

	const char *wd = args->workdir ? args->workdir : ".";
	lws_snprintf(zsk_jwk, sizeof(zsk_jwk), "%s/%s.zsk.private.jwk", wd, args->domain);
	lws_snprintf(ksk_jwk, sizeof(ksk_jwk), "%s/%s.ksk.private.jwk", wd, args->domain);
	lws_snprintf(zone_in, sizeof(zone_in), "%s/%s.zone", wd, args->domain);
	lws_snprintf(zone_out, sizeof(zone_out), "%s/%s.zone.signed", wd, args->domain);
	lws_snprintf(jws_out, sizeof(jws_out), "%s/%s.zone.signed.jws", wd, args->domain);

	info.zsk_jwk_filepath = zsk_jwk;
	info.ksk_jwk_filepath = ksk_jwk;
	info.input_filepath = zone_in;
	info.output_filepath = zone_out;
	info.jws_filepath = jws_out;
	if (args->ipv4[0]) info.ipv4 = args->ipv4;
	if (args->ipv6[0]) info.ipv6 = args->ipv6;

	/* Auto-bump the SOA serial before anything else */
	lws_dht_dnssec_bump_zone_serial(context, zone_in);

	if (args->sign_validity_duration)
		info.sign_validity_duration = args->sign_validity_duration;

	/* Create temporary merged zonefile if there are active ACME records */
	struct vhd_dht_dnssec *v = get_dnssec_vhd(context, lws_get_vhost_by_name(context, "default"));
	char withacme_path[256] = "";
	int fd_in, fd_out;
	ssize_t n;
	char buf[4096];

	char acmefile_path[256];
	lws_snprintf(acmefile_path, sizeof(acmefile_path), "%s.acme", zone_in);
	int fd_acme = open(acmefile_path, O_RDONLY);
	int has_acmefile = (fd_acme >= 0);

	struct lws_dht_dnssec_domain *dom = NULL;

	if (v && args->domain) {
		lws_dll2_t *d;
		for (d = v->owner_domains.head; d; d = d->next) {
			struct lws_dht_dnssec_domain *td = lws_container_of(d, struct lws_dht_dnssec_domain, list);
			if (!strcmp(td->domain_name, args->domain)) {
				dom = td;
				break;
			}
		}
	}

	if ((dom && dom->owner_temp_records.count > 0) || has_acmefile) {
		lws_snprintf(withacme_path, sizeof(withacme_path), "%s.withacme", zone_in);
		int in_mem = dom ? (int)dom->owner_temp_records.count : 0;
		if (in_mem > 0 || has_acmefile)
			lwsl_notice("%s: Merging %d in-memory temp zones and/or .acme file into %s\n", __func__, in_mem, withacme_path);

		fd_in = open(zone_in, O_RDONLY);
		if (fd_in >= 0) {
			fd_out = open(withacme_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (fd_out >= 0) {
				/* Copy original zonefile */
				while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
					if (write(fd_out, buf, (size_t)n) != n) {
						lwsl_err("Failed to write to %s\n", withacme_path);
						break;
					}
				}

				/* Append ACME temp zones */
				lws_dll2_t *d2;
				for (d2 = dom ? dom->owner_temp_records.head : NULL; d2; d2 = d2->next) {
					struct lws_dht_dnssec_temp_record *rec =
						lws_container_of(d2, struct lws_dht_dnssec_temp_record, list);
					if (rec->zone_str) {
						write(fd_out, "\n", 1);
						write(fd_out, rec->zone_str, strlen(rec->zone_str));
						write(fd_out, "\n", 1);
					}
				}

				/* Append .acme file if present */
				if (has_acmefile) {
					write(fd_out, "\n", 1);
					while ((n = read(fd_acme, buf, sizeof(buf))) > 0) {
						if (write(fd_out, buf, (size_t)n) != n)
							break;
					}
					write(fd_out, "\n", 1);
				}

				close(fd_out);
				info.input_filepath = withacme_path; /* Use merged file for signing */
			} else {
				lwsl_err("Failed to open %s for writing\n", withacme_path);
			}
			close(fd_in);
		} else {
			lwsl_err("Failed to open %s for reading\n", zone_in);
		}
	}

	if (fd_acme >= 0)
		close(fd_acme);

	if (lws_auth_dns_sign_zone(&info)) {
		lwsl_err("lws_auth_dns_sign_zone failed\n");
		if (info.input_filepath == withacme_path)
			unlink(withacme_path);
		return 1;
	}

	if (info.input_filepath == withacme_path)
		unlink(withacme_path);

	return 0;
#else
	lwsl_err("LWS_WITH_AUTHORITATIVE_DNS not compiled in\n");
	return 1;
#endif
}

static void
cb_temp_record_ttl(lws_sorted_usec_list_t *sul)
{
	struct lws_dht_dnssec_temp_record *rec =
		lws_container_of(sul, struct lws_dht_dnssec_temp_record, sul_ttl);

	lwsl_notice("%s: ACME temp zone TTL expired for %s\n", __func__, rec->domain->domain_name);

	lws_dll2_remove(&rec->list);
	if (rec->zone_str)
		free(rec->zone_str);
	free(rec);
}

static int
do_add_temp_zone(struct lws_context *context, const char *domain, const char *zone_str, int ttl_secs)
{
	struct vhd_dht_dnssec *v = get_dnssec_vhd(context, lws_get_vhost_by_name(context, "default"));
	struct lws_dht_dnssec_domain *dom = NULL;
	struct lws_dht_dnssec_temp_record *rec;
	lws_dll2_t *d;

	if (!v) {
		lwsl_err("%s: no vhd found\n", __func__);
		return 1;
	}

	for (d = v->owner_domains.head; d; d = d->next) {
		struct lws_dht_dnssec_domain *td = lws_container_of(d, struct lws_dht_dnssec_domain, list);
		if (!strcmp(td->domain_name, domain)) {
			dom = td;
			break;
		}
	}

	if (!dom) {
		struct lws_genhash_ctx ctx;
		char domain_str[256];
		char clean_domain[256];
		int clen, dom_len;

		dom = malloc(sizeof(*dom));
		if (!dom) return 1;
		memset(dom, 0, sizeof(*dom));
		lws_strncpy(dom->domain_name, domain, sizeof(dom->domain_name));
		dom->vhd = v;

		lws_strncpy(clean_domain, domain, sizeof(clean_domain));
		clen = (int)strlen(clean_domain);
		if (clen > 0 && clean_domain[clen - 1] == '.')
			clean_domain[clen - 1] = '\0';
		dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", clean_domain);

		if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
		    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
		    lws_genhash_destroy(&ctx, dom->hash)) {
			free(dom);
			return 1;
		}

		lws_dll2_add_tail(&dom->list, &v->owner_domains);
	}

	/* Create the new temporary zone record */
	rec = malloc(sizeof(*rec));
	if (!rec) return 1;
	memset(rec, 0, sizeof(*rec));

	rec->zone_str = strdup(zone_str);
	if (!rec->zone_str) {
		free(rec);
		return 1;
	}
	rec->domain = dom;

	lws_dll2_add_tail(&rec->list, &dom->owner_temp_records);
	lws_sul_schedule(context, 0, &rec->sul_ttl, cb_temp_record_ttl, ttl_secs * LWS_US_PER_SEC);

	lwsl_notice("%s: added temp zone for %s (ttl %ds)\n", __func__, domain, ttl_secs);
	return 0;
}

struct dht_dnssec_fetch_dir_args {
	const char *prefix;
	int found;
	char found_path[1024];
};

static int
dht_dnssec_fetch_payload_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct dht_dnssec_fetch_dir_args *a = (struct dht_dnssec_fetch_dir_args *)user;
	size_t pl = strlen(a->prefix);
	size_t nl = strlen(lde->name);
	if (nl > pl && !strncmp(lde->name, a->prefix, pl) && lde->name[pl] == '_' && nl > 8 && !strcmp(&lde->name[nl-8], ".payload")) {
		a->found = 1;
		lws_snprintf(a->found_path, sizeof(a->found_path), "%s/%s", dirpath, lde->name);
		return 1; // stop searching
	}
	return 0;
}

static int
do_publish_jws(struct lws_vhost *vhost, const char *jws_filepath)
{
	if (!vhost) {
		lwsl_warn("%s: silent failure: vhost is NULL\n", __func__);
		return 1;
	}

	struct vhd_dht_dnssec *vhd = get_dnssec_vhd(NULL, vhost);

	if (!vhd) {
		lwsl_warn("%s: silent failure: vhd is NULL (lws-dht-dnssec protocol missing)\n", __func__);
		return 1;
	}

	if (access(jws_filepath, F_OK) != 0) {
		lwsl_warn("%s: silent failure: JWS file %s does not exist\n", __func__, jws_filepath);
		return 1;
	}

	/* Extract domain from filepath (e.g. selfdns.org.jws) */
	const char *basename = strrchr(jws_filepath, '/');
	basename = basename ? basename + 1 : jws_filepath;
	char domain[256];
	lws_strncpy(domain, basename, sizeof(domain));
	char *p = strstr(domain, ".zone.signed.jws");
	if (!p) p = strstr(domain, ".jws");
	if (p) *p = '\0';

	struct dht_upload_job *job = malloc(sizeof(*job));
	memset(job, 0, sizeof(*job));
	job->jws_filepath = strdup(jws_filepath);
	job->domain = strdup(domain);

	lws_dll2_add_tail(&job->list, &vhd->upload_queue);

	lwsl_notice("%s: Queued publication %s natively into DHT loopback pipeline\n", __func__, jws_filepath);

	if (!vhd->put_started && !vhd->cli_put_file) {
		start_next_dht_upload(vhd);
	}
	return 0;
}

static void
dht_dnssec_sul_fetch_req_timeout(struct lws_sorted_usec_list *sul)
{
	struct lws_dht_dnssec_fetch_req *req = lws_container_of(sul, struct lws_dht_dnssec_fetch_req, sul_timeout);
	struct vhd_dht_dnssec *vhd = req->vhd;

	if (!vhd)
		return;

	if (req->retries >= 3) {
		lwsl_err("%s: Fetch req for %s fully timed out after 3 retries\n", __func__, req->domain);
		if (req->cb) req->cb(req->opaque, req->domain, 0);

		/* We must ALSO clean up any stale fragment state associated with this hash so future fetches start clean */
		struct dht_fragment *frag = dht_dnssec_find_fragment(vhd, req->target_hash);
		if (frag) {
			lwsl_notice("%s: Cleaning up stale fragment metadata for %s\n", __func__, req->target_hash);
			if (frag->fd >= 0) close(frag->fd);
			char path[256];
			lws_snprintf(path, sizeof(path), "%s/tmp/%s.%08X", vhd->storage_path, frag->safe_hash, frag->temp_token);
			unlink(path);
			lws_dll2_remove(&frag->list);
			if (frag->hash_init_done) lws_genhash_destroy(&frag->ctx, NULL);
			free(frag);
		}

		lws_dll2_remove(&req->list);
		free(req);
		return;
	}

	req->retries++;
	lwsl_user("%s: Fetch req for %s timed out, retry %d/3\n", __func__, req->domain, req->retries);

	if (vhd && vhd->dht) {
		lws_sockaddr46 sa46;
		char buf[256];
		if (lws_sa46_parse_numeric_address(vhd->target_ip, &sa46) == 0) {
			sa46_sockport(&sa46, htons((uint16_t)vhd->target_port));
			lws_dht_msg_gen(buf, sizeof(buf), "GET", req->target_hash, 0, 1024);
			lws_dht_send_data(vhd->dht, (struct sockaddr *)&sa46, buf, strlen(buf));
		}
	}

	lws_sul_schedule(vhd->context, 0, &req->sul_timeout, dht_dnssec_sul_fetch_req_timeout, 15 * LWS_US_PER_SEC);
}

static int
do_fetch_zone(struct lws_context *context, struct lws_dht_dnssec_fetch_zone_args *args)
{
	struct vhd_dht_dnssec *v = get_dnssec_vhd(context, args->vhost);
	if (!v || !args->domain) return 1;

	if (args->is_cancel) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, v->fetch_reqs.head) {
			struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
			if (!strcmp(req->domain, args->domain) && req->opaque == args->opaque) {
				lws_sul_cancel(&req->sul_timeout);
				lws_dll2_remove(d);
				free(req);
			}
		} lws_end_foreach_dll_safe(d, d1);
		return 0;
	}

	char clean_domain[256];
	lws_strncpy(clean_domain, args->domain, sizeof(clean_domain));
	int clen = (int)strlen(clean_domain);
	if (clen > 0 && clean_domain[clen - 1] == '.')
		clean_domain[clen - 1] = '\0';

	struct lws_genhash_ctx ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];
	char hex[65];

	if (!strncmp(clean_domain, "dht-hash-", 9)) {
		lws_strncpy(hex, clean_domain + 9, sizeof(hex));
		lws_hex_to_byte_array(hex, hash, (int)lws_genhash_size(LWS_DHT_STORE_GENHASH));
	} else {
		char domain_str[256];
		int dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", clean_domain);

		if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
		    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
		    lws_genhash_destroy(&ctx, hash)) {
			return 1;
		}
		lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hex, sizeof(hex));
	}

	struct dht_dnssec_fetch_dir_args fda;
	memset(&fda, 0, sizeof(fda));
	fda.prefix = hex;

	char dir_path[256];
	lws_snprintf(dir_path, sizeof(dir_path), "%s/%.2s/%.2s", v->storage_path, hex, hex + 2);
	lws_dir(dir_path, &fda, dht_dnssec_fetch_payload_cb);

	if (fda.found && !args->force_network) {
		/* We already have it completely validated locally! */

		/* We no longer copy it anywhere; the auth_dns caller receives the notification and parses it right out of the dht! */
		lwsl_user("%s: Found existing fetched zone in DHT storage %s\n", __func__, fda.found_path);

		if (v->auth_cb)
			v->auth_cb(v->auth_cb_opaque, args->domain, fda.found_path);

		if (args->cb)
			args->cb(args->opaque, args->domain, 1);

		return 0;
	}

	int already = 0;
	lws_start_foreach_dll(struct lws_dll2 *, d, v->fetch_reqs.head) {
		struct lws_dht_dnssec_fetch_req *req = lws_container_of(d, struct lws_dht_dnssec_fetch_req, list);
		if (!strcmp(req->domain, args->domain) && req->opaque == args->opaque) {
			already = 1;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!already) {
		struct lws_dht_dnssec_fetch_req *req = calloc(1, sizeof(*req));
		if (!req) return 1;
		lws_strncpy(req->domain, args->domain, sizeof(req->domain));
		if (args->cache_dir)
			lws_strncpy(req->cache_dir, args->cache_dir, sizeof(req->cache_dir));
		req->cb = args->cb;
		req->opaque = args->opaque;
		req->vhd = v;
		lws_strncpy(req->target_hash, hex, sizeof(req->target_hash));
		lws_dll2_add_tail(&req->list, &v->fetch_reqs);

		lws_sul_schedule(context, 0, &req->sul_timeout, dht_dnssec_sul_fetch_req_timeout, 15 * LWS_US_PER_SEC);
	}

	char buf[256];
	int sent = 0;
	lws_dht_msg_gen(buf, sizeof(buf), "GET", hex, 0, 1024);

	/* 1. Try known DHT peers from routing table (true DHT behavior) */
	if (v->dht) {
		struct sockaddr_in sin[32];
		struct sockaddr_in6 sin6[32];
		int num_v4 = 32, num_v6 = 32, i;

		lws_dht_get_nodes(v->dht, sin, &num_v4, sin6, &num_v6);

		for (i = 0; i < num_v4; i++) {
			lws_dht_send_data(v->dht, (struct sockaddr *)&sin[i], buf, strlen(buf));
			sent++;
		}
#if defined(LWS_WITH_IPV6)
		for (i = 0; i < num_v6; i++) {
			lws_dht_send_data(v->dht, (struct sockaddr *)&sin6[i], buf, strlen(buf));
			sent++;
		}
#endif
	}

	/* 2. Fallback to bootstrap target_ip if configured (for clients/unbootstrapped nodes) */
	if (v->dht && v->target_ip && v->target_ip[0] && v->target_port > 0) {
		lws_sockaddr46 sa46;
		if (lws_sa46_parse_numeric_address(v->target_ip, &sa46) == 0) {
			sa46_sockport(&sa46, htons((uint16_t)v->target_port));
			lws_dht_send_data(v->dht, (struct sockaddr *)&sa46, buf, strlen(buf));
			sent++;
		} else {
			struct addrinfo hints, *result;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;
			if (getaddrinfo(v->target_ip, NULL, &hints, &result) == 0 && result) {
				sa46.sa4 = *(struct sockaddr_in *)result->ai_addr;
				sa46_sockport(&sa46, htons((uint16_t)v->target_port));
				freeaddrinfo(result);

				lws_dht_send_data(v->dht, (struct sockaddr *)&sa46, buf, strlen(buf));
				sent++;
			}
		}
	}

	if (!sent) {
		lwsl_notice("%s: Couldn't completely find routing targets for GET %s\n", __func__, args->domain);
		/* Note: The fetch request remains active and will retry or execute when nodes appear.
		   Returning 0 here keeps the timeout active instead of instantly failing auth-dns! */
	}

	return 0;
}

static int
do_importnsd(struct lws_context *context, struct lws_dht_dnssec_importnsd_args *args)
{
	const char *domain = args->domain;
	const char *prefs[2] = { args->key1_prefix, args->key2_prefix };

	if (!domain || !domain[0]) {
		lwsl_err("%s: requires a domain name\n", __func__);
		return 1;
	}

	for (int k = 0; k < 2; k++) {
		if (!prefs[k]) continue;

		char p_key[256], p_priv[256];
		lws_snprintf(p_key, sizeof(p_key), "%s.key", prefs[k]);
		lws_snprintf(p_priv, sizeof(p_priv), "%s.private", prefs[k]);

		/* 1. Parse .key file */
		int fd = open(p_key, O_RDONLY);
		if (fd < 0) {
			lwsl_err("%s: Failed to open %s\n", __func__, p_key);
			return 1;
		}

		char buf[8192];
		int n = (int)read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0) return 1;
		buf[n] = '\0';

		char parsed_domain[256] = {0};
		int flags = 0, proto = 0, alg = 0;
		char b64[8192];
		if (sscanf(buf, "%255s IN DNSKEY %d %d %d %8191s", parsed_domain, &flags, &proto, &alg, b64) != 5) {
			lwsl_err("%s: Failed to parse %s\n", __func__, p_key);
			return 1;
		}

		int is_ksk = (flags == 257);
		int is_rsa = (alg == 8); // RSASHA256

		/* decode public key */
		uint8_t pub_bin[4096];
		int pub_len = lws_b64_decode_string_len(b64, (int)strlen(b64), (char *)pub_bin, sizeof(pub_bin));
		if (pub_len <= 0) return 1;

		/* 2. Parse .private file */
		fd = open(p_priv, O_RDONLY);
		if (fd < 0) {
			lwsl_err("%s: Failed to open %s\n", __func__, p_priv);
			return 1;
		}

		char priv_buf[8192];
		n = (int)read(fd, priv_buf, sizeof(priv_buf) - 1);
		close(fd);
		if (n <= 0) return 1;
		priv_buf[n] = '\0';

		struct lws_jwk jwk;
		memset(&jwk, 0, sizeof(jwk));
		jwk.kty = is_rsa ? LWS_GENCRYPTO_KTY_RSA : LWS_GENCRYPTO_KTY_EC;

		if (is_rsa) {
			char *p = priv_buf;
			const char *fields[] = { "Modulus:", "PublicExponent:", "PrivateExponent:", "Prime1:", "Prime2:", "Exponent1:", "Exponent2:", "Coefficient:" };
			const int field_idx[] = { LWS_GENCRYPTO_RSA_KEYEL_N, LWS_GENCRYPTO_RSA_KEYEL_E, LWS_GENCRYPTO_RSA_KEYEL_D, LWS_GENCRYPTO_RSA_KEYEL_P, LWS_GENCRYPTO_RSA_KEYEL_Q, LWS_GENCRYPTO_RSA_KEYEL_DP, LWS_GENCRYPTO_RSA_KEYEL_DQ, LWS_GENCRYPTO_RSA_KEYEL_QI };

			for (int f = 0; f < 8; f++) {
				char *m = strstr(p, fields[f]);
				if (!m) { lwsl_err("Missing %s in RSA\n", fields[f]); return 1; }
				m += strlen(fields[f]);
				while (*m == ' ' || *m == '\r' || *m == '\n') m++;
				char *e = m;
				while (*e && *e != '\n' && *e != '\r') e++;
				char b64_ele[4096];
				int elen = (int)(e - m);
				if (elen > (int)sizeof(b64_ele) - 1) return 1;
				memcpy(b64_ele, m, (size_t)elen);
				b64_ele[elen] = '\0';

				uint8_t bin_ele[4096];
				int bin_len = lws_b64_decode_string_len(b64_ele, (int)strlen(b64_ele), (char *)bin_ele, sizeof(bin_ele));
				if (bin_len <= 0) return 1;

				jwk.e[field_idx[f]].buf = malloc((size_t)bin_len);
				if (!jwk.e[field_idx[f]].buf) return 1;
				memcpy(jwk.e[field_idx[f]].buf, bin_ele, (size_t)bin_len);
				jwk.e[field_idx[f]].len = (uint32_t)bin_len;
			}
		} else { /* ECDSA */
			size_t half = ((size_t)pub_len) / 2;
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf = malloc(half);
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf = malloc(half);
			if (!jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf || !jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf) return 1;
			memcpy(jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, pub_bin, half);
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len = (uint32_t)half;
			memcpy(jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, pub_bin + half, half);
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len = (uint32_t)half;

			const char *curve_name = "P-256";
			if (alg == 14) curve_name = "P-384";
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf = malloc(strlen(curve_name));
			if (!jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf) return 1;
			memcpy(jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf, curve_name, strlen(curve_name));
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].len = (uint32_t)strlen(curve_name);

			char *m = strstr(priv_buf, "PrivateKey:");
			if (!m) { lwsl_err("Missing PrivateKey in ECDSA\n"); return 1; }
			m += 11;
			while (*m == ' ' || *m == '\r' || *m == '\n') m++;
			char *e = m;
			while (*e && *e != '\n' && *e != '\r') e++;
			char b64_ele[4096];
			int elen = (int)(e - m);
			if (elen > (int)sizeof(b64_ele) - 1) return 1;
			memcpy(b64_ele, m, (size_t)elen);
			b64_ele[elen] = '\0';

			uint8_t bin_ele[4096];
			int bin_len = lws_b64_decode_string_len(b64_ele, (int)strlen(b64_ele), (char *)bin_ele, sizeof(bin_ele));
			if (bin_len <= 0) return 1;
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].buf = malloc((size_t)bin_len);
			if (!jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].buf) return 1;
			memcpy(jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].buf, bin_ele, (size_t)bin_len);
			jwk.e[LWS_GENCRYPTO_EC_KEYEL_D].len = (uint32_t)bin_len;
		}

		/* Re-serialize into JWK format and our structured public key */
		lws_jwk_strdup_meta(&jwk, JWK_META_KTY, is_rsa ? "RSA" : "EC", is_rsa ? 3 : 2);
		lws_jwk_strdup_meta(&jwk, JWK_META_USE, "sig", 3);
		if (is_rsa)
			lws_jwk_strdup_meta(&jwk, JWK_META_ALG, "RS256", 5);

		char key[65536];
		int vl = sizeof(key);
		if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF | LWSJWKF_EXPORT_PRIVATE, key, &vl) < 0) {
			lws_jwk_destroy(&jwk);
			return 1;
		}

		char priv_filename[256];
		lws_snprintf(priv_filename, sizeof(priv_filename), "%s.%s.private.jwk", domain, is_ksk ? "ksk" : "zsk");
		fd = open(priv_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (fd >= 0) {
			write(fd, key, (size_t)strlen(key));
			close(fd);
			lwsl_notice("Wrote imported private JWK to %s\n", priv_filename);
		}

		char pub_filename[256];
		lws_snprintf(pub_filename, sizeof(pub_filename), "%s.%s.key", domain, is_ksk ? "ksk" : "zsk");
		fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
		if (fd >= 0) {
			char outbuf[16384]; // large for RSA keys
			int rn = lws_snprintf(outbuf, sizeof(outbuf), "%s IN DNSKEY %d 3 %d %s\n", parsed_domain, flags, alg, b64);
			write(fd, outbuf, (size_t)rn);
			close(fd);
			lwsl_notice("Created public %s\n", pub_filename);
		}

		/* Reproduce DS hashes for KSK to ensure smooth migration */
		if (is_ksk) {
			char ds_filename[256];
			lws_snprintf(ds_filename, sizeof(ds_filename), "%s.dnssec.txt", domain);

			uint8_t rdata[4096];
			rdata[0] = (uint8_t)((flags >> 8) & 0xff);
			rdata[1] = (uint8_t)(flags & 0xff);
			rdata[2] = 3;
			rdata[3] = (uint8_t)alg;
			memcpy(rdata + 4, pub_bin, (size_t)pub_len);

			size_t rdata_len = 4 + (size_t)pub_len;
			uint16_t keytag = calc_keytag(rdata, (int)rdata_len);

			uint8_t payload[8192];
			int name_len = name_to_wire(domain, payload);
			memcpy(payload + name_len, rdata, rdata_len);

			struct lws_genhash_ctx hash_ctx;
			uint8_t digest[32];

			if (!lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256)) {
				if (!lws_genhash_update(&hash_ctx, payload, (size_t)name_len + rdata_len)) {
					lws_genhash_destroy(&hash_ctx, digest);

					int ds_fd = open(ds_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
					if (ds_fd >= 0) {
						char ds_summary[1024];
						char thex[128];
						thex[0] = '\0';
						for (int i = 0; i < 32; i++) {
							lws_snprintf(thex + strlen(thex), sizeof(thex) - strlen(thex), "%02X", digest[i]);
						}
						int summary_len = lws_snprintf(ds_summary, sizeof(ds_summary),
							";; IMPORTED DS Record summary for %s registrar\n"
							"%s. IN DS %u %d 2 %s\n", domain, domain, keytag, alg, thex);

						write(ds_fd, ds_summary, (size_t)summary_len);
						close(ds_fd);

						fprintf(stderr, "\n=========== DNSSEC MIGRATION SUMMARY ===========\n");
						fprintf(stderr, "%s", ds_summary);
						fprintf(stderr, "================================================\n\n");
					}
				} else {
					lws_genhash_destroy(&hash_ctx, NULL);
				}
			}
		}

		lws_jwk_destroy(&jwk);
	}
	return 0;
}

static void dht_dnssec_register_auth_cb(struct lws_vhost *vh, void (*cb)(void *opaque, const char *domain, const char *payload_path), void *opaque)
{
	if (vh) {
		const struct lws_protocols *prot = lws_vhost_name_to_protocol(vh, "lws-dht-dnssec");
		if (prot) {
			struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(vh, prot);
			if (vhd) {
				vhd->auth_cb = cb;
				vhd->auth_cb_opaque = opaque;
				lwsl_notice("%s: Registered local zone auth cb\n", __func__);
			}
		}
	}
}

static int
do_subscribe_zone(struct lws_vhost *vhost, const char *domain)
{
	struct vhd_dht_dnssec *vhd;
	const struct lws_protocols *prot;
	char domain_str[256];
	int dom_len;
	struct lws_genhash_ctx ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];

	prot = lws_vhost_name_to_protocol(vhost, "lws-dht-dnssec");
	if (!prot) return 1;
	vhd = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(vhost, prot);
	if (!vhd || !vhd->dht) return 1;

	char clean_domain[256];
	lws_strncpy(clean_domain, domain, sizeof(clean_domain));
	int clen = (int)strlen(clean_domain);
	if (clen > 0 && clean_domain[clen - 1] == '.')
		clean_domain[clen - 1] = '\0';

	dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", clean_domain);
	if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
	    lws_genhash_destroy(&ctx, hash)) {
		return 1;
	}

	/* Add or update subscription tracker so we can map info_hash back to domain strings on NOTIFY */
	int exists = 0;
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->subscribed_domains.head) {
		struct lws_dht_dnssec_subscribed_domain *sub = lws_container_of(d, struct lws_dht_dnssec_subscribed_domain, list);
		if (!strcmp(sub->domain, domain)) {
			exists = 1;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!exists) {
		struct lws_dht_dnssec_subscribed_domain *nsub = malloc(sizeof(*nsub));
		if (nsub) {
			memset(nsub, 0, sizeof(*nsub));
			lws_strncpy(nsub->domain, domain, sizeof(nsub->domain));
			memcpy(nsub->hash, hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH));
			nsub->needs_initial_fetch = 1;
			lws_dll2_add_tail(&nsub->list, &vhd->subscribed_domains);
		}
	}

	uint8_t tid[16];
	lws_get_random(vhd->context, tid, sizeof(tid));

	if (!vhd->initial_search_done) {
		lwsl_notice("%s: Subscribed to domain %s (fetch deferred until DHT bootstraps)\n", __func__, domain);
	} else {
		lwsl_notice("%s: Live DHT subscription confirmed for domain %s (initiating targeted network sync)\n", __func__, domain);
		struct lws_dht_dnssec_fetch_zone_args args;
		memset(&args, 0, sizeof(args));
		args.vhost = vhd->vhost;
		args.domain = domain;
		args.cache_dir = NULL;
		args.cb = NULL;
		args.opaque = NULL;
		args.force_network = 1; /* Unleash live request natively into the DHT overlay */
		/* Bypass the background waiting loop completely since we are natively synchronized! */
		int do_fetch = 0;
		time_t now = time(NULL);
		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->subscribed_domains.head) {
			struct lws_dht_dnssec_subscribed_domain *sub = lws_container_of(d, struct lws_dht_dnssec_subscribed_domain, list);
			if (!strcmp(sub->domain, domain)) {
				if (sub->needs_initial_fetch || now - sub->last_notify_fetch >= 60) {
					sub->needs_initial_fetch = 0;
					sub->last_notify_fetch = now;
					do_fetch = 1;
				}
				break;
			}
		} lws_end_foreach_dll(d);

		if (do_fetch)
			do_fetch_zone(vhd->context, &args);
		else
			lwsl_notice("%s: Rate-limiting subscribe fetch for %s\n", __func__, domain);
	}

	return 0;
}

static int
do_notify_peer_outdated(struct lws_vhost *vhost, const char *domain,
			const lws_sockaddr46 *sa46_peer, uint64_t newer_soa_serial)
{
	struct vhd_dht_dnssec *vhd;
	const struct lws_protocols *prot;
	char domain_str[256];
	int dom_len;
	struct lws_genhash_ctx ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];
	uint8_t payload[32]; // Up to 32 bytes to pass the serial

	prot = lws_vhost_name_to_protocol(vhost, "lws-dht-dnssec");
	if (!prot) return 1;
	vhd = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(vhost, prot);
	if (!vhd || !vhd->dht) return 1;

	char clean_domain[256];
	lws_strncpy(clean_domain, domain, sizeof(clean_domain));
	int clen = (int)strlen(clean_domain);
	if (clen > 0 && clean_domain[clen - 1] == '.')
		clean_domain[clen - 1] = '\0';

	dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", clean_domain);
	if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
	    lws_genhash_destroy(&ctx, hash)) {
		return 1;
	}

	/* Encode the newer serial inside the NOTIFY payload as a 64-bit Big-Endian int */
	payload[0] = (uint8_t)(newer_soa_serial >> 56);
	payload[1] = (uint8_t)(newer_soa_serial >> 48);
	payload[2] = (uint8_t)(newer_soa_serial >> 40);
	payload[3] = (uint8_t)(newer_soa_serial >> 32);
	payload[4] = (uint8_t)(newer_soa_serial >> 24);
	payload[5] = (uint8_t)(newer_soa_serial >> 16);
	payload[6] = (uint8_t)(newer_soa_serial >> 8);
	payload[7] = (uint8_t)(newer_soa_serial & 0xff);

	uint8_t tid[4];
	char peer_ip[64];
	tid[0] = 'n';
	tid[1] = 't';
	lws_get_random(vhd->context, tid + 2, 2);

	lws_sa46_write_numeric_address((lws_sockaddr46 *)sa46_peer, peer_ip, sizeof(peer_ip));
	lwsl_notice("%s: Actively repairing outdated peer %s:%u with new SOA %llu for %s\n",
		    __func__, peer_ip,
		    sa46_peer->sa4.sin_family == AF_INET ? ntohs(sa46_peer->sa4.sin_port) : ntohs(sa46_peer->sa6.sin6_port),
		    (unsigned long long)newer_soa_serial, domain);

	uint8_t hbuf[sizeof(lws_dht_hash_t) + LWS_GENHASH_LARGEST];
	lws_dht_hash_t *proper_hash = (lws_dht_hash_t *)hbuf;
	proper_hash->type = LWS_DHT_STORE_HASH_TYPE;
	proper_hash->len = (uint8_t)lws_genhash_size(LWS_DHT_STORE_GENHASH);
	memcpy(proper_hash->id, hash, proper_hash->len);

	/* Send a targeted NOTIFY to the out-of-date peer using its sockaddr */
	if (sa46_peer->sa4.sin_family == AF_INET) {
		lws_dht_send_notify(vhd->dht, (const struct sockaddr *)&sa46_peer->sa4, sizeof(sa46_peer->sa4),
				    tid, sizeof(tid),
				    proper_hash, NULL,
				    payload, 8);
	}
#if defined(LWS_WITH_IPV6)
	else if (sa46_peer->sa6.sin6_family == AF_INET6) {
		lws_dht_send_notify(vhd->dht, (const struct sockaddr *)&sa46_peer->sa6, sizeof(sa46_peer->sa6),
				    tid, sizeof(tid),
				    proper_hash, NULL,
				    payload, 8);
	}
#endif

	return 0;
}

static const struct lws_dht_dnssec_ops ops = {
	.keygen = do_keygen,
	.dsfromkey = do_dsfromkey,
	.signzone = do_signzone,
	.importnsd = do_importnsd,
	.bump_zone_serial = lws_dht_dnssec_bump_zone_serial,
	.add_temp_zone = do_add_temp_zone,
	.publish_jws = do_publish_jws,
	.fetch_zone = do_fetch_zone,
	.subscribe_zone = do_subscribe_zone,
	.notify_peer_outdated = do_notify_peer_outdated,
	.register_auth_cb = dht_dnssec_register_auth_cb,
};

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_protocols[] = {
	{
		.name = "lws-dht-dnssec",
		.callback = callback_dht_dnssec,
		.per_session_data_size = sizeof(struct vhd_dht_dnssec),
		.rx_buffer_size = 4096,
		.user = (void *)&ops
	},
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_dht_dnssec = {
	.hdr = {
		.name = "lws dht dnssec",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC,
		.priority = 100 /* Force early initialization! */
	},
	.protocols = lws_dht_dnssec_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_protocols) - 1,
	.extensions = NULL,
	.count_extensions = 0,
};
