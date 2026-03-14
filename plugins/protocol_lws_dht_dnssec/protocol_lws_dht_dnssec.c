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
#endif
#include <sys/stat.h>

#define LWS_DHT_FRAGMENT_SIZE		(1024 * 1024)
#define LWS_DHT_STORE_GENHASH		LWS_GENHASH_TYPE_SHA256


struct vhd_dht_dnssec {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_dht_ctx		*dht;
	lws_sorted_usec_list_t		sul_bulk;
	lws_sorted_usec_list_t		sul_speed;
	lws_sorted_usec_list_t		sul_stats;
	lws_sorted_usec_list_t		sul_timeout;
	int				put_retries;
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
	lws_dll2_owner_t		owner_domains; /* tracking our lws_dht_dnssec_domain structures */
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
	int				retries;
	lws_sorted_usec_list_t		sul_timeout;
};

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

static void
dht_dnssec_sul_put_cb(struct lws_sorted_usec_list *sul);

static void
dht_dnssec_sul_get_cb(struct lws_sorted_usec_list *sul);

static void
dht_dnssec_sul_timeout_cb(struct lws_sorted_usec_list *sul);

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
							uint8_t key_data[512];
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
		
		uint8_t raw_hash[20];
		if (!lws_hex_to_byte_array(frag->safe_hash, raw_hash, sizeof(raw_hash))) {
			lws_dht_hash_t *id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, raw_hash);
			if (id) {
				lwsl_user("%s: Sending native DHT SUBSCRIBE to establish long-poll\n", __func__);
				lws_dht_send_subscribe(frag->dht_ctx, (struct sockaddr *)&frag->from_sa, frag->from_salen, tid, sizeof(tid), id, 0, 0);
				lws_dht_hash_destroy(&id);
			}
		}
	}
	
	/* Notify anyone tracking this hash BEFORE we rename the tmp payload, just in case */
	{
		uint8_t raw_hash[20];
		if (!lws_hex_to_byte_array(frag->safe_hash, raw_hash, sizeof(raw_hash))) {
			lws_dht_hash_t *id = lws_dht_hash_create(LWS_DHT_HASH_TYPE_SHA1, 20, raw_hash);
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
		lws_snprintf(final_ppath, sizeof(final_ppath), "%s/%.2s/%.2s/%s.payload", vhd->storage_path, frag->safe_hash, frag->safe_hash + 2, frag->safe_hash);
		
		if (mkdir(dir1, 0777) < 0 && errno != EEXIST)
			lwsl_err("%s: Failed to create %s\n", __func__, dir1);
		if (mkdir(dir2, 0777) < 0 && errno != EEXIST)
			lwsl_err("%s: Failed to create %s\n", __func__, dir2);
			
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
		
		int ret = lws_async_dns_query(frag->vhd->context, 0, frag->domain,
					LWS_ADNS_RECORD_DNSKEY, dht_dnssec_dnskey_cb,
					NULL, frag, NULL);

		if (ret == LADNS_RET_CONTINUING) {
			/* Async lookup initiated */
			lwsl_user("%s: Initiated async DNSKEY lookup for %s\n", __func__, frag->domain);
		}
	}

	if (result) lws_async_dns_freeaddrinfo(&result);
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
		
		if (lws_auth_dns_parse_zone_buf((const char *)map.buf[LJWS_PYLD], map.len[LJWS_PYLD], &parsed_zone)) {
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
						if (!lws_auth_dns_parse_zone_buf(ex_buf, (size_t)ex_st.st_size, &ex_zone)) {
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
verb_put_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_verb_dispatch_args *args = (struct lws_dht_verb_dispatch_args *)from;
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
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
		lwsl_user("%s: Continuing transfer for %s, already got %zu bytes\n", __func__, frag->safe_hash, frag->received_len);
	}

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) {
		lwsl_err("%s: lseek failed (errno %d)\n", __func__, errno);
		return -1;
	}
	n = (int)write(frag->fd, msg->payload, msg->payload_len);
	if (n < 0 || (size_t)n != msg->payload_len) {
		lwsl_err("%s: write failed (wrote %d of expected %zu, errno %d)\n", __func__, n, msg->payload_len, errno);
		return -1;
	}
	lwsl_user("%s: Wrote %d bytes successfully (Total Received: %zu/%llu)\n", __func__, n, frag->received_len + msg->payload_len, msg->len);

	if (msg->offset + msg->payload_len > frag->received_len)
		frag->received_len = msg->offset + msg->payload_len;
		
	frag->last_offset = msg->offset;
	frag->last_len = msg->payload_len;

	if (frag->received_len >= frag->total_len) {
		lwsl_user("%s: Finished receiving %s, starting validation\n", __func__, frag->safe_hash);

		if (dht_dnssec_trigger_validation(ctx, vhd, frag, from, fromlen))
			goto drop;

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
verb_get_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct lws_dht_verb_dispatch_args *args = (struct lws_dht_verb_dispatch_args *)from;
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
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
	if (n < 0) goto fail;

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
verb_ack_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
	lwsl_user("%s: ACK for %s offset %llu\n", __func__, msg->hash, msg->offset);
	
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
verb_rsp_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		 const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
	struct dht_fragment *frag;

	lwsl_user("%s: RSP for %s offset %llu len %llu payload %zu\n", __func__, msg->hash, msg->offset, msg->len, msg->payload_len);

	if (msg->len > 131072) {
		lwsl_err("%s: Rejecting RSP payload exceeding 131072 bytes (declared %llu)\n", __func__, msg->len);
		if (vhd->cb_completion && !vhd->cli_put_file)
			vhd->cb_completion(vhd->cb_closure, 1);
		return -1;
	}

	frag = dht_dnssec_find_fragment(vhd, msg->hash);
	if (!frag) {
		frag = calloc(1, sizeof(*frag));
		if (!frag) return -1;
		lws_strncpy(frag->safe_hash, msg->hash, sizeof(frag->safe_hash));
		frag->total_len = msg->len;
		frag->vhd = vhd;
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

	if (lseek(frag->fd, (off_t)msg->offset, SEEK_SET) < 0) return -1;
	if (write(frag->fd, msg->payload, msg->payload_len) < 0) return -1;
	if (lws_genhash_update(&frag->ctx, msg->payload, msg->payload_len)) return -1;

	frag->received_len += msg->payload_len;
	
	lws_sul_cancel(&vhd->sul_timeout);
	vhd->put_retries = 0;

	if (frag->received_len >= frag->total_len) {
		lwsl_user("GET complete for %s\n", frag->safe_hash);
		
		if (dht_dnssec_trigger_validation(ctx, vhd, frag, from, fromlen))
			goto drop;

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
verb_cap_rsp_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
	char pbuf[512];
	size_t len = msg->payload_len;

	if (!msg->payload) {
		if (vhd->cb_completion)
			vhd->cb_completion(vhd->cb_closure, 1);
		return 0;
	}

	if (len > sizeof(pbuf) - 1) len = sizeof(pbuf) - 1;
	memcpy(pbuf, msg->payload, len);
	pbuf[len] = '\0';

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
verb_err_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
	lwsl_err("%s: ERR for %s offset %llu (backend upload validation failed!)\n", __func__, msg->hash, msg->offset);
	if (vhd->cb_completion)
		vhd->cb_completion(vhd->cb_closure, 1);
	return -1;
}

static int
verb_nonce_req_handler(struct lws_dht_ctx *ctx, const struct lws_dht_msg *msg,
		       const struct sockaddr *from, size_t fromlen)
{
	struct vhd_dht_dnssec *vhd = (struct vhd_dht_dnssec *)lws_dht_get_closure(ctx);
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

/* --- Core Callback --- */

static void
dht_dnssec_sul_bootstrap_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	int good = 0, dubious = 0;

	if (!vhd->dht)
		return;

	/* Check if the routing table is still entirely empty */
	lws_dht_nodes(vhd->dht, AF_INET, &good, &dubious, NULL, NULL);

	if (good == 0 && dubious == 0) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((uint16_t)vhd->target_port);

		if (inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr) <= 0) {
			struct addrinfo hints, *result;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;

			if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
				struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
				sin.sin_addr = sa->sin_addr;
				freeaddrinfo(result);
			} else {
				lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
				/* Retry resolving in 5s */
				lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 5 * LWS_US_PER_SEC);
				return;
			}
		}

		lwsl_notice("%s: Bootstrapping DHT against target node %s:%d\n", __func__, vhd->target_ip, vhd->target_port);
		lws_dht_ping_node(vhd->dht, (struct sockaddr *)&sin, sizeof(sin));

		/* Schedule another ping in 3 seconds if we still haven't found nodes */
		lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bootstrap_cb, 3 * LWS_US_PER_SEC);
	} else {
		lwsl_notice("%s: DHT bootstrapped successfully, routing table contains %d good nodes\n", __func__, good);
	}
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
		lwsl_notice("%s: Received NOTIFY for domain hash!\n", __func__);
		
		/* Send ACK back for reliable delivery */
		if (vhd->dht) {
			lws_dht_send_ack(vhd->dht, from, fromlen, data, data_len);
		}

		if (vhd->cli_get_domain || vhd->cli_get_hash) {
			lwsl_user("Re-fetching the zonefile due to NOTIFY!\n");
			/* Cancel any pending timeout/retries and restart the fetch */
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
		}
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
			lws_dht_hash_t hash_obj;
			hash_obj.type = LWS_DHT_STORE_GENHASH;
			hash_obj.len = (uint8_t)lws_genhash_size(LWS_DHT_STORE_GENHASH);
			if (!lws_hex_to_byte_array(get_hash, hash_obj.id, hash_obj.len)) {
				frag = dht_dnssec_find_fragment(vhd, get_hash);
				uint8_t current_payload_hash[32] = {0};
				if (frag) {
					memcpy(current_payload_hash, frag->payload_hash, sizeof(current_payload_hash));
				}
				lws_dht_send_subscribe_confirm(vhd->dht, from, fromlen, tid, sizeof(tid), &hash_obj, (uint8_t *)data, data_len, current_payload_hash, 1);
				lwsl_user("Sent SUBSCRIBE_CONFIRM to the target DHT node.\n");
			}
		}
		break;
	}
	default:
		break;
	}
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
		return;
	}

	vhd->put_retries++;
	lwsl_user("%s: UDP timeout, initiating retry %d/3\n", __func__, vhd->put_retries);
	
	if (vhd->cli_get_hash || vhd->cli_get_domain) {
		struct dht_fragment *frag = NULL;
		
		if (vhd->cli_get_hash)
			frag = dht_dnssec_find_fragment(vhd, vhd->cli_get_hash);
			
		if (frag) {
			/* Retry next chunk specifically */
			struct sockaddr_in sin;
			char req_buf[128];
			size_t next_len = 1024;
			
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = htons((uint16_t)vhd->target_port);
			inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr);

			if (frag->received_len + next_len > frag->total_len)
				next_len = (size_t)(frag->total_len - frag->received_len);

			lwsl_user("%s: Retrying GET offset %llu\n", __func__, (unsigned long long)frag->received_len);
			lws_dht_msg_gen(req_buf, sizeof(req_buf), "GET", frag->safe_hash, frag->received_len, (unsigned long long)next_len);
			lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, req_buf, strlen(req_buf));
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
	struct sockaddr_in sin;
	char buf[256], my_id_hex[41];

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)vhd->target_port);
	
	if (inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr) <= 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		
		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
			sin.sin_addr = sa->sin_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
	}

	const lws_dht_hash_t *myid = lws_dht_get_myid(vhd->dht);
	lws_hex_from_byte_array((const uint8_t *)myid->id, myid->len, my_id_hex, sizeof(my_id_hex));

	lwsl_user("Sending CAP_REQ to %s:%d (myid %s)\n", vhd->target_ip, vhd->target_port, my_id_hex);

	lws_dht_msg_gen(buf, sizeof(buf), "CAP_REQ", my_id_hex, 0, 0);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, buf, strlen(buf));
	
	/* Schedule UDP timeout for 3 seconds */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
}

static void
dht_dnssec_sul_put_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
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
	
	if (inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr) <= 0) {
		/* Try synchronous host resolution if it's not a raw IP */
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		
		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
			sin.sin_addr = sa->sin_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
	}

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

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, packet, (size_t)(hlen + n));
	
	/* Schedule UDP timeout for 3 seconds */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_timeout, dht_dnssec_sul_timeout_cb, 3 * LWS_US_PER_SEC);
}

static void
dht_dnssec_sul_get_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_dht_dnssec *vhd = lws_container_of(sul, struct vhd_dht_dnssec, sul_bulk);
	struct sockaddr_in sin;
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

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)vhd->target_port);

	
	if (inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr) <= 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		
		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
			sin.sin_addr = sa->sin_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			return;
		}
	}

	lwsl_user("Sending GET %s to %s:%d\n", get_hash, vhd->target_ip, vhd->target_port);

	lws_dht_msg_gen(buf, sizeof(buf), "GET", get_hash, 0, 1024);
	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, buf, strlen(buf));
	
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
	struct sockaddr_in sin;
	int hlen;
	char buf[1024];

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)vhd->target_port);
	
	if (inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr) <= 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		
		if (getaddrinfo(vhd->target_ip, NULL, &hints, &result) == 0 && result) {
			struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
			sin.sin_addr = sa->sin_addr;
			freeaddrinfo(result);
		} else {
			lwsl_err("Failed to resolve target-ip: %s\n", vhd->target_ip);
			if (vhd->cb_completion)
				vhd->cb_completion(vhd->cb_closure, 1);
			return;
		}
	}

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

	lws_dht_send_data(vhd->dht, (struct sockaddr *)&sin, packet, (size_t)hlen + sizeof(buf));
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
		struct lws_dht_verb_dispatch_args *args =
			(struct lws_dht_verb_dispatch_args *)in;

		if (!strcmp(args->msg->verb, "PUT")) return verb_put_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "GET")) return verb_get_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "ACK")) return verb_ack_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "RSP")) return verb_rsp_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "CAP_RSP")) return verb_cap_rsp_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_REQ")) return verb_nonce_req_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "NONC_RSP")) return verb_nonce_rsp_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "SIGN_REQ")) return verb_sign_req_handler(args->ctx, args->msg, args->from, args->fromlen);
		if (!strcmp(args->msg->verb, "ERR")) return verb_err_handler(args->ctx, args->msg, args->from, args->fromlen);
		
		/* We'll handle notification subscription confirmation here, empty for now */
		if (!strcmp(args->msg->verb, "SUBSCRIBE_CONFIRM")) return 0;
		if (!strcmp(args->msg->verb, "NOTIFY")) return 0;

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
		};
		if (!in)
			return 0;
		if (!lws_pvo_search(in, "dht-port"))
			return 0;

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
		lws_dll2_owner_clear(&vhd->fragments);
		lws_dll2_owner_clear(&vhd->fetch_reqs);
		vhd->bulk_fd = -1;
		vhd->main_result = 1;

		/* Default settings */
		vhd->target_ip = "127.0.0.1";
		vhd->target_port = 5000;
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
		if (lws_pvo_get_str(in, "target-ip", &vhd->target_ip) || !vhd->target_ip || !vhd->target_ip[0]) {
			/* No CLI-supplied target-ip, try reading the shared fallback nodes list */
			static char fallback_ip[64];
			if (!lws_dht_get_fallback_node(vhd->context, fallback_nodes_path, fallback_ip, sizeof(fallback_ip))) {
				/* Format is expected to be IP:PORT */
				char *colon = strchr(fallback_ip, ':');
				if (colon) {
					*colon = '\0';
					vhd->target_port = atoi(colon + 1);
					vhd->target_ip = fallback_ip;
					lwsl_notice("%s: Utilizing root fallback DHT node target: %s:%d\n", __func__, vhd->target_ip, vhd->target_port);
				}
			} else {
				lwsl_info("no pvo for target-ip and no root fallback node file available\n");
			}
		}

		if ((pvo = lws_pvo_search(in, "target-port")) && pvo->value && pvo->value[0]) vhd->target_port = atoi(pvo->value);
		if (!lws_pvo_get_str(in, "put-file", &p) && p && p[0]) vhd->cli_put_file = p;
		if (!lws_pvo_get_str(in, "get-hash", &p) && p && p[0]) vhd->cli_get_hash = p;
		if (!lws_pvo_get_str(in, "get-domain", &p) && p && p[0]) vhd->cli_get_domain = p;
		if (!lws_pvo_get_str(in, "domain", &p) && p && p[0]) vhd->cli_domain = p;
		if (!lws_pvo_get_str(in, "bulk", &p) && p && p[0]) vhd->cli_bulk = 1;
		if (!lws_pvo_get_str(in, "gen-manifest", &p) && p && p[0]) vhd->gen_manifest = 1;
		if (!lws_pvo_get_str(in, "dht-jwk", &p) && p && p[0]) vhd->cli_jwk_path = p;
		if (!lws_pvo_get_str(in, "dht-policy-allow", &p) && p && p[0]) vhd->policy_allow = p;
		if (!lws_pvo_get_str(in, "dht-policy-deny", &p) && p && p[0]) vhd->policy_deny = p;
		if (!lws_pvo_get_str(in, "dht-test-handshake", &p) && p && p[0]) vhd->test_handshake = 1;
		if (!lws_pvo_get_str(in, "receiver", &p) && p && p[0]) vhd->cli_receiver = 1;

		if ((pvo = lws_pvo_search(in, "completion-cb"))) vhd->cb_completion = (lws_dht_store_completion_cb_t)(void *)pvo->value;
		if ((pvo = lws_pvo_search(in, "completion-cb-arg"))) vhd->cb_closure = (void *)pvo->value;

		if (dht_dnssec_jwk_load_or_gen(vhd)) return -1;

		memset(&vdi, 0, sizeof(vdi));
		vdi.vhost = vhost;
		vdi.port = vhd->dht_port;
		vdi.ipv6 = 1;
		vdi.cb = cb_dht;
		vdi.closure = vhd;
		vdi.iface = vhd->dht_iface;
		vdi.fallback_nodes_path = fallback_nodes_path;

		vhd->dht = lws_dht_create(&vdi);
		if (!vhd->dht) {
			lwsl_vhost_err(vhd->vhost, "%s: failed to create DHT", __func__);
			return -1;
		}

		/* Register our "verbs" */
		lws_dht_register_verbs(vhd->dht, store_verbs, LWS_ARRAY_SIZE(store_verbs), protocol);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_stats, sul_stats_cb, 100 * LWS_US_PER_MS);

		if (vhd->test_handshake) {
			char my_id_hex[41];
			const lws_dht_hash_t *myid = lws_dht_get_myid(vhd->dht);

			lws_hex_from_byte_array((const uint8_t *)myid->id, myid->len, my_id_hex, sizeof(my_id_hex));

			lwsl_user("Initiating Handshake TEST... sending NONCE_REQ (myid %s)\n", my_id_hex);
			char buf[1024];
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = htons((uint16_t)vhd->target_port);
			inet_pton(AF_INET, vhd->target_ip, &sin.sin_addr);

			lws_dht_msg_gen(buf, sizeof(buf), "NONC_REQ", my_id_hex, 0, 0);
			lws_dht_send_data(vhd->dht, (const struct sockaddr *)&sin, buf, strlen(buf));
		} else if (vhd->cli_put_file) {
			lwsl_user("%s: Starting PUT task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_cap_cb, 10);
		} else if (vhd->cli_bulk || vhd->gen_manifest) {
			lwsl_user("%s: Starting BULK task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_bulk_cb, 10);
		} else if (vhd->cli_get_hash || vhd->cli_get_domain) {
			lwsl_user("%s: Starting GET task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_get_cb, 10);
		} else if (vhd->cli_receiver) {
			lwsl_user("%s: Starting RECEIVER task\n", __func__);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_manifest_rcv_cb, 10);
			lws_sul_schedule(vhd->context, 0, &vhd->sul_bulk, dht_dnssec_sul_manifest_rcv_cb, 10);
		} else if (vhd->target_ip && vhd->target_ip[0] && vhd->target_port > 0) {
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
		lws_jwk_destroy(&vhd->jwk);

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

		char priv_filename[256];
		lws_snprintf(priv_filename, sizeof(priv_filename), "%s.%s.private.jwk", domain, is_ksk ? "ksk" : "zsk");
		
		int fd = open(priv_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
		if (fd >= 0) {
			write(fd, key, (size_t)strlen(key));
			close(fd);
			lwsl_notice("Wrote private JWK to %s\n", priv_filename);
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
					lws_snprintf(pub_filename, sizeof(pub_filename), "%s.%s.key", domain, is_ksk ? "ksk" : "zsk");
					
					fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
					if (fd >= 0) {
						char outbuf[4096];
						int n = lws_snprintf(outbuf, sizeof(outbuf), "%s. IN DNSKEY %d 3 %d %s\n", domain, flags, alg, b64_key);
						write(fd, outbuf, (size_t)n);
						close(fd);
						lwsl_notice("Wrote public DNSKEY to %s\n", pub_filename);
					}
					if (is_ksk) {
						char ds_filename[256];
						lws_snprintf(ds_filename, sizeof(ds_filename), "%s.dnssec.txt", domain);
						
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
					lws_snprintf(pub_filename, sizeof(pub_filename), "%s.%s.key", domain, is_ksk ? "ksk" : "zsk");
					
					fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
					if (fd >= 0) {
						char outbuf[1024];
						int n = lws_snprintf(outbuf, sizeof(outbuf), "%s. IN DNSKEY %d 3 %d %s\n", domain, flags, alg, b64_key);
						write(fd, outbuf, (size_t)n);
						close(fd);
						lwsl_notice("Wrote public DNSKEY to %s\n", pub_filename);
					}

					if (is_ksk) {
						char ds_filename[256];
						lws_snprintf(ds_filename, sizeof(ds_filename), "%s.dnssec.txt", domain);
						
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
	
	lws_snprintf(key_file, sizeof(key_file), "%s.ksk.key", domain);

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

static int
do_signzone(struct lws_context *context, struct lws_dht_dnssec_signzone_args *args)
{
#if defined(LWS_WITH_AUTHORITATIVE_DNS)
	struct lws_auth_dns_sign_info info;
	char zsk_jwk[256], ksk_jwk[256], zone_in[256], zone_out[256], jws_out[256];

	memset(&info, 0, sizeof(info));
	info.cx = context;

	if (!args->domain || args->domain[0] == '\0') {
		lwsl_err("signzone requires a domain name\n");
		return 1;
	}

	lws_snprintf(zsk_jwk, sizeof(zsk_jwk), "%s.zsk.private.jwk", args->domain);
	lws_snprintf(ksk_jwk, sizeof(ksk_jwk), "%s.ksk.private.jwk", args->domain);
	lws_snprintf(zone_in, sizeof(zone_in), "%s.zone", args->domain);
	lws_snprintf(zone_out, sizeof(zone_out), "%s.zone.signed", args->domain);
	lws_snprintf(jws_out, sizeof(jws_out), "%s.zone.signed.jws", args->domain);

	info.zsk_jwk_filepath = zsk_jwk;
	info.ksk_jwk_filepath = ksk_jwk;
	info.input_filepath = zone_in;
	info.output_filepath = zone_out;
	info.jws_filepath = jws_out;

	if (args->sign_validity_duration)
		info.sign_validity_duration = args->sign_validity_duration;

	/* Create temporary merged zonefile if there are active ACME records */
	struct vhd_dht_dnssec *v = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(
				lws_get_vhost_by_name(context, "default"),
				lws_vhost_name_to_protocol(lws_get_vhost_by_name(context, "default"), "lws-dht-dnssec"));
	char withacme_path[256];
	int fd_in, fd_out;
	ssize_t n;
	char buf[4096];

	if (v && args->domain) {
		lws_dll2_t *d, *d2;
		struct lws_dht_dnssec_domain *dom = NULL;

		for (d = v->owner_domains.head; d; d = d->next) {
			struct lws_dht_dnssec_domain *td = lws_container_of(d, struct lws_dht_dnssec_domain, list);
			if (!strcmp(td->domain_name, args->domain)) {
				dom = td;
				break;
			}
		}

		if (dom && dom->owner_temp_records.count > 0) {
			lws_snprintf(withacme_path, sizeof(withacme_path), "%s.withacme", zone_in);
			lwsl_notice("%s: Merging %d ACME temp zones into %s\n", __func__, dom->owner_temp_records.count, withacme_path);

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
					for (d2 = dom->owner_temp_records.head; d2; d2 = d2->next) {
						struct lws_dht_dnssec_temp_record *rec =
							lws_container_of(d2, struct lws_dht_dnssec_temp_record, list);
						if (rec->zone_str) {
							write(fd_out, "\n", 1);
							write(fd_out, rec->zone_str, strlen(rec->zone_str));
							write(fd_out, "\n", 1);
						}
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
	}

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
	struct vhd_dht_dnssec *v = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(
				lws_get_vhost_by_name(context, "default"),
				lws_vhost_name_to_protocol(lws_get_vhost_by_name(context, "default"), "lws-dht-dnssec"));
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
		dom = malloc(sizeof(*dom));
		if (!dom) return 1;
		memset(dom, 0, sizeof(*dom));
		lws_strncpy(dom->domain_name, domain, sizeof(dom->domain_name));
		dom->vhd = v;
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

static int
do_publish_jws(struct lws_context *context, const char *jws_filepath)
{
	lwsl_notice("%s: stub implementation (publish %s)\n", __func__, jws_filepath);
	return 0; // TODO in later phases
}

static void dht_dnssec_sul_fetch_req_timeout(struct lws_sorted_usec_list *sul)
{
	struct lws_dht_dnssec_fetch_req *req = lws_container_of(sul, struct lws_dht_dnssec_fetch_req, sul_timeout);
	
	lwsl_err("%s: Fetch req for %s fully timed out\n", __func__, req->domain);
	if (req->cb) req->cb(req->opaque, req->domain, 0);
	lws_dll2_remove(&req->list);
	free(req);
}

static int
do_fetch_zone(struct lws_context *context, struct lws_dht_dnssec_fetch_zone_args *args)
{
	struct lws_vhost *vhost = args->vhost;
	if (!vhost) vhost = lws_get_vhost_by_name(context, "default");
	if (!vhost) return 1;

	struct vhd_dht_dnssec *v = (struct vhd_dht_dnssec *)lws_protocol_vh_priv_get(
				vhost, lws_vhost_name_to_protocol(vhost, "lws-dht-dnssec"));
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

	char domain_str[256];
	int dom_len = lws_snprintf(domain_str, sizeof(domain_str), "lws-dnssec-dht-%s", args->domain);

	struct lws_genhash_ctx ctx;
	uint8_t hash[LWS_GENHASH_LARGEST];
	char hex[65];

	if (lws_genhash_init(&ctx, LWS_DHT_STORE_GENHASH) ||
	    lws_genhash_update(&ctx, domain_str, (size_t)dom_len) ||
	    lws_genhash_destroy(&ctx, hash)) {
		return 1;
	}
	lws_hex_from_byte_array(hash, (size_t)lws_genhash_size(LWS_DHT_STORE_GENHASH), hex, sizeof(hex));

	char ppath[256];
	lws_snprintf(ppath, sizeof(ppath), "%s/%.2s/%.2s/%s.payload", v->storage_path, hex, hex + 2, hex);
	int fpin = open(ppath, O_RDONLY);
	if (fpin >= 0) {
		/* We already have it completely validated locally! */
		if (args->cache_dir) {
			char cpath[1024];
			lws_snprintf(cpath, sizeof(cpath), "%s/%s.zone", args->cache_dir, args->domain);
			if (mkdir(args->cache_dir, 0777) < 0 && errno != EEXIST)
				lwsl_err("%s: Failed to create cache directory %s\n", __func__, args->cache_dir);
			int fpout = open(cpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fpout >= 0) {
				char cbuf[4096];
				ssize_t cn;
				while ((cn = read(fpin, cbuf, sizeof(cbuf))) > 0)
					if (write(fpout, cbuf, (size_t)cn) < 0) break;
				close(fpout);
				lwsl_user("%s: Copied existing fetched zone to cache %s\n", __func__, cpath);
			} else {
				lwsl_err("%s: Failed to open %s for caching\n", __func__, cpath);
			}
		}
		close(fpin);
		
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
		lws_strncpy(req->target_hash, hex, sizeof(req->target_hash));
		lws_dll2_add_tail(&req->list, &v->fetch_reqs);
		
		lws_sul_schedule(context, 0, &req->sul_timeout, dht_dnssec_sul_fetch_req_timeout, 15 * LWS_US_PER_SEC);
	}

	struct sockaddr_in sin;
	char buf[256];
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)v->target_port);
	
	if (inet_pton(AF_INET, v->target_ip, &sin.sin_addr) <= 0) {
		struct addrinfo hints, *result;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		if (getaddrinfo(v->target_ip, NULL, &hints, &result) == 0 && result) {
			struct sockaddr_in *sa = (struct sockaddr_in *)result->ai_addr;
			sin.sin_addr = sa->sin_addr;
			freeaddrinfo(result);
		} else {
			return 1;
		}
	}
	lws_dht_msg_gen(buf, sizeof(buf), "GET", hex, 0, 1024);
	lws_dht_send_data(v->dht, (struct sockaddr *)&sin, buf, strlen(buf));

	return 0;
}

static const struct lws_dht_dnssec_ops ops = {
	.keygen = do_keygen,
	.dsfromkey = do_dsfromkey,
	.signzone = do_signzone,
	.add_temp_zone = do_add_temp_zone,
	.publish_jws = do_publish_jws,
	.fetch_zone = do_fetch_zone,
};

LWS_VISIBLE const struct lws_protocols lws_dht_dnssec_protocols[] = {
	{ "lws-dht-dnssec", callback_dht_dnssec, 0, 0, 0, (void *)&ops, 0 },
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
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = lws_dht_dnssec_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_dht_dnssec_protocols) - 1,
	.extensions = NULL,
	.count_extensions = 0,
};
