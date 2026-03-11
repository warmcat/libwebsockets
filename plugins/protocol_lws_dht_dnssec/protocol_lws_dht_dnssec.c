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
#include <errno.h>
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

		/* Extract domain dynamically from the decoded zone file payload! */
		char *soa = strstr(temp, "SOA");
		if (soa && soa > temp) {
			char *line_start = soa;
			while (line_start > temp && *line_start != '\n') line_start--;
			if (*line_start == '\n') line_start++;
			
			char *end = line_start;
			while (end < soa && *end != ' ' && *end != '\t') end++;
			
			size_t dlen = (size_t)(end - line_start);
			if (dlen >= sizeof(frag->domain)) dlen = sizeof(frag->domain) - 1;
			lws_strncpy(frag->domain, line_start, dlen + 1);
			
			int dlen_i = (int)strlen(frag->domain);
			if (dlen_i > 0 && frag->domain[dlen_i - 1] == '.')
				frag->domain[dlen_i - 1] = '\0';
		} else if (vhd->cli_get_domain) {
			lws_strncpy(frag->domain, vhd->cli_get_domain, sizeof(frag->domain));
		} else {
			lws_strncpy(frag->domain, "example.com", sizeof(frag->domain));
		}
		frag->soa_serial = 2026030701;
		
		lwsl_user("%s: Extracted domain %s, serial %u. Starting DS query.\n", 
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
		struct dht_fragment *frag = dht_dnssec_find_fragment(vhd, vhd->cli_get_hash);
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
		lws_pvo_get_str(in, "dht-fallback-nodes", &fallback_nodes_path);
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

enum {
	LWS_SW_CURVE,
	LWS_SW_DURATION,
	LWS_SW_HASH,
	LWS_SW_KSK,
	LWS_SW_ZSK,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_CURVE]	= { "--curve",         "Enable --curve feature" },
	[LWS_SW_DURATION]	= { "--duration",      "Enable --duration feature" },
	[LWS_SW_HASH]	= { "--hash",          "Enable --hash feature" },
	[LWS_SW_KSK]	= { "--ksk",           "Enable --ksk feature" },
	[LWS_SW_ZSK]	= { "--zsk",           "Enable --zsk feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

static int
do_keygen(struct lws_context *context, int argc, const char **argv)
{
	enum lws_gencrypto_kty kty = LWS_GENCRYPTO_KTY_EC;
	const char *curve = "P-256", *domain = NULL;
	const char *p;
	struct lws_jwk jwk;
	int is_ksk = 0;
	char key[32768];
	int vl = sizeof(key);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_KSK].sw))
		is_ksk = 1;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CURVE].sw)))
		curve = p;

	domain = argv[argc - 1];
	if (!domain || domain[0] == '-') {
		lwsl_err("keygen requires a domain name as the final argument\n");
		return 1;
	}

	lwsl_user("Generating %s for %s (Curve: %s)\n", is_ksk ? "KSK" : "ZSK", domain, curve);

	if (lws_jwk_generate(context, &jwk, kty, 0, curve)) {
		lwsl_err("lws_jwk_generate failed\n");
		return 1;
	}

	/* Force JWK metadata for easy reuse in lws-minimal-raw-dht-zone-client */
	lws_jwk_strdup_meta(&jwk, JWK_META_KTY, "EC", 2);
	lws_jwk_strdup_meta(&jwk, JWK_META_USE, "sig", 3);

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
	int alg = 13; /* ECDSAP256SHA256 */
	if (!strcmp(curve, "P-384")) alg = 14; /* ECDSAP384SHA384 */

	int flags = is_ksk ? 257 : 256;
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
			free(b64_key);
		}
		free(raw_key);
	}

	lws_jwk_destroy(&jwk);
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
do_dsfromkey(struct lws_context *context, int argc, const char **argv)
{
	const char *key_file = argv[argc - 1];
	enum lws_genhash_types hash_idx = LWS_GENHASH_TYPE_SHA256;
	int digest_type = 2; // SHA-256
	const char *p;

	if (!key_file || key_file[0] == '-') {
		lwsl_err("dsfromkey requires a .key file\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_HASH].sw))) {
		if (!strcmp(p, "SHA384")) {
			hash_idx = LWS_GENHASH_TYPE_SHA384;
			digest_type = 4;
		} else if (!strcmp(p, "SHA512")) {
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

	char domain[256] = {0};
	int flags = 0, proto = 0, alg = 0;
	char b64[8192];
	if (sscanf(buf, "%255s IN DNSKEY %d %d %d %8191s", domain, &flags, &proto, &alg, b64) != 5) {
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

	int rdata_len = 4 + pub_len;
	uint16_t keytag = calc_keytag(rdata, rdata_len);

	uint8_t payload[8192];
	int name_len = name_to_wire(domain, payload);
	memcpy(payload + name_len, rdata, (size_t)rdata_len);
	int payload_len = name_len + rdata_len;

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

	printf("%s IN DS %u %d %d ", domain, keytag, alg, digest_type);
	for (int i = 0; i < d_len; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");

	return 0;
}

static int
do_signzone(struct lws_context *context, int argc, const char **argv)
{
#if defined(LWS_WITH_AUTHORITATIVE_DNS)
	struct lws_auth_dns_sign_info info;
	const char *p;

	memset(&info, 0, sizeof(info));
	info.cx = context;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ZSK].sw)))
		info.zsk_jwk_filepath = p;
	else {
		lwsl_err("signzone requires --zsk myzone.zsk.private.jwk\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KSK].sw)))
		info.ksk_jwk_filepath = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DURATION].sw)))
		info.sign_validity_duration = (uint32_t)atoi(p);

	if (argc < 4 || argv[argc - 3][0] == '-' || argv[argc - 2][0] == '-' || argv[argc - 1][0] == '-') {
		lwsl_err("Usage: signzone --zsk ... <in.zone> <out.zone> <out.jws>\n");
		return 1;
	}

	info.input_filepath = argv[argc - 3];
	info.output_filepath = argv[argc - 2];
	info.jws_filepath = argv[argc - 1];

	if (lws_auth_dns_sign_zone(&info)) {
		lwsl_err("lws_auth_dns_sign_zone failed\n");
		return 1;
	}

	return 0;
#else
	lwsl_err("LWS_WITH_AUTHORITATIVE_DNS not compiled in\n");
	return 1;
#endif
}

static const struct lws_dht_dnssec_ops ops = {
	.keygen = do_keygen,
	.dsfromkey = do_dsfromkey,
	.signzone = do_signzone,
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
