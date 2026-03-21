/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if !defined (LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libwebsockets/lws-dht-dnssec.h>

#if defined(LWS_WITH_AUTHORITATIVE_DNS)

static int
name_to_wire(const char *name, const char *origin, uint8_t *wire, size_t *wire_len)
{
	char f[256];
	const char *p;
	size_t wl = 0, l;

	if (!strcmp(name, "@") && origin[0]) {
		lws_strncpy(f, origin, sizeof(f));
	} else if (name[0] && name[strlen(name) - 1] != '.' && origin && origin[0]) {
		lws_snprintf(f, sizeof(f), "%s.%s", name, origin);
	} else {
		lws_strncpy(f, name, sizeof(f));
	}

	int cycles = 0;
	p = f;
	while (*p) {
		if (++cycles > 128)
			return 1;
		const char *dot = strchr(p, '.');
		if (!dot)
			l = strlen(p);
		else
			l = lws_ptr_diff_size_t(dot, p);

		if (l > 63 || wl + 1 + l >= *wire_len)
			return 1;

		wire[wl++] = (uint8_t)l;
		if (l) {
			memcpy(&wire[wl], p, l);
			for (size_t n = 0; n < l; n++)
				wire[wl + n] = (uint8_t)tolower(wire[wl + n]);
			wl += l;
		}

		if (!dot)
			break;
		p = dot + 1;
	}

	if (wl == 0 || wire[wl - 1] != 0) {
		if (wl >= *wire_len)
			return 1;
		wire[wl++] = 0;
	}

	*wire_len = wl;
	return 0;
}

struct auth_dns_cache_entry {
	lws_dll2_t list;
	struct auth_dns_zone zone;
	time_t ttl_expiry;
	time_t sig_expiry;
	uint64_t serial;
	char filename[256];

	lws_sorted_usec_list_t sul_subscribe;
	struct per_vhost_data__auth_dns *vhd;
};

struct per_vhost_data__auth_dns {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	char zone_dir[1024];
	uint32_t dht_max_pending;
	uint32_t cache_max_zones;
	const struct lws_dht_dnssec_ops *dht_ops;
	lws_dll2_owner_t zones;
	lws_dll2_owner_t pending_queries;
	lws_sorted_usec_list_t sul_evict;

	/* DNSBL tracking */
	int has_dnsbl;                     /* 1 if we have any DNSBLs configured */
	char dnsbl_list[256];              /* Comma-separated list of DNSBL domains */
	int dnsbl_count;                   /* Total number of configured DNSBL domains */
	char *dnsbl[16];                   /* Pointers into dnsbl_list */
	lws_dll2_owner_t dnsbl_cache;      /* Cache of DNSBL lookups */
	lws_dll2_owner_t pending_dnsbl;    /* Queries waiting for DNSBL completion */
};

struct pending_dns_query {
	lws_dll2_t list;
	struct per_vhost_data__auth_dns *vhd;
	struct lws *wsi;
	lws_sockaddr46 sa46_peer;
	int is_tcp;
	char domain[256];
	uint8_t packet[512];
	size_t packet_len;
	lws_sorted_usec_list_t sul_timeout;
};

struct dnsbl_cache_entry {
	lws_dll2_t list;
	lws_sorted_usec_list_t sul_expire;
	char target[256]; /* the domain or reversed IP checked */
	int is_blacklisted; /* 1 if known to be blacklisted */
};

struct pending_dnsbl_query {
	lws_dll2_t list;
	struct per_vhost_data__auth_dns *vhd;
	struct lws *wsi;
	lws_sockaddr46 sa46_peer;
	int is_tcp;
	char domain[256];
	uint8_t packet[512];
	size_t packet_len;

	lws_sorted_usec_list_t sul_timeout;

	int pending_lookups;
	int is_blacklisted; /* 1 if any lookup came back positive */
};

struct per_session_data__auth_dns {
	unsigned char rx_buf[1024];
	int rx_len;
	unsigned char buf[LWS_PRE + 1024];
	int len;
};

static void
extract_base_domain(const char *qname, char *base, size_t max)
{
	int dots = 0;
	const char *p = qname + strlen(qname) - 1;

	if (p >= qname && *p == '.')
		p--;

	while (p >= qname) {
		if (*p == '.') {
			dots++;
			if (dots == 2) {
				p++;
				break;
			}
		}
		p--;
	}

	if (p < qname) p = qname;
	lws_strncpy(base, p, max);

	int bl = (int)strlen(base);
	if (bl > 0 && base[bl - 1] == '.')
		base[bl - 1] = '\0';

	lwsl_notice("%s: Extracted base domain '%s' from qname '%s'\n", __func__, base, qname);
}

static void
auth_dns_sul_subscribe_cb(lws_sorted_usec_list_t *sul)
{
	struct auth_dns_cache_entry *ce = lws_container_of(sul, struct auth_dns_cache_entry, sul_subscribe);

	if (ce->vhd && ce->vhd->dht_ops && ce->vhd->dht_ops->subscribe_zone) {
		lwsl_info("%s: Refreshing DHT subscription for %s\n", __func__, ce->zone.origin);
		ce->vhd->dht_ops->subscribe_zone(ce->vhd->vhost, ce->zone.origin);

		/* Reschedule for 45 mins since DHT expires them in 60 mins */
		lws_sul_schedule(ce->vhd->context, 0, &ce->sul_subscribe,
				 auth_dns_sul_subscribe_cb, 45 * 60 * LWS_US_PER_SEC);
	}
}

static int
auth_dns_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct per_vhost_data__auth_dns *vhd = (struct per_vhost_data__auth_dns *)user;
	char filepath[1024];
	int fd;
	size_t len;
	char *buf;
	struct auth_dns_cache_entry *ce;
	struct stat st;

	lwsl_notice("%s: check %s (type %d)\n", __func__, lde->name, lde->type);

	if (lde->type != LDOT_UNKNOWN && lde->type != LDOT_FILE)
		return 0;

	len = strlen(lde->name);
	if (len < 6 || strcmp(&lde->name[len - 5], ".zone"))
			/* With DHT integration we don't try to sync initial loads since it comes ad-hoc */{ lwsl_notice("open failed\n"); return 0; }

	lws_snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, lde->name);

	fd = open(filepath, O_RDONLY);
	if (fd < 0) { lwsl_notice("open failed\n"); return 0; }

	if (fstat(fd, &st) < 0 || st.st_size == 0) {
		lwsl_notice("fstat failed or size 0\n");
		close(fd);
		return 0;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return 0;
	}

	if (read(fd, buf, (size_t)st.st_size) != st.st_size) {
		lwsl_notice("read failed\n");
		free(buf);
		close(fd);
		return 0;
	}
	buf[st.st_size] = '\0';
	close(fd);

	lwsl_notice("read zone file %s size %d\n", filepath, (int)st.st_size);

	ce = malloc(sizeof(*ce));
	if (!ce) {
		free(buf);
		return 0;
	}
	memset(ce, 0, sizeof(*ce));
	lws_strncpy(ce->filename, lde->name, sizeof(ce->filename));

	/* Parse suffix format: domain_ttl_sig_serial.zone */
	{
		char *p = ce->filename + (len - 5);
		while (p > ce->filename && *(p - 1) != '_') p--;
		if (p > ce->filename) {
			ce->serial = strtoull(p, NULL, 10);
			p--;
			while (p > ce->filename && *(p - 1) != '_') p--;
			if (p > ce->filename) {
				ce->sig_expiry = (time_t)strtoull(p, NULL, 10);
				p--;
				while (p > ce->filename && *(p - 1) != '_') p--;
				if (p > ce->filename)
					ce->ttl_expiry = (time_t)strtoull(p, NULL, 10);
			}
		}
	}

	time_t now = time(NULL);
	if ((ce->ttl_expiry && now >= ce->ttl_expiry) ||
	    (ce->sig_expiry && now >= ce->sig_expiry)) {
		lwsl_notice("%s: zone %s expired logically, unlinking\n", __func__, lde->name);
		unlink(filepath);
		free(ce);
		free(buf);
		return 0;
	}

	if (lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, &ce->zone, NULL, NULL)) {
		lwsl_notice("parse failed\n");
		free(ce);
		free(buf);
		return 0;
	}
	free(buf);

	/* Limit cache */
	while ((uint32_t)vhd->zones.count >= vhd->cache_max_zones) {
		struct auth_dns_cache_entry *old = lws_container_of(vhd->zones.tail, struct auth_dns_cache_entry, list);
		char dpath[1024];
		lws_snprintf(dpath, sizeof(dpath), "%s/%s", dirpath, old->filename);
		unlink(dpath);
		lws_sul_cancel(&old->sul_subscribe);
		lws_auth_dns_free_zone(&old->zone);
		lws_dll2_remove(&old->list);
		free(old);
	}

	ce->vhd = vhd;
	lws_dll2_add_head(&ce->list, &vhd->zones);

	lwsl_info("Parsed zone %s from %s (serial %llu, ttl_exp %llu, sig_exp %llu)\n",
		ce->zone.origin, filepath, (unsigned long long)ce->serial,
		(unsigned long long)ce->ttl_expiry, (unsigned long long)ce->sig_expiry);

	if (vhd->dht_ops && vhd->dht_ops->subscribe_zone) {
		/* Kick off initial subscription and schedule rolling updates */
		vhd->dht_ops->subscribe_zone(vhd->vhost, ce->zone.origin);
		lws_sul_schedule(vhd->context, 0, &ce->sul_subscribe,
				 auth_dns_sul_subscribe_cb, 45 * 60 * LWS_US_PER_SEC);
	}

	return 0;
}

static void
auth_dns_local_zone_cb(void *opaque, const char *domain, const char *payload_path)
{
	struct per_vhost_data__auth_dns *vhd = (struct per_vhost_data__auth_dns *)opaque;
	char tzdir[1024];

	/* Prefer dht_zone_dir if available, otherwise zone_dir */
	if (vhd->zone_dir[0])
		lws_strncpy(tzdir, vhd->zone_dir, sizeof(tzdir));
	else
		return;

	int fpin = open(payload_path, O_RDONLY);
	if (fpin >= 0) {
		struct stat st;
		if (fstat(fpin, &st) == 0 && st.st_size > 0 && st.st_size < 1024 * 1024) {
			char *buf = malloc((size_t)st.st_size + 1);
			if (buf && read(fpin, buf, (size_t)st.st_size) == st.st_size) {
				buf[st.st_size] = '\0';

				struct auth_dns_zone z;
				memset(&z, 0, sizeof(z));
				uint64_t serial = 0;
				time_t sig_expiry = 0;
				time_t default_ttl = 3600;

				if (!lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, &z, NULL, NULL)) {
					if (z.default_ttl[0]) default_ttl = (time_t)atoi(z.default_ttl);

					lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&z.rrset_list)) {
						struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
						if (rs->type == 6) { /* SOA */
							lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
								struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
								/* extremely basic wire parse to get serial, which is 5th 32bit int after names */
								int p2 = 0;
								while (p2 < (int)rr->wire_rdata_len && rr->wire_rdata[p2]) {
									p2 += rr->wire_rdata[p2] + 1;
								}
								p2++;
								while (p2 < (int)rr->wire_rdata_len && rr->wire_rdata[p2]) {
									p2 += rr->wire_rdata[p2] + 1;
								}
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
									/* Expiry is 4 bytes at offset 8 */
									time_t e = ((time_t)rr->wire_rdata[8] << 24) |
											   ((time_t)rr->wire_rdata[9] << 16) |
											   ((time_t)rr->wire_rdata[10] << 8) |
											   (time_t)rr->wire_rdata[11];
									if (sig_expiry == 0 || e < sig_expiry)
										sig_expiry = e;
								}
							} lws_end_foreach_dll(d2);
						}
					} lws_end_foreach_dll(d);

					time_t ttl_expiry = time(NULL) + default_ttl;
					if (sig_expiry == 0) sig_expiry = ttl_expiry + 86400 * 30; /* Fake if no RRSIG */

					char clean_origin[256];
					lws_strncpy(clean_origin, z.origin, sizeof(clean_origin));
					int col = (int)strlen(clean_origin);
					if (col > 0 && clean_origin[col - 1] == '.') {
						clean_origin[col - 1] = '\0';
						col--;
					}

					int serial_is_newer = 1;

					/* Remove old versions from memory cache */
					lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->zones.head) {
						struct auth_dns_cache_entry *old = lws_container_of(d, struct auth_dns_cache_entry, list);
						if (!strncmp(old->filename, clean_origin, (size_t)col) && old->filename[col] == '_') {
							if ((int32_t)((uint32_t)serial - (uint32_t)old->serial) <= 0) {
								lwsl_notice("%s: Rejecting zone update for %s: serial %u is not newer than %u\n",
											__func__, clean_origin, (uint32_t)serial, (uint32_t)old->serial);
								serial_is_newer = 0;
								break;
							}
							char dpath[1024];
							if (tzdir[0]) {
								lws_snprintf(dpath, sizeof(dpath), "%s/%s", tzdir, old->filename);
								unlink(dpath);
							}
							lws_sul_cancel(&old->sul_subscribe);
							lws_auth_dns_free_zone(&old->zone);
							lws_dll2_remove(&old->list);
							free(old);
						}
					} lws_end_foreach_dll_safe(d, d1);

					if (!serial_is_newer) {
						lws_auth_dns_free_zone(&z);
						if (buf) free(buf);
						close(fpin);
						return;
					}

					/* Enforce cache limits */
					while ((uint32_t)vhd->zones.count >= vhd->cache_max_zones) {
						struct auth_dns_cache_entry *old = lws_container_of(vhd->zones.tail, struct auth_dns_cache_entry, list);
						char dpath[1024];
						if (tzdir[0]) {
							lws_snprintf(dpath, sizeof(dpath), "%s/%s", tzdir, old->filename);
							unlink(dpath);
						}
						lws_sul_cancel(&old->sul_subscribe);
						lws_auth_dns_free_zone(&old->zone);
						lws_dll2_remove(&old->list);
						free(old);
					}

					struct auth_dns_cache_entry *ce = malloc(sizeof(*ce));
					if (ce) {
						memset(ce, 0, sizeof(*ce));
						/* we use the filename field just as a domain label natively now */
						lws_snprintf(ce->filename, sizeof(ce->filename), "%s_%llu_%llu_%llu.zone", clean_origin,
							(unsigned long long)ttl_expiry, (unsigned long long)sig_expiry, (unsigned long long)serial);

						ce->serial = serial;
						ce->sig_expiry = sig_expiry;
						ce->ttl_expiry = ttl_expiry;

						/* Transfer zone struct ownership */
						memcpy(&ce->zone, &z, sizeof(z));
						memset(&z, 0, sizeof(z)); /* Prevent free_zone locally */

						/* Safely repoint all child elements to the new heap owner instead of the original stack address */
						lws_start_foreach_dll(struct lws_dll2 *, d, ce->zone.rrset_list.head) {
							d->owner = &ce->zone.rrset_list;
						} lws_end_foreach_dll(d);

						ce->vhd = vhd;
						lws_dll2_add_head(&ce->list, &vhd->zones);

						lwsl_info("Loaded DHT payload %s from %s natively (serial %llu, ttl_exp %llu, sig_exp %llu)\n",
							ce->zone.origin, payload_path, (unsigned long long)ce->serial,
							(unsigned long long)ce->ttl_expiry, (unsigned long long)ce->sig_expiry);

						if (vhd->dht_ops && vhd->dht_ops->subscribe_zone) {
							vhd->dht_ops->subscribe_zone(vhd->vhost, ce->zone.origin);
							lws_sul_schedule(vhd->context, 0, &ce->sul_subscribe,
									 auth_dns_sul_subscribe_cb, 45 * 60 * LWS_US_PER_SEC);
						}
					} else {
						lws_auth_dns_free_zone(&z);
					}
				}

				if (buf) free(buf);
			}
		}
		close(fpin);
	} else {
		lwsl_err("%s: Failed to read validated payload at %s\n", __func__, payload_path);
	}
}

static void
auth_dns_fetch_cb(void *opaque, const char *domain, int status)
{
	struct per_vhost_data__auth_dns *vhd = (struct per_vhost_data__auth_dns *)opaque;

	if (status == 1) {
		/* Search latest file via dir callback?
		 * Actually, auth_dns_local_zone_cb is already called and creates the file.
		 * So no need to call auth_dns_dir_cb here, it would be redundant.
		 */
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->pending_queries.head) {
		struct pending_dns_query *q = lws_container_of(d, struct pending_dns_query, list);
		if (!strcmp(q->domain, domain)) {
			lws_sul_cancel(&q->sul_timeout);
			lws_dll2_remove(&q->list);

			if (q->wsi) {
				const struct lws_protocols *prot = lws_get_protocol(q->wsi);
				if (prot && prot->callback) {
					/* Replay the query with the newly loaded zone or same old zone */
					prot->callback(q->wsi, LWS_CALLBACK_USER,
						lws_wsi_user(q->wsi), q, 0);
				}
			}
			free(q);
		}
	} lws_end_foreach_dll_safe(d, d1);
}

static void
dnsbl_cache_expire_cb(lws_sorted_usec_list_t *sul)
{
	struct dnsbl_cache_entry *c = lws_container_of(sul, struct dnsbl_cache_entry, sul_expire);
	lwsl_info("%s: expired %s\n", __func__, c->target);
	lws_dll2_remove(&c->list);
	free(c);
}

static void
dnsbl_cache_add(struct per_vhost_data__auth_dns *vhd, const char *target, int is_blacklisted)
{
	struct dnsbl_cache_entry *c;

	/* Search if already exists */
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->dnsbl_cache.head) {
		c = lws_container_of(d, struct dnsbl_cache_entry, list);
		if (!strcmp(c->target, target)) {
			c->is_blacklisted = is_blacklisted;
			lws_sul_schedule(vhd->context, 0, &c->sul_expire, dnsbl_cache_expire_cb, 5 * 60 * LWS_US_PER_SEC);
			return;
		}
	} lws_end_foreach_dll(d);

	/* Limit cache size */
	if (vhd->dnsbl_cache.count > 1024) {
		c = lws_container_of(vhd->dnsbl_cache.tail, struct dnsbl_cache_entry, list);
		lws_sul_cancel(&c->sul_expire);
		lws_dll2_remove(&c->list);
		free(c);
	}

	c = malloc(sizeof(*c));
	if (!c) return;
	memset(c, 0, sizeof(*c));
	lws_strncpy(c->target, target, sizeof(c->target));
	c->is_blacklisted = is_blacklisted;
	lws_dll2_add_head(&c->list, &vhd->dnsbl_cache);
	lws_sul_schedule(vhd->context, 0, &c->sul_expire, dnsbl_cache_expire_cb, 5 * 60 * LWS_US_PER_SEC);

	lwsl_info("%s: caching %s (blacklisted=%d)\n", __func__, target, is_blacklisted);
}

static int
dnsbl_cache_lookup(struct per_vhost_data__auth_dns *vhd, const char *target, int *is_blacklisted)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->dnsbl_cache.head) {
		struct dnsbl_cache_entry *c = lws_container_of(d, struct dnsbl_cache_entry, list);
		if (!strcmp(c->target, target)) {
			*is_blacklisted = c->is_blacklisted;
			return 1; /* Found */
		}
	} lws_end_foreach_dll(d);
	return 0; /* Not found */
}

static void
auth_dns_evict_cb(lws_sorted_usec_list_t *sul)
{
	struct per_vhost_data__auth_dns *vhd = lws_container_of(sul, struct per_vhost_data__auth_dns, sul_evict);
	time_t now = time(NULL);
	char tzdir[1024];

	if (vhd->zone_dir[0])
		lws_strncpy(tzdir, vhd->zone_dir, sizeof(tzdir));
	else
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->zones.head) {
		struct auth_dns_cache_entry *ce = lws_container_of(d, struct auth_dns_cache_entry, list);
		if ((ce->ttl_expiry && now >= ce->ttl_expiry) ||
		    (ce->sig_expiry && now >= ce->sig_expiry)) {
			char dpath[1024];
			lws_snprintf(dpath, sizeof(dpath), "%s/%s", tzdir, ce->filename);
			lwsl_notice("%s: Evicting expired zone %s from disk and memory\n", __func__, ce->filename);
			unlink(dpath);
			lws_sul_cancel(&ce->sul_subscribe);
			lws_auth_dns_free_zone(&ce->zone);
			lws_dll2_remove(&ce->list);
			free(ce);
		}
	} lws_end_foreach_dll_safe(d, d1);

	lws_sul_schedule(vhd->context, 0, &vhd->sul_evict, auth_dns_evict_cb, 5 * 60 * LWS_US_PER_SEC);
}

static int
callback_auth_dns(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		  void *in, size_t len);

static void
pending_query_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_dns_query *q = lws_container_of(sul, struct pending_dns_query, sul_timeout);
	lwsl_info("%s: timeout for query\n", __func__);
	if (q->wsi) {
		const struct lws_protocols *prot = lws_get_protocol(q->wsi);
		if (prot && prot->callback)
			prot->callback(q->wsi, LWS_CALLBACK_USER, lws_wsi_user(q->wsi), q, 0);
	}
	lws_dll2_remove(&q->list);
	free(q);
}

static void
dnsbl_timeout_cb(lws_sorted_usec_list_t *sul)
{
	struct pending_dnsbl_query *q = lws_container_of(sul, struct pending_dnsbl_query, sul_timeout);
	lwsl_info("%s: dnsbl timeout for query\n", __func__);

	/* Assume clean if timeout */
	if (!q->is_blacklisted && q->wsi) {
		const struct lws_protocols *prot = lws_get_protocol(q->wsi);
		if (prot && prot->callback)
			prot->callback(q->wsi, LWS_CALLBACK_USER, lws_wsi_user(q->wsi), q, 0);
	}

	lws_dll2_remove(&q->list);
	free(q);
}

static struct lws *
dnsbl_query_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct pending_dnsbl_query *q = (struct pending_dnsbl_query *)opaque;
	lwsl_info("%s: n=%d for ads=%s\n", __func__, n, ads ? ads : "null");

	q->pending_lookups--;

	if (n >= 0 && (n & ~LWS_ADNS_DNSSEC_VALID) == LADNS_RET_FOUND) {
		/* Found an A record on the DNSBL - it's blacklisted! */
		lwsl_notice("%s: DNSBL HIT for %s\n", __func__, ads ? ads : "known target");
		dnsbl_cache_add(q->vhd, ads, 1);
		q->is_blacklisted = 1;
	} else if (n == LADNS_RET_NXDOMAIN || n == LADNS_RET_TIMEDOUT || n == LADNS_RET_FAILED) {
		/* Clean or timeout */
		dnsbl_cache_add(q->vhd, ads, 0);
	}

	if (q->pending_lookups <= 0) {
		lws_sul_cancel(&q->sul_timeout);

		if (q->is_blacklisted) {
			lwsl_notice("%s: query dropped due to DNSBL blacklist\n", __func__);
			/* Drop it */
		} else if (q->wsi) {
			/* Clean! Resume auth query */
			const struct lws_protocols *prot = lws_get_protocol(q->wsi);
			if (prot && prot->callback)
				prot->callback(q->wsi, LWS_CALLBACK_USER, lws_wsi_user(q->wsi), q, 0);
		}

		lws_dll2_remove(&q->list);
		free(q);
	}

	if (result)
		lws_async_dns_freeaddrinfo(&result);

	return wsi;
}

static int
callback_auth_dns(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		  void *in, size_t len)
{
	struct per_session_data__auth_dns *pss =
			(struct per_session_data__auth_dns *)user;
	struct per_vhost_data__auth_dns *vhd =
			(struct per_vhost_data__auth_dns *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));

	(void)pss;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__auth_dns));
		if (!vhd)
			return 0;
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);
		vhd->dht_max_pending = 16;
		vhd->cache_max_zones = 1000;

		{
			const struct lws_protocol_vhost_options *pvo =
				(const struct lws_protocol_vhost_options *)in;

			lwsl_notice("%s: INIT pvo is %p\n", __func__, pvo);
			while (pvo) {
				lwsl_notice("%s: pvo name '%s', value '%s'\n", __func__, pvo->name, pvo->value);
				if (!strcmp(pvo->name, "zone-dir")) {
					lws_strncpy(vhd->zone_dir, pvo->value,
							sizeof(vhd->zone_dir));
				} else if (!strcmp(pvo->name, "dht-max-pending")) {
					vhd->dht_max_pending = (uint32_t)atoi(pvo->value);
				} else if (!strcmp(pvo->name, "cache-max-zones")) {
					vhd->cache_max_zones = (uint32_t)atoi(pvo->value);
				} else if (!strcmp(pvo->name, "dnsbl")) {
					lws_strncpy(vhd->dnsbl_list, pvo->value, sizeof(vhd->dnsbl_list));
					char *p = vhd->dnsbl_list;
					vhd->has_dnsbl = 1;
					vhd->dnsbl_count = 0;
					while (p && *p && vhd->dnsbl_count < 16) {
						vhd->dnsbl[vhd->dnsbl_count++] = p;
						p = strchr(p, ',');
						if (p) {
							*p++ = '\0';
							while (*p == ' ') p++; /* Skip leading spaces */
						}
					}
					lwsl_vhost_info(vhd->vhost, "%s: Parsed %d DNSBL domains", __func__, vhd->dnsbl_count);
				}
				pvo = pvo->next;
			}
			if (vhd->zone_dir[0] == '\0') {
				lws_strncpy(vhd->zone_dir, "/tmp/lws-auth-dns", sizeof(vhd->zone_dir));
				if (!lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec"))
					lwsl_vhost_warn(vhd->vhost, "%s: Missing pvo \"zone-dir\", defaulting to %s",
						 __func__, vhd->zone_dir);
			}
		}

		{
			/* Retrieve operations from dht-dnssec plugin if present BEFORE scanning the directory */
			const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
			if (prot && prot->user) {
				vhd->dht_ops = (const struct lws_dht_dnssec_ops *)prot->user;
				if (vhd->dht_ops->register_auth_cb)
					vhd->dht_ops->register_auth_cb(vhd->vhost, auth_dns_local_zone_cb, vhd);
			}
		}

		/* read zone files only if DHT is not taking over zone management */
		if (vhd->zone_dir[0] != '\0' && !vhd->dht_ops) {
			lwsl_notice("%s: scanning directory %s (local disk mode)\n", __func__, vhd->zone_dir);
			int r = lws_dir(vhd->zone_dir, vhd, auth_dns_dir_cb);
			lwsl_notice("%s: lws_dir returned %d\n", __func__, r);
		}

		{
			int vport = lws_get_vhost_listen_port(vhd->vhost);
			if (vport > 0) {
				struct lws *wsi_v4 = NULL, *wsi_v6 = NULL;

				wsi_v4 = lws_create_adopt_udp(vhd->vhost, "0.0.0.0", vport, LWS_CAUDP_BIND,
							  vhd->protocol->name, NULL, NULL, NULL,
							  NULL, "auth-dns-v4");
				if (!wsi_v4) {
					lwsl_vhost_err(vhd->vhost, "%s: unable to bind to ipv4 udp port %d",
						       __func__, vport);
				} else {
					lwsl_vhost_notice(vhd->vhost, "%s: bound to ipv4 udp port %d",
							  __func__, vport);
				}

#if defined(LWS_WITH_IPV6)
				wsi_v6 = lws_create_adopt_udp(vhd->vhost, "::", vport, LWS_CAUDP_BIND,
							  vhd->protocol->name, NULL, NULL, NULL,
							  NULL, "auth-dns-v6");
				if (!wsi_v6) {
					lwsl_vhost_err(vhd->vhost, "%s: unable to bind to ipv6 udp port %d",
						       __func__, vport);
				} else {
					lwsl_vhost_notice(vhd->vhost, "%s: bound to ipv6 udp port %d",
							  __func__, vport);
				}
#endif
				if (!wsi_v4 && !wsi_v6)
					lwsl_vhost_err(vhd->vhost, "%s: completely failed to bind DNS listeners", __func__);
			}
		}

		lws_sul_schedule(vhd->context, 0, &vhd->sul_evict, auth_dns_evict_cb, 5 * 60 * LWS_US_PER_SEC);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		{
			lws_sul_cancel(&vhd->sul_evict);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->zones.head) {
				struct auth_dns_cache_entry *ce = lws_container_of(d, struct auth_dns_cache_entry, list);
				lws_sul_cancel(&ce->sul_subscribe);
				lws_auth_dns_free_zone(&ce->zone);
				lws_dll2_remove(&ce->list);
				free(ce);
			} lws_end_foreach_dll_safe(d, d1);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->pending_queries.head) {
				struct pending_dns_query *q = lws_container_of(d, struct pending_dns_query, list);
				lws_dll2_remove(&q->list);
				if (vhd->dht_ops && vhd->dht_ops->fetch_zone) {
					struct lws_dht_dnssec_fetch_zone_args args;
					memset(&args, 0, sizeof(args));
					args.vhost = vhd->vhost;
					args.domain = q->domain;
					args.opaque = vhd;
					args.is_cancel = 1;
					vhd->dht_ops->fetch_zone(vhd->context, &args);
				}
				free(q);
			} lws_end_foreach_dll_safe(d, d1);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->pending_dnsbl.head) {
				struct pending_dnsbl_query *q = lws_container_of(d, struct pending_dnsbl_query, list);
				lws_sul_cancel(&q->sul_timeout);
				lws_dll2_remove(&q->list);
				free(q);
			} lws_end_foreach_dll_safe(d, d1);

			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->dnsbl_cache.head) {
				struct dnsbl_cache_entry *c = lws_container_of(d, struct dnsbl_cache_entry, list);
				lws_sul_cancel(&c->sul_expire);
				lws_dll2_remove(&c->list);
				free(c);
			} lws_end_foreach_dll_safe(d, d1);
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (vhd) {
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->pending_queries.head) {
				struct pending_dns_query *q = lws_container_of(d, struct pending_dns_query, list);
				if (q->wsi == wsi && q->is_tcp) {
					q->wsi = NULL;
				}
			} lws_end_foreach_dll_safe(d, d1);
		}
		break;

	case LWS_CALLBACK_USER:
	case LWS_CALLBACK_RAW_RX: {
		uint8_t *p = (uint8_t *)in;
		uint8_t *end = p + len;
		int is_tcp = (lws_get_udp(wsi) == NULL);
		uint16_t req_len = 0;
		int qtype = 0, qclass = 0;
		char qname[256];
		int qname_len = 0;
		char peer_ip[64] = "unknown";
		struct pending_dns_query *delayed_q = NULL;

		if (reason == LWS_CALLBACK_USER) {
			/* Either returning from DHT or from DNSBL */
			/* Distinguish based on struct type or caller logic */
			struct pending_dns_query *pqdht = (struct pending_dns_query *)in;

			/* Hacky check: we only have two possible `in` types here.
			   Both have `list` as first member then `vhd`. We can check if `pqbl->pending_lookups` is initialized, etc.
			   Actually we can distinguish by looking at the originating list?
			   Let's just use the `is_tcp` offset or `vhd` offset.
			   Actually both share standard fields up to `packet_len`.
			   We should probably add a magic number. But since we originate it...
			   Let's check if the list head matches pending_dnsbl or pending_queries.
			   No, it's removed from the list right before calling LWS_CALLBACK_USER!
			   For now, assume if it has `is_blacklisted` logic it's coming from DNSBL if we dispatched it.
			   Actually, let's just make both structurally compatible up to packet_len. */

			p = pqdht->packet;
			end = p + pqdht->packet_len;
			is_tcp = pqdht->is_tcp;
			req_len = (uint16_t)pqdht->packet_len;

			/* It could be delayed_q or delayed_dnsbl. For extracting packet it doesn't matter since they start identical */
			delayed_q = pqdht;
			lws_sa46_write_numeric_address(&delayed_q->sa46_peer, peer_ip, sizeof(peer_ip));
		} else {
			if (wsi) {
				const struct lws_udp *udp = lws_get_udp(wsi);
				if (!is_tcp && udp)
					lws_sa46_write_numeric_address((lws_sockaddr46 *)&udp->sa46, peer_ip, sizeof(peer_ip));
				else
					lws_get_peer_simple(wsi, peer_ip, sizeof(peer_ip));
			}
			if (is_tcp) {
				if ((size_t)pss->rx_len + len > sizeof(pss->rx_buf)) { lwsl_notice("tcp req too large (%d)\n", (int)len); return -1; }
				memcpy(pss->rx_buf + pss->rx_len, in, len);
				pss->rx_len += (int)len;
				if (pss->rx_len < 2) return 0;
				req_len = (uint16_t)((pss->rx_buf[0] << 8) | pss->rx_buf[1]);
				if (req_len > pss->rx_len - 2) { lwsl_notice("tcp req_len %d > avail %d\n", req_len, pss->rx_len - 2); return 0; }
				p = pss->rx_buf + 2;
				end = pss->rx_buf + 2 + req_len;
			}
		}

		lwsl_notice("LWS_CALLBACK_RAW_RX len %ld, reason %d, is_tcp=%d, peer=%s\n", (long)len, reason, is_tcp, peer_ip);

		if (p + 12 > end) {
			if (reason == LWS_CALLBACK_RAW_RX) lwsl_notice("short header (len %d)\n", (int)len);
			goto done;
		}

		uint16_t id = (uint16_t)((p[0] << 8) | p[1]);
		uint16_t flags = (uint16_t)((p[2] << 8) | p[3]);
		uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);
		uint16_t ancount = (uint16_t)((p[6] << 8) | p[7]);
		uint16_t nscount = (uint16_t)((p[8] << 8) | p[9]);
		uint16_t arcount = (uint16_t)((p[10] << 8) | p[11]);

		lwsl_info("DNS id %04x flags %04x qdcount %d arcount %d (from %s)\n", id, flags, qdcount, arcount, peer_ip);

		if (flags & 0x8000) { lwsl_notice("not a query (flags %04x)\n", flags); goto done; }
		if (qdcount != 1) { lwsl_notice("qdcount != 1 (%d)\n", qdcount); goto done; }

		uint8_t *q = p + 12;
		qname[0] = '\0';
		int cycles = 0;
		while (q < end && *q) {
			if (++cycles > 128) { lwsl_notice("qname cycles %d\n", cycles); goto done; }
			int l = *q++;
			if (l & 0xc0) { lwsl_notice("compression ptr in query at qname pos %d\n", qname_len); goto done; }
			if (q + l > end) { lwsl_notice("qname label exceeds buffer\n"); goto done; }
			if (qname_len + l + 2 > (int)sizeof(qname)) { lwsl_notice("qname too long for buffer\n"); goto done; }
			if (qname_len) qname[qname_len++] = '.';
			memcpy(qname + qname_len, q, (size_t)l);
			qname_len += l;
			qname[qname_len] = '\0';
			q += l;
		}
		if (q < end && !*q) q++;
		else { lwsl_notice("qname no null term (q %p end %p)\n", q, end); goto done; }

		for (int i = 0; qname[i]; i++)
			qname[i] = (char)tolower((unsigned char)qname[i]);

		if (q + 4 > end) { lwsl_notice("no qtype/qclass (q %p end %p)\n", q, end); goto done; }
		qtype = (q[0] << 8) | q[1];
		qclass = (q[2] << 8) | q[3];
		q += 4;

		lwsl_info("DNS qname '%s' type %d class %d\n", qname, qtype, qclass);

		int do_bit = 0;
		if (ancount == 0 && nscount == 0 && arcount > 0) {
			uint8_t *arq = q;
			int ar_c = arcount;
			while (ar_c > 0 && arq < end) {
				while (arq < end && *arq) {
					if ((*arq & 0xc0) == 0xc0) {
						arq += 2;
						break;
					} else {
						arq += *arq + 1;
					}
				}
				if (arq < end && *arq == 0) arq++;

				if (arq + 10 <= end) {
					uint16_t type = (uint16_t)((arq[0] << 8) | arq[1]);
					if (type == 41) { /* OPT */
						if (arq[6] & 0x80)
							do_bit = 1;
						break;
					}
					uint16_t rdlen = (uint16_t)((arq[8] << 8) | arq[9]);
					arq += 10 + rdlen;
				} else {
					break;
				}
				ar_c--;
			}
		}

		uint8_t *dbuf = pss->buf + LWS_PRE;
		uint8_t *rp = dbuf;
		if (is_tcp) rp += 2;

		rp[0] = (uint8_t)(id >> 8); rp[1] = (uint8_t)(id & 0xff);
		uint16_t rflags = 0x8400 | (flags & 0x0100);

		struct auth_dns_cache_entry *matched_ce = NULL;
		struct auth_dns_rrset *found_rs = NULL;

		lws_start_foreach_dll(struct lws_dll2 *, d, vhd->zones.head) {
			struct auth_dns_cache_entry *ce = lws_container_of(d, struct auth_dns_cache_entry, list);
			int ql = (int)strlen(qname);
			int ol = (int)strlen(ce->zone.origin);
			if (ol > 0 && ce->zone.origin[ol - 1] == '.') ol--;
			if (ql >= ol) {
				const char *tail = qname + ql - ol;
				if ((ql == ol || *(tail - 1) == '.') && !strncmp(tail, ce->zone.origin, (size_t)ol)) {
					matched_ce = ce; /* We have the zone */
					lws_start_foreach_dll(struct lws_dll2 *, cd, lws_dll2_get_head(&ce->zone.rrset_list)) {
						struct auth_dns_rrset *rs = lws_container_of(cd, struct auth_dns_rrset, list);
						int rnl = (int)strlen(rs->name);
						if (rnl > 0 && rs->name[rnl - 1] == '.') rnl--;
						if (rnl == ql && !strncmp(rs->name, qname, (size_t)ql) && rs->type == qtype && rs->class_ == qclass) {
							found_rs = rs;
							break;
						}
					} lws_end_foreach_dll(cd);
					if (found_rs) {
						break;
					}
				}
			}
		} lws_end_foreach_dll(d);

		if (matched_ce && reason == LWS_CALLBACK_RAW_RX) {
			/* MRU Promotion */
			lws_dll2_remove(&matched_ce->list);
			lws_dll2_add_head(&matched_ce->list, &vhd->zones);
		}

		lwsl_info("found_rs? %p\n", found_rs);

		if (!found_rs) {
			if (matched_ce) {
				/* We have the zone but the record doesn't exist. Send NXDOMAIN. */
				goto send_nxdomain;
			}
			if (vhd->dht_ops && vhd->dht_ops->fetch_zone && reason == LWS_CALLBACK_RAW_RX) {
				if ((uint32_t)vhd->pending_queries.count >= vhd->dht_max_pending) {
					lwsl_notice("dht pending queries maxed out\n");
					goto send_refused;
				}
				char base[256];
				extract_base_domain(qname, base, sizeof(base));

				lwsl_notice("Initiating DHT fetch for missing zone %s (qname %s)\n", base, qname);

				struct pending_dns_query *pq = malloc(sizeof(*pq));
				if (!pq) goto send_refused;
				memset(pq, 0, sizeof(*pq));
				pq->vhd = vhd;
				pq->wsi = wsi;
				if (delayed_q) pq->sa46_peer = delayed_q->sa46_peer;
				else if (!is_tcp && lws_get_udp(wsi)) pq->sa46_peer = lws_get_udp(wsi)->sa46;
				pq->is_tcp = is_tcp;
				lws_strncpy(pq->domain, base, sizeof(pq->domain));
				pq->packet_len = is_tcp ? (size_t)req_len : len;
				if (pq->packet_len <= sizeof(pq->packet))
					memcpy(pq->packet, p, pq->packet_len);

				lws_dll2_add_tail(&pq->list, &vhd->pending_queries);
				lws_sul_schedule(vhd->context, 0, &pq->sul_timeout, pending_query_timeout_cb, 5 * LWS_US_PER_SEC);

				struct lws_dht_dnssec_fetch_zone_args fza;
				memset(&fza, 0, sizeof(fza));
				fza.vhost = vhd->vhost;
				fza.domain = base;
				fza.cb = auth_dns_fetch_cb;
				fza.opaque = vhd;

				if (vhd->dht_ops->fetch_zone(vhd->context, &fza)) {
					lwsl_notice("dht error\n");
				}
				goto done;
			}

send_refused:
			rflags |= 5; /* REFUSED */
			goto send_out;

send_nxdomain:
			{
				int domain_exists = 0;
				if (matched_ce) {
					int qln = (int)strlen(qname);
					lws_start_foreach_dll(struct lws_dll2 *, cd, lws_dll2_get_head(&matched_ce->zone.rrset_list)) {
						struct auth_dns_rrset *rs = lws_container_of(cd, struct auth_dns_rrset, list);
						int rnl = (int)strlen(rs->name);
						if (rnl > 0 && rs->name[rnl - 1] == '.') rnl--;
						if (rnl == qln && !strncmp(rs->name, qname, (size_t)rnl)) {
							domain_exists = 1;
							break;
						}
					} lws_end_foreach_dll(cd);
				}

				if (!domain_exists)
					rflags |= 3; /* NXDOMAIN */
			}
			/* Add SOA and NSEC3 into Authority section */
			int added_auth = 0;
			if (matched_ce) {
				struct auth_dns_rrset *soa_rs = NULL;
				lws_start_foreach_dll(struct lws_dll2 *, cd, lws_dll2_get_head(&matched_ce->zone.rrset_list)) {
					struct auth_dns_rrset *rs = lws_container_of(cd, struct auth_dns_rrset, list);
					if (rs->type == 6) { /* SOA */
						soa_rs = rs;
						break;
					}
				} lws_end_foreach_dll(cd);

				size_t max_buf = sizeof(pss->buf) - LWS_PRE;

				rp[2] = (uint8_t)(rflags >> 8); rp[3] = (uint8_t)(rflags & 0xff);
				rp[4] = 0; rp[5] = 1; /* QDCOUNT = 1 */
				rp[6] = 0; rp[7] = 0; /* ANCOUNT = 0 */

				/* Write standard DNS Question */
				uint8_t *rp_auth_count = rp + 8; /* Save pointer to NSCOUNT */
				rp[8] = 0; rp[9] = 0; /* NSCOUNT */
				rp[10] = 0; rp[11] = 0; /* ARCOUNT = 0 */
				rp += 12;

				int qlen = (int)(q - (p + 12));
				memcpy(rp, p + 12, (size_t)qlen);
				rp += qlen;

				/* Serialize SOA */
				if (soa_rs && soa_rs->rr_list.head) {
					struct auth_dns_rr *soa_rr = lws_container_of(soa_rs->rr_list.head, struct auth_dns_rr, list);
					if ((size_t)(rp - dbuf) + 16 + soa_rr->wire_rdata_len <= max_buf) {
						int ql = (int)strlen(qname);
						int ol = (int)strlen(matched_ce->zone.origin);
						if (ol > 0 && matched_ce->zone.origin[ol - 1] == '.') ol--;
						uint16_t name_ptr = (uint16_t)(0xc000 | (0x0c + (ql > ol ? ql - ol : 0)));
						*rp++ = (uint8_t)(name_ptr >> 8); *rp++ = (uint8_t)(name_ptr & 0xff);

						*rp++ = 0x00; *rp++ = 0x06; /* Type SOA */
						*rp++ = 0x00; *rp++ = 0x01; /* Class IN */
						*rp++ = (uint8_t)(soa_rs->ttl >> 24); *rp++ = (uint8_t)(soa_rs->ttl >> 16);
						*rp++ = (uint8_t)(soa_rs->ttl >> 8); *rp++ = (uint8_t)(soa_rs->ttl);
						*rp++ = (uint8_t)(soa_rr->wire_rdata_len >> 8); *rp++ = (uint8_t)(soa_rr->wire_rdata_len);
						memcpy(rp, soa_rr->wire_rdata, soa_rr->wire_rdata_len);
						rp += soa_rr->wire_rdata_len;
						added_auth++;
					}
				}

				/* Serialize NSEC3 and their RRSIGs if requested */
				if (do_bit) {
					lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&matched_ce->zone.rrset_list)) {
						struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
						if (rs->type == 50 || (rs->type == 46)) {
							/* check if it's an RRSIG for NSEC3 */
							int is_nsec3_rrsig = 0;
							if (rs->type == 46) {
								if (rs->rr_list.head) {
									struct auth_dns_rr *rr = lws_container_of(rs->rr_list.head, struct auth_dns_rr, list);
									if (rr->wire_rdata_len >= 2 && ((rr->wire_rdata[0] << 8) | rr->wire_rdata[1]) == 50)
										is_nsec3_rrsig = 1;
								}
								if (!is_nsec3_rrsig) continue;
							}

							lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
								struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
								size_t nlen = strlen(rs->name);
								if ((size_t)(rp - dbuf) + 12 + nlen + 1 + rr->wire_rdata_len <= max_buf) {
									if (name_to_wire(rs->name, matched_ce->zone.origin, rp, &max_buf) == 0) {
										size_t written_len = strlen((char *)rp) + 1; /* Name length including root dot */
										rp += written_len;
										*rp++ = (uint8_t)(rs->type >> 8); *rp++ = (uint8_t)(rs->type & 0xff);
										*rp++ = (uint8_t)(rs->class_ >> 8); *rp++ = (uint8_t)(rs->class_ & 0xff);
										*rp++ = (uint8_t)(rs->ttl >> 24); *rp++ = (uint8_t)(rs->ttl >> 16);
										*rp++ = (uint8_t)(rs->ttl >> 8); *rp++ = (uint8_t)(rs->ttl);
										*rp++ = (uint8_t)(rr->wire_rdata_len >> 8); *rp++ = (uint8_t)(rr->wire_rdata_len);
										memcpy(rp, rr->wire_rdata, rr->wire_rdata_len);
										rp += rr->wire_rdata_len;
										added_auth++;
									}
								}
							} lws_end_foreach_dll(d2);
						}
					} lws_end_foreach_dll(d);
				}

				/* Update Authority Count dynamically */
				rp_auth_count[0] = (uint8_t)(added_auth >> 8);
				rp_auth_count[1] = (uint8_t)(added_auth & 0xff);

				goto after_refused;
			}

send_out:
			rp[2] = (uint8_t)(rflags >> 8); rp[3] = (uint8_t)(rflags & 0xff);
			rp[4] = 0; rp[5] = 1; /* QDCOUNT = 1 */
			rp[6] = 0; rp[7] = 0; /* ANCOUNT = 0 */
			rp[8] = 0; rp[9] = 0; /* NSCOUNT = 0 */
			rp[10] = 0; rp[11] = 0; /* ARCOUNT = 0 */
			rp += 12;
			int qlen = (int)(q - (p + 12));
			memcpy(rp, p + 12, (size_t)qlen);
			rp += qlen;

after_refused:
			;
		} else {
			int anc = 0;
			size_t max_buf = sizeof(pss->buf) - LWS_PRE;
			size_t total_size = lws_ptr_diff_size_t(rp, dbuf) + 12 + (size_t)(q - (p + 12));
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&found_rs->rr_list)) {
				struct auth_dns_rr *rr = lws_container_of(d, struct auth_dns_rr, list);
				if (total_size + 12 + (size_t)rr->wire_rdata_len > max_buf) {
					rflags |= 0x0200; /* Truncated TC bit */
					break;
				}
				total_size += 12 + (size_t)rr->wire_rdata_len;
				anc++;
			} lws_end_foreach_dll(d);

			int added_rrsig = 0;
			if (do_bit && matched_ce) {
				lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&matched_ce->zone.rrset_list)) {
					struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
					if (rs->type == 46 && !strcmp(rs->name, found_rs->name) && rs->class_ == qclass) {
						lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
							struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
							if (rr->wire_rdata_len >= 2 && ((rr->wire_rdata[0] << 8) | rr->wire_rdata[1]) == found_rs->type) {
								if (total_size + 12 + (size_t)rr->wire_rdata_len > max_buf) {
									rflags |= 0x0200;
									break;
								}
								total_size += 12 + (size_t)rr->wire_rdata_len;
								added_rrsig++;
							}
						} lws_end_foreach_dll(d2);
					}
				} lws_end_foreach_dll(d);
			}

			int added_opt = 0;
			if (arcount > 0) {
				if (total_size + 11 > max_buf) {
					rflags |= 0x0200;
				} else {
					total_size += 11;
					added_opt++;
				}
			}

			rp[2] = (uint8_t)(rflags >> 8); rp[3] = (uint8_t)(rflags & 0xff);
			rp[4] = 0; rp[5] = 1;
			rp[6] = (uint8_t)((anc + added_rrsig) >> 8); rp[7] = (uint8_t)((anc + added_rrsig) & 0xff);
			rp[8] = 0; rp[9] = 0;
			rp[10] = (uint8_t)(added_opt >> 8); rp[11] = (uint8_t)(added_opt & 0xff);
			rp += 12;
			int qlen = (int)(q - (p + 12));
			memcpy(rp, p + 12, (size_t)qlen);
			rp += qlen;

			int added = 0;

			if (vhd->has_dnsbl && reason == LWS_CALLBACK_RAW_RX) {
				/* We found an answer, let's collect targets (qname + A/AAAA records) */
				char targets[16][256];
				int num_targets = 0;
				int i;
				int target_blacklisted = 0;
				int missing_cache = 0;

				/* Add qname */
				lws_strncpy(targets[num_targets++], qname, sizeof(targets[0]));

				lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&found_rs->rr_list)) {
					struct auth_dns_rr *rr = lws_container_of(d, struct auth_dns_rr, list);
					if (found_rs->type == 1 && rr->wire_rdata_len == 4 && num_targets < 16) {
						/* IPv4 A record */
						const uint8_t *ip = rr->wire_rdata;
						lws_snprintf(targets[num_targets++], sizeof(targets[0]), "%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0]);
					} else if (found_rs->type == 28 && rr->wire_rdata_len == 16 && num_targets < 16) {
						/* IPv6 AAAA record nibbles */
						const uint8_t *ip = rr->wire_rdata;
						char *out = targets[num_targets++];
						int pos = 0;
						for (int j = 15; j >= 0; j--) {
							pos += lws_snprintf(out + pos, sizeof(targets[0]) - (size_t)pos, "%x.%x.", ip[j] & 0x0f, ip[j] >> 4);
						}
						out[pos - 1] = '\0'; /* strip last dot */
					}
				} lws_end_foreach_dll(d);

				/* Check cache for all targets */
				for (i = 0; i < num_targets; i++) {
					int isbl = 0;
					if (dnsbl_cache_lookup(vhd, targets[i], &isbl)) {
						if (isbl) target_blacklisted = 1;
					} else {
						missing_cache = 1;
					}
				}

				if (target_blacklisted) {
					lwsl_notice("%s: Answer contains blacklisted target, dropping\n", __func__);
					goto send_refused;
				}

				if (missing_cache) {
					lwsl_notice("%s: Suspending query for DNSBL lookups (%d targets)\n", __func__, num_targets);
					struct pending_dnsbl_query *q = calloc(1, sizeof(*q));
					if (!q) goto send_refused;
					q->wsi = wsi;
					q->vhd = vhd;
					q->is_tcp = is_tcp;
					if (!is_tcp) {
						const struct lws_udp *udp = lws_get_udp(wsi);
						if (udp) q->sa46_peer = udp->sa46;
					}
					q->packet_len = is_tcp ? (size_t)req_len : len;
					if (q->packet_len <= sizeof(q->packet))
						memcpy(q->packet, p, q->packet_len);

					lws_dll2_add_tail(&q->list, &vhd->pending_dnsbl);
					lws_sul_schedule(vhd->context, 0, &q->sul_timeout, dnsbl_timeout_cb, 5 * LWS_US_PER_SEC);

					q->pending_lookups = 1;

					for (i = 0; i < num_targets; i++) {
						int isbl = 0;
						if (!dnsbl_cache_lookup(vhd, targets[i], &isbl)) {
							int b;
							for (b = 0; b < vhd->dnsbl_count; b++) {
								char lookup[512];
								lws_snprintf(lookup, sizeof(lookup), "%s.%s", targets[i], vhd->dnsbl[b]);
								lwsl_notice("%s: Issuing DNSBL lookup for %s\n", __func__, lookup);
								q->pending_lookups++;

								if (lws_async_dns_query(vhd->context, 0, lookup,
										LWS_ADNS_RECORD_A, dnsbl_query_cb,
										NULL, q, NULL) == LADNS_RET_FAILED) {
									q->pending_lookups--;
								}
							}
						}
					}

					q->pending_lookups--;

					if (q->pending_lookups == 0) {
						/* Immediate failure or synchronous cache? */
						lws_sul_cancel(&q->sul_timeout);
						int isbl = q->is_blacklisted;
						lws_dll2_remove(&q->list);
						free(q);

						if (isbl) {
							lwsl_notice("%s: Answer contains blacklisted target, dropping (sync)\n", __func__);
							goto send_refused;
						}
						/* Proceed normally since no lookups pending and not blacklisted */
					} else {
						/* Let it fly */
						goto done;
					}
				}
			}

			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&found_rs->rr_list)) {
				if (added >= anc) break;
				struct auth_dns_rr *rr = lws_container_of(d, struct auth_dns_rr, list);
				*rp++ = 0xc0; *rp++ = 0x0c; /* Pointer to question name */
				*rp++ = (uint8_t)(qtype >> 8); *rp++ = (uint8_t)(qtype & 0xff);
				*rp++ = (uint8_t)(qclass >> 8); *rp++ = (uint8_t)(qclass & 0xff);
				*rp++ = (uint8_t)(found_rs->ttl >> 24); *rp++ = (uint8_t)((found_rs->ttl >> 16) & 0xff);
				*rp++ = (uint8_t)((found_rs->ttl >> 8) & 0xff); *rp++ = (uint8_t)(found_rs->ttl & 0xff);
				*rp++ = (uint8_t)(rr->wire_rdata_len >> 8); *rp++ = (uint8_t)(rr->wire_rdata_len & 0xff);
				memcpy(rp, rr->wire_rdata, rr->wire_rdata_len);
				rp += rr->wire_rdata_len;
				added++;
			} lws_end_foreach_dll(d);

			if (added_rrsig > 0 && matched_ce) {
				int a_rssig = 0;
				lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&matched_ce->zone.rrset_list)) {
					struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
					if (rs->type == 46 && !strcmp(rs->name, found_rs->name) && rs->class_ == qclass) {
						lws_start_foreach_dll(struct lws_dll2 *, d2, lws_dll2_get_head(&rs->rr_list)) {
							if (a_rssig >= added_rrsig) break;
							struct auth_dns_rr *rr = lws_container_of(d2, struct auth_dns_rr, list);
							if (rr->wire_rdata_len >= 2 && ((rr->wire_rdata[0] << 8) | rr->wire_rdata[1]) == found_rs->type) {
								*rp++ = 0xc0; *rp++ = 0x0c; /* Pointer to question name */
								*rp++ = (uint8_t)(46 >> 8); *rp++ = (uint8_t)(46 & 0xff);
								*rp++ = (uint8_t)(qclass >> 8); *rp++ = (uint8_t)(qclass & 0xff);
								*rp++ = (uint8_t)(rs->ttl >> 24); *rp++ = (uint8_t)((rs->ttl >> 16) & 0xff);
								*rp++ = (uint8_t)((rs->ttl >> 8) & 0xff); *rp++ = (uint8_t)(rs->ttl & 0xff);
								*rp++ = (uint8_t)(rr->wire_rdata_len >> 8); *rp++ = (uint8_t)(rr->wire_rdata_len & 0xff);
								memcpy(rp, rr->wire_rdata, rr->wire_rdata_len);
								rp += rr->wire_rdata_len;
								a_rssig++;
							}
						} lws_end_foreach_dll(d2);
					}
				} lws_end_foreach_dll(d);
			}

			if (added_opt) {
				*rp++ = 0; /* root name */
				*rp++ = 0; *rp++ = 41; /* Type OPT */
				*rp++ = 16; *rp++ = 0; /* UDP payload size 4096 */
				*rp++ = 0; *rp++ = 0; /* Ext rcode + version */
				*rp++ = do_bit ? 0x80 : 0; *rp++ = 0; /* DO bit */
				*rp++ = 0; *rp++ = 0; /* rdlen 0 */
			}
		}

		pss->len = (int)(rp - dbuf);
		if (is_tcp) {
			int plen = pss->len - 2;
			dbuf[0] = (uint8_t)(plen >> 8);
			dbuf[1] = (uint8_t)(plen & 0xff);
			lws_callback_on_writable(wsi);
		} else {
			if (reason == LWS_CALLBACK_USER && delayed_q) {
				int sockfd = lws_get_socket_fd(wsi);
				struct sockaddr *sa = (struct sockaddr *)&delayed_q->sa46_peer;
				socklen_t salen = delayed_q->sa46_peer.sa4.sin_family == AF_INET6 ?
						sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

				ssize_t snt = sendto(sockfd, (char *)dbuf, (size_t)pss->len, 0, sa, salen);
				if (snt < 0) {
					lwsl_err("%s: sendto failed on fd %d: err %d\n", __func__, sockfd, errno);
				} else {
					lwsl_notice("%s: sendto succeeded %ld bytes to delayed peer on fd %d\n", __func__, (long)snt, sockfd);
				}
			} else {
				lws_write(wsi, dbuf, (size_t)pss->len, LWS_WRITE_RAW);
			}
			pss->len = 0;
		}

done:
		if (is_tcp && reason == LWS_CALLBACK_RAW_RX) {
			int consumed = req_len + 2;
			if (consumed < pss->rx_len) {
				memmove(pss->rx_buf, pss->rx_buf + consumed, (size_t)(pss->rx_len - consumed));
				pss->rx_len -= consumed;
			} else {
				pss->rx_len = 0;
			}
		}
		} break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (pss->len) {
			lws_write(wsi, pss->buf + LWS_PRE, (size_t)pss->len, LWS_WRITE_RAW);
			pss->len = 0;
		}
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_AUTH_DNS \
	{ \
		"protocol-lws-auth-dns", \
		callback_auth_dns, \
		sizeof(struct per_session_data__auth_dns), \
		1024, 0, NULL, 0\
	}

#if !defined (LWS_PLUGIN_STATIC)
LWS_VISIBLE const struct lws_protocols lws_auth_dns_protocols[] = {
	LWS_PLUGIN_PROTOCOL_AUTH_DNS
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_auth_dns = {
	.hdr = {
		.name = "lws auth dns",
		._class = "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic = LWS_PLUGIN_API_MAGIC
	},
	.protocols = lws_auth_dns_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_auth_dns_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif

#endif
