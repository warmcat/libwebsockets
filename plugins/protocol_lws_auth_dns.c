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

struct auth_dns_zone_list {
	struct auth_dns_zone_list *next;
	struct auth_dns_zone zone;
};

struct per_vhost_data__auth_dns {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;
	char zone_dir[1024];
	char dht_zone_dir[1024];
	uint32_t dht_max_pending;
	const struct lws_dht_dnssec_ops *dht_ops;
	struct auth_dns_zone_list *zones;
	lws_dll2_owner_t pending_queries;
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
}

static int
auth_dns_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct per_vhost_data__auth_dns *vhd = (struct per_vhost_data__auth_dns *)user;
	char filepath[1024];
	int fd;
	size_t len;
	char *buf;
	struct auth_dns_zone_list *zl;
	struct stat st;

	lwsl_notice("%s: check %s (type %d)\n", __func__, lde->name, lde->type);

	if (lde->type != LDOT_UNKNOWN && lde->type != LDOT_FILE)
		return 0;

	len = strlen(lde->name);
	if (len < 5 || strcmp(&lde->name[len - 5], ".zone"))
		return 0;

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

	zl = malloc(sizeof(*zl));
	if (!zl) {
		free(buf);
		return 0;
	}
	memset(zl, 0, sizeof(*zl));

	if (lws_auth_dns_parse_zone_buf(buf, (size_t)st.st_size, &zl->zone)) {
		lwsl_notice("parse failed\n");
		free(zl);
		free(buf);
		return 0;
	}
	free(buf);

	zl->next = vhd->zones;
	vhd->zones = zl;

	lwsl_info("Parsed zone %s from %s\n", zl->zone.origin, filepath);

	return 0;
}



static void
auth_dns_fetch_cb(void *opaque, const char *domain, int status)
{
	struct per_vhost_data__auth_dns *vhd = (struct per_vhost_data__auth_dns *)opaque;

	if (status == 1 && vhd->dht_zone_dir[0]) {
		struct lws_dir_entry lde;
		char namebuf[256];
		memset(&lde, 0, sizeof(lde));
		lde.type = LDOT_FILE;
		lws_snprintf(namebuf, sizeof(namebuf), "%s.zone", domain);
		lde.name = namebuf;
		/* We call auth_dns_dir_cb directly for the single new file */
		auth_dns_dir_cb(vhd->dht_zone_dir, vhd, &lde);
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, vhd->pending_queries.head) {
		struct pending_dns_query *q = lws_container_of(d, struct pending_dns_query, list);
		if (!strcmp(q->domain, domain)) {
			lws_sul_cancel(&q->sul_timeout);
			lws_dll2_remove(&q->list);

			if (status == 1 && q->wsi) {
				const struct lws_protocols *prot = lws_get_protocol(q->wsi);
				if (prot && prot->callback) {
					/* Replay the query with the newly loaded zone */
					prot->callback(q->wsi, LWS_CALLBACK_USER,
						lws_wsi_user(q->wsi), q, 0);
				}
			}
			free(q);
		}
	} lws_end_foreach_dll_safe(d, d1);
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

		{
			const struct lws_protocol_vhost_options *pvo =
				(const struct lws_protocol_vhost_options *)in;

			lwsl_notice("%s: INIT pvo is %p\n", __func__, pvo);
			while (pvo) {
				lwsl_notice("%s: pvo name '%s', value '%s'\n", __func__, pvo->name, pvo->value);
				if (!strcmp(pvo->name, "zone-dir"))
					lws_strncpy(vhd->zone_dir, pvo->value,
							sizeof(vhd->zone_dir));
				if (!strcmp(pvo->name, "dht-zone-dir"))
					lws_strncpy(vhd->dht_zone_dir, pvo->value,
							sizeof(vhd->dht_zone_dir));
				if (!strcmp(pvo->name, "dht-max-pending"))
					vhd->dht_max_pending = (uint32_t)atoi(pvo->value);
				pvo = pvo->next;
			}
			if (vhd->zone_dir[0] == '\0' && vhd->dht_zone_dir[0] == '\0') {
				lwsl_vhost_warn(vhd->vhost, "%s: Missing pvo \"zone-dir\" and \"dht-zone-dir\"",
					 __func__);
				break;
			}
		}

		/* read zone files */
		if (vhd->zone_dir[0] != '\0') {
			lwsl_notice("%s: scanning directory %s\n", __func__, vhd->zone_dir);
			int r = lws_dir(vhd->zone_dir, vhd, auth_dns_dir_cb);
			lwsl_notice("%s: lws_dir returned %d\n", __func__, r);
		}


		if (vhd->dht_zone_dir[0] != '\0') {
			/* Retrieve operations from dht-dnssec plugin if present */
			const struct lws_protocols *prot = lws_vhost_name_to_protocol(vhd->vhost, "lws-dht-dnssec");
			if (prot && prot->user) {
				vhd->dht_ops = (const struct lws_dht_dnssec_ops *)prot->user;
			}

			/* Also optionally scan cache dir on start? */
			lws_dir(vhd->dht_zone_dir, vhd, auth_dns_dir_cb);
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

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (!vhd)
			break;
		{
			struct auth_dns_zone_list *zl = vhd->zones, *nxt;
			while (zl) {
				nxt = zl->next;
				lws_auth_dns_free_zone(&zl->zone);
				free(zl);
				zl = nxt;
			}

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
		struct pending_dns_query *delayed_q = NULL;

		lwsl_notice("LWS_CALLBACK_RAW_RX len %ld, is_tcp=%d\n", (long)len, is_tcp);

		if (reason == LWS_CALLBACK_USER) {
			delayed_q = (struct pending_dns_query *)in;
			p = delayed_q->packet;
			end = p + delayed_q->packet_len;
			is_tcp = delayed_q->is_tcp;
			req_len = (uint16_t)(delayed_q->packet_len - (is_tcp ? 2 : 0));
		} else if (is_tcp) {
			if ((size_t)pss->rx_len + len > sizeof(pss->rx_buf)) { lwsl_notice("tcp req too large\n"); return -1; }
			memcpy(pss->rx_buf + pss->rx_len, in, len);
			pss->rx_len += (int)len;
			if (pss->rx_len < 2) return 0;
			req_len = (uint16_t)((pss->rx_buf[0] << 8) | pss->rx_buf[1]);
			if (req_len > pss->rx_len - 2) return 0;
			p = pss->rx_buf + 2;
			end = pss->rx_buf + 2 + req_len;
		}

		if (p + 12 > end) {
			if (reason == LWS_CALLBACK_RAW_RX) lwsl_notice("short header\n");
			goto done;
		}

		uint16_t id = (uint16_t)((p[0] << 8) | p[1]);
		uint16_t flags = (uint16_t)((p[2] << 8) | p[3]);
		uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);

		lwsl_notice("DNS id %04x flags %04x qdcount %d\n", id, flags, qdcount);

		if (flags & 0x8000) { lwsl_notice("not a query\n"); goto done; }
		if (qdcount != 1) { lwsl_notice("qdcount != 1\n"); goto done; }

		uint8_t *q = p + 12;
		qname[0] = '\0';
		int cycles = 0;
		while (q < end && *q) {
			if (++cycles > 128) { lwsl_notice("qname cycles %d\n", cycles); goto done; }
			int l = *q++;
			if (l & 0xc0) { lwsl_notice("compression ptr in query\n"); goto done; }
			if (q + l > end) goto done;
			if (qname_len + l + 2 > (int)sizeof(qname)) goto done;
			if (qname_len) qname[qname_len++] = '.';
			memcpy(qname + qname_len, q, (size_t)l);
			qname_len += l;
			qname[qname_len] = '\0';
			q += l;
		}
		if (q < end && !*q) q++;
		else { lwsl_notice("qname no null term\n"); goto done; }

		for (int i = 0; qname[i]; i++)
			qname[i] = (char)tolower((unsigned char)qname[i]);

		if (q + 4 > end) { lwsl_notice("no qtype/qclass\n"); goto done; }
		qtype = (q[0] << 8) | q[1];
		qclass = (q[2] << 8) | q[3];
		q += 4;

		lwsl_notice("DNS qname '%s' type %d class %d\n", qname, qtype, qclass);

		uint8_t *dbuf = pss->buf + LWS_PRE;
		uint8_t *rp = dbuf;
		if (is_tcp) rp += 2;

		rp[0] = (uint8_t)(id >> 8); rp[1] = (uint8_t)(id & 0xff);
		uint16_t rflags = 0x8400 | (flags & 0x0100);

		struct auth_dns_zone_list *zl = vhd->zones;
		struct auth_dns_rrset *found_rs = NULL;
		while (zl) {
			int ql = (int)strlen(qname);
			int ol = (int)strlen(zl->zone.origin);
			if (ol > 0 && zl->zone.origin[ol - 1] == '.') ol--;
			if (ql >= ol) {
				const char *tail = qname + ql - ol;
				if ((ql == ol || *(tail - 1) == '.') && !strncmp(tail, zl->zone.origin, (size_t)ol)) {
					lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&zl->zone.rrset_list)) {
						struct auth_dns_rrset *rs = lws_container_of(d, struct auth_dns_rrset, list);
						int rnl = (int)strlen(rs->name);
						if (rnl > 0 && rs->name[rnl - 1] == '.') rnl--;
						if (rnl == ql && !strncmp(rs->name, qname, (size_t)ql) && rs->type == qtype && rs->class_ == qclass) {
							found_rs = rs;
							break;
						}
					} lws_end_foreach_dll(d);
					if (found_rs) break;
				}
			}
			zl = zl->next;
		}

		lwsl_notice("found_rs? %p\n", found_rs);

		if (!found_rs) {
			if (vhd->dht_zone_dir[0] && vhd->dht_ops && vhd->dht_ops->fetch_zone && reason == LWS_CALLBACK_RAW_RX) {
				if ((uint32_t)vhd->pending_queries.count >= vhd->dht_max_pending) {
					lwsl_notice("dht pending queries maxed out\n");
					goto send_refused;
				}
				char base[256];
				extract_base_domain(qname, base, sizeof(base));

				struct pending_dns_query *q = calloc(1, sizeof(*q));
				if (q) {
					q->wsi = wsi;
					q->vhd = vhd;
					q->is_tcp = is_tcp;
					if (!is_tcp) {
						const struct lws_udp *udp = lws_get_udp(wsi);
						if (udp) q->sa46_peer = udp->sa46;
					}
					lws_strncpy(q->domain, base, sizeof(q->domain));
					q->packet_len = is_tcp ? (size_t)req_len + 2 : len;
					if (q->packet_len <= sizeof(q->packet))
						memcpy(q->packet, in, q->packet_len);

					lws_dll2_add_tail(&q->list, &vhd->pending_queries);

					struct lws_dht_dnssec_fetch_zone_args args;
					memset(&args, 0, sizeof(args));
					args.vhost = vhd->vhost;
					args.domain = base;
					args.cache_dir = vhd->dht_zone_dir;
					args.cb = auth_dns_fetch_cb;
					args.opaque = vhd;
					vhd->dht_ops->fetch_zone(vhd->context, &args);
				}
				goto done;
			}

send_refused:
			rflags |= 5; /* REFUSED */
			rp[2] = (uint8_t)(rflags >> 8); rp[3] = (uint8_t)(rflags & 0xff);
			rp[4] = 0; rp[5] = 1;
			rp[6] = 0; rp[7] = 0;
			rp[8] = 0; rp[9] = 0;
			rp[10] = 0; rp[11] = 0;
			rp += 12;
			int qlen = (int)(q - (p + 12));
			memcpy(rp, p + 12, (size_t)qlen);
			rp += qlen;
		} else {
			int anc = 0;
			size_t max_buf = sizeof(pss->buf) - LWS_PRE;
			size_t total_size = lws_ptr_diff_size_t(rp, dbuf) + 12 + (size_t)(q - (p + 12));
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&found_rs->rr_list)) {
				struct auth_dns_rr *rr = lws_container_of(d, struct auth_dns_rr, list);
				if (total_size + 12 + rr->wire_rdata_len > max_buf) {
					rflags |= 0x0200; /* Truncated TC bit */
					break;
				}
				total_size += 12 + rr->wire_rdata_len;
				anc++;
			} lws_end_foreach_dll(d);

			rp[2] = (uint8_t)(rflags >> 8); rp[3] = (uint8_t)(rflags & 0xff);
			rp[4] = 0; rp[5] = 1;
			rp[6] = (uint8_t)(anc >> 8); rp[7] = (uint8_t)(anc & 0xff);
			rp[8] = 0; rp[9] = 0;
			rp[10] = 0; rp[11] = 0;
			rp += 12;
			int qlen = (int)(q - (p + 12));
			memcpy(rp, p + 12, (size_t)qlen);
			rp += qlen;

			int added = 0;
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
		}

		pss->len = (int)(rp - dbuf);
		if (is_tcp) {
			int plen = pss->len - 2;
			dbuf[0] = (uint8_t)(plen >> 8);
			dbuf[1] = (uint8_t)(plen & 0xff);
			lws_callback_on_writable(wsi);
		} else {
			if (reason == LWS_CALLBACK_USER && delayed_q) {
				sendto(lws_get_socket_fd(wsi), (char *)dbuf, (size_t)pss->len, 0,
					(struct sockaddr *)&delayed_q->sa46_peer,
					delayed_q->sa46_peer.sa4.sin_family == AF_INET6 ?
						sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
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
