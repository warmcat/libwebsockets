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
	struct auth_dns_zone_list *zones;
};

struct per_session_data__auth_dns {
	unsigned char rx_buf[1024];
	int rx_len;
	unsigned char buf[LWS_PRE + 1024];
	int len;
};

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
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__auth_dns));
		if (!vhd)
			return 0;
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		{
			const struct lws_protocol_vhost_options *pvo =
				(const struct lws_protocol_vhost_options *)in;
			
			lwsl_notice("%s: INIT pvo is %p\n", __func__, pvo);
			while (pvo) {
				lwsl_notice("%s: pvo name '%s', value '%s'\n", __func__, pvo->name, pvo->value);
				if (!strcmp(pvo->name, "zone-dir"))
					lws_strncpy(vhd->zone_dir, pvo->value,
							sizeof(vhd->zone_dir));
				pvo = pvo->next;
			}
			if (vhd->zone_dir[0] == '\0') {
				lwsl_vhost_warn(vhd->vhost, "%s: Missing pvo \"zone-dir\"",
					 __func__);
				break;
			}
		}

		/* read zone files */
		lwsl_notice("%s: scanning directory %s\n", __func__, vhd->zone_dir);
		int r = lws_dir(vhd->zone_dir, vhd, auth_dns_dir_cb);
		lwsl_notice("%s: lws_dir returned %d\n", __func__, r);
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
		}
		break;

	case LWS_CALLBACK_RAW_RX: {
		uint8_t *p = (uint8_t *)in;
		uint8_t *end = p + len;
		int is_tcp = (lws_get_udp(wsi) == NULL);
		uint16_t req_len = 0;
		int qtype = 0, qclass = 0;
		char qname[256];
		int qname_len = 0;

		lwsl_notice("LWS_CALLBACK_RAW_RX len %ld, is_tcp=%d\n", (long)len, is_tcp);

		if (is_tcp) {
			if (pss->rx_len + len > sizeof(pss->rx_buf)) { lwsl_notice("tcp req too large\n"); return -1; }
			memcpy(pss->rx_buf + pss->rx_len, in, len);
			pss->rx_len += (int)len;
			if (pss->rx_len < 2) return 0;
			req_len = (pss->rx_buf[0] << 8) | pss->rx_buf[1];
			if (req_len > pss->rx_len - 2) return 0;
			p = pss->rx_buf + 2;
			end = pss->rx_buf + 2 + req_len;
		}

		if (p + 12 > end) { lwsl_notice("short header\n"); goto done; }

		uint16_t id = (p[0] << 8) | p[1];
		uint16_t flags = (p[2] << 8) | p[3];
		uint16_t qdcount = (p[4] << 8) | p[5];

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
			size_t total_size = lws_ptr_diff_size_t(rp, dbuf) + 12 + (size_t)(q - (p + 12));
			lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&found_rs->rr_list)) { 
				struct auth_dns_rr *rr = lws_container_of(d, struct auth_dns_rr, list);
				if (total_size + 12 + rr->wire_rdata_len > 1024) {
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
			lws_write(wsi, dbuf, (size_t)pss->len, LWS_WRITE_RAW);
			pss->len = 0;
		}

done:
		if (is_tcp) {
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

LWS_VISIBLE const lws_plugin_protocol_t lws_auth_dns = {
	.hdr = {
		"lws auth dns",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},
	.protocols = lws_auth_dns_protocols,
	.count_protocols = LWS_ARRAY_SIZE(lws_auth_dns_protocols),
	.extensions = NULL,
	.count_extensions = 0,
};
#endif

#endif
