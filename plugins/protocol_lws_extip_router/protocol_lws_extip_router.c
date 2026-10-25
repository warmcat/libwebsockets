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
 *
 * The router knows the addresses we are reachable on from outside directly,
 * since they are configured on its outward interfaces: eg, the IPv4 address
 * on its ppp link and the IPv6 prefix on its LAN interface.
 *
 * In router mode, this plugin answers GET <mount>?nonce=<nonce> with a
 * compact JWS, signed with the router's private key, of
 *
 *  {"pur":"lws-extip-router","nonce":"<nonce>",
 *   "v4":["192.0.2.1"],"v6":["2001:db8:1:2::/64"]}
 *
 * In client mode, it periodically asks the router with a fresh random nonce,
 * and only takes a reply signed by the router's key over that nonce.  It
 * reports the IPv4 address as ours, and for IPv6, the address of ours that
 * is inside the router's prefix (we are not NATed on IPv6), or failing that,
 * the prefix with a configured suffix.  These reports go to the context as
 * LWS_EXTIP_SRC_ROUTER, which ranks above what the extip server or the DHT
 * see.
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
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define EXTIP_ROUTER_PURPOSE		"lws-extip-router"
#define EXTIP_ROUTER_ALG		"ES256"
/* a multiple of 3, so its b64url has no '=' padding: 44 chars */
#define EXTIP_ROUTER_NONCE_BYTES	33
/* accept a little range from other peers */
#define EXTIP_ROUTER_NONCE_MIN		16
#define EXTIP_ROUTER_NONCE_MAX		64
/* most addresses of a family we will put in, or take from, a reply */
#define EXTIP_ROUTER_MAX_ADS		4
#define EXTIP_ROUTER_JWS_MAX		1536
#define EXTIP_ROUTER_TEMP		2048
#define EXTIP_ROUTER_DEF_INTERVAL	60
/* consecutive failed polls before we withdraw what we reported */
#define EXTIP_ROUTER_FAILS_OFFLINE	3
#define EXTIP_ROUTER_TIMEOUT_SECS	10

#if !defined(IFA_F_TEMPORARY)
#define IFA_F_TEMPORARY			0x01
#endif
#if !defined(IFA_F_DADFAILED)
#define IFA_F_DADFAILED			0x08
#endif
#if !defined(IFA_F_DEPRECATED)
#define IFA_F_DEPRECATED		0x20
#endif
#if !defined(IFA_F_TENTATIVE)
#define IFA_F_TENTATIVE			0x40
#endif

/*
 * An IPv6 address with any of these is no good as a stable external
 * address (RFC 8981 temporary, or not, or no longer, usable)
 */
#define EXTIP_ROUTER_V6_BAD_FLAGS	(IFA_F_TEMPORARY | IFA_F_DADFAILED | \
					 IFA_F_DEPRECATED | IFA_F_TENTATIVE)

struct vhd_extip_router {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_jwk			jwk;
	char				jwk_loaded;

	/* router mode */

	char				is_router;
	char				v4_iface[32];
	char				v6_iface[32];

	/* client mode */

	char				is_client;
	char				in_connect;
	char				reply_ok;
	char				truncated;
	char				reported[2];
	unsigned int			fails;
	unsigned int			interval_secs;
	unsigned int			status;
	lws_parse_uri_t			*puri;
	lws_sockaddr46			v6_suffix;
	lws_sorted_usec_list_t		sul;
	struct lws			*cwsi;
	size_t				body_len;
	char				nonce[EXTIP_ROUTER_NONCE_MAX + 1];
	char				body[EXTIP_ROUTER_JWS_MAX + 1];
};

struct pss_extip_router {
	size_t				len;
	unsigned int			status;
	char				sent_headers;
	char				buf[LWS_PRE + EXTIP_ROUTER_JWS_MAX];
};

static int
extip_router_nonce_valid(const char *n, size_t len)
{
	size_t m;

	if (len < EXTIP_ROUTER_NONCE_MIN || len > EXTIP_ROUTER_NONCE_MAX)
		return 0;

	/* b64url alphabet only: it goes into JSON and we compare it exactly */
	for (m = 0; m < len; m++)
		if (!((n[m] >= 'A' && n[m] <= 'Z') ||
		      (n[m] >= 'a' && n[m] <= 'z') ||
		      (n[m] >= '0' && n[m] <= '9') ||
		      n[m] == '-' || n[m] == '_'))
			return 0;

	return 1;
}

static int
extip_router_v6_link_local(const struct in6_addr *a)
{
	return a->s6_addr[0] == 0xfe && (a->s6_addr[1] & 0xc0) == 0x80;
}

static int
extip_router_next_hex(const char **p, const char *end, unsigned int *v)
{
	int digits = 0;

	while (*p < end && **p == ' ')
		(*p)++;

	*v = 0;
	while (*p < end && digits < 8) {
		char c = **p;
		unsigned int nyb;

		if (c >= '0' && c <= '9')
			nyb = (unsigned int)(c - '0');
		else if (c >= 'a' && c <= 'f')
			nyb = (unsigned int)(c - 'a' + 10);
		else
			break;

		*v = (*v << 4) | nyb;
		(*p)++;
		digits++;
	}

	return !digits;
}

/*
 * getifaddrs() can't tell us an IPv6 address is temporary, deprecated or
 * still doing DAD, but Linux lists those flags for each address in
 * /proc/net/if_inet6, one line per address, all fields hex:
 *
 *   20010db8000000000000000000000001 02 40 00 80     eth0
 *   address                          idx plen scope flags  name
 *
 * Elsewhere we can't see them, and take every address as usable.
 */

static unsigned int
extip_router_v6_flags(const struct in6_addr *a)
{
#if defined(__linux__)
	unsigned int flags = 0, v;
	char buf[512], *nl;
	size_t have = 0;
	int fd, found = 0;
	ssize_t n;

	fd = lws_open("/proc/net/if_inet6", O_RDONLY);
	if (fd < 0)
		return 0;

	while (!found) {
		n = read(fd, buf + have, sizeof(buf) - have);
		if (n <= 0)
			break;
		have += (size_t)n;

		while (!found && (nl = memchr(buf, '\n', have))) {
			const char *p = buf + 32, *end = nl;
			uint8_t ads[16];
			int f;

			if (nl - buf > 32 &&
			    lws_hex_len_to_byte_array(buf, 32, ads,
						      sizeof(ads)) == 16 &&
			    !memcmp(ads, a->s6_addr, sizeof(ads))) {
				/* idx, plen, scope, then the flags we want */
				for (f = 0; f < 4; f++)
					if (extip_router_next_hex(&p, end, &v))
						break;
				if (f == 4) {
					flags = v;
					found = 1;
				}
			}

			have -= lws_ptr_diff_size_t(nl + 1, buf);
			memmove(buf, nl + 1, have);
		}

		if (have == sizeof(buf))
			/* not a line we know how to read: drop it */
			have = 0;
	}

	close(fd);

	return flags;
#else
	(void)a;

	return 0;
#endif
}

static void
extip_router_mask(struct in6_addr *a, int plen)
{
	int n;

	for (n = 0; n < 16; n++) {
		if (plen >= 8) {
			plen -= 8;
			continue;
		}
		a->s6_addr[n] = (uint8_t)(a->s6_addr[n] &
					  ((0xff00 >> plen) & 0xff));
		plen = 0;
	}
}

static int
extip_router_netmask_len(const struct sockaddr_in6 *m)
{
	int n, len = 0;

	for (n = 0; n < 16; n++) {
		uint8_t b = m->sin6_addr.s6_addr[n];

		while (b & 0x80) {
			len++;
			b = (uint8_t)(b << 1);
		}
		if (m->sin6_addr.s6_addr[n] != 0xff)
			break;
	}

	return len;
}

#if defined(LWS_WITH_SERVER)

/*
 * Lay out the JSON array members for the interface addresses: the IPv4
 * addresses on v4_iface, and the distinct, usable IPv6 prefixes on v6_iface
 */

static void
extip_router_collect(struct vhd_extip_router *vhd, char *v4, size_t v4len,
		     char *v6, size_t v6len)
{
	struct in6_addr seen[EXTIP_ROUTER_MAX_ADS];
	int c4 = 0, c6 = 0, plens[EXTIP_ROUTER_MAX_ADS], n;
	struct ifaddrs *ifa, *i;
	char *p4 = v4, *p6 = v6, ads[64];

	*v4 = *v6 = '\0';

	if (getifaddrs(&ifa)) {
		lwsl_vhost_warn(vhd->vhost, "getifaddrs failed");
		return;
	}

	for (i = ifa; i; i = i->ifa_next) {
		if (!i->ifa_addr || !i->ifa_name)
			continue;

		if (i->ifa_addr->sa_family == AF_INET && vhd->v4_iface[0] &&
		    !strcmp(i->ifa_name, vhd->v4_iface) &&
		    c4 < EXTIP_ROUTER_MAX_ADS) {
			const struct sockaddr_in *sin =
					(const struct sockaddr_in *)i->ifa_addr;

			if (!inet_ntop(AF_INET, &sin->sin_addr, ads,
				       sizeof(ads)))
				continue;

			p4 += lws_snprintf(p4, lws_ptr_diff_size_t(v4 + v4len, p4),
					   "%s\"%s\"", c4 ? "," : "", ads);
			c4++;
			continue;
		}

		if (i->ifa_addr->sa_family == AF_INET6 && vhd->v6_iface[0] &&
		    i->ifa_netmask && !strcmp(i->ifa_name, vhd->v6_iface) &&
		    c6 < EXTIP_ROUTER_MAX_ADS) {
			struct in6_addr pfx = ((const struct sockaddr_in6 *)
						i->ifa_addr)->sin6_addr;
			int plen = extip_router_netmask_len(
				(const struct sockaddr_in6 *)i->ifa_netmask);

			if (extip_router_v6_link_local(&pfx) ||
			    (extip_router_v6_flags(&pfx) &
					    EXTIP_ROUTER_V6_BAD_FLAGS))
				continue;

			extip_router_mask(&pfx, plen);

			/* several addresses usually share one prefix */
			for (n = 0; n < c6; n++)
				if (plens[n] == plen &&
				    !memcmp(&seen[n], &pfx, sizeof(pfx)))
					break;
			if (n != c6)
				continue;

			if (!inet_ntop(AF_INET6, &pfx, ads, sizeof(ads)))
				continue;

			seen[c6] = pfx;
			plens[c6] = plen;
			p6 += lws_snprintf(p6, lws_ptr_diff_size_t(v6 + v6len, p6),
					   "%s\"%s/%d\"", c6 ? "," : "", ads, plen);
			c6++;
		}
	}

	freeifaddrs(ifa);
}

static int
extip_router_http(struct lws *wsi, struct vhd_extip_router *vhd,
		  struct pss_extip_router *pss)
{
	char nonce[EXTIP_ROUTER_NONCE_MAX + 2], v4[256], v6[384],
	     temp[EXTIP_ROUTER_TEMP];
	size_t ol = sizeof(pss->buf) - LWS_PRE;
	int n;

	pss->status = HTTP_STATUS_BAD_REQUEST;
	pss->len = 0;

	n = lws_get_urlarg_by_name_safe(wsi, "nonce", nonce, sizeof(nonce));
	if (n < 0 || !extip_router_nonce_valid(nonce, (size_t)n)) {
		lwsl_vhost_info(vhd->vhost, "missing or bad nonce");
		return 0;
	}

	extip_router_collect(vhd, v4, sizeof(v4), v6, sizeof(v6));

	if (lws_jwt_sign_compact(vhd->context, &vhd->jwk, EXTIP_ROUTER_ALG,
				 pss->buf + LWS_PRE, &ol, temp, sizeof(temp),
				 "{\"pur\":\"" EXTIP_ROUTER_PURPOSE "\","
				 "\"nonce\":\"%s\",\"v4\":[%s],\"v6\":[%s]}",
				 nonce, v4, v6)) {
		lwsl_vhost_err(vhd->vhost, "signing failed");
		pss->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		return 0;
	}

	lwsl_vhost_info(vhd->vhost, "v4 [%s], v6 [%s]", v4, v6);

	pss->status = HTTP_STATUS_OK;
	pss->len = ol;

	return 0;
}

static int
extip_router_http_writeable(struct lws *wsi, struct pss_extip_router *pss)
{
	uint8_t hdrs[LWS_PRE + 512], *start = hdrs + LWS_PRE, *p = start,
		*end = hdrs + sizeof(hdrs) - 1;

	if (pss->sent_headers)
		return 0;

	if (lws_add_http_common_headers(wsi, pss->status,
					pss->len ? "application/jose" :
						   "text/plain",
					(lws_filepos_t)pss->len, &p, end) ||
	    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
					 (uint8_t *)"no-store", 8, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	pss->sent_headers = 1;

	if (pss->len &&
	    lws_write(wsi, (uint8_t *)pss->buf + LWS_PRE, pss->len,
		      LWS_WRITE_HTTP_FINAL) != (int)pss->len)
		return 1;

	return lws_http_transaction_completed(wsi);
}

#endif /* SERVER */

#if defined(LWS_WITH_CLIENT)

struct extip_router_parse {
	char		nonce[EXTIP_ROUTER_NONCE_MAX + 1];
	char		pur;
	char		dupe;
	int		c4, c6;
	lws_sockaddr46	v4[EXTIP_ROUTER_MAX_ADS];
#if defined(LWS_WITH_IPV6)
	lws_sockaddr46	v6[EXTIP_ROUTER_MAX_ADS];
	int		v6_plen[EXTIP_ROUTER_MAX_ADS];
#endif
};

static const char * const extip_router_paths[] = {
	"pur",
	"nonce",
	"v4[]",
	"v6[]",
};

enum {
	EXR_PUR = 1,
	EXR_NONCE,
	EXR_V4,
	EXR_V6,
};

static signed char
extip_router_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct extip_router_parse *ep = (struct extip_router_parse *)ctx->user;
	lws_sockaddr46 sa46;
#if defined(LWS_WITH_IPV6)
	int plen;
#endif

	if (reason != LEJPCB_VAL_STR_END)
		return 0;

	switch (ctx->path_match) {
	case EXR_PUR:
		if (ep->pur)
			ep->dupe = 1;
		ep->pur = !strcmp(ctx->buf, EXTIP_ROUTER_PURPOSE) ? 1 : 2;
		break;

	case EXR_NONCE:
		if (ep->nonce[0])
			ep->dupe = 1;
		lws_strncpy(ep->nonce, ctx->buf, sizeof(ep->nonce));
		break;

	case EXR_V4:
		memset(&sa46, 0, sizeof(sa46));
		if (ep->c4 < EXTIP_ROUTER_MAX_ADS &&
		    !lws_sa46_parse_numeric_address(ctx->buf, &sa46) &&
		    sa46.sa4.sin_family == AF_INET)
			ep->v4[ep->c4++] = sa46;
		break;

#if defined(LWS_WITH_IPV6)
	case EXR_V6:
		memset(&sa46, 0, sizeof(sa46));
		if (ep->c6 < EXTIP_ROUTER_MAX_ADS &&
		    !lws_parse_cidr(ctx->buf, &sa46, &plen) &&
		    sa46.sa4.sin_family == AF_INET6 &&
		    plen >= 0 && plen <= 128) {
			ep->v6[ep->c6] = sa46;
			ep->v6_plen[ep->c6++] = plen;
		}
		break;
#endif
	}

	return 0;
}

#if defined(LWS_WITH_IPV6)
/* find our own usable address inside the router's prefix */

static int
extip_router_v6_ours(const lws_sockaddr46 *pfx, int plen, lws_sockaddr46 *out)
{
	struct ifaddrs *ifa, *i;
	int found = 0;

	if (!getifaddrs(&ifa)) {
		for (i = ifa; i && !found; i = i->ifa_next) {
			const struct sockaddr_in6 *s6;

			if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET6)
				continue;

			s6 = (const struct sockaddr_in6 *)i->ifa_addr;
			if (extip_router_v6_link_local(&s6->sin6_addr))
				continue;

			memset(out, 0, sizeof(*out));
			out->sa6.sin6_family = AF_INET6;
			out->sa6.sin6_addr = s6->sin6_addr;

			if (!lws_sa46_on_net(out, pfx, plen) &&
			    !(extip_router_v6_flags(&s6->sin6_addr) &
					    EXTIP_ROUTER_V6_BAD_FLAGS))
				found = 1;
		}
		freeifaddrs(ifa);
	}

	return !found;
}

/* the prefix bits from the router, the rest from our configured suffix */

static int
extip_router_v6_suffixed(struct vhd_extip_router *vhd,
			 const lws_sockaddr46 *pfx, int plen,
			 lws_sockaddr46 *out)
{
	int n;

	if (!vhd->v6_suffix.sa4.sin_family || plen >= 128)
		return 1;

	memset(out, 0, sizeof(*out));
	out->sa6.sin6_family = AF_INET6;
	for (n = 0; n < 16; n++) {
		int pb = plen - (n * 8);
		uint8_t m = pb >= 8 ? 0xff : (pb > 0 ? (uint8_t)(0xff00 >> pb) :
						       0);

		out->sa6.sin6_addr.s6_addr[n] = (uint8_t)(
			(pfx->sa6.sin6_addr.s6_addr[n] & m) |
			(vhd->v6_suffix.sa6.sin6_addr.s6_addr[n] & ~m));
	}

	return 0;
}
#endif

static void
extip_router_report(struct vhd_extip_router *vhd, int fi,
		    const lws_sockaddr46 *sa46)
{
	vhd->reported[fi] = !!sa46;
	lws_extip_report(vhd->context, LWS_EXTIP_SRC_ROUTER, sa46,
			 fi ? AF_INET6 : AF_INET,
			 sa46 ? LWS_EXTIP_STATUS_CHANGED :
				LWS_EXTIP_STATUS_OFFLINE, NULL, 0);
}

static void
extip_router_failed(struct vhd_extip_router *vhd, const char *why)
{
	int fi;

	lwsl_vhost_warn(vhd->vhost, "router query failed: %s", why);

	if (++vhd->fails < EXTIP_ROUTER_FAILS_OFFLINE)
		return;

	/* we can't vouch for what we said any more */

	for (fi = 0; fi < 2; fi++)
		if (vhd->reported[fi])
			extip_router_report(vhd, fi, NULL);
}

static void
extip_router_reply(struct vhd_extip_router *vhd)
{
	char temp[EXTIP_ROUTER_TEMP], pl[EXTIP_ROUTER_JWS_MAX];
	struct extip_router_parse ep;
	struct lejp_ctx ctx;
	size_t pll = sizeof(pl) - 1;
#if defined(LWS_WITH_IPV6)
	lws_sockaddr46 v6;
	int n;
#endif
	int m;

	if (vhd->status != HTTP_STATUS_OK || vhd->truncated) {
		extip_router_failed(vhd, vhd->truncated ? "reply too large" :
							  "http status");
		return;
	}

	if (lws_jwt_signed_validate(vhd->context, &vhd->jwk, EXTIP_ROUTER_ALG,
				    vhd->body, vhd->body_len, temp,
				    sizeof(temp), pl, &pll)) {
		extip_router_failed(vhd, "signature");
		return;
	}

	memset(&ep, 0, sizeof(ep));
	lejp_construct(&ctx, extip_router_lejp_cb, &ep, extip_router_paths,
		       LWS_ARRAY_SIZE(extip_router_paths));
	m = lejp_parse(&ctx, (const uint8_t *)pl, (int)pll);
	lejp_destruct(&ctx);

	/*
	 * It's signed by the router, but it must also be its answer to this
	 * question: anything else may be a replay of an old answer
	 */

	if (m < 0 || ep.dupe || ep.pur != 1 || strcmp(ep.nonce, vhd->nonce)) {
		extip_router_failed(vhd, "payload or nonce mismatch");
		return;
	}

	vhd->fails = 0;

	extip_router_report(vhd, 0, ep.c4 ? &ep.v4[0] : NULL);

#if defined(LWS_WITH_IPV6)
	for (n = 0; n < ep.c6; n++)
		if (!extip_router_v6_ours(&ep.v6[n], ep.v6_plen[n], &v6))
			break;

	if (n == ep.c6 && ep.c6) {
		if (!extip_router_v6_suffixed(vhd, &ep.v6[0], ep.v6_plen[0], &v6))
			n = 0;
		else
			lwsl_vhost_warn(vhd->vhost, "no address of ours in the "
					"router's IPv6 prefix, and no v6-suffix");
	}

	extip_router_report(vhd, 1, n < ep.c6 ? &v6 : NULL);
#endif
}

static void
extip_router_poll(lws_sorted_usec_list_t *sul)
{
	struct vhd_extip_router *vhd = lws_container_of(sul,
					struct vhd_extip_router, sul);
	struct lws_client_connect_info i;
	uint8_t rnd[EXTIP_ROUTER_NONCE_BYTES];
	char path[384];

	lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_router_poll,
			 vhd->interval_secs * LWS_US_PER_SEC);

	if (vhd->cwsi) {
		extip_router_failed(vhd, "previous query still pending");
		return;
	}

	lws_get_random(vhd->context, rnd, sizeof(rnd));
	if (lws_b64_encode_string_url((const char *)rnd, sizeof(rnd),
				      vhd->nonce, sizeof(vhd->nonce)) < 0)
		return;

	lws_snprintf(path, sizeof(path), "/%s?nonce=%s",
		     vhd->puri->path ? vhd->puri->path : "", vhd->nonce);

	vhd->body_len	= 0;
	vhd->truncated	= 0;
	vhd->reply_ok	= 0;
	vhd->status	= 0;

	memset(&i, 0, sizeof(i));
	i.context		= vhd->context;
	i.vhost			= vhd->vhost;
	i.address		= vhd->puri->host;
	i.host			= vhd->puri->host;
	i.origin		= vhd->puri->host;
	i.port			= vhd->puri->port;
	i.path			= path;
	i.method		= "GET";
	i.ssl_connection	= !strcmp(vhd->puri->scheme, "https") ?
							LCCSCF_USE_SSL : 0;
	i.local_protocol_name	= "lws-extip-router";
	i.pwsi			= &vhd->cwsi;

	/*
	 * The connection error may be delivered inside the call: it clears
	 * cwsi and counts the failure itself
	 */

	vhd->in_connect = 1;
	if (!lws_client_connect_via_info(&i) && vhd->in_connect)
		extip_router_failed(vhd, "connect");
	vhd->in_connect = 0;
}

#endif /* CLIENT */

static void
extip_router_vhd_clean(struct vhd_extip_router *vhd)
{
#if defined(LWS_WITH_CLIENT)
	lws_sul_cancel(&vhd->sul);
#endif
	if (vhd->jwk_loaded)
		lws_jwk_destroy(&vhd->jwk);
	vhd->jwk_loaded = 0;
	if (vhd->puri)
		lws_parse_uri_destroy(&vhd->puri);
}

static int
extip_router_init(struct lws *wsi, struct vhd_extip_router *vhd,
		  const struct lws_protocol_vhost_options *pvo)
{
	const char *jwk_path = NULL;

	for (; pvo; pvo = pvo->next) {
		if (!strcmp(pvo->name, "jwk-private")) {
			vhd->is_router = 1;
			jwk_path = pvo->value;
		} else if (!strcmp(pvo->name, "v4-iface"))
			lws_strncpy(vhd->v4_iface, pvo->value,
				    sizeof(vhd->v4_iface));
		else if (!strcmp(pvo->name, "v6-iface"))
			lws_strncpy(vhd->v6_iface, pvo->value,
				    sizeof(vhd->v6_iface));
		else if (!strcmp(pvo->name, "router-url")) {
			vhd->is_client = 1;
			vhd->puri = lws_parse_uri_create(pvo->value);
		} else if (!strcmp(pvo->name, "jwk-public"))
			jwk_path = pvo->value;
		else if (!strcmp(pvo->name, "interval-secs"))
			vhd->interval_secs = (unsigned int)atoi(pvo->value);
#if defined(LWS_WITH_IPV6)
		else if (!strcmp(pvo->name, "v6-suffix") &&
			 (lws_sa46_parse_numeric_address(pvo->value,
							 &vhd->v6_suffix) ||
			  vhd->v6_suffix.sa4.sin_family != AF_INET6)) {
			lwsl_vhost_err(vhd->vhost, "bad v6-suffix '%s'",
				       pvo->value);
			return 1;
		}
#endif
	}

	if (vhd->is_router == vhd->is_client) {
		lwsl_vhost_err(vhd->vhost, "give exactly one of jwk-private "
			       "(router) or router-url (client)");
		return 1;
	}

#if !defined(LWS_WITH_SERVER)
	if (vhd->is_router) {
		lwsl_vhost_err(vhd->vhost, "router mode needs server support");
		return 1;
	}
#endif
#if !defined(LWS_WITH_CLIENT)
	if (vhd->is_client) {
		lwsl_vhost_err(vhd->vhost, "client mode needs client support");
		return 1;
	}
#endif

	if (vhd->is_client && (!vhd->puri || !vhd->puri->host ||
			       !vhd->puri->scheme ||
			       (strcmp(vhd->puri->scheme, "http") &&
				strcmp(vhd->puri->scheme, "https")))) {
		lwsl_vhost_err(vhd->vhost, "router-url must be http(s)://...");
		return 1;
	}

	if (!jwk_path) {
		lwsl_vhost_err(vhd->vhost, "%s needs %s", vhd->is_router ?
			       "router" : "client", vhd->is_router ?
			       "jwk-private" : "jwk-public");
		return 1;
	}

	if (lws_jwk_load(&vhd->jwk, jwk_path, NULL, NULL)) {
		lwsl_vhost_err(vhd->vhost, "unable to load key %s", jwk_path);
		return 1;
	}
	vhd->jwk_loaded = 1;

	/*
	 * The alg is fixed, but the key is still checked against it, so a
	 * wrong file is found at startup instead of failing every query
	 */

	if (vhd->jwk.kty != LWS_GENCRYPTO_KTY_EC ||
	    !vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf ||
	    strcmp((const char *)vhd->jwk.e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
		   "P-256") ||
	    (vhd->is_router && !vhd->jwk.private_key)) {
		lwsl_vhost_err(vhd->vhost, "%s must be an EC P-256 %s key",
			       jwk_path, vhd->is_router ? "private" : "public");
		return 1;
	}

	if (vhd->is_router) {
		if (!vhd->v4_iface[0] && !vhd->v6_iface[0]) {
			lwsl_vhost_err(vhd->vhost, "router needs v4-iface "
				       "and / or v6-iface");
			return 1;
		}
		lwsl_vhost_notice(vhd->vhost, "router: v4 from '%s', v6 from "
				  "'%s'", vhd->v4_iface, vhd->v6_iface);
		return 0;
	}

#if defined(LWS_WITH_CLIENT)
	if (!vhd->interval_secs)
		vhd->interval_secs = EXTIP_ROUTER_DEF_INTERVAL;

	lwsl_vhost_notice(vhd->vhost, "client: asking %s://%s:%u/%s every %us",
			  vhd->puri->scheme, vhd->puri->host, vhd->puri->port,
			  vhd->puri->path ? vhd->puri->path : "",
			  vhd->interval_secs);

	lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_router_poll, 1);
#endif

	(void)wsi;

	return 0;
}

static int
callback_extip_router(struct lws *wsi, enum lws_callback_reasons reason,
		      void *user, void *in, size_t len)
{
	struct vhd_extip_router *vhd = (struct vhd_extip_router *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
#if defined(LWS_WITH_SERVER)
	struct pss_extip_router *pss = (struct pss_extip_router *)user;
#endif

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		if (!in || vhd)
			return 0;

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi), sizeof(*vhd));
		if (!vhd)
			return 1;

		vhd->context	= lws_get_context(wsi);
		vhd->vhost	= lws_get_vhost(wsi);

		if (extip_router_init(wsi, vhd,
			(const struct lws_protocol_vhost_options *)in)) {
			extip_router_vhd_clean(vhd);
			return 1;
		}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			extip_router_vhd_clean(vhd);
		break;

#if defined(LWS_WITH_SERVER)
	case LWS_CALLBACK_HTTP:
		/* we only answer GET, so there's never a request body */
		if (!vhd || !vhd->is_router ||
		    lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) <= 0)
			return 1;
		if (extip_router_http(wsi, vhd, pss))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!vhd || !vhd->is_router)
			return 1;
		return extip_router_http_writeable(wsi, pss);
#endif

#if defined(LWS_WITH_CLIENT)
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!vhd || wsi != vhd->cwsi)
			break;
		vhd->cwsi = NULL;
		vhd->in_connect = 0;
		extip_router_failed(vhd, in ? (const char *)in : "connect");
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!vhd || wsi != vhd->cwsi)
			break;
		/* 0 is an h2 / h3 stream joining a connection, no reply yet */
		if (lws_http_client_http_response(wsi))
			vhd->status = lws_http_client_http_response(wsi);
		lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
				EXTIP_ROUTER_TIMEOUT_SECS);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!vhd || wsi != vhd->cwsi)
			break;
		if (vhd->body_len + len > EXTIP_ROUTER_JWS_MAX) {
			vhd->truncated = 1;
			break;
		}
		memcpy(vhd->body + vhd->body_len, in, len);
		vhd->body_len += len;
		vhd->body[vhd->body_len] = '\0';
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
		int lenx = sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!vhd || wsi != vhd->cwsi)
			break;
		/* the connection may be kept warm: it's no longer our query */
		vhd->cwsi = NULL;
		vhd->reply_ok = 1;
		extip_router_reply(vhd);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!vhd || wsi != vhd->cwsi)
			break;
		vhd->cwsi = NULL;
		if (!vhd->reply_ok)
			extip_router_failed(vhd, "closed before reply");
		break;
#endif

	default:
		return lws_callback_http_dummy(wsi, reason, user, in, len);
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_EXTIP_ROUTER \
	{ \
		"lws-extip-router", \
		callback_extip_router, \
		sizeof(struct pss_extip_router), \
		1024, 0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
LWS_VISIBLE const struct lws_protocols lws_extip_router_protocols[] = {
	LWS_PLUGIN_PROTOCOL_EXTIP_ROUTER
};

LWS_VISIBLE const lws_plugin_protocol_t lws_extip_router = {
	.hdr = {
		.name		= "lws extip router",
		._class		= "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic	= LWS_PLUGIN_API_MAGIC
	},
	.protocols		= lws_extip_router_protocols,
	.count_protocols	= LWS_ARRAY_SIZE(lws_extip_router_protocols),
};
#endif
