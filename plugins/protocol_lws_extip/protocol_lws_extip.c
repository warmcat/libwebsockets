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

#if !defined(WIN32)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#define LENGTH_EXTIP_COOKIE		32

struct vhd_extip {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws_sorted_usec_list	sul;

	int				is_server;
	int				is_client;
	int				bind_port;
	char				server_addr[256];
	int				server_port;

	int				dns_done;

	uint8_t				secret[LENGTH_EXTIP_COOKIE];

	// Client state
	struct extip_ip {
		struct lws			*cwsi;
		lws_sockaddr46			srv_sa46;
		uint8_t				cookie[LENGTH_EXTIP_COOKIE];
		int				has_cookie;
		lws_usec_t			last_rx;
		lws_usec_t			last_tx;
		int				offline;
	} ip[2]; /* 0: IPv4, 1: IPv6 */
};

static int
generate_cookie(struct vhd_extip *vhd, const struct sockaddr *sa, socklen_t salen, uint8_t *hash_out)
{
	struct lws_genhash_ctx hctx;

	if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hctx, vhd->secret, sizeof(vhd->secret)) ||
	    lws_genhash_update(&hctx, sa, salen) ||
	    lws_genhash_destroy(&hctx, hash_out)) {
		lwsl_err("%s: hmac failed\n", __func__);
		return 1;
	}
	
	return 0;
}

static void
extip_client_sul_cb(struct lws_sorted_usec_list *sul);

static struct lws *
extip_dns_cb(struct lws *wsi, const char *ads, const struct addrinfo *result, int n, void *opaque)
{
	struct vhd_extip *vhd = (struct vhd_extip *)opaque;
	const struct addrinfo *ai = result;

	if (!vhd || !vhd->is_client)
		return NULL;

	if (!result) {
		lwsl_notice("extip: dns resolution failed for %s\n", ads);
		return NULL;
	}

	while (ai) {
		if (ai->ai_family == AF_INET && vhd->ip[0].srv_sa46.sa4.sin_family == 0) {
			struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
			vhd->ip[0].srv_sa46.sa4.sin_family = AF_INET;
			vhd->ip[0].srv_sa46.sa4.sin_addr = sa->sin_addr;
			vhd->ip[0].srv_sa46.sa4.sin_port = htons((uint16_t)vhd->server_port);
			
			vhd->ip[0].cwsi = lws_create_adopt_udp(vhd->vhost, "0.0.0.0", 0, LWS_CAUDP_BIND,
				"protocol-lws-extip", NULL, NULL, NULL, NULL, "extip_c4");
		} else if (ai->ai_family == AF_INET6 && vhd->ip[1].srv_sa46.sa6.sin6_family == 0) {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
			vhd->ip[1].srv_sa46.sa6.sin6_family = AF_INET6;
			vhd->ip[1].srv_sa46.sa6.sin6_addr = sa6->sin6_addr;
			vhd->ip[1].srv_sa46.sa6.sin6_port = htons((uint16_t)vhd->server_port);
			
			vhd->ip[1].cwsi = lws_create_adopt_udp(vhd->vhost, "::", 0, LWS_CAUDP_BIND,
				"protocol-lws-extip", NULL, NULL, NULL, NULL, "extip_c6");
		}

		ai = ai->ai_next;
	}

	/* Trigger ping immediately now that we have a socket */
	lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_client_sul_cb, 1);

	lws_async_dns_freeaddrinfo(&result);

	return NULL;
}

static void
extip_report_ip_offline(struct vhd_extip *vhd, int i)
{
        vhd->ip[i].offline = 1;
        lwsl_notice("extip client: IPv%c offline\n", i ? '6' : '4');

	lws_sockaddr46 zero;
	memset(&zero, 0, sizeof(zero));

	if (!i)
		zero.sa4.sin_family = AF_INET;
	else
		zero.sa6.sin6_family = AF_INET6;

	lwsl_notice("EXTIP_DEBUG: extip_report_ip_offline for IPv%c\n", i ? '6' : '4');
	lws_extip_report(vhd->context, LWS_EXTIP_SRC_EXTIP, &zero, !i ? AF_INET : AF_INET6, 2, NULL, 0);
}

static void
extip_client_sul_cb(struct lws_sorted_usec_list *sul)
{
	struct vhd_extip *vhd = lws_container_of(sul, struct vhd_extip, sul);
	char payload[128];
	int plen = 0;
	lws_usec_t now = lws_now_usecs();

	if (!vhd->dns_done) {
		vhd->dns_done = 1;
		lws_async_dns_query(vhd->context, 0, vhd->server_addr, LWS_ADNS_RECORD_A, extip_dns_cb, NULL, vhd, NULL);
		lws_async_dns_query(vhd->context, 0, vhd->server_addr, LWS_ADNS_RECORD_AAAA, extip_dns_cb, NULL, vhd, NULL);
	}

	lws_usec_t shortest = 30 * LWS_US_PER_SEC;

	for (int i = 0; i < 2; i++) {
		if (vhd->ip[i].cwsi && (
		    (i == 0 && vhd->ip[i].srv_sa46.sa4.sin_family == AF_INET) ||
		    (i == 1 && vhd->ip[i].srv_sa46.sa6.sin6_family == AF_INET6))) {

			if (now - vhd->ip[i].last_rx > 90 * LWS_US_PER_SEC && vhd->ip[i].last_rx) {
				if (!vhd->ip[i].offline)
					extip_report_ip_offline(vhd, i);
			}
			
			int need_tx = 0;
			if (!vhd->ip[i].last_tx) {
				need_tx = 1;
			} else if (vhd->ip[i].last_rx >= vhd->ip[i].last_tx) {
				if (now - vhd->ip[i].last_rx >= 30 * LWS_US_PER_SEC)
					need_tx = 1;
				else {
					lws_usec_t wait = (30 * LWS_US_PER_SEC) - (now - vhd->ip[i].last_rx);
					if (wait < shortest)
						shortest = wait;
				}
			} else {
				if (now - vhd->ip[i].last_tx >= 3 * LWS_US_PER_SEC)
					need_tx = 1;
				else {
					lws_usec_t wait = (3 * LWS_US_PER_SEC) - (now - vhd->ip[i].last_tx);
					if (wait < shortest)
						shortest = wait;
				}
			}

			if (need_tx) {
				if (!vhd->ip[i].has_cookie) {
					payload[0] = 'R';
					plen = 1;
				} else {
					payload[0] = 'P';
					memcpy(payload + 1, vhd->ip[i].cookie, LENGTH_EXTIP_COOKIE);
					plen = (1 + LENGTH_EXTIP_COOKIE);
				}

				if (sendto(lws_get_socket_fd(vhd->ip[i].cwsi), payload, (size_t)plen, 0, sa46_sockaddr(&vhd->ip[i].srv_sa46), sa46_socklen(&vhd->ip[i].srv_sa46)) < 0) {
					lwsl_warn("%s: sendto ping failed (i=%d, errno=%d)\n", __func__, i, errno);
					if (!vhd->ip[i].offline)
						extip_report_ip_offline(vhd, i);
				}
				
				vhd->ip[i].last_tx = now;
				if (3 * LWS_US_PER_SEC < shortest)
					shortest = 3 * LWS_US_PER_SEC;
			}
		}
	}

	lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_client_sul_cb, shortest);
}

static int
callback_extip(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	struct vhd_extip *vhd = (struct vhd_extip *)lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
	const struct lws_udp *udp = lws_get_udp(wsi);

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
	{
		const struct lws_protocol_vhost_options *pvo = (const struct lws_protocol_vhost_options *)in;

                if (!pvo)
                        return -1;

		lwsl_vhost_notice(lws_get_vhost(wsi), "EXTIP_DEBUG: %s: LWS_CALLBACK_PROTOCOL_INIT starting\n", __func__);

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi), lws_get_protocol(wsi), sizeof(struct vhd_extip));
		if (!vhd)
			return 1;
		
		vhd->context		= lws_get_context(wsi);
		vhd->vhost		= lws_get_vhost(wsi);

		while (pvo) {
			lwsl_vhost_notice(vhd->vhost, "extip: processing PVO: '%s' = '%s'\n", pvo->name, pvo->value);
			if (!strcmp(pvo->name, "listen-port")) {
				vhd->is_server = 1;
				vhd->bind_port = atoi(pvo->value);
			}
			if (!strcmp(pvo->name, "connect")) {
				const char *colon = strrchr(pvo->value, ':');
				vhd->is_client = 1;
				if (colon) {
					size_t len = (size_t)(colon - pvo->value);
					if (len >= sizeof(vhd->server_addr))
						len = sizeof(vhd->server_addr) - 1;
					memcpy(vhd->server_addr, pvo->value, len);
					vhd->server_addr[len] = '\0';
					vhd->server_port = atoi(colon + 1);
				} else {
					lwsl_err("extip: connect PVO must format as addr:port\n");

					return -1;
				}
			}

			pvo = pvo->next;
		}

		if (vhd->is_server) {
			lwsl_vhost_notice(vhd->vhost, "extip: initializing server mode on port %d\n", vhd->bind_port);
			lws_get_random(vhd->context, vhd->secret, sizeof(vhd->secret));

			vhd->ip[0].cwsi = lws_create_adopt_udp(vhd->vhost, "0.0.0.0", vhd->bind_port, LWS_CAUDP_BIND,
					lws_get_protocol(wsi)->name, NULL, NULL, NULL, NULL, "extip_srv4");

#if defined(LWS_WITH_IPV6)
			vhd->ip[1].cwsi = lws_create_adopt_udp(vhd->vhost, "::", vhd->bind_port, LWS_CAUDP_BIND,
					lws_get_protocol(wsi)->name, NULL, NULL, NULL, NULL, "extip_srv6");
#endif

			if (!vhd->ip[0].cwsi && !vhd->ip[1].cwsi) {
				lwsl_err("extip: failed to adopt any server udp sockets\n");
				return -1;
			}

			lwsl_notice("extip: Server listening successfully on UDP port %d\n", vhd->bind_port);
		}

		if (vhd->is_client) {
			if (!vhd->server_addr[0]) {
				lwsl_err("%s: extip: client connect requires addr:port\n", __func__);
				return -1;
			}
			lwsl_notice("%s: extip: Client starting, targeting %s\n", __func__, vhd->server_addr);

			lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_client_sul_cb, 1);
		}

		break;
	}

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd)
			lws_sul_cancel(&vhd->sul);
		break;

	case LWS_CALLBACK_RAW_RX:
	{
		char *buf = (char *)in;
		char reply[128];

		if (!vhd || !in || !udp)
			break;

		if (vhd->is_server && len == 1 && buf[0] == 'R') {
			reply[0] = 'C';
			if (!generate_cookie(vhd, sa46_sockaddr(&udp->sa46), sa46_socklen(&udp->sa46), (uint8_t *)reply + 1)) {
				lws_sa46_write_numeric_address((lws_sockaddr46 *)&udp->sa46, reply + 1 + LENGTH_EXTIP_COOKIE, sizeof(reply) - 2 - LENGTH_EXTIP_COOKIE);
				if (sendto(lws_get_socket_fd(wsi), reply, (size_t)(1 + LENGTH_EXTIP_COOKIE + strlen(reply + 1 + LENGTH_EXTIP_COOKIE)), 0, sa46_sockaddr(&udp->sa46), sa46_socklen(&udp->sa46)) < 0)
					lwsl_warn("%s: sendto 'C' failed\n", __func__);
			}
		}

		if (vhd->is_server && len == (1 + LENGTH_EXTIP_COOKIE) && buf[0] == 'P') {
			uint8_t expected[LENGTH_EXTIP_COOKIE];
			if (!generate_cookie(vhd, sa46_sockaddr(&udp->sa46), sa46_socklen(&udp->sa46), expected)) {
				if (memcmp(expected, buf + 1, LENGTH_EXTIP_COOKIE) == 0) {
					/* Valid */
					reply[0] = 'O';
					memcpy(reply + 1, buf + 1, LENGTH_EXTIP_COOKIE);
					if (sendto(lws_get_socket_fd(wsi), reply, (size_t)(1 + LENGTH_EXTIP_COOKIE), 0, sa46_sockaddr(&udp->sa46), sa46_socklen(&udp->sa46)) < 0)
						lwsl_warn("%s: sendto 'O' failed\n", __func__);
				} else {
					/* IP Changed */
					reply[0] = 'I';
					lws_sa46_write_numeric_address((lws_sockaddr46 *)&udp->sa46, reply + 1, sizeof(reply) - 2);
					if (sendto(lws_get_socket_fd(wsi), reply, 1 + strlen(reply + 1), 0, sa46_sockaddr(&udp->sa46), sa46_socklen(&udp->sa46)) < 0)
						lwsl_warn("%s: sendto 'I' failed\n", __func__);
				}
			}
		}

		if (!vhd->is_client)
			break;

		int is_v6 = (wsi == vhd->ip[1].cwsi);
		
		if (len >= (1 + LENGTH_EXTIP_COOKIE) && buf[0] == 'C') {
			memcpy(vhd->ip[is_v6].cookie, buf + 1, LENGTH_EXTIP_COOKIE);
			vhd->ip[is_v6].has_cookie	= 1;
			vhd->ip[is_v6].last_rx		= lws_now_usecs();
			vhd->ip[is_v6].offline		= 0;
			lwsl_notice("extip client: IPv%c obtained cookie\n", is_v6 ? '6' : '4');

			if (len > 1 + LENGTH_EXTIP_COOKIE) {
				lws_sockaddr46 sa46;
				buf[len] = '\0';
				memset(&sa46, 0, sizeof(sa46));
				lws_sa46_parse_numeric_address(buf + 1 + LENGTH_EXTIP_COOKIE, &sa46);
				lwsl_notice("EXTIP_DEBUG: Client reporting online IP to lws_extip_report\n");
				lws_extip_report(vhd->context, LWS_EXTIP_SRC_EXTIP, &sa46, sa46.sa4.sin_family == AF_INET ? AF_INET : AF_INET6, 1, NULL, 0);
			}

			lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_client_sul_cb, 1);
			break;
		}

		if (len == (1 + LENGTH_EXTIP_COOKIE) && buf[0] == 'O') {
			vhd->ip[is_v6].last_rx		= lws_now_usecs();
			vhd->ip[is_v6].offline		= 0;
			break;
		}

		if (len > 1 && buf[0] == 'I') {
			lws_sockaddr46 sa46;

			buf[len] = '\0';
			lwsl_notice("%s: extip client: reported IP change to %s\n", __func__, buf + 1);
			
			memset(&sa46, 0, sizeof(sa46));
			lws_sa46_parse_numeric_address(buf + 1, &sa46);
			
			vhd->ip[is_v6].has_cookie	= 0;
			vhd->ip[is_v6].last_rx		= lws_now_usecs();
			vhd->ip[is_v6].offline		= 0;

			lws_extip_report(vhd->context, LWS_EXTIP_SRC_EXTIP, &sa46, sa46.sa4.sin_family == AF_INET ? AF_INET : AF_INET6, 1, NULL, 0);

			lws_sul_schedule(vhd->context, 0, &vhd->sul, extip_client_sul_cb, 1);
		}
		break;
	}
	default:
		break;
	}
	return 0;
}

#define LWS_PLUGIN_PROTOCOL_EXTIP \
	{ \
		"protocol-lws-extip", \
		callback_extip, \
		0, \
		1024, 0, NULL, 0 \
	}

#if !defined (LWS_PLUGIN_STATIC)
LWS_VISIBLE const struct lws_protocols lws_extip_protocols[] = {
	LWS_PLUGIN_PROTOCOL_EXTIP
};

/*
 * The exported lws_plugin_protocol_t struct MUST be named EXACTLY the same as
 * your plugin's shared object suffix (after removing 'libprotocol_').
 * lwsws uses this exact string directly in its dlsym() lookup on startup.
 */
LWS_VISIBLE const lws_plugin_protocol_t lws_extip = {
	.hdr = {
		.name		= "lws extip",
		._class		= "lws_protocol_plugin",
		.lws_build_hash = LWS_BUILD_HASH,
		.api_magic	= LWS_PLUGIN_API_MAGIC
	},
	.protocols		= lws_extip_protocols,
	.count_protocols	= LWS_ARRAY_SIZE(lws_extip_protocols),
};
#endif
