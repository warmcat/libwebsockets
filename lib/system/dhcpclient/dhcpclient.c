 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"
#include "private-lib-system-dhcpclient.h"

typedef enum {
	LDHC_INIT_REBOOT,
	LDHC_REBOOTING,		/* jitterwait */
	LDHC_INIT,		/* issue DHCPDISCOVER */
	LDHC_SELECTING,
	LDHC_REQUESTING,
	LDHC_REBINDING,
	LDHC_BOUND,
	LDHC_RENEWING
} lws_dhcpc_state_t;

enum {
	LWSDHCPDISCOVER			= 1,
	LWSDHCPOFFER,
	LWSDHCPREQUEST,
	LWSDHCPDECLINE,
	LWSDHCPACK,
	LWSDHCPNACK,
	LWSDHCPRELEASE,

	IPV4_PROPOSED			= 0,
	IPV4_SERVER,
	IPV4_ROUTER,
	IPV4_SUBNET_MASK,
	IPV4_BROADCAST,
	IPV4_TIME_SERVER,
	IPV4_DNS_SRV_1,
	IPV4_DNS_SRV_2,
	IPV4_DNS_SRV_3,
	IPV4_DNS_SRV_4,
	IPV4_LEASE_SECS,
	IPV4_REBINDING_SECS,
	IPV4_RENEWAL_SECS,

	_IPV4_COUNT,

	LWSDHCPOPT_PAD			= 0,
	LWSDHCPOPT_SUBNET_MASK		= 1,
	LWSDHCPOPT_TIME_OFFSET		= 2,
	LWSDHCPOPT_ROUTER		= 3,
	LWSDHCPOPT_TIME_SERVER		= 4,
	LWSDHCPOPT_NAME_SERVER		= 5,
	LWSDHCPOPT_DNSERVER		= 6,
	LWSDHCPOPT_LOG_SERVER		= 7,
	LWSDHCPOPT_COOKIE_SERVER	= 8,
	LWSDHCPOPT_LPR_SERVER		= 9,
	LWSDHCPOPT_IMPRESS_SERVER	= 10,
	LWSDHCPOPT_RESLOC_SERVER	= 11,
	LWSDHCPOPT_HOST_NAME		= 12,
	LWSDHCPOPT_BOOTFILE_SIZE	= 13,
	LWSDHCPOPT_MERIT_DUMP_FILE	= 14,
	LWSDHCPOPT_DOMAIN_NAME		= 15,
	LWSDHCPOPT_SWAP_SERVER		= 16,
	LWSDHCPOPT_ROOT_PATH		= 17,
	LWSDHCPOPT_EXTENSIONS_PATH	= 18,
	LWSDHCPOPT_BROADCAST_ADS	= 28,

	LWSDHCPOPT_REQUESTED_ADS	= 50,
	LWSDHCPOPT_LEASE_TIME		= 51,
	LWSDHCPOPT_OPTION_OVERLOAD	= 52,
	LWSDHCPOPT_MESSAGE_TYPE		= 53,
	LWSDHCPOPT_SERVER_ID		= 54,
	LWSDHCPOPT_PARAM_REQ_LIST	= 55,
	LWSDHCPOPT_MESSAGE		= 56,
	LWSDHCPOPT_MAX_DHCP_MSG_SIZE	= 57,
	LWSDHCPOPT_RENEWAL_TIME		= 58, /* AKA T1 */
	LWSDHCPOPT_REBINDING_TIME	= 59, /* AKA T2 */
	LWSDHCPOPT_VENDOR_CLASS_ID	= 60,
	LWSDHCPOPT_CLIENT_ID		= 61,

	LWSDHCPOPT_END_OPTIONS		= 255
};

typedef struct lws_dhcpc_req {
	lws_dll2_t		list;
	char			domain[64];
	struct lws_context	*context;
	lws_sorted_usec_list_t 	sul_conn;
	lws_sorted_usec_list_t 	sul_write;
	dhcpc_cb_t		cb;	    /* cb on completion / failure */
	void			*opaque;    /* ignored by lws, give to cb */

	/* these are separated so we can close the bcast one asynchronously */
	struct lws		*wsi_raw;   /* for broadcast */
	lws_dhcpc_state_t	state;

	uint32_t		ipv4[_IPV4_COUNT];

	uint16_t		retry_count_conn;
	uint16_t		retry_count_write;
	uint8_t			mac[6];
	uint8_t			xid[4];
	uint8_t			af;	    /* address family */
} lws_dhcpc_req_t;
/* interface name is overallocated here */

static const uint32_t botable2[] = { 1500, 1750, 5000 /* in case dog slow */ };
static const lws_retry_bo_t bo2 = {
	botable2, LWS_ARRAY_SIZE(botable2), LWS_RETRY_CONCEAL_ALWAYS, 0, 0, 20 };

static const uint8_t rawdisc[] = {
	0x45, 0x00, 0, 0, 0, 0, 0x40, 0, 0x2e, IPPROTO_UDP,
	0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,
	0, 68, 0, 67, 0, 0, 0, 0
};

#define LDHC_OP_BOOTREQUEST 1
#define LDHC_OP_BOOTREPLY 2

/*
 *  IPv4... max total 576
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 * +---------------+---------------+---------------+---------------+
 * |  +04                       xid (4)                            |
 * +-------------------------------+-------------------------------+
 * |  +08      secs (2)            |  +0a         flags (2)        |
 * +-------------------------------+-------------------------------+
 * |  +0C                     ciaddr  (4)      client IP           |
 * +---------------------------------------------------------------+
 * |  +10                     yiaddr  (4)      your IP             |
 * +---------------------------------------------------------------+
 * |  +14                     siaddr  (4)      server IP           |
 * +---------------------------------------------------------------+
 * |  +18                     giaddr  (4)      gateway IP          |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |  +1C                     chaddr  (16)     client HWADDR       |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |  +2C                     sname   (64)                         |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |  +6C                     file    (128)                        |
 * +---------------------------------------------------------------+
 * |                                                               |
 * |  +EC                     options (variable)                   |
 * +---------------------------------------------------------------+
 */

#if defined(_DEBUG)
static const char *dhcp_entry_names[] = {
	"proposed ip",
	"dhcp server",
	"router",
	"subnet mask",
	"broadcast",
	"time server",
	"dns1",
	"dns2",
	"dns3",
	"dns4",
	"lease secs",
	"rebinding secs",
	"renewal secs",
};
#endif

static void
lws_dhcpc_retry_conn(struct lws_sorted_usec_list *sul)
{
	lws_dhcpc_req_t *r = lws_container_of(sul, lws_dhcpc_req_t, sul_conn);

	if (r->wsi_raw || !lws_dll2_is_detached(&r->sul_conn.list))
		return;

	/* create the UDP socket aimed at the server */

	r->retry_count_write = 0;
	r->wsi_raw = lws_create_adopt_udp(r->context->vhost_system, "0.0.0.0",
					  68, LWS_CAUDP_PF_PACKET |
					      LWS_CAUDP_BROADCAST,
					  "lws-dhcpclient", (const char *)&r[1],
					  NULL, NULL, &bo2);
	lwsl_debug("%s: created wsi_raw: %p\n", __func__, r->wsi_raw);
	if (!r->wsi_raw) {
		lwsl_err("%s: unable to create udp skt\n", __func__);

		lws_retry_sul_schedule(r->context, 0, &r->sul_conn, &bo2,
				       lws_dhcpc_retry_conn,
				       &r->retry_count_conn);

		return;
	}

	/* force the network if up */
	lws_plat_if_up((const char *)&r[1], r->wsi_raw->desc.sockfd, 0);
	lws_plat_if_up((const char *)&r[1], r->wsi_raw->desc.sockfd, 1);

	r->wsi_raw->user_space = r;
	r->wsi_raw->user_space_externally_allocated = 1;

	lws_get_random(r->wsi_raw->a.context, r->xid, 4);
}

static void
lws_dhcpc_retry_write(struct lws_sorted_usec_list *sul)
{
	lws_dhcpc_req_t *r = lws_container_of(sul, lws_dhcpc_req_t, sul_write);

	lwsl_debug("%s\n", __func__);

	if (r && r->wsi_raw)
		lws_callback_on_writable(r->wsi_raw);
}

static int
lws_dhcpc_prep(uint8_t *start, int bufsiz, lws_dhcpc_req_t *r, int op)
{
	uint8_t *p = start;

	memset(start, 0, bufsiz);

	*p++ = 1;
	*p++ = 1;
	*p++ = 6; /* sizeof ethernet MAC */

	memcpy(p + 1, r->xid, 4);

//	p[7] = 0x80; /* broadcast flag */

	p += 0x1c - 3;

	if (lws_plat_ifname_to_hwaddr(r->wsi_raw->desc.sockfd,
				      (const char *)&r[1], r->mac, 6) < 0)
		return -1;

	memcpy(p, r->mac, 6);

	p += 16 + 64 + 128;

	*p++ = 0x63; /* RFC2132 Magic Cookie indicates start of options */
	*p++ = 0x82;
	*p++ = 0x53;
	*p++ = 0x63;

	*p++ = LWSDHCPOPT_MESSAGE_TYPE;
	*p++ = 1;	/* length */
	*p++ = op;

	switch (op) {
	case LWSDHCPDISCOVER:
		*p++ = LWSDHCPOPT_PARAM_REQ_LIST;
		*p++ = 4; 	/* length */
		*p++ = 1;	/* subnet mask */
		*p++ = 3;	/* router */
		*p++ = 15;	/* domain name */
		*p++ = 6;	/* DNServer */
		break;
	case LWSDHCPREQUEST:
		*p++ = LWSDHCPOPT_REQUESTED_ADS;
		*p++ = 4; 	/* length */
		lws_ser_wu32be(p, r->ipv4[IPV4_PROPOSED]);
		p += 4;
		*p++ = LWSDHCPOPT_SERVER_ID;
		*p++ = 4; 	/* length */
		lws_ser_wu32be(p, r->ipv4[IPV4_SERVER]);
		p += 4;
		break;
	}

	*p++ = LWSDHCPOPT_END_OPTIONS;

	return lws_ptr_diff(p, start);
}

static int
callback_dhcpc(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	lws_dhcpc_req_t *r = (lws_dhcpc_req_t *)user;
	uint8_t pkt[LWS_PRE + 576], *p = pkt + LWS_PRE, *end;
	int n, m;

	switch (reason) {

        case LWS_CALLBACK_RAW_ADOPT:
		lwsl_debug("%s: LWS_CALLBACK_RAW_ADOPT\n", __func__);
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: udp conn failed\n", __func__);

		/* fallthru */
	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_debug("%s: LWS_CALLBACK_RAW_CLOSE\n", __func__);
		if (!r)
			break;
		r->wsi_raw = NULL;
		lws_sul_cancel(&r->sul_write);
		if (r->state != LDHC_BOUND) {
			r->state = LDHC_INIT;
			lws_retry_sul_schedule(r->context, 0, &r->sul_conn,
					       &bo2, lws_dhcpc_retry_conn,
					       &r->retry_count_conn);
		}
		break;

	case LWS_CALLBACK_RAW_RX:

		switch (r->state) {
		case LDHC_INIT:		/* expect DHCPOFFER */
		case LDHC_REQUESTING:	/* expect DHCPACK */
			/*
			 * We should check carefully if we like what we were
			 * sent... anything can spam us with crafted replies
			 */
			if (len < 0x100)
				break;

			p = (uint8_t *)in + 28; /* skip to UDP payload */
			if (p[0] != 2 || p[1] != 1 || p[2] != 6)
				break;

			if (memcmp(&p[4], r->xid, 4))	/* must be our xid */
				break;

			if (memcmp(&p[0x1c], r->mac, 6)) /* our netif mac? */
				break;

			/* the DHCP magic cookie must be in place */
			if (lws_ser_ru32be(&p[0xec]) != 0x63825363)
				break;

			r->ipv4[IPV4_PROPOSED] = lws_ser_ru32be(&p[0x10]);
			r->ipv4[IPV4_SERVER] = lws_ser_ru32be(&p[0x14]);

			/* it looks legit so far... look at the options */

			end = (uint8_t *)in + len;
			p += 0xec + 4;
			while (p < end) {
				uint8_t c = *p++;
				uint8_t l = 0;

				if (c && c != 0xff) {
					/* pad 0 and EOT 0xff have no length */
					l = *p++;
					if (!l) {
						lwsl_err("%s: zero length\n",
								__func__);
						goto broken;
					}
					if (p + l > end) {
						/* ...nice try... */
						lwsl_err("%s: bad len\n",
								__func__);
						goto broken;
					}
				}

				if (c == 0xff) /* end of options */
					break;

				m = 0;
				switch (c) {
				case LWSDHCPOPT_SUBNET_MASK:
					n = IPV4_SUBNET_MASK;
					goto get_ipv4;

				case LWSDHCPOPT_ROUTER:
					n = IPV4_ROUTER;
					goto get_ipv4;

				case LWSDHCPOPT_TIME_SERVER:
					n = IPV4_TIME_SERVER;
					goto get_ipv4;

				case LWSDHCPOPT_BROADCAST_ADS:
					n = IPV4_BROADCAST;
					goto get_ipv4;

				case LWSDHCPOPT_LEASE_TIME:
					n = IPV4_LEASE_SECS;
					goto get_ipv4;

				case LWSDHCPOPT_RENEWAL_TIME: /* AKA T1 */
					n = IPV4_RENEWAL_SECS;
					goto get_ipv4;

				case LWSDHCPOPT_REBINDING_TIME: /* AKA T2 */
					n = IPV4_REBINDING_SECS;
					goto get_ipv4;

				case LWSDHCPOPT_DNSERVER:
					if (l & 3)
						break;
					m = IPV4_DNS_SRV_1;
					while (l && m - IPV4_DNS_SRV_1 < 4) {
						r->ipv4[m++] = lws_ser_ru32be(p);
						l -= 4;
						p += 4;
					}
					break;
				case LWSDHCPOPT_DOMAIN_NAME:
					m = l;
					if (m > (int)sizeof(r->domain) - 1)
						m = sizeof(r->domain) - 1;
					memcpy(r->domain, p, m);
					r->domain[m] = '\0';
					break;

				case LWSDHCPOPT_MESSAGE_TYPE:
					/*
					 * Confirm this is the right message
					 * for the state of the negotiation
					 */
					if (r->state == LDHC_INIT &&
					    *p != LWSDHCPOFFER)
						goto broken;
					if (r->state == LDHC_REQUESTING &&
					    *p != LWSDHCPACK)
						goto broken;
					break;

				default:
					break;
				}

				p += l;
				continue;
get_ipv4:
				if (l >= 4)
					r->ipv4[n] = lws_ser_ru32be(p);
				p += l;
				continue;
broken:
				memset(r->ipv4, 0, sizeof(r->ipv4));
				break;
			}

#if defined(_DEBUG)
			/* dump what we have parsed out */

			for (n = 0; n < (int)LWS_ARRAY_SIZE(dhcp_entry_names);
									    n++)
				if (n >= IPV4_LEASE_SECS)
					lwsl_info("%s: %s: %ds\n", __func__,
						    dhcp_entry_names[n],
						    r->ipv4[n]);
				else {
					m = ntohl(r->ipv4[n]);
					lws_write_numeric_address((uint8_t *)&m,
							     4,(char *)pkt, 20);
					lwsl_info("%s: %s: %s\n", __func__,
							dhcp_entry_names[n],
							pkt);
				}
#endif

			/*
			 * Having seen everything in there... do we really feel
			 * we could use it?  Everything critical is there?
			 */

			if (!r->ipv4[IPV4_PROPOSED] ||
			    !r->ipv4[IPV4_SERVER] ||
			    !r->ipv4[IPV4_ROUTER] ||
			    !r->ipv4[IPV4_SUBNET_MASK] ||
			    !r->ipv4[IPV4_LEASE_SECS] ||
			    !r->ipv4[IPV4_DNS_SRV_1]) {
				memset(r->ipv4, 0, sizeof(r->ipv4));
				break;
			}

			/*
			 * Network layout has to be internally consistent...
			 * DHCP server has to be reachable by broadcast and
			 * default route has to be on same subnet
			 */

			if ((r->ipv4[IPV4_PROPOSED] & r->ipv4[IPV4_SUBNET_MASK]) !=
			    (r->ipv4[IPV4_SERVER] & r->ipv4[IPV4_SUBNET_MASK]))
				break;

			if ((r->ipv4[IPV4_PROPOSED] & r->ipv4[IPV4_SUBNET_MASK]) !=
			    (r->ipv4[IPV4_ROUTER] & r->ipv4[IPV4_SUBNET_MASK]))
				break;

			if (r->state == LDHC_INIT) {
				lwsl_info("%s: moving to REQ\n", __func__);
				r->state = LDHC_REQUESTING;
				lws_callback_on_writable(r->wsi_raw);
				break;
			}

			/*
			 * that's it... commit to the configuration
			 */

			/* set up our network interface as offered */

			if (lws_plat_ifconfig_ip((const char *)&r[1],
						 r->wsi_raw->desc.sockfd,
					(uint8_t *)&r->ipv4[IPV4_PROPOSED],
					(uint8_t *)&r->ipv4[IPV4_SUBNET_MASK],
					(uint8_t *)&r->ipv4[IPV4_ROUTER])) {
				/*
				 * Problem setting the IP... maybe something
				 * transient like racing with NetworkManager?
				 * Since the sul retries are still around it
				 * will retry
				 */
				return -1;
			}

			/* clear timeouts related to the broadcast socket */

			lws_sul_cancel(&r->sul_write);
			lws_sul_cancel(&r->sul_conn);

			lwsl_notice("%s: DHCP configured %s\n", __func__,
					(const char *)&r[1]);
			r->state = LDHC_BOUND;

			lws_state_transition_steps(&wsi->a.context->mgr_system,
						   LWS_SYSTATE_OPERATIONAL);

			r->cb(r->opaque, r->af,
					(uint8_t *)&r->ipv4[IPV4_PROPOSED], 4);

			r->wsi_raw = NULL;
			return -1; /* close the broadcast wsi */
		default:
			break;
		}

		break;

	case LWS_CALLBACK_RAW_WRITEABLE:

		if (!r)
			break;

		/*
		 * UDP is not reliable, it can be locally dropped, or dropped
		 * by any intermediary or the remote peer.  So even though we
		 * will do the write in a moment, we schedule another request
		 * for rewrite according to the wsi retry policy.
		 *
		 * If the result came before, we'll cancel it in the close flow.
		 *
		 * If we have already reached the end of our concealed retries
		 * in the policy, just close without another write.
		 */
		if (lws_dll2_is_detached(&r->sul_write.list) &&
		    lws_retry_sul_schedule_retry_wsi(wsi, &r->sul_write,
						     lws_dhcpc_retry_write,
						     &r->retry_count_write)) {
			/* we have reached the end of our concealed retries */
			lwsl_warn("%s: concealed retries done, failing\n",
				  __func__);
			goto retry_conn;
		}

		switch (r->state) {
		case LDHC_INIT:
			n = LWSDHCPDISCOVER;
			goto bcast;

		case LDHC_REQUESTING:
			n = LWSDHCPREQUEST;

			/* fallthru */
bcast:
			n = lws_dhcpc_prep(p + 28, sizeof(pkt) - LWS_PRE - 28,
					   r, n);
			if (n < 0) {
				lwsl_err("%s: failed to prep\n", __func__);
				break;
			}

			m = lws_plat_rawudp_broadcast(p, rawdisc,
						      LWS_ARRAY_SIZE(rawdisc),
						      n + 28,
						      r->wsi_raw->desc.sockfd,
						      (const char *)&r[1]);
			if (m < 0)
				lwsl_err("%s: Failed to write dhcp client req: "
					 "%d %d, errno %d\n", __func__,
					 n, m, LWS_ERRNO);
			break;
		default:
			break;
		}

		return 0;

retry_conn:
		lws_retry_sul_schedule(wsi->a.context, 0, &r->sul_conn, &bo2,
				       lws_dhcpc_retry_conn,
				       &r->retry_count_conn);

		return -1;

	default:
		break;
	}

	return 0;
}

struct lws_protocols lws_system_protocol_dhcpc =
	{ "lws-dhcpclient", callback_dhcpc, 0, 128, };

static void
lws_dhcpc_destroy(lws_dhcpc_req_t **pr)
{
	lws_dhcpc_req_t *r = *pr;

	lws_sul_cancel(&r->sul_conn);
	lws_sul_cancel(&r->sul_write);
	if (r->wsi_raw)
		lws_set_timeout(r->wsi_raw, 1, LWS_TO_KILL_ASYNC);

	lws_dll2_remove(&r->list);

	lws_free_set_NULL(r);
}

int
lws_dhcpc_status(struct lws_context *context, lws_sockaddr46 *sa46)
{
	lws_dhcpc_req_t *r;

	lws_start_foreach_dll(struct lws_dll2 *, p, context->dhcpc_owner.head) {
		r = (lws_dhcpc_req_t *)p;

		if (r->state == LDHC_BOUND) {
			if (sa46) {
				memset(sa46, 0, sizeof(*sa46));
				sa46->sa4.sin_family = AF_INET;
				sa46->sa4.sin_addr.s_addr =
						r->ipv4[IPV4_DNS_SRV_1];
			}
			return 1;
		}

	} lws_end_foreach_dll(p);

	return 0;
}

static lws_dhcpc_req_t *
lws_dhcpc_find(struct lws_context *context, const char *iface, int af)
{
	lws_dhcpc_req_t *r;

	/* see if we are already looking after this af / iface combination */

	lws_start_foreach_dll(struct lws_dll2 *, p, context->dhcpc_owner.head) {
		r = (lws_dhcpc_req_t *)p;

		if (!strcmp((const char *)&r[1], iface) && af == r->af)
			return r; /* yes...  */

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * Create a persistent dhcp client entry for network interface "iface" and AF
 * type "af"
 */

int
lws_dhcpc_request(struct lws_context *context, const char *iface, int af,
		  dhcpc_cb_t cb, void *opaque)
{
	lws_dhcpc_req_t *r = lws_dhcpc_find(context, iface, af);
	int n;

	/* see if we are already looking after this af / iface combination */

	if (r)
		return 0;

	/* nope... let's create a request object as he asks */

	n = strlen(iface);
	r = lws_zalloc(sizeof(*r) + n + 1, __func__);
	if (!r)
		return 1;

	memcpy(&r[1], iface, n + 1);
	r->af = af;
	r->cb = cb;
	r->opaque = opaque;
	r->context = context;
	r->state = LDHC_INIT;

	lws_dll2_add_head(&r->list, &context->dhcpc_owner); /* add him to list */

	lws_dhcpc_retry_conn(&r->sul_conn);

	return 0;
}

/*
 * Destroy every DHCP client object related to interface "iface"
 */

static int
_remove_if(struct lws_dll2 *d, void *opaque)
{
	lws_dhcpc_req_t *r = lws_container_of(d, lws_dhcpc_req_t, list);

	if (!opaque || !strcmp((const char *)&r[1], (const char *)opaque))
		lws_dhcpc_destroy(&r);

	return 0;
}

int
lws_dhcpc_remove(struct lws_context *context, const char *iface)
{
	lws_dll2_foreach_safe(&context->dhcpc_owner, (void *)iface, _remove_if);

	return 0;
}
