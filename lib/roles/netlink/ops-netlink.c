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
 *
 * We mainly focus on the routing table / gateways because those are the
 * elements that decide if we can get on to the internet or not.
 *
 * We also need to understand the source addresses of possible outgoing routes,
 * and follow LINK down (ifconfig down) to clean up routes on the interface idx
 * going down that are not otherwise cleaned.
 */

#include <private-lib-core.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static void
lws_netlink_coldplug_done_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context *ctx = lws_container_of(sul, struct lws_context,
						   sul_nl_coldplug);
	ctx->nl_initial_done = 1;

	/* if nothing is there to intercept anything, go all the way */
	lws_state_transition_steps(&ctx->mgr_system, LWS_SYSTATE_OPERATIONAL);
}

static int
rops_handle_POLLIN_netlink(struct lws_context_per_thread *pt, struct lws *wsi,
			   struct lws_pollfd *pollfd)
{
	uint8_t s[512]
#if defined(_DEBUG)
	        , route_change = 0
#endif
#if defined(LWS_WITH_SYS_SMD)
		, gateway_change = 0
#endif
			;
	struct sockaddr_nl	nladdr;
	lws_route_t		robj, *rou;
	struct nlmsghdr		*h;
	struct msghdr		msg;
	struct iovec		iov;
	int			n;

	if (!(pollfd->revents & LWS_POLLIN))
		return LWS_HPI_RET_HANDLED;

	if (!pt->context->nl_initial_done && pt == &pt->context->pt[0]) {
		/*
		 * While netlink info still coming, keep moving the timer for
		 * calling it "done" to +100ms until after it stops coming
		 */
		lws_context_lock(pt->context, __func__);
		lws_sul_schedule(pt->context, 0, &pt->context->sul_nl_coldplug,
				 lws_netlink_coldplug_done_cb,
				 100 * LWS_US_PER_MS);
		lws_context_unlock(pt->context);
	}

	memset(&msg, 0, sizeof(msg));

	iov.iov_base		= (void *)s;
	iov.iov_len		= sizeof(s);
	msg.msg_name		= (void *)&(nladdr);
	msg.msg_namelen		= sizeof(nladdr);

	msg.msg_iov		= &iov;
	msg.msg_iovlen		= 1;

	n = recvmsg(wsi->desc.sockfd, &msg, 0);
	if (n < 0)
		return LWS_HPI_RET_PLEASE_CLOSE_ME;

	h = (struct nlmsghdr *)s;

/*
 * On some platforms nlh->nlmsg_len is a uint32_t but len is expected to be
 * an int.  This causes the last comparison to blow with
 *
 * comparison of integers of different signs: '__u32' (aka 'unsigned int') and
 * 'int' [-Werror,-Wsign-compare]
 *
 * rtnetlink messages cannot be huge, solve it by casting nmmsg_len to int
 */

#define LWS_NLMSG_OK(nlh, len) ((len) >= (int) sizeof(struct nlmsghdr) && \
			       (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			       (int)(nlh)->nlmsg_len <= (len))

	for ( ; LWS_NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
		struct ifaddrmsg *ifam;
		struct rtattr *ra;
		struct rtmsg *rm;
		int ra_len;
		uint8_t *p;

		/*
		 * We have to care about NEWLINK so we can understand when a
		 * network interface went down, and clear the related routes.
		 *
		 * We don't get individual DELROUTEs for these.
		 */

		if (h->nlmsg_type == RTM_NEWLINK) {
			struct ifinfomsg *ifi = NLMSG_DATA(h);

			/*
			 * Despite "New"link this is actually telling us there
			 * is some change on the network interface IFF_ state
			 */

			if (!(ifi->ifi_flags & IFF_UP)) {
				/*
				 * Interface is down, so scrub all routes that
				 * applied to it
				 */
				lws_pt_lock(pt, __func__);
				_lws_route_table_ifdown(pt, ifi->ifi_index);
				lws_pt_unlock(pt);
			}
			continue;
		}

		memset(&robj, 0, sizeof(robj));
		robj.if_idx = -1;
		robj.priority = -1;

		rm = (struct rtmsg *)NLMSG_DATA(h);

		if (h->nlmsg_type == RTM_NEWADDR ||
		    h->nlmsg_type == RTM_DELADDR) {
			ifam = (struct ifaddrmsg *)NLMSG_DATA(h);

			robj.source_ads = 1;
			robj.dest_len = ifam->ifa_prefixlen;
			robj.if_idx = ifam->ifa_index;
			robj.scope = ifam->ifa_scope;
			robj.ifa_flags = ifam->ifa_flags;
			robj.dest.sa4.sin_family = ifam->ifa_family;

			/* address attributes */
			ra = (struct rtattr *)IFA_RTA(ifam);
			ra_len = IFA_PAYLOAD(h);
		} else {
			/* route attributes */
			ra = (struct rtattr *)RTM_RTA(rm);
			ra_len = RTM_PAYLOAD(h);
		}

		robj.proto = rm->rtm_protocol;

		for ( ; RTA_OK(ra, ra_len); ra = RTA_NEXT(ra, ra_len)) {
			switch (ra->rta_type) {
			case RTA_DST:
				lws_sa46_copy_address(&robj.dest, RTA_DATA(ra),
							rm->rtm_family);
				robj.dest_len = rm->rtm_dst_len;
				break;
			case RTA_GATEWAY:
				lws_sa46_copy_address(&robj.gateway,
						      RTA_DATA(ra),
						      rm->rtm_family);
#if defined(LWS_WITH_SYS_SMD)
				gateway_change = 1;
#endif
				break;
			case RTA_OIF: /* int: output interface index */
				robj.if_idx = *(char*)RTA_DATA(ra);
				break;
			case RTA_PRIORITY: /* int: priority of route */
				p = RTA_DATA(ra);
				robj.priority = p[3] << 24 | p[2] << 16 |
						 p[1] << 8  | p[0];
				break;
			case RTA_PREFSRC: /* protocol ads: preferred src ads */
				break;
			case RTA_CACHEINFO: /* struct rta_cacheinfo */
				break;
#if defined(LWS_HAVE_RTA_PREF)
			case RTA_PREF: /* char: RFC4191 v6 router preference */
				break;
#endif
			case RTA_TABLE: /* int */
				break;

			default:
				lwsl_info("%s: unknown attr type %d\n",
						__func__, ra->rta_type);
				break;
			}
		}

		switch (h->nlmsg_type) {

		case RTM_DELROUTE:
			/*
			 * This will also take down wsi marked as using it
			 */
			lws_pt_lock(pt, __func__);
			_lws_route_remove(pt, &robj);
			lws_pt_unlock(pt);
			goto inform;

		case RTM_NEWROUTE:

			/*
			 * We don't want any routing debris like /32 or broadcast
			 * in our routing table... we will collect source addresses
			 * bound to interfaces via NEWADDR
			 */

			if (rm->rtm_type != RTN_UNICAST &&
			    rm->rtm_type != RTN_LOCAL)
				break;

			if (rm->rtm_flags & RTM_F_CLONED)
				break;

			/* fallthru */

		case RTM_NEWADDR:
			rou = lws_malloc(sizeof(*rou), __func__);
			if (!rou) {
				lwsl_err("%s: oom\n", __func__);
				return LWS_HPI_RET_HANDLED;
			}

			*rou = robj;

			lws_pt_lock(pt, __func__);

			/*
			 * We lock the pt before getting the uidx, so it
			 * cannot race
			 */

			rou->uidx = _lws_route_get_uidx(pt);
			lws_dll2_add_tail(&rou->list, &pt->routing_table);

			_lws_route_pt_close_unroutable(pt);

			lws_pt_unlock(pt);

inform:
#if defined(_DEBUG)
			route_change = 1;
#endif
#if defined(LWS_WITH_SYS_SMD)
			/*
			 * Reflect the route add / del event using SMD.
			 * Participants interested can refer to the pt
			 * routing table
			 */
			(void)lws_smd_msg_printf(pt->context, LWSSMDCL_NETWORK,
				   "{\"rt\":\"%s\"}\n",
				   (h->nlmsg_type == RTM_DELROUTE) ?
						"del" : "add");
#endif

			break;

		default:
			// lwsl_info("%s: unknown msg type %d\n", __func__,
			//		h->nlmsg_type);
			break;
		}
	}

#if defined(LWS_WITH_SYS_SMD)
	if (gateway_change)
		/*
		 * If a route with a gw was added or deleted, retrigger captive
		 * portal detection if we have that
		 */
		(void)lws_smd_msg_printf(pt->context, LWSSMDCL_NETWORK,
				   "{\"trigger\": \"cpdcheck\", "
				   "\"src\":\"gw-change\"}");
#endif

#if defined(_DEBUG)
	if (route_change) {
		lws_pt_lock(pt, __func__);
		_lws_routing_table_dump(pt);
		lws_pt_unlock(pt);
	}
#endif

	return LWS_HPI_RET_HANDLED;
}

struct nl_req_s {
	struct nlmsghdr hdr;
	struct rtmsg gen;
};

int
rops_pt_init_destroy_netlink(struct lws_context *context,
			     const struct lws_context_creation_info *info,
			     struct lws_context_per_thread *pt, int destroy)
{
	struct sockaddr_nl sanl;
	struct nl_req_s req;
	struct msghdr msg;
	struct iovec iov;
	struct lws *wsi;
	int n;

	if (destroy) {
		/*
		 * pt netlink wsi closed + freed as part of pt's destroy
		 * wsi mass close, just need to take down the routing table
		 */
		_lws_route_table_empty(pt);

		return 0;
	}

	if (pt->netlink)
		return 0;

	lwsl_info("%s: creating netlink skt\n", __func__);

	/*
	 * We want a netlink socket per pt as well
	 */
	wsi = lws_wsi_create_with_role(context, (int)(pt - &context->pt[0]),
				       &role_ops_netlink);
	if (!wsi)
		goto bail;

	wsi->desc.sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (wsi->desc.sockfd == LWS_SOCK_INVALID) {
		lwsl_err("%s: unable to open netlink\n", __func__);
		goto bail1;
	}

	memset(&sanl, 0, sizeof(sanl));
	sanl.nl_family		= AF_NETLINK;
	sanl.nl_pid		= getpid();
	sanl.nl_groups		= RTMGRP_LINK | RTMGRP_IPV4_ROUTE
#if defined(LWS_WITH_IPV6)
				  | RTMGRP_IPV6_ROUTE
#endif
				  ;

	if (bind(wsi->desc.sockfd, (struct sockaddr*)&sanl, sizeof(sanl)) < 0) {
		lwsl_err("%s: netlink bind failed\n", __func__);
		goto bail2;
	}

	pt->netlink = wsi;
	if (lws_wsi_inject_to_loop(pt, wsi))
		goto bail2;

	if (lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
		lwsl_err("%s: pollfd in fail\n", __func__);
		goto bail2;
	}

	/*
	 * Since we're starting the PT, ask to be sent all the existing routes.
	 *
	 * This requires CAP_ADMIN, or root... we do this early before dropping
	 * privs
	 */

	memset(&sanl, 0, sizeof(sanl));
	memset(&msg, 0, sizeof(msg));
	memset(&req, 0, sizeof(req));

	sanl.nl_family		= AF_NETLINK;

	req.hdr.nlmsg_len	= NLMSG_LENGTH(sizeof(req.gen));
	req.hdr.nlmsg_type	= RTM_GETROUTE;
	req.hdr.nlmsg_flags	= NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_seq	= 1;
	req.hdr.nlmsg_pid	= getpid();
	req.gen.rtm_family	= AF_PACKET;
	req.gen.rtm_table	= RT_TABLE_DEFAULT;

	iov.iov_base		= &req;
	iov.iov_len		= req.hdr.nlmsg_len;
	msg.msg_iov		= &iov;
	msg.msg_iovlen		= 1;
	msg.msg_name		= &sanl;
	msg.msg_namelen		= sizeof(sanl);

	n = sendmsg(wsi->desc.sockfd, (struct msghdr *)&msg, 0);
	if (n < 0) {
		lwsl_notice("%s: rt dump req failed... permissions? errno %d\n",
				__func__, LWS_ERRNO);
	}

	/*
	 * Responses are going to come asynchronously, since we can't process
	 * DNS lookups properly until we collected the initial netlink responses
	 * let's set a timer that will let us advance from lws_system
	 * LWS_SYSTATE_IFACE_COLDPLUG
	 */

	lwsl_debug("%s: starting netlink coldplug wait\n", __func__);
	lws_sul_schedule(context, 0, &context->sul_nl_coldplug,
			 lws_netlink_coldplug_done_cb, 450 * LWS_US_PER_MS);

	return 0;

bail2:
	compatible_close(wsi->desc.sockfd);
bail1:
	lws_free(wsi);
bail:
	return 1;
}

static const lws_rops_t rops_table_netlink[] = {
	/*  1 */ { .pt_init_destroy	= rops_pt_init_destroy_netlink },
	/*  2 */ { .handle_POLLIN	= rops_handle_POLLIN_netlink },
};

const struct lws_role_ops role_ops_netlink = {
	/* role name */			"netlink",
	/* alpn id */			NULL,

	/* rops_table */		rops_table_netlink,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x01,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x02,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x00,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00,
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00,
					},

	/* adoption_cb clnt, srv */	{ 0, 0 },
	/* rx_cb clnt, srv */		{ 0, 0 },
	/* writeable cb clnt, srv */	{ 0, 0 },
	/* close cb clnt, srv */	{ 0, 0 },
	/* protocol_bind_cb c,s */	{ 0, 0 },
	/* protocol_unbind_cb c,s */	{ 0, 0 },
	/* file_handle */		0,
};
