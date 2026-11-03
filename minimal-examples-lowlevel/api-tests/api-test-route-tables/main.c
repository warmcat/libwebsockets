/*
 * lws-api-test-route-tables
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws keeps one routing table, from the route messages the kernel sends it
 * over netlink, about the routes in all of the kernel's tables.  With policy
 * routing, eg, "ip rule from <addr> lookup 107", another table can hold a copy
 * of the main table's routes for an interface.
 *
 * lws used to take no notice of which table a route was in, and a route the
 * kernel deleted took with it every route on the same interface whose network
 * was as long or longer, whatever its address.  So flushing table 107 deleted
 * the main table's routes too, and the local table's route to the host's own
 * address on that interface: then lws saw connections from that address as
 * unroutable and closed them.  Refilling the table replaced the main table's
 * routes with its copies, closing the connections using those as well.
 *
 * Once netlink has given the context the host's routes, for each case this
 * empties the context's table, gives it the case's route messages the way the
 * kernel would send them, and checks which routes it holds after each one.
 *
 * Linux only: netlink is where the routing table comes from.
 */

#include <libwebsockets.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define RT_IF		1000	/* the interface index the routes are on */
#define RT_SLOTS	4

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout;
static int fails = 1;

typedef enum {
	RT_NEW,		/* the kernel says it added the route */
	RT_REPLACE,	/* the kernel says the route replaced one */
	RT_DEL,		/* the kernel says it deleted the route */
	RT_HAS,		/* the table must hold the route */
	RT_HASNT,	/* the table must not hold the route */
	RT_NOTE,	/* remember the route's uidx in slot */
	RT_KEPT,	/* the table must hold the route with the uidx in slot */
} rt_op_t;

typedef struct {
	rt_op_t		op;
	uint32_t	table;
	uint8_t		type;		/* RTN_UNICAST or RTN_LOCAL */
	const char	*dst;
	uint8_t		dst_len;
	const char	*gw;		/* NULL: none */
	const char	*prefsrc;	/* NULL: none */
	int		priority;	/* -1: none, like the kernel's metric 0 */
	int		slot;		/* for RT_NOTE and RT_KEPT */
	int		oif;		/* 0: RT_IF */
} rt_step_t;

typedef struct {
	const char		*what;
	const rt_step_t		*steps;
} rt_case_t;

/* the kernel's routes for an address 192.168.81.5/24 with a gateway at .1 */

#define NET(_op, _t, _slot) \
	{ _op, _t, RTN_UNICAST, "192.168.81.0", 24, NULL, "192.168.81.5", -1, \
	  _slot, 0 }
#define DEFRT(_op, _t, _slot) \
	{ _op, _t, RTN_UNICAST, "0.0.0.0", 0, "192.168.81.1", NULL, 100, \
	  _slot, 0 }
#define LOCAL(_op, _slot) \
	{ _op, RT_TABLE_LOCAL, RTN_LOCAL, "192.168.81.5", 32, NULL, \
	  "192.168.81.5", -1, _slot, 0 }

static const rt_step_t
	policy_table_flushed[] = {
		NET(RT_NEW, RT_TABLE_MAIN, 0),
		DEFRT(RT_NEW, RT_TABLE_MAIN, 0),
		LOCAL(RT_NEW, 0),
		NET(RT_NOTE, RT_TABLE_MAIN, 0),
		DEFRT(RT_NOTE, RT_TABLE_MAIN, 1),
		LOCAL(RT_NOTE, 2),

		/* table 107 is filled with a copy of main's routes */
		NET(RT_NEW, 107, 0),
		DEFRT(RT_NEW, 107, 0),
		NET(RT_HAS, 107, 0),
		DEFRT(RT_HAS, 107, 0),
		NET(RT_KEPT, RT_TABLE_MAIN, 0),
		DEFRT(RT_KEPT, RT_TABLE_MAIN, 1),
		LOCAL(RT_KEPT, 2),

		/* ... flushed ... */
		NET(RT_DEL, 107, 0),
		DEFRT(RT_DEL, 107, 0),
		NET(RT_HASNT, 107, 0),
		DEFRT(RT_HASNT, 107, 0),
		NET(RT_KEPT, RT_TABLE_MAIN, 0),
		DEFRT(RT_KEPT, RT_TABLE_MAIN, 1),
		LOCAL(RT_KEPT, 2),

		/* ... and refilled */
		NET(RT_NEW, 107, 0),
		DEFRT(RT_NEW, 107, 0),
		NET(RT_HAS, 107, 0),
		DEFRT(RT_HAS, 107, 0),
		NET(RT_KEPT, RT_TABLE_MAIN, 0),
		DEFRT(RT_KEPT, RT_TABLE_MAIN, 1),
		LOCAL(RT_KEPT, 2),

		/* main's own routes can still be deleted */
		DEFRT(RT_DEL, RT_TABLE_MAIN, 0),
		DEFRT(RT_HASNT, RT_TABLE_MAIN, 0),
		DEFRT(RT_HAS, 107, 0),
		NET(RT_KEPT, RT_TABLE_MAIN, 0),
		LOCAL(RT_KEPT, 2),
		{ .op = RT_NEW, .dst = NULL }
	}, high_table_flushed[] = {
		/* ids over 255 come as RT_TABLE_COMPAT, with RTA_TABLE */
		NET(RT_NEW, RT_TABLE_MAIN, 0),
		LOCAL(RT_NEW, 0),
		NET(RT_NOTE, RT_TABLE_MAIN, 0),
		LOCAL(RT_NOTE, 1),
		NET(RT_NEW, 1000, 0),
		NET(RT_HAS, 1000, 0),
		NET(RT_HASNT, RT_TABLE_COMPAT, 0),
		NET(RT_DEL, 1000, 0),
		NET(RT_HASNT, 1000, 0),
		NET(RT_KEPT, RT_TABLE_MAIN, 0),
		LOCAL(RT_KEPT, 1),
		{ .op = RT_NEW, .dst = NULL }
	}, shorter_net_deleted[] = {
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 16, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_NEW,  RT_TABLE_LOCAL, RTN_LOCAL, "10.0.0.5", 32, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_NOTE, RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 16, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_NOTE, RT_TABLE_LOCAL, RTN_LOCAL, "10.0.0.5", 32, NULL,
			   "10.0.0.5", -1, 1, 0 },
		/* the same address, a shorter network, isn't a dupe */
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 8, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 8, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 16, NULL,
			   "10.0.0.5", -1, 0, 0 },
		/* ... and deleting it takes nothing else */
		{ RT_DEL,  RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 8, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_HASNT, RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 8, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "10.0.0.0", 16, NULL,
			   "10.0.0.5", -1, 0, 0 },
		{ RT_KEPT, RT_TABLE_LOCAL, RTN_LOCAL, "10.0.0.5", 32, NULL,
			   "10.0.0.5", -1, 1, 0 },
		{ .op = RT_NEW, .dst = NULL }
	}, gateway_routes[] = {
		/* the same network, once on the link and once via a gateway */
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   NULL, "198.51.100.5", -1, 0, 0 },
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   "192.0.2.1", NULL, -1, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   NULL, "198.51.100.5", -1, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   "192.0.2.1", NULL, -1, 0, 0 },
		/* deleting the one on the link leaves the one via a gateway */
		{ RT_DEL,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   NULL, "198.51.100.5", -1, 0, 0 },
		{ RT_HASNT, RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   NULL, "198.51.100.5", -1, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "198.51.100.0", 24,
			   "192.0.2.1", NULL, -1, 0, 0 },
		{ .op = RT_NEW, .dst = NULL }
	}, route_replaced[] = {
		/* "ip route replace" comes as a NEWROUTE alone */
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 200, 0, 0 },
		{ RT_NOTE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 200, 0, 0 },
		{ RT_REPLACE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.2", NULL, 100, 0, 0 },
		{ RT_HASNT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.2", NULL, 100, 0, 0 },
		/* ... onto another interface */
		{ RT_REPLACE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.3", NULL, 100, 0, RT_IF + 1 },
		{ RT_HASNT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.2", NULL, 100, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.3", NULL, 100, 0, RT_IF + 1 },
		/* the route with another priority is another route */
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 200, 0, 0 },
		{ .op = RT_NEW, .dst = NULL }
	}, announced_again[] = {
		/* eg, a DHCP client renewing its lease */
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "192.0.2.0", 24,
			   NULL, "192.0.2.5", -1, 0, 0 },
		{ RT_NOTE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_NOTE, RT_TABLE_MAIN, RTN_UNICAST, "192.0.2.0", 24,
			   NULL, "192.0.2.5", -1, 1, 0 },
		{ RT_REPLACE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_REPLACE, RT_TABLE_MAIN, RTN_UNICAST, "192.0.2.0", 24,
			   NULL, "192.0.2.5", -1, 0, 0 },
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "192.0.2.0", 24,
			   NULL, "192.0.2.5", -1, 1, 0 },
		{ .op = RT_NEW, .dst = NULL }
	}, priority_changed[] = {
		/* "ip route" adds the route with the new metric, deletes the old */
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_NEW,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 600, 0, 0 },
		{ RT_HAS,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_NOTE, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 600, 0, 0 },
		{ RT_DEL,  RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_HASNT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 100, 0, 0 },
		{ RT_KEPT, RT_TABLE_MAIN, RTN_UNICAST, "0.0.0.0", 0,
			   "192.0.2.1", NULL, 600, 0, 0 },
		{ .op = RT_NEW, .dst = NULL }
	};

static const rt_case_t cases[] = {
	{ "a policy table holding a copy of main's routes, flushed and refilled",
	  policy_table_flushed },
	{ "a policy table with an id over 255, flushed",
	  high_table_flushed },
	{ "a shorter network on the same address, added and deleted",
	  shorter_net_deleted },
	{ "a network on the link and via a gateway",
	  gateway_routes },
	{ "a default route replaced",
	  route_replaced },
	{ "the same routes announced again",
	  announced_again },
	{ "a route's priority changed",
	  priority_changed },
};

static void
routes_clear(lws_dll2_owner_t *rt)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(rt)) {
		lws_route_t *r = lws_container_of(d, lws_route_t, list);

		lws_dll2_remove(&r->list);
		lws_realloc(r, 0, "free");
	} lws_end_foreach_dll_safe(d, d1);
}

static int
rta_add(uint8_t *msg, size_t max, uint16_t type, const void *data,
	size_t len)
{
	struct nlmsghdr *h = (struct nlmsghdr *)msg;
	struct rtattr *ra = (struct rtattr *)(msg + NLMSG_ALIGN(h->nlmsg_len));

	if (NLMSG_ALIGN(h->nlmsg_len) + RTA_SPACE(len) > max)
		return 1;

	ra->rta_type = type;
	ra->rta_len = (unsigned short)RTA_LENGTH(len);
	memcpy(RTA_DATA(ra), data, len);
	h->nlmsg_len = (uint32_t)(NLMSG_ALIGN(h->nlmsg_len) + RTA_SPACE(len));

	return 0;
}

static int
rta_add_ads(uint8_t *msg, size_t max, uint16_t type, const char *ads)
{
	uint8_t a[16];
	int n = lws_parse_numeric_address(ads, a, sizeof(a));

	if (n != 4)
		return 1;

	return rta_add(msg, max, type, a, (size_t)n);
}

/* the route message the kernel sends when it adds or deletes the route */

static int
route_msg(const rt_step_t *st)
{
	uint32_t m[128]; /* aligned for the nlmsghdr */
	uint8_t *msg = (uint8_t *)m;
	struct nlmsghdr *h = (struct nlmsghdr *)msg;
	struct rtmsg *rm = NLMSG_DATA(h);
	uint32_t u = (uint32_t)(st->oif ? st->oif : RT_IF);

	memset(m, 0, sizeof(m));
	h->nlmsg_len = NLMSG_LENGTH(sizeof(*rm));
	switch (st->op) {
	case RT_NEW:
		h->nlmsg_type = RTM_NEWROUTE;
		h->nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
		break;
	case RT_REPLACE:
		h->nlmsg_type = RTM_NEWROUTE;
		h->nlmsg_flags = NLM_F_REPLACE;
		break;
	default:
		h->nlmsg_type = RTM_DELROUTE;
		break;
	}

	rm->rtm_family = AF_INET;
	rm->rtm_dst_len = st->dst_len;
	rm->rtm_table = (uint8_t)(st->table > 255 ? RT_TABLE_COMPAT :
						    st->table);
	rm->rtm_protocol = RTPROT_KERNEL;
	rm->rtm_scope = st->type == RTN_LOCAL ? RT_SCOPE_HOST :
			(st->gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK);
	rm->rtm_type = st->type;

	if (rta_add(msg, sizeof(m), RTA_TABLE, &st->table, sizeof(st->table)) ||
	    /* like the kernel, a default route has no RTA_DST */
	    (st->dst_len && rta_add_ads(msg, sizeof(m), RTA_DST, st->dst)) ||
	    (st->prefsrc &&
	     rta_add_ads(msg, sizeof(m), RTA_PREFSRC, st->prefsrc)) ||
	    (st->gw && rta_add_ads(msg, sizeof(m), RTA_GATEWAY, st->gw)) ||
	    rta_add(msg, sizeof(m), RTA_OIF, &u, sizeof(u)))
		return 1;

	if (st->priority >= 0) {
		u = (uint32_t)st->priority;
		if (rta_add(msg, sizeof(m), RTA_PRIORITY, &u, sizeof(u)))
			return 1;
	}

	return lws_netlink_inject(context, msg, h->nlmsg_len);
}

static lws_route_t *
route_find(const rt_step_t *st)
{
	lws_sockaddr46 dst, gw;

	memset(&gw, 0, sizeof(gw));
	if (lws_sa46_parse_numeric_address(st->dst, &dst) ||
	    (st->gw && lws_sa46_parse_numeric_address(st->gw, &gw)))
		return NULL;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			lws_dll2_get_head(lws_routing_table_get(context))) {
		lws_route_t *r = lws_container_of(d, lws_route_t, list);

		if (r->table == st->table && r->dest_len == st->dst_len &&
		    !lws_sa46_compare_ads(&r->dest, &dst) &&
		    !r->gateway.sa4.sin_family == !st->gw &&
		    (!st->gw || !lws_sa46_compare_ads(&r->gateway, &gw)) &&
		    r->if_idx == (st->oif ? st->oif : RT_IF) &&
		    r->priority == st->priority)
			return r;
	} lws_end_foreach_dll(d);

	return NULL;
}

static int
try_case(const rt_case_t *c)
{
	lws_route_uidx_t noted[RT_SLOTS];
	const rt_step_t *st;
	lws_route_t *r;
	int n = 0;

	routes_clear(lws_routing_table_get(context));
	memset(noted, 0, sizeof(noted));

	for (st = c->steps; st->dst; st++, n++) {
		if (st->slot < 0 || st->slot >= RT_SLOTS)
			goto bail;

		switch (st->op) {
		case RT_NEW:
		case RT_REPLACE:
		case RT_DEL:
			if (route_msg(st))
				goto bail;
			continue;
		default:
			break;
		}

		r = route_find(st);

		switch (st->op) {
		case RT_HAS:
			if (!r)
				goto bail;
			break;
		case RT_HASNT:
			if (r)
				goto bail;
			break;
		case RT_NOTE:
			if (!r)
				goto bail;
			noted[st->slot] = r->uidx;
			break;
		case RT_KEPT:
			if (!r || r->uidx != noted[st->slot])
				goto bail;
			break;
		default:
			break;
		}
	}

	lwsl_user("%s: ok: %s\n", __func__, c->what);

	return 0;

bail:
	lwsl_err("%s: FAIL: %s: step %d (%s table %u %s/%u)\n", __func__,
		 c->what, n, st->op == RT_HAS ? "has" :
			     st->op == RT_HASNT ? "hasn't" :
			     st->op == RT_KEPT ? "kept" : "message",
		 (unsigned int)st->table, st->dst, st->dst_len);

	return 1;
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		 int current, int target)
{
	size_t n;

	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* netlink has delivered the host's routes by now */

	fails = 0;
	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++)
		fails += try_case(&cases[n]);

	lws_default_loop_exit(context);

	return 0;
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: FAIL: never became operational\n", __func__);
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
					     system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: routes in several routing tables\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.register_notifier_list = na;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb,
			 10 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
