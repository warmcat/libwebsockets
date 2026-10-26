/*
 * lws-api-test-route-dual-stack
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws picks the route a destination would go out on from its routing table,
 * and drops a DNS result it has no way to use.  A v4 destination can go out
 * through a v6 gateway, promoted to ::ffff:a.b.c.d, but only on a host whose
 * egress is v6 alone: on a dual-stack host it must take the v4 gateway.
 *
 * The v4 and v6 default routes often have the same priority, and lws used to
 * take whichever came first in its table.  When netlink told it about the v6
 * one first, eg, a host booting with its RA in before its DHCP lease, every
 * v4 destination went the v6 way, found no v6 source to go with it and was
 * dropped: a v4-only name, like pool.ntp.org, could never be resolved to
 * anything usable, while names with AAAA records worked.
 *
 * A default route on a point-to-point link has no gateway, eg, wg-quick's
 * "::/0 dev wg0".  lws used to see no way out in it at all, so on a host
 * whose only v6 egress was a tunnel like that, every v6 destination was
 * dropped for having no route out, though the kernel would route it.
 *
 * A v6 network route doesn't take in v4 destinations, though lws compares
 * them as v4-mapped: a split tunnel's "::/1 dev wg0" holds ::ffff:a.b.c.d.
 *
 * And a route to a network via a gateway, eg, "10.0.0.0/8 via 192.0.2.1",
 * is not a default route: lws used to take any route with a gateway as one.
 *
 * Once netlink has given the context the host's routes, for each case this
 * replaces them with the case's routes and asks for a udp socket to a
 * destination, which must be made, or must not be, as the case says.
 *
 * Linux only: the context only judges by routes when it has them from
 * netlink.
 */

#include <libwebsockets.h>
#include <string.h>

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout;
static int fails = 1;

static const struct lws_protocols protocols[] = {
	{ "route-udp", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
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

/*
 * A route the way netlink makes one.  A default route has the unspecified
 * address of its family as its dest, with length 0, and a gateway, unless
 * it's on a point-to-point link, eg, wg-quick's "::/0 dev wg0".  An address
 * on an interface is a source route, with the address as its src.
 */

typedef struct {
	const char	*dest;
	uint8_t		dest_len;
	const char	*gw;
	const char	*src;
	int		if_idx;
	int		priority;
} route_spec_t;

typedef struct {
	const char		*what;
	const char		*ads;	/* where the udp socket is aimed */
	int			made;	/* 1: it must be made, 0: dropped */
	const route_spec_t	*routes;
} case_t;

static int
route_add(lws_dll2_owner_t *rt, const route_spec_t *rs)
{
	lws_route_t *r = lws_realloc(NULL, sizeof(*r), "route");

	if (!r)
		return 1;

	memset(r, 0, sizeof(*r));
	if (lws_sa46_parse_numeric_address(rs->dest, &r->dest) ||
	    (rs->gw && lws_sa46_parse_numeric_address(rs->gw, &r->gateway)) ||
	    (rs->src && lws_sa46_parse_numeric_address(rs->src, &r->src))) {
		lws_realloc(r, 0, "free");
		return 1;
	}
	r->dest_len = rs->dest_len;
	r->source_ads = !!rs->src;
	r->if_idx = rs->if_idx;
	r->priority = rs->priority;
	r->uidx = (lws_route_uidx_t)(rt->count + 1);
	lws_dll2_add_tail(&r->list, rt);

	return 0;
}

static const route_spec_t
	v6_first_same_pri[] = {
		{ "::",		0, "fe80::1",	NULL, 1, 100 },
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 100 },
		{ NULL }
	}, v6_first_better_pri[] = {
		{ "::",		0, "fe80::1",	NULL, 1, 100 },
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 1024 },
		{ NULL }
	}, v4_first_same_pri[] = {
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 100 },
		{ "::",		0, "fe80::1",	NULL, 1, 100 },
		{ NULL }
	}, v6_on_link[] = {
		/* a LAN with only a v4 default route, and a v6 tunnel */
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 100 },
		{ "::",		0, NULL,	NULL, 2, 0 },
		{ "2001:db8::2", 64, NULL,	"2001:db8::2", 2, 0 },
		{ NULL }
	}, v6_on_link_first[] = {
		{ "::",		0, NULL,	NULL, 2, 100 },
		{ "2001:db8::2", 64, NULL,	"2001:db8::2", 2, 0 },
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 100 },
		{ NULL }
	}, v4_on_link[] = {
		{ "0.0.0.0",	0, NULL,	NULL, 2, 0 },
		{ "2001:db8::2", 64, NULL,	"2001:db8::2", 1, 0 },
		{ NULL }
	}, v6_split_tunnel[] = {
		/* "::/1" holds ::ffff:127.0.0.1, but only as a v6 network */
		{ "::",		1, NULL,	NULL, 2, 0 },
		{ "8000::",	1, NULL,	NULL, 2, 0 },
		{ "0.0.0.0",	0, "192.0.2.1",	NULL, 1, 100 },
		{ NULL }
	}, net_via_gw[] = {
		{ "10.0.0.0",	8, "192.0.2.1",	NULL, 1, 0 },
		{ NULL }
	};

static const case_t cases[] = {
	{ "v6 default route first, same priority",
	  "127.0.0.1", 1, v6_first_same_pri },
	{ "v6 default route has the better priority",
	  "127.0.0.1", 1, v6_first_better_pri },
	{ "v4 default route first, same priority",
	  "127.0.0.1", 1, v4_first_same_pri },
	{ "v6 dest, v6 default route on a link with no gateway",
	  "::1", 1, v6_on_link },
	{ "v4 dest, v6 default route with no gateway first",
	  "127.0.0.1", 1, v6_on_link_first },
	{ "v6 dest, only a v4 default route with no gateway",
	  "::1", 0, v4_on_link },
	{ "v4 dest, v6 split tunnel routes and a v4 default route",
	  "127.0.0.1", 1, v6_split_tunnel },
	{ "v4 dest, only a network route via a gateway",
	  "127.0.0.1", 0, net_via_gw },
};

static int
try_case(const case_t *c)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "route");
	lws_dll2_owner_t *rt = lws_routing_table_get(context);
	const route_spec_t *rs;
	struct lws *wsi;

	routes_clear(rt);

	for (rs = c->routes; rs->dest; rs++)
		if (route_add(rt, rs)) {
			lwsl_err("%s: %s: making the routes failed\n",
				 __func__, c->what);
			return 1;
		}

	/* where it's aimed doesn't matter: nothing is sent */
	wsi = lws_create_adopt_udp(vh, c->ads, 7681, 0, "route-udp",
				   NULL, NULL, NULL, NULL, "route-udp");
	if (!wsi != !c->made) {
		lwsl_err("%s: FAIL: %s: %s %s\n", __func__, c->what, c->ads,
			 c->made ? "dropped" : "not dropped");
		if (wsi)
			lws_set_timeout(wsi, 1, LWS_TO_KILL_ASYNC);
		return 1;
	}

	if (wsi)
		lws_set_timeout(wsi, 1, LWS_TO_KILL_ASYNC);
	lwsl_user("%s: ok: %s\n", __func__, c->what);

	return 0;
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

	lwsl_user("LWS API selftest: route selection on a dual-stack host\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.vhost_name = "route";
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
