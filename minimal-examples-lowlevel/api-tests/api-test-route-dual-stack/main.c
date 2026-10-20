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
 * Once netlink has given the context the host's routes, this replaces them
 * with a v6 default route and then a v4 one, both of the same priority, and
 * asks for a udp socket to a v4 address.  It must get one.  Then again with
 * the v4 route's priority worse than the v6 one's, and with the v4 route
 * first.
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

/* a default route, the way netlink makes one: a gateway, no dest */

static int
route_add_default(lws_dll2_owner_t *rt, const char *gw, int priority)
{
	lws_route_t *r = lws_realloc(NULL, sizeof(*r), "route");

	if (!r)
		return 1;

	memset(r, 0, sizeof(*r));
	if (lws_sa46_parse_numeric_address(gw, &r->gateway)) {
		lws_realloc(r, 0, "free");
		return 1;
	}
	r->if_idx = 1;
	r->priority = priority;
	r->uidx = (lws_route_uidx_t)(rt->count + 1);
	lws_dll2_add_tail(&r->list, rt);

	return 0;
}

static int
try_v4(const char *what, int v6_first, int pri4, int pri6)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "route");
	lws_dll2_owner_t *rt = lws_routing_table_get(context);
	struct lws *wsi;

	routes_clear(rt);

	if (v6_first ? route_add_default(rt, "fe80::1", pri6) ||
		       route_add_default(rt, "192.0.2.1", pri4) :
		       route_add_default(rt, "192.0.2.1", pri4) ||
		       route_add_default(rt, "fe80::1", pri6)) {
		lwsl_err("%s: %s: making the routes failed\n", __func__, what);
		return 1;
	}

	/* where it's aimed doesn't matter: nothing is sent */
	wsi = lws_create_adopt_udp(vh, "127.0.0.1", 7681, 0, "route-udp",
				   NULL, NULL, NULL, NULL, "route-udp");
	if (!wsi) {
		lwsl_err("%s: FAIL: %s: v4 destination dropped\n", __func__,
			 what);
		return 1;
	}

	lws_set_timeout(wsi, 1, LWS_TO_KILL_ASYNC);
	lwsl_user("%s: ok: %s\n", __func__, what);

	return 0;
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		 int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* netlink has delivered the host's routes by now */

	fails = try_v4("v6 default route first, same priority", 1, 100, 100) +
		try_v4("v6 default route has the better priority", 1, 1024,
		       100) +
		try_v4("v4 default route first, same priority", 0, 100, 100);

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

	lwsl_user("LWS API selftest: v4 destinations on a dual-stack host\n");

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
