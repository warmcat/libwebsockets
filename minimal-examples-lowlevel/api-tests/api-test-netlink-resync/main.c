/*
 * lws-api-test-netlink-resync
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws keeps its routing table from netlink.  If the kernel can't deliver
 * every route message, eg, many interfaces came up at once, as when a host
 * starts a batch of VMs, it drops some and says so (ENOBUFS).  The table
 * has missed changes then: lws used to close its netlink socket on that, and
 * never hear about routes again, so connections could later be refused, or
 * culled, by a table that no longer matched the system's.  Instead, it gets
 * all the routes again.
 *
 * Two contexts take their routes from netlink, one after the other.  The
 * first has the "netlink_lost" fault, which loses the first read from
 * netlink, the start of the route dump at init, as if the kernel had dropped
 * it.  Where there are enough routes that the dump takes more than one read,
 * the rest of that dump is still coming when it asks for all the routes
 * again, and the kernel refuses to start another one until it ends.  Once
 * it has settled, it must hold as many routes as the second context, which
 * lost nothing.
 *
 * The contexts run one at a time, since lws_service() on one sleeps until
 * that context has something to do, while the other one waits.
 *
 * Linux only: netlink is where the routing table comes from.
 */

#include <libwebsockets.h>
#include <string.h>

#define NLR_SETTLE_US		(3 * LWS_US_PER_SEC)

static lws_sorted_usec_list_t sul_settle;
static int settled;

static void
settle_cb(lws_sorted_usec_list_t *sul)
{
	settled = 1;
}

/* how many routes a context holds after it has had time to settle */

static int
routes_after_settling(struct lws_context_creation_info *info,
		      unsigned int *count)
{
	struct lws_context *cx = lws_create_context(info);

	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	settled = 0;
	lws_sul_schedule(cx, 0, &sul_settle, settle_cb, NLR_SETTLE_US);

	while (!settled)
		if (lws_service(cx, 0) < 0)
			break;

	*count = lws_routing_table_get(cx)->count;

	lws_sul_cancel(&sul_settle);
	lws_context_destroy(cx);

	return !settled;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_fi_t fi = { .name = "netlink_lost", .type = LWSFI_DETERMINISTIC,
			.pre = 0, .count = 1 };
	unsigned int ref, lost;
	int r, result = 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

	lwsl_user("LWS API selftest: netlink route messages lost\n");

	/* its first read from netlink is lost */
	lws_fi_add(&info.fic, &fi);
	r = routes_after_settling(&info, &lost);
	lws_fi_destroy(&info.fic);
	if (r)
		goto bail;

	/* the reference, that lost nothing */
	if (routes_after_settling(&info, &ref))
		goto bail;

	lwsl_user("%s: routes: %u in the reference, %u after the lost read\n",
		  __func__, ref, lost);

	if (!ref)
		/* eg, a sandbox with no routes: nothing to compare */
		lwsl_user("%s: no routes here, not applicable\n", __func__);

	result = ref != lost;

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
