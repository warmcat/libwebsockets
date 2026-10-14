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
 * Two contexts take their routes from netlink.  One has the "netlink_lost"
 * fault, which loses the first read from netlink, the start of the route
 * dump at init, as if the kernel had dropped it.  Once both have settled,
 * the one that lost the read must hold as many routes as the other.
 *
 * Linux only: netlink is where the routing table comes from.
 */

#include <libwebsockets.h>
#include <string.h>

#define NLR_SETTLE_US		(4 * LWS_US_PER_SEC)

static struct lws_context *cx_ref, *cx_lost;
static lws_sorted_usec_list_t sul_check;
static int interrupted, result = 1;

static void
check_cb(lws_sorted_usec_list_t *sul)
{
	unsigned int ref = lws_routing_table_get(cx_ref)->count,
		     lost = lws_routing_table_get(cx_lost)->count;

	lwsl_user("%s: routes: %u in the reference, %u after the lost read\n",
		  __func__, ref, lost);

	if (!ref)
		/* eg, a sandbox with no routes: nothing to compare */
		lwsl_user("%s: no routes here, not applicable\n", __func__);

	result = ref != lost;
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	lws_fi_t fi = { .name = "netlink_lost", .type = LWSFI_DETERMINISTIC,
			.pre = 0, .count = 1 };

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

	lwsl_user("LWS API selftest: netlink route messages lost\n");

	cx_ref = lws_create_context(&info);
	if (!cx_ref) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the same, but its first read from netlink is lost */
	lws_fi_add(&info.fic, &fi);
	cx_lost = lws_create_context(&info);
	lws_fi_destroy(&info.fic);
	if (!cx_lost) {
		lwsl_err("lws init failed\n");
		goto bail;
	}

	lws_sul_schedule(cx_ref, 0, &sul_check, check_cb, NLR_SETTLE_US);

	/* both contexts have to be serviced */
	while (!interrupted) {
		if (lws_service(cx_ref, 10) < 0 || lws_service(cx_lost, 10) < 0)
			break;
	}

	lws_context_destroy(cx_lost);
bail:
	lws_context_destroy(cx_ref);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
