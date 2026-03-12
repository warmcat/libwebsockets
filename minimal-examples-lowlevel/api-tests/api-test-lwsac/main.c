/*
 * lws-api-test-lwsac
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>


enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

struct mytest {
	int payload;
	/* notice doesn't have to be at start of struct */
	lws_list_ptr list_next;
	/* a struct can appear on multiple lists too... */
};

/* converts a ptr to struct mytest .list_next to a ptr to struct mytest */
#define list_to_mytest(p) lws_list_ptr_container(p, struct mytest, list_next)

int main(int argc, const char **argv)
{
	int n, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, acc;
	lws_list_ptr list_head = NULL, iter;
	struct lwsac *lwsac = NULL;
	struct mytest *m;
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: lwsac\n");

	/*
	 * 1) allocate and create 1000 struct mytest in a linked-list
	 */

	for (n = 0; n < 1000; n++) {
		m = lwsac_use(&lwsac, sizeof(*m), 0);
		if (!m)
			return -1;
		m->payload = n;

		lws_list_ptr_insert(&list_head, &m->list_next, NULL);
	}

	/*
	 * 2) report some debug info about the lwsac state... those 1000
	 * allocations actually only required 4 mallocs
	 */

	lwsac_info(lwsac);

	/* 3) iterate the list, accumulating the payloads */

	acc = 0;
	iter = list_head;
	while (iter) {
		m = list_to_mytest(iter);
		acc += m->payload;

		lws_list_ptr_advance(iter);
	}

	if (acc != 499500) {
		lwsl_err("%s: FAIL acc %d\n", __func__, acc);

		return 1;
	}

	/*
	 * 4) deallocate everything (lwsac is also set to NULL).  It just
	 *    deallocates the 4 mallocs, everything in there is gone accordingly
	 */

	lwsac_free(&lwsac);

	lwsl_user("Completed: PASS\n");

	return 0;
}
