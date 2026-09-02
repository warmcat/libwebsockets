/*
 * lws-api-test-system-cpd
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks that system state progression towards OPERATIONAL is not held up
 * waiting on the outcome of lws' own captive portal detection, once the
 * platform stack has already done the DHCP and told lws about the IP on an
 * interface with an SMD "ipacq" message.
 *
 * Phase 1 runs without any IP acquisition: the context must not reach
 * OPERATIONAL, it should be held at the DHCP gate waiting for an interface
 * to acquire an IP at all.
 *
 * Phase 2 synthesizes the "ipacq" SMD message an esp32 netdev driver emits
 * on IP_EVENT_STA_GOT_IP: the context must proceed to OPERATIONAL without
 * any captive portal detection having completed... there is deliberately no
 * policy for the CPD streamtype, so the CPD attempt cannot even start.
 */

#include <libwebsockets.h>
#include <string.h>

#define PHASE1_MS_NO_IP			750
#define PHASE2_MS_REACH_OPERATIONAL	10000

static struct lws_context *cx;
static struct lws_smd_peer *pr;
static lws_sorted_usec_list_t sul;
static int ipacq_sent, bad, quit;

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	if (lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL"))
		return 0;

	if (!ipacq_sent) {
		lwsl_user("%s: reached OPERATIONAL before any ipacq\n",
			  __func__);
		bad = 1;
	} else
		lwsl_user("%s: reached OPERATIONAL after ipacq\n", __func__);

	quit = 1;

	return 0;
}

static void
sul_cb(lws_sorted_usec_list_t *_sul)
{
	if (!ipacq_sent) {
		/*
		 * Phase 1 is done: we made it this far without reaching
		 * OPERATIONAL, which is what's supposed to happen when no
		 * interface has an IP yet.
		 */

		ipacq_sent = 1;
		lwsl_user("Phase 1: held before OPERATIONAL with no IP: PASS\n");

		/*
		 * Phase 2: pretend the platform stack did the DHCP and told
		 * us about it, exactly like the esp32 netdev driver does
		 */

		if (lws_smd_msg_printf(cx, LWSSMDCL_NETWORK,
				       "{\"type\":\"ipacq\",\"if\":\"wl0\","
				       "\"ipv4\":\"10.199.0.26\"}")) {
			lwsl_user("%s: smd msg failed\n", __func__);
			bad = quit = 1;

			return;
		}

		lws_sul_schedule(cx, 0, &sul, sul_cb,
				 PHASE2_MS_REACH_OPERATIONAL * LWS_US_PER_MS);

		return;
	}

	lwsl_user("%s: failed to reach OPERATIONAL after ipacq\n", __func__);
	bad = quit = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int n = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	lwsl_user("LWS API selftest: system CPD gating\n");

	memset(&info, 0, sizeof(info));

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context create failed\n", __func__);

		return 1;
	}

	pr = lws_smd_register(cx, NULL, 0, LWSSMDCL_SYSTEM_STATE, smd_cb);
	if (!pr) {
		lwsl_err("%s: smd register failed\n", __func__);
		lws_context_destroy(cx);

		return 1;
	}

	lws_sul_schedule(cx, 0, &sul, sul_cb,
			 PHASE1_MS_NO_IP * LWS_US_PER_MS);

	while (n >= 0 && !quit)
		n = lws_service(cx, 0);

	lws_smd_unregister(pr);
	lws_context_destroy(cx);

	if (bad || n < 0) {
		lwsl_user("Completed: FAIL\n");

		return 1;
	}

	lwsl_user("Completed: ALL PASS\n");

	return 0;
}
