/*
 * lws-api-test-sspc-link-retry
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An sspc stream is told LWSSSCS_UPSTREAM_LINK_RETRY each time its link to
 * the SS proxy fails, and user code may give up on the stream then by
 * returning LWSSSSRET_DESTROY_ME.  The link fails inside the transport, often
 * synchronously inside the connect attempt, so the handle must stay usable
 * until the transport and the retry machinery are done with it, and only
 * then be destroyed.
 *
 * Nothing listens on the proxy address we give, so each link attempt fails.
 *
 *  - leg 1 gives up on the first failure, which comes during
 *    lws_sspc_create() on platforms where the connect fails synchronously:
 *    create must then fail cleanly, or, if the failure came later, the
 *    stream must be destroyed once
 *
 *  - leg 2 gives up on the second failure, which comes from the retry timer
 */

#include <libwebsockets.h>
#include <string.h>

typedef struct myss {
	struct lws_sspc_handle		*ss;
	void				*opaque_data;
} myss_t;

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog;
static int link_retry, destroying, give_up_at, timed_out, fails;

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	switch (state) {
	case LWSSSCS_UPSTREAM_LINK_RETRY:
		lwsl_user("%s: UPSTREAM_LINK_RETRY %d\n", __func__,
			  link_retry + 1);
		if (++link_retry >= give_up_at)
			/* we give up on the stream */
			return LWSSSSRET_DESTROY_ME;
		break;

	case LWSSSCS_DESTROYING:
		lwsl_user("%s: DESTROYING\n", __func__);
		destroying++;
		lws_cancel_service(cx);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_cancel_service(cx);
}

/* service until the stream is destroyed, or the time is up */

static void
run(lws_usec_t us)
{
	timed_out = 0;
	lws_sul_schedule(cx, 0, &sul_watchdog, sul_watchdog_cb, us);

	while (!destroying && !timed_out)
		if (lws_service(cx, 0) < 0)
			break;

	lws_sul_cancel(&sul_watchdog);
}

static void
leg(const char *name, int _give_up_at)
{
	struct lws_sspc_handle *h = NULL;
	lws_ss_info_t ssi;
	int r;

	lwsl_user("%s: %s\n", __func__, name);

	link_retry	= 0;
	destroying	= 0;
	give_up_at	= _give_up_at;

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	ssi.streamtype			= "api-test";

	r = lws_sspc_create(cx, 0, &ssi, NULL, &h, NULL, NULL);
	if (r) {
		/* only allowed if we already gave up inside create */
		if (link_retry != give_up_at || destroying != 1 || h) {
			lwsl_err("%s: %s: create failed: retries %d, "
				 "destroying %d, h %p\n", __func__, name,
				 link_retry, destroying, (void *)h);
			fails++;
		}
	} else
		run(5 * LWS_US_PER_SEC);

	if (link_retry != give_up_at || destroying != 1) {
		lwsl_err("%s: %s: retries %d (expected %d), destroying %d%s\n",
			 __func__, name, link_retry, give_up_at, destroying,
			 timed_out ? ", timed out" : "");
		fails++;
	}

	/*
	 * Nothing may still be scheduled against the destroyed stream: service
	 * past when its retry timer would have fired
	 */

	destroying = 0;
	run(1500 * LWS_US_PER_MS);
	if (destroying || link_retry != give_up_at) {
		lwsl_err("%s: %s: stream still active after destroy\n",
			 __func__, name);
		fails++;
	}
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: sspc link retry\n");

	/*
	 * A proxy address nothing listens on, so every link attempt fails.  The
	 * name is only ever a connect() target, it is never created, and
	 * nothing is ever sent to it.
	 */

#if defined(__linux__)
	info.ss_proxy_bind		= "+@lws-api-test-sspc-link-retry";
#else
	info.ss_proxy_bind		= "+/tmp/lws-api-test-sspc-link-retry"; // NOSONAR
#endif
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.fd_limit_per_thread	= 0;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	leg("give up on the first failure", 1);
	leg("give up on a retry", 2);

	lws_context_destroy(cx);

	if (fails) {
		lwsl_user("Completed: FAIL (%d)\n", fails);
		return 1;
	}

	lwsl_user("Completed: PASS\n");

	return 0;
}
