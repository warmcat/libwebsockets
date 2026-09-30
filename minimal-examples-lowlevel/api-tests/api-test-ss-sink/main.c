/*
 * lws-api-test-ss-sink
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms how creating a Secure Stream of a "local_sink" streamtype fails
 * when there is no sink for it, or the sink doesn't want it.
 *
 * Creating a stream of a streamtype the policy marks as "local_sink" binds it
 * to a stream the registered sink accepts for it, instead of connecting
 * anywhere.  The sink can refuse the new stream when it hears
 * LWSSSCS_SINK_JOIN, or by returning LWSSSSRET_DESTROY_ME from the accepted
 * sink stream's own LWSSSCS_CREATING, CONNECTING or CONNECTED.  In every case
 * lws_ss_create() must fail cleanly for the source, and the accepted sink
 * stream it made, if any, must be destroyed exactly once.
 *
 *  - no-sink:           the streamtype has no sink registered
 *  - join-refused:      the sink refuses at LWSSSCS_SINK_JOIN
 *  - creating-refused:  the accepted sink refuses in LWSSSCS_CREATING
 *  - connected-refused: the accepted sink refuses in LWSSSCS_CONNECTED
 *  - accepted:          the sink takes the stream, destroying the source
 *                       destroys the accepted sink with it
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

enum {
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

typedef struct sink_case {
	const char		*name;
	const char		*streamtype;
	int			refuse;		/* sink refuses in this state,
						 * -1 = never */
	char			create_ok;	/* source create must work */

	/* results */
	char			ok;
} sink_case_t;

static sink_case_t cases[] = {
	{ "no-sink",		"nosink",	-1,			0, 0 },
	{ "join-refused",	"sinkt",	LWSSSCS_SINK_JOIN,	0, 0 },
	{ "creating-refused",	"sinkt",	LWSSSCS_CREATING,	0, 0 },
	{ "connected-refused",	"sinkt",	LWSSSCS_CONNECTED,	0, 0 },
	{ "accepted",		"sinkt",	-1,			1, 0 },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_run;
static unsigned int cur_case;
static int failed;

/* CREATING and DESTROYING seen by accepted sink and by source streams */
static int sink_created, sink_destroyed, src_created, src_destroyed;

/* the same user object type serves the sink and source streams */

typedef struct ss_obj {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} ss_obj_t;

static lws_ss_state_return_t
sink_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
sink_state(void *userobj, void *h_src, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	lwsl_user("%s: %s: %s\n", __func__, cases[cur_case].name,
		  lws_ss_state_name(state));

	/*
	 * SINK_JOIN is about the joining source, and comes with the source's
	 * user object, not one of ours
	 */

	if (state == LWSSSCS_CREATING)
		sink_created++;
	if (state == LWSSSCS_DESTROYING)
		sink_destroyed++;

	if ((int)state == cases[cur_case].refuse) {
		lwsl_user("%s: refusing\n", __func__);
		return LWSSSSRET_DESTROY_ME;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_sink = {
	.handle_offset			= offsetof(ss_obj_t, ss),
	.opaque_user_data_offset	= offsetof(ss_obj_t, opaque_data),
	.streamtype			= "sinkt",
	.rx				= sink_rx,
	.state				= sink_state,
	.user_alloc			= sizeof(ss_obj_t),
	.flags				= LWSSSINFLAGS_REGISTER_SINK,
};

static lws_ss_state_return_t
src_state(void *userobj, void *h_src, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	lwsl_user("%s: %s: %s\n", __func__, cases[cur_case].name,
		  lws_ss_state_name(state));

	if (state == LWSSSCS_CREATING)
		src_created++;
	if (state == LWSSSCS_DESTROYING)
		src_destroyed++;

	return LWSSSSRET_OK;
}

static void
run_cases(lws_sorted_usec_list_t *sul)
{
	struct lws_ss_handle *h;
	lws_ss_info_t ssi;
	sink_case_t *c;
	int n;

	if (lws_ss_create(context, 0, &ssi_sink, NULL, NULL, NULL, NULL)) {
		lwsl_err("%s: failed to register the sink\n", __func__);
		failed = 1;
		goto bail;
	}

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(ss_obj_t, ss);
	ssi.opaque_user_data_offset	= offsetof(ss_obj_t, opaque_data);
	ssi.state			= src_state;
	ssi.user_alloc			= sizeof(ss_obj_t);

	for (cur_case = 0; cur_case < LWS_ARRAY_SIZE(cases); cur_case++) {
		c = &cases[cur_case];
		lwsl_user("--- case %s ---\n", c->name);

		ssi.streamtype = c->streamtype;
		h = NULL;
		n = lws_ss_create(context, 0, &ssi, NULL, &h, NULL, NULL);

		if ((n == 0) != (c->create_ok != 0)) {
			lwsl_err("--- %s: create %s, expected %s ---\n",
				 c->name, n ? "failed" : "worked",
				 c->create_ok ? "success" : "failure");
			continue;
		}
		if (n && h) {
			lwsl_err("--- %s: failed create left a handle ---\n",
				 c->name);
			continue;
		}

		if (h)
			lws_ss_destroy(&h);

		if (sink_created != sink_destroyed ||
		    src_created != src_destroyed) {
			lwsl_err("--- %s: sinks %d created %d destroyed, "
				 "sources %d created %d destroyed ---\n",
				 c->name, sink_created, sink_destroyed,
				 src_created, src_destroyed);
			continue;
		}

		c->ok = 1;
	}

bail:
	lws_default_loop_exit(context);
}

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_SYSTEM_STATE) ||
	    lws_json_simple_strcmp(buf, len, "\"state\":", "OPERATIONAL"))
		return 0;

	/* from the event loop, not the state change */
	lws_sul_schedule(context, 0, &sul_run, run_cases, 1);

	return 0;
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_default_loop_exit(context);
}

static const char * const policy =
	"{\"release\":\"01234567\",\"product\":\"myproduct\","
	 "\"schema-version\":1,"
	 "\"retry\":[{\"default\":{\"backoff\":[1000,2000,3000],"
		"\"conceal\":3,\"jitterpc\":20,"
		"\"svalidping\":30,\"svalidhup\":35}}],"
	 "\"s\":["
		"{\"sinkt\":{\"local_sink\":true}},"
		"{\"nosink\":{\"local_sink\":true}}"
	 "]}";

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	unsigned int n;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS local sink creation failures\n");

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.early_smd_cb		= smd_cb;
	info.early_smd_class_filter	= LWSSMDCL_SYSTEM_STATE;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_context_default_loop_run_destroy(context);

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {
		lwsl_user("%s: %s\n", cases[n].name,
			  cases[n].ok ? "ok" : "FAILED");
		if (!cases[n].ok)
			failed = 1;
	}

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
