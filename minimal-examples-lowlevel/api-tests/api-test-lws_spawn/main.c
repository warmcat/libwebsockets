/*
 * lws-api-test-lws_spawn
 *
 * Written in 2010-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This test checks the lws_spawn() api, including linux cgroup integration.
 */

#include <libwebsockets.h>
#include <sys/stat.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

struct test_state; /* Forward declaration */

/*
 * A dedicated context for each spawn instance. This avoids race conditions
 * by making the opaque pointer for the wsi and reap_cb self-contained.
 */
struct per_spawn_state {
	struct test_state	*ts;
	struct lws_spawn_piped	*lsp;
	lws_spawn_resource_us_t	res;
};

typedef enum {
	PHASE_INIT,
	PHASE_TEST_NO_CGROUP,
	PHASE_TEST_CGROUP,
	PHASE_DONE
} test_phase_t;

struct test_state {
	struct lws_context		*context;
	struct lws_vhost		*vhost;
	test_phase_t			phase;
	int				result;
	int				reap_count;

	/* We need one state object per test we intend to run */
	struct per_spawn_state		pss[2];

#if defined(__linux__)
	char				cgroup_path[256];
#endif
};

static void
reap_cb(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
	int we_killed_him);

static int
callback_spawn_test(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_spawn_state *pss = (struct per_spawn_state *)
					lws_get_opaque_user_data(wsi);

//	lwsl_wsi_err(wsi, "reason %d\n", reason);

	switch (reason) {
	case LWS_CALLBACK_RAW_CLOSE_FILE:
                lws_spawn_stdwsi_closed(pss->lsp, wsi);
		break;
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static struct lws_protocols protocols[] = {
	{ "spawn-test-protocol", callback_spawn_test, 0, 0, 0, 0, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
spawn_next(struct test_state *ts)
{
	struct lws_spawn_piped_info info;
	const char * const exec_array[] = { "/bin/true", NULL };
	struct per_spawn_state *pss = NULL;

	memset(&info, 0, sizeof(info));
	info.vh = ts->vhost;
	info.exec_array = exec_array;
	info.reap_cb = reap_cb;
	info.protocol_name = "spawn-test-protocol";
	info.timeout_us = 2 * LWS_US_PER_SEC;

	switch (ts->phase) {
	case PHASE_TEST_NO_CGROUP:
		lwsl_user("%s: ---- Test 1: Spawn without cgroup ----\n", __func__);
		pss = &ts->pss[0];
		pss->ts = ts;
		info.opaque = pss;
		info.plsp = &pss->lsp;
		info.res = &pss->res;

		pss->lsp = lws_spawn_piped(&info);
		if (!pss->lsp) {
			lwsl_err("%s: Failed to spawn for no-cgroup test\n", __func__);
			ts->result = 1;
		}
		break;

	case PHASE_TEST_CGROUP:
#if defined(__linux__)
		lwsl_user("%s: ---- Test 2: Spawn with cgroup ----\n", __func__);
		pss = &ts->pss[1];
		pss->ts = ts;
		info.opaque = pss;
		info.plsp = &pss->lsp;
		{
			struct stat s;
			char cgb[128], cgroup_name[256];
			lws_spawn_get_self_cgroup(cgb, sizeof(cgb));
			lws_snprintf(cgroup_name, sizeof(cgroup_name), "lws/api-test-lws_spawn-%d", (int)getpid());
			lws_snprintf(ts->cgroup_path, sizeof(ts->cgroup_path), "/sys/fs/cgroup%s/%s", cgb, cgroup_name);
			lwsl_notice("%s: %s\n", __func__, ts->cgroup_path);
			if (stat(ts->cgroup_path, &s) == 0) {
				lwsl_err("%s: cgroup path '%s' exists before test\n", __func__, ts->cgroup_path);
				ts->result = 1;
				return 1;
			}
			info.cgroup_name_suffix = cgroup_name;
			info.res = &pss->res;
			pss->lsp = lws_spawn_piped(&info);
			if (!pss->lsp) {
				lwsl_err("%s: Failed to spawn for cgroup test\n", __func__);
				ts->result = 1;
				return 1;
			}
			if (stat(ts->cgroup_path, &s) != 0) {
				lwsl_err("%s: cgroup path '%s' not created\n", __func__, ts->cgroup_path);
				ts->result = 1;
				return 1;
			}
			lwsl_user("%s: Verified cgroup dir created: %s\n", __func__, ts->cgroup_path);
		}
#else
		lwsl_user("%s: Skipping cgroup test on non-linux platform\n", __func__);
		ts->phase = PHASE_DONE;
#endif
		break;
	default:
		break;
	}
	return ts->result;
}

static void
reap_cb(void *opaque, const lws_spawn_resource_us_t *res, siginfo_t *si,
	int we_killed_him)
{
	/* Opaque is the per-spawn state, from which we find the main state */
	struct per_spawn_state *pss = (struct per_spawn_state *)opaque;
	struct test_state *ts = pss->ts;
	test_phase_t last_phase = ts->phase;

	if (si) {
#if defined(WIN32)
		lwsl_user("%s: Reap callback for phase %d, exit code %d\n",
			  __func__, (int)last_phase, (int)si->retcode);
#else
		lwsl_user("%s: Reap callback for phase %d, exit code %d\n",
			  __func__, (int)last_phase, si->si_status);
#endif
		lwsl_notice(" CPU us: user %llu, sys %llu\n",
			    (unsigned long long)res->us_cpu_user,
			    (unsigned long long)res->us_cpu_sys);
		lwsl_notice(" Mem peak: %llu\n",
			    (unsigned long long)res->peak_mem_rss);

		ts->reap_count++;
		if (we_killed_him) {
			lwsl_err("%s: Spawned process was killed by timeout\n",
				 __func__);
			ts->result = 1;
		} else {
#if defined(WIN32)
			if (si->retcode != 0) {
				lwsl_err("%s: Spawned process failed with exit code %d\n",
				 __func__, (int)si->retcode);
#else
			if (si->si_status != 0) {
				lwsl_err("%s: Spawned process failed with exit code %d\n",
				 __func__, si->si_status);
#endif
				ts->result = 1;
			}
		}

		if (res->us_cpu_user == 0 && res->us_cpu_sys == 0) {
			lwsl_err("%s: cpu usage reported as zero\n", __func__);
			ts->result = 1;
		}

		if (res->peak_mem_rss == 0) {
			lwsl_err("%s: peak mem usage reported as zero\n", __func__);
			ts->result = 1;
		}

#if defined(__linux__)
		if (last_phase == PHASE_TEST_CGROUP) {
			struct stat s;
			if (stat(ts->cgroup_path, &s) == 0) {
				lwsl_err("%s: cgroup path '%s' not removed after reap\n",
					 __func__, ts->cgroup_path);
				ts->result = 1;
			} else {
				lwsl_user("%s: Verified cgroup dir removed: %s\n",
					  __func__, ts->cgroup_path);
			}
		}
#endif
	}

	if (ts->result) {
		ts->phase = PHASE_DONE;
		return;
	}

	ts->phase++;
	spawn_next(ts);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct test_state ts;

	memset(&ts, 0, sizeof(ts));
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_spawn_prepare_self_cgroup(NULL, NULL)) {
		lwsl_err("%s: this api-test must run as root\n", __func__);
		return 1;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	lwsl_user("LWS spawn API test\n");
	ts.context = lws_create_context(&info);
	if (!ts.context) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	ts.vhost = lws_create_vhost(ts.context, &info);
	if (!ts.vhost) {
		lwsl_err("lws_create_vhost failed\n");
		lws_context_destroy(ts.context);
		return 1;
	}

	/* Kick off state machine. It needs a valid pss to get ts from */
	ts.pss[0].ts = &ts;
	reap_cb(&ts.pss[0], NULL, NULL, 0);

	while (ts.phase != PHASE_DONE && !ts.result)
		if (lws_service(ts.context, 50) < 0) {
			ts.result = 1;
			break;
		}

	lws_context_destroy(ts.context);

#if defined(__linux__)
	if (!ts.result && ts.reap_count != 2) {
		lwsl_err("Expected 2 reaps, got %d\n", ts.reap_count);
		ts.result = 1;
	}
#else
	if (!ts.result && ts.reap_count != 1) {
		lwsl_err("Expected 1 reap, got %d\n", ts.reap_count);
		ts.result = 1;
	}
#endif

	if (!ts.result)
		lwsl_user("Completed: PASS\n");
	else
		lwsl_err("Completed: FAIL\n");

	return ts.result;
}

