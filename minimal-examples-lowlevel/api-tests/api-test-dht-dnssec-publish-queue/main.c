/*
 * lws-api-test-dht-dnssec-publish-queue
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the lws-dht-dnssec plugin's queue of zone publications (the
 * JWS the dnssec-monitor hands it as zones are signed) against a target
 * that never answers:
 *
 *  - each publication gets the full CAP_REQ retries, not just the first
 *    one in the queue
 *  - a failed publication is not forgotten: it goes back on the queue and
 *    is tried again after a backoff, which grows with each failure
 *  - queueing a file that is already queued does not add it twice, and
 *    takes it out of its backoff, since it has changed
 *
 * The plugin is built into this test with its upload timings shortened, so
 * the test sees several rounds of failures in a couple of seconds.
 */

#include <libwebsockets.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define DHT_UPLOAD_TIMEOUT_US		(50 * LWS_US_PER_MS)
#define DHT_UPLOAD_VALIDATE_TIMEOUT_US	(50 * LWS_US_PER_MS)
#define DHT_UPLOAD_RETRY_US		(200 * LWS_US_PER_MS)
#define DHT_UPLOAD_RETRY_MAX_US		(400 * LWS_US_PER_MS)

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_dht_dnssec/protocol_lws_dht_dnssec.c"

#define PUBQ_STORE		"./publish-queue-store"
#define PUBQ_JWS_A		PUBQ_STORE "/a.example.zone.signed.jws"
#define PUBQ_JWS_B		PUBQ_STORE "/b.example.zone.signed.jws"

static struct lws_context *context;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_start, sul_check;
static int cap_reqs, fails;

/* the plugin logs each CAP_REQ it sends: count them */

static void
pubq_log_emit(int level, const char *line)
{
	if ((char *)strstr(line, "Sending CAP_REQ"))
		cap_reqs++;

	lwsl_emit_stderr(level, line);
}

static int
pubq_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);
		fails++;

		return 1;
	}

	return 0;
}

static int
pubq_write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	size_t l = strlen(content);

	if (fd < 0)
		return 1;
	if (write(fd, content, LWS_POSIX_LENGTH_CAST(l)) != (ssize_t)l) {
		close(fd);

		return 1;
	}
	close(fd);

	return 0;
}

/* publications queued or in progress */

static int
pubq_count(struct vhd_dht_dnssec *v)
{
	return (int)lws_dll2_count(&v->upload_queue) + !!v->upload_job;
}

static struct dht_upload_job *
pubq_find(struct vhd_dht_dnssec *v, const char *path)
{
	if (v->upload_job && !strcmp(v->upload_job->jws_filepath, path))
		return v->upload_job;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&v->upload_queue)) {
		struct dht_upload_job *j = lws_container_of(d,
					struct dht_upload_job, list);

		if (!strcmp(j->jws_filepath, path))
			return j;
	} lws_end_foreach_dll(d);

	return NULL;
}

static void
pubq_start_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *v = get_dnssec_vhd(context, vh);

	if (pubq_expect(!!v, "plugin instantiated")) {
		lws_default_loop_exit(context);
		return;
	}

	pubq_expect(!do_publish_jws(vh, PUBQ_JWS_A), "queue a");
	pubq_expect(!do_publish_jws(vh, PUBQ_JWS_B), "queue b");
	pubq_expect(!do_publish_jws(vh, PUBQ_JWS_B), "queue b again");

	pubq_expect(pubq_count(v) == 2, "b queued once");
	pubq_expect(v->upload_job &&
		    !strcmp(v->upload_job->jws_filepath, PUBQ_JWS_A),
		    "a started at once");
}

static void
pubq_check_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd_dht_dnssec *v = get_dnssec_vhd(context, vh);
	struct dht_upload_job *a, *b, *idle;
	int expected;

	if (!v) {
		lws_default_loop_exit(context);
		return;
	}

	a = pubq_find(v, PUBQ_JWS_A);
	b = pubq_find(v, PUBQ_JWS_B);

	lwsl_user("%s: %d CAP_REQ, a failed %u, b failed %u, %s in progress "
		  "(retry %d)\n", __func__, cap_reqs, a ? a->fails : 0,
		  b ? b->fails : 0, v->upload_job ?
				v->upload_job->jws_filepath : "nothing",
		  v->upload_retries);

	if (pubq_expect(a && b && pubq_count(v) == 2,
			"failed publications stay queued")) {
		lws_default_loop_exit(context);
		return;
	}

	pubq_expect(a->fails >= 2 && b->fails >= 2,
		    "both retried after failing");
	pubq_expect(a->fails <= 8 && b->fails <= 8,
		    "retries back off");

	/*
	 * Every attempt that failed sent the CAP_REQ and its three resends,
	 * and the one in progress has sent one more than its retries so far
	 */
	expected = 4 * (int)(a->fails + b->fails);
	if (v->upload_job)
		expected += 1 + v->upload_retries;
	pubq_expect(cap_reqs == expected, "every attempt fully retried");

	/* a changed file that is backing off goes again at its turn */
	idle = v->upload_job == a ? b : a;
	pubq_expect(!do_publish_jws(vh, idle->jws_filepath), "queue again");
	pubq_expect(pubq_count(v) == 2, "requeue does not duplicate");
	pubq_expect(pubq_find(v, idle->jws_filepath) == idle &&
		    (v->upload_job == idle || (!idle->fails && !idle->due)),
		    "requeue clears the backoff");

	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	static const struct lws_protocols *pprotocols[] = {
		&lws_dht_dnssec_protocols[0], NULL
	};
	struct lws_protocol_vhost_options pvo[6], pvo_wrap;
	struct lws_context_creation_info info;
	const char *p, *port_dead = NULL;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE,
			  pubq_log_emit);

	lwsl_user("LWS API selftest: dht-dnssec publication queue\n");

	if ((p = lws_cmdline_option(argc, argv, "--port-dead")))
		port_dead = p;
	if (!port_dead) {
		lwsl_err("%s: --port-dead <udp port> is required\n", __func__);

		return 1;
	}

	lws_dir(PUBQ_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(PUBQ_STORE);
	if ((mkdir(PUBQ_STORE, 0700) && errno != EEXIST) ||
	    pubq_write_file(PUBQ_JWS_A, "eyJhIjoxfQ.e30.c2ln\n") ||
	    pubq_write_file(PUBQ_JWS_B, "eyJiIjoxfQ.e30.c2ln\n")) {
		lwsl_err("%s: unable to create the corpus\n", __func__);

		return 1;
	}

	memset(pvo, 0, sizeof(pvo));
	pvo[0].name = "dht-storage-path";
	pvo[0].value = PUBQ_STORE;
	pvo[0].next = &pvo[1];
	pvo[1].name = "dht-port";
	pvo[1].value = "0";
	pvo[1].next = &pvo[2];
	pvo[2].name = "dht-allow-private";
	pvo[2].value = "1";
	pvo[2].next = &pvo[3];
	pvo[3].name = "target-ip";
	pvo[3].value = "127.0.0.1";
	pvo[3].next = &pvo[4];
	pvo[4].name = "target-port";
	pvo[4].value = port_dead;

	memset(&pvo_wrap, 0, sizeof(pvo_wrap));
	pvo_wrap.name = "lws-dht-dnssec";
	pvo_wrap.value = "";
	pvo_wrap.options = pvo;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.pprotocols = pprotocols;
	info.pvo = &pvo_wrap;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);

		return 1;
	}

	vh = lws_get_vhost_by_name(context, "default");
	if (!vh) {
		lwsl_err("%s: no default vhost\n", __func__);
		lws_context_destroy(context);

		return 1;
	}

	lws_sul_schedule(context, 0, &sul_start, pubq_start_cb,
			 10 * LWS_US_PER_MS);
	lws_sul_schedule(context, 0, &sul_check, pubq_check_cb,
			 2500 * LWS_US_PER_MS);

	while (lws_service(context, 0) >= 0)
		;

	lws_context_destroy(context);

	lws_dir(PUBQ_STORE, NULL, lws_dir_rm_rf_cb);
	rmdir(PUBQ_STORE);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
