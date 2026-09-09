/*
 * lws-api-test-dht-create
 *
 * Fault-injection coverage for cleanup when DHT context creation cannot
 * allocate its random node ID.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TRACKED 16

static void *tracked[MAX_TRACKED];
static size_t tracked_count;
static int tracking;
static int injected_failures;

static int
tracked_index(void *ptr)
{
	size_t n;

	for (n = 0; n < tracked_count; n++)
		if (tracked[n] == ptr)
			return (int)n;

	return -1;
}

static void
tracked_add(void *ptr)
{
	if (!ptr)
		return;

	if (tracked_count == LWS_ARRAY_SIZE(tracked)) {
		lwsl_err("too many tracked allocations\n");
		abort();
	}

	tracked[tracked_count++] = ptr;
}

static void
tracked_remove(void *ptr)
{
	int n = tracked_index(ptr);

	if (n < 0)
		return;

	tracked[(size_t)n] = tracked[--tracked_count];
}

static void *
test_realloc(void *ptr, size_t size, const char *reason)
{
	int n = tracked_index(ptr);
	void *p;

	if (!size) {
		tracked_remove(ptr);
		free(ptr);

		return NULL;
	}

	if (tracking && !ptr && reason &&
	    !strcmp(reason, "lws_dht_hash_create")) {
		injected_failures++;

		return NULL;
	}

	p = realloc(ptr, size);
	if (!p)
		return NULL;

	if (n >= 0)
		tracked[(size_t)n] = p;
	else if (tracking && !ptr)
		tracked_add(p);

	return p;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_dht_info dht_info;
	struct lws_dht_ctx *dht;
	struct lws_context *context;
	struct lws_vhost *vhost;
	int fails = 0;

	lwsl_user("LWS API selftest: dht-create allocation failure\n");

	lws_set_allocator(test_realloc);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

	context = lws_create_context(&info);
	if (!context) {
		fprintf(stderr, "lws init failed\n");

		return 1;
	}

	info.vhost_name = "dht-create-test";
	vhost = lws_create_vhost(context, &info);
	if (!vhost) {
		lwsl_err("test vhost creation failed\n");
		lws_context_destroy(context);

		return 1;
	}

	memset(&dht_info, 0, sizeof(dht_info));
	dht_info.vhost = vhost;
	dht_info.name = "allocation-failure-test";
	dht_info.port = -1;

	tracking = 1;
	dht = lws_dht_create(&dht_info);
	tracking = 0;

	if (dht) {
		lwsl_err("DHT creation unexpectedly succeeded\n");
		lws_dht_destroy(&dht);
		fails++;
	}

	if (injected_failures != 1) {
		lwsl_err("expected one injected hash allocation failure, got %d\n",
			 injected_failures);
		fails++;
	}

	if (tracked_count) {
		lwsl_err("DHT creation failure leaked %zu allocation(s)\n",
			 tracked_count);
		fails++;
	}

	while (tracked_count)
		free(tracked[--tracked_count]);

	lws_context_destroy(context);

	if (fails)
		lwsl_user("Completed with %d failed checks\n", fails);
	else
		lwsl_user("Completed with no failed checks\n");

	return fails ? 1 : 0;
}
