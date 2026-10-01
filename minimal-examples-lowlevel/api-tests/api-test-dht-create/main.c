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

	/*
	 * BEP42 id derivation and check, against the test vectors in the BEP
	 * (first three bytes, with the low three bits of the third random, and
	 * the last byte r)
	 */
	{
		static const struct {
			const char	*ip;
			uint8_t		r;
			uint8_t		pre[3];
		} v[] = {
			{ "124.31.75.21",	1,	{ 0x5f, 0xbf, 0xb8 } },
			{ "21.75.31.124",	86,	{ 0x5a, 0x3c, 0xe8 } },
			{ "65.23.51.170",	22,	{ 0xa5, 0xd4, 0x30 } },
			{ "84.124.73.14",	65,	{ 0x1b, 0x03, 0x20 } },
			{ "43.213.53.83",	90,	{ 0xe5, 0x6f, 0x68 } },
		};
		lws_sockaddr46 sin, other;
		lws_dht_hash_t *h;
		size_t n;

		memset(&other, 0, sizeof(other));
		lws_sa46_parse_numeric_address("8.8.8.8", &other);

		for (n = 0; n < LWS_ARRAY_SIZE(v); n++) {
			memset(&sin, 0, sizeof(sin));
			if (lws_sa46_parse_numeric_address(v[n].ip, &sin)) {
				lwsl_err("bep42: cannot parse %s\n", v[n].ip);
				fails++;
				continue;
			}
			h = lws_dht_bep42_id(context, (struct sockaddr *)&sin, v[n].r,
					     LWS_DHT_HASH_TYPE_SHA1, 20);
			if (!h) {
				lwsl_err("bep42: no id for %s\n", v[n].ip);
				fails++;
				continue;
			}
			if (h->id[0] != v[n].pre[0] || h->id[1] != v[n].pre[1] ||
			    (h->id[2] & 0xf8) != v[n].pre[2] || h->id[19] != v[n].r) {
				lwsl_err("bep42: %s r %u: %02x%02x%02x..%02x\n",
					 v[n].ip, v[n].r, h->id[0], h->id[1],
					 h->id[2], h->id[19]);
				fails++;
			}
			if (!lws_dht_bep42_check(h, (struct sockaddr *)&sin)) {
				lwsl_err("bep42: own derivation fails check\n");
				fails++;
			}
			if (lws_dht_bep42_check(h, (struct sockaddr *)&other)) {
				lwsl_err("bep42: id passes for another address\n");
				fails++;
			}
			lws_dht_hash_destroy(&h);
		}
	}

	lws_context_destroy(context);

	if (fails)
		lwsl_user("Completed with %d failed checks\n", fails);
	else
		lwsl_user("Completed with no failed checks\n");

	return fails ? 1 : 0;
}
