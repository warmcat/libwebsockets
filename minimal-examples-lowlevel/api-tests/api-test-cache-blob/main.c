/*
 * lws-api-test-cache-blob
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * Made available under the Creative Commons CC0 1.0 Universal Public Domain
 * Dedication.
 *
 * Tests the file-backed blob lws-cache-ttl level: write-through, gets from
 * the backing files, invalidation, per-item expiry, per-item payload size
 * cap, and that the background sul maintenance incrementally brings the
 * store under its size limit without ever blocking the event loop.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

enum {
	LWS_SW_SCRATCH,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_SCRATCH]	= { "--scratch",	"Directory to use for the cache files" },
	[LWS_SW_D]		= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

static int checks, fails, phase_done;

static struct lws_context *cx;
static struct lws_cache_ttl_lru *blob, *l1;
static lws_sorted_usec_list_t sul_wait;

static const char *scratch = "./cache-blob-scratch";

/* the cache limit used for the trim test */

#define TEST_LIMIT_BYTES		(192 * 1024)
#define TEST_MAX_PAYLOAD		(64 * 1024)

static uint8_t payload[80 * 1024];

#define CHK(_cond, _fmt, ...) do { \
	checks++; \
	if (!(_cond)) { \
		fails++; \
		lwsl_user("FAIL L%d: " _fmt "\n", __LINE__, ##__VA_ARGS__); \
	} \
} while (0)

static void
sul_wait_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	phase_done = 1;
}

/* service the loop until sul_wait_cb fires, ms from now */

static void
wait_ms(int ms)
{
	phase_done = 0;
	lws_sul_schedule(cx, 0, &sul_wait, sul_wait_cb,
			 (lws_usec_t)ms * LWS_US_PER_MS);

	while (!phase_done)
		if (lws_service(cx, 0) < 0)
			break;
}

/*
 * lws_dir is non-recursive: this callback recurses into subdirs itself and
 * totals the size of regular files it finds
 */

static int
dir_walk_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	uint64_t *total = (uint64_t *)user;
	struct stat s;
	char path[384];

	if (lde->type == LDOT_DIR) {
		lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
		lws_dir(path, user, dir_walk_cb);

		return 0;
	}

	if (lde->type != LDOT_FILE)
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	if (!stat(path, &s) && S_ISREG(s.st_mode))
		*total += (uint64_t)s.st_size;

	return 0;
}

/* total bytes of files currently in the cache dir */

static uint64_t
cache_bytes(void)
{
	uint64_t total = 0;

	lws_dir(scratch, &total, dir_walk_cb);

	return total;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const void *data;
	size_t size;
	uint64_t was;
	const char *p;
	time_t start;
	int n;

	if ((argc == 1) || lws_cmdline_option(argc, argv,
						switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SCRATCH].sw)))
		scratch = p;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);

	for (n = 0; n < (int)sizeof(payload); n++)
		payload[n] = (uint8_t)(n ^ 0x5a);

	/*
	 * Part 1: write-through, get from the file store, invalidate
	 */

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_user("%s: no context\n", __func__);
		goto bail;
	}

	{
		struct lws_cache_creation_info ci;

		/* outermost level: the file-backed blob store */

		memset(&ci, 0, sizeof(ci));
		ci.cx			= cx;
		ci.ops			= &lws_cache_ops_blob;
		ci.name			= "TESTBLOB";
		ci.u.blob.dir		= scratch;
		ci.max_footprint	= TEST_LIMIT_BYTES;
		ci.max_payload		= TEST_MAX_PAYLOAD;

		blob = lws_cache_create(&ci);
		CHK(blob != NULL, "unable to create blob cache");

		/* then the heap L1 on top of it, like the context does */

		memset(&ci, 0, sizeof(ci));
		ci.cx			= cx;
		ci.ops			= &lws_cache_ops_heap;
		ci.name			= "TESTL1";
		ci.parent		= blob;
		ci.max_footprint	= 1024 * 1024;
		ci.max_items		= 64;
		ci.max_payload		= TEST_MAX_PAYLOAD;

		l1 = lws_cache_create(&ci);
		CHK(l1 != NULL, "unable to create L1 cache");

		if (!blob || !l1)
			goto bail;
	}

	CHK(!lws_cache_write_through(l1, "https://example.com/a.png", payload,
				     48 * 1024,
				     lws_now_usecs() + 3600 * LWS_US_PER_SEC,
				     NULL), "write_through failed");

	CHK(cache_bytes() >= 48 * 1024, "no cache file appeared on disk");

	CHK(!lws_cache_item_get(l1, "https://example.com/a.png",
				&data, &size), "get after write failed");
	CHK(size == 48 * 1024, "got size %u, expected %u",
	    (unsigned int)size, 48 * 1024);
	CHK(data && !memcmp(data, payload, size), "payload mismatch");

	/* the payload pointer is only valid until the event loop: wait */

	wait_ms(10);

	CHK(!lws_cache_item_get(l1, "https://example.com/a.png",
				&data, &size), "get after wait failed");
	CHK(size == 48 * 1024, "got size %u after wait", (unsigned int)size);

	was = cache_bytes();

	CHK(!lws_cache_item_remove(l1, "https://example.com/a.png"),
				    "remove failed");
	CHK(lws_cache_item_get(l1, "https://example.com/a.png",
			       &data, &size), "get after remove should miss");
	CHK(cache_bytes() < was, "file not removed from disk");

	/*
	 * Part 2: items past their expiry are refused and dropped
	 */

	CHK(!lws_cache_write_through(l1, "https://example.com/short.png",
				     payload, 2048,
				     lws_now_usecs() + 400 * LWS_US_PER_MS,
				     NULL), "write short-life item failed");

	CHK(!lws_cache_item_get(l1, "https://example.com/short.png",
				&data, &size), "get of fresh short item failed");

	wait_ms(600);

	CHK(lws_cache_item_get(l1, "https://example.com/short.png",
			       &data, &size),
			       "get of expired item should miss");
	CHK(cache_bytes() == 0, "expired item file not dropped");

	/*
	 * Part 3: items over the level payload cap are not stored
	 */

	CHK(lws_cache_write_through(l1, "https://example.com/big.png",
				    payload, TEST_MAX_PAYLOAD + 1,
				    lws_now_usecs() + 3600 * LWS_US_PER_SEC,
				    NULL), "oversize write_through should fail");
	CHK(cache_bytes() == 0, "oversize item should leave nothing on disk");

	/*
	 * Part 4: the background maintenance brings the store under its size
	 * limit incrementally on the event loop
	 */

	for (n = 0; n < 8; n++) {
		char key[64];

		lws_snprintf(key, sizeof(key), "https://example.com/t%d.png", n);
		CHK(!lws_cache_write_through(l1, key, payload, 48 * 1024,
					     lws_now_usecs() +
						     3600 * LWS_US_PER_SEC,
					     NULL), "write t%d failed", n);
	}

	CHK(cache_bytes() > TEST_LIMIT_BYTES,
	    "expected to start oversize (%llu bytes)",
	    (unsigned long long)cache_bytes());

	/* each wait_ms() pass services the maintenance suls */

	start = time(NULL);
	while (cache_bytes() > TEST_LIMIT_BYTES) {
		if (time(NULL) - start > 90) {
			lwsl_user("trim did not converge: %llu bytes after 90s\n",
				  (unsigned long long)cache_bytes());
			break;
		}
		wait_ms(500);
	}

	CHK(cache_bytes() <= TEST_LIMIT_BYTES,
	    "cache did not come under limit: %llu bytes",
	    (unsigned long long)cache_bytes());

	/*
	 * Part 5: expunge clears the store
	 */

	CHK(!lws_cache_expunge(l1), "expunge failed");
	CHK(cache_bytes() == 0, "expunge left files behind");
	CHK(lws_cache_item_get(l1, "https://example.com/t7.png",
			       &data, &size), "get after expunge should miss");

	lws_cache_destroy(&l1);
	lws_cache_destroy(&blob);

	lws_context_destroy(cx);

bail:
	lwsl_user("Completed: %s (%d checks, %d fail)\n",
		  fails ? "FAIL" : "PASS", checks, fails);

	return !!fails;
}
