/*
 * lws fuzz target: lecp CBOR parser
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The whole input is passed to the parser in two chunks at a random-ish
 * split, so both single-shot and partial-input parser states get coverage.
 */

#include <libwebsockets.h>
#include <stdlib.h>

/*
 * Fuzzing means constantly feeding the parser garbage, so its rejection
 * logs are expected noise that dominates the runtime.  Set LWS_FUZZ_VERBOSE=1
 * to get them back (eg, when replaying a crash artifact).
 */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	return 0;
}

static const char * const paths[] = {
	"schema",
	"targets[].name",
	"x.*",
};

static signed char
cb(struct lecp_ctx *ctx, char reason)
{
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lecp_ctx ctx;
	size_t half = size / 2;

	lecp_construct(&ctx, cb, NULL, paths, LWS_ARRAY_SIZE(paths));

	lecp_parse(&ctx, data, half);
	lecp_parse(&ctx, data + half, size - half);

	lecp_destruct(&ctx);

	return 0;
}
