/*
 * lws fuzz target: lws native QPACK decoders (h3 header compression)
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The first input byte selects the decoder under test:
 *
 *   0x00: remainder is a header block for lws_qpack_decode_header_block()
 *   else: remainder is encoder stream input for
 *         lws_qpack_decode_encoder_stream()
 *
 * Both are untrusted peer input during h3 connections.  The dynamic table
 * is sized like ops-h3.c sizes it, and destroyed on the way out so leaks
 * are caught.
 */

#include <libwebsockets.h>
#include <string.h>
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

static int
hdr_cb(void *user, int name_idx, const char *name, size_t name_len,
       const char *value, size_t value_len)
{
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lws_qpack_stream_state state;
	struct lws_qpack_context qctx;

	if (!size)
		return 0;

	memset(&state, 0, sizeof(state));
	memset(&qctx, 0, sizeof(qctx));

	/* ops-h3.c sets this from LWS_QPACK_CAP_VAL before any decode */

	qctx.dyn_table.virtual_payload_limit = 4096;

	if (data[0]) {
		state.state = LQP_DEC_INSTRUCTION;
		lws_qpack_decode_encoder_stream(&state, &qctx,
						data + 1, size - 1);
	} else
		lws_qpack_decode_header_block(&state, &qctx, data + 1,
					      size - 1, hdr_cb, NULL);

	lws_qpack_destroy_dynamic_header(&qctx);

	return 0;
}
