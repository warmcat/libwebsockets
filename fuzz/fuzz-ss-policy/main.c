/*
 * lws fuzz target: the Secure Streams JSON policy parser
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A device fetches its policy from the operator's server (fetch-policy),
 * so the parser (lib/secure-streams/policy-json.c) takes it from the
 * network: its retry and backoff tables, x.509 certs and trust stores,
 * auth objects, server certs and every streamtype's protocol, metadata and
 * endpoint.
 *
 * The input is a policy, given to the parser in two chunks so the
 * partial-input states are reached too.  Only an input starting '{' is
 * used: a fetch marks its parse untrusted, which a harness can't, and the
 * parser takes the first chunk of a trusted one that isn't JSON as the path
 * of a file to read the policy from.
 *
 * A policy that parses to the end has what it built walked, every string and
 * metadata entry of every streamtype, for ASan to see each is still there.
 * Each input's parse is abandoned after, which frees it all and puts back
 * the policy in force before, none, so every input starts the same.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>

static struct lws_context *cx;
/* where the walk's sum goes, so it's done */
static volatile size_t fzp_sink;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct lws_context_creation_info info;

	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	cx = lws_create_context(&info);

	return cx ? 0 : 1;
}

static size_t
fzp_str(const char *s)
{
	return s ? strlen(s) : 0;
}

/* every streamtype the complete policy has, and its strings and metadata */
static size_t
fzp_walk(void)
{
	const lws_ss_policy_t *p = lws_ss_policy_get(cx);
	const lws_ss_metadata_t *md;
	const lws_ss_auth_t *a;
	size_t t = 0;

	for (; p; p = p->next) {
		t += fzp_str(p->streamtype) + fzp_str(p->endpoint) +
		     fzp_str(p->rideshare_streamtype) +
		     fzp_str(p->payload_fmt) + fzp_str(p->socks5_proxy);
		for (md = p->metadata; md; md = md->next)
			t += fzp_str(md->name) + md->length;
	}

	for (a = lws_ss_auth_get(cx); a; a = a->next)
		t += fzp_str(a->name) + fzp_str(a->type) + fzp_str(a->streamtype);

	return t;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t half = size / 2;
	int m;

	if (!size || data[0] != '{')
		return 0;

	if (lws_ss_policy_parse_begin(cx, 0))
		return 0;

	m = lws_ss_policy_parse(cx, data, half ? half : size);
	if (m == LEJP_CONTINUE && half)
		m = lws_ss_policy_parse(cx, data + half, size - half);

	/* a failed parse has abandoned itself, and there's nothing to walk */
	if (m >= 0)
		fzp_sink = fzp_walk();

	lws_ss_policy_parse_abandon(cx);

	return 0;
}
