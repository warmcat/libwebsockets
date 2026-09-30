/*
 * lws-api-test-ss-policy
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Confirms that a JSON Secure Streams policy the parser rejects is thrown
 * away cleanly, and leaves the policy that was in force before it alone.
 *
 * The context starts with the policy given by -c.  Then documents the parser
 * must reject are fed to it, the way the fetch_policy system stream feeds a
 * policy from the network, and as overlays.  Each one defines at least one
 * cert before the part that gets it rejected, since the X.509 objects are
 * what the abandon path walks.  After each one, the original streamtypes must
 * still be there and nothing from the rejected document may be.  The
 * original tls server streamtype must still come up with its cert and key
 * after all that.  A streamtype with more metadata than the policy can count,
 * or a metadata value longer than the policy can hold, must be refused.  A
 * valid document must still parse, and its metadata value that is longer
 * than one lejp string chunk must still become one metadata item.
 *
 * Build with ASan to see the teardown is clean.
 */

#include <libwebsockets.h>
#include <string.h>

enum {
	LWS_SW_POLICY,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_POLICY]	= { "-c",	"Path to the JSON policy to start with" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

/*
 * Documents the parser must reject, each after it has already created at
 * least one X.509 object
 */

static const char * const rejected[] = {

	/* a trust store naming a cert that does not exist */

	"{\"certs\": [{\"t_a\": \"AAAA\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_nope\"]}],"
	 "\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\"}}]}",

	/* a trust store stack before its name */

	"{\"certs\": [{\"t_a\": \"AAAA\"}],"
	 "\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\"}}],"
	 "\"trust_stores\": [{\"stack\": [\"t_a\"], \"name\": \"t_ts\"}]}",

	/* a server streamtype naming a cert that does not exist */

	"{\"certs\": [{\"t_a\": \"AAAA\"}],"
	 "\"s\": [{\"t_srv\": {\"server\": true, \"server_cert\": \"t_nope\"}}]}",

	/*
	 * a server streamtype taking its cert and key, so they are kept for
	 * the server, and then a trust store naming a cert that does not exist
	 */

	"{\"certs\": [{\"t_a\": \"AAAA\"}, {\"t_b\": \"AAAA\"}],"
	 "\"s\": [{\"t_srv\": {\"server\": true, \"server_cert\": \"t_a\","
				"\"server_key\": \"t_b\"}}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_nope\"]}]}",
};

/* a document that ends partway through a cert, the connection dropped */

static const char truncated[] =
	"{\"certs\": [{\"t_a\": \"AAAA\"}, {\"t_b\": \"AAAA";

/*
 * A valid document, whose one metadata value is given at run time, so it can
 * be longer than a lejp string chunk
 */

static const char valid_fmt[] =
	"{\"retry\": [{\"t_retry\": {\"backoff\": [1000, 2000]}}],"
	 "\"certs\": [{\"t_a\": \"AAAA\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_a\"]}],"
	 "\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\", \"port\": 1,"
			"\"protocol\": \"h1\", \"retry\": \"t_retry\","
			"\"metadata\": [{\"t_md\": \"%s\"}]}}]}";

/*
 * The policy metadata value length is a uint8_t, and a streamtype can have
 * at most 255 metadata
 */

#define MAX_MD_VALUE		255
#define MAX_MD			255

static char doc[8192];

/* a document whose streamtype has count metadata items */

static const char *
doc_md_count(int count)
{
	char *p = doc, *end = doc + sizeof(doc);
	int n;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\","
			  "\"metadata\": [");
	for (n = 0; n < count; n++)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s{\"t_md%d\": \"\"}", n ? "," : "", n);
	lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}}]}");

	return doc;
}

static int
is_valid_md_value(const void *v)
{
	const char *p = (const char *)v;
	int n;

	for (n = 0; n < MAX_MD_VALUE; n++)
		if (p[n] != 'v')
			return 0;

	return !p[n];
}

/* the valid document, with a metadata value of len bytes */

static const char *
doc_valid(size_t len)
{
	char val[MAX_MD_VALUE + 2];

	memset(val, 'v', len);
	val[len] = '\0';
	lws_snprintf(doc, sizeof(doc), valid_fmt, val);

	return doc;
}

typedef struct myss {
	struct lws_ss_handle		*ss;
	void				*opaque_data;
} myss_t;

static lws_ss_state_return_t
myss_state(void *userobj, void *sh, lws_ss_constate_t state,
	   lws_ss_tx_ordinal_t ack)
{
	/* nothing is nailed up and we never ask to send, so no connection */

	return LWSSSSRET_OK;
}

static int
streamtype_exists(struct lws_context *cx, const char *streamtype)
{
	struct lws_ss_handle *h;
	lws_ss_info_t ssi;

	memset(&ssi, 0, sizeof(ssi));
	ssi.handle_offset		= offsetof(myss_t, ss);
	ssi.opaque_user_data_offset	= offsetof(myss_t, opaque_data);
	ssi.state			= myss_state;
	ssi.user_alloc			= sizeof(myss_t);
	ssi.streamtype			= streamtype;

	if (lws_ss_create(cx, 0, &ssi, NULL, &h, NULL, NULL))
		return 0;

	lws_ss_destroy(&h);

	return 1;
}

/*
 * The policy we started with must still be the one in force, and nothing
 * from the rejected document may have leaked into it
 */

static int
original_in_force(struct lws_context *cx, const char *what)
{
	if (!streamtype_exists(cx, "polt_cli")) {
		lwsl_err("%s: original streamtype gone\n", what);
		return 0;
	}

	if (streamtype_exists(cx, "t_cli") || streamtype_exists(cx, "t_srv")) {
		lwsl_err("%s: rejected streamtype is visible\n", what);
		return 0;
	}

	return 1;
}

/*
 * Feed a whole document the way the fetch_policy system stream feeds the
 * policy it fetched, as a replacement for the policy in force
 */

static int
fetched(struct lws_context *cx, const char *doc)
{
	if (lws_ss_policy_parse_begin(cx, 0))
		return LEJP_REJECT_UNKNOWN;

	return lws_ss_policy_parse(cx, (const uint8_t *)doc, strlen(doc));
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const lws_ss_policy_t *pol;
	struct lws_context *cx;
	const char *policy;
	int result = 1, n, m;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	policy = lws_cmdline_option(argc, argv, switches[LWS_SW_POLICY].sw);
	if (!policy) {
		lwsl_err("-c <policy JSON path> is required\n");
		return 1;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: SS policy rejection\n");

	info.options		= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
				  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json	= policy;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!original_in_force(cx, "start"))
		goto bail;

	/* rejected documents, as if fetched from the network */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(rejected); n++) {
		m = fetched(cx, rejected[n]);
		if (m == LEJP_CONTINUE || m >= 0) {
			lwsl_err("fetched %d: not rejected (%d)\n", n, m);
			lws_ss_policy_parse_abandon(cx);
			goto bail;
		}
		if (!original_in_force(cx, "fetched"))
			goto bail;
	}

	/*
	 * A document that stops partway through, the fetch then abandons it
	 * on the disconnect, and perhaps again on the stream destroy
	 */

	m = fetched(cx, truncated);
	if (m != LEJP_CONTINUE) {
		lwsl_err("truncated: unexpected %d\n", m);
		goto bail;
	}
	if (lws_ss_policy_parse_abandon(cx) ||
	    lws_ss_policy_parse_abandon(cx) ||
	    !original_in_force(cx, "truncated"))
		goto bail;

	/* the same rejected documents as overlays on the live policy */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(rejected); n++) {
		m = lws_ss_policy_overlay(cx, rejected[n]);
		if (m == LEJP_CONTINUE || m >= 0) {
			lwsl_err("overlay %d: not rejected (%d)\n", n, m);
			lws_ss_policy_parse_abandon(cx);
			goto bail;
		}
		if (!original_in_force(cx, "overlay"))
			goto bail;
	}

	/*
	 * Some of the rejected documents kept server certs before failing.
	 * Throwing those away must not have taken the DER of the original
	 * policy's server cert and key with it: its tls server streamtype
	 * must still come up
	 */

	if (!streamtype_exists(cx, "polt_srv")) {
		lwsl_err("server: original tls server streamtype unusable\n");
		goto bail;
	}

	/*
	 * One metadata more than the count can hold, and a metadata value one
	 * byte longer than its length can hold, must be refused
	 */

	m = fetched(cx, doc_md_count(MAX_MD + 1));
	if (m == LEJP_CONTINUE || m >= 0) {
		lwsl_err("metadata count: not rejected (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	if (!original_in_force(cx, "metadata count"))
		goto bail;

	m = fetched(cx, doc_valid(MAX_MD_VALUE + 1));
	if (m == LEJP_CONTINUE || m >= 0) {
		lwsl_err("metadata value: not rejected (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	if (!original_in_force(cx, "metadata value"))
		goto bail;

	/* ... but as many as the count can hold is fine */

	m = fetched(cx, doc_md_count(MAX_MD));
	if (m == LEJP_CONTINUE || m < 0) {
		lwsl_err("metadata count: max not accepted (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	pol = lws_ss_policy_get(cx);
	n = pol ? pol->metadata_count : -1;
	lws_ss_policy_parse_abandon(cx);
	if (n != MAX_MD) {
		lwsl_err("metadata count: %d, not %d\n", n, MAX_MD);
		goto bail;
	}

	/*
	 * After all that, a valid document must still parse.  Its metadata
	 * value is longer than a lejp string chunk, so it arrives in pieces,
	 * but it must still be one metadata item with the whole value
	 */

	m = fetched(cx, doc_valid(MAX_MD_VALUE));
	if (m == LEJP_CONTINUE || m < 0) {
		lwsl_err("valid: not accepted (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	pol = lws_ss_policy_get(cx);
	if (!pol || strcmp(pol->streamtype, "t_cli")) {
		lwsl_err("valid: parsed policy lacks its streamtype\n");
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	if (pol->metadata_count != 1 || !pol->metadata ||
	    strcmp(pol->metadata->name, "t_md") ||
	    pol->metadata->value_length != MAX_MD_VALUE ||
	    !is_valid_md_value(pol->metadata->value__may_own_heap)) {
		lwsl_err("valid: long metadata value is not one whole item\n");
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}

	/* ... and giving it up must put the original back too */

	if (lws_ss_policy_parse_abandon(cx) ||
	    !original_in_force(cx, "valid abandoned"))
		goto bail;

	result = 0;

bail:
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
