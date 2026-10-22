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
 * or a metadata value longer than the policy can hold, must be refused, as
 * must members outside the object they belong to (eg, a key with a '.' in
 * it making a member path with no streamtype open).  A
 * valid document must still parse, and its metadata value that is longer
 * than one lejp string chunk must still become one metadata item.  An
 * overlay may only override streamtypes that exist, a completed one leaves
 * no parse behind, and a truncated one is refused.  A policy that ends
 * partway through, as JSON or in the file given by -t, is never installed.
 * A parse still pending when the context is destroyed must be cleaned up by
 * it.
 *
 * Build with ASan to see the teardown is clean.
 */

#include <libwebsockets.h>
#include <string.h>

enum {
	LWS_SW_POLICY,
	LWS_SW_TRUNCATED,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_POLICY]		= { "-c",	"Path to the JSON policy to start with" },
	[LWS_SW_TRUNCATED]	= { "-t",	"Path to a JSON policy that ends partway through" },
	[LWS_SW_HELP]		= { "--help",	"Show this help information" },
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

	/* a trust store naming only the start of a cert name */

	"{\"certs\": [{\"t_abc\": \"AAAA\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_a\"]}]}",

	/* a trust store naming an empty cert name */

	"{\"certs\": [{\"t_abc\": \"AAAA\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"\"]}]}",

	/* a cert with no DER, or whose value is not a string */

	"{\"certs\": [{\"t_a\": \"AAAA\"}, {\"t_b\": \"\"}]}",
	"{\"certs\": [{\"t_a\": \"AAAA\"}, {\"t_b\": {}}]}",
};

/*
 * Documents whose members are not inside the object they belong to.  lejp
 * joins keys with '.' into the path it matches, so a key with a '.' in it can
 * make a member path without its streamtype, backoff scheme or auth ever
 * being opened, or name one opened earlier.  Each must be refused, not write
 * through NULL or into the earlier object.
 */

static const char * const malformed[] = {

	/* streamtype / backoff member keys with nothing open */

	"{\"s\": [{\"t_cli.port\": 1}]}",
	"{\"s\": [{\"polt_cli.endpoint\": \"t_evil\"}]}",
	"{\"retry\": [{\"t_retry.conceal\": 1}]}",

	/* ... naming a streamtype / backoff from earlier in the document */

	"{\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\"}},"
		"{\"t_cli.endpoint\": \"t_evil\"}]}",
	"{\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\"},"
		"\"t_cli.endpoint\": \"t_evil\"}]}",
	"{\"retry\": [{\"t_retry\": {\"backoff\": [1000]}},"
		"{\"t_retry.conceal\": 1}]}",

	/* member paths made by a top-level key */

	"{\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\"}}],"
		"\"s[].t_cli.port\": 1}",
	"{\"s[].t_cli.http_resp_map[].200\": 1}",
	"{\"auth[].name\": \"t_auth\"}",

	/* a streamtype name its members' paths would not match */

	"{\"s\": [{\"t.cli\": {\"endpoint\": \"localhost\"}}]}",

	/* a cert whose value is not a string */

	"{\"certs\": [{\"t_a\": [{\"t_b\": \"AAAA\"}, \"AAAA\"]}]}",
	"{\"certs\": [{\"t_a\": {\"t_b\": \"AAAA\"}}]}",
	"{\"certs\": [{\"t_a\": 1}]}",

	/* a trust store element with no name, after one with a name */

	"{\"certs\": [{\"t_a\": \"AAAA\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_a\"]},"
			   "{\"stack\": [\"t_a\"]}]}",
};

/*
 * A valid document with shapes near those: a cert and a metadata name may
 * contain '.', a certs[] element can hold more than one cert, an unknown streamtype member (with members of the same names
 * as real ones inside it) is ignored, and each streamtype has its own options
 * and response map
 */

static const char valid_shapes[] =
	"{\"retry\": [{\"t_retry\": {\"backoff\": [1000, 2000],"
				"\"conceal\": 3}}],"
	 "\"auth\": [{\"name\": \"t_auth\", \"type\": \"sigv4\","
		    "\"streamtype\": \"t_two\", \"blob\": 1}],"
	 "\"certs\": [{\"t.a\": \"AAAA\", \"t_b\": \"AAAB\"}],"
	 "\"trust_stores\": [{\"name\": \"t_ts\","
			    "\"stack\": [\"t.a\", \"t_b\"]}],"
	 "\"s\": [{\"t_one\": {\"endpoint\": \"one\","
				"\"t_unknown\": {\"port\": 2},"
				"\"port\": 1, \"tls_trust_store\": \"t_ts\","
				"\"retry\": \"t_retry\","
				"\"metadata\": [{\"t.md\": \"\"}],"
				"\"http_resp_map\": [{\"530\": 1}],"
				"\"options\": [{\"t_o1\": \"1\"}]}},"
		 "{\"t_two\": {\"endpoint\": \"two\","
				"\"options\": [{\"t_o2\": \"2\"}]}}]}";

/*
 * Overlays that define something of their own instead of overriding an
 * existing streamtype: a new streamtype, a cert, a trust store, a backoff
 * scheme, an auth
 */

static const char * const overlay_rejected[] = {
	"{\"s\": [{\"t_new\": {\"endpoint\": \"localhost\"}}]}",
	"{\"certs\": [{\"t_a\": \"AAAA\"}]}",
	"{\"trust_stores\": [{\"name\": \"t_ts\", \"stack\": [\"t_a\"]}]}",
	"{\"retry\": [{\"t_retry\": {\"backoff\": [1000]}}]}",
	"{\"auth\": [{\"name\": \"t_auth\", \"type\": \"sigv4\"}]}",
};

/* an overlay that overrides a streamtype the policy already has */

static const char overlay_ok[] =
	"{\"s\": [{\"polt_cli\": {\"endpoint\": \"overlay.invalid\"}}]}";

/* a document that ends partway through a cert, the connection dropped */

static const char truncated[] =
	"{\"certs\": [{\"t_a\": \"AAAA\"}, {\"t_b\": \"AAAA";

/*
 * A policy that ends partway through a streamtype, after its endpoint and port
 * but before whatever was to follow, eg "tls": true
 */

static const char truncated_st[] =
	"{\"s\": [{\"t_cli\": {\"endpoint\": \"localhost\", \"port\": 443";

/* an overlay that ends partway through */

static const char overlay_truncated[] = "{\"s\": [{\"polt_cli\": {";

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

/* the parsed valid_shapes document has exactly what it says */

static int
valid_shapes_parsed(const lws_ss_policy_t *pol, const lws_ss_auth_t *auth)
{
	const lws_ss_policy_t *one = NULL, *two = NULL;
	int count = 0;

	for (; pol; pol = pol->next, count++)
		if (!strcmp(pol->streamtype, "t_one"))
			one = pol;
		else if (!strcmp(pol->streamtype, "t_two"))
			two = pol;

	if (count != 2 || !one || !two) {
		lwsl_err("shapes: %d streamtypes\n", count);
		return 0;
	}

	if (strcmp(one->endpoint, "one") || one->port != 1 ||
	    !one->trust.store || strcmp(one->trust.store->name, "t_ts") ||
	    one->trust.store->count != 2 ||
	    !one->trust.store->ssx509[0]->ca_der ||
	    one->trust.store->ssx509[0]->ca_der_len != 3 ||
	    !one->trust.store->ssx509[1]->ca_der ||
	    one->trust.store->ssx509[1]->ca_der_len != 3 ||
	    !one->metadata || strcmp(one->metadata->name, "t.md") ||
	    one->u.http.count_respmap != 1 || !one->retry_bo ||
	    one->retry_bo->retry_ms_table_count != 2 ||
	    one->retry_bo->conceal_count != 3 ||
	    !one->pvo || strcmp(one->pvo->name, "t_o1") || one->pvo->next) {
		lwsl_err("shapes: t_one members wrong\n");
		return 0;
	}

	if (strcmp(two->endpoint, "two") || !two->pvo ||
	    strcmp(two->pvo->name, "t_o2") || two->pvo->next) {
		lwsl_err("shapes: t_two members wrong\n");
		return 0;
	}

	if (!auth || auth->next || strcmp(auth->name, "t_auth") ||
	    strcmp(auth->type, "sigv4") || strcmp(auth->streamtype, "t_two") ||
	    auth->blob_index != 1) {
		lwsl_err("shapes: auth wrong\n");
		return 0;
	}

	return 1;
}

/*
 * A context whose policy ends partway through must not be created with
 * whatever part of the policy there was
 */

static int
incomplete_policy_refused(const struct lws_context_creation_info *ref,
			  const char *policy, const char *what)
{
	struct lws_context_creation_info info = *ref;
	struct lws_context *cx;

	info.pss_policies_json = policy;

	cx = lws_create_context(&info);
	if (!cx)
		return 1;

	lwsl_err("%s: context created with an incomplete policy\n", what);
	lws_context_destroy(cx);

	return 0;
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
	const char *policy, *policy_truncated;
	int result = 1, n, m;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	policy = lws_cmdline_option(argc, argv, switches[LWS_SW_POLICY].sw);
	policy_truncated = lws_cmdline_option(argc, argv,
					      switches[LWS_SW_TRUNCATED].sw);
	if (!policy || !policy_truncated) {
		lwsl_err("-c <policy JSON path> and -t <truncated policy JSON "
			 "path> are required\n");
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
	 * Overlays may only override streamtypes the policy already has: one
	 * defining a streamtype, cert, trust store, backoff scheme or auth of
	 * its own is rejected, and the live policy is still usable
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(overlay_rejected); n++) {
		m = lws_ss_policy_overlay(cx, overlay_rejected[n]);
		if (m == LEJP_CONTINUE || m >= 0) {
			lwsl_err("overlay_rejected %d: not rejected (%d)\n",
				 n, m);
			lws_ss_policy_parse_abandon(cx);
			goto bail;
		}
		if (!original_in_force(cx, "overlay_rejected"))
			goto bail;
	}

	/*
	 * Members outside the object they belong to are refused, fetched or
	 * as overlays, and the policy in force is left alone
	 */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(malformed); n++) {
		m = fetched(cx, malformed[n]);
		if (m == LEJP_CONTINUE || m >= 0) {
			lwsl_err("malformed %d: not rejected (%d)\n", n, m);
			lws_ss_policy_parse_abandon(cx);
			goto bail;
		}
		if (!original_in_force(cx, "malformed"))
			goto bail;

		m = lws_ss_policy_overlay(cx, malformed[n]);
		if (m == LEJP_CONTINUE || m >= 0) {
			lwsl_err("malformed overlay %d: not rejected (%d)\n",
				 n, m);
			lws_ss_policy_parse_abandon(cx);
			goto bail;
		}
		if (!original_in_force(cx, "malformed overlay"))
			goto bail;
	}

	/* ... while the valid shapes near them parse to what they say */

	m = fetched(cx, valid_shapes);
	if (m == LEJP_CONTINUE || m < 0) {
		lwsl_err("shapes: not accepted (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}
	n = valid_shapes_parsed(lws_ss_policy_get(cx), lws_ss_auth_get(cx));
	lws_ss_policy_parse_abandon(cx);
	if (!n || !original_in_force(cx, "shapes"))
		goto bail;

	/*
	 * An overlay that ends partway through is refused, rather than left
	 * pending as if more might come (the overlays below could then not
	 * begin)
	 */

	m = lws_ss_policy_overlay(cx, overlay_truncated);
	if (m == LEJP_CONTINUE || m >= 0) {
		lwsl_err("overlay_truncated: not rejected (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}

	/*
	 * A valid override completes, and a second one after it does too: a
	 * completed overlay leaves no parse behind to block the next (or to
	 * leak, under ASan)
	 */

	for (n = 0; n < 2; n++) {
		m = lws_ss_policy_overlay(cx, overlay_ok);
		if (m == LEJP_CONTINUE || m < 0) {
			lwsl_err("overlay_ok %d: failed (%d)\n", n, m);
			goto bail;
		}
		if (!original_in_force(cx, "overlay_ok"))
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

	/*
	 * A policy that ends partway through, given as JSON or in a file, must
	 * not be installed: a context whose policy it is fails to create
	 */

	if (!incomplete_policy_refused(&info, truncated_st, "truncated json") ||
	    !incomplete_policy_refused(&info, policy_truncated,
				       "truncated file"))
		goto bail;

	/*
	 * Leave a valid parse pending, as a fetched policy waiting to be set
	 * is, when the context is destroyed: the destroy must clean it up
	 */

	m = fetched(cx, doc_valid(1));
	if (m == LEJP_CONTINUE || m < 0) {
		lwsl_err("pending: not accepted (%d)\n", m);
		lws_ss_policy_parse_abandon(cx);
		goto bail;
	}

	result = 0;

bail:
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
