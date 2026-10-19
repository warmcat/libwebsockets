/*
 * lws-api-test-webrtc-mixer-signal
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Runs the webrtc mixer plugin's handling of the set_control message one
 * peer addresses at another (plugins/protocol_lws_webrtc_mixer/
 * mixer-signal.c).  The mixer used to relay the sender's bytes to the target
 * as they came; it picked the type from the first "type" in them, while the
 * target's JSON.parse() keeps the last, so the room controller could send
 * any server message (a WebRTC answer, say) to any participant.  Now the
 * message is parsed strictly and the target gets one the mixer composed.
 *
 * Covered behaviours:
 *
 *  - set_control as the browser sends it (control id as a string) and with
 *    numeric ids, extreme values and whitespace, is accepted
 *  - the message composed for the target has one "type", "set_control", and
 *    carries only the parsed members and the sender's id
 *  - a second "type", plain or spelled with escapes, is refused
 *  - any other duplicated member is refused
 *  - unknown members, nested objects, arrays, and trailing input after the
 *    object are refused
 *  - a missing member, or one of the wrong kind or out of range, is refused
 *  - a too-small buffer for the composed message fails cleanly
 */

#include <libwebsockets.h>

#include <string.h>

#include "mixer-signal.h"

static int fails, oks;

struct msc_good {
	const char			*json;
	const char			*target;
	enum mixer_control_kind		kind;
	uint32_t			id;
	int32_t				val;
};

static const struct msc_good good[] = {
	{ /* as main.js sends it: the control id is a string */
		"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
		"\"id\":\"9963776\",\"val\":5}",
		"u2", MIXER_CONTROL_VIDEO, 9963776, 5
	},
	{
		"{ \"val\" : -2147483648 , \"id\" : 4294967295, "
		"\"kind\":\"audio\", \"target\":\"u17\", \"type\" : \"set_control\" }",
		"u17", MIXER_CONTROL_AUDIO, 4294967295u, INT32_MIN
	},
	{
		"{\"type\":\"set_control\",\"target\":\"u1\",\"kind\":\"video\","
		"\"id\":0,\"val\":2147483647}",
		"u1", MIXER_CONTROL_VIDEO, 0, INT32_MAX
	},
};

static const char * const bad[] = {
	/* the G-264 forgery: a set_control to the mixer, an answer to JSON.parse */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"type\":\"answer\"}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"type\":\"answer\",\"sdp\":\"v=0\\r\\n\"}",
	/* ... with the second type's name spelled with escapes */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"t\\u0079pe\":\"answer\"}",
	/* ... or the set_control hidden in a nested object */
	"{\"x\":{\"type\":\"set_control\"},\"type\":\"answer\","
	"\"target\":\"u2\",\"kind\":\"video\",\"id\":1,\"val\":1}",
	/* other duplicates */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"target\":\"u3\","
	"\"kind\":\"video\",\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"val\":2}",
	/* unknown members */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"candidate\":{}}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1,\"a.b\":1}",
	/* not one flat object, using all the input */
	"[{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}]",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":[1]}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}{\"type\":\"answer\"}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1",
	/* a member missing */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1}",
	"{\"target\":\"u2\",\"kind\":\"video\",\"id\":1,\"val\":1}",
	/* wrong type */
	"{\"type\":\"answer\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}",
	"{\"type\":\"set_controls\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}",
	/* member values of the wrong kind or out of range */
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"screen\","
	"\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u23456789012345678901234\","
	"\"kind\":\"video\",\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":2,\"kind\":\"video\","
	"\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u\\u00002\",\"kind\":\"video\","
	"\"id\":1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":4294967296,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":-1,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":\"0x10\",\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":\"01\",\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":true,\"val\":1}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":2147483648}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":-2147483649}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":1.5}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":\"5\"}",
	"{\"type\":\"set_control\",\"target\":\"u2\",\"kind\":\"video\","
	"\"id\":1,\"val\":null}",
	"",
};

/* how many times `needle` appears in `hay` */
static int
count(const char *hay, const char *needle)
{
	size_t nl = strlen(needle);
	int n = 0;

	while ((hay = strstr(hay, needle))) {
		n++;
		hay += nl;
	}

	return n;
}

static int
test_good(const struct msc_good *g)
{
	struct mixer_set_control sc;
	char out[160], exp[160];
	size_t al;
	const char *v;
	int n;

	if (mixer_set_control_parse(g->json, strlen(g->json), &sc)) {
		lwsl_err("refused: %s\n", g->json);
		return 1;
	}

	if (strcmp(sc.target, g->target) || sc.kind != g->kind ||
	    sc.id != g->id || sc.val != g->val) {
		lwsl_err("misparsed: %s\n", g->json);
		return 1;
	}

	n = mixer_set_control_compose(out, sizeof(out), "u1", &sc);
	if (n <= 0 || (size_t)n != strlen(out)) {
		lwsl_err("compose failed: %s\n", g->json);
		return 1;
	}

	lws_snprintf(exp, sizeof(exp), "{\"type\":\"set_control\",\"from\":\"u1\","
		     "\"kind\":\"%s\",\"id\":%u,\"val\":%d}",
		     g->kind == MIXER_CONTROL_AUDIO ? "audio" : "video",
		     (unsigned int)g->id, (int)g->val);
	if (strcmp(out, exp)) {
		lwsl_err("composed '%s', expected '%s'\n", out, exp);
		return 1;
	}

	/* whoever reads it, it has one type, and that is set_control */
	v = lws_json_simple_find(out, (size_t)n, "\"type\":", &al);
	if (count(out, "type") != 1 || !v || al != 11 ||
	    strncmp(v, "set_control", 11)) {
		lwsl_err("composed message has the wrong type: %s\n", out);
		return 1;
	}

	/* the composed message is itself a valid set_control... except it has
	 * "from" and no "target", so it must not parse as a peer's one */
	if (!mixer_set_control_parse(out, (size_t)n, &sc)) {
		lwsl_err("composed message parsed as a peer set_control\n");
		return 1;
	}

	return 0;
}

static int
test_bad(const char *json)
{
	struct mixer_set_control sc;

	memset(&sc, 0x5a, sizeof(sc));

	if (!mixer_set_control_parse(json, strlen(json), &sc)) {
		lwsl_err("accepted: %s\n", json);
		return 1;
	}

	/* nothing half-parsed is left behind */
	if (sc.target[0] || sc.id || sc.val) {
		lwsl_err("left parsed state behind: %s\n", json);
		return 1;
	}

	return 0;
}

static int
test_limits(void)
{
	static const char *j = "{\"type\":\"set_control\",\"target\":\"u2\","
			       "\"kind\":\"video\",\"id\":1,\"val\":1}";
	struct mixer_set_control sc;
	char big[600], out[32];

	/* too small a buffer for the composed message */
	if (mixer_set_control_parse(j, strlen(j), &sc) ||
	    mixer_set_control_compose(out, sizeof(out), "u1", &sc) != -1 ||
	    mixer_set_control_compose(out, 0, "u1", &sc) != -1) {
		lwsl_err("compose into a small buffer\n");
		return 1;
	}

	/* nothing legitimate is anywhere near this long */
	memset(big, ' ', sizeof(big));
	memcpy(big, j, strlen(j));
	if (!mixer_set_control_parse(big, sizeof(big), &sc)) {
		lwsl_err("accepted an overlong message\n");
		return 1;
	}

	/* NULL or empty input */
	if (!mixer_set_control_parse(NULL, 10, &sc) ||
	    !mixer_set_control_parse(j, 0, &sc)) {
		lwsl_err("accepted no input\n");
		return 1;
	}

	return 0;
}

static void
result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

int
main(int argc, const char **argv)
{
	size_t n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: webrtc mixer set_control\n");

	for (n = 0; n < LWS_ARRAY_SIZE(good); n++)
		result("good", test_good(&good[n]));

	for (n = 0; n < LWS_ARRAY_SIZE(bad); n++)
		result("bad", test_bad(bad[n]));

	result("limits", test_limits());

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
