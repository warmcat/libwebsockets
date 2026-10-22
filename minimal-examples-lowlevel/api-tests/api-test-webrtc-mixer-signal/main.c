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
 *
 * and the helpers for peer text the mixer echoes to the whole room in ws TEXT
 * frames, where a browser fails the connection on invalid UTF-8:
 *
 *  - mixer_json_str() takes valid UTF-8 values and refuses invalid, partial
 *    or NUL-holding ones, empty ones and ones that do not fit
 *  - a list composed with mixer_json_list_add() from names full of multibyte
 *    characters, into every buffer size, is always complete JSON and valid
 *    UTF-8, holding as many whole entries as fit
 *
 * and the gate spacing out what the mixer does room-wide for peers:
 *
 *  - mixer_gate_wait() allows the first time, then nothing until the
 *    interval is up, saying how long is left
 *  - used as the mixer uses it (act now, else once when the interval is up
 *    however many asked meanwhile), a peer asking every millisecond for a
 *    second gets about 1s / interval actions, and a lone request still gets
 *    one promptly
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

static const char * const text_ok[] = {
	"plain",
	"caf\xc3\xa9",
	"\xe2\x82\xac\xe2\x82\xac",
	"\xf0\x9f\x98\x80 1280x720 -> 640x360 @ 25fps (Good)",
};

static const char * const text_bad[] = {
	"\xe2\x82",			/* ends partway through a sequence */
	"a\x80",			/* stray continuation */
	"\xc0\xaf",			/* overlong '/' */
	"\xed\xa0\x80",			/* surrogate */
	"\xf4\x90\x80\x80",		/* past U+10FFFF */
	"\xff",
};

static int
test_text(void)
{
	char dest[16];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(text_ok); n++) {
		size_t l = strlen(text_ok[n]);
		char big[64];

		if (mixer_json_str(big, sizeof(big), text_ok[n], l) ||
		    strcmp(big, text_ok[n])) {
			lwsl_err("%s: refused ok %d\n", __func__, (int)n);
			return 1;
		}
	}

	for (n = 0; n < LWS_ARRAY_SIZE(text_bad); n++)
		if (!mixer_json_str(dest, sizeof(dest), text_bad[n],
				    strlen(text_bad[n]))) {
			lwsl_err("%s: accepted bad %d\n", __func__, (int)n);
			return 1;
		}

	/* NUL inside, empty, NULL, and exactly too long for dest */
	if (!mixer_json_str(dest, sizeof(dest), "a\0b", 3) ||
	    !mixer_json_str(dest, sizeof(dest), "", 0) ||
	    !mixer_json_str(dest, sizeof(dest), NULL, 3) ||
	    !mixer_json_str(dest, sizeof(dest), "0123456789abcdef", 16) ||
	    mixer_json_str(dest, sizeof(dest), "0123456789abcde", 15)) {
		lwsl_err("%s: limits\n", __func__);
		return 1;
	}

	return 0;
}

static signed char
list_cb(struct lejp_ctx *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return 0;
}

/*
 * Compose a client_list as the mixer does, for three participants whose
 * names are 21 x U+20AC, 63 bytes that do not fit the 64-byte escape buffer,
 * into every size of message buffer
 */
static int
test_list(void)
{
	char name[64], name_esc[64], ent[256], buf[600], *p, *end;
	struct lejp_ctx ctx;
	int i, n, m, ents, size, last = 0;
	unsigned char st;

	for (i = 0; i < 21; i++)
		memcpy(name + (i * 3), "\xe2\x82\xac", 3);
	name[63] = '\0';

	lws_json_purify(name_esc, name, sizeof(name_esc), NULL);

	for (size = 40; size <= (int)sizeof(buf); size++) {
		p = buf;
		end = buf + size;
		ents = 0;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "{\"type\":\"client_list\",\"clients\":[");

		for (i = 0; i < 3; i++) {
			n = lws_snprintf(ent, sizeof(ent),
					 "{\"id\":\"u%d\",\"name\":\"%s\"}",
					 i + 1, name_esc);
			if (mixer_json_list_add(&p, end, 3, &ents, ent,
						(size_t)n))
				break;
		}

		lws_snprintf(p, lws_ptr_diff_size_t(end, p), "]}");
		n = (int)strlen(buf);

		st = 0;
		if (lws_check_utf8(&st, (const unsigned char *)buf,
				   (size_t)n) || st) {
			lwsl_err("%s: size %d: invalid UTF-8\n", __func__, size);
			return 1;
		}

		lejp_construct(&ctx, list_cb, NULL, NULL, 0);
		m = lejp_parse(&ctx, (const unsigned char *)buf, n);
		lejp_destruct(&ctx);
		if (m) {
			lwsl_err("%s: size %d: not complete JSON: %s\n",
				 __func__, size, buf);
			return 1;
		}

		/* it holds whole entries, never fewer as there is more room */
		if (ents < last || count(buf, "\"id\"") != ents) {
			lwsl_err("%s: size %d: %d entries\n", __func__, size,
				 ents);
			return 1;
		}
		last = ents;
	}

	if (last != 3) {
		lwsl_err("%s: never fitted all three\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * The mixer's room_client_list_changed() / room_keyframe(): a request does
 * it at once if the gate allows, else arms a timer for when it will, unless
 * one is armed already.  Model the timer here, and count what gets done.
 */
struct gate_model {
	struct mixer_gate	g;
	lws_usec_t		armed;	/* when the timer fires, 0: not armed */
	int			done;
};

static void
gate_model_service(struct gate_model *m, lws_usec_t now)
{
	if (m->armed && now >= m->armed) {
		m->armed = 0;
		mixer_gate_mark(&m->g, now);
		m->done++;
	}
}

static void
gate_model_request(struct gate_model *m, lws_usec_t now)
{
	lws_usec_t wait;

	gate_model_service(m, now);
	if (m->armed)
		return;

	wait = mixer_gate_wait(&m->g, now);
	if (wait) {
		m->armed = now + wait;
		return;
	}

	mixer_gate_mark(&m->g, now);
	m->done++;
}

static int
test_gate(void)
{
	struct mixer_gate g = { 0, 250000 };
	struct gate_model m;
	lws_usec_t t, t0 = 1000000;

	/* never done: allowed at once */
	if (mixer_gate_wait(&g, t0)) {
		lwsl_err("%s: first refused\n", __func__);
		return 1;
	}
	mixer_gate_mark(&g, t0);

	if (mixer_gate_wait(&g, t0) != 250000 ||
	    mixer_gate_wait(&g, t0 + 100000) != 150000 ||
	    mixer_gate_wait(&g, t0 + 249999) != 1 ||
	    mixer_gate_wait(&g, t0 + 250000) ||
	    mixer_gate_wait(&g, t0 + 5000000)) {
		lwsl_err("%s: spacing\n", __func__);
		return 1;
	}

	/* a peer asking every ms for 1s */
	memset(&m, 0, sizeof(m));
	m.g.interval = 250000;
	for (t = t0; t < t0 + 1000000; t += 1000)
		gate_model_request(&m, t);
	gate_model_service(&m, t0 + 2000000); /* the last one still comes */

	/* at 0, 250, 500, 750 and 1000ms, the last when its timer fires */
	if (m.done != 5) {
		lwsl_err("%s: 1000 requests did %d\n", __func__, m.done);
		return 1;
	}

	/* a lone request after a quiet spell is done at once */
	t = t0 + 10000000;
	gate_model_request(&m, t);
	if (m.done != 6 || m.armed) {
		lwsl_err("%s: lone request was delayed\n", __func__);
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
	result("text", test_text());
	result("list", test_list());
	result("gate", test_gate());

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
