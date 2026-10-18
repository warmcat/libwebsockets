/*
 * lws-api-test-http-cookie: request cookie getters
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 *
 * Fences lws_http_cookie_get(), lws_http_cookie_get_nth() and the JWT cookie
 * readers built on them, lws_jwt_get_http_cookie_validate_jwt() and
 * lws_jwt_auth_create(), against real request headers: a server vhost and a
 * client in this process, the client sending each case's Cookie header(s) and
 * the server resolving the case's lookup from them.
 *
 * The contracts fenced:
 *
 *  - exactly the name asked for is resolved.  "__Host-x" is only found by
 *    asking for "__Host-x" and "x" only by asking for "x", whichever order the
 *    browser lists them in (G-008): a bare-named cookie, which a sibling host
 *    can set, never stands in for the prefixed one.  The JWT readers read the
 *    __Host- cookie the library mints and nothing else, so an attacker's
 *    validly signed JWT planted under the bare name is not taken.
 *
 *  - a name only matches at the start of a cookie-pair (G-010).  A "name="
 *    inside another cookie's value, eg after a space, which browsers keep in
 *    values, is not a cookie of that name.
 *
 *  - a JWT minted for one purpose is not accepted for another (G-171): the
 *    client chooses which cookie name it presents a token under, so only the
 *    signed "pur" claim can tell, eg, a visit token from a pass token signed
 *    with the same key, iss and aud.  A token with a purpose is refused where
 *    none is asked for, and one without where one is.
 *
 *  - lws_jwt_auth_create_via_info() holds session tokens to the same
 *    contract (G-188): the iss, aud and purpose asked for must each be the
 *    token's top-level claim, exactly and once, so eg an interceptor's visit
 *    token signed with a shared key is not a session; lws_jwt_auth_create()
 *    asks for none, so refuses any token with a purpose; and
 *    lws_jwt_auth_update() keeps the requirements the object was created
 *    with.
 */

#include <libwebsockets.h>
#include <string.h>

#include "getters.h"

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_CLIENT) && \
    defined(LWS_ROLE_H1)

#define CKG_TIMEOUT_S		5
#define CKG_ISS			"lws-api-test-http-cookie"

enum ckg_kind {
	CKG_GET,	/* lws_http_cookie_get() */
	CKG_NTH,	/* lws_http_cookie_get_nth() */
	CKG_JWT_VALIDATE, /* lws_jwt_get_http_cookie_validate_jwt() */
	CKG_JWT_AUTH,	/* lws_jwt_auth_create(), or _via_info() */
	CKG_JWT_AUTH_UPDATE, /* lws_jwt_auth_update() after _via_info() */
	CKG_JWT_SIGN,	/* lws_jwt_sign_token_set_cookie_ascii() */
};

/* which JWT, if any, is appended to a Cookie: header's text */
enum ckg_jwt {
	CKG_J_NONE,
	CKG_J_VICTIM,
	CKG_J_ATTACKER,
	CKG_J_PASS,	/* victim's, minted with purpose "pass" */
	CKG_J_VISIT,	/* victim's, minted with purpose "visit" */
	CKG_J_SSO,	/* victim's, minted with purpose "sso" */
	CKG_J_PUR_DUP,	/* "pur":"sso" and then "pur":"visit" */
	CKG_J_PUR_NESTED, /* "sso" only as a "pur" inside an object */
	CKG_J_PUR_NUM,	/* "pur":1 */
	CKG_J_PUR_LONGER, /* "pur":"ssox" */

	CKG_J_COUNT
};

struct ckg_case {
	const char		*label;
	const char		*hdr[2];  /* each non-NULL one is a Cookie: */
	enum ckg_jwt		jwt[2];   /* appended to the matching hdr */
	enum ckg_kind		kind;
	const char		*name;
	int			nth;
	size_t			buflen;	  /* 0 means the whole buffer */
	int			want_rc;  /* 0 found, 1 absent, 2 too big */
	const char		*want;	  /* value, or sub for the JWT kinds */
	const char		*purpose; /* JWT validate / sign purpose */
	const char		*ext;	  /* CKG_JWT_SIGN: extra_json */
	const char		*iss;	  /* CKG_JWT_AUTH*: iss required */
	const char		*aud;	  /* CKG_JWT_AUTH*: aud required */
	enum ckg_jwt		upd;	  /* CKG_JWT_AUTH_UPDATE: new token */
	char			via_info; /* CKG_JWT_AUTH: use _via_info() */
};

static const struct ckg_case ckg_cases[] = {
	{ .label = "plain", .hdr = { "a=1; b=2" }, .kind = CKG_GET,
	  .name = "b", .want = "2" },
	{ .label = "first of name", .hdr = { "a=1; b=2; a=3" },
	  .kind = CKG_GET, .name = "a", .want = "1" },
	{ .label = "nth 1", .hdr = { "s=1; s=2" }, .kind = CKG_NTH,
	  .name = "s", .nth = 1, .want = "2" },
	{ .label = "nth past end", .hdr = { "s=1; s=2" }, .kind = CKG_NTH,
	  .name = "s", .nth = 2, .want_rc = 1 },
	{ .label = "two fields", .hdr = { "a=1", "s=2" }, .kind = CKG_GET,
	  .name = "s", .want = "2" },
	{ .label = "nth across fields", .hdr = { "s=1", "s=2" },
	  .kind = CKG_NTH, .name = "s", .nth = 1, .want = "2" },
	{ .label = "too big", .hdr = { "s=123456789" }, .kind = CKG_GET,
	  .name = "s", .buflen = 9, .want_rc = 2 },
	{ .label = "exact fit", .hdr = { "s=12345678" }, .kind = CKG_GET,
	  .name = "s", .buflen = 9, .want = "12345678" },
	{ .label = "absent", .hdr = { "a=1" }, .kind = CKG_GET, .name = "s",
	  .want_rc = 1 },

	/* G-008: no aliasing between prefixed and bare names */

	{ .label = "bare asked, only __Host-", .hdr = { "__Host-s=H" },
	  .kind = CKG_GET, .name = "s", .want_rc = 1 },
	{ .label = "bare asked, only __Secure-", .hdr = { "__Secure-s=S" },
	  .kind = CKG_GET, .name = "s", .want_rc = 1 },
	{ .label = "__Host- asked, bare first", .hdr = { "s=B; __Host-s=H" },
	  .kind = CKG_GET, .name = "__Host-s", .want = "H" },
	{ .label = "bare asked, bare first", .hdr = { "s=B; __Host-s=H" },
	  .kind = CKG_GET, .name = "s", .want = "B" },
	{ .label = "__Host- asked, __Host- first",
	  .hdr = { "__Host-s=H; s=B" }, .kind = CKG_GET, .name = "__Host-s",
	  .want = "H" },
	{ .label = "bare asked, __Host- first", .hdr = { "__Host-s=H; s=B" },
	  .kind = CKG_GET, .name = "s", .want = "B" },
	{ .label = "__Host- nth skips bare",
	  .hdr = { "s=B; __Host-s=H; s=C" }, .kind = CKG_NTH,
	  .name = "__Host-s", .nth = 1, .want_rc = 1 },

	/* G-010: names only match at the start of a cookie-pair */

	{ .label = "name inside a value", .hdr = { "a=x s=F; s=R" },
	  .kind = CKG_GET, .name = "s", .want = "R" },
	{ .label = "name inside a value only", .hdr = { "a=x s=F" },
	  .kind = CKG_GET, .name = "s", .want_rc = 1 },
	{ .label = "__Host- name inside a value",
	  .hdr = { "z=1 __Host-s=F", "__Host-s=R" }, .kind = CKG_GET,
	  .name = "__Host-s", .want = "R" },
	{ .label = "nth skips names inside values",
	  .hdr = { "a=x s=F; s=1; s=2" }, .kind = CKG_NTH, .name = "s",
	  .nth = 1, .want = "2" },
	{ .label = "nth past names inside values",
	  .hdr = { "a=x s=F; s=1; s=2" }, .kind = CKG_NTH, .name = "s",
	  .nth = 2, .want_rc = 1 },
	{ .label = "name after '=' in a value", .hdr = { "a=b=s=F; s=R" },
	  .kind = CKG_GET, .name = "s", .want = "R" },
	{ .label = "no space after ';'", .hdr = { "a=1;s=2" },
	  .kind = CKG_GET, .name = "s", .want = "2" },
	{ .label = "whitespace trimmed", .hdr = { "a=1;  s = 2  ; b=3" },
	  .kind = CKG_GET, .name = "s", .want = "2" },
	{ .label = "value with '='", .hdr = { "s=a=b" }, .kind = CKG_GET,
	  .name = "s", .want = "a=b" },
	{ .label = "empty value", .hdr = { "s=; b=1" }, .kind = CKG_GET,
	  .name = "s", .want = "" },
	{ .label = "nameless pair", .hdr = { "junk; s=1" }, .kind = CKG_GET,
	  .name = "s", .want = "1" },
	{ .label = "nameless pair is not the name", .hdr = { "s; b=1" },
	  .kind = CKG_GET, .name = "s", .want_rc = 1 },
	{ .label = "name is a suffix", .hdr = { "xs=1" }, .kind = CKG_GET,
	  .name = "s", .want_rc = 1 },
	{ .label = "name is a prefix", .hdr = { "sx=1" }, .kind = CKG_GET,
	  .name = "s", .want_rc = 1 },

#if defined(LWS_WITH_JOSE)
	{ .label = "jwt: __Host- validates", .hdr = { "__Host-tj=" },
	  .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_VALIDATE, .name = "tj",
	  .want = "victim" },
	{ .label = "jwt: bare is not read", .hdr = { "tj=" },
	  .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_VALIDATE, .name = "tj",
	  .want_rc = 1 },
	{ .label = "jwt: planted bare does not shadow",
	  .hdr = { "tj=", "__Host-tj=" },
	  .jwt = { CKG_J_ATTACKER, CKG_J_VICTIM }, .kind = CKG_JWT_VALIDATE,
	  .name = "tj", .want = "victim" },
	{ .label = "jwt: __Host- name inside a value is not read",
	  .hdr = { "z=1 __Host-tj=" }, .jwt = { CKG_J_ATTACKER },
	  .kind = CKG_JWT_VALIDATE, .name = "tj", .want_rc = 1 },
	{ .label = "jwt: __Host- name inside a value does not shadow",
	  .hdr = { "z=1 __Host-tj=", "__Host-tj=" },
	  .jwt = { CKG_J_ATTACKER, CKG_J_VICTIM }, .kind = CKG_JWT_VALIDATE,
	  .name = "tj", .want = "victim" },

	/* G-171: the purpose claim, not the cookie name, tells tokens apart */

	{ .label = "jwt: purpose matches", .hdr = { "__Host-tj=" },
	  .jwt = { CKG_J_PASS }, .kind = CKG_JWT_VALIDATE, .name = "tj",
	  .purpose = "pass", .want = "victim" },
	{ .label = "jwt: other purpose refused", .hdr = { "__Host-tj=" },
	  .jwt = { CKG_J_VISIT }, .kind = CKG_JWT_VALIDATE, .name = "tj",
	  .purpose = "pass", .want_rc = 1 },
	{ .label = "jwt: no purpose refused where one asked",
	  .hdr = { "__Host-tj=" }, .jwt = { CKG_J_VICTIM },
	  .kind = CKG_JWT_VALIDATE, .name = "tj", .purpose = "pass",
	  .want_rc = 1 },
	{ .label = "jwt: purpose refused where none asked",
	  .hdr = { "__Host-tj=" }, .jwt = { CKG_J_PASS },
	  .kind = CKG_JWT_VALIDATE, .name = "tj", .want_rc = 1 },
	{ .label = "jwt: purpose is not a prefix match",
	  .hdr = { "__Host-tj=" }, .jwt = { CKG_J_PASS },
	  .kind = CKG_JWT_VALIDATE, .name = "tj", .purpose = "pas",
	  .want_rc = 1 },
	{ .label = "sign: purpose", .kind = CKG_JWT_SIGN, .name = "tj",
	  .purpose = "pass" },
	{ .label = "sign: purpose that ends its string refused",
	  .kind = CKG_JWT_SIGN, .name = "tj", .purpose = "pass\",\"x\":\"",
	  .want_rc = 1 },
	{ .label = "sign: \"pur\" in ext refused", .kind = CKG_JWT_SIGN,
	  .name = "tj", .ext = "\"pur\":\"pass\"", .want_rc = 1 },

	{ .label = "jwt-auth: name inside a value is not read",
	  .hdr = { "z=1 auth_x=" }, .jwt = { CKG_J_ATTACKER },
	  .kind = CKG_JWT_AUTH, .name = "auth_x", .want_rc = 1 },
	{ .label = "jwt-auth: exact prefixed name", .hdr = { "__Host-tj=" },
	  .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_AUTH, .name = "__Host-tj",
	  .want = "victim" },
	{ .label = "jwt-auth: bare name finds no __Host-",
	  .hdr = { "__Host-tj=" }, .jwt = { CKG_J_VICTIM },
	  .kind = CKG_JWT_AUTH, .name = "tj", .want_rc = 1 },

	/* G-188: session tokens are held to iss / aud / purpose too */

	{ .label = "jwt-auth: purpose refused where none asked",
	  .hdr = { "s=" }, .jwt = { CKG_J_VISIT }, .kind = CKG_JWT_AUTH,
	  .name = "s", .want_rc = 1 },
	{ .label = "jwt-auth info: purpose matches", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "sso", .want = "victim" },
	{ .label = "jwt-auth info: other purpose refused", .hdr = { "s=" },
	  .jwt = { CKG_J_VISIT }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "sso", .want_rc = 1 },
	{ .label = "jwt-auth info: no purpose refused where one asked",
	  .hdr = { "s=" }, .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .purpose = "sso", .want_rc = 1 },
	{ .label = "jwt-auth info: purpose refused where none asked",
	  .hdr = { "s=" }, .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .want_rc = 1 },
	{ .label = "jwt-auth info: no purpose where none asked",
	  .hdr = { "s=" }, .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .want = "victim" },
	{ .label = "jwt-auth info: purpose is not a prefix match",
	  .hdr = { "s=" }, .jwt = { CKG_J_PUR_LONGER }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .purpose = "sso", .want_rc = 1 },
	{ .label = "jwt-auth info: duplicate purpose refused",
	  .hdr = { "s=" }, .jwt = { CKG_J_PUR_DUP }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .purpose = "sso", .want_rc = 1 },
	{ .label = "jwt-auth info: nested purpose is not the purpose",
	  .hdr = { "s=" }, .jwt = { CKG_J_PUR_NESTED }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .purpose = "sso", .want_rc = 1 },
	{ .label = "jwt-auth info: non-string purpose refused",
	  .hdr = { "s=" }, .jwt = { CKG_J_PUR_NUM }, .kind = CKG_JWT_AUTH,
	  .via_info = 1, .name = "s", .want_rc = 1 },
	{ .label = "jwt-auth info: live one behind a wrong purpose",
	  .hdr = { "s=", "s=" }, .jwt = { CKG_J_VISIT, CKG_J_SSO },
	  .kind = CKG_JWT_AUTH, .via_info = 1, .name = "s",
	  .purpose = "sso", .want = "victim" },
	{ .label = "jwt-auth info: iss and aud match", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "sso", .iss = CKG_ISS, .aud = CKG_ISS,
	  .want = "victim" },
	{ .label = "jwt-auth info: other iss refused", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "sso", .iss = "someone-else",
	  .want_rc = 1 },
	{ .label = "jwt-auth info: other aud refused", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "sso", .aud = CKG_ISS "x", .want_rc = 1 },
	{ .label = "jwt-auth info: empty purpose refused", .hdr = { "s=" },
	  .jwt = { CKG_J_VICTIM }, .kind = CKG_JWT_AUTH, .via_info = 1,
	  .name = "s", .purpose = "", .want_rc = 1 },
	{ .label = "jwt-auth update: same purpose", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH_UPDATE, .name = "s",
	  .purpose = "sso", .upd = CKG_J_SSO, .want = "victim" },
	{ .label = "jwt-auth update: other purpose refused", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH_UPDATE, .name = "s",
	  .purpose = "sso", .upd = CKG_J_VISIT, .want_rc = 1 },
	{ .label = "jwt-auth update: no purpose refused", .hdr = { "s=" },
	  .jwt = { CKG_J_SSO }, .kind = CKG_JWT_AUTH_UPDATE, .name = "s",
	  .purpose = "sso", .upd = CKG_J_VICTIM, .want_rc = 1 },
#endif
};

static struct lws_context *ckg_cx;
static lws_sorted_usec_list_t ckg_sul_next, ckg_sul_watchdog;
static const char *ckg_server;
static int ckg_cur = -1, ckg_port, ckg_fails, ckg_finished, ckg_answered,
	   ckg_case_done;

#if defined(LWS_WITH_JOSE)
static struct lws_jwk ckg_jwk;
static char ckg_jwts[CKG_J_COUNT][1024]; /* by enum ckg_jwt */
#endif

static void
ckg_fail(const char *why)
{
	lwsl_err("case %d (%s): FAIL: %s\n", ckg_cur, ckg_cases[ckg_cur].label,
		 why);
	ckg_fails++;
}

/* the server half: resolve the case's lookup from the request's headers */

static void
ckg_resolve(struct lws *wsi, const struct ckg_case *c)
{
	char buf[2048], why[256];
	size_t bl = c->buflen ? c->buflen : sizeof(buf);
	const char *got = buf;
	int rc = 1;

	buf[0] = '\0';

	switch (c->kind) {
	case CKG_GET:
		rc = lws_http_cookie_get(wsi, c->name, buf, &bl);
		break;
	case CKG_NTH:
		rc = lws_http_cookie_get_nth(wsi, c->name, c->nth, buf, &bl);
		break;
#if defined(LWS_WITH_JOSE)
	case CKG_JWT_VALIDATE: {
		struct lws_jwt_sign_set_cookie ck;

		memset(&ck, 0, sizeof(ck));
		ck.jwk		= &ckg_jwk;
		ck.alg		= "ES256";
		ck.iss		= CKG_ISS;
		ck.aud		= CKG_ISS;
		ck.cookie_name	= c->name;
		ck.purpose	= c->purpose;

		rc = lws_jwt_get_http_cookie_validate_jwt(wsi, &ck, buf, &bl);
		lws_strncpy(buf, ck.sub, sizeof(buf));
		break;
	}
	case CKG_JWT_SIGN: {
		struct lws_jwt_sign_set_cookie ck;

		memset(&ck, 0, sizeof(ck));
		ck.jwk			= &ckg_jwk;
		ck.alg			= "ES256";
		ck.iss			= CKG_ISS;
		ck.aud			= CKG_ISS;
		ck.cookie_name		= c->name;
		ck.purpose		= c->purpose;
		ck.extra_json		= c->ext;
		ck.expiry_unix_time	= 60;
		lws_strncpy(ck.sub, "victim", sizeof(ck.sub));

		rc = lws_jwt_sign_token_set_cookie_ascii(wsi, &ck, buf,
							 sizeof(buf));
		got = "";
		break;
	}
	case CKG_JWT_AUTH:
	case CKG_JWT_AUTH_UPDATE: {
		struct lws_jwt_auth_info ai;
		struct lws_jwt_auth *ja;

		memset(&ai, 0, sizeof(ai));
		ai.jwk		= &ckg_jwk;
		ai.cookie_name	= c->name;
		ai.iss		= c->iss;
		ai.aud		= c->aud;
		ai.purpose	= c->purpose;

		if (c->kind == CKG_JWT_AUTH && !c->via_info)
			ja = lws_jwt_auth_create(wsi, &ckg_jwk, c->name, NULL,
						 NULL, NULL);
		else
			ja = lws_jwt_auth_create_via_info(wsi, &ai, NULL);

		if (!ja)
			break;

		rc = 0;
		if (c->kind == CKG_JWT_AUTH_UPDATE &&
		    lws_jwt_auth_update(ja, ckg_jwts[c->upd], NULL))
			rc = 1;

		if (!rc)
			lws_strncpy(buf, lws_jwt_auth_get_sub(ja) ?
				    lws_jwt_auth_get_sub(ja) : "",
				    sizeof(buf));
		lws_jwt_auth_destroy(&ja);
		break;
	}
#else
	default:
		break;
#endif
	}

	if (rc != c->want_rc) {
		lws_snprintf(why, sizeof(why), "rc %d, want %d (value '%s')",
			     rc, c->want_rc, rc ? "" : got);
		ckg_fail(why);
		return;
	}

	if (!rc && c->want && strcmp(got, c->want)) {
		lws_snprintf(why, sizeof(why), "got '%s', want '%s'", got,
			     c->want);
		ckg_fail(why);
	}
}

static int
ckg_srv_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	uint8_t hb[LWS_PRE + 256], *start = &hb[LWS_PRE], *p = start,
		*end = &hb[sizeof(hb) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (ckg_cur >= 0 && ckg_cur < (int)LWS_ARRAY_SIZE(ckg_cases)) {
			ckg_resolve(wsi, &ckg_cases[ckg_cur]);
			ckg_answered++;
		}

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", 0, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
ckg_next(lws_sorted_usec_list_t *sul);

static void
ckg_case_end(struct lws *wsi, const char *why)
{
	if (lws_get_opaque_user_data(wsi) != (void *)(intptr_t)(ckg_cur + 1) ||
	    ckg_case_done)
		return; /* a late event from an earlier case */

	ckg_case_done = 1;
	if (why)
		ckg_fail(why);
	else if (ckg_answered != 1)
		ckg_fail("server did not see the request");

	lws_sul_cancel(&ckg_sul_watchdog);
	lws_sul_schedule(ckg_cx, 0, &ckg_sul_next, ckg_next, 1);
}

static int
ckg_add_line(struct lws *wsi, const char *text, enum ckg_jwt jwt,
	     unsigned char **p, unsigned char *end)
{
	char line[3072];
	const char *j = "";
	int n;

#if defined(LWS_WITH_JOSE)
	if (jwt != CKG_J_NONE && jwt < CKG_J_COUNT)
		j = ckg_jwts[jwt];
#else
	(void)jwt;
#endif

	n = lws_snprintf(line, sizeof(line), "%s%s", text, j);
	if ((size_t)n >= sizeof(line))
		return 1;

	return lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_COOKIE,
					    (unsigned char *)line, n, p, end);
}

static int
ckg_cli_cb(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	   void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		const struct ckg_case *c;
		size_t n;

		if (lws_get_opaque_user_data(wsi) !=
					(void *)(intptr_t)(ckg_cur + 1))
			return -1;
		c = &ckg_cases[ckg_cur];

		for (n = 0; n < LWS_ARRAY_SIZE(c->hdr); n++)
			if (c->hdr[n] && ckg_add_line(wsi, c->hdr[n],
						       c->jwt[n], p, end))
				return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[LWS_PRE + 256], *px = buf + LWS_PRE;
		int lenx = sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;

		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		ckg_case_end(wsi, NULL);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		ckg_case_end(wsi, in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		ckg_case_end(wsi, "closed before completion");
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols ckg_protocols_srv[] = {
	{ "ckg-srv", ckg_srv_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols ckg_protocols_cli[] = {
	{ "ckg-cli", ckg_cli_cb, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
ckg_watchdog(lws_sorted_usec_list_t *sul)
{
	ckg_fail("timed out");
	ckg_case_done = 1;
	lws_sul_schedule(ckg_cx, 0, &ckg_sul_next, ckg_next, 1);
}

static void
ckg_next(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	if (++ckg_cur == (int)LWS_ARRAY_SIZE(ckg_cases)) {
		ckg_finished = 1;
		lws_cancel_service(ckg_cx);
		return;
	}

	ckg_answered = 0;
	ckg_case_done = 0;

	memset(&i, 0, sizeof(i));
	i.context		= ckg_cx;
	i.vhost			= lws_get_vhost_by_name(ckg_cx, "ckg-cli");
	i.address		= ckg_server;
	i.host			= i.address;
	i.origin		= i.address;
	i.port			= ckg_port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= ckg_protocols_cli[0].name;
	i.local_protocol_name	= ckg_protocols_cli[0].name;
	i.opaque_user_data	= (void *)(intptr_t)(ckg_cur + 1);

	lws_sul_schedule(ckg_cx, 0, &ckg_sul_watchdog, ckg_watchdog,
			 CKG_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
		ckg_fail("connect failed");
		ckg_case_done = 1;
		lws_sul_cancel(&ckg_sul_watchdog);
		lws_sul_schedule(ckg_cx, 0, &ckg_sul_next, ckg_next, 1);
	}
}

#if defined(LWS_WITH_JOSE)
/*
 * The claims as jwt_sign_cookie_value() lays them out, with pur, if any,
 * being the raw members for the purpose
 */
static int
ckg_mint(enum ckg_jwt which, const char *sub, const char *pur)
{
	unsigned long long now = (unsigned long long)lws_now_secs();
	size_t out_len = sizeof(ckg_jwts[0]);
	char temp[2048];

	return lws_jwt_sign_compact(ckg_cx, &ckg_jwk, "ES256", ckg_jwts[which],
				    &out_len, temp, (int)sizeof(temp),
				    "{\"iss\":\"%s\",\"aud\":\"%s\",%s"
				    "\"iat\":%llu,\"nbf\":%llu,\"exp\":%llu,"
				    "\"csrf\":\"0123456789abcdef\","
				    "\"sub\":\"%s\"}", CKG_ISS, CKG_ISS,
				    pur ? pur : "", now, now - 60, now + 600,
				    sub);
}
#endif

int
ckg_test(const char *server)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	int n = 0;

	ckg_server = server;
	lws_context_info_defaults(&info, NULL);
	/* a server and a client in one process: don't budget fds */
	info.fd_limit_per_thread = 0;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	ckg_cx = lws_create_context(&info);
	if (!ckg_cx) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	info.port = 0;
	info.protocols = ckg_protocols_srv;
	info.vhost_name = "ckg-srv";
	vh = lws_create_vhost(ckg_cx, &info);
	if (!vh)
		goto bail;
	ckg_port = lws_get_vhost_listen_port(vh);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = ckg_protocols_cli;
	info.vhost_name = "ckg-cli";
	if (!lws_create_vhost(ckg_cx, &info))
		goto bail;

#if defined(LWS_WITH_JOSE)
	if (lws_jwk_generate(ckg_cx, &ckg_jwk, LWS_GENCRYPTO_KTY_EC, 0,
			     "P-256")) {
		lwsl_err("%s: jwk generation failed\n", __func__);
		goto bail;
	}
	if (ckg_mint(CKG_J_VICTIM, "victim", NULL) ||
	    ckg_mint(CKG_J_ATTACKER, "attacker", NULL) ||
	    ckg_mint(CKG_J_PASS, "victim", "\"pur\":\"pass\",") ||
	    ckg_mint(CKG_J_VISIT, "victim", "\"pur\":\"visit\",") ||
	    ckg_mint(CKG_J_SSO, "victim", "\"pur\":\"sso\",") ||
	    ckg_mint(CKG_J_PUR_DUP, "victim",
		     "\"pur\":\"sso\",\"pur\":\"visit\",") ||
	    ckg_mint(CKG_J_PUR_NESTED, "victim",
		     "\"ext\":{\"pur\":\"sso\"},") ||
	    ckg_mint(CKG_J_PUR_NUM, "victim", "\"pur\":1,") ||
	    ckg_mint(CKG_J_PUR_LONGER, "victim", "\"pur\":\"ssox\",")) {
		lwsl_err("%s: jwt minting failed\n", __func__);
		lws_jwk_destroy(&ckg_jwk);
		goto bail;
	}
#endif

	lws_sul_schedule(ckg_cx, 0, &ckg_sul_next, ckg_next, 1);

	while (n >= 0 && !ckg_finished)
		n = lws_service(ckg_cx, 0);

	lws_sul_cancel(&ckg_sul_watchdog);
	lws_sul_cancel(&ckg_sul_next);
#if defined(LWS_WITH_JOSE)
	lws_jwk_destroy(&ckg_jwk);
#endif
	lws_context_destroy(ckg_cx);

	if (!ckg_finished) {
		lwsl_err("%s: service loop ended early\n", __func__);
		return 1;
	}

	lwsl_user("%s: %d of %d getter cases failed\n", __func__, ckg_fails,
		  (int)LWS_ARRAY_SIZE(ckg_cases));

	return ckg_fails;

bail:
	lwsl_err("%s: setup failed\n", __func__);
	lws_context_destroy(ckg_cx);

	return 1;
}

#else

int
ckg_test(const char *server)
{
	(void)server;
	lwsl_user("%s: needs server, client and h1: skipped\n", __func__);

	return 0;
}

#endif
