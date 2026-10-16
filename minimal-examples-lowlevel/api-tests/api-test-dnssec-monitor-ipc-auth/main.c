/*
 * lws-api-test-dnssec-monitor-ipc-auth
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Exercises the dnssec-monitor root process's checks on the JWT of each IPC
 * request (monitor-ipc-auth.c), with tokens signed the way the unprivileged
 * process signs them.
 *
 * Covered behaviours:
 *
 *  - without the shared secret, or without a JWT, or with one signed with
 *    another key, expired, or saying nothing about who signed it, nothing
 *    is accepted
 *  - what the proxy forwards for a browser ("sub":"ui") is accepted for
 *    the requests the UI makes...
 *  - ...but not for saving keys, certs or dns-01 challenges, or asking for
 *    a resign, which only the ACME client may, nor for update_whois, which
 *    only the whois lookups may... a browser could once have the proxy
 *    overwrite a domain's TLS key and cert
 *  - the ACME client and the whois lookups each get theirs, and not the
 *    other's
 */

#include <libwebsockets.h>

#include <string.h>

#include "private.h"

static struct lws_context *cx;
static int fails, oks;

static void
mia_result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

/* a token as the unprivileged process makes them; sub NULL: none */

static int
mia_sign(struct lws_jwk *jwk, const char *sub, long exp_delta, char *jwt,
	 size_t jwt_len)
{
	unsigned long long now = (unsigned long long)lws_now_secs();
	char claims[256], subm[64], temp[2048];

	subm[0] = '\0';
	if (sub)
		lws_snprintf(subm, sizeof(subm), "\"sub\":\"%s\",", sub);

	lws_snprintf(claims, sizeof(claims), "{\"iss\":\"acme-ipc\","
		     "\"aud\":\"dnssec-monitor\",%s\"iat\":%llu,\"nbf\":%llu,"
		     "\"exp\":%llu}", subm, now, now - 60,
		     (unsigned long long)((long long)now + exp_delta));

	return lws_jwt_sign_compact(cx, jwk, "HS256", jwt, &jwt_len, temp,
				    sizeof(temp), "%s", claims);
}

static int
mia_expect(struct lws_jwk *secret, const char *jwt, const char *req,
	   mon_ipc_auth_t want, const char *what)
{
	mon_ipc_auth_t got = monitor_ipc_authorize(cx, secret, jwt, req);

	if (got == want)
		return 0;

	lwsl_err("%s: %s: got %d, want %d\n", what, req, (int)got, (int)want);

	return 1;
}

static const char * const mia_ui_reqs[] = {
	"get_domains", "get_zone", "update_zone", "get_all_tls", "create_tls",
	"set_acme_config", "regen_keys", "get_cert_validity",
};

static const char * const mia_acme_reqs[] = {
	"save_auth_key", "save_cert", "save_key", "save_dns_challenge",
	"cleanup_dns_challenge", "trigger_resign",
};

static int
mia_who(struct lws_jwk *secret)
{
	char ui[1024], acme[1024], whois[1024];
	int bad = 0;
	size_t n;

	if (mia_sign(secret, MON_IPC_SUB_UI, 60, ui, sizeof(ui)) ||
	    mia_sign(secret, MON_IPC_SUB_ACME, 300, acme, sizeof(acme)) ||
	    mia_sign(secret, MON_IPC_SUB_WHOIS, 60, whois, sizeof(whois))) {
		lwsl_err("%s: unable to sign\n", __func__);
		return 1;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(mia_ui_reqs); n++) {
		bad |= mia_expect(secret, ui, mia_ui_reqs[n], MON_IPC_AUTH_OK,
				  "ui");
		bad |= mia_expect(secret, acme, mia_ui_reqs[n], MON_IPC_AUTH_OK,
				  "acme");
	}

	for (n = 0; n < LWS_ARRAY_SIZE(mia_acme_reqs); n++) {
		bad |= mia_expect(secret, acme, mia_acme_reqs[n],
				  MON_IPC_AUTH_OK, "acme");
		bad |= mia_expect(secret, ui, mia_acme_reqs[n],
				  MON_IPC_AUTH_NOT_PERMITTED, "ui");
		bad |= mia_expect(secret, whois, mia_acme_reqs[n],
				  MON_IPC_AUTH_NOT_PERMITTED, "whois");
	}

	bad |= mia_expect(secret, whois, "update_whois", MON_IPC_AUTH_OK,
			  "whois");
	bad |= mia_expect(secret, ui, "update_whois",
			  MON_IPC_AUTH_NOT_PERMITTED, "ui");
	bad |= mia_expect(secret, acme, "update_whois",
			  MON_IPC_AUTH_NOT_PERMITTED, "acme");

	return bad;
}

static int
mia_unauthenticated(struct lws_jwk *secret, struct lws_jwk *other)
{
	struct lws_jwk none;
	char jwt[1024];
	int bad = 0;

	memset(&none, 0, sizeof(none));

	if (mia_sign(secret, MON_IPC_SUB_UI, 60, jwt, sizeof(jwt)))
		return 1;
	bad |= mia_expect(&none, jwt, "get_domains", MON_IPC_AUTH_FAILED,
			  "no secret");
	bad |= mia_expect(secret, "", "get_domains", MON_IPC_AUTH_FAILED,
			  "no jwt");
	bad |= mia_expect(secret, NULL, "get_domains", MON_IPC_AUTH_FAILED,
			  "NULL jwt");

	if (mia_sign(other, MON_IPC_SUB_ACME, 60, jwt, sizeof(jwt)))
		return 1;
	bad |= mia_expect(secret, jwt, "save_key", MON_IPC_AUTH_FAILED,
			  "other key");

	if (mia_sign(secret, MON_IPC_SUB_ACME, -10, jwt, sizeof(jwt)))
		return 1;
	bad |= mia_expect(secret, jwt, "save_key", MON_IPC_AUTH_FAILED,
			  "expired");

	if (mia_sign(secret, NULL, 60, jwt, sizeof(jwt)))
		return 1;
	bad |= mia_expect(secret, jwt, "get_domains", MON_IPC_AUTH_FAILED,
			  "no sub");

	if (mia_sign(secret, "", 60, jwt, sizeof(jwt)))
		return 1;
	bad |= mia_expect(secret, jwt, "get_domains", MON_IPC_AUTH_FAILED,
			  "empty sub");

	return bad;
}

int
main(int argc, const char **argv)
{
	static const uint8_t k1[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 },
			     k2[32] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	struct lws_context_creation_info info;
	struct lws_jwk secret, other;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: dnssec-monitor IPC authorization\n");

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("context creation failed\n");
		return 1;
	}

	memset(&secret, 0, sizeof(secret));
	memset(&other, 0, sizeof(other));
	if (lws_jwk_dup_oct(&secret, k1, (int)sizeof(k1)) ||
	    lws_jwk_dup_oct(&other, k2, (int)sizeof(k2))) {
		lwsl_err("unable to make keys\n");
		lws_context_destroy(cx);
		return 1;
	}

	mia_result("unauthenticated", mia_unauthenticated(&secret, &other));
	mia_result("who", mia_who(&secret));

	lws_jwk_destroy(&secret);
	lws_jwk_destroy(&other);
	lws_context_destroy(cx);

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
