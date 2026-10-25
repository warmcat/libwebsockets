/*
 * lws-api-test-acme-renew
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Runs the ACME client plugin's decisions about renewing the certs it
 * manages (see plugins/protocol_lws_acme_client/acme-renew.c) through
 * evaluations shaped like the plugin's: the certs are looked at in order,
 * the root daemon says how much life each has left, and the evaluation stops
 * at the first cert it starts an acquisition for.
 *
 * Covered behaviours:
 *
 *  - a cert with more than a quarter of its life left is not due, and one
 *    with a quarter or less, or one the daemon could not read, is
 *  - a forced reissue is due however much life is left, and even while the
 *    cert is backing off after failures
 *  - after a failed acquisition the cert backs off, 2h then doubling up to
 *    24h, and is due again once that has passed
 *  - a success ends the backoff
 *  - the backoff is the cert's own: with two certs due, the first failing
 *    every time it is tried, the second is still tried, and renewed, while
 *    the first backs off... the backoff was once shared by every cert, so
 *    the first took the only attempt each time it ran out, the second was
 *    never tried, and expired
 */

#include <libwebsockets.h>

#include <string.h>

#include "private-acme-client.h"

#define AR_HOUR (3600ll * LWS_USEC_PER_SEC)

static int fails, oks;

static void
ar_result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

static int
ar_expect(const char *what, acme_renew_t got, acme_renew_t want)
{
	if (got == want)
		return 0;

	lwsl_err("%s: got verdict %d, want %d\n", what, (int)got, (int)want);

	return 1;
}

static struct acme_ipc_reply
ar_validity(int ok, int days_left, int total_days)
{
	struct acme_ipc_reply r;

	memset(&r, 0, sizeof(r));
	r.type = ACME_IPC_LINE_VALIDITY;
	r.ok = !!ok;
	r.days_left = days_left;
	r.total_days = total_days;

	return r;
}

static int
ar_due(void)
{
	struct lws_acme_cert_config cfg;
	struct acme_ipc_reply r;
	int bad = 0;

	memset(&cfg, 0, sizeof(cfg));

	r = ar_validity(1, 5, 6);
	bad |= ar_expect("5 of 6 days", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_NOT_DUE);
	r = ar_validity(1, 23, 90);
	bad |= ar_expect("23 of 90 days", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_NOT_DUE);
	r = ar_validity(1, 22, 90);
	bad |= ar_expect("22 of 90 days", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_DUE);
	r = ar_validity(1, 1, 6);
	bad |= ar_expect("1 of 6 days", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_DUE);
	r = ar_validity(1, -2, 6);
	bad |= ar_expect("expired", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_DUE);
	r = ar_validity(0, 0, 0);
	bad |= ar_expect("unreadable", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_DUE);

	cfg.force_reissue = 1;
	r = ar_validity(1, 5, 6);
	bad |= ar_expect("forced", acme_renew_verdict(&cfg, &r, 0),
			 ACME_RENEW_DUE);

	return bad;
}

static int
ar_backoff(void)
{
	static const int hours[] = { 2, 4, 8, 16, 24, 24, 24 };
	struct lws_acme_cert_config cfg;
	struct acme_ipc_reply r = ar_validity(1, 1, 6);
	lws_usec_t now = 1000 * AR_HOUR, u;
	int bad = 0;
	size_t n;

	memset(&cfg, 0, sizeof(cfg));

	for (n = 0; n < LWS_ARRAY_SIZE(hours); n++) {
		u = acme_renew_failed(&cfg, now);
		if (u != hours[n] * AR_HOUR) {
			lwsl_err("failure %d: backs off %lld us, want %dh\n",
				 (int)n + 1, (long long)u, hours[n]);
			bad = 1;
		}
		bad |= ar_expect("just failed",
				 acme_renew_verdict(&cfg, &r, now + 1),
				 ACME_RENEW_BACKOFF);
		bad |= ar_expect("almost backed off",
				 acme_renew_verdict(&cfg, &r, now + u - 1),
				 ACME_RENEW_BACKOFF);
		now += u;
		bad |= ar_expect("backed off",
				 acme_renew_verdict(&cfg, &r, now),
				 ACME_RENEW_DUE);
	}

	/* while it backs off, it's still due if forced: that was asked for */
	acme_renew_failed(&cfg, now);
	cfg.force_reissue = 1;
	bad |= ar_expect("forced, backing off",
			 acme_renew_verdict(&cfg, &r, now + 1),
			 ACME_RENEW_DUE);
	cfg.force_reissue = 0;
	bad |= ar_expect("no longer forced, backing off",
			 acme_renew_verdict(&cfg, &r, now + 1),
			 ACME_RENEW_BACKOFF);

	acme_renew_succeeded(&cfg);
	bad |= ar_expect("succeeded", acme_renew_verdict(&cfg, &r, now + 1),
			 ACME_RENEW_DUE);
	u = acme_renew_failed(&cfg, now);
	if (u != 2 * AR_HOUR) {
		lwsl_err("failure after a success backs off %lld us\n",
			 (long long)u);
		bad = 1;
	}

	return bad;
}

/*
 * The case that let selfdns.org expire: npro.rs first in the list, both
 * nearly expired, and every acquisition for npro.rs failing.  Each hour, as
 * the plugin does, look at the certs in order, starting an acquisition for
 * the first that is due, then stop.
 */

struct ar_cert {
	struct lws_acme_cert_config	cfg;
	const char			*cn;
	lws_usec_t			expires;
	int				always_fails;
	int				attempts;
};

static int
ar_starvation(void)
{
	struct ar_cert certs[] = {
		{ .cn = "npro.rs",	.always_fails = 1 },
		{ .cn = "selfdns.org" },
	};
	lws_usec_t start = 1000 * AR_HOUR, now, end = start + 48 * AR_HOUR;
	struct acme_ipc_reply r;
	int bad = 0, renewed_at = -1;
	size_t n;

	/* about one day of each's six left: due */
	certs[0].expires = start + 26 * AR_HOUR;
	certs[1].expires = start + 25 * AR_HOUR;

	for (now = start; now < end; now += AR_HOUR) {
		for (n = 0; n < LWS_ARRAY_SIZE(certs); n++) {
			struct ar_cert *c = &certs[n];
			lws_usec_t left = c->expires - now;

			r = ar_validity(1, (int)(left / (24 * AR_HOUR)), 6);
			if (acme_renew_verdict(&c->cfg, &r, now) !=
							ACME_RENEW_DUE)
				continue;

			/* this evaluation stops at the acquisition */
			c->attempts++;
			if (c->always_fails)
				acme_renew_failed(&c->cfg, now);
			else {
				acme_renew_succeeded(&c->cfg);
				c->expires = now + 6 * 24 * AR_HOUR;
				if (renewed_at < 0)
					renewed_at = (int)((now - start) /
							   AR_HOUR);
			}
			break;
		}

		if (certs[1].expires <= now) {
			lwsl_err("%s expired, after %d attempts at it, %d at "
				 "%s\n", certs[1].cn, certs[1].attempts,
				 certs[0].attempts, certs[0].cn);
			return 1;
		}
	}

	if (renewed_at < 0 || renewed_at > 1) {
		lwsl_err("%s renewed at hour %d, want within the first two\n",
			 certs[1].cn, renewed_at);
		bad = 1;
	}
	if (certs[1].attempts != 1) {
		lwsl_err("%s: %d attempts, want 1\n", certs[1].cn,
			 certs[1].attempts);
		bad = 1;
	}

	/* backing off 2h, 4h, 8h, 16h: tried at hours 0, 2, 6, 14 and 30 */
	if (certs[0].attempts != 5) {
		lwsl_err("%s: %d attempts in 48h, want 5\n", certs[0].cn,
			 certs[0].attempts);
		bad = 1;
	}

	return bad;
}

int
main(int argc, const char **argv)
{
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: ACME client cert renewal decisions\n");

	ar_result("due", ar_due());
	ar_result("backoff", ar_backoff());
	ar_result("starvation", ar_starvation());

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
