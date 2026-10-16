/*
 * libwebsockets ACME client protocol plugin
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Whether a cert we manage is renewed on this evaluation
 *
 * A cert is due when it has a quarter or less of its life left, when the
 * root daemon could not read it, or when a reissue was forced.  But LE
 * allows 5 duplicate certs / 7 days, so after a failed acquisition the cert
 * backs off exponentially before it is tried again.
 *
 * The backoff belongs to each cert.  It used to be shared by every cert on
 * the vhost, and since an evaluation stops at the first cert it starts an
 * acquisition for, a cert that kept failing early in the list took the only
 * attempt every time the backoff ran out: the certs after it were never
 * tried, and expired.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include "private-acme-client.h"

/*
 * seconds to wait after the n'th consecutive failed acquisition:
 * 2h, 4h, 8h, 16h, then 24h... still comfortably inside the renewal
 * margin of a 6-day cert renewed at 25% life
 */

static lws_usec_t
acme_backoff_us(int fails)
{
	lws_usec_t u = 3600ll * LWS_USEC_PER_SEC << (fails > 5 ? 5 : fails);

	return u > 24 * 3600ll * LWS_USEC_PER_SEC ?
			24 * 3600ll * LWS_USEC_PER_SEC : u;
}

acme_renew_t
acme_renew_verdict(const struct lws_acme_cert_config *cfg,
		   const struct acme_ipc_reply *r, lws_usec_t now)
{
	if (!cfg->force_reissue && r->ok &&
	    !(r->total_days && r->days_left <= (r->total_days / 4)))
		return ACME_RENEW_NOT_DUE;

	if (now < cfg->retry_not_before)
		return ACME_RENEW_BACKOFF;

	return ACME_RENEW_DUE;
}

lws_usec_t
acme_renew_failed(struct lws_acme_cert_config *cfg, lws_usec_t now)
{
	lws_usec_t u;

	if (cfg->fail_count < 1000)
		cfg->fail_count++;

	u = acme_backoff_us(cfg->fail_count);
	cfg->retry_not_before = now + u;

	return u;
}

void
acme_renew_succeeded(struct lws_acme_cert_config *cfg)
{
	cfg->fail_count = 0;
	cfg->retry_not_before = 0;
}
