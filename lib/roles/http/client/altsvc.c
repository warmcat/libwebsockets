/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2026 Andy Green <andy@warmcat.com>
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
 * Client-side Alt-Svc processing (RFC 7838): learn h3 endpoints from
 * authenticated TLS responses, so the client connect flow can aim its QUIC
 * attempt at the advertised UDP endpoint instead of the origin's port.
 */

#include "private-lib-core.h"

/*
 * We only trust server-provided max-age up to a day
 */
#define ALT_SVC_MA_MAX_SECS (24u * 3600u)
#define ALT_SVC_HDR_NAME "alt-svc:"

/*
 * alt-svc values are untrusted input from the server.  Strictly return 0 for
 * anything that does not exactly match the shape we expect, no partial trust.
 */

static int
alt_svc_token_eq(const char *tok, size_t tok_len, const char *lcname)
{
	size_t n = 0;

	while (n < tok_len && lcname[n]) {
		char c = tok[n];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + 'a' - 'A');

		if (c != lcname[n])
			return 0;
		n++;
	}

	return n == tok_len && !lcname[n];
}

/*
 * Parse the "authority" part shared by "host:port" and ":port" forms, eg from
 * h3="[2001:db8::1]:443" or h3=":443".
 *
 * Returns 0 and fills host (possibly empty) and port, or 1 if malformed.
 */

static int
alt_svc_parse_authority(const char *auth, size_t auth_len, char *host,
			size_t host_len, uint16_t *port)
{
	size_t split = auth_len, digits, n;
	uint32_t p = 0;

	/* the authority splits at the last ':' */

	while (split > 0 && auth[split - 1] != ':')
		split--;

	if (!split)
		/* there is no port part */
		return 1;

	digits = auth_len - split;

	if (!digits || digits > 5)
		return 1;

	for (n = split; n < auth_len; n++)
		if (auth[n] < '0' || auth[n] > '9')
			return 1;
		else
			p = (p * 10u) + (uint32_t)(auth[n] - '0');

	if (!p || p > 65535)
		return 1;

	*port = (uint16_t)p;

	/* the host part may be empty for the ":port" form */

	if (split - 1 >= host_len)
		/* oversized host is not something we will trust */
		return 1;

	if (split > 1) {
		memcpy(host, auth, split - 1);
		host[split - 1] = '\0';
	} else
		host[0] = '\0';

	return 0;
}

/*
 * Bounded conversion of decimal digits to u32, for the ma= parameter.
 * Returns 1, or 0 if it is not exactly plain digits in range.
 */
static int
alt_svc_parse_u32(const char *tok, size_t tok_len, uint32_t *result)
{
	uint32_t v = 0;
	size_t n = 0;

	if (!tok_len || tok_len > 10)
		return 1;

	for (n = 0; n < tok_len; n++) {
		if (tok[n] < '0' || tok[n] > '9')
			return 1;
		v = (v * 10u) + (uint32_t)(tok[n] - '0');
	}

	*result = v;

	return 0;
}

int
lws_client_alt_svc_parse(const char *val, size_t len,
			 struct lws_alt_svc *alt)
{
	lws_tokenize_t ts;
	/*
	 * What we are currently expecting, if anything:
	 *
	 *  0: anything (an alternative's protocol-id or a parameter name)
	 *  1: the quoted "authority" of the current alternative
	 *  2: the integer value of a ma= parameter
	 */
	int want = 0, cur_is_h3 = 0, cur_valid = 0, got = 0;

	memset(alt, 0, sizeof(*alt));
	alt->ma_secs = ALT_SVC_MA_MAX_SECS;

	if (!val || !len)
		return 0;

	memset(&ts, 0, sizeof(ts));
	ts.start = val;
	ts.len = (unsigned int)len;
	ts.flags = LWS_TOKENIZE_F_RFC7230_DELIMS |
		   LWS_TOKENIZE_F_DOT_NONTERM |
		   LWS_TOKENIZE_F_COLON_NONTERM |
		   LWS_TOKENIZE_F_NO_FLOATS;

	do {
		ts.e = lws_tokenize(&ts);
		switch (ts.e) {
		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			/*
			 * Either the protocol-id of an alternative (eg,
			 * h3=), or a parameter name (eg, ma=) following a
			 * complete alternative
			 */
			if (cur_valid &&
			    alt_svc_token_eq(ts.token, ts.token_len, "ma")) {
				want = 2;
				break;
			}

			cur_is_h3 = alt_svc_token_eq(ts.token, ts.token_len,
						     "h3");
			cur_valid = 0;
			want = 1;
			break;

		case LWS_TOKZE_QUOTED_STRING:
			/* the quoted "authority" of an alternative */

			if (want == 1 && cur_is_h3 && !got &&
			    !alt_svc_parse_authority(ts.token, ts.token_len,
						     alt->host,
						     sizeof(alt->host),
						     &alt->port))
				/* we keep the first well-formed h3 one */
				got = cur_valid = 1;
			want = 0;
			break;

		case LWS_TOKZE_INTEGER:
			/* ma= parameter value */

			if (want == 2 && cur_is_h3 && cur_valid) {
				uint32_t ma;

				if (!alt_svc_parse_u32(ts.token, ts.token_len,
						       &ma))
					alt->ma_secs = ma > ALT_SVC_MA_MAX_SECS ?
						       ALT_SVC_MA_MAX_SECS : ma;
			}
			want = 0;
			break;

		case LWS_TOKZE_DELIMITER:
			/* ';' between params, ',' between alternatives */
			break;

		default:
			return got;
		}
	} while (ts.e > 0);

	return got;
}

#if defined(LWS_WITH_CLIENT)

/*
 * Learn any h3 endpoint advertised by Alt-Svc on this authenticated client
 * response, into the context altsvc cache, and record at host level that the
 * origin has an h3 alternative.  Called when client response headers are
 * complete.  Anything not exactly as we expect is ignored.
 *
 * This is a no-op unless the connection is TLS, per RFC 7838 security
 * considerations (alt-svc from insecure origins must not be actioned).
 */

void
lws_client_alt_svc_learn(struct lws *wsi)
{
#if defined(LWS_WITH_CUSTOM_HEADERS)
	char buf[192], key[256];
	const char *ads;
	struct lws_alt_svc alt;
	uint8_t payload[2];
	lws_usec_t expiry;
	struct lws *nwsi = lws_get_network_wsi(wsi);
	int n;

#if defined(LWS_WITH_TLS)
	if (!(nwsi->tls.use_ssl & LCCSCF_USE_SSL))
		/* insecure origin, ignore per RFC 7838 */
		return;
#endif

	/*
	 * For muxed protocols the response arrives on a stream wsi, but the
	 * origin identity (and tls state) belongs to the network wsi
	 */

	if (!wsi->a.context->altsvc_cache || !nwsi->c_port ||
	    !nwsi->cli_hostname_copy)
		return;

	n = lws_hdr_custom_copy(wsi, buf, sizeof(buf) - 1,
				ALT_SVC_HDR_NAME,
				sizeof(ALT_SVC_HDR_NAME) - 1);
	if (n < 0)
		/* no alt-svc header */
		return;

	if (!lws_client_alt_svc_parse(buf, (size_t)n, &alt))
		/* nothing usable for h3 */
		return;

	if (alt.host[0] && strcmp(alt.host, nwsi->cli_hostname_copy)) {
		/*
		 * For now we only follow alternatives in the same authority
		 * as the origin, cross-host alternatives are ignored
		 */
		lwsl_wsi_info(wsi, "Alt-Svc: ignoring cross-host h3 alt %s",
			      alt.host);
		return;
	}

	/* the connect path looks it up by address, matching the ALPN cache
	 * key convention */
	ads = (nwsi->stash && nwsi->stash->cis[CIS_ADDRESS]) ?
			nwsi->stash->cis[CIS_ADDRESS] : nwsi->cli_hostname_copy;

	lws_snprintf(key, sizeof(key), "altsvc_%s_%u", ads, nwsi->c_port);

	if (!alt.ma_secs) {
		/* ma=0 means the server is withdrawing the alternative */
		lwsl_wsi_notice(wsi, "Alt-Svc: forgot h3 alt for %s", key);
		lws_cache_item_remove(wsi->a.context->altsvc_cache, key);
		return;
	}

	expiry = lws_now_usecs() + ((lws_usec_t)alt.ma_secs * LWS_US_PER_SEC);

	payload[0] = (uint8_t)(alt.port >> 8);
	payload[1] = (uint8_t)alt.port;

	lws_cache_write_through(wsi->a.context->altsvc_cache, key, payload,
				sizeof(payload), expiry, NULL);

	lwsl_wsi_notice(wsi, "Alt-Svc: learned h3 :%u for %s (ma %us)",
			alt.port, key, alt.ma_secs);

	/* record host-level knowledge that an h3 alternative exists */

	if (wsi->a.context->h3_cap_cache && nwsi->stash &&
	    nwsi->stash->cis[CIS_HOST]) {
		lws_h3_cap_info_t cap;

		memset(&cap, 0, sizeof(cap));
		cap.state = LWS_H3_STATE_ALTSVC_EXISTS;

		lws_cache_write_through(wsi->a.context->h3_cap_cache,
					nwsi->stash->cis[CIS_HOST],
					(const uint8_t *)&cap, sizeof(cap),
					expiry, NULL);
	}
#else
	(void)wsi;
#endif /* LWS_WITH_CUSTOM_HEADERS */
}

/*
 * Drop any learned h3 alternative for this wsi's origin, eg because the QUIC
 * attempt against it timed out or failed.  RFC 7838 says clients should stop
 * using an alternative that cannot be connected to, and return to the origin.
 */

void
lws_client_alt_svc_forget(struct lws *wsi)
{
	char key[256];
	const char *ads;

	if (!wsi->a.context->altsvc_cache || !wsi->c_port)
		return;

	ads = (wsi->stash && wsi->stash->cis[CIS_ADDRESS]) ?
			wsi->stash->cis[CIS_ADDRESS] : wsi->cli_hostname_copy;

	if (!ads)
		return;

	lws_snprintf(key, sizeof(key), "altsvc_%s_%u", ads, wsi->c_port);
	lws_cache_item_remove(wsi->a.context->altsvc_cache, key);
}

#endif
