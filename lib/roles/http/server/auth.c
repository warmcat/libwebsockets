/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2019 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * This implements either basic auth (RFC2617) and / or digest auth (RFC7616).
 *
 * Unfortunately although Chrome and Firefox support both, they only support
 * RFC7616 algorithm of MD5.
 */

#include "core/private.h"

#if defined(LWS_WITH_HTTP_AUTH_BASIC) && !defined(LWS_WITH_ESP32)
static int
lws_find_string_in_file(const char *filename, const char *string, int stringlen)
{
	char buf[128];
	int fd, match = 0, pos = 0, n = 0, hit = 0;

	fd = lws_open(filename, O_RDONLY);
	if (fd < 0) {
		lwsl_err("can't open auth file: %s\n", filename);
		return 0;
	}

	while (1) {
		if (pos == n) {
			n = read(fd, buf, sizeof(buf));
			if (n <= 0) {
				if (match == stringlen)
					hit = 1;
				break;
			}
			pos = 0;
		}

		if (match == stringlen) {
			if (buf[pos] == '\r' || buf[pos] == '\n') {
				hit = 1;
				break;
			}
			match = 0;
		}

		if (buf[pos] == string[match])
			match++;
		else
			match = 0;

		pos++;
	}

	close(fd);

	return hit;
}
#endif

int
lws_unauthorised_http_auth(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	unsigned char *start = pt->serv_buf + LWS_PRE,
		      *p = start, *end = p + 2048;
	char buf[256];
	int n;

	/* no auth... tell him it is required */

	if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end))
		return -1;

#if defined(LWS_WITH_HTTP_AUTH_DIGEST)
	{
		uint8_t digest[LWS_GENHASH_LARGEST];
		char nbuf[64], vh_priv[33], nonce[LWS_GENHASH_LARGEST * 2 + 1],
		     *uri;
	        struct lws_genhash_ctx hc;
	        int urilen;
		time_t t;

		/* if the vhost digest key has not yet been set, create it */

		if (!wsi->vhost->http.http_digest_auth_key[0] &&
		    !wsi->vhost->http.http_digest_auth_key[1] &&
		    !wsi->vhost->http.http_digest_auth_key[2] &&
		    !wsi->vhost->http.http_digest_auth_key[3])
			lws_get_random(wsi->context,
				       wsi->vhost->http.http_digest_auth_key,
				       sizeof(wsi->vhost->http.http_digest_auth_key));

		/*
		 * Create an RFC7616 nonce from H(client IP : etag : vh privkey)
		 * atm we just use url for etag
		 */

		if (lws_http_get_uri_and_method(wsi, &uri, &urilen) < 0) {
			lwsl_notice("%s: get uri failed\n", __func__);

			return -1;
		}

		time(&t);
		lws_byte_array_to_hex(wsi->vhost->http.http_digest_auth_key,
				      sizeof(wsi->vhost->http.http_digest_auth_key),
				      vh_priv, sizeof(vh_priv));

		n = lws_snprintf(nbuf, sizeof(nbuf), "%lu:%.*s:%s",
				 (unsigned long)t, urilen, uri, vh_priv);

	        if (lws_genhash_init(&hc, LWS_HTTP_AUTH_DIGEST_GENHASH) ||
	            lws_genhash_update(&hc, nbuf, n) ||
	            lws_genhash_destroy(&hc, digest)) {
	                lws_genhash_destroy(&hc, NULL);
			lwsl_err("%s: hash failed\n", __func__);

	                return -1;
	        }

	        /* turn the nonce hash into an ascii string */

		lws_byte_array_to_hex(digest,
				 lws_genhash_size(LWS_HTTP_AUTH_DIGEST_GENHASH),
				 nonce, sizeof(nonce));

	        n = lws_snprintf(buf, sizeof(buf), "Digest realm=\"%s\","
	        		 "qop=\"auth\",algorithm=%s,"
	        		 "nonce=\"%s\",opaque=\"%s\"",
	        		 wsi->vhost->http.http_auth_realm ?
	        		       wsi->vhost->http.http_auth_realm : "lws",
	        		 LWS_HTTP_AUTH_DIGEST_NAME, nonce, nonce);
	}
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
					 (unsigned char *)buf, n, &p, end))
		return -1;
#endif

#if defined(LWS_WITH_HTTP_AUTH_BASIC)
	n = lws_snprintf(buf, sizeof(buf), "Basic realm=\"%s\"",
				wsi->vhost->http.http_auth_realm ?
				      wsi->vhost->http.http_auth_realm : "lws");
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
					 (unsigned char *)buf, n, &p, end))
		return -1;
#endif

	if (lws_add_http_header_content_length(wsi, 0, &p, end))
		return -1;

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS |
					     LWS_WRITE_H2_STREAM_END);
	if (n < 0)
		return -1;

	return lws_http_transaction_completed(wsi);

}


#if defined(LWS_WITH_HTTP_AUTH_DIGEST)
static const char *digest_toks[] = {
	"Digest",	// 1 <<  0
	"username",	// 1 <<  1
	"realm",	// 1 <<  2
	"nonce",	// 1 <<  3
	"uri",		// 1 <<  4 optional
	"response",	// 1 <<  5
	"opaque",	// 1 <<  6
	"qop",		// 1 <<  7
	"algorithm"	// 1 <<  8
	"nc",		// 1 <<  9
	"cnonce",	// 1 << 10
	"domain",	// 1 << 11
};

#define PEND_NAME_EQ -1
#define PEND_DELIM -2

#endif

enum lws_check_http_auth_results
lws_check_http_auth(struct lws *wsi, const char *http_auth_login_file)
{
	char b64[512];
	int m, ml, fi;
#if defined(LWS_WITH_HTTP_AUTH_DIGEST)
	uint8_t nonce[LWS_GENHASH_LARGEST], response[LWS_GENHASH_LARGEST];
		//a1[LWS_GENHASH_LARGEST];
	int seen = 0, n, pend = -1, skipping = 0, urilen;
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	char username[32], realm[32], vh_priv[33], *uri, nbuf[128];
	time_t t;
#endif
#if defined(LWS_WITH_HTTP_AUTH_BASIC)
	char plain[(sizeof(b64) * 3) / 4];
	char *pcolon;
#endif

	if (!http_auth_login_file)
		return LCBA_CONTINUE;

	/* Did he send auth? */
	ml = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	if (!ml)
		return LCBA_FAILED_AUTH;

	/* Disallow fragmentation monkey business */

	fi = wsi->http.ah->frag_index[WSI_TOKEN_HTTP_AUTHORIZATION];
	if (wsi->http.ah->frags[fi].nfrag) {
		lwsl_err("fragmented http auth header not allowed\n");
		return LCBA_FAILED_AUTH;
	}

	m = lws_hdr_copy(wsi, b64, sizeof(b64), WSI_TOKEN_HTTP_AUTHORIZATION);
	if (m < 7) {
		lwsl_err("%s: HTTP auth length bad\n", __func__);
		return LCBA_END_TRANSACTION;
	}

	puts(b64);

#if defined(LWS_WITH_HTTP_AUTH_DIGEST)
	/*
	 * We are expecting AUTHORIZATION to have something like this
	 *
	 * Authorization: Digest
	 *   username="Mufasa",
	 *   realm="testrealm@host.com",
	 *   nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	 *   uri="/dir/index.html",
	 *   response="e966c932a9242554e42c8ee200cec7f6",
	 *   opaque="5ccc069c403ebaf9f0171e9517f40e41"
	 *
	 * but the order, whitespace etc is quite open.  uri is optional
	 */

	ts.start = b64;
	ts.len = m;
	ts.flags = LWS_TOKENIZE_F_MINUS_NONTERM | LWS_TOKENIZE_F_NO_INTEGERS |
		   LWS_TOKENIZE_F_RFC7230_DELIMS;

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (pend == 8) {
				/* algorithm name */

				if (strncasecmp(ts.token, "MD5", ts.token_len)) {
					lwsl_err("wrog alg %.*s\n", ts.token_len, ts.token);
					return LCBA_END_TRANSACTION;
				}
				pend = PEND_DELIM;
				break;
			}
			if (strncasecmp(ts.token, "Digest", ts.token_len)) {
				skipping = 1;
				break;
			}
			if (seen) { /* we must be first and one time */
				lwsl_notice("%s: repeated auth type\n", __func__);
				return LCBA_END_TRANSACTION;
			}

			seen |= 1 << 15;
			pend = PEND_NAME_EQ;
			break;

		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			if (skipping)
				break;
			if (!(seen & (1 << 15)) || pend != -1) {
				lwsl_notice("%s: b\n", __func__);

				/* no auth type token or disordered */
				return LCBA_END_TRANSACTION;
			}

			for (n = 0; n < (int)LWS_ARRAY_SIZE(digest_toks); n++)
				if (!strncmp(ts.token, digest_toks[n],
					    ts.token_len))
					break;

			if (n == LWS_ARRAY_SIZE(digest_toks)) {
				lwsl_notice("%s: c: '%.*s'\n", __func__,
						ts.token_len, ts.token);

				return LCBA_END_TRANSACTION;
			}

			if (seen & (1 << n) || !(seen & (1 << 15))) {
				lwsl_notice("%s: d\n", __func__);
				/* dup or no auth type token */
				return LCBA_END_TRANSACTION;
			}

			seen |= 1 << n;
			pend = n;
			break;

		case LWS_TOKZE_QUOTED_STRING:
			if (skipping)
				break;
			if (pend < 0) {
				lwsl_notice("%s: e\n", __func__);

				return LCBA_END_TRANSACTION;
			}

			switch (pend) {
			case 1: /* username */
				if (ts.token_len >= (int)sizeof(username)) {
					lwsl_notice("%s: f\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				strncpy(username, ts.token, sizeof(username));
				break;
			case 2: /* realm */
				if (ts.token_len >= (int)sizeof(realm)) {
					lwsl_notice("%s: f1\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				strncpy(realm, ts.token, sizeof(realm));
				break;
			case 3: /* nonce */
				if (lws_hex_to_byte_array(ts.token,
						ts.token_len, nonce,
						sizeof(nonce)) < 0) {
					lwsl_notice("%s: g\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				break;
			case 4: /* uri */
				break;
			case 5: /* response */
				if (ts.token_len != (int)
				    lws_genhash_size(LWS_HTTP_AUTH_DIGEST_GENHASH) * 2) {
					lwsl_notice("%s: h\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				if (lws_hex_to_byte_array(ts.token,
						ts.token_len, response,
						sizeof(response)) < 0) {
					lwsl_notice("%s: i\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				break;
			case 6: /* opaque */
				break;
			case 7: /* qop */
				if (strncmp(ts.token, "auth", ts.token_len)) {
					lwsl_notice("%s: j\n", __func__);

					return LCBA_END_TRANSACTION;
				}
				break;
			}
			pend = PEND_DELIM;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == ',') {
				if (skipping)
					break;
				if (pend != PEND_DELIM) {
					lwsl_notice("%s: k\n", __func__);
					return LCBA_END_TRANSACTION;
				}
				pend = PEND_NAME_EQ;
				break;
			}
			if (*ts.token == ';') {
				if (skipping) {
					/* try again with this one */
					skipping = 0;
					break;
				}
				/* it's the end */
				e = LWS_TOKZE_ENDED;
				break;
			}
			break;

		case LWS_TOKZE_ENDED:
			break;

		default:
			lwsl_notice("%s: unexpected token %d\n", __func__, e);
			return LCBA_END_TRANSACTION;
		}

	} while (e > 0);

	if (e != LWS_TOKZE_ENDED) {
		lwsl_notice("%s: l\n", __func__);
		return LCBA_END_TRANSACTION;
	}

	/* we got all the parts we care about? */

	if ((seen & 0x810e) != 0x810e) {
		lwsl_notice("%s: m: 0x%x\n", __func__, seen & 0x81ef);
		return LCBA_END_TRANSACTION;
	}

	if (lws_http_get_uri_and_method(wsi, &uri, &urilen) < 0) {
		lwsl_notice("%s: get uri failed\n", __func__);

		return -1;
	}

	/* look up the user */

	//n = lws_snprintf(nbuf, sizeof(nbuf), "%s:", username);


	/* ... todo ... */

	time(&t);

	lws_byte_array_to_hex(wsi->vhost->http.http_digest_auth_key,
			      sizeof(wsi->vhost->http.http_digest_auth_key),
			      vh_priv, sizeof(vh_priv));

	/* A1       = unq(username) ":" unq(realm) ":" passwd */

	// n = lws_snprintf(nbuf, sizeof(nbuf), "%s:%s:%s", username, realm,



	/* check if the nonce is one of ours, allowing 0-2s to have passed */

	for (m = 0; m >= -2; m--) {
		uint8_t digest[LWS_GENHASH_LARGEST];
	        struct lws_genhash_ctx hc;

		time(&t);
		lws_byte_array_to_hex(wsi->vhost->http.http_digest_auth_key,
				      sizeof(wsi->vhost->http.http_digest_auth_key),
				      vh_priv, sizeof(vh_priv));

		n = lws_snprintf(nbuf, sizeof(nbuf), "%lu:%.*s:%s",
				 (unsigned long)t + (long)m, urilen, uri,
				 vh_priv);

	        if (lws_genhash_init(&hc, LWS_HTTP_AUTH_DIGEST_GENHASH) ||
	            lws_genhash_update(&hc, nbuf, n) ||
	            lws_genhash_destroy(&hc, digest)) {
	                lws_genhash_destroy(&hc, NULL);
			lwsl_err("%s: hash failed\n", __func__);

			return LCBA_END_TRANSACTION;
	        }

	        /* do we accept this nonce as valid? */
	        lwsl_hexdump_notice(response, 16);
		if (!memcmp(digest, response,
			    lws_genhash_size(LWS_HTTP_AUTH_DIGEST_GENHASH)))
			break;
	}

	if (n == -3) {
		lwsl_notice("%s: couldn't match digest\n", __func__);
		return LCBA_END_TRANSACTION;
	}

	/* check the response */

	/* accept it */

	strncpy(wsi->http.username, username, sizeof(wsi->http.username));
#endif

#if defined(LWS_WITH_HTTP_AUTH_BASIC)
	b64[5] = '\0';
	if (strcasecmp(b64, "Basic")) {
		lwsl_err("auth missing basic: %s\n", b64);
		return LCBA_END_TRANSACTION;
	}

	/* It'll be like Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l */

	m = lws_b64_decode_string(b64 + 6, plain, sizeof(plain) - 1);
	if (m < 0) {
		lwsl_err("plain auth too long\n");
		return LCBA_END_TRANSACTION;
	}

	plain[m] = '\0';
	pcolon = strchr(plain, ':');
	if (!pcolon) {
		lwsl_err("basic auth format broken\n");
		return LCBA_END_TRANSACTION;
	}
	if (!lws_find_string_in_file(http_auth_login_file, plain, m)) {
		lwsl_err("basic auth lookup failed\n");
		return LCBA_FAILED_AUTH;
	}
	*pcolon = '\0';

	/*
	 * Rewrite WSI_TOKEN_HTTP_AUTHORIZATION so it is just the
	 * authorized username
	 */

	wsi->http.ah->frags[fi].len = lws_ptr_diff(pcolon, plain);
	pcolon = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
	strncpy(pcolon, plain, ml - 1);
	pcolon[ml - 1] = '\0';
#endif

	lwsl_info("%s: http auth accepted for %s\n", __func__,
		 lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_AUTHORIZATION));

	return LCBA_CONTINUE;
}

