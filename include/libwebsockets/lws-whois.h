/*
 * libwebsockets - small server side websockets and web server implementation
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LWS_WHOIS_H
#define _LWS_WHOIS_H

/** \defgroup whois WHOIS Client
 * ##WHOIS Client APIs
 */
///@{

/* hard cap on the size of lws_whois_json_purify() canonical output */
#define LWS_WHOIS_CANON_MAX	4096

/* the deadline for a whole query, if lws_whois_args.timeout_ms is 0 */
#define LWS_WHOIS_TIMEOUT_DEFAULT_MS	(20 * 1000)
/* an answer from one whois server larger than this fails the query */
#define LWS_WHOIS_ANSWER_MAX		(64 * 1024)

struct lws_whois_results {
	lws_usec_t		creation_date;
	lws_usec_t		expiry_date;
	lws_usec_t		updated_date;
	char			nameservers[256];
	/**< the nameservers, as "a, b, c" */
	char			dnssec[64];
	char			ds_data[512];
	uint8_t			nameservers_dropped;
	/**< nonzero if there were nameservers that did not fit in
	 * nameservers[]: only whole names are listed there */
};

typedef void (*lws_whois_cb_t)(void *opaque, const struct lws_whois_results *res);

struct lws_whois_args {
	struct lws_context	*context;
	/**< The lws context to run the query in */
	const char		*domain;
	/**< The domain name to query */
	const char		*server;
	/**< Optional: The WHOIS server to query directly. If NULL, recursive
	 * lookup starting from whois.iana.org is performed. */
	lws_whois_cb_t		cb;
	/**< Callback to receive results.  Called exactly once, when the
	 * query completes, or with NULL results when it fails: a failed
	 * connection, no referral, the deadline passing, an answer larger
	 * than LWS_WHOIS_ANSWER_MAX, or the context being destroyed with
	 * the query in flight. */
	void			*opaque;
	/**< User-supplied pointer passed to the callback */
	uint16_t		port;
	/**< Optional: TCP port for every connection of the query, or 0 for
	 * the standard whois port 43 */
	uint32_t		timeout_ms;
	/**< Optional: deadline for the whole query, including any referral,
	 * in ms, or 0 for LWS_WHOIS_TIMEOUT_DEFAULT_MS.  Whois servers only
	 * answer once and close, so nothing else notices one that accepts
	 * the connection and never does either. */
};

/**
 * lws_whois_query() - Trigger a WHOIS query for a domain
 *
 * \param args: struct containing query parameters
 *
 * Returns 0 if the query was successfully initiated, or nonzero if failed.
 * The results are delivered asynchronously via the callback in args, which
 * is only called if this returned 0.
 */
#if defined(LWS_WITH_SYS_WHOIS)
LWS_VISIBLE LWS_EXTERN int
lws_whois_query(const struct lws_whois_args *args);
#else
#define lws_whois_query(_a) (1)
#endif

/**
 * lws_whois_json_purify() - canonicalize untrusted whois JSON
 *
 * \param out: buffer to receive the canonical JSON; must be at least
 *	       4097 bytes
 * \param out_len: size of \p out in bytes
 * \param in: the untrusted JSON to purify
 * \param in_len: length of \p in in bytes
 * \param problems: if non-NULL, set nonzero if anything in the input was
 *		    not schema-conformant and had to be dropped (unknown
 *		    members, wrong-typed or out-of-range values, over-quota
 *		    nameservers) or the canonical form hit its size cap
 *
 * Parses \p in against a fixed whitelist of whois members
 * (creation_date, expiry_date, updated_date, nameservers, dnssec,
 * ds_data) with type, charset and range validation, and re-emits the
 * validated members as canonical JSON.  Members that are absent in the
 * input stay absent in the output; anything else in the input is
 * dropped and flagged via \p problems.
 *
 * Returns the length of the NUL-terminated canonical JSON written to
 * \p out, or -1 if \p in does not parse as JSON at all (in which case
 * nothing is written to \p out).  The canonical form is never larger
 * than 4096 bytes.
 */
#if defined(LWS_WITH_SYS_WHOIS)
LWS_VISIBLE LWS_EXTERN int
lws_whois_json_purify(char *out, size_t out_len, const char *in,
		      size_t in_len, int *problems);
#else
#define lws_whois_json_purify(_o, _ol, _i, _il, _p) ((void)(_o), -1)
#endif

/**
 * lws_whois_results_to_json() - express whois results as canonical JSON
 *
 * \param out: buffer to receive the canonical JSON; must be at least
 *	       4097 bytes
 * \param out_len: size of \p out in bytes
 * \param res: the results, as delivered to an lws_whois_cb_t
 * \param problems: if non-NULL, set nonzero if anything in \p res could
 *		    not be expressed and was left out, as
 *		    lws_whois_json_purify() would drop it, or if \p res
 *		    says the whois client already had to leave out some
 *		    nameservers
 *
 * Produces the same canonical form as lws_whois_json_purify(), with the
 * same validation: members with zero or empty values are absent, and the
 * comma-separated nameservers become an array.  So the output can be
 * handed to something that purifies it again, and pass cleanly.
 *
 * Returns the length of the NUL-terminated canonical JSON written to
 * \p out, or -1 if \p out is too small.
 */
#if defined(LWS_WITH_SYS_WHOIS)
LWS_VISIBLE LWS_EXTERN int
lws_whois_results_to_json(char *out, size_t out_len,
			  const struct lws_whois_results *res, int *problems);
#else
#define lws_whois_results_to_json(_o, _ol, _r, _p) ((void)(_o), -1)
#endif

///@}

#endif /* _LWS_WHOIS_H */
