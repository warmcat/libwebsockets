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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/** \defgroup whois WHOIS Client
 * ##WHOIS Client APIs
 */
///@{

struct lws_whois_results {
	lws_usec_t		creation_date;
	lws_usec_t		expiry_date;
	lws_usec_t		updated_date;
	char			nameservers[256];
	char			dnssec[64];
	char			ds_data[512];
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
	/**< Callback to receive results. Called once when query completes or fails. */
	void			*opaque;
	/**< User-supplied pointer passed to the callback */
};

/**
 * lws_whois_query() - Trigger a WHOIS query for a domain
 *
 * \param args: struct containing query parameters
 *
 * Returns 0 if the query was successfully initiated, or nonzero if failed.
 * The results are delivered asynchronously via the callback in args.
 */
#if defined(LWS_WITH_SYS_WHOIS)
LWS_VISIBLE LWS_EXTERN int
lws_whois_query(const struct lws_whois_args *args);
#else
#define lws_whois_query(_a) (1)
#endif

///@}
