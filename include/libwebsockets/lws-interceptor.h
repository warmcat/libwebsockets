#include <stddef.h>
#if defined(LWS_WITH_JOSE)
/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

/** \defgroup captcha Captcha
 * ##Captcha API
 *
 * Lws provides a generic captcha "engine" that handles JWT sessions,
 * redirection flows, and asset serving. Captcha implementations (puzzles,
 * ratelimits, etc) provide a `struct lws_captcha_ops` to customize the
 * behavior.
 */
/**@{*/

typedef enum {
	LWS_INTERCEPTOR_RET_REJECT	= 0, /* Failed the challenge */
	LWS_INTERCEPTOR_RET_PASS	= 1, /* Passed immediately */
	LWS_INTERCEPTOR_RET_DELAYED	= 2, /* Use a timer before passing (for ratelimiting) */
} lws_interceptor_result_t;

struct lws_interceptor_ops {
	const char *name;		/* e.g., "ratelimit" or "puzzle" */

	/**
	 * [Optional] Add implementation-specific dynamic JS variables to
	 * the automatically served "captcha-config.js".
	 */
	int (*get_config_js)(struct lws *wsi, char *buf, size_t len);

	/**
	 * [Optional] Customize the "visit" JWT claims.
	 * e.g., Store a random math problem or puzzle seed here.
	 */
	int (*init_visit_cookie)(struct lws *wsi, char *buf, size_t len);

	/**
	 * Verify the POSTed challenge submission.
	 * Decides if the user passes, fails, or needs to wait.
	 */
	lws_interceptor_result_t (*verify)(struct lws *wsi, const void *data, size_t len);

	/**
	 * [Optional] Extra logic to run if verify returned LWS_INTERCEPTOR_RET_DELAYED
	 * and the timer expired.
	 */
	void (*on_delay_expired)(struct lws *wsi);
};

/**
 * lws_interceptor_check() - Check if a valid interceptor session exists
 *
 * \param wsi: the connection to check
 *
 * Returns 0 if a valid interceptor session exists (JWT cookie present and valid for IP),
 * non-zero if a interceptor diversion is required.
 */
LWS_VISIBLE LWS_EXTERN int
lws_interceptor_check(struct lws *wsi, const struct lws_protocols *prot);

/**
 * lws_interceptor_handle_http() - Generic HTTP handler for interceptor plugins
 *
 * \param wsi: the connection
 * \param user: PSS
 * \param ops: the interceptor implementations ops
 *
 * This handles serving assets, config JS, and processing POST submissions
 * using the provided wheat.
 */
LWS_VISIBLE LWS_EXTERN int
lws_interceptor_handle_http(struct lws *wsi, void *user, const struct lws_interceptor_ops *ops);

/**
 * lws_callback_interceptor() - Generic protocol callback for interceptor plugins
 */
LWS_VISIBLE LWS_EXTERN int
lws_callback_interceptor(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len,
		     const struct lws_interceptor_ops *ops);

/**@}*/

#endif
