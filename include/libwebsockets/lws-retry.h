/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/*
 * Specifies backoff ranges using a pair of uint32_t in ms for the min, max.
 *
 * The actual backoff timing is picked randomly within the range.
 */

typedef struct lws_retry_range {
	uint32_t		min_ms;
	uint32_t		max_ms;
} lws_retry_range_t;

typedef struct lws_retry_bo {
	const lws_retry_range_t	*retry_ms_table;        /* backoff range pair */
	uint16_t		retry_ms_table_count;      /* ranges in table */
	uint16_t		conceal_count;	    /* max retries to conceal */
} lws_retry_bo_t;

/**
 * lws_retry_get_delay_ms() - get next delay from backoff table
 *
 * \param lws_context: the lws context (used for getting random)
 * \param retry: the retry backoff table we are using
 * \param ctry: pointer to the try counter
 * \param conceal: pointer to flag set to nonzero if the try should be concealed
 *			in terms of creating an error
 *
 * Increments *\p try and retruns the number of ms that should elapse before the
 * next connection retry, according to the backoff table \p retry. *\p conceal is
 * set if the number of tries is less than the backoff table conceal_count, or
 * is zero if it exceeded it.  This lets you conceal a certain number of retries
 * before alerting the caller there is a problem.
 */

LWS_VISIBLE LWS_EXTERN unsigned int
lws_retry_get_delay_ms(struct lws_context *context, const lws_retry_bo_t *retry,
		        uint16_t *ctry, char *conceal);

