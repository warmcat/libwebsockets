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
 * included from libwebsockets.h
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

