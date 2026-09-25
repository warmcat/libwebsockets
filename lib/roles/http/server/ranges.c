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

#include "private-lib-core.h"

/*
 * RFC7233 examples
 *
 * o  The first 500 bytes (byte offsets 0-499, inclusive):
 *
 *      bytes=0-499
 *
 * o  The second 500 bytes (byte offsets 500-999, inclusive):
 *
 *      bytes=500-999
 *
 * o  The final 500 bytes (byte offsets 9500-9999, inclusive):
 *
 *      bytes=-500
 *
 * Or:
 *
 *      bytes=9500-
 *
 * o  The first and last bytes only (bytes 0 and 9999):
 *
 *      bytes=0-0,-1
 *
 * o  Other valid (but not canonical) specifications of the second 500
 *    bytes (byte offsets 500-999, inclusive):
 *
 *      bytes=500-600,601-999
 *      bytes=500-700,601-999
 */

/*
 * returns 1 if the range struct represents a usable range
 *   if no ranges header, you get one of these for the whole
 *   file.  Otherwise you get one for each valid range in the
 *   header.
 *
 * returns 0 if no further valid range forthcoming; rp->state
 *   may be LWSRS_SYNTAX or LWSRS_COMPLETED
 */

int
lws_ranges_next(struct lws_range_parsing *rp)
{
	static const char * const beq = "bytes=";

	if (!rp->buf) {
		/* there was no Range: header, or it has been let go of */
		rp->state = LWSRS_COMPLETED;

		return 0;
	}

	while (1) {

		char c = rp->buf[rp->pos];

		switch (rp->state) {
		case LWSRS_SYNTAX:
		case LWSRS_COMPLETED:
			return 0;

		case LWSRS_NO_ACTIVE_RANGE:
			rp->state = LWSRS_COMPLETED;
			return 0;

		case LWSRS_BYTES_EQ: // looking for "bytes="
			if (c != beq[rp->pos]) {
				rp->state = LWSRS_SYNTAX;
				return -1;
			}
			if (rp->pos == 5)
				rp->state = LWSRS_FIRST;
			break;

		case LWSRS_FIRST:
			rp->start = 0;
			rp->end = 0;
			rp->start_valid = 0;
			rp->end_valid = 0;

			rp->state = LWSRS_STARTING;

			// fallthru

		case LWSRS_STARTING:
			if (c == '-') {
				rp->state = LWSRS_ENDING;
				break;
			}

			if (!(c >= '0' && c <= '9')) {
				rp->state = LWSRS_SYNTAX;
				return 0;
			}
			rp->start = (unsigned long long)(((unsigned long long)rp->start * 10) + (unsigned long long)(c - '0'));
			rp->start_valid = 1;
			break;

		case LWSRS_ENDING:
			if (c == ',' || c == '\0') {
				rp->state = LWSRS_FIRST;
				if (c == ',')
					rp->pos++;

				rp->did_try = 1;

				/*
				 * RFC 7233 2.1: an empty representation has
				 * no satisfiable byte-range at all (and
				 * extent - 1 below would wrap).
				 */
				if (!rp->extent) {
					if (c == ',')
						break;
					rp->state = LWSRS_COMPLETED;
					return 0;
				}

				/*
				 * By the end of this, start and end are
				 * always valid if the range still is
				 */

				if (!rp->start_valid) { /* eg, -500 */
					if (rp->end > rp->extent)
						rp->end = rp->extent;

					rp->start = rp->extent - rp->end;
					rp->end = rp->extent - 1;
				} else
					if (!rp->end_valid)
						rp->end = rp->extent - 1;

				/*
				 * RFC 7233 2.1: a last-byte-pos at or past
				 * the representation length means "to the
				 * end"; without the clamp we would promise a
				 * Content-Length / Content-Range we cannot
				 * deliver and desync the connection.  A
				 * first-byte-pos past the end is
				 * unsatisfiable.
				 */
				if (rp->end >= rp->extent)
					rp->end = rp->extent - 1;

				/* end must be >= start or ignore it */
				if (rp->end < rp->start ||
				    rp->start >= rp->extent) {
					if (c == ',')
						break;
					rp->state = LWSRS_COMPLETED;
					return 0;
				}

				return 1; /* issue range */
			}

			if (!(c >= '0' && c <= '9')) {
				rp->state = LWSRS_SYNTAX;
				return 0;
			}
			rp->end = (unsigned long long)(((unsigned long long)rp->end * 10) + (unsigned long long)(c - '0'));
			rp->end_valid = 1;
			break;
		}

		rp->pos++;
	}
}

/*
 * A multipart/byteranges response has to delimit its parts with something
 * that cannot occur in what it is delimiting.  With a fixed boundary, a file
 * that contains the delimiter -- which a file the peer uploaded earlier may
 * well do on purpose -- forges parts of its own in the eyes of a client that
 * parses by scanning.  64 bits of random per response takes that away.
 */

int
lws_ranges_boundary_create(struct lws_context *cx,
			   struct lws_range_parsing *rp)
{
	uint8_t r[8];

	if (lws_get_random(cx, r, sizeof(r)) != sizeof(r)) {
		lwsl_err("%s: unable to get random\n", __func__);

		return 1;
	}

	memcpy(rp->boundary, "_lws_", 5);
	lws_hex_from_byte_array(r, sizeof(r), rp->boundary + 5,
				sizeof(rp->boundary) - 5);

	return 0;
}

size_t
lws_ranges_close_len(struct lws_range_parsing *rp)
{
	/* CRLF "--" boundary "--" CRLF */

	return strlen(rp->boundary) + 8;
}

void
lws_ranges_destroy(struct lws_range_parsing *rp)
{
	if (rp->buf)
		lws_free_set_NULL(rp->buf);

	rp->state = LWSRS_COMPLETED;
	rp->count_ranges = 0;
}

void
lws_ranges_reset(struct lws_range_parsing *rp)
{
	rp->pos = 0;
	rp->ctr = 0;
	rp->start = 0;
	rp->end = 0;
	rp->start_valid = 0;
	rp->end_valid = 0;
	rp->state = LWSRS_BYTES_EQ;
}

/*
 * returns count of valid ranges
 */
int
lws_ranges_init(struct lws *wsi, struct lws_range_parsing *rp,
		unsigned long long extent)
{
	int len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_RANGE);

	/* the previous request on this connection may have had ranges */
	lws_ranges_destroy(rp);

	rp->agg = 0;
	rp->send_ctr = 0;
	rp->inside = 0;
	rp->count_ranges = 0;
	rp->did_try = 0;
	lws_ranges_reset(rp);
	rp->state = LWSRS_COMPLETED;

	rp->extent = extent;

	if (!len)
		return 0; /* no Range: at all, serve the whole thing */

	/*
	 * Keep our own copy of the header for as long as the response takes:
	 * the parser is walked again for each range as its budget is spent,
	 * by which time the ah has long been handed to somebody else.  The
	 * ah bounds what len can be.
	 */

	rp->buf = lws_malloc((size_t)len + 1, "ranges");
	if (!rp->buf)
		return -1;

	if (lws_hdr_copy(wsi, rp->buf, len + 1,
			 WSI_TOKEN_HTTP_RANGE) <= 0) {
		lws_ranges_destroy(rp);

		return -1;
	}

	rp->state = LWSRS_BYTES_EQ;

	/*
	 * Note lws_ranges_next() returns -1 (not 0) if the header does not
	 * even start with "bytes=", so only a 1 means a range was issued
	 */

	while (lws_ranges_next(rp) == 1) {
		rp->count_ranges++;
		rp->agg += rp->end - rp->start + 1;

		/*
		 * RFC 7233 4.1: we are allowed to refuse an unreasonable set
		 * of ranges.  Non-overlapping ranges can never aggregate to
		 * more than the whole representation, so a larger total means
		 * the peer repeated or overlapped ranges to multiply what we
		 * send (and re-read from the filesystem) for one small header.
		 */

		if (rp->agg > rp->extent) {
			lwsl_notice("%s: overlapping / repeated ranges\n",
				    __func__);

			goto refuse;
		}

		/* the count is incremented above, so this accepts exactly
		 * LWS_RANGES_MAX of them and refuses the one after */

		if (rp->count_ranges > LWS_RANGES_MAX) {
			lwsl_notice("%s: more than %d ranges\n", __func__,
				    LWS_RANGES_MAX);

			goto refuse;
		}
	}

	lwsl_debug("%s: count %d\n", __func__, rp->count_ranges);
	lws_ranges_reset(rp);

	if (rp->did_try && !rp->count_ranges)
		goto refuse; /* not satisfiable */

	lws_ranges_next(rp);

	return rp->count_ranges;

refuse:
	/* nothing will be served from it, so it need not outlive the header */
	lws_ranges_destroy(rp);

	return -1;
}
