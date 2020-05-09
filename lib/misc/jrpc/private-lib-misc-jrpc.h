/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 * This written from scratch, but props to falk-werner for his earlier
 * work on top of lws for JRPC.
 *
 * https://github.com/falk-werner/jrpc
 *
 * https://www.jsonrpc.org/specification
 *
 * LWS JRPC takes the approach to stream-parse the incoming JRPC object in
 * place to maximize the flexibility and parameter sizes that can be handled.
 * Although "id" is often last, actually it has no users except to append the
 * same id to the response.
 *
 * Therefore we parse the outer JSON and treat params as a wormhole to be
 * parsed by a method-bound user callback.
 *
 * Streamed request processing must buffer its output before sending, since
 * it does not know until the end if it must replace the intended response
 * with an exception.  It may not know that it wants to make an exception
 * until it really processes all the params either.  Results must be held in
 * a side buffer until the response is able to complete or has errored.
 *
 * Types for id, method and params are ill-defined.  They're all treated as
 * strings internally, so a "method": 1 is handled as the string "1".  id
 * may be NULL, if so it's explicitly returned in the response with "id":null
 * Whether id came in as a non-quoted number is remembered and is reproduced
 * when giving the id.
 */

/*
 * Opaque object representing a request both at the sender and receiver
 */

typedef struct lws_jrpc_obj {
	lws_dll2_t		list;

	struct lejp_ctx		lejp_ctx;

	void			*opaque;
	const lws_jrpc_method_t	*pmethod; /* only look up once if multi part */

	char			id[16]; /* includes quotes if was string */
	char			method[48];
	/*
	 * Eg Sony API "getCurrentExternalTerminalsStatus" (30 chars)
	 *  https://developer.sony.com/develop/audio-control-api/api-references/api-overview-2
	 */
	char			version[4]; /* Eg for Sony, "2.0" */

	int			parse_result;

	uint8_t			count_batch_objects;

	uint8_t			seen_id		:1;
	uint8_t			inside_params	:1;
	uint8_t			has_jrpc_member	:1;
	uint8_t			response	:1;

} lws_jrpc_obj_t;


typedef struct lws_jrpc {
	lws_dll2_owner_t		req_owner;
	const lws_jrpc_method_t		*methods;
	void				*opaque;
} lws_jrpc_t;
