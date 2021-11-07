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
 * We use the lejp parse stack to replace the callback context for JSON
 * subtrees.
 *
 * It's optionally done when we see we're in a [] batch of reqs, we pass each
 * unitary req to the internal req parser.
 *
 * Each req does it to hand off the parsing of the parameters section.
 */

#include <private-lib-core.h>
#include "private-lib-misc-jrpc.h"

static const char * const paths[] = {
	"jsonrpc",
	"method",
	"version",
	"params",
	"id",
	/* only for responses --> */
	"result",
	"error",
	"code",
	"message",
	"data",
};

enum enum_paths {
	LEJPN_JSONRPC,
	LEJPN_METHOD,
	LEJPN_VERSION,
	LEJPN_PARAMS,
	LEJPN_ID,
	/* only for responses --> */
	LEJPN_RESULT,
	LEJPN_ERROR,
	LEJPN_E_CODE,
	LEJPN_E_MESSAGE,
	LEJPN_E_DATA,
};

/*
 * Get the registered handler for a method name... a registered handler for
 * a NULL method name matches any other unmatched name.
 */

static const lws_jrpc_method_t *
lws_jrpc_method_lookup(lws_jrpc_t *jrpc, const char *method_name)
{
	const lws_jrpc_method_t *m = jrpc->methods, *m_null = NULL;

	while (1) {

		if (!m->method_name)
			return m;

		if (!strcmp(method_name, m->method_name))
			return m;

		m++;
	}

	return m_null;
}

static signed char
req_cb(struct lejp_ctx *ctx, char reason)
{
	lws_jrpc_obj_t *r = (lws_jrpc_obj_t *)ctx->user;
	lws_jrpc_t *jrpc;
	char *p;

	lwsl_warn("%s: %d '%s' %s (sp %d, pst_sp %d)\n", __func__, reason, ctx->path, ctx->buf, ctx->sp, ctx->pst_sp);

	if (reason == LEJPCB_PAIR_NAME && ctx->path_match - 1 == LEJPN_PARAMS) {

		if (r->response)
			goto fail_invalid_members;
		/*
		 * Params are a wormhole to another LEJP parser context to deal
		 * with, chosen based on the method name and the callbacks
		 * associated with that at init time.
		 *
		 * Params may be provided in a toplevel array, called a "batch",
		 * these are treated as n independent subrequests to be handled
		 * sequentially, and if the request is parseable, the scope of
		 * errors is only the current batch entry.
		 */

		jrpc = lws_container_of(r->list.owner, lws_jrpc_t, req_owner);
		r->pmethod = lws_jrpc_method_lookup(jrpc, r->method);
		if (!r->pmethod || !r->pmethod->cb)
			/*
			 * There's nothing we can do with no method binding, or
			 * one that lacks a callback...
			 */
			goto fail_method_not_found;

		r->inside_params = 1;

		lwsl_notice("%s: params: entering subparser\n", __func__);
		lejp_parser_push(ctx, r, r->pmethod->paths,
				 (uint8_t)r->pmethod->count_paths, r->pmethod->cb);
	}

	if (reason == LEJPCB_COMPLETE && !r->response) {
		if (!r->has_jrpc_member)
			goto fail_invalid_request;
		if (r->method[0] && !r->pmethod) {
			jrpc = lws_container_of(r->list.owner, lws_jrpc_t,
						req_owner);
			r->pmethod = lws_jrpc_method_lookup(jrpc, r->method);
			if (!r->pmethod || !r->pmethod->cb)
				/*
				 * There's nothing we can do with no method
				 * binding, or one that lacks a callback...
				 */
				goto fail_method_not_found;
		}

		/*
		 * Indicate that the whole of the request has been parsed now
		 * and the id is known, so the method can complete and finalize
		 * its response
		 */
		r->pmethod->cb(ctx, LEJPCB_USER_START);

		return 0;
	}

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (ctx->path_match - 1 >= LEJPN_RESULT && !r->response)
		goto fail_invalid_members;

	switch (ctx->path_match - 1) {
	case LEJPN_JSONRPC:
		/*
		 * A String specifying the version of the JSON-RPC protocol.
		 * MUST be exactly "2.0".
		 */
		if (ctx->npos != 3 && strcmp(ctx->buf, "2.0")) {
			r->parse_result = LWSJRPCWKE__INVALID_REQUEST;
			return -1;
		}
		r->has_jrpc_member = 1;
		break;

	case LEJPN_METHOD:
		if (r->response)
			goto fail_invalid_members;

		/*
		 * Method is defined to be a string... anything else is invalid
		 */

		if (reason != LEJPCB_VAL_STR_END)
			goto fail_invalid_request;

		/*
		 * Restrict the method length to something sane
		 */
		if (ctx->npos > sizeof(r->method) - 1)
			goto fail_method_not_found;

		lws_strnncpy(r->method, ctx->buf, ctx->npos, sizeof(r->method));

		/* defer trying to use it so we catch parser errors */
		break;



	case LEJPN_ID:
		/*
		 * "An identifier established by the Client that MUST contain a
		 * String, Number, or NULL value if included. If it is not
		 * included it is assumed to be a notification. The value SHOULD
		 * normally not be Null and Numbers SHOULD NOT contain
		 * fractional parts."
		 *
		 * We defaulted the id to null, let's continue to store the id
		 * exactly as it would be reissued, ie, if a string, then we'll
		 * add the quotes around it now.
		 *
		 * Restrict the method length and type to something sane
		 */
		if (ctx->npos > sizeof(r->id) - 3 ||
		    reason == LEJPCB_VAL_TRUE ||
		    reason == LEJPCB_VAL_FALSE ||
		    /* if float, has "fractional part" */
		    reason == LEJPCB_VAL_NUM_FLOAT)
			goto fail_invalid_request;

		r->seen_id = 1;
		if (reason == LEJPCB_VAL_NULL)
			/* it already defaults to null */
			break;

		p = r->id;
		if (reason == LEJPCB_VAL_STR_END)
			*p++ = '\"';

		lws_strnncpy(p, ctx->buf, ctx->npos, sizeof(r->id) - 2);

		if (reason == LEJPCB_VAL_STR_END) {
			p += strlen(p);
			*p++ = '\"';
			*p = '\0';
		}

		break;

	case LEJPN_VERSION:
		/*
		 * Restrict the method length to something sane
		 */
		if (ctx->npos > sizeof(r->version) - 1)
			goto fail_invalid_request;
		lws_strnncpy(r->version, ctx->buf, ctx->npos, sizeof(r->version));
		break;

	/*
	 * Only for responses
	 */

	case LEJPN_RESULT:
		break;

	case LEJPN_ERROR:
		break;
	case LEJPN_E_CODE:
		break;
	case LEJPN_E_MESSAGE:
		break;
	case LEJPN_E_DATA:
		break;
	}

	return 0;

fail_invalid_members:
	r->parse_result = LWSJRPCE__INVALID_MEMBERS;

	return -1;

fail_invalid_request:
	r->parse_result = LWSJRPCWKE__INVALID_REQUEST;

	return -1;

fail_method_not_found:
	r->parse_result = LWSJRPCWKE__METHOD_NOT_FOUND;

	return -1;
}

const char *
lws_jrpc_obj_id(const struct lws_jrpc_obj *r)
{
	return r->id;
}

/*
 * Return code is >= 0 if completed, representing the amount of unused data in
 * the input buffer.  -1 indicates more input data needed, <-1 indicates an
 * error from the LWSJRPCWKE_ set above
 */
int
lws_jrpc_obj_parse(lws_jrpc_t *jrpc, int type, void *opaque,
		   const char *buf, size_t l, lws_jrpc_obj_t **_r)
{
	lws_jrpc_obj_t *r = *_r;
	int n;

	if (!r) {
		/*
		 * We need to init the request object
		 */
		r = *_r = malloc(sizeof(*r));
		if (!r)
			return LEJP_REJECT_UNKNOWN; /* OOM */

		memset(r, 0, sizeof *r);

		lws_dll2_add_tail(&r->list, &jrpc->req_owner);
		r->opaque = opaque;
		r->response = type == LWSJRPC_PARSE_RESPONSE;
		lws_strncpy(r->id, "null", sizeof(r->id));
		lejp_construct(&r->lejp_ctx, req_cb, r, paths,
			       LWS_ARRAY_SIZE(paths));
	}

	n = lejp_parse(&r->lejp_ctx, (uint8_t *)buf, (int)l);
	lwsl_debug("%s: raw parse result %d\n", __func__, n);
	if (n == LEJP_REJECT_CALLBACK)
		return r->parse_result;

	if (n < -1)
		return LWSJRPCWKE__PARSE_ERROR;

	return n;
}

void *
lws_jrpc_obj_get_opaque(const struct lws_jrpc_obj * r)
{
	return (void *)r->opaque;
}

void
lws_jrpc_obj_destroy(lws_jrpc_obj_t **_r)
{
	lws_jrpc_obj_t *r = *_r;

	if (!r)
		return;

	lws_dll2_remove(&r->list);

	free(r);
	*_r = NULL;
}

struct lws_jrpc *
lws_jrpc_create(const lws_jrpc_method_t *methods, void *opaque)
{
	lws_jrpc_t *j = malloc(sizeof(*j));

	if (!j)
		return NULL;

	memset(j, 0, sizeof(*j));

	j->opaque = opaque;
	j->methods = methods;

	return j;
}
void *
lws_jrpc_get_opaque(const struct lws_jrpc *jrpc)
{
	return (void *)jrpc->opaque;
}

void
lws_jrpc_destroy(lws_jrpc_t **_jrpc)
{
	struct lws_jrpc *jrpc = *_jrpc;

	if (!jrpc)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   jrpc->req_owner.head) {
		lws_jrpc_obj_t *r = lws_container_of(p, lws_jrpc_obj_t, list);

		lws_jrpc_obj_destroy(&r);
	} lws_end_foreach_dll_safe(p, p1);

	free(jrpc);
	*_jrpc = NULL;
}
