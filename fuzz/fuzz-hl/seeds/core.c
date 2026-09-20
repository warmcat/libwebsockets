 */

#include "private-lib-core.h"
#include <string.h>

int
lws_hl_construct(lws_hl_ctx_t *ctx, const lws_hl_ops_t *lang,
		 lws_hl_token_cb cb, void *user)
{
	if (!ctx || !lang || !lang->parse || !lang->finish || !cb)
		return 1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ops	= lang;
	ctx->cb		= cb;
	ctx->user	= user;

	if (lang->construct && lang->construct(ctx))
		return 1;

	return 0;
}

lws_stateful_ret_t
lws_hl_parse(lws_hl_ctx_t *ctx, const uint8_t **buf, size_t *len)
{
	if (!ctx || !buf || !len)
		return LWS_SRET_FATAL;

	if (!*len)
		return LWS_SRET_OK;

	return ctx->ops->parse(ctx, buf, len);
}

lws_stateful_ret_t
lws_hl_finish(lws_hl_ctx_t *ctx)
{
	if (!ctx)
		return LWS_SRET_FATAL;

	return ctx->ops->finish(ctx);
}
