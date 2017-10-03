#include "private-libwebsockets.h"


LWS_EXTERN struct lws_rewrite *
lws_rewrite_create(struct lws *wsi, hubbub_callback_t cb, const char *from, const char *to)
{
	struct lws_rewrite *r = lws_malloc(sizeof(*r), "rewrite");

	if (!r) {
		lwsl_err("OOM\n");
		return NULL;
	}

	if (hubbub_parser_create("UTF-8", false, &r->parser) != HUBBUB_OK) {
		lws_free(r);

		return NULL;
	}
	r->from = from;
	r->from_len = strlen(from);
	r->to = to;
	r->to_len = strlen(to);
	r->params.token_handler.handler = cb;
	r->wsi = wsi;
	r->params.token_handler.pw = (void *)r;
	if (hubbub_parser_setopt(r->parser, HUBBUB_PARSER_TOKEN_HANDLER,
				 &r->params) != HUBBUB_OK) {
		lws_free(r);

		return NULL;
	}

	return r;
}

LWS_EXTERN int
lws_rewrite_parse(struct lws_rewrite *r,
		  const unsigned char *in, int in_len)
{
	if (hubbub_parser_parse_chunk(r->parser, in, in_len) != HUBBUB_OK)
		return -1;

	return 0;
}

LWS_EXTERN void
lws_rewrite_destroy(struct lws_rewrite *r)
{
	hubbub_parser_destroy(r->parser);
	lws_free(r);
}

