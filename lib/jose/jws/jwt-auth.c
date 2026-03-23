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
 */

#include "private-lib-core.h"

struct lws_jwt_auth {
	struct lws_context *cx;
	struct lws *wsi;
	struct lws_jwk *jwk;
	lws_sorted_usec_list_t sul;
	lws_jwt_auth_cb_t cb;
	void *user;

	struct lws_dll2_owner grants;
	uint64_t exp;
	char cookie_name[64];
	char sub[128];
};

struct lws_jwt_auth_grant {
	lws_dll2_t list;
	char service_name[64];
	int grant_level;
};

static void
lws_jwt_auth_sul_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_jwt_auth *ja = lws_container_of(sul, struct lws_jwt_auth, sul);
	uint64_t now = (uint64_t)lws_now_secs();

	if (now >= ja->exp) {
		if (ja->cb)
			ja->cb(ja, LWS_JWT_AUTH_STATE_EXPIRED, ja->user);
	} else {
		if (ja->cb)
			ja->cb(ja, LWS_JWT_AUTH_STATE_REAUTH, ja->user);
	}
}

static void
lws_jwt_auth_schedule(struct lws_jwt_auth *ja)
{
	uint64_t now = (uint64_t)lws_now_secs();
	lws_usec_t us;

	lws_sul_cancel(&ja->sul);

	if (now >= ja->exp) {
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, 1);
		return;
	}

	uint64_t ttl = ja->exp - now;
	if (ttl <= 3600) {
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, 1);
	} else {
		us = (lws_usec_t)(ttl - 3600) * LWS_US_PER_SEC;
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
	}
}

struct jwt_auth_parse_ctx {
	struct lws_jwt_auth *ja;
	int parsing_grants;
};

static const char * const auth_paths[] = {
	"exp",
	"grants",
	"grants.*",
	"sub",
	"email",
};

enum {
	JAP_EXP,
	JAP_GRANTS,
	JAP_GRANTS_ANY,
	JAP_SUB,
	JAP_EMAIL,
};

static signed char
jwt_auth_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct jwt_auth_parse_ctx *pctx = (struct jwt_auth_parse_ctx *)ctx->user;

	if (reason == LEJPCB_OBJECT_START && ctx->path_match == JAP_GRANTS + 1) {
		pctx->parsing_grants = 1;
		return 0;
	}
	if (reason == LEJPCB_OBJECT_END && pctx->parsing_grants) {
		pctx->parsing_grants = 0;
		return 0;
	}

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match == JAP_EXP + 1) {
			pctx->ja->exp = (uint64_t)atoll(ctx->buf);
		} else if (ctx->path_match == JAP_GRANTS_ANY + 1 && pctx->parsing_grants) {
			struct lws_jwt_auth_grant *g = malloc(sizeof(*g));
			if (g) {
				memset(g, 0, sizeof(*g));
				lws_strncpy(g->service_name, ctx->path + 7, sizeof(g->service_name));
				g->grant_level = atoi(ctx->buf);
				lws_dll2_add_tail(&g->list, &pctx->ja->grants);
			}
		}
	} else if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		if (ctx->path_match == JAP_SUB + 1 || ctx->path_match == JAP_EMAIL + 1) {
			lws_strncpy(pctx->ja->sub, ctx->buf, sizeof(pctx->ja->sub));
		}
	}

	return 0;
}

int
lws_jwt_auth_update(struct lws_jwt_auth *ja, const char *jwt)
{
	char temp[2048], out[2048];
	size_t out_len = sizeof(out);
	struct lejp_ctx ctx;
	struct jwt_auth_parse_ctx pctx;
	int m;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ja->grants.head) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		lws_dll2_remove(&g->list);
		free(g);
	} lws_end_foreach_dll_safe(d, d1);

	if (lws_jwt_signed_validate(ja->cx, ja->jwk, "ES256,ES384,ES512,RS256,RS384,RS512,HS256",
				    jwt, strlen(jwt), temp, sizeof(temp), out, &out_len)) {
		lwsl_err("%s: Verification failed\n", __func__);
		return -1;
	}

	pctx.ja = ja;
	pctx.parsing_grants = 0;
	lejp_construct(&ctx, jwt_auth_lejp_cb, &pctx, auth_paths, LWS_ARRAY_SIZE(auth_paths));
	m = (int)(lejp_parse(&ctx, (uint8_t *)out, (int)out_len));
	lejp_destruct(&ctx);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_err("%s: JSON decode failed\n", __func__);
		return -1;
	}

	lws_jwt_auth_schedule(ja);

	return 0;
}

struct lws_jwt_auth *
lws_jwt_auth_create(struct lws *wsi, struct lws_jwk *jwk,
                    const char *cookie_name,
                    lws_jwt_auth_cb_t cb, void *user)
{
	char cookie[1024];
	char jwt[1024];
	struct lws_jwt_auth *ja;
	char *p;
	int i = 0;

	if (lws_hdr_copy(wsi, cookie, sizeof(cookie), WSI_TOKEN_HTTP_COOKIE) <= 0)
		return NULL;

	p = strstr(cookie, cookie_name);
	if (!p)
		return NULL;

	p += strlen(cookie_name);
	if (*p != '=')
		return NULL;
	p++;

	while (*p && *p != ';' && i < (int)sizeof(jwt) - 1)
		jwt[i++] = *p++;
	jwt[i] = '\0';

	ja = malloc(sizeof(*ja));
	if (!ja)
		return NULL;

	memset(ja, 0, sizeof(*ja));
	ja->cx = lws_get_context(wsi);
	ja->wsi = wsi;
	ja->jwk = jwk;
	ja->cb = cb;
	ja->user = user;
	lws_strncpy(ja->cookie_name, cookie_name, sizeof(ja->cookie_name));

	if (lws_jwt_auth_update(ja, jwt)) {
		free(ja);
		return NULL;
	}

	return ja;
}

int
lws_jwt_auth_query_grant(struct lws_jwt_auth *ja, const char *service_name)
{
	if (!ja)
		return -1;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, ja->grants.head) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		if (!strcmp(g->service_name, service_name))
			return g->grant_level;
	} lws_end_foreach_dll_safe(d, d1);

	return -1;
}

void
lws_jwt_auth_destroy(struct lws_jwt_auth **ja)
{
	if (!ja || !*ja)
		return;

	lws_sul_cancel(&((*ja)->sul));

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, (*ja)->grants.head) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		lws_dll2_remove(&g->list);
		free(g);
	} lws_end_foreach_dll_safe(d, d1);

	free(*ja);
	*ja = NULL;
}

const char *
lws_jwt_auth_get_sub(struct lws_jwt_auth *ja)
{
	if (!ja || !ja->sub[0])
		return NULL;
	return ja->sub;
}
