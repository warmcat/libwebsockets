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

#define LWS_AUTH_MAX_COOKIE_LEN 4096

struct lws_jwt_auth {
	struct lws_context *cx;
	struct lws *wsi;
	struct lws_jwk *jwk;
	lws_sorted_usec_list_t sul;
	lws_jwt_auth_cb_t cb;
	void *user;

	struct lws_dll2_owner grants;
	uint64_t iat;
	uint64_t exp;
	uint64_t nbf;
	char cookie_name[64];
	char sub[128];
	char did[128];
	uint32_t uid;
	uint32_t session_epoch;
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

		/* Reschedule for the actual expiration */
		lws_usec_t us = (lws_usec_t)(ja->exp - now) * LWS_US_PER_SEC;
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
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

	uint64_t total_val = 0;
	if (ja->iat && ja->exp > ja->iat)
		total_val = ja->exp - ja->iat;
	else
		total_val = ja->exp - now;

	uint64_t reauth_point = ja->exp - (total_val * 15) / 100; /* 85% */

	if (now >= reauth_point) {
		us = (lws_usec_t)(ja->exp - now) * LWS_US_PER_SEC;
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
	} else {
		us = (lws_usec_t)(reauth_point - now) * LWS_US_PER_SEC;
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
	}
}

struct jwt_auth_parse_ctx {
	struct lws_jwt_auth *ja;
	int parsing_grants;
	int spos;		/* collation offset for the current string */
	char got_sub;		/* a "sub" claim was seen: "email" can't win */
};

static const char * const auth_paths[] = {
	"exp",
	"iat",
	"grants",
	"grants.*",
	"sub",
	"email",
	"uid",
	"did",
	"sec",
	"nbf",
};

enum {
	JAP_EXP,
	JAP_IAT,
	JAP_GRANTS,
	JAP_GRANTS_ANY,
	JAP_SUB,
	JAP_EMAIL,
	JAP_UID,
	JAP_DID,
	JAP_SEC,
	JAP_NBF,
};

/*
 * lejp delivers a long string value in LEJP_STRING_CHUNK pieces: collate them
 * from *pos instead of letting each piece overwrite the last, which would
 * store the *tail* of the claim as the identity.  A value that does not fit
 * is refused rather than truncated, since two different subjects must never
 * be able to collapse into one.
 */

static int
jwt_auth_collate(char *dest, size_t dest_len, int *pos, struct lejp_ctx *ctx)
{
	if ((size_t)*pos + (size_t)ctx->npos >= dest_len)
		return -1;

	memcpy(dest + *pos, ctx->buf, (size_t)ctx->npos);
	*pos += ctx->npos;
	dest[*pos] = '\0';

	return 0;
}

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

	if (reason == LEJPCB_VAL_STR_START) {
		pctx->spos = 0;

		return 0;
	}

	if (reason == LEJPCB_VAL_NUM_INT) {
		if (ctx->path_match == JAP_EXP + 1) {
			pctx->ja->exp = (uint64_t)atoll(ctx->buf);
		} else if (ctx->path_match == JAP_NBF + 1) {
			pctx->ja->nbf = (uint64_t)atoll(ctx->buf);
		} else if (ctx->path_match == JAP_IAT + 1) {
			pctx->ja->iat = (uint64_t)atoll(ctx->buf);
		} else if (ctx->path_match == JAP_UID + 1) {
			pctx->ja->uid = (uint32_t)atoi(ctx->buf);
		} else if (ctx->path_match == JAP_SEC + 1) {
			pctx->ja->session_epoch = (uint32_t)atoi(ctx->buf);
		} else if (ctx->path_match == JAP_GRANTS_ANY + 1 && pctx->parsing_grants) {
			struct lws_jwt_auth_grant *g =
					lws_zalloc(sizeof(*g), __func__);
			if (g) {
				lws_strncpy(g->service_name, ctx->path + 7, sizeof(g->service_name));
				g->grant_level = atoi(ctx->buf);
				lws_dll2_add_tail(&g->list, &pctx->ja->grants);
			}
		}
	} else if (reason == LEJPCB_VAL_STR_CHUNK || reason == LEJPCB_VAL_STR_END) {
		/*
		 * "sub" and "email" share one storage slot, so without a
		 * precedence rule the identity is decided by JSON member
		 * order... an issuer that emits a user-settable "email"
		 * alongside "sub" would then let the user choose his own
		 * subject.  "sub" always wins.
		 */
		if (ctx->path_match == JAP_SUB + 1) {
			if (jwt_auth_collate(pctx->ja->sub,
					     sizeof(pctx->ja->sub),
					     &pctx->spos, ctx))
				return -1;
			if (reason == LEJPCB_VAL_STR_END)
				pctx->got_sub = 1;
		} else if (ctx->path_match == JAP_EMAIL + 1 && !pctx->got_sub) {
			if (jwt_auth_collate(pctx->ja->sub,
					     sizeof(pctx->ja->sub),
					     &pctx->spos, ctx))
				return -1;
		} else if (ctx->path_match == JAP_DID + 1) {
			if (jwt_auth_collate(pctx->ja->did,
					     sizeof(pctx->ja->did),
					     &pctx->spos, ctx))
				return -1;
		}
	}

	return 0;
}

int
lws_jwt_auth_update(struct lws_jwt_auth *ja, const char *jwt, const char **reason)
{
	char temp[2048], out[2048];
	size_t out_len = sizeof(out);
	struct lejp_ctx ctx;
	struct jwt_auth_parse_ctx pctx;
	int m;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ja->grants)) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		lws_dll2_remove(&g->list);
		lws_free(g);
	} lws_end_foreach_dll_safe(d, d1);

	if (lws_jwt_signed_validate(ja->cx, ja->jwk, "ES256,ES384,ES512,RS256,RS384,RS512,HS256",
				    jwt, strlen(jwt), temp, sizeof(temp), out, &out_len)) {
		lwsl_err("%s: Verification failed\n", __func__);
		if (reason)
			*reason = "JWT signature verification failed";
		return -1;
	}

	memset(&pctx, 0, sizeof(pctx));
	pctx.ja = ja;

	/*
	 * Re-parsing an existing object must not inherit the old claims...
	 * uid and the session epoch especially, since those are what callers
	 * authorize and revoke on: a refresh token that omits them must not
	 * silently keep the identity and the epoch of the token before it.
	 */
	ja->exp = 0;
	ja->nbf = 0;
	ja->iat = 0;
	ja->uid = 0;
	ja->session_epoch = 0;
	ja->sub[0] = '\0';
	ja->did[0] = '\0';
	lejp_construct(&ctx, jwt_auth_lejp_cb, &pctx, auth_paths, LWS_ARRAY_SIZE(auth_paths));
	m = (int)(lejp_parse(&ctx, (uint8_t *)out, (int)out_len));
	lejp_destruct(&ctx);

	if (m < 0 && m != LEJP_REJECT_UNKNOWN) {
		lwsl_err("%s: JSON decode failed\n", __func__);
		if (reason)
			*reason = "Failed to parse JWT payload JSON";
		return -1;
	}

	/*
	 * RFC7519 leaves "exp" optional, but a session token without one never
	 * expires: refuse it rather than treat it as live forever.  All lws
	 * issuers mint an "exp".
	 */

	if (!ja->exp) {
		lwsl_err("%s: JWT has no exp claim\n", __func__);
		if (reason)
			*reason = "JWT has no exp claim";
		return -1;
	}

	/* and a token that is not valid yet is not usable either */

	if (ja->nbf && ja->nbf > (uint64_t)lws_now_secs()) {
		lwsl_err("%s: JWT not valid yet\n", __func__);
		if (reason)
			*reason = "JWT is not valid yet";
		return -1;
	}

	lws_jwt_auth_schedule(ja);

	return 0;
}

struct lws_jwt_auth *
lws_jwt_auth_create(struct lws *wsi, struct lws_jwk *jwk,
		    const char *cookie_name,
		    lws_jwt_auth_cb_t cb, void *user,
		    const char **reason)
{
	struct lws_jwt_auth *ja = NULL, *cand;
	uint64_t now = (uint64_t)lws_now_secs();
	const char *r = NULL, *cr;
	char jwt[8192];
	size_t jwt_len;
	int n = 0, m;

	/*
	 * Browsers legitimately present several same-named cookies at once
	 * (host-only alongside Domain=, or a leftover minted under an earlier
	 * cookie-domain config), ordered oldest-first per RFC 6265.  Taking
	 * only the first lets a stale one shadow a live one sitting behind it
	 * in the same header, and since every renewal and login re-mints the
	 * *other* scope, the user stays "not logged in" until the stale cookie
	 * ages out.  So walk every occurrence and take the first that
	 * verifies and is unexpired.  If none is live, return the first that
	 * verified: what an expired token means is the caller's decision,
	 * exactly as before.  NULL only when nothing verified at all.
	 */
	for (;;) {
		jwt_len = sizeof(jwt);
		if (!n)
			/*
			 * occurrence 0 via the prefix-aware lookup, so the
			 * __Host- / __Secure- aliases keep working when no
			 * plain-named cookie exists
			 */
			m = lws_http_cookie_get(wsi, cookie_name, jwt, &jwt_len);
		else
			m = lws_http_cookie_get_nth(wsi, cookie_name, n, jwt,
						    &jwt_len);
		if (m) {
			if (!r)
				r = m == 2 ? "Cookie value too large for buffer" :
					     "Cookie not found";
			if (m != 2)
				break; /* no more occurrences */
			n++; /* oversized: skip it, look behind it */
			continue;
		}

		cand = lws_zalloc(sizeof(*cand), __func__);
		if (!cand) {
			r = "OOM";
			break;
		}

		cand->cx = lws_get_context(wsi);
		cand->wsi = wsi;
		cand->jwk = jwk;
		cand->cb = cb;
		cand->user = user;
		lws_strncpy(cand->cookie_name, cookie_name,
			    sizeof(cand->cookie_name));

		cr = NULL;
		if (lws_jwt_auth_update(cand, jwt, &cr)) {
			if (!r)
				r = cr;
			lws_jwt_auth_destroy(&cand);
			n++;
			continue;
		}

		/* lws_jwt_auth_update() guarantees a nonzero exp */
		if (cand->exp > now) {
			/* live: this is the one, drop any expired fallback */
			if (ja)
				lws_jwt_auth_destroy(&ja);
			ja = cand;
			break;
		}

		if (!ja)
			ja = cand; /* verified but expired: fallback only */
		else
			lws_jwt_auth_destroy(&cand);
		n++;
	}

	/*
	 * Every way out of the loop with ja still NULL has set r: a cookie
	 * lookup miss, OOM, or lws_jwt_auth_update() failing, which always
	 * supplies a reason.
	 */
	if (!ja && reason)
		*reason = r;

	return ja;
}

int
lws_jwt_auth_query_grant(struct lws_jwt_auth *ja, const char *service_name)
{
	int wildcard_level = -1;

	if (!ja)
		return -1;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ja->grants)) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		if (!strcmp(g->service_name, service_name))
			return g->grant_level;
		if (!strcmp(g->service_name, "*"))
			wildcard_level = g->grant_level;
	} lws_end_foreach_dll_safe(d, d1);

	return wildcard_level;
}

void
lws_jwt_auth_destroy(struct lws_jwt_auth **ja)
{
	if (!ja || !*ja)
		return;

	lws_sul_cancel(&((*ja)->sul));

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&(*ja)->grants)) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		lws_dll2_remove(&g->list);
		lws_free(g);
	} lws_end_foreach_dll_safe(d, d1);

	lws_free(*ja);
	*ja = NULL;
}

const char *
lws_jwt_auth_get_sub(struct lws_jwt_auth *ja)
{
	if (!ja || !ja->sub[0])
		return NULL;
	return ja->sub;
}

const char *
lws_jwt_auth_get_did(struct lws_jwt_auth *ja)
{
	if (!ja || !ja->did[0])
		return NULL;
	return ja->did;
}

uint32_t
lws_jwt_auth_get_uid(struct lws_jwt_auth *ja)
{
	if (!ja)
		return 0;
	return ja->uid;
}

uint64_t
lws_jwt_auth_get_exp(struct lws_jwt_auth *ja)
{
	if (!ja)
		return 0;
	return ja->exp;
}

uint32_t
lws_jwt_auth_count_grants(struct lws_jwt_auth *ja)
{
	if (!ja)
		return 0;
	return lws_dll2_count(&ja->grants);
}

uint32_t
lws_jwt_auth_get_sec(struct lws_jwt_auth *ja)
{
	if (!ja)
		return 0;
	return ja->session_epoch;
}
