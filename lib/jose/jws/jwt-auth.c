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

/*
 * The claims a caller can require, held by value in the object so that a later
 * lws_jwt_auth_update() applies the same contract without the caller's strings
 * having to outlive the create call.  An empty one is not required, except the
 * purpose: empty there means the token must carry no "pur" at all.
 */
#define LWS_JWT_AUTH_MAX_ISS_AUD	128
#define LWS_JWT_AUTH_MAX_PURPOSE	32

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
	char req_iss[LWS_JWT_AUTH_MAX_ISS_AUD];
	char req_aud[LWS_JWT_AUTH_MAX_ISS_AUD];
	char req_pur[LWS_JWT_AUTH_MAX_PURPOSE];
	uint32_t uid;
	uint32_t session_epoch;
};

struct lws_jwt_auth_grant {
	lws_dll2_t list;
	char service_name[64];
	int grant_level;
};

/*
 * "exp" and "iat" come out of the token, ie, they are chosen by the issuer and
 * atoll() saturates a wild one to LLONG_MAX.  Converting that many seconds to
 * us overflows the signed lws_usec_t (undefined, and in practice a tiny or
 * negative delay that re-arms immediately and spins).  Saturate the delay we
 * are willing to schedule instead.
 */

#define LWS_JWT_AUTH_MAX_SCHED_SECS ((uint64_t)10 * 365 * 24 * 60 * 60)

static lws_usec_t
lws_jwt_auth_secs_to_us(uint64_t secs)
{
	if (secs > LWS_JWT_AUTH_MAX_SCHED_SECS)
		secs = LWS_JWT_AUTH_MAX_SCHED_SECS;

	return (lws_usec_t)secs * LWS_US_PER_SEC;
}

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
		lws_usec_t us = lws_jwt_auth_secs_to_us(ja->exp - now);
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

	/* keep the 85% computation below out of uint64 wrap territory */
	if (total_val > LWS_JWT_AUTH_MAX_SCHED_SECS)
		total_val = LWS_JWT_AUTH_MAX_SCHED_SECS;

	uint64_t reauth_point = ja->exp - (total_val * 15) / 100; /* 85% */

	if (now >= reauth_point) {
		us = lws_jwt_auth_secs_to_us(ja->exp - now);
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
	} else {
		us = lws_jwt_auth_secs_to_us(reauth_point - now);
		lws_sul_schedule(ja->cx, 0, &ja->sul, lws_jwt_auth_sul_cb, us);
	}
}

/*
 * One top-level claim the caller may require: the token's value, its length
 * (a decoded \u0000 must not let a longer value compare equal), and how many
 * times it appeared, as any JSON type
 */
struct jwt_auth_claim {
	char val[LWS_JWT_AUTH_MAX_ISS_AUD];
	int len;		/* -1 unless it appeared as a string */
	int seen;
};

enum {
	JAC_ISS,
	JAC_AUD,
	JAC_PUR,

	JAC_COUNT
};

struct jwt_auth_parse_ctx {
	struct lws_jwt_auth *ja;
	struct jwt_auth_claim claim[JAC_COUNT];
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
	"iss",
	"aud",
	"pur",
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
	JAP_ISS,
	JAP_AUD,
	JAP_PUR,
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

/*
 * The slot for a top-level claim we judge, or NULL.  iss and aud are judged
 * only when the caller requires them, so that a token whose iss we don't care
 * about can't be refused for its shape.  "pur" is always judged: with no
 * purpose required, its mere presence refuses the token.
 */

static struct jwt_auth_claim *
jwt_auth_claim(struct jwt_auth_parse_ctx *pctx, struct lejp_ctx *ctx)
{
	switch (ctx->path_match - 1) {
	case JAP_ISS:
		return pctx->ja->req_iss[0] ? &pctx->claim[JAC_ISS] : NULL;
	case JAP_AUD:
		return pctx->ja->req_aud[0] ? &pctx->claim[JAC_AUD] : NULL;
	case JAP_PUR:
		return &pctx->claim[JAC_PUR];
	}

	return NULL;
}

static signed char
jwt_auth_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct jwt_auth_parse_ctx *pctx = (struct jwt_auth_parse_ctx *)ctx->user;
	struct jwt_auth_claim *cl = jwt_auth_claim(pctx, ctx);

	if (cl) {
		switch (reason) {
		case LEJPCB_VAL_STR_START:
		case LEJPCB_VAL_TRUE:
		case LEJPCB_VAL_FALSE:
		case LEJPCB_VAL_NULL:
		case LEJPCB_VAL_NUM_INT:
		case LEJPCB_VAL_NUM_FLOAT:
		case LEJPCB_OBJECT_START:
		case LEJPCB_ARRAY_START:
			/*
			 * A claim we judge must be unambiguous: a second
			 * occurrence refuses the token rather than letting
			 * member order decide which one we read
			 */
			if (cl->seen++)
				return -1;
			cl->len = -1;
			pctx->spos = 0;
			return 0;

		case LEJPCB_VAL_STR_CHUNK:
		case LEJPCB_VAL_STR_END:
			/*
			 * Too long to fit is too long to match anything a
			 * caller can require, so refusing is right
			 */
			if (jwt_auth_collate(cl->val, sizeof(cl->val),
					     &pctx->spos, ctx))
				return -1;
			if (reason == LEJPCB_VAL_STR_END)
				cl->len = pctx->spos;
			return 0;
		}

		return 0;
	}

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

/*
 * Any token the SSO pipeline carries, up to LWS_SSO_MAX_COOKIE, must verify
 * here: with 2KB buffers, a bigger one that was planted as the session cookie
 * never got through the gate.  On the heap, since lws_jwt_auth_create()
 * already has a cookie's worth on the stack when it calls us.
 */
#define LWS_JWT_AUTH_BUF	LWS_SSO_MAX_COOKIE

/*
 * Nonzero unless the token carried the claim once, as a string exactly equal
 * to req.  An empty req is not required, and never mismatches.
 */

static int
jwt_auth_claim_mismatch(const struct jwt_auth_claim *cl, const char *req)
{
	size_t rl = strlen(req);

	if (!rl)
		return 0;

	return cl->seen != 1 || cl->len < 0 || (size_t)cl->len != rl ||
	       memcmp(cl->val, req, rl);
}

int
lws_jwt_auth_update(struct lws_jwt_auth *ja, const char *jwt, const char **reason)
{
	size_t out_len = LWS_JWT_AUTH_BUF;
	struct jwt_auth_parse_ctx pctx;
	struct lejp_ctx ctx;
	char *temp, *out;
	int m, r;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, lws_dll2_get_head(&ja->grants)) {
		struct lws_jwt_auth_grant *g = lws_container_of(d, struct lws_jwt_auth_grant, list);
		lws_dll2_remove(&g->list);
		lws_free(g);
	} lws_end_foreach_dll_safe(d, d1);

	temp = lws_malloc(LWS_JWT_AUTH_BUF * 2, __func__);
	if (!temp) {
		if (reason)
			*reason = "OOM";
		return -1;
	}
	out = temp + LWS_JWT_AUTH_BUF;

	r = lws_jwt_signed_validate(ja->cx, ja->jwk,
				    "ES256,ES384,ES512,RS256,RS384,RS512,HS256",
				    jwt, strlen(jwt), temp, LWS_JWT_AUTH_BUF,
				    out, &out_len);
	if (r) {
		lws_free(temp);
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
	lws_free(temp);

	if (m < 0) {
		lwsl_err("%s: JSON decode failed\n", __func__);
		if (reason)
			*reason = "Failed to parse JWT payload JSON";
		return -1;
	}

	/*
	 * Tokens signed with one jwk for different purposes are told apart only
	 * by their claims: the signature covers the claims, and the client
	 * chooses which cookie it presents a token under.  So the issuer,
	 * audience and purpose the caller requires must be exactly the token's,
	 * and with no purpose required, a token that has one, ie, that was
	 * minted for something else, is refused (the same contract as
	 * lws_jwt_get_http_cookie_validate_jwt()).
	 */

	if (jwt_auth_claim_mismatch(&pctx.claim[JAC_ISS], ja->req_iss) ||
	    jwt_auth_claim_mismatch(&pctx.claim[JAC_AUD], ja->req_aud)) {
		lwsl_notice("%s: JWT iss / aud mismatch\n", __func__);
		if (reason)
			*reason = "JWT iss or aud mismatch";
		return -1;
	}

	if (ja->req_pur[0] ?
		jwt_auth_claim_mismatch(&pctx.claim[JAC_PUR], ja->req_pur) :
		pctx.claim[JAC_PUR].seen) {
		lwsl_notice("%s: JWT purpose mismatch\n", __func__);
		if (reason)
			*reason = "JWT purpose mismatch";
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

/*
 * A required claim must be held whole: a truncated requirement would accept
 * tokens it should not.  NULL is "not required"; "" can't be told from that,
 * so it is refused.
 */

static int
jwt_auth_req_bad(const char *req, size_t max)
{
	return req && (!*req || strlen(req) >= max);
}

struct lws_jwt_auth *
lws_jwt_auth_create(struct lws *wsi, struct lws_jwk *jwk,
		    const char *cookie_name,
		    lws_jwt_auth_cb_t cb, void *user,
		    const char **reason)
{
	struct lws_jwt_auth_info i;

	memset(&i, 0, sizeof(i));
	i.jwk		= jwk;
	i.cookie_name	= cookie_name;
	i.cb		= cb;
	i.user		= user;

	return lws_jwt_auth_create_via_info(wsi, &i, reason);
}

struct lws_jwt_auth *
lws_jwt_auth_create_via_info(struct lws *wsi,
			     const struct lws_jwt_auth_info *i,
			     const char **reason)
{
	struct lws_jwt_auth *ja = NULL, *cand;
	uint64_t now = (uint64_t)lws_now_secs();
	const char *r = NULL, *cr;
	char jwt[8192];
	size_t jwt_len;
	int n = 0, m;

	if (jwt_auth_req_bad(i->iss, LWS_JWT_AUTH_MAX_ISS_AUD) ||
	    jwt_auth_req_bad(i->aud, LWS_JWT_AUTH_MAX_ISS_AUD) ||
	    jwt_auth_req_bad(i->purpose, LWS_JWT_AUTH_MAX_PURPOSE)) {
		lwsl_err("%s: iss, aud or purpose empty or too long\n",
			 __func__);
		if (reason)
			*reason = "Unusable iss, aud or purpose requirement";

		return NULL;
	}

	/*
	 * Browsers legitimately present several same-named cookies at once
	 * (host-only alongside Domain=, or a leftover minted under an earlier
	 * cookie-domain config), ordered oldest-first per RFC 6265.  Taking
	 * only the first lets a stale one shadow a live one sitting behind it
	 * in the same header, and since every renewal and login re-mints the
	 * *other* scope, the user stays "not logged in" until the stale cookie
	 * ages out.  So walk every occurrence and take, of those that verify
	 * and are unexpired, the one that expires last.  Taking the first live
	 * one is not enough: an older token still a few seconds from its exp
	 * shadows the renewal that was just minted into the other scope, the
	 * page sees its session still about to expire and asks for another
	 * renewal, which lands in the other scope again, as fast as the round
	 * trip allows until the old one ages out.  If none is live, return the
	 * first that verified: what an expired token means is the caller's
	 * decision, exactly as before.  NULL only when nothing verified at all.
	 */
	for (;;) {
		jwt_len = sizeof(jwt);
		/*
		 * Exactly cookie_name: a caller whose cookie is minted as
		 * __Host-x passes "__Host-x", and a bare "x" planted by a
		 * sibling host is never taken for it
		 */
		m = lws_http_cookie_get_nth(wsi, i->cookie_name, n, jwt,
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
		cand->jwk = i->jwk;
		cand->cb = i->cb;
		cand->user = i->user;
		lws_strncpy(cand->cookie_name, i->cookie_name,
			    sizeof(cand->cookie_name));

		if (i->iss)
			lws_strncpy(cand->req_iss, i->iss,
				    sizeof(cand->req_iss));
		if (i->aud)
			lws_strncpy(cand->req_aud, i->aud,
				    sizeof(cand->req_aud));
		if (i->purpose)
			lws_strncpy(cand->req_pur, i->purpose,
				    sizeof(cand->req_pur));

		cr = NULL;
		if (lws_jwt_auth_update(cand, jwt, &cr)) {
			if (!r)
				r = cr;
			lws_jwt_auth_destroy(&cand);
			n++;
			continue;
		}

		/*
		 * lws_jwt_auth_update() guarantees a nonzero exp.  A live one
		 * replaces an expired fallback or a live one expiring sooner;
		 * an expired one is only kept as the fallback if nothing
		 * verified before it.
		 */
		if (!ja || (cand->exp > now && cand->exp > ja->exp)) {
			if (ja)
				lws_jwt_auth_destroy(&ja);
			ja = cand;
		} else
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
