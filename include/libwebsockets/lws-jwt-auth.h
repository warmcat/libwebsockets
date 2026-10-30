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

#if !defined(_LWS_JWT_AUTH_H_)
#define _LWS_JWT_AUTH_H_

#define LWS_SSO_MAX_COOKIE 4096
struct lws_jwt_auth;

/* States emitted via the callback */
#define LWS_JWT_AUTH_STATE_REAUTH  1
#define LWS_JWT_AUTH_STATE_EXPIRED 2

typedef int (*lws_jwt_auth_cb_t)(struct lws_jwt_auth *ja, int state, void *user);

/*
 * The "pur" claim the lws auth server signs into its session and device
 * tokens, and that its in-tree relying parties (lws-login, deaddrop, hls,
 * oauth-preauth, dht-dnssec-monitor, the auth server itself) require.  Any
 * other kind of token signed with the same jwk carries a different purpose,
 * or none, and is refused by them.
 */
#define LWS_JWT_AUTH_PURPOSE_SSO "sso"

/**
 * struct lws_jwt_auth_info - what lws_jwt_auth_create_via_info() requires
 *
 * The strings are copied into the object, so they need not outlive the call;
 * lws_jwt_auth_update() on the object later applies the same requirements.
 */
struct lws_jwt_auth_info {
	struct lws_jwk		*jwk;
	/**< the key the issuer's signature must verify with */
	const char		*cookie_name;
	/**< exactly the name of the cookie to look for, eg "__Host-x" */
	const char		*iss;
	/**< NULL, or the issuer the token's "iss" must be exactly (< 128) */
	const char		*aud;
	/**< NULL, or the audience the token's "aud" must be exactly, as a
	 * string (< 128) */
	const char		*purpose;
	/**< NULL, or the purpose the token's "pur" must be exactly (< 32).
	 * When NULL, a token that has a "pur" claim at all is refused: it was
	 * minted for something else.  The signature covers the claims but not
	 * the cookie name, which the client chooses, so a jwk that signs more
	 * than one kind of token is only safe when every kind has its own
	 * purpose and every check asks for the one it wants. */
	lws_jwt_auth_cb_t	cb;
	/**< NULL, or the reauth / expiry callback */
	void			*user;
	/**< opaque pointer passed to cb */
};

/**
 * lws_jwt_auth_create_via_info() - lws_jwt_auth_create() with claim requirements
 *
 * \param wsi: The connection to extract the HTTP cookie from
 * \param i: the key, cookie name, required claims and callback
 * \param reason: NULL, or set to why on failure
 *
 * As lws_jwt_auth_create(), but each occurrence of the cookie must also carry
 * exactly the "iss", "aud" and "pur" claims \p i requires (see struct
 * lws_jwt_auth_info), each once, at the top level of the claims.  An
 * occurrence that doesn't is treated as one that failed verification.
 *
 * Returns NULL if no occurrence verified, or if \p i asks for an empty or
 * over-long claim, otherwise the allocated opaque object.
 */
LWS_VISIBLE LWS_EXTERN struct lws_jwt_auth *
lws_jwt_auth_create_via_info(struct lws *wsi, const struct lws_jwt_auth_info *i,
			     const char **reason);

/**
 * lws_jwt_auth_create() - Instantiates an opaque heap allocation from an incoming HTTP request
 *
 * \param wsi: The connection to extract the HTTP cookie from
 * \param jwk: The public JSON Web Key used to verify the issuer's signature
 * \param cookie_name: Natively searches WSI_TOKEN_HTTP_COOKIE for this payload.
 *		Exactly this name is looked for, with no __Host- / __Secure-
 *		aliasing: give the full name the cookie was minted under, eg,
 *		"__Host-x" for a cookie set by lws_jwt_sign_token_set_http_cookie()
 *		with a cookie_name of "x".
 * \param cb: Reauth/Expiry callback handler
 * \param user: Opaque context passed cleanly to the callback
 *
 * Scans the WSI for the designated cookie, validates cryptographic signatures natively,
 * executes lightweight lejp JSON parsing to extract the exp timestamp and ANY custom grants dictionaries,
 * allocates the tracking object, and registers the proactive SUL timer natively.
 *
 * Browsers can present several same-named cookies at once (host-only
 * alongside Domain=, or a leftover from an earlier cookie scope), oldest
 * first.  Every occurrence is tried: of those that verify and are unexpired,
 * the one that expires last wins, so a just-renewed token is not shadowed by
 * an older one still alive in the other scope.  If none is live, the first
 * that verified is returned so
 * the caller decides what an expired token means (check lws_jwt_auth_get_exp()).
 *
 * It requires no iss or aud, and no purpose: so a token that carries a "pur"
 * claim, ie, one minted for a specific purpose, is refused.  To accept tokens
 * of one purpose, or to require an issuer or audience, use
 * lws_jwt_auth_create_via_info().
 *
 * Returns NULL if no occurrence verified, or the allocated opaque object.
 */
LWS_VISIBLE LWS_EXTERN struct lws_jwt_auth *
lws_jwt_auth_create(struct lws *wsi, struct lws_jwk *jwk,
                    const char *cookie_name,
                    lws_jwt_auth_cb_t cb, void *user,
                    const char **reason);

/**
 * lws_jwt_auth_query_grant() - Extract a dynamic grant level
 *
 * \param ja: The opaque helper object
 * \param service_name: The target category string (e.g. "git-server")
 *
 * Evaluates the internally parsed grants array recursively.
 * Returns the integer level (e.g. 1, 2) if authorized, or -1 if unauthorized or missing.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwt_auth_query_grant(struct lws_jwt_auth *ja, const char *service_name);

/**
 * lws_jwt_auth_get_sub() - Extract the native subject (identity) string
 *
 * \param ja: The opaque helper object
 *
 * Returns a pointer to the extracted "sub" or "email" string literal on the object.
 * Returns NULL if no identity claim was parsed naturally.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_jwt_auth_get_sub(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_get_did() - get the device id associated with the jwt (if any)
 *
 * \param ja: the jwt auth object
 *
 * Returns the device ID ("did" claim) from the jwt, or NULL.
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_jwt_auth_get_did(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_get_uid() - Extract the native uid integer
 *
 * \param ja: The opaque helper object
 *
 * \return the integer UID natively parsed out of the token, or 0 if missing.
 */
LWS_VISIBLE LWS_EXTERN uint32_t
lws_jwt_auth_get_uid(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_get_exp() - Extract the expiration timestamp
 *
 * \param ja: The opaque helper object
 *
 * \return the uint64_t expiration unix timestamp, or 0 if missing.
 */
LWS_VISIBLE LWS_EXTERN uint64_t
lws_jwt_auth_get_exp(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_get_sec() - Extract the session epoch
 *
 * \param ja: The opaque helper object
 *
 * \return the session epoch parsed out of the token, or 0 if missing.
 */
LWS_VISIBLE LWS_EXTERN uint32_t
lws_jwt_auth_get_sec(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_count_grants() - Return the scalar count of active parsed grants
 *
 * \param ja: The opaque helper object
 */
LWS_VISIBLE LWS_EXTERN uint32_t
lws_jwt_auth_count_grants(struct lws_jwt_auth *ja);

/**
 * lws_jwt_auth_update() - Applies a refreshed JWT to the existing structure
 *
 * \param ja: The opaque helper object
 * \param jwt: The raw refreshed JWT signed blob string
 *
 * Processes the updated JWT cryptographically. Re-evaluates all grant strings,
 * recalculates exp, and safely shifts the SUL timer natively.  The new JWT
 * must meet the same iss / aud / purpose requirements the object was created
 * with.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwt_auth_update(struct lws_jwt_auth *ja, const char *jwt, const char **reason);

/**
 * lws_jwt_auth_destroy() - Gracefully cancels SUL instances and frees the allocation
 *
 * \param ja: Double-pointer to the object to cleanly wipe
 */
LWS_VISIBLE LWS_EXTERN void
lws_jwt_auth_destroy(struct lws_jwt_auth **ja);

#endif /* _LWS_JWT_AUTH_H_ */
