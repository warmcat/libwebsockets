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

/**
 * lws_jwt_auth_create() - Instantiates an opaque heap allocation from an incoming HTTP request
 *
 * \param wsi: The connection to extract the HTTP cookie from
 * \param jwk: The public JSON Web Key used to verify the issuer's signature
 * \param cookie_name: Natively searches WSI_TOKEN_HTTP_COOKIE for this payload
 * \param cb: Reauth/Expiry callback handler
 * \param user: Opaque context passed cleanly to the callback
 *
 * Scans the WSI for the designated cookie, validates cryptographic signatures natively,
 * executes lightweight lejp JSON parsing to extract the exp timestamp and ANY custom grants dictionaries,
 * allocates the tracking object, and registers the proactive SUL timer natively.
 *
 * Returns NULL on failure, or the allocated opaque object on a successful verification.
 */
LWS_VISIBLE LWS_EXTERN struct lws_jwt_auth *
lws_jwt_auth_create(struct lws *wsi, struct lws_jwk *jwk,
                    const char *cookie_name,
                    lws_jwt_auth_cb_t cb, void *user);

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
 * recalculates exp, and safely shifts the SUL timer natively.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jwt_auth_update(struct lws_jwt_auth *ja, const char *jwt);

/**
 * lws_jwt_auth_destroy() - Gracefully cancels SUL instances and frees the allocation
 *
 * \param ja: Double-pointer to the object to cleanly wipe
 */
LWS_VISIBLE LWS_EXTERN void
lws_jwt_auth_destroy(struct lws_jwt_auth **ja);

#endif /* _LWS_JWT_AUTH_H_ */
