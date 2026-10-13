/*
 * lws-auth-feed: what the auth server tells the lws-login bouncers about its
 * records
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws-auth-server sends this, as one JSON object per ws message, over the
 * "lws-auth-feed" ws protocol to each lws-login that subscribes, once when it
 * connects and again whenever its records change.  It is everything lws-login
 * needs to decide whether an authentic, unexpired session token still stands,
 * so lws-login never needs the auth server's database or its private key, and
 * can run on another host.
 *
 * Both plugins include this, so the two ends share the one definition.
 */

#if !defined(__LWS_AUTH_FEED_H__)
#define __LWS_AUTH_FEED_H__

#define LWS_AUTH_FEED_PROTOCOL		"lws-auth-feed"
#define LWS_AUTH_FEED_SCHEMA		"lws-auth-feed-1"

/*
 * A feed secret shorter than this is refused at both ends: it is all that
 * stands between anybody who can reach the auth server and the list of its
 * users and grants
 */
#define LWS_AUTH_FEED_SECRET_MIN	32
#define LWS_AUTH_FEED_SECRET_MAX	128

/* one per account: the session epoch a live token for it must carry */
typedef struct lws_auth_feed_user {
	lws_dll2_t		list;
	uint64_t		uid;
	uint64_t		sec;
} lws_auth_feed_user_t;

/* one per grant an account holds */
typedef struct lws_auth_feed_grant {
	lws_dll2_t		list;
	const char		*svc;
	uint64_t		uid;
	int64_t			level;
} lws_auth_feed_grant_t;

/* one per device token that has not been revoked */
typedef struct lws_auth_feed_device {
	lws_dll2_t		list;
	const char		*did;
	uint64_t		uid;
} lws_auth_feed_device_t;

/* one per oauth client: its comma-separated redirect_uris, as stored */
typedef struct lws_auth_feed_ruris {
	lws_dll2_t		list;
	const char		*uris;
} lws_auth_feed_ruris_t;

typedef struct lws_auth_feed {
	const char		*jwk;	/* the public key tokens are signed with */
	lws_dll2_owner_t	users;	  /* lws_auth_feed_user_t */
	lws_dll2_owner_t	grants;	  /* lws_auth_feed_grant_t */
	lws_dll2_owner_t	devices;  /* lws_auth_feed_device_t */
	lws_dll2_owner_t	ruris;	  /* lws_auth_feed_ruris_t */
} lws_auth_feed_t;

static const lws_struct_map_t lsm_auth_feed_user[] = {
	LSM_UNSIGNED	(lws_auth_feed_user_t, uid,		"uid"),
	LSM_UNSIGNED	(lws_auth_feed_user_t, sec,		"sec"),
};

static const lws_struct_map_t lsm_auth_feed_grant[] = {
	LSM_STRING_PTR	(lws_auth_feed_grant_t, svc,		"svc"),
	LSM_UNSIGNED	(lws_auth_feed_grant_t, uid,		"uid"),
	LSM_SIGNED	(lws_auth_feed_grant_t, level,		"level"),
};

static const lws_struct_map_t lsm_auth_feed_device[] = {
	LSM_STRING_PTR	(lws_auth_feed_device_t, did,		"did"),
	LSM_UNSIGNED	(lws_auth_feed_device_t, uid,		"uid"),
};

static const lws_struct_map_t lsm_auth_feed_ruris[] = {
	LSM_STRING_PTR	(lws_auth_feed_ruris_t, uris,		"uris"),
};

static const lws_struct_map_t lsm_auth_feed[] = {
	LSM_STRING_PTR	(lws_auth_feed_t, jwk,			"jwk"),
	LSM_LIST	(lws_auth_feed_t, users, lws_auth_feed_user_t, list,
			 NULL, lsm_auth_feed_user,		"users"),
	LSM_LIST	(lws_auth_feed_t, grants, lws_auth_feed_grant_t, list,
			 NULL, lsm_auth_feed_grant,		"grants"),
	LSM_LIST	(lws_auth_feed_t, devices, lws_auth_feed_device_t, list,
			 NULL, lsm_auth_feed_device,		"devices"),
	LSM_LIST	(lws_auth_feed_t, ruris, lws_auth_feed_ruris_t, list,
			 NULL, lsm_auth_feed_ruris,		"ruris"),
};

static const lws_struct_map_t lsm_auth_feed_schema[] = {
	LSM_SCHEMA	(lws_auth_feed_t, NULL, lsm_auth_feed,
			 LWS_AUTH_FEED_SCHEMA),
};

/*
 * The feed secret PVO is either the secret itself, or, if it starts with a
 * '/', the path of a file holding it, so it can be kept out of the config.
 * It goes in an Authorization: header, so it must be printable ASCII with no
 * spaces.  Returns 0 if out holds a usable secret.
 */
static LWS_INLINE int
lws_auth_feed_secret_load(const char *pvo, char *out, size_t len)
{
	size_t n;
	int r;

	if (len < LWS_AUTH_FEED_SECRET_MAX + 1)
		return 1;

	if (*pvo == '/') {
		r = lws_plat_read_file(pvo, out, len - 1);
		if (r <= 0 || r >= (int)len - 1)
			return 1;
		out[r] = '\0';
	} else {
		/* never a truncated secret */
		if (strlen(pvo) >= len)
			return 1;
		lws_strncpy(out, pvo, len);
	}

	/* a file usually ends with a newline */
	n = strlen(out);
	while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';

	if (n < LWS_AUTH_FEED_SECRET_MIN || n > LWS_AUTH_FEED_SECRET_MAX)
		goto bail;

	while (n--)
		if (out[n] <= ' ' || out[n] > '~')
			goto bail;

	return 0;

bail:
	lws_explicit_bzero(out, len);

	return 1;
}

#endif
