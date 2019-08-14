/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#include "private-lwsgs.h"
#include <stdlib.h>

void
sha256_to_lwsgw_hash(unsigned char *hash, lwsgw_hash *shash)
{
	static const char *hex = "0123456789abcdef";
	char *p = shash->id;
	int n;

	for (n = 0; n < (int)lws_genhash_size(LWS_GENHASH_TYPE_SHA256); n++) {
		*p++ = hex[(hash[n] >> 4) & 0xf];
		*p++ = hex[hash[n] & 15];
	}

	*p = '\0';
}

int
lwsgw_check_admin(struct per_vhost_data__gs *vhd,
		  const char *username, const char *password)
{
	lwsgw_hash_bin hash_bin;
	lwsgw_hash pw_hash;

	if (strcmp(vhd->admin_user, username))
		return 0;

	lws_SHA1((unsigned char *)password, strlen(password), hash_bin.bin);
	sha256_to_lwsgw_hash(hash_bin.bin, &pw_hash);

	return !strcmp(vhd->admin_password_sha256.id, pw_hash.id);
}

/*
 * secure cookie: it can only be passed over https where it cannot be
 *		  snooped in transit
 * HttpOnly:	  it can only be accessed via http[s] transport, it cannot be
 *		  gotten at by JS
 */
void
lwsgw_cookie_from_session(lwsgw_hash *sid, time_t expires, char **p, char *end)
{
	struct tm *tm = gmtime(&expires);
	time_t n = lws_now_secs();

	*p += lws_snprintf(*p, end - *p, "id=%s;Expires=", sid->id);
#ifdef WIN32
	*p += strftime(*p, end - *p, "%Y %H:%M %Z", tm);
#else
	*p += strftime(*p, end - *p, "%F %H:%M %Z", tm);
#endif
	*p += lws_snprintf(*p, end - *p, ";path=/");
	*p += lws_snprintf(*p, end - *p, ";Max-Age=%lu", (unsigned long)(expires - n));
//	*p += lws_snprintf(*p, end - *p, ";secure");
	*p += lws_snprintf(*p, end - *p, ";HttpOnly");
}

int
lwsgw_expire_old_sessions(struct per_vhost_data__gs *vhd)
{
	time_t n = lws_now_secs();
	char s[200];

	if (n - vhd->last_session_expire < 5)
		return 0;

	vhd->last_session_expire = n;

	lws_snprintf(s, sizeof(s) - 1,
		 "delete from sessions where "
		 "expire <= %lu;", (unsigned long)n);

	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to expire sessions: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}

int
lwsgw_update_session(struct per_vhost_data__gs *vhd,
		     lwsgw_hash *hash, const char *user)
{
	time_t n = lws_now_secs();
	char s[200], esc[96], esc1[96];

	if (user[0])
		n += vhd->timeout_absolute_secs;
	else
		n += vhd->timeout_anon_absolute_secs;

	lws_snprintf(s, sizeof(s) - 1,
		 "update sessions set expire=%lu,username='%s' where name='%s';",
		 (unsigned long)n,
		 lws_sql_purify(esc, user, sizeof(esc)),
		 lws_sql_purify(esc1, hash->id, sizeof(esc1)));

	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to update session: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	puts(s);

	return 0;
}

static int
lwsgw_session_from_cookie(const char *cookie, lwsgw_hash *sid)
{
	const char *p = cookie;
	int n;

	while (*p) {
		if (p[0] == 'i' && p[1] == 'd' && p[2] == '=') {
			p += 3;
			break;
		}
		p++;
	}
	if (!*p) {
		lwsl_info("no id= in cookie\n");
		return 1;
	}

	for (n = 0; n < (int)sizeof(sid->id) - 1 && *p; n++) {
		/* our SID we issue only has these chars */
		if ((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f'))
			sid->id[n] = *p++;
		else {
			lwsl_info("bad chars in cookie id %c\n", *p);
			return 1;
		}
	}

	if (n < (int)sizeof(sid->id) - 1) {
		lwsl_info("cookie id too short\n");
		return 1;
	}

	sid->id[sizeof(sid->id) - 1] = '\0';

	return 0;
}

int
lwsgs_get_sid_from_wsi(struct lws *wsi, lwsgw_hash *sid)
{
	char cookie[1024];

	/* fail it on no cookie */
	if (!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE)) {
		lwsl_info("%s: no cookie\n", __func__);
		return 1;
	}
	if (lws_hdr_copy(wsi, cookie, sizeof cookie, WSI_TOKEN_HTTP_COOKIE) < 0) {
		lwsl_info("cookie copy failed\n");
		return 1;
	}
	/* extract the sid from the cookie */
	if (lwsgw_session_from_cookie(cookie, sid)) {
		lwsl_info("%s: session from cookie failed\n", __func__);
		return 1;
	}

	return 0;
}

struct lla {
	char *username;
	int len;
	int results;
};

static int
lwsgs_lookup_callback(void *priv, int cols, char **col_val, char **col_name)
{
	struct lla *lla = (struct lla *)priv;

	//lwsl_err("%s: %d\n", __func__, cols);

	if (cols)
		lla->results = 0;
	if (col_val && col_val[0]) {
		lws_strncpy(lla->username, col_val[0], lla->len + 1);
		lwsl_info("%s: %s\n", __func__, lla->username);
	}

	return 0;
}

int
lwsgs_lookup_session(struct per_vhost_data__gs *vhd,
		     const lwsgw_hash *sid, char *username, int len)
{
	struct lla lla = { username, len, 1 };
	char s[150], esc[96];

	lwsgw_expire_old_sessions(vhd);

	lws_snprintf(s, sizeof(s) - 1,
		 "select username from sessions where name = '%s';",
		 lws_sql_purify(esc, sid->id, sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback, &lla, NULL) != SQLITE_OK) {
		lwsl_err("Unable to create user table: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return 1;
	}

	/* 0 if found */
	return lla.results;
}

int
lwsgs_lookup_callback_user(void *priv, int cols, char **col_val, char **col_name)
{
	struct lwsgs_user *u = (struct lwsgs_user *)priv;
	int n;

	for (n = 0; n < cols; n++) {
		if (!strcmp(col_name[n], "username")) {
			lws_strncpy(u->username, col_val[n], sizeof(u->username));
			continue;
		}
		if (!strcmp(col_name[n], "ip")) {
			lws_strncpy(u->ip, col_val[n], sizeof(u->ip));
			continue;
		}
		if (!strcmp(col_name[n], "creation_time")) {
			u->created = atol(col_val[n]);
			continue;
		}
		if (!strcmp(col_name[n], "last_forgot_validated")) {
			if (col_val[n])
				u->last_forgot_validated = atol(col_val[n]);
			else
				u->last_forgot_validated = 0;
			continue;
		}
		if (!strcmp(col_name[n], "email")) {
			lws_strncpy(u->email, col_val[n], sizeof(u->email));
			continue;
		}
		if (!strcmp(col_name[n], "verified")) {
			u->verified = atoi(col_val[n]);
			continue;
		}
		if (!strcmp(col_name[n], "pwhash")) {
			lws_strncpy(u->pwhash.id, col_val[n], sizeof(u->pwhash.id));
			continue;
		}
		if (!strcmp(col_name[n], "pwsalt")) {
			lws_strncpy(u->pwsalt.id, col_val[n], sizeof(u->pwsalt.id));
			continue;
		}
		if (!strcmp(col_name[n], "token")) {
			lws_strncpy(u->token.id, col_val[n], sizeof(u->token.id));
			continue;
		}
	}
	return 0;
}

int
lwsgs_lookup_user(struct per_vhost_data__gs *vhd,
		  const char *username, struct lwsgs_user *u)
{
	char s[150], esc[96];

	u->username[0] = '\0';
	lws_snprintf(s, sizeof(s) - 1,
		 "select username,creation_time,ip,email,verified,pwhash,pwsalt,last_forgot_validated "
		 "from users where username = '%s';",
		 lws_sql_purify(esc, username, sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup user: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return -1;
	}

	return !u->username[0];
}

int
lwsgs_new_session_id(struct per_vhost_data__gs *vhd,
		     lwsgw_hash *sid, const char *username, int exp)
{
	unsigned char sid_rand[32];
	const char *u;
	char s[300], esc[96], esc1[96];

	if (username)
		u = username;
	else
		u = "";

	if (!sid) {
		lwsl_err("%s: NULL sid\n", __func__);
		return 1;
	}

	memset(sid, 0, sizeof(*sid));

	if (lws_get_random(vhd->context, sid_rand, sizeof(sid_rand)) !=
			   sizeof(sid_rand))
		return 1;

	sha256_to_lwsgw_hash(sid_rand, sid);

	lws_snprintf(s, sizeof(s) - 1,
		 "insert into sessions(name, username, expire) "
		 "values ('%s', '%s', %u);",
		 lws_sql_purify(esc, sid->id, sizeof(esc) - 1),
		 lws_sql_purify(esc1, u, sizeof(esc1) - 1), exp);

	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert session: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return 1;
	}

	lwsl_notice("%s: created session %s\n", __func__, sid->id);

	return 0;
}

int
lwsgs_get_auth_level(struct per_vhost_data__gs *vhd, const char *username)
{
	struct lwsgs_user u;
	int n = 0;

	/* we are logged in as some kind of user */
	if (username[0]) {
		/* we are logged in as admin */
		if (!strcmp(username, vhd->admin_user))
			/* automatically verified */
			n |= LWSGS_AUTH_VERIFIED | LWSGS_AUTH_ADMIN;
	}

	if (!lwsgs_lookup_user(vhd, username, &u)) {
		if ((u.verified & 0xff) == LWSGS_VERIFIED_ACCEPTED)
			n |= LWSGS_AUTH_LOGGED_IN | LWSGS_AUTH_VERIFIED;

		if (u.last_forgot_validated > (time_t)lws_now_secs() - 300)
			n |= LWSGS_AUTH_FORGOT_FLOW;
	}

	return n;
}

int
lwsgs_check_credentials(struct per_vhost_data__gs *vhd,
			const char *username, const char *password)
{
	struct lws_genhash_ctx hash_ctx;
	lwsgw_hash_bin hash_bin;
	struct lwsgs_user u;
	lwsgw_hash hash;

	if (lwsgs_lookup_user(vhd, username, &u))
		return -1;

	lwsl_info("user %s found, salt '%s'\n", username, u.pwsalt.id);

	/* sha256sum of password + salt */

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hash_ctx, password, strlen(password)) ||
	    lws_genhash_update(&hash_ctx, "-", 1) ||
	    lws_genhash_update(&hash_ctx, vhd->confounder, strlen(vhd->confounder)) ||
	    lws_genhash_update(&hash_ctx, "-", 1) ||
	    lws_genhash_update(&hash_ctx, u.pwsalt.id, strlen(u.pwsalt.id)) ||
	    lws_genhash_destroy(&hash_ctx, hash_bin.bin)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		return 1;
	}

	sha256_to_lwsgw_hash(&hash_bin.bin[0], &hash);

	return !!strcmp(hash.id, u.pwhash.id);
}

/* sets u->pwsalt and u->pwhash */

int
lwsgs_hash_password(struct per_vhost_data__gs *vhd,
		    const char *password, struct lwsgs_user *u)
{
	unsigned char sid_rand[32];
	struct lws_genhash_ctx hash_ctx;
	lwsgw_hash_bin hash_bin;

	/* create a random salt as big as the hash */

	if (lws_get_random(vhd->context, sid_rand,
			   sizeof(sid_rand)) !=
			   sizeof(sid_rand)) {
		lwsl_err("Problem getting random for salt\n");
		return 1;
	}
	sha256_to_lwsgw_hash(sid_rand, &u->pwsalt);
/*
	if (lws_get_random(vhd->context, sid_rand,
			   sizeof(sid_rand)) !=
			   sizeof(sid_rand)) {
		lwsl_err("Problem getting random for token\n");
		return 1;
	}
	sha256_to_lwsgw_hash(sid_rand, &hash);
*/
	/* sha256sum of password + salt */

	if (lws_genhash_init(&hash_ctx, LWS_GENHASH_TYPE_SHA256) ||
	    lws_genhash_update(&hash_ctx, password, strlen(password)) ||
	    lws_genhash_update(&hash_ctx, "-", 1) ||
	    lws_genhash_update(&hash_ctx, vhd->confounder, strlen(vhd->confounder)) ||
	    lws_genhash_update(&hash_ctx, "-", 1) ||
	    lws_genhash_update(&hash_ctx, u->pwsalt.id, strlen(u->pwsalt.id)) ||
	    lws_genhash_destroy(&hash_ctx, hash_bin.bin)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		return 1;
	}

	sha256_to_lwsgw_hash(&hash_bin.bin[0], &u->pwhash);

	return 0;
}
