/*
 * ws protocol handler plugin for "generic sessions"
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#include "private-lwsgs.h"

void
sha1_to_lwsgw_hash(unsigned char *hash, lwsgw_hash *shash)
{
	static const char *hex = "0123456789abcdef";
	char *p = shash->id;
	int n;

	for (n = 0; n < 20; n++) {
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
	sha1_to_lwsgw_hash(hash_bin.bin, &pw_hash);

	return !strcmp(vhd->admin_password_sha1.id, pw_hash.id);
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
	char s[200], esc[50], esc1[50];

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

	for (n = 0; n < sizeof(sid->id) - 1 && *p; n++) {
		/* our SID we issue only has these chars */
		if ((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f'))
			sid->id[n] = *p++;
		else {
			lwsl_info("bad chars in cookie id %c\n", *p);
			return 1;
		}
	}

	if (n < sizeof(sid->id) - 1) {
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
		lwsl_info("session from cookie failed\n");
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
		strncpy(lla->username, col_val[0], lla->len);
		lla->username[lla->len - 1] = '\0';
		lwsl_info("%s: %s\n", __func__, lla->username);
	}

	return 0;
}

int
lwsgs_lookup_session(struct per_vhost_data__gs *vhd,
		     const lwsgw_hash *sid, char *username, int len)
{
	struct lla lla = { username, len, 1 };
	char s[150], esc[50];

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
			strncpy(u->username, col_val[n], sizeof(u->username) - 1);
			u->username[sizeof(u->username) - 1] = '\0';
			continue;
		}
		if (!strcmp(col_name[n], "ip")) {
			strncpy(u->ip, col_val[n], sizeof(u->ip) - 1);
			u->ip[sizeof(u->ip) - 1] = '\0';
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
			strncpy(u->email, col_val[n], sizeof(u->email) - 1);
			u->email[sizeof(u->email) - 1] = '\0';
			continue;
		}
		if (!strcmp(col_name[n], "verified")) {
			u->verified = atoi(col_val[n]);
			continue;
		}
		if (!strcmp(col_name[n], "pwhash")) {
			strncpy(u->pwhash.id, col_val[n], sizeof(u->pwhash.id) - 1);
			u->pwhash.id[sizeof(u->pwhash.id) - 1] = '\0';
			continue;
		}
		if (!strcmp(col_name[n], "pwsalt")) {
			strncpy(u->pwsalt.id, col_val[n], sizeof(u->pwsalt.id) - 1);
			u->pwsalt.id[sizeof(u->pwsalt.id) - 1] = '\0';
			continue;
		}
		if (!strcmp(col_name[n], "token")) {
			strncpy(u->token.id, col_val[n], sizeof(u->token.id) - 1);
			u->token.id[sizeof(u->token.id) - 1] = '\0';
			continue;
		}
	}
	return 0;
}

int
lwsgs_lookup_user(struct per_vhost_data__gs *vhd,
		  const char *username, struct lwsgs_user *u)
{
	char s[150], esc[50];

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
	unsigned char sid_rand[20];
	const char *u;
	char s[300], esc[50], esc1[50];

	if (username)
		u = username;
	else
		u = "";

	if (!sid)
		return 1;

	memset(sid, 0, sizeof(*sid));

	if (lws_get_random(vhd->context, sid_rand, sizeof(sid_rand)) !=
			   sizeof(sid_rand))
		return 1;

	sha1_to_lwsgw_hash(sid_rand, sid);

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

	return 0;
}

int
lwsgs_get_auth_level(struct per_vhost_data__gs *vhd,
		     const char *username)
{
	struct lwsgs_user u;
	int n = 0;

	/* we are logged in as some kind of user */
	if (username[0]) {
		n |= LWSGS_AUTH_LOGGED_IN;
		/* we are logged in as admin */
		if (!strcmp(username, vhd->admin_user))
			n |= LWSGS_AUTH_VERIFIED | LWSGS_AUTH_ADMIN; /* automatically verified */
	}

	if (!lwsgs_lookup_user(vhd, username, &u)) {
		if ((u.verified & 0xff) == LWSGS_VERIFIED_ACCEPTED)
			n |= LWSGS_AUTH_VERIFIED;

		if (u.last_forgot_validated > lws_now_secs() - 300)
			n |= LWSGS_AUTH_FORGOT_FLOW;
	}

	return n;
}

int
lwsgs_check_credentials(struct per_vhost_data__gs *vhd,
			const char *username, const char *password)
{
	unsigned char buffer[300];
	lwsgw_hash_bin hash_bin;
	struct lwsgs_user u;
	lwsgw_hash hash;
	int n;

	if (lwsgs_lookup_user(vhd, username, &u))
		return -1;

	lwsl_info("user %s found, salt '%s'\n", username, u.pwsalt.id);

	/* [password in ascii][salt] */
	n = lws_snprintf((char *)buffer, sizeof(buffer) - 1,
		     "%s-%s-%s", password, vhd->confounder, u.pwsalt.id);

	/* sha1sum of password + salt */
	lws_SHA1(buffer, n, hash_bin.bin);
	sha1_to_lwsgw_hash(&hash_bin.bin[0], &hash);

	return !!strcmp(hash.id, u.pwhash.id);
}

/* sets u->pwsalt and u->pwhash */

int
lwsgs_hash_password(struct per_vhost_data__gs *vhd,
		    const char *password, struct lwsgs_user *u)
{
	lwsgw_hash_bin hash_bin;
	lwsgw_hash hash;
	unsigned char sid_rand[20];
	unsigned char buffer[150];
	int n;

	/* create a random salt as big as the hash */

	if (lws_get_random(vhd->context, sid_rand,
			   sizeof(sid_rand)) !=
			   sizeof(sid_rand)) {
		lwsl_err("Problem getting random for salt\n");
		return 1;
	}
	sha1_to_lwsgw_hash(sid_rand, &u->pwsalt);

	if (lws_get_random(vhd->context, sid_rand,
			   sizeof(sid_rand)) !=
			   sizeof(sid_rand)) {
		lwsl_err("Problem getting random for token\n");
		return 1;
	}
	sha1_to_lwsgw_hash(sid_rand, &hash);

	/* [password in ascii][salt] */
	n = lws_snprintf((char *)buffer, sizeof(buffer) - 1,
		    "%s-%s-%s", password, vhd->confounder, u->pwsalt.id);

	/* sha1sum of password + salt */
	lws_SHA1(buffer, n, hash_bin.bin);
	sha1_to_lwsgw_hash(&hash_bin.bin[0], &u->pwhash);

	return 0;
}
