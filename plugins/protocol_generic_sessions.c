/*
 * ws protocol handler plugin for "generic sessions"
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
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

#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"

#include <sqlite3.h>
#include <string.h>

#define LWSGS_EMAIL_CONTENT_SIZE 16384
#define LWSGS_VERIFIED_ACCEPTED 100

/* SHA-1 binary and hexified versions */
typedef struct { unsigned char bin[20]; } lwsgw_hash_bin;
typedef struct { char id[41]; } lwsgw_hash;

enum lwsgs_smtp_states {
	LGSSMTP_IDLE,
	LGSSMTP_CONNECTING,
	LGSSMTP_CONNECTED,
	LGSSMTP_SENT_HELO,
	LGSSMTP_SENT_FROM,
	LGSSMTP_SENT_TO,
	LGSSMTP_SENT_DATA,
	LGSSMTP_SENT_BODY,
	LGSSMTP_SENT_QUIT,
};

struct lwsgs_user {
	char username[32];
	char ip[16];
	lwsgw_hash pwhash;
	lwsgw_hash pwsalt;
	lwsgw_hash token;
	time_t created;
	char email[100];
	int verified;
};

struct per_vhost_data__generic_sessions {
	uv_timer_t timeout_email;
	enum lwsgs_smtp_states estate;
	struct lws_context *context;
	char session_db[256];
	char admin_user[32];
	char confounder[32];
	char email_from[72];
	char email_contact_person[128];
	char email_helo[32];
	char email_title[128];
	char email_template[128];
	char email_confirm_url[128];
	char email_smtp_ip[32];
	lwsgw_hash admin_password_sha1;
	sqlite3 *pdb;
	int timeout_idle_secs;
	int timeout_absolute_secs;
	int timeout_anon_absolute_secs;
	int timeout_email_secs;
	time_t last_session_expire;

	uv_connect_t email_connect_req;
	uv_tcp_t email_client;
	time_t email_connect_started;
	char email_buf[256];
	struct lwsgs_user u;
};

struct per_session_data__generic_sessions {
	lwsgw_hash login_session;
	lwsgw_hash delete_session;
	unsigned int login_expires;
	char onward[256];
	char result[500 + LWS_PRE];
	int result_len;
	char *start;
	char swallow[16];
	char ip[46];
	int pos;
	int spos;

	unsigned int logging_out:1;
};

static const char *
sql_purify(const char *string, char *escaped, int len)
{
	const char *p = string;
	char *q = escaped;

	while (*p && len-- > 2) {
		if (*p == '\'') {
			*q++ = '\\';
			*q++ = '\'';
			len --;
			p++;
		} else
			*q++ = *p++;
	}
	*q = '\0';

	return escaped;
}

static signed char
char_to_hex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

static void
sha1_to_lwsgw_hash(unsigned char *hash, lwsgw_hash *shash)
{
	static const char * const hex = "0123456789abcdef";
	char *p = shash->id;
	int n;

	for (n = 0; n < 20; n++) {
		*p++ = hex[hash[n] >> 4];
		*p++ = hex[hash[n] & 15];
	}

	*p = '\0';
}

static unsigned int
lwsgw_now_secs(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec;
}
#if 0
static int
strcmp_end(const char *a, const char *b)
{
	int n = strlen(a), m = strlen(b);

	if (n < m)
		return -1;

	return strcmp(a + (n - m), b);
}
#endif

static int
strcpy_urldecode(char *a, int len, const char *b)
{
	int state = 0, n;
	char sum = 0;

	while (*b && len) {
		switch (state) {
		case 0:
			if (*b == '%') {
				state++;
				b++;
				continue;
			}
			if (*b == '+') {
				b++;
				*a++ = ' ';
				continue;
			}
			*a++ = *b++;
			len--;
			break;
		case 1:
			n = char_to_hex(*b);
			if (n < 0)
				return -1;
			b++;
			sum = n << 4;
			state++;
			break;

		case 2:
			n = char_to_hex(*b);
			if (n < 0)
				return -1;
			b++;
			*a++ = sum | n;
			len--;
			state = 0;
			break;
		}

	}
	*a = '\0';

	return 0;
}

static int
lwsgw_check_admin(struct per_vhost_data__generic_sessions *vhd,
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
static void
lwsgw_cookie_from_session(lwsgw_hash *sid, time_t expires,
			  char **p, char *end)
{
	struct tm *tm = gmtime(&expires);
	time_t n = lwsgw_now_secs();

	*p += snprintf(*p, end - *p, "id=%s;Expires=", sid->id);
#ifdef WIN32
	*p += strftime(*p, end - *p, "%Y %H:%M %Z", tm);
#else
	*p += strftime(*p, end - *p, "%F %H:%M %Z", tm);
#endif
	*p += snprintf(*p, end - *p, ";path=/");
	*p += snprintf(*p, end - *p, ";Max-Age=%lu", (unsigned long)(expires - n));
//	*p += snprintf(*p, end - *p, ";secure");
	*p += snprintf(*p, end - *p, ";HttpOnly");
}

static int
lwsgw_expire_old_sessions(struct per_vhost_data__generic_sessions *vhd)
{
	time_t n = lwsgw_now_secs();
	char s[200];

	if (n - vhd->last_session_expire < 5)
		return 0;

	vhd->last_session_expire = n;

	snprintf(s, sizeof(s) - 1,
		 "delete from sessions where "
		 "expire <= %lu;", (unsigned long)n);

	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to expire sessions: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}

static int
lwsgw_update_session(struct per_vhost_data__generic_sessions *vhd,
		     lwsgw_hash *hash, const char *user)
{
	time_t n = lwsgw_now_secs();
	char s[200], esc[50], esc1[50];

	if (user[0])
		n += vhd->timeout_absolute_secs;
	else
		n += vhd->timeout_anon_absolute_secs;

	snprintf(s, sizeof(s) - 1,
		 "update sessions set expire=%lu,username='%s' where name='%s';",
		 (unsigned long)n,
		 sql_purify(user, esc, sizeof(esc)),
		 sql_purify(hash->id, esc1, sizeof(esc1)));

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

static int
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

static int
lwsgs_lookup_session(struct per_vhost_data__generic_sessions *vhd,
		     const lwsgw_hash *sid, char *username, int len)
{
	struct lla lla = { username, len, 1 };
	char s[150], esc[50];

	lwsgw_expire_old_sessions(vhd);

	snprintf(s, sizeof(s) - 1,
		 "select username from sessions where name = '%s';",
		 sql_purify(sid->id, esc, sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback, &lla, NULL) != SQLITE_OK) {
		lwsl_err("Unable to create user table: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return 1;
	}

	/* 0 if found */
	return lla.results;
}

static int
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

static int
lwsgs_lookup_user(struct per_vhost_data__generic_sessions *vhd,
		  const char *username, struct lwsgs_user *u)
{
	char s[150], esc[50];

	u->username[0] = '\0';
	snprintf(s, sizeof(s) - 1,
		 "select username,creation_time,ip,email,verified,pwhash,pwsalt "
		 "from users where username = '%s';",
		 sql_purify(username, esc, sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup user: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return -1;
	}

	return !u->username[0];
}

static int
lwsgs_new_session_id(struct per_vhost_data__generic_sessions *vhd,
		     lwsgw_hash *sid, char *username, int exp)
{
	unsigned char sid_rand[20];
	char *u;
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

	snprintf(s, sizeof(s) - 1,
		 "insert into sessions(name, username, expire) "
		 "values ('%s', '%s', %u);",
		 sql_purify(sid->id, esc, sizeof(esc) - 1),
		 sql_purify(u, esc1, sizeof(esc1) - 1), exp);

	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert session: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return 1;
	}

	return 0;
}

static int
lwsgs_get_auth_level(struct per_vhost_data__generic_sessions *vhd,
		     const char *username)
{
	int n = 0;

	/* we are logged in as some kind of user */
	if (username[0]) {
		n |= 1;
		/* we are logged in as admin */
		if (!strcmp(username, vhd->admin_user))
			n |= 4 | 2; /* automatically verified */
		else {
			struct lwsgs_user u;

			if (!lwsgs_lookup_user(vhd, username, &u)) {
				if (u.verified == LWSGS_VERIFIED_ACCEPTED)
					n |= 4;
			}
		}
	}

	return n;
}

/*
 * 220 build.warmcat.com ESMTP Postfix
HELO example.com
250 build.warmcat.com
MAIL FROM: <andy@warmcat.com>
250 2.1.0 Ok
RCPT TO: <andy@warmcat.com>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: "Andy" <andy@warmcat.com>
To: "Me" <andy@warmcat.com>
Subject: Test message

Hello it's a test

.
250 2.0.0 Ok: queued as 6ED4A24004F
quit
221 2.0.0 Bye
 * enum lwsgs_smtp_states {
	LGSSMTP_IDLE,
	LGSSMTP_CONNECTING,
	LGSSMTP_CONNECTED,
	LGSSMTP_SENT_HELO,
	LGSSMTP_SENT_FROM,
	LGSSMTP_SENT_TO,
	LGSSMTP_SENT_DATA,
	LGSSMTP_SENT_BODY,
	LGSSMTP_SENT_QUIT,
};
 */

static void
ccb(uv_handle_t* handle)
{

}

static void
alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	struct per_vhost_data__generic_sessions *vhd =
		(struct per_vhost_data__generic_sessions *)handle->data;

	*buf = uv_buf_init(vhd->email_buf, sizeof(vhd->email_buf) - 1);
}

static void
on_write_end(uv_write_t *req, int status) {
	lwsl_notice("%s\n", __func__);
	if (status == -1) {
		fprintf(stderr, "error on_write_end");
		return;
	}
}

static int
lwsgs_lookup_callback_email(void *priv, int cols, char **col_val, char **col_name)
{
	char *s = (char *)priv;
	int n;

	for (n = 0; n < cols; n++) {
		if (!strcmp(col_name[n], "content")) {
			strncpy(s, col_val[n], LWSGS_EMAIL_CONTENT_SIZE - 1);
			s[LWSGS_EMAIL_CONTENT_SIZE - 1] = '\0';
			continue;
		}
	}
	return 0;
}

static void
lwsgs_email_read(struct uv_stream_s *s, ssize_t nread, const uv_buf_t *buf) {
	struct per_vhost_data__generic_sessions *vhd =
		(struct per_vhost_data__generic_sessions *)s->data;
	static const short retcodes[] = {
		0,	/* idle */
		0,	/* connecting */
		220,	/* connected */
		250,	/* helo */
		250,	/* from */
		250,	/* to */
		354,	/* data */
		250,	/* body */
		221,	/* quit */
	};
	uv_write_t write_req;
	char helo[LWSGS_EMAIL_CONTENT_SIZE], ss[150], esc[50];
	uv_buf_t wbuf;
	int n;

	if (nread >= 0)
		vhd->email_buf[nread] = '\0';
	lwsl_notice("%s: %p: %s\n", __func__, vhd, buf->base);
	if (nread == -1) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	n = atoi(buf->base);
	if (n != retcodes[vhd->estate]) {
		lwsl_err("%s: bad response from server\n", __func__);
		goto close_conn;
	}

	switch (vhd->estate) {
	case LGSSMTP_CONNECTED:
		n = sprintf(helo, "HELO %s\n", vhd->email_helo);
		vhd->estate = LGSSMTP_SENT_HELO;
		break;
	case LGSSMTP_SENT_HELO:
		n = sprintf(helo, "MAIL FROM: <%s>\n", vhd->email_from);
		vhd->estate = LGSSMTP_SENT_FROM;
		break;
	case LGSSMTP_SENT_FROM:
		n = sprintf(helo, "RCPT TO: <%s>\n", vhd->u.email);
		vhd->estate = LGSSMTP_SENT_TO;
		break;
	case LGSSMTP_SENT_TO:
		n = sprintf(helo, "DATA\n");
		vhd->estate = LGSSMTP_SENT_DATA;
		break;
	case LGSSMTP_SENT_DATA:
		snprintf(ss, sizeof(ss) - 1,
			 "select content from email where username='%s';",
			 sql_purify(vhd->u.username, esc, sizeof(esc) - 1));

		strcpy(helo, "failed");
		if (sqlite3_exec(vhd->pdb, ss, lwsgs_lookup_callback_email, helo,
				 NULL) != SQLITE_OK) {
			lwsl_err("Unable to lookup email: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return;
		}
		puts(helo);
		n = strlen(helo);
		vhd->estate = LGSSMTP_SENT_BODY;
		break;
	case LGSSMTP_SENT_BODY:
		n = sprintf(helo, "quit\n");
		vhd->estate = LGSSMTP_SENT_QUIT;
		break;
	case LGSSMTP_SENT_QUIT:
		lwsl_notice("%s: done\n", __func__);

		/* mark the user as having sent the verification email */
		snprintf(helo, sizeof(helo) - 1,
			 "update users set verified=1 where username='%s' and verified==0;",
			 sql_purify(vhd->u.username, esc, sizeof(esc) - 1));
		if (sqlite3_exec(vhd->pdb, helo, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("%s: Unable to update user: %s\n", __func__,
				 sqlite3_errmsg(vhd->pdb));
			return;
		}
		snprintf(helo, sizeof(helo) - 1,
			 "delete from email where username='%s';",
			 sql_purify(vhd->u.username, esc, sizeof(esc) - 1));
		if (sqlite3_exec(vhd->pdb, helo, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("%s: Unable to delete email text: %s\n", __func__,
				 sqlite3_errmsg(vhd->pdb));
			return;
		}
		vhd->estate = LGSSMTP_IDLE;
		goto close_conn;
	default:
		return;
	}

	puts(helo);
	wbuf = uv_buf_init(helo, n);
	uv_write(&write_req, s, &wbuf, 1, on_write_end);

	return;

close_conn:

	uv_close((uv_handle_t *)s, ccb);
}

static void
lwsgs_email_on_connect(uv_connect_t *req, int status)
{
	struct per_vhost_data__generic_sessions *vhd =
		(struct per_vhost_data__generic_sessions *)req->data;

	lwsl_notice("%s\n", __func__);

	if (status == -1) {
		lwsl_err("%s: failed\n", __func__);
		return;
	}

	uv_read_start(req->handle, alloc_buffer, lwsgs_email_read);
	vhd->estate = LGSSMTP_CONNECTED;
}

static void
uv_timeout_cb_email(uv_timer_t *w
#if UV_VERSION_MAJOR == 0
		, int status
#endif
)
{
	struct per_vhost_data__generic_sessions *vhd = lws_container_of(w,
			struct per_vhost_data__generic_sessions, timeout_email);
	time_t now = lwsgw_now_secs();
	struct sockaddr_in req_addr;
	char s[LWSGS_EMAIL_CONTENT_SIZE];

	switch (vhd->estate) {
	case LGSSMTP_IDLE:
		/*
		 * users not verified in 24h get deleted
		 */
		snprintf(s, sizeof(s) - 1,
			 "delete from users where ((verified != %d) and "
			 "(creation_time <= %lu));", LWSGS_VERIFIED_ACCEPTED,
			 (unsigned long)now - vhd->timeout_email_secs);

		if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to expire users: %s\n",
				 sqlite3_errmsg(vhd->pdb));
			return;
		}

		snprintf(s, sizeof(s) - 1,
			 "update users set token_time=0 where "
			 "(token_time <= %lu);",
			 (unsigned long)now - vhd->timeout_email_secs);

		if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to expire users: %s\n",
				 sqlite3_errmsg(vhd->pdb));
			return;
		}

		vhd->u.username[0] = '\0';
		snprintf(s, sizeof(s) - 1,
			 "select username"
			 " from email limit 1;");

		if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &vhd->u,
				 NULL) != SQLITE_OK) {
			lwsl_err("Unable to lookup user: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return;
		}
		snprintf(s, sizeof(s) - 1,
			 "select username, creation_time, email, ip, verified, token"
			 " from users where username='%s' limit 1;",
			 vhd->u.username);

		if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &vhd->u,
				 NULL) != SQLITE_OK) {
			lwsl_err("Unable to lookup user: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return;
		}

		if (!vhd->u.username[0])
			/*
			 * nothing to do, we are idle and no suitable
			 * accounts waiting for verification.  When a new user
			 * is added we will get kicked to try again.
			 */
			break;

		vhd->estate = LGSSMTP_CONNECTING;

		uv_tcp_init(lws_uv_getloop(vhd->context, 0), &vhd->email_client);
		if (uv_ip4_addr(vhd->email_smtp_ip, 25, &req_addr)) {
			lwsl_err("Unable to convert mailserver ads\n");
			return;
		}

		lwsl_notice("LGSSMTP_IDLE: connecting\n");

		vhd->email_connect_started = now;
		vhd->email_connect_req.data = vhd;
		vhd->email_client.data = vhd;
		uv_tcp_connect(&vhd->email_connect_req, &vhd->email_client,
			       (struct sockaddr *)&req_addr, lwsgs_email_on_connect);

		uv_timer_start(&vhd->timeout_email,
			       uv_timeout_cb_email, 5000, 0);

		break;

	case LGSSMTP_CONNECTING:
		if (vhd->email_connect_started - now > 5) {
			lwsl_err("mail session timed out\n");
			/* !!! kill the connection */
			uv_close((uv_handle_t *) &vhd->email_connect_req, ccb);
			vhd->estate = LGSSMTP_IDLE;
		}
		break;

	default:
		break;
	}
}

static int
callback_generic_sessions(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__generic_sessions *pss =
			(struct per_session_data__generic_sessions *)user;
	const struct lws_protocol_vhost_options *pvo;
	struct per_vhost_data__generic_sessions *vhd =
			(struct per_vhost_data__generic_sessions *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					lws_get_protocol(wsi));
	static const char * const formnames[] = {
		"username=",
		"password=",
		"password2=",
		"email=",
		"register=",
		"good=",
		"bad=",
		"reg-good=",
		"reg-bad=",
		"admin=",
		"forgot=",
	};
	enum {
		FGS_USERNAME,
		FGS_PASSWORD,
		FGS_PASSWORD2,
		FGS_EMAIL,
		FGS_REGISTER,
		FGS_GOOD,
		FGS_BAD,
		FGS_REG_GOOD,
		FGS_REG_BAD,
		FGS_ADMIN,
		FGS_FORGOT,

		FGS_COUNT
	};
	char *formvals[FGS_COUNT], *cp;
	unsigned char buffer[LWS_PRE + LWSGS_EMAIL_CONTENT_SIZE];
	char cookie[1024], username[32], *pc = cookie, *sp;
	char esc[50], esc1[50], esc2[50], esc3[50], esc4[50];
	struct lws_process_html_args *args;
	unsigned char *p, *start, *end;
	sqlite3_stmt *sm;
	lwsgw_hash sid;
	int n, old_len;
	struct lwsgs_user u;
	char s[LWSGS_EMAIL_CONTENT_SIZE];

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__generic_sessions));
		vhd->context = lws_get_context(wsi);

		/* defaults */

		vhd->timeout_idle_secs = 600;
		vhd->timeout_absolute_secs = 36000;
		vhd->timeout_anon_absolute_secs = 1200;
		vhd->timeout_email_secs = 24 * 3600;
		strcpy(vhd->email_helo, "unconfigured.com");
		strcpy(vhd->email_from, "noreply@unconfigured.com");
		strcpy(vhd->email_title, "Registration Email from unconfigured");
		strcpy(vhd->email_smtp_ip, "127.0.0.1");

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "admin-user"))
				strncpy(vhd->admin_user, pvo->value,
					sizeof(vhd->admin_user) - 1);
			if (!strcmp(pvo->name, "admin-password-sha1"))
				strncpy(vhd->admin_password_sha1.id, pvo->value,
					sizeof(vhd->admin_password_sha1.id) - 1);
			if (!strcmp(pvo->name, "session-db"))
				strncpy(vhd->session_db, pvo->value,
					sizeof(vhd->session_db) - 1);
			if (!strcmp(pvo->name, "confounder"))
				strncpy(vhd->confounder, pvo->value,
					sizeof(vhd->confounder) - 1);
			if (!strcmp(pvo->name, "email-from"))
				strncpy(vhd->email_from, pvo->value,
					sizeof(vhd->email_from) - 1);
			if (!strcmp(pvo->name, "email-helo"))
				strncpy(vhd->email_helo, pvo->value,
					sizeof(vhd->email_helo) - 1);
			if (!strcmp(pvo->name, "email-template"))
				strncpy(vhd->email_template, pvo->value,
					sizeof(vhd->email_template) - 1);
			if (!strcmp(pvo->name, "email-title"))
				strncpy(vhd->email_title, pvo->value,
					sizeof(vhd->email_title) - 1);
			if (!strcmp(pvo->name, "email-contact-person"))
				strncpy(vhd->email_contact_person, pvo->value,
					sizeof(vhd->email_contact_person) - 1);
			if (!strcmp(pvo->name, "email-confirm-url-base"))
				strncpy(vhd->email_confirm_url, pvo->value,
					sizeof(vhd->email_confirm_url) - 1);
			if (!strcmp(pvo->name, "email-server-ip"))
				strncpy(vhd->email_smtp_ip, pvo->value,
					sizeof(vhd->email_smtp_ip) - 1);

			if (!strcmp(pvo->name, "timeout-idle-secs"))
				vhd->timeout_idle_secs = atoi(pvo->value);
			if (!strcmp(pvo->name, "timeout-absolute-secs"))
				vhd->timeout_absolute_secs = atoi(pvo->value);
			if (!strcmp(pvo->name, "timeout-anon-absolute-secs"))
				vhd->timeout_anon_absolute_secs = atoi(pvo->value);
			if (!strcmp(pvo->name, "email-expire"))
				vhd->timeout_email_secs = atoi(pvo->value);
			pvo = pvo->next;
		}
		if (!vhd->admin_user[0] ||
		    !vhd->admin_password_sha1.id[0] ||
		    !vhd->session_db[0]) {
			lwsl_err("generic-sessions: "
				 "You must give \"admin-user\", "
				 "\"admin-password-sha1\", "
				 "and \"session_db\" per-vhost options\n");
			return 1;
		}

		if (sqlite3_open_v2(vhd->session_db, &vhd->pdb,
				    SQLITE_OPEN_READWRITE |
				    SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
			lwsl_err("Unable to open session db %s: %s\n",
				 vhd->session_db, sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		if (sqlite3_prepare(vhd->pdb,
				    "create table if not exists sessions ("
				    " name char(40),"
				    " username varchar(32),"
				    " expire integer"
				    ");",
				    -1, &sm, NULL) != SQLITE_OK) {
			lwsl_err("Unable to prepare session table init: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		if (sqlite3_step(sm) != SQLITE_DONE) {
			lwsl_err("Unable to run session table init: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}
		sqlite3_finalize(sm);

		if (sqlite3_exec(vhd->pdb,
				 "create table if not exists users ("
				 " username varchar(32),"
				 " creation_time integer,"
				 " ip varchar(46),"
				 " email varchar(100),"
				 " pwhash varchar(42),"
				 " pwsalt varchar(42),"
				 " pwchange_time integer,"
				 " token varchar(42),"
				 " verified integer,"
				 " token_time integer,"
				 " primary key (username)"
				 ");",
				 NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to create user table: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		sprintf(s, "create table if not exists email ("
				 " username varchar(32),"
				 " content blob,"
				 " primary key (username)"
				 ");");
		if (sqlite3_exec(vhd->pdb, s,
				 NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to create user table: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		uv_timer_init(lws_uv_getloop(vhd->context, 0),
			      &vhd->timeout_email);

		/* trigger him one time in a bit */
		uv_timer_start(&vhd->timeout_email,
			       uv_timeout_cb_email, 2000, 0);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd->pdb) {
			sqlite3_close(vhd->pdb);
			vhd->pdb = NULL;
		}
		break;

	case LWS_CALLBACK_HTTP:
		lwsl_notice("LWS_CALLBACK_HTTP: %s\n", in);

		pss->login_session.id[0] = '\0';
		pss->pos = 0;
		strncpy(pss->onward, (char *)in, sizeof(pss->onward));

		if (!strcmp((const char *)in, "/forgot")) {

			if (lws_hdr_copy_fragment(wsi, cookie, sizeof(cookie),
						  WSI_TOKEN_HTTP_URI_ARGS, 0) < 0)
				goto forgot_fail;

			if (strncmp(cookie, "token=", 6))
				goto forgot_fail;

			u.username[0] = '\0';
			snprintf(s, sizeof(s) - 1,
				 "select username,verified "
				 "from users where verified=%d and "
				 "token = '%s' and token_time != 0;",
				 LWSGS_VERIFIED_ACCEPTED,
				 sql_purify(&cookie[6], esc, sizeof(esc) - 1));
			if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
			    SQLITE_OK) {
				lwsl_err("Unable to lookup token: %s\n",
					 sqlite3_errmsg(vhd->pdb));

				goto forgot_fail;
			}

			if (!u.username[0]) {
				puts(s);
				lwsl_notice("forgot token doesn't map to verified user\n");
				goto forgot_fail;
			}

			snprintf(s, sizeof(s) - 1,
				 "update users set token_time=0 where username='%s';",
				 sql_purify(u.username, esc, sizeof(esc) - 1));

			if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
			    SQLITE_OK) {
				lwsl_err("Unable to lookup token: %s\n",
					 sqlite3_errmsg(vhd->pdb));

				goto verf_fail;
			}

			snprintf(pss->onward, sizeof(pss->onward),
				 "%s/post-forgot-ok.html",
				 vhd->email_confirm_url);

			pss->login_expires = lwsgw_now_secs() +
					     vhd->timeout_absolute_secs;

			pss->delete_session.id[0] = '\0';
			lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);

			/* we need to create a new, authorized session */
			if (lwsgs_new_session_id(vhd, &pss->login_session,
						 u.username,
						 pss->login_expires))
				goto forgot_fail;

			lwsl_notice("Creating new session: %s, redir to %s\n",
				    pss->login_session.id, pss->onward);

			goto redirect_with_cookie;

forgot_fail:
			pss->delete_session.id[0] = '\0';
			lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);
			pss->login_expires = 0;

			snprintf(pss->onward, sizeof(pss->onward),
				 "%s/post-forgot-fail.html",
				  vhd->email_confirm_url);

			goto redirect_with_cookie;
		}

		if (!strcmp((const char *)in, "/confirm")) {

			if (lws_hdr_copy_fragment(wsi, cookie, sizeof(cookie),
						  WSI_TOKEN_HTTP_URI_ARGS, 0) < 0)
				goto verf_fail;

			if (strncmp(cookie, "token=", 6))
				goto verf_fail;

			u.username[0] = '\0';
			snprintf(s, sizeof(s) - 1,
				 "select username,verified "
				 "from users where token = '%s';",
				 sql_purify(&cookie[6], esc, sizeof(esc) - 1));
			if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
			    SQLITE_OK) {
				lwsl_err("Unable to lookup token: %s\n",
					 sqlite3_errmsg(vhd->pdb));

				goto verf_fail;
			}

			if (!u.username[0] || u.verified != 1) {
				lwsl_notice("verify token doesn't map to unverified user\n");
				goto verf_fail;
			}

			lwsl_notice("Verifying %s\n", u.username);
			snprintf(s, sizeof(s) - 1,
				 "update users set verified=%d where username='%s';",
				 LWSGS_VERIFIED_ACCEPTED,
				 sql_purify(u.username, esc, sizeof(esc) - 1));

			if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
			    SQLITE_OK) {
				lwsl_err("Unable to lookup token: %s\n",
					 sqlite3_errmsg(vhd->pdb));

				goto verf_fail;
			}

			snprintf(pss->onward, sizeof(pss->onward),
				 "%s/post-verify-ok.html",
				 vhd->email_confirm_url);

			pss->login_expires = lwsgw_now_secs() +
					     vhd->timeout_absolute_secs;

			pss->delete_session.id[0] = '\0';
			lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);

			/* we need to create a new, authorized session */

			if (lwsgs_new_session_id(vhd, &pss->login_session,
						 u.username,
						 pss->login_expires))
				goto verf_fail;

			lwsl_notice("Creating new session: %s, redir to %s\n",
				    pss->login_session.id, pss->onward);

			goto redirect_with_cookie;

verf_fail:
			pss->delete_session.id[0] = '\0';
			lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);
			pss->login_expires = 0;

			snprintf(pss->onward, sizeof(pss->onward),
				 "%s/post-verify-fail.html",
				  vhd->email_confirm_url);

			goto redirect_with_cookie;
		}
		if (!strcmp((const char *)in, "/check")) {
			/*
			 * either /check?email=xxx@yyy
			 *
			 * or, /check?username=xxx
			 *
			 * returns '0' if not already registered, else '1'
			 */

			static const char * const colname[] = {
				"username", "email"
			};

			u.username[0] = '\0';
			if (lws_hdr_copy_fragment(wsi, cookie, sizeof(cookie),
						  WSI_TOKEN_HTTP_URI_ARGS, 0) < 0)
				goto nope;

			n = !strncmp(cookie, "email=", 6);
			pc = strchr(cookie, '=');
			if (!pc) {
				lwsl_notice("cookie has no =\n");
				goto nope;
			}
			pc++;

			snprintf(s, sizeof(s) - 1,
				 "select username, email "
				 "from users where %s = '%s';",
				 colname[n],
				 sql_purify(pc, esc, sizeof(esc) - 1));

			puts(s);

			if (sqlite3_exec(vhd->pdb, s,
					 lwsgs_lookup_callback_user, &u, NULL) !=
			    SQLITE_OK) {
				lwsl_err("Unable to lookup token: %s\n",
					 sqlite3_errmsg(vhd->pdb));
				n = FGS_REG_BAD;
				goto reg_done;
			}
nope:
			s[0] = '0' + !!u.username[0];
			p = buffer + LWS_PRE;
			start = p;
			end = p + sizeof(buffer) - LWS_PRE;

			if (lws_add_http_header_status(wsi, 200, &p, end))
				return -1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
							 (unsigned char *)"text/plain", 10,
							 &p, end))
				return -1;

			if (lws_add_http_header_content_length(wsi, 1, &p, end))
					return -1;

			if (lws_finalize_http_header(wsi, &p, end))
				return -1;

			n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
			if (n != (p - start)) {
				lwsl_err("_write returned %d from %d\n",
					 n, (p - start));
				return -1;
			}
			n = lws_write(wsi, (unsigned char *)s, 1, LWS_WRITE_HTTP);
			if (n != 1)
				return -1;
			break;
		}

		if (!strcmp((const char *)in, "/login"))
			break;
		if (!strcmp((const char *)in, "/logout"))
			break;
		if (!strcmp((const char *)in, "/forgot"))
			break;

		lwsl_err("http doing 404 on %s\n", in);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		break;

	case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
		n = 0;
		username[0] = '\0';
		sid.id[0] = '\0';
		args = (struct lws_process_html_args *)in;
		lwsl_debug("LWS_CALLBACK_CHECK_ACCESS_RIGHTS\n");
		if (!lwsgs_get_sid_from_wsi(wsi, &sid)) {
			if (lwsgs_lookup_session(vhd, &sid, username, sizeof(username))) {
				static const char * const oprot[] = {
					"http://", "https://"
				};
				lwsl_notice("session lookup for %s failed, probably expired\n", sid.id);
				pss->delete_session = sid;
				args->final = 1; /* signal we dealt with it */
				if (lws_hdr_copy(wsi, cookie, sizeof(cookie) - 1,
					     WSI_TOKEN_HOST) < 0)
					return 1;
				snprintf(pss->onward, sizeof(pss->onward) - 1,
					 "%s%s%s", oprot[lws_is_ssl(wsi)],
					    cookie, args->p);
				lwsl_notice("redirecting to ourselves with cookie refresh\n");
				/* we need a redirect to ourselves, session cookie is expired */
				goto redirect_with_cookie;
			}
		} else
			lwsl_notice("failed to get sid from wsi\n");

		n = lwsgs_get_auth_level(vhd, username);

		if ((args->max_len & n) != args->max_len) {
			lwsl_notice("Access rights fail 0x%X vs 0x%X (cookie %s)\n",
					args->max_len, n, sid.id);
			return 1;
		}
		lwsl_debug("Access rights OK\n");
		break;

	case LWS_CALLBACK_PROCESS_HTML:
		/*
		 * replace placeholders with session data and prepare the
		 * preamble to send chunked, p is already at +10 from the
		 * real buffer start to allow us to add the chunk header
		 *
		 * struct lws_process_html_args {
		 *	char *p;
		 *	int len;
		 *	int max_len;
		 *	int final;
		 * };
		 */

		args = (struct lws_process_html_args *)in;

		username[0] = '\0';
		if (!lwsgs_get_sid_from_wsi(wsi, &sid))
			if (lwsgs_lookup_session(vhd, &sid, username, sizeof(username))) {
				lwsl_notice("session lookup for %s failed\n", sid.id);
				pss->delete_session = sid;
				return 1;
			}

		/* do replacements */
		sp = args->p;
		old_len = args->len;
		args->len = 0;
		pss->start = sp;
		while (sp < args->p + old_len) {

			if (args->len + 5 >= args->max_len) {
				lwsl_err("Used up interpret padding\n");
				return -1;
			}

			if ((!pss->pos && *sp == '$') ||
			    pss->pos) {
				static const char * const vars[] = {
					"$lwsgs_user",
					"$lwsgs_auth"
				};
				int hits = 0, hit;

				if (!pss->pos)
					pss->start = sp;
				pss->swallow[pss->pos++] = *sp;
				if (pss->pos == sizeof(pss->swallow))
					goto skip;
				for (n = 0; n < ARRAY_SIZE(vars); n++)
					if (!strncmp(pss->swallow, vars[n], pss->pos)) {
						hits++;
						hit = n;
					}
				if (!hits) {
skip:
					memcpy(pss->start, pss->swallow, pss->pos);
					args->len += pss->pos;
					pss->pos = 0;
					continue;
				}
				if (hits == 1 && pss->pos == strlen(vars[hit])) {
					switch (hit) {
					case 0:
						pc = username;
						break;
					case 1:
						pc = cookie;
						n = lwsgs_get_auth_level(vhd, username);
						sprintf(cookie, "%d", n);
						break;
					}

					pss->swallow[pss->pos] = '\0';
					lwsl_info("replacing %s (%d) with %s\n",
						    pss->swallow, pss->pos, pc);

					n = strlen(pc);
					if (n != pss->pos) {
						memmove(pss->start + n,
							pss->start + pss->pos,
							old_len - (sp - args->p));
						sp = pss->start + n;
						old_len += (n - pss->pos);
						args->len += n;
					}
					memcpy(pss->start, pc, n);

					pss->pos = 0;
				}
				sp++;
				continue;
			}

			args->len++;
			sp++;
		}

		/* no space left for final chunk trailer */
		if (args->final && args->len + 5 >= args->max_len)
			return -1;

		n = sprintf((char *)buffer, "%X\x0d\x0a", args->len);

		args->p -= n;

		memcpy(args->p, buffer, n);
		args->len += n;

		if (args->final) {
			sp = args->p + args->len;
			*sp++ = '\x0d';
			*sp++ = '\x0a';
			*sp++ = '0';
			*sp++ = '\x0d';
			*sp++ = '\x0a';
			*sp++ = '\x0d';
			*sp++ = '\x0a';
			args->len += 7;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY: %s\n", pss->onward);

		/* we will get something like this
		 *
		 * username=admin&password=xyz
		 */

		if (len < 20)
			return 1;

		memset(formvals, 0, sizeof(formvals));
		sp = (char *)in;
		sp[len]='\0';

		/*
		 * Whatever we're here for, we will need the POST args
		 * processing...
		 */

		while (sp < ((char *)in + len)) {
			for (n = 0; n < ARRAY_SIZE(formnames); n++)
				if (!strncmp(sp, formnames[n],
					     strlen(formnames[n])))
					break;
			if (n < ARRAY_SIZE(formnames)) {
				sp += strlen(formnames[n]);
				formvals[n] = sp;
			}

			sp = strchr(sp, '&');
			if (!sp) {
				if (n < ARRAY_SIZE(formnames) && formvals[n]) {
					if (strcpy_urldecode(formvals[n],
							     strlen(formvals[n]),
							     formvals[n]))
						return -1;
					lwsl_debug("%d: %s\n", n, formvals[n]);
				}
				break;
			}
			*(sp++) = '\0';
			if (formvals[n])
				if (strcpy_urldecode(formvals[n], sp - formvals[n],
						formvals[n]))
					return -1;
			lwsl_debug("%d: %s\n", n, formvals[n]);
		}

		if (!strcmp((char *)pss->onward, "/login")) {
			lwsgw_hash_bin hash_bin;
			lwsgw_hash hash;
			struct lwsgs_user u;
			unsigned char sid_rand[20];

			if (formvals[FGS_FORGOT] && formvals[FGS_FORGOT][0]) {

				lwsl_notice("FORGOT %s %s\n",
					    formvals[FGS_USERNAME],
					    formvals[FGS_EMAIL]);

				if (!formvals[FGS_GOOD] ||
				    !formvals[FGS_BAD]) {
					lwsl_err("Form must provide reg-good "
						  "and reg-bad targets\n");
					return -1;
				}

				u.username[0] = '\0';
				if (formvals[FGS_USERNAME])
					snprintf(s, sizeof(s) - 1,
					 "select username,email "
					 "from users where username = '%s';",
					 sql_purify(formvals[FGS_USERNAME], esc, sizeof(esc) - 1));
				else
					snprintf(s, sizeof(s) - 1,
					 "select username,email "
					 "from users where email = '%s';",
					 sql_purify(formvals[FGS_EMAIL], esc, sizeof(esc) - 1));
				if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
				    SQLITE_OK) {
					lwsl_err("Unable to lookup token: %s\n",
						 sqlite3_errmsg(vhd->pdb));

					n = FGS_BAD;
					goto reg_done;
				}
				if (!u.username[0]) {
					lwsl_err("No match found %s\n", s);
					n = FGS_BAD;
					goto reg_done;
				}

				lws_get_peer_simple(wsi, pss->ip, sizeof(pss->ip));
				if (lws_get_random(vhd->context, sid_rand,
						   sizeof(sid_rand)) !=
						   sizeof(sid_rand)) {
					lwsl_err("Problem getting random for token\n");
					n = FGS_BAD;
					goto reg_done;
				}
				sha1_to_lwsgw_hash(sid_rand, &hash);
				snprintf(s, sizeof(s),
					"From: Noreply <%s>\n"
					"To: %s <%s>\n"
					  "Subject: Password reset request\n"
					  "\n"
					  "Hello, %s\n\n"
					  "We received a password reset request from IP %s for this email,\n"
					  "to confirm you want to do that, please click the link below.\n\n"
					  "%s/forgot?token=%s\n\n"
					  "If this request is unexpected, please ignore it and\n"
					  "no further action will be taken.\n\n"
					"If you have any questions or concerns about this\n"
					"automated email, you can contact a real person at\n"
					"%s.\n"
					"\n.\n",
					sql_purify(vhd->email_from, esc, sizeof(esc) - 1),
					sql_purify(u.username, esc1, sizeof(esc1) - 1),
					sql_purify(u.email, esc2, sizeof(esc2) - 1),
					sql_purify(u.username, esc3, sizeof(esc3) - 1),
					sql_purify(pss->ip, esc4, sizeof(esc4) - 1),
					vhd->email_confirm_url, hash.id,
					vhd->email_contact_person);

				snprintf((char *)buffer, sizeof(buffer) - 1,
					 "insert into email(username, content)"
					 " values ('%s', '%s');",
					sql_purify(u.username, esc, sizeof(esc) - 1), s);
				if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL,
						 NULL, NULL) != SQLITE_OK) {
					lwsl_err("Unable to insert email: %s\n",
						 sqlite3_errmsg(vhd->pdb));

					n = FGS_BAD;
					goto reg_done;
				}

				snprintf(s, sizeof(s) - 1,
					 "update users set token='%s',token_time='%ld' where username='%s';",
					 hash.id, (long)lwsgw_now_secs(),
					 sql_purify(u.username, esc, sizeof(esc) - 1));
				if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) !=
				    SQLITE_OK) {
					lwsl_err("Unable to set token: %s\n",
						 sqlite3_errmsg(vhd->pdb));

					n = FGS_BAD;
					goto reg_done;
				}

				/* get the email monitor to take a look */
				uv_timer_start(&vhd->timeout_email,
					       uv_timeout_cb_email, 1000, 0);

				n = FGS_GOOD;
				goto reg_done;
			}

			if (!formvals[FGS_USERNAME] ||
			    !formvals[FGS_PASSWORD])
				return -1;

			if (formvals[FGS_REGISTER] && formvals[FGS_REGISTER][0]) {

				lwsl_notice("REGISTER %s %s %s\n",
						formvals[FGS_USERNAME],
						formvals[FGS_PASSWORD],
						formvals[FGS_EMAIL]);
				if (lwsgs_get_sid_from_wsi(wsi,
				    &pss->login_session))
					return 1;

				lws_get_peer_simple(wsi, pss->ip, sizeof(pss->ip));
				lwsl_notice("IP=%s\n", pss->ip);

				if (!formvals[FGS_REG_GOOD] ||
				    !formvals[FGS_REG_BAD]) {
					lwsl_info("Form must provide reg-good "
						  "and reg-bad targets\n");
					return -1;
				}

				/* admin user cannot be registered in user db */
				if (!strcmp(vhd->admin_user, formvals[FGS_USERNAME])) {
					n = FGS_REG_BAD;
					goto reg_done;
				}

				if (!lwsgs_lookup_user(vhd,
						formvals[FGS_USERNAME], &u)) {
					lwsl_notice("user %s already registered\n",
							formvals[FGS_USERNAME]);
					n = FGS_REG_BAD;
					goto reg_done;
				}

				u.username[0] = '\0';
				snprintf(s, sizeof(s) - 1,
					 "select username, email "
					 "from users where email = '%s';",
					 sql_purify(formvals[FGS_EMAIL], esc,
					 sizeof(esc) - 1));

				if (sqlite3_exec(vhd->pdb, s,
						 lwsgs_lookup_callback_user, &u, NULL) !=
				    SQLITE_OK) {
					lwsl_err("Unable to lookup token: %s\n",
						 sqlite3_errmsg(vhd->pdb));
					n = FGS_REG_BAD;
					goto reg_done;
				}

				if (u.username[0]) {
					lwsl_notice("email %s already in use\n",
						    formvals[FGS_USERNAME]);
					n = FGS_REG_BAD;
					goto reg_done;
				}

				/* create a random salt as big as the hash */

				if (lws_get_random(vhd->context, sid_rand,
						   sizeof(sid_rand)) !=
						   sizeof(sid_rand)) {
					lwsl_err("Problem getting random for salt\n");
					n = FGS_REG_BAD;
					goto reg_done;
				}
				sha1_to_lwsgw_hash(sid_rand, &u.pwsalt);

				if (lws_get_random(vhd->context, sid_rand,
						   sizeof(sid_rand)) !=
						   sizeof(sid_rand)) {
					lwsl_err("Problem getting random for token\n");
					n = FGS_REG_BAD;
					goto reg_done;
				}
				sha1_to_lwsgw_hash(sid_rand, &hash);

				/* [password in ascii][salt] */
				n = snprintf((char *)buffer, sizeof(buffer) - 1,
					 "%s-%s-%s", formvals[FGS_PASSWORD],
					 vhd->confounder, u.pwsalt.id);

				/* sha1sum of password + salt */
				lws_SHA1(buffer, n, hash_bin.bin);
				sha1_to_lwsgw_hash(&hash_bin.bin[0], &u.pwhash);

				snprintf((char *)buffer, sizeof(buffer) - 1,
					 "insert into users(username,"
					 " creation_time, ip, email, verified,"
					 " pwhash, pwsalt, token)"
					 " values ('%s', %lu, '%s', '%s', 0,"
					 " '%s', '%s', '%s');",
					sql_purify(formvals[FGS_USERNAME], esc, sizeof(esc) - 1),
					(unsigned long)lwsgw_now_secs(),
					sql_purify(pss->ip, esc1, sizeof(esc1) - 1),
					sql_purify(formvals[FGS_EMAIL], esc2, sizeof(esc2) - 1),
					u.pwhash.id, u.pwsalt.id, hash.id);

				n = FGS_REG_GOOD;
				if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL,
						 NULL, NULL) != SQLITE_OK) {
					lwsl_err("Unable to insert user: %s\n",
						 sqlite3_errmsg(vhd->pdb));

					n = FGS_REG_BAD;
					goto reg_done;
				}

				snprintf(s, sizeof(s),
					"From: Noreply <%s>\n"
					"To: %s <%s>\n"
					  "Subject: Registration verification\n"
					  "\n"
					  "Hello, %s\n\n"
					  "We received a registration from IP %s using this email,\n"
					  "to confirm it is legit, please click the link below.\n\n"
					  "%s/confirm?token=%s\n\n"
					  "If this request is unexpected, please ignore it and\n"
					  "no further action will be taken.\n\n"
					"If you have any questions or concerns about this\n"
					"automated email, you can contact a real person at\n"
					"%s.\n"
					"\n.\n",
					sql_purify(vhd->email_from, esc, sizeof(esc) - 1),
					sql_purify(formvals[FGS_USERNAME], esc1, sizeof(esc1) - 1),
					sql_purify(formvals[FGS_EMAIL], esc2, sizeof(esc2) - 1),
					sql_purify(formvals[FGS_USERNAME], esc3, sizeof(esc3) - 1),
					sql_purify(pss->ip, esc4, sizeof(esc4) - 1),
					vhd->email_confirm_url, hash.id,
					vhd->email_contact_person);

				snprintf((char *)buffer, sizeof(buffer) - 1,
					 "insert into email(username, content)"
					 " values ('%s', '%s');",
					sql_purify(formvals[FGS_USERNAME], esc, sizeof(esc) - 1), s);

				if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL,
						 NULL, NULL) != SQLITE_OK) {
					lwsl_err("Unable to insert email: %s\n",
						 sqlite3_errmsg(vhd->pdb));

					n = FGS_REG_BAD;
					goto reg_done;
				}

				/* get the email monitor to take a look */
				uv_timer_start(&vhd->timeout_email,
					       uv_timeout_cb_email, 1000, 0);

reg_done:
				strncpy(pss->onward, formvals[n],
					sizeof(pss->onward) - 1);
				pss->onward[sizeof(pss->onward) - 1] = '\0';

				pss->login_expires = 0;
				pss->logging_out = 1;
				break;
			}

			/* we have the username and password... check if admin */
			if (lwsgw_check_admin(vhd, formvals[FGS_USERNAME],
					      formvals[FGS_PASSWORD])) {
				if (formvals[FGS_ADMIN])
					cp = formvals[FGS_ADMIN];
				else
					if (formvals[FGS_GOOD])
						cp = formvals[FGS_GOOD];
					else {
						lwsl_info("No admin or good target url in form\n");
						return -1;
					}
				lwsl_debug("admin\n");
				goto pass;
			}

			/* check users in database */

			if (!lwsgs_lookup_user(vhd,
					formvals[FGS_USERNAME], &u)) {
				lwsgw_hash hash;

				lwsl_info("user %s found, salt '%s'\n",
						formvals[FGS_USERNAME], u.pwsalt.id);

				/* [password in ascii][salt] */
				n = snprintf((char *)buffer, sizeof(buffer) - 1,
					 "%s-%s-%s", formvals[FGS_PASSWORD],
					 vhd->confounder,
					 u.pwsalt.id);

				/* sha1sum of password + salt */
				lws_SHA1(buffer, n, hash_bin.bin);
				sha1_to_lwsgw_hash(&hash_bin.bin[0], &hash);

				if (!strcmp(hash.id, u.pwhash.id)) {
					lwsl_info("pw hash check met\n");
					cp = formvals[FGS_GOOD];
					goto pass;
				}
			} else
				lwsl_notice("unable to find user %s\n",
						formvals[FGS_USERNAME]);

			if (!formvals[FGS_BAD]) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			strncpy(pss->onward, formvals[FGS_BAD],
				sizeof(pss->onward) - 1);
			pss->onward[sizeof(pss->onward) - 1] = '\0';
			lwsl_debug("failed\n");

			break;
		}

		if (!strcmp((char *)pss->onward, "/logout")) {

			lwsl_notice("/logout\n");

			if (lwsgs_get_sid_from_wsi(wsi, &pss->login_session)) {
				lwsl_notice("not logged in...\n");
				return 1;
			}

			lwsgw_update_session(vhd, &pss->login_session, "");

			if (!formvals[FGS_GOOD]) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			strncpy(pss->onward, formvals[FGS_GOOD], sizeof(pss->onward) - 1);
			pss->onward[sizeof(pss->onward) - 1] = '\0';

			pss->login_expires = 0;
			pss->logging_out = 1;

			break;
		}

		break;

pass:
		strncpy(pss->onward, cp, sizeof(pss->onward) - 1);
		pss->onward[sizeof(pss->onward) - 1] = '\0';

		if (lwsgs_get_sid_from_wsi(wsi, &sid))
			sid.id[0] = '\0';

		pss->login_expires = lwsgw_now_secs() +
				     vhd->timeout_absolute_secs;

		if (!sid.id[0]) {
			/* we need to create a new, authorized session */

			if (lwsgs_new_session_id(vhd, &pss->login_session,
						 formvals[FGS_USERNAME],
						 pss->login_expires))
				goto try_to_reuse;

			lwsl_notice("Creating new session: %s\n",
				    pss->login_session.id);
		} else {
			/*
			 * we can just update the existing session to be
			 * authorized
			 */
			lwsl_notice("Authorizing current session %s", sid.id);
			lwsgw_update_session(vhd, &sid, formvals[FGS_USERNAME]);
			pss->login_session = sid;
		}
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION: onward=%s\n", pss->onward);

		lwsgw_expire_old_sessions(vhd);

redirect_with_cookie:
		p = buffer + LWS_PRE;
		start = p;
		end = p + sizeof(buffer) - LWS_PRE;

		if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, &p, end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
				(unsigned char *)pss->onward,
				strlen(pss->onward), &p, end))
			return 1;

		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)"text/html", 9, &p, end))
			return 1;
		if (lws_add_http_header_content_length(wsi, 0, &p, end))
			return 1;

		lwsl_notice("x\n");

		if (pss->delete_session.id[0]) {
			lwsgw_cookie_from_session(&pss->delete_session, 0, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_notice("deleting cookie '%s'\n", cookie);

			if (lws_add_http_header_by_name(wsi,
					(unsigned char *)"set-cookie:",
					(unsigned char *)cookie, pc - cookie,
					&p, end))
				return 1;
		}

		if (!pss->login_session.id[0]) {
			pss->login_expires = lwsgw_now_secs() +
					     vhd->timeout_anon_absolute_secs;
			if (lwsgs_new_session_id(vhd, &pss->login_session, "",
						 pss->login_expires))
				return 1;
		} else
			pss->login_expires = lwsgw_now_secs() +
					     vhd->timeout_absolute_secs;

		if (pss->login_session.id[0] || pss->logging_out) {
			/*
			 * we succeeded to login, we must issue a login
			 * cookie with the prepared data
			 */
			pc = cookie;

			lwsgw_cookie_from_session(&pss->login_session,
						  pss->login_expires, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_notice("setting cookie '%s'\n", cookie);

			pss->logging_out = 0;

			if (lws_add_http_header_by_name(wsi,
					(unsigned char *)"set-cookie:",
					(unsigned char *)cookie, pc - cookie,
					&p, end))
				return 1;
		}

		if (lws_finalize_http_header(wsi, &p, end))
			return 1;

		n = lws_write(wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
		if (n < 0)
			return 1;
		goto try_to_reuse;

	case LWS_CALLBACK_ADD_HEADERS:
		lwsgw_expire_old_sessions(vhd);

		args = (struct lws_process_html_args *)in;

		if (pss->delete_session.id[0]) {
			pc = cookie;
			lwsgw_cookie_from_session(&pss->delete_session, 0, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_notice("deleting cookie '%s'\n", cookie);

			if (lws_add_http_header_by_name(wsi,
					(unsigned char *)"set-cookie:",
					(unsigned char *)cookie, pc - cookie,
					(unsigned char **)&args->p,
					(unsigned char *)args->p + args->max_len))
				return 1;
		}

		if (!pss->login_session.id[0])
			lwsgs_get_sid_from_wsi(wsi, &pss->login_session);

		if (!pss->login_session.id[0] && !pss->logging_out) {

			pss->login_expires = lwsgw_now_secs() +
					     vhd->timeout_anon_absolute_secs;
			if (lwsgs_new_session_id(vhd, &pss->login_session, "",
						 pss->login_expires))
				goto try_to_reuse;
			pc = cookie;
			lwsgw_cookie_from_session(&pss->login_session,
						  pss->login_expires, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_notice("LWS_CALLBACK_ADD_HEADERS: setting cookie '%s'\n", cookie);
			if (lws_add_http_header_by_name(wsi,
					(unsigned char *)"set-cookie:",
					(unsigned char *)cookie, pc - cookie,
					(unsigned char **)&args->p,
					(unsigned char *)args->p + args->max_len))
				return 1;
		}
		break;

	default:
		break;
	}

	return 0;

try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"protocol-generic-sessions",
		callback_generic_sessions,
		sizeof(struct per_session_data__generic_sessions),
		1024,
	},
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_generic_sessions(struct lws_context *context,
			struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_generic_sessions(struct lws_context *context)
{
	return 0;
}
