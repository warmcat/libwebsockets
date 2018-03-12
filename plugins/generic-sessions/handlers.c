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

/* handle account confirmation links */

int
lwsgs_handler_confirm(struct per_vhost_data__gs *vhd, struct lws *wsi,
		      struct per_session_data__gs *pss)
{
	char cookie[1024], s[256], esc[50];
	struct lws_gs_event_args a;
	struct lwsgs_user u;

	if (lws_hdr_copy_fragment(wsi, cookie, sizeof(cookie),
				  WSI_TOKEN_HTTP_URI_ARGS, 0) < 0)
		goto verf_fail;

	if (strncmp(cookie, "token=", 6))
		goto verf_fail;

	u.username[0] = '\0';
	lws_snprintf(s, sizeof(s) - 1,
		 "select username,email,verified from users where token = '%s';",
		 lws_sql_purify(esc, &cookie[6], sizeof(esc) - 1));
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
	lws_snprintf(s, sizeof(s) - 1,
		 "update users set verified=%d where username='%s';",
		 LWSGS_VERIFIED_ACCEPTED,
		 lws_sql_purify(esc, u.username, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		goto verf_fail;
	}

	lwsl_notice("deleting account\n");

	a.event = LWSGSE_CREATED;
	a.username = u.username;
	a.email = u.email;
	lws_callback_vhost_protocols_vhost(lws_get_vhost(wsi),
					   LWS_CALLBACK_GS_EVENT, &a, 0);

	lws_snprintf(pss->onward, sizeof(pss->onward),
		 "%s/post-verify-ok.html", vhd->email_confirm_url);

	pss->login_expires = lws_now_secs() + vhd->timeout_absolute_secs;

	pss->delete_session.id[0] = '\0';
	lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);

	/* we need to create a new, authorized session */

	if (lwsgs_new_session_id(vhd, &pss->login_session, u.username,
				 pss->login_expires))
		goto verf_fail;

	lwsl_notice("Creating new session: %s, redir to %s\n",
		    pss->login_session.id, pss->onward);

	return 0;

verf_fail:
	pss->delete_session.id[0] = '\0';
	lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);
	pss->login_expires = 0;

	lws_snprintf(pss->onward, sizeof(pss->onward), "%s/post-verify-fail.html",
		 vhd->email_confirm_url);

	return 1;
}

/* handle forgot password confirmation links */

int
lwsgs_handler_forgot(struct per_vhost_data__gs *vhd, struct lws *wsi,
		     struct per_session_data__gs *pss)
{
	char cookie[1024], s[256], esc[50];
	struct lwsgs_user u;
	const char *a;

	a = lws_get_urlarg_by_name(wsi, "token=", cookie, sizeof(cookie));
	if (!a)
		goto forgot_fail;

	u.username[0] = '\0';
	lws_snprintf(s, sizeof(s) - 1,
		 "select username,verified from users where verified=%d and "
		 "token = '%s' and token_time != 0;",
		 LWSGS_VERIFIED_ACCEPTED,
		 lws_sql_purify(esc, &cookie[6], sizeof(esc) - 1));
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

	/* mark user as having validated forgot flow just now */

	lws_snprintf(s, sizeof(s) - 1,
		 "update users set token_time=0,last_forgot_validated=%lu "
		 "where username='%s';",
		 (unsigned long)lws_now_secs(),
		 lws_sql_purify(esc, u.username, sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		goto forgot_fail;
	}

	a = lws_get_urlarg_by_name(wsi, "good=", cookie, sizeof(cookie));
	if (!a)
		a = "broken-forget-post-good-url";

	lws_snprintf(pss->onward, sizeof(pss->onward),
		 "%s/%s", vhd->email_confirm_url, a);

	pss->login_expires = lws_now_secs() + vhd->timeout_absolute_secs;

	pss->delete_session.id[0] = '\0';
	lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);

	/* we need to create a new, authorized session */
	if (lwsgs_new_session_id(vhd, &pss->login_session,
				 u.username,
				 pss->login_expires))
		goto forgot_fail;

	lwsl_notice("Creating new session: %s, redir to %s\n",
		    pss->login_session.id, pss->onward);

	return 0;

forgot_fail:
	pss->delete_session.id[0] = '\0';
	lwsgs_get_sid_from_wsi(wsi, &pss->delete_session);
	pss->login_expires = 0;

	a = lws_get_urlarg_by_name(wsi, "bad=", cookie, sizeof(cookie));
	if (!a)
		a = "broken-forget-post-bad-url";

	lws_snprintf(pss->onward, sizeof(pss->onward), "%s/%s",
		 vhd->email_confirm_url, a);

	return 1;
}

/* support dynamic username / email checking */

int
lwsgs_handler_check(struct per_vhost_data__gs *vhd,
		    struct lws *wsi, struct per_session_data__gs *pss)
{
	static const char * const colname[] = { "username", "email" };
	char cookie[1024], s[256], esc[50], *pc;
	unsigned char *p, *start, *end, buffer[LWS_PRE + 256];
	struct lwsgs_user u;
	int n;

	/*
	 * either /check?email=xxx@yyy   or: /check?username=xxx
	 * returns '0' if not already registered, else '1'
	 */

	u.username[0] = '\0';
	if (lws_hdr_copy_fragment(wsi, cookie, sizeof(cookie),
				  WSI_TOKEN_HTTP_URI_ARGS, 0) < 0)
		goto reply;

	n = !strncmp(cookie, "email=", 6);
	pc = strchr(cookie, '=');
	if (!pc) {
		lwsl_notice("cookie has no =\n");
		goto reply;
	}
	pc++;

	/* admin user cannot be registered in user db */
	if (!strcmp(vhd->admin_user, pc)) {
		u.username[0] = 'a';
		goto reply;
	}

	lws_snprintf(s, sizeof(s) - 1,
		 "select username, email from users where %s = '%s';",
		 colname[n], lws_sql_purify(esc, pc, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		goto reply;
	}

reply:
	s[0] = '0' + !!u.username[0];
	p = buffer + LWS_PRE;
	start = p;
	end = p + sizeof(buffer) - LWS_PRE;

	if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end))
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
		lwsl_err("_write returned %d from %ld\n", n, (long)(p - start));
		return -1;
	}
	pss->check_response_value = s[0];
	pss->check_response = 1;

	lws_callback_on_writable(wsi);

	return 0;
}

/* handle forgot password confirmation links */

int
lwsgs_handler_change_password(struct per_vhost_data__gs *vhd, struct lws *wsi,
			      struct per_session_data__gs *pss)
{
	char s[256], esc[50], username[50];
	struct lwsgs_user u;
	lwsgw_hash sid;
	int n = 0;

	/* see if he's logged in */
	username[0] = '\0';
	if (!lwsgs_get_sid_from_wsi(wsi, &sid)) {
		u.username[0] = '\0';
		if (!lwsgs_lookup_session(vhd, &sid, username, sizeof(username))) {
			n = 1; /* yes, logged in */
			if (lwsgs_lookup_user(vhd, username, &u))
				return 1;

			/* did a forgot pw ? */
			if (u.last_forgot_validated > (time_t)lws_now_secs() - 300) {
				n |= LWSGS_AUTH_FORGOT_FLOW;
				lwsl_debug("within forgot password flow\n");
			}
		}
	}

	lwsl_debug("auth value %d\n", n);

	/* if he just did forgot pw flow, don't need old pw */
	if ((n & (LWSGS_AUTH_FORGOT_FLOW | 1)) != (LWSGS_AUTH_FORGOT_FLOW | 1)) {
		/* otherwise user:pass must be right */
		lwsl_debug("checking pw\n");
		if (lwsgs_check_credentials(vhd,
			   lws_spa_get_string(pss->spa, FGS_USERNAME),
			   lws_spa_get_string(pss->spa, FGS_CURPW))) {
			lwsl_notice("credentials bad\n");
			return 1;
		}

		lwsl_debug("current pw checks out\n");

		lws_strncpy(u.username, lws_spa_get_string(pss->spa, FGS_USERNAME),
			    sizeof(u.username));
	}

	/* does he want to delete his account? */

	if (lws_spa_get_length(pss->spa, FGS_DELETE)) {
		struct lws_gs_event_args a;

		lwsl_notice("deleting account\n");

		a.event = LWSGSE_DELETED;
		a.username = u.username;
		a.email = "";
		lws_callback_vhost_protocols_vhost(lws_get_vhost(wsi),
						   LWS_CALLBACK_GS_EVENT, &a, 0);

		lws_snprintf(s, sizeof(s) - 1,
			 "delete from users where username='%s';"
			 "delete from sessions where username='%s';",
			 lws_sql_purify(esc, u.username, sizeof(esc) - 1),
			 lws_sql_purify(esc, u.username, sizeof(esc) - 1));
		goto sql;
	}

	if (lwsgs_hash_password(vhd, lws_spa_get_string(pss->spa, FGS_PASSWORD), &u))
		return 1;

	lwsl_notice("updating password hash\n");

	lws_snprintf(s, sizeof(s) - 1,
		 "update users set pwhash='%s', pwsalt='%s', "
		 "last_forgot_validated=0 where username='%s';",
		 u.pwhash.id, u.pwsalt.id,
		 lws_sql_purify(esc, u.username, sizeof(esc) - 1));

sql:
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to update pw hash: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}

int
lwsgs_handler_forgot_pw_form(struct per_vhost_data__gs *vhd,
			     struct lws *wsi,
			     struct per_session_data__gs *pss)
{
	char s[LWSGS_EMAIL_CONTENT_SIZE];
	unsigned char buffer[LWS_PRE + LWSGS_EMAIL_CONTENT_SIZE];
	char esc[50], esc1[50], esc2[50], esc3[50], esc4[50];
	struct lwsgs_user u;
	lwsgw_hash hash;
	unsigned char sid_rand[20];
	int n;

	lwsl_notice("FORGOT %s %s\n",
		    lws_spa_get_string(pss->spa, FGS_USERNAME),
		    lws_spa_get_string(pss->spa, FGS_EMAIL));

	if (!lws_spa_get_string(pss->spa, FGS_USERNAME) &&
	    !lws_spa_get_string(pss->spa, FGS_EMAIL)) {
		lwsl_err("Form must provide either "
			  "username or email\n");
		return -1;
	}

	if (!lws_spa_get_string(pss->spa, FGS_FORGOT_GOOD) ||
	    !lws_spa_get_string(pss->spa, FGS_FORGOT_BAD) ||
	    !lws_spa_get_string(pss->spa, FGS_FORGOT_POST_GOOD) ||
	    !lws_spa_get_string(pss->spa, FGS_FORGOT_POST_BAD)) {
		lwsl_err("Form must provide reg-good "
			  "and reg-bad (and post-*)"
			  "targets\n");
		return -1;
	}

	u.username[0] = '\0';
	if (lws_spa_get_string(pss->spa, FGS_USERNAME))
		lws_snprintf(s, sizeof(s) - 1,
		 "select username,email "
		 "from users where username = '%s';",
		 lws_sql_purify(esc, lws_spa_get_string(pss->spa, FGS_USERNAME),
				 sizeof(esc) - 1));
	else
		lws_snprintf(s, sizeof(s) - 1,
		 "select username,email "
		 "from users where email = '%s';",
		 lws_sql_purify(esc, lws_spa_get_string(pss->spa, FGS_EMAIL), sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}
	if (!u.username[0]) {
		lwsl_err("No match found %s\n", s);
		return 1;
	}

	lws_get_peer_simple(wsi, pss->ip, sizeof(pss->ip));
	if (lws_get_random(vhd->context, sid_rand,
			   sizeof(sid_rand)) !=
			   sizeof(sid_rand)) {
		lwsl_err("Problem getting random for token\n");
		return 1;
	}
	sha1_to_lwsgw_hash(sid_rand, &hash);
	n = lws_snprintf(s, sizeof(s),
		"From: Forgot Password Assistant Noreply <%s>\n"
		"To: %s <%s>\n"
		  "Subject: Password reset request\n"
		  "\n"
		  "Hello, %s\n\n"
		  "We received a password reset request from IP %s for this email,\n"
		  "to confirm you want to do that, please click the link below.\n\n",
		lws_sql_purify(esc, vhd->email.email_from, sizeof(esc) - 1),
		lws_sql_purify(esc1, u.username, sizeof(esc1) - 1),
		lws_sql_purify(esc2, u.email, sizeof(esc2) - 1),
		lws_sql_purify(esc3, u.username, sizeof(esc3) - 1),
		lws_sql_purify(esc4, pss->ip, sizeof(esc4) - 1));
	lws_snprintf(s + n, sizeof(s) -n,
		  "%s/lwsgs-forgot?token=%s"
		   "&good=%s"
		   "&bad=%s\n\n"
		  "If this request is unexpected, please ignore it and\n"
		  "no further action will be taken.\n\n"
		"If you have any questions or concerns about this\n"
		"automated email, you can contact a real person at\n"
		"%s.\n"
		"\n.\n",
		vhd->email_confirm_url, hash.id,
		lws_urlencode(esc1,
			     lws_spa_get_string(pss->spa, FGS_FORGOT_POST_GOOD),
			     sizeof(esc1) - 1),
		lws_urlencode(esc3,
			      lws_spa_get_string(pss->spa, FGS_FORGOT_POST_BAD),
			      sizeof(esc3) - 1),
		vhd->email_contact_person);

	lws_snprintf((char *)buffer, sizeof(buffer) - 1,
		 "insert into email(username, content)"
		 " values ('%s', '%s');",
		lws_sql_purify(esc, u.username, sizeof(esc) - 1), s);
	if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL,
			 NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert email: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	lws_snprintf(s, sizeof(s) - 1,
		 "update users set token='%s',token_time='%ld' where username='%s';",
		 hash.id, (long)lws_now_secs(),
		 lws_sql_purify(esc, u.username, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) !=
	    SQLITE_OK) {
		lwsl_err("Unable to set token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}

int
lwsgs_handler_register_form(struct per_vhost_data__gs *vhd,
			     struct lws *wsi,
			     struct per_session_data__gs *pss)
{
	unsigned char buffer[LWS_PRE + LWSGS_EMAIL_CONTENT_SIZE];
	char esc[50], esc1[50], esc2[50], esc3[50], esc4[50];
	char s[LWSGS_EMAIL_CONTENT_SIZE];
	unsigned char sid_rand[20];
	struct lwsgs_user u;
	lwsgw_hash hash;

	lwsl_notice("REGISTER %s %s %s\n",
			lws_spa_get_string(pss->spa, FGS_USERNAME),
			lws_spa_get_string(pss->spa, FGS_PASSWORD),
			lws_spa_get_string(pss->spa, FGS_EMAIL));
	if (lwsgs_get_sid_from_wsi(wsi,
	    &pss->login_session))
		return 1;

	lws_get_peer_simple(wsi, pss->ip, sizeof(pss->ip));
	lwsl_notice("IP=%s\n", pss->ip);

	if (!lws_spa_get_string(pss->spa, FGS_REG_GOOD) ||
	    !lws_spa_get_string(pss->spa, FGS_REG_BAD)) {
		lwsl_info("Form must provide reg-good and reg-bad targets\n");
		return -1;
	}

	/* admin user cannot be registered in user db */
	if (!strcmp(vhd->admin_user,
		    lws_spa_get_string(pss->spa, FGS_USERNAME)))
		return 1;

	if (!lwsgs_lookup_user(vhd,
			lws_spa_get_string(pss->spa, FGS_USERNAME), &u)) {
		lwsl_notice("user %s already registered\n",
			    lws_spa_get_string(pss->spa, FGS_USERNAME));
		return 1;
	}

	u.username[0] = '\0';
	lws_snprintf(s, sizeof(s) - 1, "select username, email from users where email = '%s';",
		 lws_sql_purify(esc, lws_spa_get_string(pss->spa, FGS_EMAIL),
		 sizeof(esc) - 1));

	if (sqlite3_exec(vhd->pdb, s,
			 lwsgs_lookup_callback_user, &u, NULL) != SQLITE_OK) {
		lwsl_err("Unable to lookup token: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	if (u.username[0]) {
		lwsl_notice("email %s already in use\n",
			    lws_spa_get_string(pss->spa, FGS_USERNAME));
		return 1;
	}

	if (lwsgs_hash_password(vhd, lws_spa_get_string(pss->spa, FGS_PASSWORD),
			        &u)) {
		lwsl_err("Password hash failed\n");
		return 1;
	}

	if (lws_get_random(vhd->context, sid_rand, sizeof(sid_rand)) !=
	    sizeof(sid_rand)) {
		lwsl_err("Problem getting random for token\n");
		return 1;
	}
	sha1_to_lwsgw_hash(sid_rand, &hash);

	lws_snprintf((char *)buffer, sizeof(buffer) - 1,
		 "insert into users(username,"
		 " creation_time, ip, email, verified,"
		 " pwhash, pwsalt, token, last_forgot_validated)"
		 " values ('%s', %lu, '%s', '%s', 0,"
		 " '%s', '%s', '%s', 0);",
		lws_sql_purify(esc, lws_spa_get_string(pss->spa, FGS_USERNAME), sizeof(esc) - 1),
		(unsigned long)lws_now_secs(),
		lws_sql_purify(esc1, pss->ip, sizeof(esc1) - 1),
		lws_sql_purify(esc2, lws_spa_get_string(pss->spa, FGS_EMAIL), sizeof(esc2) - 1),
		u.pwhash.id, u.pwsalt.id, hash.id);

	if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert user: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	lws_snprintf(s, sizeof(s),
		"From: Noreply <%s>\n"
		"To: %s <%s>\n"
		  "Subject: Registration verification\n"
		  "\n"
		  "Hello, %s\n\n"
		  "We received a registration from IP %s using this email,\n"
		  "to confirm it is legitimate, please click the link below.\n\n"
		  "%s/lwsgs-confirm?token=%s\n\n"
		  "If this request is unexpected, please ignore it and\n"
		  "no further action will be taken.\n\n"
		"If you have any questions or concerns about this\n"
		"automated email, you can contact a real person at\n"
		"%s.\n"
		"\n.\n",
		lws_sql_purify(esc, vhd->email.email_from, sizeof(esc) - 1),
		lws_sql_purify(esc1, lws_spa_get_string(pss->spa, FGS_USERNAME), sizeof(esc1) - 1),
		lws_sql_purify(esc2, lws_spa_get_string(pss->spa, FGS_EMAIL), sizeof(esc2) - 1),
		lws_sql_purify(esc3, lws_spa_get_string(pss->spa, FGS_USERNAME), sizeof(esc3) - 1),
		lws_sql_purify(esc4, pss->ip, sizeof(esc4) - 1),
		vhd->email_confirm_url, hash.id,
		vhd->email_contact_person);

	lws_snprintf((char *)buffer, sizeof(buffer) - 1,
		 "insert into email(username, content) values ('%s', '%s');",
		lws_sql_purify(esc, lws_spa_get_string(pss->spa, FGS_USERNAME),
			       sizeof(esc) - 1), s);

	if (sqlite3_exec(vhd->pdb, (char *)buffer, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to insert email: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}
