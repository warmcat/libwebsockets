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
#include <stdlib.h>

/* keep changes in sync with the enum in lwsgs.h */
static const char * const param_names[] = {
	"username",
	"password",
	"password2",
	"email",
	"register",
	"good",
	"bad",
	"reg-good",
	"reg-bad",
	"admin",
	"forgot",
	"forgot-good",
	"forgot-bad",
	"forgot-post-good",
	"forgot-post-bad",
	"change",
	"curpw",
	"delete"
};

struct lwsgs_fill_args {
	char *buf;
	int len;
};

static const struct lws_protocols protocols[];

static int
lwsgs_lookup_callback_email(void *priv, int cols, char **col_val,
			    char **col_name)
{
	struct lwsgs_fill_args *a = (struct lwsgs_fill_args *)priv;
	int n;

	for (n = 0; n < cols; n++) {
		if (!strcmp(col_name[n], "content")) {
			lws_strncpy(a->buf, col_val[n], a->len);
			continue;
		}
	}
	return 0;
}

static int
lwsgs_email_cb_get_body(struct lws_email *email, char *buf, int len)
{
	struct per_vhost_data__gs *vhd = (struct per_vhost_data__gs *)email->data;
	struct lwsgs_fill_args a;
	char ss[150], esc[50];

	a.buf = buf;
	a.len = len;

	lws_snprintf(ss, sizeof(ss) - 1,
		 "select content from email where username='%s';",
		 lws_sql_purify(esc, vhd->u.username, sizeof(esc) - 1));

	lws_strncpy(buf, "failed", len);
	if (sqlite3_exec(vhd->pdb, ss, lwsgs_lookup_callback_email, &a,
			 NULL) != SQLITE_OK) {
		lwsl_err("Unable to lookup email: %s\n",
			 sqlite3_errmsg(vhd->pdb));

		return 1;
	}

	return 0;
}

static int
lwsgs_email_cb_sent(struct lws_email *email)
{
	struct per_vhost_data__gs *vhd = (struct per_vhost_data__gs *)email->data;
	char s[200], esc[50];

	/* mark the user as having sent the verification email */
	lws_snprintf(s, sizeof(s) - 1,
		 "update users set verified=1 where username='%s' and verified==0;",
		 lws_sql_purify(esc, vhd->u.username, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: Unable to update user: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	lws_snprintf(s, sizeof(s) - 1,
		 "delete from email where username='%s';",
		 lws_sql_purify(esc, vhd->u.username, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("%s: Unable to delete email text: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	return 0;
}

static int
lwsgs_email_cb_on_next(struct lws_email *email)
{
	struct per_vhost_data__gs *vhd = lws_container_of(email,
			struct per_vhost_data__gs, email);
	char s[LWSGS_EMAIL_CONTENT_SIZE], esc[50];
	time_t now = lws_now_secs();

	/*
	 * users not verified in 24h get deleted
	 */
	lws_snprintf(s, sizeof(s) - 1, "delete from users where ((verified != %d)"
		 " and (creation_time <= %lu));", LWSGS_VERIFIED_ACCEPTED,
		 (unsigned long)now - vhd->timeout_email_secs);
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to expire users: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	lws_snprintf(s, sizeof(s) - 1, "update users set token_time=0 where "
		 "(token_time <= %lu);",
		 (unsigned long)now - vhd->timeout_email_secs);
	if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
		lwsl_err("Unable to expire users: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	vhd->u.username[0] = '\0';
	lws_snprintf(s, sizeof(s) - 1, "select username from email limit 1;");
	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &vhd->u,
			 NULL) != SQLITE_OK) {
		lwsl_err("Unable to lookup user: %s\n", sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	lws_snprintf(s, sizeof(s) - 1,
		 "select username, creation_time, email, ip, verified, token"
		 " from users where username='%s' limit 1;",
		 lws_sql_purify(esc, vhd->u.username, sizeof(esc) - 1));
	if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &vhd->u,
			 NULL) != SQLITE_OK) {
		lwsl_err("Unable to lookup user: %s\n",
			 sqlite3_errmsg(vhd->pdb));
		return 1;
	}

	if (!vhd->u.username[0])
		/*
		 * nothing to do, we are idle and no suitable
		 * accounts waiting for verification.  When a new user
		 * is added we will get kicked to try again.
		 */
		return 1;

	lws_strncpy(email->email_to, vhd->u.email, sizeof(email->email_to));

	return 0;
}


struct lwsgs_subst_args
{
	struct per_session_data__gs *pss;
	struct per_vhost_data__gs *vhd;
	struct lws *wsi;
};

static const char *
lwsgs_subst(void *data, int index)
{
	struct lwsgs_subst_args *a = (struct lwsgs_subst_args *)data;
	struct lwsgs_user u;
	lwsgw_hash sid;
	char esc[50], s[100];
	int n;

	a->pss->result[0] = '\0';
	u.email[0] = '\0';
	if (!lwsgs_get_sid_from_wsi(a->wsi, &sid)) {
		if (lwsgs_lookup_session(a->vhd, &sid, a->pss->result, 31)) {
			lwsl_notice("sid lookup for %s failed\n", sid.id);
			a->pss->delete_session = sid;
			return NULL;
		}
		lws_snprintf(s, sizeof(s) - 1, "select username,email "
			 "from users where username = '%s';",
			 lws_sql_purify(esc, a->pss->result, sizeof(esc) - 1));
		if (sqlite3_exec(a->vhd->pdb, s, lwsgs_lookup_callback_user,
				 &u, NULL) != SQLITE_OK) {
			lwsl_err("Unable to lookup token: %s\n",
				 sqlite3_errmsg(a->vhd->pdb));
			a->pss->delete_session = sid;
			return NULL;
		}
	} else
		lwsl_notice("no sid\n");

	lws_strncpy(a->pss->result + 32, u.email, 100);

	switch (index) {
	case 0:
		return a->pss->result;

	case 1:
		n = lwsgs_get_auth_level(a->vhd, a->pss->result);
		sprintf(a->pss->result, "%d", n);
		return a->pss->result;
	case 2:
		return a->pss->result + 32;
	}

	return NULL;
}

static int
callback_generic_sessions(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__gs *pss = (struct per_session_data__gs *)user;
	const struct lws_protocol_vhost_options *pvo;
	struct per_vhost_data__gs *vhd = (struct per_vhost_data__gs *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
					&protocols[0]);
	char cookie[1024], username[32], *pc = cookie;
	unsigned char buffer[LWS_PRE + LWSGS_EMAIL_CONTENT_SIZE];
	struct lws_process_html_args *args;
	struct lws_session_info *sinfo;
	char s[LWSGS_EMAIL_CONTENT_SIZE];
	unsigned char *p, *start, *end;
	sqlite3_stmt *sm;
	lwsgw_hash sid;
	const char *cp;
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
			&protocols[0], sizeof(struct per_vhost_data__gs));
		if (!vhd)
			return 1;
		vhd->context = lws_get_context(wsi);

		/* defaults */
		vhd->timeout_idle_secs = 600;
		vhd->timeout_absolute_secs = 36000;
		vhd->timeout_anon_absolute_secs = 1200;
		vhd->timeout_email_secs = 24 * 3600;
		strcpy(vhd->email.email_helo, "unconfigured.com");
		strcpy(vhd->email.email_from, "noreply@unconfigured.com");
		strcpy(vhd->email_title, "Registration Email from unconfigured");
		strcpy(vhd->email.email_smtp_ip, "127.0.0.1");

		vhd->email.on_next = lwsgs_email_cb_on_next;
		vhd->email.on_get_body = lwsgs_email_cb_get_body;
		vhd->email.on_sent = lwsgs_email_cb_sent;
		vhd->email.data = (void *)vhd;

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "admin-user"))
				lws_strncpy(vhd->admin_user, pvo->value,
					sizeof(vhd->admin_user));
			if (!strcmp(pvo->name, "admin-password-sha1"))
				lws_strncpy(vhd->admin_password_sha1.id, pvo->value,
					sizeof(vhd->admin_password_sha1.id));
			if (!strcmp(pvo->name, "session-db"))
				lws_strncpy(vhd->session_db, pvo->value,
					sizeof(vhd->session_db));
			if (!strcmp(pvo->name, "confounder"))
				lws_strncpy(vhd->confounder, pvo->value,
					sizeof(vhd->confounder));
			if (!strcmp(pvo->name, "email-from"))
				lws_strncpy(vhd->email.email_from, pvo->value,
					sizeof(vhd->email.email_from));
			if (!strcmp(pvo->name, "email-helo"))
				lws_strncpy(vhd->email.email_helo, pvo->value,
					sizeof(vhd->email.email_helo));
			if (!strcmp(pvo->name, "email-template"))
				lws_strncpy(vhd->email_template, pvo->value,
					sizeof(vhd->email_template));
			if (!strcmp(pvo->name, "email-title"))
				lws_strncpy(vhd->email_title, pvo->value,
					sizeof(vhd->email_title));
			if (!strcmp(pvo->name, "email-contact-person"))
				lws_strncpy(vhd->email_contact_person, pvo->value,
					sizeof(vhd->email_contact_person));
			if (!strcmp(pvo->name, "email-confirm-url-base"))
				lws_strncpy(vhd->email_confirm_url, pvo->value,
					sizeof(vhd->email_confirm_url));
			if (!strcmp(pvo->name, "email-server-ip"))
				lws_strncpy(vhd->email.email_smtp_ip, pvo->value,
					sizeof(vhd->email.email_smtp_ip));

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
				 " last_forgot_validated integer,"
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
		if (sqlite3_exec(vhd->pdb, s, NULL, NULL, NULL) != SQLITE_OK) {
			lwsl_err("Unable to create user table: %s\n",
				 sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		lws_email_init(&vhd->email, lws_uv_getloop(vhd->context, 0),
				LWSGS_EMAIL_CONTENT_SIZE);

		vhd->email_inited = 1;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
	//	lwsl_notice("gs: LWS_CALLBACK_PROTOCOL_DESTROY: v=%p, ctx=%p\n", vhd, vhd->context);
		if (vhd->pdb) {
			sqlite3_close(vhd->pdb);
			vhd->pdb = NULL;
		}
		if (vhd->email_inited) {
			lws_email_destroy(&vhd->email);
			vhd->email_inited = 0;
		}
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
                if (!pss->check_response)
                        break;
		n = lws_write(wsi, (unsigned char *)&pss->check_response_value, 1, LWS_WRITE_HTTP_FINAL);
		if (n != 1)
			return -1;
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP:
		lwsl_info("LWS_CALLBACK_HTTP: %s\n", (const char *)in);

		pss->login_session.id[0] = '\0';
		pss->phs.pos = 0;
		lws_strncpy(pss->onward, (char *)in, sizeof(pss->onward));

		if (!strcmp((const char *)in, "/lwsgs-forgot")) {
			lwsgs_handler_forgot(vhd, wsi, pss);
			goto redirect_with_cookie;
		}

		if (!strcmp((const char *)in, "/lwsgs-confirm")) {
			lwsgs_handler_confirm(vhd, wsi, pss);
			goto redirect_with_cookie;
		}
		if (!strcmp((const char *)in, "/lwsgs-check")) {
			lwsgs_handler_check(vhd, wsi, pss);
			/* second, async part will complete transaction */
			break;
		}

		if (!strcmp((const char *)in, "/lwsgs-login"))
			break;
		if (!strcmp((const char *)in, "/lwsgs-logout"))
			break;
		if (!strcmp((const char *)in, "/lwsgs-forgot"))
			break;
		if (!strcmp((const char *)in, "/lwsgs-change"))
			break;

		/* if no legitimate url for GET, return 404 */

		lwsl_err("http doing 404 on %s\n", (const char *)in);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
		return -1;
		//goto try_to_reuse;

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
				lws_snprintf(pss->onward, sizeof(pss->onward) - 1,
					 "%s%s%s", oprot[!!lws_is_ssl(wsi)],
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

	case LWS_CALLBACK_SESSION_INFO:
	{
		struct lwsgs_user u;
		sinfo = (struct lws_session_info *)in;
		sinfo->username[0] = '\0';
		sinfo->email[0] = '\0';
		sinfo->ip[0] = '\0';
		sinfo->session[0] = '\0';
		sinfo->mask = 0;

		sid.id[0] = '\0';
		lwsl_debug("LWS_CALLBACK_SESSION_INFO\n");
		if (lwsgs_get_sid_from_wsi(wsi, &sid))
			break;
		if (lwsgs_lookup_session(vhd, &sid, username, sizeof(username)))
			break;

		lws_snprintf(s, sizeof(s) - 1,
			 "select username, email from users where username='%s';",
			 username);
		if (sqlite3_exec(vhd->pdb, s, lwsgs_lookup_callback_user, &u, NULL) !=
		    SQLITE_OK) {
			lwsl_err("Unable to lookup token: %s\n",
				 sqlite3_errmsg(vhd->pdb));
			break;
		}
		lws_strncpy(sinfo->username, u.username, sizeof(sinfo->username));
		lws_strncpy(sinfo->email, u.email, sizeof(sinfo->email));
		lws_strncpy(sinfo->session, sid.id, sizeof(sinfo->session));
		sinfo->mask = lwsgs_get_auth_level(vhd, username);
		lws_get_peer_simple(wsi, sinfo->ip, sizeof(sinfo->ip));
	}

		break;

	case LWS_CALLBACK_PROCESS_HTML:

		args = (struct lws_process_html_args *)in;
		{
			static const char * const vars[] = {
				"$lwsgs_user",
				"$lwsgs_auth",
				"$lwsgs_email"
			};
			struct lwsgs_subst_args a;

			a.vhd = vhd;
			a.pss = pss;
			a.wsi = wsi;

			pss->phs.vars = vars;
			pss->phs.count_vars = ARRAY_SIZE(vars);
			pss->phs.replace = lwsgs_subst;
			pss->phs.data = &a;

			if (lws_chunked_html_process(args, &pss->phs))
				return -1;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY:
		if (len < 2)
			break;

		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
						ARRAY_SIZE(param_names), 1024,
						NULL, NULL);
			if (!pss->spa)
				return -1;
		}

		if (lws_spa_process(pss->spa, in, len)) {
			lwsl_notice("spa process blew\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:

		if (!pss->spa)
			break;

		lwsl_info("LWS_CALLBACK_HTTP_BODY_COMPLETION: %s\n", pss->onward);
		lws_spa_finalize(pss->spa);

		if (!strcmp((char *)pss->onward, "/lwsgs-change")) {
			if (!lwsgs_handler_change_password(vhd, wsi, pss)) {
				cp = lws_spa_get_string(pss->spa, FGS_GOOD);
				goto pass;
			}

			cp = lws_spa_get_string(pss->spa, FGS_BAD);
			lwsl_notice("user/password no good %s\n",
				lws_spa_get_string(pss->spa, FGS_USERNAME));
			lws_strncpy(pss->onward, cp, sizeof(pss->onward) - 1);
			pss->onward[sizeof(pss->onward) - 1] = '\0';
			goto completion_flow;
		}

		if (!strcmp((char *)pss->onward, "/lwsgs-login")) {
			if (lws_spa_get_string(pss->spa, FGS_FORGOT) &&
			    lws_spa_get_string(pss->spa, FGS_FORGOT)[0]) {
				if (lwsgs_handler_forgot_pw_form(vhd, wsi, pss)) {
					n = FGS_FORGOT_BAD;
					goto reg_done;
				}
				/* get the email monitor to take a look */
				lws_email_check(&vhd->email);
				n = FGS_FORGOT_GOOD;
				goto reg_done;
			}

			if (!lws_spa_get_string(pss->spa, FGS_USERNAME) ||
			    !lws_spa_get_string(pss->spa, FGS_PASSWORD)) {
				lwsl_notice("username '%s' or pw '%s' missing\n",
						lws_spa_get_string(pss->spa, FGS_USERNAME),
						lws_spa_get_string(pss->spa, FGS_PASSWORD));
				return -1;
			}

			if (lws_spa_get_string(pss->spa, FGS_REGISTER) &&
			    lws_spa_get_string(pss->spa, FGS_REGISTER)[0]) {

				if (lwsgs_handler_register_form(vhd, wsi, pss))
					n = FGS_REG_BAD;
				else {
					n = FGS_REG_GOOD;

					/* get the email monitor to take a look */
					lws_email_check(&vhd->email);
				}
reg_done:
				lws_strncpy(pss->onward, lws_spa_get_string(pss->spa, n),
					    sizeof(pss->onward));
				pss->login_expires = 0;
				pss->logging_out = 1;
				goto completion_flow;
			}

			/* we have the username and password... check if admin */
			if (lwsgw_check_admin(vhd, lws_spa_get_string(pss->spa, FGS_USERNAME),
					      lws_spa_get_string(pss->spa, FGS_PASSWORD))) {
				if (lws_spa_get_string(pss->spa, FGS_ADMIN))
					cp = lws_spa_get_string(pss->spa, FGS_ADMIN);
				else
					if (lws_spa_get_string(pss->spa, FGS_GOOD))
						cp = lws_spa_get_string(pss->spa, FGS_GOOD);
					else {
						lwsl_info("No admin or good target url in form\n");
						return -1;
					}
				lwsl_debug("admin\n");
				goto pass;
			}

			/* check users in database */

			if (!lwsgs_check_credentials(vhd, lws_spa_get_string(pss->spa, FGS_USERNAME),
						     lws_spa_get_string(pss->spa, FGS_PASSWORD))) {
				lwsl_info("pw hash check met\n");
				cp = lws_spa_get_string(pss->spa, FGS_GOOD);
				goto pass;
			} else
				lwsl_notice("user/password no good %s\n",
						lws_spa_get_string(pss->spa, FGS_USERNAME));

			if (!lws_spa_get_string(pss->spa, FGS_BAD)) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			lws_strncpy(pss->onward, lws_spa_get_string(pss->spa, FGS_BAD),
				    sizeof(pss->onward));
			lwsl_debug("failed\n");

			goto completion_flow;
		}

		if (!strcmp((char *)pss->onward, "/lwsgs-logout")) {

			lwsl_notice("/logout\n");

			if (lwsgs_get_sid_from_wsi(wsi, &pss->login_session)) {
				lwsl_notice("not logged in...\n");
				return 1;
			}

			lwsgw_update_session(vhd, &pss->login_session, "");

			if (!lws_spa_get_string(pss->spa, FGS_GOOD)) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			lws_strncpy(pss->onward, lws_spa_get_string(pss->spa, FGS_GOOD),
				    sizeof(pss->onward));

			pss->login_expires = 0;
			pss->logging_out = 1;

			goto completion_flow;
		}

		break;

pass:
		lws_strncpy(pss->onward, cp, sizeof(pss->onward));

		if (lwsgs_get_sid_from_wsi(wsi, &sid))
			sid.id[0] = '\0';

		pss->login_expires = lws_now_secs() +
				     vhd->timeout_absolute_secs;

		if (!sid.id[0]) {
			/* we need to create a new, authorized session */

			if (lwsgs_new_session_id(vhd, &pss->login_session,
						 lws_spa_get_string(pss->spa, FGS_USERNAME),
						 pss->login_expires))
				goto try_to_reuse;

			lwsl_info("Creating new session: %s\n",
				    pss->login_session.id);
		} else {
			/*
			 * we can just update the existing session to be
			 * authorized
			 */
			lwsl_info("Authorizing existing session %s", sid.id);
			lwsgw_update_session(vhd, &sid,
				lws_spa_get_string(pss->spa, FGS_USERNAME));
			pss->login_session = sid;
		}

completion_flow:
		lwsgw_expire_old_sessions(vhd);
		goto redirect_with_cookie;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	case LWS_CALLBACK_ADD_HEADERS:
		lwsgw_expire_old_sessions(vhd);

		args = (struct lws_process_html_args *)in;
		if (!pss)
			return 1;
		if (pss->delete_session.id[0]) {
			pc = cookie;
			lwsgw_cookie_from_session(&pss->delete_session, 0, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_info("deleting cookie '%s'\n", cookie);

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

			pss->login_expires = lws_now_secs() +
					     vhd->timeout_anon_absolute_secs;
			if (lwsgs_new_session_id(vhd, &pss->login_session, "",
						 pss->login_expires))
				goto try_to_reuse;
			pc = cookie;
			lwsgw_cookie_from_session(&pss->login_session,
						  pss->login_expires, &pc,
						  cookie + sizeof(cookie) - 1);

			lwsl_info("LWS_CALLBACK_ADD_HEADERS: setting cookie '%s'\n", cookie);
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
		pss->login_expires = lws_now_secs() +
				     vhd->timeout_anon_absolute_secs;
		if (lwsgs_new_session_id(vhd, &pss->login_session, "",
					 pss->login_expires))
			return 1;
	} else
		pss->login_expires = lws_now_secs() +
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

		lwsl_info("setting cookie '%s'\n", cookie);

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

	/* fallthru */

try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		"protocol-generic-sessions",
		callback_generic_sessions,
		sizeof(struct per_session_data__gs),
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
