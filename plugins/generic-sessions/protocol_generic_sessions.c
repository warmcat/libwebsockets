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
	char esc[96], s[100];
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
lws_get_effective_host(struct lws *wsi, char *buf, size_t buflen)
{
	/* h2 */
	if (lws_hdr_copy(wsi, buf, buflen - 1,
			 WSI_TOKEN_HTTP_COLON_AUTHORITY) > 0)
		return 0;

	/* h1 */
	if (lws_hdr_copy(wsi, buf, buflen - 1,  WSI_TOKEN_HOST) > 0)
		return 0;

	return 1;
}

static int
callback_generic_sessions(struct lws *wsi, enum lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__gs *pss = (struct per_session_data__gs *)user;
	const struct lws_protocol_vhost_options *pvo;
	struct per_vhost_data__gs *vhd = (struct per_vhost_data__gs *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
				lws_vhost_name_to_protocol(lws_get_vhost(wsi),
						"protocol-generic-sessions"));
	char cookie[1024], username[32], *pc = cookie;
	unsigned char buffer[LWS_PRE + LWSGS_EMAIL_CONTENT_SIZE];
	struct lws_process_html_args *args = in;
	struct lws_session_info *sinfo;
	char s[LWSGS_EMAIL_CONTENT_SIZE];
	unsigned char *p, *start, *end;
	const char *cp, *cp1;
	sqlite3_stmt *sm;
	lwsgw_hash sid;
#if defined(LWS_WITH_SMTP)
	lws_abs_t abs;
#endif
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */

		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
			lws_get_protocol(wsi), sizeof(struct per_vhost_data__gs));
		if (!vhd)
			return 1;
		vhd->context = lws_get_context(wsi);

		/* defaults */
		vhd->timeout_idle_secs = 600;
		vhd->timeout_absolute_secs = 36000;
		vhd->timeout_anon_absolute_secs = 1200;
		vhd->timeout_email_secs = 24 * 3600;


		strcpy(vhd->helo, "unconfigured.com");
		strcpy(vhd->ip, "127.0.0.1");
		strcpy(vhd->email_from, "noreply@unconfigured.com");
		strcpy(vhd->email_title, "Registration Email from unconfigured");
		vhd->urlroot[0] = '\0';

		pvo = (const struct lws_protocol_vhost_options *)in;
		while (pvo) {
			if (!strcmp(pvo->name, "admin-user"))
				lws_strncpy(vhd->admin_user, pvo->value,
					sizeof(vhd->admin_user));
			if (!strcmp(pvo->name, "urlroot"))
				lws_strncpy(vhd->urlroot, pvo->value,
					sizeof(vhd->urlroot));
			if (!strcmp(pvo->name, "admin-password-sha256"))
				lws_strncpy(vhd->admin_password_sha256.id, pvo->value,
					sizeof(vhd->admin_password_sha256.id));
			if (!strcmp(pvo->name, "session-db"))
				lws_strncpy(vhd->session_db, pvo->value,
					sizeof(vhd->session_db));
			if (!strcmp(pvo->name, "confounder"))
				lws_strncpy(vhd->confounder, pvo->value,
					sizeof(vhd->confounder));
			if (!strcmp(pvo->name, "email-from"))
				lws_strncpy(vhd->email_from, pvo->value,
					sizeof(vhd->email_from));
			if (!strcmp(pvo->name, "email-helo"))
				lws_strncpy(vhd->helo, pvo->value, sizeof(vhd->helo));
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
				lws_strncpy(vhd->ip, pvo->value, sizeof(vhd->ip));

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
		    !vhd->admin_password_sha256.id[0] ||
		    !vhd->session_db[0]) {
			lwsl_err("generic-sessions: "
				 "You must give \"admin-user\", "
				 "\"admin-password-sha256\", "
				 "and \"session_db\" per-vhost options\n");
			return 1;
		}

		if (lws_struct_sq3_open(lws_get_context(wsi),
					vhd->session_db, &vhd->pdb)) {
			lwsl_err("Unable to open session db %s: %s\n",
				 vhd->session_db, sqlite3_errmsg(vhd->pdb));

			return 1;
		}

		if (sqlite3_prepare(vhd->pdb,
				    "create table if not exists sessions ("
				    " name char(65),"
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
				 " pwhash varchar(65),"
				 " pwsalt varchar(65),"
				 " pwchange_time integer,"
				 " token varchar(65),"
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

#if defined(LWS_WITH_SMTP)

		memset(&abs, 0, sizeof(abs));
		abs.vh = lws_get_vhost(wsi);

		/* select the protocol and bind its tokens */

		abs.ap = lws_abs_protocol_get_by_name("smtp");
		if (!abs.ap)
			return 1;

		vhd->protocol_tokens[0].name_index = LTMI_PSMTP_V_HELO;
		vhd->protocol_tokens[0].u.value = vhd->helo;

		abs.ap_tokens = vhd->protocol_tokens;

		/* select the transport and bind its tokens */

		abs.at = lws_abs_transport_get_by_name("raw_skt");
		if (!abs.at)
			return 1;

		vhd->transport_tokens[0].name_index = LTMI_PEER_V_DNS_ADDRESS;
		vhd->transport_tokens[0].u.value = vhd->ip;
		vhd->transport_tokens[1].name_index = LTMI_PEER_LV_PORT;
		vhd->transport_tokens[1].u.lvalue = 25;

		abs.at_tokens = vhd->transport_tokens;

		vhd->smtp_client = lws_abs_bind_and_create_instance(&abs);
		if (!vhd->smtp_client)
			return 1;

		lwsl_notice("%s: created SMTP client\n", __func__);
#endif
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
	//	lwsl_notice("gs: LWS_CALLBACK_PROTOCOL_DESTROY: v=%p, ctx=%p\n", vhd, vhd->context);
		if (vhd->pdb) {
			sqlite3_close(vhd->pdb);
			vhd->pdb = NULL;
		}
#if defined(LWS_WITH_SMTP)
		if (vhd->smtp_client)
			lws_abs_destroy_instance(&vhd->smtp_client);
#endif
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
                if (!pss->check_response)
                        break;
                pss->check_response = 0;
		n = lws_write(wsi, (unsigned char *)&pss->check_response_value,
				1, LWS_WRITE_HTTP | LWS_WRITE_H2_STREAM_END);
		if (n != 1)
			return -1;
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP:
		if (!pss) {
			lwsl_err("%s: no valid pss\n", __func__);
			return 1;
		}

		pss->login_session.id[0] = '\0';
		pss->phs.pos = 0;

		cp = in;
		if ((*(const char *)in == '/'))
			cp++;

		if (lws_get_effective_host(wsi, cookie, sizeof(cookie))) {
			lwsl_err("%s: HTTP: no effective host\n", __func__);
			return 1;
		}

		lwsl_notice("LWS_CALLBACK_HTTP: %s, HOST '%s'\n",
				(const char *)in, cookie);

		n = strlen(cp);

		lws_snprintf(pss->onward, sizeof(pss->onward),
			     "%s%s", vhd->urlroot, (const char *)in);

		if (n >= 12 &&
		    !strcmp(cp + n - 12, "lwsgs-forgot")) {
			lwsgs_handler_forgot(vhd, wsi, pss);
			goto redirect_with_cookie;
		}

		if (n >= 13 &&
		    !strcmp(cp + n - 13, "lwsgs-confirm")) {
			lwsgs_handler_confirm(vhd, wsi, pss);
			goto redirect_with_cookie;
		}
		cp1 = strstr(cp, "lwsgs-check/");
		if (cp1) {
			lwsgs_handler_check(vhd, wsi, pss, cp1 + 12);
			/* second, async part will complete transaction */
			break;
		}

		if (n >= 11 && cp && !strcmp(cp + n - 11, "lwsgs-login"))
			break;
		if (n >= 12 && cp && !strcmp(cp + n - 12, "lwsgs-logout"))
			break;
		if (n >= 12 && cp && !strcmp(cp + n - 12, "lwsgs-forgot"))
			break;
		if (n >= 12 && cp && !strcmp(cp + n - 12, "lwsgs-change"))
			break;

		/* if no legitimate url for GET, return 404 */

		lwsl_err("%s: http doing 404 on %s\n", __func__, cp ? cp : "null");
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);

		return -1;
		//goto try_to_reuse;

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		args = (struct lws_process_html_args *)in;
		if (!args->chunked)
			break;
	case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
		n = 0;
		username[0] = '\0';
		sid.id[0] = '\0';
		args = (struct lws_process_html_args *)in;
		lwsl_notice("%s: LWS_CALLBACK_CHECK_ACCESS_RIGHTS: need 0x%x\n",
				__func__, args->max_len);
		if (!lwsgs_get_sid_from_wsi(wsi, &sid)) {
			if (lwsgs_lookup_session(vhd, &sid, username,
						 sizeof(username))) {

				/*
				 * if we're authenticating for ws, we don't
				 * want to redirect it or gain a cookie on that,
				 * he'll need to get the cookie from http
				 * interactions outside of this.
				 */
				if (args->chunked) {
					lwsl_notice("%s: ws auth failed\n",
							__func__);

					return 1;
				}

				lwsl_notice("session lookup for %s failed, "
					    "probably expired\n", sid.id);
				pss->delete_session = sid;
				args->final = 1; /* signal we dealt with it */
				lws_snprintf(pss->onward, sizeof(pss->onward) - 1,
					 "%s%s", vhd->urlroot, args->p);
				lwsl_notice("redirecting to ourselves with "
					    "cookie refresh\n");
				/* we need a redirect to ourselves,
				 * session cookie is expired */
				goto redirect_with_cookie;
			}
		} else
			lwsl_notice("%s: failed to get sid from wsi\n", __func__);

		n = lwsgs_get_auth_level(vhd, username);
		lwsl_notice("%s: lwsgs_get_auth_level '%s' says %d\n", __func__, username, n);

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
			pss->phs.count_vars = LWS_ARRAY_SIZE(vars);
			pss->phs.replace = lwsgs_subst;
			pss->phs.data = &a;

			if (lws_chunked_html_process(args, &pss->phs))
				return -1;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY:
		if (len < 2) {
			lwsl_err("%s: HTTP_BODY: len %d < 2\n", __func__, (int)len);
			break;
		}

		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					LWS_ARRAY_SIZE(param_names), 1024,
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

		lwsl_debug("%s: LWS_CALLBACK_HTTP_BODY_COMPLETION\n", __func__);

		if (!pss->spa)
			break;

		cp1 = (const char *)pss->onward;
		if (*cp1 == '/')
			cp1++;


		lws_spa_finalize(pss->spa);
		n = strlen(cp1);

		if (lws_get_effective_host(wsi, cookie, sizeof(cookie)))
			return 1;

		if (!strcmp(cp1 + n - 12, "lwsgs-change")) {
			if (!lwsgs_handler_change_password(vhd, wsi, pss)) {
				cp = lws_spa_get_string(pss->spa, FGS_GOOD);
				goto pass;
			}

			cp = lws_spa_get_string(pss->spa, FGS_BAD);
			lwsl_notice("user/password no good %s\n",
				lws_spa_get_string(pss->spa, FGS_USERNAME));
			lws_snprintf(pss->onward, sizeof(pss->onward),
				     "%s%s", vhd->urlroot, cp);

			pss->onward[sizeof(pss->onward) - 1] = '\0';
			goto completion_flow;
		}

		if (!strcmp(cp1 + n - 11, "lwsgs-login")) {
			lwsl_err("%s: lwsgs-login\n", __func__);
			if (lws_spa_get_string(pss->spa, FGS_FORGOT) &&
			    lws_spa_get_string(pss->spa, FGS_FORGOT)[0]) {
				if (lwsgs_handler_forgot_pw_form(vhd, wsi, pss)) {
					n = FGS_FORGOT_BAD;
					goto reg_done;
				}
#if defined(LWS_WITH_SMTP)
				/* get the email monitor to take a look */
				lws_smtpc_kick(vhd->smtp_client);
#endif
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
#if defined(LWS_WITH_SMTP)
					/* get the email monitor to take a look */
					lws_smtpc_kick(vhd->smtp_client);
#endif
				}
reg_done:
				lws_snprintf(pss->onward, sizeof(pss->onward),
					     "%s%s", vhd->urlroot,
					     lws_spa_get_string(pss->spa, n));

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

			if (!lwsgs_check_credentials(vhd,
					lws_spa_get_string(pss->spa, FGS_USERNAME),
					lws_spa_get_string(pss->spa, FGS_PASSWORD))) {
				lwsl_notice("pw hash check met\n");
				cp = lws_spa_get_string(pss->spa, FGS_GOOD);
				goto pass;
			} else
				lwsl_notice("user/password no good %s %s\n",
						lws_spa_get_string(pss->spa, FGS_USERNAME),
						lws_spa_get_string(pss->spa, FGS_PASSWORD));

			if (!lws_spa_get_string(pss->spa, FGS_BAD)) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			lws_snprintf(pss->onward, sizeof(pss->onward),
				     "%s%s", vhd->urlroot,
				     lws_spa_get_string(pss->spa, FGS_BAD));

			lwsl_notice("failed: %s\n", pss->onward);

			goto completion_flow;
		}

		if (!strcmp(cp1 + n - 12, "lwsgs-logout")) {

			lwsl_notice("/logout\n");

			if (lwsgs_get_sid_from_wsi(wsi, &pss->login_session)) {
				lwsl_notice("not logged in...\n");
				return 1;
			}

			/*
			 * We keep the same session, but mark it as not
			 * being associated to any authenticated user
			 */

			lwsgw_update_session(vhd, &pss->login_session, "");

			if (!lws_spa_get_string(pss->spa, FGS_GOOD)) {
				lwsl_info("No admin or good target url in form\n");
				return -1;
			}

			lws_snprintf(pss->onward, sizeof(pss->onward),
				     "%s%s", vhd->urlroot,
				     lws_spa_get_string(pss->spa, FGS_GOOD));

			pss->login_expires = 0;
			pss->logging_out = 1;

			goto completion_flow;
		}

		break;

pass:
		lws_snprintf(pss->onward, sizeof(pss->onward),
			     "%s%s", vhd->urlroot, cp);

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

			lwsl_notice("%s: Creating new session: %s\n", __func__,
				    pss->login_session.id);
		} else {
			/*
			 * we can just update the existing session to be
			 * authorized
			 */
			lwsl_notice("%s: Authorizing existing session %s, name %s\n",
				    __func__, sid.id,
				    lws_spa_get_string(pss->spa, FGS_USERNAME));
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

		lwsl_warn("ADD_HEADERS\n");

		args = (struct lws_process_html_args *)in;
		if (!pss)
			return 1;
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

	lwsl_warn("%s: redirect_with_cookie\n", __func__);

	if (lws_add_http_header_status(wsi, HTTP_STATUS_SEE_OTHER, &p, end))
		return 1;

	{
		char loc[1024], uria[128];

		uria[0] = '\0';
		lws_hdr_copy_fragment(wsi, uria, sizeof(uria),
					  WSI_TOKEN_HTTP_URI_ARGS, 0);
		n = lws_snprintf(loc, sizeof(loc), "%s?%s",
				pss->onward, uria);
		lwsl_notice("%s: redirect to '%s'\n", __func__, loc);
		if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
				(unsigned char *)loc, n, &p, end))
			return 1;
	}

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
				&p, end)) {
			lwsl_err("fail0\n");
			return 1;
		}
	}

	if (!pss->login_session.id[0]) {
		pss->login_expires = lws_now_secs() +
				     vhd->timeout_anon_absolute_secs;
		if (lwsgs_new_session_id(vhd, &pss->login_session, "",
					 pss->login_expires)) {
			lwsl_err("fail1\n");
			return 1;
		}
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

		lwsl_err("%s: setting cookie '%s'\n", __func__, cookie);

		pss->logging_out = 0;

		if (lws_add_http_header_by_name(wsi,
				(unsigned char *)"set-cookie:",
				(unsigned char *)cookie, pc - cookie,
				&p, end)) {
			lwsl_err("fail2\n");
			return 1;
		}
	}

	if (lws_finalize_http_header(wsi, &p, end))
		return 1;

	// lwsl_hexdump_notice(start, p - start);

	n = lws_write(wsi, start, p - start, LWS_WRITE_H2_STREAM_END |
					     LWS_WRITE_HTTP_HEADERS);
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

LWS_VISIBLE int
init_protocol_generic_sessions(struct lws_context *context,
			struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = LWS_ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_VISIBLE int
destroy_protocol_generic_sessions(struct lws_context *context)
{
	return 0;
}
